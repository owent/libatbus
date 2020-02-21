#include <assert.h>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <stdint.h>

#include <common/string_oprs.h>

#include "detail/buffer.h"

#include "atbus_endpoint.h"
#include "atbus_node.h"

#include "libatbus_protocol.h"

namespace atbus {
    endpoint::ptr_t endpoint::create(node *owner, bus_id_t id, uint32_t children_mask, int32_t pid, const std::string &hn) {
        if (NULL == owner) {
            return endpoint::ptr_t();
        }

        endpoint::ptr_t ret(new endpoint());
        if (!ret) {
            return ret;
        }

        ret->id_            = id;
        ret->children_mask_ = children_mask;
        ret->pid_           = pid;
        ret->hostname_      = hn;

        ret->owner_   = owner;
        ret->watcher_ = ret;
        return ret;
    }

    endpoint::endpoint() : id_(0), children_mask_(0), pid_(0), owner_(NULL) { flags_.reset(); }

    endpoint::~endpoint() {
        if (NULL != owner_) {
            ATBUS_FUNC_NODE_DEBUG(*owner_, this, NULL, NULL, "endpoint deallocated");
        }

        flags_.set(flag_t::DESTRUCTING, true);

        reset();
    }

    void endpoint::reset() {
        // 这个函数可能会在析构时被调用，这时候不能使用watcher_.lock()
        if (flags_.test(flag_t::RESETTING)) {
            return;
        }
        flags_.set(flag_t::RESETTING, true);

        // 需要临时给自身加引用计数，否则后续移除的过程中可能导致数据被提前释放
        ptr_t tmp_holder = watcher_.lock();

        // 释放连接
        if (ctrl_conn_) {
            ctrl_conn_->binding_ = NULL;
            ctrl_conn_->reset();
            ctrl_conn_.reset();
        }

        // 这时候connection可能在其他地方被引用，不会触发reset函数，所以还是要reset一下
        while (!data_conn_.empty()) {
            std::list<connection::ptr_t>::iterator iter = data_conn_.begin();
            (*iter)->reset();

            if (!data_conn_.empty() && data_conn_.begin() == iter) {
                data_conn_.erase(iter);
            }
        }

        listen_address_.clear();

        flags_.reset();
        // 只要endpoint存在，则它一定存在于owner_的某个位置。
        // 并且这个值只能在创建时指定，所以不能重置这个值

        // 所有的endpoint的reset行为都要加入到检测和释放列表
        if (NULL != owner_) {
            owner_->add_endpoint_gc_list(tmp_holder);
        }
    }

    bool endpoint::is_child_node(bus_id_t id) const {
        // id_ == 0 means a temporary node, and has no child
        if (0 == id_) {
            return false;
        }

        // 目前id是整数，直接位运算即可
        bus_id_t mask = ~((1 << children_mask_) - 1);
        return (id & mask) == (id_ & mask);
    }

    bool endpoint::is_brother_node(bus_id_t id, uint32_t parent_mask) const {
        // id_ == 0 means a temporary node, and all other node is a brother
        if (0 == id_) {
            return true;
        }

        // 兄弟节点的子节点也视为兄弟节点
        // 目前id是整数，直接位运算即可
        bus_id_t c_mask = ~((1 << children_mask_) - 1);
        bus_id_t f_mask = ~((1 << parent_mask) - 1);
        // 同一父节点下，且子节点域不同
        return (id & c_mask) != (id_ & c_mask) && (0 == parent_mask || (id & f_mask) == (id_ & f_mask));
    }

    bool endpoint::is_parent_node(bus_id_t id, bus_id_t parent_id, uint32_t /*parent_mask*/) {
        // bus_id_t mask = ~((1 << parent_mask) - 1);
        return id == parent_id;
    }

    endpoint::bus_id_t endpoint::get_children_min_id(bus_id_t children_prefix, uint32_t mask) {
        bus_id_t maskv = (1 << mask) - 1;
        return children_prefix & (~maskv);
    }

    endpoint::bus_id_t endpoint::get_children_max_id(bus_id_t children_prefix, uint32_t mask) {
        bus_id_t maskv = (1 << mask) - 1;
        return children_prefix | maskv;
    }

    bool endpoint::is_child_node(bus_id_t parent_id, bus_id_t parent_children_prefix, uint32_t parent_mask, bus_id_t checked_id) {
        if (0 == parent_children_prefix) {
            parent_children_prefix = parent_id;
        }

        bus_id_t min_c = get_children_min_id(parent_children_prefix, parent_mask);
        bus_id_t max_c = get_children_max_id(parent_children_prefix, parent_mask);
        if (parent_id != checked_id && checked_id >= min_c && checked_id <= max_c) {
            return true;
        }

        return false;
    }

    bool endpoint::add_connection(connection *conn, bool force_data) {
        if (!conn) {
            return false;
        }

        if (flags_.test(flag_t::RESETTING)) {
            return false;
        }

        if (this == conn->binding_) {
            return true;
        }

        if (NULL != conn->binding_) {
            return false;
        }

        if (force_data || ctrl_conn_) {
            data_conn_.push_back(conn->watcher_.lock());
            flags_.set(flag_t::CONNECTION_SORTED, false); // 置为未排序状态
        } else {
            ctrl_conn_ = conn->watcher_.lock();
        }

        // 已经成功连接可以不需要握手
        conn->binding_ = this;
        if (connection::state_t::HANDSHAKING == conn->get_status()) {
            conn->set_status(connection::state_t::CONNECTED);
        }
        return true;
    }

    bool endpoint::is_available() const {
        if (!ctrl_conn_) {
            return false;
        }

        for (std::list<connection::ptr_t>::const_iterator iter = data_conn_.begin(); iter != data_conn_.end(); ++iter) {
            if ((*iter) && (*iter)->is_running()) {
                return true;
            }
        }

        return false;
    }

    bool endpoint::remove_connection(connection *conn) {
        if (!conn) {
            return false;
        }

        assert(this == conn->binding_);

        // 重置流程会在reset里清理对象，不需要再进行一次查找
        if (flags_.test(flag_t::RESETTING)) {
            conn->binding_ = NULL;
            return true;
        }

        if (conn == ctrl_conn_.get()) {
            // 控制节点离线则直接下线
            reset();
            return true;
        }

        // 每个节点的连接数不会很多，并且连接断开时是个低频操作
        // 所以O(log(n))的复杂度并没有关系
        for (std::list<connection::ptr_t>::iterator iter = data_conn_.begin(); iter != data_conn_.end(); ++iter) {
            if ((*iter).get() == conn) {
                conn->binding_ = NULL;
                data_conn_.erase(iter);

                // 数据节点全部离线也直接下线
                // 内存和共享内存通道不会被动下线
                // 如果任意tcp通道被动下线或者存在内存或共享内存通道则无需下线
                // 因为通常来说内存或共享内存通道就是最快的通道
                if (data_conn_.empty()) {
                    reset();
                }
                return true;
            }
        }

        return false;
    }

    bool endpoint::get_flag(flag_t::type f) const {
        if (f >= flag_t::MAX) {
            return false;
        }

        return flags_.test(f);
    }

    int endpoint::set_flag(flag_t::type f, bool v) {
        if (f >= flag_t::MAX || f < flag_t::MUTABLE_FLAGS) {
            return EN_ATBUS_ERR_PARAMS;
        }

        flags_.set(f, v);

        return EN_ATBUS_ERR_SUCCESS;
    }

    uint32_t endpoint::get_flags() const { return static_cast<uint32_t>(flags_.to_ulong()); }

    endpoint::ptr_t endpoint::watch() const {
        if (flags_.test(flag_t::DESTRUCTING) || watcher_.expired()) {
            return endpoint::ptr_t();
        }

        return watcher_.lock();
    }

    void endpoint::add_listen(const std::string &addr) {
        if (addr.empty()) {
            return;
        }

        if (0 == UTIL_STRFUNC_STRNCASE_CMP("mem:", addr.c_str(), 4) || 0 == UTIL_STRFUNC_STRNCASE_CMP("shm:", addr.c_str(), 4)) {
            flags_.set(flag_t::HAS_LISTEN_PORC, true);
        } else {
            flags_.set(flag_t::HAS_LISTEN_FD, true);
        }

        listen_address_.push_back(addr);
    }

    bool endpoint::sort_connection_cmp_fn(const connection::ptr_t &left, const connection::ptr_t &right) {
        int lscore = 0, rscore = 0;
        if (!left->check_flag(connection::flag_t::ACCESS_SHARE_ADDR)) {
            lscore += 0x08;
        }
        if (!left->check_flag(connection::flag_t::ACCESS_SHARE_HOST)) {
            lscore += 0x04;
        }

        if (!right->check_flag(connection::flag_t::ACCESS_SHARE_ADDR)) {
            rscore += 0x08;
        }
        if (!right->check_flag(connection::flag_t::ACCESS_SHARE_HOST)) {
            rscore += 0x04;
        }

        return lscore < rscore;
    }

    connection *endpoint::get_ctrl_connection(endpoint *ep) const {
        if (NULL == ep) {
            return NULL;
        }

        if (this == ep) {
            return NULL;
        }

        if (ep->ctrl_conn_ && connection::state_t::CONNECTED == ep->ctrl_conn_->get_status()) {
            return ep->ctrl_conn_.get();
        }

        return NULL;
    }

    connection *endpoint::get_data_connection(endpoint *ep) const { return get_data_connection(ep, true); }

    connection *endpoint::get_data_connection(endpoint *ep, bool enable_fallback_ctrl) const {
        if (NULL == ep) {
            return NULL;
        }

        if (this == ep) {
            return NULL;
        }

        bool share_pid = false, share_host = false;
        if (ep->get_hostname() == get_hostname()) {
            share_host = true;
            if (ep->get_pid() == get_pid()) {
                share_pid = true;
            }
        }

        // 按性能优先级排序mem>shm>fd
        if (false == ep->flags_.test(flag_t::CONNECTION_SORTED)) {
            ep->data_conn_.sort(sort_connection_cmp_fn);
            ep->flags_.set(flag_t::CONNECTION_SORTED, true);
        }

        for (std::list<connection::ptr_t>::iterator iter = ep->data_conn_.begin(); iter != ep->data_conn_.end(); ++iter) {
            if (connection::state_t::CONNECTED != (*iter)->get_status()) {
                continue;
            }

            if (share_pid && (*iter)->check_flag(connection::flag_t::ACCESS_SHARE_ADDR)) {
                return (*iter).get();
            }

            if (share_host && (*iter)->check_flag(connection::flag_t::ACCESS_SHARE_HOST)) {
                return (*iter).get();
            }

            if (!(*iter)->check_flag(connection::flag_t::ACCESS_SHARE_HOST)) {
                return (*iter).get();
            }
        }

        if (enable_fallback_ctrl) {
            return get_ctrl_connection(ep);
        } else {
            return NULL;
        }
    }

    endpoint::stat_t::stat_t() : fault_count(0), unfinished_ping(0), ping_delay(0), last_pong_time(0) {}

    /** 增加错误计数 **/
    size_t endpoint::add_stat_fault() { return ++stat_.fault_count; }

    /** 清空错误计数 **/
    void endpoint::clear_stat_fault() { stat_.fault_count = 0; }

    void endpoint::set_stat_ping(uint32_t p) { stat_.unfinished_ping = p; }

    uint32_t endpoint::get_stat_ping() const { return stat_.unfinished_ping; }

    void endpoint::set_stat_ping_delay(time_t pd, time_t pong_tm) {
        stat_.ping_delay     = pd;
        stat_.last_pong_time = pong_tm;
    }

    time_t endpoint::get_stat_ping_delay() const { return stat_.ping_delay; }

    time_t endpoint::get_stat_last_pong() const { return stat_.last_pong_time; }

    size_t endpoint::get_stat_push_start_times() const {
        size_t ret = 0;
        for (std::list<connection::ptr_t>::const_iterator iter = data_conn_.begin(); iter != data_conn_.end(); ++iter) {
            if (*iter) {
                ret += (*iter)->get_statistic().push_start_times;
            }
        }

        if (ctrl_conn_) {
            ret += ctrl_conn_->get_statistic().push_start_times;
        }

        return ret;
    }

    size_t endpoint::get_stat_push_start_size() const {
        size_t ret = 0;
        for (std::list<connection::ptr_t>::const_iterator iter = data_conn_.begin(); iter != data_conn_.end(); ++iter) {
            if (*iter) {
                ret += (*iter)->get_statistic().push_start_size;
            }
        }

        if (ctrl_conn_) {
            ret += ctrl_conn_->get_statistic().push_start_size;
        }

        return ret;
    }

    size_t endpoint::get_stat_push_success_times() const {
        size_t ret = 0;
        for (std::list<connection::ptr_t>::const_iterator iter = data_conn_.begin(); iter != data_conn_.end(); ++iter) {
            if (*iter) {
                ret += (*iter)->get_statistic().push_success_times;
            }
        }

        if (ctrl_conn_) {
            ret += ctrl_conn_->get_statistic().push_success_times;
        }

        return ret;
    }

    size_t endpoint::get_stat_push_success_size() const {
        size_t ret = 0;
        for (std::list<connection::ptr_t>::const_iterator iter = data_conn_.begin(); iter != data_conn_.end(); ++iter) {
            if (*iter) {
                ret += (*iter)->get_statistic().push_success_size;
            }
        }

        if (ctrl_conn_) {
            ret += ctrl_conn_->get_statistic().push_success_size;
        }

        return ret;
    }

    size_t endpoint::get_stat_push_failed_times() const {
        size_t ret = 0;
        for (std::list<connection::ptr_t>::const_iterator iter = data_conn_.begin(); iter != data_conn_.end(); ++iter) {
            if (*iter) {
                ret += (*iter)->get_statistic().push_failed_times;
            }
        }

        if (ctrl_conn_) {
            ret += ctrl_conn_->get_statistic().push_failed_times;
        }

        return ret;
    }

    size_t endpoint::get_stat_push_failed_size() const {
        size_t ret = 0;
        for (std::list<connection::ptr_t>::const_iterator iter = data_conn_.begin(); iter != data_conn_.end(); ++iter) {
            if (*iter) {
                ret += (*iter)->get_statistic().push_failed_size;
            }
        }

        if (ctrl_conn_) {
            ret += ctrl_conn_->get_statistic().push_failed_size;
        }

        return ret;
    }

    size_t endpoint::get_stat_pull_times() const {
        size_t ret = 0;
        for (std::list<connection::ptr_t>::const_iterator iter = data_conn_.begin(); iter != data_conn_.end(); ++iter) {
            if (*iter) {
                ret += (*iter)->get_statistic().pull_times;
            }
        }

        if (ctrl_conn_) {
            ret += ctrl_conn_->get_statistic().pull_times;
        }

        return ret;
    }

    size_t endpoint::get_stat_pull_size() const {
        size_t ret = 0;
        for (std::list<connection::ptr_t>::const_iterator iter = data_conn_.begin(); iter != data_conn_.end(); ++iter) {
            if (*iter) {
                ret += (*iter)->get_statistic().pull_size;
            }
        }

        if (ctrl_conn_) {
            ret += ctrl_conn_->get_statistic().pull_size;
        }

        return ret;
    }
} // namespace atbus
