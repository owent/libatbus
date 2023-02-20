#include <assert.h>
#include <stdint.h>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>

#include <common/string_oprs.h>

#include "detail/buffer.h"

#include "atbus_endpoint.h"
#include "atbus_node.h"

#include "libatbus_protocol.h"

namespace atbus {
ATBUS_MACRO_API endpoint_subnet_conf::endpoint_subnet_conf() : id_prefix(0), mask_bits(0) {}
ATBUS_MACRO_API endpoint_subnet_conf::endpoint_subnet_conf(ATBUS_MACRO_BUSID_TYPE a, uint32_t b)
    : id_prefix(a), mask_bits(b) {}

ATBUS_MACRO_API endpoint_subnet_range::endpoint_subnet_range() : id_prefix_(0), mask_bits_(0) {
  max_id_ = 0;
  min_id_ = 0;
}

ATBUS_MACRO_API endpoint_subnet_range::endpoint_subnet_range(ATBUS_MACRO_BUSID_TYPE a, uint32_t b)
    : id_prefix_(a), mask_bits_(b) {
  max_id_ = id_prefix_ | ((static_cast<uint64_t>(1) << mask_bits_) - 1);
  min_id_ = max_id_ - ((static_cast<uint64_t>(1) << mask_bits_) - 1);
}

ATBUS_MACRO_API bool endpoint_subnet_range::operator==(const endpoint_subnet_range &other) const {
  return max_id_ == other.max_id_ && min_id_ == other.min_id_;
}

#ifdef __cpp_impl_three_way_comparison
ATBUS_MACRO_API std::strong_ordering endpoint_subnet_range::operator<=>(const endpoint_subnet_range &other) const {
  if (max_id_ != other.max_id_) {
    if (max_id_ < other.max_id_) {
      return std::strong_ordering::less;
    }

    return std::strong_ordering::greater;
  }

  if (min_id_ != other.min_id_) {
    if (min_id_ > other.min_id_) {
      return std::strong_ordering::less;
    }

    return std::strong_ordering::greater;
  }

  return std::strong_ordering::equal;
}
#else

ATBUS_MACRO_API bool endpoint_subnet_range::operator<(const endpoint_subnet_range &other) const {
  if (max_id_ != other.max_id_) {
    return max_id_ < other.max_id_;
  }

  return min_id_ > other.min_id_;
}

ATBUS_MACRO_API bool endpoint_subnet_range::operator<=(const endpoint_subnet_range &other) const {
  if (max_id_ != other.max_id_) {
    return max_id_ < other.max_id_;
  }

  return min_id_ >= other.min_id_;
}

ATBUS_MACRO_API bool endpoint_subnet_range::operator>(const endpoint_subnet_range &other) const {
  if (max_id_ != other.max_id_) {
    return max_id_ > other.max_id_;
  }

  return min_id_ < other.min_id_;
}

ATBUS_MACRO_API bool endpoint_subnet_range::operator>=(const endpoint_subnet_range &other) const {
  if (max_id_ != other.max_id_) {
    return max_id_ > other.max_id_;
  }

  return min_id_ <= other.min_id_;
}

ATBUS_MACRO_API bool endpoint_subnet_range::operator!=(const endpoint_subnet_range &other) const {
  return max_id_ != other.max_id_ || min_id_ != other.min_id_;
}

#endif

ATBUS_MACRO_API bool endpoint_subnet_range::contain(const endpoint_subnet_range &other) const {
  return max_id_ >= other.max_id_ && min_id_ <= other.min_id_;
}

ATBUS_MACRO_API bool endpoint_subnet_range::contain(ATBUS_MACRO_BUSID_TYPE id) const {
  if (0 == id) {
    return false;
  }

  return max_id_ >= id && min_id_ <= id;
}

ATBUS_MACRO_API bool endpoint_subnet_range::contain(ATBUS_MACRO_BUSID_TYPE id_prefix, uint32_t mask_bits,
                                                    ATBUS_MACRO_BUSID_TYPE id) {
  if (0 == id) {
    return false;
  }

  return (id_prefix | ((static_cast<uint64_t>(1) << mask_bits) - 1)) ==
         (id | ((static_cast<uint64_t>(1) << mask_bits) - 1));
}

ATBUS_MACRO_API bool endpoint_subnet_range::contain(const endpoint_subnet_conf &conf, ATBUS_MACRO_BUSID_TYPE id) {
  return contain(conf.id_prefix, conf.mask_bits, id);
}

ATBUS_MACRO_API bool endpoint_subnet_range::lower_bound_by_max_id(const endpoint_subnet_range &l,
                                                                  ATBUS_MACRO_BUSID_TYPE r) {
  /**
   * max_id_相同时，范围大的>范围小的
   * 注意下面这种情况
   * ============****========
   * ========********========
   *    ^      ^   ^   ^
   *    1      3   2   4
   */

  return l.get_id_max() < r;
}

ATBUS_MACRO_API endpoint::ptr_t endpoint::create(node *owner, bus_id_t id,
                                                 const std::vector<endpoint_subnet_conf> &subnets, int32_t pid,
                                                 const std::string &hn) {
  if (nullptr == owner) {
    return endpoint::ptr_t();
  }

  endpoint::ptr_t ret(new endpoint());
  if (!ret) {
    return ret;
  }

  ret->id_ = id;
  ret->pid_ = pid;
  ret->hostname_ = hn;

  ret->owner_ = owner;
  if (node_access_controller::add_ping_timer(*owner, ret, ret->ping_timer_)) {
    ret->set_flag(flag_t::HAS_PING_TIMER, true);
  }
  ret->watcher_ = ret;

  ret->subnets_.reserve(subnets.size() + 1);
  bool auto_add_self_subnet = true;
  for (size_t i = 0; i < subnets.size(); ++i) {
    if (subnets[i].id_prefix == 0) {
      ret->subnets_.push_back(endpoint_subnet_range(id, subnets[i].mask_bits));
      auto_add_self_subnet = false;
    } else {
      ret->subnets_.push_back(endpoint_subnet_range(subnets[i].id_prefix, subnets[i].mask_bits));
      if (endpoint_subnet_range::contain(subnets[i].id_prefix, subnets[i].mask_bits, id)) {
        auto_add_self_subnet = false;
      }
    }
  }
  if (auto_add_self_subnet) {
    ret->subnets_.push_back(endpoint_subnet_range(id, 0));
  }

  merge_subnets(ret->subnets_);

  return ret;
}

endpoint::endpoint() : id_(0), pid_(0), owner_(nullptr) { flags_.reset(); }

ATBUS_MACRO_API endpoint::~endpoint() {
  if (nullptr != owner_) {
    ATBUS_FUNC_NODE_INFO(*owner_, this, nullptr, "endpoint deallocated");
  }

  flags_.set(flag_t::DESTRUCTING, true);

  reset();
}

ATBUS_MACRO_API void endpoint::reset() {
  // 这个函数可能会在析构时被调用，这时候不能使用watcher_.lock()
  if (flags_.test(flag_t::RESETTING)) {
    return;
  }
  flags_.set(flag_t::RESETTING, true);

  // 需要临时给自身加引用计数，否则后续移除的过程中可能导致数据被提前释放
  ptr_t tmp_holder = watch();

  // 释放连接
  if (ctrl_conn_) {
    ctrl_conn_->binding_ = nullptr;
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
  clear_ping_timer();

  // 所有的endpoint的reset行为都要加入到检测和释放列表
  if (nullptr != owner_) {
    owner_->add_endpoint_gc_list(tmp_holder);
  }

  flags_.reset();
  // 只要endpoint存在，则它一定存在于owner_的某个位置。
  // 并且这个值只能在创建时指定，所以不能重置这个值
}

ATBUS_MACRO_API endpoint::bus_id_t endpoint::get_id() const { return id_; }
ATBUS_MACRO_API const std::vector<endpoint_subnet_range> &endpoint::get_subnets() const { return subnets_; }

ATBUS_MACRO_API int32_t endpoint::get_pid() const { return pid_; };
ATBUS_MACRO_API const std::string &endpoint::get_hostname() const { return hostname_; };
ATBUS_MACRO_API const std::string &endpoint::get_hash_code() const { return hash_code_; }
ATBUS_MACRO_API void endpoint::update_hash_code(const std::string &in) {
  if (in.empty()) {
    return;
  }

  hash_code_ = in;
}

ATBUS_MACRO_API bool endpoint::is_child_node(bus_id_t id) const {
  // id_ == 0 means a temporary node, and has no child
  if (0 == id_) {
    return false;
  }

  for (size_t i = 0; i < subnets_.size(); ++i) {
    if (subnets_[i].contain(id)) {
      return true;
    }
  }

  return false;
}

ATBUS_MACRO_API endpoint::bus_id_t endpoint::get_children_min_id(bus_id_t children_prefix, uint32_t mask) {
  bus_id_t maskv = (static_cast<bus_id_t>(1) << mask) - 1;
  return children_prefix & (~maskv);
}

ATBUS_MACRO_API endpoint::bus_id_t endpoint::get_children_max_id(bus_id_t children_prefix, uint32_t mask) {
  bus_id_t maskv = (static_cast<bus_id_t>(1) << mask) - 1;
  return children_prefix | maskv;
}

ATBUS_MACRO_API bool endpoint::is_child_node(bus_id_t parent_id, bus_id_t parent_children_prefix, uint32_t parent_mask,
                                             bus_id_t checked_id) {
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

ATBUS_MACRO_API bool endpoint::add_connection(connection *conn, bool force_data) {
  if (!conn) {
    return false;
  }

  if (flags_.test(flag_t::RESETTING)) {
    return false;
  }

  if (this == conn->binding_) {
    return true;
  }

  if (nullptr != conn->binding_) {
    return false;
  }

  if (force_data || ctrl_conn_) {
    data_conn_.push_back(conn->watch());
    flags_.set(flag_t::CONNECTION_SORTED, false);  // 置为未排序状态
  } else {
    ctrl_conn_ = conn->watch();
  }

  // 已经成功连接可以不需要握手
  conn->binding_ = this;
  if (connection::state_t::HANDSHAKING == conn->get_status()) {
    conn->set_status(connection::state_t::CONNECTED);
  }
  return true;
}

ATBUS_MACRO_API bool endpoint::remove_connection(connection *conn) {
  if (!conn) {
    return false;
  }

  assert(this == conn->binding_);

  // 重置流程会在reset里清理对象，不需要再进行一次查找
  if (flags_.test(flag_t::RESETTING)) {
    conn->binding_ = nullptr;
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
      conn->binding_ = nullptr;
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

ATBUS_MACRO_API bool endpoint::is_available() const {
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

ATBUS_MACRO_API bool endpoint::get_flag(flag_t::type f) const {
  if (f >= flag_t::MAX) {
    return false;
  }

  return flags_.test(f);
}

ATBUS_MACRO_API int endpoint::set_flag(flag_t::type f, bool v) {
  if (f >= flag_t::MAX || f < flag_t::MUTABLE_FLAGS) {
    return EN_ATBUS_ERR_PARAMS;
  }

  flags_.set(f, v);

  return EN_ATBUS_ERR_SUCCESS;
}

ATBUS_MACRO_API uint32_t endpoint::get_flags() const { return static_cast<uint32_t>(flags_.to_ulong()); }

ATBUS_MACRO_API endpoint::ptr_t endpoint::watch() const {
  if (flags_.test(flag_t::DESTRUCTING) || watcher_.expired()) {
    return endpoint::ptr_t();
  }

  return watcher_.lock();
}

ATBUS_MACRO_API const std::list<std::string> &endpoint::get_listen() const { return listen_address_; }

ATBUS_MACRO_API void endpoint::add_listen(const std::string &addr) {
  if (addr.empty()) {
    return;
  }

  if (0 == UTIL_STRFUNC_STRNCASE_CMP("mem:", addr.c_str(), 4) ||
      0 == UTIL_STRFUNC_STRNCASE_CMP("shm:", addr.c_str(), 4)) {
    flags_.set(flag_t::HAS_LISTEN_PORC, true);
  } else {
    flags_.set(flag_t::HAS_LISTEN_FD, true);
  }

  listen_address_.push_back(addr);
}

ATBUS_MACRO_API void endpoint::add_ping_timer() {
  if (nullptr == owner_) {
    return;
  }

  clear_ping_timer();

  if (flags_.test(flag_t::RESETTING)) {
    return;
  }

  if (node_access_controller::add_ping_timer(*owner_, watch(), ping_timer_)) {
    set_flag(flag_t::HAS_PING_TIMER, true);
  }
}

ATBUS_MACRO_API void endpoint::clear_ping_timer() {
  if (nullptr == owner_ || false == get_flag(flag_t::HAS_PING_TIMER)) {
    return;
  }

  node_access_controller::remove_ping_timer(*owner_, ping_timer_);
  set_flag(flag_t::HAS_PING_TIMER, false);
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

ATBUS_MACRO_API connection *endpoint::get_ctrl_connection(endpoint *ep) const {
  if (nullptr == ep) {
    return nullptr;
  }

  if (this == ep) {
    return nullptr;
  }

  if (ep->ctrl_conn_ && connection::state_t::CONNECTED == ep->ctrl_conn_->get_status()) {
    return ep->ctrl_conn_.get();
  }

  return nullptr;
}

ATBUS_MACRO_API connection *endpoint::get_data_connection(endpoint *ep) const { return get_data_connection(ep, true); }

ATBUS_MACRO_API connection *endpoint::get_data_connection(endpoint *ep, bool enable_fallback_ctrl) const {
  if (nullptr == ep) {
    return nullptr;
  }

  if (this == ep) {
    return nullptr;
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
    return nullptr;
  }
}

endpoint::stat_t::stat_t()
    : fault_count(0), unfinished_ping(0), ping_delay(0), last_pong_time(0), created_time_sec(0), created_time_usec(0) {}

/** 增加错误计数 **/
ATBUS_MACRO_API size_t endpoint::add_stat_fault() { return ++stat_.fault_count; }

/** 清空错误计数 **/
ATBUS_MACRO_API void endpoint::clear_stat_fault() { stat_.fault_count = 0; }

ATBUS_MACRO_API void endpoint::set_stat_ping(uint64_t p) { stat_.unfinished_ping = p; }

ATBUS_MACRO_API uint64_t endpoint::get_stat_ping() const { return stat_.unfinished_ping; }

ATBUS_MACRO_API void endpoint::set_stat_ping_delay(time_t pd, time_t pong_tm) {
  stat_.ping_delay = pd;
  stat_.last_pong_time = pong_tm;
}

ATBUS_MACRO_API time_t endpoint::get_stat_ping_delay() const { return stat_.ping_delay; }

ATBUS_MACRO_API time_t endpoint::get_stat_last_pong() const { return stat_.last_pong_time; }

ATBUS_MACRO_API size_t endpoint::get_stat_push_start_times() const {
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

ATBUS_MACRO_API size_t endpoint::get_stat_push_start_size() const {
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

ATBUS_MACRO_API size_t endpoint::get_stat_push_success_times() const {
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

ATBUS_MACRO_API size_t endpoint::get_stat_push_success_size() const {
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

ATBUS_MACRO_API size_t endpoint::get_stat_push_failed_times() const {
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

ATBUS_MACRO_API size_t endpoint::get_stat_push_failed_size() const {
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

ATBUS_MACRO_API size_t endpoint::get_stat_pull_times() const {
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

ATBUS_MACRO_API size_t endpoint::get_stat_pull_size() const {
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

ATBUS_MACRO_API time_t endpoint::get_stat_created_time_sec() {
  UTIL_LIKELY_IF(stat_.created_time_sec > 0) { return stat_.created_time_sec; }

  stat_.created_time_sec = owner_->get_timer_sec();
  stat_.created_time_usec = owner_->get_timer_usec();
  return stat_.created_time_sec;
}

ATBUS_MACRO_API time_t endpoint::get_stat_created_time_usec() {
  UTIL_LIKELY_IF(stat_.created_time_sec > 0) { return stat_.created_time_usec; }

  stat_.created_time_sec = owner_->get_timer_sec();
  stat_.created_time_usec = owner_->get_timer_usec();
  return stat_.created_time_usec;
}

ATBUS_MACRO_API const node *endpoint::get_owner() const { return owner_; }

ATBUS_MACRO_API void endpoint::merge_subnets(std::vector<endpoint_subnet_range> &subnets) {
  if (subnets.size() <= 1) {
    return;
  }

  std::sort(subnets.begin(), subnets.end());

  size_t new_size = 1;
  size_t old_index = 1;

  for (; old_index < subnets.size(); ++old_index) {
    assert(new_size >= 1);
    assert(old_index >= new_size);

    /**
     * PREV: ========****============
     * NEXT: ========********========
     * Just replace previous
     */
    if (subnets[old_index].get_id_min() <= subnets[new_size - 1].get_id_min()) {
      subnets[new_size - 1] = subnets[old_index];
    } else {
      /**
       * PREV: ====****================
       * NEXT: ============****========
       * OR
       * PREV: ======****==============
       * NEXT: ==========****==========
       */
      if (new_size != old_index) {
        subnets[new_size] = subnets[old_index];
      }
      ++new_size;
    }

    /**
     * PREV: ======****==============
     * NEXT: ==========****==========
     * TO
     * PREV: ======********==========
     */
    bool check_merge = true;
    while (check_merge && new_size > 1) {
      check_merge = false;
      if (subnets[new_size - 1].get_mask_bits() == subnets[new_size - 2].get_mask_bits() &&
          subnets[new_size - 1].get_id_min() == subnets[new_size - 2].get_id_max() + 1) {
        endpoint_subnet_range up(subnets[new_size - 2].get_id_min(), subnets[new_size - 2].get_mask_bits() + 1);
        if (up.get_id_max() == subnets[new_size - 1].get_id_max() &&
            up.get_id_min() == subnets[new_size - 2].get_id_min()) {
          subnets[new_size - 2] = up;
          --new_size;
          check_merge = true;
        }
      }
    }
  }

  if (new_size != subnets.size()) {
    subnets.resize(new_size);
  }
}

ATBUS_MACRO_API std::vector<endpoint_subnet_range>::const_iterator endpoint::search_subnet_for_id(
    const std::vector<endpoint_subnet_range> &subnets, bus_id_t id) {
  std::vector<endpoint_subnet_range>::const_iterator iter = subnets.begin();
  // 初始也可以用下面的二分查找，但是没什么意义。最终还是要while循环判到底,因为后面如果有范围更大的max_id然后覆盖到id的
  // iter = std::lower_bound(subnets.begin(), subnets.end(), id, endpoint_subnet_range::lower_bound_by_max_id);

  while (iter != subnets.end()) {
    if ((*iter).contain(id)) {
      break;
    }

    ++iter;
  }

  return iter;
}

ATBUS_MACRO_API bool endpoint::contain(const std::vector<endpoint_subnet_range> &parent_subnets,
                                       const std::vector<endpoint_subnet_range> &child_subnets) {
  if (parent_subnets.empty() && !child_subnets.empty()) {
    return false;
  }

  for (size_t i = 0; i < child_subnets.size(); ++i) {
    bool check_passed = false;
    for (size_t j = 0; !check_passed && j < parent_subnets.size(); ++j) {
      if (parent_subnets[j].contain(child_subnets[i].get_id_min()) &&
          parent_subnets[j].contain(child_subnets[i].get_id_max())) {
        check_passed = true;
      }
    }

    if (!check_passed) {
      return false;
    }
  }

  return true;
}

ATBUS_MACRO_API bool endpoint::contain(const std::vector<endpoint_subnet_range> &parent_subnets,
                                       const std::vector<endpoint_subnet_conf> &child_subnets) {
  if (parent_subnets.empty() && !child_subnets.empty()) {
    return false;
  }

  for (size_t i = 0; i < child_subnets.size(); ++i) {
    bool check_passed = false;
    for (size_t j = 0; !check_passed && j < parent_subnets.size(); ++j) {
      if (parent_subnets[j].contain(child_subnets[i].id_prefix) &&
          parent_subnets[j].get_mask_bits() >= child_subnets[i].mask_bits) {
        check_passed = true;
      }
    }

    if (!check_passed) {
      return false;
    }
  }

  return true;
}

ATBUS_MACRO_API bool endpoint::contain(const std::vector<endpoint_subnet_range> &parent_subnets, bus_id_t id) {
  if (parent_subnets.empty() || 0 == id) {
    return false;
  }

  for (size_t i = 0; i < parent_subnets.size(); ++i) {
    if (parent_subnets[i].contain(id)) {
      return true;
    }
  }

  return false;
}

ATBUS_MACRO_API bool endpoint::contain(const std::vector<endpoint_subnet_conf> &parent_subnets, bus_id_t id) {
  if (parent_subnets.empty() || 0 == id) {
    return false;
  }

  for (size_t i = 0; i < parent_subnets.size(); ++i) {
    if (endpoint_subnet_range::contain(parent_subnets[i], id)) {
      return true;
    }
  }

  return false;
}
}  // namespace atbus
