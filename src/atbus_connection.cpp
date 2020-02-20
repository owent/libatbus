#include <assert.h>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <stdint.h>


#include <common/file_system.h>
#include <common/string_oprs.h>


#include "detail/buffer.h"

#include "atbus_connection.h"
#include "atbus_node.h"

#include "libatbus_protocol.h"

namespace atbus {
    namespace detail {
        struct connection_async_data {
            node *owner_node;
            connection::ptr_t conn;

            connection_async_data(node *o) : owner_node(o) {
                assert(owner_node);
                if (NULL != owner_node) {
                    owner_node->ref_object(reinterpret_cast<void *>(this));
                }
            }

            ~connection_async_data() { owner_node->unref_object(reinterpret_cast<void *>(this)); }

            connection_async_data(const connection_async_data &other) : owner_node(other.owner_node), conn(other.conn) {
                assert(owner_node);

                if (NULL != owner_node) {
                    owner_node->ref_object(reinterpret_cast<void *>(this));
                }
            }

            connection_async_data &operator=(const connection_async_data &other) {
                assert(owner_node);
                assert(other.owner_node);

                if (NULL == owner_node || NULL == other.owner_node) {
                    return *this;
                }

                if (owner_node != other.owner_node) {
                    owner_node->unref_object(reinterpret_cast<void *>(this));
                    other.owner_node->ref_object(reinterpret_cast<void *>(this));

                    owner_node = other.owner_node;
                }

                conn = other.conn;

                return *this;
            }
        };
    } // namespace detail

    connection::connection() : state_(state_t::DISCONNECTED), owner_(NULL), binding_(NULL) {
        flags_.reset();
        memset(&conn_data_, 0, sizeof(conn_data_));
        memset(&stat_, 0, sizeof(stat_));
    }

    connection::ptr_t connection::create(node *owner) {
        if (!owner) {
            return connection::ptr_t();
        }

        connection::ptr_t ret(new connection());
        if (!ret) {
            return ret;
        }

        ret->owner_   = owner;
        ret->watcher_ = ret;

        owner->add_connection_timer(ret, ret->owner_checker_);
        return ret;
    }

    connection::~connection() {
        flags_.set(flag_t::DESTRUCTING, true);

        if (NULL != owner_) {
            ATBUS_FUNC_NODE_DEBUG(*owner_, get_binding(), this, NULL, "connection delocated");
        }

        reset();
    }

    void connection::reset() {
        // 这个函数可能会在析构时被调用，这时候不能使用watcher_.lock()
        if (flags_.test(flag_t::RESETTING)) {
            return;
        }
        flags_.set(flag_t::RESETTING, true);

        // 需要临时给自身加引用计数，否则后续移除的过程中可能导致数据被提前释放
        ptr_t tmp_holder = watcher_.lock();

        // 后面会重置状态，影响事件判定，所以要先移除检查队列
        owner_->remove_connection_timer(owner_checker_);

        disconnect();

        if (NULL != binding_) {
            binding_->remove_connection(this);

            // 只能由上层设置binding_所属的节点
            // binding_ = NULL;
            assert(NULL == binding_);
        }

        flags_.reset();
        // 只要connection存在，则它一定存在于owner_的某个位置。
        // 并且这个值只能在创建时指定，所以不能重置这个值
        // owner_ = NULL;

        // reset statistics
        memset(&stat_, 0, sizeof(stat_));
    }

    int connection::proc(node &n, time_t sec, time_t usec) {
        if (state_t::CONNECTED != state_) {
            return 0;
        }

        if (NULL != conn_data_.proc_fn) {
            return conn_data_.proc_fn(n, *this, sec, usec);
        }

        return 0;
    }

    int connection::listen(const char *addr_str) {
        if (state_t::DISCONNECTED != state_) {
            return EN_ATBUS_ERR_ALREADY_INITED;
        }

        if (NULL == owner_) {
            return EN_ATBUS_ERR_NOT_INITED;
        }
        const node::conf_t &conf = owner_->get_conf();

        if (false == channel::make_address(addr_str, address_)) {
            return EN_ATBUS_ERR_CHANNEL_ADDR_INVALID;
        }

        if (0 == UTIL_STRFUNC_STRNCASE_CMP("mem", address_.scheme.c_str(), 3)) {
            channel::mem_channel *mem_chann = NULL;
            intptr_t ad;
            util::string::str2int(ad, address_.host.c_str());
            int res = channel::mem_attach(reinterpret_cast<void *>(ad), conf.recv_buffer_size, &mem_chann, NULL);
            if (res < 0) {
                res = channel::mem_init(reinterpret_cast<void *>(ad), conf.recv_buffer_size, &mem_chann, NULL);
            }

            if (res < 0) {
                ATBUS_FUNC_NODE_ERROR(*owner_, get_binding(), this, res, 0);
                return res;
            }

            conn_data_.proc_fn = mem_proc_fn;
            conn_data_.free_fn = mem_free_fn;

            // 加入轮询队列
            conn_data_.shared.mem.channel = mem_chann;
            conn_data_.shared.mem.buffer  = reinterpret_cast<void *>(ad);
            conn_data_.shared.mem.len     = conf.recv_buffer_size;
            owner_->add_proc_connection(watcher_.lock());
            flags_.set(flag_t::REG_PROC, true);
            flags_.set(flag_t::ACCESS_SHARE_ADDR, true);
            flags_.set(flag_t::ACCESS_SHARE_HOST, true);
            set_status(state_t::CONNECTED);
            ATBUS_FUNC_NODE_DEBUG(*owner_, get_binding(), this, NULL, "channel connected(listen)");

            owner_->on_new_connection(this);
            return res;
        } else if (0 == UTIL_STRFUNC_STRNCASE_CMP("shm", address_.scheme.c_str(), 3)) {
#ifdef ATBUS_CHANNEL_SHM
            channel::shm_channel *shm_chann = NULL;
            int res = channel::shm_attach(address_.host.c_str(), conf.recv_buffer_size, &shm_chann, NULL);
            if (res < 0) {
                res = channel::shm_init(address_.host.c_str(), conf.recv_buffer_size, &shm_chann, NULL);
            }

            if (res < 0) {
                ATBUS_FUNC_NODE_ERROR(*owner_, get_binding(), this, res, 0);
                return res;
            }

            conn_data_.proc_fn = shm_proc_fn;
            conn_data_.free_fn = shm_free_fn;

            // 加入轮询队列
            conn_data_.shared.shm.channel = shm_chann;
            conn_data_.shared.shm.len     = conf.recv_buffer_size;
            owner_->add_proc_connection(watcher_.lock());
            flags_.set(flag_t::REG_PROC, true);
            flags_.set(flag_t::ACCESS_SHARE_HOST, true);
            set_status(state_t::CONNECTED);
            ATBUS_FUNC_NODE_DEBUG(*owner_, get_binding(), this, NULL, "channel connected(listen)");

            owner_->on_new_connection(this);
            return res;
#else
            return EN_ATBUS_ERR_CHANNEL_NOT_SUPPORT;
#endif
        } else {
            // Unix sock的listen的地址应该转为绝对地址，方便跨组连接时可以不依赖相对目录
            // Unix sock也必须共享Host
            if (0 == UTIL_STRFUNC_STRNCASE_CMP("unix", address_.scheme.c_str(), 4)) {
                if (false == util::file_system::is_abs_path(address_.host.c_str())) {
                    std::string abs_host_path = util::file_system::get_abs_path(address_.host.c_str());
                    size_t max_addr_size      = ::atbus::channel::io_stream_get_max_unix_socket_length();
                    if (max_addr_size > 0 && abs_host_path.size() <= max_addr_size) {
                        address_.host = abs_host_path;
                    }
                }

                flags_.set(flag_t::ACCESS_SHARE_HOST, true);
            }

            if (util::file_system::is_exist(address_.host.c_str())) {
                if (false == util::file_system::remove(address_.host.c_str())) {
                    ATBUS_FUNC_NODE_ERROR(*owner_, get_binding(), this, EN_ATBUS_ERR_PIPE_REMOVE_FAILED, 0);
                }
            }

            detail::connection_async_data *async_data = new detail::connection_async_data(owner_);
            if (NULL == async_data) {
                ATBUS_FUNC_NODE_ERROR(*owner_, get_binding(), this, EN_ATBUS_ERR_MALLOC, 0);
                return EN_ATBUS_ERR_MALLOC;
            }
            connection::ptr_t self = watcher_.lock();
            async_data->conn       = self;

            set_status(state_t::CONNECTING);
            int res = channel::io_stream_listen(owner_->get_iostream_channel(), address_, iostream_on_listen_cb, async_data, 0);
            if (res < 0) {
                ATBUS_FUNC_NODE_ERROR(*owner_, get_binding(), this, res, owner_->get_iostream_channel()->error_code);
                delete async_data;
            }

            return res;
        }
    }

    int connection::connect(const char *addr_str) {
        if (state_t::DISCONNECTED != state_) {
            return EN_ATBUS_ERR_ALREADY_INITED;
        }

        if (NULL == owner_) {
            return EN_ATBUS_ERR_NOT_INITED;
        }
        const node::conf_t &conf = owner_->get_conf();

        if (false == channel::make_address(addr_str, address_)) {
            return EN_ATBUS_ERR_CHANNEL_ADDR_INVALID;
        }

        if (0 == UTIL_STRFUNC_STRNCASE_CMP("mem", address_.scheme.c_str(), 3)) {
            channel::mem_channel *mem_chann = NULL;
            intptr_t ad;
            util::string::str2int(ad, address_.host.c_str());
            int res = channel::mem_attach(reinterpret_cast<void *>(ad), conf.recv_buffer_size, &mem_chann, NULL);
            if (res < 0) {
                res = channel::mem_init(reinterpret_cast<void *>(ad), conf.recv_buffer_size, &mem_chann, NULL);
            }

            if (res < 0) {
                ATBUS_FUNC_NODE_ERROR(*owner_, get_binding(), this, res, 0);
                return res;
            }

            // conn_data_.proc_fn = mem_proc_fn;
            conn_data_.proc_fn = NULL;
            conn_data_.free_fn = mem_free_fn;
            conn_data_.push_fn = mem_push_fn;

            // 连接信息
            conn_data_.shared.mem.channel = mem_chann;
            conn_data_.shared.mem.buffer  = reinterpret_cast<void *>(ad);
            conn_data_.shared.mem.len     = conf.recv_buffer_size;
            // 仅在listen时要设置proc,否则同机器的同名通道离线会导致proc中断
            // flags_.set(flag_t::REG_PROC, true);
            flags_.set(flag_t::ACCESS_SHARE_ADDR, true);
            flags_.set(flag_t::ACCESS_SHARE_HOST, true);

            if (NULL == binding_) {
                set_status(state_t::HANDSHAKING);
                ATBUS_FUNC_NODE_DEBUG(*owner_, binding_, this, NULL, "channel handshaking(connect)");
            } else {
                set_status(state_t::CONNECTED);
                ATBUS_FUNC_NODE_DEBUG(*owner_, binding_, this, NULL, "channel connected(connect)");
            }

            owner_->on_new_connection(this);
            return res;
        } else if (0 == UTIL_STRFUNC_STRNCASE_CMP("shm", address_.scheme.c_str(), 3)) {
#ifdef ATBUS_CHANNEL_SHM
            channel::shm_channel *shm_chann = NULL;
            int res = channel::shm_attach(address_.host.c_str(), conf.recv_buffer_size, &shm_chann, NULL);
            if (res < 0) {
                res = channel::shm_init(address_.host.c_str(), conf.recv_buffer_size, &shm_chann, NULL);
            }

            if (res < 0) {
                ATBUS_FUNC_NODE_ERROR(*owner_, get_binding(), this, res, 0);
                return res;
            }

            // conn_data_.proc_fn = shm_proc_fn;
            conn_data_.proc_fn = NULL;
            conn_data_.free_fn = shm_free_fn;
            conn_data_.push_fn = shm_push_fn;

            // 连接信息
            conn_data_.shared.shm.channel = shm_chann;
            conn_data_.shared.shm.len     = conf.recv_buffer_size;

            // 仅在listen时要设置proc,否则同机器的同名通道离线会导致proc中断
            // flags_.set(flag_t::REG_PROC, true);
            flags_.set(flag_t::ACCESS_SHARE_HOST, true);

            if (NULL == binding_) {
                set_status(state_t::HANDSHAKING);
                ATBUS_FUNC_NODE_DEBUG(*owner_, binding_, this, NULL, "channel handshaking(connect)");
            } else {
                set_status(state_t::CONNECTED);
                ATBUS_FUNC_NODE_DEBUG(*owner_, binding_, this, NULL, "channel connected(connect)");
            }

            owner_->on_new_connection(this);
            return res;
#else
            return EN_ATBUS_ERR_CHANNEL_NOT_SUPPORT;
#endif
        } else {
            // redirect loopback address to local address
            if (0 == UTIL_STRFUNC_STRNCASE_CMP("ipv4", address_.scheme.c_str(), 4) && "0.0.0.0" == address_.host) {
                make_address("ipv4", "127.0.0.1", address_.port, address_);
            } else if (0 == UTIL_STRFUNC_STRNCASE_CMP("ipv6", address_.scheme.c_str(), 4) && "::" == address_.host) {
                make_address("ipv6", "::1", address_.port, address_);
            } else if (0 == UTIL_STRFUNC_STRNCASE_CMP("unix", address_.scheme.c_str(), 4)) {
                flags_.set(flag_t::ACCESS_SHARE_HOST, true);
            }

            detail::connection_async_data *async_data = new detail::connection_async_data(owner_);
            if (NULL == async_data) {
                ATBUS_FUNC_NODE_ERROR(*owner_, get_binding(), this, EN_ATBUS_ERR_MALLOC, 0);
                return EN_ATBUS_ERR_MALLOC;
            }
            connection::ptr_t self = watcher_.lock();
            async_data->conn       = self;

            set_status(state_t::CONNECTING);
            int res = channel::io_stream_connect(owner_->get_iostream_channel(), address_, iostream_on_connected_cb, async_data, 0);
            if (res < 0) {
                ATBUS_FUNC_NODE_ERROR(*owner_, get_binding(), this, res, owner_->get_iostream_channel()->error_code);
                delete async_data;
            }

            return res;
        }
    }

    int connection::disconnect() {
        if (state_t::DISCONNECTED == state_) {
            return EN_ATBUS_ERR_NOT_INITED;
        }

        if (state_t::DISCONNECTING == state_) {
            return EN_ATBUS_ERR_SUCCESS;
        }

        set_status(state_t::DISCONNECTING);
        if (NULL != conn_data_.free_fn) {
            if (NULL != owner_) {
                int res = conn_data_.free_fn(*owner_, *this);
                if (res < 0) {
                    ATBUS_FUNC_NODE_DEBUG(*owner_, get_binding(), this, NULL, "destroy connection failed, res: %d", res);
                }
            }
        }

        if (NULL != owner_) {
            ATBUS_FUNC_NODE_DEBUG(*owner_, get_binding(), this, NULL, "connection disconnected");
            owner_->on_disconnect(this);
        }

        // 移除proc队列
        if (flags_.test(flag_t::REG_PROC)) {
            if (NULL != owner_) {
                owner_->remove_proc_connection(address_.address);
            }
            flags_.set(flag_t::REG_PROC, false);
        }

        memset(&conn_data_, 0, sizeof(conn_data_));
        set_status(state_t::DISCONNECTED);
        return EN_ATBUS_ERR_SUCCESS;
    }

    int connection::push(const void *buffer, size_t s) {
        ++stat_.push_start_times;
        stat_.push_start_size += s;

        if (state_t::CONNECTED != state_ && state_t::HANDSHAKING != state_) {
            ++stat_.push_failed_times;
            stat_.push_failed_size += s;

            return EN_ATBUS_ERR_NOT_INITED;
        }

        if (NULL == conn_data_.push_fn) {
            ++stat_.push_failed_times;
            stat_.push_failed_size += s;

            return EN_ATBUS_ERR_ACCESS_DENY;
        }

        return conn_data_.push_fn(*this, buffer, s);
    }

    /** 增加错误计数 **/
    size_t connection::add_stat_fault() { return ++stat_.fault_count; }

    /** 清空错误计数 **/
    void connection::clear_stat_fault() { stat_.fault_count = 0; }

    bool connection::is_connected() const { return state_t::CONNECTED == state_; }

    endpoint *connection::get_binding() { return binding_; }

    const endpoint *connection::get_binding() const { return binding_; }

    connection::ptr_t connection::watch() const {
        if (flags_.test(flag_t::DESTRUCTING) || watcher_.expired()) {
            return connection::ptr_t();
        }

        return watcher_.lock();
    }


    /** 是否正在连接、或者握手或者已连接 **/
    bool connection::is_running() const {
        return state_t::CONNECTING == state_ || state_t::HANDSHAKING == state_ || state_t::CONNECTED == state_;
    }

    void connection::remove_owner_checker(const timer_desc_ls<ptr_t>::type::iterator& v) {
        if (owner_checker_ != v) {
            return;
        }

        if (NULL != owner_) {
            owner_->remove_connection_timer(owner_checker_);
        }
    }

    void connection::set_status(state_t::type v) {
        if (state_ == v) {
            return;
        }

        state_ = v;

        if (NULL != owner_ && v == state_t::CONNECTED) {
            owner_->remove_connection_timer(owner_checker_);
        }
    }

    void connection::iostream_on_listen_cb(channel::io_stream_channel *channel, channel::io_stream_connection *connection, int status,
                                           void *buffer, size_t) {
        detail::connection_async_data *async_data = reinterpret_cast<detail::connection_async_data *>(buffer);
        assert(NULL != async_data);
        if (NULL == async_data) {
            return;
        }

        if (status < 0) {
            ATBUS_FUNC_NODE_ERROR(*async_data->owner_node, async_data->conn->binding_, async_data->conn.get(), status, channel->error_code);
            async_data->conn->set_status(state_t::DISCONNECTED);
            ATBUS_FUNC_NODE_DEBUG(*async_data->conn->owner_, async_data->conn->binding_, async_data->conn.get(), NULL,
                                  "channel disconnected(listen callback)");

        } else {
            async_data->conn->flags_.set(flag_t::REG_FD, true);
            async_data->conn->flags_.set(flag_t::LISTEN_FD, true);
            async_data->conn->set_status(state_t::CONNECTED);
            ATBUS_FUNC_NODE_DEBUG(*async_data->conn->owner_, async_data->conn->binding_, async_data->conn.get(), NULL,
                                  "channel connected(listen callback)");

            async_data->conn->conn_data_.shared.ios_fd.channel = channel;
            async_data->conn->conn_data_.shared.ios_fd.conn    = connection;
            async_data->conn->conn_data_.free_fn               = ios_free_fn;
            connection->data                                   = async_data->conn.get();

            async_data->owner_node->on_new_connection(async_data->conn.get());
        }

        delete async_data;
    }

    void connection::iostream_on_connected_cb(channel::io_stream_channel *channel, channel::io_stream_connection *connection, int status,
                                              void *buffer, size_t) {
        detail::connection_async_data *async_data = reinterpret_cast<detail::connection_async_data *>(buffer);
        assert(NULL != async_data);
        if (NULL == async_data) {
            return;
        }

        if (status < 0) {
            ATBUS_FUNC_NODE_ERROR(*async_data->owner_node, async_data->conn->binding_, async_data->conn.get(), status, channel->error_code);
            // 连接失败，重置连接
            async_data->conn->reset();

        } else {
            async_data->conn->flags_.set(flag_t::REG_FD, true);
            if (NULL == async_data->conn->binding_) {
                async_data->conn->set_status(state_t::HANDSHAKING);
                ATBUS_FUNC_NODE_DEBUG(*async_data->conn->owner_, async_data->conn->binding_, async_data->conn.get(), NULL,
                                      "channel handshaking(connect callback)");
            } else {
                async_data->conn->set_status(state_t::CONNECTED);
                ATBUS_FUNC_NODE_DEBUG(*async_data->conn->owner_, async_data->conn->binding_, async_data->conn.get(), NULL,
                                      "channel connected(connect callback)");
            }

            async_data->conn->conn_data_.shared.ios_fd.channel = channel;
            async_data->conn->conn_data_.shared.ios_fd.conn    = connection;

            async_data->conn->conn_data_.free_fn = ios_free_fn;
            async_data->conn->conn_data_.push_fn = ios_push_fn;
            connection->data                     = async_data->conn.get();

            async_data->owner_node->on_new_connection(async_data->conn.get());
        }

        delete async_data;
    }

    void connection::iostream_on_recv_cb(channel::io_stream_channel *channel, channel::io_stream_connection *conn_ios, int status,
                                         void *buffer, size_t s) {

        assert(channel && channel->data);
        if (NULL == channel || NULL == channel->data) {
            return;
        }

        node *_this = reinterpret_cast<node *>(channel->data);

        assert(_this);
        if (NULL == _this) {
            return;
        }
        connection *conn = reinterpret_cast<connection *>(conn_ios->data);

        if (status < 0 || NULL == buffer || s <= 0) {
            ::atbus::protocol::msg m;
            _this->on_recv(conn, ATBUS_MACRO_MOVE(m), status, channel->error_code);
            return;
        }

        // connection 已经释放并解除绑定，这时候会先把剩下未处理的消息处理完再关闭
        if (NULL == conn) {
            // ATBUS_FUNC_NODE_ERROR(*_this, NULL, conn, EN_ATBUS_ERR_UNPACK, EN_ATBUS_ERR_PARAMS);
            return;
        }

        // statistic
        ++conn->stat_.pull_times;
        conn->stat_.pull_size += s;

        // unpack
        std::vector<unsigned char> msg_buffer;
        msg_buffer.assign(static_cast<const unsigned char *>(buffer), static_cast<const unsigned char *>(buffer) + s);
        protocol::msg *m;
        ::ATBUS_MACRO_PROTOBUF_NAMESPACE_ID::ArenaOptions arena_options;
        arena_options.initial_block_size = ATBUS_MACRO_RESERVED_SIZE;
        ::ATBUS_MACRO_PROTOBUF_NAMESPACE_ID::Arena arena(arena_options);

        if (false == unpack(*conn, m, arena, msg_buffer)) {
            return;
        }

        assert(m);

        if (NULL != _this) {
            _this->on_recv(conn, ATBUS_MACRO_MOVE(*m), status, channel->error_code);
        }
    }

    void connection::iostream_on_accepted(channel::io_stream_channel *channel, channel::io_stream_connection *conn_ios, int /*status*/,
                                          void * /*buffer*/, size_t) {
        // 连接成功加入点对点传输池
        // 加入超时检测
        node *n = reinterpret_cast<node *>(channel->data);
        assert(NULL != n);
        if (NULL == n) {
            channel::io_stream_disconnect(channel, conn_ios, NULL);
            return;
        }

        // 超过最大排队数
        if (n->get_conf().backlog <= n->get_connection_timer_size()) {
            channel::io_stream_disconnect(channel, conn_ios, NULL);
            return;
        }

        ptr_t conn   = create(n);
        conn->set_status(state_t::HANDSHAKING);
        conn->flags_.set(flag_t::REG_FD, true);

        conn->conn_data_.free_fn = ios_free_fn;
        conn->conn_data_.push_fn = ios_push_fn;

        conn->conn_data_.shared.ios_fd.channel = channel;
        conn->conn_data_.shared.ios_fd.conn    = conn_ios;
        conn_ios->data                         = conn.get();

        // copy address
        conn->address_ = conn_ios->addr;


        ATBUS_FUNC_NODE_DEBUG(*n, NULL, conn.get(), NULL, "connection accepted");
        n->on_new_connection(conn.get());
    }

    void connection::iostream_on_connected(channel::io_stream_channel *, channel::io_stream_connection *, int /*status*/, void * /*buffer*/,
                                           size_t) {}

    void connection::iostream_on_disconnected(channel::io_stream_channel *, channel::io_stream_connection *conn_ios, int /*status*/,
                                              void * /*buffer*/, size_t) {
        connection *conn = reinterpret_cast<connection *>(conn_ios->data);

        // 主动关闭时会先释放connection，这时候connection已经被释放，不需要再重置
        if (NULL == conn) {
            return;
        }

        ATBUS_FUNC_NODE_DEBUG(*conn->owner_, conn->get_binding(), conn, NULL, "connection reset by peer");
        conn->reset();
    }

    void connection::iostream_on_written(channel::io_stream_channel *channel, channel::io_stream_connection *conn_ios, int status,
                                         void * /*buffer*/, size_t s) {
        node *n = reinterpret_cast<node *>(channel->data);
        assert(NULL != n);
        if (NULL == n) {
            return;
        }
        connection *conn = reinterpret_cast<connection *>(conn_ios->data);

        if (EN_ATBUS_ERR_SUCCESS != status) {
            if (NULL != conn) {
                ++conn->stat_.push_failed_times;
                conn->stat_.push_failed_size += s;

                ATBUS_FUNC_NODE_DEBUG(*n, conn->get_binding(), conn, NULL, "write data to %p failed, err=%d, status=%d", conn_ios,
                                      channel->error_code, status);
            } else {
                ATBUS_FUNC_NODE_DEBUG(*n, NULL, conn, NULL, "write data to %p failed, err=%d, status=%d", conn_ios, channel->error_code,
                                      status);
            }

            ATBUS_FUNC_NODE_ERROR(*n, NULL, conn, status, channel->error_code);
        } else {
            if (NULL != conn) {
                ++conn->stat_.push_success_times;
                conn->stat_.push_success_size += s;

                ATBUS_FUNC_NODE_DEBUG(*n, conn->get_binding(), conn, NULL, "write data to %p success", conn_ios);
            } else {
                ATBUS_FUNC_NODE_DEBUG(*n, NULL, conn, NULL, "write data to %p success", conn_ios);
            }
        }
    }

#ifdef ATBUS_CHANNEL_SHM
    int connection::shm_proc_fn(node &n, connection &conn, time_t /*sec*/, time_t /*usec*/) {
        int ret                             = 0;
        size_t left_times                   = n.get_conf().loop_times;
        detail::buffer_block *static_buffer = n.get_temp_static_buffer();
        if (NULL == static_buffer) {
            return ATBUS_FUNC_NODE_ERROR(n, NULL, &conn, EN_ATBUS_ERR_NOT_INITED, 0);
        }

        while (left_times-- > 0) {
            size_t recv_len;
            int res = channel::shm_recv(conn.conn_data_.shared.shm.channel, static_buffer->data(), static_buffer->size(), &recv_len);

            if (EN_ATBUS_ERR_NO_DATA == res) {
                break;
            }

            // 回调收到数据事件
            if (res < 0) {
                ret = res;
                ::atbus::protocol::msg m;
                n.on_recv(&conn, ATBUS_MACRO_MOVE(m), res, res);
                break;
            } else {
                // statistic
                ++conn.stat_.pull_times;
                conn.stat_.pull_size += recv_len;

                // unpack
                std::vector<unsigned char> msg_buffer;
                msg_buffer.assign(static_cast<const unsigned char *>(static_buffer->data()),
                                  static_cast<const unsigned char *>(static_buffer->data()) + recv_len);
                protocol::msg *m;
                ::ATBUS_MACRO_PROTOBUF_NAMESPACE_ID::ArenaOptions arena_options;
                arena_options.initial_block_size = ATBUS_MACRO_RESERVED_SIZE;
                ::ATBUS_MACRO_PROTOBUF_NAMESPACE_ID::Arena arena(arena_options);
                if (false == unpack(conn, m, arena, msg_buffer)) {
                    continue;
                }

                assert(m);

                n.on_recv(&conn, ATBUS_MACRO_MOVE(*m), res, res);
                ++ret;
            }
        }

        return ret;
    }

    int connection::shm_free_fn(node &, connection &conn) { return channel::shm_close(conn.get_address().host.c_str()); }

    int connection::shm_push_fn(connection &conn, const void *buffer, size_t s) {
        int ret = channel::shm_send(conn.conn_data_.shared.shm.channel, buffer, s);
        if (ret >= 0) {
            ++conn.stat_.push_success_times;
            conn.stat_.push_success_size += s;
        } else {
            ++conn.stat_.push_failed_times;
            conn.stat_.push_failed_size += s;
        }

        return ret;
    }
#endif

    int connection::mem_proc_fn(node &n, connection &conn, time_t /*sec*/, time_t /*usec*/) {
        int ret                             = 0;
        size_t left_times                   = n.get_conf().loop_times;
        detail::buffer_block *static_buffer = n.get_temp_static_buffer();
        if (NULL == static_buffer) {
            return ATBUS_FUNC_NODE_ERROR(n, NULL, &conn, EN_ATBUS_ERR_NOT_INITED, 0);
        }

        while (left_times-- > 0) {
            size_t recv_len;
            int res = channel::mem_recv(conn.conn_data_.shared.mem.channel, static_buffer->data(), static_buffer->size(), &recv_len);

            if (EN_ATBUS_ERR_NO_DATA == res) {
                break;
            }

            // 回调收到数据事件
            if (res < 0) {
                ret = res;
                ::atbus::protocol::msg m;
                n.on_recv(&conn, ATBUS_MACRO_MOVE(m), res, res);
                break;
            } else {
                // statistic
                ++conn.stat_.pull_times;
                conn.stat_.pull_size += recv_len;

                // unpack
                std::vector<unsigned char> msg_buffer;
                msg_buffer.assign(static_cast<const unsigned char *>(static_buffer->data()),
                                  static_cast<const unsigned char *>(static_buffer->data()) + recv_len);
                protocol::msg *m;
                ::ATBUS_MACRO_PROTOBUF_NAMESPACE_ID::ArenaOptions arena_options;
                arena_options.initial_block_size = ATBUS_MACRO_RESERVED_SIZE;
                ::ATBUS_MACRO_PROTOBUF_NAMESPACE_ID::Arena arena(arena_options);
                if (false == unpack(conn, m, arena, msg_buffer)) {
                    continue;
                }

                assert(m);
                n.on_recv(&conn, ATBUS_MACRO_MOVE(*m), res, res);
                ++ret;
            }
        }

        return ret;
    }

    int connection::mem_free_fn(node &, connection &) { return 0; }

    int connection::mem_push_fn(connection &conn, const void *buffer, size_t s) {
        int ret = channel::mem_send(conn.conn_data_.shared.mem.channel, buffer, s);
        if (ret >= 0) {
            ++conn.stat_.push_success_times;
            conn.stat_.push_success_size += s;
        } else {
            ++conn.stat_.push_failed_times;
            conn.stat_.push_failed_size += s;
        }
        return ret;
    }

    int connection::ios_free_fn(node &, connection &conn) {
        int ret = channel::io_stream_disconnect(conn.conn_data_.shared.ios_fd.channel, conn.conn_data_.shared.ios_fd.conn, NULL);
        // 释放后移除关联关系
        conn.conn_data_.shared.ios_fd.conn->data = NULL;

        return ret;
    }

    int connection::ios_push_fn(connection &conn, const void *buffer, size_t s) {
        int ret = channel::io_stream_send(conn.conn_data_.shared.ios_fd.conn, buffer, s);
        if (ret < 0) {
            ++conn.stat_.push_failed_times;
            conn.stat_.push_failed_size += s;
        }
        return ret;
    }

    bool connection::unpack(connection &conn, ::atbus::msg_t *&m, ::ATBUS_MACRO_PROTOBUF_NAMESPACE_ID::Arena& arena, std::vector<unsigned char> &in) {
        m = ::ATBUS_MACRO_PROTOBUF_NAMESPACE_ID::Arena::CreateMessage<atbus::protocol::msg>(&arena);
        if (NULL == m) {
            ATBUS_FUNC_NODE_ERROR(*conn.owner_, conn.binding_, &conn, EN_ATBUS_ERR_UNPACK, EN_ATBUS_ERR_MALLOC);
            return false;
        }

        // unpack
        if (false == m->ParseFromArray(reinterpret_cast<const void*>(&in[0]), static_cast<int>(in.size()))) {
            ATBUS_FUNC_NODE_DEBUG(*conn.owner_, conn.binding_, &conn, m, "%s", m->InitializationErrorString().c_str());
            ATBUS_FUNC_NODE_ERROR(*conn.owner_, conn.binding_, &conn, EN_ATBUS_ERR_UNPACK, EN_ATBUS_ERR_UNPACK);
            return false;
        }

        if (false == m->has_head() || atbus::protocol::msg::MSG_BODY_NOT_SET == m->msg_body_case()) {
            ATBUS_FUNC_NODE_ERROR(*conn.owner_, conn.binding_, &conn, EN_ATBUS_ERR_UNPACK, EN_ATBUS_ERR_BAD_DATA);
            return false;
        }

        if (NULL != conn.binding_ && 0 != conn.binding_->get_id()) {
            m->mutable_head()->set_src_bus_id(conn.binding_->get_id());
        }

        return true;
    }
} // namespace atbus
