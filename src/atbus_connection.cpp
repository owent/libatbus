// Copyright 2026 atframework
//
// Created by owent on on 2015-11-20

#include "atbus_connection.h"  // NOLINT: build/include_subdir

#include <common/file_system.h>
#include <common/string_oprs.h>

#if !defined(_WIN32)
#  include <errno.h>
#  include <fcntl.h>
#  include <sys/file.h>
#endif

#include <assert.h>
#include <stdint.h>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>

#include "atbus_node.h"  // NOLINT: build/include_subdir
#include "detail/buffer.h"

#include "atbus_message_handler.h"  // NOLINT: build/include_subdir
#include "libatbus_protocol.h"      // NOLINT: build/include_subdir

ATBUS_MACRO_NAMESPACE_BEGIN
namespace detail {

#if !defined(_WIN32)
static int try_flock_file(const std::string &lock_path) {
  // mkdir if dir not exists
  std::string dirname;
  if (atfw::util::file_system::dirname(lock_path.c_str(), lock_path.size(), dirname)) {
    if (!atfw::util::file_system::is_exist(dirname.c_str())) {
      atfw::util::file_system::mkdir(dirname.c_str(), true);
    }
  }

  int lock_fd = open(lock_path.c_str(), O_RDONLY | O_CREAT, 0600);
  if (lock_fd < 0) {
    return lock_fd;
  }

  int res = flock(lock_fd, LOCK_EX | LOCK_NB);
  if (res < 0) {
    close(lock_fd);
    return res;
  }

  return lock_fd;
}
#endif

struct connection_async_data {
  node *owner_node;
  connection::ptr_t conn;

  explicit connection_async_data(node *o) : owner_node(o) {
    assert(owner_node);
    if (nullptr != owner_node) {
      owner_node->ref_object(reinterpret_cast<void *>(this));
    }
  }

  ~connection_async_data() { owner_node->unref_object(reinterpret_cast<void *>(this)); }

  connection_async_data(const connection_async_data &other) : owner_node(other.owner_node), conn(other.conn) {
    assert(owner_node);

    if (nullptr != owner_node) {
      owner_node->ref_object(reinterpret_cast<void *>(this));
    }
  }

  connection_async_data &operator=(const connection_async_data &other) {
    assert(owner_node);
    assert(other.owner_node);

    if (nullptr == owner_node || nullptr == other.owner_node) {
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
}  // namespace detail

connection::connection(ctor_guard_t &guard)
    : state_(state_t::type::kDisconnected),
#if !defined(_WIN32)
      address_lock_(0),
#endif
      owner_(guard.owner),
      binding_(nullptr),
      conn_context_(connection_context::create(guard.crypto_algorithm, guard.shared_dh_context)) {

  channel::make_address(guard.addr, address_);

  flags_.reset();
  memset(&conn_data_, 0, sizeof(conn_data_));
  memset(&stat_, 0, sizeof(stat_));
}

ATBUS_MACRO_API connection::ptr_t connection::create(node *owner, gsl::string_view addr) {
  if (!owner || addr.empty()) {
    return connection::ptr_t();
  }

  ctor_guard_t guard;
  guard.owner = owner;
  guard.addr = addr;
  guard.crypto_algorithm = owner->get_crypto_key_exchange_type();
  guard.shared_dh_context = owner->get_crypto_key_exchange_context();

  connection::ptr_t ret = ::atfw::util::memory::make_strong_rc<connection>(guard);
  if (!ret) {
    return ret;
  }

  ret->watcher_ = ret;

  owner->add_connection_timer(ret);
  return ret;
}

ATBUS_MACRO_API connection::~connection() {
  flags_.set(static_cast<size_t>(flag_t::type::kDestructing), true);

  if (nullptr != owner_) {
    ATBUS_FUNC_NODE_INFO(*owner_, get_binding(), this, "connection deallocated");
  }

  reset();
}

ATBUS_MACRO_API void connection::reset() {
  // 这个函数可能会在析构时被调用，这时候不能使用watcher_.lock()
  if (flags_.test(static_cast<size_t>(flag_t::type::kResetting))) {
    return;
  }
  flags_.set(static_cast<size_t>(flag_t::type::kResetting), true);

#if !defined(_WIN32)
  unlock_address();
#endif

  // 需要临时给自身加引用计数，否则后续移除的过程中可能导致数据被提前释放
  ptr_t tmp_holder = watch();

  // 后面会重置状态，影响事件判定，所以要先移除检查队列
  owner_->remove_connection_timer(this);

  disconnect();

  endpoint::ptr_t binding_ep;
  if (nullptr != binding_) {
    binding_ep = binding_->watch();
    binding_->remove_connection(this);

    // 只能由上层设置binding_所属的节点
    // binding_ = nullptr;
    assert(nullptr == binding_);
  }

  // 只要connection存在，则它一定存在于owner_的某个位置。
  // 并且这个值只能在创建时指定，所以不能重置这个值
  if (tmp_holder) {
    owner_->add_connection_gc_list(tmp_holder);
  }

  flags_.reset();
  // reset statistics
  memset(&stat_, 0, sizeof(stat_));

  ATBUS_FUNC_NODE_DEBUG(*owner_, get_binding(), this, nullptr, "connection disconnected");
  owner_->on_disconnect(binding_ep.get(), this);
}

ATBUS_MACRO_API int connection::proc(node &n, std::chrono::system_clock::time_point now) {
  if (state_t::type::kConnected != state_) {
    return 0;
  }

  if (nullptr != conn_data_.proc_fn) {
    return conn_data_.proc_fn(n, *this, now);
  }

  return 0;
}

ATBUS_MACRO_API int connection::listen() {
  if (state_t::type::kDisconnected != state_) {
    return EN_ATBUS_ERR_ALREADY_INITED;
  }

  if (nullptr == owner_) {
    return EN_ATBUS_ERR_NOT_INITED;
  }
  const node::conf_t &conf = owner_->get_conf();

  if (address_.scheme.empty() || address_.host.empty()) {
    return EN_ATBUS_ERR_CHANNEL_ADDR_INVALID;
  }

  if (0 == UTIL_STRFUNC_STRNCASE_CMP("mem", address_.scheme.c_str(), 3)) {
    channel::mem_channel *mem_chann = nullptr;
    intptr_t ad;
    atfw::util::string::str2int(ad, address_.host.c_str());
    int res = channel::mem_attach(reinterpret_cast<void *>(ad), conf.receive_buffer_size, &mem_chann, nullptr);
    if (res < 0) {
      res = channel::mem_init(reinterpret_cast<void *>(ad), conf.receive_buffer_size, &mem_chann, nullptr);
    }

    if (res < 0) {
      ATBUS_FUNC_NODE_ERROR(*owner_, get_binding(), this, res, 0, "listen to mem address {} failed", address_.address);
      return res;
    }

    conn_data_.proc_fn = mem_proc_fn;
    conn_data_.free_fn = mem_free_fn;

    // 加入轮询队列
    conn_data_.shared.mem.channel = mem_chann;
    conn_data_.shared.mem.buffer = reinterpret_cast<void *>(ad);
    conn_data_.shared.mem.len = conf.receive_buffer_size;
    owner_->add_proc_connection(watch());
    flags_.set(static_cast<size_t>(flag_t::type::kRegProc), true);
    flags_.set(static_cast<size_t>(flag_t::type::kAccessShareAddr), true);
    flags_.set(static_cast<size_t>(flag_t::type::kAccessShareHost), true);
    flags_.set(static_cast<size_t>(flag_t::type::kServerMode), true);
    set_status(state_t::type::kConnected);
    ATBUS_FUNC_NODE_INFO(*owner_, get_binding(), this, "channel connected(listen)");

    owner_->on_new_connection(this);
    return res;
  } else if (0 == UTIL_STRFUNC_STRNCASE_CMP("shm", address_.scheme.c_str(), 3)) {
#ifdef ATBUS_CHANNEL_SHM
    channel::shm_channel *shm_chann = nullptr;
    int res = channel::shm_attach(address_.host.c_str(), conf.receive_buffer_size, &shm_chann, nullptr);
    if (res < 0) {
      res = channel::shm_init(address_.host.c_str(), conf.receive_buffer_size, &shm_chann, nullptr);
    }

    if (res < 0) {
      ATBUS_FUNC_NODE_ERROR(*owner_, get_binding(), this, res, 0, "listen to shm address {} failed", address_.address);
      return res;
    }

    conn_data_.proc_fn = shm_proc_fn;
    conn_data_.free_fn = shm_free_fn;

    // 加入轮询队列
    conn_data_.shared.shm.channel = shm_chann;
    conn_data_.shared.shm.len = conf.receive_buffer_size;
    owner_->add_proc_connection(watch());
    flags_.set(static_cast<size_t>(flag_t::type::kRegProc), true);
    flags_.set(static_cast<size_t>(flag_t::type::kAccessShareHost), true);
    flags_.set(static_cast<size_t>(flag_t::type::kServerMode), true);
    set_status(state_t::type::kConnected);
    ATBUS_FUNC_NODE_INFO(*owner_, get_binding(), this, "channel connected(listen)");

    owner_->on_new_connection(this);
    return res;
#else
    return EN_ATBUS_ERR_CHANNEL_NOT_SUPPORT;
#endif
  } else {
    // Unix sock的listen的地址应该转为绝对地址，方便跨组连接时可以不依赖相对目录
    // Unix sock也必须共享Host
    if (0 == UTIL_STRFUNC_STRNCASE_CMP("unix", address_.scheme.c_str(), 4) ||
        0 == UTIL_STRFUNC_STRNCASE_CMP("pipe", address_.scheme.c_str(), 4)) {
      if (false == atfw::util::file_system::is_abs_path(address_.host.c_str())) {
        std::string abs_host_path = atfw::util::file_system::get_abs_path(address_.host.c_str());
        size_t max_addr_size = ::atframework::atbus::channel::io_stream_get_max_unix_socket_length();
        if (max_addr_size > 0 && abs_host_path.size() <= max_addr_size) {
          address_.host = abs_host_path;
        }
      }

      flags_.set(static_cast<size_t>(flag_t::type::kAccessShareHost), true);

      // We use file lock to check and reuse unix domain socket
#if !defined(_WIN32)
      if (!owner_->get_conf().overwrite_listen_path) {
        unlock_address();

        std::string lock_path = address_.host + ".lock";
        int lock_fd = detail::try_flock_file(lock_path);
        if (lock_fd < 0) {
          ATBUS_FUNC_NODE_ERROR(*owner_, get_binding(), this, EN_ATBUS_ERR_PIPE_LOCK_PATH_FAILED, errno,
                                "listen {} and lock {} failed", address_.address, lock_path.c_str());
          return EN_ATBUS_ERR_PIPE_LOCK_PATH_FAILED;
        }

        address_lock_path_.swap(lock_path);
        address_lock_ = lock_fd;
      }
#endif

      if (atfw::util::file_system::is_exist(address_.host.c_str())) {
        if (false == atfw::util::file_system::remove(address_.host.c_str())) {
          ATBUS_FUNC_NODE_ERROR(*owner_, get_binding(), this, EN_ATBUS_ERR_PIPE_REMOVE_FAILED, 0,
                                "listen {} and remove old file {} failed", address_.address, address_.host.c_str());
          return EN_ATBUS_ERR_PIPE_REMOVE_FAILED;
        }
      }
    }

    detail::connection_async_data *async_data = new detail::connection_async_data(owner_);
    if (nullptr == async_data) {
      ATBUS_FUNC_NODE_ERROR(*owner_, get_binding(), this, EN_ATBUS_ERR_MALLOC, 0,
                            "listen {} but malloc async data failed", address_.address);
      return EN_ATBUS_ERR_MALLOC;
    }
    connection::ptr_t self = watch();
    async_data->conn = self;

    set_status(state_t::type::kConnecting);
    int res = channel::io_stream_listen(owner_->get_iostream_channel(), address_, iostream_on_listen_cb, async_data, 0);
    if (res < 0) {
      ATBUS_FUNC_NODE_ERROR(*owner_, get_binding(), this, res, owner_->get_iostream_channel()->error_code,
                            "listen {} failed", address_.address);
      delete async_data;
    }

    return res;
  }
}

ATBUS_MACRO_API int connection::connect() {
  if (state_t::type::kDisconnected != state_) {
    return EN_ATBUS_ERR_ALREADY_INITED;
  }

  if (nullptr == owner_) {
    return EN_ATBUS_ERR_NOT_INITED;
  }
  const node::conf_t &conf = owner_->get_conf();

  if (address_.scheme.empty() || address_.host.empty()) {
    return EN_ATBUS_ERR_CHANNEL_ADDR_INVALID;
  }

  if (0 == UTIL_STRFUNC_STRNCASE_CMP("mem", address_.scheme.c_str(), 3)) {
    channel::mem_channel *mem_chann = nullptr;
    intptr_t ad;
    atfw::util::string::str2int(ad, address_.host.c_str());
    int res = channel::mem_attach(reinterpret_cast<void *>(ad), conf.receive_buffer_size, &mem_chann, nullptr);
    if (res < 0) {
      res = channel::mem_init(reinterpret_cast<void *>(ad), conf.receive_buffer_size, &mem_chann, nullptr);
    }

    if (res < 0) {
      ATBUS_FUNC_NODE_ERROR(*owner_, get_binding(), this, res, 0, "connect to address {} failed", address_.address);
      return res;
    }

    // conn_data_.proc_fn = mem_proc_fn;
    conn_data_.proc_fn = nullptr;
    conn_data_.free_fn = mem_free_fn;
    conn_data_.push_fn = mem_push_fn;

    // 连接信息
    conn_data_.shared.mem.channel = mem_chann;
    conn_data_.shared.mem.buffer = reinterpret_cast<void *>(ad);
    conn_data_.shared.mem.len = conf.receive_buffer_size;
    // 仅在listen时要设置proc,否则同机器的同名通道离线会导致proc中断
    // flags_.set(flag_t::REG_PROC, true);
    flags_.set(static_cast<size_t>(flag_t::type::kAccessShareAddr), true);
    flags_.set(static_cast<size_t>(flag_t::type::kAccessShareHost), true);
    flags_.set(static_cast<size_t>(flag_t::type::kClientMode), true);

    if (nullptr == binding_) {
      set_status(state_t::type::kHandshaking);
      ATBUS_FUNC_NODE_INFO(*owner_, binding_, this, "channel handshaking(connect)");
    } else {
      set_status(state_t::type::kConnected);
      ATBUS_FUNC_NODE_INFO(*owner_, binding_, this, "channel connected(connect)");
    }

    owner_->on_new_connection(this);
    return res;
  } else if (0 == UTIL_STRFUNC_STRNCASE_CMP("shm", address_.scheme.c_str(), 3)) {
#ifdef ATBUS_CHANNEL_SHM
    channel::shm_channel *shm_chann = nullptr;
    int res = channel::shm_attach(address_.host.c_str(), conf.receive_buffer_size, &shm_chann, nullptr);
    if (res < 0) {
      res = channel::shm_init(address_.host.c_str(), conf.receive_buffer_size, &shm_chann, nullptr);
    }

    if (res < 0) {
      ATBUS_FUNC_NODE_ERROR(*owner_, get_binding(), this, res, 0, "connect to address {} failed", address_.address);
      return res;
    }

    // conn_data_.proc_fn = shm_proc_fn;
    conn_data_.proc_fn = nullptr;
    conn_data_.free_fn = shm_free_fn;
    conn_data_.push_fn = shm_push_fn;

    // 连接信息
    conn_data_.shared.shm.channel = shm_chann;
    conn_data_.shared.shm.len = conf.receive_buffer_size;

    // 仅在listen时要设置proc,否则同机器的同名通道离线会导致proc中断
    // flags_.set(flag_t::REG_PROC, true);
    flags_.set(static_cast<size_t>(flag_t::type::kAccessShareHost), true);
    flags_.set(static_cast<size_t>(flag_t::type::kClientMode), true);

    if (nullptr == binding_) {
      set_status(state_t::type::kHandshaking);
      ATBUS_FUNC_NODE_INFO(*owner_, binding_, this, "channel handshaking(connect)");
    } else {
      set_status(state_t::type::kConnected);
      ATBUS_FUNC_NODE_INFO(*owner_, binding_, this, "channel connected(connect)");
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
    } else if (0 == UTIL_STRFUNC_STRNCASE_CMP("unix", address_.scheme.c_str(), 4) ||
               0 == UTIL_STRFUNC_STRNCASE_CMP("pipe", address_.scheme.c_str(), 4)) {
      flags_.set(static_cast<size_t>(flag_t::type::kAccessShareHost), true);
    }

    detail::connection_async_data *async_data = new detail::connection_async_data(owner_);
    if (nullptr == async_data) {
      ATBUS_FUNC_NODE_ERROR(*owner_, get_binding(), this, EN_ATBUS_ERR_MALLOC, 0,
                            "connect {} but malloc async data failed", address_.address);
      return EN_ATBUS_ERR_MALLOC;
    }
    connection::ptr_t self = watch();
    async_data->conn = self;

    set_status(state_t::type::kConnecting);
    int res =
        channel::io_stream_connect(owner_->get_iostream_channel(), address_, iostream_on_connected_cb, async_data, 0);
    if (res < 0) {
      ATBUS_FUNC_NODE_ERROR(*owner_, get_binding(), this, res, owner_->get_iostream_channel()->error_code,
                            "connect {} failed", address_.address);
      delete async_data;
    }

    return res;
  }
}

ATBUS_MACRO_API int connection::disconnect() {
  if (state_t::type::kDisconnected == state_) {
    return EN_ATBUS_ERR_NOT_INITED;
  }

  if (state_t::type::kDisconnecting == state_) {
    return EN_ATBUS_ERR_SUCCESS;
  }

  set_status(state_t::type::kDisconnecting);
  if (nullptr != conn_data_.free_fn) {
    if (nullptr != owner_) {
      int res = conn_data_.free_fn(*owner_, *this);
      if (res < 0) {
        ATBUS_FUNC_NODE_DEBUG(*owner_, get_binding(), this, nullptr, "destroy connection failed, res: {}", res);
      }
    }
  }

  // 移除proc队列
  if (flags_.test(static_cast<size_t>(flag_t::type::kRegProc))) {
    if (nullptr != owner_) {
      owner_->remove_proc_connection(address_.address);
    }
    flags_.set(static_cast<size_t>(flag_t::type::kRegProc), false);
  }

  memset(&conn_data_, 0, sizeof(conn_data_));
  set_status(state_t::type::kDisconnected);
  return EN_ATBUS_ERR_SUCCESS;
}

ATBUS_MACRO_API ATBUS_ERROR_TYPE connection::push(gsl::span<const unsigned char> buffer) {
  ++stat_.push_start_times;
  stat_.push_start_size += buffer.size();

  if (state_t::type::kConnected != state_ && state_t::type::kHandshaking != state_) {
    ++stat_.push_failed_times;
    stat_.push_failed_size += buffer.size();

    return EN_ATBUS_ERR_NOT_INITED;
  }

  if (nullptr == conn_data_.push_fn) {
    ++stat_.push_failed_times;
    stat_.push_failed_size += buffer.size();

    return EN_ATBUS_ERR_ACCESS_DENY;
  }

  return conn_data_.push_fn(*this, buffer.data(), buffer.size());
}

/** 增加错误计数 **/
ATBUS_MACRO_API size_t connection::add_stat_fault() { return ++stat_.fault_count; }

/** 清空错误计数 **/
ATBUS_MACRO_API void connection::clear_stat_fault() { stat_.fault_count = 0; }

ATBUS_MACRO_API const channel::channel_address_t &connection::get_address() const { return address_; }

ATBUS_MACRO_API bool connection::is_connected() const { return state_t::type::kConnected == state_; }

ATBUS_MACRO_API endpoint *connection::get_binding() { return binding_; }

ATBUS_MACRO_API const endpoint *connection::get_binding() const { return binding_; }

ATBUS_MACRO_API connection::state_t::type connection::get_status() const { return state_; }
ATBUS_MACRO_API bool connection::check_flag(flag_t::type f) const { return flags_.test(static_cast<size_t>(f)); }
ATBUS_MACRO_API void connection::set_temporary() { flags_.set(static_cast<size_t>(flag_t::type::kTemporary), true); }

ATBUS_MACRO_API connection::ptr_t connection::watch() const {
  if (flags_.test(static_cast<size_t>(flag_t::type::kDestructing)) || watcher_.expired()) {
    return connection::ptr_t();
  }

  return watcher_.lock();
}

/** 是否正在连接、或者握手或者已连接 **/
ATBUS_MACRO_API bool connection::is_running() const {
  return state_t::type::kConnecting == state_ || state_t::type::kHandshaking == state_ ||
         state_t::type::kConnected == state_;
}

ATBUS_MACRO_API const connection::stat_t &connection::get_statistic() const { return stat_; }

ATBUS_MACRO_API void connection::remove_owner_checker() {
  if (nullptr != owner_) {
    owner_->remove_connection_timer(this);
  }
}

ATBUS_MACRO_API connection_context &connection::get_connection_context() noexcept { return *conn_context_; }

ATBUS_MACRO_API void connection::set_status(state_t::type v) {
  if (state_ == v) {
    return;
  }

  state_ = v;

  if (nullptr != owner_ && v == state_t::type::kConnected) {
    owner_->remove_connection_timer(this);
  }
}

#if !defined(_WIN32)
ATBUS_MACRO_API void connection::unlock_address() noexcept {
  if (0 == address_lock_) {
    return;
  }

  flock(address_lock_, LOCK_UN);
  close(address_lock_);
  address_lock_ = 0;

  // Remove lock file
  unlink(address_lock_path_.c_str());
  address_lock_path_.clear();
}
#endif

ATBUS_MACRO_API void connection::iostream_on_listen_cb(channel::io_stream_channel *channel,
                                                       channel::io_stream_connection *connection, int status,
                                                       void *buffer, size_t) {
  detail::connection_async_data *async_data = reinterpret_cast<detail::connection_async_data *>(buffer);
  assert(nullptr != async_data);
  if (nullptr == async_data) {
    return;
  }

  gsl::string_view addr_str;
  if (nullptr != connection) {
    addr_str = connection->addr.address;
  }

  if (status < 0) {
    ATBUS_FUNC_NODE_ERROR(*async_data->owner_node, async_data->conn->binding_, async_data->conn.get(), status,
                          channel->error_code, "channel listen to {} failed", addr_str);
    async_data->conn->set_status(state_t::type::kDisconnected);
    ATBUS_FUNC_NODE_INFO(*async_data->conn->owner_, async_data->conn->binding_, async_data->conn.get(),
                         "channel disconnected(listen failed)");

  } else {
    async_data->conn->flags_.set(static_cast<size_t>(flag_t::type::kRegFd), true);
    async_data->conn->flags_.set(static_cast<size_t>(flag_t::type::kListenFd), true);
    async_data->conn->flags_.set(static_cast<size_t>(flag_t::type::kServerMode), true);
    async_data->conn->set_status(state_t::type::kConnected);
    ATBUS_FUNC_NODE_INFO(*async_data->conn->owner_, async_data->conn->binding_, async_data->conn.get(),
                         "channel connected(listen callback)");

    async_data->conn->conn_data_.shared.ios_fd.channel = channel;
    async_data->conn->conn_data_.shared.ios_fd.conn = connection;
    async_data->conn->conn_data_.free_fn = ios_free_fn;
    connection->data = async_data->conn.get();

    async_data->owner_node->on_new_connection(async_data->conn.get());
  }

  delete async_data;
}

ATBUS_MACRO_API void connection::iostream_on_connected_cb(channel::io_stream_channel *channel,
                                                          channel::io_stream_connection *connection, int status,
                                                          void *buffer, size_t) {
  detail::connection_async_data *async_data = reinterpret_cast<detail::connection_async_data *>(buffer);
  assert(nullptr != async_data);
  if (nullptr == async_data) {
    return;
  }

  gsl::string_view addr_str;
  if (nullptr != connection) {
    addr_str = connection->addr.address;
  }
  if (status < 0) {
    ATBUS_FUNC_NODE_ERROR(*async_data->owner_node, async_data->conn->binding_, async_data->conn.get(), status,
                          channel->error_code, "channel connect to {} failed", addr_str);
    // 连接失败，重置连接
    async_data->conn->reset();

  } else {
    async_data->conn->flags_.set(static_cast<size_t>(flag_t::type::kRegFd), true);
    async_data->conn->flags_.set(static_cast<size_t>(flag_t::type::kClientMode), true);
    async_data->conn->set_status(state_t::type::kHandshaking);
    ATBUS_FUNC_NODE_INFO(*async_data->conn->owner_, async_data->conn->binding_, async_data->conn.get(),
                         "channel handshaking(connect callback)");

    async_data->conn->conn_data_.shared.ios_fd.channel = channel;
    async_data->conn->conn_data_.shared.ios_fd.conn = connection;

    async_data->conn->conn_data_.free_fn = ios_free_fn;
    async_data->conn->conn_data_.push_fn = ios_push_fn;
    connection->data = async_data->conn.get();

    async_data->owner_node->on_new_connection(async_data->conn.get());
  }

  delete async_data;
}

ATBUS_MACRO_API void connection::iostream_on_receive_cb(channel::io_stream_channel *channel,
                                                        channel::io_stream_connection *conn_ios, int status,
                                                        void *buffer, size_t s) {
  assert(channel && channel->data);
  if (nullptr == channel || nullptr == channel->data) {
    return;
  }

  node *_this = reinterpret_cast<node *>(channel->data);

  assert(_this);
  if (nullptr == _this) {
    return;
  }
  connection *conn = reinterpret_cast<connection *>(conn_ios->data);

  if (status < 0 || nullptr == buffer || s <= 0) {
    if (nullptr != conn && (UV_EOF == channel->error_code || UV_ECONNRESET == channel->error_code)) {
      conn->flags_.set(static_cast<size_t>(flag_t::type::kPeerClosed), true);
    }

    ::ATBUS_MACRO_PROTOBUF_NAMESPACE_ID::ArenaOptions arena_options;
    arena_options.initial_block_size = ATBUS_MACRO_RESERVED_SIZE;
    message m{arena_options};
    _this->on_receive_message(conn, std::move(m), status, static_cast<ATBUS_ERROR_TYPE>(channel->error_code));
    return;
  }

  // connection 已经释放并解除绑定，这时候会先把剩下未处理的消息处理完再关闭
  if (nullptr == conn) {
    return;
  }

  // statistic
  ++conn->stat_.pull_times;
  conn->stat_.pull_size += s;

  // unpack
  gsl::span<const unsigned char> msg_buffer{static_cast<const unsigned char *>(buffer), s};
  ::ATBUS_MACRO_PROTOBUF_NAMESPACE_ID::ArenaOptions arena_options;
  arena_options.initial_block_size = ATBUS_MACRO_RESERVED_SIZE;
  message m{arena_options};

  if (false == unpack(*conn, m, msg_buffer)) {
    return;
  }

  if (nullptr != _this) {
    _this->on_receive_message(conn, std::move(m), status, static_cast<ATBUS_ERROR_TYPE>(channel->error_code));
  }
}

ATBUS_MACRO_API void connection::iostream_on_accepted(channel::io_stream_channel *channel,
                                                      channel::io_stream_connection *conn_ios, int /*status*/,
                                                      void * /*buffer*/, size_t) {
  // 连接成功加入点对点传输池
  // 加入超时检测
  node *n = reinterpret_cast<node *>(channel->data);
  assert(nullptr != n);
  if (nullptr == n) {
    channel::io_stream_disconnect(channel, conn_ios, nullptr);
    return;
  }

  // 超过最大排队数
  if (n->get_conf().backlog > 0 && static_cast<size_t>(n->get_conf().backlog) <= n->get_connection_timer_size()) {
    channel::io_stream_disconnect(channel, conn_ios, nullptr);
    return;
  }

  ptr_t conn = create(n, conn_ios->addr.address);
  conn->set_status(state_t::type::kHandshaking);
  conn->flags_.set(static_cast<size_t>(flag_t::type::kRegFd), true);
  conn->flags_.set(static_cast<size_t>(flag_t::type::kServerMode), true);

  conn->conn_data_.free_fn = ios_free_fn;
  conn->conn_data_.push_fn = ios_push_fn;

  conn->conn_data_.shared.ios_fd.channel = channel;
  conn->conn_data_.shared.ios_fd.conn = conn_ios;
  conn_ios->data = conn.get();

  // copy address
  conn->address_ = conn_ios->addr;

  ATBUS_FUNC_NODE_INFO(*n, nullptr, conn.get(), "channel handshaking(accepted callback)");
  n->on_new_connection(conn.get());
}

ATBUS_MACRO_API void connection::iostream_on_connected(channel::io_stream_channel *, channel::io_stream_connection *,
                                                       int /*status*/, void * /*buffer*/, size_t) {}

ATBUS_MACRO_API void connection::iostream_on_disconnected(channel::io_stream_channel *,
                                                          channel::io_stream_connection *conn_ios, int /*status*/,
                                                          void * /*buffer*/, size_t) {
  connection *conn = reinterpret_cast<connection *>(conn_ios->data);

  // 主动关闭时会先释放connection，这时候connection已经被释放，不需要再重置
  if (nullptr == conn) {
    return;
  }

  ATBUS_FUNC_NODE_INFO(*conn->owner_, conn->get_binding(), conn, "connection reset by peer");
  conn->reset();
}

ATBUS_MACRO_API void connection::iostream_on_written(channel::io_stream_channel *channel,
                                                     channel::io_stream_connection *conn_ios, int status,
                                                     void * /*buffer*/, size_t s) {
  node *n = reinterpret_cast<node *>(channel->data);
  assert(nullptr != n);
  if (nullptr == n) {
    return;
  }
  connection *conn = reinterpret_cast<connection *>(conn_ios->data);

  if (EN_ATBUS_ERR_SUCCESS != status) {
    if (nullptr != conn) {
      ++conn->stat_.push_failed_times;
      conn->stat_.push_failed_size += s;
    }

    ATBUS_FUNC_NODE_ERROR(*n, conn->get_binding(), conn, status, channel->error_code,
                          "write data({} bytes) to {} failed", s, conn_ios->addr.address);
  } else {
    if (nullptr != conn) {
      ++conn->stat_.push_success_times;
      conn->stat_.push_success_size += s;

      ATBUS_FUNC_NODE_DEBUG(*n, conn->get_binding(), conn, nullptr, "write data({} bytes) to {} success", s,
                            reinterpret_cast<void *>(conn_ios));
    } else {
      ATBUS_FUNC_NODE_DEBUG(*n, nullptr, conn, nullptr, "write data({} bytes) to {} success", s,
                            reinterpret_cast<void *>(conn_ios));
    }
  }
}

#ifdef ATBUS_CHANNEL_SHM
ATBUS_MACRO_API ATBUS_ERROR_TYPE connection::shm_proc_fn(node &n, connection &conn,
                                                         std::chrono::system_clock::time_point /*now*/) {
  int ret = 0;
  size_t left_times = static_cast<size_t>(n.get_conf().loop_times);
  detail::buffer_block *static_buffer = n.get_temp_static_buffer();
  if (nullptr == static_buffer) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr, &conn, static_cast<int>(EN_ATBUS_ERR_NOT_INITED), 0, "node not inited");
    return EN_ATBUS_ERR_NOT_INITED;
  }

  while (left_times-- > 0) {
    size_t recv_len;
    int res =
        channel::shm_recv(conn.conn_data_.shared.shm.channel, static_buffer->data(), static_buffer->size(), &recv_len);

    if (EN_ATBUS_ERR_NO_DATA == res) {
      break;
    }

    // 回调收到数据事件
    if (res < 0) {
      ret = res;
      ::ATBUS_MACRO_PROTOBUF_NAMESPACE_ID::ArenaOptions arena_options;
      arena_options.initial_block_size = ATBUS_MACRO_RESERVED_SIZE;
      message m{arena_options};

      n.on_receive_message(&conn, std::move(m), res, static_cast<ATBUS_ERROR_TYPE>(res));
      break;
    } else {
      // statistic
      ++conn.stat_.pull_times;
      conn.stat_.pull_size += recv_len;

      // unpack
      gsl::span<const unsigned char> msg_buffer{static_cast<const unsigned char *>(static_buffer->data()), recv_len};
      ::ATBUS_MACRO_PROTOBUF_NAMESPACE_ID::ArenaOptions arena_options;
      arena_options.initial_block_size = ATBUS_MACRO_RESERVED_SIZE;
      message m{arena_options};

      if (false == unpack(conn, m, msg_buffer)) {
        continue;
      }

      n.on_receive_message(&conn, std::move(m), res, static_cast<ATBUS_ERROR_TYPE>(res));
      ++ret;
    }
  }

  return static_cast<ATBUS_ERROR_TYPE>(ret);
}

ATBUS_MACRO_API ATBUS_ERROR_TYPE connection::shm_free_fn(node &, connection &conn) {
  return static_cast<ATBUS_ERROR_TYPE>(channel::shm_close(conn.get_address().host.c_str()));
}

ATBUS_MACRO_API ATBUS_ERROR_TYPE connection::shm_push_fn(connection &conn, const void *buffer, size_t s) {
  int ret = channel::shm_send(conn.conn_data_.shared.shm.channel, buffer, s);
  if (ret >= 0) {
    ++conn.stat_.push_success_times;
    conn.stat_.push_success_size += s;
  } else {
    ++conn.stat_.push_failed_times;
    conn.stat_.push_failed_size += s;
  }

  return static_cast<ATBUS_ERROR_TYPE>(ret);
}
#endif

ATBUS_MACRO_API ATBUS_ERROR_TYPE connection::mem_proc_fn(node &n, connection &conn,
                                                         std::chrono::system_clock::time_point /*now*/) {
  int ret = 0;
  size_t left_times = static_cast<size_t>(n.get_conf().loop_times);
  detail::buffer_block *static_buffer = n.get_temp_static_buffer();
  if (nullptr == static_buffer) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr, &conn, EN_ATBUS_ERR_NOT_INITED, 0, "node not inited");
    return EN_ATBUS_ERR_NOT_INITED;
  }

  while (left_times-- > 0) {
    size_t recv_len;
    int res =
        channel::mem_recv(conn.conn_data_.shared.mem.channel, static_buffer->data(), static_buffer->size(), &recv_len);

    if (EN_ATBUS_ERR_NO_DATA == res) {
      break;
    }

    // 回调收到数据事件
    if (res < 0) {
      ret = res;
      ::ATBUS_MACRO_PROTOBUF_NAMESPACE_ID::ArenaOptions arena_options;
      arena_options.initial_block_size = ATBUS_MACRO_RESERVED_SIZE;
      message m{arena_options};

      n.on_receive_message(&conn, std::move(m), res, static_cast<ATBUS_ERROR_TYPE>(res));
      break;
    } else {
      // statistic
      ++conn.stat_.pull_times;
      conn.stat_.pull_size += recv_len;

      // unpack
      gsl::span<const unsigned char> msg_buffer{static_cast<const unsigned char *>(static_buffer->data()), recv_len};
      ::ATBUS_MACRO_PROTOBUF_NAMESPACE_ID::ArenaOptions arena_options;
      arena_options.initial_block_size = ATBUS_MACRO_RESERVED_SIZE;
      message m{arena_options};
      if (false == unpack(conn, m, msg_buffer)) {
        continue;
      }

      n.on_receive_message(&conn, std::move(m), res, static_cast<ATBUS_ERROR_TYPE>(res));
      ++ret;
    }
  }

  return static_cast<ATBUS_ERROR_TYPE>(ret);
}

ATBUS_MACRO_API ATBUS_ERROR_TYPE connection::mem_free_fn(node &, connection &) { return EN_ATBUS_ERR_SUCCESS; }

ATBUS_MACRO_API ATBUS_ERROR_TYPE connection::mem_push_fn(connection &conn, const void *buffer, size_t s) {
  int ret = channel::mem_send(conn.conn_data_.shared.mem.channel, buffer, s);
  if (ret >= 0) {
    ++conn.stat_.push_success_times;
    conn.stat_.push_success_size += s;
  } else {
    ++conn.stat_.push_failed_times;
    conn.stat_.push_failed_size += s;
  }
  return static_cast<ATBUS_ERROR_TYPE>(ret);
}

ATBUS_MACRO_API ATBUS_ERROR_TYPE connection::ios_free_fn(node &, connection &conn) {
  int ret =
      channel::io_stream_disconnect(conn.conn_data_.shared.ios_fd.channel, conn.conn_data_.shared.ios_fd.conn, nullptr);
  // 释放后移除关联关系
  conn.conn_data_.shared.ios_fd.conn->data = nullptr;

  return static_cast<ATBUS_ERROR_TYPE>(ret);
}

ATBUS_MACRO_API ATBUS_ERROR_TYPE connection::ios_push_fn(connection &conn, const void *buffer, size_t s) {
  int ret = channel::io_stream_send(conn.conn_data_.shared.ios_fd.conn, buffer, s);
  if (ret < 0) {
    ++conn.stat_.push_failed_times;
    conn.stat_.push_failed_size += s;
  }
  return static_cast<ATBUS_ERROR_TYPE>(ret);
}

ATBUS_MACRO_API bool connection::unpack(connection &conn, message &m, gsl::span<const unsigned char> in) {
  // unpack
  int res = message_handler::unpack_message(conn.get_connection_context(), m, in, conn.owner_->get_conf().message_size);
  if (res != EN_ATBUS_ERR_SUCCESS) {
    if (res == EN_ATBUS_ERR_UNPACK) {
      ATBUS_FUNC_NODE_DEBUG(*conn.owner_, conn.binding_, &conn, &m, "{}", m.get_unpack_error_message());
    }

    ATBUS_FUNC_NODE_ERROR(*conn.owner_, conn.binding_, &conn, EN_ATBUS_ERR_UNPACK, res, "unpack message failed: {}",
                          m.get_unpack_error_message());
    return false;
  }

  if (message_body_type::MESSAGE_TYPE_NOT_SET == m.get_body_type()) {
    ATBUS_FUNC_NODE_ERROR(*conn.owner_, conn.binding_, &conn, EN_ATBUS_ERR_UNPACK, EN_ATBUS_ERR_BAD_DATA,
                          "unpack message failed: {}", "body type not set");
    return false;
  }

  if (nullptr != conn.binding_ && 0 != conn.binding_->get_id()) {
    m.mutable_head().set_source_bus_id(conn.binding_->get_id());
  }

  return true;
}
ATBUS_MACRO_NAMESPACE_END

