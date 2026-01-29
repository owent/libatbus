// Copyright 2026 atframework

#include <common/string_oprs.h>

#include <assert.h>
#include <stdint.h>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>

#include "detail/buffer.h"

#include "atbus_endpoint.h"  // NOLINT: build/include_subdir
#include "atbus_node.h"      // NOLINT: build/include_subdir

#include "libatbus_protocol.h"  // NOLINT: build/include_subdir

ATBUS_MACRO_NAMESPACE_BEGIN

ATBUS_MACRO_API endpoint::ptr_t endpoint::create(node *owner, bus_id_t id, int32_t pid, gsl::string_view hn) {
  if (nullptr == owner) {
    return endpoint::ptr_t();
  }

  ctor_t ctor_guard;
  ctor_guard.owner = owner;
  ctor_guard.id = id;
  ctor_guard.pid = pid;
  ctor_guard.hostname = hn;

  endpoint::ptr_t ret = atfw::util::memory::make_strong_rc<endpoint>(ctor_guard);
  if (!ret) {
    return ret;
  }

  if (node_access_controller::add_ping_timer(*owner, ret)) {
    ret->set_flag(flag_t::type::kHasPingTimer, true);
  }
  ret->watcher_ = ret;

  return ret;
}

ATBUS_MACRO_API endpoint::endpoint(ctor_t &guard)
    : id_(guard.id), hostname_(guard.hostname), pid_(guard.pid), owner_(guard.owner) {
  flags_.reset();
}

ATBUS_MACRO_API endpoint::~endpoint() {
  if (nullptr != owner_) {
    ATBUS_FUNC_NODE_INFO(*owner_, this, nullptr, "endpoint deallocated");
  }

  flags_.set(static_cast<size_t>(flag_t::type::kDestructing), true);

  reset();
}

ATBUS_MACRO_API void endpoint::reset() {
  // 这个函数可能会在析构时被调用，这时候不能使用watcher_.lock()
  if (flags_.test(static_cast<size_t>(flag_t::type::kResetting))) {
    return;
  }
  flags_.set(static_cast<size_t>(flag_t::type::kResetting), true);

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

ATBUS_MACRO_API bus_id_t endpoint::get_id() const { return id_; }

ATBUS_MACRO_API int32_t endpoint::get_pid() const { return pid_; }
ATBUS_MACRO_API const std::string &endpoint::get_hostname() const { return hostname_; }
ATBUS_MACRO_API const std::string &endpoint::get_hash_code() const { return hash_code_; }
ATBUS_MACRO_API void endpoint::update_hash_code(gsl::string_view in) {
  if (in.empty()) {
    return;
  }

  hash_code_ = std::string(in);
}

ATBUS_MACRO_API bool endpoint::add_connection(connection *conn, bool force_data) {
  if (!conn) {
    return false;
  }

  if (flags_.test(static_cast<size_t>(flag_t::type::kResetting))) {
    return false;
  }

  // 如果进入了handshake流程会第二次添加同一个连接
  if (this == conn->binding_) {
    if (connection::state_t::type::kHandshaking == conn->get_status()) {
      conn->set_status(connection::state_t::type::kConnected);
    }
    return true;
  }

  if (nullptr != conn->binding_) {
    return false;
  }

  if (force_data || ctrl_conn_) {
    data_conn_.push_back(conn->watch());
    flags_.set(static_cast<size_t>(flag_t::type::kConnectionSorted), false);  // 置为未排序状态
  } else {
    ctrl_conn_ = conn->watch();
  }

  // 已经成功连接可以不需要握手
  // 注意这里新连接要控制时序，Handshaking检查之后才允许发起连接/响应连接回调流程
  // 目前走libuv流程connection和endpoint管理都是单线程的，不会有时序问题
  conn->binding_ = this;
  if (connection::state_t::type::kHandshaking == conn->get_status()) {
    conn->set_status(connection::state_t::type::kConnected);
  }
  return true;
}

ATBUS_MACRO_API bool endpoint::remove_connection(connection *conn) {
  if (!conn) {
    return false;
  }

  assert(this == conn->binding_);

  // 重置流程会在reset里清理对象，不需要再进行一次查找
  if (flags_.test(static_cast<size_t>(flag_t::type::kResetting))) {
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
  if (static_cast<size_t>(f) >= static_cast<size_t>(flag_t::type::kMax)) {
    return false;
  }

  return flags_.test(static_cast<size_t>(f));
}

ATBUS_MACRO_API int endpoint::set_flag(flag_t::type f, bool v) {
  if (static_cast<size_t>(f) >= static_cast<size_t>(flag_t::type::kMax) ||
      static_cast<size_t>(f) < static_cast<size_t>(flag_t::type::kMutableFlags)) {
    return EN_ATBUS_ERR_PARAMS;
  }

  flags_.set(static_cast<size_t>(f), v);

  return EN_ATBUS_ERR_SUCCESS;
}

ATBUS_MACRO_API uint32_t endpoint::get_flags() const { return static_cast<uint32_t>(flags_.to_ulong()); }

ATBUS_MACRO_API endpoint::ptr_t endpoint::watch() const {
  if (flags_.test(static_cast<size_t>(flag_t::type::kDestructing)) || watcher_.expired()) {
    return endpoint::ptr_t();
  }

  return watcher_.lock();
}

ATBUS_MACRO_API const std::list<channel::channel_address_t> &endpoint::get_listen() const { return listen_address_; }

ATBUS_MACRO_API void endpoint::clear_listen() {
  listen_address_.clear();
  flags_.set(static_cast<size_t>(flag_t::type::kHasListenPorc), false);
  flags_.set(static_cast<size_t>(flag_t::type::kHasListenFd), false);
}

ATBUS_MACRO_API void endpoint::add_listen(gsl::string_view addr) {
  if (addr.empty()) {
    return;
  }

  if (addr.size() >= 4 && (0 == UTIL_STRFUNC_STRNCASE_CMP("mem:", addr.data(), 4) ||
                           0 == UTIL_STRFUNC_STRNCASE_CMP("shm:", addr.data(), 4))) {
    flags_.set(static_cast<size_t>(flag_t::type::kHasListenPorc), true);
  } else {
    flags_.set(static_cast<size_t>(flag_t::type::kHasListenFd), true);
  }

  channel::channel_address_t parsed_addr;
  if (channel::make_address(addr, parsed_addr)) {
    listen_address_.push_back(std::move(parsed_addr));
  }
}

ATBUS_MACRO_API void endpoint::update_supported_schemas(const std::unordered_set<std::string> &&schemas) {
  supported_schemas_ = std::move(schemas);
}

ATBUS_MACRO_API bool endpoint::is_schema_supported(const std::string &checked) const noexcept {
  return supported_schemas_.find(checked) != supported_schemas_.end();
}

ATBUS_MACRO_API void endpoint::add_ping_timer() {
  if (nullptr == owner_) {
    return;
  }

  clear_ping_timer();

  if (flags_.test(static_cast<size_t>(flag_t::type::kResetting))) {
    return;
  }

  if (node_access_controller::add_ping_timer(*owner_, watch())) {
    set_flag(flag_t::type::kHasPingTimer, true);
  }
}

ATBUS_MACRO_API void endpoint::clear_ping_timer() {
  if (nullptr == owner_ || false == get_flag(flag_t::type::kHasPingTimer)) {
    return;
  }

  node_access_controller::remove_ping_timer(*owner_, this);
  set_flag(flag_t::type::kHasPingTimer, false);
}

bool endpoint::sort_connection_cmp_fn(const connection::ptr_t &left, const connection::ptr_t &right) {
  int lscore = 0, rscore = 0;
  if (!left->check_flag(connection::flag_t::type::kAccessShareAddr)) {
    lscore += 0x08;
  }
  if (!left->check_flag(connection::flag_t::type::kAccessShareHost)) {
    lscore += 0x04;
  }

  if (!right->check_flag(connection::flag_t::type::kAccessShareAddr)) {
    rscore += 0x08;
  }
  if (!right->check_flag(connection::flag_t::type::kAccessShareHost)) {
    rscore += 0x04;
  }

  return lscore < rscore;
}

ATBUS_MACRO_API connection *endpoint::get_ctrl_connection(const endpoint *ep) const {
  if (nullptr == ep) {
    return nullptr;
  }

  if (this == ep) {
    return nullptr;
  }

  if (ep->ctrl_conn_ && connection::state_t::type::kConnected == ep->ctrl_conn_->get_status()) {
    return ep->ctrl_conn_.get();
  }

  return nullptr;
}

ATBUS_MACRO_API connection *endpoint::get_data_connection(const endpoint *ep) const {
  return get_data_connection(ep, true);
}

ATBUS_MACRO_API connection *endpoint::get_data_connection(const endpoint *ep, bool enable_fallback_ctrl) const {
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
  if (false == ep->flags_.test(static_cast<size_t>(flag_t::type::kConnectionSorted))) {
    const_cast<endpoint *>(ep)->data_conn_.sort(sort_connection_cmp_fn);
    const_cast<endpoint *>(ep)->flags_.set(static_cast<size_t>(flag_t::type::kConnectionSorted), true);
  }

  for (auto &conn : ep->data_conn_) {
    if (connection::state_t::type::kConnected != conn->get_status()) {
      continue;
    }

    if (share_pid && conn->check_flag(connection::flag_t::type::kAccessShareAddr)) {
      return conn.get();
    }

    if (share_host && conn->check_flag(connection::flag_t::type::kAccessShareHost)) {
      return conn.get();
    }

    if (!conn->check_flag(connection::flag_t::type::kAccessShareHost)) {
      return conn.get();
    }
  }

  if (enable_fallback_ctrl) {
    return get_ctrl_connection(ep);
  } else {
    return nullptr;
  }
}

ATBUS_MACRO_API size_t endpoint::get_data_connection_count(bool enable_fallback_ctrl) const noexcept {
  size_t count = 0;
  for (auto &conn : data_conn_) {
    if (connection::state_t::type::kDisconnecting == conn->get_status() ||
        connection::state_t::type::kDisconnected == conn->get_status()) {
      continue;
    }

    ++count;
  }

  if (count == 0 && enable_fallback_ctrl) {
    if (ctrl_conn_ && connection::state_t::type::kDisconnecting != ctrl_conn_->get_status() &&
        connection::state_t::type::kDisconnected != ctrl_conn_->get_status()) {
      ++count;
    }
  }

  return count;
}

endpoint::stat_t::stat_t()
    : fault_count(0),
      unfinished_ping(0),
      ping_delay(0),
      last_pong_time(std::chrono::system_clock::from_time_t(0)),
      created_time(std::chrono::system_clock::from_time_t(0)) {}

/** 增加错误计数 **/
ATBUS_MACRO_API size_t endpoint::add_stat_fault() noexcept { return ++stat_.fault_count; }

/** 清空错误计数 **/
ATBUS_MACRO_API void endpoint::clear_stat_fault() noexcept { stat_.fault_count = 0; }

ATBUS_MACRO_API void endpoint::set_stat_unfinished_ping(uint64_t p) noexcept { stat_.unfinished_ping = p; }

ATBUS_MACRO_API uint64_t endpoint::get_stat_unfinished_ping() const noexcept { return stat_.unfinished_ping; }

ATBUS_MACRO_API void endpoint::set_stat_ping_delay(std::chrono::microseconds pd,
                                                   std::chrono::system_clock::time_point pong_tm) noexcept {
  stat_.ping_delay = pd;
  stat_.last_pong_time = pong_tm;
}

ATBUS_MACRO_API std::chrono::microseconds endpoint::get_stat_ping_delay() const { return stat_.ping_delay; }

ATBUS_MACRO_API std::chrono::system_clock::time_point endpoint::get_stat_last_pong() const {
  return stat_.last_pong_time;
}

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

ATBUS_MACRO_API std::chrono::system_clock::time_point endpoint::get_stat_created_time() {
  if ATFW_UTIL_LIKELY_CONDITION (stat_.created_time > std::chrono::system_clock::from_time_t(0)) {
    return stat_.created_time;
  }

  stat_.created_time = owner_->get_timer_tick();
  return stat_.created_time;
}

ATBUS_MACRO_API const node *endpoint::get_owner() const { return owner_; }

ATBUS_MACRO_NAMESPACE_END

