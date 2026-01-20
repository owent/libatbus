// Copyright 2025 atframework
/**
 * @brief 所有channel文件的模式均为 c + channel<br />
 *        使用c的模式是为了简单、结构清晰并且避免异常<br />
 *        附带c++的部分是为了避免命名空间污染并且c++的跨平台适配更加简单
 */

#include "atbus_node.h"

#include <algorithm/crypto_cipher.h>
#include <algorithm/murmur_hash.h>
#include <algorithm/sha.h>
#include <common/string_oprs.h>
#include <string/string_format.h>
#include <time/time_utility.h>

#ifndef _MSC_VER

#  include <algorithm>
#  include <string>
#  include <unordered_set>
#  include <vector>

#  include <sys/types.h>
#  include <unistd.h>

#else
#  pragma comment(lib, "Ws2_32.lib")
#endif

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <functional>
#include <sstream>
#if !(defined(ATFRAMEWORK_UTILS_THREAD_TLS_USE_PTHREAD) && ATFRAMEWORK_UTILS_THREAD_TLS_USE_PTHREAD) && \
    __cplusplus >= 201103L
#  include <mutex>
#endif

#include "detail/buffer.h"

#include "atbus_message_handler.h"

#include "libatbus_protocol.h"

ATBUS_MACRO_NAMESPACE_BEGIN

#if defined(ATFRAMEWORK_UTILS_THREAD_TLS_USE_PTHREAD) && ATFRAMEWORK_UTILS_THREAD_TLS_USE_PTHREAD
namespace detail {
static pthread_once_t gt_atbus_node_global_init_once = PTHREAD_ONCE_INIT;
static void atbus_node_global_init_once() {
  uv_loop_t loop;
  // Call uv_loop_init() to initialize the global data.
  uv_loop_init(&loop);
  uv_loop_configure(&loop, UV_METRICS_IDLE_TIME);
  uv_loop_close(&loop);
}
}  // namespace detail
#elif __cplusplus >= 201103L
namespace detail {
static std::once_flag gt_atbus_node_global_init_once;
static void atbus_node_global_init_once() {
  uv_loop_t loop;
  // Call uv_loop_init() to initialize the global data.
  uv_loop_init(&loop);
  uv_loop_configure(&loop, UV_METRICS_IDLE_TIME);
  uv_loop_close(&loop);
}
}  // namespace detail
#endif

bool node_access_controller::add_ping_timer(node &n, const endpoint::ptr_t &ep) { return n.add_ping_timer(ep); }

void node_access_controller::remove_ping_timer(node &n, const endpoint *ep) { n.remove_ping_timer(ep); }

ATBUS_MACRO_API node::conf_t::conf_t() { node::default_conf(this); }

ATBUS_MACRO_API node::conf_t::conf_t(const conf_t &other) { *this = other; }

ATBUS_MACRO_API node::conf_t::~conf_t() {}

ATBUS_MACRO_API node::conf_t &node::conf_t::operator=(const conf_t &other) {
  ev_loop = other.ev_loop;
  topology_labels = other.topology_labels;
  flags = other.flags;
  upstream_address = other.upstream_address;
  loop_times = other.loop_times;
  ttl = other.ttl;
  protocol_version = other.protocol_version;
  protocol_minimal_version = other.protocol_minimal_version;

  first_idle_timeout = other.first_idle_timeout;
  ping_interval = other.ping_interval;
  retry_interval = other.retry_interval;
  fault_tolerant = other.fault_tolerant;
  backlog = other.backlog;
  access_token_max_number = other.access_token_max_number;
  access_tokens = other.access_tokens;
  overwrite_listen_path = other.overwrite_listen_path;

  crypto_key_exchange_type = other.crypto_key_exchange_type;
  crypto_key_refresh_interval = other.crypto_key_refresh_interval;
  crypto_allow_algorithms = other.crypto_allow_algorithms;

  compression_allow_algorithms = other.compression_allow_algorithms;

  message_size = other.message_size;
  receive_buffer_size = other.receive_buffer_size;
  send_buffer_size = other.send_buffer_size;
  send_buffer_number = other.send_buffer_number;

  return *this;
}

ATBUS_MACRO_API node::flag_guard_t::flag_guard_t(const node *o, flag_t::type f)
    : owner(const_cast<node *>(o)), flag(f), holder(false) {
  if (owner && !owner->flags_.test(static_cast<size_t>(flag))) {
    holder = true;
    owner->flags_.set(static_cast<size_t>(flag), true);
  }
}

ATBUS_MACRO_API node::flag_guard_t::~flag_guard_t() {
  if ((*this) && owner) {
    owner->flags_.set(static_cast<size_t>(flag), false);
  }
}

node::node()
    : state_(state_t::type::CREATED),
      crypto_key_exchange_type_(protocol::ATBUS_CRYPTO_KEY_EXCHANGE_NONE),
      ev_loop_(nullptr),
      static_buffer_(nullptr),
      logger_enable_debug_message_verbose_(false) {
  ::atfw::util::time::time_utility::update();

  event_timer_.tick = std::chrono::system_clock::from_time_t(0);
  event_timer_.upstream_op_timepoint = std::chrono::system_clock::from_time_t(0);
  random_engine_.init_seed(static_cast<uint64_t>(time(nullptr)));

  flags_.reset();

#if defined(ATFRAMEWORK_UTILS_THREAD_TLS_USE_PTHREAD) && ATFRAMEWORK_UTILS_THREAD_TLS_USE_PTHREAD
  (void)pthread_once(&detail::gt_atbus_node_global_init_once, detail::atbus_node_global_init_once);
#elif __cplusplus >= 201103L
  std::call_once(detail::gt_atbus_node_global_init_once, detail::atbus_node_global_init_once);
#endif

  logger_ = atfw::util::log::log_wrapper::create_user_logger();
  logger_->set_level(atfw::util::log::log_formatter::level_t::LOG_LW_INFO);
  logger_->add_sink(
      [](const atfw::util::log::log_formatter::caller_info_t &caller, const char *content, size_t content_size) {
        auto default_cat =
            atfw::util::log::log_wrapper::mutable_log_cat(atfw::util::log::log_wrapper::categorize_t::DEFAULT);
        if (default_cat == nullptr) {
          return;
        }

        if (!default_cat->check_level(caller.level_id)) {
          return;
        }

        default_cat->write_log(caller, content, content_size);
      },
      atfw::util::log::log_formatter::level_t::LOG_LW_DEBUG, atfw::util::log::log_formatter::level_t::LOG_LW_FATAL);
}

void node::io_stream_channel_del::operator()(channel::io_stream_channel *p) const {
  channel::io_stream_close(p);
  delete p;
}

ATBUS_MACRO_API void node::default_conf(conf_t *conf) {
  if (nullptr == conf) {
    return;
  }

  conf->ev_loop = nullptr;
  conf->flags.reset();
  conf->upstream_address.clear();
  conf->topology_labels.clear();
  conf->loop_times = 256;
  conf->ttl = 16;  // 默认最长16次跳转
  conf->protocol_version = atbus::protocol::ATBUS_PROTOCOL_VERSION;
  conf->protocol_minimal_version = atbus::protocol::ATBUS_PROTOCOL_MINIMAL_VERSION;

  conf->first_idle_timeout = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::seconds{ATBUS_MACRO_CONNECTION_CONFIRM_TIMEOUT});
  conf->ping_interval =
      std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::seconds{8});  // 默认ping包间隔为8s
  conf->retry_interval = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::seconds{3});
  conf->fault_tolerant = 2;  // 允许最多失败2次，第3次直接失败，默认配置里3次ping包无响应则是最多24s可以发现节点下线
  conf->backlog = ATBUS_MACRO_CONNECTION_BACKLOG;
  conf->access_token_max_number = 5;
  conf->access_tokens.clear();
  conf->overwrite_listen_path = false;

  // 加密算法
  conf->crypto_key_exchange_type = protocol::ATBUS_CRYPTO_KEY_EXCHANGE_NONE;
  conf->crypto_key_refresh_interval =
      std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::hours{3});  // 默认3小时重新协商一次
  conf->crypto_allow_algorithms.clear();
#if defined(ATFW_UTIL_MACRO_CRYPTO_CIPHER_ENABLED)
  std::unordered_set<protocol::ATBUS_CRYPTO_ALGORITHM_TYPE> algorithm;
  algorithm.reserve(8);
  for (auto &name : ::atfw::util::crypto::cipher::get_all_cipher_names()) {
    protocol::ATBUS_CRYPTO_ALGORITHM_TYPE algo = parse_crypto_algorithm_name(name);
    if (algo != protocol::ATBUS_CRYPTO_ALGORITHM_NONE) {
      algorithm.insert(algo);
      continue;
    }
  }
  conf->crypto_allow_algorithms.reserve(algorithm.size());
  conf->crypto_allow_algorithms.assign(algorithm.begin(), algorithm.end());
#endif

  // 压缩算法
  conf->compression_allow_algorithms.clear();
  conf->compression_allow_algorithms.reserve(4);
#if defined(ATBUS_MACRO_COMPRESSION_ZSTD) && ATBUS_MACRO_COMPRESSION_ZSTD
  conf->compression_allow_algorithms.push_back(protocol::ATBUS_COMPRESSION_ALGORITHM_ZSTD);
#endif
#if defined(ATBUS_MACRO_COMPRESSION_LZ4) && ATBUS_MACRO_COMPRESSION_LZ4
  conf->compression_allow_algorithms.push_back(protocol::ATBUS_COMPRESSION_ALGORITHM_LZ4);
#endif
#if defined(ATBUS_MACRO_COMPRESSION_SNAPPY) && ATBUS_MACRO_COMPRESSION_SNAPPY
  conf->compression_allow_algorithms.push_back(protocol::ATBUS_COMPRESSION_ALGORITHM_SNAPPY);
#endif
#if defined(ATBUS_MACRO_COMPRESSION_ZLIB) && ATBUS_MACRO_COMPRESSION_ZLIB
  conf->compression_allow_algorithms.push_back(protocol::ATBUS_COMPRESSION_ALGORITHM_ZLIB);
#endif

  // Message配置
  conf->message_size = ATBUS_MACRO_MESSAGE_LIMIT;

  // receive_buffer_size 用于内存/共享内存通道的缓冲区长度，因为本机节点一般数量少所以默认设的大一点
  conf->receive_buffer_size = ATBUS_MACRO_SHM_MEM_CHANNEL_LENGTH;

  // send_buffer_size 用于IO流通道的发送缓冲区长度，远程节点可能数量很多所以设的小一点
  conf->send_buffer_size = ATBUS_MACRO_IOS_SEND_BUFFER_LENGTH;
  conf->send_buffer_number = 0;  // 默认不使用静态缓冲区，所以设为0
}

ATBUS_MACRO_API void node::default_conf(start_conf_t *conf) {
  if (nullptr == conf) {
    return;
  }

  conf->timer_timepoint = std::chrono::system_clock::from_time_t(0);
}

ATBUS_MACRO_API node::ptr_t node::create() {
  ptr_t ret(new node());
  if (!ret) {
    return ret;
  }

  ret->watcher_ = ret;
  return ret;
}

ATBUS_MACRO_API node::~node() {
  if (state_t::type::CREATED != state_) {
    reset();
  }

  self_.reset();
  ATBUS_FUNC_NODE_INFO(*this, nullptr, nullptr, "node destroyed");
}

ATBUS_MACRO_API int node::init(bus_id_t id, const conf_t *conf) {
  if (state_t::type::CREATED != state_) {
    reset();
  }

  if (nullptr == conf) {
    default_conf(&conf_);
  } else {
    conf_ = *conf;
  }

  // 初始化拓扑配置
  if (!topology_) {
    topology_ = ::atfw::util::memory::make_strong_rc<topology_data>();
  }
  topology_->pid = get_pid();
  topology_->hostname = get_hostname();
  topology_->labels = conf_.topology_labels;
  topology_registry_ = topology_registry::create();
  if (id != 0) {
    // 初始化先复制一份，后面再更新
    topology_registry_->update_peer(id, 0, topology_);
  }

  // 加载加密和压缩配置
  reload_crypto(conf_.crypto_key_exchange_type, conf_.crypto_key_refresh_interval,
                gsl::span<const protocol::ATBUS_CRYPTO_ALGORITHM_TYPE>(conf_.crypto_allow_algorithms.data(),
                                                                       conf_.crypto_allow_algorithms.size()));
  reload_compression(gsl::span<const protocol::ATBUS_COMPRESSION_ALGORITHM_TYPE>(
      conf_.compression_allow_algorithms.data(), conf_.compression_allow_algorithms.size()));

  if (conf_.access_tokens.size() > conf_.access_token_max_number) {
    conf_.access_tokens.resize(conf_.access_token_max_number);
  }
  // follow protocol, not input configure
  conf_.protocol_version = atbus::protocol::ATBUS_PROTOCOL_VERSION;
  conf_.protocol_minimal_version = atbus::protocol::ATBUS_PROTOCOL_MINIMAL_VERSION;

  ev_loop_ = conf_.ev_loop;
  self_ = endpoint::create(this, id, get_pid(), get_hostname());
  if (!self_) {
    return EN_ATBUS_ERR_MALLOC;
  }
  self_->clear_ping_timer();
  // 复制配置

  static_buffer_ = detail::buffer_block::malloc(
      conf_.message_size + detail::buffer_block::head_size(conf_.message_size) + 64);  // 预留hash码64位长度和vint长度);

  self_data_messages_.clear();
  self_command_messages_.clear();

  state_ = state_t::type::INITED;
  return EN_ATBUS_ERR_SUCCESS;
}

ATBUS_MACRO_API void node::reload_crypto(
    protocol::ATBUS_CRYPTO_KEY_EXCHANGE_TYPE crypto_key_exchange_type,
    std::chrono::microseconds crypto_key_refresh_interval,
    gsl::span<const protocol::ATBUS_CRYPTO_ALGORITHM_TYPE> crypto_allow_algorithms) {
  conf_.crypto_key_refresh_interval = crypto_key_refresh_interval;

  if (crypto_key_exchange_type_ != crypto_key_exchange_type) {
    bool is_success = false;
    ::atfw::util::crypto::dh::shared_context::ptr_t new_dh_ctx;
    switch (crypto_key_exchange_type) {
      case protocol::ATBUS_CRYPTO_KEY_EXCHANGE_X25519:
        new_dh_ctx = ::atfw::util::crypto::dh::shared_context::create();
        if (!new_dh_ctx || new_dh_ctx->init("ecdh:x25519") < 0) {
          break;
        }
        is_success = true;
        break;
      case protocol::ATBUS_CRYPTO_KEY_EXCHANGE_SECP256R1:
        new_dh_ctx = ::atfw::util::crypto::dh::shared_context::create();
        if (!new_dh_ctx || new_dh_ctx->init("ecdh:p-256") < 0) {
          break;
        }
        is_success = true;
        break;
      case protocol::ATBUS_CRYPTO_KEY_EXCHANGE_SECP384R1:
        new_dh_ctx = ::atfw::util::crypto::dh::shared_context::create();
        if (!new_dh_ctx || new_dh_ctx->init("ecdh:p-384") < 0) {
          break;
        }
        is_success = true;
        break;
      case protocol::ATBUS_CRYPTO_KEY_EXCHANGE_SECP521R1:
        new_dh_ctx = ::atfw::util::crypto::dh::shared_context::create();
        if (!new_dh_ctx || new_dh_ctx->init("ecdh:p-521") < 0) {
          break;
        }
        is_success = true;
        break;
      default:
        crypto_key_exchange_type = protocol::ATBUS_CRYPTO_KEY_EXCHANGE_NONE;
        is_success = true;
        break;
    }

    if (is_success) {
      crypto_key_exchange_type_ = crypto_key_exchange_type;
      crypto_key_exchange_context_ = new_dh_ctx;
    }
  }

  conf_.crypto_key_exchange_type = crypto_key_exchange_type_;
  if (crypto_allow_algorithms.data() == conf_.crypto_allow_algorithms.data()) {
    return;
  }
  conf_.crypto_allow_algorithms.reserve(crypto_allow_algorithms.size());
  conf_.crypto_allow_algorithms.clear();
  for (auto &alg : crypto_allow_algorithms) {
    if (alg == protocol::ATBUS_CRYPTO_ALGORITHM_NONE) {
      continue;
    }
    conf_.crypto_allow_algorithms.push_back(alg);
  }
}

ATBUS_MACRO_API void node::reload_compression(
    gsl::span<const protocol::ATBUS_COMPRESSION_ALGORITHM_TYPE> compression_allow_algorithms) {
  if (compression_allow_algorithms.data() == conf_.compression_allow_algorithms.data()) {
    return;
  }

  conf_.compression_allow_algorithms.reserve(compression_allow_algorithms.size());
  conf_.compression_allow_algorithms.assign(compression_allow_algorithms.begin(), compression_allow_algorithms.end());
}

ATBUS_MACRO_API int node::start(const start_conf_t &start_conf) {
  if (state_t::type::CREATED == state_) {
    return EN_ATBUS_ERR_NOT_INITED;
  }

  // 初始化时间
  if (start_conf.timer_timepoint == std::chrono::system_clock::from_time_t(0)) {
    atfw::util::time::time_utility::update();
    event_timer_.tick = atfw::util::time::time_utility::sys_now();
  } else {
    event_timer_.tick = start_conf.timer_timepoint;
  }

  init_hash_code();
  if (self_) {
    self_->update_hash_code(get_hash_code());
  }

  // 连接上游节点
  if (0 != get_id() && !conf_.upstream_address.empty()) {
    if (!node_upstream_.node_) {
      // 如果上游节点被激活了，那么上游节点操作时间必须更新到非0值，以启用这个功能
      if (connect(conf_.upstream_address.c_str()) >= 0) {
        event_timer_.upstream_op_timepoint = event_timer_.tick + conf_.first_idle_timeout;
        state_ = state_t::type::CONNECTING_UPSTREAM;
      } else {
        event_timer_.upstream_op_timepoint = event_timer_.tick + conf_.retry_interval;
        state_ = state_t::type::LOST_UPSTREAM;
      }
    }
  } else {
    on_actived();
  }

  return 0;
}

ATBUS_MACRO_API int node::start() {
  start_conf_t start_conf;
  default_conf(&start_conf);
  return start(start_conf);
}

ATBUS_MACRO_API int node::reset() {
  // 这个函数可能会在析构时被调用，这时候不能使用watcher_.lock()
  if (flags_.test(static_cast<size_t>(flag_t::type::EN_FT_RESETTING))) {
    return EN_ATBUS_ERR_SUCCESS;
  }
  flags_.set(static_cast<size_t>(flag_t::type::EN_FT_RESETTING), true);
  ATBUS_FUNC_NODE_INFO(*this, nullptr, nullptr, "node reset");

  // dispatch all self messages
  {
    while (dispatch_all_self_messages() > 0);
  }

  // first save all connection, and then reset it
  using auto_map_t = std::unordered_map<std::string, connection::ptr_t>;
  {
    std::vector<auto_map_t::mapped_type> temp_vec;
    temp_vec.reserve(proc_connections_.size());
    for (auto_map_t::iterator iter = proc_connections_.begin(); iter != proc_connections_.end(); ++iter) {
      if (iter->second) {
        temp_vec.push_back(iter->second);
      }
    }

    // 所有连接断开
    for (size_t i = 0; i < temp_vec.size(); ++i) {
      temp_vec[i]->reset();
    }
  }
  proc_connections_.clear();

  // 销毁endpoint
  if (node_upstream_.node_) {
    remove_endpoint(node_upstream_.node_->get_id());
  }
  // endpoint 不应该游离在node以外，所以这里就应该要触发endpoint::reset
  remove_collection(node_route_);

  // 清空正在连接或握手的列表
  // 必须显式指定断开，以保证会主动断开正在进行的连接
  // 因为正在进行的连接会增加connection的引用计数
  while (!event_timer_.connecting_list.empty()) {
    timer_desc_ls<std::string, connection::ptr_t>::type::iterator iter = event_timer_.connecting_list.begin();
    if (iter->second) {
      iter->second->second->reset();
    }

    // 保护性清理操作
    if (!event_timer_.connecting_list.empty()) {
      iter = event_timer_.connecting_list.begin();
      if (!iter->second || !iter->second->second) {
        event_timer_.connecting_list.pop_front();
      }
    }
  }

  // 重置自身的endpoint
  if (self_) {
    // 不销毁，下一次替换，保证某些接口可用
    self_->reset();
  }

  // 清空检测列表和ping列表
  flags_.set(static_cast<size_t>(flag_t::type::EN_FT_RESETTING_GC), true);
  event_timer_.pending_endpoint_gc_list.clear();
  event_timer_.pending_connection_gc_list.clear();
  {
    std::vector<endpoint::ptr_t> force_clear_endpoint;
    force_clear_endpoint.reserve(event_timer_.ping_list.size());
    // 清理ping定时器
    for (timer_desc_ls<const endpoint *, ::atfw::util::memory::weak_rc_ptr<endpoint>>::type::iterator iter =
             event_timer_.ping_list.begin();
         iter != event_timer_.ping_list.end(); ++iter) {
      if (iter->second && iter->second->second.expired()) {
        continue;
      }
      force_clear_endpoint.push_back(iter->second->second.lock());
    }

#if defined(ATBUS_MACRO_ABORT_ON_PROTECTED_ERROR) && ATBUS_MACRO_ABORT_ON_PROTECTED_ERROR
    assert(0 == force_clear_endpoint.size());
#endif

    for (size_t i = 0; i < force_clear_endpoint.size(); ++i) {
      if (force_clear_endpoint[i]) {
        force_clear_endpoint[i]->reset();
        force_clear_endpoint[i]->clear_ping_timer();
        force_clear_endpoint[i].reset();
      }
    }
    event_timer_.ping_list.clear();
  }

  // 引用的数据(正在进行的连接)也必须全部释放完成
  // 保证延迟释放的连接也释放完成
  while (!ref_objs_.empty()) {
    uv_run(get_evloop(), UV_RUN_ONCE);
  }

  // 基础数据
  iostream_channel_.reset();  // 这里结束后就不会再触发回调了
  iostream_conf_.reset();

  // 不用重置ev_loop_，其他地方还可以用
  // 只能通过init函数重新初始化来修改它
  // if (nullptr != ev_loop_) {
  //     ev_loop_ = nullptr;
  // }

  if (nullptr != static_buffer_) {
    detail::buffer_block::free(static_buffer_);
    static_buffer_ = nullptr;
  }

  conf_.flags.reset();
  state_ = state_t::type::CREATED;
  flags_.reset();

  self_data_messages_.clear();
  self_command_messages_.clear();

  return EN_ATBUS_ERR_SUCCESS;
}

ATBUS_MACRO_API int node::proc(std::chrono::system_clock::time_point now) {
  flag_guard_t fgd_proc(this, flag_t::type::EN_FT_IN_PROC);
  if (!fgd_proc) {
    return 0;
  }

  if (now > event_timer_.tick) {
    event_timer_.tick = now;
  }

  if (state_t::type::CREATED == state_) {
    return EN_ATBUS_ERR_NOT_INITED;
  }

  int ret = 0;
  // stop action happened between previous proc and this one
  if (flags_.test(static_cast<size_t>(flag_t::type::EN_FT_SHUTDOWN))) {
    ret = 1 + dispatch_all_self_messages();
    reset();
    return ret;
  }

  // TODO 以后可以优化成event_fd通知，这样就不需要轮询了
  // 点对点IO流通道
  for (std::unordered_map<std::string, connection::ptr_t>::iterator iter = proc_connections_.begin();
       iter != proc_connections_.end(); ++iter) {
    ret += iter->second->proc(*this, now);
  }

  // connection超时下线
  while (!event_timer_.connecting_list.empty()) {
    timer_desc_ls<std::string, connection::ptr_t>::type::iterator iter = event_timer_.connecting_list.begin();

    if (!iter->second) {
      event_timer_.connecting_list.erase(iter);
      continue;
    }

    if (!iter->second->second) {
      event_timer_.connecting_list.erase(iter);
      continue;
    }

    auto &timer_obj_ptr = iter->second;

    if (timer_obj_ptr->second->is_connected()) {
      timer_obj_ptr->second->remove_owner_checker();
      // 保护性清理操作
      if (!event_timer_.connecting_list.empty() && event_timer_.connecting_list.begin() == iter) {
        event_timer_.connecting_list.erase(iter);
      }
      continue;
    }

    if (timer_obj_ptr->first >= now) {
      break;
    }

    if (!timer_obj_ptr->second->check_flag(connection::flag_t::type::TEMPORARY)) {
      ATBUS_FUNC_NODE_ERROR(*this, nullptr, timer_obj_ptr->second.get(), EN_ATBUS_ERR_NODE_TIMEOUT, 0,
                            "connection {} timeout", timer_obj_ptr->second->get_address().address);
    }
    timer_obj_ptr->second->reset();

    // 保护性清理操作
    if (!event_timer_.connecting_list.empty() && event_timer_.connecting_list.begin() == iter) {
      if (event_message_.on_invalid_connection) {
        flag_guard_t fgd(this, flag_t::type::EN_FT_IN_CALLBACK);
        event_message_.on_invalid_connection(std::cref(*this), timer_obj_ptr->second.get(), EN_ATBUS_ERR_NODE_TIMEOUT);
      }
      event_timer_.connecting_list.erase(iter);
    }
  }

  // 上游节点操作
  if (0 != get_id() && !conf_.upstream_address.empty() &&
      event_timer_.upstream_op_timepoint > std::chrono::system_clock::from_time_t(0) &&
      event_timer_.upstream_op_timepoint < now) {
    // 获取命令节点
    connection *ctl_conn = nullptr;
    if (node_upstream_.node_ && self_) {
      ctl_conn = self_->get_ctrl_connection(node_upstream_.node_.get());
    }

    // 上游节点重连
    if (nullptr == ctl_conn) {
      int res = connect(conf_.upstream_address.c_str());
      if (res < 0) {
        ATBUS_FUNC_NODE_ERROR(*this, nullptr, nullptr, res, 0, "reconnect upstream node {} failed",
                              conf_.upstream_address);

        event_timer_.upstream_op_timepoint = now + conf_.retry_interval;
      } else {
        // 下一次判定上游节点连接超时再重新连接
        event_timer_.upstream_op_timepoint = now + conf_.first_idle_timeout;
        state_ = state_t::type::CONNECTING_UPSTREAM;
      }
    } else {
      if (node_upstream_.node_ && !node_upstream_.node_->is_available() &&
          node_upstream_.node_->get_stat_created_time() + conf_.first_idle_timeout < now) {
        add_endpoint_gc_list(node_upstream_.node_);
      } else {
        int res = ping_endpoint(*node_upstream_.node_);
        if (res < 0) {
          ATBUS_FUNC_NODE_ERROR(*this, nullptr, nullptr, res, 0, "ping upstream node {} failed",
                                conf_.upstream_address);
        }
      }

      // ping包不需要重试
      event_timer_.upstream_op_timepoint = now + conf_.ping_interval;
    }
  }

  // Ping包
  {
    while (true) {
      if (event_timer_.ping_list.empty()) {
        break;
      }

      timer_desc_ls<const endpoint *, ::atfw::util::memory::weak_rc_ptr<endpoint>>::type::iterator timer_iter =
          event_timer_.ping_list.begin();
      if (!timer_iter->second) {
        event_timer_.ping_list.pop_front();
        continue;
      }
      auto &timer_obj_ptr = timer_iter->second;

      std::chrono::system_clock::time_point timeout_tick = timer_obj_ptr->first;
      if (timeout_tick > now) {
        break;
      }

      endpoint::ptr_t next_ep = timer_obj_ptr->second.lock();
      if (!next_ep) {
        event_timer_.ping_list.pop_front();
        continue;
      }

      // Ping
      // 前检测有效性，如果超出最大首次空闲时间后还处于不可用状态（没有数据连接），可能是等待对方连接超时。这时候需要踢下线
      if (!next_ep->is_available() && next_ep->get_stat_created_time() + conf_.first_idle_timeout < now) {
        add_endpoint_gc_list(next_ep);
        // 多追加一次，以防万一状态错误能够自动恢复或则再次回收
        // 正常是不会触发这次的定时器的，一会回收的时候会删除掉
        next_ep->add_ping_timer();
        continue;
      }

      // 已移除对象则忽略, 上游节点使用上面的定时ping流程
      if (next_ep != node_upstream_.node_) {
        ping_endpoint(*next_ep);
      }

      // 重设定时器
      next_ep->add_ping_timer();

      // 如果endpoint对象过期了这里也要移除（保护性措施，理论上不会跑到）
      while (!event_timer_.ping_list.empty()) {
        if (!event_timer_.ping_list.front().second) {
          event_timer_.ping_list.pop_front();
          continue;
        }
        break;
      }

      if (event_timer_.ping_list.empty()) {
        break;
      }

      // 如果迭代器已经被其他流程移除了则忽略
      auto &next_timer_obj = event_timer_.ping_list.front();
      std::chrono::system_clock::time_point next_tick = next_timer_obj.second->first;
      if (next_tick > now) {
        break;
      }

      if (next_tick != timeout_tick) {
        next_ep.reset();
      } else {
        endpoint::ptr_t test_ep = next_timer_obj.second->second.lock();
        if (test_ep == next_ep) {
#if defined(ATBUS_MACRO_ABORT_ON_PROTECTED_ERROR) && ATBUS_MACRO_ABORT_ON_PROTECTED_ERROR
          assert(false);
#endif
          event_timer_.ping_list.pop_front();
          next_ep.reset();
        }
      }
    }
  }

  // dispatcher all self messages
  ret += dispatch_all_self_messages();

  // GC - endpoint
  if (!event_timer_.pending_endpoint_gc_list.empty()) {
    flag_guard_t fgd_gc_endpoints(this, flag_t::type::EN_FT_IN_GC_ENDPOINTS);
    std::list<endpoint::ptr_t> checked;
    checked.swap(event_timer_.pending_endpoint_gc_list);

    for (std::list<endpoint::ptr_t>::iterator iter = checked.begin(); iter != checked.end(); ++iter) {
      if (*iter) {
        if (false == (*iter)->is_available()) {
          (*iter)->reset();
          ATBUS_FUNC_NODE_INFO(*this, (*iter).get(), nullptr, "endpoint gc timeout and reset");
          remove_endpoint((*iter)->get_id(), (*iter).get());
        }
      }
    }

    // 再清理一次，因为endpoint::reset可能触发进入pending_endpoint_gc_list
    event_timer_.pending_endpoint_gc_list.clear();
  }

  // GC - connection
  if (!event_timer_.pending_connection_gc_list.empty()) {
    flag_guard_t fgd_gc_connections(this, flag_t::type::EN_FT_IN_GC_CONNECTIONS);
    event_timer_.pending_connection_gc_list.clear();
  }

  // stop action happened in any callback
  if (flags_.test(static_cast<size_t>(flag_t::type::EN_FT_SHUTDOWN))) {
    reset();
    return ret + 1;
  }

  return ret;
}

ATBUS_MACRO_API int node::poll() {
  flag_guard_t fgd_poll(this, flag_t::type::EN_FT_IN_POLL);
  if (!fgd_poll) {
    return 0;
  }

  // stop action happened between previous proc and this one
  if (flags_.test(static_cast<size_t>(flag_t::type::EN_FT_SHUTDOWN))) {
    int ret = 1 + dispatch_all_self_messages();
    reset();
    return ret;
  }

  // point to point IO stream channels
  int loop_left = conf_.loop_times;
  size_t stat_dispatch = stat_.dispatch_times;
  while (iostream_channel_ && loop_left > 0 &&
         EN_ATBUS_ERR_EV_RUN == channel::io_stream_run(get_iostream_channel(), adapter::run_mode_t::RUN_NOWAIT)) {
    --loop_left;
  }

  int ret = static_cast<int>(stat_.dispatch_times - stat_dispatch);

  // dispatcher all self messages
  ret += dispatch_all_self_messages();

  // GC - endpoint
  if (!event_timer_.pending_endpoint_gc_list.empty()) {
    flag_guard_t fgd_gc_endpoints(this, flag_t::type::EN_FT_IN_GC_ENDPOINTS);
    std::list<endpoint::ptr_t> checked;
    checked.swap(event_timer_.pending_endpoint_gc_list);

    for (std::list<endpoint::ptr_t>::iterator iter = checked.begin(); iter != checked.end(); ++iter) {
      if (*iter) {
        if (false == (*iter)->is_available()) {
          (*iter)->reset();
          ATBUS_FUNC_NODE_DEBUG(*this, (*iter).get(), nullptr, nullptr, "endpoint handshake timeout and reset");
          remove_endpoint((*iter)->get_id(), (*iter).get());
        }
      }
    }

    // 再清理一次，因为endpoint::reset可能触发进入pending_endpoint_gc_list
    event_timer_.pending_endpoint_gc_list.clear();
  }

  // GC - connection
  if (!event_timer_.pending_connection_gc_list.empty()) {
    flag_guard_t fgd_gc_connections(this, flag_t::type::EN_FT_IN_GC_CONNECTIONS);
    event_timer_.pending_connection_gc_list.clear();
  }

  // stop action happened in any callback
  if (flags_.test(static_cast<size_t>(flag_t::type::EN_FT_SHUTDOWN))) {
    reset();
    return ret + 1;
  }

  return ret;
}

ATBUS_MACRO_API int node::listen(gsl::string_view addr_str) {
  if (state_t::type::CREATED == state_) {
    return EN_ATBUS_ERR_NOT_INITED;
  }

  if (!self_) {
    return EN_ATBUS_ERR_NOT_INITED;
  }

  connection::ptr_t conn = connection::create(this, addr_str);
  if (!conn) {
    return EN_ATBUS_ERR_MALLOC;
  }

  int ret = conn->listen();
  if (ret < 0) {
    return ret;
  }

  // 添加到self_里
  if (false == self_->add_connection(conn.get(), false)) {
    return EN_ATBUS_ERR_ALREADY_INITED;
  }

  // 记录监听地址
  self_->add_listen(conn->get_address().address);

  ATBUS_FUNC_NODE_DEBUG(*this, self_.get(), conn.get(), nullptr, "listen to {} success", addr_str);

  return EN_ATBUS_ERR_SUCCESS;
}

ATBUS_MACRO_API int node::connect(gsl::string_view addr_str) {
  if (state_t::type::CREATED == state_) {
    return EN_ATBUS_ERR_NOT_INITED;
  }

  // if there is already connection of this addr not completed, just return success
  auto iter = event_timer_.connecting_list.find(std::string{addr_str}, false);
  if (iter != event_timer_.connecting_list.end()) {
    if (iter->second && iter->second->second && !iter->second->second->is_connected()) {
      return EN_ATBUS_ERR_SUCCESS;
    }
  }

  connection::ptr_t conn = connection::create(this, addr_str);
  if (!conn) {
    return EN_ATBUS_ERR_MALLOC;
  }

  // 内存通道和共享内存通道不允许协商握手，必须直接指定endpoint
  if (addr_str.size() >= 4 && 0 == UTIL_STRFUNC_STRNCASE_CMP("mem:", addr_str.data(), 4)) {
    return EN_ATBUS_ERR_ACCESS_DENY;
  } else if (addr_str.size() >= 4 && 0 == UTIL_STRFUNC_STRNCASE_CMP("shm:", addr_str.data(), 4)) {
    return EN_ATBUS_ERR_ACCESS_DENY;
  }

  int ret = conn->connect();
  if (ret < 0) {
    return ret;
  }

  ATBUS_FUNC_NODE_DEBUG(*this, nullptr, conn.get(), nullptr, "connect to {} success", addr_str);

  return EN_ATBUS_ERR_SUCCESS;
}

ATBUS_MACRO_API int node::connect(gsl::string_view addr_str, endpoint *ep) {
  if (state_t::type::CREATED == state_) {
    return EN_ATBUS_ERR_NOT_INITED;
  }

  if (nullptr == ep) {
    return EN_ATBUS_ERR_PARAMS;
  }

  // if there is already connection of this addr not completed, just return success
  auto iter = event_timer_.connecting_list.find(std::string{addr_str}, false);
  if (iter != event_timer_.connecting_list.end()) {
    if (iter->second && iter->second->second && !iter->second->second->is_connected() &&
        iter->second->second->get_binding() == ep) {
      return EN_ATBUS_ERR_SUCCESS;
    }
  }

  connection::ptr_t conn = connection::create(this, addr_str);
  if (!conn) {
    return EN_ATBUS_ERR_MALLOC;
  }

  int ret = conn->connect();
  if (ret < 0) {
    return ret;
  }

  ATBUS_FUNC_NODE_DEBUG(*this, ep, conn.get(), nullptr, "connect to {} and bind to a endpoint {} success", addr_str,
                        ep->get_id());

  if (addr_str.size() >= 4 && (0 == UTIL_STRFUNC_STRNCASE_CMP("mem:", addr_str.data(), 4) ||
                               0 == UTIL_STRFUNC_STRNCASE_CMP("shm:", addr_str.data(), 4))) {
    if (ep->add_connection(conn.get(), true)) {
      return EN_ATBUS_ERR_SUCCESS;
    }
  } else {
    if (ep->add_connection(conn.get(), false)) {
      return EN_ATBUS_ERR_SUCCESS;
    }
  }

  return EN_ATBUS_ERR_BAD_DATA;
}

ATBUS_MACRO_API int node::disconnect(bus_id_t id) {
  if (node_upstream_.node_ && id == node_upstream_.node_->get_id()) {
    endpoint::ptr_t ep_ptr;
    ep_ptr.swap(node_upstream_.node_);

    // event
    if (event_message_.on_endpoint_removed) {
      flag_guard_t fgd(this, flag_t::type::EN_FT_IN_CALLBACK);
      event_message_.on_endpoint_removed(std::cref(*this), ep_ptr.get(), EN_ATBUS_ERR_SUCCESS);
    }

    ep_ptr->reset();
    return EN_ATBUS_ERR_SUCCESS;
  }

  endpoint *ep = find_route(node_route_, id);
  if (nullptr != ep && ep->get_id() == id) {
    endpoint::ptr_t ep_ptr = ep->watch();

    // 移除连接关系
    remove_child(node_route_, id);

    ep_ptr->reset();
    return EN_ATBUS_ERR_SUCCESS;
  }

  return EN_ATBUS_ERR_ATNODE_NOT_FOUND;
}

ATBUS_MACRO_API protocol::ATBUS_CRYPTO_KEY_EXCHANGE_TYPE node::get_crypto_key_exchange_type() const noexcept {
  return crypto_key_exchange_type_;
}

ATBUS_MACRO_API const ::atfw::util::crypto::dh::shared_context::ptr_t &node::get_crypto_key_exchange_context()
    const noexcept {
  return crypto_key_exchange_context_;
}

ATBUS_MACRO_API int node::send_data(bus_id_t tid, int type, gsl::span<const unsigned char> data) {
  send_data_options_t options;
  return send_data(tid, type, data, options);
}

ATBUS_MACRO_API int node::send_data(bus_id_t tid, int type, gsl::span<const unsigned char> data,
                                    send_data_options_t &options) {
  if (state_t::type::CREATED == state_) {
    return EN_ATBUS_ERR_NOT_INITED;
  }

  if (data.size() > conf_.message_size) {
    return EN_ATBUS_ERR_INVALID_SIZE;
  }

  ::ATBUS_MACRO_PROTOBUF_NAMESPACE_ID::ArenaOptions arena_options;
  arena_options.initial_block_size = ATBUS_MACRO_RESERVED_SIZE;
  message m{arena_options};

  atbus::protocol::message_head &head = m.mutable_head();
  atbus::protocol::forward_data *body = m.mutable_body().mutable_data_transform_req();
  if (nullptr == body) {
    ATBUS_FUNC_NODE_ERROR(*this, nullptr, nullptr, EN_ATBUS_ERR_UNPACK, EN_ATBUS_ERR_MALLOC,
                          "failed to allocate forward_data");
    return EN_ATBUS_ERR_MALLOC;
  }

  uint64_t self_id = get_id();
  uint32_t flags = 0;
  if (options.check_flag(send_data_options_t::flag_type::EN_SDOPT_REQUIRE_RESPONSE)) {
    flags |= atbus::protocol::FORWARD_DATA_FLAG_REQUIRE_RSP;
  }

  // all transfer message must be send by a verified connect, there is no need to check access token again

  head.set_version(get_protocol_version());
  head.set_type(type);
  head.set_source_bus_id(self_id);
  if (0 == options.sequence) {
    options.sequence = allocate_message_sequence();
  }
  head.set_sequence(options.sequence);

  body->set_from(self_id);
  body->set_to(tid);
  body->add_router(self_id);
  body->mutable_content()->assign(reinterpret_cast<const char *>(data.data()), data.size());
  body->set_flags(flags);

  return send_data_message(tid, m);
}

ATBUS_MACRO_API int node::send_custom_command(bus_id_t tid, gsl::span<gsl::span<const unsigned char>> args) {
  send_data_options_t options;
  return send_custom_command(tid, args, options);
}

ATBUS_MACRO_API int node::send_custom_command(bus_id_t tid, gsl::span<gsl::span<const unsigned char>> args,
                                              send_data_options_t &options) {
  if (state_t::type::CREATED == state_) {
    return EN_ATBUS_ERR_NOT_INITED;
  }

  size_t sum_len = 0;
  for (const auto &arg : args) {
    sum_len += arg.size();
  }

  if (sum_len > conf_.message_size) {
    return EN_ATBUS_ERR_INVALID_SIZE;
  }

  ::ATBUS_MACRO_PROTOBUF_NAMESPACE_ID::ArenaOptions arena_options;
  arena_options.initial_block_size = ATBUS_MACRO_RESERVED_SIZE;
  ::ATBUS_MACRO_PROTOBUF_NAMESPACE_ID::Arena arena(arena_options);
  message m{arena_options};

  atbus::protocol::message_head &head = m.mutable_head();
  atbus::protocol::custom_command_data *body = m.mutable_body().mutable_custom_command_req();
  if (nullptr == body) {
    ATBUS_FUNC_NODE_ERROR(*this, nullptr, nullptr, EN_ATBUS_ERR_UNPACK, EN_ATBUS_ERR_MALLOC,
                          "failed to allocate custom command");
    return EN_ATBUS_ERR_MALLOC;
  }

  uint64_t self_id = get_id();
  if (0 == options.sequence) {
    options.sequence = allocate_message_sequence();
  }
  head.set_sequence(options.sequence);

  head.set_version(get_protocol_version());
  head.set_source_bus_id(self_id);

  body->set_from(self_id);
  body->mutable_commands()->Reserve(static_cast<int>(args.size()));
  for (const auto &arg : args) {
    ::atframework::atbus::protocol::custom_command_argv *arg_ptr = body->add_commands();
    if (nullptr == arg_ptr) {
      continue;
    }

    arg_ptr->mutable_arg()->assign(reinterpret_cast<const char *>(arg.data()), arg.size());
  }

  if (!get_conf().access_tokens.empty()) {
    body->mutable_access_key();
    message_handler::generate_access_data(
        *body->mutable_access_key(), self_id, static_cast<uint64_t>(random_engine_.random()),
        static_cast<uint64_t>(random_engine_.random()), gsl::make_span(get_conf().access_tokens), *body);
  }

  return send_data_message(tid, m);
}

ATBUS_MACRO_API ATBUS_ERROR_TYPE node::get_peer_channel(bus_id_t tid, endpoint::get_connection_fn_t fn,
                                                        endpoint **ep_out, connection **conn_out,
                                                        get_peer_options_t options) {
  if (!self_) {
    return EN_ATBUS_ERR_NOT_INITED;
  }

#define ASSIGN_EPCONN()                    \
  if (nullptr != ep_out) *ep_out = target; \
  if (nullptr != conn_out) *conn_out = conn

  endpoint *target = nullptr;
  connection *conn = nullptr;

  ASSIGN_EPCONN();

  if (state_t::type::CREATED == state_) {
    return EN_ATBUS_ERR_NOT_INITED;
  }

  if (tid == get_id()) {
    return EN_ATBUS_ERR_ATNODE_INVALID_ID;
  }

  do {
    // 上游节点
    if (node_upstream_.node_ && node_upstream_.node_->get_id() == tid) {
      target = node_upstream_.node_.get();
      conn = (self_.get()->*fn)(target);

      ASSIGN_EPCONN();
      break;
    }

    // 直连节点
    target = find_route(node_route_, tid);
    if (nullptr != target) {
      conn = (self_.get()->*fn)(target);

      ASSIGN_EPCONN();
      break;
    }

    topology_peer::ptr_t next_hop_peer = nullptr;
    topology_relation_type relation = get_topology_relation(tid, &next_hop_peer);
    // 子节点
    if (relation == topology_relation_type::kImmediateDownstream ||
        relation == topology_relation_type::kTransitiveDownstream) {
      if (!next_hop_peer) {
        return EN_ATBUS_ERR_ATNODE_INVALID_ID;
      }
      target = find_route(node_route_, next_hop_peer->get_bus_id());
      if (nullptr != target) {
        conn = (self_.get()->*fn)(target);

        ASSIGN_EPCONN();
        break;
      } else {
        return EN_ATBUS_ERR_ATNODE_INVALID_ID;
      }
    }

    // 只有邻居节点,远方节点,间接上游都可以走上游节点。有个特殊情况是未注册拓扑关系视为远方节点，也允许走上游节点
    if (relation == topology_relation_type::kSelf) {
      return EN_ATBUS_ERR_ATNODE_INVALID_ID;
    }

    // 自动发现邻居路由
    /**
     *     F1 ----主动连接---- F2
     *    /  \                /  \
     *  C11  C12            C21  C22
     * 当C11/F1发往C21或C22时触发这种情况
     */
    if (relation == topology_relation_type::kOtherUpstreamPeer && topology_registry_) {
      auto find_nearest_neighbour_peer = topology_registry_->get_peer(tid);
      if (find_nearest_neighbour_peer) {
        find_nearest_neighbour_peer = find_nearest_neighbour_peer->get_upstream();
      }
      while (find_nearest_neighbour_peer) {
        target = find_route(node_route_, find_nearest_neighbour_peer->get_bus_id());
        if (nullptr != target) {
          conn = (self_.get()->*fn)(target);

          ASSIGN_EPCONN();
          break;
        }
        find_nearest_neighbour_peer = find_nearest_neighbour_peer->get_upstream();
      }
      if (nullptr != target) {
        break;
      }
    }

    // Fallback到上游转发
    /**
     *     F1
     *    /  \
     *  C11  C12
     * 当C11发往C12时触发这种情况
     */
    if (!options.check_flag(get_peer_options_t::option_type::EN_GPOPT_NO_UPSTREAM) && node_upstream_.node_) {
      target = node_upstream_.node_.get();
      conn = (self_.get()->*fn)(target);

      ASSIGN_EPCONN();
      break;
    }
  } while (false);

#undef ASSIGN_EPCONN

  if (nullptr == target) {
    return EN_ATBUS_ERR_ATNODE_INVALID_ID;
  }

  if (nullptr == conn) {
    return EN_ATBUS_ERR_ATNODE_NO_CONNECTION;
  }

  return EN_ATBUS_ERR_SUCCESS;
}

ATBUS_MACRO_API void node::set_topology_upstream(bus_id_t tid) {
  // 上游节点已经设置了，那拓扑关系也一定是一样的
  if (node_upstream_.node_ && node_upstream_.node_->get_id() == tid) {
    return;
  }

  // 当前节点是临时节点的话，不用处理拓扑关系
  bus_id_t self_id = get_id();
  if (self_id == 0 || !topology_registry_) {
    return;
  }

  // 初始化先复制一份，后面再更新
  topology_peer::ptr_t self_topology = topology_registry_->get_peer(self_id);

  // 上游未变化则直接跳过
  if (self_topology) {
    if (tid == 0 && !self_topology->get_upstream()) {
      return;
    } else if (tid != 0 && self_topology->get_upstream() && self_topology->get_upstream()->get_bus_id() == tid) {
      return;
    }
  }

  // 不合法的上游关系则跳过
  if (!topology_registry_->update_peer(self_id, tid, nullptr)) {
    return;
  }

  // 更新上游 endpoint
  if (node_upstream_.node_) {
    insert_child(node_route_, node_upstream_.node_, true);
  }

  if (tid == 0) {
    node_upstream_.node_.reset();
  } else {
    node_upstream_.node_ = find_route(node_route_, tid);
    if (node_upstream_.node_) {
      remove_child(node_route_, tid, nullptr, true);
    }
  }

  // event
  if (event_message_.on_topology_update_upstream) {
    topology_peer::ptr_t upstream;
    if (tid != 0) {
      upstream = topology_registry_->get_peer(tid);
    }
    if (!self_topology) {
      self_topology = topology_registry_->get_peer(self_id);
    }
    flag_guard_t fgd(this, flag_t::type::EN_FT_IN_CALLBACK);
    event_message_.on_topology_update_upstream(std::cref(*this), self_topology, upstream, topology_);
  }
}

ATBUS_MACRO_API endpoint *node::get_endpoint(bus_id_t tid) noexcept {
  if (node_upstream_.node_ && node_upstream_.node_->get_id() == tid) {
    return node_upstream_.node_.get();
  }

  endpoint *res = find_route(node_route_, tid);
  if (nullptr != res && res->get_id() == tid) {
    return res;
  }

  return nullptr;
}

ATBUS_MACRO_API const endpoint *node::get_endpoint(bus_id_t tid) const noexcept {
  return const_cast<node *>(this)->get_endpoint(tid);
}

ATBUS_MACRO_API ATBUS_ERROR_TYPE node::add_endpoint(endpoint::ptr_t ep) {
  if (!ep) {
    return EN_ATBUS_ERR_PARAMS;
  }

  if (flags_.test(static_cast<size_t>(flag_t::type::EN_FT_RESETTING))) {
    return EN_ATBUS_ERR_CLOSING;
  }

  if (!self_) {
    return EN_ATBUS_ERR_NOT_INITED;
  }

  if (this != ep->get_owner()) {
    return EN_ATBUS_ERR_PARAMS;
  }

  // 快速更新上游
  bool is_update_upstream = false;
  if (node_upstream_.node_) {
    if (node_upstream_.node_ == ep) {
      return EN_ATBUS_ERR_SUCCESS;
    }
    if (node_upstream_.node_->get_id() == ep->get_id()) {
      is_update_upstream = true;
    }
  }

  if (!is_update_upstream && 0 != get_id() && topology_registry_) {
    topology_peer::ptr_t peer = topology_registry_->get_peer(get_id());
    if (peer && peer->get_upstream()) {
      bus_id_t upstream_id = peer->get_upstream()->get_bus_id();
      if (upstream_id == ep->get_id()) {
        is_update_upstream = true;
      }
    }
  }

  // 上游节点单独判定
  if (is_update_upstream) {
    node_upstream_.node_ = ep;

    if (!ep->get_flag(endpoint::flag_t::type::HAS_PING_TIMER)) {
      ep->add_ping_timer();
    }

    if ((state_t::type::LOST_UPSTREAM == get_state() || state_t::type::CONNECTING_UPSTREAM == get_state()) &&
        check_flag(flag_t::type::EN_FT_UPSTREAM_REG_DONE)) {
      // 这里是自己先注册到上游节点，然后才完成上游节点对自己的注册流程，在message_handler::on_recv_node_reg_rsp里已经标记
      // EN_FT_UPSTREAM_REG_DONE 了
      on_actived();
    }

    // event
    if (event_message_.on_endpoint_added) {
      flag_guard_t fgd(this, flag_t::type::EN_FT_IN_CALLBACK);
      event_message_.on_endpoint_added(std::cref(*this), ep.get(), EN_ATBUS_ERR_SUCCESS);
    }

    return EN_ATBUS_ERR_SUCCESS;
  }

  if (insert_child(node_route_, ep)) {
    ep->add_ping_timer();

    return EN_ATBUS_ERR_SUCCESS;
  } else {
    return EN_ATBUS_ERR_ATNODE_MASK_CONFLICT;
  }
}

ATBUS_MACRO_API ATBUS_ERROR_TYPE node::remove_endpoint(bus_id_t tid) { return remove_endpoint(tid, nullptr); }

ATBUS_MACRO_API bool node::is_endpoint_available(bus_id_t tid) const {
  if (!flags_.test(static_cast<size_t>(flag_t::type::EN_FT_ACTIVED))) {
    return false;
  }

  if (!self_) {
    return false;
  }

  endpoint *ep = const_cast<endpoint *>(get_endpoint(tid));
  if (nullptr == ep) {
    return false;
  }

  return 0 == get_id() || nullptr != self_->get_data_connection(ep, false);
}

ATBUS_MACRO_API bool node::check_access_hash(const ::atframework::atbus::protocol::access_data &access_key,
                                             atfw::util::nostd::string_view plaintext, connection *conn) const {
  const endpoint *ep = conn == nullptr ? nullptr : conn->get_binding();
  if (access_key.algorithm() != ::atframework::atbus::protocol::ATBUS_ACCESS_DATA_ALGORITHM_HMAC_SHA256) {
    ATBUS_FUNC_NODE_ERROR(*this, ep, conn, EN_ATBUS_ERR_ALGORITHM_NOT_SUPPORT, 0,
                          "access hash algorithm {} not supported", static_cast<int>(access_key.algorithm()));
    return false;
  }

  if (conf_.access_tokens.empty() && access_key.signature().empty()) {
    return true;
  }

  if (conf_.access_tokens.empty()) {
    ATBUS_FUNC_NODE_ERROR(
        *this, ep, conn, EN_ATBUS_ERR_ACCESS_DENY, 0,
        "access hash configuration is empty; we do not allow handshaking an endpoint with a signature.");
    return false;
  }

  if (access_key.signature().empty()) {
    ATBUS_FUNC_NODE_ERROR(*this, ep, conn, EN_ATBUS_ERR_ACCESS_DENY, 0,
                          "access hash configuration is not empty; signature is required.");
    return false;
  }

  // TODO(owent): 如果要阻挡重放攻击，需要验证和记录近期的nonce重复，也需要保证生成nonce的算法保证在一段时间内不重复

  const EVP_MD *evp_md = EVP_sha256();
  if (nullptr == evp_md) {
    ATBUS_FUNC_NODE_ERROR(*this, ep, conn, EN_ATBUS_ERR_NOT_INITED, EN_ATBUS_ERR_NOT_INITED, "sha256 unavailabled.");
    return false;
  }

  for (const auto &access_token : conf_.access_tokens) {
    std::string real_signature = message_handler::calculate_access_data_signature(
        access_key, gsl::make_span(access_token.data(), access_token.size()), plaintext);
    for (const auto &expect_signature : access_key.signature()) {
      if (real_signature == expect_signature) {
        return true;
      }
    }
  }

  ATBUS_FUNC_NODE_ERROR(*this, ep, conn, EN_ATBUS_ERR_ACCESS_DENY, 0, "no valid access hash found.");
  return false;
}

ATBUS_MACRO_API const std::string &node::get_hash_code() const { return hash_code_; }

ATBUS_MACRO_API channel::io_stream_channel *node::get_iostream_channel() {
  if (iostream_channel_) {
    return iostream_channel_.get();
  }
  iostream_channel_.reset(new channel::io_stream_channel());

  channel::io_stream_init(iostream_channel_.get(), get_evloop(), get_iostream_conf());
  iostream_channel_->data = this;

  // callbacks
  iostream_channel_->evt.callbacks[static_cast<size_t>(channel::io_stream_callback_event_t::ios_fn_t::EN_FN_ACCEPTED)] =
      connection::iostream_on_accepted;
  iostream_channel_->evt
      .callbacks[static_cast<size_t>(channel::io_stream_callback_event_t::ios_fn_t::EN_FN_CONNECTED)] =
      connection::iostream_on_connected;
  iostream_channel_->evt
      .callbacks[static_cast<size_t>(channel::io_stream_callback_event_t::ios_fn_t::EN_FN_DISCONNECTED)] =
      connection::iostream_on_disconnected;
  iostream_channel_->evt.callbacks[static_cast<size_t>(channel::io_stream_callback_event_t::ios_fn_t::EN_FN_RECEIVED)] =
      connection::iostream_on_receive_cb;
  iostream_channel_->evt.callbacks[static_cast<size_t>(channel::io_stream_callback_event_t::ios_fn_t::EN_FN_WRITEN)] =
      connection::iostream_on_written;

  return iostream_channel_.get();
}

ATBUS_MACRO_API const endpoint *node::get_self_endpoint() const { return self_ ? self_.get() : nullptr; }

ATBUS_MACRO_API const endpoint *node::get_upstream_endpoint() const { return node_upstream_.node_.get(); }

ATBUS_MACRO_API const node::endpoint_collection_t &node::get_immediate_endpoint_set() const { return node_route_; };

ATBUS_MACRO_API adapter::loop_t *node::get_evloop() {
  // if just created, do not alloc new event loop
  if (state_t::type::CREATED == state_) {
    return ev_loop_;
  }

  if (nullptr != ev_loop_) {
    return ev_loop_;
  }

  if (nullptr != conf_.ev_loop) {
    return ev_loop_ = conf_.ev_loop;
  }

  ev_loop_ = uv_default_loop();
  return ev_loop_;
}

ATBUS_MACRO_API bus_id_t node::get_id() const { return self_ ? self_->get_id() : 0; }
ATBUS_MACRO_API const node::conf_t &node::get_conf() const { return conf_; }

ATBUS_MACRO_API bool node::check_flag(flag_t::type f) const { return flags_.test(static_cast<size_t>(f)); }
ATBUS_MACRO_API node::state_t::type node::get_state() const { return state_; }

ATBUS_MACRO_API node::ptr_t node::get_watcher() { return watcher_.lock(); }

ATBUS_MACRO_API const ::atfw::util::nostd::nonnull<topology_registry::ptr_t> &node::get_topology_registry()
    const noexcept {
  return topology_registry_;
}

ATBUS_MACRO_API topology_relation_type node::get_topology_relation(bus_id_t id,
                                                                   topology_peer::ptr_t *next_hop_peer) const noexcept {
  // 临时节点都是直连
  if (0 == get_id() || !self_) {
    return topology_relation_type::kOtherUpstreamPeer;
  }

  if (id == get_id()) {
    if (next_hop_peer != nullptr && topology_registry_) {
      *next_hop_peer = topology_registry_->get_peer(get_id());
    }
    return topology_relation_type::kSelf;
  }

  topology_relation_type ret = topology_relation_type::kInvalid;
  if (topology_registry_) {
    ret = topology_registry_->get_relation(get_id(), id, next_hop_peer);
  }

  if (ret == topology_relation_type::kInvalid) {
    if (node_upstream_.node_ && id == node_upstream_.node_->get_id()) {
      ret = topology_relation_type::kImmediateUpstream;
    } else if (nullptr != get_endpoint(id)) {
      ret = topology_relation_type::kOtherUpstreamPeer;
    }
  }

  return ret;
}

ATBUS_MACRO_API int node::get_pid() {
#ifdef _MSC_VER
  return _getpid();
#else
  return getpid();
#endif
}

static std::string &host_name_buffer() {
  static std::string server_addr;
  return server_addr;
}

ATBUS_MACRO_API const std::string &node::get_hostname() {
  std::string &hn = host_name_buffer();
  if (!hn.empty()) {
    return hn;
  }

  // use sorted mac address first, hostname is too easy to conflict
  {
    std::vector<std::string> all_outter_inters;
    uv_interface_address_t *interface_addrs = nullptr;
    int interface_sz = 0;
    size_t total_size = 0;
    uv_interface_addresses(&interface_addrs, &interface_sz);
    for (int i = 0; i < interface_sz; ++i) {
      uv_interface_address_t *inter_addr = interface_addrs + i;
      if (inter_addr->is_internal) {
        continue;
      }

      std::string one_addr;
      size_t dump_index = 0;
      while (dump_index < sizeof(inter_addr->phys_addr) && 0 == inter_addr->phys_addr[dump_index]) {
        ++dump_index;
      }
      if (dump_index < sizeof(inter_addr->phys_addr)) {
        one_addr.resize((sizeof(inter_addr->phys_addr) - dump_index) * 2);
        atfw::util::string::dumphex(inter_addr->phys_addr + dump_index, (sizeof(inter_addr->phys_addr) - dump_index),
                                    &one_addr[0]);
      }

      if (!one_addr.empty()) {
        all_outter_inters.push_back(one_addr);
        total_size += one_addr.size();
      }
    }

    if (total_size > 0) {
      hn.reserve(total_size + all_outter_inters.size());
    }

    std::sort(all_outter_inters.begin(), all_outter_inters.end());
    std::vector<std::string>::iterator new_end = std::unique(all_outter_inters.begin(), all_outter_inters.end());
    all_outter_inters.erase(new_end, all_outter_inters.end());
    for (size_t i = 0; i < all_outter_inters.size(); ++i) {
      if (i > 0) {
        hn += ":";
      }
      hn += all_outter_inters[i];
    }

    if (nullptr != interface_addrs) {
      uv_free_interface_addresses(interface_addrs, interface_sz);
    }
  }

  if (!hn.empty()) {
    return hn;
  }

  // @see man gethostname
  // 255 or less in posix standard
  // 64 in linux(defined as HOST_NAME_MAX)
  // 256 or less in windows(https://msdn.microsoft.com/en-us/library/windows/desktop/ms738527(v=vs.85).aspx)
  char buffer[256] = {0};
  if (0 == gethostname(buffer, sizeof(buffer))) {
    hn = buffer;
  }
#ifdef _MSC_VER
  else {
    if (WSANOTINITIALISED == WSAGetLastError()) {
      WSADATA wsaData;
      WORD version = MAKEWORD(2, 0);
      if (0 == WSAStartup(version, &wsaData) && 0 == gethostname(buffer, sizeof(buffer))) {
        hn = buffer;
      }
    }
  }
#endif

  return hn;
}

ATBUS_MACRO_API bool node::set_hostname(gsl::string_view hn, bool force) {
  std::string &h = host_name_buffer();
  if (force || h.empty()) {
    h = std::string(hn);
    return true;
  }

  return false;
}

ATBUS_MACRO_API int32_t node::get_protocol_version() const { return conf_.protocol_version; }

ATBUS_MACRO_API int32_t node::get_protocol_minimal_version() const { return conf_.protocol_minimal_version; }

ATBUS_MACRO_API const std::list<channel::channel_address_t> &node::get_listen_list() const {
  UTIL_LIKELY_IF (self_) {
    return self_->get_listen();
  }

  static std::list<channel::channel_address_t> empty;
  return empty;
}

ATBUS_MACRO_API bool node::add_proc_connection(connection::ptr_t conn) {
  if (state_t::type::CREATED == state_) {
    return false;
  }

  if (!conn || conn->get_address().address.empty() ||
      proc_connections_.end() != proc_connections_.find(conn->get_address().address)) {
    return false;
  }

  proc_connections_[conn->get_address().address] = conn;
  return true;
}

ATBUS_MACRO_API bool node::remove_proc_connection(const std::string &conn_key) {
  std::unordered_map<std::string, connection::ptr_t>::iterator iter = proc_connections_.find(conn_key);
  if (iter == proc_connections_.end()) {
    return false;
  }

  proc_connections_.erase(iter);
  return true;
}

ATBUS_MACRO_API bool node::add_connection_timer(connection::ptr_t conn) {
  if (state_t::type::CREATED == state_) {
    return false;
  }

  if (!conn) {
    return false;
  }

  // 如果处于握手阶段，发送节点关系逻辑并加入握手连接池并加入超时判定池
  if (false == conn->is_connected()) {
    event_timer_.connecting_list.insert_key_value(conn->get_address().address,
                                                  std::make_pair(event_timer_.tick + conf_.first_idle_timeout, conn));
  }

  return true;
}

ATBUS_MACRO_API bool node::remove_connection_timer(const connection *conn) {
  if (conn == nullptr) {
    return false;
  }

  auto iter = event_timer_.connecting_list.find(conn->get_address().address, false);
  if (iter == event_timer_.connecting_list.end()) {
    return false;
  }
  if (!iter->second) {
    event_timer_.connecting_list.erase(iter);
    return false;
  }
  if (iter->second->second.get() != conn) {
    return false;
  }

  if (event_message_.on_invalid_connection && !iter->second->second->is_connected()) {
    // 确认的临时连接断开不属于无效连接
    if (!iter->second->second->check_flag(connection::flag_t::type::TEMPORARY) ||
        !iter->second->second->check_flag(connection::flag_t::type::PEER_CLOSED)) {
      flag_guard_t fgd(this, flag_t::type::EN_FT_IN_CALLBACK);
      event_message_.on_invalid_connection(std::cref(*this), iter->second->second.get(), EN_ATBUS_ERR_NODE_TIMEOUT);
    }
  }

  event_timer_.connecting_list.erase(iter);
  return true;
}

ATBUS_MACRO_API size_t node::get_connection_timer_size() const { return event_timer_.connecting_list.size(); }

ATBUS_MACRO_API std::chrono::system_clock::time_point node::get_timer_tick() const { return event_timer_.tick; }

ATBUS_MACRO_API void node::on_receive_message(connection *conn, message &&m, int status, ATBUS_ERROR_TYPE errcode) {
  if (status < 0 || errcode < 0) {
    gsl::string_view conn_addr;
    if (conn != nullptr) {
      conn_addr = conn->get_address().address;
    }
    ATBUS_FUNC_NODE_ERROR(*this, nullptr, conn, status, errcode, "receive message from {} failed", conn_addr);

    if (nullptr != conn) {
      // maybe removed all reference of this connection after call add_endpoint_fault()
      connection::ptr_t conn_sptr = conn->watch();
      endpoint *ep = conn->get_binding();
      if (nullptr != ep) {
        add_endpoint_fault(*ep);
      }
      if (conn_sptr) {
        add_connection_fault(*conn);
      }
    }
    return;
  }

  connection::ptr_t conn_sptr;
  if (nullptr != conn) {
    conn_sptr = conn->watch();
  }
  // 内部协议处理
  int res = message_handler::dispatch_message(*this, conn, std::move(m), status, errcode);
  if (res < 0) {
    if (nullptr != conn) {
      // maybe removed all reference of this connection after call add_endpoint_fault()
      endpoint *ep = conn->get_binding();
      if (nullptr != ep) {
        add_endpoint_fault(*ep);
      }
      if (conn_sptr) {
        add_connection_fault(*conn);
      }
    }

    return;
  }

  if (nullptr != conn) {
    endpoint *ep = conn->get_binding();
    if (nullptr != ep) {
      ep->clear_stat_fault();
    }
    conn->clear_stat_fault();
  }
}

ATBUS_MACRO_API void node::on_receive_data(const endpoint *ep, connection *conn, const ::atframework::atbus::message &m,
                                           gsl::span<const unsigned char> data) const {
  if (nullptr == ep && nullptr != conn) {
    ep = conn->get_binding();
  }

  if (event_message_.on_forward_request) {
    flag_guard_t fgd(this, flag_t::type::EN_FT_IN_CALLBACK);
    event_message_.on_forward_request(std::cref(*this), ep, conn, std::cref(m), data);
  }
}

ATBUS_MACRO_API void node::on_receive_forward_response(const endpoint *ep, const connection *conn,
                                                       const ::atframework::atbus::message *m) {
  if (event_message_.on_forward_response) {
    flag_guard_t fgd(this, flag_t::type::EN_FT_IN_CALLBACK);
    event_message_.on_forward_response(std::cref(*this), ep, conn, m);
  }
}

ATBUS_MACRO_API ATBUS_ERROR_TYPE node::on_disconnect(const connection *conn) {
  if (nullptr == conn) {
    return EN_ATBUS_ERR_PARAMS;
  }

  // 上游节点断线逻辑则重置状态
  if (state_t::type::CONNECTING_UPSTREAM == state_ && !conf_.upstream_address.empty() &&
      conf_.upstream_address == conn->get_address().address) {
    state_ = state_t::type::LOST_UPSTREAM;

    // set reconnect to upstream into retry interval
    event_timer_.upstream_op_timepoint = get_timer_tick() + conf_.retry_interval;

    // if not activited, shutdown
    if (!flags_.test(static_cast<size_t>(flag_t::type::EN_FT_ACTIVED))) {
      // lost conflict response from the upstream, maybe cancled.
      ATBUS_FUNC_NODE_FATAL_SHUTDOWN(*this, nullptr, conn, UV_ECANCELED, EN_ATBUS_ERR_ATNODE_MASK_CONFLICT);
    }
  }
  return EN_ATBUS_ERR_SUCCESS;
}

ATBUS_MACRO_API ATBUS_ERROR_TYPE node::on_new_connection(connection *conn) {
  if (nullptr == conn) {
    return EN_ATBUS_ERR_PARAMS;
  }

  if (event_message_.on_new_connection) {
    flag_guard_t fgd(this, flag_t::type::EN_FT_IN_CALLBACK);
    event_message_.on_new_connection(std::cref(*this), conn);
  }

  // 如果ID有效，且是IO流连接，则发送注册协议
  // ID为0则是临时节点，不需要注册
  if (conn->check_flag(connection::flag_t::type::REG_FD) &&
      false == conn->check_flag(connection::flag_t::type::LISTEN_FD) &&
      conn->check_flag(connection::flag_t::type::CLIENT_MODE)) {
    ATBUS_ERROR_TYPE ret = message_handler::send_register(message_body_type::kNodeRegisterReq, *this, *conn, 0,
                                                          allocate_message_sequence());
    if (ret < 0) {
      ATBUS_FUNC_NODE_ERROR(*this, nullptr, conn, ret, 0, "send node register message to {} failed",
                            conn->get_address().address);
      conn->reset();
      return ret;
    }
  }

  return EN_ATBUS_ERR_SUCCESS;
}

ATBUS_MACRO_API ATBUS_ERROR_TYPE node::on_shutdown(ATBUS_ERROR_TYPE errcode) {
  if (!flags_.test(static_cast<size_t>(flag_t::type::EN_FT_ACTIVED))) {
    return EN_ATBUS_ERR_SUCCESS;
  }
  // flags_.set(flag_t::EN_FT_ACTIVED, false); // will be reset in reset()

  if (event_message_.on_node_down) {
    flag_guard_t fgd(this, flag_t::type::EN_FT_IN_CALLBACK);
    event_message_.on_node_down(std::cref(*this), errcode);
  }

  return EN_ATBUS_ERR_SUCCESS;
}

ATBUS_MACRO_API ATBUS_ERROR_TYPE node::on_register(const endpoint *ep, const connection *conn,
                                                   ATBUS_ERROR_TYPE errcode) {
  if (event_message_.on_register) {
    flag_guard_t fgd(this, flag_t::type::EN_FT_IN_CALLBACK);
    event_message_.on_register(std::cref(*this), ep, conn, errcode);
  }

  return EN_ATBUS_ERR_SUCCESS;
}

ATBUS_MACRO_API ATBUS_ERROR_TYPE node::on_actived() {
  state_ = state_t::type::RUNNING;

  if (flags_.test(static_cast<size_t>(flag_t::type::EN_FT_ACTIVED))) {
    return EN_ATBUS_ERR_SUCCESS;
  }

  flags_.set(static_cast<size_t>(flag_t::type::EN_FT_ACTIVED), true);
  if (event_message_.on_node_up) {
    flag_guard_t fgd(this, flag_t::type::EN_FT_IN_CALLBACK);
    event_message_.on_node_up(std::cref(*this), EN_ATBUS_ERR_SUCCESS);
  }

  return EN_ATBUS_ERR_SUCCESS;
}

ATBUS_MACRO_API ATBUS_ERROR_TYPE node::on_upstream_register_done() {
  flags_.set(static_cast<size_t>(flag_t::type::EN_FT_UPSTREAM_REG_DONE), true);

  // 上游节点成功上线以后要更新一下上游节点action定时器。以便能够及时发起第一个ping包
  std::chrono::system_clock::time_point ping_timepoint = get_timer_tick() + conf_.ping_interval;
  if (ping_timepoint < event_timer_.upstream_op_timepoint) {
    event_timer_.upstream_op_timepoint = ping_timepoint;
  }
  return EN_ATBUS_ERR_SUCCESS;
}

ATBUS_MACRO_API ATBUS_ERROR_TYPE node::on_custom_command_request(const endpoint *ep, const connection *conn,
                                                                 bus_id_t from,
                                                                 gsl::span<gsl::span<const unsigned char>> args,
                                                                 std::list<std::string> &rsp) {
  if (event_message_.on_custom_command_request) {
    flag_guard_t fgd(this, flag_t::type::EN_FT_IN_CALLBACK);
    event_message_.on_custom_command_request(std::cref(*this), ep, conn, from, args, std::ref(rsp));
  }
  return EN_ATBUS_ERR_SUCCESS;
}

ATBUS_MACRO_API ATBUS_ERROR_TYPE node::on_custom_command_response(const endpoint *ep, const connection *conn,
                                                                  bus_id_t from,
                                                                  gsl::span<gsl::span<const unsigned char>> args,
                                                                  uint64_t sequence) {
  if (event_message_.on_custom_command_response) {
    flag_guard_t fgd(this, flag_t::type::EN_FT_IN_CALLBACK);
    event_message_.on_custom_command_response(std::cref(*this), ep, conn, from, args, sequence);
  }
  return EN_ATBUS_ERR_SUCCESS;
}

ATBUS_MACRO_API ATBUS_ERROR_TYPE node::on_ping(const endpoint *ep, const message &m,
                                               const ::atframework::atbus::protocol::ping_data &body) {
  if (event_message_.on_endpoint_ping) {
    flag_guard_t fgd(this, flag_t::type::EN_FT_IN_CALLBACK);
    event_message_.on_endpoint_ping(std::cref(*this), ep, std::cref(m), std::cref(body));
  }
  return EN_ATBUS_ERR_SUCCESS;
}

ATBUS_MACRO_API ATBUS_ERROR_TYPE node::on_pong(const endpoint *ep, const message &m,
                                               const ::atframework::atbus::protocol::ping_data &body) {
  if (event_message_.on_endpoint_pong) {
    flag_guard_t fgd(this, flag_t::type::EN_FT_IN_CALLBACK);
    event_message_.on_endpoint_pong(std::cref(*this), ep, std::cref(m), std::cref(body));
  }
  return EN_ATBUS_ERR_SUCCESS;
}

ATBUS_MACRO_API int node::shutdown(ATBUS_ERROR_TYPE errcode) {
  if (flags_.test(static_cast<size_t>(flag_t::type::EN_FT_SHUTDOWN))) {
    return 0;
  }

  flags_.set(static_cast<size_t>(flag_t::type::EN_FT_SHUTDOWN), true);
  return on_shutdown(errcode);
}

ATBUS_MACRO_API int node::fatal_shutdown(const atfw::util::log::log_wrapper::caller_info_t &caller, const endpoint *ep,
                                         const connection *conn, int status, ATBUS_ERROR_TYPE errcode) {
  if (flags_.test(static_cast<size_t>(flag_t::type::EN_FT_SHUTDOWN))) {
    return 0;
  }

  shutdown(errcode);
  if (logger_ && logger_->check_level(caller.level_id)) {
    logger_->format_log(caller, "node={:#x}, endpoint={:#x}, connection={}, status: {}, error_code: {}: ",
                        ::atframework::atbus::details::__log_get_node_id(*this),
                        ::atframework::atbus::details::__log_get_endpoint_id(ep),
                        ::atframework::atbus::details::__log_get_connection_fmt_ptr(conn), status, errcode);
  }
  return 0;
}

ATBUS_MACRO_API int node::dispatch_all_self_messages() {
  int ret = 0;

  // recursive call will be ignored
  if (check_flag(flag_t::type::EN_FT_RECV_SELF_MSG) || check_flag(flag_t::type::EN_FT_IN_CALLBACK)) {
    return ret;
  }
  flag_guard_t fgd(this, flag_t::type::EN_FT_RECV_SELF_MSG);
  int loop_left = conf_.loop_times;
  if (loop_left <= 0) {
    loop_left = 10240;
  }

  while (loop_left-- > 0 && !self_data_messages_.empty()) {
    message m = std::move(self_data_messages_.front());
    // pop front message
    self_data_messages_.pop_front();

    do {
      // unpack
      auto body_type = m.get_body_type();
      if (nullptr == m.get_head() || message_body_type::MESSAGE_TYPE_NOT_SET == body_type) {
        ATBUS_FUNC_NODE_ERROR(*this, get_self_endpoint(), nullptr, EN_ATBUS_ERR_UNPACK, EN_ATBUS_ERR_UNPACK,
                              "head or body type unset");
        break;
      }

      if (message_body_type::kDataTransformReq == body_type) {
        ::atframework::atbus::protocol::message_body &body = m.mutable_body();
        const ::atframework::atbus::protocol::forward_data &fwd_data = body.data_transform_req();
        on_receive_data(
            get_self_endpoint(), nullptr, m,
            gsl::span<const unsigned char>(reinterpret_cast<const unsigned char *>(fwd_data.content().data()),
                                           fwd_data.content().size()));
        ++ret;

        // fake response
        if (fwd_data.flags() & atbus::protocol::FORWARD_DATA_FLAG_REQUIRE_RSP) {
          // be careful, all mutable action here can not set any new element.
          m.mutable_head().set_result_code(0);
          // Same arena here and so we can use unsafe release and set_allocated
          body.unsafe_arena_set_allocated_data_transform_rsp(body.unsafe_arena_release_data_transform_req());
          on_receive_forward_response(get_self_endpoint(), nullptr, &m);
        }
      }
    } while (false);
  }

  while (loop_left-- > 0 && !self_command_messages_.empty()) {
    message m = std::move(self_command_messages_.front());
    // pop front message
    self_command_messages_.pop_front();
    do {
      // unpack
      auto body_type = m.get_body_type();
      if (nullptr == m.get_head() || message_body_type::MESSAGE_TYPE_NOT_SET == body_type) {
        ATBUS_FUNC_NODE_ERROR(*this, get_self_endpoint(), nullptr, EN_ATBUS_ERR_UNPACK, EN_ATBUS_ERR_UNPACK,
                              "head or body type unset");
        break;
      }

      on_receive_message(nullptr, std::move(m), 0, EN_ATBUS_ERR_SUCCESS);
      ++ret;

    } while (false);
  }
  return ret;
}

ATBUS_MACRO_API const detail::buffer_block *node::get_temp_static_buffer() const { return static_buffer_; }
ATBUS_MACRO_API detail::buffer_block *node::get_temp_static_buffer() { return static_buffer_; }

ATBUS_MACRO_API int node::ping_endpoint(endpoint &ep) {
  // 检测上一次ping是否返回
  if (0 != ep.get_stat_unfinished_ping()) {
    if (add_endpoint_fault(ep)) {
      return EN_ATBUS_ERR_ATNODE_FAULT_TOLERANT;
    }
  }

  if (!self_) {
    return EN_ATBUS_ERR_NOT_INITED;
  }

  // 临时节点不需要对外发送ping包
  if (0 == get_id()) {
    return EN_ATBUS_ERR_SUCCESS;
  }

  // 允许跳过未连接或握手完成的endpoint
  connection *ctl_conn = self_->get_ctrl_connection(&ep);
  if (nullptr == ctl_conn) {
    add_endpoint_fault(ep);
    return EN_ATBUS_ERR_SUCCESS;
  }

  // 出错则增加错误计数
  uint64_t ping_seq = allocate_message_sequence();
  int res = message_handler::send_ping(*this, *ctl_conn, ping_seq);
  if (res < 0) {
    add_endpoint_fault(ep);
    return res;
  }

  // no data channel is also a error
  if (nullptr == self_->get_data_connection(&ep, false)) {
    add_endpoint_fault(ep);
  }

  ep.set_stat_unfinished_ping(ping_seq);
  return EN_ATBUS_ERR_SUCCESS;
}

ATBUS_MACRO_API uint64_t node::allocate_message_sequence() {
  uint64_t ret = 0;
  while (!ret) {
    ret = message_sequence_allocator_.inc();
  }
  return ret;
}

ATBUS_MACRO_API void node::add_endpoint_gc_list(const endpoint::ptr_t &ep) {
  // 重置过程中不需要再加进来了，反正等会也会移除
  // 这个代码加不加一样，只不过会少一些废操作
  if (flags_.test(static_cast<size_t>(flag_t::type::EN_FT_RESETTING_GC)) ||
      flags_.test(static_cast<size_t>(flag_t::type::EN_FT_IN_GC_ENDPOINTS))) {
    return;
  }

  if (ep) {
    event_timer_.pending_endpoint_gc_list.push_back(ep);
  }
}

ATBUS_MACRO_API void node::add_connection_gc_list(const connection::ptr_t &conn) {
  if (flags_.test(static_cast<size_t>(flag_t::type::EN_FT_RESETTING_GC)) ||
      flags_.test(static_cast<size_t>(flag_t::type::EN_FT_IN_GC_CONNECTIONS))) {
    return;
  }

  if (conn) {
    event_timer_.pending_connection_gc_list.push_back(conn);
  }
}

ATBUS_MACRO_API void node::set_on_forward_request_handle(event_handle_set_t::on_forward_request_fn_t fn) {
  event_message_.on_forward_request = fn;
}
ATBUS_MACRO_API const node::event_handle_set_t::on_forward_request_fn_t &node::get_on_forward_request_handle() const {
  return event_message_.on_forward_request;
}

ATBUS_MACRO_API void node::set_on_forward_response_handle(event_handle_set_t::on_forward_response_fn_t fn) {
  event_message_.on_forward_response = fn;
}
ATBUS_MACRO_API const node::event_handle_set_t::on_forward_response_fn_t &node::get_on_forward_response_handle() const {
  return event_message_.on_forward_response;
}

ATBUS_MACRO_API void node::set_on_register_handle(node::event_handle_set_t::on_register_fn_t fn) {
  event_message_.on_register = fn;
}
ATBUS_MACRO_API const node::event_handle_set_t::on_register_fn_t &node::get_on_register_handle() const {
  return event_message_.on_register;
}

ATBUS_MACRO_API void node::set_on_shutdown_handle(event_handle_set_t::on_node_down_fn_t fn) {
  event_message_.on_node_down = fn;
}
ATBUS_MACRO_API const node::event_handle_set_t::on_node_down_fn_t &node::get_on_shutdown_handle() const {
  return event_message_.on_node_down;
}

ATBUS_MACRO_API void node::set_on_available_handle(node::event_handle_set_t::on_node_up_fn_t fn) {
  event_message_.on_node_up = fn;
}
ATBUS_MACRO_API const node::event_handle_set_t::on_node_up_fn_t &node::get_on_available_handle() const {
  return event_message_.on_node_up;
}

ATBUS_MACRO_API void node::set_on_invalid_connection_handle(node::event_handle_set_t::on_invalid_connection_fn_t fn) {
  event_message_.on_invalid_connection = fn;
}
ATBUS_MACRO_API const node::event_handle_set_t::on_invalid_connection_fn_t &node::get_on_invalid_connection_handle()
    const {
  return event_message_.on_invalid_connection;
}

ATBUS_MACRO_API void node::set_on_new_connection_handle(event_handle_set_t::on_new_connection_fn_t fn) {
  event_message_.on_new_connection = fn;
}
ATBUS_MACRO_API const node::event_handle_set_t::on_new_connection_fn_t &node::get_on_new_connection_handle() const {
  return event_message_.on_new_connection;
}

ATBUS_MACRO_API void node::set_on_custom_command_request_handle(event_handle_set_t::on_custom_command_request_fn_t fn) {
  event_message_.on_custom_command_request = fn;
}
ATBUS_MACRO_API const node::event_handle_set_t::on_custom_command_request_fn_t &
node::get_on_custom_command_request_handle() const {
  return event_message_.on_custom_command_request;
}

ATBUS_MACRO_API void node::set_on_custom_command_response_handle(
    event_handle_set_t::on_custom_command_response_fn_t fn) {
  event_message_.on_custom_command_response = fn;
}
ATBUS_MACRO_API const node::event_handle_set_t::on_custom_command_response_fn_t &
node::get_on_custom_command_response_handle() const {
  return event_message_.on_custom_command_response;
}

ATBUS_MACRO_API void node::set_on_add_endpoint_handle(event_handle_set_t::on_add_endpoint_fn_t fn) {
  event_message_.on_endpoint_added = fn;
}
ATBUS_MACRO_API const node::event_handle_set_t::on_add_endpoint_fn_t &node::get_on_add_endpoint_handle() const {
  return event_message_.on_endpoint_added;
}

ATBUS_MACRO_API void node::set_on_remove_endpoint_handle(event_handle_set_t::on_remove_endpoint_fn_t fn) {
  event_message_.on_endpoint_removed = fn;
}
ATBUS_MACRO_API const node::event_handle_set_t::on_remove_endpoint_fn_t &node::get_on_remove_endpoint_handle() const {
  return event_message_.on_endpoint_removed;
}

ATBUS_MACRO_API void node::set_on_ping_endpoint_handle(event_handle_set_t::on_ping_pong_endpoint_fn_t fn) {
  event_message_.on_endpoint_ping = fn;
}
ATBUS_MACRO_API const node::event_handle_set_t::on_ping_pong_endpoint_fn_t &node::get_on_ping_endpoint_handle() const {
  return event_message_.on_endpoint_ping;
}

ATBUS_MACRO_API void node::set_on_pong_endpoint_handle(event_handle_set_t::on_ping_pong_endpoint_fn_t fn) {
  event_message_.on_endpoint_pong = fn;
}
ATBUS_MACRO_API const node::event_handle_set_t::on_ping_pong_endpoint_fn_t &node::get_on_pong_endpoint_handle() const {
  return event_message_.on_endpoint_pong;
}

ATBUS_MACRO_API void node::set_on_topology_update_upstream_handle(
    event_handle_set_t::on_topology_update_upstream_fn_t fn) {
  event_message_.on_topology_update_upstream = fn;
}

ATBUS_MACRO_API const node::event_handle_set_t::on_topology_update_upstream_fn_t &
node::get_on_topology_update_upstream_handle() const {
  return event_message_.on_topology_update_upstream;
}

ATBUS_MACRO_API void node::set_logger(atfw::util::log::log_wrapper::ptr_t logger) noexcept { logger_ = logger; }

ATBUS_MACRO_API void node::ref_object(void *obj) {
  if (nullptr == obj) {
    return;
  }

  ref_objs_.insert(obj);
}

ATBUS_MACRO_API void node::unref_object(void *obj) { ref_objs_.erase(obj); }

ATBUS_MACRO_API protocol::ATBUS_CRYPTO_ALGORITHM_TYPE node::parse_crypto_algorithm_name(
    gsl::string_view name) noexcept {
#if defined(ATFW_UTIL_MACRO_CRYPTO_CIPHER_ENABLED)
  if (name.size() == 8 && 0 == UTIL_STRFUNC_STRNCASE_CMP("chacha20", name.data(), name.size())) {
    return protocol::ATBUS_CRYPTO_ALGORITHM_CHACHA20;
  } else if (name.size() == 22 && 0 == UTIL_STRFUNC_STRNCASE_CMP("chacha20-poly1305-ietf", name.data(), name.size())) {
    return protocol::ATBUS_CRYPTO_ALGORITHM_CHACHA20_POLY1305_IETF;
  } else if (name.size() == 23 && 0 == UTIL_STRFUNC_STRNCASE_CMP("xchacha20-poly1305-ietf", name.data(), name.size())) {
    return protocol::ATBUS_CRYPTO_ALGORITHM_XCHACHA20_POLY1305_IETF;
  } else if (name.size() == 11 && 0 == UTIL_STRFUNC_STRNCASE_CMP("aes-256-gcm", name.data(), name.size())) {
    return protocol::ATBUS_CRYPTO_ALGORITHM_AES_256_GCM;
  } else if (name.size() == 11 && 0 == UTIL_STRFUNC_STRNCASE_CMP("aes-256-cbc", name.data(), name.size())) {
    return protocol::ATBUS_CRYPTO_ALGORITHM_AES_256_CBC;
  } else if (name.size() == 11 && 0 == UTIL_STRFUNC_STRNCASE_CMP("aes-192-gcm", name.data(), name.size())) {
    return protocol::ATBUS_CRYPTO_ALGORITHM_AES_192_GCM;
  } else if (name.size() == 11 && 0 == UTIL_STRFUNC_STRNCASE_CMP("aes-192-cbc", name.data(), name.size())) {
    return protocol::ATBUS_CRYPTO_ALGORITHM_AES_192_CBC;
  } else if (name.size() == 11 && 0 == UTIL_STRFUNC_STRNCASE_CMP("aes-128-gcm", name.data(), name.size())) {
    return protocol::ATBUS_CRYPTO_ALGORITHM_AES_128_GCM;
  } else if (name.size() == 11 && 0 == UTIL_STRFUNC_STRNCASE_CMP("aes-128-cbc", name.data(), name.size())) {
    return protocol::ATBUS_CRYPTO_ALGORITHM_AES_128_CBC;
  } else if (name.size() == 5 && 0 == UTIL_STRFUNC_STRNCASE_CMP("xxtea", name.data(), name.size())) {
    return protocol::ATBUS_CRYPTO_ALGORITHM_XXTEA;
  }
  return protocol::ATBUS_CRYPTO_ALGORITHM_NONE;
#else
  return protocol::ATBUS_CRYPTO_ALGORITHM_NONE;
#endif
}

ATBUS_MACRO_API protocol::ATBUS_COMPRESSION_ALGORITHM_TYPE node::parse_compression_algorithm_name(
    gsl::string_view name) noexcept {
  if (name.size() == 4 && 0 == UTIL_STRFUNC_STRNCASE_CMP("zstd", name.data(), name.size())) {
    return protocol::ATBUS_COMPRESSION_ALGORITHM_ZSTD;
  } else if (name.size() == 3 && 0 == UTIL_STRFUNC_STRNCASE_CMP("lz4", name.data(), name.size())) {
    return protocol::ATBUS_COMPRESSION_ALGORITHM_LZ4;
  } else if (name.size() == 4 && 0 == UTIL_STRFUNC_STRNCASE_CMP("zlib", name.data(), name.size())) {
    return protocol::ATBUS_COMPRESSION_ALGORITHM_ZLIB;
  } else if (name.size() == 6 && 0 == UTIL_STRFUNC_STRNCASE_CMP("snappy", name.data(), name.size())) {
    return protocol::ATBUS_COMPRESSION_ALGORITHM_SNAPPY;
  }

  return protocol::ATBUS_COMPRESSION_ALGORITHM_NONE;
}

endpoint *node::find_route(endpoint_collection_t &coll, bus_id_t id) {
  endpoint_collection_t::iterator iter = coll.find(id);
  if (iter == coll.end()) {
    return nullptr;
  }

  return iter->second.get();
}

bool node::insert_child(endpoint_collection_t &coll, endpoint::ptr_t ep, bool ignore_event) {
  if (!ep) {
    return false;
  }

  auto iter = coll.find(ep->get_id());
  if (iter != coll.end() && iter->second.get() != ep.get()) {
    return true;
  }
  coll[ep->get_id()] = ep;

  // event
  if (!ignore_event && event_message_.on_endpoint_added) {
    flag_guard_t fgd(this, flag_t::type::EN_FT_IN_CALLBACK);
    event_message_.on_endpoint_added(std::cref(*this), ep.get(), EN_ATBUS_ERR_SUCCESS);
  }
  return true;
}

bool node::remove_child(endpoint_collection_t &coll, bus_id_t id, endpoint *expected, bool ignore_event) {
  endpoint_collection_t::iterator iter = coll.find(id);
  if (iter == coll.end()) {
    return false;
  }

  if (nullptr != expected && iter->second.get() != expected) {
    return false;
  }

  endpoint::ptr_t ep = iter->second;
  coll.erase(iter);

  // event
  if (!ignore_event && event_message_.on_endpoint_removed) {
    flag_guard_t fgd(this, flag_t::type::EN_FT_IN_CALLBACK);
    event_message_.on_endpoint_removed(std::cref(*this), ep.get(), EN_ATBUS_ERR_SUCCESS);
  }
  return true;
}

bool node::remove_collection(endpoint_collection_t &coll) {
  endpoint_collection_t ec;
  ec.swap(coll);

  if (event_message_.on_endpoint_removed) {
    flag_guard_t fgd(this, flag_t::type::EN_FT_IN_CALLBACK);
    for (endpoint_collection_t::iterator iter = ec.begin(); iter != ec.end(); ++iter) {
      event_message_.on_endpoint_removed(std::cref(*this), iter->second.get(), EN_ATBUS_ERR_SUCCESS);
    }
  }

  return !ec.empty();
}

bool node::add_endpoint_fault(endpoint &ep) {
  size_t fault_count = ep.add_stat_fault();
  if (fault_count > conf_.fault_tolerant) {
    remove_endpoint(ep.get_id());
    return true;
  }

  return false;
}

bool node::add_connection_fault(connection &conn) {
  size_t fault_count = conn.add_stat_fault();
  if (fault_count > conf_.fault_tolerant) {
    conn.reset();
    return true;
  }

  return false;
}

bool node::add_ping_timer(const endpoint::ptr_t &ep) {
  if (!ep) {
    return false;
  }

  // 自己不用ping
  if (ep->get_id() == get_id()) {
    return false;
  }

  if (conf_.ping_interval <= std::chrono::microseconds{0}) {
    return false;
  }

  if (flags_.test(static_cast<size_t>(flag_t::type::EN_FT_RESETTING_GC))) {
    return false;
  }

  event_timer_.ping_list.insert_key_value(ep.get(), std::make_pair(event_timer_.tick + conf_.ping_interval, ep));
  return true;
}

void node::remove_ping_timer(const endpoint *ep) { event_timer_.ping_list.erase(ep); }

void node::init_hash_code() {
  atfw::util::hash::sha sha256;
  sha256.init(atfw::util::hash::sha::EN_ALGORITHM_SHA256);

  // hash all interface
  {
    std::vector<std::string> all_outter_inters;
    uv_interface_address_t *interface_addrs = nullptr;
    int interface_sz = 0;
    // size_t total_size = 0;
    uv_interface_addresses(&interface_addrs, &interface_sz);
    for (int i = 0; i < interface_sz; ++i) {
      uv_interface_address_t *inter_addr = interface_addrs + i;
      if (inter_addr->is_internal) {
        continue;
      }

      std::string one_addr;
      size_t dump_index = 0;
      while (dump_index < sizeof(inter_addr->phys_addr) && 0 == inter_addr->phys_addr[dump_index]) {
        ++dump_index;
      }
      if (dump_index < sizeof(inter_addr->phys_addr)) {
        one_addr.resize((sizeof(inter_addr->phys_addr) - dump_index) * 2);
        atfw::util::string::dumphex(inter_addr->phys_addr + dump_index, (sizeof(inter_addr->phys_addr) - dump_index),
                                    &one_addr[0]);
      }

      if (!one_addr.empty()) {
        all_outter_inters.push_back(one_addr);
        // total_size += one_addr.size();
      }
    }

    std::sort(all_outter_inters.begin(), all_outter_inters.end());
    std::vector<std::string>::iterator new_end = std::unique(all_outter_inters.begin(), all_outter_inters.end());
    all_outter_inters.erase(new_end, all_outter_inters.end());
    for (size_t i = 0; i < all_outter_inters.size(); ++i) {
      sha256.update(reinterpret_cast<const unsigned char *>(all_outter_inters[i].c_str()), all_outter_inters[i].size());
    }

    if (nullptr != interface_addrs) {
      uv_free_interface_addresses(interface_addrs, interface_sz);
    }
  }

  // hash hostname
  {
    gsl::string_view hostname = get_hostname();
    sha256.update(reinterpret_cast<const unsigned char *>(hostname.data()), hostname.size());
  }

  // hash pid
  {
    int pid = get_pid();
    sha256.update(reinterpret_cast<const unsigned char *>(&pid), sizeof(pid));
  }

  // hash address
  {
    const unsigned char *self = reinterpret_cast<const unsigned char *>(this);
    sha256.update(reinterpret_cast<const unsigned char *>(&self), sizeof(const unsigned char *));
  }

  // hash id
  {
    bus_id_t id = get_id();
    sha256.update(reinterpret_cast<const unsigned char *>(&id), sizeof(id));
  }

  sha256.final();
  hash_code_ = sha256.get_output_hex();
}

ATBUS_MACRO_API void node::stat_add_dispatch_times() { ++stat_.dispatch_times; }

ATBUS_ERROR_TYPE node::remove_endpoint(bus_id_t tid, endpoint *expected) {
  // 上游节点单独判定，由于防止测试兄弟节点
  if (node_upstream_.node_ && node_upstream_.node_->get_id() == tid) {
    if (expected != nullptr && expected != node_upstream_.node_.get()) {
      return EN_ATBUS_ERR_ATNODE_NOT_FOUND;
    }

    endpoint::ptr_t ep = node_upstream_.node_;

    node_upstream_.node_.reset();
    state_ = state_t::type::LOST_UPSTREAM;

    // set reconnect to upstream into retry interval
    event_timer_.upstream_op_timepoint = get_timer_tick() + conf_.retry_interval;

    // event
    if (event_message_.on_endpoint_removed) {
      flag_guard_t fgd(this, flag_t::type::EN_FT_IN_CALLBACK);
      event_message_.on_endpoint_removed(std::cref(*this), ep.get(), EN_ATBUS_ERR_SUCCESS);
    }

    // if not activited, shutdown
    if (!flags_.test(static_cast<size_t>(flag_t::type::EN_FT_ACTIVED))) {
      ATBUS_FUNC_NODE_FATAL_SHUTDOWN(*this, ep.get(), nullptr, UV_ECANCELED, EN_ATBUS_ERR_ATNODE_MASK_CONFLICT);
    }
    return EN_ATBUS_ERR_SUCCESS;
  }

  if (get_id() == tid) {
    return EN_ATBUS_ERR_ATNODE_INVALID_ID;
  }

  if (remove_child(node_route_, tid, expected)) {
    return EN_ATBUS_ERR_SUCCESS;
  } else {
    return EN_ATBUS_ERR_ATNODE_NOT_FOUND;
  }
}

ATBUS_MACRO_API ATBUS_ERROR_TYPE node::send_data_message(bus_id_t tid, message_builder_ref_t mb) {
  return send_data_message(tid, mb, nullptr, nullptr);
}

ATBUS_MACRO_API ATBUS_ERROR_TYPE node::send_data_message(bus_id_t tid, message_builder_ref_t mb, endpoint **ep_out,
                                                         connection **conn_out) {
  return send_message(tid, mb, &endpoint::get_data_connection, ep_out, conn_out);
}

ATBUS_MACRO_API ATBUS_ERROR_TYPE node::send_ctrl_message(bus_id_t tid, message_builder_ref_t mb) {
  return send_ctrl_message(tid, mb, nullptr, nullptr);
}

ATBUS_MACRO_API ATBUS_ERROR_TYPE node::send_ctrl_message(bus_id_t tid, message_builder_ref_t mb, endpoint **ep_out,
                                                         connection **conn_out) {
  return send_message(tid, mb, &endpoint::get_ctrl_connection, ep_out, conn_out);
}

ATBUS_MACRO_API ATBUS_ERROR_TYPE node::send_message(bus_id_t tid, message_builder_ref_t mb,
                                                    endpoint::get_connection_fn_t fn, endpoint **ep_out,
                                                    connection **conn_out) {
  if (state_t::type::CREATED == state_) {
    return EN_ATBUS_ERR_NOT_INITED;
  }

  if (tid == get_id()) {
    // verify
    auto head = mb.get_head();
    auto body_type = mb.get_body_type();

    if (nullptr == head || message_body_type::MESSAGE_TYPE_NOT_SET == body_type) {
      ATBUS_FUNC_NODE_ERROR(*this, get_self_endpoint(), nullptr, EN_ATBUS_ERR_UNPACK, EN_ATBUS_ERR_UNPACK,
                            "head or body type unset");
      return EN_ATBUS_ERR_UNPACK;
    }

    if (0 == head->sequence()) {
      mb.mutable_head().set_sequence(allocate_message_sequence());
    }

    if (!(message_body_type::kDataTransformReq == body_type || message_body_type::kDataTransformRsp == body_type ||
          message_body_type::kCustomCommandReq == body_type || message_body_type::kCustomCommandRsp == body_type)) {
      ATBUS_FUNC_NODE_ERROR(*this, get_self_endpoint(), nullptr, EN_ATBUS_ERR_ATNODE_INVALID_MSG, 0,
                            "invalid body type {}", static_cast<int>(body_type));
      return EN_ATBUS_ERR_ATNODE_INVALID_MSG;
    }

    assert(message_body_type::kDataTransformReq == body_type || message_body_type::kDataTransformRsp == body_type ||
           message_body_type::kCustomCommandReq == body_type || message_body_type::kCustomCommandRsp == body_type);

    using bin_data_block_t = std::vector<unsigned char>;
    // self data message
    if (message_body_type::kDataTransformReq == body_type || message_body_type::kDataTransformRsp == body_type) {
      self_data_messages_.emplace_back(std::move(mb));
    }

    // self command message
    if (message_body_type::kCustomCommandReq == body_type || message_body_type::kCustomCommandRsp == body_type) {
      self_command_messages_.emplace_back(std::move(mb));
    }

    dispatch_all_self_messages();
    return EN_ATBUS_ERR_SUCCESS;
  }

  connection *conn = nullptr;
  ATBUS_ERROR_TYPE res = get_peer_channel(tid, fn, ep_out, &conn);
  if (nullptr != conn_out) {
    *conn_out = conn;
  }

  if (res < 0) {
    return res;
  }

  if (nullptr == conn) {
    return EN_ATBUS_ERR_ATNODE_NO_CONNECTION;
  }

  auto head = mb.get_head();
  auto body_type = mb.get_body_type();
  if (nullptr == head || message_body_type::MESSAGE_TYPE_NOT_SET == body_type) {
    ATBUS_FUNC_NODE_ERROR(*this, ep_out ? (*ep_out) : conn->get_binding(), conn, EN_ATBUS_ERR_UNPACK,
                          EN_ATBUS_ERR_UNPACK, "head or body type unset");
    return EN_ATBUS_ERR_UNPACK;
  }

  if (0 == head->sequence()) {
    mb.mutable_head().set_sequence(allocate_message_sequence());
  }
  return message_handler::send_message(*this, *conn, mb);
}

channel::io_stream_conf *node::get_iostream_conf() {
  if (iostream_conf_) {
    return iostream_conf_.get();
  }

  iostream_conf_.reset(new channel::io_stream_conf());
  channel::io_stream_init_configure(iostream_conf_.get());

  // 接收大小和message size一致即可，可以只使用一块静态buffer
  iostream_conf_->receive_buffer_limit_size = conf_.message_size + ATBUS_MACRO_MAX_FRAME_HEADER;
  iostream_conf_->receive_buffer_max_size =
      conf_.message_size + conf_.message_size + ATBUS_MACRO_MAX_FRAME_HEADER + 1024;  // 预留header和正在处理的buffer块

  iostream_conf_->send_buffer_static = conf_.send_buffer_number;
  iostream_conf_->send_buffer_max_size = conf_.send_buffer_size;
  iostream_conf_->send_buffer_limit_size =
      conf_.message_size + ATBUS_MACRO_MAX_FRAME_HEADER +
      ::atframework::atbus::detail::buffer_block::padding_size(sizeof(uv_write_t) + sizeof(uint32_t) + 16);
  iostream_conf_->confirm_timeout = conf_.first_idle_timeout;
  iostream_conf_->backlog = conf_.backlog;

  return iostream_conf_.get();
}

node::stat_info_t::stat_info_t() : dispatch_times(0) {}
ATBUS_MACRO_NAMESPACE_END
