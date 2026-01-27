// Copyright 2022 atframework
// Created by owent on on 2015-11-20

#pragma once

#ifdef _MSC_VER
#  include <WinSock2.h>
#endif

#include <design_pattern/nomovable.h>
#include <design_pattern/noncopyable.h>
#include <gsl/select-gsl.h>
#include <nostd/nullability.h>

#include <memory/lru_map.h>

#include <bitset>
#include <chrono>
#include <ctime>
#include <list>
#include <memory>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include "std/explicit_declare.h"

#include "detail/libatbus_channel_export.h"
#include "detail/libatbus_config.h"
#include "detail/libatbus_error.h"

#include "atbus_connection_context.h"

ATBUS_MACRO_NAMESPACE_BEGIN
class node;
class endpoint;

template <class TKey, class TObj>
struct timer_desc_ls {
  using pair_type = std::pair<std::chrono::system_clock::time_point, TObj>;
  using type = ::atfw::util::memory::lru_map<
      TKey, pair_type, std::hash<TKey>, std::equal_to<TKey>,
      ::atfw::util::memory::lru_map_option<::atfw::util::memory::compat_strong_ptr_mode::kStrongRc>>;
};

class connection final : public atfw::util::design_pattern::noncopyable {
 public:
  using ptr_t = ::atfw::util::memory::strong_rc_ptr<connection>;

  /** 并没有非常复杂的状态切换，所以没有引入状态机 **/
  struct state_t {
    enum class type : uint32_t {
      kDisconnected = 0, /** 未连接 **/
      kConnecting,       /** 正在连接 **/
      kHandshaking,      /** 正在握手 **/
      kConnected,        /** 已连接 **/
      kDisconnecting,    /** 正在断开连接 **/
    };
  };

  struct flag_t {
    enum class type : uint32_t {
      kRegProc = 0,     /** 注册了proc记录到node，清理的时候需要移除 **/
      kRegFd,           /** 关联了fd到node或endpoint，清理的时候需要移除 **/
      kAccessShareAddr, /** 共享内部地址（内存通道的地址共享） **/
      kAccessShareHost, /** 共享物理机（共享内存通道的物理机共享） **/
      kResetting,       /** 正在执行重置（防止递归死循环） **/
      kDestructing,     /** 正在执行析构（屏蔽某些接口） **/
      kListenFd,        /** 是否是用于listen的连接 **/
      kTemporary,       /** 是否是临时连接 **/
      kPeerClosed,      /** 对端已关闭 **/
      kServerMode,      /** 连接处于服务端模式 **/
      kClientMode,      /** 连接处于客户端模式 **/
      kMax
    };
  };

  struct stat_t {
    size_t push_start_times;
    size_t push_start_size;
    size_t push_success_times;
    size_t push_success_size;
    size_t push_failed_times;
    size_t push_failed_size;

    size_t pull_times;
    size_t pull_size;

    size_t fault_count;
  };

  UTIL_DESIGN_PATTERN_NOCOPYABLE(connection)
  UTIL_DESIGN_PATTERN_NOMOVABLE(connection)

 private:
  struct ctor_guard_t {
    node *owner;
    gsl::string_view addr;
    protocol::ATBUS_CRYPTO_KEY_EXCHANGE_TYPE crypto_algorithm;
    ::atfw::util::crypto::dh::shared_context::ptr_t shared_dh_context;
  };

 public:
  connection(ctor_guard_t &guard);

  static ATBUS_MACRO_API ptr_t create(node *owner, gsl::string_view addr);

  ATBUS_MACRO_API ~connection();

  ATBUS_MACRO_API void reset();

  /**
   * @brief 执行一帧
   * @param now 当前时间
   * @return 本帧处理的消息数
   */
  ATBUS_MACRO_API int proc(node &n, std::chrono::system_clock::time_point now);

  /**
   * @brief 监听数据接收地址
   * @return 0或错误码
   */
  ATBUS_MACRO_API int listen();

  /**
   * @brief 连接到目标地址
   * @return 0或错误码
   */
  ATBUS_MACRO_API int connect();

  /**
   * @brief 断开连接
   * @note 此接口不会主动把自己从endpoint或者node中移除。如果要断开连接且移除connection，请使用 reset() 接口
   * @return 0或错误码
   */
  ATBUS_MACRO_API int disconnect();

  /**
   * @brief 发送数据
   * @param buffer 数据块地址
   * @return 0或错误码
   * @note 接收端收到的数据很可能不是地址对齐的，所以这里不建议发送内存数据
   *       如果非要发送内存数据的话，一定要memcpy，不能直接类型转换，除非手动设置了地址对齐规则
   */
  ATBUS_MACRO_API ATBUS_ERROR_TYPE push(gsl::span<const unsigned char> buffer);

  /** 增加错误计数 **/
  ATBUS_MACRO_API size_t add_stat_fault();

  /** 清空错误计数 **/
  ATBUS_MACRO_API void clear_stat_fault();

  /**
   * @brief 获取连接的地址
   */
  ATBUS_MACRO_API const channel::channel_address_t &get_address() const;

  /**
   * @brief 是否已连接
   */
  ATBUS_MACRO_API bool is_connected() const;

  /**
   * @brief 获取关联的端点
   */
  ATBUS_MACRO_API endpoint *get_binding();

  /**
   * @brief 获取关联的端点
   */
  ATBUS_MACRO_API const endpoint *get_binding() const;

  ATBUS_MACRO_API state_t::type get_status() const;
  ATBUS_MACRO_API bool check_flag(flag_t::type f) const;

  ATBUS_MACRO_API void set_temporary();

  /**
   * @brief 获取自身的智能指针
   * @note 在析构阶段这个接口无效
   */
  ATBUS_MACRO_API ptr_t watch() const;

  /** 是否正在连接、或者握手或者已连接 **/
  ATBUS_MACRO_API bool is_running() const;

  ATBUS_MACRO_API const stat_t &get_statistic() const;

  ATBUS_MACRO_API void remove_owner_checker();

  ATBUS_MACRO_API connection_context &get_connection_context() noexcept;

 private:
  ATBUS_MACRO_API void set_status(state_t::type v);
#if !defined(_WIN32)
  ATBUS_MACRO_API void unlock_address() noexcept;
#endif

 public:
  static ATBUS_MACRO_API void iostream_on_listen_cb(channel::io_stream_channel *channel,
                                                    channel::io_stream_connection *connection, int status, void *buffer,
                                                    size_t s);
  static ATBUS_MACRO_API void iostream_on_connected_cb(channel::io_stream_channel *channel,
                                                       channel::io_stream_connection *connection, int status,
                                                       void *buffer, size_t s);

  static ATBUS_MACRO_API void iostream_on_receive_cb(channel::io_stream_channel *channel,
                                                     channel::io_stream_connection *connection, int status,
                                                     void *buffer, size_t s);
  static ATBUS_MACRO_API void iostream_on_accepted(channel::io_stream_channel *channel,
                                                   channel::io_stream_connection *connection, int status, void *buffer,
                                                   size_t s);
  static ATBUS_MACRO_API void iostream_on_connected(channel::io_stream_channel *channel,
                                                    channel::io_stream_connection *connection, int status, void *buffer,
                                                    size_t s);
  static ATBUS_MACRO_API void iostream_on_disconnected(channel::io_stream_channel *channel,
                                                       channel::io_stream_connection *connection, int status,
                                                       void *buffer, size_t s);
  static ATBUS_MACRO_API void iostream_on_written(channel::io_stream_channel *channel,
                                                  channel::io_stream_connection *connection, int status, void *buffer,
                                                  size_t s);

#ifdef ATBUS_CHANNEL_SHM
  static ATBUS_MACRO_API ATBUS_ERROR_TYPE shm_proc_fn(node &n, connection &conn,
                                                      std::chrono::system_clock::time_point now);

  static ATBUS_MACRO_API ATBUS_ERROR_TYPE shm_free_fn(node &n, connection &conn);

  static ATBUS_MACRO_API ATBUS_ERROR_TYPE shm_push_fn(connection &conn, const void *buffer, size_t s);
#endif

  static ATBUS_MACRO_API ATBUS_ERROR_TYPE mem_proc_fn(node &n, connection &conn,
                                                      std::chrono::system_clock::time_point now);

  static ATBUS_MACRO_API ATBUS_ERROR_TYPE mem_free_fn(node &n, connection &conn);

  static ATBUS_MACRO_API ATBUS_ERROR_TYPE mem_push_fn(connection &conn, const void *buffer, size_t s);

  static ATBUS_MACRO_API ATBUS_ERROR_TYPE ios_free_fn(node &n, connection &conn);

  static ATBUS_MACRO_API ATBUS_ERROR_TYPE ios_push_fn(connection &conn, const void *buffer, size_t s);

  static ATBUS_MACRO_API bool unpack(connection &conn, message &m, gsl::span<const unsigned char> in);

 private:
  state_t::type state_;
  channel::channel_address_t address_;
#if !defined(_WIN32)
  int address_lock_;
  std::string address_lock_path_;
#endif
  std::bitset<static_cast<size_t>(flag_t::type::kMax)> flags_;

  // 这里不用智能指针是为了该值在上层对象（node或者endpoint）析构时仍然可用
  node *ATFW_UTIL_MACRO_NONNULL owner_;
  endpoint *ATFW_UTIL_MACRO_NULLABLE binding_;
  ::atfw::util::memory::weak_rc_ptr<connection> watcher_;

  struct conn_data_mem {
    channel::mem_channel *channel;
    void *buffer;
    size_t len;
  };

#ifdef ATBUS_CHANNEL_SHM
  struct conn_data_shm {
    channel::shm_channel *channel;
    size_t len;
  };
#endif

  struct conn_data_ios {
    channel::io_stream_channel *channel;
    channel::io_stream_connection *conn;
  };

  struct connection_data_t {
    union shared_t {
      conn_data_mem mem;
#ifdef ATBUS_CHANNEL_SHM
      conn_data_shm shm;
#endif
      conn_data_ios ios_fd;
    };
    using proc_fn_t = ATBUS_ERROR_TYPE (*)(node &n, connection &conn, std::chrono::system_clock::time_point now);
    using free_fn_t = ATBUS_ERROR_TYPE (*)(node &n, connection &conn);
    using push_fn_t = ATBUS_ERROR_TYPE (*)(connection &conn, const void *buffer, size_t s);

    shared_t shared;
    proc_fn_t proc_fn;
    free_fn_t free_fn;
    push_fn_t push_fn;
  };
  connection_data_t conn_data_;
  connection_context::ptr_t conn_context_;
  stat_t stat_;

  friend class endpoint;
};
ATBUS_MACRO_NAMESPACE_END
