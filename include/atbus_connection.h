// Copyright 2022 atframework
// Created by owent on on 2015-11-20

#pragma once

#ifdef _MSC_VER
#  include <WinSock2.h>
#endif

#include <design_pattern/nomovable.h>
#include <design_pattern/noncopyable.h>

#include <bitset>
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

#include "libatbus_protocol.h"  // NOLINT: build/include_subdir

namespace atbus {
namespace protocol {
class msg;
}

class node;
class endpoint;

template <typename TObj>
struct timer_desc_ls {
  using pair_type = std::pair<time_t, TObj>;
  using type = std::list<pair_type>;
};

class connection final : public atfw::util::design_pattern::noncopyable {
 public:
  using ptr_t = std::shared_ptr<connection>;

  /** 并没有非常复杂的状态切换，所以没有引入状态机 **/
  struct state_t {
    enum type {
      DISCONNECTED = 0, /** 未连接 **/
      CONNECTING,       /** 正在连接 **/
      HANDSHAKING,      /** 正在握手 **/
      CONNECTED,        /** 已连接 **/
      DISCONNECTING,    /** 正在断开连接 **/
    };
  };

  struct flag_t {
    enum type {
      REG_PROC = 0,      /** 注册了proc记录到node，清理的时候需要移除 **/
      REG_FD,            /** 关联了fd到node或endpoint，清理的时候需要移除 **/
      ACCESS_SHARE_ADDR, /** 共享内部地址（内存通道的地址共享） **/
      ACCESS_SHARE_HOST, /** 共享物理机（共享内存通道的物理机共享） **/
      RESETTING,         /** 正在执行重置（防止递归死循环） **/
      DESTRUCTING,       /** 正在执行析构（屏蔽某些接口） **/
      LISTEN_FD,         /** 是否是用于listen的连接 **/
      TEMPORARY,         /** 是否是临时连接 **/
      PEER_CLOSED,       /** 对端已关闭 **/
      MAX
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
  connection();

 public:
  static ATBUS_MACRO_API ptr_t create(node *owner);

  ATBUS_MACRO_API ~connection();

  ATBUS_MACRO_API void reset();

  /**
   * @brief 执行一帧
   * @param sec 当前时间-秒
   * @param usec 当前时间-微秒
   * @return 本帧处理的消息数
   */
  ATBUS_MACRO_API int proc(node &n, time_t sec, time_t usec);

  /**
   * @brief 监听数据接收地址
   * @param addr 监听地址
   * @param is_caddr 是否是控制节点
   * @return 0或错误码
   */
  ATBUS_MACRO_API int listen(const char *addr);

  /**
   * @brief 连接到目标地址
   * @param addr 连接目标地址
   * @return 0或错误码
   */
  ATBUS_MACRO_API int connect(const char *addr);

  /**
   * @brief 断开连接
   * @note 此接口不会主动把自己从endpoint或者node中移除。如果要断开连接且移除connection，请使用 reset() 接口
   * @return 0或错误码
   */
  ATBUS_MACRO_API int disconnect();

  /**
   * @brief 发送数据
   * @param buffer 数据块地址
   * @param s 数据块长度
   * @return 0或错误码
   * @note 接收端收到的数据很可能不是地址对齐的，所以这里不建议发送内存数据
   *       如果非要发送内存数据的话，一定要memcpy，不能直接类型转换，除非手动设置了地址对齐规则
   */
  ATBUS_MACRO_API int push(const void *buffer, size_t s);

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

  ATBUS_MACRO_API void remove_owner_checker(const timer_desc_ls<ptr_t>::type::iterator &v);

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

  static ATBUS_MACRO_API void iostream_on_recv_cb(channel::io_stream_channel *channel,
                                                  channel::io_stream_connection *connection, int status, void *buffer,
                                                  size_t s);
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
  static ATBUS_MACRO_API int shm_proc_fn(node &n, connection &conn, time_t sec, time_t usec);

  static ATBUS_MACRO_API int shm_free_fn(node &n, connection &conn);

  static ATBUS_MACRO_API int shm_push_fn(connection &conn, const void *buffer, size_t s);
#endif

  static ATBUS_MACRO_API int mem_proc_fn(node &n, connection &conn, time_t sec, time_t usec);

  static ATBUS_MACRO_API int mem_free_fn(node &n, connection &conn);

  static ATBUS_MACRO_API int mem_push_fn(connection &conn, const void *buffer, size_t s);

  static ATBUS_MACRO_API int ios_free_fn(node &n, connection &conn);

  static ATBUS_MACRO_API int ios_push_fn(connection &conn, const void *buffer, size_t s);

  static ATBUS_MACRO_API bool unpack(connection &conn, ::atbus::protocol::msg *&m,
                                     ::ATBUS_MACRO_PROTOBUF_NAMESPACE_ID::Arena &arena, std::vector<unsigned char> &in);

 private:
  state_t::type state_;
  channel::channel_address_t address_;
#if !defined(_WIN32)
  int address_lock_;
  std::string address_lock_path_;
#endif
  std::bitset<flag_t::MAX> flags_;

  // 这里不用智能指针是为了该值在上层对象（node或者endpoint）析构时仍然可用
  node *owner_;
  timer_desc_ls<ptr_t>::type::iterator owner_checker_;
  endpoint *binding_;
  std::weak_ptr<connection> watcher_;

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
    using proc_fn_t = int (*)(node &n, connection &conn, time_t sec, time_t usec);
    using free_fn_t = int (*)(node &n, connection &conn);
    using push_fn_t = int (*)(connection &conn, const void *buffer, size_t s);

    shared_t shared;
    proc_fn_t proc_fn;
    free_fn_t free_fn;
    push_fn_t push_fn;
  };
  connection_data_t conn_data_;
  stat_t stat_;

  friend class endpoint;
};
}  // namespace atbus
