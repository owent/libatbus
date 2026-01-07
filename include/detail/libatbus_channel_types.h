/**
 * libatbus_channel_types.h
 *
 *  Created on: 2014年8月13日
 *      Author: owent
 */
#ifndef LIBATBUS_CHANNEL_TYPES_H
#define LIBATBUS_CHANNEL_TYPES_H

#pragma once

#include <lock/seq_alloc.h>
#include <memory/rc_ptr.h>

#include <stdint.h>
#include <cstddef>
#include <map>
#include <memory>
#include <ostream>
#include <string>
#include <unordered_map>
#include <utility>

#include "detail/libatbus_config.h"

#include "buffer.h"
#include "detail/libatbus_adapter_libuv.h"

#if defined(__ANDROID__)
#elif defined(__APPLE__)
#  if __dest_os == __mac_os_x
#    include <sys/ipc.h>
#    include <sys/shm.h>

#    define ATBUS_CHANNEL_SHM 1
#  endif
#elif defined(__unix__)
#  include <sys/ipc.h>
#  include <sys/shm.h>

#  define ATBUS_CHANNEL_SHM 1
#else
#  include <Windows.h>

#  define ATBUS_CHANNEL_SHM 1
#endif

ATBUS_MACRO_NAMESPACE_BEGIN
namespace channel {
// utility functions
struct ATBUS_MACRO_API_HEAD_ONLY channel_address_t {
  std::string address;  // 主机完整地址，比如：ipv4://127.0.0.1:8123 或 unix:///tmp/atbut.sock
  std::string scheme;   // 协议名称，比如：ipv4 或 unix/pipe
  std::string host;     // 主机地址，比如：127.0.0.1 或 /tmp/atbut.sock
  int port;             // 端口。（仅网络连接有效）
};

// memory channel
struct mem_channel;
struct mem_conf;

struct ATBUS_MACRO_API_HEAD_ONLY mem_stats_block_error {
  // 统计信息
  size_t write_check_sequence_failed_count;  // 写完后校验操作序号错误
  size_t write_retry_count;                  // 写操作内部重试次数

  size_t read_bad_node_count;                 // 读到的错误数据节点数量
  size_t read_bad_block_count;                // 读到的错误数据块数量
  size_t read_write_timeout_count;            // 读到的写超时保护数量
  size_t read_check_block_size_failed_count;  // 读到的数据块长度检查错误数量
  size_t read_check_node_size_failed_count;   // 读到的数据节点和长度检查错误数量
  size_t read_check_hash_failed_count;        // 读到的数据hash值检查错误数量
};

#ifdef ATBUS_CHANNEL_SHM
// shared memory channel
struct shm_channel;
struct shm_conf;

using shm_stats_block_error = mem_stats_block_error;
#endif

// stream channel(tcp,pipe(unix socket) and etc. udp is not a stream)
struct io_stream_connection;
struct io_stream_channel;
using io_stream_callback_t = void (*)(io_stream_channel *channel,        // 事件触发的channel
                                      io_stream_connection *connection,  // 事件触发的连接
                                      int status,                        // libuv传入的转态码
                                      void *,                            // 额外参数(不同事件不同含义)
                                      size_t s                           // 额外参数长度
);

struct ATBUS_MACRO_API_HEAD_ONLY io_stream_callback_evt_t {
  enum mem_fn_t {
    EN_FN_ACCEPTED = 0,
    EN_FN_CONNECTED,  // 连接或listen成功
    EN_FN_DISCONNECTED,
    EN_FN_RECVED,
    EN_FN_WRITEN,
    MAX
  };
  // 回调函数
  io_stream_callback_t callbacks[MAX];
};

// 以下不是POD类型，所以不得不暴露出来
struct ATBUS_MACRO_API_HEAD_ONLY io_stream_connection {
  enum flag_t {
    EN_CF_LISTEN = 0,
    EN_CF_CONNECT,
    EN_CF_ACCEPT,
    EN_CF_WRITING,
    EN_CF_CLOSING,
    EN_CF_MAX,
  };

  channel_address_t addr;
  ::atfw::util::memory::strong_rc_ptr<adapter::stream_t> handle;  // 流设备
  adapter::fd_t fd;                                               // 文件描述符

  enum status_t { EN_ST_CREATED = 0, EN_ST_CONNECTED, EN_ST_DISCONNECTING, EN_ST_DISCONNECTED };
  status_t status;  // 状态
  int flags;        // flag
  io_stream_channel *channel;

  // 事件响应
  io_stream_callback_evt_t evt;
  io_stream_callback_t act_disc_cbk;  // 主动关闭连接的回调（为了减少额外分配而采用的缓存策略）

  // 数据区域
  // 读数据缓冲区(两种Buffer管理方式，一种动态，一种静态)
  /**
   * @note 由于大多数数据包都比较小
   *        当数据包比较小时和动态直接放在动态int的数据包一起，这样可以减少内存拷贝次数
   */
  ::atframework::atbus::detail::buffer_manager read_buffers;

  struct read_head_t {
    char buffer[ATBUS_MACRO_DATA_SMALL_SIZE];  // varint数据暂存区和小数据包存储区
    size_t len;                                // varint数据暂存区和小数据包存储区已使用长度
  };
  read_head_t read_head;
  ::atframework::atbus::detail::buffer_manager write_buffers;  // 写数据缓冲区(两种Buffer管理方式，一种动态，一种静态)

  // 自定义数据区域
  void *data;
};

struct ATBUS_MACRO_API_HEAD_ONLY io_stream_conf {
  time_t keepalive;

  bool is_noblock;
  bool is_nodelay;
  size_t send_buffer_static;
  size_t recv_buffer_static;
  size_t send_buffer_max_size;
  size_t send_buffer_limit_size;
  size_t recv_buffer_max_size;
  size_t recv_buffer_limit_size;

  int backlog;  // backlog indicates the number of connections the kernel might queue

  time_t confirm_timeout;
  size_t max_read_net_eagain_count;
  size_t max_read_check_block_size_failed_count;
  size_t max_read_check_hash_failed_count;
};

struct ATBUS_MACRO_API_HEAD_ONLY io_stream_channel {
  enum flag_t {
    EN_CF_IS_LOOP_OWNER = 0,
    EN_CF_CLOSING,
    EN_CF_IN_CALLBACK,
    EN_CF_MAX,
  };

  adapter::loop_t *ev_loop;
  int flags;

  io_stream_conf conf;

  using conn_pool_t = std::unordered_map<adapter::fd_t, ::atfw::util::memory::strong_rc_ptr<io_stream_connection>>;
  conn_pool_t conn_pool;
  using conn_gc_pool_t = std::unordered_map<uintptr_t, ::atfw::util::memory::strong_rc_ptr<io_stream_connection>>;
  conn_gc_pool_t conn_gc_pool;

  // 事件响应
  io_stream_callback_evt_t evt;

  int error_code;  // 记录外部的错误码
  // 统计信息
  atfw::util::lock::seq_alloc_u32 active_reqs;  // 正在进行的req数量
  size_t read_net_eagain_count;                 // 读到的网络重试错误数量
  size_t read_check_block_size_failed_count;    // 读到的数据块长度检查错误数量
  size_t read_check_hash_failed_count;          // 读到的数据hash检查错误数量

  // 自定义数据区域
  void *data;
};

#define ATBUS_CHANNEL_IOS_CHECK_FLAG(f, v) (0 != ((f) & (1 << (v))))
#define ATBUS_CHANNEL_IOS_SET_FLAG(f, v) (f) |= (1 << (v))
#define ATBUS_CHANNEL_IOS_UNSET_FLAG(f, v) (f) &= ~(1 << (v))
#define ATBUS_CHANNEL_IOS_CLEAR_FLAG(f) (f) = 0

#define ATBUS_CHANNEL_REQ_START(channel) (channel)->active_reqs.inc()
#define ATBUS_CHANNEL_REQ_ACTIVE(channel) ((channel)->active_reqs.get() > 0)

#define ATBUS_CHANNEL_REQ_END(channel)       \
  assert(ATBUS_CHANNEL_REQ_ACTIVE(channel)); \
  (channel)->active_reqs.dec()
}  // namespace channel
ATBUS_MACRO_NAMESPACE_END

#endif /* LIBATBUS_CHANNEL_EXPORT_H_ */
