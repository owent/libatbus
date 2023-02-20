/**
 * @brief 所有channel文件的模式均为 c + channel<br />
 *        使用c的模式是为了简单、结构清晰并且避免异常<br />
 *        附带c++的部分是为了避免命名空间污染并且c++的跨平台适配更加简单
 */

#include <assert.h>
#include <stdint.h>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <memory>
#include <vector>

#ifndef _MSC_VER
#  include <sys/stat.h>
#  include <sys/types.h>
#  include <unistd.h>
#endif

#include "detail/libatbus_config.h"

#if defined(ATBUS_MACRO_WITH_UNIX_SOCK) && ATBUS_MACRO_WITH_UNIX_SOCK
#  include <sys/socket.h>
#  include <sys/un.h>
#endif

#include "common/file_system.h"
#include "common/string_oprs.h"
#include "config/atframe_utils_build_feature.h"
#include "config/compiler_features.h"

#include "algorithm/murmur_hash.h"

#include "detail/buffer.h"
#include "detail/libatbus_channel_export.h"
#include "detail/libatbus_error.h"

#ifdef ATBUS_MACRO_ENABLE_STATIC_ASSERT
#  include <detail/libatbus_channel_types.h>
#  include <type_traits>

#endif

#define ATBUS_MACRO_TLS_MERGE_BUFFER_LEN (ATBUS_MACRO_MSG_LIMIT - ATBUS_MACRO_DATA_ALIGN_SIZE - sizeof(uv_write_t))

#if !(defined(THREAD_TLS_USE_PTHREAD) && THREAD_TLS_USE_PTHREAD) && defined(UTIL_CONFIG_THREAD_LOCAL)
namespace atbus {
namespace channel {
namespace detail {
static char *io_stream_get_msg_buffer() {
  static UTIL_CONFIG_THREAD_LOCAL char ret[ATBUS_MACRO_TLS_MERGE_BUFFER_LEN];
  return ret;
}
}  // namespace detail
}  // namespace channel
}  // namespace atbus
#else

#  include <pthread.h>
namespace atbus {
namespace channel {
namespace detail {
static pthread_once_t gt_io_stream_get_msg_buffer_tls_once = PTHREAD_ONCE_INIT;
static pthread_key_t gt_io_stream_get_msg_buffer_tls_key;

static void dtor_pthread_io_stream_get_msg_buffer_tls(void *p) {
  char *res = reinterpret_cast<char *>(p);
  if (nullptr != res) {
    delete[] res;
  }
}

static void init_pthread_io_stream_get_msg_buffer_tls() {
  (void)pthread_key_create(&gt_io_stream_get_msg_buffer_tls_key, dtor_pthread_io_stream_get_msg_buffer_tls);
}

static char *io_stream_get_msg_buffer() {
  (void)pthread_once(&gt_io_stream_get_msg_buffer_tls_once, init_pthread_io_stream_get_msg_buffer_tls);
  char *ret = reinterpret_cast<char *>(pthread_getspecific(gt_io_stream_get_msg_buffer_tls_key));
  if (nullptr == ret) {
    ret = new char[ATBUS_MACRO_TLS_MERGE_BUFFER_LEN];
    pthread_setspecific(gt_io_stream_get_msg_buffer_tls_key, ret);
  }
  return ret;
}

struct gt_io_stream_get_msg_buffer_tls_main_thread_dtor_t {
  char *buffer_ptr;
  gt_io_stream_get_msg_buffer_tls_main_thread_dtor_t() { buffer_ptr = io_stream_get_msg_buffer(); }

  ~gt_io_stream_get_msg_buffer_tls_main_thread_dtor_t() {
    pthread_setspecific(gt_io_stream_get_msg_buffer_tls_key, nullptr);
    dtor_pthread_io_stream_get_msg_buffer_tls(buffer_ptr);
  }
};
static gt_io_stream_get_msg_buffer_tls_main_thread_dtor_t gt_io_stream_get_msg_buffer_tls_main_thread_dtor;
}  // namespace detail
}  // namespace channel
}  // namespace atbus

#endif

namespace atbus {
namespace channel {

#ifdef ATBUS_MACRO_ENABLE_STATIC_ASSERT
#  if ((defined(_MSVC_LANG) && _MSVC_LANG >= 201402L)) ||                       \
      (defined(__cplusplus) && __cplusplus >= 201402L &&                        \
       !(!defined(__clang__) && defined(__GNUC__) && defined(__GNUC_MINOR__) && \
         __GNUC__ * 100 + __GNUC_MINOR__ <= 409))
static_assert(std::is_trivially_copyable<io_stream_conf>::value, "io_stream_conf should be trivially copyable");
#  elif (defined(__cplusplus) && __cplusplus >= 201103L) || ((defined(_MSVC_LANG) && _MSVC_LANG >= 201103L))
static_assert(std::is_trivial<io_stream_conf>::value, "io_stream_conf should be trivially");
#  else
static_assert(std::is_pod<io_stream_conf>::value, "io_stream_conf should be a pod type");
#  endif
static_assert(io_stream_channel::EN_CF_MAX <= sizeof(int) * 8,
              "io_stream_channel::flag_t should has no more bits than io_stream_channel::flags");
#endif

union io_stream_sockaddr_switcher {
  sockaddr base;
  sockaddr_in ipv4;
  sockaddr_in6 ipv6;
};

struct io_stream_flag_guard {
  int *flags;
  int watch;
  bool is_active;
  io_stream_flag_guard(int &f, int v) : flags(&f), watch(v) {
    if (ATBUS_CHANNEL_IOS_CHECK_FLAG(*flags, watch)) {
      is_active = false;
    } else {
      ATBUS_CHANNEL_IOS_SET_FLAG(*flags, watch);
      is_active = true;
    }
  }

  ~io_stream_flag_guard() {
    if (is_active) {
      ATBUS_CHANNEL_IOS_UNSET_FLAG(*flags, watch);
    }
  }

  io_stream_flag_guard(const io_stream_flag_guard &other);
  io_stream_flag_guard &operator=(const io_stream_flag_guard &other);
};

static int io_stream_disconnect_inner(io_stream_channel *channel, io_stream_connection *connection,
                                      io_stream_callback_t callback, bool force);

static inline void io_stream_channel_callback(io_stream_callback_evt_t::mem_fn_t fn, io_stream_channel *channel,
                                              io_stream_callback_t async_callback, io_stream_connection *connection,
                                              int status, int errcode, void *priv_data, size_t s) {
  if (nullptr != channel) {
    channel->error_code = status;
  }

  if (nullptr != channel && nullptr != channel->evt.callbacks[fn]) {
    channel->evt.callbacks[fn](channel, connection, errcode, priv_data, s);
  }

  if (nullptr != async_callback) {
    async_callback(channel, connection, errcode, priv_data, s);
  }
}

static inline void io_stream_channel_callback(io_stream_callback_evt_t::mem_fn_t fn, io_stream_channel *channel,
                                              io_stream_connection *conn_evt, io_stream_connection *connection,
                                              int status, int errcode, void *priv_data, size_t s) {
  io_stream_callback_t async_callback =
      (nullptr != conn_evt && nullptr != conn_evt->evt.callbacks[fn]) ? conn_evt->evt.callbacks[fn] : nullptr;
  io_stream_channel_callback(fn, channel, async_callback, connection, status, errcode, priv_data, s);
}

static inline void io_stream_channel_callback(io_stream_callback_evt_t::mem_fn_t fn, io_stream_channel *channel,
                                              io_stream_connection *connection, int status, int errcode,
                                              void *priv_data, size_t s) {
  io_stream_channel_callback(fn, channel, connection, connection, status, errcode, priv_data, s);
}

void io_stream_init_configure(io_stream_conf *conf) {
  if (nullptr == conf) {
    return;
  }

  conf->keepalive = 60;
  conf->is_noblock = true;
  conf->is_nodelay = true;
  conf->send_buffer_static = 0;  // 默认动态缓冲区
  conf->recv_buffer_static = 0;  // 默认动态缓冲区

  conf->send_buffer_max_size = 0;
  conf->send_buffer_limit_size =
      ATBUS_MACRO_MSG_LIMIT +
      ::atbus::detail::buffer_block::padding_size(sizeof(uv_write_t) + sizeof(uint32_t) + 16);  // 预留header长度

  conf->recv_buffer_max_size =
      ATBUS_MACRO_MSG_LIMIT * 2;  // 最大接收缓冲区2个最大包体够了，一般一个正在处理的和一个正在接收的
  conf->recv_buffer_limit_size = ATBUS_MACRO_MSG_LIMIT;

  conf->backlog = ATBUS_MACRO_CONNECTION_BACKLOG;

  conf->confirm_timeout = 10;
  conf->max_read_net_eagain_count = 256;
  conf->max_read_check_block_size_failed_count = 10;
  conf->max_read_check_hash_failed_count = 10;
}

static adapter::loop_t *io_stream_get_loop(io_stream_channel *channel) {
  if (nullptr == channel) {
    return nullptr;
  }

  if (nullptr == channel->ev_loop) {
    channel->ev_loop = reinterpret_cast<adapter::loop_t *>(malloc(sizeof(adapter::loop_t)));
    if (nullptr != channel->ev_loop) {
      uv_loop_init(channel->ev_loop);
      ATBUS_CHANNEL_IOS_SET_FLAG(channel->flags, io_stream_channel::EN_CF_IS_LOOP_OWNER);
    }
  }

  return channel->ev_loop;
}

int io_stream_init(io_stream_channel *channel, adapter::loop_t *ev_loop, const io_stream_conf *conf) {
  if (nullptr == channel) {
    return EN_ATBUS_ERR_PARAMS;
  }

  if (nullptr == conf) {
    io_stream_conf default_conf;
    io_stream_init_configure(&default_conf);

    return io_stream_init(channel, ev_loop, &default_conf);
  }

  channel->conf = *conf;
  channel->ev_loop = ev_loop;
  ATBUS_CHANNEL_IOS_CLEAR_FLAG(channel->flags);

  memset(channel->evt.callbacks, 0, sizeof(channel->evt.callbacks));

  channel->error_code = 0;
  channel->read_net_eagain_count = 0;
  channel->read_check_block_size_failed_count = 0;
  channel->read_check_hash_failed_count = 0;
  return EN_ATBUS_ERR_SUCCESS;
}

int io_stream_close(io_stream_channel *channel) {
  if (nullptr == channel) {
    return EN_ATBUS_ERR_PARAMS;
  }

  io_stream_flag_guard flag_guard(channel->flags, io_stream_channel::EN_CF_CLOSING);

  // 不允许在回调中关闭
  if (ATBUS_CHANNEL_IOS_CHECK_FLAG(channel->flags, io_stream_channel::EN_CF_IN_CALLBACK)) {
    abort();
  }

  // 释放所有连接
  {
    std::vector<io_stream_connection *> pending_release;
    pending_release.reserve(channel->conn_pool.size());
    for (io_stream_channel::conn_pool_t::iterator iter = channel->conn_pool.begin(); iter != channel->conn_pool.end();
         ++iter) {
      pending_release.push_back(iter->second.get());
    }

    for (size_t i = 0; i < pending_release.size(); ++i) {
      io_stream_disconnect(channel, pending_release[i], nullptr);
    }
  }

  // 必须保证这个接口过后channel内的数据可以正常释放
  // 所以必须等待相关的回调全部完成
  // 当然也可以用另一种方法强行结束掉所有req，但是这样会造成丢失回调
  // 并且这会要求逻辑层设计相当完善，否则可能导致内存泄漏。所以为了简化逻辑层设计，还是block并销毁所有数据

  if (ATBUS_CHANNEL_IOS_CHECK_FLAG(channel->flags, io_stream_channel::EN_CF_IS_LOOP_OWNER) &&
      nullptr != channel->ev_loop) {
    // 先清理掉所有可以完成的事件
    while (uv_run(channel->ev_loop, UV_RUN_NOWAIT)) {
      uv_run(channel->ev_loop, UV_RUN_ONCE);
    }

    // 停止时阻塞操作，保证资源正常释放
    while (UV_EBUSY == uv_loop_close(channel->ev_loop)) {
      uv_run(channel->ev_loop, UV_RUN_ONCE);
    }

    free(channel->ev_loop);
  } else {
    // both connection and pending gc connection should all be erased
    while (!channel->conn_pool.empty() || !channel->conn_gc_pool.empty()) {
      uv_run(channel->ev_loop, UV_RUN_ONCE);
    }

    // 必须等待所有pending的request完成
    // 不能简单地用uv_loop_t的active状态判定，因为可能内部会维护uv_async_t来
    while (ATBUS_CHANNEL_REQ_ACTIVE(channel)) {
      uv_run(channel->ev_loop, UV_RUN_ONCE);
    }
  }

  channel->ev_loop = nullptr;

  return EN_ATBUS_ERR_SUCCESS;
}

int io_stream_run(io_stream_channel *channel, adapter::run_mode_t mode) {
  if (nullptr == channel) {
    return EN_ATBUS_ERR_PARAMS;
  }

  channel->error_code = uv_run(io_stream_get_loop(channel), static_cast<uv_run_mode>(mode));
  if (0 != channel->error_code) {
    return EN_ATBUS_ERR_EV_RUN;
  }

  return EN_ATBUS_ERR_SUCCESS;
}

static void io_stream_on_recv_alloc_fn(uv_handle_t *handle, size_t /*suggested_size*/, uv_buf_t *buf) {
  assert(handle && handle->data);
  if (nullptr == handle || nullptr == handle->data) {
    return;
  }
  io_stream_connection *conn_raw_ptr = reinterpret_cast<io_stream_connection *>(handle->data);
  assert(conn_raw_ptr && conn_raw_ptr->channel);
  if (nullptr == conn_raw_ptr->channel) {
    return;
  }

  io_stream_flag_guard flag_guard(conn_raw_ptr->channel->flags, io_stream_channel::EN_CF_IN_CALLBACK);

  // 如果正处于关闭阶段，忽略所有数据
  if (io_stream_connection::EN_ST_CONNECTED != conn_raw_ptr->status) {
    buf->base = nullptr;
    buf->len = 0;
    uv_read_stop(conn_raw_ptr->handle.get());
    return;
  }

  void *data = nullptr;
  size_t sread = 0, swrite = 0;
  conn_raw_ptr->read_buffers.back(data, sread, swrite);

  // 正在读取vint时，指定缓冲区为head内存块
  if (nullptr == data || 0 == swrite) {
#ifdef _MSC_VER
    buf->len = static_cast<decltype(buf->len)>(sizeof(conn_raw_ptr->read_head.buffer) - conn_raw_ptr->read_head.len);
#else
    buf->len = sizeof(conn_raw_ptr->read_head.buffer) - conn_raw_ptr->read_head.len;
#endif

    if (0 == buf->len) {
      // 理论上这里不会走到，因为如果必然会先收取一次header的大小，这时候已经可以解出msg的大小
      // 如果msg超过限制大小并低于缓冲区大小，则会发出大小错误回调并会减少header的占用量，
      // 那么下一次这个回调函数调用时buf->len必然大于0
      // 如果msg超过缓冲区大小，则会出错回调并立即断开连接,不会再有下一次调用
      buf->base = nullptr;
    } else {
      buf->base = &conn_raw_ptr->read_head.buffer[conn_raw_ptr->read_head.len];
    }
    return;
  }

  // 否则指定为大内存块缓冲区
  buf->base = reinterpret_cast<char *>(data);
#ifdef _MSC_VER
  buf->len = static_cast<decltype(buf->len)>(swrite);
#else
  buf->len = swrite;
#endif
}

static void io_stream_on_recv_read_fn(uv_stream_t *stream, ssize_t nread, const uv_buf_t * /*buf*/) {
  io_stream_connection *conn_raw_ptr = reinterpret_cast<io_stream_connection *>(stream->data);
  assert(conn_raw_ptr);
  io_stream_channel *channel = conn_raw_ptr->channel;
  assert(channel);

  io_stream_flag_guard flag_guard(channel->flags, io_stream_channel::EN_CF_IN_CALLBACK);

  // 如果正处于关闭阶段，忽略所有数据
  if (io_stream_connection::EN_ST_CONNECTED != conn_raw_ptr->status) {
    return;
  }

  // 读取完或EAGAIN或signal中断，直接忽略即可
  if (0 == nread || UV_EAGAIN == nread || UV_EAI_AGAIN == nread || UV_EINTR == nread) {
    ++channel->read_net_eagain_count;
    if (channel->read_net_eagain_count > channel->conf.max_read_net_eagain_count) {
      // eagain for too many times, just close
      io_stream_disconnect(channel, conn_raw_ptr, nullptr);
    }
    return;
  }

  // 网络错误
  if (nread < 0) {
    io_stream_channel_callback(io_stream_callback_evt_t::EN_FN_RECVED, channel, conn_raw_ptr, static_cast<int>(nread),
                               EN_ATBUS_ERR_READ_FAILED, nullptr, 0);

    // 任何非重试的错误则关闭
    // 注意libuv有个特殊的错误码 UV_ENOBUFS 表示缓冲区不足
    // 理论上除非配置错误，否则不应该会出现，并且可能会导致header数据无法缩减。所以也直接关闭连接
    io_stream_disconnect_inner(channel, conn_raw_ptr, nullptr, nread == UV_ECONNRESET);
    return;
  }

  void *data = nullptr;
  size_t sread = 0, swrite = 0;
  conn_raw_ptr->read_buffers.back(data, sread, swrite);
  bool is_free = false;

  // head 阶段
  if (nullptr == data || 0 == swrite) {
    assert(static_cast<size_t>(nread) <= sizeof(conn_raw_ptr->read_head.buffer) - conn_raw_ptr->read_head.len);
    conn_raw_ptr->read_head.len += static_cast<size_t>(nread);  // 写数据计数

    // 尝试解出所有的head数据
    char *buff_start = conn_raw_ptr->read_head.buffer;
    size_t buff_left_len = conn_raw_ptr->read_head.len;

    // 可能包含多条消息
    while (buff_left_len > sizeof(uint32_t)) {
      uint64_t msg_len = 0;
      // 前4 字节为32位hash
      size_t vint_len =
          ::atbus::detail::fn::read_vint(msg_len, buff_start + sizeof(uint32_t), buff_left_len - sizeof(uint32_t));

      // 剩余数据不足以解动态长度整数，直接中断退出
      if (0 == vint_len) {
        break;
      }

      // 如果读取vint成功，判定是否有小数据包。并对小数据包直接回调
      if (buff_left_len >= sizeof(uint32_t) + vint_len + msg_len) {
        channel->error_code = 0;
        uint32_t check_hash =
            util::hash::murmur_hash3_x86_32(buff_start + sizeof(uint32_t) + vint_len, static_cast<int>(msg_len), 0);
        uint32_t expect_hash;
        memcpy(&expect_hash, buff_start, sizeof(uint32_t));
        int errcode = EN_ATBUS_ERR_SUCCESS;
        if (check_hash != expect_hash) {
          errcode = EN_ATBUS_ERR_BAD_DATA;
          ++channel->read_check_hash_failed_count;
          if (channel->read_check_hash_failed_count > channel->conf.max_read_check_hash_failed_count) {
            is_free = true;
          }
        } else if (channel->conf.recv_buffer_limit_size > 0 && msg_len > channel->conf.recv_buffer_limit_size) {
          errcode = EN_ATBUS_ERR_INVALID_SIZE;
          ++channel->read_check_block_size_failed_count;
          if (channel->read_check_block_size_failed_count > channel->conf.max_read_check_block_size_failed_count) {
            is_free = true;
          }
        }

        io_stream_channel_callback(io_stream_callback_evt_t::EN_FN_RECVED, channel, conn_raw_ptr, 0, errcode,
                                   buff_start + sizeof(uint32_t) + vint_len,
                                   // 这里的地址未对齐，所以buffer不能直接保存内存数据
                                   msg_len);

        // 32bits hash+vint+buffer
        buff_start += sizeof(uint32_t) + vint_len + msg_len;
        buff_left_len -= sizeof(uint32_t) + vint_len + msg_len;
      } else {
        // 大数据包，使用缓冲区，并且剩余数据一定是在一个包内
        // 32位hash 也暂存在这里
        if (EN_ATBUS_ERR_SUCCESS == conn_raw_ptr->read_buffers.push_back(data, sizeof(uint32_t) + msg_len)) {
          memcpy(data, buff_start, sizeof(uint32_t));  // 32位hash
          memcpy(reinterpret_cast<char *>(data) + sizeof(uint32_t), buff_start + sizeof(uint32_t) + vint_len,
                 buff_left_len - sizeof(uint32_t) - vint_len);
          conn_raw_ptr->read_buffers.pop_back(buff_left_len - vint_len, false);  // vint_len不用保存

          buff_start += buff_left_len;
          buff_left_len = 0;  // 循环退出
        } else {
          // 追加大缓冲区失败，可能是到达缓冲区限制
          // 读缓冲区一般只有一个正在处理的数据包，如果发生创建失败则是数据错误或者这个包就是超出大小限制的
          is_free = true;
          buff_start += sizeof(uint32_t) + vint_len;
          buff_left_len -= sizeof(uint32_t) + vint_len;

          ++channel->read_check_block_size_failed_count;
          break;
        }
      }
    }

    // 后续数据前移
    if (buff_start != conn_raw_ptr->read_head.buffer && buff_left_len > 0) {
      memmove(conn_raw_ptr->read_head.buffer, buff_start, buff_left_len);
    }
    conn_raw_ptr->read_head.len = buff_left_len;
  } else {
    size_t nread_s = static_cast<size_t>(nread);
    assert(nread_s <= swrite);

    // 写数据计数,但不释放缓冲区
    conn_raw_ptr->read_buffers.pop_back(nread_s, false);
  }

  // 如果在大内存块缓冲区，判定回调
  conn_raw_ptr->read_buffers.front(data, sread, swrite);
  if (nullptr != data && 0 == swrite) {
    channel->error_code = 0;
    data = ::atbus::detail::fn::buffer_prev(data, sread);

    // 32位Hash校验和
    uint32_t check_hash = util::hash::murmur_hash3_x86_32(reinterpret_cast<char *>(data) + sizeof(uint32_t),
                                                          static_cast<int>(sread - sizeof(uint32_t)), 0);
    uint32_t expect_hash;
    memcpy(&expect_hash, data, sizeof(uint32_t));
    size_t msg_len = sread - sizeof(uint32_t);  // - hash32 header

    int errcode = EN_ATBUS_ERR_SUCCESS;
    if (check_hash != expect_hash) {
      errcode = EN_ATBUS_ERR_BAD_DATA;
      ++channel->read_check_hash_failed_count;
      if (channel->read_check_hash_failed_count > channel->conf.max_read_check_hash_failed_count) {
        is_free = true;
      }
    } else if (channel->conf.recv_buffer_limit_size > 0 && msg_len > channel->conf.recv_buffer_limit_size) {
      errcode = EN_ATBUS_ERR_INVALID_SIZE;
      ++channel->read_check_block_size_failed_count;
      if (channel->read_check_block_size_failed_count > channel->conf.max_read_check_block_size_failed_count) {
        is_free = true;
      }
    }

    io_stream_channel_callback(io_stream_callback_evt_t::EN_FN_RECVED, channel, conn_raw_ptr, 0, errcode,
                               reinterpret_cast<char *>(data) + sizeof(uint32_t),  // + hash32 header
                               // 由于buffer_block内取出的数据已经保证了字节对齐，所以这里一定是4字节对齐
                               msg_len);

    // 回调并释放缓冲区
    conn_raw_ptr->read_buffers.pop_front(0, true);
  }

  if (is_free) {
    if (conn_raw_ptr->read_head.len > 0) {
      io_stream_channel_callback(io_stream_callback_evt_t::EN_FN_RECVED, channel, conn_raw_ptr, 0,
                                 EN_ATBUS_ERR_INVALID_SIZE, conn_raw_ptr->read_head.buffer,
                                 // 由于buffer_block内取出的数据已经保证了字节对齐，所以这里一定是4字节对齐
                                 conn_raw_ptr->read_head.len);
    }

    // 强制中断
    io_stream_disconnect(channel, conn_raw_ptr, nullptr);
  }
}

static void io_stream_stream_init(io_stream_channel *channel, io_stream_connection *conn, adapter::stream_t *handle) {
  if (nullptr == channel || nullptr == handle) {
    return;
  }

  handle->data = conn;
}

static void io_stream_tcp_init(io_stream_channel *channel, io_stream_connection *conn, adapter::tcp_t *handle) {
  if (nullptr == channel || nullptr == handle) {
    return;
  }

  io_stream_stream_init(channel, conn, reinterpret_cast<adapter::stream_t *>(handle));
}

static void io_stream_pipe_init(io_stream_channel *channel, io_stream_connection *conn, adapter::pipe_t *handle) {
  if (nullptr == channel || nullptr == handle) {
    return;
  }

  io_stream_stream_init(channel, conn, reinterpret_cast<adapter::stream_t *>(handle));
}

static void io_stream_stream_setup(io_stream_channel *channel, adapter::stream_t *handle) {
  if (nullptr == channel || nullptr == handle) {
    return;
  }

  uv_stream_set_blocking(handle, channel->conf.is_noblock ? 0 : 1);
}

static void io_stream_tcp_setup(io_stream_channel *channel, adapter::tcp_t *handle) {
  if (nullptr == channel || nullptr == handle) {
    return;
  }

  if (channel->conf.keepalive > 0) {
    uv_tcp_keepalive(handle, 1, static_cast<unsigned int>(channel->conf.keepalive));
  } else {
    uv_tcp_keepalive(handle, 0, 0);
  }

  uv_tcp_nodelay(handle, channel->conf.is_nodelay ? 1 : 0);
#ifndef _WIN32
  io_stream_stream_setup(channel, reinterpret_cast<adapter::stream_t *>(handle));
#endif
}

static void io_stream_pipe_setup(io_stream_channel *channel, adapter::pipe_t *handle) {
  if (nullptr == channel || nullptr == handle) {
    return;
  }

  io_stream_stream_setup(channel, reinterpret_cast<adapter::stream_t *>(handle));
}

struct io_stream_connect_async_data {
  uv_connect_t req;
  channel_address_t addr;
  io_stream_channel *channel;
  io_stream_callback_t callback;
  std::shared_ptr<adapter::stream_t> stream;
  bool pipe;
  void *priv_data;
  size_t priv_size;
};

static void io_stream_connection_on_close(uv_handle_t *handle) {
  io_stream_connection *conn_raw_ptr = reinterpret_cast<io_stream_connection *>(handle->data);
  // connect not completed, directly exit
  if (nullptr == conn_raw_ptr) {
    return;
  }

  io_stream_channel *channel = conn_raw_ptr->channel;
  assert(channel);
  // 被动断开也会触发回调，这里的流程不计数active的req
  if (nullptr == channel) {
    return;
  }

  io_stream_flag_guard flag_guard(channel->flags, io_stream_channel::EN_CF_IN_CALLBACK);

  io_stream_channel::conn_gc_pool_t::iterator iter =
      channel->conn_gc_pool.find(reinterpret_cast<uintptr_t>(conn_raw_ptr));
  assert(iter != channel->conn_gc_pool.end());

  iter->second->status = io_stream_connection::EN_ST_DISCONNECTED;
  io_stream_channel_callback(io_stream_callback_evt_t::EN_FN_DISCONNECTED, channel, iter->second.get(), 0,
                             EN_ATBUS_ERR_SUCCESS, nullptr, 0);

  if (nullptr != conn_raw_ptr->act_disc_cbk) {
    conn_raw_ptr->act_disc_cbk(channel, conn_raw_ptr, EN_ATBUS_ERR_SUCCESS, nullptr, 0);
  }

  channel->conn_gc_pool.erase(iter);
}

static void io_stream_async_data_on_close(uv_handle_t *handle) {
  assert(handle && handle->data);
  if (nullptr == handle || nullptr == handle->data) {
    return;
  }

  io_stream_connect_async_data *async_data = reinterpret_cast<io_stream_connect_async_data *>(handle->data);
  assert(async_data);
  assert(reinterpret_cast<uv_handle_t *>(async_data->stream.get()) == handle);

  // 这里channel可能已经无效了
  delete async_data;
}

static void io_stream_shared_ptr_on_close(uv_handle_t *handle) {
  assert(handle && handle->data);
  if (nullptr == handle || nullptr == handle->data) {
    return;
  }

  std::shared_ptr<adapter::stream_t> *ptr = reinterpret_cast<std::shared_ptr<adapter::stream_t> *>(handle->data);
  assert(ptr);
  assert(reinterpret_cast<uv_handle_t *>(ptr->get()) == handle);

  // 这里channel可能已经无效了
  delete ptr;
}

// 删除函数，stream绑定在connection上
static int io_stream_shutdown_ev_handle(io_stream_connection *conn) {
  assert(conn && conn->handle);
  assert(conn->handle->data == conn);
  assert(conn->channel);

  // move to gc pool
  if (conn && conn->channel) {
    io_stream_channel::conn_pool_t::iterator iter = conn->channel->conn_pool.find(conn->fd);
    assert(iter != conn->channel->conn_pool.end());

    conn->channel->conn_gc_pool[reinterpret_cast<uintptr_t>(conn)] = iter->second;
    conn->channel->conn_pool.erase(iter);
  }

  // ATBUS_CHANNEL_REQ_START(conn->channel);
  // 被动断开也会触发回调，这里的流程不计数active的req
  uv_close(reinterpret_cast<uv_handle_t *>(conn->handle.get()), io_stream_connection_on_close);

  return 0;
  // uv_shutdown_t* req = new uv_shutdown_t();
  // return uv_shutdown(req, handle, io_stream_connection_on_shutdown);
}

// 删除函数，stream绑定在io_stream_connect_async_data上
static int io_stream_shutdown_ev_handle(io_stream_connect_async_data *async_data) {
  assert(async_data);
  assert(async_data->stream->data == async_data || nullptr == async_data->stream->data);
  async_data->stream->data = async_data;

  // 这里channel可能已经无效了
  uv_close(reinterpret_cast<uv_handle_t *>(async_data->stream.get()), io_stream_async_data_on_close);
  return 0;
}

// 删除函数，stream绑定在shared_ptr上
static int io_stream_shutdown_ev_handle(std::shared_ptr<adapter::stream_t> &stream) {
  assert(nullptr == stream->data);
  stream->data = new std::shared_ptr<adapter::stream_t>(stream);

  // 这里channel可能已经无效了
  uv_close(reinterpret_cast<uv_handle_t *>(stream.get()), io_stream_shared_ptr_on_close);
  return 0;
}

static std::shared_ptr<io_stream_connection> io_stream_make_connection(io_stream_channel *channel,
                                                                       std::shared_ptr<adapter::stream_t> handle) {
  std::shared_ptr<io_stream_connection> ret;
  if (nullptr == channel) {
    return ret;
  }

  ret = std::make_shared<io_stream_connection>();
  if (!ret) {
    return ret;
  }

  if (0 != uv_fileno(reinterpret_cast<const uv_handle_t *>(handle.get()), &ret->fd)) {
    ret.reset();
    return ret;
  }

  ret->handle = handle;
  ret->data = nullptr;
  ATBUS_CHANNEL_IOS_CLEAR_FLAG(ret->flags);
  handle->data = ret.get();

  memset(ret->evt.callbacks, 0, sizeof(ret->evt.callbacks));
  ret->act_disc_cbk = nullptr;
  ret->status = io_stream_connection::EN_ST_CREATED;

  ret->read_buffers.set_limit(channel->conf.recv_buffer_max_size, 0);
  if (channel->conf.recv_buffer_max_size > 0 && channel->conf.recv_buffer_static > 0) {
    ret->read_buffers.set_mode(channel->conf.recv_buffer_max_size, channel->conf.recv_buffer_static);
  }
  ret->read_head.len = 0;

  ret->write_buffers.set_limit(channel->conf.send_buffer_max_size, 0);
  if (channel->conf.send_buffer_max_size > 0 && channel->conf.send_buffer_static > 0) {
    ret->write_buffers.set_mode(channel->conf.send_buffer_max_size, channel->conf.send_buffer_static);
  }

  channel->conn_pool[ret->fd] = ret;
  ret->channel = channel;

  // 监听关闭事件，用于释放资源
  handle->close_cb = io_stream_connection_on_close;

  // 监听可读事件
  uv_read_start(handle.get(), io_stream_on_recv_alloc_fn, io_stream_on_recv_read_fn);

  return ret;
}

// ============ C Style转C++ Style内存管理 ============
template <typename T>
static void io_stream_delete_stream_fn(adapter::stream_t *handle) {
  T *real_conn = reinterpret_cast<T *>(handle);

  // 到这里必须已经释放handle了，否则删除hanlde会导致数据异常。
  assert(uv_is_closing(reinterpret_cast<adapter::handle_t *>(handle)));
  delete real_conn;
}

template <typename T>
static T *io_stream_make_stream_ptr(std::shared_ptr<adapter::stream_t> &res) {
  T *real_conn = new T();
  adapter::stream_t *stream_conn = reinterpret_cast<adapter::stream_t *>(real_conn);
  res = std::shared_ptr<adapter::stream_t>(stream_conn, io_stream_delete_stream_fn<T>);
  stream_conn->data = nullptr;
  return real_conn;
}

// tcp 收到连接通用逻辑
static adapter::tcp_t *io_stream_tcp_connection_common(std::shared_ptr<io_stream_connection> &conn,
                                                       std::shared_ptr<adapter::stream_t> &recv_conn, uv_stream_t *req,
                                                       int &status) {
  io_stream_connection *conn_raw_ptr = reinterpret_cast<io_stream_connection *>(req->data);
  assert(conn_raw_ptr);
  io_stream_channel *channel = conn_raw_ptr->channel;
  assert(channel);

  if (0 != status) {
    return nullptr;
  }

  adapter::tcp_t *tcp_conn = io_stream_make_stream_ptr<adapter::tcp_t>(recv_conn);
  if (nullptr == tcp_conn) {
    return nullptr;
  }

  uv_tcp_init(req->loop, tcp_conn);
  if (0 != (channel->error_code = uv_accept(req, recv_conn.get()))) {
    status = channel->error_code;
    return nullptr;
  }

  // 正在关闭，新连接直接断开，要在accept后执行，以保证连接会被正确断开
  if (ATBUS_CHANNEL_IOS_CHECK_FLAG(channel->flags, io_stream_channel::EN_CF_CLOSING)) {
    return nullptr;
  }

  conn = io_stream_make_connection(channel, recv_conn);

  if (!conn) {
    return nullptr;
  }

  // 后面不会再失败了
  io_stream_tcp_setup(channel, tcp_conn);
  io_stream_tcp_init(channel, conn.get(), tcp_conn);
  return tcp_conn;
}

// tcp/ip 收到连接
static void io_stream_tcp_connection_cb(uv_stream_t *req, int status) {
  io_stream_connection *conn_raw_ptr = reinterpret_cast<io_stream_connection *>(req->data);
  assert(conn_raw_ptr);
  io_stream_channel *channel = conn_raw_ptr->channel;
  assert(channel);
  io_stream_flag_guard flag_guard(channel->flags, io_stream_channel::EN_CF_IN_CALLBACK);

  channel->error_code = status;
  int res = EN_ATBUS_ERR_SUCCESS;

  std::shared_ptr<adapter::stream_t> recv_conn;
  std::shared_ptr<io_stream_connection> conn;

  do {
    adapter::tcp_t *tcp_conn = io_stream_tcp_connection_common(conn, recv_conn, req, status);
    if (nullptr == tcp_conn || !conn) {
      if (ATBUS_CHANNEL_IOS_CHECK_FLAG(channel->flags, io_stream_channel::EN_CF_CLOSING)) {
        res = EN_ATBUS_ERR_CHANNEL_CLOSING;
      } else {
        res = EN_ATBUS_ERR_SOCK_CONNECT_FAILED;
      }
      channel->error_code = status;
      break;
    }

    // 后面不会再失败了

    conn->status = io_stream_connection::EN_ST_CONNECTED;
    ATBUS_CHANNEL_IOS_SET_FLAG(conn->flags, io_stream_connection::EN_CF_ACCEPT);

    union io_stream_sockaddr_switcher sock_addr;
    int name_len = sizeof(sock_addr);
    uv_tcp_getpeername(tcp_conn, &sock_addr.base, &name_len);

    char ip[40] = {0};
    if (sock_addr.base.sa_family == AF_INET6) {
      uv_ip6_name(&sock_addr.ipv6, ip, sizeof(ip));
      make_address("ipv6", ip, sock_addr.ipv6.sin6_port, conn->addr);
    } else {
      uv_ip4_name(&sock_addr.ipv4, ip, sizeof(ip));
      make_address("ipv4", ip, sock_addr.ipv4.sin_port, conn->addr);
    }
  } while (false);

  // 回调函数，如果发起连接接口调用成功一定要调用回调函数
  io_stream_channel_callback(io_stream_callback_evt_t::EN_FN_ACCEPTED, channel, conn_raw_ptr, conn.get(),
                             channel->error_code, res, nullptr, 0);

  if (!conn && recv_conn) {
    // 失败且已accept则关闭
    io_stream_shutdown_ev_handle(recv_conn);
  }
}

// pipe 收到连接
static void io_stream_pipe_connection_cb(uv_stream_t *req, int status) {
  io_stream_connection *conn_raw_ptr = reinterpret_cast<io_stream_connection *>(req->data);
  assert(conn_raw_ptr);
  if (!conn_raw_ptr) {
    return;
  }
  io_stream_channel *channel = conn_raw_ptr->channel;
  assert(channel);
  if (!channel) {
    return;
  }
  io_stream_flag_guard flag_guard(channel->flags, io_stream_channel::EN_CF_IN_CALLBACK);

  channel->error_code = status;
  int res = EN_ATBUS_ERR_SUCCESS;

  std::shared_ptr<io_stream_connection> conn;
  std::shared_ptr<adapter::stream_t> recv_conn;

  do {
    if (0 != status || nullptr == channel) {
      res = EN_ATBUS_ERR_PIPE_CONNECT_FAILED;
      break;
    }

    adapter::pipe_t *pipe_conn = io_stream_make_stream_ptr<adapter::pipe_t>(recv_conn);
    if (nullptr == pipe_conn) {
      res = EN_ATBUS_ERR_PIPE_CONNECT_FAILED;
      break;
    }

    uv_pipe_init(req->loop, pipe_conn, 1);
    if (0 != (channel->error_code = uv_accept(req, recv_conn.get()))) {
      res = EN_ATBUS_ERR_PIPE_CONNECT_FAILED;
      break;
    }

    // 正在关闭，新连接直接断开，要在accept后执行，以保证新连接能被正确断开
    if (ATBUS_CHANNEL_IOS_CHECK_FLAG(channel->flags, io_stream_channel::EN_CF_CLOSING)) {
      res = EN_ATBUS_ERR_CHANNEL_CLOSING;
      break;
    }

    conn = io_stream_make_connection(channel, recv_conn);

    if (!conn) {
      res = EN_ATBUS_ERR_PIPE_CONNECT_FAILED;
      break;
    }

    // 后面不会再失败了

    conn->status = io_stream_connection::EN_ST_CONNECTED;

    io_stream_pipe_setup(channel, pipe_conn);
    io_stream_pipe_init(channel, conn.get(), pipe_conn);

    char pipe_path[util::file_system::MAX_PATH_LEN];
    size_t path_len = sizeof(pipe_path);
    uv_pipe_getpeername(pipe_conn, pipe_path, &path_len);
    if (0 == path_len || 0 == pipe_path[0]) {
      path_len = sizeof(pipe_path);
      uv_pipe_getsockname(pipe_conn, pipe_path, &path_len);
    }
    if (path_len < sizeof(pipe_path)) {
      pipe_path[path_len] = 0;
    } else {
      pipe_path[sizeof(pipe_path) - 1] = 0;
    }
    make_address("unix", pipe_path, 0, conn->addr);

  } while (false);

  // 回调函数，如果发起连接接口调用成功一定要调用回调函数
  io_stream_channel_callback(io_stream_callback_evt_t::EN_FN_ACCEPTED, channel, conn_raw_ptr, conn.get(),
                             channel->error_code, res, nullptr, 0);

  if (!conn && recv_conn) {
    // 没什么要做的，直接关闭吧
    io_stream_shutdown_ev_handle(recv_conn);
  }
}

// listen 接口传入域名时的回调异步数据
struct io_stream_dns_async_data {
  io_stream_channel *channel;
  channel_address_t addr;
  io_stream_callback_t callback;
  uv_getaddrinfo_t req;
  void *priv_data;
  size_t priv_size;
};

// listen 接口传入域名时的回调
static void io_stream_dns_connection_cb(uv_getaddrinfo_t *req, int status, struct addrinfo *res) {
  assert(req && req->data);
  if (nullptr == req || nullptr == req->data) {
    return;
  }

  io_stream_dns_async_data *async_data = reinterpret_cast<io_stream_dns_async_data *>(req->data);
  assert(async_data);
  assert(async_data->channel);

  if (nullptr == async_data->channel) {
    return;
  }
  ATBUS_CHANNEL_REQ_END(async_data->channel);

  io_stream_flag_guard flag_guard(async_data->channel->flags, io_stream_channel::EN_CF_IN_CALLBACK);

  int listen_res = status;
  do {
    async_data->channel->error_code = status;

    if (0 != status) {
      break;
    }

    if (nullptr == async_data) {
      listen_res = -1;
      break;
    }

    if (nullptr == res) {
      listen_res = -1;
      break;
    }

    if (AF_INET == res->ai_family) {
      sockaddr_in *res_c = reinterpret_cast<sockaddr_in *>(res->ai_addr);
      char ip[17] = {0};
      uv_ip4_name(res_c, ip, sizeof(ip));
      make_address("ipv4", ip, async_data->addr.port, async_data->addr);
      listen_res = io_stream_listen(async_data->channel, async_data->addr, async_data->callback, async_data->priv_data,
                                    async_data->priv_size);
    } else if (AF_INET6 == res->ai_family) {
      sockaddr_in6 *res_c = reinterpret_cast<sockaddr_in6 *>(res->ai_addr);
      char ip[40] = {0};
      uv_ip6_name(res_c, ip, sizeof(ip));
      make_address("ipv6", ip, async_data->addr.port, async_data->addr);
      listen_res = io_stream_listen(async_data->channel, async_data->addr, async_data->callback, async_data->priv_data,
                                    async_data->priv_size);
    } else {
      listen_res = -1;
    }
  } while (false);

  // 接口调用不成功则要调用回调函数
  if (0 != listen_res) {
    io_stream_channel_callback(io_stream_callback_evt_t::EN_FN_CONNECTED, async_data->channel, async_data->callback,
                               nullptr, listen_res, EN_ATBUS_ERR_DNS_GETADDR_FAILED, async_data->priv_data,
                               async_data->priv_size);
  }

  if (nullptr != async_data) {
    delete async_data;
  }

  if (nullptr != res) {
    uv_freeaddrinfo(res);
  }
}

int io_stream_listen(io_stream_channel *channel, const channel_address_t &addr, io_stream_callback_t callback,
                     void *priv_data, size_t priv_size) {
  if (nullptr == channel) {
    return EN_ATBUS_ERR_PARAMS;
  }

  // 正在关闭，不允许启用新的监听
  if (ATBUS_CHANNEL_IOS_CHECK_FLAG(channel->flags, io_stream_channel::EN_CF_CLOSING)) {
    return EN_ATBUS_ERR_CHANNEL_CLOSING;
  }

  adapter::loop_t *ev_loop = io_stream_get_loop(channel);
  if (nullptr == ev_loop) {
    return EN_ATBUS_ERR_MALLOC;
  }

  // socket
  if (0 == UTIL_STRFUNC_STRNCASE_CMP("ipv4", addr.scheme.c_str(), 4) ||
      0 == UTIL_STRFUNC_STRNCASE_CMP("ipv6", addr.scheme.c_str(), 4)) {
    std::shared_ptr<adapter::stream_t> listen_conn;
    std::shared_ptr<io_stream_connection> conn;
    adapter::tcp_t *handle = io_stream_make_stream_ptr<adapter::tcp_t>(listen_conn);
    if (nullptr == handle) {
      return EN_ATBUS_ERR_MALLOC;
    }

    uv_tcp_init(ev_loop, handle);
#ifndef _WIN32
    {
      uv_os_fd_t raw_fd;
      if (0 == uv_fileno(reinterpret_cast<uv_handle_t *>(handle), &raw_fd)) {
        /* Allow reuse of the port and address. */
        int value = 1;
        setsockopt(raw_fd, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const void *>(&value), sizeof(value));
      }
    }
#endif
    int ret = EN_ATBUS_ERR_SUCCESS;
    do {
      io_stream_tcp_setup(channel, handle);

      if ('4' == addr.scheme[3]) {
        sockaddr_in sock_addr;
        uv_ip4_addr(addr.host.c_str(), addr.port, &sock_addr);
        if (0 != (channel->error_code = uv_tcp_bind(handle, reinterpret_cast<const sockaddr *>(&sock_addr), 0))) {
          ret = EN_ATBUS_ERR_SOCK_BIND_FAILED;
          break;
        }

        if (0 != (channel->error_code = uv_listen(reinterpret_cast<adapter::stream_t *>(handle), channel->conf.backlog,
                                                  io_stream_tcp_connection_cb))) {
          ret = EN_ATBUS_ERR_SOCK_LISTEN_FAILED;
          break;
        }

      } else {
        sockaddr_in6 sock_addr;
        uv_ip6_addr(addr.host.c_str(), addr.port, &sock_addr);
        if (0 != (channel->error_code = uv_tcp_bind(handle, reinterpret_cast<const sockaddr *>(&sock_addr), 0))) {
          ret = EN_ATBUS_ERR_SOCK_BIND_FAILED;
          break;
        }

        if (0 != (channel->error_code = uv_listen(reinterpret_cast<adapter::stream_t *>(handle), channel->conf.backlog,
                                                  io_stream_tcp_connection_cb))) {
          ret = EN_ATBUS_ERR_SOCK_LISTEN_FAILED;
          break;
        }
      }

      conn = io_stream_make_connection(channel, listen_conn);
      if (!conn) {
        ret = EN_ATBUS_ERR_MALLOC;
        break;
      }
      conn->addr = addr;
      conn->status = io_stream_connection::EN_ST_CONNECTED;
      ATBUS_CHANNEL_IOS_SET_FLAG(conn->flags, io_stream_connection::EN_CF_LISTEN);

      io_stream_tcp_init(channel, conn.get(), handle);
      io_stream_channel_callback(io_stream_callback_evt_t::EN_FN_CONNECTED, channel, callback, conn.get(), 0, ret,
                                 priv_data, priv_size);
      return ret;
    } while (false);

    if (conn) {
      io_stream_shutdown_ev_handle(conn.get());
    } else if (listen_conn) {
      io_stream_shutdown_ev_handle(listen_conn);
    }
    return ret;
  } else if (0 == UTIL_STRFUNC_STRNCASE_CMP("unix", addr.scheme.c_str(), 4)) {
    if (0 != io_stream_get_max_unix_socket_length() && addr.host.size() >= io_stream_get_max_unix_socket_length()) {
      return EN_ATBUS_ERR_PIPE_ADDR_TOO_LONG;
    }

    // try to mkdir for basedir
    {
      std::string dirname;
      if (util::file_system::dirname(addr.host.c_str(), addr.host.size(), dirname)) {
        if (!util::file_system::is_exist(dirname.c_str())) {
          util::file_system::mkdir(dirname.c_str(), true);
        }
      }
    }
    std::shared_ptr<adapter::stream_t> listen_conn;
    std::shared_ptr<io_stream_connection> conn;
    adapter::pipe_t *handle = io_stream_make_stream_ptr<adapter::pipe_t>(listen_conn);
    // Only a connected pipe that will be passing the handles should have this flag set, not the listening pipe that
    // uv_accept is called on.
    // @see http://docs.libuv.org/en/v1.x/pipe.html
    uv_pipe_init(ev_loop, handle, 0);
    int ret = EN_ATBUS_ERR_SUCCESS;
    do {
      if (0 != (channel->error_code = uv_pipe_bind(handle, addr.host.c_str()))) {
        if (channel->error_code == UV_EADDRINUSE) {
          ret = EN_ATBUS_ERR_PIPE_PATH_EXISTS;
        } else {
          ret = EN_ATBUS_ERR_PIPE_BIND_FAILED;
        }
        break;
      }

      io_stream_pipe_setup(channel, handle);
      if (0 != (channel->error_code = uv_listen(reinterpret_cast<adapter::stream_t *>(handle), channel->conf.backlog,
                                                io_stream_pipe_connection_cb))) {
        ret = EN_ATBUS_ERR_PIPE_LISTEN_FAILED;
        break;
      }

      conn = io_stream_make_connection(channel, listen_conn);
      if (!conn) {
        ret = EN_ATBUS_ERR_MALLOC;
        break;
      }

      conn->addr = addr;
      conn->status = io_stream_connection::EN_ST_CONNECTED;
      ATBUS_CHANNEL_IOS_SET_FLAG(conn->flags, io_stream_connection::EN_CF_LISTEN);

      io_stream_pipe_init(channel, conn.get(), handle);
      io_stream_channel_callback(io_stream_callback_evt_t::EN_FN_CONNECTED, channel, callback, conn.get(), 0, ret,
                                 priv_data, priv_size);
      return ret;
    } while (false);

    if (conn) {
      io_stream_shutdown_ev_handle(conn.get());
    } else if (listen_conn) {
      io_stream_shutdown_ev_handle(listen_conn);
    }
    return ret;
  } else if (0 == UTIL_STRFUNC_STRNCASE_CMP("dns", addr.scheme.c_str(), 3)) {
    io_stream_dns_async_data *async_data = new io_stream_dns_async_data();
    if (nullptr == async_data) {
      return EN_ATBUS_ERR_MALLOC;
    }
    async_data->channel = channel;
    async_data->addr = addr;
    async_data->callback = callback;
    async_data->req.data = async_data;
    async_data->priv_data = priv_data;
    async_data->priv_size = priv_size;

    if (0 !=
        uv_getaddrinfo(ev_loop, &async_data->req, io_stream_dns_connection_cb, addr.host.c_str(), nullptr, nullptr)) {
      delete async_data;
      return EN_ATBUS_ERR_DNS_GETADDR_FAILED;
    }
    ATBUS_CHANNEL_REQ_START(async_data->channel);

    return EN_ATBUS_ERR_SUCCESS;
  }

  return EN_ATBUS_ERR_CHANNEL_NOT_SUPPORT;
}

static void io_stream_all_connected_cb(uv_connect_t *req, int status) {
  io_stream_connect_async_data *async_data = reinterpret_cast<io_stream_connect_async_data *>(req->data);
  assert(async_data);
  assert(async_data->channel);
  ATBUS_CHANNEL_REQ_END(async_data->channel);

  io_stream_flag_guard flag_guard(async_data->channel->flags, io_stream_channel::EN_CF_IN_CALLBACK);

  int errcode = EN_ATBUS_ERR_SUCCESS;
  async_data->channel->error_code = status;
  std::shared_ptr<io_stream_connection> conn;
  do {
    if (0 != status) {
      if (async_data->pipe) {
        errcode = EN_ATBUS_ERR_PIPE_CONNECT_FAILED;
      } else {
        errcode = EN_ATBUS_ERR_SOCK_CONNECT_FAILED;
      }

      break;
    }

    // 正在关闭，新连接直接断开
    if (ATBUS_CHANNEL_IOS_CHECK_FLAG(async_data->channel->flags, io_stream_channel::EN_CF_CLOSING)) {
      errcode = EN_ATBUS_ERR_CHANNEL_CLOSING;
      break;
    }

    conn = io_stream_make_connection(async_data->channel, async_data->stream);
    if (!conn) {
      errcode = EN_ATBUS_ERR_MALLOC;
      break;
    }
    conn->addr = async_data->addr;

    if (async_data->pipe) {
      io_stream_pipe_init(async_data->channel, conn.get(), reinterpret_cast<adapter::pipe_t *>(req->handle));
    } else {
      io_stream_tcp_init(async_data->channel, conn.get(), reinterpret_cast<adapter::tcp_t *>(req->handle));
    }

    conn->status = io_stream_connection::EN_ST_CONNECTED;
    ATBUS_CHANNEL_IOS_SET_FLAG(conn->flags, io_stream_connection::EN_CF_CONNECT);
  } while (false);

  io_stream_channel_callback(io_stream_callback_evt_t::EN_FN_CONNECTED, async_data->channel, async_data->callback,
                             conn.get(), status, errcode, async_data->priv_data, async_data->priv_size);

  // 如果连接成功，async_data->stream的生命周期由conn接管
  // 如果失败，需要关闭handle并在回调之后删除async_data。所以这时候不能直接
  // delete async_data;
  // 需要等关闭回调之后移除

  if (!conn) {
    // 只有这里走特殊的流程
    io_stream_shutdown_ev_handle(async_data);
  } else {
    delete async_data;
  }
}

// listen 接口传入域名时的回调
static void io_stream_dns_connect_cb(uv_getaddrinfo_t *req, int status, struct addrinfo *res) {
  io_stream_dns_async_data *async_data = reinterpret_cast<io_stream_dns_async_data *>(req->data);
  assert(async_data);
  if (!async_data) {
    return;
  }
  assert(async_data->channel);
  if (!async_data->channel) {
    return;
  }

  ATBUS_CHANNEL_REQ_END(async_data->channel);

  io_stream_flag_guard flag_guard(async_data->channel->flags, io_stream_channel::EN_CF_IN_CALLBACK);

  int listen_res = status;
  do {
    async_data->channel->error_code = status;

    if (0 != status) {
      break;
    }

    if (nullptr == async_data) {
      listen_res = -1;
      break;
    }

    if (nullptr == res) {
      listen_res = -1;
      break;
    }

    if (AF_INET == res->ai_family) {
      sockaddr_in *res_c = reinterpret_cast<sockaddr_in *>(res->ai_addr);
      char ip[17] = {0};
      uv_ip4_name(res_c, ip, sizeof(ip));
      make_address("ipv4", ip, async_data->addr.port, async_data->addr);
      listen_res = io_stream_connect(async_data->channel, async_data->addr, async_data->callback, async_data->priv_data,
                                     async_data->priv_size);
    } else if (AF_INET6 == res->ai_family) {
      sockaddr_in6 *res_c = reinterpret_cast<sockaddr_in6 *>(res->ai_addr);
      char ip[40] = {0};
      uv_ip6_name(res_c, ip, sizeof(ip));
      make_address("ipv6", ip, async_data->addr.port, async_data->addr);
      listen_res = io_stream_connect(async_data->channel, async_data->addr, async_data->callback, async_data->priv_data,
                                     async_data->priv_size);
    } else {
      listen_res = -1;
    }
  } while (false);

  // 接口调用不成功则要调用回调函数
  if (0 != listen_res) {
    io_stream_channel_callback(io_stream_callback_evt_t::EN_FN_CONNECTED, async_data->channel, async_data->callback,
                               nullptr, listen_res, EN_ATBUS_ERR_DNS_GETADDR_FAILED, async_data->priv_data,
                               async_data->priv_size);
  }

  if (nullptr != async_data) {
    delete async_data;
  }

  if (nullptr != res) {
    uv_freeaddrinfo(res);
  }
}

int io_stream_connect(io_stream_channel *channel, const channel_address_t &addr, io_stream_callback_t callback,
                      void *priv_data, size_t priv_size) {
  if (nullptr == channel) {
    return EN_ATBUS_ERR_PARAMS;
  }

  // 正在关闭，不允许启动新连接
  if (ATBUS_CHANNEL_IOS_CHECK_FLAG(channel->flags, io_stream_channel::EN_CF_CLOSING)) {
    return EN_ATBUS_ERR_CHANNEL_CLOSING;
  }

  adapter::loop_t *ev_loop = io_stream_get_loop(channel);
  if (nullptr == ev_loop) {
    return EN_ATBUS_ERR_MALLOC;
  }

  // socket
  if (0 == UTIL_STRFUNC_STRNCASE_CMP("ipv4", addr.scheme.c_str(), 4) ||
      0 == UTIL_STRFUNC_STRNCASE_CMP("ipv6", addr.scheme.c_str(), 4)) {
    std::shared_ptr<adapter::stream_t> sock_conn;
    adapter::tcp_t *handle = io_stream_make_stream_ptr<adapter::tcp_t>(sock_conn);
    if (nullptr == handle) {
      return EN_ATBUS_ERR_MALLOC;
    }

    uv_tcp_init(ev_loop, handle);

    int ret = EN_ATBUS_ERR_SUCCESS;
    io_stream_connect_async_data *async_data = nullptr;
    do {
      async_data = new io_stream_connect_async_data();
      if (nullptr == async_data) {
        ret = EN_ATBUS_ERR_MALLOC;
        break;
      }

      async_data->pipe = false;
      async_data->addr = addr;
      async_data->channel = channel;
      async_data->callback = callback;
      async_data->req.data = async_data;
      async_data->stream = sock_conn;
      async_data->priv_data = priv_data;
      async_data->priv_size = priv_size;

      io_stream_sockaddr_switcher sock_addr;
      const sockaddr *sock_addr_ptr = nullptr;

      if ('4' == addr.scheme[3]) {
        uv_ip4_addr(addr.host.c_str(), addr.port, &sock_addr.ipv4);
        sock_addr_ptr = &sock_addr.base;
      } else {
        uv_ip6_addr(addr.host.c_str(), addr.port, &sock_addr.ipv6);
        sock_addr_ptr = &sock_addr.base;
      }

      io_stream_tcp_setup(channel, handle);
      ATBUS_CHANNEL_REQ_START(async_data->channel);
      async_data->channel->error_code =
          uv_tcp_connect(&async_data->req, handle, sock_addr_ptr, io_stream_all_connected_cb);
      if (0 != async_data->channel->error_code) {
        ATBUS_CHANNEL_REQ_END(async_data->channel);

        ret = EN_ATBUS_ERR_SOCK_CONNECT_FAILED;
        break;
      }

      // conn_req = nullptr; // 防止异常情况会调用回调时，任然释放对象
      return ret;
    } while (false);

    // 回收关闭
    io_stream_shutdown_ev_handle(async_data);
    return ret;
  } else if (0 == UTIL_STRFUNC_STRNCASE_CMP("unix", addr.scheme.c_str(), 4)) {
    std::shared_ptr<adapter::stream_t> pipe_conn;
    adapter::pipe_t *handle = io_stream_make_stream_ptr<adapter::pipe_t>(pipe_conn);
    if (nullptr == handle) {
      return EN_ATBUS_ERR_MALLOC;
    }

    uv_pipe_init(ev_loop, handle, 1);

    int ret = EN_ATBUS_ERR_SUCCESS;
    io_stream_connect_async_data *async_data = nullptr;
    do {
      async_data = new io_stream_connect_async_data();
      if (nullptr == async_data) {
        ret = EN_ATBUS_ERR_MALLOC;
        break;
      }
      async_data->pipe = true;
      async_data->addr = addr;
      async_data->channel = channel;
      async_data->callback = callback;
      async_data->req.data = async_data;
      async_data->stream = pipe_conn;
      async_data->priv_data = priv_data;
      async_data->priv_size = priv_size;

      // 不会失败
      io_stream_pipe_setup(channel, handle);

      ATBUS_CHANNEL_REQ_START(async_data->channel);
      uv_pipe_connect(&async_data->req, handle, addr.host.c_str(), io_stream_all_connected_cb);

      return ret;
    } while (false);

    // 回收关闭
    io_stream_shutdown_ev_handle(async_data);
    return ret;

  } else if (0 == UTIL_STRFUNC_STRNCASE_CMP("dns", addr.scheme.c_str(), 3)) {
    io_stream_dns_async_data *async_data = new io_stream_dns_async_data();
    if (nullptr == async_data) {
      return EN_ATBUS_ERR_MALLOC;
    }
    async_data->channel = channel;
    async_data->addr = addr;
    async_data->callback = callback;
    async_data->req.data = async_data;
    async_data->priv_data = priv_data;
    async_data->priv_size = priv_size;

    if (0 != uv_getaddrinfo(ev_loop, &async_data->req, io_stream_dns_connect_cb, addr.host.c_str(), nullptr, nullptr)) {
      delete async_data;
      return EN_ATBUS_ERR_DNS_GETADDR_FAILED;
    }
    ATBUS_CHANNEL_REQ_START(channel);

    return EN_ATBUS_ERR_SUCCESS;
  }

  return EN_ATBUS_ERR_CHANNEL_NOT_SUPPORT;
}

static int io_stream_disconnect_run(io_stream_connection *connection) {
  if (nullptr == connection) {
    return EN_ATBUS_ERR_PARAMS;
  }

  // already running closing, skip
  if (ATBUS_CHANNEL_IOS_CHECK_FLAG(connection->flags, io_stream_connection::EN_CF_CLOSING)) {
    return EN_ATBUS_ERR_SUCCESS;
  }

  // real do closing
  ATBUS_CHANNEL_IOS_SET_FLAG(connection->flags, io_stream_connection::EN_CF_CLOSING);
  io_stream_shutdown_ev_handle(connection);

  return EN_ATBUS_ERR_SUCCESS;
}

static int io_stream_disconnect_inner(io_stream_channel *channel, io_stream_connection *connection,
                                      io_stream_callback_t callback, bool force) {
  if (nullptr == channel || nullptr == connection) {
    return EN_ATBUS_ERR_PARAMS;
  }

  connection->act_disc_cbk = callback;

  if (io_stream_connection::EN_ST_CONNECTED != connection->status) {
    return EN_ATBUS_ERR_SUCCESS;
  }

  connection->status = io_stream_connection::EN_ST_DISCONNECTING;

  // if there is any writing data, closing this connection later
  if (!force && ATBUS_CHANNEL_IOS_CHECK_FLAG(connection->flags, io_stream_connection::EN_CF_WRITING)) {
    return EN_ATBUS_ERR_SUCCESS;
  }

  return io_stream_disconnect_run(connection);
}

int io_stream_disconnect(io_stream_channel *channel, io_stream_connection *connection, io_stream_callback_t callback) {
  return io_stream_disconnect_inner(channel, connection, callback, false);
}

int io_stream_disconnect_fd(io_stream_channel *channel, adapter::fd_t fd, io_stream_callback_t callback) {
  if (nullptr == channel) {
    return EN_ATBUS_ERR_PARAMS;
  }

  io_stream_channel::conn_pool_t::iterator iter = channel->conn_pool.find(fd);
  if (iter == channel->conn_pool.end()) {
    return EN_ATBUS_ERR_CONNECTION_NOT_FOUND;
  }

  return io_stream_disconnect(channel, iter->second.get(), callback);
}

static void io_stream_on_written_fn(uv_write_t *req, int status) {
  // req is at the begin of the data block, and will not be used any more, we can delete it here
  // if uv_write2 return 0, this will always be called, so free all data here

  io_stream_connection *connection = reinterpret_cast<io_stream_connection *>(req->data);
  assert(connection);
  assert(connection->channel);

  ATBUS_CHANNEL_REQ_END(connection->channel);

  io_stream_flag_guard flag_guard(connection->channel->flags, io_stream_channel::EN_CF_IN_CALLBACK);

  void *data = nullptr;
  size_t nread, nwrite;

  // popup the lost callback
  while (true) {
    connection->write_buffers.front(data, nread, nwrite);
    if (nullptr == data) {
      break;
    }

    assert(0 == nread);
    assert(req == data);

    if (0 == nwrite) {
      connection->write_buffers.pop_front(0, true);
      break;
    }

    // nwrite = sizeof(uv_write_t) + [data block...]
    // data block = 32bits hash+vint+data length
    char *buff_start = reinterpret_cast<char *>(data) + sizeof(uv_write_t);
    size_t left_length = nwrite - sizeof(uv_write_t);
    while (left_length > 0) {
      // skip 32bits hash
      buff_start += sizeof(uint32_t);
      uint64_t out;
      size_t vint_len = ::atbus::detail::fn::read_vint(out, buff_start, left_length - sizeof(uint32_t));
      // skip varint
      buff_start += vint_len;

      // data length should be enough to hold all data
      if (left_length < sizeof(uint32_t) + vint_len + static_cast<size_t>(out)) {
        assert(false);
        left_length = 0;
      }

      io_stream_channel_callback(io_stream_callback_evt_t::EN_FN_WRITEN, connection->channel, connection, status,
                                 req == data ? EN_ATBUS_ERR_SUCCESS : EN_ATBUS_ERR_NODE_TIMEOUT, buff_start, out);

      buff_start += static_cast<size_t>(out);

      // 32bits hash+vint+data length
      left_length -= sizeof(uint32_t) + vint_len + static_cast<size_t>(out);
    }

    // remove all cache buffer
    connection->write_buffers.pop_front(nwrite, true);

    // the end
    if (req == data) {
      break;
    }
  }

  // unset writing mode
  ATBUS_CHANNEL_IOS_UNSET_FLAG(connection->flags, io_stream_connection::EN_CF_WRITING);

  // Write left data
  io_stream_try_write(connection);

  // if in disconnecting status and there is no more data to write, close it
  if (io_stream_connection::EN_ST_DISCONNECTING == connection->status &&
      !ATBUS_CHANNEL_IOS_CHECK_FLAG(connection->flags, io_stream_connection::EN_CF_WRITING)) {
    io_stream_disconnect_run(connection);
  }
}

int io_stream_try_write(io_stream_connection *connection) {
  if (nullptr == connection) {
    return EN_ATBUS_ERR_PARAMS;
  }

  int ret = EN_ATBUS_ERR_SUCCESS;
  if (ATBUS_CHANNEL_IOS_CHECK_FLAG(connection->flags, io_stream_connection::EN_CF_WRITING)) {
    return ret;
  }

  // empty then skip write data
  if (connection->write_buffers.empty()) {
    return ret;
  }

  // closing or closed, cancle writing
  // If this connection is closing, it's maybe reset by peer, write data may cause SIGPIPE
  if (ATBUS_CHANNEL_IOS_CHECK_FLAG(connection->flags, io_stream_connection::EN_CF_CLOSING)) {
    while (!connection->write_buffers.empty()) {
      ::atbus::detail::buffer_block *bb = connection->write_buffers.front();
      size_t nwrite = bb->raw_size();
      // nwrite = sizeof(uv_write_t) + [data block...]
      // data block = 32bits hash+vint+data length
      char *buff_start = reinterpret_cast<char *>(bb->raw_data()) + sizeof(uv_write_t);
      size_t left_length = nwrite - sizeof(uv_write_t);
      while (left_length > 0) {
        // skip 32bits hash
        buff_start += sizeof(uint32_t);
        uint64_t out;
        size_t vint_len = ::atbus::detail::fn::read_vint(out, buff_start, left_length - sizeof(uint32_t));
        // skip varint
        buff_start += vint_len;

        // data length should be enough to hold all data
        if (left_length < sizeof(uint32_t) + vint_len + static_cast<size_t>(out)) {
          assert(false);
          left_length = 0;
        }
        io_stream_channel_callback(io_stream_callback_evt_t::EN_FN_WRITEN, connection->channel, connection,
                                   UV_ECANCELED, EN_ATBUS_ERR_CLOSING, buff_start, out);

        buff_start += static_cast<size_t>(out);

        // 32bits hash+vint+data length
        left_length -= sizeof(uint32_t) + vint_len + static_cast<size_t>(out);
      }

      // remove all cache buffer
      connection->write_buffers.pop_front(nwrite, true);
    }

    return ret;
  }

  // if not in writing mode, try to merge and write data
  // merge only if message is smaller than read buffer
  if (connection->write_buffers.limit().cost_number_ > 1 &&
      connection->write_buffers.front()->raw_size() <= ATBUS_MACRO_DATA_SMALL_SIZE) {
    size_t available_bytes = ATBUS_MACRO_TLS_MERGE_BUFFER_LEN;
    char *buffer_start = ::atbus::channel::detail::io_stream_get_msg_buffer();
    char *free_buffer = buffer_start;

    ::atbus::detail::buffer_block *preview_bb = nullptr;
    while (!connection->write_buffers.empty() && available_bytes > 0) {
      ::atbus::detail::buffer_block *bb = connection->write_buffers.front();
      if (nullptr == bb || bb->raw_size() > available_bytes) {
        break;
      }

      // if connection->write_buffers is a static circle buffer, can not merge the bound blocks
      if (connection->write_buffers.is_static_mode() && nullptr != preview_bb && preview_bb > bb) {
        break;
      }
      preview_bb = bb;

      // first sizeof(uv_write_t) is req, the rest is 32bits hash+varint+len
      size_t bb_size = bb->raw_size() - sizeof(uv_write_t);
      memcpy(free_buffer, ::atbus::detail::fn::buffer_next(bb->raw_data(), sizeof(uv_write_t)), bb_size);
      free_buffer += bb_size;
      available_bytes -= bb_size;

      connection->write_buffers.pop_front(bb->raw_size(), true);
    }

    void *data = nullptr;
    connection->write_buffers.push_front(data, sizeof(uv_write_t) + static_cast<size_t>(free_buffer - buffer_start));

    // already pop more data than sizeof(uv_write_t) + (free_buffer - buffer_start)
    // so this push_front should always success
    assert(data);
    // at least merge one block
    assert(free_buffer > buffer_start);
    assert(static_cast<size_t>(free_buffer - buffer_start) <= ATBUS_MACRO_TLS_MERGE_BUFFER_LEN);

    data = ::atbus::detail::fn::buffer_next(data, sizeof(uv_write_t));
    // copy back merged data
    memcpy(data, buffer_start, static_cast<size_t>(free_buffer - buffer_start));
  }

  ::atbus::detail::buffer_block *writing_block = connection->write_buffers.front();

  // should always exist, empty will cause return before
  if (nullptr == writing_block) {
    assert(writing_block);
    return EN_ATBUS_ERR_NO_DATA;
  }

  if (writing_block->raw_size() <= sizeof(uv_write_t)) {
    connection->write_buffers.pop_front(writing_block->raw_size(), true);
    return io_stream_try_write(connection);
  }

  // 初始化req，填充vint，复制数据区
  uv_write_t *req = reinterpret_cast<uv_write_t *>(writing_block->raw_data());
  req->data = connection;

  char *buff_start = reinterpret_cast<char *>(writing_block->raw_data());
  // req
  buff_start += sizeof(uv_write_t);

  // call write ，bufs[] will be copied in libuv, but the real data will not
  uv_buf_t bufs[1] = {
      uv_buf_init(buff_start, static_cast<unsigned int>(writing_block->raw_size() - sizeof(uv_write_t)))};

  ATBUS_CHANNEL_IOS_SET_FLAG(connection->flags, io_stream_connection::EN_CF_WRITING);
  int res = uv_write(req, connection->handle.get(), bufs, 1, io_stream_on_written_fn);
  if (0 != res) {
    connection->channel->error_code = res;
    ATBUS_CHANNEL_IOS_UNSET_FLAG(connection->flags, io_stream_connection::EN_CF_WRITING);
    return EN_ATBUS_ERR_WRITE_FAILED;
  }
  ATBUS_CHANNEL_REQ_START(connection->channel);

  return ret;
}

int io_stream_send(io_stream_connection *connection, const void *buf, size_t len) {
  if (nullptr == connection) {
    return EN_ATBUS_ERR_PARAMS;
  }

  if (connection->channel->conf.send_buffer_limit_size > 0 && len > connection->channel->conf.send_buffer_limit_size) {
    return EN_ATBUS_ERR_INVALID_SIZE;
  }

  if (io_stream_connection::EN_ST_CONNECTED != connection->status) {
    return EN_ATBUS_ERR_CLOSING;
  }

  // push back message
  if (nullptr != buf && len > 0) {
    char vint[16];
    size_t vint_len = ::atbus::detail::fn::write_vint(len, vint, sizeof(vint));
    // 计算需要的内存块大小（uv_write_t的大小+32bits hash+vint的大小+len）
    size_t total_buffer_size = sizeof(uv_write_t) + sizeof(uint32_t) + vint_len + len;

    // 判定内存限制
    void *data;
    int res = connection->write_buffers.push_back(data, total_buffer_size);
    if (res < 0) {
      return res;
    }

    // 初始化req，填充vint，复制数据区
    uv_write_t *req = reinterpret_cast<uv_write_t *>(data);
    req->data = connection;
    char *buff_start = reinterpret_cast<char *>(data);
    // req
    buff_start += sizeof(uv_write_t);

    // 32bits hash
    uint32_t hash32 = util::hash::murmur_hash3_x86_32(reinterpret_cast<const char *>(buf), static_cast<int>(len), 0);
    memcpy(buff_start, &hash32, sizeof(uint32_t));

    // vint
    memcpy(buff_start + sizeof(uint32_t), vint, vint_len);
    // buffer
    memcpy(buff_start + sizeof(uint32_t) + vint_len, buf, len);
  }

  return io_stream_try_write(connection);
}

size_t io_stream_get_max_unix_socket_length() {
#if defined(ATBUS_MACRO_WITH_UNIX_SOCK) && ATBUS_MACRO_WITH_UNIX_SOCK
  return sizeof(sockaddr_un::sun_path);
#endif
  return 0;
}

void io_stream_show_channel(io_stream_channel *channel, std::ostream &out) {
  if (nullptr == channel) {
    return;
  }

  out << "Summary:" << std::endl << "\tconnection number: " << channel->conn_pool.size() << std::endl << std::endl;

  out << "Configure:" << std::endl
      << "\tis_noblock: " << channel->conf.is_noblock << std::endl
      << "\tis_nodelay: " << channel->conf.is_nodelay << std::endl
      << "\tbacklog: " << channel->conf.backlog << std::endl
      << "\tkeepalive: " << channel->conf.keepalive << std::endl
      << "\trecv_buffer_limit_size(Bytes): " << channel->conf.recv_buffer_limit_size << std::endl
      << "\trecv_buffer_max_size(Bytes): " << channel->conf.recv_buffer_max_size << std::endl
      << "\trecv_buffer_static_max_number: " << channel->conf.recv_buffer_static << std::endl
      << "\tsend_buffer_limit_size(Bytes): " << channel->conf.send_buffer_limit_size << std::endl
      << "\tsend_buffer_max_size(Bytes): " << channel->conf.send_buffer_max_size << std::endl
      << "\tsend_buffer_static_max_number: " << channel->conf.send_buffer_static << std::endl
      << std::endl;

  out << "All connections:" << std::endl;
  for (io_stream_channel::conn_pool_t::iterator iter = channel->conn_pool.begin(); iter != channel->conn_pool.end();
       ++iter) {
    out << "\t" << iter->second->addr.address << ":(status = " << iter->second->status << ")" << std::endl;

    out << "\t\twrite_buffers.cost_number: " << iter->second->write_buffers.limit().cost_number_ << std::endl;
    out << "\t\twrite_buffers.cost_size: " << iter->second->write_buffers.limit().cost_size_ << std::endl;
    out << "\t\twrite_buffers.limit_number: " << iter->second->write_buffers.limit().limit_number_ << std::endl;
    out << "\t\twrite_buffers.limit_size: " << iter->second->write_buffers.limit().limit_size_ << std::endl;

    out << "\t\tread_buffers.cost_number: " << iter->second->read_buffers.limit().cost_number_ << std::endl;
    out << "\t\tread_buffers.cost_size: " << iter->second->read_buffers.limit().cost_size_ << std::endl;
    out << "\t\tread_buffers.limit_number: " << iter->second->read_buffers.limit().limit_number_ << std::endl;
    out << "\t\tread_buffers.limit_size: " << iter->second->read_buffers.limit().limit_size_ << std::endl;
  }
}
}  // namespace channel
}  // namespace atbus
