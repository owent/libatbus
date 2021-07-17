#include <assert.h>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <iostream>
#include <limits>
#include <memory>

#include <std/explicit_declare.h>

#include <detail/libatbus_error.h>
#include "detail/libatbus_channel_export.h"

struct run_config {
  size_t max_n;
  size_t limit_size;
  size_t limit_static_num;
  size_t *buff_pool;

  // stats
  size_t pending_send;
  size_t sum_send_len;
  size_t sum_send_times;
  size_t sum_send_full;
  size_t sum_send_err;
  size_t sum_seq;
};

run_config conf;

static void send_data(atbus::channel::io_stream_connection *connection);

static void connect_callback(atbus::channel::io_stream_channel *channel,        // 事件触发的channel
                             atbus::channel::io_stream_connection *connection,  // 事件触发的连接
                             int status,                                        // libuv传入的转态码
                             void *,  // 额外参数(不同事件不同含义)
                             size_t   // 额外参数长度
) {
  if (0 != status) {
    std::cerr << "connect failed, statue: " << status << std::endl;
    std::cerr << uv_err_name(channel->error_code) << ":" << uv_strerror(channel->error_code) << std::endl;
    uv_stop(channel->ev_loop);
    return;
  }
  assert(connection);
  send_data(const_cast<atbus::channel::io_stream_connection *>(connection));
}

static void sended_callback(atbus::channel::io_stream_channel *channel,        // 事件触发的channel
                            atbus::channel::io_stream_connection *connection,  // 事件触发的连接
                            int status,                                        // libuv传入的转态码
                            void *,                                            // 额外参数(不同事件不同含义)
                            size_t s                                           // 额外参数长度
) {
  assert(channel);
  assert(connection);

  --conf.pending_send;

  if (0 != status) {
    fprintf(stderr, "io_stream_send callback error, ret code: %d. %s: %s\n", status, uv_err_name(channel->error_code),
            uv_strerror(channel->error_code));

    ++conf.sum_send_err;
    return;
  }

  ++conf.sum_send_times;
  conf.sum_send_len += s;
  send_data(const_cast<atbus::channel::io_stream_connection *>(connection));
}

static void closed_callback(EXPLICIT_UNUSED_ATTR atbus::channel::io_stream_channel *channel,  // 事件触发的channel
                            EXPLICIT_UNUSED_ATTR atbus::channel::io_stream_connection *connection,  // 事件触发的连接
                            int /*status*/,  // libuv传入的转态码
                            void *,          // 额外参数(不同事件不同含义)
                            size_t           // 额外参数长度
) {
  assert(channel);
  assert(connection);

  uv_stop(channel->ev_loop);
}

static void stat_callback(uv_timer_t * /*handle*/) {
  static int secs = 0;
  static char unit_desc[][4] = {"B", "KB", "MB", "GB"};
  static size_t unit_devi[] = {1UL, 1UL << 10, 1UL << 20, 1UL << 30};
  static size_t unit_index = 0;

  ++secs;

  while (conf.sum_send_len / unit_devi[unit_index] > 1024 && unit_index < sizeof(unit_devi) / sizeof(size_t) - 1)
    ++unit_index;

  while (conf.sum_send_len / unit_devi[unit_index] <= 1024 && unit_index > 0) --unit_index;

  std::cout << "[ RUNNING  ] NO." << secs << " m" << std::endl
            << "[ RUNNING  ] send(" << conf.sum_send_times << " times, " << (conf.sum_send_len / unit_devi[unit_index])
            << " " << unit_desc[unit_index] << ") "
            << "full " << conf.sum_send_full << " times, err " << conf.sum_send_err << " times" << std::endl
            << std::endl;

  std::cout.flush();
  std::cerr.flush();
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    printf("usage: %s <address> [max unit size] [limit size] [limit number]\n", argv[0]);
    return 0;
  }

  using namespace atbus::channel;

  if (argc > 2)
    conf.max_n = (size_t)strtol(argv[2], nullptr, 10);
  else
    conf.max_n = 1024;

  conf.buff_pool = new size_t[conf.max_n];
  assert(conf.buff_pool);

  if (argc > 3)
    conf.limit_size = (size_t)strtol(argv[3], nullptr, 10);
  else
    conf.limit_size = 64 * 1024;  // 64KB

  if (argc > 4)
    conf.limit_static_num = (size_t)strtol(argv[4], nullptr, 10);
  else
    conf.limit_static_num = 0;  // dynamic

  srand(static_cast<unsigned>(time(nullptr)));
  conf.pending_send = 0;
  conf.sum_send_len = 0;
  conf.sum_send_times = 0;
  conf.sum_send_full = 0;
  conf.sum_send_err = 0;
  conf.sum_seq = ((size_t)rand() << (sizeof(size_t) * 4));

  io_stream_conf cfg;
  io_stream_init_configure(&cfg);
  cfg.send_buffer_max_size = conf.limit_size;
  cfg.send_buffer_static = conf.limit_static_num;

  io_stream_channel channel;
  io_stream_init(&channel, uv_default_loop(), &cfg);
  channel.evt.callbacks[io_stream_callback_evt_t::EN_FN_WRITEN] = sended_callback;
  channel.evt.callbacks[io_stream_callback_evt_t::EN_FN_DISCONNECTED] = closed_callback;

  channel_address_t addr;
  make_address(argv[1], addr);

  if (io_stream_connect(&channel, addr, connect_callback, nullptr, 0) < 0) {
    std::cerr << "connect to " << argv[1] << " failed." << uv_err_name(channel.error_code) << ":"
              << uv_strerror(channel.error_code) << std::endl;
    io_stream_close(&channel);
    delete[] conf.buff_pool;
    return -1;
  }

  uv_timer_t stat;
  uv_timer_init(uv_default_loop(), &stat);
  uv_timer_start(&stat, stat_callback, 60000, 60000);

  int ret = uv_run(uv_default_loop(), UV_RUN_DEFAULT);
  io_stream_close(&channel);

  delete[] conf.buff_pool;
  return ret;
}

static void send_data(atbus::channel::io_stream_connection *connection) {
  using namespace atbus::channel;

  assert(connection);
  // 尝试5次,逐渐填满数据
  for (int try_times = 0; try_times < 2; ++try_times) {
    size_t n = rand() % conf.max_n;  // 最大 4K-8K的包
    if (0 == n) n = 1;               // 保证一定有数据包，保证收发次数一致

    for (size_t i = 0; i < n; ++i) {
      conf.buff_pool[i] = conf.sum_seq;
    }

    int res = io_stream_send(connection, conf.buff_pool, n * sizeof(size_t));
    if (res) {
      if (EN_ATBUS_ERR_BUFF_LIMIT == res) {
        ++conf.sum_send_full;
        break;
      } else {
        ++conf.sum_send_err;
        fprintf(stderr, "io_stream_send error, ret code: %d. %s: %s\n", res,
                uv_err_name(connection->channel->error_code), uv_strerror(connection->channel->error_code));
      }
    } else {
      ++conf.pending_send;
      ++conf.sum_seq;
    }
  }
}