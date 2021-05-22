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

  // stats

  size_t sum_recv_len;
  size_t sum_recv_times;
  size_t sum_recv_full;
  size_t sum_recv_err;
};

run_config conf;

static void recv_callback(atbus::channel::io_stream_channel *channel,        // 事件触发的channel
                          atbus::channel::io_stream_connection *connection,  // 事件触发的连接
                          int status,                                        // libuv传入的转态码
                          void *buff,                                        // 额外参数(不同事件不同含义)
                          size_t s                                           // 额外参数长度
) {
  assert(channel);
  assert(connection);

  if (0 != status) {
    fprintf(stderr, "recv callback error, ret code: %d. %s: %s\n", status, uv_err_name(channel->error_code),
            uv_strerror(channel->error_code));

    ++conf.sum_recv_err;
    return;
  }

  size_t checked = 0;
  // check value
  if (s > 0) {
    size_t len = s / sizeof(size_t);
    bool passed = true;
    size_t *data_arr = reinterpret_cast<size_t *>(buff);
    checked = data_arr[0];
    for (size_t i = 1; passed && i < len; ++i) {
      passed = data_arr[i] == checked;
    }

    if (passed && 0 != reinterpret_cast<size_t>(connection->data)) {
      passed = checked == reinterpret_cast<size_t>(connection->data);
    }

    if (!passed) {
      ++conf.sum_recv_err;
      std::cerr << "recv callback check error" << std::endl;
    } else {
      ++conf.sum_recv_times;
      conf.sum_recv_len += s;
    }

    ++checked;
  }

  const_cast<atbus::channel::io_stream_connection *>(connection)->data = reinterpret_cast<void *>(checked);
}

static void stat_callback(uv_timer_t * /*handle*/) {
  static int secs = 0;
  static char unit_desc[][4] = {"B", "KB", "MB", "GB"};
  static size_t unit_devi[] = {1UL, 1UL << 10, 1UL << 20, 1UL << 30};
  static size_t unit_index = 0;

  ++secs;

  while (conf.sum_recv_len / unit_devi[unit_index] > 1024 && unit_index < sizeof(unit_devi) / sizeof(size_t) - 1)
    ++unit_index;

  while (conf.sum_recv_len / unit_devi[unit_index] <= 1024 && unit_index > 0) --unit_index;

  std::cout << "[ RUNNING  ] NO." << secs << " m" << std::endl
            << "[ RUNNING  ] recv(" << conf.sum_recv_times << " times, " << (conf.sum_recv_len / unit_devi[unit_index])
            << " " << unit_desc[unit_index] << ") "
            << "full " << conf.sum_recv_full << " times, err " << conf.sum_recv_err << " times" << std::endl
            << std::endl;

  std::cout.flush();
  std::cerr.flush();
}

static void closed_callback(EXPLICIT_UNUSED_ATTR atbus::channel::io_stream_channel *channel,  // 事件触发的channel
                            EXPLICIT_UNUSED_ATTR atbus::channel::io_stream_connection *connection,  // 事件触发的连接
                            int /*status*/,  // libuv传入的转态码
                            void *,          // 额外参数(不同事件不同含义)
                            size_t           // 额外参数长度
) {
  assert(channel);
  assert(connection);

  // 除listen外的最后一个连接
  if (channel->conn_pool.size() <= 2) uv_stop(channel->ev_loop);
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    printf("usage: %s <address> [max unit size] [limit number]\n", argv[0]);
    return 0;
  }

  using namespace atbus::channel;

  if (argc > 2)
    conf.max_n = (size_t)strtol(argv[2], NULL, 10);
  else
    conf.max_n = 1024;

  conf.limit_size = sizeof(size_t) * conf.max_n;  // 64KB

  if (argc > 3)
    conf.limit_static_num = (size_t)strtol(argv[3], NULL, 10);
  else
    conf.limit_static_num = 2;  // default

  conf.sum_recv_len = 0;
  conf.sum_recv_times = 0;
  conf.sum_recv_full = 0;
  conf.sum_recv_err = 0;

  io_stream_conf cfg;
  io_stream_init_configure(&cfg);
  cfg.recv_buffer_max_size =
      conf.limit_size + atbus::detail::buffer_block::full_size(cfg.recv_buffer_limit_size) * conf.limit_static_num +
      atbus::detail::buffer_block::padding_size(1);  // 预留一个对齐单位的空区域
  cfg.recv_buffer_static = conf.limit_static_num;

  io_stream_channel channel;
  io_stream_init(&channel, uv_default_loop(), &cfg);
  channel.evt.callbacks[io_stream_callback_evt_t::EN_FN_RECVED] = recv_callback;
  channel.evt.callbacks[io_stream_callback_evt_t::EN_FN_DISCONNECTED] = closed_callback;

  channel_address_t addr;
  make_address(argv[1], addr);

  if (io_stream_listen(&channel, addr, NULL, NULL, 0) < 0) {
    std::cerr << "listen to " << argv[1] << " failed." << uv_err_name(channel.error_code) << ":"
              << uv_strerror(channel.error_code) << std::endl;
    io_stream_close(&channel);
    return -1;
  }

  uv_timer_t stat;
  uv_timer_init(uv_default_loop(), &stat);
  uv_timer_start(&stat, stat_callback, 60000, 60000);

  int ret = uv_run(uv_default_loop(), UV_RUN_DEFAULT);
  io_stream_close(&channel);
  return ret;
}
