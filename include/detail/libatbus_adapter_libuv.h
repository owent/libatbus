//
// Created by owent on 2015/9/15.
//

#ifndef LIBATBUS_LIBATBUS_ADAPTER_LIBUV_H
#define LIBATBUS_LIBATBUS_ADAPTER_LIBUV_H

#pragma once

#include "uv.h"

namespace atbus {
namespace adapter {
using loop_t = uv_loop_t;
using poll_t = uv_poll_t;
using stream_t = uv_stream_t;
using pipe_t = uv_pipe_t;
using tty_t = uv_tty_t;
using tcp_t = uv_tcp_t;
using handle_t = uv_handle_t;
using timer_t = uv_timer_t;

using fd_t = uv_os_fd_t;

enum run_mode_t {
  RUN_DEFAULT = UV_RUN_DEFAULT,
  RUN_ONCE = UV_RUN_ONCE,
  RUN_NOWAIT = UV_RUN_NOWAIT,
};
}  // namespace adapter
}  // namespace atbus

#endif  // LIBATBUS_LIBATBUS_ADAPTER_LIBUV_H
