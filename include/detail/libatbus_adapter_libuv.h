//
// Created by owent on 2015/9/15.
//

#ifndef LIBATBUS_LIBATBUS_ADAPTER_LIBUV_H
#define LIBATBUS_LIBATBUS_ADAPTER_LIBUV_H

#pragma once

#include "uv.h"

namespace atbus {
namespace adapter {
typedef uv_loop_t loop_t;
typedef uv_poll_t poll_t;
typedef uv_stream_t stream_t;
typedef uv_pipe_t pipe_t;
typedef uv_tty_t tty_t;
typedef uv_tcp_t tcp_t;
typedef uv_handle_t handle_t;
typedef uv_timer_t timer_t;

typedef uv_os_fd_t fd_t;

enum run_mode_t {
  RUN_DEFAULT = UV_RUN_DEFAULT,
  RUN_ONCE = UV_RUN_ONCE,
  RUN_NOWAIT = UV_RUN_NOWAIT,
};
}  // namespace adapter
}  // namespace atbus

#endif  // LIBATBUS_LIBATBUS_ADAPTER_LIBUV_H
