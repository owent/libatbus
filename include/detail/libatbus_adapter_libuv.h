//
// Created by owent on 2015/9/15.
//

#ifndef LIBATBUS_LIBATBUS_ADAPTER_LIBUV_H
#define LIBATBUS_LIBATBUS_ADAPTER_LIBUV_H

#pragma once

#include "uv.h"

#include "detail/libatbus_config.h"

ATBUS_MACRO_NAMESPACE_BEGIN
namespace adapter {
using loop_t = uv_loop_t;
using poll_t = uv_poll_t;
using stream_t = uv_stream_t;
using pipe_t = uv_pipe_t;
using tty_t = uv_tty_t;
using tcp_t = uv_tcp_t;
using handle_t = uv_handle_t;
using timer_t = uv_timer_t;
using shutdown_t = uv_shutdown_t;

using fd_t = uv_os_fd_t;

enum class run_mode_t : uint32_t {
  kDefault = UV_RUN_DEFAULT,
  kOnce = UV_RUN_ONCE,
  kNoWait = UV_RUN_NOWAIT,
};
}  // namespace adapter
ATBUS_MACRO_NAMESPACE_END

#endif  // LIBATBUS_LIBATBUS_ADAPTER_LIBUV_H
