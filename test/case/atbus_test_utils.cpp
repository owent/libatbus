
// Copyright 2026 atframework

#include "atbus_test_utils.h"

#include <cstring>

#include <time/time_utility.h>

#include "frame/test_macros.h"

void unit_test_tick_handle(uv_timer_t *handle) {
  atfw::util::time::time_utility::update();

  uv_stop(handle->loop);
}

void unit_test_timeout_handle(uv_timer_t *handle) {
  atfw::util::time::time_utility::update();

  uv_stop(handle->loop);

  unit_test_libuv_wait_manager *mgr = reinterpret_cast<unit_test_libuv_wait_manager *>(handle->data);
  if (nullptr == mgr || mgr->print_error_) {
    CASE_MSG_ERROR() << CASE_MSG_FCOLOR(RED) << "wait timeout." << std::endl;
  }

  if (nullptr != mgr) {
    mgr->is_timeout_ = true;
  }
}

void unit_test_setup_exit(uv_loop_t *ev, uint64_t timeout_ms) {
  size_t left_tick = timeout_ms / 8;
  while (left_tick > 0 && UV_EBUSY == uv_loop_close(ev)) {
    // loop 8 times
    for (int i = 0; i < 8; ++i) {
      uv_run(ev, UV_RUN_NOWAIT);
    }
    CASE_THREAD_SLEEP_MS(8);

    --left_tick;
  }

  CASE_EXPECT_NE(left_tick, 0);
}

namespace {
struct unit_test_ipv6_probe_context {
  uv_tcp_t server;
  uv_tcp_t client;
  uv_timer_t timeout_timer;
  uv_connect_t connect_req;
  bool server_inited;
  bool client_inited;
  bool timer_inited;
  bool result;
};

static void unit_test_ipv6_probe_on_close(uv_handle_t *) {}

static void unit_test_ipv6_probe_finish(unit_test_ipv6_probe_context *ctx) {
  if (ctx->timer_inited) {
    uv_timer_stop(&ctx->timeout_timer);
    uv_close(reinterpret_cast<uv_handle_t *>(&ctx->timeout_timer), unit_test_ipv6_probe_on_close);
    ctx->timer_inited = false;
  }
  if (ctx->client_inited) {
    uv_close(reinterpret_cast<uv_handle_t *>(&ctx->client), unit_test_ipv6_probe_on_close);
    ctx->client_inited = false;
  }
  if (ctx->server_inited) {
    uv_close(reinterpret_cast<uv_handle_t *>(&ctx->server), unit_test_ipv6_probe_on_close);
    ctx->server_inited = false;
  }
}

static void unit_test_ipv6_probe_on_connection(uv_stream_t *, int) {}

static void unit_test_ipv6_probe_on_connect(uv_connect_t *req, int status) {
  unit_test_ipv6_probe_context *ctx = reinterpret_cast<unit_test_ipv6_probe_context *>(req->data);
  if (nullptr == ctx) {
    return;
  }
  ctx->result = (0 == status);
  unit_test_ipv6_probe_finish(ctx);
}

static void unit_test_ipv6_probe_on_timeout(uv_timer_t *handle) {
  unit_test_ipv6_probe_context *ctx = reinterpret_cast<unit_test_ipv6_probe_context *>(handle->data);
  if (nullptr == ctx) {
    return;
  }
  unit_test_ipv6_probe_finish(ctx);
}
}  // namespace

bool unit_test_probe_ipv6_loopback() {
  uv_loop_t loop;
  if (0 != uv_loop_init(&loop)) {
    return false;
  }

  unit_test_ipv6_probe_context ctx;
  memset(&ctx, 0, sizeof(ctx));

  do {
    if (0 != uv_tcp_init_ex(&loop, &ctx.server, AF_INET6)) {
      break;
    }
    ctx.server_inited = true;

    sockaddr_in6 addr;
    if (0 != uv_ip6_addr("::1", 0, &addr)) {
      break;
    }
    if (0 != uv_tcp_bind(&ctx.server, reinterpret_cast<const sockaddr *>(&addr), UV_TCP_IPV6ONLY)) {
      break;
    }
    if (0 != uv_listen(reinterpret_cast<uv_stream_t *>(&ctx.server), 4, unit_test_ipv6_probe_on_connection)) {
      break;
    }
    int name_len = sizeof(addr);
    if (0 != uv_tcp_getsockname(&ctx.server, reinterpret_cast<sockaddr *>(&addr), &name_len)) {
      break;
    }

    if (0 != uv_tcp_init_ex(&loop, &ctx.client, AF_INET6)) {
      break;
    }
    ctx.client_inited = true;

    ctx.connect_req.data = &ctx;
    if (0 != uv_tcp_connect(&ctx.connect_req, &ctx.client, reinterpret_cast<const sockaddr *>(&addr),
                            unit_test_ipv6_probe_on_connect)) {
      break;
    }

    if (0 != uv_timer_init(&loop, &ctx.timeout_timer)) {
      break;
    }
    ctx.timer_inited = true;
    ctx.timeout_timer.data = &ctx;
    if (0 != uv_timer_start(&ctx.timeout_timer, unit_test_ipv6_probe_on_timeout, 5000, 0)) {
      break;
    }

    // Runs until the connect or the timeout callback closes all handles.
    uv_run(&loop, UV_RUN_DEFAULT);
  } while (false);

  // Close handles left open by an early setup failure, then drain close callbacks.
  unit_test_ipv6_probe_finish(&ctx);
  uv_run(&loop, UV_RUN_DEFAULT);
  uv_loop_close(&loop);

  return ctx.result;
}

static void unit_test_timer_close_handle(uv_handle_t *handle) {
  handle->data = nullptr;
  uv_stop(handle->loop);
}

unit_test_libuv_wait_manager::unit_test_libuv_wait_manager(uv_loop_t *ev, uint64_t timeout_ms, uint64_t tick_ms,
                                                           bool print_error)
    : tick_enabled_(false), print_error_(print_error), is_timeout_(false) {
  uv_timer_init(ev, &timeout_timer_);

  if (tick_ms > 0) {
    if (0 == uv_timer_init(ev, &tick_timer_)) {
      tick_enabled_ = true;
    }
  }
  tick_timer_.data = this;
  timeout_timer_.data = this;

  if (0 != uv_timer_start(&timeout_timer_, unit_test_timeout_handle, timeout_ms, 0)) {
    timeout_timer_.data = nullptr;
  }

  if (tick_enabled_) {
    if (0 != uv_timer_start(&tick_timer_, unit_test_tick_handle, tick_ms, tick_ms)) {
      timeout_timer_.data = nullptr;
      tick_enabled_ = false;
    }
  }
}

unit_test_libuv_wait_manager::~unit_test_libuv_wait_manager() {
  uv_loop_t *ev = timeout_timer_.loop;
  uv_timer_stop(&timeout_timer_);

  uv_close(reinterpret_cast<uv_handle_t *>(&timeout_timer_), unit_test_timer_close_handle);

  if (tick_enabled_) {
    uv_timer_stop(&tick_timer_);
    uv_close(reinterpret_cast<uv_handle_t *>(&tick_timer_), unit_test_timer_close_handle);
  } else {
    tick_timer_.data = nullptr;
  }

  while (nullptr != timeout_timer_.data || nullptr != tick_timer_.data) {
    uv_run(ev, UV_RUN_DEFAULT);
  }
}

void unit_test_libuv_wait_manager::run(uv_loop_t *ev) { uv_run(ev, UV_RUN_ONCE); }
