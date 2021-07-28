
#include "atbus_test_utils.h"
#include "frame/test_macros.h"

void unit_test_tick_handle(uv_timer_t *handle) { uv_stop(handle->loop); }

void unit_test_timeout_handle(uv_timer_t *handle) {
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