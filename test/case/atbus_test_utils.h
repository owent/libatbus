#ifndef UNITTEST_LIBATBUS_TEST_UTILS_H_
#define UNITTEST_LIBATBUS_TEST_UTILS_H_

#pragma once

#include <chrono>

#include "uv.h"

inline std::chrono::system_clock::time_point unit_test_make_timepoint(time_t sec, time_t usec) {
  return std::chrono::system_clock::from_time_t(sec) + std::chrono::microseconds(usec);
}

void unit_test_tick_handle(uv_timer_t *handle);
void unit_test_timeout_handle(uv_timer_t *handle);
void unit_test_setup_exit(uv_loop_t *ev, uint64_t timeout_ms = 30000);

struct unit_test_libuv_wait_manager {
  unit_test_libuv_wait_manager(uv_loop_t *ev, uint64_t timeout_ms, uint64_t tick_ms, bool print_error);
  ~unit_test_libuv_wait_manager();

  void run(uv_loop_t *ev);

  uv_timer_t timeout_timer_;
  uv_timer_t tick_timer_;
  bool tick_enabled_;
  bool print_error_;
  bool is_timeout_;
};

#define UNITTEST_WAIT_UNTIL(ev, conndition, timeout_ms, tick_ms)                   \
  for (unit_test_libuv_wait_manager libuv_wait_mgr(ev, timeout_ms, tick_ms, true); \
       !libuv_wait_mgr.is_timeout_ && !(conndition); libuv_wait_mgr.run(ev))       \
    if (!libuv_wait_mgr.is_timeout_)

#define UNITTEST_WAIT_IF(ev, conndition, timeout_ms, tick_ms)                      \
  for (unit_test_libuv_wait_manager libuv_wait_mgr(ev, timeout_ms, tick_ms, true); \
       !libuv_wait_mgr.is_timeout_ && (conndition); libuv_wait_mgr.run(ev))        \
    if (!libuv_wait_mgr.is_timeout_)

#define UNITTEST_WAIT_MS(ev, timeout_ms, tick_ms)                                                                \
  for (unit_test_libuv_wait_manager libuv_wait_mgr(ev, timeout_ms, tick_ms, false); !libuv_wait_mgr.is_timeout_; \
       libuv_wait_mgr.run(ev))                                                                                   \
    if (!libuv_wait_mgr.is_timeout_)

#endif
