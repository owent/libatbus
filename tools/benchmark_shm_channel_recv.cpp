// Copyright 2026 atframework

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <functional>
#include <iostream>
#include <memory>
#include <thread>
#include <vector>

#include <detail/libatbus_channel_export.h>
#include <detail/libatbus_error.h>
#include "config/compiler_features.h"

#include "common/string_oprs.h"

#if defined(UTIL_CONFIG_COMPILER_CXX_LAMBDAS) && UTIL_CONFIG_COMPILER_CXX_LAMBDAS && defined(ATBUS_CHANNEL_SHM)

static inline char *get_pid_cur(int pid) {
  static std::vector<std::pair<int, char> > res;
  for (size_t i = 0; i < res.size(); ++i) {
    if (res[i].first == pid) {
      return &res[i].second;
    }
  }

  res.push_back(std::pair<int, char>(pid, 0));
  return &res.back().second;
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    printf("usage: %s <shm key> [max unit size] [shm size]\n", argv[0]);
    return 0;
  }

  using namespace atbus::channel;
  size_t max_n = 1024;
  if (argc > 2) max_n = (size_t)strtol(argv[2], nullptr, 10);

  size_t buffer_len = 64 * 1024 * 1024;  // 64MB
  if (argc > 3) buffer_len = (size_t)strtol(argv[3], nullptr, 10);

  shm_channel *channel = nullptr;

  int res = shm_init(argv[1], buffer_len, &channel, nullptr);
  if (res < 0) {
    fprintf(stderr, "shm_init failed, ret: %d\n", res);
    return res;
  }

  srand(static_cast<uint32_t>(time(nullptr)));

  size_t sum_recv_len = 0;
  size_t sum_recv_times = 0;
  size_t sum_recv_err = 0;
  size_t sum_data_err = 0;

  // 创建读线程
  std::thread *read_threads =
      new std::thread([&sum_recv_len, &sum_recv_times, &sum_recv_err, &sum_data_err, max_n, channel] {
        char *buf_pool = new char[max_n * sizeof(size_t)];
        char *buf_check = new char[max_n * sizeof(size_t)];

        bool is_last_tick_faild = false;
        while (true) {
          size_t n = 0;  // 最大 4K-8K的包
          int res = shm_recv(channel, buf_pool, sizeof(size_t) * max_n, &n);

          if (res) {
            if (EN_ATBUS_ERR_NO_DATA != res) {
              std::pair<size_t, size_t> last_action = shm_last_action();
              fprintf(stderr, "shm_recv error, ret code: %d. start: %d, end: %d\n", res, (int)last_action.first,
                      (int)last_action.second);
              ++sum_recv_err;

              if (!is_last_tick_faild) {
                shm_show_channel(channel, std::cout, true, 24);
              }
              is_last_tick_faild = true;
            } else {
              std::this_thread::sleep_for(std::chrono::milliseconds(128));
            }
          } else {
            ++sum_recv_times;
            sum_recv_len += n;

            int pid = *((int *)buf_pool);
            char *val_check = get_pid_cur(pid);

            if (0 == *val_check) {
              *val_check = *(buf_pool + sizeof(int));
            } else {
              ++(*val_check);
              if (0 == *val_check) {
                ++(*val_check);
              }
            }

            memset(buf_check + sizeof(int), (int)*val_check, n - sizeof(int));
            int cmp_res = memcmp(buf_pool + sizeof(int), buf_check + sizeof(int), n - sizeof(int));
            if (0 == cmp_res) {
              is_last_tick_faild = false;
            } else {
              std::cerr << "pid: " << pid << " expected data is ";
              atfw::util::string::dumphex(val_check, 1, std::cerr);
              std::cerr << ", but real is ";
              atfw::util::string::dumphex(buf_pool + sizeof(int), 1, std::cerr);
              std::cerr << std::endl;
              *val_check = *(buf_pool + sizeof(int));

              ++sum_data_err;

              if (!is_last_tick_faild) {
                shm_show_channel(channel, std::cout, true, 24);
              }
              is_last_tick_faild = true;
            }
          }
        }

        delete[] buf_pool;
        delete[] buf_check;
      });

  // 检查状态
  int secs = 0;
  char unit_desc[][4] = {"B", "KB", "MB", "GB"};
  size_t unit_devi[] = {1UL, 1UL << 10, 1UL << 20, 1UL << 30};
  size_t unit_index = 0;

  while (true) {
    ++secs;
    std::this_thread::sleep_for(std::chrono::milliseconds(60000));

    while (sum_recv_len / unit_devi[unit_index] > 1024 && unit_index < sizeof(unit_devi) / sizeof(size_t) - 1)
      ++unit_index;

    while (sum_recv_len / unit_devi[unit_index] <= 1024 && unit_index > 0) --unit_index;

    std::cout << "[ RUNNING  ] NO." << secs << " m" << std::endl
              << "[ RUNNING  ] recv(" << sum_recv_times << " times, " << (sum_recv_len / unit_devi[unit_index]) << " "
              << unit_desc[unit_index] << ") " << "recv err " << sum_recv_err << " times, data valid failed "
              << sum_data_err << " times" << std::endl
              << std::endl;

    shm_show_channel(channel, std::cout, false, 0);
  }

  read_threads->join();
  delete read_threads;

  return 0;
}

#else

int main() {
  std::cerr << "this benckmark code require your compiler support lambda and c++11/thread" << std::endl;
  return 0;
}

#endif

