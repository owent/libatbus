// Copyright 2026 atframework

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <functional>
#include <iostream>
#include <limits>
#include <memory>
#include <numeric>
#include <thread>

#include <detail/libatbus_error.h>
#include "config/compiler_features.h"
#include "detail/libatbus_channel_export.h"

#if defined(ATBUS_CHANNEL_SHM)
int main(int argc, char *argv[]) {
  if (argc < 2) {
    printf("usage: %s <shm key> [need node info: 0 or 1] [node data size]\n", argv[0]);
    return 0;
  }

  using namespace atbus::channel;
  shm_channel *channel = nullptr;
  long need_node_info = 0;
  size_t need_node_data = 0;

  if (argc > 2) {
    need_node_info = strtol(argv[2], nullptr, 10);
  }

  if (argc > 3) {
    need_node_data = (size_t)strtol(argv[3], nullptr, 10);
  }

  int res = shm_attach(argv[1], 0, &channel, nullptr);
  if (res < 0) {
    fprintf(stderr, "shm_attach for %s failed, ret: %d\n", argv[1], res);
    return res;
  }

  shm_show_channel(channel, std::cout, !!need_node_info, need_node_data);
  return 0;
}
#else
int main() {
  puts("shm channel disabled");
  return 0;
}
#endif

