// Copyright 2026 atframework

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <functional>
#include <iostream>
#include <memory>
#include <thread>

#include "config/compiler_features.h"

#include <detail/libatbus_error.h>
#include "detail/libatbus_channel_export.h"
#include "lock/atomic_int_type.h"

#include "frame/test_macros.h"

#if defined(ATBUS_CHANNEL_SHM)

CASE_TEST(channel, shm_attach_with_invalid_magic) {
  using namespace atbus::channel;
  const char *shm_path = "/atbus-channel-test";
  const size_t buffer_len = 2 * 1024 * 1024;  // 2MB

  shm_channel *channel = nullptr;
#  ifdef _WIN32
  // Win32 may need administrator permission to use shared memory
  if (0 != shm_init(shm_path, buffer_len, &channel, nullptr)) {
    return;
  }
  if (nullptr == channel) {
    return;
  }
#  else
  CASE_EXPECT_EQ(0, shm_init(shm_path, buffer_len, &channel, nullptr));
  CASE_EXPECT_NE(nullptr, channel);
#  endif

  memset(reinterpret_cast<unsigned char *>(channel) + 4, 0, 4);
  CASE_EXPECT_EQ(EN_ATBUS_ERR_CHANNEL_BUFFER_INVALID, shm_attach(shm_path, buffer_len, &channel, nullptr));
}

CASE_TEST(channel, shm_attach_with_invalid_version) {
  using namespace atbus::channel;
  const char *shm_path = "/atbus-channel-test";
  const size_t buffer_len = 2 * 1024 * 1024;  // 2MB

  shm_channel *channel = nullptr;
#  ifdef _WIN32
  // Win32 may need administrator permission to use shared memory
  if (0 != shm_init(shm_path, buffer_len, &channel, nullptr)) {
    return;
  }
  if (nullptr == channel) {
    return;
  }
#  else
  CASE_EXPECT_EQ(0, shm_init(shm_path, buffer_len, &channel, nullptr));
  CASE_EXPECT_NE(nullptr, channel);
#  endif

  CASE_EXPECT_EQ(2, shm_info_get_version(channel));
  CASE_EXPECT_EQ(0, shm_info_get_version(nullptr));

  (*reinterpret_cast<uint16_t *>(reinterpret_cast<unsigned char *>(channel) + 16)) = 1;
  CASE_EXPECT_EQ(EN_ATBUS_ERR_CHANNEL_UNSUPPORTED_VERSION, shm_attach(shm_path, buffer_len, &channel, nullptr));
}

CASE_TEST(channel, shm_attach_with_invalid_align_size) {
  using namespace atbus::channel;
  const char *shm_path = "/atbus-channel-test";
  const size_t buffer_len = 2 * 1024 * 1024;  // 2MB

  shm_channel *channel = nullptr;
#  ifdef _WIN32
  // Win32 may need administrator permission to use shared memory
  if (0 != shm_init(shm_path, buffer_len, &channel, nullptr)) {
    return;
  }
  if (nullptr == channel) {
    return;
  }
#  else
  CASE_EXPECT_EQ(0, shm_init(shm_path, buffer_len, &channel, nullptr));
  CASE_EXPECT_NE(nullptr, channel);
#  endif

  CASE_EXPECT_EQ(ATBUS_MACRO_DATA_ALIGN_SIZE, shm_info_get_align_size(channel));
  CASE_EXPECT_EQ(0, shm_info_get_align_size(nullptr));

  (*reinterpret_cast<uint16_t *>(reinterpret_cast<unsigned char *>(channel) + 18)) = ATBUS_MACRO_DATA_ALIGN_SIZE / 2;
  CASE_EXPECT_EQ(EN_ATBUS_ERR_CHANNEL_ALIGN_SIZE_MISMATCH, shm_attach(shm_path, buffer_len, &channel, nullptr));
}

CASE_TEST(channel, shm_attach_with_invalid_host_size) {
  using namespace atbus::channel;
  const size_t buffer_len = 2 * 1024 * 1024;  // 2MB
  const char *shm_path = "/atbus-channel-test";

  shm_channel *channel = nullptr;
#  ifdef _WIN32
  // Win32 may need administrator permission to use shared memory
  if (0 != shm_init(shm_path, buffer_len, &channel, nullptr)) {
    return;
  }
  if (nullptr == channel) {
    return;
  }
#  else
  CASE_EXPECT_EQ(0, shm_init(shm_path, buffer_len, &channel, nullptr));
  CASE_EXPECT_NE(nullptr, channel);
#  endif

  CASE_EXPECT_EQ(sizeof(size_t), shm_info_get_host_size(channel));
  CASE_EXPECT_EQ(0, shm_info_get_host_size(nullptr));

  (*reinterpret_cast<uint16_t *>(reinterpret_cast<unsigned char *>(channel) + 20)) =
      static_cast<uint16_t>(sizeof(size_t) / 2);
  CASE_EXPECT_EQ(EN_ATBUS_ERR_CHANNEL_ARCH_SIZE_T_MISMATCH, shm_attach(shm_path, buffer_len, &channel, nullptr));
}

CASE_TEST(channel, shm_show_channel) {
  using namespace atbus::channel;
  const char *shm_path = "/atbus-channel-test";
  const size_t buffer_len = 2 * 1024 * 1024;  // 2MB

  shm_channel *channel = nullptr;
#  ifdef _WIN32
  // Win32 may need administrator permission to use shared memory
  if (0 != shm_init(shm_path, buffer_len, &channel, nullptr)) {
    return;
  }
  if (nullptr == channel) {
    return;
  }
#  else
  CASE_EXPECT_EQ(0, shm_init(shm_path, buffer_len, &channel, nullptr));
  CASE_EXPECT_NE(nullptr, channel);
#  endif
  shm_show_channel(channel, CASE_MSG_INFO(), true, 8);
}

CASE_TEST(channel, shm_siso) {
  using namespace atbus::channel;
  const char *shm_path = "/atbus-channel-test";
  const size_t buffer_len = 2 * 1024 * 1024;  // 2MB

  shm_channel *channel = nullptr;

#  ifdef _WIN32
  // Win32 may need administrator permission to use shared memory
  if (0 != shm_init(shm_path, buffer_len, &channel, nullptr)) {
    return;
  }
  if (nullptr == channel) {
    return;
  }
#  else
  CASE_EXPECT_EQ(0, shm_init(shm_path, buffer_len, &channel, nullptr));
  CASE_EXPECT_NE(nullptr, channel);
#  endif
  // 4KB header

  // 数据初始化
  char buf_group1[2][32] = {{0}};
  char buf_group2[2][45] = {{0}};
  char buf_group3[2][133] = {{0}};
  char buf_group4[2][605] = {{0}};
  char buf_group5[2][1024] = {{0}};
  size_t len_group[] = {32, 45, 133, 605, 1024};
  size_t group_num = sizeof(len_group) / sizeof(size_t);
  char *buf_group[] = {buf_group1[0], buf_group2[0], buf_group3[0], buf_group4[0], buf_group5[0]};
  char *buf_rgroup[] = {buf_group1[1], buf_group2[1], buf_group3[1], buf_group4[1], buf_group5[1]};

  {
    size_t i = 0;
    char j = 1;

    for (; i < group_num; ++i, ++j)
      for (size_t k = 0; k < len_group[i]; ++k) buf_group[i][k] = j;
  }

  size_t send_sum_len;
  size_t try_left = 3;
  srand(static_cast<unsigned>(time(nullptr)));
  size_t first_break = (size_t)rand() % (512 * 1024);

  while (try_left-- > 0) {
    // 单进程写压力
    {
      size_t sum_len = 0, times = 0;
      int res = 0;
      size_t i = 0;
      clock_t bt = clock();
      while (0 == res) {
        if (first_break && 0 == --first_break) {
          res = EN_ATBUS_ERR_BUFF_LIMIT;
          continue;
        }

        res = shm_send(channel, buf_group[i], len_group[i]);
        if (!res) {
          sum_len += len_group[i];
          ++times;
        }

        i = (i + 1) % group_num;
      }
      clock_t et = clock();

      CASE_EXPECT_EQ(EN_ATBUS_ERR_BUFF_LIMIT, res);

      CASE_MSG_INFO() << "send " << sum_len << " bytes(" << times << " times) in "
                      << ((et - bt) / (CLOCKS_PER_SEC / 1000)) << "ms" << std::endl;
      send_sum_len = sum_len;
    }

    size_t recv_sum_len;
    // 单进程读压力
    {
      size_t sum_len = 0, times = 0;
      int res = 0;
      size_t i = 0;
      clock_t bt = clock();
      while (0 == res) {
        size_t len;
        res = shm_recv(channel, buf_rgroup[i], len_group[i], &len);
        if (0 == res) {
          CASE_EXPECT_EQ(len, len_group[i]);
          sum_len += len_group[i];
          ++times;
        }

        i = (i + 1) % group_num;
      }
      clock_t et = clock();

      CASE_EXPECT_EQ(EN_ATBUS_ERR_NO_DATA, res);
      CASE_MSG_INFO() << "recv " << sum_len << " bytes(" << times << " times) in "
                      << ((et - bt) / (CLOCKS_PER_SEC / 1000)) << "ms" << std::endl;
      recv_sum_len = sum_len;
    }

    // 简单数据校验
    {
      for (size_t i = 0; i < group_num; ++i) {
        CASE_EXPECT_EQ(0, memcmp(buf_group[i], buf_rgroup[i], len_group[i]));
      }
    }

    CASE_EXPECT_EQ(recv_sum_len, send_sum_len);
  }
}

#endif

