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

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <Windows.h>
#endif

#if defined(ATBUS_CHANNEL_SHM)

#  ifndef _WIN32
#    include <fcntl.h>
#    ifdef __linux__
#      include <sys/file.h>
#    endif
#    include <sys/mman.h>
#    include <sys/stat.h>
#    include <unistd.h>

CASE_TEST(channel, shm_close_preserves_external_owner) {
  using namespace atbus::channel;
  const size_t size = 2 * 1024 * 1024;
  const std::string path = "/atbus-shm-owner-" + std::to_string(getpid());
  int fd = shm_open(path.c_str(), O_RDWR | O_CREAT | O_EXCL, 0600);
  CASE_EXPECT_GE(fd, 0);
  if (fd < 0) return;
  CASE_EXPECT_EQ(0, ftruncate(fd, static_cast<off_t>(size)));
  close(fd);
  shm_channel *channel = nullptr;
  CASE_EXPECT_EQ(0, shm_init(path.c_str(), size, &channel, nullptr));
  CASE_EXPECT_EQ(0, shm_close(path.c_str()));
  CASE_EXPECT_EQ(0, shm_attach(path.c_str(), size, &channel, nullptr));
  CASE_EXPECT_EQ(0, shm_close(path.c_str()));
  CASE_EXPECT_EQ(EN_ATBUS_ERR_SHM_NOT_FOUND, shm_close(path.c_str()));
  CASE_EXPECT_EQ(0, shm_unlink(path.c_str()));

  CASE_EXPECT_EQ(0, shm_init(path.c_str(), size, &channel, nullptr));
  CASE_EXPECT_EQ(0, shm_attach(path.c_str(), size, &channel, nullptr));
  CASE_EXPECT_EQ(0, shm_close(path.c_str()));
  fd = shm_open(path.c_str(), O_RDWR, 0);
  CASE_EXPECT_GE(fd, 0);
  if (fd >= 0) close(fd);
  CASE_EXPECT_EQ(0, shm_close(path.c_str()));
  fd = shm_open(path.c_str(), O_RDWR, 0);
  CASE_EXPECT_LT(fd, 0);
  if (fd >= 0) close(fd);
}

CASE_TEST(channel, shm_init_recovers_empty_object) {
  using namespace atbus::channel;
  const size_t size = 2 * 1024 * 1024;
  const std::string path = "/atbus-shm-empty-" + std::to_string(getpid());
  int fd = shm_open(path.c_str(), O_RDWR | O_CREAT | O_EXCL, 0600);
  CASE_EXPECT_GE(fd, 0);
  if (fd < 0) return;

  shm_channel *channel = nullptr;
  struct stat info = {};
  CASE_EXPECT_LT(shm_attach(path.c_str(), size, &channel, nullptr), 0);
  CASE_EXPECT_EQ(0, fstat(fd, &info));
  CASE_EXPECT_EQ(0, info.st_size);
#    ifdef __linux__
  CASE_EXPECT_EQ(0, flock(fd, LOCK_EX | LOCK_NB));
  CASE_EXPECT_EQ(EN_ATBUS_ERR_SHM_GET_FAILED, shm_init(path.c_str(), size, &channel, nullptr));
  CASE_EXPECT_EQ(0, fstat(fd, &info));
  CASE_EXPECT_EQ(0, info.st_size);
  CASE_EXPECT_EQ(0, flock(fd, LOCK_UN));
#    endif
  int result = shm_init(path.c_str(), size, &channel, nullptr);
  CASE_EXPECT_EQ(0, result);
  if (result == 0) {
#    ifdef __linux__
    // The sizing lock must be available while the initialized channel is still mapped.
    CASE_EXPECT_EQ(0, flock(fd, LOCK_EX | LOCK_NB));
    CASE_EXPECT_EQ(0, flock(fd, LOCK_UN));
#    endif
    CASE_EXPECT_EQ(0, fstat(fd, &info));
    CASE_EXPECT_EQ(static_cast<off_t>(size), info.st_size);
    CASE_EXPECT_EQ(0, shm_close(path.c_str()));
    CASE_EXPECT_EQ(0, shm_attach(path.c_str(), size / 2, &channel, nullptr));
    CASE_EXPECT_EQ(0, shm_close(path.c_str()));
    CASE_EXPECT_EQ(0, shm_init(path.c_str(), size / 2, &channel, nullptr));
    CASE_EXPECT_EQ(0, fstat(fd, &info));
    CASE_EXPECT_EQ(static_cast<off_t>(size), info.st_size);
    CASE_EXPECT_EQ(0, shm_close(path.c_str()));
  }
  close(fd);
  CASE_EXPECT_EQ(0, shm_unlink(path.c_str()));
}
#  endif

#  ifdef _WIN32
CASE_TEST(channel, shm_attach_legacy_global_mapping) {
  using namespace atbus::channel;
  const char *shm_path = "/atbus-channel-legacy-global-test";
  const char *mapping_name = "Global\\atbus-channel-legacy-global-test";
  const size_t buffer_len = 2 * 1024 * 1024;  // 2MB

  HANDLE legacy_mapping = CreateFileMappingA(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0,
                                             static_cast<DWORD>(buffer_len), mapping_name);
  if (nullptr == legacy_mapping) {
    DWORD error = GetLastError();
    if (ERROR_ACCESS_DENIED == error || ERROR_PRIVILEGE_NOT_HELD == error) {
      CASE_MSG_INFO() << "SeCreateGlobalPrivilege is unavailable, skip the legacy Global\\ mapping case" << std::endl;
    } else {
      CASE_EXPECT_NE(nullptr, legacy_mapping);
      CASE_MSG_INFO() << "CreateFileMappingA failed with Win32 error " << error << std::endl;
    }
    return;
  }

  void *legacy_buffer = MapViewOfFile(legacy_mapping, FILE_MAP_ALL_ACCESS, 0, 0, buffer_len);
  CASE_EXPECT_NE(nullptr, legacy_buffer);
  if (nullptr == legacy_buffer) {
    CloseHandle(legacy_mapping);
    return;
  }

  mem_channel *legacy_channel = nullptr;
  int init_result = mem_init(legacy_buffer, buffer_len, &legacy_channel, nullptr);
  CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, init_result);
  if (EN_ATBUS_ERR_SUCCESS == init_result) {
    shm_channel *channel = nullptr;
    int attach_result = shm_attach(shm_path, buffer_len, &channel, nullptr);
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, attach_result);
    CASE_EXPECT_NE(nullptr, channel);
    if (EN_ATBUS_ERR_SUCCESS == attach_result && nullptr != channel) {
      const char payload[] = "legacy-global-mapping";
      char received[sizeof(payload)] = {0};
      size_t received_size = 0;
      CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, shm_send(channel, payload, sizeof(payload)));
      CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, mem_recv(legacy_channel, received, sizeof(received), &received_size));
      CASE_EXPECT_EQ(sizeof(payload), received_size);
      CASE_EXPECT_EQ(0, memcmp(payload, received, sizeof(payload)));
      CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, shm_close(shm_path));
    }
  }

  UnmapViewOfFile(legacy_buffer);
  CloseHandle(legacy_mapping);
}
#  endif

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
