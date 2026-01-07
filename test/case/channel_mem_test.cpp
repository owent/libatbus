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

CASE_TEST(channel, mem_attach_with_invalid_magic) {
  using namespace atbus::channel;
  const size_t buffer_len = 2 * 1024 * 1024;  // 2MB
  unsigned char *buffer = new unsigned char[buffer_len];

  mem_channel *channel = nullptr;
  CASE_EXPECT_EQ(0, mem_init(buffer, buffer_len, &channel, nullptr));
  CASE_EXPECT_NE(nullptr, channel);

  memset(buffer + 4, 0, 4);
  CASE_EXPECT_EQ(EN_ATBUS_ERR_CHANNEL_BUFFER_INVALID, mem_attach(buffer, buffer_len, &channel, nullptr));

  delete[] buffer;
}

CASE_TEST(channel, mem_attach_with_invalid_version) {
  using namespace atbus::channel;
  const size_t buffer_len = 2 * 1024 * 1024;  // 2MB
  unsigned char *buffer = new unsigned char[buffer_len];

  mem_channel *channel = nullptr;
  CASE_EXPECT_EQ(0, mem_init(buffer, buffer_len, &channel, nullptr));
  CASE_EXPECT_NE(nullptr, channel);

  CASE_EXPECT_EQ(2, mem_info_get_version(channel));
  CASE_EXPECT_EQ(0, mem_info_get_version(nullptr));

  (*reinterpret_cast<uint16_t *>(buffer + 16)) = 1;
  CASE_EXPECT_EQ(EN_ATBUS_ERR_CHANNEL_UNSUPPORTED_VERSION, mem_attach(buffer, buffer_len, &channel, nullptr));

  delete[] buffer;
}

CASE_TEST(channel, mem_attach_with_invalid_align_size) {
  using namespace atbus::channel;
  const size_t buffer_len = 2 * 1024 * 1024;  // 2MB
  unsigned char *buffer = new unsigned char[buffer_len];

  mem_channel *channel = nullptr;
  CASE_EXPECT_EQ(0, mem_init(buffer, buffer_len, &channel, nullptr));
  CASE_EXPECT_NE(nullptr, channel);

  CASE_EXPECT_EQ(ATBUS_MACRO_DATA_ALIGN_SIZE, mem_info_get_align_size(channel));
  CASE_EXPECT_EQ(0, mem_info_get_align_size(nullptr));

  (*reinterpret_cast<uint16_t *>(buffer + 18)) = ATBUS_MACRO_DATA_ALIGN_SIZE / 2;
  CASE_EXPECT_EQ(EN_ATBUS_ERR_CHANNEL_ALIGN_SIZE_MISMATCH, mem_attach(buffer, buffer_len, &channel, nullptr));

  delete[] buffer;
}

CASE_TEST(channel, mem_attach_with_invalid_host_size) {
  using namespace atbus::channel;
  const size_t buffer_len = 2 * 1024 * 1024;  // 2MB
  unsigned char *buffer = new unsigned char[buffer_len];

  mem_channel *channel = nullptr;
  CASE_EXPECT_EQ(0, mem_init(buffer, buffer_len, &channel, nullptr));
  CASE_EXPECT_NE(nullptr, channel);

  CASE_EXPECT_EQ(sizeof(size_t), mem_info_get_host_size(channel));
  CASE_EXPECT_EQ(0, mem_info_get_host_size(nullptr));

  (*reinterpret_cast<uint16_t *>(buffer + 20)) = static_cast<uint16_t>(sizeof(size_t) / 2);
  CASE_EXPECT_EQ(EN_ATBUS_ERR_CHANNEL_ARCH_SIZE_T_MISMATCH, mem_attach(buffer, buffer_len, &channel, nullptr));

  delete[] buffer;
}

CASE_TEST(channel, mem_show_channel) {
  using namespace atbus::channel;
  const size_t buffer_len = 16 * 1024;  // 16KB
  unsigned char *buffer = new unsigned char[buffer_len];

  mem_channel *channel = nullptr;
  CASE_EXPECT_EQ(0, mem_init(buffer, buffer_len, &channel, nullptr));
  CASE_EXPECT_NE(nullptr, channel);
  mem_show_channel(channel, CASE_MSG_INFO(), true, 8);

  delete[] buffer;
}

CASE_TEST(channel, mem_siso) {
  using namespace atbus::channel;
  const size_t buffer_len = 512 * 1024 * 1024;  // 512MB
  char *buffer = new char[buffer_len];

  mem_channel *channel = nullptr;

  CASE_EXPECT_EQ(0, mem_init(buffer, buffer_len, &channel, nullptr));
  CASE_EXPECT_NE(nullptr, channel);
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

        res = mem_send(channel, buf_group[i], len_group[i]);
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
        res = mem_recv(channel, buf_rgroup[i], len_group[i], &len);
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

  delete[] buffer;
}

#if defined(UTIL_CONFIG_COMPILER_CXX_LAMBDAS) && UTIL_CONFIG_COMPILER_CXX_LAMBDAS

CASE_TEST(channel, mem_miso) {
  using namespace atbus::channel;
  const size_t buffer_len = 8 * 1024 * 1024;  // 8MB
  char *buffer = new char[buffer_len];

  mem_channel *channel = nullptr;

  CASE_EXPECT_EQ(EN_ATBUS_ERR_CHANNEL_SIZE_TOO_SMALL, mem_attach(buffer, 4096, &channel, nullptr));
  CASE_EXPECT_EQ(EN_ATBUS_ERR_CHANNEL_SIZE_TOO_SMALL, mem_init(buffer, 4096, &channel, nullptr));
  CASE_EXPECT_EQ(0, mem_init(buffer, buffer_len, &channel, nullptr));
  CASE_EXPECT_NE(nullptr, channel);
  // 4KB header

  // set longer timeout when in unit test(appveyor ci timeout sometimes)
  CASE_EXPECT_EQ(0, mem_configure_set_write_timeout(channel, 256));
  CASE_EXPECT_EQ(256, mem_configure_get_write_timeout(channel));
  CASE_EXPECT_EQ(0, mem_configure_set_write_retry_times(channel, 3));
  CASE_EXPECT_EQ(3, mem_configure_get_write_retry_times(channel));
  srand(static_cast<unsigned>(time(nullptr)));

  CASE_EXPECT_EQ(EN_ATBUS_ERR_PARAMS, mem_send(nullptr, nullptr, 0));
  CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, mem_send(channel, nullptr, 0));
  CASE_EXPECT_EQ(EN_ATBUS_ERR_BUFF_LIMIT, mem_send(channel, buffer, buffer_len));

  int left_sec = 16;
  atfw::util::lock::atomic_int_type<size_t> sum_send_len;
  sum_send_len.store(0);
  atfw::util::lock::atomic_int_type<size_t> sum_send_times;
  sum_send_times.store(0);
  atfw::util::lock::atomic_int_type<size_t> sum_send_full;
  sum_send_full.store(0);
  atfw::util::lock::atomic_int_type<size_t> sum_send_err;
  sum_send_err.store(0);
  atfw::util::lock::atomic_int_type<size_t> sum_seq;
  sum_seq.store(0);
  size_t sum_recv_len = 0;
  size_t sum_recv_times = 0;
  size_t sum_recv_err = 0;
  bool all_write_thread_exit = false;

  // 创建32个写线程
  const size_t wn = 32;
  std::thread *write_threads[wn];
  for (size_t i = 0; i < wn; ++i) {
    write_threads[i] =
        new std::thread([&left_sec, &sum_send_len, &sum_send_times, &sum_send_full, &sum_send_err, &sum_seq, channel] {
          size_t buf_pool[1024];
          size_t seq_head = sum_seq.fetch_add(1);
          size_t head_offset = sizeof(size_t) * 6;
          size_t head_len = sizeof(size_t) * 2;
          seq_head <<= head_offset;

          size_t seq_body = 0;

          while (left_sec > 0) {
            size_t n = static_cast<size_t>(rand() % 1024);  // 最大 4K-8K的包
            if (0 == n) n = 1;                              /** 去除0字节包，保证顺序 **/

            size_t seq = seq_body | seq_head;
            for (size_t j = 0; j < n; ++j) {
              buf_pool[j] = seq;
            }

            // CASE_THREAD_SLEEP_MS(800)
            // std::cout<< "[ RUNNING  ] seq_head="<< seq_head<< ", seq_body="<< seq_body<< std::endl;
            int res = mem_send(channel, buf_pool, n * sizeof(size_t));

            if (res) {
              if (EN_ATBUS_ERR_BUFF_LIMIT == res) {
                ++sum_send_full;
              } else {
                ++sum_send_err;
              }

              CASE_THREAD_YIELD();
            } else {
              ++sum_send_times;
              size_t cas_len = sum_send_len.load();
              while (false == sum_send_len.compare_exchange_strong(cas_len, cas_len + n * sizeof(size_t)));

              ++seq_body;
              seq_body <<= head_len;
              seq_body >>= head_len;
            }
          }
        });
  }

  // 读进程
  std::thread *read_thread =
      new std::thread([&sum_recv_len, &sum_recv_times, &sum_recv_err, &all_write_thread_exit, channel] {
        size_t buff_recv[1024];  // 最大 4K-8K的包

        size_t head_offset = sizeof(size_t) * 6;
        size_t head_len = sizeof(size_t) * 2;
        size_t data_seq[256] = {0};
        // bool dump_flag = true;

        while (true) {
          size_t len = 0;
          // CASE_THREAD_SLEEP_MS(500);
          int res = mem_recv(channel, buff_recv, sizeof(buff_recv), &len);
          if (res) {
            if (EN_ATBUS_ERR_NO_DATA == res) {
              CASE_THREAD_YIELD();
              if (all_write_thread_exit) {
                break;
              }
            } else {
              CASE_EXPECT_LE(EN_ATBUS_ERR_NODE_BAD_BLOCK_CSEQ_ID, res);
              CASE_EXPECT_GE(EN_ATBUS_ERR_BAD_DATA, res);
              ++sum_recv_err;
            }
          } else {
            sum_recv_len += len;
            ++sum_recv_times;

            CASE_EXPECT_EQ(0, len % sizeof(size_t));
            len /= sizeof(size_t);

            if (len > 0) {
              size_t rdh = buff_recv[0] >> head_offset;
              size_t rdd = (buff_recv[0] << head_len) >> head_len;
              CASE_EXPECT_EQ(data_seq[rdh], rdd);

              if (data_seq[rdh] != rdd) {
                mem_show_channel(channel,
                                 CASE_MSG_INFO() << "rdh=" << rdh << ", data_seq[rdh]=" << data_seq[rdh]
                                                 << ", rdd=" << rdd << ", receive[0]=" << buff_recv[0] << std::endl,
                                 true, 16);
              }

              data_seq[rdh] = rdd + 1;
              data_seq[rdh] <<= head_len;
              data_seq[rdh] >>= head_len;

              for (size_t i = 1; i < len; ++i) {
                bool flag = buff_recv[i] == buff_recv[0];
                CASE_EXPECT_EQ(buff_recv[i], buff_recv[0]);
                if (!flag) {
                  break;
                }
              }
            }
          }
        }
      });

  // 检查状态
  {
    int secs = 0;
    do {
      --left_sec;
      ++secs;
      CASE_THREAD_SLEEP_MS(1000);
      std::pair<size_t, size_t> curent_cursor = ::atbus::channel::mem_last_action();
      CASE_MSG_INFO() << "NO." << secs << " second(s)" << std::endl;
      CASE_MSG_INFO() << "recv(" << sum_recv_times << " times, " << sum_recv_len << " Bytes) err " << sum_recv_err
                      << " times" << std::endl;
      CASE_MSG_INFO() << "send(" << sum_send_times.load() << " times, " << sum_send_len.load() << " Bytes) " << "full "
                      << sum_send_full.load() << " times, err " << sum_send_err.load() << " times" << std::endl;
      CASE_MSG_INFO() << "\tdata nodes [" << curent_cursor.first << ", " << curent_cursor.second << ")" << std::endl;

    } while (left_sec >= 0);
  }

  for (size_t i = 0; i < wn; ++i) {
    write_threads[i]->join();
    delete write_threads[i];
  }

  all_write_thread_exit = true;
  read_thread->join();
  delete read_thread;

  mem_stats_block_error stats_error;
  mem_stats_get_error(channel, stats_error);
  CASE_EXPECT_EQ(0, stats_error.write_check_sequence_failed_count);
  CASE_EXPECT_EQ(0, stats_error.write_retry_count);

  CASE_EXPECT_EQ(0, stats_error.read_bad_node_count);
  CASE_EXPECT_EQ(0, stats_error.read_bad_block_count);
  CASE_EXPECT_EQ(0, stats_error.read_write_timeout_count);
  CASE_EXPECT_EQ(0, stats_error.read_check_block_size_failed_count);
  CASE_EXPECT_EQ(0, stats_error.read_check_node_size_failed_count);
  CASE_EXPECT_EQ(0, stats_error.read_check_hash_failed_count);
  delete[] buffer;
}

#endif
