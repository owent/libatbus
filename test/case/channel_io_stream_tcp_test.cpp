#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <sstream>

#include <detail/libatbus_error.h>
#include "detail/libatbus_channel_export.h"
#include "frame/test_macros.h"

static constexpr const size_t MAX_TEST_BUFFER_LEN = ATBUS_MACRO_MESSAGE_LIMIT * 4;
static int g_check_flag = 0;
static std::pair<size_t, size_t> g_recv_rec = std::make_pair(0, 0);
static std::list<std::pair<size_t, size_t> > g_check_buff_sequence;

static void disconnected_callback_test_fn(atbus::channel::io_stream_channel *channel,        // 事件触发的channel
                                          atbus::channel::io_stream_connection *connection,  // 事件触发的连接
                                          int status,                                        // libuv传入的转态码
                                          void *,  // 额外参数(不同事件不同含义)
                                          size_t   // 额外参数长度
) {
  CASE_EXPECT_NE(nullptr, channel);
  CASE_EXPECT_NE(nullptr, connection);
  CASE_EXPECT_EQ(0, status);
  CASE_EXPECT_EQ(0, channel->error_code);

  if (0 != status) {
    CASE_MSG_INFO() << uv_err_name(channel->error_code) << ":" << uv_strerror(channel->error_code) << std::endl;
  } else {
    CASE_MSG_INFO() << "disconnect done: " << connection->addr.address << std::endl;
  }

  ++g_check_flag;
}

static void accepted_callback_test_fn(atbus::channel::io_stream_channel *channel,        // 事件触发的channel
                                      atbus::channel::io_stream_connection *connection,  // 事件触发的连接
                                      int status,                                        // libuv传入的转态码
                                      void *,                                            // 额外参数(不同事件不同含义)
                                      size_t                                             // 额外参数长度
) {
  CASE_EXPECT_NE(nullptr, channel);
  CASE_EXPECT_NE(nullptr, connection);
  CASE_EXPECT_EQ(0, status);
  CASE_EXPECT_EQ(0, channel->error_code);

  if (0 != status) {
    CASE_MSG_INFO() << uv_err_name(channel->error_code) << ":" << uv_strerror(channel->error_code) << std::endl;
  } else {
    CASE_MSG_INFO() << "accept connection: " << connection->addr.address << std::endl;
  }

  ++g_check_flag;
}

static void listen_callback_test_fn(atbus::channel::io_stream_channel *channel,        // 事件触发的channel
                                    atbus::channel::io_stream_connection *connection,  // 事件触发的连接
                                    int status,                                        // libuv传入的转态码
                                    void *,                                            // 额外参数(不同事件不同含义)
                                    size_t                                             // 额外参数长度
) {
  CASE_EXPECT_NE(nullptr, channel);
  CASE_EXPECT_NE(nullptr, connection);
  CASE_EXPECT_EQ(0, status);
  CASE_EXPECT_EQ(0, channel->error_code);

  // listen accepted event
  connection->evt.callbacks[atbus::channel::io_stream_callback_evt_t::EN_FN_ACCEPTED] = accepted_callback_test_fn;

  ++g_check_flag;
}

static void connected_callback_test_fn(atbus::channel::io_stream_channel *channel,        // 事件触发的channel
                                       atbus::channel::io_stream_connection *connection,  // 事件触发的连接
                                       int status,                                        // libuv传入的转态码
                                       void *,                                            // 额外参数(不同事件不同含义)
                                       size_t                                             // 额外参数长度
) {
  CASE_EXPECT_NE(nullptr, channel);
  CASE_EXPECT_NE(nullptr, connection);
  CASE_EXPECT_EQ(0, status);
  CASE_EXPECT_EQ(0, channel->error_code);

  if (0 != status) {
    CASE_MSG_INFO() << uv_err_name(channel->error_code) << ":" << uv_strerror(channel->error_code) << std::endl;
  } else {
    CASE_MSG_INFO() << "connect to " << connection->addr.address << " success" << std::endl;
  }

  ++g_check_flag;
}

static int setup_channel(atbus::channel::io_stream_channel &channel, const char *listen, const char *conn) {
  atbus::channel::channel_address_t addr;

  int res = 0;
  if (nullptr != listen) {
    atbus::channel::make_address(listen, addr);
    res = atbus::channel::io_stream_listen(&channel, addr, listen_callback_test_fn, nullptr, 0);
  } else {
    atbus::channel::make_address(conn, addr);
    res = atbus::channel::io_stream_connect(&channel, addr, connected_callback_test_fn, nullptr, 0);
  }

  if (0 != res) {
    CASE_MSG_INFO() << uv_err_name(channel.error_code) << ":" << uv_strerror(channel.error_code) << std::endl;
    return 0;
  } else {
    return 1;
  }
}

static char *get_test_buffer() {
  static char ret[MAX_TEST_BUFFER_LEN] = {0};
  if (0 != ret[0]) {
    return ret;
  }

  for (size_t i = 0; i < MAX_TEST_BUFFER_LEN - 1; ++i) {
    ret[i] = static_cast<char>('A' + rand() % 26);
  }

  return ret;
}

static void recv_callback_check_fn(atbus::channel::io_stream_channel *channel,        // 事件触发的channel
                                   atbus::channel::io_stream_connection *connection,  // 事件触发的连接
                                   int status,                                        // libuv传入的转态码
                                   void *input,                                       // 额外参数(不同事件不同含义)
                                   size_t s                                           // 额外参数长度
) {
  CASE_EXPECT_NE(nullptr, channel);
  CASE_EXPECT_NE(nullptr, connection);

  if (status < 0) {
    CASE_EXPECT_EQ(nullptr, input);
    CASE_EXPECT_EQ(0, s);

    CASE_EXPECT_TRUE(UV_EOF == channel->error_code || UV_ECONNRESET == channel->error_code);
    return;
  }

  CASE_EXPECT_NE(nullptr, input);
  CASE_EXPECT_EQ(0, status);
  CASE_EXPECT_EQ(0, channel->error_code);

  CASE_EXPECT_FALSE(g_check_buff_sequence.empty());
  if (g_check_buff_sequence.empty()) {
    return;
  }

  ++g_recv_rec.first;
  g_recv_rec.second += s;

  CASE_EXPECT_EQ(s, g_check_buff_sequence.front().second);
  char *buff = get_test_buffer();
  char *input_buff = reinterpret_cast<char *>(input);
  for (size_t i = 0; i < g_check_buff_sequence.front().second; ++i) {
    CASE_EXPECT_EQ(buff[i + g_check_buff_sequence.front().first], input_buff[i]);
    if (buff[i + g_check_buff_sequence.front().first] != input_buff[i]) {
      break;
    }
  }
  g_check_buff_sequence.pop_front();

  ++g_check_flag;
}

CASE_TEST(channel, io_stream_tcp_basic) {
  atbus::adapter::loop_t loop;
  uv_loop_init(&loop);

  atbus::channel::io_stream_channel svr, cli;
  atbus::channel::io_stream_init(&svr, &loop, nullptr);
  atbus::channel::io_stream_init(&cli, &loop, nullptr);
  CASE_EXPECT_EQ(&loop, svr.ev_loop);
  CASE_EXPECT_EQ(&loop, cli.ev_loop);

  g_check_flag = 0;

  int inited_fds = 0;
  inited_fds += setup_channel(svr, "ipv6://:::16387", nullptr);
  CASE_EXPECT_EQ(1, g_check_flag);
  CASE_EXPECT_NE(nullptr, svr.ev_loop);

  if (0 == inited_fds) {
    uv_loop_close(&loop);
    return;
  }

  inited_fds = 0;
  inited_fds += setup_channel(cli, nullptr, "ipv4://127.0.0.1:16387");
  inited_fds += setup_channel(cli, nullptr, "dns://localhost:16387");
  inited_fds += setup_channel(cli, nullptr, "ipv6://::1:16387");

  int check_flag = g_check_flag;
  while (g_check_flag - check_flag < 2 * inited_fds) {
    uv_run(&loop, UV_RUN_ONCE);
  }

  svr.evt.callbacks[atbus::channel::io_stream_callback_evt_t::EN_FN_RECVED] = recv_callback_check_fn;
  cli.evt.callbacks[atbus::channel::io_stream_callback_evt_t::EN_FN_RECVED] = recv_callback_check_fn;
  char *buf = get_test_buffer();

  check_flag = g_check_flag;
  // small buffer
  atbus::channel::io_stream_send(cli.conn_pool.begin()->second.get(), buf, 13);
  g_check_buff_sequence.push_back(std::make_pair(0, 13));
  atbus::channel::io_stream_send(cli.conn_pool.begin()->second.get(), buf + 13, 28);
  g_check_buff_sequence.push_back(std::make_pair(13, 28));
  atbus::channel::io_stream_send(cli.conn_pool.begin()->second.get(), buf + 13 + 28, 100);
  g_check_buff_sequence.push_back(std::make_pair(13 + 28, 100));

  // big buffer
  atbus::channel::io_stream_send(cli.conn_pool.begin()->second.get(), buf + 1024, 56 * 1024 + 3);
  g_check_buff_sequence.push_back(std::make_pair(1024, 56 * 1024 + 3));

  while (g_check_flag - check_flag < 4) {
    uv_run(&loop, UV_RUN_ONCE);
  }

  // many big buffer
  {
    check_flag = g_check_flag;
    atbus::channel::io_stream_channel::conn_pool_t::iterator it = svr.conn_pool.begin();
    // 跳过listen的socket
    if (it->second->addr.address == "ipv6://:::16387") {
      ++it;
    }

    size_t sum_size = 0;
    g_recv_rec = std::make_pair(0, 0);
    for (int i = 0; i < 153; ++i) {
      size_t s = static_cast<size_t>(rand() % 2048);
      size_t l = static_cast<size_t>(rand() % 10240) + 20 * 1024;
      atbus::channel::io_stream_send(it->second.get(), buf + s, l);
      g_check_buff_sequence.push_back(std::make_pair(s, l));
      sum_size += l;
    }

    CASE_MSG_INFO() << "send " << sum_size << " bytes data with " << g_check_buff_sequence.size() << " packages done."
                    << std::endl;

    while (g_check_flag - check_flag < 153) {
      uv_run(&loop, UV_RUN_ONCE);
    }

    CASE_MSG_INFO() << "recv " << g_recv_rec.second << " bytes data with " << g_recv_rec.first
                    << " packages and checked done." << std::endl;
  }

  std::stringstream ssout;
  atbus::channel::io_stream_show_channel(nullptr, ssout);
  atbus::channel::io_stream_show_channel(&svr, ssout);

  atbus::channel::io_stream_close(&svr);
  atbus::channel::io_stream_close(&cli);
  CASE_EXPECT_EQ(0, svr.conn_pool.size());
  CASE_EXPECT_EQ(0, cli.conn_pool.size());

  uv_loop_close(&loop);
}

// reset by peer(client)
CASE_TEST(channel, io_stream_tcp_reset_by_client) {
  atbus::channel::io_stream_channel svr, cli;
  atbus::channel::io_stream_init(&svr, nullptr, nullptr);
  atbus::channel::io_stream_init(&cli, nullptr, nullptr);

  svr.evt.callbacks[atbus::channel::io_stream_callback_evt_t::EN_FN_DISCONNECTED] = disconnected_callback_test_fn;

  int check_flag = g_check_flag = 0;

  int inited_fds = 0;
  inited_fds += setup_channel(svr, "ipv6://:::16387", nullptr);
  CASE_EXPECT_EQ(1, g_check_flag);
  CASE_EXPECT_NE(nullptr, svr.ev_loop);
  if (0 == inited_fds) {
    return;
  }

  inited_fds = 0;
  inited_fds += setup_channel(cli, nullptr, "ipv4://127.0.0.1:16387");
  inited_fds += setup_channel(cli, nullptr, "dns://localhost:16387");
  inited_fds += setup_channel(cli, nullptr, "ipv6://::1:16387");

  while (g_check_flag - check_flag < 2 * inited_fds + 1) {
    atbus::channel::io_stream_run(&svr, atbus::adapter::RUN_NOWAIT);
    atbus::channel::io_stream_run(&cli, atbus::adapter::RUN_NOWAIT);
    CASE_THREAD_SLEEP_MS(8);
  }
  CASE_EXPECT_NE(0, cli.conn_pool.size());

  check_flag = g_check_flag;
  atbus::channel::io_stream_close(&cli);
  CASE_EXPECT_EQ(0, cli.conn_pool.size());

  while (g_check_flag - check_flag < inited_fds) {
    atbus::channel::io_stream_run(&svr, atbus::adapter::RUN_NOWAIT);
    CASE_THREAD_SLEEP_MS(8);
  }
  CASE_EXPECT_EQ(1, svr.conn_pool.size());

  atbus::channel::io_stream_close(&svr);
  CASE_EXPECT_EQ(0, svr.conn_pool.size());
}

// reset by peer(server)
CASE_TEST(channel, io_stream_tcp_reset_by_server) {
  atbus::channel::io_stream_channel svr, cli;
  atbus::channel::io_stream_init(&svr, nullptr, nullptr);
  atbus::channel::io_stream_init(&cli, nullptr, nullptr);

  cli.evt.callbacks[atbus::channel::io_stream_callback_evt_t::EN_FN_DISCONNECTED] = disconnected_callback_test_fn;

  int check_flag = g_check_flag = 0;

  int inited_fds = 0;
  inited_fds += setup_channel(svr, "ipv6://:::16387", nullptr);
  CASE_EXPECT_EQ(1, g_check_flag);
  CASE_EXPECT_NE(nullptr, svr.ev_loop);
  if (0 == inited_fds) {
    return;
  }

  inited_fds = 0;
  inited_fds += setup_channel(cli, nullptr, "ipv4://127.0.0.1:16387");
  inited_fds += setup_channel(cli, nullptr, "dns://localhost:16387");
  inited_fds += setup_channel(cli, nullptr, "ipv6://::1:16387");

  while (g_check_flag - check_flag < 2 * inited_fds + 1) {
    atbus::channel::io_stream_run(&svr, atbus::adapter::RUN_NOWAIT);
    atbus::channel::io_stream_run(&cli, atbus::adapter::RUN_NOWAIT);
    CASE_THREAD_SLEEP_MS(8);
  }
  CASE_EXPECT_NE(0, cli.conn_pool.size());

  check_flag = g_check_flag;
  atbus::channel::io_stream_close(&svr);
  CASE_EXPECT_EQ(0, svr.conn_pool.size());

  while (g_check_flag - check_flag < inited_fds) {
    atbus::channel::io_stream_run(&cli, atbus::adapter::RUN_NOWAIT);
    CASE_THREAD_SLEEP_MS(8);
  }
  CASE_EXPECT_EQ(0, cli.conn_pool.size());

  atbus::channel::io_stream_close(&cli);
}

static void recv_size_err_callback_check_fn(atbus::channel::io_stream_channel *channel,        // 事件触发的channel
                                            atbus::channel::io_stream_connection *connection,  // 事件触发的连接
                                            int status,                                        // libuv传入的转态码
                                            void *input,  // 额外参数(不同事件不同含义)
                                            size_t        // 额外参数长度
) {
  CASE_EXPECT_NE(nullptr, channel);
  CASE_EXPECT_NE(nullptr, connection);

  if (EN_ATBUS_ERR_INVALID_SIZE == status) {
    CASE_EXPECT_NE(nullptr, input);
    CASE_EXPECT_EQ(EN_ATBUS_ERR_INVALID_SIZE, status);
    CASE_EXPECT_EQ(0, channel->error_code);

  } else if (EN_ATBUS_ERR_READ_FAILED == status) {
    CASE_EXPECT_EQ(nullptr, input);
    CASE_EXPECT_EQ(EN_ATBUS_ERR_READ_FAILED, status);
    CASE_EXPECT_TRUE(UV_ECONNRESET == channel->error_code || UV_EOF == channel->error_code);
  } else {
    CASE_EXPECT_TRUE(EN_ATBUS_ERR_INVALID_SIZE == status || EN_ATBUS_ERR_READ_FAILED == status);
  }

  ++g_check_flag;
}

// buffer recv/send size limit
CASE_TEST(channel, io_stream_tcp_size_extended) {
  atbus::channel::io_stream_channel svr, cli;
  atbus::channel::io_stream_conf conf;
  atbus::channel::io_stream_init_configure(&conf);
  conf.send_buffer_limit_size = conf.recv_buffer_max_size + 1;

  atbus::channel::io_stream_init(&svr, nullptr, &conf);
  atbus::channel::io_stream_init(&cli, nullptr, &conf);

  svr.evt.callbacks[atbus::channel::io_stream_callback_evt_t::EN_FN_RECVED] = recv_size_err_callback_check_fn;
  cli.evt.callbacks[atbus::channel::io_stream_callback_evt_t::EN_FN_RECVED] = recv_size_err_callback_check_fn;
  svr.evt.callbacks[atbus::channel::io_stream_callback_evt_t::EN_FN_DISCONNECTED] = disconnected_callback_test_fn;
  svr.evt.callbacks[atbus::channel::io_stream_callback_evt_t::EN_FN_DISCONNECTED] = disconnected_callback_test_fn;

  int check_flag = g_check_flag = 0;

  setup_channel(svr, "ipv6://:::16387", nullptr);
  CASE_EXPECT_EQ(1, g_check_flag);
  CASE_EXPECT_NE(nullptr, svr.ev_loop);

  int inited_fds = 0;
  inited_fds += setup_channel(cli, nullptr, "ipv4://127.0.0.1:16387");

  while (g_check_flag - check_flag < 2 * inited_fds) {
    atbus::channel::io_stream_run(&svr, atbus::adapter::RUN_NOWAIT);
    atbus::channel::io_stream_run(&cli, atbus::adapter::RUN_NOWAIT);
    CASE_THREAD_SLEEP_MS(8);
  }
  CASE_EXPECT_NE(0, cli.conn_pool.size());

  check_flag = g_check_flag;

  int res = atbus::channel::io_stream_send(cli.conn_pool.begin()->second.get(), get_test_buffer(),
                                           conf.recv_buffer_limit_size + 1);
  CASE_EXPECT_EQ(0, res);

  res = atbus::channel::io_stream_send(cli.conn_pool.begin()->second.get(), get_test_buffer(),
                                       conf.send_buffer_limit_size + 1);
  CASE_EXPECT_EQ(EN_ATBUS_ERR_INVALID_SIZE, res);

  while (g_check_flag - check_flag < 1) {
    atbus::channel::io_stream_run(&svr, atbus::adapter::RUN_NOWAIT);
    atbus::channel::io_stream_run(&cli, atbus::adapter::RUN_NOWAIT);
    CASE_THREAD_SLEEP_MS(32);
  }

  // 错误的数据大小会导致连接断开
  res = atbus::channel::io_stream_send(cli.conn_pool.begin()->second.get(), get_test_buffer(),
                                       conf.send_buffer_limit_size);
  CASE_EXPECT_EQ(0, res);

  // 有接收端关闭，所以一定是接收端先出发关闭连接。
  // 这里只要判定后触发方完成回调，那么先触发方必然已经完成
  while (!cli.conn_pool.empty()) {
    atbus::channel::io_stream_run(&svr, atbus::adapter::RUN_NOWAIT);
    atbus::channel::io_stream_run(&cli, atbus::adapter::RUN_NOWAIT);
    CASE_THREAD_SLEEP_MS(32);
  }

  CASE_EXPECT_EQ(0, cli.conn_pool.size());
  CASE_EXPECT_EQ(1, svr.conn_pool.size());

  atbus::channel::io_stream_close(&cli);
  atbus::channel::io_stream_close(&svr);
}

static void connect_failed_callback_test_fn(atbus::channel::io_stream_channel *channel,        // 事件触发的channel
                                            atbus::channel::io_stream_connection *connection,  // 事件触发的连接
                                            int status,                                        // libuv传入的转态码
                                            void *,  // 额外参数(不同事件不同含义)
                                            size_t   // 额外参数长度
) {
  CASE_EXPECT_NE(nullptr, channel);
  CASE_EXPECT_EQ(nullptr, connection);

  CASE_EXPECT_TRUE(EN_ATBUS_ERR_SOCK_CONNECT_FAILED == status || EN_ATBUS_ERR_DNS_GETADDR_FAILED == status);

  if (EN_ATBUS_ERR_SOCK_CONNECT_FAILED == status) {
    CASE_EXPECT_EQ(UV_ECONNREFUSED, channel->error_code);
  } else {
    CASE_EXPECT_TRUE(UV_EAI_NONAME == channel->error_code || UV_EAI_AGAIN == channel->error_code);
  }

  if (0 != channel->error_code) {
    CASE_MSG_INFO() << uv_err_name(channel->error_code) << ":" << uv_strerror(channel->error_code) << std::endl;
  }

  ++g_check_flag;
}

// connect failed
CASE_TEST(channel, io_stream_tcp_connect_failed) {
  atbus::channel::io_stream_channel cli;
  atbus::channel::io_stream_init(&cli, nullptr, nullptr);

  int check_flag = g_check_flag = 0;

  atbus::channel::channel_address_t addr;

  int inited_fds = 0;

  // assume port 16388 is unreachable
  atbus::channel::make_address("ipv4://127.0.0.1:16388", addr);
  int res = atbus::channel::io_stream_connect(&cli, addr, connect_failed_callback_test_fn, nullptr, 0);
  CASE_EXPECT_EQ(0, res);
  if (0 == res) {
    ++inited_fds;
  }

  atbus::channel::make_address("dns://localhost:16388", addr);
  res = atbus::channel::io_stream_connect(&cli, addr, connect_failed_callback_test_fn, nullptr, 0);
  // CASE_EXPECT_EQ(0, res); // travis ci dns error
  if (0 == res) {
    ++inited_fds;
  }

  atbus::channel::make_address("dns://localhost_invalid:16388", addr);
  res = atbus::channel::io_stream_connect(&cli, addr, connect_failed_callback_test_fn, nullptr, 0);
  // CASE_EXPECT_EQ(0, res); // travis ci dns error
  if (0 == res) {
    ++inited_fds;
  }

  while (g_check_flag - check_flag < inited_fds) {
    atbus::channel::io_stream_run(&cli, atbus::adapter::RUN_ONCE);
  }

  atbus::channel::io_stream_close(&cli);
}
