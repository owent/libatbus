
// Copyright 2026 atframework

#include <signal.h>

#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

#include <atbus_connection.h>
#include <atbus_node.h>
#include <libatbus_protocol.h>

#include <common/file_system.h>
#include <common/string_oprs.h>
#include <log/log_wrapper.h>
#include <std/explicit_declare.h>

#include <algorithm/crypto_cipher.h>

#include "atbus_test_utils.h"
#include "frame/test_macros.h"

#include <stdarg.h>

CASE_TEST_EVENT_ON_START(unit_test_event_on_start_setup_project_directory) {
  std::string project_dir;
  if (atfw::util::file_system::dirname(__FILE__, 0, project_dir, 3)) {
    atfw::util::log::log_formatter::set_project_directory(project_dir.c_str(), project_dir.size());
  }
}

#ifdef ATFW_UTIL_MACRO_CRYPTO_CIPHER_ENABLED
CASE_TEST_EVENT_ON_START(unit_test_event_on_start_setup_openssl) {
  atfw::util::crypto::cipher::init_global_algorithm();
}

CASE_TEST_EVENT_ON_EXIT(unit_test_event_on_exit_close_openssl) {
  atfw::util::crypto::cipher::cleanup_global_algorithm();
}
#endif

CASE_TEST_EVENT_ON_START(unit_test_event_on_start_ignore_sigpipe) {
#ifndef WIN32
  signal(SIGPIPE, SIG_IGN);  // close stdin, stdout or stderr
  signal(SIGTSTP, SIG_IGN);  // close tty
  signal(SIGTTIN, SIG_IGN);  // tty input
  signal(SIGTTOU, SIG_IGN);  // tty output
#endif
}

CASE_TEST_EVENT_ON_EXIT(unit_test_event_on_exit_shutdown_protobuf) {
  ATBUS_MACRO_PROTOBUF_NAMESPACE_ID::ShutdownProtobufLibrary();
}

CASE_TEST_EVENT_ON_EXIT(unit_test_event_on_exit_close_libuv) {
  int finish_event = 2048;
  while (0 != uv_loop_alive(uv_default_loop()) && finish_event-- > 0) {
    uv_run(uv_default_loop(), UV_RUN_NOWAIT);
  }
  uv_loop_close(uv_default_loop());
}

#ifndef _WIN32
static int node_msg_test_on_log(const atfw::util::log::log_formatter::caller_info_t &,
                                atfw::util::nostd::string_view content) {
  CASE_MSG_INFO() << content << std::endl;
  return 0;
}
static void setup_atbus_node_logger(atbus::node &n) {
  n.get_logger()->set_level(atfw::util::log::log_level::kDebug);
  n.get_logger()->clear_sinks();
  n.get_logger()->add_sink(node_msg_test_on_log);
}

// 主动reset流程测试
// 正常首发数据测试
CASE_TEST(atbus_node_setup, override_listen_path) {
  atbus::node::conf_t conf;
  atbus::node::default_conf(&conf);
  conf.overwrite_listen_path = false;

  uv_loop_t ev_loop;
  uv_loop_init(&ev_loop);

  conf.ev_loop = &ev_loop;

  {
    atbus::node::ptr_t node1 = atbus::node::create();
    atbus::node::ptr_t node2 = atbus::node::create();
    atbus::node::ptr_t node3 = atbus::node::create();
    setup_atbus_node_logger(*node1);
    setup_atbus_node_logger(*node2);
    setup_atbus_node_logger(*node3);

    CASE_EXPECT_EQ(EN_ATBUS_ERR_NOT_INITED, node1->start());
    CASE_EXPECT_EQ(EN_ATBUS_ERR_NOT_INITED, node2->start());
    CASE_EXPECT_EQ(EN_ATBUS_ERR_NOT_INITED, node3->start());

    node1->init(0x12345678, &conf);
    node2->init(0x12356789, &conf);
    conf.overwrite_listen_path = true;
    node3->init(0x12367890, &conf);

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node1->listen("unix:///tmp/atbus-unit-test-overwrite-unix.sock"));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_PIPE_LOCK_PATH_FAILED,
                   node2->listen("pipe:///tmp/atbus-unit-test-overwrite-unix.sock"));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node3->listen("unix:///tmp/atbus-unit-test-overwrite-unix.sock"));
  }

  unit_test_setup_exit(&ev_loop);
}
#endif

#ifdef ATFW_UTIL_MACRO_CRYPTO_CIPHER_ENABLED
CASE_TEST(atbus_node_setup, crypto_algorithms) {
  std::pair<std::string, ::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_TYPE> algorithms[] = {
      {"xxtea", ::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_XXTEA},
      {"chacha20", ::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_CHACHA20},
      {"chacha20-poly1305-ietf", ::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_CHACHA20_POLY1305_IETF},
      {"xchacha20-poly1305-ietf", ::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_XCHACHA20_POLY1305_IETF},
      {"aes-128-cbc", ::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_128_CBC},
      {"aes-128-gcm", ::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_128_GCM},
      {"aes-192-cbc", ::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_192_CBC},
      {"aes-192-gcm", ::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_192_GCM},
      {"aes-256-cbc", ::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_256_CBC},
      {"aes-256-gcm", ::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_256_GCM}};
  std::unordered_set<std::string> cipher_support_algorithms;
  for (auto &name : atfw::util::crypto::cipher::get_all_cipher_names()) {
    cipher_support_algorithms.insert(name);
  }

  size_t count = 0;
  for (auto &test_algorithm : algorithms) {
    if (cipher_support_algorithms.find(test_algorithm.first) == cipher_support_algorithms.end()) {
      continue;
    }

    ::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_TYPE algo_type =
        ::atbus::node::parse_crypto_algorithm_name(test_algorithm.first);
    CASE_EXPECT_EQ(algo_type, test_algorithm.second);
    if (algo_type == test_algorithm.second) {
      ++count;
    }
  }

  CASE_EXPECT_GT(count, 0);
}
#endif

CASE_TEST(atbus_node_setup, compression_algorithms) {
  std::pair<std::string, ::atbus::protocol::ATBUS_COMPRESSION_ALGORITHM_TYPE> algorithms[] = {
      {"zstd", ::atbus::protocol::ATBUS_COMPRESSION_ALGORITHM_ZSTD},
      {"lz4", ::atbus::protocol::ATBUS_COMPRESSION_ALGORITHM_LZ4},
      {"snappy", ::atbus::protocol::ATBUS_COMPRESSION_ALGORITHM_SNAPPY},
      {"zlib", ::atbus::protocol::ATBUS_COMPRESSION_ALGORITHM_ZLIB},
  };

  size_t count = 0;
  for (auto &test_algorithm : algorithms) {
    ++count;
    ::atbus::protocol::ATBUS_COMPRESSION_ALGORITHM_TYPE algo_type =
        ::atbus::node::parse_compression_algorithm_name(test_algorithm.first);
    CASE_EXPECT_EQ(algo_type, test_algorithm.second);
    if (algo_type == test_algorithm.second) {
      ++count;
    }
  }

  CASE_EXPECT_GT(count, 0);
}

// 复现: 以 0.0.0.0 为目标的连接在 connect() 内被重定向到 127.0.0.1 时会改写 connection 的地址,
// 而未完成连接列表的索引 key 仍是原始地址字符串, reset 按新地址查找导致条目无法移除
CASE_TEST(atbus_node_setup, reset_connection_after_loopback_redirect) {
  atbus::node::conf_t conf;
  atbus::node::default_conf(&conf);

  uv_loop_t ev_loop;
  uv_loop_init(&ev_loop);

  conf.ev_loop = &ev_loop;

  {
    atbus::node::ptr_t node = atbus::node::create();
    node->init(0x12345678, &conf);

    atbus::connection::ptr_t conn = atbus::connection::create(node.get(), "atcp://0.0.0.0:16433", false);
    CASE_EXPECT_TRUE(!!conn);
    CASE_EXPECT_EQ(1, node->get_connection_timer_size());

    conn->connect();
    // 连接发起后, reset 必须把连接从未完成连接列表中移除
    conn->reset();
    CASE_EXPECT_EQ(0, node->get_connection_timer_size());
  }

  unit_test_setup_exit(&ev_loop);
}

// 复现: node::reset 清理未完成连接列表的循环曾依赖 connection::reset 自行摘除条目,
// 一旦摘除失败(地址已被改写)且条目非空, while 循环永远无法推进并且 pending_connection_gc_list 无限增长
CASE_TEST(atbus_node_setup, reset_node_with_pending_loopback_redirect_connection) {
  atbus::node::conf_t conf;
  atbus::node::default_conf(&conf);

  uv_loop_t ev_loop;
  uv_loop_init(&ev_loop);

  conf.ev_loop = &ev_loop;

  {
    atbus::node::ptr_t node = atbus::node::create();
    node->init(0x12345678, &conf);

    atbus::connection::ptr_t conn = atbus::connection::create(node.get(), "atcp://0.0.0.0:16433", false);
    CASE_EXPECT_TRUE(!!conn);
    conn->connect();

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node->reset());
    CASE_EXPECT_EQ(0, node->get_connection_timer_size());
  }

  unit_test_setup_exit(&ev_loop);
}

// 复现: 连接失败后残留的连接条目会让后续同地址 connect 被去重判定直接吞掉, 永远不再真正发起连接
CASE_TEST(atbus_node_setup, reconnect_after_failed_loopback_redirect_connect) {
  atbus::node::conf_t conf;
  atbus::node::default_conf(&conf);

  uv_loop_t ev_loop;
  uv_loop_init(&ev_loop);

  conf.ev_loop = &ev_loop;

  {
    atbus::node::ptr_t node = atbus::node::create();
    node->init(0x12345678, &conf);

    // 首次连接到未监听端口, 等待异步连接失败被处理
    atbus::connection::ptr_t conn = atbus::connection::create(node.get(), "atcp://0.0.0.0:16433", false);
    CASE_EXPECT_TRUE(!!conn);
    conn->connect();

    UNITTEST_WAIT_UNTIL(conf.ev_loop, atbus::connection::state_t::kDisconnected == conn->get_status(), 8000, 0) {}
    CASE_EXPECT_EQ(atbus::connection::state_t::kDisconnected, conn->get_status());
    if (atbus::connection::state_t::kDisconnected != conn->get_status()) {
      return;
    }

    // 失败的连接必须从未完成连接列表中移除
    CASE_EXPECT_EQ(0, node->get_connection_timer_size());
    if (0 != node->get_connection_timer_size()) {
      return;
    }

    // 再次 connect 必须真正发起新连接, 并在失败后再次清空列表
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node->connect("atcp://0.0.0.0:16433"));
    UNITTEST_WAIT_UNTIL(conf.ev_loop, 0 == node->get_connection_timer_size(), 8000, 0) {}
    CASE_EXPECT_EQ(0, node->get_connection_timer_size());
  }

  unit_test_setup_exit(&ev_loop);
}

// 同地址的多个连接允许共存(按连接指针独立跟踪超时), 每个连接都必须能独立移除;
// node::connect 通过 by_channel 索引去重, 已有同地址未完成连接时不再发起新连接
CASE_TEST(atbus_node_setup, create_connection_with_duplicated_address) {
  atbus::node::conf_t conf;
  atbus::node::default_conf(&conf);

  uv_loop_t ev_loop;
  uv_loop_init(&ev_loop);

  conf.ev_loop = &ev_loop;

  {
    atbus::node::ptr_t node = atbus::node::create();
    node->init(0x12345678, &conf);

    atbus::connection::ptr_t conn1 = atbus::connection::create(node.get(), "ipv4://127.0.0.1:16434", false);
    CASE_EXPECT_TRUE(!!conn1);
    CASE_EXPECT_EQ(1, node->get_connection_timer_size());

    atbus::connection::ptr_t conn2 = atbus::connection::create(node.get(), "ipv4://127.0.0.1:16434", false);
    CASE_EXPECT_TRUE(!!conn2);
    CASE_EXPECT_EQ(2, node->get_connection_timer_size());
    if (!conn1 || !conn2) {
      return;
    }

    // 已有同地址未完成连接时, node::connect 去重, 不再发起新连接
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node->connect("ipv4://127.0.0.1:16434"));
    CASE_EXPECT_EQ(2, node->get_connection_timer_size());

    // 两个连接必须能互不影响地移除
    conn1->reset();
    CASE_EXPECT_EQ(1, node->get_connection_timer_size());

    conn2->reset();
    CASE_EXPECT_EQ(0, node->get_connection_timer_size());
  }

  unit_test_setup_exit(&ev_loop);
}

// 复现: 上游配置为 0.0.0.0 通配地址时, 连接的归一化地址(atcp://127.0.0.1:PORT)与配置串不同,
// 注册回包必须能通过原始地址匹配上游并刷新拓扑关系
CASE_TEST(atbus_node_setup, upstream_topology_with_wildcard_upstream_address) {
  atbus::node::conf_t conf;
  atbus::node::default_conf(&conf);

  uv_loop_t ev_loop;
  uv_loop_init(&ev_loop);

  conf.ev_loop = &ev_loop;

  {
    atbus::node::ptr_t node1 = atbus::node::create();
    atbus::node::ptr_t node2 = atbus::node::create();

    node1->init(0x12345678, &conf);

    atbus::node::conf_t conf_upstream;
    atbus::node::default_conf(&conf_upstream);
    conf_upstream.ev_loop = &ev_loop;
    conf_upstream.upstream_address = "ipv4://0.0.0.0:16435";
    node2->init(0x12356789, &conf_upstream);

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node1->listen("ipv4://127.0.0.1:16435"));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node1->start());
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node2->start());

    // 注册成功后 node2 必须通过原始地址匹配上游并建立上游拓扑
    UNITTEST_WAIT_UNTIL(
        conf.ev_loop,
        nullptr != node2->get_upstream_endpoint() && node2->get_upstream_endpoint()->get_id() == node1->get_id(), 8000,
        0) {}
    CASE_EXPECT_TRUE(nullptr != node2->get_upstream_endpoint());
    if (nullptr != node2->get_upstream_endpoint()) {
      CASE_EXPECT_EQ(node1->get_id(), node2->get_upstream_endpoint()->get_id());
    }
  }

  unit_test_setup_exit(&ev_loop);
}

// 集群隔离: conf_t 的拷贝构造与赋值必须保留 gateway 列表, default_conf 必须清空它
CASE_TEST(atbus_node_setup, gateway_conf_copy_and_default) {
  atbus::node::conf_t conf;
  atbus::node::default_conf(&conf);

  atbus::node::gateway_t gw;
  gw.address = "ipv4://127.0.0.1:16450";
  gw.match_scope = "prod";
  gw.match_hosts.insert("host-a");
  gw.match_namespaces.insert("game");
  gw.match_labels.emplace("zone", "a");
  conf.gateway.push_back(gw);

  atbus::node::conf_t conf_copied(conf);
  CASE_EXPECT_EQ(static_cast<size_t>(1), conf_copied.gateway.size());
  if (!conf_copied.gateway.empty()) {
    CASE_EXPECT_EQ(gw.address, conf_copied.gateway[0].address);
    CASE_EXPECT_EQ(gw.match_scope, conf_copied.gateway[0].match_scope);
    CASE_EXPECT_TRUE(gw.match_hosts == conf_copied.gateway[0].match_hosts);
    CASE_EXPECT_TRUE(gw.match_namespaces == conf_copied.gateway[0].match_namespaces);
    CASE_EXPECT_TRUE(gw.match_labels == conf_copied.gateway[0].match_labels);
  }

  atbus::node::conf_t conf_assigned;
  conf_assigned = conf;
  CASE_EXPECT_EQ(static_cast<size_t>(1), conf_assigned.gateway.size());
  if (!conf_assigned.gateway.empty()) {
    CASE_EXPECT_EQ(gw.address, conf_assigned.gateway[0].address);
    CASE_EXPECT_TRUE(gw.match_labels == conf_assigned.gateway[0].match_labels);
  }

  // 复用 conf_t 时 default_conf 必须清掉旧的隔离配置
  atbus::node::default_conf(&conf_assigned);
  CASE_EXPECT_TRUE(conf_assigned.gateway.empty());
}

// 集群隔离: gateway_t 与 channel_data 互转必须保留全部匹配规则, 空规则保持通配
CASE_TEST(atbus_node_setup, gateway_channel_data_roundtrip) {
  atbus::node::gateway_t gw;
  gw.address = "ipv4://127.0.0.1:16450";
  gw.match_scope = "prod";
  gw.match_hosts.insert("host-a");
  gw.match_hosts.insert("host-b");
  gw.match_namespaces.insert("game");
  gw.match_labels.emplace("zone", "a");
  gw.match_labels.emplace("app", "x");

  atbus::protocol::channel_data chan;
  atbus::node::dump_gateway_to_channel_data(gw, chan);
  CASE_EXPECT_EQ(gw.address, chan.address());
  CASE_EXPECT_EQ(gw.match_scope, chan.match_scope());
  CASE_EXPECT_EQ(2, chan.match_hosts_size());
  CASE_EXPECT_EQ(1, chan.match_namespaces_size());
  CASE_EXPECT_EQ(2, static_cast<int>(chan.match_labels().size()));

  atbus::node::gateway_t restored = atbus::node::build_gateway_from_channel_data(chan);
  CASE_EXPECT_EQ(gw.address, restored.address);
  CASE_EXPECT_EQ(gw.match_scope, restored.match_scope);
  CASE_EXPECT_TRUE(gw.match_hosts == restored.match_hosts);
  CASE_EXPECT_TRUE(gw.match_namespaces == restored.match_namespaces);
  CASE_EXPECT_TRUE(gw.match_labels == restored.match_labels);

  // 未配置任何匹配规则的地址对所有对端可达
  atbus::protocol::channel_data wildcard_chan;
  wildcard_chan.set_address("ipv4://127.0.0.1:16451");
  atbus::node::gateway_t wildcard_gw = atbus::node::build_gateway_from_channel_data(wildcard_chan);
  CASE_EXPECT_TRUE(wildcard_gw.match_scope.empty());
  CASE_EXPECT_TRUE(wildcard_gw.match_hosts.empty());
  CASE_EXPECT_TRUE(wildcard_gw.match_namespaces.empty());
  CASE_EXPECT_TRUE(wildcard_gw.match_labels.empty());
}

// 集群隔离: listen 地址导出时按本端 scope/namespace 附加默认限制, 未配置则为通配
CASE_TEST(atbus_node_setup, dump_listen_to_channel_data) {
  atbus::node::conf_t conf;
  atbus::node::default_conf(&conf);

  uv_loop_t ev_loop;
  uv_loop_init(&ev_loop);
  conf.ev_loop = &ev_loop;
  conf.scope = "prod";
  conf.namespace_name = "game";

  {
    atbus::node::ptr_t node = atbus::node::create();
    node->init(0x12345678, &conf);

    atbus::protocol::channel_data chan;
    node->dump_listen_to_channel_data("ipv4://127.0.0.1:16450", chan);
    CASE_EXPECT_EQ(std::string("ipv4://127.0.0.1:16450"), chan.address());
    CASE_EXPECT_EQ(std::string("prod"), chan.match_scope());
    CASE_EXPECT_EQ(1, chan.match_namespaces_size());
    if (chan.match_namespaces_size() > 0) {
      CASE_EXPECT_EQ(std::string("game"), chan.match_namespaces(0));
    }
    CASE_EXPECT_EQ(0, chan.match_hosts_size());
    CASE_EXPECT_EQ(0, static_cast<int>(chan.match_labels().size()));
  }

  {
    atbus::node::conf_t wildcard_conf;
    atbus::node::default_conf(&wildcard_conf);
    wildcard_conf.ev_loop = &ev_loop;

    atbus::node::ptr_t node = atbus::node::create();
    node->init(0x12345679, &wildcard_conf);

    atbus::protocol::channel_data chan;
    node->dump_listen_to_channel_data("ipv4://127.0.0.1:16450", chan);
    CASE_EXPECT_TRUE(chan.match_scope().empty());
    CASE_EXPECT_EQ(0, chan.match_namespaces_size());
  }

  unit_test_setup_exit(&ev_loop);
}
