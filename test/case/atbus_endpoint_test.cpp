// Copyright 2026 atframework

#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>
#include <limits>
#include <memory>
#include <numeric>
#include <vector>

#include <common/string_oprs.h>

#include <atbus_connection.h>
#include <atbus_endpoint.h>
#include <atbus_node.h>
#include <detail/libatbus_error.h>

#include "atbus_test_utils.h"
#include "frame/test_macros.h"

CASE_TEST(atbus_endpoint, connection_basic) {
  atbus::connection::ptr_t p = atbus::connection::create(nullptr, "", false);
  CASE_EXPECT_TRUE(!p);
}

CASE_TEST(atbus_endpoint, endpoint_basic) {
  atbus::endpoint::ptr_t p = atbus::endpoint::create(nullptr, 0, 0, "");
  CASE_EXPECT_TRUE(!p);
}

CASE_TEST(atbus_endpoint, is_child) {
  atbus::node::conf_t conf;
  atbus::node::default_conf(&conf);

  atbus::node::ptr_t node = atbus::node::create();
  node->init(0x12345678, &conf);

  auto registry = node->get_topology_registry();
  CASE_EXPECT_TRUE(registry);

  auto make_topology_data = [](int32_t pid, const char *hostname) {
    atbus::topology_data::ptr_t data = ::atfw::util::memory::make_strong_rc<atbus::topology_data>();
    data->pid = pid;
    data->hostname = hostname ? hostname : "";
    return data;
  };

  registry->update_peer(node->get_id(), 0, make_topology_data(node->get_pid(), node->get_hostname().c_str()));
  registry->update_peer(0x12340000, node->get_id(), make_topology_data(1234, "host_a"));
  registry->update_peer(0x1234FFFF, node->get_id(), make_topology_data(1235, "host_a"));

  atbus::topology_peer::ptr_t next_hop;
  CASE_EXPECT_EQ(static_cast<int>(atbus::topology_relation_type::kSelf),
                 static_cast<int>(node->get_topology_relation(node->get_id(), &next_hop)));
  CASE_EXPECT_TRUE(next_hop);
  CASE_EXPECT_EQ(node->get_id(), next_hop->get_bus_id());

  CASE_EXPECT_EQ(static_cast<int>(atbus::topology_relation_type::kImmediateDownstream),
                 static_cast<int>(node->get_topology_relation(0x12340000, &next_hop)));
  CASE_EXPECT_TRUE(next_hop);
  CASE_EXPECT_EQ(0x12340000, next_hop->get_bus_id());

  CASE_EXPECT_EQ(static_cast<int>(atbus::topology_relation_type::kImmediateDownstream),
                 static_cast<int>(node->get_topology_relation(0x1234FFFF, &next_hop)));
  CASE_EXPECT_TRUE(next_hop);
  CASE_EXPECT_EQ(0x1234FFFF, next_hop->get_bus_id());

  CASE_EXPECT_EQ(static_cast<int>(atbus::topology_relation_type::kInvalid),
                 static_cast<int>(node->get_topology_relation(0x12350000, &next_hop)));
  CASE_EXPECT_FALSE(next_hop);
}

CASE_TEST(atbus_endpoint, get_connection) {
  atbus::node::conf_t conf;
  atbus::node::default_conf(&conf);
  uv_loop_t ev_loop;
  uv_loop_init(&ev_loop);

  conf.ev_loop = &ev_loop;
  conf.receive_buffer_size = 64 * 1024;

  char *buffer = new char[conf.receive_buffer_size];
  memset(buffer, -1, sizeof(conf.receive_buffer_size));  // init it and then valgrind will now report uninitialised used

  char addr[32] = {0};
  UTIL_STRFUNC_SNPRINTF(addr, sizeof(addr), "mem://0x%p", buffer);
  if (addr[8] == '0' && addr[9] == 'x') {
    memset(addr, 0, sizeof(addr));
    UTIL_STRFUNC_SNPRINTF(addr, sizeof(addr), "mem://%p", buffer);
  }

  // 排除未完成连接
  {
    atbus::node::ptr_t node = atbus::node::create();
    node->init(0x12345678, &conf);

    atbus::connection::ptr_t conn1 = atbus::connection::create(node.get(), addr, false);

    CASE_EXPECT_EQ(0, conn1->connect());
    atbus::connection::ptr_t conn2 = atbus::connection::create(node.get(), "ipv4://127.0.0.1:80", false);
    conn2->connect();

    atbus::endpoint::ptr_t ep = atbus::endpoint::create(node.get(), 0x12345679, node->get_pid(), node->get_hostname());
    CASE_EXPECT_TRUE(ep->add_connection(conn1.get(), false));
    CASE_EXPECT_TRUE(ep->add_connection(conn2.get(), false));

    CASE_EXPECT_EQ(0, node->add_endpoint(ep));

    atbus::connection *conn3 = node->get_self_endpoint()->get_data_connection(ep.get());
    CASE_EXPECT_EQ(conn3, conn1.get());

    ep = atbus::endpoint::create(node.get(), 0x12345680, node->get_pid(), node->get_hostname());
    CASE_EXPECT_EQ(0, node->add_endpoint(ep));
  }

  unit_test_setup_exit(&ev_loop);

  delete[] buffer;
}

CASE_TEST(atbus_channel, address) {
  atbus::channel::channel_address_t addr;
  CASE_EXPECT_FALSE(atbus::channel::make_address("", addr));

  CASE_EXPECT_FALSE(atbus::channel::is_duplex_address({}));
  CASE_EXPECT_FALSE(atbus::channel::is_simplex_address({}));

  CASE_EXPECT_TRUE(atbus::channel::is_simplex_address("mem://0x1234"));
  CASE_EXPECT_TRUE(atbus::channel::is_simplex_address("shm://0x1234"));

  CASE_EXPECT_FALSE(atbus::channel::is_local_host_address({}));
  CASE_EXPECT_TRUE(atbus::channel::is_local_host_address("unix:///tmp/abc.sock"));
  CASE_EXPECT_TRUE(atbus::channel::is_local_host_address("pipe:///tmp/abc.sock"));

  CASE_EXPECT_FALSE(atbus::channel::is_local_process_address({}));
  CASE_EXPECT_TRUE(atbus::channel::is_local_process_address("mem://0x1234"));
}

// 集群隔离: endpoint 必须保存对端的 scope/namespace/labels 与通道匹配规则
CASE_TEST(atbus_endpoint, reload_scope_labels_and_gateway) {
  atbus::node::conf_t conf;
  atbus::node::default_conf(&conf);

  uv_loop_t ev_loop;
  uv_loop_init(&ev_loop);
  conf.ev_loop = &ev_loop;

  {
    atbus::node::ptr_t node = atbus::node::create();
    node->init(0x12345678, &conf);

    atbus::endpoint::ptr_t ep = atbus::endpoint::create(node.get(), 0x12345679, node->get_pid(), node->get_hostname());
    CASE_EXPECT_TRUE(!!ep);
    if (!ep) {
      unit_test_setup_exit(&ev_loop);
      return;
    }

    // 初始为空, 表示不限制
    CASE_EXPECT_TRUE(ep->get_scope().empty());
    CASE_EXPECT_TRUE(ep->get_namespace().empty());
    CASE_EXPECT_TRUE(ep->get_labels().empty());
    CASE_EXPECT_TRUE(ep->get_gateway().empty());

    // 本地配置源 reload
    std::unordered_map<std::string, std::string> labels;
    labels.emplace("zone", "a");
    std::vector<atbus::node::gateway_t> gateways;
    atbus::node::gateway_t gw;
    gw.address = "ipv4://127.0.0.1:16450";
    gw.match_scope = "prod";
    gateways.push_back(gw);
    ep->reload("prod", "game", labels, gsl::span<const atbus::node::gateway_t>(gateways.data(), gateways.size()));
    CASE_EXPECT_EQ(std::string("prod"), ep->get_scope());
    CASE_EXPECT_EQ(std::string("game"), ep->get_namespace());
    CASE_EXPECT_EQ(static_cast<size_t>(1), ep->get_labels().size());
    CASE_EXPECT_EQ(static_cast<size_t>(1), ep->get_gateway().size());
    if (!ep->get_gateway().empty()) {
      CASE_EXPECT_EQ(gw.address, ep->get_gateway()[0].address);
      CASE_EXPECT_EQ(gw.match_scope, ep->get_gateway()[0].match_scope);
    }

    // 注册包数据源 reload (线上协议字段)
    atbus::protocol::register_data reg;
    reg.set_scope("dev");
    reg.set_namespace_name("lobby");
    (*reg.mutable_labels())["zone"] = "b";
    atbus::protocol::channel_data *chan = reg.add_channels();
    chan->set_address("ipv4://127.0.0.1:16451");
    chan->set_match_scope("dev");
    chan->add_match_hosts("host-a");
    chan->add_match_namespaces("lobby");
    (*chan->mutable_match_labels())["zone"] = "b";
    ep->reload(reg.scope(), reg.namespace_name(), reg.labels(), reg.channels());
    CASE_EXPECT_EQ(std::string("dev"), ep->get_scope());
    CASE_EXPECT_EQ(std::string("lobby"), ep->get_namespace());
    CASE_EXPECT_EQ(static_cast<size_t>(1), ep->get_labels().size());
    {
      auto label_iter = ep->get_labels().find("zone");
      CASE_EXPECT_TRUE(label_iter != ep->get_labels().end() && label_iter->second == "b");
    }
    CASE_EXPECT_EQ(static_cast<size_t>(1), ep->get_gateway().size());
    if (!ep->get_gateway().empty()) {
      const auto &wire_gw = ep->get_gateway()[0];
      CASE_EXPECT_EQ(std::string("ipv4://127.0.0.1:16451"), wire_gw.address);
      CASE_EXPECT_EQ(std::string("dev"), wire_gw.match_scope);
      CASE_EXPECT_TRUE(wire_gw.match_hosts.end() != wire_gw.match_hosts.find("host-a"));
      CASE_EXPECT_TRUE(wire_gw.match_namespaces.end() != wire_gw.match_namespaces.find("lobby"));
      auto label_iter = wire_gw.match_labels.find("zone");
      CASE_EXPECT_TRUE(label_iter != wire_gw.match_labels.end() && label_iter->second == "b");
    }
  }

  unit_test_setup_exit(&ev_loop);
}
