#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <numeric>
#include <vector>

#include <common/string_oprs.h>

#include <atbus_connection.h>
#include <atbus_endpoint.h>
#include <atbus_node.h>
#include <detail/libatbus_error.h>

#include "frame/test_macros.h"

CASE_TEST(atbus_endpoint, connection_basic) {
  atbus::connection::ptr_t p = atbus::connection::create(nullptr, "");
  CASE_EXPECT_TRUE(!p);
}

CASE_TEST(atbus_endpoint, endpoint_basic) {
  std::vector<atbus::endpoint_subnet_conf> subnets;
  atbus::endpoint::ptr_t p = atbus::endpoint::create(nullptr, 0, subnets, 0, "");
  CASE_EXPECT_TRUE(!p);
}

CASE_TEST(atbus_endpoint, get_children_min_max) {
  atbus::endpoint::bus_id_t tested = atbus::endpoint::get_children_max_id(0x12345678, 16);
  CASE_EXPECT_EQ(tested, 0x1234FFFF);

  tested = atbus::endpoint::get_children_min_id(0x12345678, 16);
  CASE_EXPECT_EQ(tested, 0x12340000);
}

CASE_TEST(atbus_endpoint, is_child) {
  atbus::node::conf_t conf;
  atbus::node::default_conf(&conf);

  {
    conf.subnets.push_back(atbus::endpoint_subnet_conf(0, 16));
    conf.subnets.push_back(atbus::endpoint_subnet_conf(0x22345678, 16));
    atbus::node::ptr_t node = atbus::node::create();
    node->init(0x12345678, &conf);

    // 0值边界检测
    CASE_EXPECT_TRUE(node->is_child_node(0x12340000));
    CASE_EXPECT_TRUE(node->is_child_node(0x1234FFFF));
    CASE_EXPECT_FALSE(node->is_child_node(0x1233FFFF));
    CASE_EXPECT_FALSE(node->is_child_node(0x12350000));

    CASE_EXPECT_TRUE(node->is_child_node(0x22340000));
    CASE_EXPECT_TRUE(node->is_child_node(0x2234FFFF));
    CASE_EXPECT_FALSE(node->is_child_node(0x2233FFFF));
    CASE_EXPECT_FALSE(node->is_child_node(0x22350000));

    // 自己是自己的子节点
    CASE_EXPECT_TRUE(node->is_child_node(node->get_id()));

    // 0值边界检测 - 静态接口
    CASE_EXPECT_TRUE(atbus::endpoint::is_child_node(0x12345678, 0x12345678, 16, 0x12340000));
    CASE_EXPECT_TRUE(atbus::endpoint::is_child_node(0x12345678, 0x12345678, 16, 0x1234FFFF));
    CASE_EXPECT_FALSE(atbus::endpoint::is_child_node(0x12345678, 0x12345678, 16, 0x1233FFFF));
    CASE_EXPECT_FALSE(atbus::endpoint::is_child_node(0x12345678, 0x12345678, 16, 0x12350000));

    // 自己是自己的子节点 - 静态接口
    CASE_EXPECT_FALSE(atbus::endpoint::is_child_node(0x12345678, 0x12345678, 16, 0x12345678));
  }

  {
    conf.subnets.clear();
    atbus::node::ptr_t node = atbus::node::create();
    node->init(0x12345678, &conf);
    // 0值判定，无子节点
    CASE_EXPECT_TRUE(node->is_child_node(0x12345678));
    CASE_EXPECT_FALSE(node->is_child_node(0x12345679));
  }
}

CASE_TEST(atbus_endpoint, get_connection) {
  atbus::node::conf_t conf;
  atbus::node::default_conf(&conf);
  conf.subnets.push_back(atbus::endpoint_subnet_conf(0, 16));
  uv_loop_t ev_loop;
  uv_loop_init(&ev_loop);

  conf.ev_loop = &ev_loop;
  conf.recv_buffer_size = 64 * 1024;

  char *buffer = new char[conf.recv_buffer_size];
  memset(buffer, -1, sizeof(conf.recv_buffer_size));  // init it and then valgrind will now report uninitialised used

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

    atbus::connection::ptr_t conn1 = atbus::connection::create(node.get(), addr);

    CASE_EXPECT_EQ(0, conn1->connect());
    atbus::connection::ptr_t conn2 = atbus::connection::create(node.get(), "ipv4://127.0.0.1:80");
    conn2->connect();

    std::vector<atbus::endpoint_subnet_conf> ep_subnets;
    ep_subnets.push_back(atbus::endpoint_subnet_conf(0, 8));

    atbus::endpoint::ptr_t ep =
        atbus::endpoint::create(node.get(), 0x12345679, ep_subnets, node->get_pid(), node->get_hostname());
    CASE_EXPECT_TRUE(ep->add_connection(conn1.get(), false));
    CASE_EXPECT_TRUE(ep->add_connection(conn2.get(), false));

    CASE_EXPECT_EQ(0, node->add_endpoint(ep));

    atbus::connection *conn3 = node->get_self_endpoint()->get_data_connection(ep.get());
    CASE_EXPECT_EQ(conn3, conn1.get());

    // conflict id range
    ep = atbus::endpoint::create(node.get(), 0x12345680, ep_subnets, node->get_pid(), node->get_hostname());
    CASE_EXPECT_EQ(EN_ATBUS_ERR_ATNODE_MASK_CONFLICT, node->add_endpoint(ep));

    ep_subnets.clear();
    ep_subnets.push_back(atbus::endpoint_subnet_conf(0, 24));
    ep = atbus::endpoint::create(node.get(), 0x12355680, ep_subnets, node->get_pid(), node->get_hostname());
    CASE_EXPECT_EQ(0, node->add_endpoint(ep));

    // It can only add one parent endpoint
    ep = atbus::endpoint::create(node.get(), 0x12365680, ep_subnets, node->get_pid(), node->get_hostname());
    CASE_EXPECT_EQ(EN_ATBUS_ERR_ATNODE_INVALID_ID, node->add_endpoint(ep));
  }

  while (UV_EBUSY == uv_loop_close(&ev_loop)) {
    uv_run(&ev_loop, UV_RUN_ONCE);
  }

  delete[] buffer;
}

CASE_TEST(atbus_endpoint, subnet_range) {
  {
    atbus::endpoint_subnet_range subnet;

    CASE_EXPECT_EQ(subnet.get_id_prefix(), 0);
    CASE_EXPECT_EQ(subnet.get_mask_bits(), 0);
    CASE_EXPECT_EQ(subnet.get_id_min(), 0);
    CASE_EXPECT_EQ(subnet.get_id_max(), 0);

    CASE_EXPECT_TRUE(subnet.contain(subnet));
  }

  {
    atbus::endpoint_subnet_range subnet(0x12345678, 8);

    CASE_EXPECT_EQ(subnet.get_id_prefix(), 0x12345678);
    CASE_EXPECT_EQ(subnet.get_mask_bits(), 8);
    CASE_EXPECT_EQ(subnet.get_id_min(), 0x12345600);
    CASE_EXPECT_EQ(subnet.get_id_max(), 0x123456ff);

    CASE_EXPECT_TRUE(subnet.contain(subnet));
    CASE_EXPECT_TRUE(subnet.contain(0x12345600));
    CASE_EXPECT_TRUE(subnet.contain(0x123456ff));
    CASE_EXPECT_TRUE(subnet.contain(0x12345678));
    CASE_EXPECT_FALSE(subnet.contain(0x12345700));
    CASE_EXPECT_FALSE(subnet.contain(0x123455ff));
  }

  {
    atbus::endpoint_subnet_range subnet(0x12345678, 0);

    CASE_EXPECT_EQ(subnet.get_id_prefix(), 0x12345678);
    CASE_EXPECT_EQ(subnet.get_mask_bits(), 0);
    CASE_EXPECT_EQ(subnet.get_id_min(), 0x12345678);
    CASE_EXPECT_EQ(subnet.get_id_max(), 0x12345678);

    CASE_EXPECT_FALSE(subnet.contain(0x12345600));
    CASE_EXPECT_FALSE(subnet.contain(0x123456ff));
    CASE_EXPECT_TRUE(subnet.contain(0x12345678));
    CASE_EXPECT_FALSE(subnet.contain(0x12345679));
    CASE_EXPECT_FALSE(subnet.contain(0x12345677));
  }

  {
    atbus::endpoint_subnet_range l(0x12345678, 8);
    atbus::endpoint_subnet_range r(0x12345789, 8);
    CASE_EXPECT_TRUE(l < r);
    CASE_EXPECT_TRUE(l <= r);
    CASE_EXPECT_FALSE(l > r);
    CASE_EXPECT_FALSE(l >= r);
    CASE_EXPECT_FALSE(l == r);
    CASE_EXPECT_TRUE(l != r);
  }

  {
    atbus::endpoint_subnet_range l(0x12345678, 8);
    atbus::endpoint_subnet_range r(0x12345789, 16);
    CASE_EXPECT_TRUE(l < r);
    CASE_EXPECT_TRUE(l <= r);
    CASE_EXPECT_FALSE(l > r);
    CASE_EXPECT_FALSE(l >= r);
    CASE_EXPECT_FALSE(l == r);
    CASE_EXPECT_TRUE(l != r);
  }

  {
    atbus::endpoint_subnet_range l(0x1234ffff, 8);
    atbus::endpoint_subnet_range r(0x12345789, 16);
    CASE_EXPECT_TRUE(l < r);
    CASE_EXPECT_TRUE(l <= r);
    CASE_EXPECT_FALSE(l > r);
    CASE_EXPECT_FALSE(l >= r);
    CASE_EXPECT_FALSE(l == r);
    CASE_EXPECT_TRUE(l != r);
  }

  {
    atbus::endpoint_subnet_range l(0x1234ffff, 16);
    atbus::endpoint_subnet_range r(0x12340000, 16);
    CASE_EXPECT_FALSE(l < r);
    CASE_EXPECT_TRUE(l <= r);
    CASE_EXPECT_FALSE(l > r);
    CASE_EXPECT_TRUE(l >= r);
    CASE_EXPECT_TRUE(l == r);
    CASE_EXPECT_FALSE(l != r);
  }
}

CASE_TEST(atbus_endpoint, merge_subnets) {
  {
    std::vector<atbus::endpoint_subnet_range> subnets;
    subnets.push_back(atbus::endpoint_subnet_range(0x12345678, 8));
    subnets.push_back(atbus::endpoint_subnet_range(0x12345670, 0));

    atbus::endpoint::merge_subnets(subnets);
    CASE_EXPECT_EQ(1, subnets.size());

    CASE_EXPECT_EQ(subnets[0].get_mask_bits(), 8);
    CASE_EXPECT_EQ(subnets[0].get_id_min(), 0x12345600);
    CASE_EXPECT_EQ(subnets[0].get_id_max(), 0x123456ff);
  }

  {
    std::vector<atbus::endpoint_subnet_range> subnets;
    subnets.push_back(atbus::endpoint_subnet_range(0x12345678, 8));
    subnets.push_back(atbus::endpoint_subnet_range(0x12345789, 8));

    atbus::endpoint::merge_subnets(subnets);
    CASE_EXPECT_EQ(1, subnets.size());

    CASE_EXPECT_EQ(subnets[0].get_mask_bits(), 9);
    CASE_EXPECT_EQ(subnets[0].get_id_min(), 0x12345600);
    CASE_EXPECT_EQ(subnets[0].get_id_max(), 0x123457ff);
  }

  {
    std::vector<atbus::endpoint_subnet_range> subnets;
    subnets.push_back(atbus::endpoint_subnet_range(0x12345678, 8));
    subnets.push_back(atbus::endpoint_subnet_range(0x12356789, 8));

    atbus::endpoint::merge_subnets(subnets);
    CASE_EXPECT_EQ(2, subnets.size());

    CASE_EXPECT_EQ(subnets[0].get_id_prefix(), 0x12345678);
    CASE_EXPECT_EQ(subnets[0].get_mask_bits(), 8);
    CASE_EXPECT_EQ(subnets[0].get_id_min(), 0x12345600);
    CASE_EXPECT_EQ(subnets[0].get_id_max(), 0x123456ff);

    CASE_EXPECT_EQ(subnets[1].get_id_prefix(), 0x12356789);
    CASE_EXPECT_EQ(subnets[1].get_mask_bits(), 8);
    CASE_EXPECT_EQ(subnets[1].get_id_min(), 0x12356700);
    CASE_EXPECT_EQ(subnets[1].get_id_max(), 0x123567ff);
  }

  {
    std::vector<atbus::endpoint_subnet_range> subnets;
    subnets.push_back(atbus::endpoint_subnet_range(0x12345709, 7));
    subnets.push_back(atbus::endpoint_subnet_range(0x12345678, 8));
    subnets.push_back(atbus::endpoint_subnet_range(0x12356789, 16));
    subnets.push_back(atbus::endpoint_subnet_range(0x12345789, 7));
    subnets.push_back(atbus::endpoint_subnet_range(0x12356900, 8));
    subnets.push_back(atbus::endpoint_subnet_range(0x12396789, 16));

    atbus::endpoint::merge_subnets(subnets);
    CASE_EXPECT_EQ(3, subnets.size());

    CASE_EXPECT_EQ(subnets[0].get_mask_bits(), 9);
    CASE_EXPECT_EQ(subnets[0].get_id_min(), 0x12345600);
    CASE_EXPECT_EQ(subnets[0].get_id_max(), 0x123457ff);

    CASE_EXPECT_EQ(subnets[1].get_mask_bits(), 16);
    CASE_EXPECT_EQ(subnets[1].get_id_min(), 0x12350000);
    CASE_EXPECT_EQ(subnets[1].get_id_max(), 0x1235ffff);

    CASE_EXPECT_EQ(subnets[2].get_id_prefix(), 0x12396789);
    CASE_EXPECT_EQ(subnets[2].get_mask_bits(), 16);
    CASE_EXPECT_EQ(subnets[2].get_id_min(), 0x12390000);
    CASE_EXPECT_EQ(subnets[2].get_id_max(), 0x1239ffff);
  }
}

CASE_TEST(atbus_endpoint, subnet_range_contain) {
  std::vector<atbus::endpoint_subnet_range> subnets;

  subnets.push_back(atbus::endpoint_subnet_range(0x12345678, 16));  // 0x12340000-0x1234ffff
  subnets.push_back(atbus::endpoint_subnet_range(0x12356789, 8));   // 0x12356700-0x123567ff

  CASE_EXPECT_TRUE(atbus::endpoint::contain(subnets, 0x12340000));
  CASE_EXPECT_TRUE(atbus::endpoint::contain(subnets, 0x1234ffff));
  CASE_EXPECT_FALSE(atbus::endpoint::contain(subnets, 0x1233ffff));
  CASE_EXPECT_FALSE(atbus::endpoint::contain(subnets, 0x12350000));
  CASE_EXPECT_TRUE(atbus::endpoint::contain(subnets, 0x12356700));
  CASE_EXPECT_TRUE(atbus::endpoint::contain(subnets, 0x123567ff));
  CASE_EXPECT_FALSE(atbus::endpoint::contain(subnets, 0x123566ff));
  CASE_EXPECT_FALSE(atbus::endpoint::contain(subnets, 0x12356800));
  CASE_EXPECT_FALSE(atbus::endpoint::contain(subnets, 0));

  {
    std::vector<atbus::endpoint_subnet_range> child_subnets;
    child_subnets.push_back(atbus::endpoint_subnet_range(0x12345678, 16));
    child_subnets.push_back(atbus::endpoint_subnet_range(0x12356789, 8));

    CASE_EXPECT_TRUE(atbus::endpoint::contain(subnets, child_subnets));
  }

  {
    std::vector<atbus::endpoint_subnet_range> child_subnets;
    child_subnets.push_back(atbus::endpoint_subnet_range(0x12345678, 8));
    child_subnets.push_back(atbus::endpoint_subnet_range(0x12356789, 8));

    CASE_EXPECT_TRUE(atbus::endpoint::contain(subnets, child_subnets));
    CASE_EXPECT_FALSE(atbus::endpoint::contain(child_subnets, subnets));
  }

  {
    std::vector<atbus::endpoint_subnet_range> child_subnets;
    child_subnets.push_back(atbus::endpoint_subnet_range(0x12345678, 8));
    child_subnets.push_back(atbus::endpoint_subnet_range(0x12356789, 16));

    CASE_EXPECT_FALSE(atbus::endpoint::contain(subnets, child_subnets));
    CASE_EXPECT_FALSE(atbus::endpoint::contain(child_subnets, subnets));
  }

  {
    std::vector<atbus::endpoint_subnet_conf> child_subnets;
    child_subnets.push_back(atbus::endpoint_subnet_conf(0x12345678, 16));
    child_subnets.push_back(atbus::endpoint_subnet_conf(0x12356789, 8));

    CASE_EXPECT_TRUE(atbus::endpoint::contain(subnets, child_subnets));
  }

  {
    std::vector<atbus::endpoint_subnet_conf> child_subnets;
    child_subnets.push_back(atbus::endpoint_subnet_conf(0x12345678, 8));
    child_subnets.push_back(atbus::endpoint_subnet_conf(0x12356789, 8));

    CASE_EXPECT_TRUE(atbus::endpoint::contain(subnets, child_subnets));
  }

  {
    std::vector<atbus::endpoint_subnet_conf> child_subnets;
    child_subnets.push_back(atbus::endpoint_subnet_conf(0x12345678, 16));
    child_subnets.push_back(atbus::endpoint_subnet_conf(0x12356789, 16));

    CASE_EXPECT_FALSE(atbus::endpoint::contain(subnets, child_subnets));
  }

  {
    std::vector<atbus::endpoint_subnet_conf> child_subnets;
    child_subnets.push_back(atbus::endpoint_subnet_conf(0x12345678, 8));
    child_subnets.push_back(atbus::endpoint_subnet_conf(0x12356789, 16));

    CASE_EXPECT_FALSE(atbus::endpoint::contain(subnets, child_subnets));
  }

  std::vector<atbus::endpoint_subnet_conf> subnets_conf;

  subnets_conf.push_back(atbus::endpoint_subnet_conf(0x12345678, 16));  // 0x12340000-0x1234ffff
  subnets_conf.push_back(atbus::endpoint_subnet_conf(0x12356789, 8));   // 0x12356700-0x123567ff

  CASE_EXPECT_TRUE(atbus::endpoint::contain(subnets_conf, 0x12340000));
  CASE_EXPECT_TRUE(atbus::endpoint::contain(subnets_conf, 0x1234ffff));
  CASE_EXPECT_FALSE(atbus::endpoint::contain(subnets_conf, 0x1233ffff));
  CASE_EXPECT_FALSE(atbus::endpoint::contain(subnets_conf, 0x12350000));
  CASE_EXPECT_TRUE(atbus::endpoint::contain(subnets_conf, 0x12356700));
  CASE_EXPECT_TRUE(atbus::endpoint::contain(subnets_conf, 0x123567ff));
  CASE_EXPECT_FALSE(atbus::endpoint::contain(subnets_conf, 0x123566ff));
  CASE_EXPECT_FALSE(atbus::endpoint::contain(subnets_conf, 0x12356800));
  CASE_EXPECT_FALSE(atbus::endpoint::contain(subnets_conf, 0));

  {
    std::vector<atbus::endpoint_subnet_range> subnets_empty;
    std::vector<atbus::endpoint_subnet_conf> subnets_conf_empty;
    CASE_EXPECT_TRUE(atbus::endpoint::contain(subnets_empty, subnets_empty));
    CASE_EXPECT_FALSE(atbus::endpoint::contain(subnets_empty, subnets));
    CASE_EXPECT_TRUE(atbus::endpoint::contain(subnets_empty, subnets_conf_empty));
    CASE_EXPECT_FALSE(atbus::endpoint::contain(subnets_empty, subnets_conf));
    CASE_EXPECT_FALSE(atbus::endpoint::contain(subnets_empty, 0));
    CASE_EXPECT_FALSE(atbus::endpoint::contain(subnets_conf_empty, 0));
  }
}

CASE_TEST(atbus_endpoint, search_subnet_for_id) {
  {
    std::vector<atbus::endpoint_subnet_range> subnets;

    subnets.push_back(atbus::endpoint_subnet_range(0x12345678, 16));  // 0x12340000-0x1234ffff
    subnets.push_back(atbus::endpoint_subnet_range(0x12356789, 8));   // 0x12356700-0x123567ff

    {
      std::vector<atbus::endpoint_subnet_range>::const_iterator iter1 =
          atbus::endpoint::search_subnet_for_id(subnets, 0x12356700);
      std::vector<atbus::endpoint_subnet_range>::const_iterator iter2 =
          atbus::endpoint::search_subnet_for_id(subnets, 0x123567ff);
      std::vector<atbus::endpoint_subnet_range>::const_iterator iter3 =
          atbus::endpoint::search_subnet_for_id(subnets, 0x12350000);
      std::vector<atbus::endpoint_subnet_range>::const_iterator iter4 =
          atbus::endpoint::search_subnet_for_id(subnets, 0x123566ff);
      std::vector<atbus::endpoint_subnet_range>::const_iterator iter5 =
          atbus::endpoint::search_subnet_for_id(subnets, 0x1234ffff);
      std::vector<atbus::endpoint_subnet_range>::const_iterator iter6 =
          atbus::endpoint::search_subnet_for_id(subnets, 0x12340000);
      std::vector<atbus::endpoint_subnet_range>::const_iterator iter7 =
          atbus::endpoint::search_subnet_for_id(subnets, 0x1233ffff);

      CASE_EXPECT_TRUE(iter1 == iter2);
      CASE_EXPECT_TRUE(subnets.end() == iter3);
      CASE_EXPECT_TRUE(subnets.end() == iter4);
      CASE_EXPECT_TRUE(iter1 != subnets.end());
      CASE_EXPECT_TRUE(iter1 != iter5);
      CASE_EXPECT_TRUE(iter5 != subnets.end());
      CASE_EXPECT_TRUE(iter5 == iter6);
      CASE_EXPECT_TRUE(subnets.end() == iter7);
    }

    {
      std::vector<atbus::endpoint_subnet_range>::const_iterator iter =
          atbus::endpoint::search_subnet_for_id(subnets, 0x12356800);
      CASE_EXPECT_TRUE(iter == subnets.end());
    }

    {
      std::vector<atbus::endpoint_subnet_range>::const_iterator iter =
          atbus::endpoint::search_subnet_for_id(subnets, 0);
      CASE_EXPECT_TRUE(iter == subnets.end());
    }
  }

  {
    std::vector<atbus::endpoint_subnet_range> subnets;

    subnets.push_back(atbus::endpoint_subnet_range(0x12340000, 8));   // 0x12340000-0x123400ff
    subnets.push_back(atbus::endpoint_subnet_range(0x12345678, 8));   // 0x12345600-0x123456ff
    subnets.push_back(atbus::endpoint_subnet_range(0x1234ff78, 8));   // 0x1234ff00-0x1234ffff
    subnets.push_back(atbus::endpoint_subnet_range(0x12345679, 16));  // 0x12340000-0x1234ffff

    std::vector<atbus::endpoint_subnet_range>::const_iterator iter1 =
        atbus::endpoint::search_subnet_for_id(subnets, 0x1233ffff);
    std::vector<atbus::endpoint_subnet_range>::const_iterator iter2 =
        atbus::endpoint::search_subnet_for_id(subnets, 0x12340035);
    std::vector<atbus::endpoint_subnet_range>::const_iterator iter3 =
        atbus::endpoint::search_subnet_for_id(subnets, 0x12340100);
    std::vector<atbus::endpoint_subnet_range>::const_iterator iter4 =
        atbus::endpoint::search_subnet_for_id(subnets, 0x12345678);
    std::vector<atbus::endpoint_subnet_range>::const_iterator iter5 =
        atbus::endpoint::search_subnet_for_id(subnets, 0x12347890);
    std::vector<atbus::endpoint_subnet_range>::const_iterator iter6 =
        atbus::endpoint::search_subnet_for_id(subnets, 0x1234ff79);
    std::vector<atbus::endpoint_subnet_range>::const_iterator iter7 =
        atbus::endpoint::search_subnet_for_id(subnets, 0x1234ffff);

    CASE_EXPECT_TRUE(iter1 == subnets.end());
    CASE_EXPECT_TRUE(iter2 != subnets.end());
    CASE_EXPECT_EQ((*iter2).get_id_prefix(), 0x12340000);
    CASE_EXPECT_EQ((*iter2).get_mask_bits(), 8);
    CASE_EXPECT_TRUE(iter3 != subnets.end());
    CASE_EXPECT_EQ((*iter3).get_id_prefix(), 0x12345679);
    CASE_EXPECT_EQ((*iter3).get_mask_bits(), 16);
    CASE_EXPECT_TRUE(iter4 != subnets.end());
    CASE_EXPECT_EQ((*iter4).get_id_prefix(), 0x12345678);
    CASE_EXPECT_EQ((*iter4).get_mask_bits(), 8);
    CASE_EXPECT_TRUE(iter5 != subnets.end());
    CASE_EXPECT_EQ((*iter5).get_id_prefix(), 0x12345679);
    CASE_EXPECT_EQ((*iter5).get_mask_bits(), 16);
    CASE_EXPECT_TRUE(iter6 != subnets.end());
    CASE_EXPECT_EQ((*iter6).get_id_prefix(), 0x1234ff78);
    CASE_EXPECT_EQ((*iter6).get_mask_bits(), 8);
    CASE_EXPECT_TRUE(iter6 == iter7);
  }
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
