#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <numeric>

#include <common/string_oprs.h>

#include <atbus_endpoint.h>
#include <atbus_node.h>
#include <detail/libatbus_error.h>

#include "frame/test_macros.h"

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

    conf.ev_loop          = &ev_loop;
    conf.recv_buffer_size = 64 * 1024;

    char *buffer = new char[conf.recv_buffer_size];
    memset(buffer, -1, sizeof(conf.recv_buffer_size)); // init it and then valgrind will now report uninitialised used

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

        atbus::connection::ptr_t conn1 = atbus::connection::create(node.get());

        CASE_EXPECT_EQ(0, conn1->connect(addr));
        atbus::connection::ptr_t conn2 = atbus::connection::create(node.get());
        conn2->connect("ipv4://127.0.0.1:80");

        std::vector<atbus::endpoint_subnet_conf> ep_subnets;
        ep_subnets.push_back(atbus::endpoint_subnet_conf(0, 8));

        atbus::endpoint::ptr_t ep = atbus::endpoint::create(node.get(), 0x12345679, ep_subnets, node->get_pid(), node->get_hostname());
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
