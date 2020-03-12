#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>

#include "common/string_oprs.h"

#ifdef max
#undef max
#endif

#ifdef min
#undef min
#endif

#include <atbus_node.h>
#include <libatbus_protocol.h>

#include "frame/test_macros.h"

#include "atbus_test_utils.h"

#include <stdarg.h>

static void node_msg_test_on_debug(const char *file_path, size_t line, const atbus::node &n, const atbus::endpoint *ep,
                                   const atbus::connection *conn, const atbus::protocol::msg *, const char *fmt, ...) {
    size_t offset = 0;
    for (size_t i = 0; file_path[i]; ++i) {
        if ('/' == file_path[i] || '\\' == file_path[i]) {
            offset = i + 1;
        }
    }
    file_path += offset;

    std::streamsize w = std::cout.width();
    CASE_MSG_INFO() << "[Log Debug][" << std::setw(24) << file_path << ":" << std::setw(4) << line << "] node=0x" << std::setfill('0')
                    << std::hex << std::setw(8) << n.get_id() << ", ep=0x" << std::setw(8) << (NULL == ep ? 0 : ep->get_id())
                    << ", c=" << conn << std::setfill(' ') << std::setw(w) << std::dec << "\t";

    va_list ap;
    va_start(ap, fmt);

    vprintf(fmt, ap);

    va_end(ap);

    puts("");
}

static int node_msg_test_on_error(const atbus::node &n, const atbus::endpoint *ep, const atbus::connection *conn, int status, int errcode) {
    if (0 == errcode || UV_EOF == errcode || UV_ECONNRESET == errcode) {
        return 0;
    }

    std::streamsize w = std::cout.width();
    CASE_MSG_INFO() << "[Log Error] node=0x" << std::setfill('0') << std::hex << std::setw(8) << n.get_id() << ", ep=0x" << std::setw(8)
                    << (NULL == ep ? 0 : ep->get_id()) << ", c=" << conn << std::setfill(' ') << std::setw(w) << std::dec
                    << "=> status: " << status << ", errcode: " << errcode << std::endl;
    return 0;
}

struct node_msg_test_recv_msg_record_t {
    const atbus::node *n;
    const atbus::endpoint *ep;
    const atbus::connection *conn;
    std::string data;
    int status;
    int count;
    int failed_count;
    int remove_endpoint_count;
    std::vector<ATBUS_MACRO_BUSID_TYPE> last_msg_router;
    uint64_t last_cmd_seq;
    uint64_t expect_cmd_req_from;
    uint64_t expect_cmd_rsp_from;

    node_msg_test_recv_msg_record_t()
        : n(NULL), ep(NULL), conn(NULL), status(0), count(0), failed_count(0), remove_endpoint_count(0), last_cmd_seq(0),
          expect_cmd_req_from(0), expect_cmd_rsp_from(0) {}
};

static node_msg_test_recv_msg_record_t recv_msg_history;

static int node_msg_test_recv_msg_test_record_fn(const atbus::node &n, const atbus::endpoint *ep, const atbus::connection *conn,
                                                 const atbus::protocol::msg &m, const void *buffer, size_t len) {
    recv_msg_history.n      = &n;
    recv_msg_history.ep     = ep;
    recv_msg_history.conn   = conn;
    recv_msg_history.status = m.head().ret();
    ++recv_msg_history.count;

    const ::atbus::protocol::forward_data *fwd_data = NULL;
    if (m.msg_body_case() == ::atbus::protocol::msg::kDataTransformReq) {
        fwd_data = &m.data_transform_req();
    } else if (m.msg_body_case() == ::atbus::protocol::msg::kDataTransformRsp) {
        fwd_data = &m.data_transform_rsp();
    }

    if (NULL != fwd_data) {
        recv_msg_history.last_msg_router.assign(fwd_data->router().begin(), fwd_data->router().end());
    } else {
        recv_msg_history.last_msg_router.clear();
    }

    std::streamsize w = std::cout.width();
    if (NULL != buffer && len > 0) {
        recv_msg_history.data.assign(reinterpret_cast<const char *>(buffer), len);
        CASE_MSG_INFO() << "[Log Debug] node=0x" << std::setfill('0') << std::hex << std::setw(8) << n.get_id() << ", ep=0x" << std::setw(8)
                        << (NULL == ep ? 0 : ep->get_id()) << ", c=" << conn << std::setfill(' ') << std::setw(w) << std::dec << "\t"
                        << "recv message: ";
        std::cout.write(reinterpret_cast<const char *>(buffer), len);
        std::cout << std::endl;
    } else {
        recv_msg_history.data.clear();
        CASE_MSG_INFO() << "[Log Debug] node=0x" << std::setfill('0') << std::hex << std::setw(8) << n.get_id() << ", ep=0x" << std::setw(8)
                        << (NULL == ep ? 0 : ep->get_id()) << ", c=" << conn << std::setfill(' ') << std::setw(w) << std::dec << "\t"
                        << "recv message: [NOTHING]" << std::endl;
    }

    return 0;
}

static int node_msg_test_send_data_forward_response_fn(const atbus::node &n, const atbus::endpoint *ep, const atbus::connection *conn,
                                             const atbus::protocol::msg *m) {
    recv_msg_history.n      = &n;
    recv_msg_history.ep     = ep;
    recv_msg_history.conn   = conn;
    recv_msg_history.status = NULL == m ? 0 : m->head().ret();
    ++recv_msg_history.failed_count;

    const ::atbus::protocol::forward_data *fwd_data = NULL;
    if (NULL != m) {
        if (m->msg_body_case() == ::atbus::protocol::msg::kDataTransformReq) {
            fwd_data = &m->data_transform_req();
        } else if (m->msg_body_case() == ::atbus::protocol::msg::kDataTransformRsp) {
            fwd_data = &m->data_transform_rsp();
        }
    }

    if (NULL != fwd_data) {
        recv_msg_history.last_msg_router.assign(fwd_data->router().begin(), fwd_data->router().end());
    } else {
        recv_msg_history.last_msg_router.clear();
    }

    if (NULL != m && NULL != fwd_data && fwd_data->content().size() > 0) {
        recv_msg_history.data.assign(fwd_data->content().data(), fwd_data->content().size());
    } else {
        recv_msg_history.data.clear();
    }

    return 0;
}

static int node_msg_test_remove_endpoint_fn(const atbus::node &, atbus::endpoint *, int) {
    ++recv_msg_history.remove_endpoint_count;
    return 0;
}

// 定时Ping Pong协议测试
CASE_TEST(atbus_node_msg, ping_pong) {
    atbus::node::conf_t conf;
    atbus::node::default_conf(&conf);
    conf.subnets.push_back(atbus::endpoint_subnet_conf(0, 16));
    uv_loop_t ev_loop;
    uv_loop_init(&ev_loop);

    conf.ev_loop = &ev_loop;

    {
        atbus::node::ptr_t node1 = atbus::node::create();
        atbus::node::ptr_t node2 = atbus::node::create();
        node1->on_debug          = node_msg_test_on_debug;
        node2->on_debug          = node_msg_test_on_debug;
        node1->set_on_error_handle(node_msg_test_on_error);
        node2->set_on_error_handle(node_msg_test_on_error);

        CASE_EXPECT_EQ(NULL, node1->get_self_endpoint());
        CASE_EXPECT_EQ(NULL, node2->get_self_endpoint());

        node1->init(0x12345678, &conf);
        node2->init(0x12356789, &conf);

        CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node1->listen("ipv4://127.0.0.1:16387"));
        CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node2->listen("ipv4://127.0.0.1:16388"));

        CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node1->start());
        CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node2->start());

        time_t proc_t = time(NULL) + 1;
        node1->poll();
        node2->poll();
        node1->proc(proc_t, 0);
        node2->proc(proc_t, 0);

        node1->connect("ipv4://127.0.0.1:16388");

        // 8s timeout
        UNITTEST_WAIT_UNTIL(conf.ev_loop, node1->is_endpoint_available(node2->get_id()) && node2->is_endpoint_available(node1->get_id()),
                            8000, 0) {}

        proc_t += conf.ping_interval;

        UNITTEST_WAIT_UNTIL(conf.ev_loop,
                            !node1->is_endpoint_available(node2->get_id()) || !node2->is_endpoint_available(node1->get_id()) ||
                                (node2->get_endpoint(node1->get_id())->get_stat_last_pong() > 0 &&
                                 node1->get_endpoint(node2->get_id())->get_stat_last_pong() > 0),
                            8000, 32) {
            ++proc_t;
            node1->proc(proc_t, 0);
            node2->proc(proc_t, 0);
        }
    }

    unit_test_setup_exit(&ev_loop);
}

static int node_msg_test_recv_msg_test_custom_cmd_fn(const atbus::node &, const atbus::endpoint *, const atbus::connection *,
                                                     atbus::node::bus_id_t from, const std::vector<std::pair<const void *, size_t> > &data,
                                                     std::list<std::string> &rsp) {
    ++recv_msg_history.count;

    recv_msg_history.data.clear();
    for (size_t i = 0; i < data.size(); ++i) {
        recv_msg_history.data.append(static_cast<const char *>(data[i].first), data[i].second);
        recv_msg_history.data += '\0';
        rsp.push_back(std::string(static_cast<const char *>(data[i].first), data[i].second));
    }

    rsp.push_back("run custom cmd done");

    CASE_EXPECT_EQ(from, recv_msg_history.expect_cmd_req_from);
    return 0;
}

static int node_msg_test_recv_msg_test_custom_rsp_fn(const atbus::node &, const atbus::endpoint *, const atbus::connection *,
                                                     atbus::node::bus_id_t from, const std::vector<std::pair<const void *, size_t> > &data,
                                                     uint64_t seq) {
    ++recv_msg_history.count;

    for (size_t i = 0; i < data.size(); ++i) {
        std::string text(static_cast<const char *>(data[i].first), data[i].second);
        CASE_MSG_INFO() << "Custom Rsp(" << seq << "): " << text << std::endl;
    }

    CASE_EXPECT_EQ(seq, recv_msg_history.last_cmd_seq);
    CASE_EXPECT_EQ(from, recv_msg_history.expect_cmd_rsp_from);
    CASE_EXPECT_GT(data.size(), 1);
    if (data.size() > 1) {
        CASE_EXPECT_EQ(0, UTIL_STRFUNC_STRNCMP("run custom cmd done", static_cast<const char *>(data.back().first), data.back().second));
    }

    return 0;
}

// 自定义命令协议测试
CASE_TEST(atbus_node_msg, custom_cmd) {
    atbus::node::conf_t conf;
    atbus::node::default_conf(&conf);
    conf.subnets.push_back(atbus::endpoint_subnet_conf(0, 16));
    uv_loop_t ev_loop;
    uv_loop_init(&ev_loop);

    conf.ev_loop = &ev_loop;

    do {
        atbus::node::ptr_t node1 = atbus::node::create();
        atbus::node::ptr_t node2 = atbus::node::create();
        node1->on_debug          = node_msg_test_on_debug;
        node2->on_debug          = node_msg_test_on_debug;
        node1->set_on_error_handle(node_msg_test_on_error);
        node2->set_on_error_handle(node_msg_test_on_error);

        node1->init(0x12345678, &conf);
        node2->init(0x12356789, &conf);

        CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node1->listen("ipv4://127.0.0.1:16387"));
        CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node2->listen("ipv4://127.0.0.1:16388"));

        CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node1->start());
        CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node2->start());

        time_t proc_t = time(NULL) + 1;
        node1->poll();
        node2->poll();
        node1->proc(proc_t, 0);
        node2->proc(proc_t, 0);

        node1->connect("ipv4://127.0.0.1:16388");

        UNITTEST_WAIT_UNTIL(conf.ev_loop, node1->is_endpoint_available(node2->get_id()) && node2->is_endpoint_available(node1->get_id()),
                            8000, 0) {}

        int count = recv_msg_history.count;
        node2->set_on_custom_cmd_handle(node_msg_test_recv_msg_test_custom_cmd_fn);
        node1->set_on_custom_rsp_handle(node_msg_test_recv_msg_test_custom_rsp_fn);

        char test_str[]       = "hello world!";
        std::string send_data = test_str;
        const void *custom_data[3];
        custom_data[0]      = &test_str[0];
        custom_data[1]      = &test_str[6];
        custom_data[2]      = &test_str[11];
        size_t custom_len[] = {5, 5, 1};

        send_data[5]  = '\0';
        send_data[11] = '\0';
        send_data += '!';
        send_data += '\0';

        recv_msg_history.last_cmd_seq        = 0;
        recv_msg_history.expect_cmd_req_from = node1->get_id();
        recv_msg_history.expect_cmd_rsp_from = node2->get_id();
        CASE_EXPECT_EQ(0, node1->send_custom_cmd(node2->get_id(), custom_data, custom_len, 3, &recv_msg_history.last_cmd_seq));

        UNITTEST_WAIT_UNTIL(conf.ev_loop, count + 1 < recv_msg_history.count, 3000, 0) {}

        CASE_EXPECT_EQ(send_data, recv_msg_history.data);
    } while (false);

    unit_test_setup_exit(&ev_loop);
}

// 发给自己的命令
CASE_TEST(atbus_node_msg, send_cmd_to_self) {
    atbus::node::conf_t conf;
    atbus::node::default_conf(&conf);
    conf.subnets.push_back(atbus::endpoint_subnet_conf(0, 16));
    uv_loop_t ev_loop;
    uv_loop_init(&ev_loop);

    conf.ev_loop = &ev_loop;

    {
        char cmds[][8]        = {"self", "command", "yep"};
        size_t cmds_len[]     = {strlen(cmds[0]), strlen(cmds[1]), strlen(cmds[2])};
        const void *cmds_in[] = {cmds[0], cmds[1], cmds[2]};

        atbus::node::ptr_t node1 = atbus::node::create();
        node1->on_debug          = node_msg_test_on_debug;
        node1->set_on_error_handle(node_msg_test_on_error);

        CASE_EXPECT_EQ(EN_ATBUS_ERR_NOT_INITED, node1->send_custom_cmd(node1->get_id(), cmds_in, cmds_len, 3));

        node1->init(0x12345678, &conf);

        CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node1->listen("ipv4://127.0.0.1:16387"));

        CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node1->start());

        time_t proc_tm = time(NULL) + 1;
        node1->poll();
        node1->proc(proc_tm, 0);

        int count = recv_msg_history.count;
        node1->set_on_custom_cmd_handle(node_msg_test_recv_msg_test_custom_cmd_fn);
        node1->set_on_custom_rsp_handle(node_msg_test_recv_msg_test_custom_rsp_fn);
        CASE_EXPECT_TRUE(!!node1->get_on_custom_cmd_handle());

        recv_msg_history.last_cmd_seq        = 0;
        recv_msg_history.expect_cmd_req_from = node1->get_id();
        recv_msg_history.expect_cmd_rsp_from = node1->get_id();
        recv_msg_history.data.clear();
        node1->send_custom_cmd(node1->get_id(), cmds_in, cmds_len, 3, &recv_msg_history.last_cmd_seq);

        CASE_EXPECT_EQ(count + 2, recv_msg_history.count);
        CASE_EXPECT_EQ(cmds_len[0] + cmds_len[1] + cmds_len[2] + 3, recv_msg_history.data.size());
        size_t start_index = 0;
        for (int i = 0; i < 3; ++i) {
            std::string l, r;
            l.assign(cmds[i], cmds_len[i]);
            r.assign(recv_msg_history.data.c_str() + start_index, cmds_len[i]);
            CASE_EXPECT_EQ(l, r);
            start_index += cmds_len[i] + 1;
        }
    }

    unit_test_setup_exit(&ev_loop);
}


// 发给自己,直接回调
CASE_TEST(atbus_node_msg, reset_and_send) {
    atbus::node::conf_t conf;
    atbus::node::default_conf(&conf);
    conf.subnets.push_back(atbus::endpoint_subnet_conf(0, 16));
    uv_loop_t ev_loop;
    uv_loop_init(&ev_loop);

    conf.ev_loop = &ev_loop;

    {
        atbus::node::ptr_t node1 = atbus::node::create();
        node1->on_debug          = node_msg_test_on_debug;
        node1->set_on_error_handle(node_msg_test_on_error);

        node1->init(0x12345678, &conf);

        CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node1->listen("ipv4://127.0.0.1:16387"));

        CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node1->start());

        time_t proc_t = time(NULL) + 1;
        node1->poll();
        node1->proc(proc_t, 0);

        std::string send_data;
        send_data.assign("self\0hello world!\n", sizeof("self\0hello world!\n") - 1);

        int count = recv_msg_history.count;
        node1->set_on_recv_handle(node_msg_test_recv_msg_test_record_fn);
        node1->send_data(node1->get_id(), 0, send_data.data(), send_data.size());

        CASE_EXPECT_EQ(count + 1, recv_msg_history.count);
        CASE_EXPECT_EQ(send_data, recv_msg_history.data);
    }

    unit_test_setup_exit(&ev_loop);
}

static int node_msg_test_recv_and_send_msg_on_forward_response_fn(const atbus::node &, const atbus::endpoint *, const atbus::connection *,
                                                        const atbus::protocol::msg *) {
    ++recv_msg_history.count;
    return 0;
}

static int node_msg_test_recv_and_send_msg_fn(const atbus::node &n, const atbus::endpoint *ep, const atbus::connection *conn,
                                              const atbus::protocol::msg &m, const void *buffer, size_t len) {
    recv_msg_history.n      = &n;
    recv_msg_history.ep     = ep;
    recv_msg_history.conn   = conn;
    recv_msg_history.status = m.head().ret();
    ++recv_msg_history.count;

    std::streamsize w = std::cout.width();
    if (NULL != buffer && len > 0) {
        recv_msg_history.data.assign(reinterpret_cast<const char *>(buffer), len);
        CASE_MSG_INFO() << "[Log Debug] node=0x" << std::setfill('0') << std::hex << std::setw(8) << n.get_id() << ", ep=0x" << std::setw(8)
                        << (NULL == ep ? 0 : ep->get_id()) << ", c=" << conn << std::setfill(' ') << std::setw(w) << std::dec << "\t"
                        << "recv message: ";
        std::cout.write(reinterpret_cast<const char *>(buffer), len);
        std::cout << std::endl;
    } else {
        recv_msg_history.data.clear();
        CASE_MSG_INFO() << "[Log Debug] node=0x" << std::setfill('0') << std::hex << std::setw(8) << n.get_id() << ", ep=0x" << std::setw(8)
                        << (NULL == ep ? 0 : ep->get_id()) << ", c=" << conn << std::setfill(' ') << std::setw(w) << std::dec << "\t"
                        << "recv message: [NOTHING]" << std::endl;
    }

    std::string sended_data;
    sended_data.assign(reinterpret_cast<const char *>(buffer), len);
    sended_data += sended_data;

    atbus::node *np = const_cast<atbus::node *>(&n);
    np->set_on_recv_handle(node_msg_test_recv_msg_test_record_fn);
    np->set_on_forward_response_handle(node_msg_test_recv_and_send_msg_on_forward_response_fn);

    np->send_data(n.get_id(), 0, sended_data.c_str(), sended_data.size(), true);
    return 0;
}

// 发给自己,下一帧回调
CASE_TEST(atbus_node_msg, send_msg_to_self_and_need_rsp) {
    atbus::node::conf_t conf;
    atbus::node::default_conf(&conf);
    conf.subnets.push_back(atbus::endpoint_subnet_conf(0, 16));
    uv_loop_t ev_loop;
    uv_loop_init(&ev_loop);

    conf.ev_loop = &ev_loop;

    {
        atbus::node::ptr_t node1 = atbus::node::create();
        node1->on_debug          = node_msg_test_on_debug;
        node1->set_on_error_handle(node_msg_test_on_error);

        node1->init(0x12345678, &conf);

        CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node1->listen("ipv4://127.0.0.1:16387"));

        CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node1->start());

        time_t proc_t = time(NULL) + 1;
        node1->poll();
        node1->proc(proc_t, 0);

        std::string send_data;
        send_data.assign("self\0hello world!\n", sizeof("self\0hello world!\n") - 1);

        int count = recv_msg_history.count;
        node1->set_on_recv_handle(node_msg_test_recv_and_send_msg_fn);
        node1->send_data(node1->get_id(), 0, send_data.data(), send_data.size());

        CASE_EXPECT_EQ(count + 3, recv_msg_history.count);
        send_data += send_data;
        CASE_EXPECT_EQ(send_data, recv_msg_history.data);
    }

    unit_test_setup_exit(&ev_loop);
}


// 父子节点消息转发测试
CASE_TEST(atbus_node_msg, parent_and_child) {
    atbus::node::conf_t conf;
    atbus::node::default_conf(&conf);
    conf.subnets.push_back(atbus::endpoint_subnet_conf(0, 16));
    uv_loop_t ev_loop;
    uv_loop_init(&ev_loop);

    conf.ev_loop = &ev_loop;

    {
        atbus::node::ptr_t node_parent = atbus::node::create();
        atbus::node::ptr_t node_child  = atbus::node::create();
        node_parent->on_debug          = node_msg_test_on_debug;
        node_child->on_debug           = node_msg_test_on_debug;
        node_parent->set_on_error_handle(node_msg_test_on_error);
        node_child->set_on_error_handle(node_msg_test_on_error);

        node_parent->init(0x12345678, &conf);

        conf.subnets.clear();
        conf.subnets.push_back(atbus::endpoint_subnet_conf(0, 8));
        conf.parent_address = "ipv4://127.0.0.1:16387";
        node_child->init(0x12346789, &conf);

        CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_parent->listen("ipv4://127.0.0.1:16387"));
        CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_child->listen("ipv4://127.0.0.1:16388"));

        CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_parent->start());
        CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_child->start());

        time_t proc_t = time(NULL) + 1;

        UNITTEST_WAIT_UNTIL(conf.ev_loop,
                            node_child->is_endpoint_available(node_parent->get_id()) &&
                                node_parent->is_endpoint_available(node_child->get_id()),
                            8000, 64) {
            node_parent->proc(proc_t, 0);
            node_child->proc(proc_t, 0);
            ++proc_t;
        }

        // 顺便启动父子节点的ping
        proc_t += conf.ping_interval + 1;
        node_parent->proc(proc_t, 0);
        node_child->proc(proc_t, 0);

        node_child->set_on_recv_handle(node_msg_test_recv_msg_test_record_fn);
        node_parent->set_on_recv_handle(node_msg_test_recv_msg_test_record_fn);

        int count = recv_msg_history.count;

        // 发消息啦 -  parent to child
        {
            std::string send_data;
            send_data.assign("parent to child\0hello world!\n", sizeof("parent to child\0hello world!\n") - 1);

            node_parent->send_data(node_child->get_id(), 0, send_data.data(), send_data.size());
            UNITTEST_WAIT_UNTIL(conf.ev_loop, count != recv_msg_history.count, 3000, 0) {}

            CASE_EXPECT_EQ(send_data, recv_msg_history.data);
        }

        // 发消息啦 - child to parent
        {
            std::string send_data;
            send_data.assign("child to parent\0hello world!\n", sizeof("child to parent\0hello world!\n") - 1);

            count = recv_msg_history.count;
            node_child->send_data(node_parent->get_id(), 0, send_data.data(), send_data.size());
            UNITTEST_WAIT_UNTIL(conf.ev_loop, count != recv_msg_history.count, 3000, 0) {}

            CASE_EXPECT_EQ(send_data, recv_msg_history.data);
        }

        CASE_EXPECT_GT(node_child->get_endpoint(node_parent->get_id())->get_stat_last_pong(), 0);
        CASE_EXPECT_GT(node_parent->get_endpoint(node_child->get_id())->get_stat_last_pong(), 0);
    }

    unit_test_setup_exit(&ev_loop);
}

// 兄弟节点通过父节点转发消息并建立直连测试（测试路由）
CASE_TEST(atbus_node_msg, transfer_and_connect) {
    atbus::node::conf_t conf;
    atbus::node::default_conf(&conf);
    conf.subnets.push_back(atbus::endpoint_subnet_conf(0, 16));
    uv_loop_t ev_loop;
    uv_loop_init(&ev_loop);

    conf.ev_loop = &ev_loop;

    // 只有发生冲突才会注册不成功，否则会无限重试注册父节点，直到其上线
    {
        atbus::node::ptr_t node_parent  = atbus::node::create();
        atbus::node::ptr_t node_child_1 = atbus::node::create();
        atbus::node::ptr_t node_child_2 = atbus::node::create();
        node_parent->on_debug           = node_msg_test_on_debug;
        node_child_1->on_debug          = node_msg_test_on_debug;
        node_child_2->on_debug          = node_msg_test_on_debug;
        node_parent->set_on_error_handle(node_msg_test_on_error);
        node_child_1->set_on_error_handle(node_msg_test_on_error);
        node_child_2->set_on_error_handle(node_msg_test_on_error);

        node_parent->init(0x12345678, &conf);

        conf.subnets.clear();
        conf.subnets.push_back(atbus::endpoint_subnet_conf(0, 8));
        conf.parent_address = "ipv4://127.0.0.1:16387";
        node_child_1->init(0x12346789, &conf);
        node_child_2->init(0x12346890, &conf);

        CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_parent->listen("ipv4://127.0.0.1:16387"));
        CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_child_1->listen("ipv4://127.0.0.1:16388"));
        CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_child_2->listen("ipv4://127.0.0.1:16389"));

        CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_parent->start());
        CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_child_1->start());
        CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_child_2->start());

        time_t proc_t = time(NULL) + 1;
        node_child_1->set_on_recv_handle(node_msg_test_recv_msg_test_record_fn);
        node_child_2->set_on_recv_handle(node_msg_test_recv_msg_test_record_fn);

        // wait for register finished
        UNITTEST_WAIT_UNTIL(
            conf.ev_loop,
            node_parent->is_endpoint_available(node_child_1->get_id()) && node_parent->is_endpoint_available(node_child_2->get_id()) &&
                node_child_2->is_endpoint_available(node_parent->get_id()) && node_child_1->is_endpoint_available(node_parent->get_id()),
            8000, 64) {
            node_parent->proc(proc_t, 0);
            node_child_1->proc(proc_t, 0);
            node_child_2->proc(proc_t, 0);

            ++proc_t;
        }

        // 转发消息
        std::string send_data;
        send_data.assign("transfer through parent\n", sizeof("transfer through parent\n") - 1);

        int count = recv_msg_history.count;
        recv_msg_history.data.clear();
        node_child_1->send_data(node_child_2->get_id(), 0, send_data.data(), send_data.size());
        UNITTEST_WAIT_UNTIL(conf.ev_loop, count != recv_msg_history.count && !recv_msg_history.data.empty(), 5000, 0) {}

        CASE_EXPECT_EQ(send_data, recv_msg_history.data);

        // 自动直连测试
        UNITTEST_WAIT_UNTIL(conf.ev_loop, node_child_1->is_endpoint_available(node_child_2->get_id()), 8000, 0) {}
        atbus::endpoint *ep1 = node_child_1->get_endpoint(node_child_2->get_id());
        CASE_EXPECT_NE(NULL, ep1);
    }

    unit_test_setup_exit(&ev_loop);
}

// 兄弟节点通过多层父节点转发消息并不会建立直连测试
CASE_TEST(atbus_node_msg, transfer_only) {
    atbus::node::conf_t conf;
    atbus::node::default_conf(&conf);
    conf.subnets.push_back(atbus::endpoint_subnet_conf(0, 16));
    uv_loop_t ev_loop;
    uv_loop_init(&ev_loop);

    conf.ev_loop = &ev_loop;

    // 只有发生冲突才会注册不成功，否则会无限重试注册父节点，直到其上线
    {
        atbus::node::ptr_t node_parent_1 = atbus::node::create();
        atbus::node::ptr_t node_parent_2 = atbus::node::create();
        atbus::node::ptr_t node_child_1  = atbus::node::create();
        atbus::node::ptr_t node_child_2  = atbus::node::create();
        node_parent_1->on_debug          = node_msg_test_on_debug;
        node_parent_2->on_debug          = node_msg_test_on_debug;
        node_child_1->on_debug           = node_msg_test_on_debug;
        node_child_2->on_debug           = node_msg_test_on_debug;
        node_parent_1->set_on_error_handle(node_msg_test_on_error);
        node_parent_2->set_on_error_handle(node_msg_test_on_error);
        node_child_1->set_on_error_handle(node_msg_test_on_error);
        node_child_2->set_on_error_handle(node_msg_test_on_error);

        node_parent_1->init(0x12345678, &conf);
        node_parent_2->init(0x12356789, &conf);

        conf.subnets.clear();
        conf.subnets.push_back(atbus::endpoint_subnet_conf(0, 8));
        conf.parent_address = "ipv4://127.0.0.1:16387";
        node_child_1->init(0x12346789, &conf);
        conf.parent_address = "ipv4://127.0.0.1:16388";
        node_child_2->init(0x12354678, &conf);

        CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_parent_1->listen("ipv4://127.0.0.1:16387"));
        CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_parent_2->listen("ipv4://127.0.0.1:16388"));
        CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_child_1->listen("ipv4://127.0.0.1:16389"));
        CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_child_2->listen("ipv4://127.0.0.1:16390"));

        CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_parent_1->start());
        CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_parent_2->start());
        CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_child_1->start());
        CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_child_2->start());

        time_t proc_t = time(NULL) + 1;
        node_child_1->set_on_recv_handle(node_msg_test_recv_msg_test_record_fn);
        node_child_2->set_on_recv_handle(node_msg_test_recv_msg_test_record_fn);
        node_parent_1->connect("ipv4://127.0.0.1:16388");

        // wait for register finished
        UNITTEST_WAIT_UNTIL(conf.ev_loop,
                            node_child_1->is_endpoint_available(node_parent_1->get_id()) &&
                                node_parent_1->is_endpoint_available(node_child_1->get_id()) &&
                                node_child_2->is_endpoint_available(node_parent_2->get_id()) &&
                                node_parent_2->is_endpoint_available(node_child_2->get_id()) &&
                                node_parent_1->is_endpoint_available(node_parent_2->get_id()) &&
                                node_parent_2->is_endpoint_available(node_parent_1->get_id()),
                            8000, 64) {
            node_parent_1->proc(proc_t, 0);
            node_parent_2->proc(proc_t, 0);
            node_child_1->proc(proc_t, 0);
            node_child_2->proc(proc_t, 0);

            ++proc_t;
        }

        // 转发消息
        std::string send_data;
        recv_msg_history.data.clear();
        send_data.assign("transfer through parent only\n", sizeof("transfer through parent only\n") - 1);

        int count = recv_msg_history.count;
        node_child_1->send_data(node_child_2->get_id(), 0, send_data.data(), send_data.size());
        UNITTEST_WAIT_UNTIL(conf.ev_loop, count != recv_msg_history.count, 8000, 0) {}

        CASE_EXPECT_EQ(send_data, recv_msg_history.data);
        for (int i = 0; i < 64; ++i) {
            uv_run(conf.ev_loop, UV_RUN_NOWAIT);
            CASE_THREAD_SLEEP_MS(4);
        }

        // 非直接子节点互相不建立直连
        atbus::endpoint *ep1 = node_child_1->get_endpoint(node_child_2->get_id());
        CASE_EXPECT_EQ(NULL, ep1);
    }

    unit_test_setup_exit(&ev_loop);
}

// 直连节点发送失败测试
CASE_TEST(atbus_node_msg, send_failed) {
    atbus::node::conf_t conf;
    atbus::node::default_conf(&conf);
    conf.subnets.push_back(atbus::endpoint_subnet_conf(0, 16));
    uv_loop_t ev_loop;
    uv_loop_init(&ev_loop);

    conf.ev_loop = &ev_loop;

    {
        atbus::node::ptr_t node_parent = atbus::node::create();
        node_parent->on_debug          = node_msg_test_on_debug;
        node_parent->set_on_error_handle(node_msg_test_on_error);
        node_parent->init(0x12345678, &conf);

        CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_parent->listen("ipv4://127.0.0.1:16387"));
        CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_parent->start());

        CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_parent->start());

        std::string send_data;
        send_data.assign("send failed", sizeof("send failed") - 1);

        // send to child failed
        CASE_EXPECT_EQ(EN_ATBUS_ERR_ATNODE_INVALID_ID, node_parent->send_data(0x12346780, 0, send_data.data(), send_data.size()));
        // send to brother and failed
        CASE_EXPECT_EQ(EN_ATBUS_ERR_ATNODE_INVALID_ID, node_parent->send_data(0x12356789, 0, send_data.data(), send_data.size()));
    }

    unit_test_setup_exit(&ev_loop);
}

// 发送给子节点转发失败的回复通知测试
// 发送给父节点转发失败的回复通知测试
CASE_TEST(atbus_node_msg, transfer_failed) {
    atbus::node::conf_t conf;
    atbus::node::default_conf(&conf);
    conf.subnets.push_back(atbus::endpoint_subnet_conf(0, 16));
    uv_loop_t ev_loop;
    uv_loop_init(&ev_loop);

    conf.ev_loop = &ev_loop;

    // 只有发生冲突才会注册不成功，否则会无限重试注册父节点，直到其上线
    {
        atbus::node::ptr_t node_parent  = atbus::node::create();
        atbus::node::ptr_t node_child_1 = atbus::node::create();
        node_parent->on_debug           = node_msg_test_on_debug;
        node_child_1->on_debug          = node_msg_test_on_debug;
        node_parent->set_on_error_handle(node_msg_test_on_error);
        node_child_1->set_on_error_handle(node_msg_test_on_error);

        node_parent->init(0x12345678, &conf);

        conf.subnets.clear();
        conf.subnets.push_back(atbus::endpoint_subnet_conf(0, 8));
        conf.parent_address = "ipv4://127.0.0.1:16387";
        node_child_1->init(0x12346789, &conf);

        CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_parent->listen("ipv4://127.0.0.1:16387"));
        CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_child_1->listen("ipv4://127.0.0.1:16388"));

        CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_parent->start());
        CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_child_1->start());

        time_t proc_t = time(NULL) + 1;
        node_child_1->set_on_recv_handle(node_msg_test_recv_msg_test_record_fn);
        node_child_1->set_on_forward_response_handle(node_msg_test_send_data_forward_response_fn);
        CASE_EXPECT_TRUE(!!node_child_1->get_on_forward_response_handle());

        // wait for register finished
        UNITTEST_WAIT_UNTIL(conf.ev_loop,
                            node_child_1->is_endpoint_available(node_parent->get_id()) &&
                                node_parent->is_endpoint_available(node_child_1->get_id()),
                            8000, 64) {
            node_parent->proc(proc_t, 0);
            node_child_1->proc(proc_t, 0);

            ++proc_t;
        }

        // 转发消息
        std::string send_data;
        send_data.assign("transfer through parent\n", sizeof("transfer through parent\n") - 1);

        int count = recv_msg_history.failed_count;
        CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_child_1->send_data(0x12346890, 0, send_data.data(), send_data.size()));
        CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_child_1->send_data(0x12356789, 0, send_data.data(), send_data.size()));

        UNITTEST_WAIT_UNTIL(conf.ev_loop, count + 1 < recv_msg_history.failed_count, 8000, 0) {}

        CASE_EXPECT_EQ(count + 2, recv_msg_history.failed_count);
        CASE_EXPECT_EQ(EN_ATBUS_ERR_ATNODE_INVALID_ID, recv_msg_history.status);
    }

    unit_test_setup_exit(&ev_loop);
}

// 通过两个父节点转发失败测试，本地连接不应该断
//     F1 <-----> F2
//    /            -(此连接断开)
//   C1             C2
// C1向C2发送消息，F2->F1->C1失败通知。重试多次后 F1-C1连接不断
CASE_TEST(atbus_node_msg, transfer_failed_cross_parents) {
    atbus::node::conf_t conf;
    atbus::node::default_conf(&conf);
    conf.subnets.push_back(atbus::endpoint_subnet_conf(0, 16));
    uv_loop_t ev_loop;
    uv_loop_init(&ev_loop);

    conf.ev_loop        = &ev_loop;
    conf.fault_tolerant = 2; // 容错设为2次。
    size_t try_times    = 5; //我们尝试5次发失败

    // 只有发生冲突才会注册不成功，否则会无限重试注册父节点，直到其上线
    {
        atbus::node::ptr_t node_parent_1 = atbus::node::create();
        atbus::node::ptr_t node_parent_2 = atbus::node::create();
        atbus::node::ptr_t node_child_1  = atbus::node::create();
        node_parent_1->on_debug          = node_msg_test_on_debug;
        node_parent_2->on_debug          = node_msg_test_on_debug;
        node_child_1->on_debug           = node_msg_test_on_debug;
        node_parent_1->set_on_error_handle(node_msg_test_on_error);
        node_child_1->set_on_error_handle(node_msg_test_on_error);
        node_parent_2->set_on_error_handle(node_msg_test_on_error);

        node_parent_1->init(0x12345678, &conf);
        node_parent_1->set_on_remove_endpoint_handle(node_msg_test_remove_endpoint_fn);
        node_parent_2->init(0x12356789, &conf);
        node_parent_2->set_on_remove_endpoint_handle(node_msg_test_remove_endpoint_fn);


        conf.subnets.clear();
        conf.subnets.push_back(atbus::endpoint_subnet_conf(0, 8));
        conf.parent_address = "ipv4://127.0.0.1:16387";
        node_child_1->init(0x12346789, &conf);

        CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_parent_1->listen("ipv4://127.0.0.1:16387"));
        CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_parent_2->listen("ipv4://127.0.0.1:16388"));
        CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_child_1->listen("ipv4://127.0.0.1:16389"));

        CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_parent_1->start());
        CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_parent_2->start());
        CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_child_1->start());

        time_t proc_t = time(NULL) + 1;
        node_child_1->set_on_recv_handle(node_msg_test_recv_msg_test_record_fn);
        node_child_1->set_on_forward_response_handle(node_msg_test_send_data_forward_response_fn);
        node_child_1->set_on_remove_endpoint_handle(node_msg_test_remove_endpoint_fn);

        node_parent_1->connect("ipv4://127.0.0.1:16388");
        // wait for register finished
        UNITTEST_WAIT_UNTIL(conf.ev_loop,
                            node_child_1->is_endpoint_available(node_parent_1->get_id()) &&
                                node_parent_1->is_endpoint_available(node_child_1->get_id()) &&
                                node_parent_1->is_endpoint_available(node_parent_2->get_id()) &&
                                node_parent_2->is_endpoint_available(node_parent_1->get_id()),
                            8000, 64) {
            node_parent_1->proc(proc_t, 0);
            node_child_1->proc(proc_t, 0);

            ++proc_t;
        }

        int before_remove_endpoint_count = recv_msg_history.remove_endpoint_count;
        int before_test_count            = recv_msg_history.failed_count;
        int recv_transfer_failed         = 0;
        
        recv_msg_history.last_msg_router.clear();
        for (size_t i = 0; i < try_times; ++i) {
            // 转发消息
            std::string send_data;
            send_data.assign("transfer through parent\n", sizeof("transfer through parent\n") - 1);

            int count    = recv_msg_history.failed_count;
            int send_res = node_child_1->send_data(0x12356666, 0, send_data.data(), send_data.size());
            CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, send_res);

            if (send_res != EN_ATBUS_ERR_SUCCESS) {
                continue;
            }

            ++recv_transfer_failed;
            UNITTEST_WAIT_UNTIL(conf.ev_loop, count < recv_msg_history.failed_count, 8000, 0) {}
        }

        CASE_EXPECT_FALSE(recv_msg_history.last_msg_router.empty());
        if (!recv_msg_history.last_msg_router.empty()) {
            CASE_EXPECT_EQ(0x12356789, recv_msg_history.last_msg_router.back());
        }

        CASE_EXPECT_EQ(before_test_count + recv_transfer_failed, recv_msg_history.failed_count);
        CASE_EXPECT_EQ(before_remove_endpoint_count, recv_msg_history.remove_endpoint_count);
        CASE_EXPECT_TRUE(node_child_1->is_endpoint_available(node_parent_1->get_id()));
        CASE_EXPECT_TRUE(node_parent_1->is_endpoint_available(node_child_1->get_id()));
    }

    unit_test_setup_exit(&ev_loop);
}


// TODO 全量表第一次拉取测试
// TODO 全量表通知给父节点和子节点测试
