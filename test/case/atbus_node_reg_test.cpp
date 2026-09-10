// Copyright 2026 atframework

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>

#include <atbus_node.h>
#include <libatbus_protocol.h>

#include <common/file_system.h>
#include <common/string_oprs.h>
#include <std/explicit_declare.h>

#include "atbus_test_utils.h"
#include "frame/test_macros.h"

#include <stdarg.h>

struct node_reg_test_recv_msg_record_t {
  std::string data;
  int status;
  int count;
  int add_endpoint_count;
  int remove_endpoint_count;
  int register_count;
  int register_failed_count;
  int availavle_count;
  int new_connection_count;
  int invalid_connection_count;
  int dealloc_endpoint_count;
  int dealloc_connection_count;

  node_reg_test_recv_msg_record_t()
      : status(0),
        count(0),
        add_endpoint_count(0),
        remove_endpoint_count(0),
        register_count(0),
        register_failed_count(0),
        availavle_count(0),
        new_connection_count(0),
        invalid_connection_count(0),
        dealloc_endpoint_count(0),
        dealloc_connection_count(0) {}
};

static node_reg_test_recv_msg_record_t recv_msg_history;

static void node_reg_test_on_debug(const atfw::util::log::log_formatter::caller_info_t &,
                                   atfw::util::nostd::string_view content) {
  if (gsl::string_view::npos != content.find("connection deallocated")) {
    ++recv_msg_history.dealloc_connection_count;
  } else if (gsl::string_view::npos != content.find("endpoint deallocated")) {
    ++recv_msg_history.dealloc_endpoint_count;
  }

  CASE_MSG_INFO() << content << '\n';

#ifdef _MSC_VER

  // static char *APPVEYOR = getenv("APPVEYOR");
  // static char *CI       = getenv("CI");

  // appveyor ci open msg content
  // if (APPVEYOR && APPVEYOR[0] && CI && CI[0] && nullptr != m) {
  //     std::cout << *m << '\n';
  // }
#endif
}

static int node_reg_test_on_error(const atfw::util::log::log_formatter::caller_info_t &,
                                  atfw::util::nostd::string_view content) {
  // find status: {}, error_code: {}
  int status = 0;
  ATBUS_ERROR_TYPE errcode = EN_ATBUS_ERR_SUCCESS;
  size_t pos = content.find("status:");
  if (gsl::string_view::npos != pos) {
    for (; pos < content.size(); ++pos) {
      if ((content[pos] >= '0' && content[pos] <= '9') || content[pos] == '-') {
        break;
      }
    }
    if (pos < content.size()) {
      status = atfw::util::string::to_int<int>(content.substr(pos));
    }
  }
  pos = content.find("error_code:", pos);
  if (gsl::string_view::npos != pos) {
    pos += 11;
    for (; pos < content.size(); ++pos) {
      if ((content[pos] >= '0' && content[pos] <= '9') || content[pos] == '-') {
        break;
      }
    }
    if (pos < content.size()) {
      errcode = static_cast<ATBUS_ERROR_TYPE>(atfw::util::string::to_int<int>(content.substr(pos)));
    }
  }
  if ((0 == status && 0 == errcode) || UV_EOF == status || UV_ECONNRESET == status) {
    return 0;
  }

  // 随时可能收到网络错误，排除错误检查
  if (recv_msg_history.status == 0 || errcode > EN_ATBUS_ERR_DNS_GETADDR_FAILED || errcode < EN_ATBUS_ERR_NOT_READY) {
    recv_msg_history.status = (0 != errcode) ? static_cast<int>(errcode) : status;
  }
  ++recv_msg_history.register_failed_count;

  CASE_MSG_INFO() << content << '\n';
  return 0;
}

static int node_reg_test_on_info_log(const atfw::util::log::log_formatter::caller_info_t &,
                                     atfw::util::nostd::string_view content) {
  CASE_MSG_INFO() << content << '\n';
  if (gsl::string_view::npos != content.find("connection deallocated")) {
    ++recv_msg_history.dealloc_connection_count;
  } else if (gsl::string_view::npos != content.find("endpoint deallocated")) {
    ++recv_msg_history.dealloc_endpoint_count;
  }
  return 0;
}

static void setup_atbus_node_logger(atbus::node &n) {
  n.get_logger()->set_level(atfw::util::log::log_level::kDebug);
  n.get_logger()->clear_sinks();
  n.get_logger()->add_sink(node_reg_test_on_debug, atfw::util::log::log_level::kDebug,
                           atfw::util::log::log_level::kDebug);
  n.get_logger()->add_sink(node_reg_test_on_info_log, atfw::util::log::log_level::kInfo,
                           atfw::util::log::log_level::kInfo);
  n.get_logger()->add_sink(node_reg_test_on_error, atfw::util::log::log_level::kError,
                           atfw::util::log::log_level::kError);

  n.enable_debug_message_verbose();
}

static int node_reg_test_recv_msg_test_record_fn(const atbus::node & /*n*/, const atbus::endpoint * /*ep*/,
                                                 const atbus::connection * /*conn*/, const atbus::message &m,
                                                 gsl::span<const unsigned char> buffer) {
  recv_msg_history.status = m.get_head() == nullptr ? 0 : m.get_head()->result_code();
  ++recv_msg_history.count;

  if (!buffer.empty()) {
    recv_msg_history.data.assign(reinterpret_cast<const char *>(buffer.data()), buffer.size());
  } else {
    recv_msg_history.data.clear();
  }

  return 0;
}

static int node_reg_test_add_endpoint_fn(const atbus::node &n, atbus::endpoint *ep, int) {
  ++recv_msg_history.add_endpoint_count;

  CASE_EXPECT_NE(nullptr, ep);
  CASE_EXPECT_NE(n.get_self_endpoint(), ep);
  return 0;
}

static int node_reg_test_remove_endpoint_fn(const atbus::node &n, atbus::endpoint *ep, int) {
  ++recv_msg_history.remove_endpoint_count;

  CASE_EXPECT_NE(nullptr, ep);
  CASE_EXPECT_NE(n.get_self_endpoint(), ep);
  return 0;
}

static int node_reg_test_on_register_fn(const atbus::node &, const atbus::endpoint *, const atbus::connection *, int) {
  ++recv_msg_history.register_count;
  return 0;
}

static int node_reg_test_on_available_fn(const atbus::node &, int status) {
  ++recv_msg_history.availavle_count;

  CASE_EXPECT_EQ(0, status);
  return 0;
}

static int node_reg_test_new_connection_fn(const atbus::node &, const atbus::connection *) {
  ++recv_msg_history.new_connection_count;
  return 0;
}

static int node_reg_test_invalid_fn(const atbus::node &, const atbus::connection *, int status) {
  ++recv_msg_history.invalid_connection_count;

  recv_msg_history.status = status;
  return 0;
}

// 主动reset流程测试
// 正常首发数据测试
CASE_TEST(atbus_node_reg, reset_and_send_tcp) {
  atbus::node::conf_t conf;
  atbus::node::default_conf(&conf);
  conf.access_tokens.push_back(std::vector<unsigned char>());
  unsigned char access_token[] = "test access token";
  conf.access_tokens.back().assign(access_token, access_token + sizeof(access_token) - 1);
  uv_loop_t ev_loop;
  uv_loop_init(&ev_loop);

  conf.ev_loop = &ev_loop;

  {
    atbus::node::ptr_t node1 = atbus::node::create();
    atbus::node::ptr_t node2 = atbus::node::create();
    setup_atbus_node_logger(*node1);
    setup_atbus_node_logger(*node2);

    CASE_EXPECT_EQ(EN_ATBUS_ERR_NOT_INITED, node1->start());
    CASE_EXPECT_EQ(EN_ATBUS_ERR_NOT_INITED, node2->start());

    node1->init(0x12345678, &conf);
    node2->init(0x12356789, &conf);

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node1->listen("ipv4://127.0.0.1:16387"));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node2->listen("ipv4://127.0.0.1:16388"));

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node1->start());
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node2->start());

    time_t proc_t = time(nullptr);
    node1->poll();
    node2->poll();
    node1->proc(unit_test_make_timepoint(proc_t + 1, 0));
    node1->proc(unit_test_make_timepoint(proc_t + 1, 1));
    node2->proc(unit_test_make_timepoint(proc_t + 1, 0));
    node2->proc(unit_test_make_timepoint(proc_t + 1, 1));

    // 连接兄弟节点回调测试
    int check_ep_count = recv_msg_history.add_endpoint_count;
    node1->set_on_add_endpoint_handle(node_reg_test_add_endpoint_fn);
    node1->set_on_remove_endpoint_handle(node_reg_test_remove_endpoint_fn);
    node2->set_on_add_endpoint_handle(node_reg_test_add_endpoint_fn);
    node2->set_on_remove_endpoint_handle(node_reg_test_remove_endpoint_fn);

    node1->connect("ipv4://127.0.0.1:16388");

    UNITTEST_WAIT_UNTIL(conf.ev_loop,
                        node1->is_endpoint_available(node2->get_id()) && node2->is_endpoint_available(node1->get_id()),
                        8000, 0) {}
    // in windows CI, connection will be closed sometimes, it will lead to add one endpoint more than one times
    CASE_EXPECT_LE(check_ep_count + 2, recv_msg_history.add_endpoint_count);

    // 兄弟节点消息转发测试
    std::string send_data;
    send_data.assign("abcdefg\0hello world!\n", sizeof("abcdefg\0hello world!\n") - 1);

    node1->poll();
    node2->poll();
    proc_t += 1000;
    node1->proc(unit_test_make_timepoint(proc_t, 0));
    node2->proc(unit_test_make_timepoint(proc_t, 0));

    int count = recv_msg_history.count;
    node2->set_on_forward_request_handle(node_reg_test_recv_msg_test_record_fn);
    CASE_EXPECT_TRUE(!!node2->get_on_forward_request_handle());
    node1->send_data(
        node2->get_id(), 0,
        gsl::span<const unsigned char>(reinterpret_cast<const unsigned char *>(send_data.data()), send_data.size()));

    UNITTEST_WAIT_UNTIL(conf.ev_loop, count != recv_msg_history.count, 8000, 0) {}

    // check add endpoint callback
    CASE_EXPECT_EQ(send_data, recv_msg_history.data);
    // CASE_EXPECT_NE(nullptr, node1->get_iostream_conf());

    check_ep_count = recv_msg_history.remove_endpoint_count;

    // reset
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS,
                   node1->shutdown(EN_ATBUS_ERR_SUCCESS));  // shutdown - test, next proc() will call reset()
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node1->shutdown(EN_ATBUS_ERR_SUCCESS));  // shutdown - again

    UNITTEST_WAIT_UNTIL(
        conf.ev_loop,
        nullptr == node1->get_endpoint(node2->get_id()) && nullptr == node2->get_endpoint(node1->get_id()), 8000, 64) {
      ++proc_t;

      node1->proc(unit_test_make_timepoint(proc_t, 0));
      node2->proc(unit_test_make_timepoint(proc_t, 0));
    }

    UNITTEST_WAIT_UNTIL(conf.ev_loop, true, 1024, 64) {
      ++proc_t;

      node1->proc(unit_test_make_timepoint(proc_t, 0));
      node2->proc(unit_test_make_timepoint(proc_t, 0));
    }

    CASE_MSG_INFO() << "Ready to exit" << '\n';

    node2->reset();

    // check remove endpoint callback
    // in windows CI, connection will be closed sometimes, it will lead to add one endpoint more than one times
    CASE_EXPECT_LE(check_ep_count + 2, recv_msg_history.remove_endpoint_count);

    CASE_EXPECT_EQ(nullptr, node2->get_endpoint(node1->get_id()));
    CASE_EXPECT_EQ(nullptr, node1->get_endpoint(node2->get_id()));
  }

  unit_test_setup_exit(&ev_loop);
}

CASE_TEST(atbus_node_reg, timeout) {
  atbus::node::conf_t conf;
  atbus::node::default_conf(&conf);
  conf.access_tokens.push_back(std::vector<unsigned char>());
  unsigned char access_token[] = "test access token";
  conf.access_tokens.back().assign(access_token, access_token + sizeof(access_token) - 1);
  uv_loop_t ev_loop;
  uv_loop_init(&ev_loop);

  conf.ev_loop = &ev_loop;

  {
    atbus::node::ptr_t node1 = atbus::node::create();
    atbus::node::ptr_t node2 = atbus::node::create();
    setup_atbus_node_logger(*node1);
    setup_atbus_node_logger(*node2);

    CASE_EXPECT_EQ(EN_ATBUS_ERR_NOT_INITED, node1->start());
    CASE_EXPECT_EQ(EN_ATBUS_ERR_NOT_INITED, node2->start());

    node1->init(0x12345678, &conf);
    node2->init(0x12356789, &conf);

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node1->listen("ipv4://127.0.0.1:16387"));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node2->listen("ipv4://127.0.0.1:16388"));

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node1->start());
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node2->start());

    time_t proc_t = time(nullptr);
    node1->poll();
    node2->poll();
    node1->proc(unit_test_make_timepoint(proc_t + 1, 0));
    node1->proc(unit_test_make_timepoint(proc_t + 1, 1));
    node2->proc(unit_test_make_timepoint(proc_t + 1, 0));
    node2->proc(unit_test_make_timepoint(proc_t + 1, 1));

    // 连接兄弟节点回调测试
    int check_new_connection_count = recv_msg_history.new_connection_count;
    int check_invalid_connection_count = recv_msg_history.invalid_connection_count;
    node1->set_on_new_connection_handle(node_reg_test_new_connection_fn);
    CASE_EXPECT_TRUE(!!node1->get_on_new_connection_handle());
    node1->set_on_invalid_connection_handle(node_reg_test_invalid_fn);
    CASE_EXPECT_TRUE(!!node1->get_on_invalid_connection_handle());
    node2->set_on_new_connection_handle(node_reg_test_new_connection_fn);
    node2->set_on_invalid_connection_handle(node_reg_test_invalid_fn);

    node1->connect("ipv4://127.0.0.1:16388");

    UNITTEST_WAIT_UNTIL(conf.ev_loop, recv_msg_history.new_connection_count >= check_new_connection_count + 1, 8000,
                        0) {}

    CASE_EXPECT_LE(check_new_connection_count + 1, recv_msg_history.new_connection_count);
    if (check_new_connection_count + 1 > recv_msg_history.new_connection_count) {
      return;
    }

    // 正常情况下第一条连接会成功，第二条连接会被超时关闭。如果IO事件导致后续链接流程被处理了则跳过这个单元测试吧
    if (node1->is_endpoint_available(node2->get_id()) && node2->is_endpoint_available(node1->get_id())) {
      CASE_MSG_INFO() << "more events than expected, skip this unit test." << '\n';
      return;
    }

    proc_t = time(nullptr) + 2;
    time_t first_idle_timeout_sec = static_cast<time_t>(conf.first_idle_timeout.count() / 1000000);
    node1->proc(unit_test_make_timepoint(proc_t + first_idle_timeout_sec + 2, 0));
    node2->proc(unit_test_make_timepoint(proc_t + first_idle_timeout_sec + 2, 0));

    UNITTEST_WAIT_UNTIL(conf.ev_loop, recv_msg_history.invalid_connection_count >= check_invalid_connection_count + 1,
                        8000, 0) {}
    CASE_EXPECT_LE(check_invalid_connection_count + 1, recv_msg_history.invalid_connection_count);

    node1->poll();
    node2->poll();

    CASE_MSG_INFO() << "new connection: " << (recv_msg_history.new_connection_count - check_new_connection_count)
                    << '\n';
    CASE_MSG_INFO() << "invalid connection: "
                    << (recv_msg_history.invalid_connection_count - check_invalid_connection_count) << '\n';

    CASE_EXPECT_TRUE(recv_msg_history.status == EN_ATBUS_ERR_NODE_TIMEOUT || recv_msg_history.status == -604);
    CASE_EXPECT_EQ(0, node1->get_connection_timer_size());
    CASE_EXPECT_EQ(0, node2->get_connection_timer_size());
  }

  unit_test_setup_exit(&ev_loop);
}

CASE_TEST(atbus_node_reg, message_size_limit) {
  atbus::node::conf_t conf;
  atbus::node::default_conf(&conf);
  conf.message_size = 4 * 1024;
  conf.access_tokens.push_back(std::vector<unsigned char>());
  unsigned char access_token[] = "test access token";
  conf.access_tokens.back().assign(access_token, access_token + sizeof(access_token) - 1);
  uv_loop_t ev_loop;
  uv_loop_init(&ev_loop);

  conf.ev_loop = &ev_loop;

  {
    atbus::node::ptr_t node1 = atbus::node::create();
    atbus::node::ptr_t node2 = atbus::node::create();
    setup_atbus_node_logger(*node1);
    setup_atbus_node_logger(*node2);

    CASE_EXPECT_EQ(EN_ATBUS_ERR_NOT_INITED, node1->start());
    CASE_EXPECT_EQ(EN_ATBUS_ERR_NOT_INITED, node2->start());

    node1->init(0x12345678, &conf);
    node2->init(0x12356789, &conf);

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node1->listen("ipv4://127.0.0.1:16387"));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node2->listen("ipv4://127.0.0.1:16388"));

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node1->start());
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node2->start());

    time_t proc_t = time(nullptr);
    node1->poll();
    node2->poll();
    node1->proc(unit_test_make_timepoint(proc_t + 1, 0));
    node1->proc(unit_test_make_timepoint(proc_t + 1, 1));
    node2->proc(unit_test_make_timepoint(proc_t + 1, 0));
    node2->proc(unit_test_make_timepoint(proc_t + 1, 1));

    // 连接兄弟节点回调测试
    int check_ep_count = recv_msg_history.add_endpoint_count;
    node1->set_on_add_endpoint_handle(node_reg_test_add_endpoint_fn);
    node1->set_on_remove_endpoint_handle(node_reg_test_remove_endpoint_fn);
    node2->set_on_add_endpoint_handle(node_reg_test_add_endpoint_fn);
    node2->set_on_remove_endpoint_handle(node_reg_test_remove_endpoint_fn);

    node1->connect("ipv4://127.0.0.1:16388");

    UNITTEST_WAIT_UNTIL(conf.ev_loop,
                        node1->is_endpoint_available(node2->get_id()) && node2->is_endpoint_available(node1->get_id()),
                        8000, 0) {}
    // in windows CI, connection will be closed sometimes, it will lead to add one endpoint more than one times
    CASE_EXPECT_LE(check_ep_count + 2, recv_msg_history.add_endpoint_count);

    // 兄弟节点消息转发测试
    std::string send_data;
    send_data.reserve(conf.message_size + 8);
    send_data.resize(conf.message_size, 'a');

    node1->poll();
    node2->poll();
    proc_t += 1000;
    node1->proc(unit_test_make_timepoint(proc_t, 0));
    node2->proc(unit_test_make_timepoint(proc_t, 0));

    int count = recv_msg_history.count;
    node2->set_on_forward_request_handle(node_reg_test_recv_msg_test_record_fn);
    CASE_EXPECT_TRUE(!!node2->get_on_forward_request_handle());
    CASE_EXPECT_EQ(
        0, node1->send_data(node2->get_id(), 0,
                            gsl::span<const unsigned char>(reinterpret_cast<const unsigned char *>(send_data.data()),
                                                           send_data.size())));

    UNITTEST_WAIT_UNTIL(conf.ev_loop, count != recv_msg_history.count, 8000, 0) {}

    // check add endpoint callback
    CASE_EXPECT_EQ(send_data, recv_msg_history.data);

    send_data += 'b';
    CASE_EXPECT_EQ(EN_ATBUS_ERR_INVALID_SIZE,
                   node1->send_data(node2->get_id(), 0,
                                    gsl::span<const unsigned char>(
                                        reinterpret_cast<const unsigned char *>(send_data.data()), send_data.size())));

    check_ep_count = recv_msg_history.remove_endpoint_count;

    // reset
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS,
                   node1->shutdown(EN_ATBUS_ERR_SUCCESS));  // shutdown - test, next proc() will call reset()
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node1->shutdown(EN_ATBUS_ERR_SUCCESS));  // shutdown - again

    UNITTEST_WAIT_UNTIL(
        conf.ev_loop,
        nullptr == node1->get_endpoint(node2->get_id()) && nullptr == node2->get_endpoint(node1->get_id()), 8000, 64) {
      ++proc_t;

      node1->proc(unit_test_make_timepoint(proc_t, 0));
      node2->proc(unit_test_make_timepoint(proc_t, 0));
    }

    node2->reset();

    CASE_EXPECT_EQ(nullptr, node2->get_endpoint(node1->get_id()));
    CASE_EXPECT_EQ(nullptr, node1->get_endpoint(node2->get_id()));
  }

  unit_test_setup_exit(&ev_loop);

  CASE_MSG_INFO() << "default message max size: " << conf.message_size << '\n';
}

CASE_TEST(atbus_node_reg, reg_failed_with_mismatch_access_token) {
  atbus::node::conf_t conf1;
  atbus::node::conf_t conf2;
  atbus::node::default_conf(&conf1);
  atbus::node::default_conf(&conf2);
  {
    conf1.access_tokens.push_back(std::vector<unsigned char>());
    unsigned char access_token1[] = "test access token";
    conf1.access_tokens.back().assign(access_token1, access_token1 + sizeof(access_token1) - 1);
  }
  {
    conf2.access_tokens.push_back(std::vector<unsigned char>());
    unsigned char access_token2[] = "invalid access token";
    conf2.access_tokens.back().assign(access_token2, access_token2 + sizeof(access_token2) - 1);
  }
  uv_loop_t ev_loop;
  uv_loop_init(&ev_loop);

  conf1.ev_loop = &ev_loop;
  conf2.ev_loop = &ev_loop;

  {
    atbus::node::ptr_t node1 = atbus::node::create();
    atbus::node::ptr_t node2 = atbus::node::create();
    setup_atbus_node_logger(*node1);
    setup_atbus_node_logger(*node2);

    CASE_EXPECT_EQ(EN_ATBUS_ERR_NOT_INITED, node1->start());
    CASE_EXPECT_EQ(EN_ATBUS_ERR_NOT_INITED, node2->start());

    node1->init(0x12345678, &conf1);
    node2->init(0x12356789, &conf2);

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node1->listen("ipv4://127.0.0.1:10387"));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node2->listen("ipv4://127.0.0.1:10388"));

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node1->start());
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node2->start());

    time_t proc_t = time(nullptr);
    recv_msg_history.status = 0;
    node1->poll();
    node2->poll();
    node1->proc(unit_test_make_timepoint(proc_t + 1, 0));
    node1->proc(unit_test_make_timepoint(proc_t + 1, 1));
    node2->proc(unit_test_make_timepoint(proc_t + 1, 0));
    node2->proc(unit_test_make_timepoint(proc_t + 1, 1));

    // 连接兄弟节点回调测试
    int check_ep_count = recv_msg_history.register_failed_count;
    node1->set_on_add_endpoint_handle(node_reg_test_add_endpoint_fn);
    node1->set_on_remove_endpoint_handle(node_reg_test_remove_endpoint_fn);
    node2->set_on_add_endpoint_handle(node_reg_test_add_endpoint_fn);
    node2->set_on_remove_endpoint_handle(node_reg_test_remove_endpoint_fn);

    node1->connect("ipv4://127.0.0.1:10388");

    UNITTEST_WAIT_MS(&ev_loop, 500, 0) {}
    // in windows CI, connection will be closed sometimes, it will lead to add one endpoint more than one times
    CASE_EXPECT_LE(check_ep_count + 2, recv_msg_history.register_failed_count);

    CASE_EXPECT_EQ(nullptr, node2->get_endpoint(node1->get_id()));
    CASE_EXPECT_EQ(nullptr, node1->get_endpoint(node2->get_id()));

    CASE_EXPECT_TRUE(recv_msg_history.status == EN_ATBUS_ERR_ACCESS_DENY || recv_msg_history.status == -604);
  }

  unit_test_setup_exit(&ev_loop);
}

CASE_TEST(atbus_node_reg, reg_failed_with_missing_access_token) {
  atbus::node::conf_t conf1;
  atbus::node::conf_t conf2;
  atbus::node::default_conf(&conf1);
  atbus::node::default_conf(&conf2);
  {
    conf1.access_tokens.push_back(std::vector<unsigned char>());
    unsigned char access_token1[] = "test access token";
    conf1.access_tokens.back().assign(access_token1, access_token1 + sizeof(access_token1) - 1);
  }
  uv_loop_t ev_loop;
  uv_loop_init(&ev_loop);

  conf1.ev_loop = &ev_loop;
  conf2.ev_loop = &ev_loop;

  {
    atbus::node::ptr_t node1 = atbus::node::create();
    atbus::node::ptr_t node2 = atbus::node::create();
    setup_atbus_node_logger(*node1);
    setup_atbus_node_logger(*node2);

    CASE_EXPECT_EQ(EN_ATBUS_ERR_NOT_INITED, node1->start());
    CASE_EXPECT_EQ(EN_ATBUS_ERR_NOT_INITED, node2->start());

    node1->init(0x12345678, &conf1);
    node2->init(0x12356789, &conf2);

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node1->listen("ipv4://127.0.0.1:10387"));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node2->listen("ipv4://127.0.0.1:10388"));

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node1->start());
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node2->start());

    time_t proc_t = time(nullptr);
    recv_msg_history.status = 0;
    node1->poll();
    node2->poll();
    node1->proc(unit_test_make_timepoint(proc_t + 1, 0));
    node1->proc(unit_test_make_timepoint(proc_t + 1, 1));
    node2->proc(unit_test_make_timepoint(proc_t + 1, 0));
    node2->proc(unit_test_make_timepoint(proc_t + 1, 1));

    // 连接兄弟节点回调测试
    int check_ep_count = recv_msg_history.register_failed_count;
    node1->set_on_add_endpoint_handle(node_reg_test_add_endpoint_fn);
    node1->set_on_remove_endpoint_handle(node_reg_test_remove_endpoint_fn);
    node2->set_on_add_endpoint_handle(node_reg_test_add_endpoint_fn);
    node2->set_on_remove_endpoint_handle(node_reg_test_remove_endpoint_fn);

    node1->connect("ipv4://127.0.0.1:10388");

    UNITTEST_WAIT_MS(&ev_loop, 500, 0) {}
    // in windows CI, connection will be closed sometimes, it will lead to add one endpoint more than one times
    CASE_EXPECT_LE(check_ep_count + 2, recv_msg_history.register_failed_count);

    CASE_EXPECT_EQ(nullptr, node2->get_endpoint(node1->get_id()));
    CASE_EXPECT_EQ(nullptr, node1->get_endpoint(node2->get_id()));

    CASE_EXPECT_TRUE(recv_msg_history.status == EN_ATBUS_ERR_ACCESS_DENY || recv_msg_history.status == -604);
  }

  unit_test_setup_exit(&ev_loop);
}

CASE_TEST(atbus_node_reg, reg_failed_with_unsupported) {
  atbus::node::conf_t conf1;
  atbus::node::conf_t conf2;
  atbus::node::default_conf(&conf1);
  atbus::node::default_conf(&conf2);
  uv_loop_t ev_loop;
  uv_loop_init(&ev_loop);

  conf1.ev_loop = &ev_loop;
  conf2.ev_loop = &ev_loop;

  {
    atbus::node::ptr_t node1 = atbus::node::create();
    atbus::node::ptr_t node2 = atbus::node::create();
    setup_atbus_node_logger(*node1);
    setup_atbus_node_logger(*node2);

    CASE_EXPECT_EQ(EN_ATBUS_ERR_NOT_INITED, node1->start());
    CASE_EXPECT_EQ(EN_ATBUS_ERR_NOT_INITED, node2->start());

    node1->init(0x12345678, &conf1);
    node2->init(0x12356789, &conf2);

    CASE_EXPECT_EQ(atbus::protocol::ATBUS_PROTOCOL_MINIMAL_VERSION, node1->get_protocol_minimal_version());
    CASE_EXPECT_EQ(atbus::protocol::ATBUS_PROTOCOL_VERSION, node1->get_protocol_version());

    // reset protocol version to unsupported
    const_cast<atbus::node::conf_t &>(node1->get_conf()).protocol_version =
        atbus::protocol::ATBUS_PROTOCOL_MINIMAL_VERSION - 1;

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node1->listen("ipv4://127.0.0.1:10387"));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node2->listen("ipv4://127.0.0.1:10388"));

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node1->start());
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node2->start());

    time_t proc_t = time(nullptr);
    recv_msg_history.status = 0;
    node1->poll();
    node2->poll();
    node1->proc(unit_test_make_timepoint(proc_t + 1, 0));
    node1->proc(unit_test_make_timepoint(proc_t + 1, 1));
    node2->proc(unit_test_make_timepoint(proc_t + 1, 0));
    node2->proc(unit_test_make_timepoint(proc_t + 1, 1));

    // 连接兄弟节点回调测试
    int check_ep_count = recv_msg_history.register_failed_count;
    node1->set_on_add_endpoint_handle(node_reg_test_add_endpoint_fn);
    node1->set_on_remove_endpoint_handle(node_reg_test_remove_endpoint_fn);
    node2->set_on_add_endpoint_handle(node_reg_test_add_endpoint_fn);
    node2->set_on_remove_endpoint_handle(node_reg_test_remove_endpoint_fn);

    node1->connect("ipv4://127.0.0.1:10388");

    UNITTEST_WAIT_MS(&ev_loop, 500, 0) {}
    // in windows CI, connection will be closed sometimes, it will lead to add one endpoint more than one times
    CASE_EXPECT_LE(check_ep_count + 1, recv_msg_history.register_failed_count);

    CASE_EXPECT_EQ(nullptr, node2->get_endpoint(node1->get_id()));
    CASE_EXPECT_EQ(nullptr, node1->get_endpoint(node2->get_id()));

    CASE_EXPECT_TRUE(recv_msg_history.status == EN_ATBUS_ERR_UNSUPPORTED_VERSION || recv_msg_history.status == -604);
  }

  unit_test_setup_exit(&ev_loop);
}

// 被动析构流程测试
CASE_TEST(atbus_node_reg, destruct) {
  atbus::node::conf_t conf;
  atbus::node::default_conf(&conf);
  conf.message_size = 256 * 1024;
  uv_loop_t ev_loop;
  uv_loop_init(&ev_loop);

  conf.ev_loop = &ev_loop;

  {
    atbus::node::ptr_t node1 = atbus::node::create();
    atbus::node::ptr_t node2 = atbus::node::create();
    setup_atbus_node_logger(*node1);
    setup_atbus_node_logger(*node2);

    CASE_EXPECT_EQ(EN_ATBUS_ERR_NOT_INITED, node1->listen("ipv4://127.0.0.1:16387"));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_NOT_INITED, node1->connect("ipv4://127.0.0.1:16388"));
    {
      atbus::node::send_data_options_t options;
      options.flags |=
          static_cast<decltype(options.flags)>(atbus::node::send_data_options_t::flag_type::kRequireResponse);
      CASE_EXPECT_EQ(EN_ATBUS_ERR_NOT_INITED,
                     node1->send_data(0x12345678, 213, gsl::span<const unsigned char>(), options));
    }

    node1->init(0x12345678, &conf);
    node2->init(0x12356789, &conf);

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node1->listen("ipv4://127.0.0.1:16387"));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node2->listen("ipv4://127.0.0.1:16388"));

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node1->start());
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node2->start());

    time_t proc_t = time(nullptr);
    node1->poll();
    node2->poll();
    node1->proc(unit_test_make_timepoint(proc_t + 1, 0));
    node2->proc(unit_test_make_timepoint(proc_t + 1, 0));

    node1->connect("ipv4://127.0.0.1:16388");

    UNITTEST_WAIT_UNTIL(conf.ev_loop,
                        node1->is_endpoint_available(node2->get_id()) && node2->is_endpoint_available(node1->get_id()),
                        8000, 0) {}

    {
      atbus::node::send_data_options_t options;
      options.flags |=
          static_cast<decltype(options.flags)>(atbus::node::send_data_options_t::flag_type::kRequireResponse);
      CASE_EXPECT_EQ(EN_ATBUS_ERR_INVALID_SIZE,
                     node1->send_data(0x12345678, 213,
                                      gsl::span<const unsigned char>(reinterpret_cast<const unsigned char *>(&conf),
                                                                     conf.message_size + 1),
                                      options));
    }

    for (int i = 0; i < 16; ++i) {
      uv_run(conf.ev_loop, UV_RUN_NOWAIT);
      CASE_THREAD_SLEEP_MS(4);
    }

    // reset strong_rc_ptr and delete it
    node1.reset();

    ++proc_t;
    UNITTEST_WAIT_UNTIL(conf.ev_loop, nullptr == node2->get_endpoint(0x12345678), 8000, 64) {
      ++proc_t;

      node2->proc(unit_test_make_timepoint(proc_t, 0));
    }

    CASE_EXPECT_EQ(nullptr, node2->get_endpoint(0x12345678));
  }

  unit_test_setup_exit(&ev_loop);
}

// 注册成功流程测试 - 上下游
CASE_TEST(atbus_node_reg, reg_pc_success) {
  atbus::node::conf_t conf;
  atbus::node::default_conf(&conf);
  uv_loop_t ev_loop;
  uv_loop_init(&ev_loop);

  conf.ev_loop = &ev_loop;

  int check_ep_rm = recv_msg_history.remove_endpoint_count;
  {
    int old_register_count = recv_msg_history.register_count;
    int old_available_count = recv_msg_history.availavle_count;

    atbus::node::ptr_t node_upstream = atbus::node::create();
    atbus::node::ptr_t node_downstream = atbus::node::create();
    setup_atbus_node_logger(*node_upstream);
    setup_atbus_node_logger(*node_downstream);
    node_upstream->set_on_register_handle(node_reg_test_on_register_fn);
    node_upstream->set_on_available_handle(node_reg_test_on_available_fn);

    node_downstream->set_on_register_handle(node_reg_test_on_register_fn);
    node_downstream->set_on_available_handle(node_reg_test_on_available_fn);
    CASE_EXPECT_TRUE(!!node_downstream->get_on_register_handle());
    CASE_EXPECT_TRUE(!!node_downstream->get_on_available_handle());

    node_upstream->init(0x12345678, &conf);

    conf.upstream_address = "ipv4://127.0.0.1:16387";
    node_downstream->init(0x12346789, &conf);

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream->listen("ipv4://127.0.0.1:16387"));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_downstream->listen("ipv4://127.0.0.1:16388"));

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream->start());
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_downstream->start());

    CASE_EXPECT_EQ(old_register_count, recv_msg_history.register_count);
    CASE_EXPECT_EQ(old_available_count + 1, recv_msg_history.availavle_count);

    // 上下游节点注册回调测试
    int check_ep_count = recv_msg_history.add_endpoint_count;
    node_upstream->set_on_add_endpoint_handle(node_reg_test_add_endpoint_fn);
    CASE_EXPECT_TRUE(!!node_upstream->get_on_add_endpoint_handle());
    node_upstream->set_on_remove_endpoint_handle(node_reg_test_remove_endpoint_fn);
    CASE_EXPECT_TRUE(!!node_upstream->get_on_remove_endpoint_handle());
    node_downstream->set_on_add_endpoint_handle(node_reg_test_add_endpoint_fn);
    node_downstream->set_on_remove_endpoint_handle(node_reg_test_remove_endpoint_fn);

    time_t proc_t_start_sec = time(nullptr);
    time_t proc_t_sec = proc_t_start_sec;
    time_t proc_t_usec = 0;
    node_upstream->poll();
    node_downstream->poll();

    ++proc_t_sec;
    node_upstream->proc(unit_test_make_timepoint(proc_t_sec, proc_t_usec));
    node_downstream->proc(unit_test_make_timepoint(proc_t_sec, proc_t_usec));

    // 注册成功自动会有可用的端点
    UNITTEST_WAIT_UNTIL(conf.ev_loop,
                        node_downstream->is_endpoint_available(node_upstream->get_id()) &&
                            node_upstream->is_endpoint_available(node_downstream->get_id()),
                        8000, 8) {
      proc_t_usec += 8000;
      if (proc_t_usec >= 1000000) {
        proc_t_usec = 0;
        ++proc_t_sec;
      }
      node_upstream->proc(unit_test_make_timepoint(proc_t_sec, proc_t_usec));
      node_downstream->proc(unit_test_make_timepoint(proc_t_sec, proc_t_usec));
    }

    // in windows CI, connection will be closed sometimes, it will lead to add one endpoint more than one times
    CASE_EXPECT_LE(check_ep_count + 2, recv_msg_history.add_endpoint_count);
    CASE_EXPECT_LE(old_register_count + 2, recv_msg_history.register_count);
    CASE_EXPECT_LE(old_available_count + 2, recv_msg_history.availavle_count);

    // API - test
    {
      atbus::endpoint *test_ep = nullptr;
      atbus::connection *test_conn = nullptr;
      atbus::topology_peer::ptr_t next_hop;
      node_upstream->get_peer_channel(node_downstream->get_id(), &atbus::endpoint::get_data_connection, &test_ep,
                                      &test_conn, &next_hop);
      CASE_EXPECT_NE(nullptr, test_ep);
      CASE_EXPECT_NE(nullptr, test_conn);
      if (nullptr != test_ep) {
        auto created_time = test_ep->get_stat_created_time();
        auto created_usec =
            std::chrono::duration_cast<std::chrono::microseconds>(created_time.time_since_epoch()).count();
        CASE_EXPECT_GE(created_usec, static_cast<int64_t>(proc_t_start_sec) * 1000000);

        CASE_EXPECT_FALSE(test_ep->get_hash_code().empty());
        CASE_EXPECT_EQ(node_downstream->get_self_endpoint()->get_hash_code(), test_ep->get_hash_code());
      }
      node_upstream->get_topology_registry()->update_peer(node_downstream->get_id(), node_upstream->get_id(), nullptr);
      next_hop.reset();
      CASE_EXPECT_EQ(static_cast<int>(atbus::topology_relation_type::kImmediateDownstream),
                     static_cast<int>(node_upstream->get_topology_relation(node_downstream->get_id(), &next_hop)));
      CASE_EXPECT_TRUE(next_hop);
      if (next_hop) {
        CASE_EXPECT_EQ(node_downstream->get_id(), next_hop->get_bus_id());
      }
      atbus::endpoint *route_ep = nullptr;
      atbus::connection *route_conn = nullptr;
      atbus::topology_peer::ptr_t route_next_hop;
      CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS,
                     node_upstream->get_peer_channel(node_downstream->get_id(), &atbus::endpoint::get_data_connection,
                                                     &route_ep, &route_conn, &route_next_hop));
      CASE_EXPECT_NE(nullptr, route_ep);
      CASE_EXPECT_NE(nullptr, route_conn);
      CASE_EXPECT_TRUE(route_next_hop);
      if (route_next_hop) {
        CASE_EXPECT_EQ(node_downstream->get_id(), route_next_hop->get_bus_id());
      }
    }

    // API - test
    {
      atbus::endpoint *test_ep = nullptr;
      atbus::connection *test_conn = nullptr;
      atbus::topology_peer::ptr_t next_hop;
      node_downstream->get_peer_channel(node_upstream->get_id(), &atbus::endpoint::get_data_connection, &test_ep,
                                        &test_conn, &next_hop);
      CASE_EXPECT_NE(nullptr, test_ep);
      CASE_EXPECT_NE(nullptr, test_conn);
      if (nullptr != test_ep) {
        auto created_time = test_ep->get_stat_created_time();
        auto created_usec =
            std::chrono::duration_cast<std::chrono::microseconds>(created_time.time_since_epoch()).count();
        CASE_EXPECT_GE(created_usec, static_cast<int64_t>(proc_t_start_sec) * 1000000);
        CASE_EXPECT_FALSE(test_ep->get_hash_code().empty());
        CASE_EXPECT_EQ(node_upstream->get_self_endpoint()->get_hash_code(), test_ep->get_hash_code());
      }
      next_hop.reset();
      CASE_EXPECT_EQ(static_cast<int>(atbus::topology_relation_type::kImmediateUpstream),
                     static_cast<int>(node_downstream->get_topology_relation(node_upstream->get_id(), &next_hop)));
      CASE_EXPECT_TRUE(next_hop);
      if (next_hop) {
        CASE_EXPECT_EQ(node_upstream->get_id(), next_hop->get_bus_id());
      }
      atbus::endpoint *route_ep = nullptr;
      atbus::connection *route_conn = nullptr;
      atbus::topology_peer::ptr_t route_next_hop;
      CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS,
                     node_downstream->get_peer_channel(node_upstream->get_id(), &atbus::endpoint::get_data_connection,
                                                       &route_ep, &route_conn, &route_next_hop));
      CASE_EXPECT_NE(nullptr, route_ep);
      CASE_EXPECT_NE(nullptr, route_conn);
      CASE_EXPECT_TRUE(route_next_hop);
      if (route_next_hop) {
        CASE_EXPECT_EQ(node_upstream->get_id(), route_next_hop->get_bus_id());
      }
    }

    // disconnect - upstream and downstream
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream->disconnect(0x12346789));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_ATNODE_NOT_FOUND, node_upstream->disconnect(0x12346789));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_downstream->disconnect(0x12345678));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_ATNODE_NOT_FOUND, node_downstream->disconnect(0x12345678));
  }

  unit_test_setup_exit(&ev_loop);

  CASE_EXPECT_LE(check_ep_rm + 2, recv_msg_history.remove_endpoint_count);
}

// 注册成功流程测试 - 上下游(跨子网)
CASE_TEST(atbus_node_reg, reg_pc_success_cross_subnet) {
  atbus::node::conf_t conf;
  atbus::node::default_conf(&conf);
  uv_loop_t ev_loop;
  uv_loop_init(&ev_loop);

  conf.ev_loop = &ev_loop;

  int check_ep_rm = recv_msg_history.remove_endpoint_count;
  {
    int old_register_count = recv_msg_history.register_count;
    int old_available_count = recv_msg_history.availavle_count;

    atbus::node::ptr_t node_upstream = atbus::node::create();
    atbus::node::ptr_t node_downstream = atbus::node::create();
    setup_atbus_node_logger(*node_upstream);
    setup_atbus_node_logger(*node_downstream);
    node_upstream->set_on_register_handle(node_reg_test_on_register_fn);
    node_upstream->set_on_available_handle(node_reg_test_on_available_fn);

    node_downstream->set_on_register_handle(node_reg_test_on_register_fn);
    node_downstream->set_on_available_handle(node_reg_test_on_available_fn);
    CASE_EXPECT_TRUE(!!node_downstream->get_on_register_handle());
    CASE_EXPECT_TRUE(!!node_downstream->get_on_available_handle());

    node_upstream->init(0x12345678, &conf);

    conf.upstream_address = "ipv4://127.0.0.1:16387";
    node_downstream->init(0x22346789, &conf);

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream->listen("ipv4://127.0.0.1:16387"));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_downstream->listen("ipv4://127.0.0.1:16388"));

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream->start());
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_downstream->start());

    CASE_EXPECT_EQ(old_register_count, recv_msg_history.register_count);
    CASE_EXPECT_EQ(old_available_count + 1, recv_msg_history.availavle_count);

    // 上下游节点注册回调测试
    int check_ep_count = recv_msg_history.add_endpoint_count;
    node_upstream->set_on_add_endpoint_handle(node_reg_test_add_endpoint_fn);
    CASE_EXPECT_TRUE(!!node_upstream->get_on_add_endpoint_handle());
    node_upstream->set_on_remove_endpoint_handle(node_reg_test_remove_endpoint_fn);
    CASE_EXPECT_TRUE(!!node_upstream->get_on_remove_endpoint_handle());
    node_downstream->set_on_add_endpoint_handle(node_reg_test_add_endpoint_fn);
    node_downstream->set_on_remove_endpoint_handle(node_reg_test_remove_endpoint_fn);

    time_t proc_t = time(nullptr);
    node_upstream->poll();
    node_downstream->poll();
    node_upstream->proc(unit_test_make_timepoint(proc_t + 1, 0));
    node_downstream->proc(unit_test_make_timepoint(proc_t + 1, 0));

    // 注册成功自动会有可用的端点
    UNITTEST_WAIT_UNTIL(conf.ev_loop,
                        node_downstream->is_endpoint_available(node_upstream->get_id()) &&
                            node_upstream->is_endpoint_available(node_downstream->get_id()),
                        8000, 0) {}

    // in windows CI, connection will be closed sometimes, it will lead to add one endpoint more than one times
    CASE_EXPECT_LE(check_ep_count + 2, recv_msg_history.add_endpoint_count);
    CASE_EXPECT_LE(old_register_count + 2, recv_msg_history.register_count);
    CASE_EXPECT_LE(old_available_count + 2, recv_msg_history.availavle_count);

    // API - test
    {
      atbus::endpoint *test_ep = nullptr;
      atbus::connection *test_conn = nullptr;
      atbus::topology_peer::ptr_t next_hop;
      node_upstream->get_peer_channel(node_downstream->get_id(), &atbus::endpoint::get_data_connection, &test_ep,
                                      &test_conn, &next_hop);
      CASE_EXPECT_NE(nullptr, test_ep);
      CASE_EXPECT_NE(nullptr, test_conn);
      CASE_EXPECT_TRUE(!next_hop || next_hop->get_bus_id() == node_downstream->get_id());
    }

    // API - test
    {
      atbus::endpoint *test_ep = nullptr;
      atbus::connection *test_conn = nullptr;
      atbus::topology_peer::ptr_t next_hop;
      node_downstream->get_peer_channel(node_upstream->get_id(), &atbus::endpoint::get_data_connection, &test_ep,
                                        &test_conn, &next_hop);
      CASE_EXPECT_NE(nullptr, test_ep);
      CASE_EXPECT_NE(nullptr, test_conn);
      CASE_EXPECT_TRUE(!next_hop || next_hop->get_bus_id() == node_upstream->get_id());
    }

    // disconnect - upstream and downstream
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream->disconnect(0x22346789));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_ATNODE_NOT_FOUND, node_upstream->disconnect(0x22346789));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_downstream->disconnect(0x12345678));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_ATNODE_NOT_FOUND, node_downstream->disconnect(0x12345678));
  }

  unit_test_setup_exit(&ev_loop);

  CASE_EXPECT_LE(check_ep_rm + 2, recv_msg_history.remove_endpoint_count);
}

// 注册失败流程测试 - 上下游subnet不匹配
CASE_TEST(atbus_node_reg, reg_pc_failed_with_subnet_mismatch) {
  atbus::node::conf_t conf;
  atbus::node::default_conf(&conf);
  uv_loop_t ev_loop;
  uv_loop_init(&ev_loop);

  conf.ev_loop = &ev_loop;
  {
    int old_register_count = recv_msg_history.register_count;
    int old_available_count = recv_msg_history.availavle_count;

    atbus::node::ptr_t node_upstream = atbus::node::create();
    atbus::node::ptr_t node_downstream = atbus::node::create();
    setup_atbus_node_logger(*node_upstream);
    setup_atbus_node_logger(*node_downstream);
    node_upstream->set_on_register_handle(node_reg_test_on_register_fn);
    node_upstream->set_on_available_handle(node_reg_test_on_available_fn);

    node_downstream->set_on_register_handle(node_reg_test_on_register_fn);
    node_downstream->set_on_available_handle(node_reg_test_on_available_fn);
    CASE_EXPECT_TRUE(!!node_downstream->get_on_register_handle());
    CASE_EXPECT_TRUE(!!node_downstream->get_on_available_handle());

    node_upstream->init(0x12345678, &conf);

    conf.upstream_address = "ipv4://127.0.0.1:16387";
    node_downstream->init(0x12346789, &conf);

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream->listen("ipv4://127.0.0.1:16387"));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_downstream->listen("ipv4://127.0.0.1:16388"));

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream->start());
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_downstream->start());

    CASE_EXPECT_EQ(old_register_count, recv_msg_history.register_count);
    CASE_EXPECT_EQ(old_available_count + 1, recv_msg_history.availavle_count);

    // 上下游节点注册回调测试
    int check_ep_count = recv_msg_history.add_endpoint_count;
    node_upstream->set_on_add_endpoint_handle(node_reg_test_add_endpoint_fn);
    CASE_EXPECT_TRUE(!!node_upstream->get_on_add_endpoint_handle());
    node_upstream->set_on_remove_endpoint_handle(node_reg_test_remove_endpoint_fn);
    CASE_EXPECT_TRUE(!!node_upstream->get_on_remove_endpoint_handle());
    node_downstream->set_on_add_endpoint_handle(node_reg_test_add_endpoint_fn);
    node_downstream->set_on_remove_endpoint_handle(node_reg_test_remove_endpoint_fn);

    time_t proc_t = time(nullptr);
    node_upstream->poll();
    node_downstream->poll();
    ++proc_t;
    node_upstream->proc(unit_test_make_timepoint(proc_t, 0));
    node_downstream->proc(unit_test_make_timepoint(proc_t, 0));

    // 注册成功自动会有可用的端点
    time_t proc_us = 0;
    UNITTEST_WAIT_UNTIL(conf.ev_loop,
                        node_downstream->is_endpoint_available(node_upstream->get_id()) &&
                            node_upstream->is_endpoint_available(node_downstream->get_id()),
                        8000, 4) {
      proc_us += 4000;
      if (proc_us >= 1000000) {
        ++proc_t;
        proc_us = 0;
      }
      node_upstream->proc(unit_test_make_timepoint(proc_t, proc_us));
      node_downstream->proc(unit_test_make_timepoint(proc_t, proc_us));
    }

    node_upstream->proc(unit_test_make_timepoint(proc_t, proc_us));
    node_downstream->proc(unit_test_make_timepoint(proc_t, proc_us));

    // in windows CI, connection will be closed sometimes, it will lead to add one endpoint more than one times
    CASE_EXPECT_TRUE(
        static_cast<uint32_t>(node_downstream->get_state()) == static_cast<uint32_t>(atbus::node::state_t::kCreated) ||
        static_cast<uint32_t>(node_downstream->get_state()) == static_cast<uint32_t>(atbus::node::state_t::kRunning));
    CASE_EXPECT_LE(check_ep_count, recv_msg_history.add_endpoint_count);
    CASE_EXPECT_LE(old_register_count, recv_msg_history.register_count);
    CASE_EXPECT_LE(old_available_count, recv_msg_history.availavle_count);

    // API - test
    {
      atbus::endpoint *test_ep = nullptr;
      atbus::connection *test_conn = nullptr;
      atbus::topology_peer::ptr_t next_hop;
      node_upstream->get_peer_channel(node_downstream->get_id(), &atbus::endpoint::get_data_connection, &test_ep,
                                      &test_conn, &next_hop);
      CASE_EXPECT_NE(nullptr, test_ep);
      CASE_EXPECT_NE(nullptr, test_conn);
    }

    // API - test
    {
      atbus::endpoint *test_ep = nullptr;
      atbus::connection *test_conn = nullptr;
      atbus::topology_peer::ptr_t next_hop;
      node_downstream->get_peer_channel(node_upstream->get_id(), &atbus::endpoint::get_data_connection, &test_ep,
                                        &test_conn, &next_hop);
      CASE_EXPECT_NE(nullptr, test_ep);
      CASE_EXPECT_NE(nullptr, test_conn);
    }

    CASE_MSG_INFO() << "atbus_node_reg.reg_pc_failed_with_subnet_mismatch done." << '\n';
    // disconnect - upstream and downstream
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream->disconnect(0x12346789));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_ATNODE_NOT_FOUND, node_upstream->disconnect(0x12346789));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_downstream->disconnect(0x12345678));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_ATNODE_NOT_FOUND, node_downstream->disconnect(0x12345678));
  }

  unit_test_setup_exit(&ev_loop);
}

// 注册成功流程测试 - 兄弟
CASE_TEST(atbus_node_reg, reg_bro_success) {
  atbus::node::conf_t conf;
  atbus::node::default_conf(&conf);
  uv_loop_t ev_loop;
  uv_loop_init(&ev_loop);

  conf.ev_loop = &ev_loop;

  int check_ep_rm = recv_msg_history.remove_endpoint_count;
  {
    atbus::node::ptr_t node_1 = atbus::node::create();
    atbus::node::ptr_t node_2 = atbus::node::create();
    setup_atbus_node_logger(*node_1);
    setup_atbus_node_logger(*node_2);

    node_1->init(0x12345678, &conf);
    node_2->init(0x12356789, &conf);

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_1->listen("ipv4://127.0.0.1:16387"));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_2->listen("ipv4://127.0.0.1:16388"));

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_1->start());
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_2->start());

    // 兄弟节点注册回调测试
    int check_ep_count = recv_msg_history.add_endpoint_count;
    node_1->set_on_add_endpoint_handle(node_reg_test_add_endpoint_fn);
    node_1->set_on_remove_endpoint_handle(node_reg_test_remove_endpoint_fn);
    node_2->set_on_add_endpoint_handle(node_reg_test_add_endpoint_fn);
    node_2->set_on_remove_endpoint_handle(node_reg_test_remove_endpoint_fn);

    time_t proc_t = time(nullptr);
    node_1->poll();
    node_2->poll();
    node_1->proc(unit_test_make_timepoint(proc_t + 1, 0));
    node_2->proc(unit_test_make_timepoint(proc_t + 1, 0));

    node_1->connect("ipv4://127.0.0.1:16388");

    // 注册成功自动会有可用的端点
    UNITTEST_WAIT_UNTIL(
        conf.ev_loop,
        node_2->is_endpoint_available(node_1->get_id()) && node_1->is_endpoint_available(node_2->get_id()), 8000, 0) {}

    CASE_EXPECT_TRUE(node_2->is_endpoint_available(node_1->get_id()));
    CASE_EXPECT_TRUE(node_1->is_endpoint_available(node_2->get_id()));
    // in windows CI, connection will be closed sometimes, it will lead to add one endpoint more than one times
    CASE_EXPECT_LE(check_ep_count + 2, recv_msg_history.add_endpoint_count);

    // API - test
    {
      atbus::endpoint *test_ep = nullptr;
      atbus::connection *test_conn = nullptr;
      atbus::topology_peer::ptr_t next_hop;
      node_1->get_peer_channel(node_2->get_id(), &atbus::endpoint::get_data_connection, &test_ep, &test_conn,
                               &next_hop);
      CASE_EXPECT_NE(nullptr, test_ep);
      CASE_EXPECT_NE(nullptr, test_conn);
    }

    // API - test
    {
      atbus::endpoint *test_ep = nullptr;
      atbus::connection *test_conn = nullptr;
      atbus::topology_peer::ptr_t next_hop;
      node_2->get_peer_channel(node_1->get_id(), &atbus::endpoint::get_data_connection, &test_ep, &test_conn,
                               &next_hop);
      CASE_EXPECT_NE(nullptr, test_ep);
      CASE_EXPECT_NE(nullptr, test_conn);
    }

    // disconnect - upstream and downstream
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_1->disconnect(0x12356789));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_ATNODE_NOT_FOUND, node_1->disconnect(0x12356789));
  }

  unit_test_setup_exit(&ev_loop);

  CASE_EXPECT_LE(check_ep_rm + 2, recv_msg_history.remove_endpoint_count);
}

static int g_node_test_on_shutdown_check_reason = 0;
static int node_test_on_shutdown(const atbus::node &, int reason) {
  if (0 == g_node_test_on_shutdown_check_reason) {
    ++g_node_test_on_shutdown_check_reason;
  } else {
    CASE_EXPECT_EQ(reason, g_node_test_on_shutdown_check_reason);
    g_node_test_on_shutdown_check_reason = 0;
  }

  return 0;
}

// 注册到上游节点失败导致下线的流程测试
// 注册到下游节点失败不会导致下线的流程测试
CASE_TEST(atbus_node_reg, conflict) {
  atbus::node::conf_t conf;
  atbus::node::default_conf(&conf);
  uv_loop_t ev_loop;
  uv_loop_init(&ev_loop);

  conf.ev_loop = &ev_loop;

  // 只有发生冲突才会注册不成功，否则会无限重试注册上游节点，直到其上线
  {
    atbus::node::ptr_t node_upstream = atbus::node::create();
    atbus::node::ptr_t node_downstream = atbus::node::create();
    atbus::node::ptr_t node_downstream_fail = atbus::node::create();
    setup_atbus_node_logger(*node_upstream);
    setup_atbus_node_logger(*node_downstream);
    setup_atbus_node_logger(*node_downstream_fail);

    node_upstream->init(0x12345678, &conf);

    conf.upstream_address = "ipv4://127.0.0.1:16387";
    node_downstream->init(0x12346789, &conf);
    // 子域冲突，注册失败
    node_downstream_fail->init(0x12346780, &conf);

    node_downstream->set_on_shutdown_handle(node_test_on_shutdown);
    CASE_EXPECT_TRUE(!!node_downstream->get_on_shutdown_handle());
    node_downstream_fail->set_on_shutdown_handle(node_test_on_shutdown);
    g_node_test_on_shutdown_check_reason = EN_ATBUS_ERR_ATNODE_INVALID_ID;

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream->listen("ipv4://127.0.0.1:16387"));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_downstream->listen("ipv4://127.0.0.1:16388"));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_downstream_fail->listen("ipv4://127.0.0.1:16389"));

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream->start());
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_downstream->start());
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_downstream_fail->start());

    time_t proc_t = time(nullptr) + 1;
    // 必然有一个失败的
    UNITTEST_WAIT_UNTIL(conf.ev_loop,
                        atbus::node::state_t::kCreated != node_downstream->get_state() &&
                            atbus::node::state_t::kCreated != node_downstream_fail->get_state(),
                        8000, 64) {
      node_upstream->proc(unit_test_make_timepoint(proc_t, 0));
      node_downstream->proc(unit_test_make_timepoint(proc_t, 0));
      node_downstream_fail->proc(unit_test_make_timepoint(proc_t, 0));
      proc_t += static_cast<time_t>(conf.retry_interval.count() / 1000000);
    }

    for (int i = 0; i < 64; ++i) {
      CASE_THREAD_SLEEP_MS(4);
      uv_run(&ev_loop, UV_RUN_NOWAIT);
    }

    // 注册到下游节点失败不会导致下线的流程测试
    CASE_EXPECT_TRUE(static_cast<uint32_t>(node_downstream->get_state()) ==
                         static_cast<uint32_t>(atbus::node::state_t::kRunning) ||
                     static_cast<uint32_t>(node_downstream_fail->get_state()) ==
                         static_cast<uint32_t>(atbus::node::state_t::kRunning));
    CASE_EXPECT_EQ(static_cast<uint32_t>(atbus::node::state_t::kRunning),
                   static_cast<uint32_t>(node_upstream->get_state()));
  }

  unit_test_setup_exit(&ev_loop);
}

// 对上游节点重连失败不会导致下线的流程测试
// 对上游节点断线重连的流程测试
CASE_TEST(atbus_node_reg, reconnect_upstream_failed) {
  atbus::node::conf_t conf;
  atbus::node::default_conf(&conf);
  uv_loop_t ev_loop;
  uv_loop_init(&ev_loop);

  conf.ev_loop = &ev_loop;

  // 只有发生冲突才会注册不成功，否则会无限重试注册上游节点，直到其上线
  {
    atbus::node::ptr_t node_upstream = atbus::node::create();
    atbus::node::ptr_t node_downstream = atbus::node::create();
    setup_atbus_node_logger(*node_upstream);
    setup_atbus_node_logger(*node_downstream);

    node_upstream->init(0x12345678, &conf);

    conf.upstream_address = "ipv4://127.0.0.1:16387";
    node_downstream->init(0x12346789, &conf);

    node_downstream->set_on_shutdown_handle(node_test_on_shutdown);
    g_node_test_on_shutdown_check_reason = EN_ATBUS_ERR_ATNODE_INVALID_ID;

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream->listen("ipv4://127.0.0.1:16387"));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_downstream->listen("ipv4://127.0.0.1:16388"));

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream->start());
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_downstream->start());

    time_t proc_t = time(nullptr) + 1;
    // 先等连接成功
    UNITTEST_WAIT_UNTIL(conf.ev_loop, atbus::node::state_t::kRunning == node_downstream->get_state(), 8000, 64) {
      node_upstream->proc(unit_test_make_timepoint(proc_t, 0));
      node_downstream->proc(unit_test_make_timepoint(proc_t, 0));
      ++proc_t;
    }

    // 关闭上游节点
    node_upstream->reset();

    // 重连上游节点，但是连接不成功也不会导致下线
    // 连接过程中的转态变化
    size_t retry_times = 0;
    UNITTEST_WAIT_IF(conf.ev_loop, atbus::node::state_t::kRunning == node_downstream->get_state() || retry_times < 16,
                     8000, 64) {
      proc_t += static_cast<time_t>(conf.retry_interval.count() / 1000000) + 1;

      node_downstream->proc(unit_test_make_timepoint(proc_t, 0));

      if (atbus::node::state_t::kRunning != node_downstream->get_state()) {
        ++retry_times;
        CASE_EXPECT_TRUE(static_cast<uint32_t>(node_downstream->get_state()) ==
                             static_cast<uint32_t>(atbus::node::state_t::kLostUpstream) ||
                         static_cast<uint32_t>(node_downstream->get_state()) ==
                             static_cast<uint32_t>(atbus::node::state_t::kConnectingUpstream));
        CASE_EXPECT_NE(static_cast<uint32_t>(atbus::node::state_t::kCreated),
                       static_cast<uint32_t>(node_downstream->get_state()));
        CASE_EXPECT_NE(static_cast<uint32_t>(atbus::node::state_t::kInited),
                       static_cast<uint32_t>(node_downstream->get_state()));
      }

      CASE_THREAD_SLEEP_MS(4);
      uv_run(&ev_loop, UV_RUN_NOWAIT);
      uv_run(&ev_loop, UV_RUN_NOWAIT);
      uv_run(&ev_loop, UV_RUN_NOWAIT);
    }

    // 上游节点断线重连测试
    // 下游节点断线后重新注册测试
    conf.upstream_address = "";
    node_upstream->init(0x12345678, &conf);
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream->listen("ipv4://127.0.0.1:16387"));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream->start());

    UNITTEST_WAIT_IF(conf.ev_loop,
                     atbus::node::state_t::kRunning != node_downstream->get_state() ||
                         nullptr == node_upstream->get_endpoint(node_downstream->get_id()),
                     8000, 64) {
      proc_t += static_cast<time_t>(conf.retry_interval.count() / 1000000);
      node_upstream->proc(unit_test_make_timepoint(proc_t, 0));
      node_downstream->proc(unit_test_make_timepoint(proc_t, 0));
    }

    {
      atbus::endpoint *ep1 = node_downstream->get_endpoint(node_upstream->get_id());
      atbus::endpoint *ep2 = node_upstream->get_endpoint(node_downstream->get_id());

      CASE_EXPECT_NE(nullptr, ep1);
      CASE_EXPECT_NE(nullptr, ep2);
      CASE_EXPECT_EQ(static_cast<uint32_t>(atbus::node::state_t::kRunning),
                     static_cast<uint32_t>(node_downstream->get_state()));
    }

    // 注册到子节点失败不会导致下线的流程测试
    CASE_EXPECT_EQ(static_cast<uint32_t>(atbus::node::state_t::kRunning),
                   static_cast<uint32_t>(node_upstream->get_state()));
  }

  unit_test_setup_exit(&ev_loop);
}

// 上游节点上报的通道地址对下游不可达时的注册流程测试
// 用 set_self_hostname 模拟双方处于不同物理机：上游只监听本机回环地址，下游对 127.0.0.1 的地址会按跨机地址跳过，
// 下游即无法建立数据通道。期望行为（当前实现不满足，此用例用于重现失败）：
// 注册完成后上游端点应保持可用，而不是因没有数据通道被回收并不断重连。
CASE_TEST(atbus_node_reg, reg_pc_success_with_unreachable_upstream_channel) {
  atbus::node::conf_t conf;
  atbus::node::default_conf(&conf);
  uv_loop_t ev_loop;
  uv_loop_init(&ev_loop);

  conf.ev_loop = &ev_loop;

  {
    atbus::node::ptr_t node_upstream = atbus::node::create();
    atbus::node::ptr_t node_downstream = atbus::node::create();
    setup_atbus_node_logger(*node_upstream);
    setup_atbus_node_logger(*node_downstream);

    // 模拟上游和下游处于不同物理机
    node_upstream->set_self_hostname("test-host-a");
    node_downstream->set_self_hostname("test-host-b");

    node_upstream->init(0x12345678, &conf);

    conf.upstream_address = "ipv4://127.0.0.1:16395";
    node_downstream->init(0x12346789, &conf);

    // 上游只监听本机回环地址（对处于其他物理机的下游不可达），下游不监听任何地址
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream->listen("ipv4://127.0.0.1:16395"));

    int old_register_count = recv_msg_history.register_count;
    node_downstream->set_on_register_handle(node_reg_test_on_register_fn);

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream->start());
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_downstream->start());

    time_t proc_sec = time(nullptr) + 1;
    time_t proc_usec = 0;

    // 等待下游完成第一次到上游的注册，每次 proc 推进 100ms 虚拟时间
    UNITTEST_WAIT_UNTIL(conf.ev_loop, recv_msg_history.register_count > old_register_count, 8000, 64) {
      node_upstream->proc(unit_test_make_timepoint(proc_sec, proc_usec));
      node_downstream->proc(unit_test_make_timepoint(proc_sec, proc_usec));
      proc_usec += 100000;
      if (proc_usec >= 1000000) {
        proc_usec -= 1000000;
        ++proc_sec;
      }
    }

    // 注册被接受后，下游会使用 upstream 配置地址异步建立数据通道，等待其完成
    UNITTEST_WAIT_UNTIL(conf.ev_loop, node_downstream->is_endpoint_available(node_upstream->get_id()), 8000, 8) {
      node_upstream->poll();
      node_upstream->proc(unit_test_make_timepoint(proc_sec, proc_usec));
      node_downstream->poll();
      node_downstream->proc(unit_test_make_timepoint(proc_sec, proc_usec));
      proc_usec += 100000;
      if (proc_usec >= 1000000) {
        proc_usec -= 1000000;
        ++proc_sec;
      }
    }

    // 数据通道建立完成后上游端点应该可用
    CASE_EXPECT_NE(nullptr, node_downstream->get_endpoint(node_upstream->get_id()));
    CASE_EXPECT_TRUE(node_downstream->is_endpoint_available(node_upstream->get_id()));

    // 再推进若干次 ping 周期的虚拟时间后，上游端点应该保持存活且可用
    // ping_interval 单位为微秒，每次循环推进 100ms
    time_t wait_tick_count = 2 * static_cast<time_t>(conf.ping_interval.count() / 100000) + 20;
    time_t waited_tick_count = 0;
    UNITTEST_WAIT_UNTIL(conf.ev_loop, waited_tick_count >= wait_tick_count, 30000, 8) {
      proc_usec += 100000;
      if (proc_usec >= 1000000) {
        proc_usec -= 1000000;
        ++proc_sec;
      }
      ++waited_tick_count;
      node_upstream->poll();
      node_upstream->proc(unit_test_make_timepoint(proc_sec, proc_usec));
      node_downstream->poll();
      node_downstream->proc(unit_test_make_timepoint(proc_sec, proc_usec));
    }

    CASE_EXPECT_EQ(static_cast<uint32_t>(atbus::node::state_t::kRunning),
                   static_cast<uint32_t>(node_downstream->get_state()));
    CASE_EXPECT_NE(nullptr, node_downstream->get_endpoint(node_upstream->get_id()));
    CASE_EXPECT_TRUE(node_downstream->is_endpoint_available(node_upstream->get_id()));
  }

  unit_test_setup_exit(&ev_loop);
}

// 上游节点上报通配监听地址(0.0.0.0)且双方处于不同物理机时的注册流程测试
// 用真实上游节点配合注入的 register 回包：对端位于其他物理机，上报的监听地址为不可达的通配地址
// （本进程内 0.0.0.0 会被重定向到 127.0.0.1 对应端口，这里使用无监听的端口模拟跨机不可达）。
// 下游不应使用该地址建立数据通道，而应改用注册连接的已知可达地址。
// 期望行为（当前实现不满足，此用例用于重现失败）：注册完成后上游端点应保持可用，而不是被回收。
CASE_TEST(atbus_node_reg, reg_with_wildcard_upstream_channel_cross_host) {
  atbus::node::conf_t conf;
  atbus::node::default_conf(&conf);
  uv_loop_t ev_loop;
  uv_loop_init(&ev_loop);

  conf.ev_loop = &ev_loop;

  {
    atbus::node::ptr_t node_upstream = atbus::node::create();
    atbus::node::ptr_t node_downstream = atbus::node::create();
    setup_atbus_node_logger(*node_upstream);
    setup_atbus_node_logger(*node_downstream);

    // 模拟上游和下游处于不同物理机
    node_upstream->set_self_hostname("test-host-a");
    node_downstream->set_self_hostname("test-host-b");

    node_upstream->init(0x12345678, &conf);
    // 下游不配置 upstream_address，通过手动连接发起注册
    node_downstream->init(0x12346789, &conf);

    // 上游只监听本机回环地址（对处于其他物理机的下游不可达），下游不监听任何地址
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream->listen("ipv4://127.0.0.1:16396"));

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream->start());
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_downstream->start());

    // 手动连接上游节点，进入握手状态（此时已发出 register 请求）
    atbus::connection::ptr_t ctrl_conn =
        atbus::connection::create(node_downstream.get(), "ipv4://127.0.0.1:16396", false);
    CASE_EXPECT_TRUE(!!ctrl_conn);
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, ctrl_conn->connect());

    UNITTEST_WAIT_UNTIL(conf.ev_loop, atbus::connection::state_t::kHandshaking == ctrl_conn->get_status(), 8000, 0) {}

    // 在真实的 register 回包到达前注入伪造回包：对端上报的监听地址为不可达的通配地址
    {
      ::ATBUS_MACRO_PROTOBUF_NAMESPACE_ID::ArenaOptions arena_options;
      arena_options.initial_block_size = ATBUS_MACRO_RESERVED_SIZE;
      atbus::message register_rsp{arena_options};

      auto &head = register_rsp.mutable_head();
      head.set_version(atbus::protocol::ATBUS_PROTOCOL_VERSION);
      head.set_type(0);
      head.set_result_code(EN_ATBUS_ERR_SUCCESS);
      head.set_sequence(node_downstream->allocate_message_sequence());
      head.set_source_bus_id(0x12345678);

      auto *body = register_rsp.mutable_body().mutable_node_register_rsp();
      body->set_bus_id(0x12345678);
      // 与真实上游节点上报的身份保持一致（同进程但不同主机名，模拟不同物理机），
      // 否则真实的 register 回包到达时会因身份不一致判定 ID 冲突
      body->set_pid(atbus::node::get_pid());
      body->set_hostname("test-host-a");
      body->add_channels()->set_address("ipv4://0.0.0.0:16398");  // 不可达的通配地址

      node_downstream->on_receive_message(ctrl_conn.get(), std::move(register_rsp), 0, EN_ATBUS_ERR_SUCCESS);
    }

    time_t proc_sec = time(nullptr) + 1;
    time_t proc_usec = 0;

    // 注册被接受后，下游会使用注册连接的已知可达地址异步建立数据通道，等待其完成
    UNITTEST_WAIT_UNTIL(conf.ev_loop, node_downstream->is_endpoint_available(0x12345678), 8000, 4) {
      node_upstream->poll();
      node_upstream->proc(unit_test_make_timepoint(proc_sec, proc_usec));
      node_downstream->poll();
      node_downstream->proc(unit_test_make_timepoint(proc_sec, proc_usec));
      proc_usec += 100000;
      if (proc_usec >= 1000000) {
        proc_usec -= 1000000;
        ++proc_sec;
      }
    }

    // 数据通道建立完成后上游端点应该可用
    CASE_EXPECT_NE(nullptr, node_downstream->get_endpoint(0x12345678));
    CASE_EXPECT_TRUE(node_downstream->is_endpoint_available(0x12345678));

    // 再推进若干次 ping 周期的虚拟时间后，上游端点应该保持存活且可用
    // ping_interval 单位为微秒，每次循环推进 100ms
    time_t wait_tick_count = 2 * static_cast<time_t>(conf.ping_interval.count() / 100000) + 20;
    time_t waited_tick_count = 0;
    UNITTEST_WAIT_UNTIL(conf.ev_loop, waited_tick_count >= wait_tick_count, 30000, 4) {
      proc_usec += 100000;
      if (proc_usec >= 1000000) {
        proc_usec -= 1000000;
        ++proc_sec;
      }
      ++waited_tick_count;
      node_upstream->poll();
      node_upstream->proc(unit_test_make_timepoint(proc_sec, proc_usec));
      node_downstream->poll();
      node_downstream->proc(unit_test_make_timepoint(proc_sec, proc_usec));
    }

    CASE_EXPECT_NE(nullptr, node_downstream->get_endpoint(0x12345678));
    CASE_EXPECT_TRUE(node_downstream->is_endpoint_available(0x12345678));
  }

  unit_test_setup_exit(&ev_loop);
}

// API: hostname
CASE_TEST(atbus_node_reg, set_hostname) {
  std::string old_hostname = ::atbus::node::get_hostname();
  CASE_EXPECT_TRUE(atbus::node::set_hostname("test-host-for", true));
  CASE_EXPECT_EQ(std::string("test-host-for"), ::atbus::node::get_hostname());
  CASE_EXPECT_TRUE(atbus::node::set_hostname(old_hostname, true));
}

// 正常首发数据测试 -- 内存通道
CASE_TEST(atbus_node_reg, mem_and_send) {
  atbus::node::conf_t conf;
  atbus::node::default_conf(&conf);
  uv_loop_t ev_loop;
  uv_loop_init(&ev_loop);

  conf.ev_loop = &ev_loop;

  const size_t memory_chan_len = conf.receive_buffer_size;
  char *memory_chan_buf = reinterpret_cast<char *>(malloc(memory_chan_len));
  memset(memory_chan_buf, 0, memory_chan_len);

  {
    atbus::node::ptr_t node1 = atbus::node::create();
    atbus::node::ptr_t node2 = atbus::node::create();
    setup_atbus_node_logger(*node1);
    setup_atbus_node_logger(*node2);

    CASE_EXPECT_EQ(EN_ATBUS_ERR_NOT_INITED, node1->start());
    CASE_EXPECT_EQ(EN_ATBUS_ERR_NOT_INITED, node2->start());

    node1->init(0x12345678, &conf);
    node2->init(0x12356789, &conf);

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node1->listen("ipv4://127.0.0.1:16387"));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node2->listen("ipv4://127.0.0.1:16388"));
    char mem_chan_addr[64] = {0};
    UTIL_STRFUNC_SNPRINTF(mem_chan_addr, sizeof(mem_chan_addr), "mem://0x%llx",
                          reinterpret_cast<unsigned long long>(memory_chan_buf));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node2->listen(mem_chan_addr));

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node1->start());
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node2->start());

    time_t proc_t = time(nullptr);
    node1->poll();
    node2->poll();
    node1->proc(unit_test_make_timepoint(proc_t + 1, 0));
    node1->proc(unit_test_make_timepoint(proc_t + 1, 1));
    node2->proc(unit_test_make_timepoint(proc_t + 1, 0));
    node2->proc(unit_test_make_timepoint(proc_t + 1, 1));

    // 连接兄弟节点回调测试
    int check_ep_count = recv_msg_history.add_endpoint_count;
    node1->set_on_add_endpoint_handle(node_reg_test_add_endpoint_fn);
    node1->set_on_remove_endpoint_handle(node_reg_test_remove_endpoint_fn);
    node2->set_on_add_endpoint_handle(node_reg_test_add_endpoint_fn);
    node2->set_on_remove_endpoint_handle(node_reg_test_remove_endpoint_fn);

    node1->connect("ipv4://127.0.0.1:16388");

    UNITTEST_WAIT_UNTIL(conf.ev_loop,
                        node1->is_endpoint_available(node2->get_id()) && node2->is_endpoint_available(node1->get_id()),
                        8000, 1000) {
      ++proc_t;
      node1->poll();
      node1->proc(unit_test_make_timepoint(proc_t, 2));
      node2->poll();
      node2->proc(unit_test_make_timepoint(proc_t, 2));
    }

    // wait memory channel to complete
    for (time_t i = 1; i <= 32; ++i) {
      node1->proc(unit_test_make_timepoint(proc_t, i * 16));
      node2->proc(unit_test_make_timepoint(proc_t, i * 16));
    }

    // API - test - 数据通道优先应该是内存通道
    {
      atbus::endpoint *test_ep = nullptr;
      atbus::connection *test_conn = nullptr;
      atbus::topology_peer::ptr_t next_hop;
      node1->get_peer_channel(node2->get_id(), &atbus::endpoint::get_data_connection, &test_ep, &test_conn, &next_hop);
      CASE_EXPECT_NE(nullptr, test_ep);
      CASE_EXPECT_NE(nullptr, test_conn);

      if (nullptr != test_conn) {
        CASE_EXPECT_TRUE(test_conn->is_connected());
        // connect的节点是不注册kRegProc的
        CASE_EXPECT_FALSE(test_conn->check_flag(atbus::connection::flag_t::kRegProc));
      }
    }

    // in windows CI, connection will be closed sometimes, it will lead to add one endpoint more than one times
    CASE_EXPECT_LE(check_ep_count + 2, recv_msg_history.add_endpoint_count);

    // 兄弟节点消息转发测试
    std::string send_data;
    send_data.assign("abcdefg\0hello world!\n", sizeof("abcdefg\0hello world!\n") - 1);

    node1->poll();
    node2->poll();
    proc_t += 1;
    node1->proc(unit_test_make_timepoint(proc_t, 0));
    node2->proc(unit_test_make_timepoint(proc_t, 0));

    int count = recv_msg_history.count;
    node2->set_on_forward_request_handle(node_reg_test_recv_msg_test_record_fn);
    CASE_EXPECT_TRUE(!!node2->get_on_forward_request_handle());
    CASE_EXPECT_EQ(
        0, node1->send_data(node2->get_id(), 0,
                            gsl::span<const unsigned char>(reinterpret_cast<const unsigned char *>(send_data.data()),
                                                           send_data.size())));

    proc_t += 1;
    node1->proc(unit_test_make_timepoint(proc_t, 0));
    node2->proc(unit_test_make_timepoint(proc_t, 0));

    time_t proc_sum = 0;
    UNITTEST_WAIT_UNTIL(conf.ev_loop, count != recv_msg_history.count, 8000, 50) {
      proc_sum += 50;
      if (proc_sum >= 1000) {
        ++proc_t;
        proc_sum = 0;
      }
      node1->poll();
      node1->proc(unit_test_make_timepoint(proc_t, proc_sum * 1000));
      node2->poll();
      node2->proc(unit_test_make_timepoint(proc_t, proc_sum * 1000));
    }

    // check add endpoint callback
    CASE_EXPECT_EQ(send_data, recv_msg_history.data);
    // CASE_EXPECT_NE(nullptr, node1->get_iostream_conf());

    check_ep_count = recv_msg_history.remove_endpoint_count;

    // reset
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS,
                   node1->shutdown(EN_ATBUS_ERR_SUCCESS));  // shutdown - test, next proc() will call reset()
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node1->shutdown(EN_ATBUS_ERR_SUCCESS));  // shutdown - again

    UNITTEST_WAIT_UNTIL(
        conf.ev_loop,
        nullptr == node1->get_endpoint(node2->get_id()) && nullptr == node2->get_endpoint(node1->get_id()), 8000, 64) {
      ++proc_t;

      node1->proc(unit_test_make_timepoint(proc_t, 0));
      node2->proc(unit_test_make_timepoint(proc_t, 0));
    }

    node2->reset();

    // check remove endpoint callback
    // in windows CI, connection will be closed sometimes, it will lead to add one endpoint more than one times
    CASE_EXPECT_LE(check_ep_count + 2, recv_msg_history.remove_endpoint_count);

    CASE_EXPECT_EQ(nullptr, node2->get_endpoint(node1->get_id()));
    CASE_EXPECT_EQ(nullptr, node1->get_endpoint(node2->get_id()));
  }

  unit_test_setup_exit(&ev_loop);

  free(memory_chan_buf);
}

#if defined(ATBUS_CHANNEL_SHM) && ATBUS_CHANNEL_SHM

static bool node_reg_test_is_shm_available(const atbus::node::conf_t &conf) {
  // check if /proc/sys/kernel/shmmax exists
  if (!atfw::util::file_system::is_exist("/proc/sys/kernel/shmmax")) {
    return false;
  }

  std::string sz_contest;
  atfw::util::file_system::get_file_content(sz_contest, "/proc/sys/kernel/shmmax");
  return atfw::util::string::to_int<size_t>(sz_contest.c_str()) >= conf.receive_buffer_size;
}

// 正常首发数据测试 -- 共享内存
CASE_TEST(atbus_node_reg, shm_and_send) {
  atbus::node::conf_t conf;
  atbus::node::default_conf(&conf);

  if (!node_reg_test_is_shm_available(conf)) {
    return;
  }

  uv_loop_t ev_loop;
  uv_loop_init(&ev_loop);

  conf.ev_loop = &ev_loop;

  {
    atbus::node::ptr_t node1 = atbus::node::create();
    atbus::node::ptr_t node2 = atbus::node::create();
    setup_atbus_node_logger(*node1);
    setup_atbus_node_logger(*node2);

    CASE_EXPECT_EQ(EN_ATBUS_ERR_NOT_INITED, node1->start());
    CASE_EXPECT_EQ(EN_ATBUS_ERR_NOT_INITED, node2->start());

    node1->init(0x12345678, &conf);
    node2->init(0x12356789, &conf);

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node1->listen("ipv4://127.0.0.1:16387"));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node2->listen("ipv4://127.0.0.1:16388"));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node2->listen("shm://0x23456789"));

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node1->start());
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node2->start());

    time_t proc_t = time(nullptr);
    node1->poll();
    node2->poll();
    node1->proc(unit_test_make_timepoint(proc_t + 1, 0));
    node1->proc(unit_test_make_timepoint(proc_t + 1, 1));
    node2->proc(unit_test_make_timepoint(proc_t + 1, 0));
    node2->proc(unit_test_make_timepoint(proc_t + 1, 1));

    // 连接兄弟节点回调测试
    int check_ep_count = recv_msg_history.add_endpoint_count;
    node1->set_on_add_endpoint_handle(node_reg_test_add_endpoint_fn);
    node1->set_on_remove_endpoint_handle(node_reg_test_remove_endpoint_fn);
    node2->set_on_add_endpoint_handle(node_reg_test_add_endpoint_fn);
    node2->set_on_remove_endpoint_handle(node_reg_test_remove_endpoint_fn);

    node1->connect("ipv4://127.0.0.1:16388");

    UNITTEST_WAIT_UNTIL(conf.ev_loop,
                        node1->is_endpoint_available(node2->get_id()) && node2->is_endpoint_available(node1->get_id()),
                        8000, 1000) {
      ++proc_t;
      node1->poll();
      node1->proc(unit_test_make_timepoint(proc_t, 2));
      node2->poll();
      node2->proc(unit_test_make_timepoint(proc_t, 2));
    }

    // wait memory channel to complete
    for (time_t i = 1; i <= 32; ++i) {
      node1->proc(unit_test_make_timepoint(proc_t, i * 16));
      node2->proc(unit_test_make_timepoint(proc_t, i * 16));
    }

    // API - test - 数据通道优先应该是共享内存通道
    {
      atbus::endpoint *test_ep = nullptr;
      atbus::connection *test_conn = nullptr;
      atbus::topology_peer::ptr_t next_hop;
      node1->get_peer_channel(node2->get_id(), &atbus::endpoint::get_data_connection, &test_ep, &test_conn, &next_hop);
      CASE_EXPECT_NE(nullptr, test_ep);
      CASE_EXPECT_NE(nullptr, test_conn);

      if (nullptr != test_conn) {
        CASE_EXPECT_TRUE(test_conn->is_connected());
        // connect的节点是不注册kRegProc的
        CASE_EXPECT_FALSE(test_conn->check_flag(atbus::connection::flag_t::kRegProc));
      }
    }

    // in windows CI, connection will be closed sometimes, it will lead to add one endpoint more than one times
    CASE_EXPECT_LE(check_ep_count + 2, recv_msg_history.add_endpoint_count);

    // 兄弟节点消息转发测试
    std::string send_data;
    send_data.assign("abcdefg\0hello world!\n", sizeof("abcdefg\0hello world!\n") - 1);

    node1->poll();
    node2->poll();
    proc_t += 1;
    node1->proc(unit_test_make_timepoint(proc_t, 0));
    node2->proc(unit_test_make_timepoint(proc_t, 0));

    int count = recv_msg_history.count;
    node2->set_on_forward_request_handle(node_reg_test_recv_msg_test_record_fn);
    CASE_EXPECT_TRUE(!!node2->get_on_forward_request_handle());
    CASE_EXPECT_EQ(
        0, node1->send_data(node2->get_id(), 0,
                            gsl::span<const unsigned char>(reinterpret_cast<const unsigned char *>(send_data.data()),
                                                           send_data.size())));

    proc_t += 1;
    node1->proc(unit_test_make_timepoint(proc_t, 0));
    node2->proc(unit_test_make_timepoint(proc_t, 0));

    time_t proc_sum = 0;
    UNITTEST_WAIT_UNTIL(conf.ev_loop, count != recv_msg_history.count, 8000, 50) {
      proc_sum += 50;
      if (proc_sum >= 1000) {
        ++proc_t;
        proc_sum = 0;
      }
      node1->poll();
      node1->proc(unit_test_make_timepoint(proc_t, proc_sum * 1000));
      node2->poll();
      node2->proc(unit_test_make_timepoint(proc_t, proc_sum * 1000));
    }

    // check add endpoint callback
    CASE_EXPECT_EQ(send_data, recv_msg_history.data);
    // CASE_EXPECT_NE(nullptr, node1->get_iostream_conf());

    check_ep_count = recv_msg_history.remove_endpoint_count;

    // reset
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS,
                   node1->shutdown(EN_ATBUS_ERR_SUCCESS));  // shutdown - test, next proc() will call reset()
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node1->shutdown(EN_ATBUS_ERR_SUCCESS));  // shutdown - again

    UNITTEST_WAIT_UNTIL(
        conf.ev_loop,
        nullptr == node1->get_endpoint(node2->get_id()) && nullptr == node2->get_endpoint(node1->get_id()), 8000, 64) {
      ++proc_t;

      node1->proc(unit_test_make_timepoint(proc_t, 0));
      node2->proc(unit_test_make_timepoint(proc_t, 0));
    }

    node2->reset();

    // check remove endpoint callback
    // in windows CI, connection will be closed sometimes, it will lead to add one endpoint more than one times
    CASE_EXPECT_LE(check_ep_count + 2, recv_msg_history.remove_endpoint_count);

    CASE_EXPECT_EQ(nullptr, node2->get_endpoint(node1->get_id()));
    CASE_EXPECT_EQ(nullptr, node1->get_endpoint(node2->get_id()));
  }

  unit_test_setup_exit(&ev_loop);
}
#endif

// ============ close_connection callback tests ============
static int g_close_connection_callback_count_node1 = 0;
static int g_close_connection_callback_count_node2 = 0;

static int node_reg_test_close_connection_fn_node1(const atbus::node &, const atbus::endpoint *ep,
                                                   const atbus::connection *conn) {
  ++g_close_connection_callback_count_node1;

  CASE_MSG_INFO() << "close_connection callback (node1): endpoint=" << (ep ? ep->get_id() : 0)
                  << ", connection=" << (conn ? conn->get_address().address.c_str() : "null") << '\n';
  return 0;
}

static int node_reg_test_close_connection_fn_node2(const atbus::node &, const atbus::endpoint *ep,
                                                   const atbus::connection *conn) {
  ++g_close_connection_callback_count_node2;

  CASE_MSG_INFO() << "close_connection callback (node2): endpoint=" << (ep ? ep->get_id() : 0)
                  << ", connection=" << (conn ? conn->get_address().address.c_str() : "null") << '\n';
  return 0;
}

CASE_TEST(atbus_node_reg, on_close_connection_normal) {
  atbus::node::conf_t conf;
  atbus::node::default_conf(&conf);
  conf.access_tokens.push_back(std::vector<unsigned char>());
  unsigned char access_token[] = "test access token";
  conf.access_tokens.back().assign(access_token, access_token + sizeof(access_token) - 1);
  uv_loop_t ev_loop;
  uv_loop_init(&ev_loop);

  conf.ev_loop = &ev_loop;

  {
    atbus::node::ptr_t node1 = atbus::node::create();
    atbus::node::ptr_t node2 = atbus::node::create();
    setup_atbus_node_logger(*node1);
    setup_atbus_node_logger(*node2);

    node1->init(0x12345678, &conf);
    node2->init(0x12356789, &conf);

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node1->listen("ipv4://127.0.0.1:16387"));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node2->listen("ipv4://127.0.0.1:16388"));

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node1->start());
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node2->start());

    // Set close_connection callback with separate counters for each node
    g_close_connection_callback_count_node1 = 0;
    g_close_connection_callback_count_node2 = 0;
    node1->set_on_close_connection_handle(node_reg_test_close_connection_fn_node1);
    node2->set_on_close_connection_handle(node_reg_test_close_connection_fn_node2);

    time_t proc_t = time(nullptr);
    node1->poll();
    node2->poll();
    node1->proc(unit_test_make_timepoint(proc_t + 1, 0));
    node2->proc(unit_test_make_timepoint(proc_t + 1, 0));

    // Connect nodes
    node1->connect("ipv4://127.0.0.1:16388");

    UNITTEST_WAIT_UNTIL(conf.ev_loop,
                        node1->is_endpoint_available(node2->get_id()) && node2->is_endpoint_available(node1->get_id()),
                        8000, 0) {}

    // Send some data to ensure connection is fully established
    std::string send_data = "test data";
    recv_msg_history.count = 0;
    node2->set_on_forward_request_handle(node_reg_test_recv_msg_test_record_fn);
    node1->send_data(
        node2->get_id(), 0,
        gsl::span<const unsigned char>(reinterpret_cast<const unsigned char *>(send_data.data()), send_data.size()));

    UNITTEST_WAIT_UNTIL(conf.ev_loop, recv_msg_history.count > 0, 8000, 0) {}

    int close_count_node1_before = g_close_connection_callback_count_node1;
    int close_count_node2_before = g_close_connection_callback_count_node2;

    // Shutdown node1 (active close) to trigger close_connection callback
    node1->shutdown(EN_ATBUS_ERR_SUCCESS);

    UNITTEST_WAIT_UNTIL(
        conf.ev_loop,
        nullptr == node1->get_endpoint(node2->get_id()) && nullptr == node2->get_endpoint(node1->get_id()), 8000, 64) {
      ++proc_t;
      node1->proc(unit_test_make_timepoint(proc_t, 0));
      node2->proc(unit_test_make_timepoint(proc_t, 0));
    }

    // Verify close_connection callback was called on both nodes
    // node1 is the active closer, node2 receives peer close
    CASE_EXPECT_GT(g_close_connection_callback_count_node1, close_count_node1_before);
    CASE_EXPECT_GT(g_close_connection_callback_count_node2, close_count_node2_before);
    CASE_MSG_INFO() << "close_connection callback count: node1=" << g_close_connection_callback_count_node1
                    << ", node2=" << g_close_connection_callback_count_node2 << '\n';

    node2->reset();
  }

  unit_test_setup_exit(&ev_loop);
}

CASE_TEST(atbus_node_reg, on_close_connection_by_peer) {
  atbus::node::conf_t conf;
  atbus::node::default_conf(&conf);
  conf.access_tokens.push_back(std::vector<unsigned char>());
  unsigned char access_token[] = "test access token";
  conf.access_tokens.back().assign(access_token, access_token + sizeof(access_token) - 1);
  uv_loop_t ev_loop;
  uv_loop_init(&ev_loop);

  conf.ev_loop = &ev_loop;

  {
    atbus::node::ptr_t node1 = atbus::node::create();
    atbus::node::ptr_t node2 = atbus::node::create();
    setup_atbus_node_logger(*node1);
    setup_atbus_node_logger(*node2);

    node1->init(0x12345678, &conf);
    node2->init(0x12356789, &conf);

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node1->listen("ipv4://127.0.0.1:16387"));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node2->listen("ipv4://127.0.0.1:16388"));

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node1->start());
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node2->start());

    // Set close_connection callback only on node2 (the peer that will receive close event)
    g_close_connection_callback_count_node2 = 0;
    node2->set_on_close_connection_handle(node_reg_test_close_connection_fn_node2);

    time_t proc_t = time(nullptr);
    node1->poll();
    node2->poll();
    node1->proc(unit_test_make_timepoint(proc_t + 1, 0));
    node2->proc(unit_test_make_timepoint(proc_t + 1, 0));

    // Connect nodes
    node1->connect("ipv4://127.0.0.1:16388");

    UNITTEST_WAIT_UNTIL(conf.ev_loop,
                        node1->is_endpoint_available(node2->get_id()) && node2->is_endpoint_available(node1->get_id()),
                        8000, 0) {}

    int close_count_before = g_close_connection_callback_count_node2;

    // Reset node1 (peer close) to trigger close_connection callback on node2
    node1->reset();

    UNITTEST_WAIT_UNTIL(conf.ev_loop, nullptr == node2->get_endpoint(node1->get_id()), 8000, 64) {
      ++proc_t;
      node2->proc(unit_test_make_timepoint(proc_t, 0));
    }

    // Verify close_connection callback was called on node2
    CASE_EXPECT_GT(g_close_connection_callback_count_node2, close_count_before);
    CASE_MSG_INFO() << "close_connection callback count (by peer): " << g_close_connection_callback_count_node2 << '\n';

    node2->reset();
  }

  unit_test_setup_exit(&ev_loop);
}

// ============ topology_update_upstream callback tests ============
static int g_topology_upstream_callback_count = 0;
static uint64_t g_topology_upstream_self_id = 0;
static uint64_t g_topology_upstream_new_id = 0;

static void node_reg_test_topology_upstream_fn(const atbus::node &, const atbus::topology_peer::ptr_t &self_peer,
                                               const atbus::topology_peer::ptr_t &new_upstream_peer,
                                               const atbus::topology_data::ptr_t &) {
  ++g_topology_upstream_callback_count;
  g_topology_upstream_self_id = self_peer ? self_peer->get_bus_id() : 0;
  g_topology_upstream_new_id = new_upstream_peer ? new_upstream_peer->get_bus_id() : 0;

  CASE_MSG_INFO() << "topology_update_upstream callback: self_peer=" << g_topology_upstream_self_id
                  << ", new_upstream_peer=" << g_topology_upstream_new_id << '\n';
}

// Test topology_update_upstream callback when downstream node connects to upstream
// This tests the callback triggered via conf.upstream_address configuration
CASE_TEST(atbus_node_reg, on_topology_upstream_set) {
  atbus::node::conf_t conf;
  atbus::node::default_conf(&conf);
  conf.access_tokens.push_back(std::vector<unsigned char>());
  unsigned char access_token[] = "test access token";
  conf.access_tokens.back().assign(access_token, access_token + sizeof(access_token) - 1);
  uv_loop_t ev_loop;
  uv_loop_init(&ev_loop);

  conf.ev_loop = &ev_loop;

  {
    // Create upstream node first
    atbus::node::ptr_t node_upstream = atbus::node::create();
    setup_atbus_node_logger(*node_upstream);
    node_upstream->init(0x12356789, &conf);
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream->listen("ipv4://127.0.0.1:16389"));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream->start());

    // Create downstream node with upstream_address configured
    atbus::node::conf_t downstream_conf = conf;
    downstream_conf.upstream_address = "ipv4://127.0.0.1:16389";

    atbus::node::ptr_t node_downstream = atbus::node::create();
    setup_atbus_node_logger(*node_downstream);

    // Set topology_update_upstream callback before init
    g_topology_upstream_callback_count = 0;
    g_topology_upstream_self_id = 0;
    g_topology_upstream_new_id = 0;
    node_downstream->set_on_topology_update_upstream_handle(node_reg_test_topology_upstream_fn);

    node_downstream->init(0x12345678, &downstream_conf);
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_downstream->listen("ipv4://127.0.0.1:16390"));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_downstream->start());

    time_t proc_t = time(nullptr);

    // Wait for downstream to connect to upstream and trigger topology callback
    UNITTEST_WAIT_UNTIL(
        conf.ev_loop,
        atbus::node::state_t::kRunning == node_downstream->get_state() && g_topology_upstream_callback_count > 0, 8000,
        64) {
      ++proc_t;
      node_upstream->proc(unit_test_make_timepoint(proc_t, 0));
      node_downstream->proc(unit_test_make_timepoint(proc_t, 0));
    }

    // Verify callback was called
    CASE_EXPECT_GT(g_topology_upstream_callback_count, 0);
    CASE_EXPECT_EQ(node_downstream->get_id(), g_topology_upstream_self_id);
    CASE_EXPECT_EQ(node_upstream->get_id(), g_topology_upstream_new_id);

    CASE_MSG_INFO() << "topology_update_upstream callback count: " << g_topology_upstream_callback_count << '\n';

    // Clear the callback before reset to avoid accessing deallocated objects
    node_downstream->set_on_topology_update_upstream_handle(nullptr);

    // Clean shutdown
    node_downstream->shutdown(EN_ATBUS_ERR_SUCCESS);
    UNITTEST_WAIT_UNTIL(conf.ev_loop, nullptr == node_upstream->get_endpoint(node_downstream->get_id()), 8000, 64) {
      ++proc_t;
      node_upstream->proc(unit_test_make_timepoint(proc_t, 0));
      node_downstream->proc(unit_test_make_timepoint(proc_t, 0));
    }

    node_upstream->reset();
  }

  unit_test_setup_exit(&ev_loop);
}

// Test topology_update_upstream callback when upstream is lost
// This tests the callback triggered when upstream node goes offline
CASE_TEST(atbus_node_reg, on_topology_upstream_clear) {
  atbus::node::conf_t conf;
  atbus::node::default_conf(&conf);
  conf.access_tokens.push_back(std::vector<unsigned char>());
  unsigned char access_token[] = "test access token";
  conf.access_tokens.back().assign(access_token, access_token + sizeof(access_token) - 1);
  uv_loop_t ev_loop;
  uv_loop_init(&ev_loop);

  conf.ev_loop = &ev_loop;

  {
    // Create upstream node first
    atbus::node::ptr_t node_upstream = atbus::node::create();
    setup_atbus_node_logger(*node_upstream);
    node_upstream->init(0x12356789, &conf);
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream->listen("ipv4://127.0.0.1:16391"));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream->start());

    // Create downstream node with upstream_address configured
    atbus::node::conf_t downstream_conf = conf;
    downstream_conf.upstream_address = "ipv4://127.0.0.1:16391";

    atbus::node::ptr_t node_downstream = atbus::node::create();
    setup_atbus_node_logger(*node_downstream);

    // Set topology_update_upstream callback before init
    g_topology_upstream_callback_count = 0;
    g_topology_upstream_self_id = 0;
    g_topology_upstream_new_id = 0;
    node_downstream->set_on_topology_update_upstream_handle(node_reg_test_topology_upstream_fn);

    node_downstream->init(0x12345678, &downstream_conf);
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_downstream->listen("ipv4://127.0.0.1:16392"));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_downstream->start());

    time_t proc_t = time(nullptr);

    // Wait for downstream to connect to upstream and trigger topology callback
    UNITTEST_WAIT_UNTIL(
        conf.ev_loop,
        atbus::node::state_t::kRunning == node_downstream->get_state() && g_topology_upstream_callback_count > 0, 8000,
        64) {
      ++proc_t;
      node_upstream->proc(unit_test_make_timepoint(proc_t, 0));
      node_downstream->proc(unit_test_make_timepoint(proc_t, 0));
    }

    // First callback should have set upstream
    CASE_EXPECT_GT(g_topology_upstream_callback_count, 0);
    CASE_EXPECT_EQ(node_upstream->get_id(), g_topology_upstream_new_id);
    int callback_count_after_connect = g_topology_upstream_callback_count;

    CASE_MSG_INFO() << "After connect - topology_update_upstream callback count: " << g_topology_upstream_callback_count
                    << ", upstream_id: " << g_topology_upstream_new_id << '\n';

    // Now reset upstream node to trigger upstream clear callback
    node_upstream->reset();

    // Wait for downstream to detect upstream loss
    UNITTEST_WAIT_UNTIL(conf.ev_loop,
                        g_topology_upstream_callback_count > callback_count_after_connect ||
                            atbus::node::state_t::kLostUpstream == node_downstream->get_state(),
                        8000, 64) {
      proc_t += static_cast<time_t>(conf.retry_interval.count() / 1000000) + 1;
      node_downstream->proc(unit_test_make_timepoint(proc_t, 0));
    }

    CASE_MSG_INFO() << "After upstream reset - topology_update_upstream callback count: "
                    << g_topology_upstream_callback_count << ", upstream_id: " << g_topology_upstream_new_id
                    << ", downstream state: " << static_cast<int>(node_downstream->get_state()) << '\n';

    // Clear the callback before reset
    node_downstream->set_on_topology_update_upstream_handle(nullptr);

    node_downstream->reset();
  }

  unit_test_setup_exit(&ev_loop);
}

// Test topology_update_upstream callback when upstream node changes ID
// (same address, different ID - simulating upstream restart with new ID)
CASE_TEST(atbus_node_reg, on_topology_upstream_change_id) {
  atbus::node::conf_t conf;
  atbus::node::default_conf(&conf);
  conf.access_tokens.push_back(std::vector<unsigned char>());
  unsigned char access_token[] = "test access token";
  conf.access_tokens.back().assign(access_token, access_token + sizeof(access_token) - 1);
  uv_loop_t ev_loop;
  uv_loop_init(&ev_loop);

  conf.ev_loop = &ev_loop;

  {
    // Create first upstream node
    atbus::node::ptr_t node_upstream1 = atbus::node::create();
    setup_atbus_node_logger(*node_upstream1);
    node_upstream1->init(0x12356789, &conf);  // First upstream ID
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream1->listen("ipv4://127.0.0.1:16393"));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream1->start());

    // Create downstream node with upstream_address configured
    atbus::node::conf_t downstream_conf = conf;
    downstream_conf.upstream_address = "ipv4://127.0.0.1:16393";

    atbus::node::ptr_t node_downstream = atbus::node::create();
    setup_atbus_node_logger(*node_downstream);

    // Set topology_update_upstream callback before init
    g_topology_upstream_callback_count = 0;
    g_topology_upstream_self_id = 0;
    g_topology_upstream_new_id = 0;
    node_downstream->set_on_topology_update_upstream_handle(node_reg_test_topology_upstream_fn);

    node_downstream->init(0x12345678, &downstream_conf);
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_downstream->listen("ipv4://127.0.0.1:16394"));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_downstream->start());

    time_t proc_t = time(nullptr);

    // Wait for downstream to connect to first upstream
    UNITTEST_WAIT_UNTIL(
        conf.ev_loop,
        atbus::node::state_t::kRunning == node_downstream->get_state() && g_topology_upstream_callback_count > 0, 8000,
        64) {
      ++proc_t;
      node_upstream1->proc(unit_test_make_timepoint(proc_t, 0));
      node_downstream->proc(unit_test_make_timepoint(proc_t, 0));
    }

    // Verify first upstream connection
    CASE_EXPECT_GT(g_topology_upstream_callback_count, 0);
    CASE_EXPECT_EQ(node_downstream->get_id(), g_topology_upstream_self_id);
    CASE_EXPECT_EQ(node_upstream1->get_id(), g_topology_upstream_new_id);
    uint64_t first_upstream_id = g_topology_upstream_new_id;

    CASE_MSG_INFO() << "First upstream connected - callback count: " << g_topology_upstream_callback_count
                    << ", upstream_id: " << g_topology_upstream_new_id << '\n';

    // Reset first upstream to release the port
    node_upstream1->reset();

    // Wait for downstream to detect upstream loss
    UNITTEST_WAIT_UNTIL(conf.ev_loop, atbus::node::state_t::kLostUpstream == node_downstream->get_state(), 8000, 64) {
      proc_t += static_cast<time_t>(conf.retry_interval.count() / 1000000) + 1;
      node_downstream->proc(unit_test_make_timepoint(proc_t, 0));
    }

    CASE_MSG_INFO() << "First upstream disconnected - callback count: " << g_topology_upstream_callback_count
                    << ", downstream state: " << static_cast<int>(node_downstream->get_state()) << '\n';

    // Create second upstream node with different ID on the same address
    atbus::node::ptr_t node_upstream2 = atbus::node::create();
    setup_atbus_node_logger(*node_upstream2);
    node_upstream2->init(0x12357890, &conf);                                                 // Different upstream ID!
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream2->listen("ipv4://127.0.0.1:16393"));  // Same address
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream2->start());

    int callback_count_before_second = g_topology_upstream_callback_count;

    // Wait for downstream to connect to the new upstream with different ID
    UNITTEST_WAIT_UNTIL(conf.ev_loop,
                        atbus::node::state_t::kRunning == node_downstream->get_state() &&
                            g_topology_upstream_new_id == node_upstream2->get_id(),
                        8000, 64) {
      ++proc_t;
      node_upstream2->proc(unit_test_make_timepoint(proc_t, 0));
      node_downstream->proc(unit_test_make_timepoint(proc_t, 0));
    }

    // Verify that topology callback was called with new upstream ID
    CASE_EXPECT_GT(g_topology_upstream_callback_count, callback_count_before_second);
    CASE_EXPECT_EQ(node_downstream->get_id(), g_topology_upstream_self_id);
    CASE_EXPECT_EQ(node_upstream2->get_id(), g_topology_upstream_new_id);
    CASE_EXPECT_NE(first_upstream_id, g_topology_upstream_new_id);  // ID should be different

    CASE_MSG_INFO() << "Second upstream connected - callback count: " << g_topology_upstream_callback_count
                    << ", old_upstream_id: " << first_upstream_id << ", new_upstream_id: " << g_topology_upstream_new_id
                    << '\n';

    // Clear the callback before reset
    node_downstream->set_on_topology_update_upstream_handle(nullptr);

    // Clean shutdown
    node_downstream->shutdown(EN_ATBUS_ERR_SUCCESS);
    UNITTEST_WAIT_UNTIL(conf.ev_loop, nullptr == node_upstream2->get_endpoint(node_downstream->get_id()), 8000, 64) {
      ++proc_t;
      node_upstream2->proc(unit_test_make_timepoint(proc_t, 0));
      node_downstream->proc(unit_test_make_timepoint(proc_t, 0));
    }

    node_upstream2->reset();
  }

  unit_test_setup_exit(&ev_loop);
}

// 上游断线重连的退避测试：
// 节点激活后，每次重连失败，下一次重试间隔应翻倍且不超过 max_retry_interval；
// 重新激活成功后，退避间隔应重置回 retry_interval
CASE_TEST(atbus_node_reg, reconnect_upstream_retry_backoff) {
  atbus::node::conf_t conf;
  atbus::node::default_conf(&conf);
  uv_loop_t ev_loop;
  uv_loop_init(&ev_loop);

  conf.ev_loop = &ev_loop;

  const time_t retry_secs = static_cast<time_t>(conf.retry_interval.count() / 1000000);
  const time_t max_retry_secs = static_cast<time_t>(conf.max_retry_interval.count() / 1000000);

  {
    atbus::node::ptr_t node_upstream = atbus::node::create();
    atbus::node::ptr_t node_downstream = atbus::node::create();
    setup_atbus_node_logger(*node_upstream);
    setup_atbus_node_logger(*node_downstream);

    node_upstream->init(0x12356790, &conf);

    atbus::node::conf_t downstream_conf = conf;
    downstream_conf.upstream_address = "ipv4://127.0.0.1:16441";
    node_downstream->init(0x12345679, &downstream_conf);

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream->listen("ipv4://127.0.0.1:16441"));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_downstream->listen("ipv4://127.0.0.1:16442"));

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream->start());
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_downstream->start());

    time_t proc_t = time(nullptr) + 1;
    UNITTEST_WAIT_UNTIL(conf.ev_loop, atbus::node::state_t::kRunning == node_downstream->get_state(), 8000, 64) {
      ++proc_t;
      node_upstream->proc(unit_test_make_timepoint(proc_t, 0));
      node_downstream->proc(unit_test_make_timepoint(proc_t, 0));
    }
    CASE_EXPECT_EQ(static_cast<uint32_t>(atbus::node::state_t::kRunning),
                   static_cast<uint32_t>(node_downstream->get_state()));
    if (atbus::node::state_t::kRunning != node_downstream->get_state()) {
      node_upstream->reset();
      node_downstream->reset();
      unit_test_setup_exit(&ev_loop);
      return;
    }

    // 重连是否失败由真实IO异步通知，等待当前进行中的连接被回收
    auto wait_connecting_done = [&node_downstream, &ev_loop]() {
      for (int i = 0; i < 256 && node_downstream->get_connection_timer_size() > 0; ++i) {
        CASE_THREAD_SLEEP_MS(4);
        uv_run(&ev_loop, UV_RUN_NOWAIT);
      }
    };

    // 关闭上游节点，等待下游感知断线并发起第一次即时重连，返回发起重连的逻辑时刻
    auto wait_first_attempt = [&node_downstream, &ev_loop](time_t &tp) -> time_t {
      for (int i = 0; i < 256; ++i) {
        ++tp;
        node_downstream->proc(unit_test_make_timepoint(tp, 0));
        if (node_downstream->get_connection_timer_size() > 0) {
          return tp;
        }
        CASE_THREAD_SLEEP_MS(4);
        uv_run(&ev_loop, UV_RUN_NOWAIT);
      }
      return 0;
    };

    // 校验退避阶梯中的一级：到达重试时间之前（含 timepoint 边界，判定为严格小于）不应重连，
    // 超过重试时间后应恰好发起一次重连，随后等待这次重连真实失败
    auto expect_retry_step = [&node_downstream, &wait_connecting_done](time_t &attempt_tick, time_t retry_gap) {
      node_downstream->proc(unit_test_make_timepoint(attempt_tick + retry_gap - 1, 0));
      CASE_EXPECT_EQ(0, node_downstream->get_connection_timer_size());
      node_downstream->proc(unit_test_make_timepoint(attempt_tick + retry_gap, 0));
      CASE_EXPECT_EQ(0, node_downstream->get_connection_timer_size());

      attempt_tick += retry_gap + 1;
      node_downstream->proc(unit_test_make_timepoint(attempt_tick, 0));
      CASE_EXPECT_EQ(1, node_downstream->get_connection_timer_size());

      wait_connecting_done();
      CASE_EXPECT_EQ(0, node_downstream->get_connection_timer_size());
      CASE_EXPECT_EQ(static_cast<uint32_t>(atbus::node::state_t::kLostUpstream),
                     static_cast<uint32_t>(node_downstream->get_state()));
    };

    // 第一次即时重连失败以后，退避间隔从 retry_interval 开始
    node_upstream->reset();
    time_t attempt_tick = wait_first_attempt(proc_t);
    CASE_EXPECT_TRUE(attempt_tick > 0);

    wait_connecting_done();
    CASE_EXPECT_EQ(0, node_downstream->get_connection_timer_size());
    CASE_EXPECT_EQ(static_cast<uint32_t>(atbus::node::state_t::kLostUpstream),
                   static_cast<uint32_t>(node_downstream->get_state()));

    // 退避阶梯：每次失败翻倍，封顶 max_retry_interval
    time_t retry_gap = retry_secs;
    for (int round = 0; round < 7 && attempt_tick > 0; ++round) {
      expect_retry_step(attempt_tick, retry_gap);

      retry_gap *= 2;
      if (retry_gap > max_retry_secs) {
        retry_gap = max_retry_secs;
      }
    }

    // 重启上游节点，下游应能在下一次重试时重连成功，重新激活后退避间隔重置
    node_upstream->init(0x12356790, &conf);
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream->listen("ipv4://127.0.0.1:16441"));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream->start());

    UNITTEST_WAIT_UNTIL(conf.ev_loop, atbus::node::state_t::kRunning == node_downstream->get_state(), 8000, 64) {
      attempt_tick += 4;
      node_upstream->proc(unit_test_make_timepoint(attempt_tick, 0));
      node_downstream->proc(unit_test_make_timepoint(attempt_tick, 0));
    }
    CASE_EXPECT_EQ(static_cast<uint32_t>(atbus::node::state_t::kRunning),
                   static_cast<uint32_t>(node_downstream->get_state()));

    // 再次关闭上游节点，第一次重试间隔应重置为 retry_interval
    node_upstream->reset();
    attempt_tick = wait_first_attempt(attempt_tick);
    CASE_EXPECT_TRUE(attempt_tick > 0);

    wait_connecting_done();
    CASE_EXPECT_EQ(0, node_downstream->get_connection_timer_size());

    expect_retry_step(attempt_tick, retry_secs);
    expect_retry_step(attempt_tick, retry_secs * 2);

    node_upstream->reset();
    node_downstream->reset();
  }

  unit_test_setup_exit(&ev_loop);
}

// 集群隔离: scope/namespace/labels 一致时正常注册, 身份信息随注册包传递, 服务端照常通过单工通道反向建连
CASE_TEST(atbus_node_reg, reg_pc_success_with_same_scope) {
  atbus::node::conf_t conf;
  atbus::node::default_conf(&conf);
  uv_loop_t ev_loop;
  uv_loop_init(&ev_loop);
  conf.ev_loop = &ev_loop;

  const size_t memory_chan_len = conf.receive_buffer_size;
  char *upstream_mem_buf = reinterpret_cast<char *>(malloc(memory_chan_len));
  char *downstream_mem_buf = reinterpret_cast<char *>(malloc(memory_chan_len));
  memset(upstream_mem_buf, 0, memory_chan_len);
  memset(downstream_mem_buf, 0, memory_chan_len);

  {
    atbus::node::ptr_t node_upstream = atbus::node::create();
    atbus::node::ptr_t node_downstream = atbus::node::create();
    setup_atbus_node_logger(*node_upstream);
    setup_atbus_node_logger(*node_downstream);

    atbus::node::conf_t upstream_conf = conf;
    upstream_conf.scope = "prod";
    upstream_conf.namespace_name = "game";
    upstream_conf.node_labels.emplace("zone", "a");
    node_upstream->init(0x12345678, &upstream_conf);

    atbus::node::conf_t downstream_conf = upstream_conf;
    downstream_conf.upstream_address = "ipv4://127.0.0.1:16450";
    node_downstream->init(0x12346789, &downstream_conf);

    char upstream_mem_addr[64] = {0};
    UTIL_STRFUNC_SNPRINTF(upstream_mem_addr, sizeof(upstream_mem_addr), "mem://0x%llx",
                          reinterpret_cast<unsigned long long>(upstream_mem_buf));
    char downstream_mem_addr[64] = {0};
    UTIL_STRFUNC_SNPRINTF(downstream_mem_addr, sizeof(downstream_mem_addr), "mem://0x%llx",
                          reinterpret_cast<unsigned long long>(downstream_mem_buf));

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream->listen("ipv4://127.0.0.1:16450"));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream->listen(upstream_mem_addr));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_downstream->listen(downstream_mem_addr));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream->start());
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_downstream->start());

    time_t proc_t_sec = time(nullptr);
    time_t proc_t_usec = 0;
    UNITTEST_WAIT_UNTIL(conf.ev_loop,
                        node_downstream->is_endpoint_available(node_upstream->get_id()) &&
                            node_upstream->is_endpoint_available(node_downstream->get_id()),
                        8000, 8) {
      proc_t_usec += 8000;
      if (proc_t_usec >= 1000000) {
        proc_t_usec = 0;
        ++proc_t_sec;
      }
      node_upstream->proc(unit_test_make_timepoint(proc_t_sec, proc_t_usec));
      node_downstream->proc(unit_test_make_timepoint(proc_t_sec, proc_t_usec));
    }
    CASE_EXPECT_TRUE(node_downstream->is_endpoint_available(node_upstream->get_id()));
    CASE_EXPECT_TRUE(node_upstream->is_endpoint_available(node_downstream->get_id()));

    // 对端的 scope/namespace/labels 必须随注册包传递
    atbus::endpoint *ep_downstream = node_upstream->get_endpoint(node_downstream->get_id());
    CASE_EXPECT_NE(nullptr, ep_downstream);
    if (nullptr != ep_downstream) {
      CASE_EXPECT_EQ(std::string("prod"), ep_downstream->get_scope());
      CASE_EXPECT_EQ(std::string("game"), ep_downstream->get_namespace());
      auto label_iter = ep_downstream->get_labels().find("zone");
      CASE_EXPECT_TRUE(label_iter != ep_downstream->get_labels().end() && label_iter->second == "a");
    }

    atbus::endpoint *ep_upstream = node_downstream->get_endpoint(node_upstream->get_id());
    CASE_EXPECT_NE(nullptr, ep_upstream);
    if (nullptr != ep_upstream) {
      CASE_EXPECT_EQ(std::string("prod"), ep_upstream->get_scope());
      CASE_EXPECT_EQ(std::string("game"), ep_upstream->get_namespace());
      auto label_iter = ep_upstream->get_labels().find("zone");
      CASE_EXPECT_TRUE(label_iter != ep_upstream->get_labels().end() && label_iter->second == "a");
    }

    // 内存通道是单工通道: scope/namespace 匹配时双方必须互相通过对方的内存通道建立数据连接。
    // 反向连接在注册流程中同步发起, 可用性满足时必然已经完成
    atbus::endpoint *test_ep = nullptr;
    atbus::connection *test_conn = nullptr;
    atbus::topology_peer::ptr_t next_hop;
    node_upstream->get_peer_channel(node_downstream->get_id(), &atbus::endpoint::get_data_connection, &test_ep,
                                    &test_conn, &next_hop);
    CASE_EXPECT_NE(nullptr, test_conn);
    if (nullptr != test_conn) {
      CASE_EXPECT_EQ(std::string(downstream_mem_addr), test_conn->get_address().address);
    }
    test_ep = nullptr;
    test_conn = nullptr;
    node_downstream->get_peer_channel(node_upstream->get_id(), &atbus::endpoint::get_data_connection, &test_ep,
                                      &test_conn, &next_hop);
    CASE_EXPECT_NE(nullptr, test_conn);
    if (nullptr != test_conn) {
      CASE_EXPECT_EQ(std::string(upstream_mem_addr), test_conn->get_address().address);
    }
  }

  unit_test_setup_exit(&ev_loop);
  free(upstream_mem_buf);
  free(downstream_mem_buf);
}

// 集群隔离: scope 不匹配时自动建连必须跳过不可达的通告地址, 仅通过已知可达的上游地址建立数据连接
CASE_TEST(atbus_node_reg, reg_pc_scope_mismatch_without_redial) {
  atbus::node::conf_t conf;
  atbus::node::default_conf(&conf);
  uv_loop_t ev_loop;
  uv_loop_init(&ev_loop);
  conf.ev_loop = &ev_loop;

  const size_t memory_chan_len = conf.receive_buffer_size;
  char *upstream_mem_buf = reinterpret_cast<char *>(malloc(memory_chan_len));
  memset(upstream_mem_buf, 0, memory_chan_len);

  {
    atbus::node::ptr_t node_upstream = atbus::node::create();
    atbus::node::ptr_t node_downstream = atbus::node::create();
    setup_atbus_node_logger(*node_upstream);
    setup_atbus_node_logger(*node_downstream);

    atbus::node::conf_t upstream_conf = conf;
    upstream_conf.scope = "prod";
    node_upstream->init(0x12345678, &upstream_conf);

    atbus::node::conf_t downstream_conf = conf;
    downstream_conf.scope = "dev";
    downstream_conf.upstream_address = "ipv4://127.0.0.1:16452";
    node_downstream->init(0x12346789, &downstream_conf);

    char upstream_mem_addr[64] = {0};
    UTIL_STRFUNC_SNPRINTF(upstream_mem_addr, sizeof(upstream_mem_addr), "mem://0x%llx",
                          reinterpret_cast<unsigned long long>(upstream_mem_buf));

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream->listen("ipv4://127.0.0.1:16452"));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream->listen(upstream_mem_addr));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream->start());
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_downstream->start());

    UNITTEST_WAIT_UNTIL(conf.ev_loop,
                        node_downstream->is_endpoint_available(node_upstream->get_id()) &&
                            node_upstream->is_endpoint_available(node_downstream->get_id()),
                        8000, 8) {}
    CASE_EXPECT_TRUE(node_downstream->is_endpoint_available(node_upstream->get_id()));
    CASE_EXPECT_TRUE(node_upstream->is_endpoint_available(node_downstream->get_id()));

    // 上游通告的内存通道地址(匹配 prod)与 listen 地址都必须被跳过,
    // 否则内存通道优先级更高, 数据连接地址会变成 mem://
    atbus::endpoint *test_ep = nullptr;
    atbus::connection *test_conn = nullptr;
    atbus::topology_peer::ptr_t next_hop;
    node_downstream->get_peer_channel(node_upstream->get_id(), &atbus::endpoint::get_data_connection, &test_ep,
                                      &test_conn, &next_hop);
    CASE_EXPECT_NE(nullptr, test_conn);
    if (nullptr != test_conn) {
      CASE_EXPECT_EQ(std::string("ipv4://127.0.0.1:16452"), test_conn->get_address().address);
    }
  }

  unit_test_setup_exit(&ev_loop);
  free(upstream_mem_buf);
}

// 集群隔离: scope 相同但 namespace 不匹配时同样必须跳过不可达的通告地址
CASE_TEST(atbus_node_reg, reg_pc_namespace_mismatch_without_redial) {
  atbus::node::conf_t conf;
  atbus::node::default_conf(&conf);
  uv_loop_t ev_loop;
  uv_loop_init(&ev_loop);
  conf.ev_loop = &ev_loop;

  const size_t memory_chan_len = conf.receive_buffer_size;
  char *upstream_mem_buf = reinterpret_cast<char *>(malloc(memory_chan_len));
  memset(upstream_mem_buf, 0, memory_chan_len);

  {
    atbus::node::ptr_t node_upstream = atbus::node::create();
    atbus::node::ptr_t node_downstream = atbus::node::create();
    setup_atbus_node_logger(*node_upstream);
    setup_atbus_node_logger(*node_downstream);

    atbus::node::conf_t upstream_conf = conf;
    upstream_conf.scope = "prod";
    upstream_conf.namespace_name = "game";
    node_upstream->init(0x12345678, &upstream_conf);

    atbus::node::conf_t downstream_conf = conf;
    downstream_conf.scope = "prod";
    downstream_conf.namespace_name = "lobby";
    downstream_conf.upstream_address = "ipv4://127.0.0.1:16454";
    node_downstream->init(0x12346789, &downstream_conf);

    char upstream_mem_addr[64] = {0};
    UTIL_STRFUNC_SNPRINTF(upstream_mem_addr, sizeof(upstream_mem_addr), "mem://0x%llx",
                          reinterpret_cast<unsigned long long>(upstream_mem_buf));

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream->listen("ipv4://127.0.0.1:16454"));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream->listen(upstream_mem_addr));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream->start());
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_downstream->start());

    UNITTEST_WAIT_UNTIL(conf.ev_loop,
                        node_downstream->is_endpoint_available(node_upstream->get_id()) &&
                            node_upstream->is_endpoint_available(node_downstream->get_id()),
                        8000, 8) {}
    CASE_EXPECT_TRUE(node_downstream->is_endpoint_available(node_upstream->get_id()));
    CASE_EXPECT_TRUE(node_upstream->is_endpoint_available(node_downstream->get_id()));

    // namespace 不匹配时, 内存通道地址(匹配 game)与 listen 地址都必须被跳过
    atbus::endpoint *test_ep = nullptr;
    atbus::connection *test_conn = nullptr;
    atbus::topology_peer::ptr_t next_hop;
    node_downstream->get_peer_channel(node_upstream->get_id(), &atbus::endpoint::get_data_connection, &test_ep,
                                      &test_conn, &next_hop);
    CASE_EXPECT_NE(nullptr, test_conn);
    if (nullptr != test_conn) {
      CASE_EXPECT_EQ(std::string("ipv4://127.0.0.1:16454"), test_conn->get_address().address);
    }
  }

  unit_test_setup_exit(&ev_loop);
  free(upstream_mem_buf);
}

// 集群隔离: 配置 gateway 后只通告 gateway 地址, 下游必须选中匹配自身 scope 的地址而不是回退到注册地址
CASE_TEST(atbus_node_reg, reg_pc_gateway_select_matching_scope) {
  atbus::node::conf_t conf;
  atbus::node::default_conf(&conf);
  uv_loop_t ev_loop;
  uv_loop_init(&ev_loop);
  conf.ev_loop = &ev_loop;

  {
    atbus::node::ptr_t node_upstream = atbus::node::create();
    atbus::node::ptr_t node_downstream = atbus::node::create();
    setup_atbus_node_logger(*node_upstream);
    setup_atbus_node_logger(*node_downstream);

    atbus::node::conf_t upstream_conf = conf;
    upstream_conf.scope = "prod";
    atbus::node::gateway_t gw_other;
    gw_other.address = "ipv4://127.0.0.1:16456";
    gw_other.match_scope = "other";
    upstream_conf.gateway.push_back(gw_other);
    atbus::node::gateway_t gw_dev;
    gw_dev.address = "ipv4://127.0.0.1:16457";
    gw_dev.match_scope = "dev";
    upstream_conf.gateway.push_back(gw_dev);
    node_upstream->init(0x12345678, &upstream_conf);

    atbus::node::conf_t downstream_conf = conf;
    downstream_conf.scope = "dev";
    downstream_conf.node_labels.emplace("zone", "a");
    downstream_conf.upstream_address = "ipv4://127.0.0.1:16456";
    node_downstream->init(0x12346789, &downstream_conf);

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream->listen("ipv4://127.0.0.1:16456"));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream->listen("ipv4://127.0.0.1:16457"));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_downstream->listen("ipv4://127.0.0.1:16458"));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream->start());
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_downstream->start());

    UNITTEST_WAIT_UNTIL(conf.ev_loop,
                        node_downstream->is_endpoint_available(node_upstream->get_id()) &&
                            node_upstream->is_endpoint_available(node_downstream->get_id()),
                        8000, 8) {}
    CASE_EXPECT_TRUE(node_downstream->is_endpoint_available(node_upstream->get_id()));
    CASE_EXPECT_TRUE(node_upstream->is_endpoint_available(node_downstream->get_id()));

    // 下游必须选中匹配自身 scope 的 gateway 地址
    atbus::endpoint *test_ep = nullptr;
    atbus::connection *test_conn = nullptr;
    atbus::topology_peer::ptr_t next_hop;
    node_downstream->get_peer_channel(node_upstream->get_id(), &atbus::endpoint::get_data_connection, &test_ep,
                                      &test_conn, &next_hop);
    CASE_EXPECT_NE(nullptr, test_conn);
    if (nullptr != test_conn) {
      CASE_EXPECT_EQ(std::string("ipv4://127.0.0.1:16457"), test_conn->get_address().address);
    }

    // 下游 endpoint 必须保存上游通告的 gateway 匹配规则
    atbus::endpoint *ep_upstream = node_downstream->get_endpoint(node_upstream->get_id());
    CASE_EXPECT_NE(nullptr, ep_upstream);
    if (nullptr != ep_upstream) {
      CASE_EXPECT_EQ(static_cast<size_t>(2), ep_upstream->get_gateway().size());
      if (ep_upstream->get_gateway().size() >= 2) {
        CASE_EXPECT_EQ(std::string("ipv4://127.0.0.1:16456"), ep_upstream->get_gateway()[0].address);
        CASE_EXPECT_EQ(std::string("other"), ep_upstream->get_gateway()[0].match_scope);
        CASE_EXPECT_EQ(std::string("ipv4://127.0.0.1:16457"), ep_upstream->get_gateway()[1].address);
        CASE_EXPECT_EQ(std::string("dev"), ep_upstream->get_gateway()[1].match_scope);
      }
    }

    // 上游 endpoint 必须拿到下游上报的身份信息
    atbus::endpoint *ep_downstream = node_upstream->get_endpoint(node_downstream->get_id());
    CASE_EXPECT_NE(nullptr, ep_downstream);
    if (nullptr != ep_downstream) {
      CASE_EXPECT_EQ(std::string("dev"), ep_downstream->get_scope());
      auto label_iter = ep_downstream->get_labels().find("zone");
      CASE_EXPECT_TRUE(label_iter != ep_downstream->get_labels().end() && label_iter->second == "a");
    }
  }

  unit_test_setup_exit(&ev_loop);
}

// 集群隔离: gateway 未配置匹配规则时不限制, 任何 scope 的对端都可达
CASE_TEST(atbus_node_reg, reg_pc_gateway_wildcard_reachable) {
  atbus::node::conf_t conf;
  atbus::node::default_conf(&conf);
  uv_loop_t ev_loop;
  uv_loop_init(&ev_loop);
  conf.ev_loop = &ev_loop;

  {
    atbus::node::ptr_t node_upstream = atbus::node::create();
    atbus::node::ptr_t node_downstream = atbus::node::create();
    setup_atbus_node_logger(*node_upstream);
    setup_atbus_node_logger(*node_downstream);

    atbus::node::conf_t upstream_conf = conf;
    upstream_conf.scope = "prod";
    atbus::node::gateway_t gw_other;
    gw_other.address = "ipv4://127.0.0.1:16459";
    gw_other.match_scope = "other";
    upstream_conf.gateway.push_back(gw_other);
    atbus::node::gateway_t gw_wildcard;
    gw_wildcard.address = "ipv4://127.0.0.1:16460";
    upstream_conf.gateway.push_back(gw_wildcard);
    node_upstream->init(0x12345678, &upstream_conf);

    atbus::node::conf_t downstream_conf = conf;
    downstream_conf.scope = "dev";
    downstream_conf.upstream_address = "ipv4://127.0.0.1:16459";
    node_downstream->init(0x12346789, &downstream_conf);

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream->listen("ipv4://127.0.0.1:16459"));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream->listen("ipv4://127.0.0.1:16460"));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_downstream->listen("ipv4://127.0.0.1:16461"));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream->start());
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_downstream->start());

    UNITTEST_WAIT_UNTIL(conf.ev_loop,
                        node_downstream->is_endpoint_available(node_upstream->get_id()) &&
                            node_upstream->is_endpoint_available(node_downstream->get_id()),
                        8000, 8) {}
    CASE_EXPECT_TRUE(node_downstream->is_endpoint_available(node_upstream->get_id()));
    CASE_EXPECT_TRUE(node_upstream->is_endpoint_available(node_downstream->get_id()));

    // scope 受限的地址被跳过, 通配地址必须被选中
    atbus::endpoint *test_ep = nullptr;
    atbus::connection *test_conn = nullptr;
    atbus::topology_peer::ptr_t next_hop;
    node_downstream->get_peer_channel(node_upstream->get_id(), &atbus::endpoint::get_data_connection, &test_ep,
                                      &test_conn, &next_hop);
    CASE_EXPECT_NE(nullptr, test_conn);
    if (nullptr != test_conn) {
      CASE_EXPECT_EQ(std::string("ipv4://127.0.0.1:16460"), test_conn->get_address().address);
    }
  }

  unit_test_setup_exit(&ev_loop);
}

// 集群隔离: gateway 的 match_labels 必须是对端 labels 的子集才可达
CASE_TEST(atbus_node_reg, reg_pc_gateway_label_subset) {
  atbus::node::conf_t conf;
  atbus::node::default_conf(&conf);
  uv_loop_t ev_loop;
  uv_loop_init(&ev_loop);
  conf.ev_loop = &ev_loop;

  {
    atbus::node::ptr_t node_upstream = atbus::node::create();
    atbus::node::ptr_t node_downstream_full = atbus::node::create();
    atbus::node::ptr_t node_downstream_partial = atbus::node::create();
    setup_atbus_node_logger(*node_upstream);
    setup_atbus_node_logger(*node_downstream_full);
    setup_atbus_node_logger(*node_downstream_partial);

    atbus::node::conf_t upstream_conf = conf;
    upstream_conf.scope = "prod";
    atbus::node::gateway_t gw_labeled;
    gw_labeled.address = "ipv4://127.0.0.1:16462";
    gw_labeled.match_labels.emplace("zone", "a");
    gw_labeled.match_labels.emplace("app", "x");
    upstream_conf.gateway.push_back(gw_labeled);
    atbus::node::gateway_t gw_wildcard;
    gw_wildcard.address = "ipv4://127.0.0.1:16463";
    upstream_conf.gateway.push_back(gw_wildcard);
    node_upstream->init(0x12345678, &upstream_conf);

    // labels 覆盖 match_labels 全部键值的对端可以使用受限地址
    atbus::node::conf_t downstream_full_conf = conf;
    downstream_full_conf.scope = "dev";
    downstream_full_conf.node_labels.emplace("zone", "a");
    downstream_full_conf.node_labels.emplace("app", "x");
    downstream_full_conf.node_labels.emplace("extra", "1");
    downstream_full_conf.upstream_address = "ipv4://127.0.0.1:16463";
    node_downstream_full->init(0x12346789, &downstream_full_conf);

    // labels 只覆盖部分键值的对端必须跳过受限地址
    atbus::node::conf_t downstream_partial_conf = conf;
    downstream_partial_conf.scope = "dev";
    downstream_partial_conf.node_labels.emplace("zone", "a");
    downstream_partial_conf.upstream_address = "ipv4://127.0.0.1:16462";
    node_downstream_partial->init(0x12349012, &downstream_partial_conf);

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream->listen("ipv4://127.0.0.1:16462"));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream->listen("ipv4://127.0.0.1:16463"));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_downstream_full->listen("ipv4://127.0.0.1:16464"));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_downstream_partial->listen("ipv4://127.0.0.1:16465"));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream->start());
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_downstream_full->start());
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_downstream_partial->start());

    UNITTEST_WAIT_UNTIL(conf.ev_loop,
                        node_downstream_full->is_endpoint_available(node_upstream->get_id()) &&
                            node_upstream->is_endpoint_available(node_downstream_full->get_id()) &&
                            node_downstream_partial->is_endpoint_available(node_upstream->get_id()) &&
                            node_upstream->is_endpoint_available(node_downstream_partial->get_id()),
                        8000, 8) {}
    CASE_EXPECT_TRUE(node_downstream_full->is_endpoint_available(node_upstream->get_id()));
    CASE_EXPECT_TRUE(node_downstream_partial->is_endpoint_available(node_upstream->get_id()));

    // 全量 labels 的对端选中受限地址(列表顺序优先), 而不是回退到注册地址
    atbus::endpoint *test_ep = nullptr;
    atbus::connection *test_conn = nullptr;
    atbus::topology_peer::ptr_t next_hop;
    node_downstream_full->get_peer_channel(node_upstream->get_id(), &atbus::endpoint::get_data_connection, &test_ep,
                                           &test_conn, &next_hop);
    CASE_EXPECT_NE(nullptr, test_conn);
    if (nullptr != test_conn) {
      CASE_EXPECT_EQ(std::string("ipv4://127.0.0.1:16462"), test_conn->get_address().address);
    }

    // 部分 labels 的对端只能选中通配地址, 而不是受限的注册地址
    test_ep = nullptr;
    test_conn = nullptr;
    next_hop.reset();
    node_downstream_partial->get_peer_channel(node_upstream->get_id(), &atbus::endpoint::get_data_connection, &test_ep,
                                              &test_conn, &next_hop);
    CASE_EXPECT_NE(nullptr, test_conn);
    if (nullptr != test_conn) {
      CASE_EXPECT_EQ(std::string("ipv4://127.0.0.1:16463"), test_conn->get_address().address);
    }
  }

  unit_test_setup_exit(&ev_loop);
}
