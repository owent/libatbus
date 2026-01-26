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

static void node_reg_test_on_debug(const atfw::util::log::log_formatter::caller_info_t &, const char *content,
                                   size_t content_size) {
  gsl::string_view log_data{content, content_size};
  if (gsl::string_view::npos != log_data.find("connection deallocated")) {
    ++recv_msg_history.dealloc_connection_count;
  } else if (gsl::string_view::npos != log_data.find("endpoint deallocated")) {
    ++recv_msg_history.dealloc_endpoint_count;
  }

  CASE_MSG_INFO() << log_data << std::endl;

#ifdef _MSC_VER

  // static char *APPVEYOR = getenv("APPVEYOR");
  // static char *CI       = getenv("CI");

  // appveyor ci open msg content
  // if (APPVEYOR && APPVEYOR[0] && CI && CI[0] && nullptr != m) {
  //     std::cout << *m << std::endl;
  // }
#endif
}

static int node_reg_test_on_error(const atfw::util::log::log_formatter::caller_info_t &, const char *content,
                                  size_t content_size) {
  gsl::string_view log_data{content, content_size};
  // find status: {}, error_code: {}
  int status = 0;
  ATBUS_ERROR_TYPE errcode = EN_ATBUS_ERR_SUCCESS;
  size_t pos = log_data.find("status:");
  if (gsl::string_view::npos != pos) {
    for (; pos < log_data.size(); ++pos) {
      if ((log_data[pos] >= '0' && log_data[pos] <= '9') || log_data[pos] == '-') {
        break;
      }
    }
    if (pos < log_data.size()) {
      status = atfw::util::string::to_int<int>(log_data.substr(pos));
    }
  }
  pos = log_data.find("error_code:", pos);
  if (gsl::string_view::npos != pos) {
    errcode = static_cast<ATBUS_ERROR_TYPE>(atfw::util::string::to_int<int>(log_data.substr(pos + 11)));
  }
  if ((0 == status && 0 == errcode) || UV_EOF == status || UV_ECONNRESET == status) {
    return 0;
  }

  // 随时可能收到网络错误，排除错误检查
  if (recv_msg_history.status == 0 || errcode > EN_ATBUS_ERR_DNS_GETADDR_FAILED || errcode < EN_ATBUS_ERR_NOT_READY) {
    recv_msg_history.status = status;
  }
  ++recv_msg_history.register_failed_count;

  CASE_MSG_INFO() << log_data << std::endl;
  return 0;
}

static int node_reg_test_on_info_log(const atfw::util::log::log_formatter::caller_info_t &, const char *content,
                                     size_t content_size) {
  gsl::string_view log_data{content, content_size};
  CASE_MSG_INFO() << log_data << std::endl;
  if (gsl::string_view::npos != log_data.find("connection deallocated")) {
    ++recv_msg_history.dealloc_connection_count;
  } else if (gsl::string_view::npos != log_data.find("endpoint deallocated")) {
    ++recv_msg_history.dealloc_endpoint_count;
  }
  return 0;
}

static void setup_atbus_node_logger(atbus::node &n) {
  n.get_logger()->set_level(atfw::util::log::log_formatter::level_t::LOG_LW_DEBUG);
  n.get_logger()->clear_sinks();
  n.get_logger()->add_sink(node_reg_test_on_debug, atfw::util::log::log_formatter::level_t::LOG_LW_DEBUG,
                           atfw::util::log::log_formatter::level_t::LOG_LW_DEBUG);
  n.get_logger()->add_sink(node_reg_test_on_info_log, atfw::util::log::log_formatter::level_t::LOG_LW_INFO,
                           atfw::util::log::log_formatter::level_t::LOG_LW_INFO);
  n.get_logger()->add_sink(node_reg_test_on_error, atfw::util::log::log_formatter::level_t::LOG_LW_ERROR,
                           atfw::util::log::log_formatter::level_t::LOG_LW_ERROR);

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

    CASE_MSG_INFO() << "Ready to exit" << std::endl;

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
      CASE_MSG_INFO() << "more events than expected, skip this unit test." << std::endl;
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
                    << std::endl;
    CASE_MSG_INFO() << "invalid connection: "
                    << (recv_msg_history.invalid_connection_count - check_invalid_connection_count) << std::endl;

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

  CASE_MSG_INFO() << "default message max size: " << conf.message_size << std::endl;
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
    CASE_EXPECT_TRUE(static_cast<uint32_t>(node_downstream->get_state()) ==
                         static_cast<uint32_t>(atbus::node::state_t::type::kCreated) ||
                     static_cast<uint32_t>(node_downstream->get_state()) ==
                         static_cast<uint32_t>(atbus::node::state_t::type::kRunning));
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

    CASE_MSG_INFO() << "atbus_node_reg.reg_pc_failed_with_subnet_mismatch done." << std::endl;
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
                        atbus::node::state_t::type::kCreated != node_downstream->get_state() &&
                            atbus::node::state_t::type::kCreated != node_downstream_fail->get_state(),
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
                         static_cast<uint32_t>(atbus::node::state_t::type::kRunning) ||
                     static_cast<uint32_t>(node_downstream_fail->get_state()) ==
                         static_cast<uint32_t>(atbus::node::state_t::type::kRunning));
    CASE_EXPECT_EQ(static_cast<uint32_t>(atbus::node::state_t::type::kRunning),
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
    UNITTEST_WAIT_UNTIL(conf.ev_loop, atbus::node::state_t::type::kRunning == node_downstream->get_state(), 8000, 64) {
      node_upstream->proc(unit_test_make_timepoint(proc_t, 0));
      node_downstream->proc(unit_test_make_timepoint(proc_t, 0));
      ++proc_t;
    }

    // 关闭上游节点
    node_upstream->reset();

    // 重连上游节点，但是连接不成功也不会导致下线
    // 连接过程中的转态变化
    size_t retry_times = 0;
    UNITTEST_WAIT_IF(conf.ev_loop,
                     atbus::node::state_t::type::kRunning == node_downstream->get_state() || retry_times < 16, 8000,
                     64) {
      proc_t += static_cast<time_t>(conf.retry_interval.count() / 1000000) + 1;

      node_downstream->proc(unit_test_make_timepoint(proc_t, 0));

      if (atbus::node::state_t::type::kRunning != node_downstream->get_state()) {
        ++retry_times;
        CASE_EXPECT_TRUE(static_cast<uint32_t>(node_downstream->get_state()) ==
                             static_cast<uint32_t>(atbus::node::state_t::type::kLostUpstream) ||
                         static_cast<uint32_t>(node_downstream->get_state()) ==
                             static_cast<uint32_t>(atbus::node::state_t::type::kConnectingUpstream));
        CASE_EXPECT_NE(static_cast<uint32_t>(atbus::node::state_t::type::kCreated),
                       static_cast<uint32_t>(node_downstream->get_state()));
        CASE_EXPECT_NE(static_cast<uint32_t>(atbus::node::state_t::type::kInited),
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
                     atbus::node::state_t::type::kRunning != node_downstream->get_state() ||
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
      CASE_EXPECT_EQ(static_cast<uint32_t>(atbus::node::state_t::type::kRunning),
                     static_cast<uint32_t>(node_downstream->get_state()));
    }

    // 注册到子节点失败不会导致下线的流程测试
    CASE_EXPECT_EQ(static_cast<uint32_t>(atbus::node::state_t::type::kRunning),
                   static_cast<uint32_t>(node_upstream->get_state()));
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
        CASE_EXPECT_FALSE(test_conn->check_flag(atbus::connection::flag_t::type::kRegProc));
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
        CASE_EXPECT_FALSE(test_conn->check_flag(atbus::connection::flag_t::type::kRegProc));
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
