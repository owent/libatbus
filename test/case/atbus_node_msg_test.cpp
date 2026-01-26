#include <chrono>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>

#include "common/string_oprs.h"

#ifdef max
#  undef max
#endif

#ifdef min
#  undef min
#endif

#include <atbus_node.h>
#include <libatbus_protocol.h>

#include "frame/test_macros.h"

#include <atbus_message_handler.h>

#include "atbus_test_utils.h"

#include <stdarg.h>

static int node_msg_test_on_log(const atfw::util::log::log_formatter::caller_info_t &, const char *content,
                                size_t content_size) {
  gsl::string_view log_data{content, content_size};
  CASE_MSG_INFO() << log_data << std::endl;
  return 0;
}

static void setup_atbus_node_logger(atbus::node &n) {
  n.get_logger()->set_level(atfw::util::log::log_formatter::level_t::LOG_LW_DEBUG);
  n.get_logger()->clear_sinks();
  n.get_logger()->add_sink(node_msg_test_on_log);
  n.enable_debug_message_verbose();
}

ATBUS_MACRO_NAMESPACE_BEGIN
struct node_msg_test_access {
  static ATBUS_ERROR_TYPE send_data_message(node &n, bus_id_t tid, message &m, endpoint **ep_out, connection **conn_out,
                                            const ::atbus::node::send_data_options_t &options) {
    return n.send_data_message(tid, m, ep_out, conn_out, options);
  }
};
ATBUS_MACRO_NAMESPACE_END

struct node_msg_test_recv_msg_record_t {
  const atbus::node *n;
  const atbus::endpoint *ep;
  const atbus::connection *conn;
  std::string data;
  int status;
  int count;
  int failed_count;
  int remove_endpoint_count;
  int ping_count;
  int pong_count;
  std::vector<ATBUS_MACRO_BUSID_TYPE> last_msg_router;
  uint64_t last_cmd_seq;
  uint64_t expect_cmd_req_from;
  uint64_t expect_cmd_rsp_from;

  node_msg_test_recv_msg_record_t()
      : n(nullptr),
        ep(nullptr),
        conn(nullptr),
        status(0),
        count(0),
        failed_count(0),
        remove_endpoint_count(0),
        ping_count(0),
        pong_count(0),
        last_cmd_seq(0),
        expect_cmd_req_from(0),
        expect_cmd_rsp_from(0) {}
};

static node_msg_test_recv_msg_record_t recv_msg_history;

static int node_msg_test_recv_msg_test_record_fn(const atbus::node &n, const atbus::endpoint *ep,
                                                 const atbus::connection *conn, const atbus::message &m,
                                                 gsl::span<const unsigned char> buffer) {
  recv_msg_history.n = &n;
  recv_msg_history.ep = ep;
  recv_msg_history.conn = conn;
  recv_msg_history.status = m.get_head() == nullptr ? 0 : m.get_head()->result_code();
  ++recv_msg_history.count;

  const ::atframework::atbus::protocol::forward_data *fwd_data = nullptr;
  if (m.get_body_type() == ::atframework::atbus::message_body_type::kDataTransformReq) {
    fwd_data = m.get_body() == nullptr ? nullptr : &m.get_body()->data_transform_req();
  } else if (m.get_body_type() == ::atframework::atbus::message_body_type::kDataTransformRsp) {
    fwd_data = m.get_body() == nullptr ? nullptr : &m.get_body()->data_transform_rsp();
  }

  if (nullptr != fwd_data) {
    recv_msg_history.last_msg_router.assign(fwd_data->router().begin(), fwd_data->router().end());
  } else {
    recv_msg_history.last_msg_router.clear();
  }

  std::streamsize w = std::cout.width();
  if (!buffer.empty()) {
    recv_msg_history.data.assign(reinterpret_cast<const char *>(buffer.data()), buffer.size());
    CASE_MSG_INFO() << "[Log Debug] node=0x" << std::setfill('0') << std::hex << std::setw(8) << n.get_id() << ", ep=0x"
                    << std::setw(8) << (nullptr == ep ? 0 : ep->get_id()) << ", c=" << conn << std::setfill(' ')
                    << std::setw(static_cast<int>(w)) << std::dec << "\t" << "recv message: ";
    std::cout.write(reinterpret_cast<const char *>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
    std::cout << std::endl;
  } else {
    recv_msg_history.data.clear();
    CASE_MSG_INFO() << "[Log Debug] node=0x" << std::setfill('0') << std::hex << std::setw(8) << n.get_id() << ", ep=0x"
                    << std::setw(8) << (nullptr == ep ? 0 : ep->get_id()) << ", c=" << conn << std::setfill(' ')
                    << std::setw(static_cast<int>(w)) << std::dec << "\t" << "recv message: [NOTHING]" << std::endl;
  }

  return 0;
}

static int node_msg_test_send_data_forward_response_fn(const atbus::node &n, const atbus::endpoint *ep,
                                                       const atbus::connection *conn, const atbus::message *m) {
  recv_msg_history.n = &n;
  recv_msg_history.ep = ep;
  recv_msg_history.conn = conn;
  recv_msg_history.status = nullptr == m ? 0 : m->get_head() == nullptr ? 0 : m->get_head()->result_code();
  if (recv_msg_history.status < 0) {
    ++recv_msg_history.failed_count;
  }

  const ::atframework::atbus::protocol::forward_data *fwd_data = nullptr;
  if (nullptr != m) {
    if (m->get_body_type() == ::atframework::atbus::message_body_type::kDataTransformReq) {
      fwd_data = m->get_body() == nullptr ? nullptr : &m->get_body()->data_transform_req();
    } else if (m->get_body_type() == ::atframework::atbus::message_body_type::kDataTransformRsp) {
      fwd_data = m->get_body() == nullptr ? nullptr : &m->get_body()->data_transform_rsp();
    }
  }

  if (nullptr != fwd_data) {
    recv_msg_history.last_msg_router.assign(fwd_data->router().begin(), fwd_data->router().end());
  } else {
    recv_msg_history.last_msg_router.clear();
  }

  if (nullptr != m && nullptr != fwd_data && fwd_data->content().size() > 0) {
    recv_msg_history.data.assign(fwd_data->content().data(), fwd_data->content().size());
  } else {
    recv_msg_history.data.clear();
  }

  return 0;
}

static void node_msg_test_build_forward_message(atbus::node &sender, atbus::bus_id_t tid, int type,
                                                gsl::span<const unsigned char> data,
                                                atbus::node::send_data_options_t &options, atbus::message &m) {
  atbus::protocol::message_head &head = m.mutable_head();
  atbus::protocol::forward_data *body = m.mutable_body().mutable_data_transform_req();
  CASE_EXPECT_TRUE(nullptr != body);

  uint64_t self_id = sender.get_id();
  uint32_t flags = 0;
  if (options.check_flag(atbus::node::send_data_options_t::flag_type::kRequireResponse)) {
    flags |= atbus::protocol::FORWARD_DATA_FLAG_REQUIRE_RSP;
  }

  head.set_version(sender.get_protocol_version());
  head.set_type(type);
  head.set_source_bus_id(self_id);
  if (0 != options.sequence) {
    head.set_sequence(options.sequence);
  }

  body->set_from(self_id);
  body->set_to(tid);
  body->add_router(self_id);
  body->mutable_content()->assign(reinterpret_cast<const char *>(data.data()), data.size());
  body->set_flags(flags);
}

static int node_msg_test_remove_endpoint_fn(const atbus::node &, atbus::endpoint *, int) {
  ++recv_msg_history.remove_endpoint_count;
  return 0;
}

static int node_msg_test_on_ping(const atbus::node &n, const atbus::endpoint *ep, const ::atframework::atbus::message &,
                                 const ::atframework::atbus::protocol::ping_data &ping_data) {
  std::streamsize w = std::cout.width();
  CASE_MSG_INFO() << "[Ping] node=0x" << std::setfill('0') << std::hex << std::setw(8) << n.get_id() << ", ep=0x"
                  << std::setw(8) << (nullptr == ep ? 0 : ep->get_id()) << ", time point=" << ping_data.time_point()
                  << std::setfill(' ') << std::setw(static_cast<int>(w)) << std::dec << std::endl;

  ++recv_msg_history.ping_count;
  return 0;
}

static int node_msg_test_on_pong(const atbus::node &n, const atbus::endpoint *ep, const ::atframework::atbus::message &,
                                 const ::atframework::atbus::protocol::ping_data &ping_data) {
  std::streamsize w = std::cout.width();
  CASE_MSG_INFO() << "[Pong] node=0x" << std::setfill('0') << std::hex << std::setw(8) << n.get_id() << ", ep=0x"
                  << std::setw(8) << (nullptr == ep ? 0 : ep->get_id()) << ", time point=" << ping_data.time_point()
                  << std::setfill(' ') << std::setw(static_cast<int>(w)) << std::dec << std::endl;

  ++recv_msg_history.pong_count;
  return 0;
}

// 定时Ping Pong协议测试
CASE_TEST(atbus_node_msg, ping_pong) {
  atbus::node::conf_t conf;
  atbus::node::default_conf(&conf);
  conf.ping_interval = std::chrono::seconds{1};
  uv_loop_t ev_loop;
  uv_loop_init(&ev_loop);

  conf.ev_loop = &ev_loop;

  {
    atbus::node::ptr_t node1 = atbus::node::create();
    atbus::node::ptr_t node2 = atbus::node::create();
    setup_atbus_node_logger(*node1);
    setup_atbus_node_logger(*node2);
    node1->set_on_ping_endpoint_handle(node_msg_test_on_ping);
    CASE_EXPECT_TRUE(!!node1->get_on_ping_endpoint_handle());
    node1->set_on_pong_endpoint_handle(node_msg_test_on_pong);
    CASE_EXPECT_TRUE(!!node1->get_on_pong_endpoint_handle());
    node2->set_on_ping_endpoint_handle(node_msg_test_on_ping);
    node2->set_on_pong_endpoint_handle(node_msg_test_on_pong);

    atbus::node::ptr_t upstream = atbus::node::create();
    setup_atbus_node_logger(*upstream);
    upstream->set_on_ping_endpoint_handle(node_msg_test_on_ping);
    upstream->set_on_pong_endpoint_handle(node_msg_test_on_pong);

    CASE_EXPECT_EQ(nullptr, node1->get_self_endpoint());
    CASE_EXPECT_EQ(nullptr, node2->get_self_endpoint());
    CASE_EXPECT_EQ(nullptr, upstream->get_self_endpoint());

    upstream->init(0x12346789, &conf);

    node2->init(0x12356789, &conf);
    conf.upstream_address = "ipv4://127.0.0.1:16389";
    node1->init(0x12345678, &conf);

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, upstream->listen("ipv4://127.0.0.1:16389"));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node1->listen("ipv4://127.0.0.1:16387"));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node2->listen("ipv4://127.0.0.1:16388"));

    atbus::node::start_conf_t start_conf;
    time_t proc_sec = time(nullptr);
    time_t proc_usec = 0;
    start_conf.timer_timepoint = unit_test_make_timepoint(proc_sec, proc_usec);
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, upstream->start(start_conf));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node1->start(start_conf));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node2->start(start_conf));

    node1->connect("ipv4://127.0.0.1:16388");

    int tick_sec_count = 0;
    int old_ping_count = recv_msg_history.ping_count;
    int old_pong_count = recv_msg_history.pong_count;
    // 8s timeout
    UNITTEST_WAIT_UNTIL(conf.ev_loop, recv_msg_history.pong_count - old_pong_count >= 40, 8000, 8) {
      proc_usec += 80000;
      if (proc_usec >= 1000000) {
        proc_usec -= 1000000;
        ++proc_sec;
        ++tick_sec_count;
      }

      node1->proc(unit_test_make_timepoint(proc_sec, proc_usec));
      node2->proc(unit_test_make_timepoint(proc_sec, proc_usec));
      upstream->proc(unit_test_make_timepoint(proc_sec, proc_usec));
    }

    CASE_EXPECT_GE(recv_msg_history.pong_count - old_pong_count, 40);
    CASE_EXPECT_GE(recv_msg_history.pong_count - old_pong_count, 4 * tick_sec_count - 8);
    CASE_EXPECT_LE(recv_msg_history.pong_count - old_pong_count, 4 * tick_sec_count + 8);
    // The last ping may not dispatched yet
    CASE_EXPECT_GE(recv_msg_history.pong_count - old_pong_count + 6, recv_msg_history.ping_count - old_ping_count);
    CASE_EXPECT_LE(recv_msg_history.pong_count - old_pong_count, recv_msg_history.ping_count - old_ping_count + 8);

    CASE_EXPECT_GT(node2->get_endpoint(node1->get_id())->get_stat_last_pong().time_since_epoch().count(), 0);
    CASE_EXPECT_GT(node1->get_endpoint(node2->get_id())->get_stat_last_pong().time_since_epoch().count(), 0);
    CASE_EXPECT_GT(node1->get_endpoint(upstream->get_id())->get_stat_last_pong().time_since_epoch().count(), 0);
    CASE_EXPECT_GT(upstream->get_endpoint(node1->get_id())->get_stat_last_pong().time_since_epoch().count(), 0);
    CASE_MSG_INFO() << "Ping delay: " << node2->get_endpoint(node1->get_id())->get_stat_ping_delay() << std::endl;
  }

  unit_test_setup_exit(&ev_loop);
}

static int node_msg_test_recv_msg_test_custom_cmd_fn(const atbus::node &, const atbus::endpoint *,
                                                     const atbus::connection *, atbus::bus_id_t from,
                                                     gsl::span<gsl::span<const unsigned char>> data,
                                                     std::list<std::string> &rsp) {
  ++recv_msg_history.count;

  recv_msg_history.data.clear();
  for (size_t i = 0; i < data.size(); ++i) {
    recv_msg_history.data.append(reinterpret_cast<const char *>(data[i].data()), data[i].size());
    recv_msg_history.data += '\0';
    rsp.push_back(std::string(reinterpret_cast<const char *>(data[i].data()), data[i].size()));
  }

  rsp.push_back("run custom cmd done");

  CASE_EXPECT_EQ(from, recv_msg_history.expect_cmd_req_from);
  return 0;
}

static int node_msg_test_recv_msg_test_custom_rsp_fn(const atbus::node &, const atbus::endpoint *,
                                                     const atbus::connection *, atbus::bus_id_t from,
                                                     gsl::span<gsl::span<const unsigned char>> data, uint64_t seq) {
  ++recv_msg_history.count;

  for (size_t i = 0; i < data.size(); ++i) {
    std::string text(reinterpret_cast<const char *>(data[i].data()), data[i].size());
    CASE_MSG_INFO() << "Custom Rsp(" << seq << "): " << text << std::endl;
  }

  CASE_EXPECT_EQ(seq, recv_msg_history.last_cmd_seq);
  CASE_EXPECT_EQ(from, recv_msg_history.expect_cmd_rsp_from);
  CASE_EXPECT_GT(data.size(), 1);
  if (data.size() > 1) {
    const auto &last_item = data[data.size() - 1];
    CASE_EXPECT_EQ(0, UTIL_STRFUNC_STRNCMP("run custom cmd done", reinterpret_cast<const char *>(last_item.data()),
                                           last_item.size()));
  }

  return 0;
}

// 自定义命令协议测试
CASE_TEST(atbus_node_msg, custom_cmd) {
  atbus::node::conf_t conf;
  atbus::node::default_conf(&conf);
  uv_loop_t ev_loop;
  uv_loop_init(&ev_loop);

  conf.ev_loop = &ev_loop;

  do {
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

    time_t proc_t = time(nullptr) + 1;
    node1->poll();
    node2->poll();
    node1->proc(unit_test_make_timepoint(proc_t, 0));
    node2->proc(unit_test_make_timepoint(proc_t, 0));

    node1->connect("ipv4://127.0.0.1:16388");

    UNITTEST_WAIT_UNTIL(conf.ev_loop,
                        node1->is_endpoint_available(node2->get_id()) && node2->is_endpoint_available(node1->get_id()),
                        8000, 0) {}

    int count = recv_msg_history.count;
    node2->set_on_custom_command_request_handle(node_msg_test_recv_msg_test_custom_cmd_fn);
    node1->set_on_custom_command_response_handle(node_msg_test_recv_msg_test_custom_rsp_fn);
    CASE_EXPECT_TRUE(!!node1->get_on_custom_command_response_handle());

    char test_str[] = "hello world!";
    std::string send_data = test_str;
    gsl::span<const unsigned char> custom_args[] = {
        gsl::span<const unsigned char>(reinterpret_cast<const unsigned char *>(&test_str[0]), 5),
        gsl::span<const unsigned char>(reinterpret_cast<const unsigned char *>(&test_str[6]), 5),
        gsl::span<const unsigned char>(reinterpret_cast<const unsigned char *>(&test_str[11]), 1)};

    send_data[5] = '\0';
    send_data[11] = '\0';
    send_data += '!';
    send_data += '\0';

    recv_msg_history.last_cmd_seq = 0;
    recv_msg_history.expect_cmd_req_from = node1->get_id();
    recv_msg_history.expect_cmd_rsp_from = node2->get_id();
    recv_msg_history.data.clear();
    atbus::node::send_data_options_t options;
    options.sequence = node1->allocate_message_sequence();
    recv_msg_history.last_cmd_seq = options.sequence;
    CASE_EXPECT_EQ(0, node1->send_custom_command(node2->get_id(),
                                                 gsl::span<gsl::span<const unsigned char>>(custom_args), options));

    UNITTEST_WAIT_UNTIL(conf.ev_loop, count + 1 < recv_msg_history.count, 3000, 0) {}

    CASE_EXPECT_EQ(send_data, recv_msg_history.data);
  } while (false);

  unit_test_setup_exit(&ev_loop);
}

CASE_TEST(atbus_node_msg, custom_cmd_by_temp_node) {
  atbus::node::conf_t conf;
  atbus::node::default_conf(&conf);
  uv_loop_t ev_loop;
  uv_loop_init(&ev_loop);

  conf.ev_loop = &ev_loop;

  do {
    atbus::node::ptr_t node1 = atbus::node::create();
    atbus::node::ptr_t node2 = atbus::node::create();
    setup_atbus_node_logger(*node1);
    setup_atbus_node_logger(*node2);

    node1->init(0x12345678, &conf);
    node2->init(0, &conf);

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node1->listen("ipv4://127.0.0.1:16387"));

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node1->start());
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node2->start());

    time_t proc_t = time(nullptr) + 1;
    node1->poll();
    node2->poll();
    node1->proc(unit_test_make_timepoint(proc_t, 0));
    node2->proc(unit_test_make_timepoint(proc_t, 0));

    node2->connect("ipv4://127.0.0.1:16387");

    UNITTEST_WAIT_UNTIL(conf.ev_loop, node2->is_endpoint_available(node1->get_id()), 8000, 0) {}

    int count = recv_msg_history.count;
    node1->set_on_custom_command_request_handle(node_msg_test_recv_msg_test_custom_cmd_fn);
    node2->set_on_custom_command_response_handle(node_msg_test_recv_msg_test_custom_rsp_fn);

    char test_str[] = "hello world!";
    std::string send_data = test_str;
    gsl::span<const unsigned char> custom_args[] = {
        gsl::span<const unsigned char>(reinterpret_cast<const unsigned char *>(&test_str[0]), 5),
        gsl::span<const unsigned char>(reinterpret_cast<const unsigned char *>(&test_str[6]), 5),
        gsl::span<const unsigned char>(reinterpret_cast<const unsigned char *>(&test_str[11]), 1)};

    send_data[5] = '\0';
    send_data[11] = '\0';
    send_data += '!';
    send_data += '\0';

    recv_msg_history.last_cmd_seq = 0;
    recv_msg_history.expect_cmd_req_from = node2->get_id();
    recv_msg_history.expect_cmd_rsp_from = node1->get_id();
    recv_msg_history.data.clear();
    atbus::node::send_data_options_t options;
    options.sequence = node2->allocate_message_sequence();
    recv_msg_history.last_cmd_seq = options.sequence;
    CASE_EXPECT_EQ(0, node2->send_custom_command(node1->get_id(),
                                                 gsl::span<gsl::span<const unsigned char>>(custom_args), options));

    UNITTEST_WAIT_UNTIL(conf.ev_loop, count + 1 < recv_msg_history.count, 3000, 0) {}

    CASE_EXPECT_EQ(send_data, recv_msg_history.data);
  } while (false);

  unit_test_setup_exit(&ev_loop);
}

// 发给自己的命令
CASE_TEST(atbus_node_msg, send_cmd_to_self) {
  atbus::node::conf_t conf;
  atbus::node::default_conf(&conf);
  uv_loop_t ev_loop;
  uv_loop_init(&ev_loop);

  conf.ev_loop = &ev_loop;

  {
    char cmds[][8] = {"self", "command", "yep"};
    size_t cmds_len[] = {strlen(cmds[0]), strlen(cmds[1]), strlen(cmds[2])};
    gsl::span<const unsigned char> cmds_in[] = {
        gsl::span<const unsigned char>(reinterpret_cast<const unsigned char *>(cmds[0]), cmds_len[0]),
        gsl::span<const unsigned char>(reinterpret_cast<const unsigned char *>(cmds[1]), cmds_len[1]),
        gsl::span<const unsigned char>(reinterpret_cast<const unsigned char *>(cmds[2]), cmds_len[2])};

    atbus::node::ptr_t node1 = atbus::node::create();
    setup_atbus_node_logger(*node1);

    CASE_EXPECT_EQ(EN_ATBUS_ERR_NOT_INITED,
                   node1->send_custom_command(node1->get_id(), gsl::span<gsl::span<const unsigned char>>(cmds_in)));

    node1->init(0x12345678, &conf);

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node1->listen("ipv4://127.0.0.1:16387"));

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node1->start());

    time_t proc_tm = time(nullptr) + 1;
    node1->poll();
    node1->proc(unit_test_make_timepoint(proc_tm, 0));

    int count = recv_msg_history.count;
    node1->set_on_custom_command_request_handle(node_msg_test_recv_msg_test_custom_cmd_fn);
    node1->set_on_custom_command_response_handle(node_msg_test_recv_msg_test_custom_rsp_fn);
    CASE_EXPECT_TRUE(!!node1->get_on_custom_command_request_handle());

    recv_msg_history.last_cmd_seq = 0;
    recv_msg_history.expect_cmd_req_from = node1->get_id();
    recv_msg_history.expect_cmd_rsp_from = node1->get_id();
    recv_msg_history.data.clear();
    {
      atbus::node::send_data_options_t options;
      options.sequence = node1->allocate_message_sequence();
      recv_msg_history.last_cmd_seq = options.sequence;
      node1->send_custom_command(node1->get_id(), gsl::span<gsl::span<const unsigned char>>(cmds_in), options);
    }

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
  uv_loop_t ev_loop;
  uv_loop_init(&ev_loop);

  conf.ev_loop = &ev_loop;

  {
    atbus::node::ptr_t node1 = atbus::node::create();
    setup_atbus_node_logger(*node1);

    node1->init(0x12345678, &conf);

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node1->listen("ipv4://127.0.0.1:16387"));

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node1->start());

    time_t proc_t = time(nullptr) + 1;
    node1->poll();
    node1->proc(unit_test_make_timepoint(proc_t, 0));

    std::string send_data;
    send_data.assign("self\0hello world!\n", sizeof("self\0hello world!\n") - 1);

    int count = recv_msg_history.count;
    node1->set_on_forward_request_handle(node_msg_test_recv_msg_test_record_fn);
    uint64_t data_seq = 0;
    atbus::node::send_data_options_t options;
    node1->send_data(
        node1->get_id(), 0,
        gsl::span<const unsigned char>(reinterpret_cast<const unsigned char *>(send_data.data()), send_data.size()),
        options);
    data_seq = options.sequence;

    CASE_EXPECT_EQ(count + 1, recv_msg_history.count);
    CASE_EXPECT_EQ(send_data, recv_msg_history.data);
    CASE_EXPECT_NE(0, data_seq);
  }

  unit_test_setup_exit(&ev_loop);
}

static int node_msg_test_recv_on_forward_response_error_fn(const atbus::node &, const atbus::endpoint *,
                                                           const atbus::connection *, const atbus::message *m) {
  ++recv_msg_history.count;
  if (nullptr != m) {
    recv_msg_history.status = m->get_head() == nullptr ? 0 : m->get_head()->result_code();
    recv_msg_history.data = m->get_body() == nullptr ? std::string() : m->get_body()->data_transform_rsp().content();
    if (0 != recv_msg_history.status) {
      ++recv_msg_history.failed_count;
    }
  }
  return 0;
}

CASE_TEST(atbus_node_msg, send_loopback_error) {
  atbus::node::conf_t conf;
  atbus::node::default_conf(&conf);
  uv_loop_t ev_loop;
  uv_loop_init(&ev_loop);

  conf.ev_loop = &ev_loop;

  do {
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

    time_t proc_t = time(nullptr) + 1;
    node1->poll();
    node2->poll();
    node1->proc(unit_test_make_timepoint(proc_t, 0));
    node2->proc(unit_test_make_timepoint(proc_t, 0));

    node1->connect("ipv4://127.0.0.1:16388");

    UNITTEST_WAIT_UNTIL(conf.ev_loop,
                        node1->is_endpoint_available(node2->get_id()) && node2->is_endpoint_available(node1->get_id()),
                        8000, 0) {}

    int count = recv_msg_history.count;
    node1->set_on_forward_response_handle(node_msg_test_recv_on_forward_response_error_fn);

    std::string send_data = "loop back message!";

    recv_msg_history.last_cmd_seq = 0;
    recv_msg_history.status = 0;
    recv_msg_history.expect_cmd_req_from = node2->get_id();
    recv_msg_history.expect_cmd_rsp_from = node1->get_id();
    recv_msg_history.data.clear();

    do {
      atbus::endpoint *target = nullptr;
      atbus::connection *target_conn = nullptr;
      atbus::topology_peer::ptr_t next_hop;
      CASE_EXPECT_EQ(0, node1->get_peer_channel(node2->get_id(), &atbus::endpoint::get_data_connection, &target,
                                                &target_conn, &next_hop));
      CASE_EXPECT_NE(nullptr, target);
      CASE_EXPECT_NE(nullptr, target_conn);
      CASE_EXPECT_TRUE(!next_hop || next_hop->get_bus_id() == node2->get_id());
      if (nullptr == target_conn) {
        break;
      }

      ::google::protobuf::ArenaOptions options;
      atbus::message m{options};
      m.mutable_head().set_version(node1->get_protocol_version());
      m.mutable_head().set_type(0);
      m.mutable_head().set_result_code(0);
      m.mutable_head().set_sequence(node1->allocate_message_sequence());
      m.mutable_head().set_source_bus_id(0);  // fake bad parameter, this should be reset by receiver

      m.mutable_body().mutable_data_transform_req()->set_from(node1->get_id());
      m.mutable_body().mutable_data_transform_req()->set_to(0x12346789);
      m.mutable_body().mutable_data_transform_req()->add_router(node1->get_id());
      *m.mutable_body().mutable_data_transform_req()->mutable_content() = send_data;
      m.mutable_body().mutable_data_transform_req()->set_flags(atbus::protocol::FORWARD_DATA_FLAG_REQUIRE_RSP);
      CASE_EXPECT_EQ(0, atbus::message_handler::send_message(*node1, *target_conn, m));

    } while (false);

    UNITTEST_WAIT_UNTIL(conf.ev_loop, count + 1 <= recv_msg_history.count, 3000, 0) {}

    CASE_EXPECT_EQ(send_data, recv_msg_history.data);
    CASE_EXPECT_EQ(EN_ATBUS_ERR_ATNODE_INVALID_ID, recv_msg_history.status);
  } while (false);

  unit_test_setup_exit(&ev_loop);
}

static int node_msg_test_recv_and_send_msg_on_forward_response_fn(const atbus::node &, const atbus::endpoint *,
                                                                  const atbus::connection *, const atbus::message *) {
  ++recv_msg_history.count;
  return 0;
}

static int node_msg_test_recv_and_send_msg_fn(const atbus::node &n, const atbus::endpoint *ep,
                                              const atbus::connection *conn, const atbus::message &m,
                                              gsl::span<const unsigned char> buffer) {
  recv_msg_history.n = &n;
  recv_msg_history.ep = ep;
  recv_msg_history.conn = conn;
  recv_msg_history.status = m.get_head() == nullptr ? 0 : m.get_head()->result_code();
  ++recv_msg_history.count;

  std::streamsize w = std::cout.width();
  if (!buffer.empty()) {
    recv_msg_history.data.assign(reinterpret_cast<const char *>(buffer.data()), buffer.size());
    CASE_MSG_INFO() << "[Log Debug] node=0x" << std::setfill('0') << std::hex << std::setw(8) << n.get_id() << ", ep=0x"
                    << std::setw(8) << (nullptr == ep ? 0 : ep->get_id()) << ", c=" << conn << std::setfill(' ')
                    << std::setw(static_cast<int>(w)) << std::dec << "\t" << "recv message: ";
    std::cout.write(reinterpret_cast<const char *>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
    std::cout << std::endl;
  } else {
    recv_msg_history.data.clear();
    CASE_MSG_INFO() << "[Log Debug] node=0x" << std::setfill('0') << std::hex << std::setw(8) << n.get_id() << ", ep=0x"
                    << std::setw(8) << (nullptr == ep ? 0 : ep->get_id()) << ", c=" << conn << std::setfill(' ')
                    << std::setw(static_cast<int>(w)) << std::dec << "\t" << "recv message: [NOTHING]" << std::endl;
  }

  std::string sended_data;
  sended_data.assign(reinterpret_cast<const char *>(buffer.data()), buffer.size());
  sended_data += sended_data;

  atbus::node *np = const_cast<atbus::node *>(&n);
  np->set_on_forward_request_handle(node_msg_test_recv_msg_test_record_fn);
  np->set_on_forward_response_handle(node_msg_test_recv_and_send_msg_on_forward_response_fn);

  atbus::node::send_data_options_t options;
  options.flags |= static_cast<decltype(options.flags)>(atbus::node::send_data_options_t::flag_type::kRequireResponse);
  np->send_data(
      n.get_id(), 0,
      gsl::span<const unsigned char>(reinterpret_cast<const unsigned char *>(sended_data.data()), sended_data.size()),
      options);
  return 0;
}

// 发给自己,下一帧回调
CASE_TEST(atbus_node_msg, send_msg_to_self_and_need_rsp) {
  atbus::node::conf_t conf;
  atbus::node::default_conf(&conf);
  uv_loop_t ev_loop;
  uv_loop_init(&ev_loop);

  conf.ev_loop = &ev_loop;

  {
    atbus::node::ptr_t node1 = atbus::node::create();
    setup_atbus_node_logger(*node1);

    node1->init(0x12345678, &conf);

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node1->listen("ipv4://127.0.0.1:16387"));

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node1->start());

    time_t proc_t = time(nullptr) + 1;
    node1->poll();
    node1->proc(unit_test_make_timepoint(proc_t, 0));

    std::string send_data;
    send_data.assign("self\0hello world!\n", sizeof("self\0hello world!\n") - 1);

    int count = recv_msg_history.count;
    node1->set_on_forward_request_handle(node_msg_test_recv_and_send_msg_fn);
    node1->send_data(
        node1->get_id(), 0,
        gsl::span<const unsigned char>(reinterpret_cast<const unsigned char *>(send_data.data()), send_data.size()));

    CASE_EXPECT_EQ(count + 3, recv_msg_history.count);
    send_data += send_data;
    CASE_EXPECT_EQ(send_data, recv_msg_history.data);
  }

  unit_test_setup_exit(&ev_loop);
}

// 上下游节点消息转发测试
CASE_TEST(atbus_node_msg, upstream_and_downstream) {
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

    node_upstream->init(0x12345678, &conf);

    conf.upstream_address = "ipv4://127.0.0.1:16387";
    node_downstream->init(0x12346789, &conf);

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream->listen("ipv4://127.0.0.1:16387"));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_downstream->listen("ipv4://127.0.0.1:16388"));

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream->start());
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_downstream->start());

    time_t proc_t = time(nullptr) + 1;

    UNITTEST_WAIT_UNTIL(conf.ev_loop,
                        node_downstream->is_endpoint_available(node_upstream->get_id()) &&
                            node_upstream->is_endpoint_available(node_downstream->get_id()),
                        8000, 64) {
      node_upstream->proc(unit_test_make_timepoint(proc_t, 0));
      node_downstream->proc(unit_test_make_timepoint(proc_t, 0));
      ++proc_t;
    }

    // 顺便启动上下游节点的ping
    proc_t += static_cast<time_t>(conf.ping_interval.count() / 1000000) + 1;
    node_upstream->proc(unit_test_make_timepoint(proc_t, 0));
    node_downstream->proc(unit_test_make_timepoint(proc_t, 0));

    node_downstream->set_on_forward_request_handle(node_msg_test_recv_msg_test_record_fn);
    node_upstream->set_on_forward_request_handle(node_msg_test_recv_msg_test_record_fn);

    int count = recv_msg_history.count;

    // 发消息啦 -  upstream to downstream
    {
      std::string send_data;
      send_data.assign("upstream to downstream\0hello world!\n", sizeof("upstream to downstream\0hello world!\n") - 1);

      uint64_t data_seq = 0;
      atbus::node::send_data_options_t options;
      node_upstream->send_data(
          node_downstream->get_id(), 0,
          gsl::span<const unsigned char>(reinterpret_cast<const unsigned char *>(send_data.data()), send_data.size()),
          options);
      data_seq = options.sequence;
      UNITTEST_WAIT_UNTIL(conf.ev_loop, count != recv_msg_history.count, 3000, 0) {}

      CASE_EXPECT_EQ(send_data, recv_msg_history.data);
      CASE_EXPECT_NE(0, data_seq);
    }

    // 发消息啦 - downstream to upstream
    {
      std::string send_data;
      send_data.assign("downstream to upstream\0hello world!\n", sizeof("downstream to upstream\0hello world!\n") - 1);

      count = recv_msg_history.count;

      uint64_t data_seq = 0;
      atbus::node::send_data_options_t options;
      node_downstream->send_data(
          node_upstream->get_id(), 0,
          gsl::span<const unsigned char>(reinterpret_cast<const unsigned char *>(send_data.data()), send_data.size()),
          options);
      data_seq = options.sequence;
      UNITTEST_WAIT_UNTIL(conf.ev_loop, count != recv_msg_history.count, 3000, 0) {}

      CASE_EXPECT_EQ(send_data, recv_msg_history.data);
      CASE_EXPECT_NE(0, data_seq);
    }

    CASE_EXPECT_GT(
        node_downstream->get_endpoint(node_upstream->get_id())->get_stat_last_pong().time_since_epoch().count(), 0);

    do {
      atbus::endpoint *downstream_ep = node_upstream->get_endpoint(node_downstream->get_id());
      CASE_EXPECT_NE(nullptr, downstream_ep);
      if (nullptr == downstream_ep) {
        break;
      }
      CASE_EXPECT_GT(downstream_ep->get_stat_last_pong().time_since_epoch().count(), 0);

      CASE_MSG_INFO() << "Upstream push start times: " << downstream_ep->get_stat_push_start_times() << std::endl;
      CASE_MSG_INFO() << "Upstream push start size: " << downstream_ep->get_stat_push_start_size() << std::endl;
      CASE_MSG_INFO() << "Upstream push success times: " << downstream_ep->get_stat_push_success_times() << std::endl;
      CASE_MSG_INFO() << "Upstream push success size: " << downstream_ep->get_stat_push_success_size() << std::endl;
      CASE_MSG_INFO() << "Upstream push failed times: " << downstream_ep->get_stat_push_failed_times() << std::endl;
      CASE_MSG_INFO() << "Upstream push failed size: " << downstream_ep->get_stat_push_failed_size() << std::endl;
      CASE_MSG_INFO() << "Upstream pull size: " << downstream_ep->get_stat_pull_size() << std::endl;
      CASE_MSG_INFO() << "Upstream created time ticks: "
                      << downstream_ep->get_stat_created_time().time_since_epoch().count() << std::endl;
    } while (false);
  }

  unit_test_setup_exit(&ev_loop);
}

// 兄弟节点通过父节点转发消息
CASE_TEST(atbus_node_msg, transfer_and_connect) {
  atbus::node::conf_t conf;
  atbus::node::default_conf(&conf);
  uv_loop_t ev_loop;
  uv_loop_init(&ev_loop);

  conf.ev_loop = &ev_loop;

  // 只有发生冲突才会注册不成功，否则会无限重试注册上游节点，直到其上线
  {
    atbus::node::ptr_t node_upstream = atbus::node::create();
    atbus::node::ptr_t node_downstream_1 = atbus::node::create();
    atbus::node::ptr_t node_downstream_2 = atbus::node::create();
    setup_atbus_node_logger(*node_upstream);
    setup_atbus_node_logger(*node_downstream_1);
    setup_atbus_node_logger(*node_downstream_2);

    node_upstream->init(0x12345678, &conf);

    conf.upstream_address = "ipv4://127.0.0.1:16387";
    node_downstream_1->init(0x12346789, &conf);
    node_downstream_2->init(0x12346890, &conf);

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream->listen("ipv4://127.0.0.1:16387"));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_downstream_1->listen("ipv4://127.0.0.1:16388"));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_downstream_2->listen("ipv4://127.0.0.1:16389"));

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream->start());
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_downstream_1->start());
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_downstream_2->start());

    time_t proc_t = time(nullptr) + 1;
    node_downstream_1->set_on_forward_request_handle(node_msg_test_recv_msg_test_record_fn);
    node_downstream_2->set_on_forward_request_handle(node_msg_test_recv_msg_test_record_fn);

    // wait for register finished
    UNITTEST_WAIT_UNTIL(conf.ev_loop,
                        node_upstream->is_endpoint_available(node_downstream_1->get_id()) &&
                            node_upstream->is_endpoint_available(node_downstream_2->get_id()) &&
                            node_downstream_2->is_endpoint_available(node_upstream->get_id()) &&
                            node_downstream_1->is_endpoint_available(node_upstream->get_id()),
                        8000, 64) {
      node_upstream->proc(unit_test_make_timepoint(proc_t, 0));
      node_downstream_1->proc(unit_test_make_timepoint(proc_t, 0));
      node_downstream_2->proc(unit_test_make_timepoint(proc_t, 0));

      ++proc_t;
    }

    atbus::node::ptr_t nodes[] = {node_upstream, node_downstream_1, node_downstream_2};
    for (auto &n : nodes) {
      n->get_topology_registry()->update_peer(node_downstream_1->get_id(), node_upstream->get_id(), nullptr);
      n->get_topology_registry()->update_peer(node_downstream_2->get_id(), node_upstream->get_id(), nullptr);
    }

    // 转发消息
    std::string send_data;
    send_data.assign("transfer through upstream\n", sizeof("transfer through upstream\n") - 1);

    int count = recv_msg_history.count;
    recv_msg_history.data.clear();
    node_downstream_1->send_data(
        node_downstream_2->get_id(), 0,
        gsl::span<const unsigned char>(reinterpret_cast<const unsigned char *>(send_data.data()), send_data.size()));
    UNITTEST_WAIT_UNTIL(conf.ev_loop, count != recv_msg_history.count && !recv_msg_history.data.empty(), 5000, 0) {}

    CASE_EXPECT_EQ(send_data, recv_msg_history.data);
  }

  unit_test_setup_exit(&ev_loop);
}

// 兄弟节点通过多层父节点转发消息
CASE_TEST(atbus_node_msg, transfer_only) {
  atbus::node::conf_t conf;
  atbus::node::default_conf(&conf);
  uv_loop_t ev_loop;
  uv_loop_init(&ev_loop);

  conf.ev_loop = &ev_loop;

  // 只有发生冲突才会注册不成功，否则会无限重试注册上游节点，直到其上线
  {
    atbus::node::ptr_t node_upstream_1 = atbus::node::create();
    atbus::node::ptr_t node_upstream_2 = atbus::node::create();
    atbus::node::ptr_t node_downstream_1 = atbus::node::create();
    atbus::node::ptr_t node_downstream_2 = atbus::node::create();
    setup_atbus_node_logger(*node_upstream_1);
    setup_atbus_node_logger(*node_upstream_2);
    setup_atbus_node_logger(*node_downstream_1);
    setup_atbus_node_logger(*node_downstream_2);

    node_upstream_1->init(0x12345678, &conf);
    node_upstream_2->init(0x12356789, &conf);

    conf.upstream_address = "ipv4://127.0.0.1:16387";
    node_downstream_1->init(0x12346789, &conf);
    conf.upstream_address = "ipv4://127.0.0.1:16388";
    node_downstream_2->init(0x12354678, &conf);

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream_1->listen("ipv4://127.0.0.1:16387"));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream_2->listen("ipv4://127.0.0.1:16388"));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_downstream_1->listen("ipv4://127.0.0.1:16389"));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_downstream_2->listen("ipv4://127.0.0.1:16390"));

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream_1->start());
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream_2->start());
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_downstream_1->start());
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_downstream_2->start());

    time_t proc_t = time(nullptr) + 1;
    node_downstream_1->set_on_forward_request_handle(node_msg_test_recv_msg_test_record_fn);
    node_downstream_2->set_on_forward_request_handle(node_msg_test_recv_msg_test_record_fn);
    node_upstream_1->connect("ipv4://127.0.0.1:16388");

    // wait for register finished
    UNITTEST_WAIT_UNTIL(conf.ev_loop,
                        node_downstream_1->is_endpoint_available(node_upstream_1->get_id()) &&
                            node_upstream_1->is_endpoint_available(node_downstream_1->get_id()) &&
                            node_downstream_2->is_endpoint_available(node_upstream_2->get_id()) &&
                            node_upstream_2->is_endpoint_available(node_downstream_2->get_id()) &&
                            node_upstream_1->is_endpoint_available(node_upstream_2->get_id()) &&
                            node_upstream_2->is_endpoint_available(node_upstream_1->get_id()),
                        8000, 64) {
      node_upstream_1->proc(unit_test_make_timepoint(proc_t, 0));
      node_upstream_2->proc(unit_test_make_timepoint(proc_t, 0));
      node_downstream_1->proc(unit_test_make_timepoint(proc_t, 0));
      node_downstream_2->proc(unit_test_make_timepoint(proc_t, 0));

      ++proc_t;
    }
    CASE_EXPECT_TRUE(node_upstream_1->is_endpoint_available(node_upstream_2->get_id()) &&
                     node_upstream_2->is_endpoint_available(node_upstream_1->get_id()));

    // 注册关系
    atbus::node::ptr_t nodes[] = {node_upstream_1, node_upstream_2, node_downstream_1, node_downstream_2};
    for (auto &n : nodes) {
      n->get_topology_registry()->update_peer(node_downstream_1->get_id(), node_upstream_1->get_id(), nullptr);
      n->get_topology_registry()->update_peer(node_downstream_2->get_id(), node_upstream_2->get_id(), nullptr);
    }

    // 转发消息
    std::string send_data;
    recv_msg_history.data.clear();
    send_data.assign("transfer through upstream only\n", sizeof("transfer through upstream only\n") - 1);

    int count = recv_msg_history.count;
    node_downstream_1->send_data(
        node_downstream_2->get_id(), 0,
        gsl::span<const unsigned char>(reinterpret_cast<const unsigned char *>(send_data.data()), send_data.size()));
    UNITTEST_WAIT_UNTIL(conf.ev_loop, count != recv_msg_history.count, 8000, 0) {}
    for (int i = 0; i < 64; ++i) {
      uv_run(conf.ev_loop, UV_RUN_NOWAIT);
      CASE_THREAD_SLEEP_MS(4);
    }

    CASE_EXPECT_GT(recv_msg_history.count, count);
    CASE_EXPECT_EQ(send_data, recv_msg_history.data);
  }

  unit_test_setup_exit(&ev_loop);
}

// 基于拓扑关系的多级上游/下游转发路径测试
CASE_TEST(atbus_node_msg, topology_registry_multi_level_route) {
  atbus::node::conf_t conf;
  atbus::node::default_conf(&conf);
  uv_loop_t ev_loop;
  uv_loop_init(&ev_loop);

  conf.ev_loop = &ev_loop;

  {
    atbus::node::ptr_t node_upstream = atbus::node::create();
    atbus::node::ptr_t node_mid = atbus::node::create();
    atbus::node::ptr_t node_downstream = atbus::node::create();
    setup_atbus_node_logger(*node_upstream);
    setup_atbus_node_logger(*node_mid);
    setup_atbus_node_logger(*node_downstream);

    node_upstream->init(0x12345678, &conf);

    conf.upstream_address = "ipv4://127.0.0.1:16387";
    node_mid->init(0x12346789, &conf);

    conf.upstream_address = "ipv4://127.0.0.1:16388";
    node_downstream->init(0x12346890, &conf);

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream->listen("ipv4://127.0.0.1:16387"));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_mid->listen("ipv4://127.0.0.1:16388"));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_downstream->listen("ipv4://127.0.0.1:16389"));

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream->start());
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_mid->start());
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_downstream->start());

    time_t proc_t = time(nullptr) + 1;
    UNITTEST_WAIT_UNTIL(conf.ev_loop,
                        node_mid->is_endpoint_available(node_upstream->get_id()) &&
                            node_upstream->is_endpoint_available(node_mid->get_id()) &&
                            node_downstream->is_endpoint_available(node_mid->get_id()) &&
                            node_mid->is_endpoint_available(node_downstream->get_id()),
                        8000, 64) {
      node_upstream->proc(unit_test_make_timepoint(proc_t, 0));
      node_mid->proc(unit_test_make_timepoint(proc_t, 0));
      node_downstream->proc(unit_test_make_timepoint(proc_t, 0));
      ++proc_t;
    }

    CASE_EXPECT_EQ(nullptr, node_upstream->get_endpoint(node_downstream->get_id()));
    CASE_EXPECT_EQ(nullptr, node_downstream->get_endpoint(node_upstream->get_id()));

    atbus::topology_peer::ptr_t next_hop;
    CASE_EXPECT_EQ(static_cast<int>(atbus::topology_relation_type::kInvalid),
                   static_cast<int>(node_upstream->get_topology_relation(node_downstream->get_id(), &next_hop)));
    CASE_EXPECT_FALSE(next_hop);

    std::string send_data = "topology multi-level route\n";
    {
      atbus::node::send_data_options_t options;
      options.flags |=
          static_cast<decltype(options.flags)>(atbus::node::send_data_options_t::flag_type::kRequireResponse);
      ::ATBUS_MACRO_PROTOBUF_NAMESPACE_ID::ArenaOptions arena_options;
      arena_options.initial_block_size = ATBUS_MACRO_RESERVED_SIZE;
      atbus::message msg{arena_options};
      node_msg_test_build_forward_message(
          *node_upstream, node_downstream->get_id(), 0,
          gsl::span<const unsigned char>(reinterpret_cast<const unsigned char *>(send_data.data()), send_data.size()),
          options, msg);
      atbus::endpoint *next_ep = nullptr;
      atbus::connection *next_conn = nullptr;
      int ret = atframework::atbus::node_msg_test_access::send_data_message(*node_upstream, node_downstream->get_id(),
                                                                            msg, &next_ep, &next_conn, options);
      CASE_EXPECT_NE(EN_ATBUS_ERR_SUCCESS, ret);
      CASE_EXPECT_EQ(nullptr, next_ep);
    }

    node_upstream->get_topology_registry()->update_peer(node_mid->get_id(), node_upstream->get_id(), nullptr);
    node_upstream->get_topology_registry()->update_peer(node_downstream->get_id(), node_mid->get_id(), nullptr);

    node_mid->get_topology_registry()->update_peer(node_downstream->get_id(), node_mid->get_id(), nullptr);

    CASE_EXPECT_TRUE(
        node_downstream->get_topology_registry()->update_peer(node_mid->get_id(), node_upstream->get_id(), nullptr));
    CASE_EXPECT_FALSE(
        node_downstream->get_topology_registry()->update_peer(node_upstream->get_id(), node_mid->get_id(), nullptr));

    CASE_EXPECT_EQ(static_cast<int>(atbus::topology_relation_type::kTransitiveDownstream),
                   static_cast<int>(node_upstream->get_topology_relation(node_downstream->get_id(), &next_hop)));
    CASE_EXPECT_TRUE(next_hop);
    CASE_EXPECT_EQ(node_mid->get_id(), next_hop->get_bus_id());

    CASE_EXPECT_EQ(static_cast<int>(atbus::topology_relation_type::kTransitiveUpstream),
                   static_cast<int>(node_downstream->get_topology_relation(node_upstream->get_id(), &next_hop)));
    CASE_EXPECT_TRUE(next_hop);
    CASE_EXPECT_EQ(node_mid->get_id(), next_hop->get_bus_id());

    node_downstream->set_on_forward_request_handle(node_msg_test_recv_msg_test_record_fn);
    int old_count = recv_msg_history.count;
    recv_msg_history.data.clear();
    {
      atbus::node::send_data_options_t options;
      options.flags |=
          static_cast<decltype(options.flags)>(atbus::node::send_data_options_t::flag_type::kRequireResponse);
      ::ATBUS_MACRO_PROTOBUF_NAMESPACE_ID::ArenaOptions arena_options;
      arena_options.initial_block_size = ATBUS_MACRO_RESERVED_SIZE;
      atbus::message msg{arena_options};
      node_msg_test_build_forward_message(
          *node_upstream, node_downstream->get_id(), 0,
          gsl::span<const unsigned char>(reinterpret_cast<const unsigned char *>(send_data.data()), send_data.size()),
          options, msg);
      atbus::endpoint *next_ep = nullptr;
      atbus::connection *next_conn = nullptr;
      CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS,
                     atframework::atbus::node_msg_test_access::send_data_message(
                         *node_upstream, node_downstream->get_id(), msg, &next_ep, &next_conn, options));
      CASE_EXPECT_TRUE(nullptr != next_ep);
      CASE_EXPECT_EQ(node_mid->get_id(), next_ep->get_id());
      CASE_EXPECT_TRUE(nullptr != next_conn);
    }

    {
      atbus::endpoint *next_ep = nullptr;
      atbus::connection *next_conn = nullptr;
      next_hop.reset();
      CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS,
                     node_upstream->get_peer_channel(node_downstream->get_id(), &atbus::endpoint::get_data_connection,
                                                     &next_ep, &next_conn, &next_hop));
      CASE_EXPECT_NE(nullptr, next_ep);
      CASE_EXPECT_NE(nullptr, next_conn);
      CASE_EXPECT_TRUE(next_hop);
      if (next_hop) {
        CASE_EXPECT_EQ(node_mid->get_id(), next_hop->get_bus_id());
      }
    }

    UNITTEST_WAIT_UNTIL(conf.ev_loop, recv_msg_history.count > old_count, 8000, 0) {
      node_upstream->proc(unit_test_make_timepoint(proc_t, 0));
      node_mid->proc(unit_test_make_timepoint(proc_t, 0));
      node_downstream->proc(unit_test_make_timepoint(proc_t, 0));
      ++proc_t;
    }
    CASE_EXPECT_EQ(send_data, recv_msg_history.data);

    atbus::endpoint *mid_to_downstream = node_mid->get_endpoint(node_downstream->get_id());
    CASE_EXPECT_TRUE(nullptr != mid_to_downstream);
    if (nullptr != mid_to_downstream) {
      mid_to_downstream->reset();
    }

    node_upstream->set_on_forward_response_handle(node_msg_test_send_data_forward_response_fn);
    int old_failed = recv_msg_history.failed_count;
    recv_msg_history.status = 0;
    {
      atbus::node::send_data_options_t options;
      ::ATBUS_MACRO_PROTOBUF_NAMESPACE_ID::ArenaOptions arena_options;
      arena_options.initial_block_size = ATBUS_MACRO_RESERVED_SIZE;
      atbus::message msg{arena_options};
      node_msg_test_build_forward_message(
          *node_upstream, node_downstream->get_id(), 0,
          gsl::span<const unsigned char>(reinterpret_cast<const unsigned char *>(send_data.data()), send_data.size()),
          options, msg);
      atbus::endpoint *next_ep = nullptr;
      atbus::connection *next_conn = nullptr;
      CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS,
                     atframework::atbus::node_msg_test_access::send_data_message(
                         *node_upstream, node_downstream->get_id(), msg, &next_ep, &next_conn, options));
      CASE_EXPECT_TRUE(nullptr != next_ep);
      CASE_EXPECT_EQ(node_mid->get_id(), next_ep->get_id());
    }

    UNITTEST_WAIT_UNTIL(conf.ev_loop, recv_msg_history.failed_count > old_failed, 8000, 0) {
      node_upstream->proc(unit_test_make_timepoint(proc_t, 0));
      node_mid->proc(unit_test_make_timepoint(proc_t, 0));
      node_downstream->proc(unit_test_make_timepoint(proc_t, 0));
      ++proc_t;
    }
    CASE_EXPECT_GT(recv_msg_history.failed_count, old_failed);
    CASE_EXPECT_TRUE(EN_ATBUS_ERR_ATNODE_NO_CONNECTION == recv_msg_history.status ||
                     EN_ATBUS_ERR_ATNODE_INVALID_ID == recv_msg_history.status);
  }

  unit_test_setup_exit(&ev_loop);
}

// 基于拓扑关系的多级上游/下游反向转发路径测试（下游到上游）
CASE_TEST(atbus_node_msg, topology_registry_multi_level_route_reverse) {
  atbus::node::conf_t conf;
  atbus::node::default_conf(&conf);
  uv_loop_t ev_loop;
  uv_loop_init(&ev_loop);

  conf.ev_loop = &ev_loop;

  {
    atbus::node::ptr_t node_upstream = atbus::node::create();
    atbus::node::ptr_t node_mid = atbus::node::create();
    atbus::node::ptr_t node_downstream = atbus::node::create();
    setup_atbus_node_logger(*node_upstream);
    setup_atbus_node_logger(*node_mid);
    setup_atbus_node_logger(*node_downstream);

    node_upstream->init(0x12345678, &conf);

    conf.upstream_address = "ipv4://127.0.0.1:16387";
    node_mid->init(0x12346789, &conf);

    conf.upstream_address = "ipv4://127.0.0.1:16388";
    node_downstream->init(0x12346890, &conf);

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream->listen("ipv4://127.0.0.1:16387"));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_mid->listen("ipv4://127.0.0.1:16388"));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_downstream->listen("ipv4://127.0.0.1:16389"));

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream->start());
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_mid->start());
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_downstream->start());

    time_t proc_t = time(nullptr) + 1;
    UNITTEST_WAIT_UNTIL(conf.ev_loop,
                        node_mid->is_endpoint_available(node_upstream->get_id()) &&
                            node_upstream->is_endpoint_available(node_mid->get_id()) &&
                            node_downstream->is_endpoint_available(node_mid->get_id()) &&
                            node_mid->is_endpoint_available(node_downstream->get_id()),
                        8000, 64) {
      node_upstream->proc(unit_test_make_timepoint(proc_t, 0));
      node_mid->proc(unit_test_make_timepoint(proc_t, 0));
      node_downstream->proc(unit_test_make_timepoint(proc_t, 0));
      ++proc_t;
    }

    node_upstream->get_topology_registry()->update_peer(node_mid->get_id(), node_upstream->get_id(), nullptr);
    node_upstream->get_topology_registry()->update_peer(node_downstream->get_id(), node_mid->get_id(), nullptr);

    node_mid->get_topology_registry()->update_peer(node_downstream->get_id(), node_mid->get_id(), nullptr);

    CASE_EXPECT_TRUE(
        node_downstream->get_topology_registry()->update_peer(node_mid->get_id(), node_upstream->get_id(), nullptr));
    CASE_EXPECT_FALSE(
        node_downstream->get_topology_registry()->update_peer(node_upstream->get_id(), node_mid->get_id(), nullptr));

    node_upstream->set_on_forward_request_handle(node_msg_test_recv_msg_test_record_fn);
    int old_count = recv_msg_history.count;
    recv_msg_history.data.clear();
    std::string send_data = "topology multi-level route reverse\n";

    node_downstream->send_data(
        node_upstream->get_id(), 0,
        gsl::span<const unsigned char>(reinterpret_cast<const unsigned char *>(send_data.data()), send_data.size()));

    UNITTEST_WAIT_UNTIL(conf.ev_loop, recv_msg_history.count > old_count && !recv_msg_history.data.empty(), 8000, 0) {
      node_upstream->proc(unit_test_make_timepoint(proc_t, 0));
      node_mid->proc(unit_test_make_timepoint(proc_t, 0));
      node_downstream->proc(unit_test_make_timepoint(proc_t, 0));
      ++proc_t;
    }

    CASE_EXPECT_EQ(send_data, recv_msg_history.data);
  }

  unit_test_setup_exit(&ev_loop);
}

// 节点发送失败测试
CASE_TEST(atbus_node_msg, send_failed) {
  atbus::node::conf_t conf;
  atbus::node::default_conf(&conf);
  uv_loop_t ev_loop;
  uv_loop_init(&ev_loop);

  conf.ev_loop = &ev_loop;

  {
    atbus::node::ptr_t node_upstream = atbus::node::create();
    setup_atbus_node_logger(*node_upstream);
    node_upstream->init(0x12345678, &conf);

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream->listen("ipv4://127.0.0.1:16387"));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream->start());

    std::string send_data;
    send_data.assign("send failed", sizeof("send failed") - 1);

    // send to downstream failed
    CASE_EXPECT_EQ(
        EN_ATBUS_ERR_ATNODE_INVALID_ID,
        node_upstream->send_data(0x12346780, 0,
                                 gsl::span<const unsigned char>(
                                     reinterpret_cast<const unsigned char *>(send_data.data()), send_data.size())));
    // send to brother and failed
    CASE_EXPECT_EQ(
        EN_ATBUS_ERR_ATNODE_INVALID_ID,
        node_upstream->send_data(0x12356789, 0,
                                 gsl::span<const unsigned char>(
                                     reinterpret_cast<const unsigned char *>(send_data.data()), send_data.size())));
  }

  unit_test_setup_exit(&ev_loop);
}

// 发送给下游节点转发失败的回复通知测试
// 发送给上游节点转发失败的回复通知测试
CASE_TEST(atbus_node_msg, transfer_failed) {
  atbus::node::conf_t conf;
  atbus::node::default_conf(&conf);
  uv_loop_t ev_loop;
  uv_loop_init(&ev_loop);

  conf.ev_loop = &ev_loop;

  // 只有发生冲突才会注册不成功，否则会无限重试注册上游节点，直到其上线
  {
    atbus::node::ptr_t node_upstream = atbus::node::create();
    atbus::node::ptr_t node_downstream_1 = atbus::node::create();
    setup_atbus_node_logger(*node_upstream);
    setup_atbus_node_logger(*node_downstream_1);

    node_upstream->init(0x12345678, &conf);

    conf.upstream_address = "ipv4://127.0.0.1:16387";
    node_downstream_1->init(0x12346789, &conf);

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream->listen("ipv4://127.0.0.1:16387"));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_downstream_1->listen("ipv4://127.0.0.1:16388"));

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream->start());
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_downstream_1->start());

    time_t proc_t = time(nullptr) + 1;
    node_downstream_1->set_on_forward_request_handle(node_msg_test_recv_msg_test_record_fn);
    node_downstream_1->set_on_forward_response_handle(node_msg_test_send_data_forward_response_fn);
    CASE_EXPECT_TRUE(!!node_downstream_1->get_on_forward_response_handle());

    // wait for register finished
    UNITTEST_WAIT_UNTIL(conf.ev_loop,
                        node_downstream_1->is_endpoint_available(node_upstream->get_id()) &&
                            node_upstream->is_endpoint_available(node_downstream_1->get_id()),
                        8000, 64) {
      node_upstream->proc(unit_test_make_timepoint(proc_t, 0));
      node_downstream_1->proc(unit_test_make_timepoint(proc_t, 0));

      ++proc_t;
    }

    CASE_EXPECT_TRUE(node_upstream->is_endpoint_available(node_downstream_1->get_id()) &&
                     node_downstream_1->is_endpoint_available(node_upstream->get_id()));

    atbus::node::ptr_t nodes[] = {node_upstream, node_downstream_1};
    for (auto &n : nodes) {
      n->get_topology_registry()->update_peer(node_downstream_1->get_id(), node_upstream->get_id(), nullptr);
      n->get_topology_registry()->update_peer(0x12346890, node_upstream->get_id(), nullptr);
      n->get_topology_registry()->update_peer(0x12356789, 0, nullptr);
    }

    // 转发消息
    std::string send_data;
    send_data.assign("transfer through upstream\n", sizeof("transfer through upstream\n") - 1);

    int count = recv_msg_history.failed_count;
    CASE_EXPECT_EQ(
        EN_ATBUS_ERR_SUCCESS,
        node_downstream_1->send_data(0x12346890, 0,
                                     gsl::span<const unsigned char>(
                                         reinterpret_cast<const unsigned char *>(send_data.data()), send_data.size())));
    CASE_EXPECT_EQ(
        EN_ATBUS_ERR_SUCCESS,
        node_downstream_1->send_data(0x12356789, 0,
                                     gsl::span<const unsigned char>(
                                         reinterpret_cast<const unsigned char *>(send_data.data()), send_data.size())));

    UNITTEST_WAIT_UNTIL(conf.ev_loop, count + 1 < recv_msg_history.failed_count, 8000, 0) {}

    CASE_EXPECT_EQ(count + 2, recv_msg_history.failed_count);
    CASE_EXPECT_EQ(EN_ATBUS_ERR_ATNODE_INVALID_ID, recv_msg_history.status);
  }

  unit_test_setup_exit(&ev_loop);
}

// 通过两个上游节点转发失败测试，本地连接不应该断
//     F1 <-----> F2
//    /            -(此连接断开)
//   C1             C2
// C1向C2发送消息，F2->F1->C1失败通知。重试多次后 F1-C1连接不断
CASE_TEST(atbus_node_msg, transfer_failed_cross_upstreams) {
  atbus::node::conf_t conf;
  atbus::node::default_conf(&conf);
  uv_loop_t ev_loop;
  uv_loop_init(&ev_loop);

  conf.ev_loop = &ev_loop;
  conf.fault_tolerant = 2;  // 容错设为2次。
  size_t try_times = 5;     // 我们尝试5次发失败

  // 只有发生冲突才会注册不成功，否则会无限重试注册上游节点，直到其上线
  {
    atbus::node::ptr_t node_upstream_1 = atbus::node::create();
    atbus::node::ptr_t node_upstream_2 = atbus::node::create();
    atbus::node::ptr_t node_downstream_1 = atbus::node::create();
    setup_atbus_node_logger(*node_upstream_1);
    setup_atbus_node_logger(*node_upstream_2);
    setup_atbus_node_logger(*node_downstream_1);

    node_upstream_1->init(0x12345678, &conf);
    node_upstream_1->set_on_remove_endpoint_handle(node_msg_test_remove_endpoint_fn);
    node_upstream_2->init(0x12356789, &conf);
    node_upstream_2->set_on_remove_endpoint_handle(node_msg_test_remove_endpoint_fn);

    conf.upstream_address = "ipv4://127.0.0.1:16387";
    node_downstream_1->init(0x12346789, &conf);

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream_1->listen("ipv4://127.0.0.1:16387"));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream_2->listen("ipv4://127.0.0.1:16388"));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_downstream_1->listen("ipv4://127.0.0.1:16389"));

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream_1->start());
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream_2->start());
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_downstream_1->start());

    time_t proc_t = time(nullptr) + 1;
    node_downstream_1->set_on_forward_request_handle(node_msg_test_recv_msg_test_record_fn);
    node_downstream_1->set_on_forward_response_handle(node_msg_test_send_data_forward_response_fn);
    node_downstream_1->set_on_remove_endpoint_handle(node_msg_test_remove_endpoint_fn);

    node_upstream_1->connect("ipv4://127.0.0.1:16388");
    // wait for register finished
    UNITTEST_WAIT_UNTIL(conf.ev_loop,
                        node_downstream_1->is_endpoint_available(node_upstream_1->get_id()) &&
                            node_upstream_1->is_endpoint_available(node_downstream_1->get_id()) &&
                            node_upstream_1->is_endpoint_available(node_upstream_2->get_id()) &&
                            node_upstream_2->is_endpoint_available(node_upstream_1->get_id()),
                        8000, 64) {
      node_upstream_1->proc(unit_test_make_timepoint(proc_t, 0));
      node_downstream_1->proc(unit_test_make_timepoint(proc_t, 0));

      ++proc_t;
    }
    CASE_EXPECT_TRUE(node_upstream_1->is_endpoint_available(node_upstream_2->get_id()) &&
                     node_upstream_2->is_endpoint_available(node_upstream_1->get_id()));

    atbus::node::ptr_t nodes[] = {node_upstream_1, node_upstream_2, node_downstream_1};
    for (auto &n : nodes) {
      n->get_topology_registry()->update_peer(node_downstream_1->get_id(), node_upstream_1->get_id(), nullptr);
      n->get_topology_registry()->update_peer(0x12356666, node_upstream_2->get_id(), nullptr);
    }

    int before_remove_endpoint_count = recv_msg_history.remove_endpoint_count;
    int before_test_count = recv_msg_history.failed_count;
    int recv_transfer_failed = 0;

    recv_msg_history.last_msg_router.clear();
    for (size_t i = 0; i < try_times; ++i) {
      // 转发消息
      std::string send_data;
      send_data.assign("transfer through upstream\n", sizeof("transfer through upstream\n") - 1);

      int count = recv_msg_history.failed_count;
      int send_res = node_downstream_1->send_data(
          0x12356666, 0,
          gsl::span<const unsigned char>(reinterpret_cast<const unsigned char *>(send_data.data()), send_data.size()));
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
    CASE_EXPECT_TRUE(node_downstream_1->is_endpoint_available(node_upstream_1->get_id()));
    CASE_EXPECT_TRUE(node_upstream_1->is_endpoint_available(node_downstream_1->get_id()));
  }

  unit_test_setup_exit(&ev_loop);
}

CASE_TEST(atbus_node_msg, msg_handler_get_body_name) {
  CASE_EXPECT_EQ(0, UTIL_STRFUNC_STRCASE_CMP("Unknown", atbus::message_handler::get_body_name(0)));
  CASE_EXPECT_EQ(0, UTIL_STRFUNC_STRCASE_CMP("Unknown", atbus::message_handler::get_body_name(1000000)));

  CASE_EXPECT_EQ(0, UTIL_STRFUNC_STRCASE_CMP("Unknown", atbus::message_handler::get_body_name(0)));
  CASE_EXPECT_EQ(atbus::protocol::message_body::descriptor()
                     ->FindFieldByNumber(atbus::protocol::message_body::kDataTransformReq)
                     ->full_name(),
                 std::string(atbus::message_handler::get_body_name(atbus::protocol::message_body::kDataTransformReq)));
}

// ============ Crypto Configuration Tests ============
#ifdef ATFW_UTIL_MACRO_CRYPTO_CIPHER_ENABLED
#  include <algorithm/crypto_cipher.h>
#  include <algorithm/crypto_dh.h>
#  include <unordered_set>

// Helper: Get available cipher algorithms
static std::unordered_set<std::string> get_available_cipher_algorithms() {
  std::unordered_set<std::string> result;
  for (auto &name : atfw::util::crypto::cipher::get_all_cipher_names()) {
    result.insert(name);
  }
  return result;
}

// Helper: Get available DH algorithms
static std::unordered_set<std::string> get_available_dh_algorithms() {
  std::unordered_set<std::string> result;
  for (auto &name : atfw::util::crypto::dh::get_all_curve_names()) {
    result.insert(name);
  }
  return result;
}

// Helper: Check if a key exchange algorithm is available
static bool is_key_exchange_available(atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_TYPE type) {
  auto available = get_available_dh_algorithms();
  switch (type) {
    case atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_X25519:
      return available.find("x25519") != available.end() || available.find("ecdh:x25519") != available.end();
    case atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_SECP256R1:
      return available.find("secp256r1") != available.end() || available.find("prime256v1") != available.end() ||
             available.find("ecdh:secp256r1") != available.end() ||
             available.find("ecdh:prime256v1") != available.end();
    case atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_SECP384R1:
      return available.find("secp384r1") != available.end() || available.find("ecdh:secp384r1") != available.end();
    case atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_SECP521R1:
      return available.find("secp521r1") != available.end() || available.find("ecdh:secp521r1") != available.end();
    default:
      return false;
  }
}

// Helper: Check if a cipher algorithm is available
static bool is_cipher_available(atbus::protocol::ATBUS_CRYPTO_ALGORITHM_TYPE type) {
  auto available = get_available_cipher_algorithms();
  switch (type) {
    case atbus::protocol::ATBUS_CRYPTO_ALGORITHM_XXTEA:
      return available.find("xxtea") != available.end();
    case atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_128_CBC:
      return available.find("aes-128-cbc") != available.end();
    case atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_192_CBC:
      return available.find("aes-192-cbc") != available.end();
    case atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_256_CBC:
      return available.find("aes-256-cbc") != available.end();
    case atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_128_GCM:
      return available.find("aes-128-gcm") != available.end();
    case atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_192_GCM:
      return available.find("aes-192-gcm") != available.end();
    case atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_256_GCM:
      return available.find("aes-256-gcm") != available.end();
    case atbus::protocol::ATBUS_CRYPTO_ALGORITHM_CHACHA20:
      return available.find("chacha20") != available.end();
    case atbus::protocol::ATBUS_CRYPTO_ALGORITHM_CHACHA20_POLY1305_IETF:
      return available.find("chacha20-poly1305-ietf") != available.end();
    case atbus::protocol::ATBUS_CRYPTO_ALGORITHM_XCHACHA20_POLY1305_IETF:
      return available.find("xchacha20-poly1305-ietf") != available.end();
    default:
      return false;
  }
}

// Helper: Get key exchange algorithm name
static const char *get_key_exchange_name(atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_TYPE type) {
  switch (type) {
    case atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_X25519:
      return "X25519";
    case atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_SECP256R1:
      return "SECP256R1";
    case atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_SECP384R1:
      return "SECP384R1";
    case atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_SECP521R1:
      return "SECP521R1";
    default:
      return "Unknown";
  }
}

// Helper: Get cipher algorithm name
static const char *get_cipher_name(atbus::protocol::ATBUS_CRYPTO_ALGORITHM_TYPE type) {
  switch (type) {
    case atbus::protocol::ATBUS_CRYPTO_ALGORITHM_XXTEA:
      return "XXTEA";
    case atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_128_CBC:
      return "AES-128-CBC";
    case atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_192_CBC:
      return "AES-192-CBC";
    case atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_256_CBC:
      return "AES-256-CBC";
    case atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_128_GCM:
      return "AES-128-GCM";
    case atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_192_GCM:
      return "AES-192-GCM";
    case atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_256_GCM:
      return "AES-256-GCM";
    case atbus::protocol::ATBUS_CRYPTO_ALGORITHM_CHACHA20:
      return "ChaCha20";
    case atbus::protocol::ATBUS_CRYPTO_ALGORITHM_CHACHA20_POLY1305_IETF:
      return "ChaCha20-Poly1305-IETF";
    case atbus::protocol::ATBUS_CRYPTO_ALGORITHM_XCHACHA20_POLY1305_IETF:
      return "XChaCha20-Poly1305-IETF";
    default:
      return "None";
  }
}

// Helper: Send encrypted message between two nodes and verify
static bool test_encrypted_message_between_nodes(atbus::node::ptr_t &node1, atbus::node::ptr_t &node2,
                                                 uv_loop_t *ev_loop, const std::string &test_message,
                                                 atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_TYPE key_exchange,
                                                 atbus::protocol::ATBUS_CRYPTO_ALGORITHM_TYPE cipher) {
  recv_msg_history.data.clear();
  recv_msg_history.count = 0;

  node1->set_on_forward_request_handle(node_msg_test_recv_msg_test_record_fn);
  node2->set_on_forward_request_handle(node_msg_test_recv_msg_test_record_fn);

  int initial_count = recv_msg_history.count;
  int send_result =
      node1->send_data(node2->get_id(), 0,
                       gsl::span<const unsigned char>(reinterpret_cast<const unsigned char *>(test_message.data()),
                                                      test_message.size()));
  if (send_result != EN_ATBUS_ERR_SUCCESS) {
    CASE_MSG_INFO() << "  [FAILED] send_data returned error: " << send_result
                    << " (KeyExchange: " << get_key_exchange_name(key_exchange)
                    << ", Cipher: " << get_cipher_name(cipher) << ")" << std::endl;
    return false;
  }

  UNITTEST_WAIT_UNTIL(ev_loop, recv_msg_history.count > initial_count && !recv_msg_history.data.empty(), 5000, 0) {}

  if (recv_msg_history.data != test_message) {
    CASE_MSG_INFO() << "  [FAILED] Message mismatch. Expected: " << test_message << ", Got: " << recv_msg_history.data
                    << " (KeyExchange: " << get_key_exchange_name(key_exchange)
                    << ", Cipher: " << get_cipher_name(cipher) << ")" << std::endl;
    return false;
  }

  return true;
}

// Test: Send messages with different key exchange algorithms (using AES-256-GCM as cipher)
CASE_TEST(atbus_node_msg, crypto_config_key_exchange_algorithms) {
  std::pair<atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_TYPE, const char *> key_exchange_algorithms[] = {
      {atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_X25519, "X25519"},
      {atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_SECP256R1, "SECP256R1"},
      {atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_SECP384R1, "SECP384R1"},
      {atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_SECP521R1, "SECP521R1"},
  };

  // Use AES-256-GCM as the default cipher for key exchange tests
  atbus::protocol::ATBUS_CRYPTO_ALGORITHM_TYPE default_cipher = atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_256_GCM;

  if (!is_cipher_available(default_cipher)) {
    CASE_MSG_INFO() << "[SKIP] AES-256-GCM not available, skipping key exchange tests" << std::endl;
    return;
  }

  uv_loop_t ev_loop;
  uv_loop_init(&ev_loop);

  size_t passed_count = 0;
  size_t skipped_count = 0;
  size_t total_count = sizeof(key_exchange_algorithms) / sizeof(key_exchange_algorithms[0]);

  for (auto &kex : key_exchange_algorithms) {
    if (!is_key_exchange_available(kex.first)) {
      CASE_MSG_INFO() << "[SKIP] Key exchange algorithm " << kex.second << " not available" << std::endl;
      ++skipped_count;
      continue;
    }

    CASE_MSG_INFO() << "[TEST] Testing key exchange: " << kex.second << " with AES-256-GCM" << std::endl;

    atbus::node::conf_t conf;
    atbus::node::default_conf(&conf);
    conf.ev_loop = &ev_loop;

    // Configure crypto
    conf.crypto_key_exchange_type = kex.first;
    conf.crypto_allow_algorithms.clear();
    conf.crypto_allow_algorithms.push_back(default_cipher);

    do {
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

      time_t proc_t = time(nullptr) + 1;
      node1->poll();
      node2->poll();
      node1->proc(unit_test_make_timepoint(proc_t, 0));
      node2->proc(unit_test_make_timepoint(proc_t, 0));

      node1->connect("ipv4://127.0.0.1:16388");

      UNITTEST_WAIT_UNTIL(
          &ev_loop, node1->is_endpoint_available(node2->get_id()) && node2->is_endpoint_available(node1->get_id()),
          8000, 0) {}

      std::string test_message = "Encrypted message with ";
      test_message += kex.second;
      test_message += " key exchange!";

      bool success =
          test_encrypted_message_between_nodes(node1, node2, &ev_loop, test_message, kex.first, default_cipher);

      if (success) {
        ++passed_count;
        CASE_MSG_INFO() << "  [PASS] " << kex.second << " key exchange test passed" << std::endl;
      } else {
        CASE_MSG_INFO() << "  [FAIL] " << kex.second << " key exchange test failed" << std::endl;
      }
    } while (false);
  }

  unit_test_setup_exit(&ev_loop);

  CASE_MSG_INFO() << "[SUMMARY] Key exchange tests: " << passed_count << "/" << (total_count - skipped_count)
                  << " passed, " << skipped_count << " skipped" << std::endl;
  CASE_EXPECT_GT(passed_count, 0);
}

// Test: Send messages with different cipher algorithms (using X25519 as key exchange)
CASE_TEST(atbus_node_msg, crypto_config_cipher_algorithms) {
  std::pair<atbus::protocol::ATBUS_CRYPTO_ALGORITHM_TYPE, const char *> cipher_algorithms[] = {
      {atbus::protocol::ATBUS_CRYPTO_ALGORITHM_XXTEA, "XXTEA"},
      {atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_128_CBC, "AES-128-CBC"},
      {atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_192_CBC, "AES-192-CBC"},
      {atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_256_CBC, "AES-256-CBC"},
      {atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_128_GCM, "AES-128-GCM"},
      {atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_192_GCM, "AES-192-GCM"},
      {atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_256_GCM, "AES-256-GCM"},
      {atbus::protocol::ATBUS_CRYPTO_ALGORITHM_CHACHA20, "ChaCha20"},
      {atbus::protocol::ATBUS_CRYPTO_ALGORITHM_CHACHA20_POLY1305_IETF, "ChaCha20-Poly1305-IETF"},
      {atbus::protocol::ATBUS_CRYPTO_ALGORITHM_XCHACHA20_POLY1305_IETF, "XChaCha20-Poly1305-IETF"},
  };

  // Use X25519 as default key exchange for cipher tests
  atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_TYPE default_kex = atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_X25519;

  if (!is_key_exchange_available(default_kex)) {
    // Fallback to SECP256R1 if X25519 not available
    default_kex = atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_SECP256R1;
    if (!is_key_exchange_available(default_kex)) {
      CASE_MSG_INFO() << "[SKIP] No key exchange algorithm available, skipping cipher tests" << std::endl;
      return;
    }
  }

  uv_loop_t ev_loop;
  uv_loop_init(&ev_loop);

  size_t passed_count = 0;
  size_t skipped_count = 0;
  size_t total_count = sizeof(cipher_algorithms) / sizeof(cipher_algorithms[0]);

  for (auto &cipher : cipher_algorithms) {
    if (!is_cipher_available(cipher.first)) {
      CASE_MSG_INFO() << "[SKIP] Cipher algorithm " << cipher.second << " not available" << std::endl;
      ++skipped_count;
      continue;
    }

    CASE_MSG_INFO() << "[TEST] Testing cipher: " << cipher.second << " with " << get_key_exchange_name(default_kex)
                    << std::endl;

    atbus::node::conf_t conf;
    atbus::node::default_conf(&conf);
    conf.ev_loop = &ev_loop;

    // Configure crypto
    conf.crypto_key_exchange_type = default_kex;
    conf.crypto_allow_algorithms.clear();
    conf.crypto_allow_algorithms.push_back(cipher.first);

    do {
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

      time_t proc_t = time(nullptr) + 1;
      node1->poll();
      node2->poll();
      node1->proc(unit_test_make_timepoint(proc_t, 0));
      node2->proc(unit_test_make_timepoint(proc_t, 0));

      node1->connect("ipv4://127.0.0.1:16388");

      UNITTEST_WAIT_UNTIL(
          &ev_loop, node1->is_endpoint_available(node2->get_id()) && node2->is_endpoint_available(node1->get_id()),
          8000, 0) {}

      std::string test_message = "Encrypted message with ";
      test_message += cipher.second;
      test_message += " cipher!";

      bool success =
          test_encrypted_message_between_nodes(node1, node2, &ev_loop, test_message, default_kex, cipher.first);
      if (success) {
        ++passed_count;
        CASE_MSG_INFO() << "  [PASS] " << cipher.second << " cipher test passed" << std::endl;
      } else {
        CASE_MSG_INFO() << "  [FAIL] " << cipher.second << " cipher test failed" << std::endl;
      }
      CASE_EXPECT_TRUE(success);
    } while (false);
  }

  unit_test_setup_exit(&ev_loop);

  CASE_MSG_INFO() << "[SUMMARY] Cipher tests: " << passed_count << "/" << (total_count - skipped_count) << " passed, "
                  << skipped_count << " skipped" << std::endl;
  CASE_EXPECT_GT(passed_count, 0);
}

// Test: Comprehensive crypto matrix - test all combinations of key exchange and cipher algorithms
CASE_TEST(atbus_node_msg, crypto_config_comprehensive_matrix) {
  std::pair<atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_TYPE, const char *> key_exchange_algorithms[] = {
      {atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_X25519, "X25519"},
      {atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_SECP256R1, "SECP256R1"},
      {atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_SECP384R1, "SECP384R1"},
      {atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_SECP521R1, "SECP521R1"},
  };

  std::pair<atbus::protocol::ATBUS_CRYPTO_ALGORITHM_TYPE, const char *> cipher_algorithms[] = {
      {atbus::protocol::ATBUS_CRYPTO_ALGORITHM_XXTEA, "XXTEA"},
      {atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_128_CBC, "AES-128-CBC"},
      {atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_192_CBC, "AES-192-CBC"},
      {atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_256_CBC, "AES-256-CBC"},
      {atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_128_GCM, "AES-128-GCM"},
      {atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_192_GCM, "AES-192-GCM"},
      {atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_256_GCM, "AES-256-GCM"},
      {atbus::protocol::ATBUS_CRYPTO_ALGORITHM_CHACHA20, "ChaCha20"},
      {atbus::protocol::ATBUS_CRYPTO_ALGORITHM_CHACHA20_POLY1305_IETF, "ChaCha20-Poly1305-IETF"},
      {atbus::protocol::ATBUS_CRYPTO_ALGORITHM_XCHACHA20_POLY1305_IETF, "XChaCha20-Poly1305-IETF"},
  };

  uv_loop_t ev_loop;
  uv_loop_init(&ev_loop);

  size_t passed_count = 0;
  size_t skipped_count = 0;
  size_t failed_count = 0;

  for (auto &kex : key_exchange_algorithms) {
    if (!is_key_exchange_available(kex.first)) {
      CASE_MSG_INFO() << "[SKIP] Key exchange " << kex.second << " not available, skipping all combinations"
                      << std::endl;
      skipped_count += sizeof(cipher_algorithms) / sizeof(cipher_algorithms[0]);
      continue;
    }

    for (auto &cipher : cipher_algorithms) {
      if (!is_cipher_available(cipher.first)) {
        ++skipped_count;
        continue;
      }

      atbus::node::conf_t conf;
      atbus::node::default_conf(&conf);
      conf.ev_loop = &ev_loop;

      // Configure crypto
      conf.crypto_key_exchange_type = kex.first;
      conf.crypto_allow_algorithms.clear();
      conf.crypto_allow_algorithms.push_back(cipher.first);

      do {
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

        time_t proc_t = time(nullptr) + 1;
        node1->poll();
        node2->poll();
        node1->proc(unit_test_make_timepoint(proc_t, 0));
        node2->proc(unit_test_make_timepoint(proc_t, 0));

        node1->connect("ipv4://127.0.0.1:16388");

        UNITTEST_WAIT_UNTIL(
            &ev_loop, node1->is_endpoint_available(node2->get_id()) && node2->is_endpoint_available(node1->get_id()),
            8000, 0) {}

        std::string test_message = "Matrix test: ";
        test_message += kex.second;
        test_message += " + ";
        test_message += cipher.second;

        bool success =
            test_encrypted_message_between_nodes(node1, node2, &ev_loop, test_message, kex.first, cipher.first);

        if (success) {
          ++passed_count;
          CASE_MSG_INFO() << "[PASS] " << kex.second << " + " << cipher.second << std::endl;
        } else {
          ++failed_count;
          CASE_MSG_INFO() << "[FAIL] " << kex.second << " + " << cipher.second << std::endl;
        }
        CASE_EXPECT_TRUE(success);
      } while (false);
    }
  }

  unit_test_setup_exit(&ev_loop);

  CASE_MSG_INFO() << "[SUMMARY] Comprehensive matrix: " << passed_count << " passed, " << failed_count << " failed, "
                  << skipped_count << " skipped" << std::endl;
  CASE_EXPECT_GT(passed_count, 0);
  CASE_EXPECT_EQ(0, failed_count);
}

// Test: Multiple allowed algorithms (algorithm negotiation)
CASE_TEST(atbus_node_msg, crypto_config_multiple_algorithms) {
  atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_TYPE default_kex = atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_X25519;

  if (!is_key_exchange_available(default_kex)) {
    default_kex = atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_SECP256R1;
    if (!is_key_exchange_available(default_kex)) {
      CASE_MSG_INFO() << "[SKIP] No key exchange algorithm available" << std::endl;
      return;
    }
  }

  uv_loop_t ev_loop;
  uv_loop_init(&ev_loop);

  atbus::node::conf_t conf;
  atbus::node::default_conf(&conf);
  conf.ev_loop = &ev_loop;
  // Configure crypto with multiple allowed algorithms
  conf.crypto_key_exchange_type = default_kex;
  conf.crypto_allow_algorithms.clear();

  // Add multiple cipher algorithms in priority order
  if (is_cipher_available(atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_256_GCM)) {
    conf.crypto_allow_algorithms.push_back(atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_256_GCM);
  }
  if (is_cipher_available(atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_128_GCM)) {
    conf.crypto_allow_algorithms.push_back(atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_128_GCM);
  }
  if (is_cipher_available(atbus::protocol::ATBUS_CRYPTO_ALGORITHM_XXTEA)) {
    conf.crypto_allow_algorithms.push_back(atbus::protocol::ATBUS_CRYPTO_ALGORITHM_XXTEA);
  }

  if (conf.crypto_allow_algorithms.empty()) {
    CASE_MSG_INFO() << "[SKIP] No cipher algorithms available" << std::endl;
    unit_test_setup_exit(&ev_loop);
    return;
  }

  CASE_MSG_INFO() << "[TEST] Testing with " << conf.crypto_allow_algorithms.size() << " allowed cipher algorithms"
                  << std::endl;

  do {
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

    time_t proc_t = time(nullptr) + 1;
    node1->poll();
    node2->poll();
    node1->proc(unit_test_make_timepoint(proc_t, 0));
    node2->proc(unit_test_make_timepoint(proc_t, 0));

    node1->connect("ipv4://127.0.0.1:16388");

    UNITTEST_WAIT_UNTIL(&ev_loop,
                        node1->is_endpoint_available(node2->get_id()) && node2->is_endpoint_available(node1->get_id()),
                        8000, 0) {}

    std::string test_message = "Test message with multiple allowed algorithms!";

    recv_msg_history.data.clear();
    recv_msg_history.count = 0;
    node1->set_on_forward_request_handle(node_msg_test_recv_msg_test_record_fn);
    node2->set_on_forward_request_handle(node_msg_test_recv_msg_test_record_fn);

    int initial_count = recv_msg_history.count;
    CASE_EXPECT_EQ(
        EN_ATBUS_ERR_SUCCESS,
        node1->send_data(node2->get_id(), 0,
                         gsl::span<const unsigned char>(reinterpret_cast<const unsigned char *>(test_message.data()),
                                                        test_message.size())));

    UNITTEST_WAIT_UNTIL(&ev_loop, recv_msg_history.count > initial_count && !recv_msg_history.data.empty(), 5000, 0) {}

    CASE_EXPECT_EQ(test_message, recv_msg_history.data);
    CASE_MSG_INFO() << "[PASS] Multiple algorithms test passed" << std::endl;
  } while (false);

  unit_test_setup_exit(&ev_loop);
}

// Test: Upstream-downstream nodes with crypto configuration
CASE_TEST(atbus_node_msg, crypto_config_upstream_downstream) {
  atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_TYPE default_kex = atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_X25519;

  if (!is_key_exchange_available(default_kex)) {
    default_kex = atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_SECP256R1;
    if (!is_key_exchange_available(default_kex)) {
      CASE_MSG_INFO() << "[SKIP] No key exchange algorithm available" << std::endl;
      return;
    }
  }

  atbus::protocol::ATBUS_CRYPTO_ALGORITHM_TYPE default_cipher = atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_256_GCM;
  if (!is_cipher_available(default_cipher)) {
    default_cipher = atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_128_GCM;
    if (!is_cipher_available(default_cipher)) {
      CASE_MSG_INFO() << "[SKIP] No GCM cipher available" << std::endl;
      return;
    }
  }

  uv_loop_t ev_loop;
  uv_loop_init(&ev_loop);

  atbus::node::conf_t conf;
  atbus::node::default_conf(&conf);
  conf.ev_loop = &ev_loop;

  // Configure crypto
  conf.crypto_key_exchange_type = default_kex;
  conf.crypto_allow_algorithms.clear();
  conf.crypto_allow_algorithms.push_back(default_cipher);

  CASE_MSG_INFO() << "[TEST] Testing upstream-downstream nodes with " << get_key_exchange_name(default_kex) << " + "
                  << get_cipher_name(default_cipher) << std::endl;

  do {
    atbus::node::ptr_t node_upstream = atbus::node::create();
    atbus::node::ptr_t node_downstream = atbus::node::create();
    setup_atbus_node_logger(*node_upstream);
    setup_atbus_node_logger(*node_downstream);

    node_upstream->init(0x12345678, &conf);

    atbus::node::conf_t downstream_conf = conf;
    downstream_conf.upstream_address = "ipv4://127.0.0.1:16387";
    node_downstream->init(0x12346789, &downstream_conf);

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream->listen("ipv4://127.0.0.1:16387"));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_downstream->listen("ipv4://127.0.0.1:16388"));

    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_upstream->start());
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node_downstream->start());

    time_t proc_t = time(nullptr) + 1;

    UNITTEST_WAIT_UNTIL(&ev_loop,
                        node_downstream->is_endpoint_available(node_upstream->get_id()) &&
                            node_upstream->is_endpoint_available(node_downstream->get_id()),
                        8000, 64) {
      node_upstream->proc(unit_test_make_timepoint(proc_t, 0));
      node_downstream->proc(unit_test_make_timepoint(proc_t, 0));
      ++proc_t;
    }

    node_downstream->set_on_forward_request_handle(node_msg_test_recv_msg_test_record_fn);
    node_upstream->set_on_forward_request_handle(node_msg_test_recv_msg_test_record_fn);

    // Upstream to downstream
    {
      std::string send_data = "Encrypted upstream to downstream message!";
      recv_msg_history.data.clear();
      int count = recv_msg_history.count;

      CASE_EXPECT_EQ(
          EN_ATBUS_ERR_SUCCESS,
          node_upstream->send_data(node_downstream->get_id(), 0,
                                   gsl::span<const unsigned char>(
                                       reinterpret_cast<const unsigned char *>(send_data.data()), send_data.size())));
      UNITTEST_WAIT_UNTIL(&ev_loop, count != recv_msg_history.count, 3000, 0) {}

      CASE_EXPECT_EQ(send_data, recv_msg_history.data);
      CASE_MSG_INFO() << "  [PASS] Upstream to downstream encrypted message" << std::endl;
    }

    // Downstream to upstream
    {
      std::string send_data = "Encrypted downstream to upstream message!";
      recv_msg_history.data.clear();
      int count = recv_msg_history.count;

      CASE_EXPECT_EQ(
          EN_ATBUS_ERR_SUCCESS,
          node_downstream->send_data(node_upstream->get_id(), 0,
                                     gsl::span<const unsigned char>(
                                         reinterpret_cast<const unsigned char *>(send_data.data()), send_data.size())));
      UNITTEST_WAIT_UNTIL(&ev_loop, count != recv_msg_history.count, 3000, 0) {}

      CASE_EXPECT_EQ(send_data, recv_msg_history.data);
      CASE_MSG_INFO() << "  [PASS] Downstream to upstream encrypted message" << std::endl;
    }
  } while (false);

  unit_test_setup_exit(&ev_loop);
}

// Test: No encryption (crypto disabled)
CASE_TEST(atbus_node_msg, crypto_config_disabled) {
  uv_loop_t ev_loop;
  uv_loop_init(&ev_loop);

  atbus::node::conf_t conf;
  atbus::node::default_conf(&conf);
  conf.ev_loop = &ev_loop;

  // Explicitly disable crypto
  conf.crypto_key_exchange_type = atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_NONE;
  conf.crypto_allow_algorithms.clear();

  CASE_MSG_INFO() << "[TEST] Testing with crypto disabled" << std::endl;

  do {
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

    time_t proc_t = time(nullptr) + 1;
    node1->poll();
    node2->poll();
    node1->proc(unit_test_make_timepoint(proc_t, 0));
    node2->proc(unit_test_make_timepoint(proc_t, 0));

    node1->connect("ipv4://127.0.0.1:16388");

    UNITTEST_WAIT_UNTIL(&ev_loop,
                        node1->is_endpoint_available(node2->get_id()) && node2->is_endpoint_available(node1->get_id()),
                        8000, 0) {}

    std::string test_message = "Plain text message without encryption!";

    recv_msg_history.data.clear();
    recv_msg_history.count = 0;
    node1->set_on_forward_request_handle(node_msg_test_recv_msg_test_record_fn);
    node2->set_on_forward_request_handle(node_msg_test_recv_msg_test_record_fn);

    int initial_count = recv_msg_history.count;
    CASE_EXPECT_EQ(
        EN_ATBUS_ERR_SUCCESS,
        node1->send_data(node2->get_id(), 0,
                         gsl::span<const unsigned char>(reinterpret_cast<const unsigned char *>(test_message.data()),
                                                        test_message.size())));

    UNITTEST_WAIT_UNTIL(&ev_loop, recv_msg_history.count > initial_count && !recv_msg_history.data.empty(), 5000, 0) {}

    CASE_EXPECT_EQ(test_message, recv_msg_history.data);
    CASE_MSG_INFO() << "[PASS] No encryption test passed" << std::endl;
  } while (false);

  unit_test_setup_exit(&ev_loop);
}

// Test: List available crypto algorithms
CASE_TEST(atbus_node_msg, crypto_list_available_algorithms) {
  CASE_MSG_INFO() << "=== Available Crypto Algorithms ===" << std::endl;

  CASE_MSG_INFO() << "Key Exchange Algorithms:" << std::endl;
  auto dh_algorithms = get_available_dh_algorithms();
  for (auto &alg : dh_algorithms) {
    CASE_MSG_INFO() << "  - " << alg << std::endl;
  }

  CASE_MSG_INFO() << "Cipher Algorithms:" << std::endl;
  auto cipher_algorithms = get_available_cipher_algorithms();
  for (auto &alg : cipher_algorithms) {
    CASE_MSG_INFO() << "  - " << alg << std::endl;
  }

  CASE_MSG_INFO() << "==================================" << std::endl;

  // Check at least some algorithms are available
  CASE_EXPECT_GT(dh_algorithms.size(), 0);
  CASE_EXPECT_GT(cipher_algorithms.size(), 0);
}

#endif  // ATFW_UTIL_MACRO_CRYPTO_CIPHER_ENABLED
