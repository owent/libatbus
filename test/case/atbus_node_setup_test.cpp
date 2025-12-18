
#include <signal.h>

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

#include <algorithm/crypto_cipher.h>

#include "atbus_test_utils.h"
#include "frame/test_macros.h"

#include <stdarg.h>

#ifdef CRYPTO_CIPHER_ENABLED
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
                   node2->listen("unix:///tmp/atbus-unit-test-overwrite-unix.sock"));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node3->listen("unix:///tmp/atbus-unit-test-overwrite-unix.sock"));
  }

  unit_test_setup_exit(&ev_loop);
}
#endif
