
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
static int node_setup_test_on_error(const atbus::node &n, const atbus::endpoint *ep, const atbus::connection *conn,
                                    int status, int errcode) {
  if ((0 == status && 0 == errcode) || UV_EOF == errcode || UV_ECONNRESET == errcode) {
    return 0;
  }

  std::streamsize w = std::cout.width();
  CASE_MSG_INFO() << "[Log Error] node=0x" << std::setfill('0') << std::hex << std::setw(8) << n.get_id() << ", ep=0x"
                  << std::setw(8) << (nullptr == ep ? 0 : ep->get_id()) << ", c=" << conn << std::setfill(' ')
                  << std::setw(static_cast<int>(w)) << std::dec << "=> status: " << status << ", errcode: " << errcode
                  << std::endl;
  return 0;
}

static int node_setup_test_on_info_log(const atbus::node &n, const atbus::endpoint *ep, const atbus::connection *conn,
                                       const char *msg) {
  std::streamsize w = std::cout.width();
  CASE_MSG_INFO() << "[Log Info] node=0x" << std::setfill('0') << std::hex << std::setw(8) << n.get_id() << ", ep=0x"
                  << std::setw(8) << (nullptr == ep ? 0 : ep->get_id()) << ", c=" << conn << std::setfill(' ')
                  << std::setw(static_cast<int>(w)) << std::dec << "=> message: " << (nullptr == msg ? "" : msg)
                  << std::endl;

  return 0;
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
    node1->set_on_error_handle(node_setup_test_on_error);
    node2->set_on_error_handle(node_setup_test_on_error);
    node3->set_on_error_handle(node_setup_test_on_error);
    node1->set_on_info_log_handle(node_setup_test_on_info_log);
    node2->set_on_info_log_handle(node_setup_test_on_info_log);
    node3->set_on_info_log_handle(node_setup_test_on_info_log);

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
