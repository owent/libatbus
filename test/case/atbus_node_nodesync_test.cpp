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

#include <stdarg.h>

#if 0
static void node_nodesync_test_on_debug(const char* file_path, size_t line, const atbus::node& n, const atbus::endpoint* ep, const atbus::connection* conn, const char* fmt, ...) {
    size_t offset = 0;
    for (size_t i = 0; file_path[i]; ++i) {
        if ('/' == file_path[i] || '\\' == file_path[i]) {
            offset = i + 1;
        }
    }
    file_path += offset;

    std::streamsize w = std::cout.width();
    CASE_MSG_INFO() << "[Log Debug][" << std::setw(24) << file_path << ":" << std::setw(4) << line << "] node=0x" << 
        std::setfill('0')<< std::hex<< std::setw(8)<< n.get_id() <<
        ", ep=0x" << std::setw(8)<< (nullptr == ep ? 0 : ep->get_id()) <<
        ", c=" << conn<< std::setfill(' ')<< std::setw(w)<<  std::dec<<
        "\t";

    va_list ap;
    va_start(ap, fmt);

    vprintf(fmt, ap);

    va_end(ap);

    puts("");
}

struct node_nodesync_test_recv_msg_record_t {
    const atbus::node* n;
    const atbus::endpoint* ep;
    const atbus::connection* conn;
    std::string data;
    int status;
    int count;

    node_nodesync_test_recv_msg_record_t(): n(nullptr), ep(nullptr), conn(nullptr), status(0), count(0) {}
};

static node_nodesync_test_recv_msg_record_t recv_msg_history;

static int node_nodesync_test_recv_msg_test_record_fn(const atbus::node& n, const atbus::endpoint& ep, const atbus::connection& conn, 
    int status, const void* buffer, size_t len) {
    recv_msg_history.n = &n;
    recv_msg_history.ep = &ep;
    recv_msg_history.conn = &conn;
    recv_msg_history.status = status;
    ++recv_msg_history.count;

    if (nullptr != buffer && len > 0) {
        recv_msg_history.data.assign(reinterpret_cast<const char*>(buffer), len);
    } else {
        recv_msg_history.data.clear();
    }

    return 0;
}

// TODO 全量表第一次拉取测试
// TODO 全量表通知给父节点和子节点测试

#endif
