/**
 * atbus_msg_handler.h
 *
 *  Created on: 2015年12月14日
 *      Author: owent
 */

#pragma once

#ifndef LIBATBUS_MSG_HANDLER_H
#define LIBATBUS_MSG_HANDLER_H

#pragma once

#include <bitset>
#include <ctime>
#include <list>

#include "detail/libatbus_config.h"

namespace atbus {
    namespace protocol {
        class msg;
    }

    class node;
    class endpoint;
    class connection;

    struct msg_handler {
        typedef int (*handler_fn_t)(node &n, connection *conn, ::atbus::protocol::msg ATBUS_MACRO_RVALUE_REFERENCES, int status, int errcode);

        static ATBUS_MACRO_API int dispatch_msg(node &n, connection *conn, ::atbus::protocol::msg ATBUS_MACRO_RVALUE_REFERENCES, int status, int errcode);

        static ATBUS_MACRO_API int send_ping(node &n, connection &conn, uint64_t seq);

        static ATBUS_MACRO_API int send_reg(int32_t msg_id, node &n, connection &conn, int32_t ret_code, uint64_t seq);

        static ATBUS_MACRO_API int send_transfer_rsp(node &n, ::atbus::protocol::msg ATBUS_MACRO_RVALUE_REFERENCES, int32_t ret_code);

        static ATBUS_MACRO_API int send_custom_cmd_rsp(node &n, connection *conn, const std::list<std::string>& rsp_data, 
            int32_t type, int32_t ret_code, uint64_t sequence, uint64_t from_bus_id);

        static ATBUS_MACRO_API int send_node_connect_sync(node &n, uint64_t direct_from_bus_id, endpoint &dst_ep);

        static ATBUS_MACRO_API int send_msg(node &n, connection &conn, const ::atbus::protocol::msg & msg);

        // ========================= 接收handle =========================
        static ATBUS_MACRO_API int on_recv_data_transfer_req(node &n, connection *conn, ::atbus::protocol::msg ATBUS_MACRO_RVALUE_REFERENCES, int status, int errcode);
        static ATBUS_MACRO_API int on_recv_data_transfer_rsp(node &n, connection *conn, ::atbus::protocol::msg ATBUS_MACRO_RVALUE_REFERENCES, int status, int errcode);

        static ATBUS_MACRO_API int on_recv_custom_cmd_req(node &n, connection *conn, ::atbus::protocol::msg ATBUS_MACRO_RVALUE_REFERENCES, int status, int errcode);
        static ATBUS_MACRO_API int on_recv_custom_cmd_rsp(node &n, connection *conn, ::atbus::protocol::msg ATBUS_MACRO_RVALUE_REFERENCES, int status, int errcode);

        static ATBUS_MACRO_API int on_recv_node_sync_req(node &n, connection *conn, ::atbus::protocol::msg ATBUS_MACRO_RVALUE_REFERENCES, int status, int errcode);
        static ATBUS_MACRO_API int on_recv_node_sync_rsp(node &n, connection *conn, ::atbus::protocol::msg ATBUS_MACRO_RVALUE_REFERENCES, int status, int errcode);
        static ATBUS_MACRO_API int on_recv_node_reg_req(node &n, connection *conn, ::atbus::protocol::msg ATBUS_MACRO_RVALUE_REFERENCES, int status, int errcode);
        static ATBUS_MACRO_API int on_recv_node_reg_rsp(node &n, connection *conn, ::atbus::protocol::msg ATBUS_MACRO_RVALUE_REFERENCES, int status, int errcode);
        static ATBUS_MACRO_API int on_recv_node_conn_syn(node &n, connection *conn, ::atbus::protocol::msg ATBUS_MACRO_RVALUE_REFERENCES, int status, int errcode);
        static ATBUS_MACRO_API int on_recv_node_ping(node &n, connection *conn, ::atbus::protocol::msg ATBUS_MACRO_RVALUE_REFERENCES, int status, int errcode);
        static ATBUS_MACRO_API int on_recv_node_pong(node &n, connection *conn, ::atbus::protocol::msg ATBUS_MACRO_RVALUE_REFERENCES, int status, int errcode);
    };
} // namespace atbus

#endif /* LIBATBUS_MSG_HANDLER_H_ */
