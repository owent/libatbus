/**
 * atbus_msg_handler.h
 *
 *  Created on: 2015年12月14日
 *      Author: owent
 */

#pragma once

#include <gsl/select-gsl.h>
#include <nostd/string_view.h>

#include <bitset>
#include <ctime>
#include <list>
#include <string>

#include "detail/libatbus_config.h"

namespace atbus {
namespace protocol {
class msg;
class access_data;
class crypto_handshake_data;
class custom_command_data;
}  // namespace protocol

class node;
class endpoint;
class connection;

struct msg_handler {
  using handler_fn_t = int (*)(node &n, connection *conn, ::atbus::protocol::msg &&, int status, int errcode);

  static ATBUS_MACRO_API int dispatch_msg(node &n, connection *conn, ::atbus::protocol::msg &&, int status,
                                          int errcode);

  static ATBUS_MACRO_API const char *get_body_name(int body_case);

  static ATBUS_MACRO_API void generate_access_data(::atbus::protocol::access_data &ad, uint64_t bus_id, uint64_t nince1,
                                                   uint64_t nince2,
                                                   gsl::span<const std::vector<unsigned char>> access_tokens,
                                                   const ::atbus::protocol::crypto_handshake_data &hd);

  static ATBUS_MACRO_API void generate_access_data(::atbus::protocol::access_data &ad, uint64_t bus_id, uint64_t nince1,
                                                   uint64_t nince2,
                                                   gsl::span<const std::vector<unsigned char>> access_tokens,
                                                   const ::atbus::protocol::custom_command_data &csarg);

  static ATBUS_MACRO_API std::string make_access_data_plaintext(uint64_t bus_id,
                                                                const ::atbus::protocol::access_data &ad,
                                                                const ::atbus::protocol::crypto_handshake_data &hd);

  static ATBUS_MACRO_API std::string make_access_data_plaintext(uint64_t bus_id,
                                                                const ::atbus::protocol::access_data &ad,
                                                                const ::atbus::protocol::custom_command_data &csarg);

  static ATBUS_MACRO_API std::string calculate_access_data_signature(const ::atbus::protocol::access_data &ad,
                                                                     gsl::span<const unsigned char> access_token,
                                                                     atfw::util::nostd::string_view plaintext);

  static ATBUS_MACRO_API int send_ping(node &n, connection &conn, uint64_t seq);

  static ATBUS_MACRO_API int send_reg(int32_t msg_id, node &n, connection &conn, int32_t ret_code, uint64_t seq);

  static ATBUS_MACRO_API int send_transfer_rsp(node &n, ::atbus::protocol::msg &&, int32_t ret_code);

  static ATBUS_MACRO_API int send_custom_cmd_rsp(node &n, connection *conn, const std::list<std::string> &rsp_data,
                                                 int32_t type, int32_t ret_code, uint64_t sequence,
                                                 uint64_t from_bus_id);

  static ATBUS_MACRO_API int send_node_connect_sync(node &n, uint64_t direct_from_bus_id, endpoint &dst_ep);

  static ATBUS_MACRO_API int send_msg(node &n, connection &conn, const ::atbus::protocol::msg &msg);

  // ========================= 接收handle =========================
  static ATBUS_MACRO_API int on_recv_data_transfer_req(node &n, connection *conn, ::atbus::protocol::msg &&, int status,
                                                       int errcode);
  static ATBUS_MACRO_API int on_recv_data_transfer_rsp(node &n, connection *conn, ::atbus::protocol::msg &&, int status,
                                                       int errcode);

  static ATBUS_MACRO_API int on_recv_custom_cmd_req(node &n, connection *conn, ::atbus::protocol::msg &&, int status,
                                                    int errcode);
  static ATBUS_MACRO_API int on_recv_custom_cmd_rsp(node &n, connection *conn, ::atbus::protocol::msg &&, int status,
                                                    int errcode);

  static ATBUS_MACRO_API int on_recv_node_sync_req(node &n, connection *conn, ::atbus::protocol::msg &&, int status,
                                                   int errcode);
  static ATBUS_MACRO_API int on_recv_node_sync_rsp(node &n, connection *conn, ::atbus::protocol::msg &&, int status,
                                                   int errcode);
  static ATBUS_MACRO_API int on_recv_node_reg_req(node &n, connection *conn, ::atbus::protocol::msg &&, int status,
                                                  int errcode);
  static ATBUS_MACRO_API int on_recv_node_reg_rsp(node &n, connection *conn, ::atbus::protocol::msg &&, int status,
                                                  int errcode);
  static ATBUS_MACRO_API int on_recv_node_conn_syn(node &n, connection *conn, ::atbus::protocol::msg &&, int status,
                                                   int errcode);
  static ATBUS_MACRO_API int on_recv_node_ping(node &n, connection *conn, ::atbus::protocol::msg &&, int status,
                                               int errcode);
  static ATBUS_MACRO_API int on_recv_node_pong(node &n, connection *conn, ::atbus::protocol::msg &&, int status,
                                               int errcode);
};
}  // namespace atbus
