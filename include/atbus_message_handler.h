// Copyright 2026 atframework

#pragma once

#include <design_pattern/result_type.h>
#include <gsl/select-gsl.h>
#include <nostd/string_view.h>

#include <bitset>
#include <ctime>
#include <list>
#include <string>

#include "atbus_connection_context.h"
#include "detail/buffer.h"
#include "detail/libatbus_config.h"
#include "detail/libatbus_error.h"

ATBUS_MACRO_NAMESPACE_BEGIN

class message;
class connection_context;

class node;
class endpoint;
class connection;

struct message_handler {
  using handler_fn_t = int (*)(node &n, connection *conn, message &&, int status, int errcode);
  using buffer_result_t = ::atfw::util::design_pattern::result_type<static_buffer_block, ATBUS_ERROR_TYPE>;

  static ATBUS_MACRO_API int unpack_message(connection_context &conn_ctx, message &target,
                                            gsl::span<const unsigned char> data, size_t max_body_size);

  static ATBUS_MACRO_API buffer_result_t pack_message(connection_context &conn_ctx, message &m,
                                                      int32_t protocol_version, random_engine_t &random_engine,
                                                      size_t max_body_size);

  static ATBUS_MACRO_API int dispatch_message(node &n, connection *conn, message &&, int status, int errcode);

  static ATBUS_MACRO_API const char *get_body_name(int body_case);

  static ATBUS_MACRO_API void generate_access_data(::atframework::atbus::protocol::access_data &ad, uint64_t bus_id,
                                                   uint64_t nonce1, uint64_t nonce2,
                                                   gsl::span<const std::vector<unsigned char>> access_tokens,
                                                   const ::atframework::atbus::protocol::crypto_handshake_data &hd);

  static ATBUS_MACRO_API void generate_access_data(::atframework::atbus::protocol::access_data &ad, uint64_t bus_id,
                                                   uint64_t nonce1, uint64_t nonce2,
                                                   gsl::span<const std::vector<unsigned char>> access_tokens,
                                                   const ::atframework::atbus::protocol::custom_command_data &csarg);

  static ATBUS_MACRO_API std::string make_access_data_plaintext(
      uint64_t bus_id, const ::atframework::atbus::protocol::access_data &ad,
      const ::atframework::atbus::protocol::crypto_handshake_data &hd);

  static ATBUS_MACRO_API std::string make_access_data_plaintext(
      uint64_t bus_id, const ::atframework::atbus::protocol::access_data &ad,
      const ::atframework::atbus::protocol::custom_command_data &csarg);

  static ATBUS_MACRO_API std::string calculate_access_data_signature(
      const ::atframework::atbus::protocol::access_data &ad, gsl::span<const unsigned char> access_token,
      atfw::util::nostd::string_view plaintext);

  static ATBUS_MACRO_API int send_ping(node &n, connection &conn, uint64_t seq);

  static ATBUS_MACRO_API int send_reg(int32_t msg_id, node &n, connection &conn, int32_t ret_code, uint64_t seq);

  static ATBUS_MACRO_API int send_transfer_rsp(node &n, message &&, int32_t ret_code);

  static ATBUS_MACRO_API int send_custom_cmd_rsp(node &n, connection *conn, const std::list<std::string> &rsp_data,
                                                 int32_t type, int32_t ret_code, uint64_t sequence,
                                                 uint64_t from_bus_id);

  static ATBUS_MACRO_API int send_node_connect_sync(node &n, uint64_t direct_from_bus_id, endpoint &dst_ep);

  static ATBUS_MACRO_API int send_message(node &n, connection &conn, message &msg);

  // ========================= 接收handle =========================
  static ATBUS_MACRO_API int on_recv_data_transfer_req(node &n, connection *conn, message &&, int status, int errcode);
  static ATBUS_MACRO_API int on_recv_data_transfer_rsp(node &n, connection *conn, message &&, int status, int errcode);

  static ATBUS_MACRO_API int on_recv_custom_cmd_req(node &n, connection *conn, message &&, int status, int errcode);
  static ATBUS_MACRO_API int on_recv_custom_cmd_rsp(node &n, connection *conn, message &&, int status, int errcode);

  static ATBUS_MACRO_API int on_recv_node_sync_req(node &n, connection *conn, message &&, int status, int errcode);
  static ATBUS_MACRO_API int on_recv_node_sync_rsp(node &n, connection *conn, message &&, int status, int errcode);
  static ATBUS_MACRO_API int on_recv_node_reg_req(node &n, connection *conn, message &&, int status, int errcode);
  static ATBUS_MACRO_API int on_recv_node_reg_rsp(node &n, connection *conn, message &&, int status, int errcode);
  static ATBUS_MACRO_API int on_recv_node_conn_syn(node &n, connection *conn, message &&, int status, int errcode);
  static ATBUS_MACRO_API int on_recv_node_ping(node &n, connection *conn, message &&, int status, int errcode);
  static ATBUS_MACRO_API int on_recv_node_pong(node &n, connection *conn, message &&, int status, int errcode);
};
ATBUS_MACRO_NAMESPACE_END
