// Copyright 2025 atframework

#include <algorithm>
#include <sstream>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include <std/thread.h>

#include "algorithm/crypto_hmac.h"
#include "algorithm/sha.h"
#include "common/string_oprs.h"
#include "nostd/string_view.h"
#include "string/string_format.h"
#include "time/time_utility.h"

#include "detail/buffer.h"

#include "atbus_connection_context.h"
#include "atbus_message_handler.h"
#include "atbus_node.h"

#include "detail/libatbus_channel_export.h"
#include "libatbus_protocol.h"

#if defined(_REENTRANT)
#  define ATFRAMEWORK_LIBATBUS_TLS_BUFFER_USE_PTHREAD 1
#elif defined(THREAD_TLS_ENABLED) && THREAD_TLS_ENABLED
#  define ATFRAMEWORK_LIBATBUS_TLS_BUFFER_USE_THREAD_LOCAL 1
#else
#  define ATFRAMEWORK_LIBATBUS_TLS_BUFFER_USE_PTHREAD 1
#endif

#if defined(ATFRAMEWORK_LIBATBUS_TLS_BUFFER_USE_PTHREAD) && ATFRAMEWORK_LIBATBUS_TLS_BUFFER_USE_PTHREAD
#  include <pthread.h>
#endif

#define ATBUS_PROTOCOL_MESSAGE_BODY_MAX ::atframework::atbus::protocol::message_body::kNodePongRsp
#define ATBUS_PROTOCOL_MESSAGE_BODY_MIN ::atframework::atbus::protocol::message_body::kCustomCommandReq

ATBUS_MACRO_NAMESPACE_BEGIN

namespace {
static const char *_get_body_type_name(message_body_type cmd) {
  switch (cmd) {
    case ::atframework::atbus::protocol::message_body::kCustomCommandReq: {
      return "CustomCommandReq";
    }
    case ::atframework::atbus::protocol::message_body::kCustomCommandRsp: {
      return "CustomCommandRsp";
    }
    case ::atframework::atbus::protocol::message_body::kDataTransformReq: {
      return "DataTransformReq";
    }
    case ::atframework::atbus::protocol::message_body::kDataTransformRsp: {
      return "DataTransformRsp";
    }
    case ::atframework::atbus::protocol::message_body::kNodeSyncReq: {
      return "NodeSyncReq";
    }
    case ::atframework::atbus::protocol::message_body::kNodeSyncRsp: {
      return "NodeSyncRsp";
    }
    case ::atframework::atbus::protocol::message_body::kNodeRegisterReq: {
      return "NodeRegisterReq";
    }
    case ::atframework::atbus::protocol::message_body::kNodeRegisterRsp: {
      return "NodeRegisterRsp";
    }
    case ::atframework::atbus::protocol::message_body::kNodeConnectSync: {
      return "NodeConnectSync";
    }
    case ::atframework::atbus::protocol::message_body::kNodePingReq: {
      return "NodePingReq";
    }
    case ::atframework::atbus::protocol::message_body::kNodePongRsp: {
      return "NodePongRsp";
    }
    default: {
      return "UNKNOWN";
    }
  }
}

static int _forward_data_message(::atframework::atbus::node &n, ::atframework::atbus::node::message_builder_ref_t m,
                                 uint64_t from_server_id, uint64_t to_server_id, endpoint **out_endpoint) {
  if (0 == to_server_id) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr, nullptr, EN_ATBUS_ERR_PARAMS, EN_ATBUS_ERR_PARAMS, "invalid parameters");
    return EN_ATBUS_ERR_PARAMS;
  }

  if (n.get_id() == to_server_id) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr, nullptr, EN_ATBUS_ERR_PARAMS, EN_ATBUS_ERR_PARAMS, "invalid parameters");
    return EN_ATBUS_ERR_PARAMS;
  }

  // 检查如果发送目标不是来源，则转发失败消息
  endpoint *target = nullptr;
  connection *target_conn = nullptr;
  int ret = n.get_remote_channel(to_server_id, &endpoint::get_data_connection, &target, &target_conn);

  if (nullptr != out_endpoint) {
    *out_endpoint = target;
  }

  if (nullptr == target || nullptr == target_conn) {
    ATBUS_FUNC_NODE_ERROR(n, target, target_conn, ret, 0, "target not found");
    return ret;
  }

  if (0 != from_server_id && target->get_id() == from_server_id) {
    ret = EN_ATBUS_ERR_ATNODE_SRC_DST_IS_SAME;
    ATBUS_FUNC_NODE_ERROR(n, target, target_conn, ret, 0, "same source and target");
    return ret;
  }

  // 重设发送源
  ::atframework::atbus::protocol::message_head &head = m.mutable_head();
  head.set_source_bus_id(n.get_id());
  ret = message_handler::send_message(n, *target_conn, m);

  return ret;
}

static std::unordered_set<std::string> &get_supported_channel_schemes() {
  static std::unordered_set<std::string> s_supported_channel_schemes = []() {
    std::unordered_set<std::string> schemes;
    schemes.insert("dns");
    schemes.insert("ipv4");
    schemes.insert("ipv6");
    schemes.insert("mem");
    schemes.insert("shm");
    schemes.insert("unix");
    schemes.insert("pipe");
    return schemes;
  }();
  return s_supported_channel_schemes;
}

static int calculate_channel_address_priority(gsl::string_view addr, bool is_same_host, bool is_same_process) {
  int ret = 0;
  if (is_same_process && atbus::channel::is_local_process_address(addr)) {
    ret += 0x20;
  }
  if (is_same_host && atbus::channel::is_local_host_address(addr)) {
    ret += 0x10;

    if (addr.size() >= 4 && (0 == UTIL_STRFUNC_STRNCASE_CMP("mem:", addr.data(), 4) ||
                             0 == UTIL_STRFUNC_STRNCASE_CMP("shm:", addr.data(), 4))) {
      ret += 0x08;
    }
  }

  if (atbus::channel::is_duplex_address(addr)) {
    ret += 0x02;

    if (addr.size() >= 5 && (0 == UTIL_STRFUNC_STRNCASE_CMP("unix:", addr.data(), 5) ||
                             0 == UTIL_STRFUNC_STRNCASE_CMP("pipe:", addr.data(), 5))) {
      ret += 0x04;
    }
  }

  if (!addr.empty()) {
    ret += 0x01;
  }

  return ret;
}

struct ATFW_UTIL_SYMBOL_LOCAL dispatch_handle_set {
  std::string names[ATBUS_PROTOCOL_MESSAGE_BODY_MAX + 1];
  message_handler::handler_fn_t fns[ATBUS_PROTOCOL_MESSAGE_BODY_MAX + 1];
};

static dispatch_handle_set _build_handle_set() {
  dispatch_handle_set ret = {};
  ret.fns[::atframework::atbus::protocol::message_body::kDataTransformReq] = message_handler::on_recv_data_transfer_req;
  ret.fns[::atframework::atbus::protocol::message_body::kDataTransformRsp] = message_handler::on_recv_data_transfer_rsp;

  ret.fns[::atframework::atbus::protocol::message_body::kCustomCommandReq] = message_handler::on_recv_custom_cmd_req;
  ret.fns[::atframework::atbus::protocol::message_body::kCustomCommandRsp] = message_handler::on_recv_custom_cmd_rsp;

  ret.fns[::atframework::atbus::protocol::message_body::kNodeSyncReq] = message_handler::on_recv_node_sync_req;
  ret.fns[::atframework::atbus::protocol::message_body::kNodeSyncRsp] = message_handler::on_recv_node_sync_rsp;
  ret.fns[::atframework::atbus::protocol::message_body::kNodeRegisterReq] = message_handler::on_recv_node_reg_req;
  ret.fns[::atframework::atbus::protocol::message_body::kNodeRegisterRsp] = message_handler::on_recv_node_reg_rsp;
  ret.fns[::atframework::atbus::protocol::message_body::kNodePingReq] = message_handler::on_recv_node_ping;
  ret.fns[::atframework::atbus::protocol::message_body::kNodePongRsp] = message_handler::on_recv_node_pong;

  ret.names[0] = "Unknown";
  const ATBUS_MACRO_PROTOBUF_NAMESPACE_ID::Descriptor *msg_desc = atbus::protocol::message_body::descriptor();
  for (int i = 0; i < msg_desc->field_count(); ++i) {
    const ATBUS_MACRO_PROTOBUF_NAMESPACE_ID::FieldDescriptor *fds = msg_desc->field(i);
    assert(fds->number() <= ATBUS_PROTOCOL_MESSAGE_BODY_MAX);
    assert(fds->number() >= 0);
    ret.names[fds->number()] = fds->full_name();
  }
  return ret;
}

static const dispatch_handle_set &_get_handle_set() {
  static dispatch_handle_set s_handle_set = _build_handle_set();
  return s_handle_set;
}
}  // namespace

ATBUS_MACRO_API int message_handler::unpack_message(connection_context &conn_ctx, message &target,
                                                    gsl::span<const unsigned char> data, size_t max_body_size) {
  return conn_ctx.unpack_message(target, data, max_body_size);
}

ATBUS_MACRO_API message_handler::buffer_result_t message_handler::pack_message(connection_context &conn_ctx, message &m,
                                                                               int32_t protocol_version,
                                                                               random_engine_t &random_engine,
                                                                               size_t max_body_size) {
  return conn_ctx.pack_message(m, protocol_version, random_engine, max_body_size);
}

ATBUS_MACRO_API int message_handler::dispatch_message(node &n, connection *conn, message &&m, int status, int errcode) {
  static const dispatch_handle_set &handle_set = _get_handle_set();
  auto head = m.get_head();
  if (head == nullptr) {
    return EN_ATBUS_ERR_BAD_DATA;
  }

  auto body_type = m.get_body_type();
  ATBUS_FUNC_NODE_DEBUG(n, nullptr == conn ? nullptr : conn->get_binding(), conn, &m,
                        "node receive message(command={}, type={}, sequence={}, result_code={})",
                        _get_body_type_name(body_type), head->type(), head->sequence(), head->result_code());

  if (body_type > ATBUS_PROTOCOL_MESSAGE_BODY_MAX || body_type < ATBUS_PROTOCOL_MESSAGE_BODY_MIN) {
    return EN_ATBUS_ERR_ATNODE_INVALID_MSG;
  }

  if (nullptr == handle_set.fns[static_cast<size_t>(body_type)]) {
    return EN_ATBUS_ERR_ATNODE_INVALID_MSG;
  }

  n.stat_add_dispatch_times();
  return handle_set.fns[static_cast<size_t>(body_type)](n, conn, std::move(m), status, errcode);
}

ATBUS_MACRO_API const char *message_handler::get_body_name(int body_case) {
  const char *ret = nullptr;
  if (body_case <= ATBUS_PROTOCOL_MESSAGE_BODY_MAX && body_case >= ATBUS_PROTOCOL_MESSAGE_BODY_MIN) {
    ret = _get_handle_set().names[body_case].c_str();
  }

  if (nullptr == ret || !*ret) {
    ret = _get_handle_set().names[0].c_str();
  }

  return ret;
}

ATBUS_MACRO_API void message_handler::generate_access_data(
    ::atframework::atbus::protocol::access_data &ad, uint64_t bus_id, uint64_t nonce1, uint64_t nonce2,
    gsl::span<const std::vector<unsigned char>> access_tokens,
    const ::atframework::atbus::protocol::crypto_handshake_data &hd) {
  ad.set_algorithm(::atframework::atbus::protocol::ATBUS_ACCESS_DATA_ALGORITHM_HMAC_SHA256);
  ad.set_timestamp(atfw::util::time::time_utility::get_sys_now());
  ad.set_nonce1(nonce1);
  ad.set_nonce2(nonce2);
  ad.mutable_signature()->Reserve(static_cast<int>(access_tokens.size()));
  for (const auto &token : access_tokens) {
    ad.mutable_signature()->Add(calculate_access_data_signature(
        ad, gsl::span<const unsigned char>{token.data(), token.size()}, make_access_data_plaintext(bus_id, ad, hd)));
  }
}

ATBUS_MACRO_API void message_handler::generate_access_data(
    ::atframework::atbus::protocol::access_data &ad, uint64_t bus_id, uint64_t nonce1, uint64_t nonce2,
    gsl::span<const std::vector<unsigned char>> access_tokens,
    const ::atframework::atbus::protocol::custom_command_data &csarg) {
  ad.set_algorithm(::atframework::atbus::protocol::ATBUS_ACCESS_DATA_ALGORITHM_HMAC_SHA256);
  ad.set_timestamp(atfw::util::time::time_utility::get_sys_now());
  ad.set_nonce1(nonce1);
  ad.set_nonce2(nonce2);
  ad.mutable_signature()->Reserve(static_cast<int>(access_tokens.size()));
  for (const auto &token : access_tokens) {
    ad.mutable_signature()->Add(calculate_access_data_signature(
        ad, gsl::span<const unsigned char>{token.data(), token.size()}, make_access_data_plaintext(bus_id, ad, csarg)));
  }
}

ATBUS_MACRO_API std::string message_handler::make_access_data_plaintext(
    uint64_t bus_id, const ::atframework::atbus::protocol::access_data &ad,
    const ::atframework::atbus::protocol::crypto_handshake_data &hd) {
  if (hd.public_key().empty()) {
    return atfw::util::string::format("{}:{}-{}:{}", ad.timestamp(), ad.nonce1(), ad.nonce2(), bus_id);
  }

  std::string tail_hash = atfw::util::hash::sha::hash_to_hex(atfw::util::hash::sha::EN_ALGORITHM_SHA256,
                                                             hd.public_key().data(), hd.public_key().size());

  return atfw::util::string::format("{}:{}-{}:{}:{}:{}", ad.timestamp(), ad.nonce1(), ad.nonce2(), bus_id,
                                    static_cast<int>(hd.type()), tail_hash);
}

ATBUS_MACRO_API std::string message_handler::make_access_data_plaintext(
    uint64_t bus_id, const ::atframework::atbus::protocol::access_data &ad,
    const ::atframework::atbus::protocol::custom_command_data &csarg) {
  size_t size = 0;
  for (const auto &item : csarg.commands()) {
    size += item.arg().size();
  }

  std::string data;
  data.reserve(size);

  for (const auto &item : csarg.commands()) {
    data += item.arg();
  }

  return atfw::util::string::format(
      "{}:{}-{}:{}:{}", ad.timestamp(), ad.nonce1(), ad.nonce2(), bus_id,
      atfw::util::hash::sha::hash_to_hex(atfw::util::hash::sha::EN_ALGORITHM_SHA256, data.data(), data.size()));
}

ATBUS_MACRO_API std::string message_handler::calculate_access_data_signature(
    const ::atframework::atbus::protocol::access_data & /*ad*/, gsl::span<const unsigned char> access_token,
    atfw::util::nostd::string_view plaintext) {
  int access_token_len;
  if (access_token.size() > 32868) {
    access_token_len = 32868;
  } else {
    access_token_len = static_cast<int>(access_token.size());
  }

  ::atfw::util::crypto::hmac hmac_algo;
  std::string ret;

  // Must call init() before get_output_length() to properly initialize the context
  hmac_algo.init(atfw::util::crypto::digest_type_t::kSha256, access_token.data(),
                 static_cast<size_t>(access_token_len));
  size_t output_length = hmac_algo.get_output_length();
  ret.resize(output_length);

  hmac_algo.update(reinterpret_cast<const unsigned char *>(plaintext.data()), plaintext.size());
  hmac_algo.final(reinterpret_cast<unsigned char *>(ret.data()), &output_length);

  return ret;
}

ATBUS_MACRO_API int message_handler::send_ping(node &n, connection &conn, uint64_t msg_seq) {
  ::ATBUS_MACRO_PROTOBUF_NAMESPACE_ID::ArenaOptions arena_options;
  arena_options.initial_block_size = ATBUS_MACRO_RESERVED_SIZE;
  message m{arena_options};

  ::atframework::atbus::protocol::message_head &head = m.mutable_head();
  ::atframework::atbus::protocol::ping_data *body = m.mutable_body().mutable_node_ping_req();

  assert(body);

  uint64_t self_id = n.get_id();

  head.set_version(n.get_protocol_version());
  head.set_result_code(0);
  head.set_type(0);
  head.set_sequence(msg_seq);
  head.set_source_bus_id(self_id);

  body->set_time_point(n.get_timer_sec() * 1000 + (n.get_timer_usec() / 1000) % 1000);

  // 客户端创建己方密钥对，发给对方协商
  if (conn.check_flag(connection::flag_t::CLIENT_MODE) &&
      conn.get_connection_context().get_crypto_select_algorithm() != protocol::ATBUS_CRYPTO_ALGORITHM_NONE) {
    std::chrono::microseconds refresh_interval = n.get_conf().crypto_key_refresh_interval;
    if (refresh_interval > std::chrono::microseconds::zero() &&
        (atfw::util::time::time_utility::sys_now() >
             conn.get_connection_context().get_handshake_start_time() + refresh_interval ||
         atfw::util::time::time_utility::sys_now() + refresh_interval <
             conn.get_connection_context().get_handshake_start_time())) {
      // 检查是否需要发起握手
      int result_code = conn.get_connection_context().handshake_generate_self_key(body->crypto_handshake().sequence());
      if (result_code < 0) {
        ATBUS_FUNC_NODE_ERROR(n, conn.get_binding(), &conn, result_code, 0,
                              "node send ping but handshake refresh secret failed");
      } else {
        result_code = conn.get_connection_context().handshake_write_self_public_key(
            *body->mutable_crypto_handshake(),
            gsl::span<const protocol::ATBUS_CRYPTO_ALGORITHM_TYPE>{n.get_conf().crypto_allow_algorithms.data(),
                                                                   n.get_conf().crypto_allow_algorithms.size()});
        if (result_code < 0) {
          ATBUS_FUNC_NODE_ERROR(n, conn.get_binding(), &conn, result_code, 0,
                                "node send ping but write public key failed");
        }
      }
    }
  }

  return send_message(n, conn, m);
}

ATBUS_MACRO_API int message_handler::send_reg(int32_t msg_id, node &n, connection &conn, int32_t ret_code,
                                              uint64_t msg_seq) {
  if (msg_id != ::atframework::atbus::protocol::message_body::kNodeRegisterReq &&
      msg_id != ::atframework::atbus::protocol::message_body::kNodeRegisterRsp) {
    return EN_ATBUS_ERR_PARAMS;
  }

  ::ATBUS_MACRO_PROTOBUF_NAMESPACE_ID::ArenaOptions arena_options;
  arena_options.initial_block_size = ATBUS_MACRO_RESERVED_SIZE;
  message m{arena_options};

  ::atframework::atbus::protocol::message_head &head = m.mutable_head();

  ::atframework::atbus::protocol::register_data *body;
  if (msg_id == ::atframework::atbus::protocol::message_body::kNodeRegisterReq) {
    body = m.mutable_body().mutable_node_register_req();
  } else {
    body = m.mutable_body().mutable_node_register_rsp();
  }

  assert(body);

  uint64_t self_id = n.get_id();

  head.set_version(n.get_protocol_version());
  head.set_result_code(ret_code);
  head.set_type(0);
  head.set_sequence(msg_seq);
  head.set_source_bus_id(self_id);

  body->mutable_channels()->Reserve(static_cast<int>(n.get_listen_list().size()));
  for (auto &addr : n.get_listen_list()) {
    ::atframework::atbus::protocol::channel_data *chan = body->add_channels();
    if (chan == nullptr) {
      continue;
    }
    chan->set_address(addr.address);
  }

  body->set_bus_id(n.get_id());
  body->set_pid(n.get_pid());
  body->set_hostname(n.get_hostname());

  const endpoint *self_ep = n.get_self_endpoint();
  if (nullptr == self_ep) {
    ATBUS_FUNC_NODE_ERROR(n, self_ep, nullptr, EN_ATBUS_ERR_NOT_INITED, EN_ATBUS_ERR_NOT_INITED, "node not inited");
    return EN_ATBUS_ERR_NOT_INITED;
  }

  const std::vector<endpoint_subnet_range> &subsets = self_ep->get_subnets();
  for (size_t i = 0; i < subsets.size(); ++i) {
    atbus::protocol::subnet_range *subset = body->add_subnets();
    if (nullptr == subset) {
      ATBUS_FUNC_NODE_ERROR(n, self_ep, nullptr, EN_ATBUS_ERR_MALLOC, EN_ATBUS_ERR_MALLOC, "malloc subnet failed");
      break;
    }

    subset->set_id_prefix(subsets[i].get_id_prefix());
    subset->set_mask_bits(subsets[i].get_mask_bits());
  }
  body->set_flags(self_ep->get_flags());

  // C++实现同时支持双工和单工通道
  body->mutable_supported_channel_schema()->Reserve(static_cast<int>(get_supported_channel_schemes().size()));
  for (const auto &scheme : get_supported_channel_schemes()) {
    body->add_supported_channel_schema(scheme);
  }

  body->set_hash_code(n.get_hash_code());

  // 打包本地支持的加密算法信息,需要配置允许+本地实现接入
  for (auto &algo : n.get_conf().compression_allow_algorithms) {
    if (!connection_context::is_compression_algorithm_supported(algo)) {
      continue;
    }
    body->add_supported_compression_algorithm(algo);
  }

  // 客户端创建己方密钥对，发给对方协商
  if (msg_id == ::atframework::atbus::protocol::message_body::kNodeRegisterReq &&
      conn.check_flag(connection::flag_t::CLIENT_MODE) &&
      conn.get_connection_context().get_crypto_key_exchange_algorithm() != protocol::ATBUS_CRYPTO_KEY_EXCHANGE_NONE) {
    int res = conn.get_connection_context().handshake_generate_self_key(body->crypto_handshake().sequence());
    if (res < 0) {
      return res;
    }
  }

  // crypto handshake data
  if (ret_code == 0 &&
      conn.get_connection_context().get_crypto_key_exchange_algorithm() != protocol::ATBUS_CRYPTO_KEY_EXCHANGE_NONE) {
    protocol::ATBUS_CRYPTO_ALGORITHM_TYPE selected_algo[1] = {
        conn.get_connection_context().get_crypto_select_algorithm()};
    gsl::span<const protocol::ATBUS_CRYPTO_ALGORITHM_TYPE> allowed_algorithms;
    if (conn.check_flag(connection::flag_t::SERVER_MODE)) {
      // 服务端发回协商结果即可
      allowed_algorithms = gsl::span<const protocol::ATBUS_CRYPTO_ALGORITHM_TYPE>{selected_algo};
    } else {
      // 客户端要上报可用的算法列表
      allowed_algorithms = gsl::span<const protocol::ATBUS_CRYPTO_ALGORITHM_TYPE>{
          n.get_conf().crypto_allow_algorithms.data(), n.get_conf().crypto_allow_algorithms.size()};
    }
    conn.get_connection_context().handshake_write_self_public_key(
        *body->mutable_crypto_handshake(),
        gsl::span<const protocol::ATBUS_CRYPTO_ALGORITHM_TYPE>{n.get_conf().crypto_allow_algorithms.data(),
                                                               n.get_conf().crypto_allow_algorithms.size()});
  }

  generate_access_data(*body->mutable_access_key(), n.get_id(), static_cast<uint64_t>(n.random_engine_.random()),
                       static_cast<uint64_t>(n.random_engine_.random()), gsl::make_span(n.get_conf().access_tokens),
                       body->crypto_handshake());

  return send_message(n, conn, m);
}

ATBUS_MACRO_API int message_handler::send_transfer_rsp(node &n, message &&m, int32_t ret_code) {
  auto body_type = m.get_body_type();
  if (body_type != ::atframework::atbus::protocol::message_body::kDataTransformReq &&
      body_type != ::atframework::atbus::protocol::message_body::kDataTransformRsp) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr, nullptr, EN_ATBUS_ERR_BAD_DATA, 0, "invalid body type {}",
                          static_cast<int>(body_type));
    return EN_ATBUS_ERR_BAD_DATA;
  }

  ::atframework::atbus::protocol::forward_data *fwd_data;
  if (body_type == ::atframework::atbus::protocol::message_body::kDataTransformReq) {
    // move req to response
    // Same arena here and so we can use unsafe release and set_allocated
    fwd_data = m.mutable_body().unsafe_arena_release_data_transform_req();
    m.mutable_body().unsafe_arena_set_allocated_data_transform_rsp(fwd_data);
  } else {
    fwd_data = m.mutable_body().mutable_data_transform_rsp();
  }
  assert(fwd_data);

  uint64_t self_id = n.get_id();
  uint64_t origin_from = fwd_data->from();
  uint64_t origin_to = fwd_data->to();

  // all transfer message must be send by a verified connect, there is no need to check access token again
  auto &head = m.mutable_head();
  head.set_result_code(ret_code);
  head.set_source_bus_id(self_id);

  fwd_data->set_from(origin_to);
  fwd_data->set_to(origin_from);

  if (0 == fwd_data->router_size() || *fwd_data->router().rbegin() != self_id) {
    fwd_data->add_router(self_id);
  }

  int ret = n.send_ctrl_message(origin_from, m);
  if (ret < 0) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr, nullptr, ret, 0, "send control message to {:#x} failed", origin_from);
  }

  return ret;
}

ATBUS_MACRO_API int message_handler::send_custom_cmd_rsp(node &n, connection *conn,
                                                         const std::list<std::string> &rsp_data, int32_t type,
                                                         int32_t ret_code, uint64_t sequence, uint64_t from_bus_id) {
  int ret = 0;

  ::ATBUS_MACRO_PROTOBUF_NAMESPACE_ID::ArenaOptions arena_options;
  arena_options.initial_block_size = ATBUS_MACRO_RESERVED_SIZE;
  message m{arena_options};

  auto &head = m.mutable_head();
  ::atframework::atbus::protocol::custom_command_data *body = m.mutable_body().mutable_custom_command_rsp();
  assert(body);

  uint64_t self_id = n.get_id();

  head.set_version(n.get_protocol_version());
  head.set_result_code(ret_code);
  head.set_type(type);
  head.set_sequence(sequence);
  head.set_source_bus_id(self_id);

  body->set_from(n.get_id());
  body->mutable_commands()->Reserve(static_cast<int>(rsp_data.size()));
  for (std::list<std::string>::const_iterator iter = rsp_data.begin(); iter != rsp_data.end(); ++iter) {
    ::atframework::atbus::protocol::custom_command_argv *cmd_data = body->add_commands();
    if (cmd_data == nullptr) {
      continue;
    }

    cmd_data->set_arg(*iter);
  }

  generate_access_data(*body->mutable_access_key(), n.get_id(), static_cast<uint64_t>(n.random_engine_.random()),
                       static_cast<uint64_t>(n.random_engine_.random()), gsl::make_span(n.get_conf().access_tokens),
                       *body);

  if (nullptr != conn) {
    ret = message_handler::send_message(n, *conn, m);
  } else {
    ret = n.send_ctrl_message(from_bus_id, m);
  }

  return ret;
}

ATBUS_MACRO_API int message_handler::send_message(node &n, connection &conn, message &m) {
  auto &head = m.mutable_head();
  connection_context::buffer_result_t ret = pack_message(conn.get_connection_context(), m, n.get_protocol_version(),
                                                         n.random_engine_, n.get_conf().message_size);
  if (ret.is_error()) {
    ATBUS_FUNC_NODE_DEBUG(n, conn.get_binding(), &conn, &m, "package message failed");
    ATBUS_FUNC_NODE_ERROR(n, conn.get_binding(), &conn, *ret.get_error(), 0, "package message failed");
    return *ret.get_error();
  }

  auto success_data = ret.get_success();
  if (ret.is_none() || success_data == nullptr) {
    ATBUS_FUNC_NODE_DEBUG(n, conn.get_binding(), &conn, &m, "package message failed with unknown error");
    ATBUS_FUNC_NODE_ERROR(n, conn.get_binding(), &conn, EN_ATBUS_ERR_INNER, 0,
                          "package message failed with unknown error");
    return EN_ATBUS_ERR_INNER;
  }

  size_t used_size = success_data->used();
  ATBUS_FUNC_NODE_DEBUG(n, conn.get_binding(), &conn, &m,
                        "node send message(version={}, command={}, type={}, sequence={}, result_code={}, length={})",
                        head.version(), _get_body_type_name(m.get_body_type()), head.type(), head.sequence(),
                        head.result_code(), used_size);

  return conn.push(success_data->data(), used_size);
}

ATBUS_MACRO_API int message_handler::on_recv_data_transfer_req(node &n, connection *conn, message &&m, int /*status*/,
                                                               int /*errcode*/) {
  auto body_type = m.get_body_type();
  if (body_type != ::atframework::atbus::protocol::message_body::kDataTransformReq &&
      body_type != ::atframework::atbus::protocol::message_body::kDataTransformRsp) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, EN_ATBUS_ERR_BAD_DATA, 0,
                          "invalid body type {}", static_cast<int>(body_type));
    return EN_ATBUS_ERR_BAD_DATA;
  }

  ::atframework::atbus::protocol::forward_data *fwd_data;
  if (body_type == ::atframework::atbus::protocol::message_body::kDataTransformReq) {
    fwd_data = m.mutable_body().mutable_data_transform_req();
  } else {
    fwd_data = m.mutable_body().mutable_data_transform_rsp();
  }
  assert(fwd_data);

  auto head = m.get_head();
  if (nullptr == head) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, EN_ATBUS_ERR_BAD_DATA, 0,
                          "no head");
    return EN_ATBUS_ERR_BAD_DATA;
  }

  // check version
  if (head->version() < n.get_protocol_minimal_version()) {
    return send_transfer_rsp(n, std::move(m), EN_ATBUS_ERR_UNSUPPORTED_VERSION);
  }

  // message from self has no connection
  if (nullptr == conn && head->source_bus_id() != n.get_id()) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, EN_ATBUS_ERR_BAD_DATA, 0,
                          "no connection");
    return EN_ATBUS_ERR_BAD_DATA;
  }

  if (nullptr != conn && ::atframework::atbus::connection::state_t::CONNECTED != conn->get_status()) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, EN_ATBUS_ERR_NOT_READY, 0,
                          "connection {} not ready", conn->get_address().address);
    return EN_ATBUS_ERR_NOT_READY;
  }

  // all transfer message must be send by a verified connect, there is no need to check access token again

  // dispatch message
  const void *fwd_content_ptr = nullptr;
  size_t fwd_content_size = 0;
  if (!fwd_data->content().empty()) {
    fwd_content_ptr = reinterpret_cast<const void *>(fwd_data->content().data());
    fwd_content_size = fwd_data->content().size();
  }
  if (fwd_data->to() == n.get_id()) {
    ATBUS_FUNC_NODE_DEBUG(n, (nullptr == conn ? nullptr : conn->get_binding()), conn, &m, "node recv data length = {}",
                          fwd_content_size);
    n.on_recv_data(nullptr == conn ? nullptr : conn->get_binding(), conn, m, fwd_content_ptr, fwd_content_size);

    if (fwd_data->flags() & atbus::protocol::FORWARD_DATA_FLAG_REQUIRE_RSP) {
      return send_transfer_rsp(n, std::move(m), EN_ATBUS_ERR_SUCCESS);
    }
    return EN_ATBUS_ERR_SUCCESS;
  }

  size_t router_size = static_cast<size_t>(fwd_data->router().size());
  if (router_size >= static_cast<size_t>(n.get_conf().ttl)) {
    return send_transfer_rsp(n, std::move(m), EN_ATBUS_ERR_ATNODE_TTL);
  }

  int res = 0;
  endpoint *to_ep = nullptr;
  // 转发数据
  bus_id_t direct_from_bus_id = head->source_bus_id();

  // add router id
  fwd_data->add_router(n.get_id());
  res = _forward_data_message(n, m, direct_from_bus_id, fwd_data->to(), &to_ep);

  // 非子节点转发失败，并且不来自于父节点，则转发送给父节点
  // 如果失败可能是连接未完成，但是endpoint已建立，所以直接发给父节点
  if (res < 0 && false == n.is_parent_node(head->source_bus_id()) && false == n.is_child_node(fwd_data->to())) {
    // 如果失败的发送目标已经是父节点则不需要重发
    const endpoint *parent_ep = n.get_parent_endpoint();
    if (nullptr != parent_ep && (nullptr == to_ep || false == n.is_parent_node(to_ep->get_id()))) {
      res = _forward_data_message(n, m, direct_from_bus_id, parent_ep->get_id(), nullptr);
    }
  }

  // 只有失败或请求方要求回包，才下发通知，类似ICMP协议
  if (res < 0 || (fwd_data->flags() & atbus::protocol::FORWARD_DATA_FLAG_REQUIRE_RSP)) {
    res = send_transfer_rsp(n, std::move(m), res);
  }

  if (res < 0) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, res, 0,
                          "forward data message failed");
  }

  return res;
}

ATBUS_MACRO_API int message_handler::on_recv_data_transfer_rsp(node &n, connection *conn, message &&m, int /*status*/,
                                                               int /*errcode*/) {
  auto body_type = m.get_body_type();
  if (body_type != ::atframework::atbus::protocol::message_body::kDataTransformRsp) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, EN_ATBUS_ERR_BAD_DATA, 0,
                          "invalid body type {}", static_cast<int>(body_type));
    return EN_ATBUS_ERR_BAD_DATA;
  }

  const ::atframework::atbus::protocol::forward_data *fwd_data;
  if (body_type == ::atframework::atbus::protocol::message_body::kDataTransformReq) {
    fwd_data = &m.mutable_body().data_transform_req();
  } else {
    fwd_data = &m.mutable_body().data_transform_rsp();
  }
  assert(fwd_data);

  auto head = m.get_head();
  if (nullptr == head) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, EN_ATBUS_ERR_BAD_DATA, 0,
                          "no head");
    return EN_ATBUS_ERR_BAD_DATA;
  }
  // message from self has no connection
  if (nullptr == conn && head->source_bus_id() != n.get_id()) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, EN_ATBUS_ERR_BAD_DATA, 0,
                          "no connection");
    return EN_ATBUS_ERR_BAD_DATA;
  }

  if (nullptr != conn && ::atframework::atbus::connection::state_t::CONNECTED != conn->get_status()) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, EN_ATBUS_ERR_NOT_READY, 0,
                          "connection {} not ready", conn->get_address().address);
    return EN_ATBUS_ERR_NOT_READY;
  }

  // all transfer message must be send by a verified connect, there is no need to check access token again

  // dispatch message
  if (fwd_data->to() == n.get_id()) {
    if (head->result_code() < 0) {
      ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, head->result_code(), 0,
                            "data transfer response error code {}", head->result_code());
    }
    n.on_recv_forward_response(nullptr == conn ? nullptr : conn->get_binding(), conn, &m);
    return EN_ATBUS_ERR_SUCCESS;
  }

  // 检查如果发送目标不是来源，则转发失败消息
  return _forward_data_message(n, m, head->source_bus_id(), fwd_data->to(), nullptr);
}

ATBUS_MACRO_API int message_handler::on_recv_custom_cmd_req(node &n, connection *conn, message &&m, int /*status*/,
                                                            int /*errcode*/) {
  auto body_type = m.get_body_type();
  if (body_type != ::atframework::atbus::protocol::message_body::kCustomCommandReq &&
      body_type != ::atframework::atbus::protocol::message_body::kCustomCommandRsp) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, EN_ATBUS_ERR_BAD_DATA, 0,
                          "invalid body type {}", static_cast<int>(body_type));
    return EN_ATBUS_ERR_BAD_DATA;
  }

  const ::atframework::atbus::protocol::custom_command_data *cmd_data;
  if (body_type == ::atframework::atbus::protocol::message_body::kCustomCommandReq) {
    cmd_data = &m.mutable_body().custom_command_req();
  } else {
    cmd_data = &m.mutable_body().custom_command_rsp();
  }
  assert(cmd_data);

  auto head = m.get_head();
  if (nullptr == head) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, EN_ATBUS_ERR_BAD_DATA, 0,
                          "no head");
    return EN_ATBUS_ERR_BAD_DATA;
  }

  // check version
  if (head->version() < n.get_protocol_minimal_version()) {
    std::list<std::string> rsp_data;
    rsp_data.push_back("Access Deny - Unsupported Version");
    return send_custom_cmd_rsp(n, conn, rsp_data, head->type(), EN_ATBUS_ERR_UNSUPPORTED_VERSION, head->sequence(),
                               cmd_data->from());
  }

  // message from self has no connection
  if (nullptr == conn && cmd_data->from() != n.get_id()) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, EN_ATBUS_ERR_BAD_DATA, 0,
                          "no connection");
    return EN_ATBUS_ERR_BAD_DATA;
  }

  // Check access token
  if (!n.check_access_hash(cmd_data->access_key(),
                           make_access_data_plaintext(cmd_data->from(), cmd_data->access_key(), *cmd_data), conn)) {
    std::list<std::string> rsp_data;
    rsp_data.push_back("Access Deny - Invalid Token");
    ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, EN_ATBUS_ERR_ACCESS_DENY, 0,
                          "access deny from {:#x}, invalid token", cmd_data->from());
    return send_custom_cmd_rsp(n, conn, rsp_data, head->type(), EN_ATBUS_ERR_ACCESS_DENY, head->sequence(),
                               cmd_data->from());
  }

  std::vector<std::pair<const void *, size_t>> cmd_args;
  cmd_args.reserve(static_cast<size_t>(cmd_data->commands_size()));
  for (int i = 0; i < cmd_data->commands_size(); ++i) {
    const ::atframework::atbus::protocol::custom_command_argv &arg = cmd_data->commands(i);
    cmd_args.push_back(
        std::make_pair<const void *, size_t>(static_cast<const void *>(arg.arg().data()), arg.arg().size()));
  }

  std::list<std::string> rsp_data;
  int ret =
      n.on_custom_cmd(nullptr == conn ? nullptr : conn->get_binding(), conn, cmd_data->from(), cmd_args, rsp_data);
  // shm & mem ignore response from other node
  if ((nullptr != conn && conn->is_running() && conn->check_flag(connection::flag_t::REG_FD)) ||
      n.get_id() == cmd_data->from()) {
    ret = send_custom_cmd_rsp(n, conn, rsp_data, head->type(), 0, head->sequence(), cmd_data->from());
  }

  return ret;
}

ATBUS_MACRO_API int message_handler::on_recv_custom_cmd_rsp(node &n, connection *conn, message &&m, int /*status*/,
                                                            int /*errcode*/) {
  auto body_type = m.get_body_type();
  if (body_type != ::atframework::atbus::protocol::message_body::kCustomCommandReq &&
      body_type != ::atframework::atbus::protocol::message_body::kCustomCommandRsp) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, EN_ATBUS_ERR_BAD_DATA, 0,
                          "invalid body type {}", static_cast<int>(body_type));
    return EN_ATBUS_ERR_BAD_DATA;
  }

  const ::atframework::atbus::protocol::custom_command_data *cmd_data;
  if (body_type == ::atframework::atbus::protocol::message_body::kCustomCommandReq) {
    cmd_data = &m.mutable_body().custom_command_req();
  } else {
    cmd_data = &m.mutable_body().custom_command_rsp();
  }
  assert(cmd_data);

  auto head = m.get_head();
  if (nullptr == head) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, EN_ATBUS_ERR_BAD_DATA, 0,
                          "no head");
    return EN_ATBUS_ERR_BAD_DATA;
  }
  // message from self has no connection
  if (nullptr == conn && cmd_data->from() != n.get_id()) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, EN_ATBUS_ERR_BAD_DATA, 0,
                          "no connection");
    return EN_ATBUS_ERR_BAD_DATA;
  }

  std::vector<std::pair<const void *, size_t>> cmd_args;
  cmd_args.reserve(static_cast<size_t>(cmd_data->commands_size()));
  for (int i = 0; i < cmd_data->commands_size(); ++i) {
    const ::atframework::atbus::protocol::custom_command_argv &arg = cmd_data->commands(i);
    cmd_args.push_back(
        std::make_pair<const void *, size_t>(static_cast<const void *>(arg.arg().data()), arg.arg().size()));
  }

  return n.on_custom_rsp(nullptr == conn ? nullptr : conn->get_binding(), conn, cmd_data->from(), cmd_args,
                         head->sequence());
}

ATBUS_MACRO_API int message_handler::on_recv_node_sync_req(node &n, connection *conn, message &&m, int /*status*/,
                                                           int /*errcode*/) {
  if (nullptr == conn || nullptr == m.get_head()) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, EN_ATBUS_ERR_BAD_DATA, 0,
                          "no head");
    return EN_ATBUS_ERR_BAD_DATA;
  }

  if (::atframework::atbus::connection::state_t::CONNECTED != conn->get_status()) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, EN_ATBUS_ERR_NOT_READY, 0,
                          "connection not ready");
    return EN_ATBUS_ERR_NOT_READY;
  }

  // check version
  if (m.get_head()->version() < n.get_protocol_minimal_version()) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, EN_ATBUS_ERR_UNSUPPORTED_VERSION, 0,
                          "unsupported version {}", m.get_head()->version());
    return EN_ATBUS_ERR_UNSUPPORTED_VERSION;
  }

  return EN_ATBUS_ERR_SUCCESS;
}

ATBUS_MACRO_API int message_handler::on_recv_node_sync_rsp(node &n, connection *conn, message &&m, int /*status*/,
                                                           int /*errcode*/) {
  if (nullptr == conn || nullptr == m.get_head()) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, EN_ATBUS_ERR_BAD_DATA, 0,
                          "no head");
    return EN_ATBUS_ERR_BAD_DATA;
  }

  if (::atframework::atbus::connection::state_t::CONNECTED != conn->get_status()) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, EN_ATBUS_ERR_NOT_READY, 0,
                          "connection not ready");
    return EN_ATBUS_ERR_NOT_READY;
  }

  return EN_ATBUS_ERR_SUCCESS;
}

namespace {
static int accept_node_registration_step_make_endpoint(node &n, connection &conn, endpoint *&ep, const message &m,
                                                       const ::atframework::atbus::protocol::register_data &reg_data) {
  ep = nullptr;
  // 如果连接已经设定了端点，不需要再绑定到endpoint
  if (conn.is_connected()) {
    ep = conn.get_binding();
    if (nullptr == ep || ep->get_id() != reg_data.bus_id()) {
      ATBUS_FUNC_NODE_ERROR(n, ep, &conn, EN_ATBUS_ERR_ATNODE_BUS_ID_NOT_MATCH, 0, "bus id not match");
      conn.reset();
      return EN_ATBUS_ERR_ATNODE_BUS_ID_NOT_MATCH;
    }

    ep->update_hash_code(reg_data.hash_code());
    ATBUS_FUNC_NODE_INFO(n, ep, &conn, "connection already connected recv req");
    return EN_ATBUS_ERR_SUCCESS;
  }

  // 临时连接不需要绑定endpoint，握手成功即可发送指令消息
  if (0 == reg_data.bus_id()) {
    conn.set_temporary();
    ATBUS_FUNC_NODE_INFO(n, ep, &conn, "connection set temporary");
    return EN_ATBUS_ERR_SUCCESS;
  }

  // 老端点新增连接不需要创建新连接
  gsl::string_view hostname;
  if (!reg_data.hostname().empty()) {
    hostname = reg_data.hostname();
  }

  ep = n.get_endpoint(reg_data.bus_id());

  // 已有节点，增加连接
  if (nullptr != ep) {
    // 检测机器名和进程号必须一致,自己是临时节点则不需要检查
    if (0 != n.get_id() && (ep->get_pid() != reg_data.pid() || ep->get_hostname() != hostname)) {
      ATBUS_FUNC_NODE_ERROR(n, ep, &conn, EN_ATBUS_ERR_ATNODE_ID_CONFLICT, 0,
                            "id conflict, endpoint id: {:#x}, pid: {}, hostname: {}, req pid: {}, req hostname: {}",
                            ep->get_id(), ep->get_pid(), ep->get_hostname(), reg_data.pid(), hostname);
      return EN_ATBUS_ERR_ATNODE_ID_CONFLICT;
    } else if (false == ep->add_connection(&conn, conn.check_flag(connection::flag_t::ACCESS_SHARE_HOST))) {
      // 有共享物理机限制的连接只能加为数据节点（一般就是内存通道或者共享内存通道）
      ATBUS_FUNC_NODE_ERROR(n, ep, &conn, EN_ATBUS_ERR_ATNODE_NO_CONNECTION, 0,
                            "no permission to add connection to endpoint");
      return EN_ATBUS_ERR_ATNODE_NO_CONNECTION;
    }

    ep->update_hash_code(reg_data.hash_code());
    ATBUS_FUNC_NODE_DEBUG(n, ep, &conn, &m, "connection added to existed endpoint");
    return EN_ATBUS_ERR_SUCCESS;
  }

  // 创建新端点时需要判定全局路由表权限
  std::bitset<endpoint::flag_t::MAX> reg_flags(reg_data.flags());
  std::vector<endpoint_subnet_conf> ep_subnets;
  ep_subnets.reserve(static_cast<size_t>(reg_data.subnets_size() + 1));
  {
    bool contains_self = false;
    for (int i = 0; i < reg_data.subnets_size(); ++i) {
      const atbus::protocol::subnet_range &subnet_net_conf = reg_data.subnets(i);
      endpoint_subnet_conf conf_item(subnet_net_conf.id_prefix(), subnet_net_conf.mask_bits());
      if (endpoint_subnet_range::contain(conf_item, reg_data.bus_id())) {
        contains_self = true;
      }
      ep_subnets.push_back(conf_item);
    }

    if (!contains_self) {
      ep_subnets.push_back(endpoint_subnet_conf(reg_data.bus_id(), 0));
    }
  }

  if (n.is_child_node(reg_data.bus_id())) {
    // 子节点路由子网范围必须小于自身
    const endpoint *self_ep = n.get_self_endpoint();
    if (nullptr == self_ep) {
      ATBUS_FUNC_NODE_ERROR(n, self_ep, nullptr, EN_ATBUS_ERR_NOT_INITED, EN_ATBUS_ERR_NOT_INITED,
                            "node not initialized");
      return EN_ATBUS_ERR_NOT_INITED;
    }

    if (!endpoint::contain(self_ep->get_subnets(), ep_subnets)) {
      ATBUS_FUNC_NODE_ERROR(n, self_ep, nullptr, EN_ATBUS_ERR_ATNODE_MASK_CONFLICT, EN_ATBUS_ERR_ATNODE_MASK_CONFLICT,
                            "child mask must be greater than child node");
      return EN_ATBUS_ERR_ATNODE_MASK_CONFLICT;
    }
  }

  endpoint::ptr_t new_ep = endpoint::create(&n, reg_data.bus_id(), ep_subnets, reg_data.pid(), hostname);
  if (!new_ep) {
    ATBUS_FUNC_NODE_DEBUG(n, ep, &conn, &m, "malloc endpoint failed");
    ATBUS_FUNC_NODE_ERROR(n, nullptr, &conn, EN_ATBUS_ERR_MALLOC, 0, "malloc endpoint failed");
    return EN_ATBUS_ERR_MALLOC;
  }
  ep = new_ep.get();
  ep->update_hash_code(reg_data.hash_code());

  // 如果是正在连接父节点，要检查一下父节点覆盖的subnets是不是完全覆盖自己
  if (conn.get_address().address == n.get_conf().parent_address) {
    const endpoint *self_ep = n.get_self_endpoint();
    int result = EN_ATBUS_ERR_SUCCESS;
    if (nullptr == self_ep) {
      result = EN_ATBUS_ERR_NOT_INITED;
      ATBUS_FUNC_NODE_DEBUG(n, ep, &conn, &m, "node not initialized");
    } else if (!endpoint::contain(new_ep->get_subnets(), self_ep->get_subnets())) {
      result = EN_ATBUS_ERR_ATNODE_MASK_CONFLICT;
      ATBUS_FUNC_NODE_DEBUG(n, ep, &conn, &m, "parent subnets do not include all self's subnets");
    }

    // 如果处于正在初始化要强制失败
    if (EN_ATBUS_ERR_SUCCESS != result) {
      if (node::state_t::CONNECTING_PARENT == n.get_state()) {
        ATBUS_FUNC_NODE_FATAL_SHUTDOWN(n, ep, &conn, result, result);
      }

      conn.reset();
      n.add_endpoint_gc_list(new_ep);
      return result;
    }
  }

  int result = n.add_endpoint(new_ep);
  if (result < 0) {
    ATBUS_FUNC_NODE_ERROR(n, ep, &conn, result, 0, "add endpoint {:#x} failed", new_ep->get_id());
    return result;
  }

  ATBUS_FUNC_NODE_DEBUG(n, ep, &conn, nullptr, "node add a new endpoint success");
  // 新的endpoint第一个连接为控制连接，后续的为数据连接
  ep->add_connection(&conn, false);
  return result;
}

static void accept_node_registration_step_update_endpoint(
    node & /*n*/, connection & /*conn*/, endpoint &ep, const ::atframework::atbus::protocol::register_data &reg_data) {
  // update supported schemas
  std::unordered_set<std::string> supported_schemes;
  supported_schemes.reserve(static_cast<size_t>(reg_data.supported_channel_schema_size()));
  for (int i = 0; i < reg_data.supported_channel_schema_size(); ++i) {
    std::string schema_name = reg_data.supported_channel_schema(i);
    std::transform(schema_name.begin(), schema_name.end(), schema_name.begin(), ::atfw::util::string::tolower<char>);
    if (!schema_name.empty()) {
      supported_schemes.emplace(std::move(schema_name));
    }
  }

  ep.update_supported_schemas(std::move(supported_schemes));

  // update listen addresses
  ep.clear_listen();
  for (int i = 0; i < reg_data.channels_size(); ++i) {
    const ::atframework::atbus::protocol::channel_data &chan = reg_data.channels(i);
    if (chan.address().empty()) {
      continue;
    }

    ep.add_listen(chan.address());
  }
}

static int accept_node_registration_step_data_channel(node &n, connection &conn, endpoint &ep,
                                                      const ::atframework::atbus::protocol::register_data &reg_data) {
  // 如果双方一边有IOS通道，另一边没有，则没有的连接有的
  // 如果双方都有IOS通道，则CLIENT端连接SERVER端
  bool is_same_host = ep.get_hostname() == n.get_hostname();
  bool is_same_process = is_same_host && ep.get_pid() == n.get_pid();
  bool has_data_connection_seccess = false;

  // 如果SERVER端判定出对方可能会通过双工通道再连接自己一次，就不用反向发起数据连接。
  if (conn.check_flag(connection::flag_t::SERVER_MODE)) {
    int endpoint_select_priority = 0;
    gsl::string_view endpoint_select_address;
    for (auto &addr : n.get_listen_list()) {
      if (!ep.is_schema_supported(addr.scheme)) {
        continue;
      }

      int check_priority = calculate_channel_address_priority(addr.address, is_same_host, is_same_process);
      if (check_priority > endpoint_select_priority) {
        endpoint_select_address = addr.address;
        endpoint_select_priority = check_priority;
      }
    }
    if (!endpoint_select_address.empty() && atbus::channel::is_duplex_address(endpoint_select_address)) {
      return EN_ATBUS_ERR_SUCCESS;
    }
  }

  // io_stream channel only need one connection
  // 按优先级尝试连接对方的地址列表，建立数据连接
  std::vector<std::pair<int, gsl::string_view>> address_priority_list;
  address_priority_list.reserve(static_cast<size_t>(reg_data.channels_size()));
  for (int i = 0; i < reg_data.channels_size(); ++i) {
    const ::atframework::atbus::protocol::channel_data &chan = reg_data.channels(i);
    if (chan.address().empty()) {
      continue;
    }

    if (atbus::channel::is_local_process_address(chan.address()) && !is_same_process) {
      continue;
    }

    if (atbus::channel::is_local_host_address(chan.address()) && !is_same_host) {
      continue;
    }

    int priority = calculate_channel_address_priority(chan.address(), is_same_host, is_same_process);
    address_priority_list.push_back(std::make_pair(priority, gsl::string_view(chan.address())));
  }

  std::sort(address_priority_list.begin(), address_priority_list.end(),
            [](const std::pair<int, gsl::string_view> &a, const std::pair<int, gsl::string_view> &b) {
              return a.first > b.first;
            });

  int ret = EN_ATBUS_ERR_SUCCESS;
  for (auto &addr : address_priority_list) {
    // if n is not a temporary node, connect to other nodes
    if (!has_data_connection_seccess) {
      int res = n.connect(addr.second, &ep);
      if (res < 0) {
        ATBUS_FUNC_NODE_ERROR(n, &ep, &conn, res, 0, "connect to address {} failed", addr.second);
        ret = res;
        continue;
      }
      has_data_connection_seccess = true;
    }
  }

  // 如果新创建的endpoint没有成功进行的数据连接，加入检测列表，下一帧释放
  if (!has_data_connection_seccess) {
    // 如果不能被对方连接，进入GC检测列表
    n.add_endpoint_gc_list(ep.watch());
  } else {
    ret = EN_ATBUS_ERR_SUCCESS;
  }

  return ret;
}

static int accept_node_registration(node &n, connection &conn, endpoint *&ep, const message &m,
                                    const ::atframework::atbus::protocol::register_data &reg_data) {
  int ret = accept_node_registration_step_make_endpoint(n, conn, ep, m, reg_data);
  // 临时连接不需要创建数据通道
  if (ret < 0 || conn.check_flag(connection::flag_t::TEMPORARY) || ep == nullptr) {
    return ret;
  }

  if (n.get_id() == 0 || ep->get_id() == 0) {
    return ret;
  }

  accept_node_registration_step_update_endpoint(n, conn, *ep, reg_data);

  // 如果已经有数据通道了，就不需要再创建了
  if (ep->get_data_connection_count(false) > 0) {
    return ret;
  }

  ret = accept_node_registration_step_data_channel(n, conn, *ep, reg_data);
  return ret;
}
}  // namespace

ATBUS_MACRO_API int message_handler::on_recv_node_reg_req(node &n, connection *conn, message &&m, int /*status*/,
                                                          int errcode) {
  auto body_type = m.get_body_type();
  if (body_type != ::atframework::atbus::protocol::message_body::kNodeRegisterReq &&
      body_type != ::atframework::atbus::protocol::message_body::kNodeRegisterRsp) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, EN_ATBUS_ERR_BAD_DATA, 0,
                          "invalid body type {}", static_cast<int>(body_type));
    return EN_ATBUS_ERR_BAD_DATA;
  }

  const ::atframework::atbus::protocol::register_data *reg_data;
  if (body_type == ::atframework::atbus::protocol::message_body::kNodeRegisterReq) {
    reg_data = &m.mutable_body().node_register_req();
  } else {
    reg_data = &m.mutable_body().node_register_rsp();
  }
  assert(reg_data);

  auto head = m.get_head();
  if (nullptr == conn || nullptr == head) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, EN_ATBUS_ERR_BAD_DATA, 0,
                          "no head");
    return EN_ATBUS_ERR_BAD_DATA;
  }

  // check version
  if (head->version() < n.get_protocol_minimal_version()) {
    if (nullptr != conn) {
      int ret = send_reg(::atframework::atbus::protocol::message_body::kNodeRegisterRsp, n, *conn,
                         EN_ATBUS_ERR_UNSUPPORTED_VERSION, head->sequence());
      if (ret < 0) {
        ATBUS_FUNC_NODE_ERROR(n, conn->get_binding(), conn, ret, 0, "unsupported version {}", head->version());
        conn->reset();
      }
      return ret;
    } else {
      return EN_ATBUS_ERR_UNSUPPORTED_VERSION;
    }
  }

  int32_t response_code = 0;
  endpoint *ep = nullptr;
  do {
    // Check access token
    bool check_access_token = n.check_access_hash(
        reg_data->access_key(),
        make_access_data_plaintext(reg_data->bus_id(), reg_data->access_key(), reg_data->crypto_handshake()), conn);
    if (!check_access_token) {
      response_code = EN_ATBUS_ERR_ACCESS_DENY;
      break;
    }

    // 处理握手协商数据
    if (conn->check_flag(connection::flag_t::SERVER_MODE) && reg_data->crypto_handshake().sequence() != 0 &&
        reg_data->crypto_handshake().type() != protocol::ATBUS_CRYPTO_KEY_EXCHANGE_NONE) {
      // 服务端读取对方公钥，创建己方密钥对，发给对方协商。自己可以完成协商过程
      response_code =
          conn->get_connection_context().handshake_generate_self_key(reg_data->crypto_handshake().sequence());
      if (response_code < 0) {
        break;
      }
      response_code = conn->get_connection_context().handshake_read_peer_key(
          reg_data->crypto_handshake(),
          gsl::span<const protocol::ATBUS_CRYPTO_ALGORITHM_TYPE>{n.get_conf().crypto_allow_algorithms.data(),
                                                                 n.get_conf().crypto_allow_algorithms.size()});
      if (response_code < 0) {
        break;
      }
    }

    // 更新对端加密算法支持
    std::vector<protocol::ATBUS_COMPRESSION_ALGORITHM_TYPE> peer_supported_compression_algorithm;
    peer_supported_compression_algorithm.reserve(
        static_cast<size_t>(reg_data->supported_compression_algorithm().size()));
    for (auto &alg : reg_data->supported_compression_algorithm()) {
      peer_supported_compression_algorithm.push_back(static_cast<protocol::ATBUS_COMPRESSION_ALGORITHM_TYPE>(alg));
    }

    response_code = conn->get_connection_context().update_compression_algorithm(
        gsl::span<const protocol::ATBUS_COMPRESSION_ALGORITHM_TYPE>{peer_supported_compression_algorithm.data(),
                                                                    peer_supported_compression_algorithm.size()});
    if (response_code < 0) {
      break;
    }

    response_code = accept_node_registration(n, *conn, ep, m, *reg_data);
  } while (false);

  if (response_code < 0) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, EN_ATBUS_ERR_ACCESS_DENY, 0,
                          "access deny from {:#x}, invalid token", reg_data->bus_id());

    if (nullptr != conn) {
      int ret = send_reg(::atframework::atbus::protocol::message_body::kNodeRegisterRsp, n, *conn,
                         EN_ATBUS_ERR_ACCESS_DENY, head->sequence());
      if (ret < 0) {
        ATBUS_FUNC_NODE_ERROR(n, conn->get_binding(), conn, ret, 0, "access deny from {:#x}, invalid token",
                              reg_data->bus_id());
        conn->reset();
      }
      return ret;
    } else {
      return EN_ATBUS_ERR_ACCESS_DENY;
    }
  }

  // 仅fd连接发回注册回包，否则忽略（内存和共享内存通道为单工通道）
  if (nullptr != conn && conn->check_flag(connection::flag_t::REG_FD)) {
    int ret = send_reg(::atframework::atbus::protocol::message_body::kNodeRegisterRsp, n, *conn, response_code,
                       head->sequence());
    if (response_code < 0) {
      ATBUS_FUNC_NODE_ERROR(n, ep, conn, ret, errcode, "send reg response failed, response_code: {}", response_code);
      conn->reset();
    }

    return ret;
  } else {
    return 0;
  }
}

ATBUS_MACRO_API int message_handler::on_recv_node_reg_rsp(node &n, connection *conn, message &&m, int /*status*/,
                                                          int errcode) {
  auto body_type = m.get_body_type();
  if (body_type != ::atframework::atbus::protocol::message_body::kNodeRegisterReq &&
      body_type != ::atframework::atbus::protocol::message_body::kNodeRegisterRsp) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, EN_ATBUS_ERR_BAD_DATA, 0,
                          "invalid body type {}", static_cast<int>(body_type));
    return EN_ATBUS_ERR_BAD_DATA;
  }

  const ::atframework::atbus::protocol::register_data *reg_data;
  if (body_type == ::atframework::atbus::protocol::message_body::kNodeRegisterReq) {
    reg_data = &m.mutable_body().node_register_req();
  } else {
    reg_data = &m.mutable_body().node_register_rsp();
  }
  assert(reg_data);

  auto head = m.get_head();
  if (nullptr == conn || nullptr == head) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, EN_ATBUS_ERR_BAD_DATA, 0,
                          "no head");
    return EN_ATBUS_ERR_BAD_DATA;
  }

  int32_t result_code = head->result_code();
  endpoint *ep = nullptr;

  do {
    // Check access token
    bool check_access_token = n.check_access_hash(
        reg_data->access_key(),
        make_access_data_plaintext(reg_data->bus_id(), reg_data->access_key(), reg_data->crypto_handshake()), conn);
    if (!check_access_token) {
      ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, EN_ATBUS_ERR_ACCESS_DENY, 0,
                            "access deny from {:#x}, invalid token", reg_data->bus_id());
      result_code = EN_ATBUS_ERR_ACCESS_DENY;
      break;
    }

    if (result_code < 0) {
      break;
    }

    // 处理握手协商数据
    if (conn->check_flag(connection::flag_t::CLIENT_MODE) && reg_data->crypto_handshake().sequence() != 0 &&
        reg_data->crypto_handshake().type() != protocol::ATBUS_CRYPTO_KEY_EXCHANGE_NONE) {
      result_code = conn->get_connection_context().handshake_read_peer_key(
          reg_data->crypto_handshake(),
          gsl::span<const protocol::ATBUS_CRYPTO_ALGORITHM_TYPE>{n.get_conf().crypto_allow_algorithms.data(),
                                                                 n.get_conf().crypto_allow_algorithms.size()});
      if (result_code < 0) {
        break;
      }
    }

    std::vector<protocol::ATBUS_COMPRESSION_ALGORITHM_TYPE> peer_supported_compression_algorithm;
    peer_supported_compression_algorithm.reserve(
        static_cast<size_t>(reg_data->supported_compression_algorithm().size()));
    for (auto &alg : reg_data->supported_compression_algorithm()) {
      peer_supported_compression_algorithm.push_back(static_cast<protocol::ATBUS_COMPRESSION_ALGORITHM_TYPE>(alg));
    }

    result_code = conn->get_connection_context().update_compression_algorithm(
        gsl::span<const protocol::ATBUS_COMPRESSION_ALGORITHM_TYPE>{peer_supported_compression_algorithm.data(),
                                                                    peer_supported_compression_algorithm.size()});
    if (result_code < 0) {
      break;
    }

    result_code = accept_node_registration(n, *conn, ep, m, *reg_data);
  } while (false);

  if (result_code < 0) {
    if (ep == nullptr) {
      ep = conn->get_binding();
    }
    if (nullptr != ep) {
      n.add_endpoint_gc_list(ep->watch());
    }

    do {
      // 如果是父节点回的错误注册包，且未被激活过，则要关闭进程
      if (conn->get_address().address == n.get_conf().parent_address) {
        if (!n.check_flag(node::flag_t::EN_FT_ACTIVED)) {
          ATBUS_FUNC_NODE_DEBUG(n, ep, conn, &m, "node register to parent node failed, shutdown");
          ATBUS_FUNC_NODE_FATAL_SHUTDOWN(n, ep, conn, result_code, errcode);
          break;
        }
      }

      ATBUS_FUNC_NODE_ERROR(n, ep, conn, result_code, errcode, "node register failed, result_code: {}",
                            head->result_code());
    } while (false);

    n.on_reg(ep, conn, result_code);

    conn->reset();
    return result_code;
  }

  // 注册事件触发
  n.on_reg(ep, conn, head->result_code());

  if (node::state_t::CONNECTING_PARENT == n.get_state()) {
    // 父节点返回的rsp成功则可以上线
    // 这时候父节点的endpoint不一定初始化完毕
    if (n.is_parent_node(reg_data->bus_id())) {
      // 父节点先注册完成
      n.on_parent_reg_done();
      n.on_actived();
    } else {
      std::vector<endpoint_subnet_conf> subsets;
      subsets.reserve(static_cast<size_t>(reg_data->subnets_size()));
      for (int i = 0; i < reg_data->subnets_size(); ++i) {
        subsets.push_back(endpoint_subnet_conf(reg_data->subnets(i).id_prefix(), reg_data->subnets(i).mask_bits()));
      }
      // 父节点还没注册完成，等父节点注册完成后再 on_actived()
      if (endpoint::contain(subsets, n.get_id())) {
        n.on_parent_reg_done();
      }
    }
  }

  return EN_ATBUS_ERR_SUCCESS;
}

ATBUS_MACRO_API int message_handler::on_recv_node_ping(node &n, connection *conn, message &&m, int /*status*/,
                                                       int /*errcode*/) {
  auto head = m.get_head();
  if (nullptr == head || !m.mutable_body().has_node_ping_req()) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, EN_ATBUS_ERR_BAD_DATA, 0,
                          "no head or no node_ping_req");
    return EN_ATBUS_ERR_BAD_DATA;
  }

  // check version
  int ret_code = 0;
  if (head->version() < n.get_protocol_minimal_version()) {
    ret_code = EN_ATBUS_ERR_UNSUPPORTED_VERSION;
  }

  if (nullptr != conn) {
    endpoint *ep = conn->get_binding();

    // 处理握手协商数据
    auto &ping_data = m.mutable_body().node_ping_req();
    bool with_handshake =
        nullptr != ep && ping_data.has_crypto_handshake() && conn->check_flag(connection::flag_t::SERVER_MODE) &&
        conn->get_connection_context().get_crypto_select_algorithm() != protocol::ATBUS_CRYPTO_ALGORITHM_NONE &&
        ping_data.crypto_handshake().sequence() != 0 &&
        ping_data.crypto_handshake().type() != protocol::ATBUS_CRYPTO_KEY_EXCHANGE_NONE;
    if (with_handshake) {
      // 服务端读取对方公钥，创建己方密钥对，发给对方协商。自己可以完成协商过程
      ret_code = conn->get_connection_context().handshake_generate_self_key(ping_data.crypto_handshake().sequence());
      if (ret_code >= 0) {
        ret_code = conn->get_connection_context().handshake_read_peer_key(
            ping_data.crypto_handshake(),
            gsl::span<const protocol::ATBUS_CRYPTO_ALGORITHM_TYPE>{n.get_conf().crypto_allow_algorithms.data(),
                                                                   n.get_conf().crypto_allow_algorithms.size()});
      }
      if (ret_code < 0) {
        ATBUS_FUNC_NODE_ERROR(n, ep, conn, ret_code, 0, "ping handshake refresh secret failed");
        with_handshake = false;
      }
    }

    n.on_ping(ep, std::cref(m), std::cref(ping_data));
    if (nullptr != ep) {
      ::ATBUS_MACRO_PROTOBUF_NAMESPACE_ID::ArenaOptions arena_options;
      arena_options.initial_block_size = ATBUS_MACRO_RESERVED_SIZE;
      message response_m{arena_options};

      ::atframework::atbus::protocol::message_head &response_head = response_m.mutable_head();
      ::atframework::atbus::protocol::ping_data *response_body = response_m.mutable_body().mutable_node_pong_rsp();

      assert(response_body);

      uint64_t self_id = n.get_id();

      response_head.set_version(n.get_protocol_version());
      response_head.set_result_code(ret_code);
      response_head.set_type(head->type());
      response_head.set_sequence(head->sequence());
      response_head.set_source_bus_id(self_id);

      response_body->set_time_point(m.mutable_body().node_ping_req().time_point());

      // 下发协商换密钥数据
      if (with_handshake) {
        protocol::ATBUS_CRYPTO_ALGORITHM_TYPE selected_algo[1] = {
            conn->get_connection_context().get_crypto_select_algorithm()};
        gsl::span<const protocol::ATBUS_CRYPTO_ALGORITHM_TYPE> allowed_algorithms;
        // 服务端发回协商结果即可
        allowed_algorithms = gsl::span<const protocol::ATBUS_CRYPTO_ALGORITHM_TYPE>{selected_algo};
        conn->get_connection_context().handshake_write_self_public_key(
            *response_body->mutable_crypto_handshake(),
            gsl::span<const protocol::ATBUS_CRYPTO_ALGORITHM_TYPE>{n.get_conf().crypto_allow_algorithms.data(),
                                                                   n.get_conf().crypto_allow_algorithms.size()});
      }
      return send_message(n, *conn, response_m);
    }
  }

  return EN_ATBUS_ERR_SUCCESS;
}

ATBUS_MACRO_API int message_handler::on_recv_node_pong(node &n, connection *conn, message &&m, int /*status*/,
                                                       int /*errcode*/) {
  if (!m.mutable_body().has_node_pong_rsp()) {
    ATBUS_FUNC_NODE_ERROR(n, conn ? conn->get_binding() : nullptr, conn, EN_ATBUS_ERR_BAD_DATA, 0,
                          "node recv node_ping from {:#x} but without node_pong_rsp", m.mutable_head().source_bus_id());
    return EN_ATBUS_ERR_BAD_DATA;
  }

  const ::atframework::atbus::protocol::ping_data &message_body = m.mutable_body().node_pong_rsp();

  if (nullptr != conn) {
    // 处理握手协商数据
    if (conn->check_flag(connection::flag_t::CLIENT_MODE) &&
        conn->get_connection_context().get_crypto_select_algorithm() != protocol::ATBUS_CRYPTO_ALGORITHM_NONE &&
        message_body.crypto_handshake().sequence() != 0 &&
        message_body.crypto_handshake().type() != protocol::ATBUS_CRYPTO_KEY_EXCHANGE_NONE) {
      int result_code = conn->get_connection_context().handshake_read_peer_key(
          message_body.crypto_handshake(),
          gsl::span<const protocol::ATBUS_CRYPTO_ALGORITHM_TYPE>{n.get_conf().crypto_allow_algorithms.data(),
                                                                 n.get_conf().crypto_allow_algorithms.size()});
      if (result_code < 0) {
        ATBUS_FUNC_NODE_ERROR(n, conn ? conn->get_binding() : nullptr, conn, result_code, 0,
                              "node recv node_pong from {:#x} handshake refresh secret failed",
                              m.mutable_head().source_bus_id());
      }
    }

    endpoint *ep = conn->get_binding();
    n.on_pong(ep, std::cref(m), std::cref(message_body));
    if (nullptr != ep && m.mutable_head().sequence() == ep->get_stat_ping()) {
      ep->set_stat_ping(0);

      time_t time_point = n.get_timer_sec() * 1000 + (n.get_timer_usec() / 1000) % 1000;
      ep->set_stat_ping_delay(time_point - message_body.time_point(), n.get_timer_sec());
    }
  }

  return EN_ATBUS_ERR_SUCCESS;
}
ATBUS_MACRO_NAMESPACE_END
