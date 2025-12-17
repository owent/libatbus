// Copyright 2025 atframework

#include <openssl/hmac.h>

#include <sstream>

#include <std/thread.h>

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

static constexpr size_t get_small_shared_message_buffer_size() noexcept {
  size_t x = ATBUS_MACRO_DATA_SMALL_SIZE;
  if (x <= 4096) {
    return 4096;
  }
  --x;
  x |= x >> 1;
  x |= x >> 2;
  x |= x >> 4;
  x |= x >> 8;
  x |= x >> 16;
#if SIZE_MAX > 0xFFFFFFFFu
  x |= x >> 32;
#endif
  return x + 1;
}

#if defined(ATFRAMEWORK_ULILITY_TLS_BUFFER_USE_PTHREAD) && ATFRAMEWORK_ULILITY_TLS_BUFFER_USE_PTHREAD
#  include <pthread.h>
static pthread_once_t gt_libatbus_shared_small_message_buffer_tls_once = PTHREAD_ONCE_INIT;
static pthread_key_t gt_libatbus_shared_small_message_buffer_tls_key;

static void dtor_pthread_atgateway_get_msg_buffer_tls(void *p) {
  unsigned char *res = reinterpret_cast<unsigned char *>(p);
  delete[] res;
}

static void init_pthread_atgateway_get_msg_buffer_tls() {
  (void)pthread_key_create(&gt_libatbus_shared_small_message_buffer_tls_key, dtor_pthread_atgateway_get_msg_buffer_tls);
}

static unsigned char *get_small_shared_message_buffer_addr() {
  (void)pthread_once(&gt_libatbus_shared_small_message_buffer_tls_once, init_pthread_atgateway_get_msg_buffer_tls);
  unsigned char *ret =
      reinterpret_cast<unsigned char *>(pthread_getspecific(gt_libatbus_shared_small_message_buffer_tls_key));
  if (nullptr == ret) {
    ret = new unsigned char[get_small_shared_message_buffer_size()];
    pthread_setspecific(gt_libatbus_shared_small_message_buffer_tls_key, ret);
  }
  return ret;
}
#else
static unsigned char *get_small_shared_message_buffer_addr() {
  static THREAD_TLS std::unique_ptr<unsigned char[]> ret(new unsigned char[get_small_shared_message_buffer_size()]);
  return ret.get();
}
#endif

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

}  // namespace

// Message帧层: vint(header长度) + header + body + padding
ATBUS_MACRO_API int message_handler::unpack_message(connection_context &conn_ctx, message &target,
                                                    gsl::span<const unsigned char> data) {
  // decode
  uint64_t head_size = 0;
  size_t head_vint_size =
      ::atframework::atbus::detail::fn::read_vint(head_size, reinterpret_cast<const void *>(data.data()), data.size());
  if (head_vint_size == 0) {
    return EN_ATBUS_ERR_INVALID_SIZE;
  }

  if (static_cast<size_t>(head_size) + head_vint_size > data.size()) {
    return EN_ATBUS_ERR_INVALID_SIZE;
  }

  if (!target.mutable_head().ParseFromArray(reinterpret_cast<const uint8_t *>(data.data() + head_vint_size),
                                            static_cast<int>(head_size))) {
    return EN_ATBUS_ERR_UNPACK;
  }
  size_t body_size = static_cast<size_t>(target.get_head()->body_size());
  if (body_size > 0) {
    int res =
        conn_ctx.unpack_body(target.mutable_body(), body_size, data.subspan(head_vint_size + head_size, body_size));
    if (res != EN_ATBUS_ERR_SUCCESS) {
      return res;
    }
  }

  return EN_ATBUS_ERR_SUCCESS;
}

ATBUS_MACRO_API void message_handler::finish_message(connection_context &conn_ctx, message &source,
                                                     int32_t protocol_version) {
  auto &head = source.mutable_head();

  head.set_version(protocol_version);

  auto body = source.get_body();
  if (body != nullptr) {
    head.set_body_size(static_cast<uint64_t>(body->ByteSizeLong()));
  } else {
    head.set_body_size(0);
  }
}

ATBUS_MACRO_API int message_handler::pack_message(connection_context &conn_ctx, const message &source,
                                                  gsl::span<unsigned char> buffer, size_t &used_size) {
  auto head = source.get_head();
  if (head == nullptr) {
    return EN_ATBUS_ERR_MESSAGE_NOT_FINISH_YET;
  }
  if (head->version() == atbus::protocol::ATBUS_PROTOCOL_CONST_UNKNOWN) {
    return EN_ATBUS_ERR_MESSAGE_NOT_FINISH_YET;
  }

  size_t head_size = head->ByteSizeLong();
  size_t body_size = static_cast<size_t>(head->body_size());

  unsigned char head_len_buffer[16];
  size_t head_vint_size = ::atframework::atbus::detail::fn::write_vint(
      static_cast<uint64_t>(head_size), reinterpret_cast<void *>(head_len_buffer), sizeof(head_len_buffer));
  used_size = head_vint_size + head_size + conn_ctx.padding_size(body_size);
  if (used_size > buffer.size()) {
    return EN_ATBUS_ERR_BUFF_LIMIT;
  }

  memcpy(reinterpret_cast<void *>(buffer.data()), reinterpret_cast<void *>(head_len_buffer), head_vint_size);
  head->SerializeWithCachedSizesToArray(reinterpret_cast<uint8_t *>(buffer.data() + head_vint_size));
  auto body = source.get_body();
  size_t total_size = head_vint_size + head_size;
  if (body != nullptr) {
    size_t cost_body_size = 0;
    int res = conn_ctx.pack_body(*body, body_size, buffer.subspan(total_size), cost_body_size);
    if (res != EN_ATBUS_ERR_SUCCESS) {
      return res;
    }
    total_size += cost_body_size;
  }
  used_size = total_size;

  return EN_ATBUS_ERR_SUCCESS;
}

ATBUS_MACRO_API int message_handler::dispatch_message(node &n, connection *conn, message &&m, int status, int errcode) {
  static handler_fn_t fns[ATBUS_PROTOCOL_MESSAGE_BODY_MAX + 1] = {nullptr};
  if (nullptr == fns[ATBUS_PROTOCOL_MESSAGE_BODY_MIN] || nullptr == fns[ATBUS_PROTOCOL_MESSAGE_BODY_MAX]) {
    fns[::atframework::atbus::protocol::message_body::kDataTransformReq] = message_handler::on_recv_data_transfer_req;
    fns[::atframework::atbus::protocol::message_body::kDataTransformRsp] = message_handler::on_recv_data_transfer_rsp;

    fns[::atframework::atbus::protocol::message_body::kCustomCommandReq] = message_handler::on_recv_custom_cmd_req;
    fns[::atframework::atbus::protocol::message_body::kCustomCommandRsp] = message_handler::on_recv_custom_cmd_rsp;

    fns[::atframework::atbus::protocol::message_body::kNodeSyncReq] = message_handler::on_recv_node_sync_req;
    fns[::atframework::atbus::protocol::message_body::kNodeSyncRsp] = message_handler::on_recv_node_sync_rsp;
    fns[::atframework::atbus::protocol::message_body::kNodeRegisterReq] = message_handler::on_recv_node_reg_req;
    fns[::atframework::atbus::protocol::message_body::kNodeRegisterRsp] = message_handler::on_recv_node_reg_rsp;
    fns[::atframework::atbus::protocol::message_body::kNodeConnectSync] = message_handler::on_recv_node_conn_syn;
    fns[::atframework::atbus::protocol::message_body::kNodePingReq] = message_handler::on_recv_node_ping;
    fns[::atframework::atbus::protocol::message_body::kNodePongRsp] = message_handler::on_recv_node_pong;
  }

  auto head = m.get_head();
  if (head == nullptr) {
    return EN_ATBUS_ERR_BAD_DATA;
  }

  auto body_type = m.get_body_type();
  ATBUS_FUNC_NODE_DEBUG(n, nullptr == conn ? nullptr : conn->get_binding(), conn, &m,
                        "node recv message(cmd={}, type={}, sequence={}, result_code={})",
                        _get_body_type_name(body_type), head->type(), head->sequence(), head->result_code());

  if (body_type > ATBUS_PROTOCOL_MESSAGE_BODY_MAX || body_type < ATBUS_PROTOCOL_MESSAGE_BODY_MIN) {
    return EN_ATBUS_ERR_ATNODE_INVALID_MSG;
  }

  if (nullptr == fns[static_cast<size_t>(body_type)]) {
    return EN_ATBUS_ERR_ATNODE_INVALID_MSG;
  }

  n.stat_add_dispatch_times();
  return fns[static_cast<size_t>(body_type)](n, conn, std::move(m), status, errcode);
}

ATBUS_MACRO_API const char *message_handler::get_body_name(int body_case) {
  static std::string atbus_fn_names[ATBUS_PROTOCOL_MESSAGE_BODY_MAX + 1];
  if (atbus_fn_names[0].empty()) {
    atbus_fn_names[0] = "Unknown";
    const ATBUS_MACRO_PROTOBUF_NAMESPACE_ID::Descriptor *msg_desc = atbus::protocol::message_body::descriptor();
    for (int i = 0; i < msg_desc->field_count(); ++i) {
      const ATBUS_MACRO_PROTOBUF_NAMESPACE_ID::FieldDescriptor *fds = msg_desc->field(i);
      assert(fds->number() <= ATBUS_PROTOCOL_MESSAGE_BODY_MAX);
      assert(fds->number() >= 0);
      atbus_fn_names[fds->number()] = fds->full_name();
    }
  }

  const char *ret = nullptr;
  if (body_case <= ATBUS_PROTOCOL_MESSAGE_BODY_MAX && body_case >= ATBUS_PROTOCOL_MESSAGE_BODY_MIN) {
    ret = atbus_fn_names[body_case].c_str();
  }

  if (nullptr == ret || !*ret) {
    ret = atbus_fn_names[0].c_str();
  }

  return ret;
}

ATBUS_MACRO_API void message_handler::generate_access_data(
    ::atframework::atbus::protocol::access_data &ad, uint64_t bus_id, uint64_t nince1, uint64_t nince2,
    gsl::span<const std::vector<unsigned char>> access_tokens,
    const ::atframework::atbus::protocol::crypto_handshake_data &hd) {
  ad.set_algorithm(::atframework::atbus::protocol::ATBUS_ACCESS_DATA_ALGORITHM_HMAC_SHA256);
  ad.set_timestamp(atfw::util::time::time_utility::get_sys_now());
  ad.set_nonce1(nince1);
  ad.set_nonce2(nince2);
  ad.mutable_signature()->Reserve(static_cast<int>(access_tokens.size()));
  for (const auto &token : access_tokens) {
    ad.mutable_signature()->Add(calculate_access_data_signature(
        ad, gsl::span<const unsigned char>{token.data(), token.size()}, make_access_data_plaintext(bus_id, ad, hd)));
  }
}

ATBUS_MACRO_API void message_handler::generate_access_data(
    ::atframework::atbus::protocol::access_data &ad, uint64_t bus_id, uint64_t nince1, uint64_t nince2,
    gsl::span<const std::vector<unsigned char>> access_tokens,
    const ::atframework::atbus::protocol::custom_command_data &csarg) {
  ad.set_algorithm(::atframework::atbus::protocol::ATBUS_ACCESS_DATA_ALGORITHM_HMAC_SHA256);
  ad.set_timestamp(atfw::util::time::time_utility::get_sys_now());
  ad.set_nonce1(nince1);
  ad.set_nonce2(nince2);
  ad.mutable_signature()->Reserve(static_cast<int>(access_tokens.size()));
  for (const auto &token : access_tokens) {
    ad.mutable_signature()->Add(calculate_access_data_signature(
        ad, gsl::span<const unsigned char>{token.data(), token.size()}, make_access_data_plaintext(bus_id, ad, csarg)));
  }
}

ATBUS_MACRO_API std::string message_handler::make_access_data_plaintext(
    uint64_t bus_id, const ::atframework::atbus::protocol::access_data &ad,
    const ::atframework::atbus::protocol::crypto_handshake_data &hd) {
  if (hd.public_key().empty() && hd.params().empty()) {
    return atfw::util::string::format("{}:{}-{}:{}", ad.timestamp(), ad.nonce1(), ad.nonce2(), bus_id);
  }

  std::string tail_hash;
  if (hd.public_key().empty()) {
    tail_hash = atfw::util::hash::sha::hash_to_binary(atfw::util::hash::sha::EN_ALGORITHM_SHA256, hd.params().data(),
                                                      hd.params().size());
  } else if (hd.params().empty()) {
    tail_hash = atfw::util::hash::sha::hash_to_binary(atfw::util::hash::sha::EN_ALGORITHM_SHA256,
                                                      hd.public_key().data(), hd.public_key().size());
  } else {
    std::string data = hd.public_key() + hd.params();
    tail_hash =
        atfw::util::hash::sha::hash_to_binary(atfw::util::hash::sha::EN_ALGORITHM_SHA256, data.data(), data.size());
  }
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
      atfw::util::hash::sha::hash_to_binary(atfw::util::hash::sha::EN_ALGORITHM_SHA256, data.data(), data.size()));
}

ATBUS_MACRO_API std::string message_handler::calculate_access_data_signature(
    const ::atframework::atbus::protocol::access_data &ad, gsl::span<const unsigned char> access_token,
    atfw::util::nostd::string_view plaintext) {
  const EVP_MD *evp_md = EVP_sha256();
  if (nullptr == evp_md) {
    return "sha256 unavailabled";
  }
  unsigned char md_buffer[EVP_MAX_MD_SIZE + 1];
  unsigned int md_len = EVP_MAX_MD_SIZE;
  HMAC(evp_md, access_token.data(), static_cast<int>(access_token.size()),  // NOLINT
       reinterpret_cast<const unsigned char *>(plaintext.data()), plaintext.size(), md_buffer, &md_len);
  return std::string(reinterpret_cast<const char *>(md_buffer), md_len);
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
  for (std::list<std::string>::const_iterator iter = n.get_listen_list().begin(); iter != n.get_listen_list().end();
       ++iter) {
    ::atframework::atbus::protocol::channel_data *chan = body->add_channels();
    if (chan == nullptr) {
      continue;
    }
    chan->set_address(*iter);
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

  body->set_hash_code(n.get_hash_code());

  // TODO(owent): crypto handshake data
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

  // TODO(owent): crypto handshake data
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

ATBUS_MACRO_API int message_handler::send_node_connect_sync(node &n, uint64_t direct_from_bus_id, endpoint &dst_ep) {
  const std::list<std::string> &listen_addrs = dst_ep.get_listen();
  const endpoint *from_ep = n.get_endpoint(direct_from_bus_id);
  bool is_same_host = (nullptr != from_ep && from_ep->get_hostname() == dst_ep.get_hostname());
  const std::string *select_address = nullptr;
  for (std::list<std::string>::const_iterator iter = listen_addrs.begin(); iter != listen_addrs.end(); ++iter) {
    // 通知连接控制通道，控制通道不能是（共享）内存通道
    if (0 == UTIL_STRFUNC_STRNCASE_CMP("mem:", iter->c_str(), 4) ||
        0 == UTIL_STRFUNC_STRNCASE_CMP("shm:", iter->c_str(), 4)) {
      continue;
    }

    // Unix Sock不能跨机器
    if (0 == UTIL_STRFUNC_STRNCASE_CMP("unix:", iter->c_str(), 5) && !is_same_host) {
      continue;
    }

    select_address = &(*iter);
    break;
  }

  if (nullptr != select_address && !select_address->empty()) {
    ::ATBUS_MACRO_PROTOBUF_NAMESPACE_ID::ArenaOptions arena_options;
    arena_options.initial_block_size = ATBUS_MACRO_RESERVED_SIZE;
    message m{arena_options};

    ::atframework::atbus::protocol::message_head &head = m.mutable_head();
    ::atframework::atbus::protocol::connection_data *body = m.mutable_body().mutable_node_connect_sync();
    ::atframework::atbus::protocol::channel_data *conn_data = body->mutable_address();
    assert(body && conn_data);

    uint64_t self_id = n.get_id();

    head.set_version(n.get_protocol_version());
    head.set_result_code(0);
    head.set_type(0);
    head.set_sequence(n.allocate_message_sequence());
    head.set_source_bus_id(self_id);

    conn_data->set_address(*select_address);
    int ret = n.send_ctrl_message(direct_from_bus_id, m);
    if (ret < 0) {
      ATBUS_FUNC_NODE_ERROR(n, nullptr, nullptr, ret, 0, "send control message to {:#x} failed", direct_from_bus_id);
    }

    return ret;
  }

  return EN_ATBUS_ERR_SUCCESS;
}

ATBUS_MACRO_API int message_handler::send_message(node &n, connection &conn, message &m) {
  auto &head = m.mutable_head();
  finish_message(conn.get_connection_context(), m, n.get_protocol_version());

  size_t used_size = 0;
  int ret = pack_message(conn.get_connection_context(), m, {}, used_size);
  if (ret != EN_ATBUS_ERR_SUCCESS && ret != EN_ATBUS_ERR_BUFF_LIMIT) {
    ATBUS_FUNC_NODE_DEBUG(n, conn.get_binding(), &conn, &m, "package message failed");
    ATBUS_FUNC_NODE_ERROR(n, conn.get_binding(), &conn, ret, 0, "package message failed");
    return ret;
  }

  if (used_size > n.get_conf().message_size + ATBUS_MACRO_MAX_FRAME_HEADER) {
    ATBUS_FUNC_NODE_DEBUG(n, conn.get_binding(), &conn, &m, "message size {} exceed limit {}", used_size,
                          n.get_conf().message_size + ATBUS_MACRO_MAX_FRAME_HEADER);
    ATBUS_FUNC_NODE_ERROR(n, conn.get_binding(), &conn, EN_ATBUS_ERR_INVALID_SIZE, 0, "message size {} exceed limit {}",
                          used_size, n.get_conf().message_size + ATBUS_MACRO_MAX_FRAME_HEADER);
    return EN_ATBUS_ERR_INVALID_SIZE;
  }

  std::string message_big_buffer;
  unsigned char *message_buffer;
  if (used_size < get_small_shared_message_buffer_size()) {
    message_buffer = get_small_shared_message_buffer_addr();
  } else {
    message_big_buffer.resize(used_size);
    message_buffer = reinterpret_cast<unsigned char *>(&message_big_buffer[0]);
  }

  ret = pack_message(conn.get_connection_context(), m, gsl::span<unsigned char>(message_buffer, used_size), used_size);
  if (ret != EN_ATBUS_ERR_SUCCESS) {
    ATBUS_FUNC_NODE_DEBUG(n, conn.get_binding(), &conn, &m, "pack message failed");
    ATBUS_FUNC_NODE_ERROR(n, conn.get_binding(), &conn, ret, 0, "pack message failed");
    return ret;
  }

  ATBUS_FUNC_NODE_DEBUG(n, conn.get_binding(), &conn, &m,
                        "node send message(version={}, cmd={}, type={}, sequence={}, result_code={}, length={})",
                        head.version(), _get_body_type_name(m.get_body_type()), head.type(), head.sequence(),
                        head.result_code(), used_size);

  return conn.push(message_buffer, used_size);
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
  node::bus_id_t direct_from_bus_id = head->source_bus_id();

  // add router id
  fwd_data->add_router(n.get_id());
  res = _forward_data_message(n, m, direct_from_bus_id, fwd_data->to(), &to_ep);

  // 子节点转发成功
  if (res >= 0 && n.is_child_node(fwd_data->to())) {
    // 如果来源和目标消息都来自于子节点，则通知建立直连
    if (nullptr != to_ep && to_ep->get_flag(endpoint::flag_t::HAS_LISTEN_FD) && n.is_child_node(direct_from_bus_id) &&
        n.is_child_node(to_ep->get_id())) {
      res = send_node_connect_sync(n, direct_from_bus_id, *to_ep);
    }

    return res;
  }

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
  if (body_type != ::atframework::atbus::protocol::message_body::kDataTransformReq &&
      body_type != ::atframework::atbus::protocol::message_body::kDataTransformRsp) {
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

  // Check access token
  if (!n.check_access_hash(
          reg_data->access_key(),
          make_access_data_plaintext(reg_data->bus_id(), reg_data->access_key(), reg_data->crypto_handshake()), conn)) {
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

  endpoint *ep = nullptr;
  int32_t res = EN_ATBUS_ERR_SUCCESS;
  int32_t response_code = EN_ATBUS_ERR_SUCCESS;

  do {
    // 如果连接已经设定了端点，不需要再绑定到endpoint
    if (conn->is_connected()) {
      ep = conn->get_binding();
      if (nullptr == ep || ep->get_id() != reg_data->bus_id()) {
        ATBUS_FUNC_NODE_ERROR(n, ep, conn, EN_ATBUS_ERR_ATNODE_BUS_ID_NOT_MATCH, 0, "bus id not match");
        conn->reset();
        response_code = EN_ATBUS_ERR_ATNODE_BUS_ID_NOT_MATCH;
        break;
      }

      ep->update_hash_code(reg_data->hash_code());
      ATBUS_FUNC_NODE_INFO(n, ep, conn, "connection already connected recv req");
      break;
    }

    if (0 == reg_data->bus_id()) {
      conn->set_temporary();
      ATBUS_FUNC_NODE_INFO(n, ep, conn, "connection set temporary");
      break;
    }

    // 老端点新增连接不需要创建新连接
    std::string hostname;
    if (!reg_data->hostname().empty()) {
      hostname = reg_data->hostname();
    }

    ep = n.get_endpoint(reg_data->bus_id());
    if (nullptr != ep) {
      // 检测机器名和进程号必须一致,自己是临时节点则不需要检查
      if (0 != n.get_id() && (ep->get_pid() != reg_data->pid() || ep->get_hostname() != hostname)) {
        res = EN_ATBUS_ERR_ATNODE_ID_CONFLICT;
        ATBUS_FUNC_NODE_ERROR(n, ep, conn, res, 0,
                              "id conflict, endpoint id: {:#x}, pid: {}, hostname: {}, req pid: {}, req hostname: {}",
                              ep->get_id(), ep->get_pid(), ep->get_hostname(), reg_data->pid(), hostname);
      } else if (false == ep->add_connection(conn, conn->check_flag(connection::flag_t::ACCESS_SHARE_HOST))) {
        // 有共享物理机限制的连接只能加为数据节点（一般就是内存通道或者共享内存通道）
        res = EN_ATBUS_ERR_ATNODE_NO_CONNECTION;
        ATBUS_FUNC_NODE_ERROR(n, ep, conn, res, 0, "no permission to add connection to endpoint");
      }
      response_code = res;

      ep->update_hash_code(reg_data->hash_code());
      ATBUS_FUNC_NODE_DEBUG(n, ep, conn, &m, "connection added to existed endpoint, result_code: {}", res);
      break;
    }

    // 创建新端点时需要判定全局路由表权限
    std::bitset<endpoint::flag_t::MAX> reg_flags(reg_data->flags());
    std::vector<endpoint_subnet_conf> ep_subnets;
    ep_subnets.reserve(static_cast<size_t>(reg_data->subnets_size() + 1));
    {
      bool contains_self = false;
      for (int i = 0; i < reg_data->subnets_size(); ++i) {
        const atbus::protocol::subnet_range &subnet_net_conf = reg_data->subnets(i);
        endpoint_subnet_conf conf_item(subnet_net_conf.id_prefix(), subnet_net_conf.mask_bits());
        if (endpoint_subnet_range::contain(conf_item, reg_data->bus_id())) {
          contains_self = true;
        }
        ep_subnets.push_back(conf_item);
      }

      if (!contains_self) {
        ep_subnets.push_back(endpoint_subnet_conf(reg_data->bus_id(), 0));
      }
    }

    if (n.is_child_node(reg_data->bus_id())) {
      // 子节点路由子网范围必须小于自身
      const endpoint *self_ep = n.get_self_endpoint();
      if (nullptr == self_ep) {
        response_code = EN_ATBUS_ERR_NOT_INITED;
        ATBUS_FUNC_NODE_ERROR(n, self_ep, nullptr, response_code, response_code, "node not initialized");
        break;
      }

      if (!endpoint::contain(self_ep->get_subnets(), ep_subnets)) {
        response_code = EN_ATBUS_ERR_ATNODE_MASK_CONFLICT;

        ATBUS_FUNC_NODE_ERROR(n, self_ep, nullptr, response_code, response_code,
                              "child mask must be greater than child node");
        break;
      }
    }

    endpoint::ptr_t new_ep = endpoint::create(&n, reg_data->bus_id(), ep_subnets, reg_data->pid(), hostname);
    if (!new_ep) {
      ATBUS_FUNC_NODE_ERROR(n, nullptr, conn, EN_ATBUS_ERR_MALLOC, 0, "malloc failed");
      response_code = EN_ATBUS_ERR_MALLOC;
      break;
    }
    ep = new_ep.get();
    ep->update_hash_code(reg_data->hash_code());

    // 如果是正在连接父节点，要检查一下父节点覆盖的subnets是不是完全覆盖自己
    if (conn->get_address().address == n.get_conf().parent_address) {
      const endpoint *self_ep = n.get_self_endpoint();
      if (nullptr == self_ep) {
        response_code = EN_ATBUS_ERR_NOT_INITED;
        ATBUS_FUNC_NODE_DEBUG(n, ep, conn, &m, "node not initialized");
      } else if (!endpoint::contain(new_ep->get_subnets(), self_ep->get_subnets())) {
        response_code = EN_ATBUS_ERR_ATNODE_MASK_CONFLICT;
        ATBUS_FUNC_NODE_DEBUG(n, ep, conn, &m, "parent subnets do not include all self's subnets");
      }
      // 如果处于正在初始化要强制失败
      if (EN_ATBUS_ERR_SUCCESS != response_code) {
        if (node::state_t::CONNECTING_PARENT == n.get_state()) {
          ATBUS_FUNC_NODE_FATAL_SHUTDOWN(n, ep, conn, response_code, response_code);
        }

        conn->reset();
        n.add_endpoint_gc_list(new_ep);
        break;
      }
    }

    res = n.add_endpoint(new_ep);
    if (res < 0) {
      ATBUS_FUNC_NODE_ERROR(n, ep, conn, res, 0, "add endpoint {:#x} failed", new_ep->get_id());
      response_code = res;
      break;
    }

    ATBUS_FUNC_NODE_DEBUG(n, ep, conn, &m, "node add a new endpoint, result_code: {}", res);
    // 新的endpoint要建立所有连接
    ep->add_connection(conn, false);

    // 如果双方一边有IOS通道，另一边没有，则没有的连接有的
    // 如果双方都有IOS通道，则ID小的连接ID大的
    bool can_be_connected_by_ep = false;
    bool is_same_host = ep->get_hostname() == n.get_hostname();
    bool is_same_pid = ep->get_pid() == n.get_pid();
    for (std::list<std::string>::const_iterator iter = n.get_listen_list().begin();
         !can_be_connected_by_ep && iter != n.get_listen_list().end(); ++iter) {
      if (atbus::channel::is_duplex_address(iter->c_str())) {
        if ((is_same_host && is_same_pid) || false == atbus::channel::is_local_process_address(iter->c_str())) {
          can_be_connected_by_ep = true;
        } else if (is_same_host || false == atbus::channel::is_local_host_address(iter->c_str())) {
          can_be_connected_by_ep = true;
        }
      }
    }

    // io_stream channel only need one connection
    bool has_data_conn = false;
    const ::ATBUS_MACRO_PROTOBUF_NAMESPACE_ID::RepeatedPtrField<::atframework::atbus::protocol::channel_data>
        &all_channels = reg_data->channels();
    for (int i = 0; i < all_channels.size(); ++i) {
      const ::atframework::atbus::protocol::channel_data &chan = all_channels.Get(i);
      if (chan.address().empty()) {
        continue;
      }

      if (can_be_connected_by_ep && n.get_id() > ep->get_id()) {
        // wait peer to connect n, do not check and close endpoint
        has_data_conn = true;
        if (atbus::channel::is_duplex_address(chan.address().c_str())) {
          continue;
        }
      }

      bool local_host_address = atbus::channel::is_local_host_address(chan.address().c_str());
      bool local_process_address = atbus::channel::is_local_process_address(chan.address().c_str());

      // check hostname
      if (local_host_address && !is_same_host) {
        continue;
      }

      // check pid
      if (local_process_address && !is_same_pid) {
        continue;
      }

      // if n is not a temporary node, connect to other nodes
      if (0 != n.get_id() && 0 != ep->get_id()) {
        res = n.connect(chan.address().c_str(), ep);
      } else {
        res = 0;
        // temporary node also should not check and close endpoint
        has_data_conn = true;
      }
      if (res < 0) {
        ATBUS_FUNC_NODE_ERROR(n, ep, conn, res, 0, "connect to address %s failed", chan.address());
      } else {
        ep->add_listen(chan.address().c_str());
        has_data_conn = true;
      }
    }

    // 如果没有成功进行的数据连接，加入检测列表，下一帧释放
    if (!has_data_conn) {
      // 如果不能被对方连接，进入GC检测列表
      // 否则在ping包时会检测endpoint有效性
      if (!can_be_connected_by_ep) {
        n.add_endpoint_gc_list(new_ep);
      }
    }
  } while (false);

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

  endpoint *ep = conn->get_binding();

  // Check access token
  bool check_access_token = true;
  if (!n.check_access_hash(
          reg_data->access_key(),
          make_access_data_plaintext(reg_data->bus_id(), reg_data->access_key(), reg_data->crypto_handshake()), conn)) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, EN_ATBUS_ERR_ACCESS_DENY, 0,
                          "access deny from {:#x}, invalid token", reg_data->bus_id());
    check_access_token = false;
  }

  if (!check_access_token || head->result_code() < 0) {
    if (nullptr != ep) {
      n.add_endpoint_gc_list(ep->watch());
    }
    int ret_code = head->result_code();
    if (!check_access_token && ret_code >= 0) {
      ret_code = EN_ATBUS_ERR_ACCESS_DENY;
    }

    do {
      // 如果是父节点回的错误注册包，且未被激活过，则要关闭进程
      if (conn->get_address().address == n.get_conf().parent_address) {
        if (!n.check_flag(node::flag_t::EN_FT_ACTIVED)) {
          ATBUS_FUNC_NODE_DEBUG(n, ep, conn, &m, "node register to parent node failed, shutdown");
          ATBUS_FUNC_NODE_FATAL_SHUTDOWN(n, ep, conn, ret_code, errcode);
          break;
        }
      }

      ATBUS_FUNC_NODE_ERROR(n, ep, conn, ret_code, errcode, "node register failed, result_code: {}",
                            head->result_code());
    } while (false);

    n.on_reg(ep, conn, ret_code);

    conn->reset();
    return ret_code;
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

ATBUS_MACRO_API int message_handler::on_recv_node_conn_syn(node &n, connection *conn, message &&m, int /*status*/,
                                                           int /*errcode*/) {
  auto body_type = m.get_body_type();
  if (body_type != ::atframework::atbus::protocol::message_body::kNodeConnectSync) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, EN_ATBUS_ERR_BAD_DATA, 0,
                          "invalid body type {}", static_cast<int>(body_type));
    return EN_ATBUS_ERR_BAD_DATA;
  }

  const ::atframework::atbus::protocol::connection_data &conn_data = m.mutable_body().node_connect_sync();

  auto head = m.get_head();
  if (nullptr == conn || nullptr == head) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, EN_ATBUS_ERR_BAD_DATA, 0,
                          "no head");
    return EN_ATBUS_ERR_BAD_DATA;
  }

  // check version
  if (head->version() < n.get_protocol_minimal_version()) {
    return EN_ATBUS_ERR_UNSUPPORTED_VERSION;
  }

  if (::atframework::atbus::connection::state_t::CONNECTED != conn->get_status()) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, EN_ATBUS_ERR_NOT_READY, 0,
                          "connection not ready");
    return EN_ATBUS_ERR_NOT_READY;
  }

  if (false == conn_data.has_address() || conn_data.address().address().empty()) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, EN_ATBUS_ERR_BAD_DATA, 0,
                          "no address");
    return EN_ATBUS_ERR_BAD_DATA;
  }

  ATBUS_FUNC_NODE_DEBUG(n, nullptr, nullptr, &m, "node recv conn_syn and prepare connect to {}",
                        conn_data.address().address());
  int ret = n.connect(conn_data.address().address().c_str());
  if (ret < 0) {
    ATBUS_FUNC_NODE_ERROR(n, n.get_self_endpoint(), nullptr, ret, 0, "connect to {} failed",
                          conn_data.address().address());
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
    n.on_ping(ep, std::cref(m), std::cref(m.mutable_body().node_ping_req()));
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
    endpoint *ep = conn->get_binding();
    n.on_pong(ep, std::cref(m), std::cref(m.mutable_body().node_ping_req()));
    if (nullptr != ep && m.mutable_head().sequence() == ep->get_stat_ping()) {
      ep->set_stat_ping(0);

      time_t time_point = n.get_timer_sec() * 1000 + (n.get_timer_usec() / 1000) % 1000;
      ep->set_stat_ping_delay(time_point - message_body.time_point(), n.get_timer_sec());
    }
  }

  return EN_ATBUS_ERR_SUCCESS;
}
ATBUS_MACRO_NAMESPACE_END
