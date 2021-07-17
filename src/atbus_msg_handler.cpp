#include <sstream>

#include "common/string_oprs.h"

#include "detail/buffer.h"

#include "atbus_msg_handler.h"
#include "atbus_node.h"

#include "detail/libatbus_channel_export.h"
#include "libatbus_protocol.h"

#define ATBUS_PROTOCOL_MSG_BODY_MAX ::atbus::protocol::msg::kNodePongRsp
#define ATBUS_PROTOCOL_MSG_BODY_MIN ::atbus::protocol::msg::kCustomCommandReq

namespace atbus {

namespace detail {
const char *get_cmd_name(int cmd) {
  const ::ATBUS_MACRO_PROTOBUF_NAMESPACE_ID::FieldDescriptor *field_desc =
      ::atbus::protocol::msg::descriptor()->FindFieldByNumber(cmd);
  if (field_desc == nullptr) {
    return "UNKNOWN";
  }

  return field_desc->name().c_str();
}

static int forward_data_message(::atbus::node &n, ::atbus::node::msg_builder_ref_t m, uint64_t from_server_id,
                                uint64_t to_server_id, endpoint **out_endpoint) {
  if (0 == to_server_id) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr, nullptr, EN_ATBUS_ERR_PARAMS, EN_ATBUS_ERR_PARAMS);
    return EN_ATBUS_ERR_PARAMS;
  }

  if (n.get_id() == to_server_id) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr, nullptr, EN_ATBUS_ERR_PARAMS, EN_ATBUS_ERR_PARAMS);
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
    ATBUS_FUNC_NODE_ERROR(n, target, target_conn, ret, 0);
    return ret;
  }

  if (0 != from_server_id && target->get_id() == from_server_id) {
    ret = EN_ATBUS_ERR_ATNODE_SRC_DST_IS_SAME;
    ATBUS_FUNC_NODE_ERROR(n, target, target_conn, ret, 0);
    return ret;
  }

  // 重设发送源
  ::atbus::protocol::msg_head *head = m.mutable_head();
  assert(head);
  if (head) {
    head->set_src_bus_id(n.get_id());
    ret = msg_handler::send_msg(n, *target_conn, m);
  }
  return ret;
}

}  // namespace detail

ATBUS_MACRO_API int msg_handler::dispatch_msg(node &n, connection *conn,
                                              ::atbus::protocol::msg ATBUS_MACRO_RVALUE_REFERENCES m, int status,
                                              int errcode) {
  static handler_fn_t fns[ATBUS_PROTOCOL_MSG_BODY_MAX + 1] = {nullptr};
  if (nullptr == fns[ATBUS_PROTOCOL_MSG_BODY_MIN] || nullptr == fns[ATBUS_PROTOCOL_MSG_BODY_MAX]) {
    fns[::atbus::protocol::msg::kDataTransformReq] = msg_handler::on_recv_data_transfer_req;
    fns[::atbus::protocol::msg::kDataTransformRsp] = msg_handler::on_recv_data_transfer_rsp;

    fns[::atbus::protocol::msg::kCustomCommandReq] = msg_handler::on_recv_custom_cmd_req;
    fns[::atbus::protocol::msg::kCustomCommandRsp] = msg_handler::on_recv_custom_cmd_rsp;

    fns[::atbus::protocol::msg::kNodeSyncReq] = msg_handler::on_recv_node_sync_req;
    fns[::atbus::protocol::msg::kNodeSyncRsp] = msg_handler::on_recv_node_sync_rsp;
    fns[::atbus::protocol::msg::kNodeRegisterReq] = msg_handler::on_recv_node_reg_req;
    fns[::atbus::protocol::msg::kNodeRegisterRsp] = msg_handler::on_recv_node_reg_rsp;
    fns[::atbus::protocol::msg::kNodeConnectSync] = msg_handler::on_recv_node_conn_syn;
    fns[::atbus::protocol::msg::kNodePingReq] = msg_handler::on_recv_node_ping;
    fns[::atbus::protocol::msg::kNodePongRsp] = msg_handler::on_recv_node_pong;
  }

  if (!m.has_head()) {
    return EN_ATBUS_ERR_BAD_DATA;
  }

  ATBUS_FUNC_NODE_DEBUG(n, nullptr == conn ? nullptr : conn->get_binding(), conn, &m,
                        "node recv msg(cmd=%s, type=%d, sequence=%u, ret=%d)", detail::get_cmd_name(m.msg_body_case()),
                        m.head().type(), m.head().sequence(), m.head().ret());

  if (m.msg_body_case() > ATBUS_PROTOCOL_MSG_BODY_MAX || m.msg_body_case() < ATBUS_PROTOCOL_MSG_BODY_MIN) {
    return EN_ATBUS_ERR_ATNODE_INVALID_MSG;
  }

  if (nullptr == fns[m.msg_body_case()]) {
    return EN_ATBUS_ERR_ATNODE_INVALID_MSG;
  }

  n.stat_add_dispatch_times();
  return fns[m.msg_body_case()](n, conn, ATBUS_MACRO_MOVE(m), status, errcode);
}

ATBUS_MACRO_API const char *msg_handler::get_body_name(int body_case) {
  static std::string atbus_fn_names[ATBUS_PROTOCOL_MSG_BODY_MAX + 1];
  if (atbus_fn_names[0].empty()) {
    atbus_fn_names[0] = "Unknown";
    const ATBUS_MACRO_PROTOBUF_NAMESPACE_ID::Descriptor *msg_desc = atbus::protocol::msg::descriptor();
    for (int i = 0; i < msg_desc->field_count(); ++i) {
      const ATBUS_MACRO_PROTOBUF_NAMESPACE_ID::FieldDescriptor *fds = msg_desc->field(i);
      assert(fds->number() <= ATBUS_PROTOCOL_MSG_BODY_MAX);
      assert(fds->number() >= 0);
      atbus_fn_names[fds->number()] = fds->full_name();
    }
  }

  const char *ret = nullptr;
  if (body_case <= ATBUS_PROTOCOL_MSG_BODY_MAX && body_case >= ATBUS_PROTOCOL_MSG_BODY_MIN) {
    ret = atbus_fn_names[body_case].c_str();
  }

  if (nullptr == ret || !*ret) {
    ret = atbus_fn_names[0].c_str();
  }

  return ret;
}

ATBUS_MACRO_API int msg_handler::send_ping(node &n, connection &conn, uint64_t msg_seq) {
  ::ATBUS_MACRO_PROTOBUF_NAMESPACE_ID::ArenaOptions arena_options;
  arena_options.initial_block_size = ATBUS_MACRO_RESERVED_SIZE;
  ::ATBUS_MACRO_PROTOBUF_NAMESPACE_ID::Arena arena(arena_options);
  atbus::protocol::msg *m = ::ATBUS_MACRO_PROTOBUF_NAMESPACE_ID::Arena::CreateMessage<atbus::protocol::msg>(&arena);
  assert(m);

  ::atbus::protocol::msg_head *head = m->mutable_head();
  ::atbus::protocol::ping_data *body = m->mutable_node_ping_req();

  assert(head && body);

  uint64_t self_id = n.get_id();

  head->set_version(n.get_protocol_version());
  head->set_ret(0);
  head->set_type(0);
  head->set_sequence(msg_seq);
  head->set_src_bus_id(self_id);

  body->set_time_point(n.get_timer_sec() * 1000 + (n.get_timer_usec() / 1000) % 1000);

  return send_msg(n, conn, *m);
}

ATBUS_MACRO_API int msg_handler::send_reg(int32_t msg_id, node &n, connection &conn, int32_t ret_code,
                                          uint64_t msg_seq) {
  if (msg_id != ::atbus::protocol::msg::kNodeRegisterReq && msg_id != ::atbus::protocol::msg::kNodeRegisterRsp) {
    return EN_ATBUS_ERR_PARAMS;
  }

  ::ATBUS_MACRO_PROTOBUF_NAMESPACE_ID::ArenaOptions arena_options;
  arena_options.initial_block_size = ATBUS_MACRO_RESERVED_SIZE;
  ::ATBUS_MACRO_PROTOBUF_NAMESPACE_ID::Arena arena(arena_options);
  atbus::protocol::msg *m = ::ATBUS_MACRO_PROTOBUF_NAMESPACE_ID::Arena::CreateMessage<atbus::protocol::msg>(&arena);
  assert(m);

  ::atbus::protocol::msg_head *head = m->mutable_head();
  ::atbus::protocol::register_data *body;
  if (msg_id == ::atbus::protocol::msg::kNodeRegisterReq) {
    body = m->mutable_node_register_req();
  } else {
    body = m->mutable_node_register_rsp();
  }

  assert(head && body);

  uint64_t self_id = n.get_id();

  head->set_version(n.get_protocol_version());
  head->set_ret(ret_code);
  head->set_type(0);
  head->set_sequence(msg_seq);
  head->set_src_bus_id(self_id);

  body->mutable_channels()->Reserve(static_cast<int>(n.get_listen_list().size()));
  for (std::list<std::string>::const_iterator iter = n.get_listen_list().begin(); iter != n.get_listen_list().end();
       ++iter) {
    ::atbus::protocol::channel_data *chan = body->add_channels();
    if (chan == nullptr) {
      continue;
    }
    chan->set_address(*iter);
  }

  body->mutable_access_keys()->Reserve(static_cast<int>(n.get_conf().access_tokens.size()));
  for (size_t idx = 0; idx < n.get_conf().access_tokens.size(); ++idx) {
    uint32_t salt = 0;
    uint64_t hashval1 = 0;
    uint64_t hashval2 = 0;
    if (n.generate_access_hash(idx, salt, hashval1, hashval2)) {
      ::atbus::protocol::access_data *access = body->add_access_keys();
      if (access == nullptr) {
        continue;
      }
      access->set_token_salt(salt);
      access->set_token_hash1(hashval1);
      access->set_token_hash2(hashval2);
    }
  }

  body->set_bus_id(n.get_id());
  body->set_pid(n.get_pid());
  body->set_hostname(n.get_hostname());

  const endpoint *self_ep = n.get_self_endpoint();
  if (nullptr == self_ep) {
    ATBUS_FUNC_NODE_ERROR(n, self_ep, nullptr, EN_ATBUS_ERR_NOT_INITED, EN_ATBUS_ERR_NOT_INITED);
    return EN_ATBUS_ERR_NOT_INITED;
  }

  const std::vector<endpoint_subnet_range> &subsets = self_ep->get_subnets();
  for (size_t i = 0; i < subsets.size(); ++i) {
    atbus::protocol::subnet_range *subset = body->add_subnets();
    if (nullptr == subset) {
      ATBUS_FUNC_NODE_ERROR(n, self_ep, nullptr, EN_ATBUS_ERR_MALLOC, EN_ATBUS_ERR_MALLOC);
      break;
    }

    subset->set_id_prefix(subsets[i].get_id_prefix());
    subset->set_mask_bits(subsets[i].get_mask_bits());
  }
  body->set_flags(self_ep->get_flags());

  body->set_hash_code(n.get_hash_code());

  return send_msg(n, conn, *m);
}

ATBUS_MACRO_API int msg_handler::send_transfer_rsp(node &n, ::atbus::protocol::msg ATBUS_MACRO_RVALUE_REFERENCES m,
                                                   int32_t ret_code) {
  if (m.msg_body_case() != ::atbus::protocol::msg::kDataTransformReq &&
      m.msg_body_case() != ::atbus::protocol::msg::kDataTransformRsp) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr, nullptr, EN_ATBUS_ERR_BAD_DATA, 0);
    return EN_ATBUS_ERR_BAD_DATA;
  }

  ::atbus::protocol::forward_data *fwd_data;
  if (m.msg_body_case() == ::atbus::protocol::msg::kDataTransformReq) {
    // move req to rsp
    // Same arena here and so we can use unsafe release and set_allocated
    fwd_data = m.unsafe_arena_release_data_transform_req();
    m.unsafe_arena_set_allocated_data_transform_rsp(fwd_data);
  } else {
    fwd_data = m.mutable_data_transform_rsp();
  }
  assert(fwd_data);

  uint64_t self_id = n.get_id();
  uint64_t origin_from = fwd_data->from();
  uint64_t origin_to = fwd_data->to();

  // all transfer message must be send by a verified connect, there is no need to check access token again
  m.mutable_head()->set_ret(ret_code);
  m.mutable_head()->set_src_bus_id(self_id);

  fwd_data->set_from(origin_to);
  fwd_data->set_to(origin_from);

  if (0 == fwd_data->router_size() || *fwd_data->router().rbegin() != self_id) {
    fwd_data->add_router(self_id);
  }

  int ret = n.send_ctrl_msg(origin_from, m);
  if (ret < 0) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr, nullptr, ret, 0);
  }

  return ret;
}

ATBUS_MACRO_API int msg_handler::send_custom_cmd_rsp(node &n, connection *conn, const std::list<std::string> &rsp_data,
                                                     int32_t type, int32_t ret_code, uint64_t sequence,
                                                     uint64_t from_bus_id) {
  int ret = 0;

  ::ATBUS_MACRO_PROTOBUF_NAMESPACE_ID::ArenaOptions arena_options;
  arena_options.initial_block_size = ATBUS_MACRO_RESERVED_SIZE;
  ::ATBUS_MACRO_PROTOBUF_NAMESPACE_ID::Arena arena(arena_options);
  atbus::protocol::msg *m = ::ATBUS_MACRO_PROTOBUF_NAMESPACE_ID::Arena::CreateMessage<atbus::protocol::msg>(&arena);
  assert(m);

  ::atbus::protocol::msg_head *head = m->mutable_head();
  ::atbus::protocol::custom_command_data *body = m->mutable_custom_command_rsp();
  assert(head && body);

  uint64_t self_id = n.get_id();

  head->set_version(n.get_protocol_version());
  head->set_ret(ret_code);
  head->set_type(type);
  head->set_sequence(sequence);
  head->set_src_bus_id(self_id);

  body->set_from(n.get_id());
  body->mutable_access_keys()->Reserve(static_cast<int>(n.get_conf().access_tokens.size()));
  for (size_t idx = 0; idx < n.get_conf().access_tokens.size(); ++idx) {
    uint32_t salt = 0;
    uint64_t hashval1 = 0;
    uint64_t hashval2 = 0;
    if (n.generate_access_hash(idx, salt, hashval1, hashval2)) {
      ::atbus::protocol::access_data *access = body->add_access_keys();
      if (access == nullptr) {
        continue;
      }
      access->set_token_salt(salt);
      access->set_token_hash1(hashval1);
      access->set_token_hash2(hashval2);
    }
  }

  body->mutable_commands()->Reserve(static_cast<int>(rsp_data.size()));
  for (std::list<std::string>::const_iterator iter = rsp_data.begin(); iter != rsp_data.end(); ++iter) {
    ::atbus::protocol::custom_command_argv *cmd_data = body->add_commands();
    if (cmd_data == nullptr) {
      continue;
    }

    cmd_data->set_arg(*iter);
  }

  if (nullptr != conn) {
    ret = msg_handler::send_msg(n, *conn, *m);
  } else {
    ret = n.send_ctrl_msg(from_bus_id, *m);
  }

  return ret;
}

ATBUS_MACRO_API int msg_handler::send_node_connect_sync(node &n, uint64_t direct_from_bus_id, endpoint &dst_ep) {
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
    ::ATBUS_MACRO_PROTOBUF_NAMESPACE_ID::Arena arena(arena_options);
    atbus::protocol::msg *m = ::ATBUS_MACRO_PROTOBUF_NAMESPACE_ID::Arena::CreateMessage<atbus::protocol::msg>(&arena);
    assert(m);

    ::atbus::protocol::msg_head *head = m->mutable_head();
    ::atbus::protocol::connection_data *body = m->mutable_node_connect_sync();
    ::atbus::protocol::channel_data *conn_data = body->mutable_address();
    assert(head && body && conn_data);

    uint64_t self_id = n.get_id();

    head->set_version(n.get_protocol_version());
    head->set_ret(0);
    head->set_type(0);
    head->set_sequence(n.alloc_msg_seq());
    head->set_src_bus_id(self_id);

    conn_data->set_address(*select_address);
    int ret = n.send_ctrl_msg(direct_from_bus_id, *m);
    if (ret < 0) {
      ATBUS_FUNC_NODE_ERROR(n, nullptr, nullptr, ret, 0);
    }

    return ret;
  }

  return EN_ATBUS_ERR_SUCCESS;
}

ATBUS_MACRO_API int msg_handler::send_msg(node &n, connection &conn, const ::atbus::protocol::msg &m) {
  std::string msg_buffer;
  if (!m.SerializeToString(&msg_buffer)) {
    ATBUS_FUNC_NODE_ERROR(n, conn.get_binding(), &conn, EN_ATBUS_ERR_PACK, 0);
    return EN_ATBUS_ERR_PACK;
  }

  if (msg_buffer.size() > n.get_conf().msg_size + ATBUS_MACRO_MAX_FRAME_HEADER) {
    ATBUS_FUNC_NODE_ERROR(n, conn.get_binding(), &conn, EN_ATBUS_ERR_INVALID_SIZE, 0);
    return EN_ATBUS_ERR_INVALID_SIZE;
  }

  ATBUS_FUNC_NODE_DEBUG(n, conn.get_binding(), &conn, &m,
                        "node send msg(version=%d, cmd=%s, type=%d, sequence=%u, ret=%d, length=%llu)",
                        m.head().version(), detail::get_cmd_name(m.msg_body_case()), m.head().type(),
                        static_cast<unsigned long long>(m.head().sequence()), m.head().ret(),
                        static_cast<unsigned long long>(msg_buffer.size()));

  return conn.push(&msg_buffer[0], msg_buffer.size());
}

ATBUS_MACRO_API int msg_handler::on_recv_data_transfer_req(node &n, connection *conn,
                                                           ::atbus::protocol::msg ATBUS_MACRO_RVALUE_REFERENCES m,
                                                           int /*status*/, int /*errcode*/) {
  if (m.msg_body_case() != ::atbus::protocol::msg::kDataTransformReq &&
      m.msg_body_case() != ::atbus::protocol::msg::kDataTransformRsp) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, EN_ATBUS_ERR_BAD_DATA, 0);
    return EN_ATBUS_ERR_BAD_DATA;
  }

  ::atbus::protocol::forward_data *fwd_data;
  if (m.msg_body_case() == ::atbus::protocol::msg::kDataTransformReq) {
    fwd_data = m.mutable_data_transform_req();
  } else {
    fwd_data = m.mutable_data_transform_rsp();
  }
  assert(fwd_data);

  if (!m.has_head()) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, EN_ATBUS_ERR_BAD_DATA, 0);
    return EN_ATBUS_ERR_BAD_DATA;
  }

  // check version
  if (m.head().version() < n.get_protocol_minimal_version()) {
    return send_transfer_rsp(n, ATBUS_MACRO_MOVE(m), EN_ATBUS_ERR_UNSUPPORTED_VERSION);
  }

  // message from self has no connection
  if (nullptr == conn && m.head().src_bus_id() != n.get_id()) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, EN_ATBUS_ERR_BAD_DATA, 0);
    return EN_ATBUS_ERR_BAD_DATA;
  }

  if (nullptr != conn && ::atbus::connection::state_t::CONNECTED != conn->get_status()) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, EN_ATBUS_ERR_NOT_READY, 0);
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
    ATBUS_FUNC_NODE_DEBUG(n, (nullptr == conn ? nullptr : conn->get_binding()), conn, &m,
                          "node recv data length = %lld", static_cast<unsigned long long>(fwd_content_size));
    n.on_recv_data(nullptr == conn ? nullptr : conn->get_binding(), conn, m, fwd_content_ptr, fwd_content_size);

    if (fwd_data->flags() & atbus::protocol::FORWARD_DATA_FLAG_REQUIRE_RSP) {
      return send_transfer_rsp(n, ATBUS_MACRO_MOVE(m), EN_ATBUS_ERR_SUCCESS);
    }
    return EN_ATBUS_ERR_SUCCESS;
  }

  size_t router_size = fwd_data->router().size();
  if (router_size >= static_cast<size_t>(n.get_conf().ttl)) {
    return send_transfer_rsp(n, ATBUS_MACRO_MOVE(m), EN_ATBUS_ERR_ATNODE_TTL);
  }

  int res = 0;
  endpoint *to_ep = nullptr;
  // 转发数据
  node::bus_id_t direct_from_bus_id = m.head().src_bus_id();

  // add router id
  fwd_data->add_router(n.get_id());
  res = detail::forward_data_message(n, m, direct_from_bus_id, fwd_data->to(), &to_ep);

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
  if (res < 0 && false == n.is_parent_node(m.head().src_bus_id()) && false == n.is_child_node(fwd_data->to())) {
    // 如果失败的发送目标已经是父节点则不需要重发
    const endpoint *parent_ep = n.get_parent_endpoint();
    if (nullptr != parent_ep && (nullptr == to_ep || false == n.is_parent_node(to_ep->get_id()))) {
      res = detail::forward_data_message(n, m, direct_from_bus_id, parent_ep->get_id(), nullptr);
    }
  }

  // 只有失败或请求方要求回包，才下发通知，类似ICMP协议
  if (res < 0 || (fwd_data->flags() & atbus::protocol::FORWARD_DATA_FLAG_REQUIRE_RSP)) {
    res = send_transfer_rsp(n, ATBUS_MACRO_MOVE(m), res);
  }

  if (res < 0) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, res, 0);
  }

  return res;
}

ATBUS_MACRO_API int msg_handler::on_recv_data_transfer_rsp(node &n, connection *conn,
                                                           ::atbus::protocol::msg ATBUS_MACRO_RVALUE_REFERENCES m,
                                                           int /*status*/, int /*errcode*/) {
  if (m.msg_body_case() != ::atbus::protocol::msg::kDataTransformReq &&
      m.msg_body_case() != ::atbus::protocol::msg::kDataTransformRsp) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, EN_ATBUS_ERR_BAD_DATA, 0);
    return EN_ATBUS_ERR_BAD_DATA;
  }

  const ::atbus::protocol::forward_data *fwd_data;
  if (m.msg_body_case() == ::atbus::protocol::msg::kDataTransformReq) {
    fwd_data = &m.data_transform_req();
  } else {
    fwd_data = &m.data_transform_rsp();
  }
  assert(fwd_data);

  if (false == m.has_head()) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, EN_ATBUS_ERR_BAD_DATA, 0);
    return EN_ATBUS_ERR_BAD_DATA;
  }
  // message from self has no connection
  if (nullptr == conn && m.head().src_bus_id() != n.get_id()) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, EN_ATBUS_ERR_BAD_DATA, 0);
    return EN_ATBUS_ERR_BAD_DATA;
  }

  if (nullptr != conn && ::atbus::connection::state_t::CONNECTED != conn->get_status()) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, EN_ATBUS_ERR_NOT_READY, 0);
    return EN_ATBUS_ERR_NOT_READY;
  }

  // all transfer message must be send by a verified connect, there is no need to check access token again

  // dispatch message
  if (fwd_data->to() == n.get_id()) {
    if (m.head().ret() < 0) {
      ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, m.head().ret(), 0);
    }
    n.on_recv_forward_response(nullptr == conn ? nullptr : conn->get_binding(), conn, &m);
    return EN_ATBUS_ERR_SUCCESS;
  }

  // 检查如果发送目标不是来源，则转发失败消息
  return detail::forward_data_message(n, m, m.head().src_bus_id(), fwd_data->to(), nullptr);
}

ATBUS_MACRO_API int msg_handler::on_recv_custom_cmd_req(node &n, connection *conn,
                                                        ::atbus::protocol::msg ATBUS_MACRO_RVALUE_REFERENCES m,
                                                        int /*status*/, int /*errcode*/) {
  if (m.msg_body_case() != ::atbus::protocol::msg::kCustomCommandReq &&
      m.msg_body_case() != ::atbus::protocol::msg::kCustomCommandRsp) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, EN_ATBUS_ERR_BAD_DATA, 0);
    return EN_ATBUS_ERR_BAD_DATA;
  }

  const ::atbus::protocol::custom_command_data *cmd_data;
  if (m.msg_body_case() == ::atbus::protocol::msg::kCustomCommandReq) {
    cmd_data = &m.custom_command_req();
  } else {
    cmd_data = &m.custom_command_rsp();
  }
  assert(cmd_data);

  if (false == m.has_head()) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, EN_ATBUS_ERR_BAD_DATA, 0);
    return EN_ATBUS_ERR_BAD_DATA;
  }

  // check version
  if (m.head().version() < n.get_protocol_minimal_version()) {
    std::list<std::string> rsp_data;
    rsp_data.push_back("Access Deny - Unsupported Version");
    return send_custom_cmd_rsp(n, conn, rsp_data, m.head().type(), EN_ATBUS_ERR_UNSUPPORTED_VERSION,
                               m.head().sequence(), cmd_data->from());
  }

  // message from self has no connection
  if (nullptr == conn && cmd_data->from() != n.get_id()) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, EN_ATBUS_ERR_BAD_DATA, 0);
    return EN_ATBUS_ERR_BAD_DATA;
  }

  // Check access token
  int access_keys_size = cmd_data->access_keys_size();
  if (!n.get_conf().access_tokens.empty() || access_keys_size > 0) {
    bool check_pass = false;
    for (int i = 0; false == check_pass && i < access_keys_size; ++i) {
      const ::atbus::protocol::access_data &access_key = cmd_data->access_keys(i);
      check_pass = n.check_access_hash(access_key.token_salt(), access_key.token_hash1(), access_key.token_hash2());
    }

    if (!check_pass) {
      std::list<std::string> rsp_data;
      rsp_data.push_back("Access Deny - Invalid Token");
      ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, EN_ATBUS_ERR_ACCESS_DENY, 0);
      return send_custom_cmd_rsp(n, conn, rsp_data, m.head().type(), EN_ATBUS_ERR_ACCESS_DENY, m.head().sequence(),
                                 cmd_data->from());
    }
  }

  std::vector<std::pair<const void *, size_t> > cmd_args;
  cmd_args.reserve(static_cast<size_t>(cmd_data->commands_size()));
  for (int i = 0; i < cmd_data->commands_size(); ++i) {
    const ::atbus::protocol::custom_command_argv &arg = cmd_data->commands(i);
    cmd_args.push_back(
        std::make_pair<const void *, size_t>(static_cast<const void *>(arg.arg().data()), arg.arg().size()));
  }

  std::list<std::string> rsp_data;
  int ret =
      n.on_custom_cmd(nullptr == conn ? nullptr : conn->get_binding(), conn, cmd_data->from(), cmd_args, rsp_data);
  // shm & mem ignore response from other node
  if ((nullptr != conn && conn->is_running() && conn->check_flag(connection::flag_t::REG_FD)) ||
      n.get_id() == cmd_data->from()) {
    ret = send_custom_cmd_rsp(n, conn, rsp_data, m.head().type(), 0, m.head().sequence(), cmd_data->from());
  }

  return ret;
}

ATBUS_MACRO_API int msg_handler::on_recv_custom_cmd_rsp(node &n, connection *conn,
                                                        ::atbus::protocol::msg ATBUS_MACRO_RVALUE_REFERENCES m,
                                                        int /*status*/, int /*errcode*/) {
  if (m.msg_body_case() != ::atbus::protocol::msg::kCustomCommandReq &&
      m.msg_body_case() != ::atbus::protocol::msg::kCustomCommandRsp) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, EN_ATBUS_ERR_BAD_DATA, 0);
    return EN_ATBUS_ERR_BAD_DATA;
  }

  const ::atbus::protocol::custom_command_data *cmd_data;
  if (m.msg_body_case() == ::atbus::protocol::msg::kCustomCommandReq) {
    cmd_data = &m.custom_command_req();
  } else {
    cmd_data = &m.custom_command_rsp();
  }
  assert(cmd_data);

  if (false == m.has_head()) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, EN_ATBUS_ERR_BAD_DATA, 0);
    return EN_ATBUS_ERR_BAD_DATA;
  }
  // message from self has no connection
  if (nullptr == conn && cmd_data->from() != n.get_id()) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, EN_ATBUS_ERR_BAD_DATA, 0);
    return EN_ATBUS_ERR_BAD_DATA;
  }

  std::vector<std::pair<const void *, size_t> > cmd_args;
  cmd_args.reserve(static_cast<size_t>(cmd_data->commands_size()));
  for (int i = 0; i < cmd_data->commands_size(); ++i) {
    const ::atbus::protocol::custom_command_argv &arg = cmd_data->commands(i);
    cmd_args.push_back(
        std::make_pair<const void *, size_t>(static_cast<const void *>(arg.arg().data()), arg.arg().size()));
  }

  return n.on_custom_rsp(nullptr == conn ? nullptr : conn->get_binding(), conn, cmd_data->from(), cmd_args,
                         m.head().sequence());
}

ATBUS_MACRO_API int msg_handler::on_recv_node_sync_req(node &n, connection *conn,
                                                       ::atbus::protocol::msg ATBUS_MACRO_RVALUE_REFERENCES m,
                                                       int /*status*/, int /*errcode*/) {
  if (nullptr == conn || false == m.has_head()) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, EN_ATBUS_ERR_BAD_DATA, 0);
    return EN_ATBUS_ERR_BAD_DATA;
  }

  if (::atbus::connection::state_t::CONNECTED != conn->get_status()) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, EN_ATBUS_ERR_NOT_READY, 0);
    return EN_ATBUS_ERR_NOT_READY;
  }

  // check version
  if (m.head().version() < n.get_protocol_minimal_version()) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, EN_ATBUS_ERR_UNSUPPORTED_VERSION,
                          0);
    return EN_ATBUS_ERR_UNSUPPORTED_VERSION;
  }

  return EN_ATBUS_ERR_SUCCESS;
}

ATBUS_MACRO_API int msg_handler::on_recv_node_sync_rsp(node &n, connection *conn,
                                                       ::atbus::protocol::msg ATBUS_MACRO_RVALUE_REFERENCES m,
                                                       int /*status*/, int /*errcode*/) {
  if (nullptr == conn || false == m.has_head()) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, EN_ATBUS_ERR_BAD_DATA, 0);
    return EN_ATBUS_ERR_BAD_DATA;
  }

  if (::atbus::connection::state_t::CONNECTED != conn->get_status()) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, EN_ATBUS_ERR_NOT_READY, 0);
    return EN_ATBUS_ERR_NOT_READY;
  }

  return EN_ATBUS_ERR_SUCCESS;
}

ATBUS_MACRO_API int msg_handler::on_recv_node_reg_req(node &n, connection *conn,
                                                      ::atbus::protocol::msg ATBUS_MACRO_RVALUE_REFERENCES m,
                                                      int /*status*/, int errcode) {
  if (m.msg_body_case() != ::atbus::protocol::msg::kNodeRegisterReq &&
      m.msg_body_case() != ::atbus::protocol::msg::kNodeRegisterRsp) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, EN_ATBUS_ERR_BAD_DATA, 0);
    return EN_ATBUS_ERR_BAD_DATA;
  }

  const ::atbus::protocol::register_data *reg_data;
  if (m.msg_body_case() == ::atbus::protocol::msg::kNodeRegisterReq) {
    reg_data = &m.node_register_req();
  } else {
    reg_data = &m.node_register_rsp();
  }
  assert(reg_data);

  if (nullptr == conn || false == m.has_head()) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, EN_ATBUS_ERR_BAD_DATA, 0);
    return EN_ATBUS_ERR_BAD_DATA;
  }

  // check version
  if (m.head().version() < n.get_protocol_minimal_version()) {
    if (nullptr != conn) {
      int ret = send_reg(::atbus::protocol::msg::kNodeRegisterRsp, n, *conn, EN_ATBUS_ERR_UNSUPPORTED_VERSION,
                         m.head().sequence());
      if (ret < 0) {
        ATBUS_FUNC_NODE_ERROR(n, conn->get_binding(), conn, ret, 0);
        conn->reset();
      }
      return ret;
    } else {
      return EN_ATBUS_ERR_UNSUPPORTED_VERSION;
    }
  }

  // Check access token
  int access_keys_size = reg_data->access_keys_size();
  if (!n.get_conf().access_tokens.empty() || access_keys_size > 0) {
    bool check_pass = false;
    for (int i = 0; false == check_pass && i < access_keys_size; ++i) {
      const ::atbus::protocol::access_data &access_key = reg_data->access_keys(i);
      check_pass = n.check_access_hash(access_key.token_salt(), access_key.token_hash1(), access_key.token_hash2());
    }

    if (!check_pass) {
      ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, EN_ATBUS_ERR_ACCESS_DENY, 0);

      if (nullptr != conn) {
        int ret =
            send_reg(::atbus::protocol::msg::kNodeRegisterRsp, n, *conn, EN_ATBUS_ERR_ACCESS_DENY, m.head().sequence());
        if (ret < 0) {
          ATBUS_FUNC_NODE_ERROR(n, conn->get_binding(), conn, ret, 0);
          conn->reset();
        }
        return ret;
      } else {
        return EN_ATBUS_ERR_ACCESS_DENY;
      }
    }
  }

  endpoint *ep = nullptr;
  int32_t res = EN_ATBUS_ERR_SUCCESS;
  int32_t rsp_code = EN_ATBUS_ERR_SUCCESS;

  do {
    // 如果连接已经设定了端点，不需要再绑定到endpoint
    if (conn->is_connected()) {
      ep = conn->get_binding();
      if (nullptr == ep || ep->get_id() != reg_data->bus_id()) {
        ATBUS_FUNC_NODE_ERROR(n, ep, conn, EN_ATBUS_ERR_ATNODE_BUS_ID_NOT_MATCH, 0);
        conn->reset();
        rsp_code = EN_ATBUS_ERR_ATNODE_BUS_ID_NOT_MATCH;
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
        ATBUS_FUNC_NODE_ERROR(n, ep, conn, res, 0);
      } else if (false == ep->add_connection(conn, conn->check_flag(connection::flag_t::ACCESS_SHARE_HOST))) {
        // 有共享物理机限制的连接只能加为数据节点（一般就是内存通道或者共享内存通道）
        res = EN_ATBUS_ERR_ATNODE_NO_CONNECTION;
        ATBUS_FUNC_NODE_ERROR(n, ep, conn, res, 0);
      }
      rsp_code = res;

      ep->update_hash_code(reg_data->hash_code());
      ATBUS_FUNC_NODE_DEBUG(n, ep, conn, &m, "connection added to existed endpoint, res: %d", res);
      break;
    }

    // 创建新端点时需要判定全局路由表权限
    std::bitset<endpoint::flag_t::MAX> reg_flags(reg_data->flags());
    std::vector<endpoint_subnet_conf> ep_subnets;
    ep_subnets.reserve(reg_data->subnets_size() + 1);
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
        rsp_code = EN_ATBUS_ERR_NOT_INITED;
        ATBUS_FUNC_NODE_DEBUG(n, ep, conn, &m, "node not initialized");
        ATBUS_FUNC_NODE_ERROR(n, self_ep, nullptr, rsp_code, rsp_code);
        break;
      }

      if (!endpoint::contain(self_ep->get_subnets(), ep_subnets)) {
        rsp_code = EN_ATBUS_ERR_ATNODE_MASK_CONFLICT;

        ATBUS_FUNC_NODE_DEBUG(n, ep, conn, &m, "child mask must be greater than child node");
        ATBUS_FUNC_NODE_ERROR(n, self_ep, nullptr, rsp_code, rsp_code);
        break;
      }
    }

    endpoint::ptr_t new_ep = endpoint::create(&n, reg_data->bus_id(), ep_subnets, reg_data->pid(), hostname);
    if (!new_ep) {
      ATBUS_FUNC_NODE_ERROR(n, nullptr, conn, EN_ATBUS_ERR_MALLOC, 0);
      rsp_code = EN_ATBUS_ERR_MALLOC;
      break;
    }
    ep = new_ep.get();
    ep->update_hash_code(reg_data->hash_code());

    // 如果是正在连接父节点，要检查一下父节点覆盖的subnets是不是完全覆盖自己
    if (conn->get_address().address == n.get_conf().parent_address) {
      const endpoint *self_ep = n.get_self_endpoint();
      if (nullptr == self_ep) {
        rsp_code = EN_ATBUS_ERR_NOT_INITED;
        ATBUS_FUNC_NODE_DEBUG(n, ep, conn, &m, "node not initialized");
      } else if (!endpoint::contain(new_ep->get_subnets(), self_ep->get_subnets())) {
        rsp_code = EN_ATBUS_ERR_ATNODE_MASK_CONFLICT;
        ATBUS_FUNC_NODE_DEBUG(n, ep, conn, &m, "parent subnets do not include all self's subnets");
      }
      // 如果处于正在初始化要强制失败
      if (EN_ATBUS_ERR_SUCCESS != rsp_code) {
        if (node::state_t::CONNECTING_PARENT == n.get_state()) {
          ATBUS_FUNC_NODE_FATAL_SHUTDOWN(n, ep, conn, rsp_code, rsp_code);
        }

        conn->reset();
        n.add_endpoint_gc_list(new_ep);
        break;
      }
    }

    res = n.add_endpoint(new_ep);
    if (res < 0) {
      ATBUS_FUNC_NODE_ERROR(n, ep, conn, res, 0);
      rsp_code = res;
      break;
    }

    ATBUS_FUNC_NODE_DEBUG(n, ep, conn, &m, "node add a new endpoint, res: %d", res);
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
    const ::ATBUS_MACRO_PROTOBUF_NAMESPACE_ID::RepeatedPtrField< ::atbus::protocol::channel_data> &all_channels =
        reg_data->channels();
    for (int i = 0; i < all_channels.size(); ++i) {
      const ::atbus::protocol::channel_data &chan = all_channels.Get(i);
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
        ATBUS_FUNC_NODE_ERROR(n, ep, conn, res, 0);
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
    int ret = send_reg(::atbus::protocol::msg::kNodeRegisterRsp, n, *conn, rsp_code, m.head().sequence());
    if (rsp_code < 0) {
      ATBUS_FUNC_NODE_ERROR(n, ep, conn, ret, errcode);
      conn->reset();
    }

    return ret;
  } else {
    return 0;
  }
}

ATBUS_MACRO_API int msg_handler::on_recv_node_reg_rsp(node &n, connection *conn,
                                                      ::atbus::protocol::msg ATBUS_MACRO_RVALUE_REFERENCES m,
                                                      int /*status*/, int errcode) {
  if (m.msg_body_case() != ::atbus::protocol::msg::kNodeRegisterReq &&
      m.msg_body_case() != ::atbus::protocol::msg::kNodeRegisterRsp) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, EN_ATBUS_ERR_BAD_DATA, 0);
    return EN_ATBUS_ERR_BAD_DATA;
  }

  const ::atbus::protocol::register_data *reg_data;
  if (m.msg_body_case() == ::atbus::protocol::msg::kNodeRegisterReq) {
    reg_data = &m.node_register_req();
  } else {
    reg_data = &m.node_register_rsp();
  }
  assert(reg_data);

  if (nullptr == conn || false == m.has_head()) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, EN_ATBUS_ERR_BAD_DATA, 0);
    return EN_ATBUS_ERR_BAD_DATA;
  }

  endpoint *ep = conn->get_binding();
  n.on_reg(ep, conn, m.head().ret());

  // Check access token
  bool check_access_token = true;
  int access_keys_size = reg_data->access_keys_size();
  if (!n.get_conf().access_tokens.empty() || access_keys_size > 0) {
    bool check_pass = false;
    for (int i = 0; false == check_pass && i < access_keys_size; ++i) {
      const ::atbus::protocol::access_data &access_key = reg_data->access_keys(i);
      check_pass = n.check_access_hash(access_key.token_salt(), access_key.token_hash1(), access_key.token_hash2());
    }

    if (!check_pass) {
      ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, EN_ATBUS_ERR_ACCESS_DENY, 0);
      check_access_token = false;
    }
  }

  if (!check_access_token || m.head().ret() < 0) {
    if (nullptr != ep) {
      n.add_endpoint_gc_list(ep->watch());
    }
    int ret_code = m.head().ret();
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

      ATBUS_FUNC_NODE_ERROR(n, ep, conn, ret_code, errcode);
    } while (false);

    conn->reset();
    return ret_code;
  } else if (node::state_t::CONNECTING_PARENT == n.get_state()) {
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

ATBUS_MACRO_API int msg_handler::on_recv_node_conn_syn(node &n, connection *conn,
                                                       ::atbus::protocol::msg ATBUS_MACRO_RVALUE_REFERENCES m,
                                                       int /*status*/, int /*errcode*/) {
  if (m.msg_body_case() != ::atbus::protocol::msg::kNodeConnectSync) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, EN_ATBUS_ERR_BAD_DATA, 0);
    return EN_ATBUS_ERR_BAD_DATA;
  }

  const ::atbus::protocol::connection_data &conn_data = m.node_connect_sync();

  if (nullptr == conn || false == m.has_head()) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, EN_ATBUS_ERR_BAD_DATA, 0);
    return EN_ATBUS_ERR_BAD_DATA;
  }

  // check version
  if (m.head().version() < n.get_protocol_minimal_version()) {
    return EN_ATBUS_ERR_UNSUPPORTED_VERSION;
  }

  if (::atbus::connection::state_t::CONNECTED != conn->get_status()) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, EN_ATBUS_ERR_NOT_READY, 0);
    return EN_ATBUS_ERR_NOT_READY;
  }

  if (false == conn_data.has_address() || conn_data.address().address().empty()) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, EN_ATBUS_ERR_BAD_DATA, 0);
    return EN_ATBUS_ERR_BAD_DATA;
  }

  ATBUS_FUNC_NODE_DEBUG(n, nullptr, nullptr, &m, "node recv conn_syn and prepare connect to %s",
                        conn_data.address().address().c_str());
  int ret = n.connect(conn_data.address().address().c_str());
  if (ret < 0) {
    ATBUS_FUNC_NODE_ERROR(n, n.get_self_endpoint(), nullptr, ret, 0);
  }
  return EN_ATBUS_ERR_SUCCESS;
}

ATBUS_MACRO_API int msg_handler::on_recv_node_ping(node &n, connection *conn,
                                                   ::atbus::protocol::msg ATBUS_MACRO_RVALUE_REFERENCES m,
                                                   int /*status*/, int /*errcode*/) {
  if (!m.has_head() || !m.has_node_ping_req()) {
    ATBUS_FUNC_NODE_ERROR(n, nullptr == conn ? nullptr : conn->get_binding(), conn, EN_ATBUS_ERR_BAD_DATA, 0);
    return EN_ATBUS_ERR_BAD_DATA;
  }

  // check version
  int ret_code = 0;
  if (m.head().version() < n.get_protocol_minimal_version()) {
    ret_code = EN_ATBUS_ERR_UNSUPPORTED_VERSION;
  }

  if (nullptr != conn) {
    endpoint *ep = conn->get_binding();
    n.on_ping(ep, std::cref(m), std::cref(m.node_ping_req()));
    if (nullptr != ep) {
      ::ATBUS_MACRO_PROTOBUF_NAMESPACE_ID::ArenaOptions arena_options;
      arena_options.initial_block_size = ATBUS_MACRO_RESERVED_SIZE;
      ::ATBUS_MACRO_PROTOBUF_NAMESPACE_ID::Arena arena(arena_options);
      atbus::protocol::msg *rsp_m =
          ::ATBUS_MACRO_PROTOBUF_NAMESPACE_ID::Arena::CreateMessage<atbus::protocol::msg>(&arena);
      assert(rsp_m);

      ::atbus::protocol::msg_head *head = rsp_m->mutable_head();
      ::atbus::protocol::ping_data *body = rsp_m->mutable_node_pong_rsp();

      assert(head && body);

      uint64_t self_id = n.get_id();

      head->set_version(n.get_protocol_version());
      head->set_ret(ret_code);
      head->set_type(m.head().type());
      head->set_sequence(m.head().sequence());
      head->set_src_bus_id(self_id);

      body->set_time_point(m.node_ping_req().time_point());
      return send_msg(n, *conn, *rsp_m);
    }
  }

  return EN_ATBUS_ERR_SUCCESS;
}

ATBUS_MACRO_API int msg_handler::on_recv_node_pong(node &n, connection *conn,
                                                   ::atbus::protocol::msg ATBUS_MACRO_RVALUE_REFERENCES m,
                                                   int /*status*/, int /*errcode*/) {
  if (!m.has_node_pong_rsp()) {
    ATBUS_FUNC_NODE_DEBUG(n, conn ? conn->get_binding() : nullptr, conn, &m,
                          "node recv node_ping from 0x%llx but without node_pong_rsp",
                          static_cast<unsigned long long>(m.head().src_bus_id()));
    return EN_ATBUS_ERR_BAD_DATA;
  }

  const ::atbus::protocol::ping_data &msg_body = m.node_pong_rsp();

  if (nullptr != conn) {
    endpoint *ep = conn->get_binding();
    n.on_pong(ep, std::cref(m), std::cref(m.node_ping_req()));
    if (nullptr != ep && m.head().sequence() == ep->get_stat_ping()) {
      ep->set_stat_ping(0);

      time_t time_point = n.get_timer_sec() * 1000 + (n.get_timer_usec() / 1000) % 1000;
      ep->set_stat_ping_delay(time_point - msg_body.time_point(), n.get_timer_sec());
    }
  }

  return EN_ATBUS_ERR_SUCCESS;
}
}  // namespace atbus
