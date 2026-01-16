// Copyright 2026 atframework

#include "atbus_topology.h"

#include <utility>

ATBUS_MACRO_NAMESPACE_BEGIN

ATBUS_MACRO_API topology_policy_rule::~topology_policy_rule() {}

ATBUS_MACRO_API topology_policy_rule::topology_policy_rule()
    : require_same_process(false), require_same_hostname(false) {}

ATBUS_MACRO_API topology_policy_rule::topology_policy_rule(const topology_policy_rule &other)
    : require_same_process(other.require_same_process),
      require_same_hostname(other.require_same_hostname),
      require_label_values(other.require_label_values) {}

ATBUS_MACRO_API topology_policy_rule &topology_policy_rule::operator=(const topology_policy_rule &other) {
  if (this != &other) {
    require_same_process = other.require_same_process;
    require_same_hostname = other.require_same_hostname;
    require_label_values = other.require_label_values;
  }

  return *this;
}

ATBUS_MACRO_API topology_policy_rule::topology_policy_rule(topology_policy_rule &&other)
    : require_same_process(other.require_same_process),
      require_same_hostname(other.require_same_hostname),
      require_label_values(std::move(other.require_label_values)) {
  other.require_same_hostname = false;
  other.require_same_process = false;
}

ATBUS_MACRO_API topology_policy_rule &topology_policy_rule::operator=(topology_policy_rule &&other) {
  if (this != &other) {
    require_same_process = other.require_same_process;
    require_same_hostname = other.require_same_hostname;
    require_label_values = std::move(other.require_label_values);

    other.require_same_hostname = false;
    other.require_same_process = false;
  }

  return *this;
}

ATBUS_MACRO_API topology_data::~topology_data() {}

ATBUS_MACRO_API topology_data::topology_data() : pid(0) {}

ATBUS_MACRO_API topology_data::topology_data(const topology_data &other)
    : pid(other.pid), hostname(other.hostname), labels(other.labels) {}

ATBUS_MACRO_API topology_data &topology_data::operator=(const topology_data &other) {
  if (this != &other) {
    pid = other.pid;
    hostname = other.hostname;
    labels = other.labels;
  }

  return *this;
}

ATBUS_MACRO_API topology_data::topology_data(topology_data &&other)
    : pid(other.pid), hostname(std::move(other.hostname)), labels(std::move(other.labels)) {
  other.pid = 0;
}

ATBUS_MACRO_API topology_data &topology_data::operator=(topology_data &&other) {
  if (this != &other) {
    pid = other.pid;
    hostname = std::move(other.hostname);
    labels = std::move(other.labels);

    other.pid = 0;
  }

  return *this;
}

ATBUS_MACRO_API topology_peer::topology_peer(ctor_guard_type &guard)
    : bus_id_(guard.bus_id), proactively_added_(false) {}

ATBUS_MACRO_API topology_peer::~topology_peer() {}

ATBUS_MACRO_API topology_peer::ptr_t topology_peer::create(bus_id_t bus_id) {
  ctor_guard_type guard;
  guard.bus_id = bus_id;
  return atfw::util::memory::make_strong_rc<topology_peer>(guard);
}

ATBUS_MACRO_API const topology_data &topology_peer::get_topology_data() const noexcept {
  if (data_) {
    return *data_;
  }

  static topology_data empty_data;
  return empty_data;
}

ATBUS_MACRO_API bool topology_peer::contains_downstream(bus_id_t downstream_bus_id) const noexcept {
  auto iter = downstream_.find(downstream_bus_id);
  if (iter == downstream_.end()) {
    return false;
  }

  if (iter->second.expired()) {
    downstream_.erase(iter);
    return false;
  }

  return true;
}

ATBUS_MACRO_API void topology_peer::set_proactively_added(bool v) noexcept { proactively_added_ = v; }

ATBUS_MACRO_API bool topology_peer::get_proactively_added() const noexcept { return proactively_added_; }

ATBUS_MACRO_API void topology_peer::update_upstream(topology_peer::ptr_t upstream) noexcept {
  upstream_ = std::move(upstream);
}

ATBUS_MACRO_API void topology_peer::update_data(topology_data::ptr_t data) noexcept {
  if (data_ == data) {
    return;
  }

  data_ = std::move(data);
}

ATBUS_MACRO_API void topology_peer::add_downstream(topology_peer::ptr_t downstream) {
  if (!downstream) {
    return;
  }

  downstream_[downstream->get_bus_id()] = atfw::util::memory::weak_rc_ptr<topology_peer>(downstream);
}

ATBUS_MACRO_API void topology_peer::remove_downstream(bus_id_t downstream_bus_id, const topology_peer *check) noexcept {
  auto iter = downstream_.find(downstream_bus_id);
  if (iter == downstream_.end()) {
    return;
  }

  if (check != nullptr && iter->second.lock().get() != check) {
    auto ptr = iter->second.lock();
    if (ptr && ptr.get() != check) {
      return;
    }
  }

  downstream_.erase(iter);
}

ATBUS_MACRO_API const topology_peer::downstream_map_t &topology_peer::get_all_downstream() const noexcept {
  return downstream_;
}

ATBUS_MACRO_API topology_registry::topology_registry(ctor_guard_type &) {}

ATBUS_MACRO_API topology_registry::~topology_registry() {}

ATBUS_MACRO_API topology_registry::ptr_t topology_registry::create() {
  ctor_guard_type guard;
  return atfw::util::memory::make_strong_rc<topology_registry>(guard);
}

ATBUS_MACRO_API topology_peer::ptr_t topology_registry::get_peer(bus_id_t target_bus_id) const noexcept {
  auto iter = data_.find(target_bus_id);
  if (iter == data_.end()) {
    return nullptr;
  }

  return iter->second;
}

ATBUS_MACRO_API void topology_registry::remove_peer(bus_id_t target_bus_id) noexcept {
  auto iter = data_.find(target_bus_id);
  if (iter == data_.end()) {
    return;
  }

  topology_peer::ptr_t peer = iter->second;

  if (!peer) {
    data_.erase(iter);
    return;
  }

  peer->set_proactively_added(false);
  // 如果还有下游节点，不能删除
  if (peer->get_all_downstream().empty()) {
    data_.erase(iter);
  }

  // remove from upstream
  if (peer->upstream_) {
    peer->upstream_->remove_downstream(target_bus_id, peer.get());

    // 如果上游是被动添加的，且没有下游了，则递归删除
    if (!peer->upstream_->get_proactively_added() && peer->upstream_->downstream_.empty()) {
      remove_peer(peer->upstream_->get_bus_id());
    }
  }
}

ATBUS_MACRO_API bool topology_registry::update_peer(bus_id_t target_bus_id, bus_id_t upstream_bus_id,
                                                    topology_data::ptr_t data) {
  if (target_bus_id == 0) {
    return false;
  }

  // Reject trivial self-loop (including the case where the peer does not exist yet).
  if (target_bus_id == upstream_bus_id) {
    return false;
  }

  topology_peer::ptr_t upstream;
  if (upstream_bus_id != 0) {
    upstream = mutable_peer(upstream_bus_id);
  }

  topology_peer::ptr_t peer = get_peer(target_bus_id);
  if (peer) {
    peer->set_proactively_added(true);
    if (data) {
      peer->update_data(std::move(data));
    }

    if (peer->get_upstream() == upstream) {
      return true;
    }

    // 检查成环
    auto cur = upstream;
    while (cur) {
      if (cur->get_bus_id() == target_bus_id) {
        return false;
      }
      cur = cur->get_upstream();
    }

    // 解除旧的上游关系
    if (peer->get_upstream()) {
      peer->get_upstream()->remove_downstream(target_bus_id, peer.get());
    }
    peer->update_upstream(upstream);

    if (upstream) {
      upstream->add_downstream(peer);
    }
    return true;
  }

  // create new peer
  peer = mutable_peer(target_bus_id);
  peer->set_proactively_added(true);
  if (data) {
    peer->update_data(std::move(data));
  }
  peer->update_upstream(upstream);

  if (upstream) {
    upstream->add_downstream(peer);
  }

  return true;
}

ATBUS_MACRO_API topology_relation_type
topology_registry::get_relation(bus_id_t from, bus_id_t to, topology_peer::ptr_t *next_hop_peer) const noexcept {
  if (from == 0 || to == 0) {
    if (next_hop_peer != nullptr) {
      next_hop_peer->reset();
    }
    return topology_relation_type::kInvalid;
  }

  auto from_peer = get_peer(from);
  auto to_peer = get_peer(to);
  if (!from_peer || !to_peer) {
    if (next_hop_peer != nullptr) {
      next_hop_peer->reset();
    }
    return topology_relation_type::kInvalid;
  }

  if (from == to) {
    if (next_hop_peer != nullptr) {
      *next_hop_peer = to_peer;
    }
    return topology_relation_type::kSelf;
  }

  auto from_peer_upstream = from_peer->get_upstream();
  if (from_peer_upstream == to_peer) {
    if (next_hop_peer != nullptr) {
      *next_hop_peer = to_peer;
    }
    return topology_relation_type::kImmediateUpstream;
  }

  auto to_peer_upstream = to_peer->get_upstream();
  if (to_peer_upstream == from_peer) {
    if (next_hop_peer != nullptr) {
      *next_hop_peer = to_peer;
    }
    return topology_relation_type::kImmediateDownstream;
  }

  if (from_peer_upstream && from_peer_upstream == to_peer_upstream) {
    if (next_hop_peer != nullptr) {
      *next_hop_peer = from_peer_upstream;
    }
    return topology_relation_type::kSameUpstreamPeer;
  }

  // check TransitiveUpstream
  while (from_peer_upstream) {
    from_peer_upstream = from_peer_upstream->get_upstream();
    if (from_peer_upstream == to_peer) {
      if (next_hop_peer != nullptr) {
        *next_hop_peer = from_peer->get_upstream();
      }
      return topology_relation_type::kTransitiveUpstream;
    }
  }

  // check TransitiveDownstream
  while (to_peer_upstream) {
    if (next_hop_peer != nullptr) {
      *next_hop_peer = to_peer_upstream;
    }
    to_peer_upstream = to_peer_upstream->get_upstream();
    if (to_peer_upstream == from_peer) {
      return topology_relation_type::kTransitiveDownstream;
    }
  }

  if (next_hop_peer != nullptr) {
    if (from_peer->get_upstream()) {
      *next_hop_peer = from_peer->get_upstream();
    } else {
      *next_hop_peer = to_peer;
    }
  }
  return topology_relation_type::kOtherUpstreamPeer;
}

ATBUS_MACRO_API bool topology_registry::foreach_peer(
    ::atfw::util::nostd::function_ref<bool(const topology_peer::ptr_t &)> fn) const noexcept {
  for (const auto &item : data_) {
    if (!item.second) {
      continue;
    }

    if (!fn(item.second)) {
      return false;
    }
  }

  return true;
}

ATBUS_MACRO_API bool topology_registry::check_policy(const topology_policy_rule &from_policy,
                                                     const topology_data &from_data,
                                                     const topology_data &to_data) noexcept {
  if (from_policy.require_same_process || from_policy.require_same_hostname) {
    if (from_data.hostname != to_data.hostname) {
      return false;
    }

    if (from_policy.require_same_process && from_data.pid != to_data.pid) {
      return false;
    }
  }

  for (const auto &label_pair : from_policy.require_label_values) {
    const auto &label_key = label_pair.first;
    const auto &label_values = label_pair.second;

    auto to_label_iter = to_data.labels.find(label_key);
    if (to_label_iter == to_data.labels.end()) {
      return false;
    }

    if (label_values.end() == label_values.find(to_label_iter->second)) {
      return false;
    }
  }

  return true;
}

topology_peer::ptr_t topology_registry::mutable_peer(bus_id_t target_bus_id) {
  auto ret = get_peer(target_bus_id);
  if (ret) {
    return ret;
  }

  ret = topology_peer::create(target_bus_id);
  data_.emplace(target_bus_id, ret);
  return ret;
}

ATBUS_MACRO_NAMESPACE_END
