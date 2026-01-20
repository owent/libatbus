// Copyright 2026 atframework

#pragma once

#include <design_pattern/nomovable.h>
#include <design_pattern/noncopyable.h>
#include <memory/rc_ptr.h>
#include <nostd/function_ref.h>

#include <unordered_map>
#include <unordered_set>

#include "detail/libatbus_config.h"

ATBUS_MACRO_NAMESPACE_BEGIN

/**
 * @brief Topology model for bus nodes.
 *
 * This header provides a lightweight in-memory topology registry:
 * - Each node is a @ref topology_peer, identified by @ref bus_id_t.
 * - A node may have an optional upstream parent (forming a tree/forest).
 * - A registry (@ref topology_registry) maintains peers and allows querying relations.
 *
 * @note This is an in-process data structure. It is NOT thread-safe.
 */

class topology_peer;
class topology_registry;
struct topology_test_handles;

/**
 * @brief Relation type between two peers in the topology registry.
 *
 * The relation is evaluated based on the upstream chain (parent links).
 */
enum class topology_relation_type : uint32_t {
  /** @brief Invalid input or one/both peers not found. */
  kInvalid = 0,

  /** @brief from == to. */
  kSelf = 1,

  /** @brief to is the direct upstream(parent) of from. */
  kImmediateUpstream = 2,

  /** @brief to is an ancestor of from, but not the direct upstream. */
  kTransitiveUpstream = 3,

  /** @brief to is the direct downstream(child) of from. */
  kImmediateDownstream = 4,

  /** @brief to is a descendant of from, but not the direct downstream. */
  kTransitiveDownstream = 5,

  /** @brief from and to share the same direct upstream. */
  kSameUpstreamPeer = 6,

  /** @brief from and to do not fall into any of the above categories. */
  kOtherUpstreamPeer = 7,
};

/**
 * @brief Policy rule used by @ref topology_registry::check_policy.
 *
 * It describes constraints that the "to" peer must satisfy.
 */
struct ATFW_UTIL_SYMBOL_VISIBLE topology_policy_rule {
  /** @brief If true, require same pid and same hostname. */
  bool require_same_process;

  /** @brief If true, require same hostname. */
  bool require_same_hostname;

  /**
   * @brief Label constraints.
   *
   * Key: label name.
   * Value: allowed label values (set).
   */
  std::unordered_map<std::string, std::unordered_set<std::string>> require_label_values;

  ATBUS_MACRO_API ~topology_policy_rule();

  ATBUS_MACRO_API topology_policy_rule();
  ATBUS_MACRO_API topology_policy_rule(const topology_policy_rule &other);
  ATBUS_MACRO_API topology_policy_rule &operator=(const topology_policy_rule &other);
  ATBUS_MACRO_API topology_policy_rule(topology_policy_rule &&other);
  ATBUS_MACRO_API topology_policy_rule &operator=(topology_policy_rule &&other);
};

/**
 * @brief Runtime topology data associated with a peer.
 */
struct ATFW_UTIL_SYMBOL_VISIBLE topology_data {
  using ptr_t = atfw::util::memory::strong_rc_ptr<topology_data>;

  /** @brief Process id of the peer. */
  int32_t pid;

  /** @brief Hostname of the peer. */
  std::string hostname;

  /** @brief Arbitrary labels for policy matching (e.g. region/zone/group/version). */
  std::unordered_map<std::string, std::string> labels;

  ATBUS_MACRO_API ~topology_data();

  ATBUS_MACRO_API topology_data();
  ATBUS_MACRO_API topology_data(const topology_data &other);
  ATBUS_MACRO_API topology_data &operator=(const topology_data &other);
  ATBUS_MACRO_API topology_data(topology_data &&other);
  ATBUS_MACRO_API topology_data &operator=(topology_data &&other);
};

/**
 * @brief A topology node (peer).
 *
 * A peer has:
 * - A stable bus id.
 * - An optional upstream peer.
 * - A set of downstream peers (tracked by weak pointers).
 * - Associated @ref topology_data.
 */
class topology_peer {
  UTIL_DESIGN_PATTERN_NOCOPYABLE(topology_peer)
  UTIL_DESIGN_PATTERN_NOMOVABLE(topology_peer)

 public:
  using ptr_t = atfw::util::memory::strong_rc_ptr<topology_peer>;

 private:
  struct ctor_guard_type {
    bus_id_t bus_id;
  };
  using downstream_map_t = std::unordered_map<bus_id_t, atfw::util::memory::weak_rc_ptr<topology_peer>>;

 public:
  ATBUS_MACRO_API topology_peer(ctor_guard_type &);
  ATBUS_MACRO_API ~topology_peer();

  static ATBUS_MACRO_API ptr_t create(bus_id_t bus_id);

  /** @brief Get the bus id of this peer. */
  ATFW_UTIL_FORCEINLINE bus_id_t get_bus_id() const noexcept { return bus_id_; }

  /** @brief Get the upstream (parent) peer, or nullptr if this peer is a root. */
  ATFW_UTIL_FORCEINLINE const topology_peer::ptr_t &get_upstream() const noexcept { return upstream_; }

  /** @brief Get current topology data of this peer. */
  ATBUS_MACRO_API const topology_data &get_topology_data() const noexcept;

  /**
   * @brief Check whether a downstream(peer) with given bus id exists.
   *
   * @note Expired weak references will be cleaned up during this call.
   */
  ATBUS_MACRO_API bool contains_downstream(bus_id_t downstream_bus_id) const noexcept;

 private:
  ATBUS_MACRO_API void set_proactively_added(bool v) noexcept;

  ATBUS_MACRO_API bool get_proactively_added() const noexcept;

  ATBUS_MACRO_API void update_upstream(topology_peer::ptr_t upstream) noexcept;

  ATBUS_MACRO_API void update_data(topology_data::ptr_t data) noexcept;

  ATBUS_MACRO_API void add_downstream(topology_peer::ptr_t downstream);

  ATBUS_MACRO_API void remove_downstream(bus_id_t downstream_bus_id, const topology_peer *check = nullptr) noexcept;

  ATBUS_MACRO_API const downstream_map_t &get_all_downstream() const noexcept;

 private:
  friend class topology_registry;
  friend struct topology_test_handles;

  bus_id_t bus_id_;
  ptr_t upstream_;
  bool proactively_added_;

  mutable downstream_map_t downstream_;

  topology_data::ptr_t data_;
};

/**
 * @brief Topology registry.
 *
 * Provides CRUD for peers and relation querying.
 */
class topology_registry {
  UTIL_DESIGN_PATTERN_NOCOPYABLE(topology_registry)
  UTIL_DESIGN_PATTERN_NOMOVABLE(topology_registry)

 public:
  using ptr_t = atfw::util::memory::strong_rc_ptr<topology_registry>;

 private:
  struct ctor_guard_type {};

 public:
  ATBUS_MACRO_API topology_registry(ctor_guard_type &);
  ATBUS_MACRO_API ~topology_registry();

  static ATBUS_MACRO_API ptr_t create();

  /** @brief Get peer by bus id, or nullptr if not found. */
  ATBUS_MACRO_API topology_peer::ptr_t get_peer(bus_id_t target_bus_id) const noexcept;

  /**
   * @brief Remove a peer and fix relationships.
   *
   * If the peer has an upstream, it will be removed from the upstream's downstream set.
   * For each downstream peer whose upstream is this peer, its upstream will be cleared.
   */
  ATBUS_MACRO_API void remove_peer(bus_id_t target_bus_id) noexcept;

  /**
   * @brief Create or update a peer.
   *
   * - If @p target_bus_id is 0, this call is ignored.
   * - If @p upstream_bus_id is 0, the peer becomes a root (no upstream).
   * - If peer exists and upstream changed, downstream links will be updated accordingly.
   *
   * @return true on success, false on failure (e.g. invalid target_bus_id or there will be a circle).
   */
  ATBUS_MACRO_API bool update_peer(bus_id_t target_bus_id, bus_id_t upstream_bus_id, topology_data::ptr_t data);

  /**
   * @brief Get the topology relation between two peers.
   * @param from Source peer id.
   * @param to Target peer id.
   * @param next_hop_peer Optional output pointer of the next-hop peer.
   * @note If the relation is kTransitiveUpstream or kTransitiveDownstream, @p next_hop_peer is the @p to.
   *       If the relation is kSameUpstreamPeer, @p next_hop_peer is the upstream of both @p from and @p to.
   *       If the relation is kOtherUpstreamPeer, @p next_hop_peer prefers the upstream of @p from;
   *       if @p from has no upstream then output @p to.
   * @return The topology relation type.
   */
  ATBUS_MACRO_API topology_relation_type get_relation(bus_id_t from, bus_id_t to,
                                                      topology_peer::ptr_t *next_hop_peer) const noexcept;

  /**
   * @brief Iterate all peers in registry.
   * @param fn Callback, returns false to stop iteration early.
   * @return true if iterated all peers, false if stopped by callback.
   */
  ATBUS_MACRO_API bool foreach_peer(
      ::atfw::util::nostd::function_ref<bool(const topology_peer::ptr_t &)> fn) const noexcept;

  /**
   * @brief Check whether @p to_data satisfies @p from_policy.
   *
   * The checks include:
   * - same hostname (optional)
   * - same process (optional, implies same hostname)
   * - required labels (optional)
   */
  static ATBUS_MACRO_API bool check_policy(const topology_policy_rule &from_policy, const topology_data &from_data,
                                           const topology_data &to_data) noexcept;

 private:
  topology_peer::ptr_t mutable_peer(bus_id_t target_bus_id);

 private:
  std::unordered_map<bus_id_t, topology_peer::ptr_t> data_;
};

ATBUS_MACRO_NAMESPACE_END
