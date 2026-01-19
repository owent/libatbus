

#include <atbus_topology.h>

#include "frame/test_macros.h"

ATBUS_MACRO_NAMESPACE_BEGIN
struct topology_test_handles {
  static void add_downstream(atbus::topology_peer &peer, atbus::topology_peer::ptr_t downstream) {
    peer.add_downstream(downstream);
  }

  static void remove_downstream(atbus::topology_peer &peer, atbus::bus_id_t downstream_bus_id,
                                const atbus::topology_peer *check = nullptr) noexcept {
    peer.remove_downstream(downstream_bus_id, check);
  }

  static void update_upstream(atbus::topology_peer &peer, atbus::topology_peer::ptr_t upstream) noexcept {
    peer.update_upstream(upstream);
  }

  static void update_data(atbus::topology_peer &peer, atbus::topology_data::ptr_t data) noexcept {
    peer.update_data(std::move(data));
  }
};
ATBUS_MACRO_NAMESPACE_END

CASE_TEST(atbus_topology, topology_peer_basic) {
  atbus::topology_peer::ptr_t peer1 = atbus::topology_peer::create(0x12345678);
  atbus::topology_peer::ptr_t peer2 = atbus::topology_peer::create(0x22345678);

  CASE_EXPECT_EQ(0x12345678, peer1->get_bus_id());
  CASE_EXPECT_EQ(0x22345678, peer2->get_bus_id());

  CASE_EXPECT_FALSE(peer1->contains_downstream(0x22345678));
  CASE_EXPECT_FALSE(peer2->contains_downstream(0x12345678));

  atbus::topology_test_handles::add_downstream(*peer1, peer2);
  atbus::topology_test_handles::update_upstream(*peer2, peer1);

  CASE_EXPECT_TRUE(peer1->contains_downstream(0x22345678));
  CASE_EXPECT_FALSE(peer2->contains_downstream(0x12345678));

  atbus::topology_test_handles::remove_downstream(*peer1, 0x22345678, peer1.get());
  CASE_EXPECT_TRUE(peer1->contains_downstream(0x22345678));

  atbus::topology_test_handles::remove_downstream(*peer1, 0x22345678, peer2.get());

  CASE_EXPECT_FALSE(peer1->contains_downstream(0x22345678));
  CASE_EXPECT_FALSE(peer2->contains_downstream(0x12345678));

  atbus::topology_data::ptr_t data = ::atfw::util::memory::make_strong_rc<atbus::topology_data>();
  data->pid = 1234;
  data->hostname = "test_host";
  data->labels["key1"] = "value1";
  data->labels["key2"] = "value2";

  atbus::topology_test_handles::update_data(*peer1, std::move(data));
  const atbus::topology_data &ret_data = peer1->get_topology_data();
  CASE_EXPECT_EQ(1234, ret_data.pid);
  CASE_EXPECT_EQ(std::string("test_host"), ret_data.hostname);
  CASE_EXPECT_EQ(2u, ret_data.labels.size());
  CASE_EXPECT_EQ(std::string("value1"), ret_data.labels.at("key1"));
  CASE_EXPECT_EQ(std::string("value2"), ret_data.labels.at("key2"));
}

static atbus::topology_data::ptr_t make_topology_data(int32_t pid, const char *hostname) {
  atbus::topology_data::ptr_t data = ::atfw::util::memory::make_strong_rc<atbus::topology_data>();
  data->pid = pid;
  data->hostname = hostname;
  return data;
}

static uint8_t to_u8(atbus::topology_relation_type v) { return static_cast<uint8_t>(v); }

CASE_TEST(atbus_topology, topology_registry_relations) {
  atbus::topology_registry::ptr_t registry = atbus::topology_registry::create();
  CASE_EXPECT_TRUE(registry);

  // Build a small forest:
  /**
   *   1
   *  / \
   * 2   4
   * |
   * 3
   *   10
   */
  registry->update_peer(1, 0, make_topology_data(1, "h1"));
  registry->update_peer(2, 1, make_topology_data(2, "h1"));
  registry->update_peer(3, 2, make_topology_data(3, "h1"));
  registry->update_peer(4, 1, make_topology_data(4, "h1"));
  registry->update_peer(10, 0, make_topology_data(10, "h2"));

  atbus::topology_peer::ptr_t next_hop;

  CASE_EXPECT_EQ(to_u8(atbus::topology_relation_type::kInvalid), to_u8(registry->get_relation(0, 1, &next_hop)));
  CASE_EXPECT_FALSE(next_hop);
  CASE_EXPECT_EQ(to_u8(atbus::topology_relation_type::kInvalid), to_u8(registry->get_relation(1, 0, &next_hop)));
  CASE_EXPECT_FALSE(next_hop);
  CASE_EXPECT_EQ(to_u8(atbus::topology_relation_type::kInvalid), to_u8(registry->get_relation(1, 9999, &next_hop)));
  CASE_EXPECT_FALSE(next_hop);

  CASE_EXPECT_EQ(to_u8(atbus::topology_relation_type::kSelf), to_u8(registry->get_relation(1, 1, &next_hop)));
  CASE_EXPECT_TRUE(next_hop);
  CASE_EXPECT_EQ(1, next_hop->get_bus_id());

  CASE_EXPECT_EQ(to_u8(atbus::topology_relation_type::kImmediateUpstream),
                 to_u8(registry->get_relation(2, 1, &next_hop)));
  CASE_EXPECT_TRUE(next_hop);
  CASE_EXPECT_EQ(1, next_hop->get_bus_id());

  CASE_EXPECT_EQ(to_u8(atbus::topology_relation_type::kImmediateDownstream),
                 to_u8(registry->get_relation(1, 2, &next_hop)));
  CASE_EXPECT_TRUE(next_hop);
  CASE_EXPECT_EQ(2, next_hop->get_bus_id());

  CASE_EXPECT_EQ(to_u8(atbus::topology_relation_type::kTransitiveUpstream),
                 to_u8(registry->get_relation(3, 1, &next_hop)));
  CASE_EXPECT_TRUE(next_hop);
  CASE_EXPECT_EQ(2, next_hop->get_bus_id());

  CASE_EXPECT_EQ(to_u8(atbus::topology_relation_type::kTransitiveDownstream),
                 to_u8(registry->get_relation(1, 3, &next_hop)));
  CASE_EXPECT_TRUE(next_hop);
  CASE_EXPECT_EQ(2, next_hop->get_bus_id());

  CASE_EXPECT_EQ(to_u8(atbus::topology_relation_type::kSameUpstreamPeer),
                 to_u8(registry->get_relation(2, 4, &next_hop)));
  CASE_EXPECT_TRUE(next_hop);
  CASE_EXPECT_EQ(1, next_hop->get_bus_id());

  // Different roots: 1 has no upstream, so next hop should fall back to "to".
  CASE_EXPECT_EQ(to_u8(atbus::topology_relation_type::kOtherUpstreamPeer),
                 to_u8(registry->get_relation(1, 10, &next_hop)));
  CASE_EXPECT_TRUE(next_hop);
  CASE_EXPECT_EQ(10, next_hop->get_bus_id());

  // "from" has an upstream, so next hop should be from's upstream.
  CASE_EXPECT_EQ(to_u8(atbus::topology_relation_type::kOtherUpstreamPeer),
                 to_u8(registry->get_relation(2, 10, &next_hop)));
  CASE_EXPECT_TRUE(next_hop);
  CASE_EXPECT_EQ(1, next_hop->get_bus_id());
}

CASE_TEST(atbus_topology, topology_registry_update_and_remove) {
  atbus::topology_registry::ptr_t registry = atbus::topology_registry::create();
  CASE_EXPECT_TRUE(registry);

  registry->update_peer(1, 0, make_topology_data(1, "h1"));
  registry->update_peer(10, 0, make_topology_data(10, "h2"));
  registry->update_peer(2, 1, make_topology_data(2, "h1"));
  registry->update_peer(3, 2, make_topology_data(3, "h1"));

  atbus::topology_peer::ptr_t peer1 = registry->get_peer(1);
  atbus::topology_peer::ptr_t peer10 = registry->get_peer(10);
  atbus::topology_peer::ptr_t peer2 = registry->get_peer(2);
  atbus::topology_peer::ptr_t peer3 = registry->get_peer(3);
  CASE_EXPECT_TRUE(peer1);
  CASE_EXPECT_TRUE(peer10);
  CASE_EXPECT_TRUE(peer2);
  CASE_EXPECT_TRUE(peer3);

  CASE_EXPECT_TRUE(peer1->contains_downstream(2));
  CASE_EXPECT_TRUE(peer2->get_upstream());
  CASE_EXPECT_EQ(1, peer2->get_upstream()->get_bus_id());

  // Move 2 from upstream=1 to upstream=10
  registry->update_peer(2, 10, make_topology_data(2, "h2"));

  peer1 = registry->get_peer(1);
  peer10 = registry->get_peer(10);
  peer2 = registry->get_peer(2);
  peer3 = registry->get_peer(3);

  CASE_EXPECT_TRUE(peer1);
  CASE_EXPECT_TRUE(peer10);
  CASE_EXPECT_TRUE(peer2);
  CASE_EXPECT_TRUE(peer3);

  CASE_EXPECT_FALSE(peer1->contains_downstream(2));
  CASE_EXPECT_TRUE(peer10->contains_downstream(2));
  CASE_EXPECT_TRUE(peer2->get_upstream());
  CASE_EXPECT_EQ(10, peer2->get_upstream()->get_bus_id());

  // Removing peer2 should:
  // - remove it from upstream's downstream list
  // - clear upstream for peer3
  // - NOT erase peer2 from registry because it still has downstream (peer3)
  registry->remove_peer(2);
  CASE_EXPECT_TRUE(registry->get_peer(2));

  peer10 = registry->get_peer(10);
  peer3 = registry->get_peer(3);
  CASE_EXPECT_TRUE(peer10);
  CASE_EXPECT_TRUE(peer3);
  CASE_EXPECT_FALSE(peer10->contains_downstream(2));
  CASE_EXPECT_TRUE(peer3->get_upstream());
  CASE_EXPECT_EQ(2, peer3->get_upstream()->get_bus_id());

  // Removing peer10 should clear upstream of peers that were attached to it (none now).
  registry->remove_peer(10);
  CASE_EXPECT_FALSE(registry->get_peer(10));
}

CASE_TEST(atbus_topology, topology_registry_proactive_peer_not_auto_removed_when_orphaned) {
  atbus::topology_registry::ptr_t registry = atbus::topology_registry::create();
  CASE_EXPECT_TRUE(registry);

  // Peer 1 is created as target_bus_id -> proactively added.
  registry->update_peer(1, 0, make_topology_data(1, "h1"));
  // Peer 2 is created as target_bus_id and attached under 1.
  registry->update_peer(2, 1, make_topology_data(2, "h1"));

  atbus::topology_peer::ptr_t peer1 = registry->get_peer(1);
  atbus::topology_peer::ptr_t peer2 = registry->get_peer(2);
  CASE_EXPECT_TRUE(peer1);
  CASE_EXPECT_TRUE(peer2);
  CASE_EXPECT_TRUE(peer1->contains_downstream(2));
  CASE_EXPECT_TRUE(peer2->get_upstream());
  CASE_EXPECT_EQ(1, peer2->get_upstream()->get_bus_id());

  // Removing peer 2 should NOT auto-remove peer 1, even if peer 1 becomes orphaned,
  // because peer 1 was proactively added via update_peer(target_bus_id).
  registry->remove_peer(2);
  CASE_EXPECT_FALSE(registry->get_peer(2));
  peer1 = registry->get_peer(1);
  CASE_EXPECT_TRUE(peer1);
  CASE_EXPECT_FALSE(peer1->contains_downstream(2));
}

CASE_TEST(atbus_topology, topology_registry_passive_upstream_auto_removed_when_orphaned) {
  atbus::topology_registry::ptr_t registry = atbus::topology_registry::create();
  CASE_EXPECT_TRUE(registry);

  // Peer 1 is created passively as upstream_bus_id (not proactively added).
  registry->update_peer(2, 1, make_topology_data(2, "h1"));

  atbus::topology_peer::ptr_t peer1 = registry->get_peer(1);
  atbus::topology_peer::ptr_t peer2 = registry->get_peer(2);
  CASE_EXPECT_TRUE(peer1);
  CASE_EXPECT_TRUE(peer2);
  CASE_EXPECT_TRUE(peer1->contains_downstream(2));

  // Removing peer 2 should make peer 1 orphaned, and since peer 1 was passively created,
  // it should be auto-removed recursively.
  registry->remove_peer(2);
  CASE_EXPECT_FALSE(registry->get_peer(2));
  CASE_EXPECT_FALSE(registry->get_peer(1));
}

CASE_TEST(atbus_topology, topology_registry_passive_to_proactive_prevents_auto_remove) {
  atbus::topology_registry::ptr_t registry = atbus::topology_registry::create();
  CASE_EXPECT_TRUE(registry);

  // First, create peer 1 passively as upstream of peer 2.
  registry->update_peer(2, 1, make_topology_data(2, "h1"));
  CASE_EXPECT_TRUE(registry->get_peer(1));
  CASE_EXPECT_TRUE(registry->get_peer(2));

  // Then, explicitly update peer 1 as target_bus_id to make it proactively added.
  registry->update_peer(1, 0, make_topology_data(1, "h1"));
  CASE_EXPECT_TRUE(registry->get_peer(1));

  // Now removing peer 2 should NOT auto-remove peer 1.
  registry->remove_peer(2);
  CASE_EXPECT_FALSE(registry->get_peer(2));
  CASE_EXPECT_TRUE(registry->get_peer(1));
}

CASE_TEST(atbus_topology, topology_registry_foreach_and_policy) {
  atbus::topology_registry::ptr_t registry = atbus::topology_registry::create();
  CASE_EXPECT_TRUE(registry);

  registry->update_peer(1, 0, make_topology_data(100, "host_a"));
  registry->update_peer(2, 1, make_topology_data(101, "host_a"));
  registry->update_peer(3, 1, make_topology_data(102, "host_b"));

  size_t count_all = 0;
  CASE_EXPECT_TRUE(registry->foreach_peer([&count_all](const atbus::topology_peer::ptr_t &) {
    ++count_all;
    return true;
  }));
  CASE_EXPECT_EQ(3u, count_all);

  size_t count_break = 0;
  CASE_EXPECT_FALSE(registry->foreach_peer([&count_break](const atbus::topology_peer::ptr_t &) {
    ++count_break;
    return false;
  }));
  CASE_EXPECT_EQ(1u, count_break);

  // check_policy
  atbus::topology_policy_rule policy;
  atbus::topology_data::ptr_t from_data = make_topology_data(1234, "host_a");
  atbus::topology_data::ptr_t to_data_ok = make_topology_data(1234, "host_a");
  to_data_ok->labels["zone"] = "1";

  policy.require_same_hostname = true;
  policy.require_same_process = true;
  policy.require_label_values["zone"].insert("1");
  policy.require_label_values["zone"].insert("2");

  CASE_EXPECT_TRUE(atbus::topology_registry::check_policy(policy, *from_data, *to_data_ok));

  atbus::topology_data::ptr_t to_data_bad_host = to_data_ok;
  to_data_bad_host->hostname = "host_b";
  CASE_EXPECT_FALSE(atbus::topology_registry::check_policy(policy, *from_data, *to_data_bad_host));
  atbus::topology_data::ptr_t to_data_bad_pid = to_data_ok;
  to_data_bad_pid->pid = 5678;
  CASE_EXPECT_FALSE(atbus::topology_registry::check_policy(policy, *from_data, *to_data_bad_pid));

  atbus::topology_data::ptr_t to_data_bad_label = to_data_ok;
  to_data_bad_label->labels["zone"] = "3";
  CASE_EXPECT_FALSE(atbus::topology_registry::check_policy(policy, *from_data, *to_data_bad_label));
  atbus::topology_data::ptr_t to_data_missing_label = to_data_ok;
  to_data_missing_label->labels.clear();
  CASE_EXPECT_FALSE(atbus::topology_registry::check_policy(policy, *from_data, *to_data_missing_label));

  {
    // require_same_hostname=true, require_same_process=false
    atbus::topology_policy_rule policy_hostname_only;
    policy_hostname_only.require_same_hostname = true;
    policy_hostname_only.require_same_process = false;
    policy_hostname_only.require_label_values["zone"].insert("1");

    atbus::topology_data::ptr_t to_data_hostname_only_ok = make_topology_data(5678, "host_a");
    to_data_hostname_only_ok->labels["zone"] = "1";
    CASE_EXPECT_TRUE(
        atbus::topology_registry::check_policy(policy_hostname_only, *from_data, *to_data_hostname_only_ok));

    atbus::topology_data::ptr_t to_data_hostname_only_bad_host = to_data_hostname_only_ok;
    to_data_hostname_only_bad_host->hostname = "host_b";
    CASE_EXPECT_FALSE(
        atbus::topology_registry::check_policy(policy_hostname_only, *from_data, *to_data_hostname_only_bad_host));

    atbus::topology_data::ptr_t to_data_hostname_only_bad_label = to_data_hostname_only_ok;
    to_data_hostname_only_bad_label->labels["zone"] = "2";
    CASE_EXPECT_FALSE(
        atbus::topology_registry::check_policy(policy_hostname_only, *from_data, *to_data_hostname_only_bad_label));
  }

  {
    // require_same_hostname=false, require_same_process=true
    // Note: require_same_process implies hostname check.
    atbus::topology_policy_rule policy_process_only;
    policy_process_only.require_same_hostname = false;
    policy_process_only.require_same_process = true;
    policy_process_only.require_label_values["zone"].insert("1");

    atbus::topology_data::ptr_t to_data_process_only_ok = make_topology_data(1234, "host_a");
    to_data_process_only_ok->labels["zone"] = "1";
    CASE_EXPECT_TRUE(atbus::topology_registry::check_policy(policy_process_only, *from_data, *to_data_process_only_ok));

    atbus::topology_data::ptr_t to_data_process_only_bad_pid = to_data_process_only_ok;
    to_data_process_only_bad_pid->pid = 5678;
    CASE_EXPECT_FALSE(
        atbus::topology_registry::check_policy(policy_process_only, *from_data, *to_data_process_only_bad_pid));

    atbus::topology_data::ptr_t to_data_process_only_bad_host = to_data_process_only_ok;
    to_data_process_only_bad_host->hostname = "host_b";
    CASE_EXPECT_FALSE(
        atbus::topology_registry::check_policy(policy_process_only, *from_data, *to_data_process_only_bad_host));
  }

  {
    // require_same_hostname=false, require_same_process=false
    atbus::topology_policy_rule policy_labels_only;
    policy_labels_only.require_same_hostname = false;
    policy_labels_only.require_same_process = false;
    policy_labels_only.require_label_values["zone"].insert("1");

    atbus::topology_data::ptr_t to_data_labels_only_ok = make_topology_data(5678, "host_b");
    to_data_labels_only_ok->labels["zone"] = "1";
    CASE_EXPECT_TRUE(atbus::topology_registry::check_policy(policy_labels_only, *from_data, *to_data_labels_only_ok));

    atbus::topology_data::ptr_t to_data_labels_only_bad_label = to_data_labels_only_ok;
    to_data_labels_only_bad_label->labels["zone"] = "2";
    CASE_EXPECT_FALSE(
        atbus::topology_registry::check_policy(policy_labels_only, *from_data, *to_data_labels_only_bad_label));

    atbus::topology_data::ptr_t to_data_labels_only_missing_label = to_data_labels_only_ok;
    to_data_labels_only_missing_label->labels.clear();
    CASE_EXPECT_FALSE(
        atbus::topology_registry::check_policy(policy_labels_only, *from_data, *to_data_labels_only_missing_label));
  }
}

CASE_TEST(atbus_topology, topology_registry_update_peer_cycle_detection) {
  atbus::topology_registry::ptr_t registry = atbus::topology_registry::create();
  CASE_EXPECT_TRUE(registry);

  // Test case 1: Self-loop should be rejected (target == upstream)
  {
    CASE_EXPECT_FALSE(registry->update_peer(1, 1, make_topology_data(1, "h1")));
    // Peer should not be created
    CASE_EXPECT_FALSE(registry->get_peer(1));
  }

  // Build initial tree:
  /**
   *   1
   *  / \
   * 2   4
   * |
   * 3
   */
  registry->update_peer(1, 0, make_topology_data(1, "h1"));
  registry->update_peer(2, 1, make_topology_data(2, "h1"));
  registry->update_peer(3, 2, make_topology_data(3, "h1"));
  registry->update_peer(4, 1, make_topology_data(4, "h1"));

  // Verify initial structure
  atbus::topology_peer::ptr_t peer1 = registry->get_peer(1);
  atbus::topology_peer::ptr_t peer2 = registry->get_peer(2);
  atbus::topology_peer::ptr_t peer3 = registry->get_peer(3);
  atbus::topology_peer::ptr_t peer4 = registry->get_peer(4);
  CASE_EXPECT_TRUE(peer1);
  CASE_EXPECT_TRUE(peer2);
  CASE_EXPECT_TRUE(peer3);
  CASE_EXPECT_TRUE(peer4);

  // Test case 2: Direct cycle - try to set 1's upstream to 2 (1 -> 2 -> 1 would be a cycle)
  {
    CASE_EXPECT_FALSE(registry->update_peer(1, 2, make_topology_data(1, "h1")));
    // Peer1 should still have no upstream
    peer1 = registry->get_peer(1);
    CASE_EXPECT_TRUE(peer1);
    CASE_EXPECT_FALSE(peer1->get_upstream());
  }

  // Test case 3: Indirect cycle - try to set 1's upstream to 3 (1 -> 3 -> 2 -> 1 would be a cycle)
  {
    CASE_EXPECT_FALSE(registry->update_peer(1, 3, make_topology_data(1, "h1")));
    // Peer1 should still have no upstream
    peer1 = registry->get_peer(1);
    CASE_EXPECT_TRUE(peer1);
    CASE_EXPECT_FALSE(peer1->get_upstream());
  }

  // Test case 4: Try to set 2's upstream to 3 (2 -> 3 -> 2 would be a cycle)
  {
    CASE_EXPECT_FALSE(registry->update_peer(2, 3, make_topology_data(2, "h1")));
    // Peer2 should still have peer1 as upstream
    peer2 = registry->get_peer(2);
    CASE_EXPECT_TRUE(peer2);
    CASE_EXPECT_TRUE(peer2->get_upstream());
    CASE_EXPECT_EQ(1, peer2->get_upstream()->get_bus_id());
  }

  // Test case 5: Valid update - move peer4 to be under peer2 (no cycle)
  /**
   *   1
   *   |
   *   2
   *  / \
   * 3   4
   */
  {
    CASE_EXPECT_TRUE(registry->update_peer(4, 2, make_topology_data(4, "h1")));
    peer4 = registry->get_peer(4);
    CASE_EXPECT_TRUE(peer4);
    CASE_EXPECT_TRUE(peer4->get_upstream());
    CASE_EXPECT_EQ(2, peer4->get_upstream()->get_bus_id());
    // Peer1 should no longer have peer4 as downstream
    peer1 = registry->get_peer(1);
    CASE_EXPECT_FALSE(peer1->contains_downstream(4));
    // Peer2 should now have peer4 as downstream
    peer2 = registry->get_peer(2);
    CASE_EXPECT_TRUE(peer2->contains_downstream(4));
  }

  // Test case 6: Deeper indirect cycle - try to set 1's upstream to 4 (1 -> 4 -> 2 -> 1 would be a cycle)
  {
    CASE_EXPECT_FALSE(registry->update_peer(1, 4, make_topology_data(1, "h1")));
    peer1 = registry->get_peer(1);
    CASE_EXPECT_TRUE(peer1);
    CASE_EXPECT_FALSE(peer1->get_upstream());
  }

  // Test case 7: Valid update - peer can be its own root (upstream = 0)
  {
    atbus::topology_registry::ptr_t registry2 = atbus::topology_registry::create();
    CASE_EXPECT_TRUE(registry2->update_peer(100, 0, make_topology_data(100, "h1")));
    atbus::topology_peer::ptr_t peer100 = registry2->get_peer(100);
    CASE_EXPECT_TRUE(peer100);
    CASE_EXPECT_FALSE(peer100->get_upstream());
  }

  // Test case 8: target_bus_id = 0 should be rejected
  {
    CASE_EXPECT_FALSE(registry->update_peer(0, 1, make_topology_data(0, "h1")));
  }

  // Test case 9: Adding a new peer with valid upstream that is already downstream creates no cycle
  /**
   *   1
   *   |
   *   2
   *  /|\
   * 3 4 5
   */
  {
    CASE_EXPECT_TRUE(registry->update_peer(5, 2, make_topology_data(5, "h1")));
    atbus::topology_peer::ptr_t peer5 = registry->get_peer(5);
    CASE_EXPECT_TRUE(peer5);
    CASE_EXPECT_TRUE(peer5->get_upstream());
    CASE_EXPECT_EQ(2, peer5->get_upstream()->get_bus_id());
    peer2 = registry->get_peer(2);
    CASE_EXPECT_TRUE(peer2->contains_downstream(5));
  }

  // Test case 10: Multiple levels - create a chain and try to create a cycle
  // Add peer 6 under peer 3: 1 -> 2 -> 3 -> 6
  {
    CASE_EXPECT_TRUE(registry->update_peer(6, 3, make_topology_data(6, "h1")));
    atbus::topology_peer::ptr_t peer6 = registry->get_peer(6);
    CASE_EXPECT_TRUE(peer6);
    CASE_EXPECT_TRUE(peer6->get_upstream());
    CASE_EXPECT_EQ(3, peer6->get_upstream()->get_bus_id());

    // Try to set peer2's upstream to peer6 (would create: 2 -> 6 -> 3 -> 2)
    CASE_EXPECT_FALSE(registry->update_peer(2, 6, make_topology_data(2, "h1")));
    peer2 = registry->get_peer(2);
    CASE_EXPECT_TRUE(peer2);
    CASE_EXPECT_TRUE(peer2->get_upstream());
    CASE_EXPECT_EQ(1, peer2->get_upstream()->get_bus_id());
  }
}
