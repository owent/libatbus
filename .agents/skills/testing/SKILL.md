---
name: testing
description: Run and write unit tests for libatbus using the private test framework, including Windows DLL/PATH setup, test groups, encryption/compression tests, multi-node patterns, and shared memory notes.
---

# Unit testing (libatbus)

This repo uses a **private unit testing framework** (not GoogleTest).

## Run tests

The test executable is `atbus_unit_test`.

Common commands:

- Run all tests: `./atbus_unit_test`
- List tests: `./atbus_unit_test -l` / `./atbus_unit_test --list-tests`
- Run a group/case: `./atbus_unit_test -r <group>` or `./atbus_unit_test -r <group>.<case>`
- Filter: `./atbus_unit_test -f "pattern*"` / `./atbus_unit_test --filter "pattern*"`
- Help/version: `./atbus_unit_test -h`, `./atbus_unit_test -v`

## Windows: DLL lookup via PATH

On Windows, `atbus_unit_test.exe` (and samples) may fail to start if dependent DLLs cannot be found.

Preferred approach: **prepend DLL directories to `PATH`** for the current run/debug session.

Typical DLL directories in the monorepo/toolset layout:

- `<BUILD_DIR>\\publish\\bin\\<Config>`
- `<REPO_ROOT>\\third_party\\install\\windows-amd64-msvc-19\\bin`

Example (PowerShell):

- `$buildDir = "<BUILD_DIR>"`
- `$cfg = "Debug"`
- `$env:PATH = "$buildDir\\publish\\bin\\$cfg;$buildDir\\publish\\bin;${PWD}\\third_party\\install\\windows-amd64-msvc-19\\bin;" + $env:PATH`
- `Set-Location "$buildDir\\_deps\\atbus\\test\\$cfg"`
- `./atbus_unit_test.exe -l`

## Test groups and cases

### Node messaging (`atbus_node_msg`) — 24 tests

Core message delivery, crypto configuration, and multi-hop routing:

- `ping_pong` — Heartbeat exchange with timing validation
- `custom_cmd` / `custom_cmd_by_temp_node` / `send_cmd_to_self` — Custom command round-trip
- `reset_and_send` — Direct self-send via callback
- `upstream_and_downstream` — Tree topology message delivery
- `transfer_and_connect` / `transfer_only` — Proxy forwarding
- `send_failed` / `transfer_failed` / `transfer_failed_cross_upstreams` — Error handling
- `send_msg_to_self_and_need_rsp` — Response flag (REQUIRE_RSP) and response callback
- `topology_registry_multi_level_route` / `..._reverse` — Multi-hop routing through 3-level hierarchy
- `msg_handler_get_body_name` — Body type name resolution
- `crypto_config_key_exchange_algorithms` — Tests X25519, SECP256R1, SECP384R1
- `crypto_config_cipher_algorithms` — Tests AES-128/192/256 CBC/GCM, XXTEA, ChaCha20
- `crypto_config_comprehensive_matrix` — All crypto combination matrix
- `crypto_config_multiple_algorithms` — Multiple algorithms at once
- `crypto_config_upstream_downstream` — Crypto across topology
- `crypto_config_disabled` — Plaintext operation
- `crypto_list_available_algorithms` — Algorithm enumeration

### Node registration (`atbus_node_reg`) — 22 tests

Registration flow, timeout, access tokens, channel types:

- `reset_and_send_tcp` — Basic TCP registration handshake
- `timeout` — Registration timeout and recovery
- `message_size_limit` — Large message handling
- `reg_pc_success` / `reg_pc_success_cross_subnet` / `reg_pc_failed_with_subnet_mismatch` — Point-to-point registration
- `reg_bro_success` — Broadcast discovery
- `reg_failed_with_mismatch_access_token` / `reg_failed_with_missing_access_token` — Token validation
- `conflict` / `destruct` / `reconnect_upstream_failed` — Lifecycle edge cases
- `on_close_connection_normal` / `on_close_connection_by_peer` — Connection close callbacks
- `mem_and_send` / `shm_and_send` — Memory/shared memory channel tests
- `on_topology_upstream_set` / `on_topology_upstream_clear` / `on_topology_upstream_change_id` — Topology events
- `set_hostname` — Hostname configuration

### Connection context (`atbus_connection_context`) — 37 tests

Encryption/compression handshake, pack/unpack, all algorithm combinations:

- `padding_*` (9 tests) — Buffer allocation alignment and overhead validation
- `create_*` (4 tests) — Context creation with various key exchange types
- `get_*` / `is_*` (3 tests) — Property getters and algorithm support checks
- `update_compression_algorithm_*` (2 tests) — Compression config updates
- `handshake_*` (7 tests) — Key generation, public key exchange, complete flow
- `pack_unpack_*` (5 tests) — Message round-trip with/without encryption/compression
- `all_*_algorithms_*` / `comprehensive_crypto_matrix` — Full algorithm combination coverage
- `aead_ciphers_verification` / `non_aead_ciphers_verification` — AEAD vs non-AEAD validation
- `key_renegotiation_flow` — Key refresh scenarios
- `bidirectional_encrypted_communication` — Full duplex encrypted channel

### Message handler (`atbus_message_handler`) — 16 tests

Access data plaintext format, HMAC-SHA256 signatures:

- `make_access_data_plaintext_crypto_*` — Plaintext format: `timestamp:nonce1-nonce2:bus_id[:type:hash]`
- `make_access_data_plaintext_custom_command_*` — Command hash inclusion
- `calculate_access_data_signature_*` — HMAC-SHA256 computation with various inputs
- `generate_access_data_*` — Full access_data generation with tokens
- `integration_*` — Plaintext-signature consistency and determinism

### Topology (`atbus_topology`) — 9 tests

- `topology_peer_basic` / `topology_peer_downstream_iteration` — Peer creation and iteration
- `topology_registry_relations` — Self/upstream/downstream relation types
- `topology_registry_update_and_remove` — Peer lifecycle
- `topology_registry_*_auto_removed_*` — Proactive vs passive peer removal
- `topology_registry_foreach_and_policy` — Iteration and policies
- `topology_registry_update_peer_cycle_detection` — Loop prevention

### Channel tests — 24 tests

#### TCP (`channel_io_stream_tcp`) — 8 tests

- `io_stream_tcp_basic` / `io_stream_tcp_reset_by_client` / `io_stream_tcp_reset_by_server`
- `io_stream_tcp_size_extended` (>64KB) / `io_stream_tcp_connect_failed`

#### Unix socket (`channel_io_stream_unix`) — 5 tests (non-Windows)

- `io_stream_unix_basic` / `io_stream_unix_reset_*` / `io_stream_unix_size_extended`

#### Memory (`channel_mem`) — 5 tests

- `mem_attach_with_invalid_*` — Magic/version/alignment validation
- `mem_siso` / `mem_miso` — Single/multi-input-single-output ring buffer

#### Shared memory (`channel_shm`) — 6 tests

- `shm_attach_with_invalid_*` — Validation checks
- `shm_siso` — SHM ring buffer round-trip

### Other test groups

- `buffer` (11 tests) — Varint encoding, static/dynamic buffer manager modes
- `atbus_endpoint` (5 tests) — Connection retrieval, address type parsing
- `atbus_node_relationship` (3 tests) — FlatBuffers message, conf copy, endpoint ops
- `atbus_node_setup` (3 tests) — Listen override, algorithm enumeration
- `libatbus_error` (6 tests) — Error code to string mapping
- `atbus_connection_context_crosslang` (10 tests) — Binary enc/dec test vector generation
- `atbus_access_data_crosslang` (9 tests) — Auth signature test vector generation

## Writing tests

Test files are under `test/case/`.

### Minimal example

```cpp
#include <frame/test_macros.h>
#include "atbus_node.h"

CASE_TEST(my_group, my_test) {
    CASE_EXPECT_EQ(1, 1);
}
```

### Multi-node test pattern

```cpp
CASE_TEST(atbus_node_msg, my_multi_node_test) {
    // 1. Setup libuv event loop
    uv_loop_t ev_loop;
    uv_loop_init(&ev_loop);

    // 2. Configure nodes
    atbus::node::conf_t conf;
    atbus::node::default_conf(&conf);
    conf.ev_loop = &ev_loop;
    conf.receive_buffer_size = 64 * 1024;
    conf.ping_interval = std::chrono::seconds{8};

    // 3. Create and initialize nodes
    auto node1 = atbus::node::create();
    auto node2 = atbus::node::create();
    node1->init(0x12345678, &conf);
    node2->init(0x12356789, &conf);

    // 4. Listen on addresses
    node1->listen("ipv4://127.0.0.1:16387");
    node2->listen("ipv4://127.0.0.1:16388");

    // 5. Start nodes
    atbus::node::start_conf_t start_conf;
    start_conf.timer_timepoint = unit_test_make_timepoint(0, 0);
    node1->start(start_conf);
    node2->start(start_conf);

    // 6. Connect and wait
    node2->connect("ipv4://127.0.0.1:16387");

    time_t proc_usec = 0;
    UNITTEST_WAIT_UNTIL(ev_loop,
        node1->is_endpoint_available(0x12356789), 8000, 8) {
        ++proc_usec;
        node1->proc(unit_test_make_timepoint(0, proc_usec));
        node2->proc(unit_test_make_timepoint(0, proc_usec));
    }
    CASE_EXPECT_TRUE(node1->is_endpoint_available(0x12356789));

    // 7. Send and verify
    // ... setup callbacks, send data, verify receipt ...

    // 8. Cleanup
    unit_test_setup_exit(&ev_loop);
}
```

### Encryption test pattern

```cpp
CASE_TEST(atbus_connection_context, my_crypto_test) {
    // 1. Init crypto globally
    atfw::util::crypto::cipher::init_global_algorithm();

    // 2. Create DH shared context
    auto dh_ctx = atfw::util::crypto::dh::shared_context::create("x25519");

    // 3. Create client/server connection contexts
    auto client_ctx = atbus::connection_context::create(
        protocol::ATBUS_CRYPTO_KEY_EXCHANGE_X25519, dh_ctx);
    auto server_ctx = atbus::connection_context::create(
        protocol::ATBUS_CRYPTO_KEY_EXCHANGE_X25519, dh_ctx);

    // 4. Perform handshake (see libatbus-protocol-crypto skill for full flow)
    // ...

    // 5. Pack encrypted message
    atbus::random_engine_t rng;
    auto packed = client_ctx->pack_message(msg, 3, rng, 65536);
    CASE_EXPECT_TRUE(packed.is_success());

    // 6. Unpack and verify
    atbus::message recv_msg;
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS,
        server_ctx->unpack_message(recv_msg, packed.get_success().as_span(), 65536));

    // 7. Cleanup
    atfw::util::crypto::cipher::cleanup_global_algorithm();
}
```

### Wait macros reference

```cpp
// Wait until condition is true (or timeout in ms)
UNITTEST_WAIT_UNTIL(uv_loop, condition, timeout_ms, tick_ms) {
    // Body executed each tick
    node->proc(timepoint);
}

// Wait while condition is true
UNITTEST_WAIT_IF(uv_loop, condition, timeout_ms, tick_ms) { ... }

// Wait fixed duration
UNITTEST_WAIT_MS(uv_loop, timeout_ms, tick_ms) { ... }

// Time point helper
auto tp = unit_test_make_timepoint(seconds, microseconds);
```

## Address schemes for tests

- **TCP**: `ipv4://127.0.0.1:PORT` or `ipv6://[::1]:PORT`
- **Unix** (non-Windows): `unix:///tmp/path.sock` (3 slashes)
- **Memory**: `mem://0xADDRESS` (single process, pointer-based)
- **Shared Memory**: `shm://NAME` (cross-process)
- **Pipe** (Windows): `pipe:///path`

## Windows notes (shared memory)

- Private shared memory does not allow cross-process sharing on Windows
- Public shared memory may require administrator privileges
