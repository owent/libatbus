# libatbus - Copilot Instructions

## Project Overview

**libatbus** is a high-performance, fully asynchronous, tree-structured message bus framework for cross-platform communication. It supports shared memory channels for intra-machine communication and TCP for inter-machine communication. The bus uses ECDH key exchange for end-to-end encryption and supports pluggable compression algorithms.

- **Repository**: https://github.com/atframework/libatbus
- **License**: MIT (libatbus), Apache 2.0 (Flatbuffers), Node's license (libuv)
- **Languages**: C++ (C++17 required, C++17/C++20/C++23 features used when available)

## Skills (How-to playbooks)

Operational, copy/paste-friendly guides live in `.agents/skills/`:

- Entry point: `.agents/skills/README.md`

## Build System

This project uses **CMake** (minimum version 3.24.0).

Build steps and common configuration options are documented in:

- `.agents/skills/build/SKILL.md`

## Directory Structure

```
libatbus/
├── include/               # Public headers
│   ├── libatbus.h         # Main include header (includes all public headers)
│   ├── atbus_node.h       # Core node: init, listen, connect, send, routing
│   ├── atbus_endpoint.h   # Remote node representation (ctrl + data connections)
│   ├── atbus_connection.h # Single connection lifecycle & state machine
│   ├── atbus_connection_context.h  # ECDH key exchange, cipher/compression negotiation
│   ├── atbus_message_handler.h     # Message dispatch table & access_data signatures
│   ├── atbus_topology.h   # Topology registry, relation types, routing decisions
│   ├── libatbus_protocol.h         # Protobuf-generated protocol wrapper (message class)
│   ├── libatbus_protocol.proto     # Protobuf v3 protocol definition (source of truth)
│   └── detail/            # Internal headers
│       ├── buffer.h                  # Varint encoding, buffer_manager (static/dynamic)
│       ├── libatbus_adapter_libuv.h  # libuv type aliases (stream_t, loop_t, etc.)
│       ├── libatbus_channel_types.h  # Channel address types, priority calculation
│       ├── libatbus_channel_export.h # Channel API exports (io_stream, mem, shm)
│       ├── libatbus_config.h.in      # CMake-generated config macros
│       ├── libatbus_error.h          # Error code enum (ATBUS_ERROR_TYPE)
│       └── libatbus_protocol.fbs     # FlatBuffers schema (legacy/internal)
├── src/                   # Implementation
│   ├── atbus_node.cpp             # Node init, routing, event loop, crypto reload
│   ├── atbus_endpoint.cpp         # Endpoint lifecycle, connection selection by priority
│   ├── atbus_connection.cpp       # Connection state machine, I/O dispatch
│   ├── atbus_connection_context.cpp  # ECDH handshake, pack/unpack with encrypt+compress
│   ├── atbus_message_handler.cpp  # Message dispatch, register/ping/forward handlers
│   ├── atbus_topology.cpp         # Topology peer tracking, relation queries
│   ├── libatbus_protocol.cpp      # Protocol message arena allocation
│   ├── channel_io_stream.cpp      # TCP/Unix/pipe channel (libuv streams)
│   ├── channel_mem.cpp            # In-process memory ring buffer channel
│   ├── channel_shm.cpp            # Cross-process shared memory channel
│   ├── channel_utility.cpp        # Channel address parsing & priority
│   └── detail/
│       ├── buffer.cpp             # Varint, buffer_block, buffer_manager impls
│       └── libatbus_error.cpp     # Error code to string mapping
├── test/                  # Unit tests
│   └── case/              # Test case files
│       ├── atbus_node_msg_test.cpp         # 24 tests: messaging, crypto config, routing
│       ├── atbus_node_reg_test.cpp         # 22 tests: registration, timeout, channels
│       ├── atbus_node_relationship_test.cpp # 3 tests: FlatBuffers, conf copy, endpoints
│       ├── atbus_node_setup_test.cpp       # 3 tests: listen override, algorithm listing
│       ├── atbus_endpoint_test.cpp         # 5 tests: connections, address parsing
│       ├── atbus_connection_context_test.cpp # 37 tests: padding, handshake, pack/unpack
│       ├── atbus_message_handler_test.cpp  # 16 tests: access_data, signatures
│       ├── atbus_topology_test.cpp         # 9 tests: peer CRUD, relation, cycle detect
│       ├── buffer_test.cpp                 # 11 tests: varint, buffer managers
│       ├── channel_io_stream_tcp_test.cpp  # 8 tests: TCP connect/send/reset
│       ├── channel_io_stream_unix_test.cpp # 5 tests: Unix socket (non-Windows)
│       ├── channel_mem_test.cpp            # 5 tests: memory channel SISO/MISO
│       ├── channel_shm_test.cpp            # 6 tests: shared memory channel
│       ├── libatbus_error_test.cpp         # 6 tests: error string mapping
│       ├── atbus_connection_context_crosslang_generator.cpp  # Cross-lang enc/dec vectors
│       ├── atbus_access_data_crosslang_generator.cpp         # Cross-lang auth vectors
│       ├── atbus_connection_context_enc_dec/  # Binary test vectors (*.bytes + *.json)
│       └── atbus_access_data_crosslang/      # Auth signature test vectors
├── sample/                # Sample applications
├── docs/                  # Documentation
└── tools/                 # Utility tools
```

## Architecture Layers

```
┌──────────────────────────────────────────────────────────┐
│  Application (send_data / on_forward_request callback)   │
├──────────────────────────────────────────────────────────┤
│  Node          - routing, event loop, crypto config      │
├──────────────────────────────────────────────────────────┤
│  Topology      - peer registry, relation queries         │
├──────────────────────────────────────────────────────────┤
│  Endpoint      - remote node, ctrl+data connections      │
├──────────────────────────────────────────────────────────┤
│  Message Handler - dispatch table, register/ping/forward │
├──────────────────────────────────────────────────────────┤
│  Connection    - state machine, I/O read/write           │
├──────────────────────────────────────────────────────────┤
│  Connection Context - ECDH handshake, cipher, compress   │
├──────────────────────────────────────────────────────────┤
│  Channel       - transport (TCP, Unix, mem, shm)         │
├──────────────────────────────────────────────────────────┤
│  Protocol      - Protobuf v3 wire format                 │
└──────────────────────────────────────────────────────────┘
```

## Protocol Definition (Protobuf v3)

The wire protocol is defined in `include/libatbus_protocol.proto`:

- **message_head** — version, type, sequence, source_bus_id, crypto metadata, compression metadata, body_size
- **message_body** — oneof: custom_command_req/rsp, data_transform_req/rsp, node_register_req/rsp, node_ping_req, node_pong_rsp, handshake_confirm
- **register_data** — bus_id, pid, hostname, channels, supported schemas/compression, access_key, crypto_handshake
- **forward_data** — from, to, router path, content, flags (REQUIRE_RSP)
- **ping_data** — time_point, crypto_handshake (carries ECDH public key)
- **crypto_handshake_data** — sequence, key exchange type, KDF types, cipher algorithms, public_key, iv_size, tag_size
- **access_data** — algorithm (HMAC-SHA256), timestamp, nonce1/nonce2, signatures

### Protocol version

Current: `ATBUS_PROTOCOL_VERSION = 3`, minimum: `ATBUS_PROTOCOL_MINIMAL_VERSION = 3`.

## Channel Types & Priority

| Channel       | Scheme                                    | Scope               | Priority            | Transport                        |
| ------------- | ----------------------------------------- | ------------------- | ------------------- | -------------------------------- |
| Memory        | `mem://`                                  | Same process        | Highest (+0x20)     | Ring buffer in process memory    |
| Shared Memory | `shm://`                                  | Same host           | High (+0x18)        | OS shared memory (POSIX/Windows) |
| Unix Socket   | `unix://`                                 | Same host           | Medium-High (+0x16) | Unix domain socket via libuv     |
| Named Pipe    | `pipe://`                                 | Same host (Windows) | Medium-High (+0x16) | Windows named pipe via libuv     |
| TCP           | `ipv4://`, `ipv6://`, `atcp://`, `dns://` | Network             | Base (+0x03)        | TCP socket via libuv             |

Connection selection priority: same-process `mem://` > same-host `shm://` > same-host `unix://`/`pipe://` > network TCP.

## Connection Lifecycle

```
[Created] → kConnecting → kHandshaking → kConnected ⇄ (key refresh) → kDisconnecting → [Destroyed]
```

1. **Connect/Listen** — TCP: async via libuv; mem/shm: immediate
2. **Register** — Send `node_register_req` with bus_id, channels, access_key, crypto_handshake
3. **ECDH Handshake** — Via ping/pong messages (see Encryption section below)
4. **Data Transfer** — Encrypted + compressed messages via `data_transform_req`/`rsp`
5. **Key Refresh** — Periodic re-handshake (default interval: 3 hours)
6. **Disconnect** — Graceful close with endpoint cleanup

## Encryption & Compression

### ECDH Key Exchange Flow

For detailed protocol transport, encryption, and compression algorithm negotiation, see `.agents/skills/libatbus-protocol-crypto/SKILL.md`.

Summary:

1. **Client** generates ECDH keypair, sends public key + supported algorithms in `ping_data.crypto_handshake`
2. **Server** generates its keypair, computes shared secret, selects best mutual algorithm, responds in `pong`
3. **Both** derive symmetric key+IV via HKDF-SHA256 from the shared secret
4. **Client** sends `handshake_confirm` to signal cipher switch
5. **Server** switches `receive_cipher` upon confirm receipt

### Supported Algorithms

**Key Exchange**: X25519, SECP256R1 (P-256), SECP384R1 (P-384), SECP521R1 (P-521)

**Symmetric Ciphers**: XXTEA, AES-128/192/256-CBC (PKCS#7), AES-128/192/256-GCM (AEAD), ChaCha20, ChaCha20-Poly1305-IETF (AEAD), XChaCha20-Poly1305-IETF (AEAD)

**KDF**: HKDF-SHA256

**Compression**: Zstd, LZ4, Snappy, Zlib (with configurable levels: STORAGE, FAST, LOW_CPU, BALANCED, HIGH_RATIO, MAX_RATIO)

### Message Pack/Unpack

Wire frame: `[varint(header_len)][protobuf_header][body][padding]`

Pack order: serialize body → compress (if size ≥ threshold) → encrypt (random IV) → serialize header → prepend varint length.

Unpack order: read varint → parse header → decrypt (if `head.crypto.algorithm != NONE`) → decompress (if `head.compression.type != NONE`) → parse body.

Control messages (register, ping/pong, handshake_confirm) are **never** encrypted or compressed.

## Node Topology & Routing

The bus uses a **tree/forest topology**:

- Each node has at most one **upstream** (parent) node
- Each node can have multiple **downstream** (child) nodes
- Nodes sharing the same parent are **peers**

Routing logic (`get_peer_channel`):

1. Look up target in local endpoint map → direct connection
2. If not found, forward to upstream parent (which recursively routes)
3. TTL prevents infinite forwarding loops

Topology relation types: `kSelf`, `kImmediateUpstream`, `kTransitiveUpstream`, `kImmediateDownstream`, `kTransitiveDownstream`, `kSameUpstreamPeer`, `kOtherUpstreamPeer`.

## Event Callbacks

```cpp
node::event_handle_set_t:
  on_forward_request_fn_t  — receive data message (main application callback)
  on_forward_response_fn_t — send success/failure notification (if REQUIRE_RSP)
  on_register_fn_t         — new endpoint registered
  on_node_down_fn_t        — node going offline
  on_node_up_fn_t          — node started
  on_invalid_connection_fn_t — connection became invalid
  on_custom_cmd_fn_t       — custom command received
  on_custom_rsp_fn_t       — custom command response
  on_add_endpoint_fn_t     — endpoint added
  on_remove_endpoint_fn_t  — endpoint removed
```

## Access Token Authentication

Registration and custom commands are protected by HMAC-SHA256 signatures:

- Plaintext format: `"{timestamp}:{nonce1}-{nonce2}:{bus_id}"` (without crypto) or `"{timestamp}:{nonce1}-{nonce2}:{bus_id}:{key_exchange_type}:{hex(sha256(pubkey))}"` (with crypto)
- Multiple access tokens supported for zero-downtime key rotation
- Timestamp tolerance: ±300 seconds

## Error Codes

Key error codes (defined in `detail/libatbus_error.h`):

| Code | Name                                                   | Description                      |
| ---- | ------------------------------------------------------ | -------------------------------- |
| 0    | `EN_ATBUS_ERR_SUCCESS`                                 | Success                          |
| -6   | `EN_ATBUS_ERR_SCHEME`                                  | Unknown protocol scheme          |
| -7   | `EN_ATBUS_ERR_BAD_DATA`                                | Validation/checksum failed       |
| -12  | `EN_ATBUS_ERR_UNPACK`                                  | Deserialization failed           |
| -13  | `EN_ATBUS_ERR_PACK`                                    | Serialization failed             |
| -65  | `EN_ATBUS_ERR_ATNODE_NOT_FOUND`                        | Target node not found            |
| -67  | `EN_ATBUS_ERR_ATNODE_NO_CONNECTION`                    | No available connection          |
| -71  | `EN_ATBUS_ERR_ATNODE_TTL`                              | TTL exceeded                     |
| -73  | `EN_ATBUS_ERR_ATNODE_ID_CONFLICT`                      | Node ID conflict                 |
| -105 | `EN_ATBUS_ERR_CHANNEL_NOT_SUPPORT`                     | Unknown channel type             |
| -211 | `EN_ATBUS_ERR_NODE_TIMEOUT`                            | Timeout                          |
| -231 | `EN_ATBUS_ERR_CRYPTO_DECRYPT`                          | Decryption failed                |
| -232 | `EN_ATBUS_ERR_CRYPTO_ENCRYPT`                          | Encryption failed                |
| -234 | `EN_ATBUS_ERR_CRYPTO_ALGORITHM_NOT_MATCH`              | Algorithm mismatch               |
| -236 | `EN_ATBUS_ERR_CRYPTO_HANDSHAKE_MAKE_KEY_PAIR`          | Key pair generation failed       |
| -237 | `EN_ATBUS_ERR_CRYPTO_HANDSHAKE_READ_PEER_KEY`          | Peer key read error              |
| -238 | `EN_ATBUS_ERR_CRYPTO_HANDSHAKE_MAKE_SECRET`            | Shared secret computation failed |
| -239 | `EN_ATBUS_ERR_CRYPTO_HANDSHAKE_SEQUENCE_EXPIRED`       | Handshake sequence expired       |
| -240 | `EN_ATBUS_ERR_CRYPTO_HANDSHAKE_NO_AVAILABLE_ALGORITHM` | No mutual algorithm              |
| -251 | `EN_ATBUS_ERR_COMPRESSION_ALGORITHM_NOT_SUPPORT`       | Compression not supported        |

## Unit Testing Framework

This project uses the **same private unit testing framework** as atframe_utils (not Google Test).

### Test Framework Macros

```cpp
CASE_TEST(test_group_name, test_case_name) {
    // Test implementation
}

// Assertions
CASE_EXPECT_TRUE(condition)
CASE_EXPECT_FALSE(condition)
CASE_EXPECT_EQ(expected, actual)
CASE_EXPECT_NE(val1, val2)
CASE_EXPECT_LT(val1, val2)
CASE_EXPECT_LE(val1, val2)
CASE_EXPECT_GT(val1, val2)
CASE_EXPECT_GE(val1, val2)
CASE_EXPECT_ERROR(message)

// Logging during tests
CASE_MSG_INFO() << "Info message";
CASE_MSG_ERROR() << "Error message";

// Test utilities
CASE_THREAD_SLEEP_MS(milliseconds)
CASE_THREAD_YIELD()
```

### Test Utility Macros (atbus_test_utils.h)

```cpp
// Wait macros for libuv event loop synchronization
UNITTEST_WAIT_UNTIL(loop, condition, timeout_ms, tick_ms)  // Wait until condition is true
UNITTEST_WAIT_IF(loop, condition, timeout_ms, tick_ms)     // Wait while condition is true
UNITTEST_WAIT_MS(loop, timeout_ms, tick_ms)                // Wait for a fixed duration

// Time point helper
unit_test_make_timepoint(sec, usec)  // Create std::chrono::system_clock::time_point
```

### Test Groups

| Group                                | File                                | Tests | Description                                           |
| ------------------------------------ | ----------------------------------- | ----- | ----------------------------------------------------- |
| `atbus_node_msg`                     | `atbus_node_msg_test.cpp`           | 24    | Messaging, crypto config, multi-hop routing           |
| `atbus_node_reg`                     | `atbus_node_reg_test.cpp`           | 22    | Registration, timeout, access tokens, channels        |
| `atbus_node_relationship`            | `atbus_node_relationship_test.cpp`  | 3     | FlatBuffers message, conf copy, endpoint ops          |
| `atbus_node_setup`                   | `atbus_node_setup_test.cpp`         | 3     | Listen override, algorithm enumeration                |
| `atbus_endpoint`                     | `atbus_endpoint_test.cpp`           | 5     | Connection retrieval, address parsing                 |
| `atbus_connection_context`           | `atbus_connection_context_test.cpp` | 37    | Padding, handshake, pack/unpack, all algorithm combos |
| `atbus_message_handler`              | `atbus_message_handler_test.cpp`    | 16    | access_data plaintext format, HMAC signatures         |
| `atbus_topology`                     | `atbus_topology_test.cpp`           | 9     | Peer CRUD, relation types, cycle detection            |
| `channel`                            | `channel_*_test.cpp`                | 24    | TCP, Unix, mem, shm channel tests                     |
| `buffer`                             | `buffer_test.cpp`                   | 11    | Varint encoding, buffer manager modes                 |
| `atbus_connection_context_crosslang` | crosslang generator                 | 10    | Binary enc/dec test vectors                           |
| `atbus_access_data_crosslang`        | crosslang generator                 | 9     | Auth signature test vectors                           |

### Running and writing tests

See `.agents/skills/testing/SKILL.md`.

## Coding Conventions

1. **Namespaces**: `atframework::atbus` for the library, `atframework::atbus::protocol` for protobuf types
2. **Include guards**: Use `#pragma once`
3. **C++ Standard**: C++17 required
4. **Naming**: `snake_case` for classes/functions/variables, `UPPER_SNAKE_CASE` for constants, `*_t` suffix for typedefs
5. **Error handling**: Return `ATBUS_ERROR_TYPE` error codes
6. **Anonymous namespace + static**: In `.cpp` files, file-local functions should be placed inside an anonymous namespace **and** keep the `static` keyword
7. **Smart pointers**: Use `atfw::util::memory::strong_rc_ptr` (not `std::shared_ptr`) for internal types
8. **Arena allocation**: Protobuf messages use `google::protobuf::Arena` for efficient allocation

## Key Components

### Node (`atbus_node.h`)

The central component representing a bus node. Manages connections, endpoints, and message routing.

```cpp
namespace atframework::atbus {
    class node {
    public:
        using ptr_t = atfw::util::memory::strong_rc_ptr<node>;
        static ptr_t create();
        int init(const conf_t& conf);
        int send_data(bus_id_t target, int type, const void* data, size_t size);
        // ...
    };
}
```

### Endpoint (`atbus_endpoint.h`)

Represents a remote node. Created automatically when connecting to other nodes.

### Connection (`atbus_connection.h`)

Manages individual connections to endpoints. Supports multiple transport types.

### Connection Context (`atbus_connection_context.h`)

Handles encryption and key exchange for secure connections.

- Key exchange algorithms: X25519, SECP256R1, SECP384R1, SECP521R1
- Cipher algorithms: AES-CBC, AES-GCM, ChaCha20-Poly1305, XXTEA
- HMAC authentication: HMAC-SHA256

### Topology (`atbus_topology.h`)

Manages upstream and downstream node relationships in the bus topology.

- Upstream node management and automatic reconnection
- Downstream node tracking
- Topology change event callbacks
- Handles node registration and deregistration

### Channels (in `detail/`)

- `channel_mem.cpp` - In-process memory channel
- `channel_shm.cpp` - Shared memory channel (same machine)
- `channel_io_stream.cpp` - TCP/Unix socket channel

## Protocol

The message protocol is defined in:

- `libatbus_protocol.proto` (Protobuf format)
- `libatbus_protocol.fbs` (FlatBuffers format)

## Error Codes

Error codes are defined in `detail/libatbus_error.h`:

- `EN_ATBUS_ERR_SUCCESS` (0) - Success
- `EN_ATBUS_ERR_*` - Various error codes

## Code Formatting

This project uses **clang-format** for code formatting. The `.clang-format` file is located at the project root.

- Style: Based on Google style
- Column limit: 120
- Run formatting: `clang-format -i <file>`

## Coding Conventions

1. **Namespace**: `atframework::atbus`
2. **Include guards**: Use `#pragma once`
3. **C++ Standard**: C++17 required
4. **Naming**:
   - Classes/structs: `snake_case`
   - Functions: `snake_case`
   - Constants: `UPPER_SNAKE_CASE` or `EN_` prefix for enums
   - Types: `*_t` suffix for typedefs
5. **Smart pointers**: Use `atfw::util::memory::strong_rc_ptr` for node ownership
6. **Anonymous namespace + static**: In `.cpp` files, file-local functions should be placed inside an anonymous namespace **and** keep the `static` keyword. Do **not** remove `static` when moving a function into an anonymous namespace.
   ```cpp
   namespace {
   static void my_helper() { /* ... */ }
   }  // namespace
   ```

## Compiler Support

| Compiler | Minimum Version |
| -------- | --------------- |
| GCC      | 7.1+            |
| Clang    | 7+              |
| MSVC     | VS2022+         |

## Dependencies

- **atframe_utils** - Core utility library
- **protobuf** - Protocol serialization
- **libuv** - Async I/O
- **OpenSSL** or **MbedTLS** - Cryptography (optional, for encryption)

## Windows Notes

- Private shared memory does not allow cross-process sharing on Windows
- Public shared memory requires administrator privileges
- If shared memory initialization fails, run with administrator rights

## Key Design Concepts

1. **64-bit Bus IDs**: Unlike 32-bit systems (tbus, skynet), libatbus uses 64-bit IDs for flexible service type allocation.

2. **Automatic Channel Selection**: Automatically chooses optimal transport (shared memory for local, TCP for remote).

3. **Dynamic Routing**: Parent-child connections are maintained automatically. Sibling connections are established on-demand.

4. **Tree Structure**: Node relationships follow subnet-like rules (e.g., 0x12345678/16 controls 0x12340000-0x1234FFFF).

5. **Lock-free Design**: Uses lock-free queues for high CPU performance.
