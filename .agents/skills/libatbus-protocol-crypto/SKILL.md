---
name: libatbus-protocol-crypto
description: libatbus protocol transport, ECDH key exchange, encryption/compression algorithm negotiation, message pack/unpack, and access token authentication. Use when working with connection_context, handshake flow, cipher algorithms, compression, message framing, or writing crypto-related tests.
---

# libatbus Protocol Transport & Crypto

This skill covers the libatbus wire protocol, ECDH key exchange handshake, encryption/compression algorithm negotiation, message framing, and access token authentication.

## Key Files

- `include/libatbus_protocol.proto` — Protobuf v3 protocol definition (source of truth for all message types)
- `include/atbus_connection_context.h` — ECDH handshake, cipher/compression negotiation, pack/unpack API
- `src/atbus_connection_context.cpp` — Implementation of handshake, algorithm selection, message encryption/compression
- `include/atbus_message_handler.h` — Message dispatch table, access_data signature generation
- `src/atbus_message_handler.cpp` — Handlers for register, ping/pong, forward, handshake_confirm
- `include/atbus_node.h` — Node configuration (`conf_t`) with crypto/compression settings
- `test/case/atbus_connection_context_test.cpp` — 37 tests for handshake, pack/unpack, algorithm combos
- `test/case/atbus_message_handler_test.cpp` — 16 tests for access_data and HMAC signatures

## Protobuf Protocol Enums

### Key Exchange Algorithms

```protobuf
enum ATBUS_CRYPTO_KEY_EXCHANGE_TYPE {
  ATBUS_CRYPTO_KEY_EXCHANGE_NONE = 0;      // No encryption
  ATBUS_CRYPTO_KEY_EXCHANGE_X25519 = 1;    // Recommended (TLS 1.3)
  ATBUS_CRYPTO_KEY_EXCHANGE_SECP256R1 = 2; // P-256
  ATBUS_CRYPTO_KEY_EXCHANGE_SECP384R1 = 3; // P-384
  ATBUS_CRYPTO_KEY_EXCHANGE_SECP521R1 = 4; // P-521
}
```

### Symmetric Cipher Algorithms

```protobuf
enum ATBUS_CRYPTO_ALGORITHM_TYPE {
  ATBUS_CRYPTO_ALGORITHM_NONE = 0;
  ATBUS_CRYPTO_ALGORITHM_XXTEA = 1;                    // Legacy
  ATBUS_CRYPTO_ALGORITHM_AES_128_CBC = 11;              // PKCS#7 padding
  ATBUS_CRYPTO_ALGORITHM_AES_192_CBC = 12;              // PKCS#7 padding
  ATBUS_CRYPTO_ALGORITHM_AES_256_CBC = 13;              // PKCS#7 padding
  ATBUS_CRYPTO_ALGORITHM_AES_128_GCM = 14;              // AEAD - recommended
  ATBUS_CRYPTO_ALGORITHM_AES_192_GCM = 15;              // AEAD
  ATBUS_CRYPTO_ALGORITHM_AES_256_GCM = 16;              // AEAD - recommended
  ATBUS_CRYPTO_ALGORITHM_CHACHA20 = 31;                 // Stream cipher
  ATBUS_CRYPTO_ALGORITHM_CHACHA20_POLY1305_IETF = 32;   // AEAD - modern
  ATBUS_CRYPTO_ALGORITHM_XCHACHA20_POLY1305_IETF = 33;  // AEAD - extended nonce
}
```

### KDF

```protobuf
enum ATBUS_CRYPTO_KDF_TYPE {
  ATBUS_CRYPTO_KDF_HKDF_SHA256 = 0;  // Only supported KDF
}
```

### Compression Algorithms

```protobuf
enum ATBUS_COMPRESSION_ALGORITHM_TYPE {
  ATBUS_COMPRESSION_ALGORITHM_NONE = 0;
  ATBUS_COMPRESSION_ALGORITHM_ZSTD = 100;    // Best general compression
  ATBUS_COMPRESSION_ALGORITHM_LZ4 = 200;     // Ultra-fast
  ATBUS_COMPRESSION_ALGORITHM_SNAPPY = 300;  // Fast, reasonable ratio
  ATBUS_COMPRESSION_ALGORITHM_ZLIB = 400;    // Universal compatibility
}

enum ATBUS_COMPRESSION_LEVEL {
  ATBUS_COMPRESSION_LEVEL_DEFAULT = 0;
  ATBUS_COMPRESSION_LEVEL_STORAGE = 100;     // Minimal CPU
  ATBUS_COMPRESSION_LEVEL_FAST = 200;        // Lowest latency
  ATBUS_COMPRESSION_LEVEL_LOW_CPU = 300;     // Light tradeoff
  ATBUS_COMPRESSION_LEVEL_BALANCED = 400;    // System recommended
  ATBUS_COMPRESSION_LEVEL_HIGH_RATIO = 500;  // Storage priority
  ATBUS_COMPRESSION_LEVEL_MAX_RATIO = 600;   // Offline/cold data only
}
```

## ECDH Key Exchange Handshake Flow

The handshake is carried within the ping/pong mechanism after node registration.

### Sequence Diagram

```
Client (connecting node)                    Server (listening node)
│                                           │
│  ── node_register_req ──────────────────> │  (bus_id, channels, access_key,
│                                           │   crypto_handshake with public key)
│  <────────────── node_register_rsp ────── │
│                                           │
│  Step 1: Generate ECDH keypair            │
│  ── node_ping_req ──────────────────────> │  (crypto_handshake {
│     crypto_handshake.sequence = N         │    sequence, type, kdf_type[],
│     crypto_handshake.public_key = PK_c    │    algorithms[], public_key,
│     crypto_handshake.algorithms = [...]   │    iv_size, tag_size })
│                                           │
│                                           │  Step 2: Generate own ECDH keypair
│                                           │  Compute shared_secret = ECDH(SK_s, PK_c)
│                                           │  Select best mutual algorithm
│                                           │  Derive key+IV via HKDF-SHA256
│                                           │  Create send_cipher (encrypt mode)
│                                           │  Create handshake_receive_cipher (decrypt)
│                                           │  Set handshake_pending_confirm = true
│                                           │
│  <───────────────── node_pong_rsp ─────── │  (crypto_handshake {
│     crypto_handshake.sequence = N         │    sequence=N, public_key=PK_s,
│     crypto_handshake.public_key = PK_s    │    algorithms=[selected] })
│     crypto_handshake.algorithms=[selected]│
│                                           │
│  Step 3: Compute shared_secret =          │
│    ECDH(SK_c, PK_s)                       │
│  Derive same key+IV via HKDF-SHA256       │
│  Create send_cipher + receive_cipher      │
│  (Client switches ciphers immediately)    │
│                                           │
│  ── handshake_confirm ──────────────────> │  (sequence = N)
│                                           │
│                                           │  Step 4: confirm_handshake(N)
│                                           │  receive_cipher = handshake_receive_cipher
│                                           │  handshake_pending_confirm = false
│                                           │
│  ═══════ Encrypted communication ════════ │
```

### Why Two Receive Ciphers on Server?

During the handshake transition, the server holds both the old `receive_cipher` and a new `handshake_receive_cipher`. This is because:

1. The server sends its pong with the new encryption, but doesn't know if the client has received it yet.
2. The client might still send messages encrypted with the old key.
3. Only after receiving `handshake_confirm` does the server know the client has switched.
4. At that point, `receive_cipher` is replaced with `handshake_receive_cipher`.

### Key Refresh (Re-keying)

Periodic key refresh uses the same handshake flow on an already-connected session:

- Default interval: `crypto_key_refresh_interval` (3 hours)
- The ping/pong mechanism carries new `crypto_handshake_data`
- Session continuity is preserved; only the cipher keys change

## Algorithm Negotiation

### Selection Rules

1. Client sends its list of supported algorithms in `crypto_handshake_data.algorithms`
2. Server intersects with its own `conf_t.crypto_allow_algorithms`
3. The **first mutually supported** algorithm (in the server's priority order) is selected
4. If no intersection exists, returns `EN_ATBUS_ERR_CRYPTO_HANDSHAKE_NO_AVAILABLE_ALGORITHM`

### Compression Negotiation

- Compression algorithm is selected during node registration via `register_data.supported_compression_algorithm`
- The `connection_context::update_compression_algorithm()` method receives the peer's supported list and selects the first mutually supported algorithm
- Compression availability depends on build-time library detection (`ATFW_UTIL_MACRO_COMPRESSION_ENABLED`)

### Compression Decision Logic

Not all messages are compressed. The decision is per-message:

```cpp
// Control messages: NEVER compressed or encrypted
// ping/pong, register req/rsp, handshake_confirm → plaintext always

// Data/command messages: compressed if body_size >= 1024 bytes
// kDataTransformReq, kDataTransformRsp, kCustomCommandReq, kCustomCommandRsp

// Other messages: compressed if body_size >= 2048 bytes

// Below 512 bytes: NEVER compressed (header overhead exceeds savings)
```

### Encryption Decision Logic

```cpp
// Control messages: NEVER encrypted
// kNodeRegisterReq, kNodeRegisterRsp, kNodePingReq, kNodePongRsp, kHandshakeConfirm

// All other messages: encrypted if send_cipher is available
```

## Message Wire Format

### Frame Layout

```
┌──────────────────┬──────────────────┬──────────────┬─────────┐
│ varint(head_len) │ protobuf header  │ body payload │ padding │
│   1-10 bytes     │ head_len bytes   │ variable     │ 0+ bytes│
└──────────────────┴──────────────────┴──────────────┴─────────┘
```

### Pack Order (send)

1. **Serialize** `message_body` to bytes
2. **Compress** (if applicable): compress body bytes, set `head.compression.type` and `head.compression.original_size`
3. **Encrypt** (if applicable): generate random IV, encrypt body, set `head.crypto.algorithm` and `head.crypto.iv`; for AEAD ciphers also set `head.crypto.aad`
4. **Pad** buffer to aligned size class (word-aligned for small, 4KB page-aligned for large)
5. **Serialize** `message_head` (with crypto/compression metadata)
6. **Prepend** varint-encoded header length

### Unpack Order (receive)

1. **Read** varint → header length
2. **Parse** `message_head` protobuf
3. **Decrypt** if `head.crypto.algorithm != NONE`: restore IV from header, decrypt payload
4. **Decompress** if `head.compression.type != NONE`: decompress to `head.body_size` bytes
5. **Parse** `message_body` protobuf

### Buffer Padding Strategy

The `internal_padding_temporary_buffer_block()` function aligns buffer sizes to reduce allocation fragmentation:

| Input Size | Alignment                | Strategy               |
| ---------- | ------------------------ | ---------------------- |
| 0          | → word size (8 bytes)    | Minimum allocation     |
| 1–64       | 8-byte aligned           | Word alignment         |
| 65–512     | 16-byte aligned          | Cache line friendly    |
| 513–8192   | mimalloc size classes    | Follows allocator bins |
| >8192      | 4096-byte (page) aligned | OS page alignment      |

## Access Token Authentication

### Signature Generation

Registration and custom commands are authenticated with HMAC-SHA256:

```
plaintext = "{timestamp}:{nonce1}-{nonce2}:{bus_id}"                                    // without crypto
plaintext = "{timestamp}:{nonce1}-{nonce2}:{bus_id}:{key_exchange_type}:{hex(sha256(pubkey))}"  // with crypto
plaintext = "{timestamp}:{nonce1}-{nonce2}:{from}:{hex(sha256(commands.arg[0]))}{hex(sha256(commands.arg[1]))}" // custom cmd

signature = HMAC-SHA256(access_token, plaintext)
```

- Timestamp tolerance: ±300 seconds
- Multiple tokens: each token produces a separate signature entry in `access_data.signature[]`
- Server verifies against ALL configured tokens (O(N²) worst case)

## Connection Context API

### Creating a Context

```cpp
auto ctx = connection_context::create(
    protocol::ATBUS_CRYPTO_KEY_EXCHANGE_X25519,  // Key exchange algorithm
    dh_shared_context                             // Pre-created DH context from node
);
```

### Handshake API

```cpp
// Step 1 (Client): Generate keypair
ctx->handshake_generate_self_key(0);  // 0 = client generates own sequence

// Step 1b: Write public key to send
protocol::crypto_handshake_data handshake_msg;
ctx->handshake_write_self_public_key(handshake_msg, supported_algorithms);

// Step 2 (Server): Receive peer key and compute shared secret
ctx->handshake_generate_self_key(peer_sequence);  // Use peer's sequence
ctx->handshake_read_peer_key(peer_handshake_data, supported_algorithms, true);  // need_confirm=true for server

// Step 3 (Client): Receive server's key
ctx->handshake_read_peer_key(server_handshake_data, supported_algorithms, false);  // need_confirm=false for client

// Step 4 (Server): Confirm cipher switch
ctx->confirm_handshake(handshake_sequence);
```

### Pack/Unpack API

```cpp
// Pack (serialize + compress + encrypt)
auto result = ctx->pack_message(msg, protocol_version, random_engine, max_body_size);
if (result.is_success()) {
    auto &buffer = result.get_success();
    // buffer.data(), buffer.size() → send over wire
}

// Unpack (decrypt + decompress + deserialize)
ATBUS_ERROR_TYPE err = ctx->unpack_message(msg, input_span, max_body_size);
```

### Compression Configuration

```cpp
// Update compression algorithm from peer's supported list
std::vector<protocol::ATBUS_COMPRESSION_ALGORITHM_TYPE> peer_algorithms = { ZSTD, LZ4 };
ctx->update_compression_algorithm(peer_algorithms);

// Check if a specific algorithm is available at build time
bool has_zstd = connection_context::is_compression_algorithm_supported(
    protocol::ATBUS_COMPRESSION_ALGORITHM_ZSTD);
```

## Node Configuration for Crypto

```cpp
atbus::node::conf_t conf;
atbus::node::default_conf(&conf);

// Key exchange
conf.crypto_key_exchange_type = protocol::ATBUS_CRYPTO_KEY_EXCHANGE_X25519;
conf.crypto_key_refresh_interval = std::chrono::hours{3};

// Allowed ciphers (in priority order)
conf.crypto_allow_algorithms = {
    protocol::ATBUS_CRYPTO_ALGORITHM_AES_256_GCM,
    protocol::ATBUS_CRYPTO_ALGORITHM_CHACHA20_POLY1305_IETF,
    protocol::ATBUS_CRYPTO_ALGORITHM_AES_128_GCM,
};

// Compression
conf.compression_allow_algorithms = {
    protocol::ATBUS_COMPRESSION_ALGORITHM_ZSTD,
    protocol::ATBUS_COMPRESSION_ALGORITHM_LZ4,
};
conf.compression_level = protocol::ATBUS_COMPRESSION_LEVEL_BALANCED;

// Access tokens
conf.access_tokens.push_back({'s','e','c','r','e','t'});
```

### Runtime Crypto Reload

```cpp
// Change crypto config without restarting
node->reload_crypto(
    protocol::ATBUS_CRYPTO_KEY_EXCHANGE_X25519,
    std::chrono::hours{1},
    {protocol::ATBUS_CRYPTO_ALGORITHM_AES_256_GCM}
);

// Change compression config
node->reload_compression(
    {protocol::ATBUS_COMPRESSION_ALGORITHM_ZSTD},
    protocol::ATBUS_COMPRESSION_LEVEL_FAST
);
```

## Writing Crypto Tests

### Test Pattern: Handshake Round-Trip

```cpp
CASE_TEST(atbus_connection_context, handshake_with_x25519) {
    // 1. Init global crypto
    atfw::util::crypto::cipher::init_global_algorithm();

    // 2. Create shared DH context
    auto dh_ctx = atfw::util::crypto::dh::shared_context::create("x25519");

    // 3. Create client and server contexts
    auto client_ctx = atbus::connection_context::create(
        protocol::ATBUS_CRYPTO_KEY_EXCHANGE_X25519, dh_ctx);
    auto server_ctx = atbus::connection_context::create(
        protocol::ATBUS_CRYPTO_KEY_EXCHANGE_X25519, dh_ctx);

    // 4. Client generates keypair
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, client_ctx->handshake_generate_self_key(0));
    protocol::crypto_handshake_data client_pub;
    std::vector<protocol::ATBUS_CRYPTO_ALGORITHM_TYPE> algorithms = {
        protocol::ATBUS_CRYPTO_ALGORITHM_AES_256_GCM};
    client_ctx->handshake_write_self_public_key(client_pub, algorithms);

    // 5. Server generates keypair using client's sequence
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS,
        server_ctx->handshake_generate_self_key(client_pub.sequence()));
    // Server reads client's public key (need_confirm=true)
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS,
        server_ctx->handshake_read_peer_key(client_pub, algorithms, true));
    protocol::crypto_handshake_data server_pub;
    server_ctx->handshake_write_self_public_key(server_pub, algorithms);

    // 6. Client reads server's public key (need_confirm=false)
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS,
        client_ctx->handshake_read_peer_key(server_pub, algorithms, false));

    // 7. Server confirms
    server_ctx->confirm_handshake(client_pub.sequence());

    // 8. Verify both selected the same algorithm
    CASE_EXPECT_EQ(client_ctx->get_crypto_select_algorithm(),
                   server_ctx->get_crypto_select_algorithm());

    // 9. Test encrypted round-trip
    atbus::message send_msg;
    // ... populate send_msg ...
    auto packed = client_ctx->pack_message(send_msg, 3, rng, 65536);
    CASE_EXPECT_TRUE(packed.is_success());

    atbus::message recv_msg;
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS,
        server_ctx->unpack_message(recv_msg, packed.get_success().as_span(), 65536));

    atfw::util::crypto::cipher::cleanup_global_algorithm();
}
```

### Test Pattern: Multi-Node with Encryption

```cpp
CASE_TEST(atbus_node_msg, crypto_config_cipher_algorithms) {
    // Setup libuv
    uv_loop_t ev_loop;
    uv_loop_init(&ev_loop);

    // Configure two nodes with encryption
    atbus::node::conf_t conf;
    atbus::node::default_conf(&conf);
    conf.ev_loop = &ev_loop;
    conf.crypto_key_exchange_type = protocol::ATBUS_CRYPTO_KEY_EXCHANGE_X25519;
    conf.crypto_allow_algorithms = {protocol::ATBUS_CRYPTO_ALGORITHM_AES_256_GCM};

    auto node1 = atbus::node::create();
    auto node2 = atbus::node::create();
    node1->init(0x12345678, &conf);
    node2->init(0x12356789, &conf);

    node1->listen("ipv4://127.0.0.1:16387");
    node2->listen("ipv4://127.0.0.1:16388");

    atbus::node::start_conf_t start_conf;
    start_conf.timer_timepoint = unit_test_make_timepoint(0, 0);
    node1->start(start_conf);
    node2->start(start_conf);

    // Connect and wait for handshake
    node2->connect("ipv4://127.0.0.1:16387");
    UNITTEST_WAIT_UNTIL(ev_loop,
        node1->is_endpoint_available(0x12356789), 8000, 8) {
        ++proc_usec;
        node1->proc(unit_test_make_timepoint(0, proc_usec));
        node2->proc(unit_test_make_timepoint(0, proc_usec));
    }

    // Send encrypted data
    unsigned char data[] = "hello encrypted";
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS,
        node1->send_data(0x12356789, 1, {data, sizeof(data)}));

    // ... verify receipt in callback ...
    uv_loop_close(&ev_loop);
}
```

### Cross-Language Test Vectors

Binary test vectors are generated by:

- `test/case/atbus_connection_context_crosslang_generator.cpp` → `test/case/atbus_connection_context_enc_dec/`
- `test/case/atbus_access_data_crosslang_generator.cpp` → `test/case/atbus_access_data_crosslang/`

Each algorithm combination produces:

- `{algorithm}_{message_type}.bytes` — binary wire-format message
- `{algorithm}_{message_type}.json` — metadata (algorithm, key, IV, plaintext hash, etc.)
- `index.json` — catalog of all test vectors

Other language implementations (Go, etc.) read these files to verify byte-for-byte compatibility.

## Common Pitfalls

1. **Control messages are never encrypted**: `register`, `ping/pong`, and `handshake_confirm` are always plaintext. Don't try to add encryption to them.

2. **Sequence ID prevents replay**: The handshake sequence ID must match between client's ping and server's pong. Mismatched sequences return `EN_ATBUS_ERR_CRYPTO_HANDSHAKE_SEQUENCE_EXPIRED`.

3. **Server needs confirm before switching receive cipher**: The server uses `handshake_receive_cipher` temporarily. Only after receiving `handshake_confirm` does it call `confirm_handshake()` to switch.

4. **Compression threshold is per-message**: Small messages (<512 bytes) are never compressed. Data messages need ≥1024 bytes, control-style messages need ≥2048 bytes.

5. **AEAD vs non-AEAD**: GCM and Poly1305 ciphers are AEAD (authenticated encryption with associated data). CBC and XXTEA are non-AEAD. The pack/unpack code handles both, but AEAD validation failures cause `EN_ATBUS_ERR_CRYPTO_DECRYPT`.

6. **Algorithm availability is build-time**: Compression algorithms depend on whether the library was built with zstd/lz4/snappy/zlib support. Use `connection_context::is_compression_algorithm_supported()` to check.
