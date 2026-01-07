# libatbus - Copilot Instructions

## Project Overview

**libatbus** is a high-performance, fully asynchronous, tree-structured message bus framework for cross-platform communication. It supports shared memory channels for intra-machine communication and TCP for inter-machine communication.

- **Repository**: https://github.com/atframework/libatbus
- **License**: MIT (libatbus), Apache 2.0 (Flatbuffers), Node's license (libuv)
- **Languages**: C++ (C++17 required, C++17/C++20/C++23 features used when available)

## Build System

This project uses **CMake** (minimum version 3.24.0).

### Build Commands

```bash
# Clone and configure
git clone --single-branch --depth=1 -b main https://github.com/atframework/libatbus.git
mkdir libatbus/build && cd libatbus/build

# Configure (Debug mode)
cmake ..

# Configure (Release mode - recommended for benchmarks)
cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo

# Build
cmake --build .                          # Linux/macOS
cmake --build . --config RelWithDebInfo  # Windows (MSVC)

# Run tests
ctest . -V
```

### Key CMake Options

| Option                   | Default  | Description                               |
| ------------------------ | -------- | ----------------------------------------- |
| `BUILD_SHARED_LIBS`      | NO       | Build dynamic library                     |
| `ATBUS_MACRO_BUSID_TYPE` | uint64_t | Bus ID type                               |
| `CMAKE_BUILD_TYPE`       | Debug    | Build type (Debug/Release/RelWithDebInfo) |

**Note**: Use `RelWithDebInfo` or `Release` for production and benchmarks. Debug mode has significant performance overhead.

## Directory Structure

```
libatbus/
├── include/               # Public headers
│   ├── libatbus.h         # Main include header
│   ├── atbus_node.h       # Node management
│   ├── atbus_endpoint.h   # Endpoint (remote node representation)
│   ├── atbus_connection.h # Connection management
│   ├── atbus_connection_context.h  # Encryption/key exchange context
│   ├── atbus_message_handler.h     # Message handling
│   ├── libatbus_protocol.h         # Protocol definitions
│   ├── libatbus_protocol.proto     # Protobuf protocol definition
│   └── detail/            # Internal headers
│       ├── buffer.h       # Buffer management
│       ├── libatbus_adapter_libuv.h  # libuv adapter
│       ├── libatbus_channel_*.h      # Channel types
│       ├── libatbus_config.h.in      # Config template
│       ├── libatbus_error.h          # Error codes
│       └── libatbus_protocol.fbs     # FlatBuffers schema
├── src/                   # Implementation
│   ├── atbus_node.cpp
│   ├── atbus_endpoint.cpp
│   ├── atbus_connection.cpp
│   ├── atbus_connection_context.cpp
│   ├── atbus_message_handler.cpp
│   ├── channel_*.cpp      # Channel implementations
│   └── detail/
├── test/                  # Unit tests
│   └── case/              # Test case files
├── sample/                # Sample applications
├── docs/                  # Documentation
│   ├── Build.md           # Build instructions
│   ├── Usage.md           # Usage examples
│   └── Benchmark.md       # Performance benchmarks
└── tools/                 # Utility tools
```

## Unit Testing Framework

This project uses the **same private unit testing framework** as atframe_utils (not Google Test).

### Test Framework Macros

```cpp
// Define a test case
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

### Running Tests

The test executable is `atbus_unit_test`.

```bash
# Run all tests
./atbus_unit_test

# List all test cases
./atbus_unit_test -l
./atbus_unit_test --list-tests

# Run specific test group(s) or case(s)
./atbus_unit_test -r <test_group_name>
./atbus_unit_test -r <test_group_name>.<test_case_name>

# Examples:
./atbus_unit_test -r atbus_node_reg
./atbus_unit_test -r atbus_node_msg
./atbus_unit_test -r atbus_connection_context_crosslang
./atbus_unit_test -r channel

# Run with filter pattern (supports wildcards)
./atbus_unit_test -f "atbus_node*"
./atbus_unit_test --filter "channel*"

# Show help
./atbus_unit_test -h

# Show version
./atbus_unit_test -v
```

### Test Groups

Common test groups include:

- `atbus_node_reg` - Node registration tests
- `atbus_node_msg` - Node messaging tests
- `atbus_node_relationship` - Node relationship tests
- `atbus_node_setup` - Node setup tests
- `atbus_endpoint` - Endpoint tests
- `atbus_message_handler` - Message handler tests
- `atbus_connection_context` - Connection context tests
- `atbus_connection_context_crosslang` - Cross-language compatibility tests
- `atbus_access_data_crosslang` - Access data cross-language tests
- `channel` - Channel tests (TCP, Unix, shared memory)
- `buffer` - Buffer tests

### Writing Test Cases

Test files are located in `test/case/`. Example:

```cpp
#include "frame/test_macros.h"
#include "atbus_node.h"

CASE_TEST(atbus_node_setup, create_node) {
    atframework::atbus::v3000::node::conf_t conf;
    conf.id = 0x12345678;

    auto node = atframework::atbus::v3000::node::create();
    CASE_EXPECT_NE(nullptr, node.get());

    int ret = node->init(conf);
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, ret);

    CASE_MSG_INFO() << "Node created with ID: " << std::hex << conf.id;
}
```

## Key Components

### Node (`atbus_node.h`)

The central component representing a bus node. Manages connections, endpoints, and message routing.

```cpp
namespace atframework::atbus::v3000 {
    class node {
    public:
        using ptr_t = std::shared_ptr<node>;
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

## Coding Conventions

1. **Namespace**: `atframework::atbus::v3000`
2. **Include guards**: Use `#pragma once`
3. **C++ Standard**: C++17 required
4. **Naming**:
   - Classes/structs: `snake_case`
   - Functions: `snake_case`
   - Constants: `UPPER_SNAKE_CASE` or `EN_` prefix for enums
   - Types: `*_t` suffix for typedefs
5. **Smart pointers**: Use `std::shared_ptr` for node ownership

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
