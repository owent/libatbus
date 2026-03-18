# Skills (Agent Playbooks)

Actionable guides for common workflows in this repo.

Each skill is a directory containing a `SKILL.md` file with YAML frontmatter, following the [Agent Skills](https://agentskills.io/) specification.

| Skill | Directory | Description |
| ----- | --------- | ----------- |
| Build | `build/` | Configure/build with CMake |
| Testing | `testing/` | Run and write unit tests (incl. Windows DLL/PATH, topology tests, shared memory notes) |
| Protocol & Crypto | `libatbus-protocol-crypto/` | ECDH key exchange, encryption/compression negotiation, message framing, access token auth |

## Key Components

- **Node** (`atbus_node.h`) — Central bus node: init, listen, connect, send, routing, crypto config
- **Endpoint** (`atbus_endpoint.h`) — Remote node representation with ctrl + data connections
- **Connection** (`atbus_connection.h`) — Single connection state machine (kDisconnected → kConnecting → kHandshaking → kConnected)
- **Connection Context** (`atbus_connection_context.h`) — ECDH handshake, cipher/compression negotiation, message pack/unpack
- **Message Handler** (`atbus_message_handler.h`) — Dispatch table for register, ping/pong, forward, handshake_confirm
- **Topology** (`atbus_topology.h`) — Peer registry, upstream/downstream relation types, routing decisions
- **Channels** — Transport layer: memory (`mem://`), shared memory (`shm://`), TCP (`ipv4://`/`ipv6://`), Unix (`unix://`), pipe (`pipe://`)
- **Protocol** (`libatbus_protocol.proto`) — Protobuf v3 wire format definition
