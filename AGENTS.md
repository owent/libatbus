# libatbus Agent Guide

This is the canonical, cross-agent guide for this subproject. Keep it short: put repeatable workflows in
`.agents/skills/*/SKILL.md`, and keep `.github/copilot-instructions.md` / `CLAUDE.md` as lightweight bridges.

**libatbus** is a high-performance asynchronous, tree-structured message bus with TCP, memory/shared-memory channels,
ECDH-based encryption, compression, and topology-aware routing.

- **Repository**: <https://github.com/atframework/libatbus>
- **Languages**: C++ (C++17 required, C++17/C++20/C++23 features used when available)

## Project Map

- `include/`: public APIs, protocol definitions, channel exports, and internal details.
- `src/`: node, endpoint, connection, topology, channel, protocol, crypto/compression implementations.
- `test/case/`: private unit tests and cross-language protocol/auth vectors.
- `sample/`, `docs/`, `tools/`: examples, documentation, and utilities.
- `.agents/skills/`: build, testing, protocol/crypto, and AI-agent maintenance playbooks.

## Always-On Rules

- Respect the user's dirty workspace: inspect current file contents before editing and avoid unrelated reformatting.
- Read the matching `.agents/skills/*/SKILL.md` before build, test, protocol, crypto, or compression work.
- `include/libatbus_protocol.proto` is the wire-protocol source of truth; generated outputs should normally be
  regenerated, not edited by hand.
- After C++ edits, run `clang-format -i <file>` and verify with `clang-format --dry-run --Werror <file>` when practical.

## C++ Conventions

1. **C++ standard**: C++17 required.
2. **Include guards**: use `#pragma once`.
3. **Naming**: follow existing `snake_case` APIs and `EN_ATBUS_ERR_*` error names.
4. **Error handling**: return `ATBUS_ERROR_TYPE` / negative error codes as existing code does.
5. **Protocol stability**: avoid renaming public protocol fields, enum values, or error codes unless migration is planned.
6. **Anonymous namespace + static**: in `.cpp` files, file-local functions should be inside an anonymous namespace **and**
   keep the `static` keyword.

   ```cpp
   namespace {
   static void my_helper() { /* ... */ }
   }  // namespace
   ```

## Skill Routing

Read the matching `.agents/skills/*/SKILL.md` before specialized work:

| Skill | Use when |
| --- | --- |
| `build` | Configuring or building with CMake |
| `testing` | Running or writing private test-framework cases |
| `libatbus-protocol-crypto` | Working on protocol transport, ECDH, ciphers, compression, framing, or auth |
| `ai-agent-maintenance` | Auditing or optimizing AI agent prompts, bridge files, and skills |

## Agent File Compatibility

- `AGENTS.md` is canonical for tools that support hierarchical agent instructions.
- `.github/copilot-instructions.md` exists only to point VS Code Copilot at this guide and `.agents/skills/`.
- `CLAUDE.md` exists only to point Claude-compatible tools at this guide and `.agents/skills/`.
- Keep skill folder names and frontmatter `name` values identical; descriptions are the discovery surface.
