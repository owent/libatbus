# libatbus Agent Guide

This is the canonical, self-contained cross-agent guide for this repository. Keep it short: put repeatable workflows in
`.agents/skills/*/SKILL.md`, keep `CLAUDE.md` as a lightweight bridge, and avoid redundant tool-specific prompt copies.
This repository manages its own AI agent prompts and skills; it must not depend on a parent or sibling repository guide.

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
- Resolve `<BUILD_DIR>` before creating build trees or temporary files: read the nearest `.vscode/settings.json` for
  `cmake.buildDirectory`; if absent, infer from clangd `--compile-commands-dir=...` or an existing configured build
  tree; if no user setting is readable, use `build`.
- Put all CMake build trees, AI scratch files, script output/logs, and temporary data under `<BUILD_DIR>/...`; for agent
  scratch use `<BUILD_DIR>/_agent_tmp/...`. Never create ad-hoc temp files in the repository root.
- Read the matching `.agents/skills/*/SKILL.md` before build, test, protocol, crypto, or compression work.
- `include/libatbus_protocol.proto` is the wire-protocol source of truth; generated outputs should normally be
  regenerated, not edited by hand.
- After C++ edits, run `clang-format -i <file>` and verify with `clang-format --dry-run --Werror <file>` when practical.

## C++ Conventions

1. **C++ standard**: C++17 required.
2. **Include guards**: use `#pragma once`.
3. **Header code**: any function, method, friend, or operator body written in a header must use
   `ATFW_UTIL_FORCEINLINE`; avoid plain `inline` for project code unless matching generated or third-party code.
4. **Exported ABI**: interfaces declared with `ATBUS_MACRO_API` or other `*_API` export macros must be implemented in
   `.cpp` files, not headers, so ABI stays stable across compilers and build options.
5. **Naming**: follow existing `snake_case` APIs and `EN_ATBUS_ERR_*` error names.
6. **Error handling**: return `ATBUS_ERROR_TYPE` / negative error codes as existing code does.
7. **Protocol stability**: avoid renaming public protocol fields, enum values, or error codes unless migration is planned.
8. **Anonymous namespace + static**: in `.cpp` files, file-local functions should be inside an anonymous namespace **and**
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
- `.agents/skills/` is the portable project skill location; keep each `SKILL.md` focused and self-contained.
- Do not maintain `.github/copilot-instructions.md` copies when `AGENTS.md` and `.agents/skills/` cover the same rules.
- `CLAUDE.md` exists only to point Claude-compatible tools at this guide and `.agents/skills/`.
- Do not make this repository depend on root, sibling, or vendored-submodule prompt files.
- Keep skill folder names and frontmatter `name` values identical; descriptions are the discovery surface.
