---
name: build
description: "Use when: configuring or building libatbus with CMake, changing shared/static builds, or adjusting bus ID/build type options."
---

# Build (libatbus)

This repo uses **CMake (>= 3.24)** and requires C++17.

## Typical build flow

- Resolve `<BUILD_DIR>` first: read the nearest `.vscode/settings.json` for `cmake.buildDirectory`; if absent, infer from
  clangd `--compile-commands-dir=...` or an existing configured build tree; if no user setting is readable, use `build`.
- Keep all build output and agent-generated scratch/log/temp files under `<BUILD_DIR>/...`; use
  `<BUILD_DIR>/_agent_tmp/...` for agent scratch.
- Configure (Debug): `cmake -S . -B <BUILD_DIR>`
- Configure (RelWithDebInfo): `cmake -S . -B <BUILD_DIR> -DCMAKE_BUILD_TYPE=RelWithDebInfo`
- Build:
  - Linux/macOS: `cmake --build <BUILD_DIR>`
  - Windows (MSVC): `cmake --build <BUILD_DIR> --config RelWithDebInfo`

## Run tests via CTest

- `ctest --test-dir <BUILD_DIR> -V`

## Key CMake options

- `BUILD_SHARED_LIBS` (NO/YES)
- `ATBUS_MACRO_BUSID_TYPE` (default: `uint64_t`)
- `CMAKE_BUILD_TYPE` (Debug/Release/RelWithDebInfo)

Tip: Prefer `RelWithDebInfo` (or `Release`) for benchmarks/production; Debug has significant overhead.
