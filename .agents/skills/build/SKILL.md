---
name: build
description: "Use when: configuring or building libatbus with CMake, editing or reviewing CMake generation/dependency rules, changing shared/static builds, or adjusting bus ID/build type options."
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

## Incremental build stability

- Treat unconditional `touch` or same-content overwrites of code/resources consumed by `add_custom_command`,
  `add_custom_target`, `add_executable`, `add_library`, or `target_sources` as a blocking defect, including generated,
  copied, and other non-handwritten files.
- Declare real `OUTPUT`/`BYPRODUCTS` and accurate `DEPENDS`/`DEPFILE`; publish content-stably with
  `configure_file`, `file(CONFIGURE)`, `file(GENERATE)`, or a temporary file plus `cmake -E copy_if_different`.
- Use a dedicated stamp/witness only when it is not itself compiled, linked, packaged, installed, or substituted for a
  real output/byproduct.

## Run tests via CTest

- `ctest --test-dir <BUILD_DIR> -V`

## Key CMake options

- `BUILD_SHARED_LIBS` (NO/YES)
- `ATBUS_MACRO_BUSID_TYPE` (default: `uint64_t`)
- `CMAKE_BUILD_TYPE` (Debug/Release/RelWithDebInfo)

Tip: Prefer `RelWithDebInfo` (or `Release`) for benchmarks/production; Debug has significant overhead.
