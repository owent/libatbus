---
name: testing
description: "Use when: designing, writing, reviewing, or running libatbus unit tests, filtering private-framework cases, testing topology/channel behavior, or diagnosing Windows test startup/PATH."
---

# Unit testing (libatbus)

The test executable is `atbus_unit_test`; cases and their real helpers live under `test/case/`.

Read [test design and acceptance](references/test-design-and-acceptance.md) when planning, writing, or reviewing cases.
It is not needed merely to run a known test command. Also load `libatbus-protocol-crypto` when protocol compatibility,
framing, authentication, encryption, compression, or cross-language vectors are in scope.

## Choose the narrowest real path

- For buffers, message packing, connection contexts, crypto primitives, topology registries, and other in-process logic,
  construct real public objects and assert public results/state. Do not start TCP/Unix/SHM merely to reach an internal
  branch that has an in-memory production path.
- Use real TCP, Unix sockets, pipes, or shared memory only when that transport's connect/read/write/close behavior is the
  subject. Treat address availability, OS permissions, and cross-process support as integration prerequisites; do not
  copy a fixed port/address or invent an allocation API because a nearby test happens to use one.
- Build protocol/auth/crypto cases from the current `.proto`, public APIs, and verified vectors. Assert stable round-trip,
  validation, compatibility, and error semantics; never assert exact random key/nonce output.
- Reuse the nearest actual fixture/helper and its cleanup order. Keep libuv, crypto, protobuf, shared-memory, and global
  callback state isolated so case order does not affect results.

## Drive time and I/O deterministically

- `UNITTEST_WAIT_UNTIL` in `test/case/atbus_test_utils.h` pumps libuv with a wall-clock safety limit. Its timeout does not
  make the case fail by itself. Always assert the awaited predicate and business result after the loop.
- Use `unit_test_make_timepoint(...)` and explicit `node::proc(...)` calls for logical timeout/heartbeat/state-machine
  behavior. Do not use real elapsed time, a fixed sleep, CPU scheduling, or a precise pump/tick count as the oracle.
- When actual asynchronous I/O is the subject, wait for an observable predicate with a bounded safety timeout. The
  timeout prevents a hang; connection/message/callback state proves correctness.
- Prefer memory/in-process channels for routing and lifecycle logic that does not require kernel transport. If a real
  transport is unavoidable, use current platform guards and verify cleanup even after a failed precondition.

`CASE_EXPECT_*` is non-fatal. Guard dependent operations after setup failures. Cross-language vector cases may return
early when required generated files are absent; inspect output/case counts and report that path as skipped, not green
compatibility coverage.

## Run tests

Resolve `<BUILD_DIR>` as required by `AGENTS.md`, then prefer the registered CTest:

```bash
ctest --test-dir <BUILD_DIR> -R "^libatbus\.unit_test$" --output-on-failure
```

Add `-C <CONFIG>` for a verified multi-config generator.

The executable supports:

- List: `atbus_unit_test -l` / `--list-tests`
- Run a group/case: `atbus_unit_test -r <group>` or `-r <group>.<case>`
- Filter: `atbus_unit_test -f "pattern*"` / `--filter "pattern*"`
- Help/version: `-h`, `-v`

Run the exact case first and confirm it was selected, then the registered CTest and broader matrix in proportion to
protocol/platform risk. Do not maintain hand-counted case inventories in this Skill; discover current groups with `-l`
and source search.

## Windows startup

Prefer the registered CTest command so the target and working directory match current CMake configuration. If CTest or a
direct run reports missing DLLs, locate the actual executable/DLL outputs in the current build tree and prepend only
those verified directories to the current process `PATH`. Windows private shared memory and public shared-memory
permissions differ; preserve current platform guards and report unsupported/skipped coverage explicitly.
