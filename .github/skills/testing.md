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

## Common test groups

- `atbus_node_reg`
- `atbus_node_msg`
- `atbus_node_relationship`
- `atbus_node_setup`
- `atbus_endpoint`
- `atbus_message_handler`
- `atbus_connection_context`
- `atbus_connection_context_crosslang`
- `atbus_access_data_crosslang`
- `channel`
- `buffer`

## Writing tests

Test files are under `test/case/`.

Minimal example:

- Include: `frame/test_macros.h`
- Use: `CASE_TEST(group, case)` and `CASE_EXPECT_*` assertions

## Windows notes (shared memory)

- Private shared memory does not allow cross-process sharing on Windows
- Public shared memory may require administrator privileges
