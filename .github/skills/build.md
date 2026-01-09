# Build (libatbus)

This repo uses **CMake (>= 3.24)** and requires C++17.

## Typical build flow

- Configure (Debug): `cmake ..`
- Configure (RelWithDebInfo): `cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo`
- Build:
  - Linux/macOS: `cmake --build .`
  - Windows (MSVC): `cmake --build . --config RelWithDebInfo`

## Run tests via CTest

- `ctest . -V`

## Key CMake options

- `BUILD_SHARED_LIBS` (NO/YES)
- `ATBUS_MACRO_BUSID_TYPE` (default: `uint64_t`)
- `CMAKE_BUILD_TYPE` (Debug/Release/RelWithDebInfo)

Tip: Prefer `RelWithDebInfo` (or `Release`) for benchmarks/production; Debug has significant overhead.
