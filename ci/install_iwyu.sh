#!/bin/bash
# Copyright 2026 atframework
# Build and install include-what-you-use from source, matching the installed clang version.

set -euo pipefail

# Detect installed clang version
CLANG_VERSION=$(clang --version | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
CLANG_MAJOR=$(echo "$CLANG_VERSION" | cut -d. -f1)

echo "Detected clang version: $CLANG_VERSION (major: $CLANG_MAJOR)"

# Map clang major version to IWYU branch
# IWYU tracks LLVM release branches (clang_18, clang_19, etc.)
IWYU_BRANCH="clang_${CLANG_MAJOR}"

echo "Will build IWYU from branch: $IWYU_BRANCH"

IWYU_BUILD_DIR=$(mktemp -d)
trap "rm -rf $IWYU_BUILD_DIR" EXIT

echo "Cloning include-what-you-use..."
git clone --depth 1 --branch "$IWYU_BRANCH" https://github.com/include-what-you-use/include-what-you-use.git "$IWYU_BUILD_DIR/iwyu"

mkdir -p "$IWYU_BUILD_DIR/iwyu/build"
cd "$IWYU_BUILD_DIR/iwyu/build"

echo "Configuring include-what-you-use..."
cmake .. \
  -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_PREFIX_PATH="$(llvm-config --prefix)"

echo "Building include-what-you-use..."
cmake --build . -j"$(nproc 2>/dev/null || echo 4)"

echo "Installing include-what-you-use..."
cmake --install .

echo "Verifying installation..."
include-what-you-use --version

echo "include-what-you-use installed successfully."
