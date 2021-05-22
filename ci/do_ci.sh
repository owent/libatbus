#!/bin/bash

cd "$(cd "$(dirname $0)" && pwd)/..";

set -ex ;

if [[ "$1" == "format" ]]; then
  python3 -m pip install --user -r ./ci/requirements.txt ;
  export PATH="$HOME/.local/bin:$PATH"
  bash ./ci/format.sh ;
  CHANGED="$(git -c core.autocrlf=true ls-files --modified)" ;
  if [[ ! -z "$CHANGED" ]]; then
    echo "The following files have changes:" ;
    echo "$CHANGED" ;
    git diff ;
    # exit 1 ; # Just warning, some versions of clang-format have different default style for unsupport syntax
  fi
  exit 0 ;
elif [[ "$1" == "coverage" ]]; then
  vcpkg install --triplet=$VCPKG_TARGET_TRIPLET fmt openssl protobuf libuv ;
  CRYPTO_OPTIONS="-DATFRAMEWORK_CMAKE_TOOLSET_THIRD_PARTY_CRYPTO_USE_OPENSSL=ON" ;
  bash cmake_dev.sh -lus -b Debug -r build_jobs_coverage -c $USE_CC -- $CRYPTO_OPTIONS "-DCMAKE_C_FLAGS=$GCOV_FLAGS" "-DCMAKE_CXX_FLAGS=$GCOV_FLAGS" "-DCMAKE_EXE_LINKER_FLAGS=$GCOV_FLAGS" -DCMAKE_TOOLCHAIN_FILE=$VCPKG_INSTALLATION_ROOT/scripts/buildsystems/vcpkg.cmake -DVCPKG_TARGET_TRIPLET=$VCPKG_TARGET_TRIPLET  -DATBUS_MACRO_ABORT_ON_PROTECTED_ERROR=ON ;
  cd build_jobs_coverage ;
  cmake --build . -j ;
  ctest . -V ;
  timeout 5s ./tools/benchmark_shm_channel_recv 12345679 1024 4194304 > recv.log 2>&1 &
  timeout 6s ./tools/benchmark_shm_channel_send 12345679 1024 4194304 > send.log 2>&1 || true
  ./tools/show_shm_channel 12345679 1 16 > /dev/null || true
elif [[ "$1" == "ssl.openssl" ]]; then
  CRYPTO_OPTIONS="-DATFRAMEWORK_CMAKE_TOOLSET_THIRD_PARTY_CRYPTO_USE_OPENSSL=ON" ;
  vcpkg install --triplet=$VCPKG_TARGET_TRIPLET fmt openssl protobuf libuv ;
  bash cmake_dev.sh -lus -b Debug -r build_jobs_ci -c $USE_CC -- $CRYPTO_OPTIONS -DCMAKE_TOOLCHAIN_FILE=$VCPKG_INSTALLATION_ROOT/scripts/buildsystems/vcpkg.cmake -DVCPKG_TARGET_TRIPLET=$VCPKG_TARGET_TRIPLET  -DATBUS_MACRO_ABORT_ON_PROTECTED_ERROR=ON ;
  cd build_jobs_ci ;
  cmake --build . -j ;
  ctest . -V ;
elif [[ "$1" == "gcc.legacy.test" ]]; then
  bash cmake_dev.sh -lus -b Debug -r build_jobs_ci -c $USE_CC ;
  cd build_jobs_ci ;
  cmake --build . -j ;
  ctest . -V ;
elif [[ "$1" == "msys2.mingw.test" ]]; then
  pacman -S --needed --noconfirm mingw-w64-x86_64-cmake git mingw-w64-x86_64-git-lfs m4 curl wget tar autoconf automake mingw-w64-x86_64-toolchain mingw-w64-x86_64-libtool python || true ;
  git config --global http.sslBackend openssl ;
  mkdir -p build_jobs_ci ;
  cd build_jobs_ci ;
  cmake .. -G 'MinGW Makefiles' "-DBUILD_SHARED_LIBS=$BUILD_SHARED_LIBS" -DPROJECT_ENABLE_UNITTEST=ON -DPROJECT_ENABLE_SAMPLE=ON -DPROJECT_ENABLE_TOOLS=ON -DATBUS_MACRO_ABORT_ON_PROTECTED_ERROR=ON ;
  cmake --build . -j ;
  for EXT_PATH in $(find ../third_party/install/ -name "*.dll" | xargs dirname | sort -u); do
    export PATH="$PWD/$EXT_PATH:$PATH"
  done
  ctest . -V ;
fi
