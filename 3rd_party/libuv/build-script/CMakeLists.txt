cmake_minimum_required(VERSION 3.4)
project(libuv LANGUAGES C)

include(CMakePackageConfigHelpers)
include(CMakeDependentOption)
include(CheckCCompilerFlag)
include(GNUInstallDirs)

set(CMAKE_C_VISIBILITY_PRESET hidden)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)
set(CMAKE_C_STANDARD 90)

# Qemu Build
option(QEMU "build for qemu" OFF)
if(QEMU)
  add_definitions(-D__QEMU__=1)
endif()

# Compiler check
string(CONCAT is-msvc $<OR:
  $<C_COMPILER_ID:MSVC>,
  $<STREQUAL:${CMAKE_C_COMPILER_FRONTEND_VARIANT},MSVC>
>)

check_c_compiler_flag(/W4 UV_LINT_W4)
check_c_compiler_flag(/wd4100 UV_LINT_NO_UNUSED_PARAMETER_MSVC)
check_c_compiler_flag(/wd4127 UV_LINT_NO_CONDITIONAL_CONSTANT_MSVC)
check_c_compiler_flag(/wd4201 UV_LINT_NO_NONSTANDARD_MSVC)
check_c_compiler_flag(/wd4206 UV_LINT_NO_NONSTANDARD_EMPTY_TU_MSVC)
check_c_compiler_flag(/wd4210 UV_LINT_NO_NONSTANDARD_FILE_SCOPE_MSVC)
check_c_compiler_flag(/wd4232 UV_LINT_NO_NONSTANDARD_NONSTATIC_DLIMPORT_MSVC)
check_c_compiler_flag(/wd4456 UV_LINT_NO_HIDES_LOCAL)
check_c_compiler_flag(/wd4457 UV_LINT_NO_HIDES_PARAM)
check_c_compiler_flag(/wd4459 UV_LINT_NO_HIDES_GLOBAL)
check_c_compiler_flag(/wd4706 UV_LINT_NO_CONDITIONAL_ASSIGNMENT_MSVC)
check_c_compiler_flag(/wd4996 UV_LINT_NO_UNSAFE_MSVC)

check_c_compiler_flag(-Wall UV_LINT_WALL) # DO NOT use this under MSVC

# TODO: Place these into its own function
check_c_compiler_flag(-Wno-unused-parameter UV_LINT_NO_UNUSED_PARAMETER)
check_c_compiler_flag(-Wstrict-prototypes UV_LINT_STRICT_PROTOTYPES)
check_c_compiler_flag(-Wextra UV_LINT_EXTRA)

set(lint-no-unused-parameter $<$<BOOL:${UV_LINT_NO_UNUSED_PARAMETER}>:-Wno-unused-parameter>)
set(lint-strict-prototypes $<$<BOOL:${UV_LINT_STRICT_PROTOTYPES}>:-Wstrict-prototypes>)
set(lint-extra $<$<BOOL:${UV_LINT_EXTRA}>:-Wextra>)
set(lint-w4 $<$<BOOL:${UV_LINT_W4}>:/W4>)
set(lint-no-unused-parameter-msvc $<$<BOOL:${UV_LINT_NO_UNUSED_PARAMETER_MSVC}>:/wd4100>)
set(lint-no-conditional-constant-msvc $<$<BOOL:${UV_LINT_NO_CONDITIONAL_CONSTANT_MSVC}>:/wd4127>)
set(lint-no-nonstandard-msvc $<$<BOOL:${UV_LINT_NO_NONSTANDARD_MSVC}>:/wd4201>)
set(lint-no-nonstandard-empty-tu-msvc $<$<BOOL:${UV_LINT_NO_NONSTANDARD_EMPTY_TU_MSVC}>:/wd4206>)
set(lint-no-nonstandard-file-scope-msvc $<$<BOOL:${UV_LINT_NO_NONSTANDARD_FILE_SCOPE_MSVC}>:/wd4210>)
set(lint-no-nonstandard-nonstatic-dlimport-msvc $<$<BOOL:${UV_LINT_NO_NONSTANDARD_NONSTATIC_DLIMPORT_MSVC}>:/wd4232>)
set(lint-no-hides-local-msvc $<$<BOOL:${UV_LINT_NO_HIDES_LOCAL}>:/wd4456>)
set(lint-no-hides-param-msvc $<$<BOOL:${UV_LINT_NO_HIDES_PARAM}>:/wd4457>)
set(lint-no-hides-global-msvc $<$<BOOL:${UV_LINT_NO_HIDES_GLOBAL}>:/wd4459>)
set(lint-no-conditional-assignment-msvc $<$<BOOL:${UV_LINT_NO_CONDITIONAL_ASSIGNMENT_MSVC}>:/wd4706>)
set(lint-no-unsafe-msvc $<$<BOOL:${UV_LINT_NO_UNSAFE_MSVC}>:/wd4996>)
# Unfortunately, this one is complicated because MSVC and clang-cl support -Wall
# but using it is like calling -Weverything
string(CONCAT lint-default $<
  $<AND:$<BOOL:${UV_LINT_WALL}>,$<NOT:${is-msvc}>>:-Wall
>)

list(APPEND uv_cflags ${lint-strict-prototypes} ${lint-extra} ${lint-default} ${lint-w4})
list(APPEND uv_cflags ${lint-no-unused-parameter})
list(APPEND uv_cflags ${lint-no-unused-parameter-msvc})
list(APPEND uv_cflags ${lint-no-conditional-constant-msvc})
list(APPEND uv_cflags ${lint-no-nonstandard-msvc})
list(APPEND uv_cflags ${lint-no-nonstandard-empty-tu-msvc})
list(APPEND uv_cflags ${lint-no-nonstandard-file-scope-msvc})
list(APPEND uv_cflags ${lint-no-nonstandard-nonstatic-dlimport-msvc})
list(APPEND uv_cflags ${lint-no-hides-local-msvc})
list(APPEND uv_cflags ${lint-no-hides-param-msvc})
list(APPEND uv_cflags ${lint-no-hides-global-msvc})
list(APPEND uv_cflags ${lint-no-conditional-assignment-msvc})
list(APPEND uv_cflags ${lint-no-unsafe-msvc})

set(uv_sources
    "${3RD_PARTY_LIBUV_REPO_DIR}/src/fs-poll.c"
    "${3RD_PARTY_LIBUV_REPO_DIR}/src/idna.c"
    "${3RD_PARTY_LIBUV_REPO_DIR}/src/inet.c"
    "${3RD_PARTY_LIBUV_REPO_DIR}/src/random.c"
    "${3RD_PARTY_LIBUV_REPO_DIR}/src/strscpy.c"
    "${3RD_PARTY_LIBUV_REPO_DIR}/src/threadpool.c"
    "${3RD_PARTY_LIBUV_REPO_DIR}/src/timer.c"
    "${3RD_PARTY_LIBUV_REPO_DIR}/src/uv-common.c"
    "${3RD_PARTY_LIBUV_REPO_DIR}/src/uv-data-getter-setters.c"
    "${3RD_PARTY_LIBUV_REPO_DIR}/src/version.c"
)

if(WIN32)
  list(APPEND uv_defines WIN32_LEAN_AND_MEAN _WIN32_WINNT=0x0600)
  list(APPEND uv_libraries
       $<$<STREQUAL:${windows-version},0x0600>:psapi>
       # advapi32
       iphlpapi
       # psapi
       # shell32
       # user32
       userenv
       ws2_32)
  list(APPEND uv_sources
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/win/async.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/win/core.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/win/detect-wakeup.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/win/dl.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/win/error.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/win/fs.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/win/fs-event.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/win/getaddrinfo.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/win/getnameinfo.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/win/handle.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/win/loop-watcher.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/win/pipe.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/win/thread.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/win/poll.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/win/process.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/win/process-stdio.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/win/signal.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/win/snprintf.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/win/stream.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/win/tcp.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/win/tty.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/win/udp.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/win/util.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/win/winapi.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/win/winsock.c"
  )
  list(APPEND uv_test_libraries ws2_32)
else()
  list(APPEND uv_defines _FILE_OFFSET_BITS=64 _LARGEFILE_SOURCE)
  if(NOT CMAKE_SYSTEM_NAME MATCHES "Android|OS390")
    # TODO: This should be replaced with find_package(Threads) if possible
    # Android has pthread as part of its c library, not as a separate
    # libpthread.so.
    list(APPEND uv_libraries pthread)
  endif()
  list(APPEND uv_sources
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/async.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/core.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/dl.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/fs.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/getaddrinfo.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/getnameinfo.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/loop-watcher.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/loop.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/pipe.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/poll.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/process.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/random-devurandom.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/signal.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/stream.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/tcp.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/thread.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/tty.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/udp.c"
  )
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "AIX")
  list(APPEND uv_defines
       _ALL_SOURCE
       _LINUX_SOURCE_COMPAT
       _THREAD_SAFE
       _XOPEN_SOURCE=500
       HAVE_SYS_AHAFS_EVPRODS_H)
  list(APPEND uv_libraries perfstat)
  list(APPEND uv_sources 
        "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/aix.c"
        "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/aix-common.c")
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Android")
  list(APPEND uv_defines _GNU_SOURCE)
  list(APPEND uv_libraries dl)
  list(APPEND uv_sources
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/android-ifaddrs.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/linux-core.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/linux-inotify.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/linux-syscalls.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/procfs-exepath.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/pthread-fixes.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/random-getentropy.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/random-getrandom.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/random-sysctl-linux.c"
  )
endif()

if(APPLE OR CMAKE_SYSTEM_NAME MATCHES "Android|Linux|OS390")
  list(APPEND uv_sources "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/proctitle.c")
endif()

if(CMAKE_SYSTEM_NAME MATCHES "DragonFly|FreeBSD")
  list(APPEND uv_sources "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/freebsd.c")
endif()

if(CMAKE_SYSTEM_NAME MATCHES "DragonFly|FreeBSD|NetBSD|OpenBSD")
  list(APPEND uv_sources "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/posix-hrtime.c src/unix/bsd-proctitle.c")
endif()

if(APPLE OR CMAKE_SYSTEM_NAME MATCHES "DragonFly|FreeBSD|NetBSD|OpenBSD")
  list(APPEND uv_sources "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/bsd-ifaddrs.c" "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/kqueue.c")
endif()

if(CMAKE_SYSTEM_NAME MATCHES "FreeBSD")
  list(APPEND uv_sources "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/random-getrandom.c")
endif()

if(APPLE OR CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
  list(APPEND uv_sources "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/random-getentropy.c")
endif()

if(APPLE)
  list(APPEND uv_defines _DARWIN_UNLIMITED_SELECT=1 _DARWIN_USE_64_BIT_INODE=1)
  list(APPEND uv_sources
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/darwin-proctitle.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/darwin.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/fsevents.c"
  )
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  list(APPEND uv_defines _GNU_SOURCE _POSIX_C_SOURCE=200112)
  list(APPEND uv_libraries dl rt)
  list(APPEND uv_sources
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/linux-core.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/linux-inotify.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/linux-syscalls.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/procfs-exepath.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/random-getrandom.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/random-sysctl-linux.c"
  )
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "NetBSD")
  list(APPEND uv_sources "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/netbsd.c")
  list(APPEND uv_libraries kvm)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
  list(APPEND uv_sources "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/openbsd.c")
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "OS390")
  list(APPEND uv_defines PATH_MAX=255)
  list(APPEND uv_defines _AE_BIMODAL)
  list(APPEND uv_defines _ALL_SOURCE)
  list(APPEND uv_defines _ISOC99_SOURCE)
  list(APPEND uv_defines _LARGE_TIME_API)
  list(APPEND uv_defines _OPEN_MSGQ_EXT)
  list(APPEND uv_defines _OPEN_SYS_FILE_EXT)
  list(APPEND uv_defines _OPEN_SYS_IF_EXT)
  list(APPEND uv_defines _OPEN_SYS_SOCK_EXT3)
  list(APPEND uv_defines _OPEN_SYS_SOCK_IPV6)
  list(APPEND uv_defines _UNIX03_SOURCE)
  list(APPEND uv_defines _UNIX03_THREADS)
  list(APPEND uv_defines _UNIX03_WITHDRAWN)
  list(APPEND uv_defines _XOPEN_SOURCE_EXTENDED)
  list(APPEND uv_sources
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/pthread-fixes.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/os390.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/os390-syscalls.c"
  )
  list(APPEND uv_cflags -Wc,DLL -Wc,exportall -Wc,xplink)
  list(APPEND uv_libraries -Wl,xplink)
  list(APPEND uv_test_libraries -Wl,xplink)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "OS400")
  list(APPEND uv_defines
       _ALL_SOURCE
       _LINUX_SOURCE_COMPAT
       _THREAD_SAFE
       _XOPEN_SOURCE=500)
  list(APPEND uv_sources
    "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/aix-common.c"
    "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/ibmi.c"
    "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/no-fsevents.c"
    "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/no-proctitle.c"
    "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/posix-poll.c")
endif()


if(CMAKE_SYSTEM_NAME STREQUAL "SunOS")
  list(APPEND uv_defines __EXTENSIONS__ _XOPEN_SOURCE=500)
  list(APPEND uv_libraries kstat nsl sendfile socket)
  list(APPEND uv_sources "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/no-proctitle.c" "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/sunos.c")
endif()

add_library(libuv STATIC ${uv_sources})
target_compile_definitions(libuv PRIVATE ${uv_defines})
target_compile_options(libuv PRIVATE ${uv_cflags})
target_include_directories(libuv 
    PUBLIC 
        "$<BUILD_INTERFACE:${3RD_PARTY_LIBUV_REPO_DIR}/include>"
        "$<INSTALL_INTERFACE:include>"
    PRIVATE 
        "$<BUILD_INTERFACE:${3RD_PARTY_LIBUV_REPO_DIR}/src>"
)
target_link_libraries(libuv INTERFACE ${uv_libraries})

# target_compile_definitions(libuv PUBLIC BUILDING_UV_SHARED=1)

if(NOT UV_SKIP_HEADERS)
    install(DIRECTORY "${3RD_PARTY_LIBUV_REPO_DIR}/include"
        DESTINATION .
        PATTERN ".svn" EXCLUDE
        PATTERN ".git" EXCLUDE
    )
endif()

install(TARGETS libuv
    EXPORT "libuv-target"
    RUNTIME DESTINATION bin
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
)

export(TARGETS libuv
    FILE "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/cmake/libuv-target.cmake"
    NAMESPACE libuv::
    # EXPORT_LINK_INTERFACE_LIBRARIES
)

install(
    EXPORT "libuv-target"
    NAMESPACE "libuv::"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake"
)

message(STATUS "summary of build options:
    Install prefix:  ${CMAKE_INSTALL_PREFIX}
    Target system:   ${CMAKE_SYSTEM_NAME}
    Compiler:
      C compiler:    ${CMAKE_C_COMPILER}
      CFLAGS:        ${CMAKE_C_FLAGS_${_build_type}} ${CMAKE_C_FLAGS}
")
