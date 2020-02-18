cmake_minimum_required(VERSION 3.5)
project(libuv C)

find_package(Threads REQUIRED)

file(GLOB UV_SOURCES_COMMON "${3RD_PARTY_LIBUV_REPO_DIR}/src/*.c")

file(GLOB UV_SOURCES_UNIX
    "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/async.c"
    "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/core.c"
    "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/dl.c"
    "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/fs.c"
    "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/getaddrinfo.c"
    "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/getnameinfo.c"
    "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/loop.c"
    "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/loop-watcher.c"
    "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/pipe.c"
    "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/poll.c"
    "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/process.c"
    "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/signal.c"
    "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/stream.c"
    "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/tcp.c"
    "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/thread.c"
    "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/tty.c"
    "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/udp.c"
)
file(GLOB UV_SOURCES_LINUX
    "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/proctitle.c"
    "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/linux-core.c"
    "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/linux-inotify.c"
    "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/linux-syscalls.c"
    "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/procfs-exepath.c"
    "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/sysinfo-loadavg.c"
    "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/sysinfo-memory.c"
)
file(GLOB UV_SOURCES_DARWIN
    "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/proctitle.c"
    "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/darwin.c"
    "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/fsevents.c"
    "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/darwin-proctitle.c"
    "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/bsd-ifaddrs.c"
    "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/kqueue.c"
)
file(GLOB UV_SOURCES_FREEBSD
    "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/freebsd.c"
    "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/posix-hrtime.c"
    "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/bsd-proctitle.c"
    "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/bsd-ifaddrs.c"
    "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/kqueue.c"
)
file(GLOB UV_SOURCES_WIN "${3RD_PARTY_LIBUV_REPO_DIR}/src/win/*.c")

if(CMAKE_SYSTEM_NAME STREQUAL "Windows" OR CMAKE_SYSTEM_NAME STREQUAL "WindowsStore")
    add_library(libuv STATIC ${UV_SOURCES_COMMON} ${UV_SOURCES_WIN})
    target_compile_definitions(libuv PRIVATE WIN32_LEAN_AND_MEAN "_WIN32_WINNT=0x0600")
    target_link_libraries(libuv PRIVATE iphlpapi psapi shell32 userenv ws2_32)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    add_library(libuv STATIC ${UV_SOURCES_COMMON} ${UV_SOURCES_UNIX} ${UV_SOURCES_DARWIN})
elseif(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
    add_library(libuv STATIC ${UV_SOURCES_COMMON} ${UV_SOURCES_UNIX} ${UV_SOURCES_FREEBSD})
else() # Assume some Linux variant
    add_library(libuv STATIC ${UV_SOURCES_COMMON} ${UV_SOURCES_UNIX} ${UV_SOURCES_LINUX})
endif()

target_link_libraries(libuv PRIVATE Threads::Threads)
target_include_directories(libuv PUBLIC $<INSTALL_INTERFACE:include> $<BUILD_INTERFACE:${3RD_PARTY_LIBUV_REPO_DIR}/include> $<BUILD_INTERFACE:${3RD_PARTY_LIBUV_REPO_DIR}/src>)
set_target_properties(libuv PROPERTIES DEFINE_SYMBOL BUILDING_UV_SHARED)

if(NOT UV_SKIP_HEADERS)
    install(
        DIRECTORY include/
        DESTINATION include
    )
endif()

install(TARGETS libuv
    EXPORT libuv
    RUNTIME DESTINATION bin
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
)
