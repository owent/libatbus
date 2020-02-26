cmake_minimum_required(VERSION 3.4)
project(libuv LANGUAGES C)

include(CMakePackageConfigHelpers)
include(CMakeDependentOption)
include(GNUInstallDirs)

if(MSVC)
  list(APPEND uv_cflags /W4)
elseif(CMAKE_C_COMPILER_ID MATCHES "AppleClang|Clang|GNU")
  list(APPEND uv_cflags -fvisibility=hidden --std=gnu89)
  list(APPEND uv_cflags -Wall -Wextra -Wstrict-prototypes)
  list(APPEND uv_cflags -Wno-unused-parameter)
endif()

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
       advapi32
       iphlpapi
       psapi
       shell32
       user32
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
  if(NOT CMAKE_SYSTEM_NAME STREQUAL "Android")
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
       _XOPEN_SOURCE=500)
  list(APPEND uv_libraries perfstat)
  list(APPEND uv_sources src/unix/aix.c)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Android")
  list(APPEND uv_libs dl)
  list(APPEND uv_sources
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/android-ifaddrs.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/linux-core.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/linux-inotify.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/linux-syscalls.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/procfs-exepath.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/pthread-fixes.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/random-getrandom.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/random-sysctl-linux.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/sysinfo-loadavg.c"
  )
endif()

if(APPLE OR CMAKE_SYSTEM_NAME MATCHES "Android|Linux|OS/390")
  list(APPEND uv_sources "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/proctitle.c")
endif()

if(CMAKE_SYSTEM_NAME MATCHES "DragonFly|FreeBSD")
  list(APPEND uv_sources "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/freebsd.c")
endif()

if(CMAKE_SYSTEM_NAME MATCHES "DragonFly|FreeBSD|NetBSD|OpenBSD")
  list(APPEND uv_sources "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/posix-hrtime.c src/unix/bsd-proctitle.c")
  list(APPEND uv_libraries kvm)
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
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/sysinfo-loadavg.c"
  )
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "NetBSD")
  list(APPEND uv_sources "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/netbsd.c")
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
  list(APPEND uv_sources "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/openbsd.c")
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "OS/390")
  list(APPEND uv_defines PATH_MAX=255)
  list(APPEND uv_defines _AE_BIMODAL)
  list(APPEND uv_defines _ALL_SOURCE)
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
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/pthread-barrier.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/os390.c"
       "${3RD_PARTY_LIBUV_REPO_DIR}/src/unix/os390-syscalls.c"
  )
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
    EXPORT_LINK_INTERFACE_LIBRARIES
)

install(
    EXPORT "libuv-target"
    NAMESPACE "libuv::"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake"
)
