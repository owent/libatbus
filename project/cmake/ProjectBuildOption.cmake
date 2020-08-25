# 默认配置选项
#####################################################################

# atbus 选项
set(ATBUS_MACRO_BUSID_TYPE "uint64_t" CACHE STRING "busid type")
set(ATBUS_MACRO_DATA_NODE_SIZE 256 CACHE STRING "node size of (shared) memory channel(must be power of 2)")
set(ATBUS_MACRO_DATA_ALIGN_SIZE 16 CACHE STRING "memory align size, most architecture require to padding to 16")
set(ATBUS_MACRO_DATA_MAX_PROTECT_SIZE 16384 CACHE STRING "max protected node size for mem/shm channel")

# for now, other component in io_stream_connection cost 472 bytes, make_shared will also cost some memory.
# we hope one connection will cost no more than 4KB, so 100K connections will cost no more than 400MB memory
# so we use 3KB for small message buffer, and left about 500 Bytes in feture use.
# This can be 512 or smaller (but not smaller than 32), but in most server environment, memory is cheap and there are only few connections between server and server. 
set(ATBUS_MACRO_DATA_SMALL_SIZE 3072 CACHE STRING "small message buffer for io_stream channel(used to reduce memory copy when there are many small messages)")

set(ATBUS_MACRO_HUGETLB_SIZE 4194304 CACHE STRING "huge page size in shared memory channel(unused now)")
set(ATBUS_MACRO_MSG_LIMIT 262144 CACHE STRING "message size limit")
set(ATBUS_MACRO_MAX_FRAME_HEADER 1024 CACHE STRING "message header size limit")
set(ATBUS_MACRO_CONNECTION_CONFIRM_TIMEOUT 30 CACHE STRING "connection confirm timeout")
set(ATBUS_MACRO_CONNECTION_BACKLOG 128 CACHE STRING "tcp backlog")
set(ATBUS_MACRO_SHM_MEM_CHANNEL_LENGTH 8388608 CACHE STRING "channel size for shm/mem channel")
set(ATBUS_MACRO_IOS_SEND_BUFFER_LENGTH 2097152 CACHE STRING "send buffer size for iostream channel")
option(ATBUS_MACRO_ABORT_ON_PROTECTED_ERROR "abort when any inner error found." OFF)

option(PROJECT_RESET_DENPEND_REPOSITORIES "Reset depended repositories if it's already exists." OFF)
option(PROJECT_GIT_CLONE_REMOTE_ORIGIN_DISABLE_SSH "Do not try to use ssh url when clone dependency." OFF)
option(PROJECT_FIND_CONFIGURE_PACKAGE_PARALLEL_BUILD "Parallel building for FindConfigurePackage. It's usually useful for some CI with low memory." ON)

option(ATFRAMEWORK_USE_DYNAMIC_LIBRARY "Build and linking with dynamic libraries." OFF)

# libuv选项
set(LIBUV_ROOT "" CACHE STRING "libuv root directory")

# 测试配置选项
set(GTEST_ROOT "" CACHE STRING "GTest root directory")
set(BOOST_ROOT "" CACHE STRING "Boost root directory")
option(PROJECT_TEST_ENABLE_BOOST_UNIT_TEST "Enable boost unit test." OFF)

# find if we have Unix Sock
include(CheckIncludeFiles)
CHECK_INCLUDE_FILES("sys/un.h;sys/socket.h" ATBUS_MACRO_WITH_UNIX_SOCK)
