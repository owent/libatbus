# =========== 3rd_party =========== 
set (PROJECT_3RD_PARTY_ROOT_DIR ${CMAKE_CURRENT_LIST_DIR})

include("${PROJECT_3RD_PARTY_ROOT_DIR}/fmtlib/fmtlib.cmake")
include("${PROJECT_3RD_PARTY_ROOT_DIR}/libuv/libuv.cmake")
include("${PROJECT_3RD_PARTY_ROOT_DIR}/protobuf/protobuf.cmake")
include("${PROJECT_3RD_PARTY_ROOT_DIR}/atframe_utils/libatframe_utils.cmake")