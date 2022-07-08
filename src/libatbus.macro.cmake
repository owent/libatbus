# =========== libatbus/src ===========
set(PROJECT_LIBATBUS_ROOT_SRC_DIR ${CMAKE_CURRENT_LIST_DIR})

set(PROJECT_LIBATBUS_LIB_LINK "atbus")
set(PROJECT_LIBATBUS_EXPORT_NAME ${PROJECT_NAME}-target)

# include("${PROJECT_LIBATBUS_ROOT_SRC_DIR}/XXX.cmake")

add_custom_command(
  OUTPUT "${PROJECT_LIBATBUS_ROOT_INC_DIR}/libatbus_protocol.pb.h"
         "${PROJECT_LIBATBUS_ROOT_SRC_DIR}/libatbus_protocol.pb.cc"
         "${PROJECT_LIBATBUS_ROOT_INC_DIR}/libatbus_protocol.pb"
  COMMAND
    ${ATFRAMEWORK_CMAKE_TOOLSET_THIRD_PARTY_PROTOBUF_BIN_PROTOC} --proto_path ${PROJECT_LIBATBUS_ROOT_INC_DIR} -o
    "${PROJECT_LIBATBUS_ROOT_INC_DIR}/libatbus_protocol.pb" "--cpp_out=${PROJECT_LIBATBUS_ROOT_INC_DIR}/"
    "${PROJECT_LIBATBUS_ROOT_INC_DIR}/libatbus_protocol.proto"
  COMMAND ${CMAKE_COMMAND} -E copy_if_different "${PROJECT_LIBATBUS_ROOT_INC_DIR}/libatbus_protocol.pb.cc"
          "${PROJECT_LIBATBUS_ROOT_SRC_DIR}/libatbus_protocol.pb.cc"
  COMMAND ${CMAKE_COMMAND} -E remove -f "${PROJECT_LIBATBUS_ROOT_INC_DIR}/libatbus_protocol.pb.cc"
  DEPENDS "${PROJECT_LIBATBUS_ROOT_INC_DIR}/libatbus_protocol.proto"
          "${ATFRAMEWORK_CMAKE_TOOLSET_THIRD_PARTY_PROTOBUF_BIN_PROTOC}"
  COMMENT
    "Generate ${PROJECT_LIBATBUS_ROOT_INC_DIR}/libatbus_protocol.pb.h, ${PROJECT_LIBATBUS_ROOT_SRC_DIR}/libatbus_protocol.pb.cc and ${PROJECT_LIBATBUS_ROOT_INC_DIR}/libatbus_protocol.pb"
)

add_custom_target("atbus-generate-protocol" SOURCES "${PROJECT_LIBATBUS_ROOT_INC_DIR}/libatbus_protocol.pb.h"
                                                    "${PROJECT_LIBATBUS_ROOT_SRC_DIR}/libatbus_protocol.pb.cc")

if(MSVC)
  set_property(TARGET "atbus-generate-protocol" PROPERTY FOLDER "atframework")
endif()
