

EchoWithColor(COLOR GREEN "-- Configure ${CMAKE_CURRENT_LIST_DIR}")

include_directories(${PROJECT_LIBATBUS_ROOT_SRC_DIR} "${PROJECT_LIBATBUS_ROOT_INC_DIR}/detail")

file(RELATIVE_PATH PROJECT_ROOT_RELINC_DIR ${CMAKE_CURRENT_LIST_DIR} ${PROJECT_LIBATBUS_ROOT_INC_DIR})

file(GLOB_RECURSE PROJECT_LIB_SRC_LIST
    ${PROJECT_ROOT_RELINC_DIR}/*.h
    ${PROJECT_ROOT_RELINC_DIR}/*.hpp
    ${PROJECT_ROOT_RELINC_DIR}/*.hxx
    ${PROJECT_LIBATBUS_ROOT_SRC_DIR}/*.h
    ${PROJECT_LIBATBUS_ROOT_SRC_DIR}/*.hpp
    ${PROJECT_LIBATBUS_ROOT_SRC_DIR}/*.c
    ${PROJECT_LIBATBUS_ROOT_SRC_DIR}/*.cpp
    ${PROJECT_LIBATBUS_ROOT_SRC_DIR}/*.cc
    ${PROJECT_LIBATBUS_ROOT_SRC_DIR}/*.cxx
)

list(REMOVE_ITEM PROJECT_LIB_SRC_LIST
    "${PROJECT_ROOT_RELINC_DIR}/detail/libatbus_protocol.pb.h"
    "${PROJECT_ROOT_RELINC_DIR}/detail/libatbus_protocol.pb.cc"
)
LIST(APPEND PROJECT_LIB_SRC_LIST
    "${PROJECT_LIBATBUS_ROOT_INC_DIR}/detail/libatbus_protocol.pb.h"
    "${PROJECT_LIBATBUS_ROOT_SRC_DIR}/detail/libatbus_protocol.pb.cc"
)

set_source_files_properties(
    "${PROJECT_LIBATBUS_ROOT_INC_DIR}/detail/libatbus_protocol.pb.h"
    "${PROJECT_LIBATBUS_ROOT_SRC_DIR}/detail/libatbus_protocol.pb.cc"
    PROPERTIES GENERATED TRUE
)
list(REMOVE_DUPLICATES PROJECT_LIB_SRC_LIST)
source_group_by_dir(PROJECT_LIB_SRC_LIST)


# ============ libatbus - src ============
add_library(${PROJECT_LIB_LINK} STATIC ${PROJECT_LIB_SRC_LIST})

add_dependencies(${PROJECT_LIB_LINK} atbus_generate_protocol)

target_compile_definitions(${PROJECT_LIB_LINK} PRIVATE ATBUS_MACRO_BUILD_API=1)

set_target_properties(${PROJECT_LIB_LINK} PROPERTIES 
    C_VISIBILITY_PRESET "default"
    CXX_VISIBILITY_PRESET "default"
    INTERFACE_LINK_LIBRARIES "${3RD_PARTY_PROTOBUF_LINK_NAME};${3RD_PARTY_LIBUV_LINK_NAME}"
)
if (MSVC)
    set_property(TARGET ${PROJECT_LIB_LINK} PROPERTY FOLDER "atframework")
endif ()

install(TARGETS ${PROJECT_LIB_LINK}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(DIRECTORY ${PROJECT_LIBATBUS_ROOT_INC_DIR}
    DESTINATION .
    FILES_MATCHING REGEX ".+\\.h(pp)?$"
    PATTERN ".svn" EXCLUDE
    PATTERN ".git" EXCLUDE
)
