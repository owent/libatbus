

EchoWithColor(COLOR GREEN "-- Configure ${CMAKE_CURRENT_LIST_DIR}")

file(RELATIVE_PATH PROJECT_ROOT_RELINC_DIR ${CMAKE_CURRENT_LIST_DIR} ${PROJECT_LIBATBUS_ROOT_INC_DIR})

set(PROJECT_LIB_SRC_LIST
    "${PROJECT_LIBATBUS_ROOT_INC_DIR}/detail/buffer.h"
    "${PROJECT_LIBATBUS_ROOT_INC_DIR}/detail/libatbus_adapter_libuv.h"
    "${PROJECT_LIBATBUS_ROOT_INC_DIR}/detail/libatbus_channel_export.h"
    "${PROJECT_LIBATBUS_ROOT_INC_DIR}/detail/libatbus_channel_types.h"
    "${PROJECT_LIBATBUS_ROOT_INC_DIR}/detail/libatbus_config.h"
    "${PROJECT_LIBATBUS_ROOT_INC_DIR}/detail/libatbus_error.h"
    "${PROJECT_LIBATBUS_ROOT_INC_DIR}/atbus_connection.h"
    "${PROJECT_LIBATBUS_ROOT_INC_DIR}/atbus_endpoint.h"
    "${PROJECT_LIBATBUS_ROOT_INC_DIR}/atbus_msg_handler.h"
    "${PROJECT_LIBATBUS_ROOT_INC_DIR}/atbus_node.h"
    "${PROJECT_LIBATBUS_ROOT_INC_DIR}/libatbus.h"
    "${PROJECT_LIBATBUS_ROOT_INC_DIR}/libatbus_protocol.h"

    "${PROJECT_LIBATBUS_ROOT_SRC_DIR}/detail/buffer.cpp"
    "${PROJECT_LIBATBUS_ROOT_SRC_DIR}/atbus_connection.cpp"
    "${PROJECT_LIBATBUS_ROOT_SRC_DIR}/atbus_endpoint.cpp"
    "${PROJECT_LIBATBUS_ROOT_SRC_DIR}/atbus_msg_handler.cpp"
    "${PROJECT_LIBATBUS_ROOT_SRC_DIR}/atbus_node.cpp"
    "${PROJECT_LIBATBUS_ROOT_SRC_DIR}/channel_io_stream.cpp"
    "${PROJECT_LIBATBUS_ROOT_SRC_DIR}/channel_mem.cpp"
    "${PROJECT_LIBATBUS_ROOT_SRC_DIR}/channel_shm.cpp"
    "${PROJECT_LIBATBUS_ROOT_SRC_DIR}/channel_utility.cpp"
)

set(PROJECT_LIB_PROTOCOL_SRC_LIST
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
add_library("${PROJECT_LIBATBUS_LIB_LINK}-protocol" STATIC ${PROJECT_LIB_PROTOCOL_SRC_LIST})
set_target_properties("${PROJECT_LIBATBUS_LIB_LINK}-protocol" PROPERTIES 
    C_VISIBILITY_PRESET "default"
    CXX_VISIBILITY_PRESET "default"
    WINDOWS_EXPORT_ALL_SYMBOLS TRUE
)
target_link_libraries("${PROJECT_LIBATBUS_LIB_LINK}-protocol"
    PUBLIC ${3RD_PARTY_PROTOBUF_LINK_NAME}
)
target_include_directories("${PROJECT_LIBATBUS_LIB_LINK}-protocol"
    PRIVATE  "$<BUILD_INTERFACE:${PROJECT_LIBATBUS_ROOT_INC_DIR}/detail>"
)
target_compile_options("${PROJECT_LIBATBUS_LIB_LINK}-protocol" PRIVATE ${PROJECT_LIBATBUS_PRIVATE_COMPILE_OPTIONS})
if (MSVC)
    set (PROJECT_LIBATBUS_PROTOCOL_COMPILE_OPTIONS "/wd4244")
    if (MSVC_VERSION GREATER_EQUAL 1922)
        # see https://docs.microsoft.com/en-us/cpp/overview/cpp-conformance-improvements?view=vs-2019#improvements_162 for detail
        list(APPEND PROJECT_LIBATBUS_PROTOCOL_COMPILE_OPTIONS "/wd5054")
    endif ()
    target_compile_options("${PROJECT_LIBATBUS_LIB_LINK}-protocol" PRIVATE ${PROJECT_LIBATBUS_PROTOCOL_COMPILE_OPTIONS})
endif ()
add_dependencies("${PROJECT_LIBATBUS_LIB_LINK}-protocol" "atbus-generate-protocol")
list(PREPEND PROJECT_LIBATBUS_PUBLIC_LINK_NAMES "${PROJECT_LIBATBUS_LIB_LINK}-protocol")

if(BUILD_SHARED_LIBS)   
    add_library(${PROJECT_LIBATBUS_LIB_LINK} SHARED ${PROJECT_LIB_SRC_LIST})
    set_target_properties(${PROJECT_LIBATBUS_LIB_LINK} PROPERTIES 
        C_VISIBILITY_PRESET "hidden"
        CXX_VISIBILITY_PRESET "hidden"
    )
    target_compile_definitions(${PROJECT_LIBATBUS_LIB_LINK}
        PRIVATE ATBUS_MACRO_API_NATIVE=1 ATBUS_MACRO_API_DLL=1
    )
    set_target_properties(${PROJECT_LIBATBUS_LIB_LINK} PROPERTIES INTERFACE_COMPILE_DEFINITIONS ATBUS_MACRO_API_DLL=1)
else ()
    add_library(${PROJECT_LIBATBUS_LIB_LINK} STATIC ${PROJECT_LIB_SRC_LIST})
    set_target_properties(${PROJECT_LIBATBUS_LIB_LINK} PROPERTIES 
        C_VISIBILITY_PRESET "hidden"
        CXX_VISIBILITY_PRESET "hidden"
    )
    target_compile_definitions(${PROJECT_LIBATBUS_LIB_LINK}
        PRIVATE ATBUS_MACRO_API_NATIVE=1
    )
endif()

add_dependencies(${PROJECT_LIBATBUS_LIB_LINK} "atbus-generate-protocol")

target_include_directories(${PROJECT_LIBATBUS_LIB_LINK} 
    PUBLIC 
        "$<BUILD_INTERFACE:${PROJECT_LIBATBUS_ROOT_INC_DIR}>"
        "$<INSTALL_INTERFACE:include>"
    PRIVATE 
        "$<BUILD_INTERFACE:${PROJECT_LIBATBUS_ROOT_SRC_DIR}>"
        "$<BUILD_INTERFACE:${PROJECT_LIBATBUS_ROOT_INC_DIR}/detail>"
)

target_compile_definitions(${PROJECT_LIBATBUS_LIB_LINK} PRIVATE ATBUS_MACRO_BUILD_API=1)
target_compile_options(${PROJECT_LIBATBUS_LIB_LINK} PRIVATE ${PROJECT_LIBATBUS_PRIVATE_COMPILE_OPTIONS})
target_link_libraries(${PROJECT_LIBATBUS_LIB_LINK}
    PUBLIC ${PROJECT_LIBATBUS_PUBLIC_LINK_NAMES}
)
if (PROJECT_LIBATBUS_INTERFACE_LINK_NAMES)
    target_link_libraries(${PROJECT_LIBATBUS_LIB_LINK}
        INTERFACE ${PROJECT_LIBATBUS_INTERFACE_LINK_NAMES}
    )
    if(BUILD_SHARED_LIBS)
        target_link_libraries(${PROJECT_LIBATBUS_LIB_LINK}
            PRIVATE ${PROJECT_LIBATBUS_INTERFACE_LINK_NAMES}
        )
    endif ()
endif ()

if (MSVC)
    set_property(TARGET ${PROJECT_LIBATBUS_LIB_LINK} PROPERTY FOLDER "atframework")
    set_property(TARGET "${PROJECT_LIBATBUS_LIB_LINK}-protocol" PROPERTY FOLDER "atframework")
endif ()
set(PROJECT_LIBATBUS_EXPORT_TARGETS ${PROJECT_LIBATBUS_LIB_LINK} "${PROJECT_LIBATBUS_LIB_LINK}-protocol")

install(TARGETS ${PROJECT_LIBATBUS_EXPORT_TARGETS}
    EXPORT ${PROJECT_LIBATBUS_EXPORT_NAME}
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

export(TARGETS ${PROJECT_LIBATBUS_EXPORT_TARGETS}
    FILE "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/cmake/${PROJECT_LIBATBUS_EXPORT_NAME}.cmake"
    NAMESPACE atframework::
    EXPORT_LINK_INTERFACE_LIBRARIES
)
install(
    EXPORT ${PROJECT_LIBATBUS_EXPORT_NAME}
    NAMESPACE "atframework::"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake"
)
