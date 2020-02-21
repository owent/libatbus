

EchoWithColor(COLOR GREEN "-- Configure Tools ${CMAKE_CURRENT_LIST_DIR}")

# ============ TOOLS - [...] ============
include_directories(${PROJECT_TOOLS_INC_DIR})

file(GLOB TOOLS_SRC_LIST
    ${PROJECT_TOOLS_SRC_DIR}/*.cpp
    ${PROJECT_TOOLS_SRC_DIR}/*.cc
    ${PROJECT_TOOLS_SRC_DIR}/*.c
    ${PROJECT_TOOLS_SRC_DIR}/*.cxx
)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/tools")

foreach(TOOLS_SRC_FILE IN LISTS TOOLS_SRC_LIST)
    get_filename_component(TOOLS_SRC_BIN_NAME "${TOOLS_SRC_FILE}" NAME_WE)

    add_executable("${TOOLS_SRC_BIN_NAME}" ${TOOLS_SRC_FILE})
    target_link_libraries("${TOOLS_SRC_BIN_NAME}"
	    ${PROJECT_LIBATBUS_LIB_LINK}
		${PROJECT_TOOLS_LIB_LINK}
        ${3RD_PARTY_LIBUV_LINK_NAME}
        ${3RD_PARTY_ATFRAME_UTILS_LINK_NAME}
        ${3RD_PARTY_LIBUV_LINK_DEPS}
        ${COMPILER_OPTION_EXTERN_CXX_LIBS}
    )
    
    if (MSVC)
        set_property(TARGET "${TOOLS_SRC_BIN_NAME}" PROPERTY FOLDER "atframework/tools")
    endif ()

	install(TARGETS "${TOOLS_SRC_BIN_NAME}"
        RUNTIME DESTINATION tools
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    )

endforeach()
