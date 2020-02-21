

EchoWithColor(COLOR GREEN "-- Configure ${CMAKE_CURRENT_LIST_DIR}")

include ("${CMAKE_CURRENT_LIST_DIR}/sample.custom-macro.cmake")

# ============ sample - [...] ============

file(GLOB SAMPLE_SRC_LIST RELATIVE "${PROJECT_SAMPLE_SRC_DIR}"
    ${PROJECT_SAMPLE_SRC_DIR}/*.cpp
    ${PROJECT_SAMPLE_SRC_DIR}/*.cc
    ${PROJECT_SAMPLE_SRC_DIR}/*.c
    ${PROJECT_SAMPLE_SRC_DIR}/*.cxx
)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/sample")

foreach(SAMPLE_SRC_FILE IN LISTS SAMPLE_SRC_LIST)
    get_filename_component(SAMPLE_SRC_BIN_NAME ${SAMPLE_SRC_FILE} NAME_WE)
    set(SAMPLE_SRC_BIN_NAME "atbus_${SAMPLE_SRC_BIN_NAME}")

    add_executable(${SAMPLE_SRC_BIN_NAME} ${SAMPLE_SRC_FILE})
    target_link_libraries(${SAMPLE_SRC_BIN_NAME}
	    ${PROJECT_LIBATBUS_LIB_LINK}
		${3RD_PARTY_LIBUV_LINK_NAME}
        ${3RD_PARTY_ATFRAME_UTILS_LINK_NAME}
        ${3RD_PARTY_LIBUV_LINK_DEPS}
        ${COMPILER_OPTION_EXTERN_CXX_LIBS}
    )

    if (MSVC)
        set_property(TARGET ${SAMPLE_SRC_BIN_NAME} PROPERTY FOLDER "atframework/sample")
    endif ()
endforeach()
