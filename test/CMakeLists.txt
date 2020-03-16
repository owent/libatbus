
EchoWithColor(COLOR GREEN "-- Configure Unit Test ${CMAKE_CURRENT_LIST_DIR}")

include("${PROJECT_TEST_BAS_DIR}/test.build_bin.cmake")

file(GLOB_RECURSE PROJECT_TEST_SRC_LIST
    ${PROJECT_TEST_SRC_DIR}/app/*.cpp
    ${PROJECT_TEST_SRC_DIR}/frame/*.h
    ${PROJECT_TEST_SRC_DIR}/frame/*.cpp
    ${CMAKE_CURRENT_LIST_DIR}/*.hpp
    ${CMAKE_CURRENT_LIST_DIR}/*.h
    ${CMAKE_CURRENT_LIST_DIR}/*.c
    ${CMAKE_CURRENT_LIST_DIR}/*.cpp
    ${CMAKE_CURRENT_LIST_DIR}/*.cc
    ${CMAKE_CURRENT_LIST_DIR}/*.cxx
)
source_group_by_dir(PROJECT_TEST_SRC_LIST)

# ============ test - coroutine test frame ============
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/test")

add_compiler_define(_CRT_SECURE_NO_WARNINGS=1)

add_executable(atbus_unit_test ${PROJECT_TEST_SRC_LIST})
target_compile_options(atbus_unit_test PRIVATE ${PROJECT_LIBATBUS_PRIVATE_COMPILE_OPTIONS})
target_link_libraries(atbus_unit_test
    ${PROJECT_LIBATBUS_LIB_LINK}
)

target_include_directories(atbus_unit_test
    PRIVATE "$<BUILD_INTERFACE:${PROJECT_LIBATBUS_ROOT_SRC_DIR}>"
)

if (MSVC)
    set_property(TARGET atbus_unit_test PROPERTY FOLDER "atframework/test")
endif ()

add_test(test atbus_unit_test)
