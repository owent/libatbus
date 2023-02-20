echowithcolor(COLOR GREEN "-- Configure Unit Test ${CMAKE_CURRENT_LIST_DIR}")

include("${PROJECT_TEST_BAS_DIR}/test.build_bin.cmake")

file(
  GLOB_RECURSE
  PROJECT_TEST_SRC_LIST
  ${PROJECT_TEST_SRC_DIR}/app/*.cpp
  ${PROJECT_TEST_SRC_DIR}/frame/*.h
  ${PROJECT_TEST_SRC_DIR}/frame/*.cpp
  ${CMAKE_CURRENT_LIST_DIR}/*.hpp
  ${CMAKE_CURRENT_LIST_DIR}/*.h
  ${CMAKE_CURRENT_LIST_DIR}/*.c
  ${CMAKE_CURRENT_LIST_DIR}/*.cpp
  ${CMAKE_CURRENT_LIST_DIR}/*.cc
  ${CMAKE_CURRENT_LIST_DIR}/*.cxx)
source_group_by_dir(PROJECT_TEST_SRC_LIST)

# ============ test - coroutine test frame ============
set(CMAKE_BUILD_RPATH "${CMAKE_INSTALL_RPATH}")
if(NOT (WIN32 AND BUILD_SHARED_LIBS))
  set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/test")
endif()

atframe_add_test_executable(atbus_unit_test ${PROJECT_TEST_SRC_LIST})

target_compile_options(atbus_unit_test PRIVATE ${PROJECT_LIBATBUS_PRIVATE_COMPILE_OPTIONS})
target_link_libraries(atbus_unit_test atframework::atbus)

target_include_directories(atbus_unit_test PRIVATE "$<BUILD_INTERFACE:${PROJECT_LIBATBUS_ROOT_SRC_DIR}>")

add_test(NAME "libatbus.unit_test" COMMAND "$<TARGET_FILE:atbus_unit_test>")
set_tests_properties("libatbus.unit_test" PROPERTIES LABELS "libatbus;libatbus.unit_test")
