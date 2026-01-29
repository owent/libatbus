# Copyright 2026 atframework
# =========== include - macro ===========
set(PROJECT_LIBATBUS_ROOT_INC_DIR ${CMAKE_CURRENT_LIST_DIR})

set(PROJECT_LIBATBUS_GENERATED_DIR "${CMAKE_CURRENT_BINARY_DIR}/_generated")
file(MAKE_DIRECTORY "${PROJECT_LIBATBUS_GENERATED_DIR}/include/detail")
file(MAKE_DIRECTORY "${PROJECT_LIBATBUS_GENERATED_DIR}/src")
file(MAKE_DIRECTORY "${PROJECT_LIBATBUS_GENERATED_DIR}/temp")

# define CONF from cmake to c macro
configure_file("${CMAKE_CURRENT_LIST_DIR}/detail/libatbus_config.h.in"
               "${PROJECT_LIBATBUS_GENERATED_DIR}/temp/libatbus_config.h" @ONLY)

execute_process(
  COMMAND "${CMAKE_COMMAND}" -E copy_if_different "${PROJECT_LIBATBUS_GENERATED_DIR}/temp/libatbus_config.h"
          "${PROJECT_LIBATBUS_GENERATED_DIR}/include/detail")

