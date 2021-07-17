include_guard(GLOBAL)

find_package(Git REQUIRED)

set(ATFRAMEWORK_CMAKE_TOOLSET_DIR
    "${PROJECT_SOURCE_DIR}/atframework/cmake-toolset"
    CACHE PATH "PATH to cmake-toolset")

if(NOT ATFRAMEWORK_CMAKE_TOOLSET_EXECUTE_PROCESS_OUTPUT_OPTIONS)
  unset(ATFRAMEWORK_CMAKE_TOOLSET_EXECUTE_PROCESS_OUTPUT_OPTIONS)
  if(CMAKE_VERSION VERSION_GREATER_EQUAL "3.15")
    list(APPEND ATFRAMEWORK_CMAKE_TOOLSET_EXECUTE_PROCESS_OUTPUT_OPTIONS COMMAND_ECHO STDOUT)
  endif()
  if(CMAKE_VERSION VERSION_GREATER_EQUAL "3.18")
    list(APPEND ATFRAMEWORK_CMAKE_TOOLSET_EXECUTE_PROCESS_OUTPUT_OPTIONS ECHO_OUTPUT_VARIABLE ECHO_ERROR_VARIABLE)
  endif()
endif()

if(NOT EXISTS "${ATFRAMEWORK_CMAKE_TOOLSET_DIR}/Import.cmake")
  execute_process(
    COMMAND ${GIT_EXECUTABLE} submodule update --depth 100 --recommend-shallow -f --init -- atframework/cmake-toolset
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}" ${ATFRAMEWORK_CMAKE_TOOLSET_EXECUTE_PROCESS_OUTPUT_OPTIONS})
  set(ATFRAMEWORK_CMAKE_TOOLSET_DIR
      "${PROJECT_SOURCE_DIR}/atframework/cmake-toolset"
      CACHE PATH "PATH to cmake-toolset" FORCE)
endif()

include("${ATFRAMEWORK_CMAKE_TOOLSET_DIR}/Import.cmake")