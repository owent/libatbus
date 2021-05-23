set(ATFRAMEWORK_ATFRAME_UTILS_REPO_DIR
    "${PROJECT_SOURCE_DIR}/atframework/atframe_utils"
    CACHE PATH "PATH to atframe_utils")

macro(ATFRAMEWORK_ATFRAME_UTILS_POPULATE)
  if(NOT EXISTS "${ATFRAMEWORK_ATFRAME_UTILS_REPO_DIR}/CMakeLists.txt")
    execute_process(
      COMMAND ${GIT_EXECUTABLE} submodule update --depth 100 --recommend-shallow -f --init -- atframework/atframe_utils
      WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}" ${ATFRAMEWORK_CMAKE_TOOLSET_EXECUTE_PROCESS_OUTPUT_OPTIONS})
    set(ATFRAMEWORK_ATFRAME_UTILS_REPO_DIR
        "${PROJECT_SOURCE_DIR}/atframework/atframe_utils"
        CACHE PATH "PATH to atframe_utils" FORCE)
  endif()
endmacro()

if(TARGET atframe_utils)
  set(ATFRAMEWORK_ATFRAME_UTILS_LINK_NAME atframe_utils)
elseif(TARGET atframework::atframe_utils)
  set(ATFRAMEWORK_ATFRAME_UTILS_LINK_NAME atframework::atframe_utils)
else()
  set(ATFRAMEWORK_ATFRAME_UTILS_LINK_NAME atframe_utils)
  if(NOT EXISTS "${CMAKE_CURRENT_BINARY_DIR}/_deps/${ATFRAMEWORK_ATFRAME_UTILS_LINK_NAME}")
    file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/_deps/${ATFRAMEWORK_ATFRAME_UTILS_LINK_NAME}")
  endif()
  atframework_atframe_utils_populate()
  add_subdirectory("${ATFRAMEWORK_ATFRAME_UTILS_REPO_DIR}"
                   "${CMAKE_CURRENT_BINARY_DIR}/_deps/${ATFRAMEWORK_ATFRAME_UTILS_LINK_NAME}")
endif()
