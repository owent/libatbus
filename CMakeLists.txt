cmake_minimum_required(VERSION 3.16.0)
cmake_policy(SET CMP0054 NEW)
cmake_policy(SET CMP0022 NEW)
cmake_policy(SET CMP0067 NEW)
cmake_policy(SET CMP0074 NEW)
cmake_policy(SET CMP0091 NEW)

enable_testing()

project(libatbus C CXX)

set(LIBATBUS_VERSION_MAJOR "2")
set(LIBATBUS_VERSION_MINOR "1")
set(LIBATBUS_VERSION_PATCH "0")
set(LIBATBUS_VERSION "${LIBATBUS_VERSION_MAJOR}.${LIBATBUS_VERSION_MINOR}.${LIBATBUS_VERSION_PATCH}")

# 准备下载依赖组件

# ######################################################################################################################
# CMake 模块 (递归包含模块, 带颜色输出模块, 平台检测模块)
include("${CMAKE_CURRENT_LIST_DIR}/project/cmake/ProjectBuildOption.cmake")
# ######################################################################################################################
# 导入编译器和编译选项配置
echowithcolor(COLOR GREEN "-- Build Type: ${CMAKE_BUILD_TYPE}")

unset(PROJECT_LIBATBUS_PRIVATE_COMPILE_OPTIONS)

# ######################################################################################################################
# 导入项目配置 导入所有 macro 定义
include("${CMAKE_CURRENT_LIST_DIR}/include/include.macro.cmake")
include("${CMAKE_CURRENT_LIST_DIR}/src/libatbus.macro.cmake")
include("${CMAKE_CURRENT_LIST_DIR}/tools/tools.macro.cmake")

# 导入工程项目
set(PROJECT_LIBATBUS_PUBLIC_LINK_NAMES
    ${ATFRAMEWORK_ATFRAME_UTILS_LINK_NAME} ${ATFRAMEWORK_CMAKE_TOOLSET_THIRD_PARTY_PROTOBUF_LINK_NAME}
    ${ATFRAMEWORK_CMAKE_TOOLSET_THIRD_PARTY_LIBUV_LINK_NAME})

if(COMPILER_STRICT_EXTRA_CFLAGS)
  list(APPEND PROJECT_LIBATBUS_PRIVATE_COMPILE_OPTIONS ${COMPILER_STRICT_EXTRA_CFLAGS})
endif()

if(COMPILER_STRICT_CFLAGS)
  list(APPEND PROJECT_LIBATBUS_PRIVATE_COMPILE_OPTIONS ${COMPILER_STRICT_CFLAGS})
endif()

# VS 2013的STL里会报这个warning
if(MSVC_VERSION LESS_EQUAL 1800)
  list(APPEND PROJECT_LIBATBUS_PRIVATE_COMPILE_OPTIONS "/wd4702")
endif()

add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/src")

if(PROJECT_ENABLE_SAMPLE)
  add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/sample")
endif()

if(PROJECT_ENABLE_UNITTEST)
  atframework_atframe_utils_populate()
  include("${ATFRAMEWORK_ATFRAME_UTILS_REPO_DIR}/test/test.utils-macro.cmake")
  add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/test")
endif()

if(PROJECT_ENABLE_TOOLS)
  add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/tools")
endif()

# 生成文档和导入配置

# Install configuration
set(CMAKE_INSTALL_CMAKEDIR
    "${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}"
    CACHE STRING "Directory relative to CMAKE_INSTALL to install the cmake configuration files")

include(CMakePackageConfigHelpers)
set(INCLUDE_INSTALL_DIR include)

file(MAKE_DIRECTORY "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/cmake/${PROJECT_NAME}")

configure_package_config_file(
  "${CMAKE_CURRENT_LIST_DIR}/libatbus-config.cmake.in"
  "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/cmake/${PROJECT_NAME}/libatbus-config.cmake"
  INSTALL_DESTINATION ${CMAKE_INSTALL_CMAKEDIR}
  PATH_VARS LIBATBUS_VERSION INCLUDE_INSTALL_DIR CMAKE_INSTALL_LIBDIR PROJECT_SOURCE_DIR
  NO_CHECK_REQUIRED_COMPONENTS_MACRO)

write_basic_package_version_file(
  "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/cmake/${PROJECT_NAME}/libatbus-config-version.cmake"
  VERSION ${LIBATBUS_VERSION}
  COMPATIBILITY SameMajorVersion)

install(FILES "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/cmake/${PROJECT_NAME}/libatbus-config.cmake"
              "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/cmake/${PROJECT_NAME}/libatbus-config-version.cmake"
        DESTINATION ${CMAKE_INSTALL_CMAKEDIR})

export(
  EXPORT ${PROJECT_LIBATBUS_EXPORT_NAME}
  NAMESPACE atframework::
  FILE "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/cmake/${PROJECT_LIBATBUS_EXPORT_NAME}.cmake")
install(
  EXPORT ${PROJECT_LIBATBUS_EXPORT_NAME}
  NAMESPACE "atframework::"
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}")
