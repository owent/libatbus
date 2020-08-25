cmake_minimum_required(VERSION 3.12.0)
cmake_policy(SET CMP0074 NEW)
cmake_policy(SET CMP0022 NEW)

enable_testing()

project(libatbus C CXX)

set(LIBATBUS_VERSION_MAJOR "2")
set(LIBATBUS_VERSION_MINOR "0")
set(LIBATBUS_VERSION_PATCH "0")
set(LIBATBUS_VERSION "${LIBATBUS_VERSION_MAJOR}.${LIBATBUS_VERSION_MINOR}.${LIBATBUS_VERSION_PATCH}")


# 准备下载依赖组件
include ("${CMAKE_CURRENT_LIST_DIR}/3rd_party/atframe_utils/libatframe_utils.prepare.cmake")

########################################################################
# CMake 模块 (递归包含模块, 带颜色输出模块, 平台检测模块)
set (PROJECT_CMAKE_MODULE_DIR "${3RD_PARTY_ATFRAME_UTILS_PKG_DIR}/project/cmake")
list(APPEND CMAKE_MODULE_PATH "${PROJECT_CMAKE_MODULE_DIR}/modules")


include("${PROJECT_CMAKE_MODULE_DIR}/modules/IncludeDirectoryRecurse.cmake")
include("${PROJECT_CMAKE_MODULE_DIR}/modules/EchoWithColor.cmake")
include("${PROJECT_CMAKE_MODULE_DIR}/modules/FindConfigurePackage.cmake")

include("${CMAKE_CURRENT_LIST_DIR}/project/cmake/ProjectBuildOption.cmake")
include("${PROJECT_CMAKE_MODULE_DIR}/FindPlatform.cmake")
include("${PROJECT_CMAKE_MODULE_DIR}/ProjectTools.cmake")


#####################################################################
# 导入编译器和编译选项配置
include("${PROJECT_CMAKE_MODULE_DIR}/CompilerOption.cmake")
include("${PROJECT_CMAKE_MODULE_DIR}/TargetOption.cmake")
EchoWithColor(COLOR GREEN "-- Build Type: ${CMAKE_BUILD_TYPE}")

unset(PROJECT_LIBATBUS_PRIVATE_COMPILE_OPTIONS)
unset(PROJECT_LIBATBUS_PUBLIC_INCLUDE_DIRS)
unset(PROJECT_LIBATBUS_PUBLIC_LINK_NAMES)
unset(PROJECT_LIBATBUS_INTERFACE_LINK_NAMES)

########################################################################
# 导入项目配置
## 导入所有 macro 定义
include("${CMAKE_CURRENT_LIST_DIR}/3rd_party/3rd_party.macro.cmake")
include("${CMAKE_CURRENT_LIST_DIR}/include/include.macro.cmake")
include("${CMAKE_CURRENT_LIST_DIR}/src/libatbus.macro.cmake")
include("${CMAKE_CURRENT_LIST_DIR}/tools/tools.macro.cmake")

## 导入工程项目
if(TARGET ${3RD_PARTY_ATFRAME_UTILS_LINK_NAME})
    message(STATUS "${3RD_PARTY_ATFRAME_UTILS_LINK_NAME} already exist, use it directly.")
else()
    if (NOT EXISTS "${CMAKE_BINARY_DIR}/deps/${3RD_PARTY_ATFRAME_UTILS_LINK_NAME}")
        file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/deps/${3RD_PARTY_ATFRAME_UTILS_LINK_NAME}")
    endif ()
    add_subdirectory(${3RD_PARTY_ATFRAME_UTILS_PKG_DIR} "${CMAKE_BINARY_DIR}/deps/${3RD_PARTY_ATFRAME_UTILS_LINK_NAME}")
endif()
if (CMAKE_VERSION VERSION_GREATER_EQUAL "3.15")
    list(PREPEND PROJECT_LIBATBUS_PUBLIC_LINK_NAMES ${3RD_PARTY_ATFRAME_UTILS_LINK_NAME})
else()
    set(PROJECT_LIBATBUS_PUBLIC_LINK_NAMES ${3RD_PARTY_ATFRAME_UTILS_LINK_NAME} ${PROJECT_LIBATBUS_PUBLIC_LINK_NAMES})
endif()

if (COMPILER_STRICT_EXTRA_CFLAGS)
    list(APPEND PROJECT_LIBATBUS_PRIVATE_COMPILE_OPTIONS ${COMPILER_STRICT_EXTRA_CFLAGS})
endif ()

if (COMPILER_STRICT_CFLAGS)
    list(APPEND PROJECT_LIBATBUS_PRIVATE_COMPILE_OPTIONS ${COMPILER_STRICT_CFLAGS})
endif ()

# VS 2013的STL里会报这个warning
if (MSVC_VERSION LESS_EQUAL 1800)
    list(APPEND PROJECT_LIBATBUS_PRIVATE_COMPILE_OPTIONS "/wd4702")
endif ()

if (WIN32)
    list(APPEND PROJECT_LIBATBUS_INTERFACE_LINK_NAMES 
        advapi32
        iphlpapi
        psapi
        shell32
        user32
        userenv
        ws2_32
    )
endif ()

add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/src")

if (PROJECT_ENABLE_SAMPLE)
    add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/sample")
endif()

if (PROJECT_ENABLE_UNITTEST)
    include ("${3RD_PARTY_ATFRAME_UTILS_PKG_DIR}/test/test.utils-macro.cmake")
    add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/test")
endif()

if (PROJECT_ENABLE_TOOLS)
    add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/tools")
endif()

## 生成文档和导入配置

# Install configuration
set(CMAKE_INSTALL_CMAKEDIR "${CMAKE_INSTALL_LIBDIR}/cmake" CACHE STRING "Directory relative to CMAKE_INSTALL to install the cmake configuration files")

include(CMakePackageConfigHelpers)
set(INCLUDE_INSTALL_DIR include)

file(MAKE_DIRECTORY "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/cmake")

configure_package_config_file(
    "${CMAKE_CURRENT_LIST_DIR}/libatbus-config.cmake.in"
    "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/cmake/libatbus-config.cmake"
    INSTALL_DESTINATION ${CMAKE_INSTALL_CMAKEDIR}
    PATH_VARS LIBATBUS_VERSION INCLUDE_INSTALL_DIR CMAKE_INSTALL_LIBDIR PROJECT_SOURCE_DIR
    NO_CHECK_REQUIRED_COMPONENTS_MACRO
)

write_basic_package_version_file(
    "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/cmake/libatbus-config-version.cmake"
    VERSION ${LIBATBUS_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(
    FILES "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/cmake/libatbus-config.cmake" "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/cmake/libatbus-config-version.cmake"
    DESTINATION ${CMAKE_INSTALL_CMAKEDIR}
)