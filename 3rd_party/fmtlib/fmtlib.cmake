if(CMAKE_VERSION VERSION_GREATER_EQUAL "3.10")
  include_guard(GLOBAL)
endif()

macro(PROJECT_LIBATBUS_FMTLIB_IMPORT)
  if(TARGET fmt::fmt-header-only)
    message(STATUS "fmtlib using target: fmt::fmt-header-only")
    set(3RD_PARTY_FMTLIB_LINK_NAME fmt::fmt-header-only)
    list(APPEND PROJECT_LIBATBUS_PUBLIC_LINK_NAMES ${3RD_PARTY_FMTLIB_LINK_NAME})
  elseif(TARGET fmt::fmt)
    message(STATUS "fmtlib using target: fmt::fmt")
    set(3RD_PARTY_FMTLIB_LINK_NAME fmt::fmt)
    list(APPEND PROJECT_LIBATBUS_PUBLIC_LINK_NAMES ${3RD_PARTY_FMTLIB_LINK_NAME})
  else()
    message(STATUS "fmtlib support disabled")
  endif()
endmacro()

if(NOT TARGET fmt::fmt-header-only
   AND NOT TARGET fmt::fmt
   AND NOT 3RD_PARTY_TEST_STD_FORMAT)
  if(VCPKG_TOOLCHAIN)
    find_package(fmt QUIET)
    project_libatbus_fmtlib_import()
  endif()

  if(NOT TARGET fmt::fmt-header-only
     AND NOT TARGET fmt::fmt
     AND NOT 3RD_PARTY_TEST_STD_FORMAT)
    include(CheckCXXSourceCompiles)
    if(NOT DEFINED 3RD_PARTY_TEST_STD_FORMAT)
      check_cxx_source_compiles(
        "#include <format>
         #include <iostream>
         #include <string>
         int main() {
             std::cout<< std::format(\"The answer is {}.\", 42)<< std::endl;
             char buffer[64] = {0};
             const auto result = std::format_to_n(buffer, sizeof(buffer), \"{} {}: {}\", \"Hello\", \"World!\", 42);
             std::cout << \"Buffer: \" << buffer << \",Untruncated output size = \" << result.size << std::endl;
             return 0;
         }"
        3RD_PARTY_TEST_STD_FORMAT)
    endif()

    # =========== 3rdparty fmtlib ==================
    if(NOT TARGET fmt::fmt-header-only
       AND NOT TARGET fmt::fmt
       AND NOT 3RD_PARTY_TEST_STD_FORMAT)
      set(3RD_PARTY_FMTLIB_DEFAULT_VERSION "7.1.3")
      set(FMT_ROOT ${PROJECT_3RD_PARTY_INSTALL_DIR})
      set(Fmt_ROOT ${PROJECT_3RD_PARTY_INSTALL_DIR})
      set(fmt_ROOT ${PROJECT_3RD_PARTY_INSTALL_DIR})

      if(NOT EXISTS ${PROJECT_3RD_PARTY_PACKAGE_DIR})
        file(MAKE_DIRECTORY ${PROJECT_3RD_PARTY_PACKAGE_DIR})
      endif()

      findconfigurepackage(
        PACKAGE
        fmt
        BUILD_WITH_CMAKE
        CMAKE_INHIRT_BUILD_ENV
        CMAKE_INHIRT_BUILD_ENV_DISABLE_C_FLAGS
        CMAKE_INHIRT_BUILD_ENV_DISABLE_ASM_FLAGS
        CMAKE_FLAGS
        "-DCMAKE_POSITION_INDEPENDENT_CODE=YES"
        "-DBUILD_SHARED_LIBS=OFF"
        "-DFMT_DOC=OFF"
        "-DFMT_INSTALL=ON"
        "-DFMT_TEST=OFF"
        "-DFMT_FUZZ=OFF"
        "-DFMT_CUDA_TEST=OFF"
        WORKING_DIRECTORY
        "${PROJECT_3RD_PARTY_PACKAGE_DIR}"
        BUILD_DIRECTORY
        "${CMAKE_CURRENT_BINARY_DIR}/deps/fmt-${3RD_PARTY_FMTLIB_DEFAULT_VERSION}/build_jobs_${PROJECT_PREBUILT_PLATFORM_NAME}"
        PREFIX_DIRECTORY
        ${PROJECT_3RD_PARTY_INSTALL_DIR}
        SRC_DIRECTORY_NAME
        "fmt-${3RD_PARTY_FMTLIB_DEFAULT_VERSION}"
        GIT_BRANCH
        ${3RD_PARTY_FMTLIB_DEFAULT_VERSION}
        GIT_URL
        "https://github.com/fmtlib/fmt.git")

      if(fmt_FOUND)
        project_libatbus_fmtlib_import()
      endif()
    endif()
  endif()
else()
  project_libatbus_fmtlib_import()
endif()
