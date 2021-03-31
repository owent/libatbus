# =========== 3rdparty flatbuffer ==================
if(CMAKE_VERSION VERSION_GREATER_EQUAL "3.10")
  include_guard(GLOBAL)
endif()

# =========== 3rdparty flatbuffer ==================
macro(PROJECT_LIBATBUS_FLATBUFFERS_IMPORT)
  if(TARGET flatbuffers::flatc AND TARGET flatbuffers::flatbuffers)
    get_target_property(3RD_PARTY_FLATBUFFER_INC_DIR flatbuffers::flatbuffers
                        INTERFACE_INCLUDE_DIRECTORIES)
    list(APPEND PROJECT_LIBATBUS_PUBLIC_INCLUDE_DIRS ${3RD_PARTY_FLATBUFFER_INC_DIR})

    echowithcolor(COLOR GREEN "-- Dependency: Flatbuffer found.(${3RD_PARTY_FLATBUFFER_INC_DIR})")
  endif()
endmacro()

if(NOT TARGET flatbuffers::flatc OR NOT TARGET flatbuffers::flatbuffers)
  if(VCPKG_TOOLCHAIN)
    find_package(Flatbuffers QUIET)
    project_libatbus_flatbuffers_import()
  endif()

  if(NOT TARGET flatbuffers::flatc OR NOT TARGET flatbuffers::flatbuffers)
    set(3RD_PARTY_FLATBUFFER_VERSION "v1.12.0")
    if(NOT Flatbuffers_ROOT)
      set(Flatbuffers_ROOT ${PROJECT_3RD_PARTY_INSTALL_DIR})
    endif()

    set(3RD_PARTY_FLATBUFFER_BUILD_OPTIONS
        -DFLATBUFFERS_CODE_COVERAGE=OFF
        -DFLATBUFFERS_BUILD_TESTS=OFF
        -DFLATBUFFERS_INSTALL=ON
        -DFLATBUFFERS_BUILD_FLATLIB=ON
        -DFLATBUFFERS_BUILD_FLATC=ON
        -DFLATBUFFERS_BUILD_FLATHASH=ON
        -DFLATBUFFERS_BUILD_GRPCTEST=OFF
        -DFLATBUFFERS_BUILD_SHAREDLIB=OFF)
    findconfigurepackage(
      PACKAGE
      Flatbuffers
      BUILD_WITH_CMAKE
      CMAKE_INHIRT_BUILD_ENV
      MSVC_CONFIGURE
      ${CMAKE_BUILD_TYPE}
      CMAKE_FLAGS
      ${3RD_PARTY_FLATBUFFER_BUILD_OPTIONS}
      WORKING_DIRECTORY
      ${PROJECT_3RD_PARTY_PACKAGE_DIR}
      BUILD_DIRECTORY
      "${CMAKE_CURRENT_BINARY_DIR}/deps/flatbuffers-${3RD_PARTY_FLATBUFFER_VERSION}/build_jobs_${PROJECT_PREBUILT_PLATFORM_NAME}"
      PREFIX_DIRECTORY
      ${Flatbuffers_ROOT}
      SRC_DIRECTORY_NAME
      "flatbuffers-${3RD_PARTY_FLATBUFFER_VERSION}"
      GIT_BRANCH
      "${3RD_PARTY_FLATBUFFER_VERSION}"
      GIT_URL
      "https://github.com/google/flatbuffers.git")

    if(NOT TARGET flatbuffers::flatc OR NOT TARGET flatbuffers::flatbuffers)
      echowithcolor(COLOR RED "-- Dependency: Flatbuffer is required but not found")
      message(FATAL_ERROR "Flatbuffer not found")
    endif()
    project_libatbus_flatbuffers_import()
  endif()
else()
  project_libatbus_flatbuffers_import()
endif()
