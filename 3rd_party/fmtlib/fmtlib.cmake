if (CMAKE_VERSION VERSION_GREATER_EQUAL "3.10")
    include_guard(GLOBAL)
endif()

if(NOT DEFINED __PROJECT_3RD_PARTY_FMTLIB_LOADED)
    include(CheckCXXSourceCompiles)
    set(__PROJECT_3RD_PARTY_FMTLIB_LOADED 1)

    macro(PROJECT_3RD_PARTY_FMTLIB_IMPORT)
        if (TARGET fmt::fmt-header-only)
            message(STATUS "fmtlib using target: fmt::fmt-header-only")
            set (3RD_PARTY_FMTLIB_LINK_NAME fmt::fmt-header-only)
            list(APPEND 3RD_PARTY_PUBLIC_LINK_NAMES ${3RD_PARTY_FMTLIB_LINK_NAME})
        elseif (TARGET fmt::fmt)
            message(STATUS "fmtlib using target: uv")
            set (3RD_PARTY_FMTLIB_LINK_NAME fmt::fmt)
            list(APPEND 3RD_PARTY_PUBLIC_LINK_NAMES ${3RD_PARTY_FMTLIB_LINK_NAME})
        else()
            message(STATUS "fmtlib support disabled")
        endif()
    endmacro()

    if (VCPKG_TOOLCHAIN)
        find_package(fmt QUIET)
        PROJECT_3RD_PARTY_FMTLIB_IMPORT()
    endif ()

    if (NOT DEFINED 3RD_PARTY_TEST_STD_FORMAT)
        check_cxx_source_compiles("
        #include <format>
        #include <iostream>
        #include <string>
        int main() {
            std::cout<< std::format(\"The answer is {}.\", 42)<< std::endl;
            char buffer[64] = {0};
            const auto result = std::format_to_n(buffer, std::size(buffer), \"{} {}: {}\", \"Hello\", \"World!\", 42);
            std::cout << \"Buffer: \" << buffer << \",Untruncated output size = \" << result.size << std::endl;
            return 0;
        }" 3RD_PARTY_TEST_STD_FORMAT)
    endif()

    # =========== 3rdparty fmtlib ==================
    if (NOT TARGET fmt::fmt-header-only AND NOT TARGET fmt::fmt AND NOT 3RD_PARTY_TEST_STD_FORMAT)
        if (NOT 3RD_PARTY_FMTLIB_BASE_DIR)
            set (3RD_PARTY_FMTLIB_BASE_DIR ${CMAKE_CURRENT_LIST_DIR})
        endif()

        set (3RD_PARTY_FMTLIB_PKG_DIR "${3RD_PARTY_FMTLIB_BASE_DIR}/pkg")

        set (3RD_PARTY_FMTLIB_DEFAULT_VERSION "6.2.1")
        if (fmt_ROOT)
            set (FMT_ROOT ${fmt_ROOT})
        elseif (Fmt_ROOT)
            set (FMT_ROOT ${Fmt_ROOT})
        endif ()
        if (FMT_ROOT)
            set (3RD_PARTY_FMTLIB_ROOT_DIR ${FMT_ROOT})
        else ()
            set (3RD_PARTY_FMTLIB_ROOT_DIR "${CMAKE_CURRENT_LIST_DIR}/prebuilt/${PROJECT_PREBUILT_PLATFORM_NAME}")
            set (fmt_ROOT ${3RD_PARTY_FMTLIB_ROOT_DIR})
        endif ()

        if(NOT EXISTS ${3RD_PARTY_FMTLIB_PKG_DIR})
            file(MAKE_DIRECTORY ${3RD_PARTY_FMTLIB_PKG_DIR})
        endif()

        set(3RD_PARTY_FMTLIB_BACKUP_FIND_ROOT ${CMAKE_FIND_ROOT_PATH})
        list(APPEND CMAKE_FIND_ROOT_PATH ${3RD_PARTY_FMTLIB_ROOT_DIR})
        FindConfigurePackage(
            PACKAGE fmt
            BUILD_WITH_CMAKE CMAKE_INHIRT_BUILD_ENV
            CMAKE_FLAGS "-DCMAKE_POSITION_INDEPENDENT_CODE=YES" "-DBUILD_SHARED_LIBS=OFF" "-DFMT_DOC=OFF" "-DFMT_INSTALL=ON" 
                        "-DFMT_TEST=OFF" "-DFMT_FUZZ=OFF" "-DFMT_CUDA_TEST=OFF"
            WORKING_DIRECTORY "${3RD_PARTY_FMTLIB_PKG_DIR}"
            BUILD_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/deps/fmt-${3RD_PARTY_FMTLIB_DEFAULT_VERSION}/build_jobs_${PROJECT_PREBUILT_PLATFORM_NAME}"
            PREFIX_DIRECTORY ${3RD_PARTY_FMTLIB_ROOT_DIR}
            SRC_DIRECTORY_NAME "fmt-${3RD_PARTY_FMTLIB_DEFAULT_VERSION}"
            GIT_BRANCH ${3RD_PARTY_FMTLIB_DEFAULT_VERSION}
            GIT_URL "https://github.com/fmtlib/fmt.git"
        )

        if (fmt_FOUND)
            PROJECT_3RD_PARTY_FMTLIB_IMPORT()
        endif()
    endif ()

    if (3RD_PARTY_FMTLIB_BACKUP_FIND_ROOT)
        set(CMAKE_FIND_ROOT_PATH ${3RD_PARTY_FMTLIB_BACKUP_FIND_ROOT})
        unset(3RD_PARTY_FMTLIB_BACKUP_FIND_ROOT)
    endif ()
endif()
