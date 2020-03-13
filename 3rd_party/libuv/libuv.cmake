if (CMAKE_VERSION VERSION_GREATER_EQUAL "3.10")
    include_guard(GLOBAL)
endif()

# =========== 3rdparty libuv ==================
if (NOT 3RD_PARTY_LIBUV_INC_DIR OR NOT 3RD_PARTY_LIBUV_LINK_NAME)
    if (NOT 3RD_PARTY_LIBUV_BASE_DIR)
        set (3RD_PARTY_LIBUV_BASE_DIR ${CMAKE_CURRENT_LIST_DIR})
    endif()

    set (3RD_PARTY_LIBUV_PKG_DIR "${3RD_PARTY_LIBUV_BASE_DIR}/pkg")

    set (3RD_PARTY_LIBUV_DEFAULT_VERSION "1.35.0")
    set (3RD_PARTY_LIBUV_ROOT_DIR "${CMAKE_CURRENT_LIST_DIR}/prebuilt/${PLATFORM_BUILD_PLATFORM_NAME}")

    if(NOT EXISTS ${3RD_PARTY_LIBUV_PKG_DIR})
        file(MAKE_DIRECTORY ${3RD_PARTY_LIBUV_PKG_DIR})
    endif()

    # force to use prebuilt when using mingw
    # if (MINGW)
    #     set(LIBUV_ROOT ${3RD_PARTY_LIBUV_ROOT_DIR})
    # endif()
    unset(LIBUV_PATCH_OPTIONS)

    if (NOT UNIX)
        # git clone
        find_package(Git)
        if (NOT EXISTS "${3RD_PARTY_LIBUV_PKG_DIR}/repo-v${3RD_PARTY_LIBUV_DEFAULT_VERSION}")
            execute_process(COMMAND ${GIT_EXECUTABLE} clone "--depth=${FindConfigurePackageGitFetchDepth}" -b "v${3RD_PARTY_LIBUV_DEFAULT_VERSION}" "https://github.com/libuv/libuv.git" "repo-v${3RD_PARTY_LIBUV_DEFAULT_VERSION}"
                WORKING_DIRECTORY ${3RD_PARTY_LIBUV_PKG_DIR}
            )
        else ()
            execute_process(
                COMMAND ${GIT_EXECUTABLE} clean -df
                COMMAND ${GIT_EXECUTABLE} fetch -f "--depth=${FindConfigurePackageGitFetchDepth}" origin "v${3RD_PARTY_LIBUV_DEFAULT_VERSION}"
                COMMAND ${GIT_EXECUTABLE} reset --hard "v${3RD_PARTY_LIBUV_DEFAULT_VERSION}"
                WORKING_DIRECTORY "${3RD_PARTY_LIBUV_PKG_DIR}/repo-v${3RD_PARTY_LIBUV_DEFAULT_VERSION}"
            )
        endif()

        set (3RD_PARTY_LIBUV_REPO_DIR "${3RD_PARTY_LIBUV_PKG_DIR}/repo-v${3RD_PARTY_LIBUV_DEFAULT_VERSION}")
        add_subdirectory("${3RD_PARTY_LIBUV_BASE_DIR}/build-script" "${CMAKE_CURRENT_BINARY_DIR}/deps/libuv-v${3RD_PARTY_LIBUV_DEFAULT_VERSION}")

        set (Libuv_INCLUDE_DIRS "${3RD_PARTY_LIBUV_PKG_DIR}/repo-v${3RD_PARTY_LIBUV_DEFAULT_VERSION}/include")
        set (Libuv_LIBRARIES libuv)
        set (Libuv_FOUND TRUE)
    else ()
        FindConfigurePackage(
            PACKAGE Libuv
            BUILD_WITH_CMAKE
            CMAKE_FLAGS "-DCMAKE_POSITION_INDEPENDENT_CODE=YES" "-DBUILD_SHARED_LIBS=OFF" "-DBUILD_TESTING=OFF"
            WORKING_DIRECTORY "${3RD_PARTY_LIBUV_PKG_DIR}"
            BUILD_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/deps/libuv-v${3RD_PARTY_LIBUV_DEFAULT_VERSION}/build_jobs_${PLATFORM_BUILD_PLATFORM_NAME}"
            PREFIX_DIRECTORY "${3RD_PARTY_LIBUV_ROOT_DIR}"
            SRC_DIRECTORY_NAME "libuv-v${3RD_PARTY_LIBUV_DEFAULT_VERSION}"
            GIT_BRANCH "v${3RD_PARTY_LIBUV_DEFAULT_VERSION}"
            GIT_URL "https://github.com/libuv/libuv.git"
        )
    endif ()

    if (NOT Libuv_FOUND)
        EchoWithColor(COLOR RED "-- Dependency: Libuv is required, we can not find prebuilt for libuv and can not find git to clone the sources")
        message(FATAL_ERROR "Libuv not found")
    endif()

    set (3RD_PARTY_LIBUV_INC_DIR ${Libuv_INCLUDE_DIRS})
    set (3RD_PARTY_LIBUV_LINK_NAME ${Libuv_LIBRARIES})

    include_directories(${3RD_PARTY_LIBUV_INC_DIR})

    # mingw
    unset(3RD_PARTY_LIBUV_LINK_DEPS)
    if (MINGW)
        EchoWithColor(COLOR GREEN "-- MinGW: custom add lib advapi32 iphlpapi psapi shell32 user32 userenv ws2_32.")
        list(APPEND 3RD_PARTY_LIBUV_LINK_DEPS advapi32 iphlpapi psapi shell32 user32 userenv ws2_32)
    elseif (WIN32)
        EchoWithColor(COLOR GREEN "-- Win32: custom add lib advapi32 iphlpapi psapi shell32 user32 userenv ws2_32")
        list(APPEND 3RD_PARTY_LIBUV_LINK_DEPS advapi32 iphlpapi psapi shell32 user32 userenv ws2_32)
    endif()
endif ()