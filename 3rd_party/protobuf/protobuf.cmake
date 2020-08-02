if (CMAKE_VERSION VERSION_GREATER_EQUAL "3.10")
    include_guard(GLOBAL)
endif()

macro(PROJECT_LIBATBUS_3RD_PARTY_PROTOBUF_IMPORT)
    if(PROTOBUF_FOUND AND PROTOBUF_PROTOC_EXECUTABLE AND Protobuf_INCLUDE_DIRS AND Protobuf_LIBRARY)
        if (UNIX)
            execute_process(COMMAND chmod +x "${PROTOBUF_PROTOC_EXECUTABLE}")
        endif()

        if (TARGET protobuf::libprotobuf AND TARGET protobuf::libprotobuf-lite)
            set (3RD_PARTY_PROTOBUF_LINK_NAME protobuf::libprotobuf)
            set (3RD_PARTY_PROTOBUF_LITE_LINK_NAME protobuf::libprotobuf-lite)
            EchoWithColor(COLOR GREEN "-- Dependency: Protobuf libraries.(${Protobuf_LIBRARY_DEBUG})")
            EchoWithColor(COLOR GREEN "-- Dependency: Protobuf lite libraries.(${Protobuf_LITE_LIBRARY_DEBUG})")
            get_target_property(3RD_PARTY_PROTOBUF_INC_DIR protobuf::libprotobuf INTERFACE_INCLUDE_DIRECTORIES)
        elseif (${CMAKE_BUILD_TYPE} STREQUAL "Debug" AND Protobuf_LIBRARY_DEBUG)
            set (3RD_PARTY_PROTOBUF_INC_DIR ${PROTOBUF_INCLUDE_DIRS})
            set (3RD_PARTY_PROTOBUF_LINK_NAME ${Protobuf_LIBRARY_DEBUG})
            set (3RD_PARTY_PROTOBUF_LITE_LINK_NAME ${Protobuf_LITE_LIBRARY_DEBUG})
            EchoWithColor(COLOR GREEN "-- Dependency: Protobuf libraries.(${Protobuf_LIBRARY_DEBUG})")
            EchoWithColor(COLOR GREEN "-- Dependency: Protobuf lite libraries.(${Protobuf_LITE_LIBRARY_DEBUG})")
        else()
            set (3RD_PARTY_PROTOBUF_INC_DIR ${PROTOBUF_INCLUDE_DIRS})
            if (Protobuf_LIBRARY_RELEASE)
                set (3RD_PARTY_PROTOBUF_LINK_NAME ${Protobuf_LIBRARY_RELEASE})
            else ()
                set (3RD_PARTY_PROTOBUF_LINK_NAME ${Protobuf_LIBRARY})
            endif ()
            if (Protobuf_LITE_LIBRARY_RELEASE)
                set (3RD_PARTY_PROTOBUF_LITE_LINK_NAME ${Protobuf_LITE_LIBRARY_RELEASE})
            else ()
                set (3RD_PARTY_PROTOBUF_LITE_LINK_NAME ${Protobuf_LIBRARY})
            endif ()
            EchoWithColor(COLOR GREEN "-- Dependency: Protobuf libraries.(${Protobuf_LIBRARY})")
            EchoWithColor(COLOR GREEN "-- Dependency: Protobuf lite libraries.(${Protobuf_LITE_LIBRARY})")
        endif()

        if (Protobuf_PROTOC_EXECUTABLE)
            set (3RD_PARTY_PROTOBUF_BIN_PROTOC ${Protobuf_PROTOC_EXECUTABLE})
        else ()
            set (3RD_PARTY_PROTOBUF_BIN_PROTOC ${PROTOBUF_PROTOC_EXECUTABLE})
        endif ()

        if (3RD_PARTY_PROTOBUF_INC_DIR)
            list(APPEND 3RD_PARTY_PUBLIC_INCLUDE_DIRS ${3RD_PARTY_PROTOBUF_INC_DIR})
        endif ()

        if (3RD_PARTY_PROTOBUF_LINK_NAME)
            list(APPEND 3RD_PARTY_PUBLIC_LINK_NAMES ${3RD_PARTY_PROTOBUF_LINK_NAME})
        endif ()
    endif()
endmacro()

# =========== 3rdparty protobuf ==================
if (NOT 3RD_PARTY_PROTOBUF_BIN_PROTOC OR (NOT 3RD_PARTY_PROTOBUF_LINK_NAME AND NOT 3RD_PARTY_PROTOBUF_INC_DIR))
    include(GNUInstallDirs)
    include(ProjectBuildTools)

    if (VCPKG_TOOLCHAIN)
        find_package(Protobuf)
        PROJECT_LIBATBUS_3RD_PARTY_PROTOBUF_IMPORT()
    endif ()

    if (NOT PROTOBUF_FOUND OR NOT PROTOBUF_PROTOC_EXECUTABLE OR NOT Protobuf_INCLUDE_DIRS OR NOT Protobuf_LIBRARY)
        set (3RD_PARTY_PROTOBUF_BASE_DIR "${CMAKE_CURRENT_LIST_DIR}")
        set (3RD_PARTY_PROTOBUF_PKG_DIR "${CMAKE_CURRENT_LIST_DIR}/pkg")

        set (3RD_PARTY_PROTOBUF_VERSION "3.12.3")

        if( ${CMAKE_CXX_COMPILER_ID} STREQUAL "GNU")
            if ( CMAKE_CXX_COMPILER_VERSION VERSION_LESS "4.7.0")
                set (3RD_PARTY_PROTOBUF_VERSION "3.5.1")
            endif()
        elseif( ${CMAKE_CXX_COMPILER_ID} STREQUAL "Clang")
            if ( CMAKE_CXX_COMPILER_VERSION VERSION_LESS "3.3")
                set (3RD_PARTY_PROTOBUF_VERSION "3.5.1")
            endif()
        elseif( ${CMAKE_CXX_COMPILER_ID} STREQUAL "AppleClang")
            if ( CMAKE_CXX_COMPILER_VERSION VERSION_LESS "5.0")
                set (3RD_PARTY_PROTOBUF_VERSION "3.5.1")
            endif()
        elseif(MSVC)
            if ( MSVC_VERSION LESS 1900)
                set (3RD_PARTY_PROTOBUF_VERSION "3.5.1")
            endif()
        endif()

        if (NOT PROJECT_PREBUILT_PLATFORM_NAME)
            if (ANDROID_ABI)
                string(TOLOWER "${CMAKE_SYSTEM_NAME}-${ANDROID_ABI}-${CMAKE_CXX_COMPILER_ID}" PROJECT_PREBUILT_PLATFORM_NAME)
                set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-omit-frame-pointer")
                set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-omit-frame-pointer")
            elseif (CMAKE_OSX_ARCHITECTURES)
                string(TOLOWER "${CMAKE_SYSTEM_NAME}-${CMAKE_OSX_ARCHITECTURES}-${CMAKE_CXX_COMPILER_ID}" PROJECT_PREBUILT_PLATFORM_NAME)
            else ()
                string(TOLOWER "${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}-${CMAKE_CXX_COMPILER_ID}" PROJECT_PREBUILT_PLATFORM_NAME)
            endif ()
        endif()
        if (NOT PROJECT_PREBUILT_HOST_PLATFORM_NAME)
            string(TOLOWER "${CMAKE_HOST_SYSTEM_NAME}-${CMAKE_HOST_SYSTEM_PROCESSOR}-${CMAKE_CXX_COMPILER_ID}" PROJECT_PREBUILT_HOST_PLATFORM_NAME)
        endif()

        if(PROTOBUF_ROOT)
            set (3RD_PARTY_PROTOBUF_ROOT_DIR ${PROTOBUF_ROOT})
        else()
            set (3RD_PARTY_PROTOBUF_ROOT_DIR "${CMAKE_CURRENT_LIST_DIR}/prebuilt/${PROJECT_PREBUILT_PLATFORM_NAME}")
        endif()

        if(PROTOBUF_HOST_ROOT)
            set (3RD_PARTY_PROTOBUF_HOST_ROOT_DIR ${PROTOBUF_HOST_ROOT})
        else()
            set (3RD_PARTY_PROTOBUF_HOST_ROOT_DIR "${CMAKE_CURRENT_LIST_DIR}/prebuilt/${PROJECT_PREBUILT_HOST_PLATFORM_NAME}")
        endif()

        project_build_tools_append_cmake_options_for_lib(3RD_PARTY_PROTOBUF_FLAG_OPTIONS)

        if (NOT EXISTS ${3RD_PARTY_PROTOBUF_PKG_DIR})
            file(MAKE_DIRECTORY ${3RD_PARTY_PROTOBUF_PKG_DIR})
        endif()

        # MSVC 必须用静态库，而且会被用/MT编译。我们要把默认的/MD改为/MT
        # 使用 /MD protobuf容易跨堆管理数据，容易崩溃，/MT依赖较少不容易出问题
        # 注意protobuf的 RelWithDebInfo 默认使用 /MT 而本工程默认是 /MTd
        # if (MSVC)
        #     set (3RD_PARTY_PROTOBUF_BUILD_SHARED_LIBS -DBUILD_SHARED_LIBS=OFF)
        #     # add_compiler_define(PROTOBUF_USE_DLLS) # MSVC 使用动态库必须加这个选项
        #     foreach(flag_var
        #         CMAKE_CXX_FLAGS CMAKE_CXX_FLAGS_DEBUG CMAKE_CXX_FLAGS_RELEASE
        #         CMAKE_CXX_FLAGS_MINSIZEREL CMAKE_CXX_FLAGS_RELWITHDEBINFO)
        #         if(${flag_var} MATCHES "/MD")
        #             string(REGEX REPLACE "/MD" "/MT" ${flag_var} "${${flag_var}}")
        #         endif(${flag_var} MATCHES "/MD")
        #     endforeach(flag_var)
        # #else ()
        #     # 其他情况使用默认值即可
        #     # set (3RD_PARTY_PROTOBUF_BUILD_SHARED_LIBS OFF)
        # endif ()

        list(APPEND CMAKE_INCLUDE_PATH "${3RD_PARTY_PROTOBUF_ROOT_DIR}/include")
        if (CMAKE_ANDROID_ARCH_ABI)
            list(APPEND CMAKE_LIBRARY_PATH "${3RD_PARTY_PROTOBUF_ROOT_DIR}/lib/${CMAKE_ANDROID_ARCH_ABI}" "${3RD_PARTY_PROTOBUF_ROOT_DIR}/${CMAKE_INSTALL_BINDIR}")
        else ()
            list(APPEND CMAKE_LIBRARY_PATH "${3RD_PARTY_PROTOBUF_ROOT_DIR}/${CMAKE_INSTALL_LIBDIR}" "${3RD_PARTY_PROTOBUF_ROOT_DIR}/${CMAKE_INSTALL_BINDIR}")
        endif()

        if (NOT CMAKE_SYSTEM STREQUAL CMAKE_HOST_SYSTEM)
            list(APPEND CMAKE_PROGRAM_PATH "${3RD_PARTY_PROTOBUF_HOST_ROOT_DIR}/${CMAKE_INSTALL_BINDIR}")
        endif ()
        set (Protobuf_ROOT ${3RD_PARTY_PROTOBUF_ROOT_DIR})
        set(3RD_PARTY_PROTOBUF_BACKUP_FIND_ROOT ${CMAKE_FIND_ROOT_PATH})
        list(APPEND CMAKE_FIND_ROOT_PATH ${3RD_PARTY_PROTOBUF_ROOT_DIR})

        if (CMAKE_VERSION VERSION_LESS "3.14" AND EXISTS "${3RD_PARTY_PROTOBUF_ROOT_DIR}/lib64" AND NOT EXISTS "${3RD_PARTY_PROTOBUF_ROOT_DIR}/lib")
            if (CMAKE_HOST_WIN32)
                execute_process(
                    COMMAND mklink /D "${3RD_PARTY_PROTOBUF_ROOT_DIR}/lib" "${3RD_PARTY_PROTOBUF_ROOT_DIR}/lib64"
                    WORKING_DIRECTORY ${3RD_PARTY_PROTOBUF_ROOT_DIR}
                )
            else ()
                execute_process(
                    COMMAND ln -s "${3RD_PARTY_PROTOBUF_ROOT_DIR}/lib64" "${3RD_PARTY_PROTOBUF_ROOT_DIR}/lib"
                    WORKING_DIRECTORY ${3RD_PARTY_PROTOBUF_ROOT_DIR}
                )
            endif ()
        endif()

        set(Protobuf_USE_STATIC_LIBS ON)
        unset(3RD_PARTY_PROTOBUF_FIND_LIB CACHE)
        find_library(3RD_PARTY_PROTOBUF_FIND_LIB NAMES protobuf libprotobuf protobufd libprotobufd
            PATHS "${3RD_PARTY_PROTOBUF_ROOT_DIR}/lib" "${3RD_PARTY_PROTOBUF_ROOT_DIR}/lib64" NO_DEFAULT_PATH)
        if (NOT 3RD_PARTY_PROTOBUF_FIND_LIB)
            if (NOT EXISTS "${3RD_PARTY_PROTOBUF_PKG_DIR}/protobuf-${3RD_PARTY_PROTOBUF_VERSION}")
                if (NOT EXISTS "${3RD_PARTY_PROTOBUF_PKG_DIR}/protobuf-all-${3RD_PARTY_PROTOBUF_VERSION}.tar.gz")
                    FindConfigurePackageDownloadFile("https://github.com/google/protobuf/releases/download/v${3RD_PARTY_PROTOBUF_VERSION}/protobuf-all-${3RD_PARTY_PROTOBUF_VERSION}.tar.gz" "${3RD_PARTY_PROTOBUF_PKG_DIR}/protobuf-all-${3RD_PARTY_PROTOBUF_VERSION}.tar.gz")
                endif ()

                FindConfigurePackageTarXV(
                    "${3RD_PARTY_PROTOBUF_PKG_DIR}/protobuf-all-${3RD_PARTY_PROTOBUF_VERSION}.tar.gz"
                    ${3RD_PARTY_PROTOBUF_PKG_DIR}
                )
            endif ()

            if (NOT EXISTS "${3RD_PARTY_PROTOBUF_PKG_DIR}/protobuf-${3RD_PARTY_PROTOBUF_VERSION}")
                EchoWithColor(COLOR RED "-- Dependency: Build protobuf failed")
                message(FATAL_ERROR "Dependency: Protobuf is required")
            endif ()

            unset(3RD_PARTY_PROTOBUF_BUILD_FLAGS)
            unset(3RD_PARTY_PROTOBUF_HOST_BUILD_FLAGS)
            list(APPEND 3RD_PARTY_PROTOBUF_BUILD_FLAGS 
                ${CMAKE_COMMAND} "${3RD_PARTY_PROTOBUF_PKG_DIR}/protobuf-${3RD_PARTY_PROTOBUF_VERSION}/cmake"
                ${3RD_PARTY_PROTOBUF_FLAG_OPTIONS} 
                "-Dprotobuf_BUILD_TESTS=OFF" "-Dprotobuf_BUILD_EXAMPLES=OFF"
                "-DBUILD_SHARED_LIBS=OFF" "-Dprotobuf_BUILD_SHARED_LIBS=OFF" "-Dprotobuf_MSVC_STATIC_RUNTIME=OFF"
                ${3RD_PARTY_PROTOBUF_BUILD_SHARED_LIBS}
            )
            list(APPEND 3RD_PARTY_PROTOBUF_HOST_BUILD_FLAGS 
                ${CMAKE_COMMAND} "${3RD_PARTY_PROTOBUF_PKG_DIR}/protobuf-${3RD_PARTY_PROTOBUF_VERSION}/cmake"
                "-Dprotobuf_BUILD_TESTS=OFF" "-Dprotobuf_BUILD_EXAMPLES=OFF"
                "-DBUILD_SHARED_LIBS=OFF" "-Dprotobuf_BUILD_SHARED_LIBS=OFF" "-Dprotobuf_MSVC_STATIC_RUNTIME=OFF"
            )

            set (3RD_PARTY_PROTOBUF_BUILD_SCRIPT_DIR "${CMAKE_CURRENT_BINARY_DIR}/deps/protobuf-${3RD_PARTY_PROTOBUF_VERSION}")
            if (NOT EXISTS ${3RD_PARTY_PROTOBUF_BUILD_SCRIPT_DIR})
                file(MAKE_DIRECTORY ${3RD_PARTY_PROTOBUF_BUILD_SCRIPT_DIR})
            endif()

            if (PROJECT_FIND_CONFIGURE_PACKAGE_PARALLEL_BUILD)
                set(3RD_PARTY_PROTOBUF_BUILD_MULTI_CORE ${FindConfigurePackageCMakeBuildMultiJobs})
            else ()
                unset(3RD_PARTY_PROTOBUF_BUILD_MULTI_CORE)
            endif ()

            string(REGEX REPLACE ";" "\" \"" 3RD_PARTY_PROTOBUF_BUILD_FLAGS_CMD "${3RD_PARTY_PROTOBUF_BUILD_FLAGS}")
            set (3RD_PARTY_PROTOBUF_BUILD_FLAGS_CMD "\"${3RD_PARTY_PROTOBUF_BUILD_FLAGS_CMD}\"")
            string(REGEX REPLACE ";" "\" \"" 3RD_PARTY_PROTOBUF_HOST_BUILD_FLAGS_CMD "${3RD_PARTY_PROTOBUF_HOST_BUILD_FLAGS}")
            set (3RD_PARTY_PROTOBUF_HOST_BUILD_FLAGS_CMD "\"${3RD_PARTY_PROTOBUF_HOST_BUILD_FLAGS_CMD}\"")

            if (CMAKE_HOST_UNIX OR MSYS)
                message(STATUS "@${3RD_PARTY_PROTOBUF_BUILD_SCRIPT_DIR} Run: run-build-release.sh")
                configure_file(
                    "${CMAKE_CURRENT_LIST_DIR}/run-build-release.sh.in" "${3RD_PARTY_PROTOBUF_BUILD_SCRIPT_DIR}/run-build-release.sh"
                    @ONLY NEWLINE_STYLE LF
                )

                # build
                execute_process(
                    COMMAND bash "${3RD_PARTY_PROTOBUF_BUILD_SCRIPT_DIR}/run-build-release.sh"
                    WORKING_DIRECTORY ${3RD_PARTY_PROTOBUF_BUILD_SCRIPT_DIR}
                )
            else ()
                configure_file(
                    "${CMAKE_CURRENT_LIST_DIR}/run-build-release.ps1.in" "${3RD_PARTY_PROTOBUF_BUILD_SCRIPT_DIR}/run-build-release.ps1"
                    @ONLY NEWLINE_STYLE CRLF
                )
                configure_file(
                    "${CMAKE_CURRENT_LIST_DIR}/run-build-release.bat.in" "${3RD_PARTY_PROTOBUF_BUILD_SCRIPT_DIR}/run-build-release.bat"
                    @ONLY NEWLINE_STYLE CRLF
                )

                find_program (3RD_PARTY_PROTOBUF_POWERSHELL_BIN NAMES pwsh pwsh.exe)
                if (NOT 3RD_PARTY_PROTOBUF_POWERSHELL_BIN)
                    find_program (3RD_PARTY_PROTOBUF_POWERSHELL_BIN NAMES powershell powershell.exe)
                endif ()
                if (NOT 3RD_PARTY_PROTOBUF_POWERSHELL_BIN)
                    EchoWithColor(COLOR RED "-- Dependency: powershell-core or powershell is required to configure protobuf")
                    message(FATAL_ERROR "powershell-core or powershell is required")
                endif ()
                # build
                message(STATUS "@${3RD_PARTY_PROTOBUF_BUILD_SCRIPT_DIR} Run: ${3RD_PARTY_PROTOBUF_POWERSHELL_BIN} -NoProfile -InputFormat None -ExecutionPolicy Bypass -NonInteractive -NoLogo -File run-build-release.ps1")
                execute_process(
                    COMMAND ${3RD_PARTY_PROTOBUF_POWERSHELL_BIN} 
                            -NoProfile -InputFormat None -ExecutionPolicy Bypass -NonInteractive -NoLogo -File
                            "${3RD_PARTY_PROTOBUF_BUILD_SCRIPT_DIR}/run-build-release.ps1"
                    WORKING_DIRECTORY ${3RD_PARTY_PROTOBUF_BUILD_SCRIPT_DIR}
                )
            endif ()
            unset(3RD_PARTY_PROTOBUF_BUILD_MULTI_CORE)
            unset(3RD_PARTY_PROTOBUF_FLAG_OPTIONS)
        endif ()

        find_package(Protobuf)
        PROJECT_LIBATBUS_3RD_PARTY_PROTOBUF_IMPORT()
    endif ()

    # try again, cached vars will cause find failed.
    if (NOT PROTOBUF_FOUND OR NOT PROTOBUF_PROTOC_EXECUTABLE OR NOT Protobuf_INCLUDE_DIRS OR NOT Protobuf_LIBRARY)
        if (CMAKE_VERSION VERSION_LESS "3.14" AND EXISTS "${3RD_PARTY_PROTOBUF_ROOT_DIR}/lib64" AND NOT EXISTS "${3RD_PARTY_PROTOBUF_ROOT_DIR}/lib")
            if (CMAKE_HOST_WIN32)
                execute_process(
                    COMMAND mklink /D "${3RD_PARTY_PROTOBUF_ROOT_DIR}/lib" "${3RD_PARTY_PROTOBUF_ROOT_DIR}/lib64"
                    WORKING_DIRECTORY ${3RD_PARTY_PROTOBUF_ROOT_DIR}
                )
            else ()
                execute_process(
                    COMMAND ln -s "${3RD_PARTY_PROTOBUF_ROOT_DIR}/lib64" "${3RD_PARTY_PROTOBUF_ROOT_DIR}/lib"
                    WORKING_DIRECTORY ${3RD_PARTY_PROTOBUF_ROOT_DIR}
                )
            endif ()
        endif()
        EchoWithColor(COLOR YELLOW "-- Dependency: Try to find protobuf libraries again")
        unset(Protobuf_LIBRARY)
        unset(Protobuf_PROTOC_LIBRARY)
        unset(Protobuf_INCLUDE_DIR)
        unset(Protobuf_PROTOC_EXECUTABLE)
        unset(Protobuf_LIBRARY_DEBUG)
        unset(Protobuf_PROTOC_LIBRARY_DEBUG)
        unset(Protobuf_LITE_LIBRARY)
        unset(Protobuf_LITE_LIBRARY_DEBUG)
        unset(Protobuf_LIBRARIES)
        unset(Protobuf_PROTOC_LIBRARIES)
        unset(Protobuf_LITE_LIBRARIES)
        unset(Protobuf::protoc)
        find_package(Protobuf)
        PROJECT_LIBATBUS_3RD_PARTY_PROTOBUF_IMPORT()
    endif()

    if(PROTOBUF_FOUND AND Protobuf_LIBRARY)
        EchoWithColor(COLOR GREEN "-- Dependency: Protobuf found.(${PROTOBUF_PROTOC_EXECUTABLE})")
        EchoWithColor(COLOR GREEN "-- Dependency: Protobuf include.(${Protobuf_INCLUDE_DIRS})")
    else()
        EchoWithColor(COLOR RED "-- Dependency: Protobuf is required")
        message(FATAL_ERROR "Protobuf not found")
    endif()
endif()

if (3RD_PARTY_PROTOBUF_BACKUP_FIND_ROOT)
    set(CMAKE_FIND_ROOT_PATH ${3RD_PARTY_PROTOBUF_BACKUP_FIND_ROOT})
    unset(3RD_PARTY_PROTOBUF_BACKUP_FIND_ROOT)
endif ()


if (3RD_PARTY_PROTOBUF_INC_DIR)
    list(APPEND PROJECT_LIBATBUS_PUBLIC_INCLUDE_DIRS ${3RD_PARTY_PROTOBUF_INC_DIR})
endif ()

if (3RD_PARTY_PROTOBUF_LINK_NAME)
    list(APPEND PROJECT_LIBATBUS_PUBLIC_LINK_NAMES ${3RD_PARTY_PROTOBUF_LINK_NAME})
endif ()

