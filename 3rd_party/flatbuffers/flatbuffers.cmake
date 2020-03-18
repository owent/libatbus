if (CMAKE_VERSION VERSION_GREATER_EQUAL "3.10")
    include_guard(GLOBAL)
endif()

# =========== 3rdparty flatbuffer ==================
if(NOT 3RD_PARTY_FLATBUFFER_BASE_DIR)
    set (3RD_PARTY_FLATBUFFER_BASE_DIR ${CMAKE_CURRENT_LIST_DIR})
endif()

if (NOT TARGET flatbuffers::flatc OR NOT TARGET flatbuffers::flatbuffers)
    set (3RD_PARTY_FLATBUFFER_REPO_DIR "${3RD_PARTY_FLATBUFFER_BASE_DIR}/repo")
    set (3RD_PARTY_FLATBUFFER_PKG_DIR "${3RD_PARTY_FLATBUFFER_BASE_DIR}/pkg")
    set (3RD_PARTY_FLATBUFFER_VERSION 1.11.0)
    if (NOT Flatbuffers_ROOT)
        set (Flatbuffers_ROOT "${3RD_PARTY_FLATBUFFER_BASE_DIR}/prebuilt/${PROJECT_PREBUILT_PLATFORM_NAME}")
    endif ()

    if ( NOT EXISTS ${3RD_PARTY_FLATBUFFER_PKG_DIR})
        message(STATUS "mkdir 3RD_PARTY_FLATBUFFER_PKG_DIR=${3RD_PARTY_FLATBUFFER_PKG_DIR}")
        file(MAKE_DIRECTORY ${3RD_PARTY_FLATBUFFER_PKG_DIR})
    endif ()
    FindConfigurePackage(
        PACKAGE Flatbuffers
        BUILD_WITH_CMAKE
        CMAKE_FLAGS -DFLATBUFFERS_CODE_COVERAGE=OFF -DFLATBUFFERS_BUILD_TESTS=OFF -DFLATBUFFERS_INSTALL=ON -DFLATBUFFERS_BUILD_FLATLIB=ON -DFLATBUFFERS_BUILD_FLATC=ON -DFLATBUFFERS_BUILD_FLATHASH=ON -DFLATBUFFERS_BUILD_GRPCTEST=OFF -DFLATBUFFERS_BUILD_SHAREDLIB=OFF
        WORKING_DIRECTORY ${3RD_PARTY_FLATBUFFER_PKG_DIR}
        BUILD_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/deps/flatbuffers-${3RD_PARTY_FLATBUFFER_VERSION}/build_jobs_${PROJECT_PREBUILT_PLATFORM_NAME}"
        PREFIX_DIRECTORY ${Flatbuffers_ROOT}
        SRC_DIRECTORY_NAME "flatbuffers-${3RD_PARTY_FLATBUFFER_VERSION}"
        TAR_URL "https://github.com/google/flatbuffers/archive/v${3RD_PARTY_FLATBUFFER_VERSION}.tar.gz"
        ZIP_URL "https://github.com/google/flatbuffers/archive/v${3RD_PARTY_FLATBUFFER_VERSION}.zip"
    )


    if (NOT TARGET flatbuffers::flatc OR NOT TARGET flatbuffers::flatbuffers)
        EchoWithColor(COLOR RED "-- Dependency: Flatbuffer is required but not found")
        message(FATAL_ERROR "Flatbuffer not found")
    endif()

    get_target_property(3RD_PARTY_FLATBUFFER_INC_DIR flatbuffers::flatbuffers INTERFACE_INCLUDE_DIRECTORIES)
    include_directories(${3RD_PARTY_FLATBUFFER_INC_DIR})

    EchoWithColor(COLOR GREEN "-- Dependency: Flatbuffer ${Flatbuffer_VERSION} found.(${3RD_PARTY_FLATBUFFER_INC_DIR})")
endif ()