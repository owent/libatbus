if (CMAKE_VERSION VERSION_GREATER_EQUAL "3.10")
    include_guard(GLOBAL)
endif()

# =========== 3rdparty atframe_utils ==================
if(NOT 3RD_PARTY_ATFRAME_UTILS_BASE_DIR)
    set (3RD_PARTY_ATFRAME_UTILS_BASE_DIR ${CMAKE_CURRENT_LIST_DIR})
endif()

if (ATFRAME_UTILS_ROOT)
    set (3RD_PARTY_ATFRAME_UTILS_PKG_DIR ${ATFRAME_UTILS_ROOT})
else()
    set (3RD_PARTY_ATFRAME_UTILS_PKG_DIR "${3RD_PARTY_ATFRAME_UTILS_BASE_DIR}/repo")
    find_package(Git)
    if(NOT EXISTS ${3RD_PARTY_ATFRAME_UTILS_PKG_DIR})
        execute_process(COMMAND ${GIT_EXECUTABLE} config "remote.origin.url"
            OUTPUT_VARIABLE PROJECT_GIT_REMOTE_ORIGIN_URL
            WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )
        string(REGEX MATCH "^http(s?):" PROJECT_GIT_REMOTE_ORIGIN_USE_SSH "${PROJECT_GIT_REMOTE_ORIGIN_URL}")
        if (PROJECT_GIT_REMOTE_ORIGIN_USE_SSH)
            execute_process(COMMAND ${GIT_EXECUTABLE} clone --depth=100 -b master "git@github.com:atframework/atframe_utils.git" ${3RD_PARTY_ATFRAME_UTILS_PKG_DIR}
                WORKING_DIRECTORY ${3RD_PARTY_ATFRAME_UTILS_BASE_DIR}
            )
        else ()
            execute_process(COMMAND ${GIT_EXECUTABLE} clone --depth=100 -b master "https://github.com/atframework/atframe_utils.git" ${3RD_PARTY_ATFRAME_UTILS_PKG_DIR}
                WORKING_DIRECTORY ${3RD_PARTY_ATFRAME_UTILS_BASE_DIR}
            )
        endif()
    elseif(PROJECT_RESET_DENPEND_REPOSITORIES)
        execute_process(
            COMMAND ${GIT_EXECUTABLE} fetch -f --depth=100 origin
            COMMAND ${GIT_EXECUTABLE} reset --hard origin/master
            WORKING_DIRECTORY ${3RD_PARTY_ATFRAME_UTILS_PKG_DIR}
        )
    endif()
endif()

set (3RD_PARTY_ATFRAME_UTILS_INC_DIR "${3RD_PARTY_ATFRAME_UTILS_PKG_DIR}/include")
set (3RD_PARTY_ATFRAME_UTILS_SRC_DIR "${3RD_PARTY_ATFRAME_UTILS_PKG_DIR}/src")
set (3RD_PARTY_ATFRAME_UTILS_LINK_NAME atframe_utils)
