# =========== include - macro ===========
set (PROJECT_LIBATBUS_ROOT_INC_DIR ${CMAKE_CURRENT_LIST_DIR})

# define CONF from cmake to c macro
configure_file(
    "${CMAKE_CURRENT_LIST_DIR}/detail/libatbus_config.h.in"
    "${CMAKE_CURRENT_LIST_DIR}/detail/libatbus_config.h"
    @ONLY
)
