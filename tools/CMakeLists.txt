echowithcolor(COLOR GREEN "-- Configure Tools ${CMAKE_CURRENT_LIST_DIR}")

# ============ TOOLS - [...] ============
file(GLOB TOOLS_SRC_LIST ${PROJECT_TOOLS_SRC_DIR}/*.cpp ${PROJECT_TOOLS_SRC_DIR}/*.cc ${PROJECT_TOOLS_SRC_DIR}/*.c
     ${PROJECT_TOOLS_SRC_DIR}/*.cxx)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/tools")

foreach(TOOLS_SRC_FILE IN LISTS TOOLS_SRC_LIST)
  get_filename_component(TOOLS_SRC_BIN_NAME "${TOOLS_SRC_FILE}" NAME_WE)

  add_executable("${TOOLS_SRC_BIN_NAME}" ${TOOLS_SRC_FILE})
  target_link_libraries("${TOOLS_SRC_BIN_NAME}" atframework::atbus)
  target_include_directories("${TOOLS_SRC_BIN_NAME}" PRIVATE "$<BUILD_INTERFACE:${PROJECT_TOOLS_INC_DIR}>")

  set_property(TARGET "${TOOLS_SRC_BIN_NAME}" PROPERTY FOLDER "atframework/tools/atbus")

  install(
    TARGETS "${TOOLS_SRC_BIN_NAME}"
    RUNTIME DESTINATION tools
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})

endforeach()
