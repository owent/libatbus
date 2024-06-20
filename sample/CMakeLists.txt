echowithcolor(COLOR GREEN "-- Configure ${CMAKE_CURRENT_LIST_DIR}")

include("${CMAKE_CURRENT_LIST_DIR}/sample.custom-macro.cmake")

# ============ sample - [...] ============

file(
  GLOB SAMPLE_SRC_LIST
  RELATIVE "${PROJECT_SAMPLE_SRC_DIR}"
  ${PROJECT_SAMPLE_SRC_DIR}/*.cpp ${PROJECT_SAMPLE_SRC_DIR}/*.cc ${PROJECT_SAMPLE_SRC_DIR}/*.c
  ${PROJECT_SAMPLE_SRC_DIR}/*.cxx)

set(CMAKE_BUILD_RPATH "${CMAKE_INSTALL_RPATH}")
if(NOT (WIN32 AND BUILD_SHARED_LIBS))
  set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/sample")
endif()

foreach(SAMPLE_SRC_FILE IN LISTS SAMPLE_SRC_LIST)
  get_filename_component(SAMPLE_SRC_BIN_NAME ${SAMPLE_SRC_FILE} NAME_WE)
  set(SAMPLE_SRC_BIN_NAME "atbus_${SAMPLE_SRC_BIN_NAME}")

  add_executable(${SAMPLE_SRC_BIN_NAME} ${SAMPLE_SRC_FILE})
  target_link_libraries(${SAMPLE_SRC_BIN_NAME} atframework::atbus)

  target_compile_options(${SAMPLE_SRC_BIN_NAME} PRIVATE ${PROJECT_LIBATBUS_PRIVATE_COMPILE_OPTIONS})

  set_property(TARGET ${SAMPLE_SRC_BIN_NAME} PROPERTY FOLDER "atframework/sample/atbus")
  if(MSVC)
    add_target_properties(${SAMPLE_SRC_BIN_NAME} LINK_FLAGS /NODEFAULTLIB:library)
  endif()
endforeach()
