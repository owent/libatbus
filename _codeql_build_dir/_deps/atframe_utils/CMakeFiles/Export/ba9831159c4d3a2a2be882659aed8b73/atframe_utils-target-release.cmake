#----------------------------------------------------------------
# Generated CMake target import file for configuration "Release".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "atframework::atframe_utils" for configuration "Release"
set_property(TARGET atframework::atframe_utils APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(atframework::atframe_utils PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/libatframe_utils.a"
  )

list(APPEND _cmake_import_check_targets atframework::atframe_utils )
list(APPEND _cmake_import_check_files_for_atframework::atframe_utils "${_IMPORT_PREFIX}/lib/libatframe_utils.a" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
