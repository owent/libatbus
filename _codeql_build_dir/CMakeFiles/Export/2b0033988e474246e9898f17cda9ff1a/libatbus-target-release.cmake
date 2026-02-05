#----------------------------------------------------------------
# Generated CMake target import file for configuration "Release".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "atframework::atbus" for configuration "Release"
set_property(TARGET atframework::atbus APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(atframework::atbus PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/libatbus.a"
  )

list(APPEND _cmake_import_check_targets atframework::atbus )
list(APPEND _cmake_import_check_files_for_atframework::atbus "${_IMPORT_PREFIX}/lib/libatbus.a" )

# Import target "atframework::atbus-protocol" for configuration "Release"
set_property(TARGET atframework::atbus-protocol APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(atframework::atbus-protocol PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/libatbus-protocol.a"
  )

list(APPEND _cmake_import_check_targets atframework::atbus-protocol )
list(APPEND _cmake_import_check_files_for_atframework::atbus-protocol "${_IMPORT_PREFIX}/lib/libatbus-protocol.a" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
