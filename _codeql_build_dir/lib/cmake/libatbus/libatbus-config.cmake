#[=======================================================================[.rst:
libatbus-config.cmake
---------------------

Find the native libatbus includes and library.


Result Variables
^^^^^^^^^^^^^^^^

This module defines the following variables:

``Libatbus_INCLUDE_DIRS``
  Where to find detail/libatbus_config.h , etc.
``Libatbus_PROTOCOL_DIRS``
  Where to find libatbus_protocol.proto , etc.
``Libatbus_LIBRARY_DIRS``
  Where to find (lib)atbus.(a/so/lib/dll/dylib), etc.
``Libatbus_LIBRARIES``
  List of libraries when using libatbus.
``Libatbus_FOUND``
  True if libatbus found.
``Libatbus_VERSION``
  Full version of libatbus


The following :prop_tgt:`IMPORTED` targets are also defined:

``atframework::atbus``
  The libatbus library

=============================================================================
Copyright 2026 OWenT.

Distributed under the OSI-approved BSD License (the "License");
see accompanying file Copyright.txt for details.

This software is distributed WITHOUT ANY WARRANTY; without even the
implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the License for more information.
=============================================================================
(To distribute this file outside of CMake, substitute the full License text for
the above reference.)

#]=======================================================================]

set(${CMAKE_FIND_PACKAGE_NAME}_VERSION "3.0.0")


####### Expanded from @PACKAGE_INIT@ by configure_package_config_file() #######
####### Any changes to this file will be overwritten by the next CMake run ####
####### The input file was libatbus-config.cmake.in                            ########

get_filename_component(PACKAGE_PREFIX_DIR "${CMAKE_CURRENT_LIST_DIR}/../../../" ABSOLUTE)

macro(set_and_check _var _file)
  set(${_var} "${_file}")
  if(NOT EXISTS "${_file}")
    message(FATAL_ERROR "File or directory ${_file} referenced by variable ${_var} does not exist !")
  endif()
endmacro()

####################################################################################

# ######################################################################################################################
# libatbus source dir
set(${CMAKE_FIND_PACKAGE_NAME}_SOURCE_DIR "/home/runner/work/libatbus/libatbus")

set_and_check(${CMAKE_FIND_PACKAGE_NAME}_INCLUDE_DIRS "${PACKAGE_PREFIX_DIR}/include")
set_and_check(${CMAKE_FIND_PACKAGE_NAME}_LIBRARY_DIRS "${PACKAGE_PREFIX_DIR}/lib")
set_and_check(${CMAKE_FIND_PACKAGE_NAME}_PROTOCOL_DIRS "${PACKAGE_PREFIX_DIR}/include")

include("${CMAKE_CURRENT_LIST_DIR}/libatbus-target.cmake")
if(EXISTS "${CMAKE_CURRENT_LIST_DIR}/libatbus-target.cmake")
  include("${CMAKE_CURRENT_LIST_DIR}/libatbus-target.cmake")
endif()
# Normal search.
set(${CMAKE_FIND_PACKAGE_NAME}_LIBRARIES atframework::atbus)

# handle the QUIETLY and REQUIRED arguments and set LIBATBUS_FOUND to TRUE if all listed variables are TRUE
include("FindPackageHandleStandardArgs")
find_package_handle_standard_args(
  ${CMAKE_FIND_PACKAGE_NAME}
  FOUND_VAR ${CMAKE_FIND_PACKAGE_NAME}_FOUND
  REQUIRED_VARS ${CMAKE_FIND_PACKAGE_NAME}_INCLUDE_DIRS ${CMAKE_FIND_PACKAGE_NAME}_LIBRARIES)

if(${CMAKE_FIND_PACKAGE_NAME}_FOUND)
  set(LIBATBUS_FOUND ${${CMAKE_FIND_PACKAGE_NAME}_FOUND})
endif()

# check_required_components(${CMAKE_FIND_PACKAGE_NAME})

