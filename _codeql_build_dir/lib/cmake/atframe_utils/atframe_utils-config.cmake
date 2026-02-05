#.rst:
# atframe_utils-config.cmake
# --------
#
# Find the native atframe_utils includes and library.
#
#
# Result Variables
# ^^^^^^^^^^^^^^^^
#
# This module defines the following variables:
#
# ::
#
#   Libatframe_utils_INCLUDE_DIRS       - where to find config/atframe_utils_build_feature.h , etc.
#   Libatframe_utils_LIBRARY_DIRS       - where to find (lib)atframe_utils.(a/so/lib/dll/dylib), etc.
#   Libatframe_utils_LIBRARIES          - List of static libraries when using atframe_utils.
#   Libatframe_utils_FOUND              - True if atframe_utils found.
#   Libatframe_utils_VERSION            - Full version of atframe_utils
#
# ::
#   atframework::atframe_utils          - Imported target of atframe_utils
#
#
# =============================================================================
# Copyright 2019 OWenT.
#
# Distributed under the OSI-approved BSD License (the "License"); see accompanying file Copyright.txt for details.
#
# This software is distributed WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
# PURPOSE. See the License for more information.
# =============================================================================
# (To distribute this file outside of CMake, substitute the full License text for the above reference.)

set(${CMAKE_FIND_PACKAGE_NAME}_VERSION "2.8.1")


####### Expanded from @PACKAGE_INIT@ by configure_package_config_file() #######
####### Any changes to this file will be overwritten by the next CMake run ####
####### The input file was atframe_utils-config.cmake.in                            ########

get_filename_component(PACKAGE_PREFIX_DIR "${CMAKE_CURRENT_LIST_DIR}/../../../" ABSOLUTE)

macro(set_and_check _var _file)
  set(${_var} "${_file}")
  if(NOT EXISTS "${_file}")
    message(FATAL_ERROR "File or directory ${_file} referenced by variable ${_var} does not exist !")
  endif()
endmacro()

####################################################################################

# ######################################################################################################################
# ${CMAKE_FIND_PACKAGE_NAME} source dir
set(${CMAKE_FIND_PACKAGE_NAME}_SOURCE_DIR "/home/runner/work/libatbus/libatbus/atframework/atframe_utils")

set_and_check(${CMAKE_FIND_PACKAGE_NAME}_INCLUDE_DIRS "${PACKAGE_PREFIX_DIR}/include")
set_and_check(${CMAKE_FIND_PACKAGE_NAME}_LIBRARY_DIRS "${PACKAGE_PREFIX_DIR}/lib")

include("${CMAKE_CURRENT_LIST_DIR}/atframe_utils-target.cmake")

# Normal search.
set(${CMAKE_FIND_PACKAGE_NAME}_LIBRARIES atframework::atframe_utils)

# handle the QUIETLY and REQUIRED arguments and set ${CMAKE_FIND_PACKAGE_NAME}_FOUND to TRUE if all listed variables are
# TRUE
include("FindPackageHandleStandardArgs")
find_package_handle_standard_args(
  ${CMAKE_FIND_PACKAGE_NAME}
  FOUND_VAR ${CMAKE_FIND_PACKAGE_NAME}_FOUND
  REQUIRED_VARS ${CMAKE_FIND_PACKAGE_NAME}_INCLUDE_DIRS)

if(${CMAKE_FIND_PACKAGE_NAME}_FOUND)
  set(ATFRAMEWORK_UTILS_FOUND ${${CMAKE_FIND_PACKAGE_NAME}_FOUND})
endif()

# check_required_components(${CMAKE_FIND_PACKAGE_NAME})
