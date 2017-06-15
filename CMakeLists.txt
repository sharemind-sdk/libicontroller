#
# Copyright (C) 2015 Cybernetica
#
# Research/Commercial License Usage
# Licensees holding a valid Research License or Commercial License
# for the Software may use this file according to the written
# agreement between you and Cybernetica.
#
# GNU General Public License Usage
# Alternatively, this file may be used under the terms of the GNU
# General Public License version 3.0 as published by the Free Software
# Foundation and appearing in the file LICENSE.GPL included in the
# packaging of this file.  Please review the following information to
# ensure the GNU General Public License version 3.0 requirements will be
# met: http://www.gnu.org/copyleft/gpl-3.0.html.
#
# For further information, please contact us at sharemind@cyber.ee.
#

CMAKE_MINIMUM_REQUIRED(VERSION 2.8.12)
PROJECT(SHAREMIND_LIBICONTROLLER CXX)

SET(CPACK_PACKAGE_VERSION_MAJOR "0")
SET(CPACK_PACKAGE_VERSION_MINOR "1")
SET(CPACK_PACKAGE_VERSION_PATCH "0")
SET(SHAREMIND_LIBICONTROLLER_VERSION
    "${CPACK_PACKAGE_VERSION_MAJOR}.${CPACK_PACKAGE_VERSION_MINOR}.${CPACK_PACKAGE_VERSION_PATCH}")

INCLUDE("${CMAKE_CURRENT_SOURCE_DIR}/config.local" OPTIONAL)
INCLUDE("${CMAKE_CURRENT_BINARY_DIR}/config.local" OPTIONAL)

FIND_PACKAGE(SharemindCxxHeaders REQUIRED)

MACRO(SetList list)
  SET("${list}" tmp)
  LIST(REMOVE_ITEM "${list}" tmp)
  LIST(APPEND "${list}" ${ARGN})
ENDMACRO()

SetList(SHAREMIND_LIBICONTROLLER_EXTERNAL_INCLUDE_DIRS ${SharemindCxxHeaders_INCLUDE_DIRS})
SetList(SHAREMIND_LIBICONTROLLER_INSTALL_INCLUDE_DIRS
        "${CMAKE_INSTALL_PREFIX}/include"
        ${SHAREMIND_LIBICONTROLLER_EXTERNAL_INCLUDE_DIRS})
LIST(REMOVE_DUPLICATES SHAREMIND_LIBICONTROLLER_INSTALL_INCLUDE_DIRS)

SetList(SHAREMIND_LIBICONTROLLER_EXTERNAL_DEFINITIONS ${SharemindCxxHeaders_DEFINITIONS})
SetList(SHAREMIND_LIBICONTROLLER_INSTALL_DEFINITIONS ${SHAREMIND_LIBICONTROLLER_EXTERNAL_DEFINITIONS})

SetList(SHAREMIND_LIBICONTROLLER_EXTERNAL_LIBRARIES ${SharemindCxxHeaders_LIBRARIES})
SetList(SHAREMIND_LIBICONTROLLER_INSTALL_LIBRARIES ${SHAREMIND_LIBICONTROLLER_EXTERNAL_LIBRARIES})

FILE(GLOB_RECURSE LIBICONTROLLER_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/src/*.h")
ADD_CUSTOM_TARGET("LIBICONTROLLER_HEADERS_in_IDE" SOURCES ${LIBICONTROLLER_HEADERS})
INSTALL(FILES ${LIBICONTROLLER_HEADERS}
        DESTINATION "include/sharemind/controller"
        COMPONENT dev)

CONFIGURE_FILE(
    "${CMAKE_CURRENT_SOURCE_DIR}/SharemindLibIControllerConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/SharemindLibIControllerConfig.cmake" @ONLY)
INSTALL(FILES "${CMAKE_CURRENT_BINARY_DIR}/SharemindLibIControllerConfig.cmake"
        DESTINATION "lib/SharemindLibIController"
        COMPONENT dev)
CONFIGURE_FILE(
    "${CMAKE_CURRENT_SOURCE_DIR}/SharemindLibIControllerConfigVersion.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/SharemindLibIControllerConfigVersion.cmake" @ONLY)
INSTALL(FILES "${CMAKE_CURRENT_BINARY_DIR}/SharemindLibIControllerConfigVersion.cmake"
        DESTINATION "lib/SharemindLibIController"
        COMPONENT dev)


# Packaging:
SET(CPACK_PACKAGE_VENDOR "Cybernetica AS")
SET(CPACK_PACKAGE_CONTACT "Sharemind packaging <sharemind-packaging@cyber.ee>")
SET(CPACK_PACKAGE_DESCRIPTION_SUMMARY
    "Sharemind Client Library interface development headers")
SET(CPACK_GENERATOR "DEB")
SET(CPACK_DEBIAN_PACKAGE_NAME "libsharemind-icontroller-dev")
SET(CPACK_DEBIAN_PACKAGE_RELEASE "cyber1")
SET(CPACK_DEBIAN_COMPRESSION_TYPE "xz")
SET(CPACK_DEBIAN_PACKAGE_DEPENDS
    "libsharemind-cheaders-dev (>= 0.1.0), libstdc++-dev")
SET(CPACK_DEBIAN_PACKAGE_SECTION "libdevel")
SET(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "any")
SET(CPACK_DEBIAN_FILE_NAME "DEB-DEFAULT")
INCLUDE(CPack)
