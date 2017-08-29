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

CMAKE_MINIMUM_REQUIRED(VERSION 3.0)
PROJECT(SharemindLibIController VERSION 0.1.0 LANGUAGES CXX)

INCLUDE("${CMAKE_CURRENT_SOURCE_DIR}/config.local" OPTIONAL)
INCLUDE("${CMAKE_CURRENT_BINARY_DIR}/config.local" OPTIONAL)

FIND_PACKAGE(SharemindCMakeHelpers REQUIRED)


FIND_PACKAGE(SharemindCxxHeaders REQUIRED)


# Headers:
FILE(GLOB_RECURSE SharemindLibIController_HEADERS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.h")
ADD_CUSTOM_TARGET("SharemindLibIController_HEADERS_in_IDE"
    SOURCES ${SharemindLibIController_HEADERS})
INSTALL(FILES ${SharemindLibIController_HEADERS}
        DESTINATION "include/sharemind/controller"
        COMPONENT "dev")


# Install CMake files:
SharemindNewUniqueList(SharemindLibIController_INSTALL_INCLUDE_DIRS
    "${CMAKE_INSTALL_PREFIX}/include"
    ${SharemindCxxHeaders_INCLUDE_DIRS}
)
SharemindNewUniqueList(SharemindLibIController_INSTALL_DEFINITIONS
    ${SharemindCxxHeaders_DEFINITIONS}
)
SharemindNewUniqueList(SharemindLibIController_INSTALL_LIBRARIES
    ${SharemindCxxHeaders_LIBRARIES}
)
SharemindUseCMakeFindFiles()


# Packaging:
SharemindSetupPackaging()
SharemindAddComponentPackage("dev"
    NAME "libsharemind-icontroller-dev"
    DESCRIPTION "Sharemind Client Library interface development headers"
    DEB_SECTION "libdevel"
    DEB_DEPENDS
        "libsharemind-cxxheaders-dev (>= 0.1.0)"
        "libstdc++-dev"
)
SharemindPackagingFinalize()
