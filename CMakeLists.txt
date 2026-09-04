cmake_minimum_required(VERSION 3.16)
list(APPEND CMAKE_PROJECT_TOP_LEVEL_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/conan_provider.cmake)
project(libkeepass VERSION 0.1.0)
set(CMAKE_MODULE_PATH ${CMAKE_BINARY_DIR})
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Link this 'library' to use the warnings specified in CompilerWarnings.cmake
add_library(project_warnings INTERFACE)

# standard compiler warnings
include(cmake/CompilerWarnings.cmake)
set_project_warnings(project_warnings)
SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin)
SET(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin)
SET(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin)

# Library
ADD_SUBDIRECTORY(src)
ADD_SUBDIRECTORY(cli)

# Tests
enable_testing()
ADD_SUBDIRECTORY(test)

# Packaging (CPack)
set(CPACK_PACKAGE_NAME libkeepass)
set(CPACK_PACKAGE_VENDOR "Dominik Kruempelmann")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_VERSION_MAJOR ${PROJECT_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${PROJECT_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${PROJECT_VERSION_PATCH})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY
        "C++11 library for importing and exporting KeePass password databases")
set(CPACK_PACKAGE_HOMEPAGE_URL "https://github.com/dkruempe/libkeepass")
set(CPACK_PACKAGE_LICENSE "GPL-3.0")
set(CPACK_PACKAGE_MAINTAINERS "Dominik Kruempelmann")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/COPYING")
set(CPACK_RESOURCE_FILE_README "${CMAKE_CURRENT_SOURCE_DIR}/README.md")

if (UNIX AND NOT APPLE)
    set(CPACK_GENERATOR "TGZ;DEB;RPM")
else()
    set(CPACK_GENERATOR "TGZ;ZIP")
endif()

# Native package dependency lists depend on the target distribution and may
# need to be adapted (override them on the command line if required).
set(CPACK_DEBIAN_PACKAGE_DEPENDS
        "libssl3, zlib1g, libpugixml1.12, libargon2-1"
        CACHE STRING "Debian package dependencies")
set(CPACK_DEBIAN_PACKAGE_SECTION "libs")
set(CPACK_DEBIAN_PACKAGE_PRIORITY "optional")

set(CPACK_RPM_PACKAGE_REQUIRES
        "openssl-libs, zlib, libpugixml, argon2-libs"
        CACHE STRING "RPM package dependencies")
set(CPACK_RPM_PACKAGE_LICENSE "GPLv3")
set(CPACK_RPM_PACKAGE_GROUP "Development/Libraries")

include(CPack)
