cmake_minimum_required(VERSION 3.16)
project(libkeepass)
set(CMAKE_MODULE_PATH ${CMAKE_BINARY_DIR})
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Link this 'library' to use the warnings specified in CompilerWarnings.cmake
add_library(project_warnings INTERFACE)

# standard compiler warnings
include(cmake/CompilerWarnings.cmake)
set_project_warnings(project_warnings)
SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin)

# Library
ADD_SUBDIRECTORY(src)
ADD_SUBDIRECTORY(sample)

# Tests
enable_testing()
ADD_SUBDIRECTORY(test)