cmake_minimum_required(VERSION 3.16)
cmake_policy(SET CMP0025 NEW)
project(libkeepass_src VERSION 0.0.1)
set(CMAKE_MACOSX_RPATH OFF)
set(CMAKE_MODULE_PATH ${CMAKE_BINARY_DIR})

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)

# build
FILE(GLOB_RECURSE headers include/libkeepass/*.hh)
FILE(GLOB_RECURSE sources *.cc)

add_library(libkeepass SHARED ${headers} ${sources})
target_compile_features(libkeepass PUBLIC cxx_std_11)
target_include_directories(libkeepass
        SYSTEM PUBLIC
        "$<BUILD_INTERFACE:${OpenSSL_INCLUDES};${ZLIB_INCLUDE_DIRS};${CMAKE_CURRENT_SOURCE_DIR}/include>"
        "$<INSTALL_INTERFACE:${OpenSSL_INCLUDES};${ZLIB_INCLUDE_DIRS};include>"
        )
target_link_libraries(libkeepass PUBLIC ZLIB::ZLIB OpenSSL::SSL OpenSSL::Crypto PRIVATE project_warnings)
add_library(kruempelmann::libkeepass ALIAS libkeepass)
INSTALL(TARGETS libkeepass
        EXPORT libkeepass_targets
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        RUNTIME DESTINATION lib
        INCLUDES DESTINATION include)
INSTALL(EXPORT libkeepass_targets
        DESTINATION lib/cmake/libkeepass
        FILE libkeepass_targets.cmake
        NAMESPACE kruempelmann::)
INSTALL(DIRECTORY include
        DESTINATION include)

# library package version file
include(CMakePackageConfigHelpers)
write_basic_package_version_file(libkeepass_config_version.cmake
        COMPATIBILITY SameMajorVersion)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libkeepass_config_version.cmake ${CMAKE_CURRENT_BINARY_DIR}/libkeepass_config_version.cmake
        DESTINATION lib/cmake/libkeepass)