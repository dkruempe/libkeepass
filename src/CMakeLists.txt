cmake_minimum_required(VERSION 3.16)
cmake_policy(SET CMP0025 NEW)
project(libkeepass_src VERSION 0.0.1)
set(CMAKE_MACOSX_RPATH OFF)
set(CMAKE_MODULE_PATH ${CMAKE_BINARY_DIR})

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)
find_package(pugixml REQUIRED)
find_package(argon2 REQUIRED)

# build
FILE(GLOB_RECURSE headers include/libkeepass/*.hh)
FILE(GLOB_RECURSE sources *.cc)

add_library(libkeepass SHARED ${headers} ${sources})

# aes_ni.cc uses AES-NI intrinsics, which are an x86/x86-64 extension. Compile
# it with the required ISA flag only on x86 architectures; on others the file
# is compiled out via its own preprocessor guard and the EVP-based AES-KDF
# fallback in Key::Transform is used instead.
if (CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64|AMD64|i[3-6]86|x86)$")
    set_source_files_properties(aes_ni.cc PROPERTIES
            COMPILE_FLAGS "-maes")
endif()
target_compile_features(libkeepass PUBLIC cxx_std_11)
target_include_directories(libkeepass
        SYSTEM PUBLIC
        "$<BUILD_INTERFACE:${OpenSSL_INCLUDES};${ZLIB_INCLUDE_DIRS};${CMAKE_CURRENT_SOURCE_DIR}/include>"
        "$<INSTALL_INTERFACE:${OpenSSL_INCLUDES};${ZLIB_INCLUDE_DIRS};include>"
        )
target_link_libraries(libkeepass PUBLIC ZLIB::ZLIB OpenSSL::SSL OpenSSL::Crypto pugixml::pugixml argon2::argon2 PRIVATE project_warnings)
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