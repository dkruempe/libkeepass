cmake_minimum_required(VERSION 3.16)
cmake_policy(SET CMP0025 NEW)
project(libkeepass_sample VERSION 0.0.1)
set(CMAKE_MACOSX_RPATH OFF)
set(CMAKE_MODULE_PATH ${CMAKE_BINARY_DIR})

#dependencies
if (NOT TARGET kruempelmann::libkeepass)
    find_package(libkeepass REQUIRED)
    include_directories(${libkeepass_INCLUDE_DIRS})
endif ()

find_package(GTest REQUIRED)

# build
add_executable(sample sample.cc)
target_compile_features(sample PUBLIC cxx_std_11)
target_link_libraries(sample PRIVATE GTest::GTest kruempelmann::libkeepass)