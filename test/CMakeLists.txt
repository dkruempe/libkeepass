cmake_minimum_required(VERSION 3.16)
cmake_policy(SET CMP0025 NEW)
project(libkeepass_test VERSION 0.0.1)
set(CMAKE_MACOSX_RPATH OFF)
set(CMAKE_MODULE_PATH ${CMAKE_BINARY_DIR})

# configuration of default path
if (NOT DEFINED PROJECT_ROOT_PATH)
    set(PROJECT_ROOT_PATH "${PROJECT_SOURCE_DIR}")
endif ()

configure_file(
        ${PROJECT_SOURCE_DIR}/config.hh.in
        ${PROJECT_SOURCE_DIR}/config.hh)

#dependencies
if (NOT TARGET kruempelmann::libkeepass)
    find_package(libkeepass REQUIRED)
    include_directories(${libkeepass_INCLUDE_DIRS})
endif ()

find_package(GTest REQUIRED)

# build
add_executable(base64 base64.cc)
target_compile_features(base64 PUBLIC cxx_std_11)
target_link_libraries(base64 PRIVATE GTest::GTest GTest::Main kruempelmann::libkeepass)
add_test(NAME libkeepass.base64 COMMAND base64)

add_executable(cipher cipher.cc)
target_compile_features(cipher PUBLIC cxx_std_11)
target_link_libraries(cipher PRIVATE GTest::GTest GTest::Main kruempelmann::libkeepass)
add_test(NAME libkeepass.cipher COMMAND cipher)

add_executable(iterator iterator.cc)
target_compile_features(iterator PUBLIC cxx_std_11)
target_link_libraries(iterator PRIVATE GTest::GTest GTest::Main kruempelmann::libkeepass)
add_test(NAME libkeepass.iterator COMMAND iterator)

add_executable(kdb kdb.cc)
target_compile_features(kdb PUBLIC cxx_std_11)
target_link_libraries(kdb PRIVATE GTest::GTest GTest::Main kruempelmann::libkeepass)
add_test(NAME libkeepass.kdb COMMAND kdb)

add_executable(kdbx kdbx.cc)
target_compile_features(kdbx PUBLIC cxx_std_11)
target_link_libraries(kdbx PRIVATE GTest::GTest GTest::Main kruempelmann::libkeepass)
add_test(NAME libkeepass.kdbx COMMAND kdbx)

add_executable(stream stream.cc)
target_compile_features(stream PUBLIC cxx_std_11)
target_link_libraries(stream PRIVATE GTest::GTest GTest::Main kruempelmann::libkeepass)
add_test(NAME libkeepass.stream COMMAND stream)

add_executable(util util.cc)
target_compile_features(util PUBLIC cxx_std_11)
target_link_libraries(util PRIVATE GTest::GTest GTest::Main kruempelmann::libkeepass)
add_test(NAME libkeepass.util COMMAND util)
