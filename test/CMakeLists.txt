cmake_minimum_required(VERSION 3.16)
cmake_policy(SET CMP0025 NEW)
project(libkeepass_test VERSION 0.2.0)
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
target_compile_features(base64 PUBLIC cxx_std_17)
target_link_libraries(base64 PRIVATE GTest::GTest GTest::Main kruempelmann::libkeepass)
add_test(NAME libkeepass.base64 COMMAND base64)

add_executable(cipher cipher.cc)
target_compile_features(cipher PUBLIC cxx_std_17)
target_link_libraries(cipher PRIVATE GTest::GTest GTest::Main kruempelmann::libkeepass)
add_test(NAME libkeepass.cipher COMMAND cipher)

add_executable(iterator iterator.cc)
target_compile_features(iterator PUBLIC cxx_std_17)
target_link_libraries(iterator PRIVATE GTest::GTest GTest::Main kruempelmann::libkeepass)
add_test(NAME libkeepass.iterator COMMAND iterator)

add_executable(kdb kdb.cc)
target_compile_features(kdb PUBLIC cxx_std_17)
target_link_libraries(kdb PRIVATE GTest::GTest GTest::Main kruempelmann::libkeepass)
add_test(NAME libkeepass.kdb COMMAND kdb)

add_executable(kdbx kdbx.cc)
target_compile_features(kdbx PUBLIC cxx_std_17)
target_link_libraries(kdbx PRIVATE GTest::GTest GTest::Main kruempelmann::libkeepass)
add_test(NAME libkeepass.kdbx COMMAND kdbx)

add_executable(kdbx4 kdbx4.cc)
target_compile_features(kdbx4 PUBLIC cxx_std_17)
target_link_libraries(kdbx4 PRIVATE GTest::GTest GTest::Main kruempelmann::libkeepass)
add_test(NAME libkeepass.kdbx4 COMMAND kdbx4)

add_executable(kdbx_header kdbx_header.cc)
target_compile_features(kdbx_header PUBLIC cxx_std_17)
target_link_libraries(kdbx_header PRIVATE GTest::GTest GTest::Main kruempelmann::libkeepass)
add_test(NAME libkeepass.kdbx_header COMMAND kdbx_header)

add_executable(key key.cc)
target_compile_features(key PUBLIC cxx_std_17)
target_link_libraries(key PRIVATE GTest::GTest GTest::Main kruempelmann::libkeepass)
add_test(NAME libkeepass.key COMMAND key)

add_executable(random random.cc)
target_compile_features(random PUBLIC cxx_std_17)
target_link_libraries(random PRIVATE GTest::GTest GTest::Main kruempelmann::libkeepass)
add_test(NAME libkeepass.random COMMAND random)

add_executable(stream stream.cc)
target_compile_features(stream PUBLIC cxx_std_17)
target_link_libraries(stream PRIVATE GTest::GTest GTest::Main kruempelmann::libkeepass)
add_test(NAME libkeepass.stream COMMAND stream)

add_executable(util util.cc)
target_compile_features(util PUBLIC cxx_std_17)
target_link_libraries(util PRIVATE GTest::GTest GTest::Main kruempelmann::libkeepass)
add_test(NAME libkeepass.util COMMAND util)

add_executable(kpx_test kpx.cc ../cli/kpx.cc ../cli/args.cc ../cli/output.cc ../cli/edit.cc)
target_compile_features(kpx_test PUBLIC cxx_std_17)
target_compile_definitions(kpx_test PRIVATE KPX_NO_MAIN=1)
target_link_libraries(kpx_test PRIVATE GTest::GTest GTest::Main kruempelmann::libkeepass)
add_test(NAME libkeepass.kpx COMMAND kpx_test)

add_executable(property property.cc)
target_compile_features(property PUBLIC cxx_std_17)
target_link_libraries(property PRIVATE GTest::GTest GTest::Main kruempelmann::libkeepass)
add_test(NAME libkeepass.property COMMAND property)

add_executable(keepass keepass.cc)
target_compile_features(keepass PUBLIC cxx_std_17)
target_link_libraries(keepass PRIVATE GTest::GTest GTest::Main kruempelmann::libkeepass)
add_test(NAME libkeepass.keepass COMMAND keepass)

add_executable(secure secure.cc)
target_compile_features(secure PUBLIC cxx_std_17)
target_link_libraries(secure PRIVATE GTest::GTest GTest::Main kruempelmann::libkeepass)
add_test(NAME libkeepass.secure COMMAND secure)

add_executable(compat compat.cc)
target_compile_features(compat PUBLIC cxx_std_17)
target_link_libraries(compat PRIVATE GTest::GTest GTest::Main kruempelmann::libkeepass)
add_test(NAME libkeepass.compat COMMAND compat)

add_executable(constant_time constant_time.cc)
target_compile_features(constant_time PUBLIC cxx_std_17)
target_link_libraries(constant_time PRIVATE GTest::GTest GTest::Main kruempelmann::libkeepass)
add_test(NAME libkeepass.constant_time COMMAND constant_time)

add_executable(robustness robustness.cc)
target_compile_features(robustness PUBLIC cxx_std_17)
target_link_libraries(robustness PRIVATE GTest::GTest GTest::Main kruempelmann::libkeepass)
add_test(NAME libkeepass.robustness COMMAND robustness)

# Standalone (non-GTest) load benchmark. Not registered as a test so that it
# never gates the build; run it explicitly or from CI to track load times.
add_executable(benchmark benchmark.cc)
target_compile_features(benchmark PUBLIC cxx_std_17)
target_link_libraries(benchmark PRIVATE kruempelmann::libkeepass)
