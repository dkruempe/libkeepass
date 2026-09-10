cmake_minimum_required(VERSION 3.16)
cmake_policy(SET CMP0025 NEW)
project(libkeepass_fuzz)

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)
find_package(pugixml REQUIRED)
find_package(argon2 REQUIRED)

# Fuzzing requires clang with the integrated libFuzzer (or an OSS-Fuzz style
# $LIB_FUZZING_ENGINE linker script).
if (NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR
            "LIBKEEPASS_BUILD_FUZZING requires the Clang compiler "
            "(found ${CMAKE_CXX_COMPILER_ID}).")
endif()

if (DEFINED ENV{LIB_FUZZING_ENGINE})
    # OSS-Fuzz passes the engine as an environment variable.
    set(FUZZING_ENGINE $ENV{LIB_FUZZING_ENGINE})
    set(SANITIZER_FLAGS)
else()
    # Local builds instrument with the integrated libFuzzer plus sanitizers.
    set(FUZZING_ENGINE "-fsanitize=fuzzer")
    set(SANITIZER_FLAGS "-fsanitize=fuzzer-no-link,address,undefined")
endif()

if (SANITIZER_FLAGS)
    # The library is processed in another directory; instrument it here so the
    # coverage that guides the fuzzer is collected from the library sources too.
    target_compile_options(libkeepass PRIVATE ${SANITIZER_FLAGS})
endif()

foreach (fuzz_target fuzz_kdbx fuzz_kdb)
    add_executable(${fuzz_target} ${fuzz_target}.cc)
    target_compile_features(${fuzz_target} PRIVATE cxx_std_11)
    if (SANITIZER_FLAGS)
        # The fuzzer runs the library under AddressSanitizer/UBSanitizer, so
        # the runtime must be linked in as well (compile-only flags are not
        # enough); -fsanitize=fuzzer provides the main() entry point.
        target_compile_options(${fuzz_target} PRIVATE ${SANITIZER_FLAGS})
        target_link_options(${fuzz_target} PRIVATE "-fsanitize=address,undefined")
    endif()
    target_link_libraries(${fuzz_target} PRIVATE libkeepass ${FUZZING_ENGINE})
endforeach()