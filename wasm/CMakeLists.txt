cmake_minimum_required(VERSION 3.16)
project(libkeepass_wasm LANGUAGES C CXX)

# Build with:
#   emcmake cmake -S wasm -B build-wasm -DLIBKEEPASS_SOURCE_DIR=..
# See wasm/README.md for the dependency notes (OpenSSL/Argon2 must be built
# for wasm32; zlib can use the Emscripten port).
if (NOT EMSCRIPTEN)
    message(FATAL_ERROR "This target must be configured through emcmake/emscripten.")
endif()

set(LIBKEEPASS_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/.." CACHE PATH
    "Path to the libkeepass source tree")
set(LIBKEEPASS_COMPONENT_KDB ON CACHE BOOL "" FORCE)
set(LIBKEEPASS_COMPONENT_KDBX ON CACHE BOOL "" FORCE)
set(LIBKEEPASS_BUILD_C_API ON CACHE BOOL "" FORCE)
set(LIBKEEPASS_BUILD_SHARED ON CACHE BOOL "" FORCE)

add_subdirectory("${LIBKEEPASS_SOURCE_DIR}/src" libkeepass-src)
add_subdirectory("${LIBKEEPASS_SOURCE_DIR}/capi" libkeepass-capi)

add_executable(libkeepass-demo demo.cc)
target_link_libraries(libkeepass-demo PRIVATE kruempelmann::libkeepass-c)

set_target_properties(libkeepass-demo PROPERTIES
    OUTPUT_NAME "libkeepass-demo"
    SUFFIX ".js"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/web")

target_link_options(libkeepass-demo PRIVATE
    "-sEXPORTED_RUNTIME_METHODS=['ccall','UTF8ToString','stringToNewUTF8']"
    "-sEXPORTED_FUNCTIONS=['_malloc','_free']"
    "-sALLOW_MEMORY_GROWTH=1"
    "-sFILESYSTEM=0"
    "-O3")

# Copy the static page next to the generated module.
add_custom_command(TARGET libkeepass-demo POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_CURRENT_SOURCE_DIR}/index.html"
            "${CMAKE_BINARY_DIR}/web/index.html")
