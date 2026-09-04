cmake_minimum_required(VERSION 3.16)
cmake_policy(SET CMP0025 NEW)
project(libkeepass_cli VERSION 0.2.0)
set(CMAKE_MACOSX_RPATH ON)
set(CMAKE_MODULE_PATH ${CMAKE_BINARY_DIR})

# dependencies
if (NOT TARGET kruempelmann::libkeepass)
    find_package(libkeepass REQUIRED)
endif ()

add_executable(kpx kpx.cc)
target_compile_features(kpx PUBLIC cxx_std_11)
target_link_libraries(kpx PRIVATE kruempelmann::libkeepass)

if (UNIX AND NOT APPLE)
    set_target_properties(kpx PROPERTIES INSTALL_RPATH "$ORIGIN/../lib")
elseif (APPLE)
    set_target_properties(kpx PROPERTIES INSTALL_RPATH "@loader_path/../lib")
endif ()

install(TARGETS kpx RUNTIME DESTINATION bin)