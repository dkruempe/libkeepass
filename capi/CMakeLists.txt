cmake_minimum_required(VERSION 3.16)

# The C ABI is a thin, optional wrapper around the C++ library. It is built by
# default but can be disabled with -DLIBKEEPASS_BUILD_C_API=OFF.
if (NOT LIBKEEPASS_BUILD_C_API)
    return()
endif()

if (LIBKEEPASS_BUILD_SHARED)
    add_library(libkeepass-c SHARED libkeepass-c.cc include/libkeepass-c.h)
else()
    add_library(libkeepass-c STATIC libkeepass-c.cc include/libkeepass-c.h)
endif()

target_compile_features(libkeepass-c PUBLIC cxx_std_17)
# libkeepass-c deliberately keeps the compiler's default symbol visibility
# (unlike the C++ library, which uses hidden visibility plus LIBKEEPASS_API).
# capi/include/libkeepass-c.h has no export/visibility macro on purpose: it is
# a plain C header usable from any FFI, and the small set of kp_* entry points
# must stay exported. The C ABI therefore remains a stable, self-contained
# surface even though the C++ symbols it links against are hidden.
target_include_directories(libkeepass-c
        PUBLIC
        "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
        "$<INSTALL_INTERFACE:include>")
target_link_libraries(libkeepass-c PUBLIC libkeepass)
if (NOT DEFINED LIBKEEPASS_VERSION)
    set(LIBKEEPASS_VERSION ${PROJECT_VERSION})
endif()
target_compile_definitions(libkeepass-c PRIVATE LIBKEEPASS_VERSION="${LIBKEEPASS_VERSION}")
set_target_properties(libkeepass-c PROPERTIES
        VERSION ${LIBKEEPASS_VERSION}
        SOVERSION 0)
if (WIN32)
    set_target_properties(libkeepass-c PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
endif()

add_library(kruempelmann::libkeepass-c ALIAS libkeepass-c)

install(TARGETS libkeepass-c
        EXPORT libkeepass_targets
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        RUNTIME DESTINATION lib)
install(FILES include/libkeepass-c.h DESTINATION include)
