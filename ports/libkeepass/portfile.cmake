cmake_minimum_required(VERSION 3.16)

vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO dkruempe/libkeepass
    REF v0.3.0
    SHA512 41d35b29d7273f0e9bb0efb26613f6f9fad7b5cdfd6a09595ab62b106efd401a09c425109f4f6e2bd1e5f6aafe05bdd3f054a7fbcbae22b3501fb47540937660
    HEAD_REF master
)

string(COMPARE EQUAL "${VCPKG_LIBRARY_LINKAGE}" "dynamic" LIBKEEPASS_BUILD_SHARED)

vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}"
    OPTIONS
        -DLIBKEEPASS_CONAN_CREATE=ON
        -DBUILD_TESTING=OFF
        -DLIBKEEPASS_BUILD_SHARED=${LIBKEEPASS_BUILD_SHARED}
)

vcpkg_cmake_install()
vcpkg_cmake_config_fixup(PACKAGE_NAME libkeepass CONFIG_PATH lib/cmake/libkeepass)
vcpkg_copy_pdbs()
vcpkg_fixup_pkgconfig()

file(REMOVE_RECURSE
    "${CURRENT_PACKAGES_DIR}/debug/include"
    "${CURRENT_PACKAGES_DIR}/debug/share"
)

vcpkg_install_copyright(FILE_LIST "${SOURCE_PATH}/COPYING")
