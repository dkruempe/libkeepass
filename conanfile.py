import os
import re

from conan import ConanFile
from conan.errors import ConanException
from conan.tools.cmake import CMake, CMakeToolchain, cmake_layout
from conan.tools.files import copy


class LibkeepassConan(ConanFile):
    name = "libkeepass"
    license = "GPL-3.0"
    url = "https://github.com/dkruempe/libkeepass"
    homepage = "https://github.com/dkruempe/libkeepass"
    description = "C++11 library for importing and exporting KeePass password databases"
    topics = ("keepass", "password", "database", "security", "kdbx")

    settings = "os", "arch", "compiler", "build_type"
    options = {"shared": [True, False], "fPIC": [True, False]}
    default_options = {"shared": False, "fPIC": True}

    generators = "CMakeDeps"

    exports_sources = (
        "CMakeLists.txt",
        "conan_provider.cmake",
        "COPYING",
        "README.md",
        "cmake/*",
        "cli/*",
        "src/*",
        "test/*",
    )

    def set_version(self):
        # The working directory and the folder attributes point to different
        # locations depending on the flow (conan install via the CMake provider
        # runs from the build directory, conan create from the source folder).
        candidates = [os.getcwd()]
        for attribute in ("source_folder", "recipe_folder"):
            folder = getattr(self, attribute, None)
            if folder:
                candidates.append(folder)
        for folder in candidates:
            path = os.path.join(folder, "CMakeLists.txt")
            if not os.path.isfile(path):
                continue
            with open(path, encoding="utf-8") as handle:
                match = re.search(r"project\(libkeepass VERSION (\d+\.\d+\.\d+)\)", handle.read())
            if match:
                self.version = match.group(1)
                return
        raise ConanException("Could not read the libkeepass version from CMakeLists.txt")

    def config_options(self):
        if self.settings.os == "Windows":
            del self.options.fPIC

    def configure(self):
        if self.options.shared:
            del self.options.fPIC

    def requirements(self):
        self.requires("openssl/3.5.7")
        self.requires("zlib/1.3.2")
        self.requires("pugixml/1.16")
        self.requires("argon2/20190702")
        # Keep GoogleTest in the dependency graph so that the in-tree build
        # (conan install via the CMake convention provider) can build the tests.
        # It is marked invisible so it is not propagated to consumers.
        self.requires("gtest/1.18.0", visible=False)

    def layout(self):
        cmake_layout(self)

    def generate(self):
        cmake_toolchain = CMakeToolchain(self)
        cmake_toolchain.generate()

    def build(self):
        cmake = CMake(self)
        cmake.configure(
            variables={
                "LIBKEEPASS_CONAN_CREATE": "ON",
                "BUILD_TESTING": "OFF",
                "LIBKEEPASS_BUILD_SHARED": "ON" if self.options.shared else "OFF",
            }
        )
        cmake.build()

    def package(self):
        copy(self, "COPYING", src=self.source_folder, dst=os.path.join(self.package_folder, "licenses"))
        cmake = CMake(self)
        cmake.install()

    def package_info(self):
        self.cpp_info.libs = ["libkeepass"]
        self.cpp_info.requires = [
            "openssl::openssl",
            "zlib::zlib",
            "pugixml::pugixml",
            "argon2::argon2",
        ]
        self.cpp_info.set_property("cmake_file_name", "libkeepass")
        self.cpp_info.set_property("cmake_target_name", "kruempelmann::libkeepass")
        self.cpp_info.set_property("cmake_target_aliases", ["libkeepass"])
        self.cpp_info.set_property("pkg_config_name", "libkeepass")