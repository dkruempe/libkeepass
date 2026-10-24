# libkeepass vcpkg port

This directory contains a [vcpkg](https://vcpkg.io/) port for libkeepass. It is
kept in-tree so it can be tested with a local overlay before being submitted to
the vcpkg registry:

```sh
vcpkg install libkeepass --overlay-ports=ports
```

The port builds the library without the test suite (`BUILD_TESTING=OFF`) and
with the Conan provider disabled (`LIBKEEPASS_CONAN_CREATE=ON`), so vcpkg
provides all dependencies through its own CMake toolchain. The installed CMake
package remains `find_package(libkeepass CONFIG REQUIRED)` with the imported
target `kruempelmann::libkeepass`.

The `SHA512` in `portfile.cmake` must be updated together with the `v0.3.0`
tag when a new release is published.
