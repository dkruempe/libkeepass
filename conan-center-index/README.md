# Conan Center Index (CCI) recipe

This directory contains a Conan 2 recipe prepared for submission to
[`conan-io/conan-center-index`](https://github.com/conan-io/conan-center-index).

## Structure

```
conan-center-index/
└── recipes/
    └── libkeepass/
        ├── config.yml
        └── all/
            ├── conanfile.py
            ├── conandata.yml
            └── test_v1_package/
                ├── CMakeLists.txt
                ├── conanfile.py
                └── test_package.cpp
```

## Submitting to Conan Center

1. Fork `https://github.com/conan-io/conan-center-index`.
2. Copy the contents of `recipes/libkeepass` into `recipes/libkeepass` in your fork.
3. Open a pull request against `conan-io/conan-center-index`.
4. The CCI CI builds the package for all supported configurations and the
   maintainers review the recipe before it is merged.

Once merged, ConanCenter builds and hosts the `libkeepass` package binaries and
it can be consumed with `[requires] libkeepass/0.2.1`.

## Local validation

From the `recipes/libkeepass/all` directory run:

```sh
conan create . --version=0.2.1 --build=missing
conan create . --version=0.2.1 --build=missing -o "libkeepass/*:shared=True"
```

The recipe fetches the sources of the tagged `v0.2.1` release from GitHub (see
`conandata.yml`) and builds static/shared libraries that are linked against
OpenSSL, zlib, pugixml and Argon2. When adding a new release, bump the version
in `conandata.yml`, `config.yml` and the test package's `requires()`.