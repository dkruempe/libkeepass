# Introduction

libkeepass is a C++11 library for importing and exporting
[KeePass](http://keepass.info) password databases. It supports importing and
exporting from/to both the legacy KDB format, as well as the new KDBX format.

# Building

The following 3rd party libraries are required to build libkeepass:

* [OpenSSL](https://www.openssl.org/)
* [zlib](http://zlib.net)
* [pugixml](https://pugixml.org)

For running the unit tests [gtest](https://code.google.com/p/googletest/)
is also required.

To build, simply do the following:

1. make sure that conan is installed
2. create build directory
3. install libraries via

```sh
conan install . --output-folder=build --build=missing
````
4. change directory via cd command
5. cmake

```sh
cmake .. -DCMAKE_TOOLCHAIN_FILE=conan_toolchain.cmake -DCMAKE_BUILD_TYPE=Release -GNinja
```

6. build

```sh
ninja
```

to run the unit tests, do the following in the build directory:

```sh
ninja test
```

# Using

The main library entry points are the *KdbFile* and *KdbxFile* classes. They
take care of both importing and exporting.

Example:

```cpp
keepass::Key key("password");

keepass::KdbxFile file;
std::unique_ptr<keepass::Database> db = file.Import("in.kdbx", key);

// Do some operations using the database object.

file.Export("out.kdbx", *db.get(), key);
```
