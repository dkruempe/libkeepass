# libkeepass

[![Build](https://github.com/dkruempe/libkeepass/actions/workflows/cmake.yml/badge.svg)](https://github.com/dkruempe/libkeepass/actions/workflows/cmake.yml)
[![codecov](https://codecov.io/gh/dkruempe/libkeepass/graph/badge.svg)](https://codecov.io/gh/dkruempe/libkeepass)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![C++ Standard](https://img.shields.io/badge/C%2B%2B-11-blue.svg)](https://isocpp.org/)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)

C++11 library for importing and exporting [KeePass](http://keepass.info) password databases.

This project is a fork of [libkeepass](https://github.com/nickvdyck/libkeepass) by Christian Kindahl.

## Features

- **Formats:** KDB (Legacy) and KDBX (KeePass2)
- **Ciphers:** AES, Twofish, ChaCha20
- **KDFs:** AES-KDF, Argon2d, Argon2id
- **Keys:** Password, Keyfile, Composite Keys
- **Platforms:** Linux, macOS, Windows

## Prerequisites

- C++11 compatible compiler (GCC 10+, Clang 12+, MSVC 19.20+)
- CMake >= 3.16
- [Conan](https://conan.io/) package manager

### Dependencies (installed automatically via Conan)

- [OpenSSL](https://www.openssl.org/)
- [zlib](http://zlib.net)
- [pugixml](https://pugixml.org)
- [Argon2](https://github.com/P-H-C/phc-winner-argon2)
- [Google Test](https://github.com/google/googletest) (for unit tests)

## Build

```sh
# Install dependencies
conan install . --output-folder=build --build=missing

# Configure CMake (Release)
cmake -B build -DCMAKE_TOOLCHAIN_FILE=build/Release/generators/conan_toolchain.cmake -DCMAKE_BUILD_TYPE=Release

# Build
cmake --build build --config Release
```

### Running Unit Tests

```sh
cd build
ctest --output-on-failure
```

## Usage

### KDBX (KeePass2)

```cpp
#include "libkeepass/kdbx.hh"
#include "libkeepass/key.hh"

keepass::Key key("password");
// Optional: add keyfile
// key.SetKeyFile("/path/to/keyfile.key");

keepass::KdbxFile file;
std::unique_ptr<keepass::Database> db = file.Import("database.kdbx", key);

// Manipulate database...
auto root = db->root();
for (const auto& entry : root->Entries()) {
    std::cout << entry->title().get() << std::endl;
}

// Export
file.Export("output.kdbx", *db, key);
```

### KDB (Legacy)

```cpp
#include "libkeepass/kdb.hh"
#include "libkeepass/key.hh"

keepass::Key key("password");
std::unique_ptr<keepass::Database> db = keepass::KdbFile::Import("database.kdb", key);

// Manipulate database...

keepass::KdbFile::Export("output.kdb", *db, key);
```

### Database Class

The `Database` class provides access to:

- `root()` - Root group of the database
- `cipher()` / `set_cipher()` - Encryption algorithm
- `kdf()` / `set_kdf()` - Key Derivation Function
- `compress()` / `set_compress()` - XML compression

### Groups and Entries

```cpp
auto root = db->root();

// Add a new group
auto group = std::make_shared<keepass::Group>();
group->set_name("My Group");
root->AddGroup(group);

// Add a new entry
auto entry = std::make_shared<keepass::Entry>();
entry->set_title("My Entry");
entry->set_username("user");
entry->set_password("secret");
entry->set_url("https://example.com");
group->AddEntry(entry);
```

## Project Structure

```
libkeepass/
├── src/                    # Library source code
│   ├── include/libkeepass/ # Public headers
│   ├── kdb.cc              # KDB format implementation
│   ├── kdbx.cc             # KDBX format implementation
│   ├── key.cc              # Key management
│   ├── cipher.cc           # Encryption
│   └── ...
├── test/                   # Unit tests
├── sample/                 # Example application
├── cmake/                  # CMake configuration
└── .github/workflows/      # CI/CD
```

## CI/CD

GitHub Actions automatically builds and tests on the following platforms:

- **Ubuntu** (GCC)
- **macOS** (Clang)
- **Windows** (MSVC)

Each platform is tested in both Debug and Release configurations.

## License

This project is based on [libkeepass](https://github.com/nickvdyck/libkeepass) by Christian Kindahl.

Copyright (C) 2014 Christian Kindahl
Copyright (C) 2024 Dominik Kruempelmann

Licensed under the [GNU General Public License v3.0](COPYING).
