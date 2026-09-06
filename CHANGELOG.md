# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Unified `KeePass` API (`libkeepass/keepass.hh`) for opening and saving
  databases: auto-detects the input format (KDB, KDBX3, KDBX4), selects the
  output format from the file extension, the database KDF/cipher or an explicit
  `SetFormat()`, and supports in-memory streams for both `Open` and `Save`
- `KeePass::Create()` factory that builds a new database with generated
  cryptographic material
- Stream-based `Import`/`Export` overloads for `KdbFile` and `KdbxFile`
- `Database` convenience API: `FindEntries`/`FindGroups` (substring or regex),
  `FindEntry`/`FindGroup`, `NewEntry`/`NewGroup`, `AddEntry`/`AddGroup`,
  `DeleteEntry`/`DeleteGroup`, `MoveEntry`/`MoveGroup`, `TrashEntry`/`TrashGroup`,
  `EmptyRecycleBin`, `IsRecycleBinEnabled`/`EnableRecycleBin`, `EntryCount`/
  `GroupCount`, `ToJson()` and `Visit()`
- `Entry` convenience API: weak parent with `path()`, `custom_properties()`,
  `GetString`/`HasString`, `set_custom_property`/`delete_custom_property`,
  attachment helpers `set_binary_property`/`get_binary_property`/
  `delete_binary_property`, `save_history`/`delete_history` and `touch()`
- `Group` convenience API: `path()`, `parent()`/`set_parent()`, `is_root_group()`,
  `entries_count()`/`groups_count()`, subtree `FindEntries`/`FindGroups` and
  `RemoveGroup`/`RemoveEntry`; groups track their parent via
  `std::enable_shared_from_this`
- `Key` convenience constructors: composite `Key(password, keyfile)` and
  pre-derived transformed key `Key(vector<uint8_t>)`
- Visitor pattern (`libkeepass/visitor.hh`) with `Visit(Group&, Visitor&)`,
  `PrintVisitor` and `Database::Visit()`
- Secure memory primitives in `libkeepass/secure.hh`: `secure_zero` volatile
  byte wiping, `secure_alloc`/`secure_free` (best-effort `mlock`/
  `VirtualLock` plus wipe-before-free) and the move-only, zeroized
  `SecureBuffer<N>` container
- `secure_string`: a wiped, best-effort locked string with no SSO that is
  used for all secret entry fields and protected values
- Dedicated `test/secure.cc` covering the secure primitives

### Changed

- Migrated the `kpx` CLI to the unified `KeePass` API
- Exporting databases without metadata or a root group no longer crashes
- `Database::NewEntry`/`NewGroup`/`AddEntry`/`AddGroup`/`MoveEntry`/`MoveGroup`
  are static members and take `std::shared_ptr` by `const&`; calls made on a
  `Database` instance keep working
- Cipher constructors (`AesCipher`, `TwofishCipher`, `Salsa20Cipher`,
  `ChaCha20Cipher`) now take the raw key as a `const uint8_t*` (null-safe)
  and wipe the key state on destruction
- `RandomObfuscator` wipes its buffered keystream and adds a `Process`
  overload that returns a `secure_string`
- `Key` subkey storage and the `Transform`/`TransformArgon2` results are kept
  in `SecureBuffer<32>`; `Database` caches the transformed key in wiped,
  best-effort locked memory
- **Breaking:** entry string fields, `Binary` payloads and KDBX protected
  strings now use `protect<secure_string>` instead of `protect<std::string>`;
  callers must convert explicitly (e.g. via `value()->str()`)
- KDBX 3/4 import and export zeroize transient transformed keys, HMAC keys,
  master keys and inner random stream keys after their last use
- The `kpx` CLI resolves the master password into a `secure_string` (`-p`,
  `KEEPASS_PASSWORD` or interactive prompt) and feeds it to the `KeePass`
  API through wiped memory

### Fixed

- Windows: `keepass::Visit(Group&, Visitor&)` is now exported from the shared
  library so consumers link correctly (was `LNK2019`)

## [0.2.1] - 2026-09-05

### Added

- Conan 2 package recipe (`conanfile.py`) replacing `conanfile.txt`, with a `test_package` consumer; `conan create` builds static and shared variants
- CI workflow that enforces `clang-format` formatting and `clang-tidy` static analysis
- `CONTRIBUTING.md` documenting the build, testing, and code style process
- `.clang-format` and `.clang-tidy` configuration files

### Changed

- Reformatted the entire codebase with `clang-format`
- Fixed static analysis findings reported by `clang-tidy`
- Replaced the transparent `std::bit_xor` functors with explicit XOR loops so the checks pass on MSVC (`/WX`)
- Tests are now built behind `BUILD_TESTING` so packaging builds can omit them

## [0.2.0] - 2026-09-04

### Added

- `kpx` command line tool (`cli/`) built on top of the library:
  - Text, JSON and CSV output formats
  - `--export` to write a new KDB/KDBX file, `--output` to redirect output
  - Keyfile support and key passphrase from option, `KEEPASS_PASSWORD`
    environment variable or interactive prompt
  - Portable argument parser (no `getopt` dependency, works on Windows)
- CPack packaging: TGZ/ZIP archives on all platforms, DEB/RPM packages on
  Linux, exposed via a `package` build target
- Complete CMake package configuration so consumers can integrate the
  library with `find_package(libkeepass)` and link the imported target
  `kruempelmann::libkeepass`

### Changed

- Replaced the sample application with the `kpx` CLI, moving `sample/` to `cli/`
- Enabled macOS rpaths so the installed `kpx` binary can locate the shared library
- Updated Doxygen excludes and the CI coverage paths for the `cli/` directory

## [0.1.0] - 2026-09-04

First public release with semantic versioning.

### Added

- Support for reading and exporting KDB (KeePass 1.x) files
- Support for reading and exporting KDBX (KeePass 2.x) files, including KDBX 4.0
- Ciphers: AES, Twofish, Salsa20, ChaCha20
- Key derivation: AES-KDF (with AES-NI hardware acceleration on x86), Argon2d and Argon2id
- Key sources: passphrase, key files, composite keys
- Read and write primitives: base64, hashed block streams, gzip compression,
  variant dictionaries, binary attachments, icon management, time reference handling
- Doxygen-based API documentation with a hosted copy on GitHub Pages
- CMake package configuration for `find_package(libkeepass)` support
- Sample application demonstrating the library API

### Changed

- Modernized the build to C++11 with the Conan 2 package manager and the Conan CMake provider
- Migrated to the OpenSSL 3.x EVP API
- Switched to pugixml and libargon2 as external Conan dependencies
- Moved all public headers under `include/libkeepass`

### Infrastructure

- CI on GitHub Actions for Linux, macOS and Windows
- Code coverage reporting via Codecov (lcov/gcov)
- Unit and integration tests covering KDB/KDBX roundtrips and key derivation
- GitHub Pages deployment of the generated API documentation

[Unreleased]: https://github.com/dkruempe/libkeepass/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/dkruempe/libkeepass/releases/tag/v0.2.1
[0.2.0]: https://github.com/dkruempe/libkeepass/releases/tag/v0.2.0
[0.1.0]: https://github.com/dkruempe/libkeepass/releases/tag/v0.1.0