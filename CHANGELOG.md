# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

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

[Unreleased]: https://github.com/dkruempe/libkeepass/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/dkruempe/libkeepass/releases/tag/v0.2.0
[0.1.0]: https://github.com/dkruempe/libkeepass/releases/tag/v0.1.0