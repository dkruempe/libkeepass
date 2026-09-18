# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Third-party interoperability for KeePassXC: real KeePassXC test-corpus
  fixtures are imported in the new `libkeepass.compat` test binary
  (`test/compat.cc`, fixtures under `test/data/compat/`) covering KDBX 4.0
  (ChaCha20 + Argon2d + gzip), KDBX 3.1 protected strings and the recycle-bin
  group layout. The verification matrix and the Strongbox analysis (16-byte
  Argon2 salts, Argon2 `K`/`A` parameters, keyfile variants) are documented in
  `docs/interop.md` together with the import tolerance policy.
- The `kpx --audit` command reports weak and reused passwords. It prints text
  by default and supports `-f json`/`-f csv`, a `--group` subtree scope and a
  `--with-passwords` flag to include the literal password in the JSON reuse
  section and the text output. Findings cover empty passwords, passwords below
  the 12-character minimum, a single character class (digits- or letters-only),
  passwords based on the title or username and entries of a common-passwords
  list; reuse groups every occurrence of a password used by several entries.
- Dedicated `test/key.cc` (transformed-key short circuit, keyfile parsing
  errors, uppercase hex keyfiles, Argon2 error paths) and `test/random.cc`
  (random-obfuscator stream processing) raise the line coverage of `key.cc`
  and `random.cc` from 76%/72% to 82%/95%.

### Fixed

- The recycle-bin metadata now points to the group that actually holds the
  recycled entries. Because `Meta` (parsed before the group tree) could
  resolve `RecycleBinUUID`/`EntryTemplatesGroup` to a placeholder instance,
  `ParseGroup` previously inserted a *separate* group into the UUID pool
  (`std::map::insert` keeps the existing entry), so `Metadata::recycle_bin()`
  returned an empty group while the tree group carried the entries.
  `ParseGroup` now reuses a pooled placeholder when the UUID was already
  resolved.

### Changed

- **Breaking:** the language standard baseline is now C++17 (previously the
  library still declared C++11 as its minimum while CI and the documentation
  already built with C++17). The CMake targets enforce this via
  `target_compile_features(... cxx_std_17)`, and the Conan recipes
  (`conanfile.py`, ConanCenter recipe) check the minimum standard in
  `validate()`.
- **Breaking:** `Icon::last_modification_time` and
  `Metadata::Field::last_modification_time` now return
  `std::optional<std::time_t>` instead of `std::time_t`; absent
  `<LastModificationTime>` elements map to `std::nullopt` instead of 0, and
  `set_last_modification_time(std::nullopt)` unsets the value.
- **Breaking:** `Entry::previous_parent_group` and
  `Group::previous_parent_group` now return
  `std::optional<std::array<uint8_t, 16>>` instead of an all-zero array; use
  `has_value()` to test for presence.
- The `base64_decode` helpers now take `std::string_view`, avoiding temporary
  `std::string` allocations when decoding pugixml node text and attribute
  values; `KdbxXml::ParseDateTime` no longer copies its input.
- **Breaking:** the database seeds are no longer kept on unprotected heap
  memory. `Database::master_seed` and `Database::argon2_salt` now return
  `const SecureBytes&`, and `Database::transform_seed` returns
  `const SecureBuffer<32>&`; all three are erased when the database is
  destroyed or the seed is replaced. `Key::Transform`
  (`const SecureBuffer<32>&`) and `Key::TransformArgon2`
  (`const SecureBytes&`) accept the secure containers directly, and
  `SecureBytes` (a new wiped, best-effort locked dynamic byte buffer) is
  exposed for callers that need to hold seed material.
  A new `SecureBuffer` constructor accepts a
  `std::array<uint8_t, N>` for callers converting existing header data.

### Infrastructure

- ConanCenter recipe raised to the CCI-v2 conventions (`test_package` instead
  of `test_v1_package`, `implements = ["auto_shared_fpic"]`, `check_min_cppstd`,
  SPDX license `GPL-3.0-only`); `conan create` verified locally for both static
  and shared variants

### Docs

- `docs/kdbx-parsing.md` folded into the modular architecture (`KdbxHeader`,
  `KdbxKdf`, `KdbxXml` instead of the monolithic `KdbxFile`)

## [0.3.0] - 2026-09-13

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
- KDBX 4.1 support: `Group` tags (`Group::tags`/`set_tags`), the entry
  "password quality estimation" flag (`Entry::quality_check`/`set_quality_check`),
  entry/group previous-parent-group UUIDs (`Entry`/`Group::previous_parent_group`),
  custom icon `Name`/`LastModificationTime` (`Icon::name`/`Icon::last_modification_time`),
  custom data item `LastModificationTime` (`Metadata::Field::last_modification_time`)
  and deletion tombstones (`Metadata::DeletedObject`) are parsed and written;
  the exporter writes version `0x00040001` only when such 4.1-only features are
  used (mirroring KeePass' `GetMinKdbxVersion`)
- KDBX 4.1 import verified against real KeePass-generated files: fixtures
  produced by KeePass 2.57 (`test/data/kdbx4/kdbx41/`, generator in
  `tools/kdbx41_fixturegen/`) with new import tests in `test/kdbx4.cc`. The
  exact version rules of KeePass 2.57 were confirmed empirically: a
  previous-parent-group reference does not enforce 4.1 (and is then omitted
  from the 4.0 output), any `<CustomData>` item enforces 4.1, entry tags do not
- Group/entry tags now interoperate with KeePass 2.48+: the wire format is
  semicolon-joined; the public API stays space-separated, with the conversion
  performed at the XML boundary on import and export
- `kpx` search, filtering, generation and editing: `--search <query>` and
  `--regex` restrict the printed tree to matching entries, `--group <name>`
  prints only the subtree of a group, `--generate[=n]` prints a generated
  random password, and the `add`/`update`/`rm` commands create, modify and
  delete entries (or whole groups) in place; `--help` documents the exit codes
- `test/kpx.cc` covers the new search, generate, add, update and rm behavior

### Changed

- Introduced `keepass::detail::constant_time_eq` (backed by OpenSSL's
  constant-time `CRYPTO_memcmp`) and switched every secret and
  integrity-critical comparison to it: the KDBX4 stored-header HMAC, the
  KDBX3/4 header-hash, content-start-byte and hashed/HMAC-block checks, the
  KDB content-hash (password) check, `secure_string` equality and the
  derived-key zero check (see `test/constant_time.cc`)
- Centralized the duplicated `WipeStream`/`WipeBuffer` helpers into the shared
  internal header `libkeepass/detail/secure_io.hh` with unit tests in
  `test/secure.cc`
- KDBX 4 export deduplicates the binary pool in O(n) instead of O(n²),
  speeding up `Save`/`Export4` for databases with many shared attachments
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

[Unreleased]: https://github.com/dkruempe/libkeepass/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/dkruempe/libkeepass/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/dkruempe/libkeepass/releases/tag/v0.2.1
[0.2.0]: https://github.com/dkruempe/libkeepass/releases/tag/v0.2.0
[0.1.0]: https://github.com/dkruempe/libkeepass/releases/tag/v0.1.0