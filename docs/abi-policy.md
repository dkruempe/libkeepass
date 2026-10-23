# ABI and API stability policy

libkeepass is in the `0.x` series. The public **source** API is the interface we
document and test; the **binary** ABI is not stable before `1.0`. This document
describes what consumers can rely on and how changes are staged.

## Versioning

- The project version comes from `CMakeLists.txt` and is also used by the Conan
  recipe and `kpx`.
- Releases follow [Semantic Versioning](https://semver.org/):
  - `MAJOR` (from `1.0`) for incompatible API/ABI changes,
  - `MINOR` for backwards-compatible functionality,
  - `PATCH` for backwards-compatible fixes.
- During `0.x`, a minor bump may contain **source-breaking** changes when a
  security or correctness fix requires it. Every such change is listed under
  **Changed/Breaking** in `CHANGELOG.md` with a migration note.

## Shared-library ABI

- The CMake targets now carry the project `VERSION` and `SOVERSION 0`
  (`liblibkeepass.so.0`), making the 0.x ABI generation explicit. Before `1.0`
  consumers should still rebuild against the matching library rather than rely
  on ABI compatibility; a major bump will change the soname.
- Public classes keep their documented layout private. New virtual functions
  are only added to classes that are explicitly documented as interfaces
  (`Cipher`, `Visitor`); concrete classes are `final` where possible.
- `LIBKEEPASS_API` marks exported symbols. Inline/template helpers in public
  headers are part of the source API but not of the ABI.
- C++ standard library types in signatures (`std::string`, `std::vector`,
  `std::shared_ptr`, ...) mean that ABI compatibility is only guaranteed for
  the same standard library and compiler ABI.

## Deprecation

1. A deprecated symbol is marked with `[[deprecated("use ...")]]` and mentioned
   in the changelog.
2. It remains available for at least one minor release before removal.
3. Removal happens in a minor release during `0.x` and in a major release after
   `1.0`, with a `CHANGELOG.md` entry and (where applicable) a migration section
   in `docs/migration-*.md`.

## Planned hardening for 1.0

- `PImpl` for `KeePass`, `KdbxFile` and the format codecs so their layout and
  third-party dependencies (OpenSSL) do not leak into the ABI.
- A generated symbol-version script or `-fvisibility=hidden` plus explicit
  exports on all platforms.
- The C ABI (`libkeepass-c`, see `capi/include/libkeepass-c.h`) is available
  now and has its own deliberately small surface for language bindings. It
  follows the same deprecation policy; the C++ API is not a stable ABI for FFI
  consumers.
