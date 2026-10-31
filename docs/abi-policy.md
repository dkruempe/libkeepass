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

## Hardening for 1.0

- `PImpl` for `KeePass` and `KdbxFile` is implemented: their public headers
  only hold `std::unique_ptr<Impl>`, and per-operation state (including
  `KdbxXml` and the key/format options) lives in the implementation files.
  Copying deep-copies that state; moving transfers it and leaves the source in
  a default-constructed, fully usable state (the move allocates a fresh
  default-initialized implementation and may throw). The format codecs under
  `keepass::detail` still expose their layout and remain a follow-up item.
- Hidden symbol visibility is implemented for GCC/Clang builds (shared and
  static): `CXX_VISIBILITY_PRESET hidden` plus `VISIBILITY_INLINES_HIDDEN`,
  with `LIBKEEPASS_API` marking the intentional exports. On ELF,
  `--exclude-libs,ALL` also hides symbols from statically linked dependencies.
  On macOS the hidden preset applies but there is no archive-level exclusion,
  so statically linked dependency symbols can still appear in the export trie.
  Windows uses `__declspec`; a version script is not used.
- Most `keepass::detail` helpers are hidden. `detail::BinarySource` and
  `detail::BufferBinarySource` stay exported because `Binary` owns a source
  through `std::shared_ptr`, so the deleter and virtual destructor must resolve
  in consumer translation units.
- The C ABI (`libkeepass-c`, see `capi/include/libkeepass-c.h`) is available
  now and has its own deliberately small surface for language bindings. It is
  built with default visibility so the `kp_*` entry points stay exported, and
  follows the same deprecation policy. The C++ API is not a stable ABI for FFI
  consumers.
