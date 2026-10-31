# libkeepass Roadmap

Status: **living document** — updated on every significant change.

This document outlines the most important future developments for libkeepass,
organized by concern. Items are prioritized to deliver the biggest value per
effort first:

- **P0** - blockers / correctness issues that should be addressed before the
  next release,
- **P1** - high-value improvements for the near term,
- **P2** - larger initiatives for the mid term,
- **P3** - stretch goals and exploratory work.

Checkboxes track the current state of the roadmap. Before starting an item,
make sure the corresponding issue/PR exists and is linked so progress is
visible (this repository currently has GitHub issues disabled, so link the PR).

> Quick wins are marked with ⚡.

---

## 1. Performance

The import path already streams ciphertext (see `docs/streaming.md`), but a
few hot spots dominate memory and time.

### P1 - Remove the whole-file buffer in `KeePass::Open(std::istream&)`
> ⚡
- [x] `src/keepass.cc` now sniffs only the 8-byte format signature and, for
  seekable streams, rewinds and hands the stream directly to the format
  importer — no whole-input buffering. The in-memory fallback remains only
  for genuinely non-seekable streams.

### P1 - Single-pass, memory-bounded export
- [x] `KdbxFile::Export3`/`Export4` (`src/kdbx_export.cc:125`, `src/kdbx_export.cc:206`) now build
  the payload through a streambuf pipeline (gzip → encrypt → HMAC framing)
  that consumes the XML output incrementally, mirroring the streaming import
  path, so plaintext and ciphertext are never both fully resident.
- Attachments in the KDBX4 inner header are written directly into the payload
  pipeline (flags byte + length prefix + raw bytes); no per-attachment
  `std::stringstream` copy is materialized. Existing attachments load lazily
  through the shared `SecureBytes` buffer and `detail::BinarySource` views
  (§1 P2 "Bound the XML DOM and binary memory further").

### P2 - Bound the XML DOM and binary memory further
- [x] KDBX 4 inner-header binaries are collected into one shared, zeroized
  `SecureBytes` buffer during import. Each `Binary` holds a
  `detail::BufferBinarySource` view and only copies its payload into a
  `secure_string` when `data()` is accessed; `Binary::WriteTo` streams the
  payload directly during export (`src/binary.cc`,
  `src/include/libkeepass/detail/binary_source.hh`). The pugixml DOM and the
  decrypted payload remain the deliberate full-buffer points (see
  `docs/streaming.md`).

### P2 - Export benchmark and performance regression tracking
- [x] `test/benchmark.cc` measures export and import time for every
  format/cipher/compression scenario, reports peak RSS (`getrusage` on POSIX,
  `GetProcessMemoryInfo` on Windows) and emits machine-readable `--json`
  output. `test/benchmark_baseline.json` stores the reference run and
  `tools/benchmark_compare.py` fails on absolute or export/import-ratio
  regressions; the Ubuntu Release CI job runs the comparison and uploads the
  result. The absolute threshold is intentionally generous on shared runners,
  while the ratio check is hardware-independent.

### P2 - Vectorize hot byte loops
- [x] `RandomObfuscator::Process` (`src/random.cc`) now consumes the keystream
  in whole 64-byte blocks and XORs 64-bit words (alignment- and endian-safe
  via `memcpy`), with a byte tail for the remainder. The vector, string and
  `secure_string` overloads share the same chunked implementation; tests cover
  every length from 0 to 200 bytes and cross-check all three overloads.

### P3 - Memory-mapped reader
- [x] `KeePass::Open(path)` maps the file read-only (`mmap` on POSIX,
  `CreateFileMapping`/`MapViewOfFile` on Windows) and exposes it through
  `detail::mapped_istreambuf`, so signature sniffing and the header rewind work
  without an `ifstream` read/copy. The stream-based API is unchanged.

---

## 2. Security

libkeepass already zeroizes keys and secret strings and uses wiped, best-effort
locked memory (see `SECURITY.md`). The following close remaining gaps.

### P0 - Constant-time comparisons everywhere secrets are compared
> ⚡
- [x] All secret and integrity-critical comparisons now go through
  `keepass::detail::constant_time_eq`
  (`src/include/libkeepass/detail/constant_time.hh`), backed by
  `CRYPTO_memcmp`: the KDBX4 stored-header HMAC (`src/kdbx_import.cc`), the
  KDBX3/4 header-hash, content-start-byte and per-block verification
  (`src/kdbx_import.cc`, `src/stream.cc`), the KDB content-hash/password check
  (`src/kdb.cc`),
  `secure_string` equality (`src/secure.cc`) and the derived-key zero check
  (`src/key.cc`).
- Unit tests in `test/constant_time.cc`.

### P1 - Bound decompressed payload size (zip-bomb protection)
- [x] gzip/hashed/HMAC block streams enforce configurable caps on total
  decompressed bytes (`max_total_bytes`) and on the number of blocks
  (`max_block_count`) and per-block size admitted before any allocation or
  MAC verification; violations surface as `FormatError`. Hostile fixtures in
  `test/robustness.cc` (gzip bomb, HMAC block size/count, hashed framing)
  cover the e2e behavior with default limits passing and tight limits
  rejected.

### P1 - Parser/XML resource budgets
- [x] XML parsing enforces budgets for nesting depth (`max_xml_depth`), the
  number of groups/entries/history items, single string-field size
  (`max_string_field_bytes`) and binary size (`max_binary_bytes`, also for
  KDBX3 meta binaries, KDBX4 inner-header binaries and custom icons), on top
  of the existing header-field caps in `src/kdbx_header.cc:83`. Verified with
  hostile fixtures in `test/robustness.cc`.

### P2 - Enforce that protected content stays in secure containers
- [x] All internal `RandomObfuscator::Process` call sites now use the
  `secure_string` overload; the TOTP helpers keep their secret in
  `secure_string` as well. The non-`secure_string` overloads remain for
  backwards source compatibility and are candidates for removal in a future
  breaking release.

### P2 - CLI credential hygiene
- [x] `kpx` accepts `--password-file <path>` (including `-` for stdin) and
  `--password-stdin`, so scripts no longer have to expose the master password
  in `argv` or the environment. Conflicting password sources are rejected,
  the interactive prompt now also works on Windows consoles, and `--help`
  documents the trade-off between the convenience sources and the safe ones.

### P2 - Keyfile hardening
- [x] Key-file parsing enforces `Key::kMaxKeyFileBytes` (1 MiB) before
  buffering, wipes every transient buffer on all paths (including malformed
  XML/base64 and I/O errors), and no longer leaves the decoded XML key in an
  unwiped `std::string` when the size check fails. `Key::FromBytes`/
  `Key::FromStream` add in-memory key-file support, and `fuzz/fuzz_keyfile.cc`
  covers the XML, hex and raw modes from both memory and streams.

### P2 - Automated dependency vulnerability scanning
- [x] `.github/workflows/security.yml` resolves the Conan graph to
  `conan.lock` and feeds it to the OSV-Scanner reusable workflow on pushes,
  pull requests and a weekly schedule; results are uploaded to code scanning.
  Dependabot (`.github/dependabot.yml`) keeps the GitHub Actions used by the
  build, fuzz, sanitizer, release and security workflows current. The existing
  CodeQL workflow continues to analyze the library, CLI and tests.

---

## 3. Architecture

### P1 - Centralize duplicated secure/stream helpers
> ⚡
- [x] `WipeStream`/`WipeBuffer` were duplicated verbatim in `src/kdbx.cc`,
  `src/kdbx_header.cc`, `src/kdb.cc` and `src/kdbx_xml.cc`. They now live in
  the shared internal header `src/include/libkeepass/detail/secure_io.hh`
  (`keepass::detail`) and are used by the KDB, KDBX and KDBX XML/header codecs
  (`src/kdbx_import.cc`, `src/kdbx_export.cc`, `src/kdbx_xml_meta.cc` and
  `src/kdbx_xml_entry.cc`).
- Unit tests in `test/secure.cc`.

### P1 - Split the monoliths
- Large translation units hurt review and testing:
  - `src/kdbx_xml.cc` (~1080 lines),
  - `src/kdbx.cc` (~885),
  - `src/kdb.cc` (~828),
  - `src/cipher.cc` (~772),
  - `cli/kpx.cc` (~800).
- **Plan:** split by feature (meta/group/entry/binary in the XML layer;
  import/export/header in the format layer; argument parsing/output/edit in
  the CLI) while keeping the public headers stable.
- [x] `src/cipher.cc` split into `src/cipher_aes.cc`, `src/cipher_chacha20.cc`,
  `src/cipher_twofish.cc` and `src/cipher_util.cc`.
- [x] `src/kdb.cc` split into `src/kdb_fields.cc`, `src/kdb_import.cc` and
  `src/kdb_export.cc` (shared helpers in `src/kdb_internal.hh`).
- [x] `src/kdbx.cc` split into `src/kdbx_import.cc` and `src/kdbx_export.cc`
  (shared constants in `src/kdbx_internal.hh`).
- [x] `src/kdbx_xml.cc` split into `src/kdbx_xml_util.cc`, `src/kdbx_xml_meta.cc`,
  `src/kdbx_xml_group.cc`, `src/kdbx_xml_entry.cc` and the trimmed
  top-level `src/kdbx_xml.cc` (shared helpers in `src/kdbx_xml_internal.hh`).
- [x] `cli/kpx.cc` split into `cli/kpx.cc` (command dispatch),
  `cli/kpx_export.cc`, `cli/kpx_import.cc` and `cli/kpx_edit.cc`.

### P2 - Introduce `keepass::detail` and lean public headers
- [x] `cipher.hh` no longer includes `<openssl/evp.h>`; OpenSSL types are
  forward-declared and only implementation files include the real headers.
  `keepass.hh` no longer pulls `kdbx.hh`, and the new registries/serializers/
  lazy binary sources live in `detail` headers. Remaining algorithm layout in
  `cipher.hh` is source-compatible and a candidate for PImpl at 1.0.

### P2 - Format codec interface behind the unified API
- [x] `detail::FormatCodec`/`FormatCodecRegistry` (with the
  `DatabaseSerializer` alias) replaces the hand-written `switch` in
  `KeePass`. Built-in KDB/KDBX 3/KDBX 4 codecs register themselves; a new
  dialect only registers a factory (in-tree; the registry is internal and not
  exported). `Find`/`Save` no longer construct codecs
  directly (`src/format_codec.cc`).

### P2 - Single ownership model for the object graph
- [x] `docs/ownership.md` codifies the ownership contract: the database owns
  the root, parents own children, children hold weak parent links, history and
  attachments have explicit ownership, and the aliasing rules for move,
  delete, trash and concurrent access are documented.

### P3 - ABI/API stability policy
- [x] `docs/abi-policy.md` documents the 0.x source/ABI expectations,
  Semantic Versioning, deprecation staging, and the PImpl/symbol visibility/
  C-ABI work for a stable 1.0.
- [x] Shared and static builds use hidden default visibility with explicit
  `LIBKEEPASS_API` exports (plus `--exclude-libs,ALL` on ELF); most internal
  `detail::*` helpers and statically linked dependency symbols are no longer
  exported (`BinarySource` stays exported for `Binary`'s `shared_ptr`).
- [x] `KeePass` and `KdbxFile` use PImpl, keeping `Key`, `KdbxXml` and option
  flags out of the public layout; moved-from instances stay usable.
- Remaining for 1.0: PImpl for the `detail::FormatCodec` implementations and
  the `cipher.hh` algorithm classes, plus an exported-symbols list for macOS
  (the hidden preset applies there, but static dependency symbols are not
  filtered from the export trie).

### P2 - Rich, structured error taxonomy
- [x] All exceptions derive from `keepass::Error` and expose a stable
  `ErrorCategory` (`authentication`, `format`, `unsupported`, `resource-limit`,
  `io`, `internal`). `UnsupportedFeatureError` and `ResourceLimitError` refine
  `FormatError`, `FormatError` carries an optional byte `offset()`, and the CLI
  maps categories to its documented exit codes without parsing messages.
- [x] Variant-dictionary parse errors now carry the failing stream offset via
  `FormatError::offset()`; further parser paths can add offsets incrementally
  without an API change.

---

## 4. Modularity

### P1 - Split the `kpx` CLI into reusable components
- [x] CSV serialization was promoted into the library as
  `Database::ToCsv(CsvFormat)` (`src/include/libkeepass/database.hh:356`, the
  CLI now consumes it from `cli/output.cc`), and argument parsing and the
  output/edit commands moved to `cli/kpx_export.cc`, `cli/kpx_import.cc` and
  `cli/kpx_edit.cc`, leaving `cli/kpx.cc` a thin driver.
- [x] `CsvFormat` now also provides `kCsvWithCustomFields` (adds a
  `CustomFields` column) and `kCsvKeePass2` (KeePass 2.x
  `Account,Login Name,Password,Web Site,Comments` layout) in addition to
  `kCsv`/`kCsvWithPasswords`.

### P2 - Pluggable cipher/KDF registry
- [x] `CipherRegistry` (`libkeepass/cipher_registry.hh`) and `KdfRegistry`
  (`libkeepass/kdf_registry.hh`) hold process-wide factories. The built-in
  AES/Twofish and AES-KDF/Argon2d/Argon2id implementations register
  themselves; KDB/KDBX import/export and `KdbxKdf::Transform` resolve through
  the registries. ChaCha20 remains a specialized stream-cipher path (its
  framing is not a 16-byte block cipher).

### P2 - Extract reusable stream components into `keepass::io`
- [x] `libkeepass/io.hh` now exposes the documented `keepass::io` module with
  stable aliases for the hashed/HMAC/gzip/cipher streambufs. The historical
  names remain in `keepass` for source compatibility; existing `test/stream.cc`
  covers the adapters.

### P2 - Decouple the object model from the codecs
- [x] `detail::DatabaseSerializer` (the `FormatCodec` interface) is the only
  path from the unified API to KDB/KDBX/XML code. `KeePass` and `Database`
  carry no codec-specific state, so the codecs can evolve and be tested
  independently.

### P2 - Centralize format constants
- [x] `libkeepass/detail/constants.hh` now owns the KDB/KDBX signatures,
  KDBX version constants, cipher UUIDs, KDF UUIDs, the inner-random-stream IV
  and the outer-header field cap. The codecs and `KdbxHeader`'s public
  constants alias these definitions instead of duplicating the magic values.

### P3 - Independent CMake components
- [x] `LIBKEEPASS_COMPONENT_KDB`/`LIBKEEPASS_COMPONENT_KDBX` and
  `LIBKEEPASS_BUILD_C_API` select the compiled codecs. The installed package
  reports `libkeepass_<component>_FOUND` and provides
  `kruempelmann::libkeepass::model/kdb/kdbx/capi` interface targets for
  `find_package(libkeepass COMPONENTS ...)`.

---

## 5. Usability

### P1 - Synchronize the `kpx` version
> ⚡
- [x] `cli/kpx.cc` no longer hard-codes a version; `KPX_VERSION` is derived
  from `PROJECT_VERSION` at build time (`CMakeLists.txt:12`).

### P1 - Complete Open/Save API parity
- [x] `KeePass::Save` has stream overloads (`src/include/libkeepass/keepass.hh:109`,
  with key at :122 and format at :193) and `SaveAs` accepts streams as well as
  paths (:146, :169), so re-encrypting to a stream is possible.

### P2 - Clarify `KeePass::Create` semantics
- [x] `KeePass::Create` now derives and caches the transformed key for the
  supplied password (except for KDB output), so a subsequent KDBX `Save` can
  use the password even when the saving `KeePass` instance has no key. Saving
  with an explicit key now also overrides an imported/created cached key, so
  `SaveAs` re-encryption actually changes the password.

### P2 - Extend the `kpx` command set
Most-wanted commands that users of a KeePass tool expect:
- [x] `kpx create <file>` - create a brand-new empty database (`--force` to
  overwrite, `--kdf` to choose the KDF),
- [x] `kpx passwd` - change the master password and/or KDF parameters in place
  (atomic temp-file replacement; `--new-password*`, `--kdf`),
- [x] `kpx groups`/`--list-groups` - list groups without entries
  (text/JSON/CSV, honours `--group`),
- [x] `kpx move` - move entries (`--title`/`--search`) or groups (`--group`)
  to `--to <group>`,
- [x] `kpx merge`/`kpx import` - merge another database (`--from <path>`,
  both using the same credentials) into the target root or `--to <group>`.
  Groups/entries (and history) receive fresh UUIDs so they cannot collide with
  existing objects.
- [x] `kpx history`/`purge` - list history versions (text/JSON/CSV) and clear
  history by `--title`/`--search`/`--group` or `--all`,
- [x] `kpx otp` - display TOTP seeds and settings stored in the `otp`/
  `TOTP Seed`/`TOTP Settings` custom fields (text/JSON/CSV; code generation is
  still out of scope).

### P2 - CLI output improvements
- [x] `docs/cli-output.md` documents the stable text/JSON/CSV schemas for
  print, `groups`, `history`, `otp` and `--audit`, and errors are emitted as
  structured JSON (`{"error":{"category":...,"message":...}}`) when
  `--format json` is selected. CSV remains RFC 4180-quoted. Print JSON lists
  attachment names by default and embeds payloads as base64 with
  `--include-attachments`.

### P2 - Better diagnostics and consistent exit codes
- [x] `kpx` maps exceptions to stable exit codes (0 success, 1
  command/usage, 3 auth, 4 format, 5 I/O) and emits structured JSON errors;
  the mapping is documented in `kpx --help`, the README and
  `docs/cli-output.md`. Library exceptions already carry contextual messages
  (`FormatError`, `IoError`) without key material.
- [x] Variant-dictionary and resource-budget errors carry the failing offset
  where the stream reports one; other parser paths can add offsets without an
  API change.

### P2 - API ergonomics
- [x] KDF parameter mutation invalidates the cached transformed key,
  `Key::FromStream`/`FromBytes` accept in-memory key files, `KeePass::Open`
  has `const uint8_t*`/size and `std::vector<uint8_t>` overloads, and
  `Entry::FindAttachment`/`HasAttachment(name)`/`attachment_names` provide
  typed attachment access that distinguishes an empty attachment from a
  missing one.

### P2 - Documentation and migration guides
- [x] `docs/support-matrix.md` documents format × cipher/KDF × feature
  support, `docs/migration-0.2-to-0.3.md` covers the `secure_string`/C++17
  migration, and `docs/examples.md` contains worked examples for streams,
  attachments, tags, recycle bin, history and resource limits. The architecture
  index links all three and `CONTRIBUTING.md` now has a table of contents.

### P3 - Language bindings
- [x] `libkeepass-c` provides a stable C ABI (`capi/include/libkeepass-c.h`,
  built by default, `-DLIBKEEPASS_BUILD_C_API=OFF` to disable) with opaque
  handles, status/category mapping, thread-local errors, open/save/JSON/CSV,
  entry lookup and simple editing. `test/capi.cc` exercises the round-trip.
  Python/Go/Rust bindings can build on this surface.

---

## 6. Testing & Quality

### P1 - Cross-format round-trip property tests
- [x] `test/property.cc` builds randomized databases through the public API
  across features × formats (KDB, KDBX3, KDBX4 and up-conversions), exports,
  re-imports and compares canonical `ToJson()` snapshots.

### P1 - Sanitizer CI job
- [x] `.github/workflows/sanitizers.yml` runs the full test suite under
  ASan+UBSan (and LSan where supported) on Linux. MSan remains a future
  option once the toolchain for dependencies is available.

### P2 - Broaden fuzzing
- [x] `fuzz_xml` parses arbitrary KDBX XML bodies directly (groups, entries,
  protected fields, custom icons, binary references) and writes the resulting
  model back. `fuzz_keyfile` covers XML/hex/raw key files from memory and
  streams, `fuzz_export` builds a model from input bytes and exercises the
  export/save path for KDBX 3 and 4, and `fuzz_kdb`/`fuzz_kdbx` continue to
  mutate whole KDB/KDBX files (including their headers). The CI fuzz workflow
  now builds and runs every target through a matrix with format-specific seed
  corpora.
- [x] The OSS-Fuzz project recipe is maintained in `oss-fuzz/`
  (`Dockerfile`, `build.sh`, `project.yaml`, corpus sync helper). It builds all
  five targets with ASan/UBSan and seeds the corpora from `test/data/`.
- Remaining: open the actual `google/oss-fuzz` submission PR (external
  repository) and sync the hosted corpus bucket.

### P2 - Adversarial fixtures
- [x] `test/robustness.cc` covers truncated payloads, oversized header fields
  and variant-dictionary values, unknown KDB/KDBX header field ids, oversized
  KDF parameters, deep XML nesting, group/entry/history/string/binary budgets,
  zip bombs, HMAC block size/count limits, HMAC tampering and CBC bit flips.

### P3 - Concurrency & resource tests
- [x] `test/concurrency.cc` opens the same database from eight threads
  concurrently and compares canonical snapshots, verifies that a failed or
  successful import does not leak the cached transformed key into other
  `KeePass` instances, and exercises `secure_alloc`/`secure_free` edge sizes
  and null/zero-sized frees under the sanitizer job.

### P2 - CodeQL/security triage loop
- [x] `.github/workflows/security-triage.yml` runs weekly and on demand,
  fetches open code-scanning alerts (CodeQL plus SARIF-producing workflows
  such as OSV-Scanner), renders a severity-grouped Markdown report with
  `tools/security_triage.py`, writes it to the job summary and uploads it as
  an artifact.

---

## 7. Ecosystem & Infrastructure

### P2 - Finalize ConanCenter publishing
- The recipe migration to CCI v2 is done for 0.3.0; finish the ConanCenter
  submission so `libkeepass/0.3.x` becomes installable via `conan install`.

### P2 - Expand package coverage
- [x] GitHub Releases now include an SPDX SBOM generated by Syft
  (`anchore/sbom-action`) alongside the CPack TGZ/ZIP/DEB/RPM artifacts and
  `SHA256SUMS.txt`, so checksums cover the SBOM too.
- [x] An in-tree vcpkg port (`ports/libkeepass/`) with a pinned source hash,
  dependency manifest and usage notes.
- [x] An optional Homebrew formula (`Formula/libkeepass.rb`) and keyless
  Sigstore/cosign signing of every release asset in the tag-driven release
  workflow (`.github/workflows/release.yml`).

### P1 - Release automation
- [x] `.github/workflows/release.yml` is a tag-driven workflow (on `v*`) that
  builds packages on all OSes, creates the GitHub Release and verifies the
  Conan recipe with `conan create` and the `test_package` consumer before
  publishing.

### P2 - CI hygiene
- [x] Conan installation/profile setup now lives in the shared composite
  action `.github/actions/setup-conan`, used by the build, fuzz, sanitizer,
  lint, CodeQL, release and security workflows. Conan cache keys hash
  `conanfile.py` instead of the non-existent `conanfile.txt`, so dependency
  changes invalidate the cache correctly.
- [x] `setup-conan` now has `cache-mode: restore|save|both` and the workflows
  use it instead of separate `actions/cache` steps. The lint workflow also has
  a `windows-lint` job that runs `run-clang-tidy.py` against an MSVC build.

### P3 - WebAssembly demo
- [x] `wasm/` contains an Emscripten build (`CMakeLists.txt`, `demo.cc`), a
  client-side-only browser page (`index.html`) using the C ABI, and build
  notes (`README.md`). It decrypts and inspects a database without uploading
  it; the dependency notes cover the wasm32 OpenSSL/Argon2 ports.

---

## 8. "Etc." - additional opportunities

- [x] **KDBX 4.1 verification surface:** the KeePass-generated fixture corpus
  (`test/data/kdbx4/kdbx41/`, produced by `tools/kdbx41_fixturegen/`) covers
  previous-parent group/entry, custom icons, deleted objects and the 4.1
  version-migration rules; `test/kdbx4.cc` verifies them against real files.
  New KeePass releases should extend the same generator/fixtures.
- [x] **TOTP / custom-field helpers:** `TotpConfig`/`Totp` parse the
  `otp`/`TOTP Seed`/`TOTP Settings` field variants and complete
  `otpauth://totp/...` URIs (Base32, SHA-1/256/512, period, digits), generate
  RFC 6238 codes and expose `Entry::totp()`/`Entry::totp_code()`.
  `kpx otp --code` prints the current code and remaining seconds.
- [x] **Entry history controls:** `Entry::delete_old_history()` and
  `Database::DeleteOldHistory()` implement the `HistoryMaxItems`/
  `HistoryMaxSize` policy, and `kpx purge --keep <n>` trims instead of clearing.
- [x] **Lazy binary loading:** attachment payloads are accessed on demand via
  `detail::BinarySource` views over one shared secure buffer; `Binary::data()`
  materializes on demand and `Binary::WriteTo()` streams during export (§1).
- [x] **Delta/backup workflows:** `Database::DeltaSince(previous)` returns a
  `DatabaseDelta` with added/modified/deleted entries matched by UUID and a
  canonical JSON export (`DatabaseDelta::ToJson`) for incremental backups.

---

## How to use this roadmap

1. Pick an item (prefer P0/P1), create a PR (or re-enable issues and file one),
   and link it here.
2. Update the checkbox when the change is merged and released.
3. Move items between priorities based on real user feedback; the roadmap is a
   plan, not a contract.

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to contribute, and
[CHANGELOG.md](CHANGELOG.md) for what has already shipped.