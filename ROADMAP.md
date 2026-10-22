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
visible.

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
- [x] `KdbxFile::Export3`/`Export4` (`src/kdbx_export.cc:124`, `src/kdbx_export.cc:203`) now build
  the payload through a streambuf pipeline (gzip → encrypt → HMAC framing)
  that consumes the XML output incrementally, mirroring the streaming import
  path, so plaintext and ciphertext are never both fully resident.
- Attachments still stream through `std::stringstream` in the KDBX4 inner
  header (see §1 P2 "Lazy binary loading").

### P2 - Bound the XML DOM and binary memory further
- The pugixml DOM (a deliberate decision, see `docs/streaming.md`) plus the
  decrypted `std::stringstream` dominate memory for large databases.
- **Plan:** for attachments, load/copy `Binary` payloads lazily on access and
  stream them during export instead of materializing every attachment in the
  inner header at once.

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
- For `Open(path)`, use a memory-mapped input (`mmap`/`CreateFileMapping`)
  behind an `IInputStream` facade so large databases avoid the read+copy cost
  entirely, while the stream-based API keeps working unchanged.

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
- Audit all `RandomObfuscator::Process` call sites so protected values never
  transit through plain `std::string`/`std::vector`. Deprecate and remove the
  non-`secure_string` overloads once the audit is clean.

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
- Move implementation details out of the public headers (`cipher.hh` is ~362
  lines and pulls OpenSSL types everywhere). Public headers should expose
  only the documented API, with heavy plumbing in a `detail` namespace.

### P2 - Format codec interface behind the unified API
- Replace the `switch` dispatch in `src/keepass.cc:86` with a
  `FormatCodec`/factory registrable per format so that adding a new dialect
  (e.g. future KDBX 4.2) does not touch `KeePass` itself.

### P2 - Single ownership model for the object graph
- `Database`/`Entry`/`Group` mix `shared_ptr`, `weak_ptr` and raw pointers,
  and `Group` uses `enable_shared_from_this`. Codify and document a clear
  ownership policy (who owns what, aliasing rules when moving/trashing
  subtrees) to make the API predictable and safe.

### P3 - ABI/API stability policy
- Introduce explicit soname/versioning strategy and a deprecation policy so
  breaking changes (like the `protect<secure_string>` migration in 0.3.0) are
  staged over releases. Consider PImpl for `KdbxFile`/`KeePass` once ABI
  stability matters.

### P2 - Rich, structured error taxonomy
- Differentiate corruption vs. wrong password vs. unsupported feature in the
  exception types (partially present), carry the failing offset/size where
  useful, and never include key material in `what()`.

---

## 4. Modularity

### P1 - Split the `kpx` CLI into reusable components
- [x] CSV serialization was promoted into the library as
  `Database::ToCsv(CsvFormat)` (`src/include/libkeepass/database.hh:356`, the
  CLI now consumes it from `cli/output.cc`), and argument parsing and the
  output/edit commands moved to `cli/kpx_export.cc`, `cli/kpx_import.cc` and
  `cli/kpx_edit.cc`, leaving `cli/kpx.cc` a thin driver.
- Remaining (P2): CSV formats beyond the two configured via `CsvFormat` and
  any further output formatters.

### P2 - Pluggable cipher/KDF registry
- Model ciphers and KDFs behind factory interfaces so external consumers can
  register implementations without touching core code. Keep Salsa20 and
  AES-KDF behind a "compatibility" flag on export.

### P2 - Extract reusable stream components into `keepass::io`
- `hashed_istreambuf`/`hashed_ostreambuf`, `hmac_istreambuf`/
  `hmac_ostreambuf`, `gzip_istreambuf`/`gzip_ostreambuf` live in `stream.cc`
  with good tests already — formalize them as a documented `io` module with a
  stable interface and dedicated tests.

### P2 - Decouple the object model from the codecs
- `Database` currently knows XML/KDBX concepts. Introduce a
  `DatabaseSerializer` abstraction so `Database`, `KdbxXml`, `KdbxHeader` and
  `Kdb` can evolve and be tested independently.

### P2 - Centralize format constants
- [x] `libkeepass/detail/constants.hh` now owns the KDB/KDBX signatures,
  KDBX version constants, cipher UUIDs, KDF UUIDs, the inner-random-stream IV
  and the outer-header field cap. The codecs and `KdbxHeader`'s public
  constants alias these definitions instead of duplicating the magic values.

### P3 - Independent CMake components
- If consumer demand grows, expose `libkeepass` as optional components
  (model / kdb / kdbx / cli) via `find_package(... COMPONENTS ...)`.

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
- `kpx merge` / `kpx import` - merge a second database into the current one,
- [x] `kpx history`/`purge` - list history versions (text/JSON/CSV) and clear
  history by `--title`/`--search`/`--group` or `--all`,
- [x] `kpx otp` - display TOTP seeds and settings stored in the `otp`/
  `TOTP Seed`/`TOTP Settings` custom fields (text/JSON/CSV; code generation is
  still out of scope).

### P2 - CLI output improvements
- [x] `docs/cli-output.md` documents the stable text/JSON/CSV schemas for
  print, `groups`, `history`, `otp` and `--audit`, and errors are emitted as
  structured JSON (`{"error":{"category":...,"message":...}}`) when
  `--format json` is selected. CSV remains RFC 4180-quoted.
- Remaining: `--include-attachments`/base64 output for entry payloads.

### P2 - Better diagnostics and consistent exit codes
- [x] `kpx` maps exceptions to stable exit codes (0 success, 1
  command/usage, 3 auth, 4 format, 5 I/O) and emits structured JSON errors;
  the mapping is documented in `kpx --help`, the README and
  `docs/cli-output.md`. Library exceptions already carry contextual messages
  (`FormatError`, `IoError`) without key material.
- Remaining: richer "while parsing group X"/offset context in every parser
  error path.

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
- Start with a C ABI (`libkeepass-c`) so Python/Go/Rust bindings and
  higher-level tools can be built without reimplementing the format logic.

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
- Remaining: submit the targets to OSS-Fuzz for continuous corpus growth and
  coverage reporting, and sync the in-repo corpus with the OSS-Fuzz corpus.

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
- Remaining: add a vcpkg port and an optional Homebrew formula, and sign the
  release artifacts where feasible.

### P1 - Release automation
- [x] `.github/workflows/release.yml` is a tag-driven workflow (on `v*`) that
  builds packages on all OSes, creates the GitHub Release and verifies the
  Conan recipe with `conan create` and the `test_package` consumer before
  publishing.

### P2 - CI hygiene
- Reduce matrix duplication across `cmake.yml`/`fuzz.yml` (shared composite
  action), cache Conan in one place, and make lint run clang-tidy on Windows
  too (currently Linux-only).

### P3 - WebAssembly demo
- Build the library (and optionally `kpx`) for WASM so databases can be
  inspected in the browser - useful as a security showcase (client-side only
  decryption) and a distribution vehicle.

---

## 8. "Etc." - additional opportunities

- **KDBX 4.1 verification surface:** keep extending the KeePass-generated
  fixture corpus (`tools/kdbx41_fixturegen/`) to future KeePass releases and
  cover every 4.1 feature against real files.
- **TOTP / custom-field helpers:** first-class helpers for the
  KeePass-specific TOTP seed fields (`otp`) used by KeePass2Android and
  KeeOtp.
- **Entry history controls:** expose `DeleteOldHistory`/max-history policy in
  the model and CLI.
- **Lazy binary loading:** access attachment payloads on demand for databases
  with many large binaries (§1).
- **Delta/backup workflows:** snapshot or incremental export of changed
  entries to support backup tools on top of the library.

---

## How to use this roadmap

1. Pick an item (prefer P0/P1), create an issue, and link it here.
2. Update the checkbox when the change is merged and released.
3. Move items between priorities based on real user feedback; the roadmap is a
   plan, not a contract.

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to contribute, and
[CHANGELOG.md](CHANGELOG.md) for what has already shipped.