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
- `src/keepass.cc:61` reads the *entire* input into a `std::string` just to
  sniff the 8-byte format signature. For large databases this negates the
  streaming work done for decryption and doubles peak memory.
- **Plan:** peek the signature from the stream (buffer only the first 12
  bytes) and pass a seekable/streaming facade to the format importers; keep
  the in-memory fallback only for genuinely non-seekable streams.

### P1 - Single-pass, memory-bounded export
- `KdbxFile::Export3`/`Export4` (`src/kdbx.cc:575`, `src/kdbx.cc:652`) chain
  several `std::stringstream`s (`inner_header_stream`, `plain_stream`,
  `cipher_input`, `hmac_input`) so the plaintext *and* a ciphertext copy are
  resident at the same time (~4× payload peak).
- **Plan:** build the payload through a streambuf pipeline (gzip → encrypt →
  HMAC framing) that consumes the XML output incrementally, mirroring the
  streaming import path. Attachments must still be zeroized after use.

### P2 - Bound the XML DOM and binary memory further
- The pugixml DOM (a deliberate decision, see `docs/streaming.md`) plus the
  decrypted `std::stringstream` dominate memory for large databases.
- **Plan:** for attachments, load/copy `Binary` payloads lazily on access and
  stream them during export instead of materializing every attachment in the
  inner header at once.

### P2 - Export benchmark and performance regression tracking
- `test/benchmark.cc` only measures **import** and nothing asserts
  performance. Add export timing and peak memory (or approximate resident set
  via `getrusage`), store baselines in `test/benchmark_baseline.json`, and add
  a CI step that fails (or files an issue) on a >X% regression vs. the
  baseline, using a dedicated runner so numbers stay comparable.

### P2 - Vectorize hot byte loops
- The inner random-stream XOR loop in `RandomObfuscator::Process`
  (`src/random.cc:91`) processes one byte per iteration; process whole
  keystream blocks with word-wise XOR when the buffers are aligned.

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
  `CRYPTO_memcmp`: the KDBX4 stored-header HMAC (`src/kdbx.cc`), the KDBX3/4
  header-hash, content-start-byte and per-block verification (`src/kdbx.cc`,
  `src/stream.cc`), the KDB content-hash/password check (`src/kdb.cc`),
  `secure_string` equality (`src/secure.cc`) and the derived-key zero check
  (`src/key.cc`).
- Unit tests in `test/constant_time.cc`.

### P1 - Bound decompressed payload size (zip-bomb protection)
- gzip/hashed-block streams can expand a small database into a huge XML DOM.
- **Plan:** enforce a configurable cap on total decompressed bytes and on the
  number of hashed/HMAC blocks, and reject databases whose declared sizes
  exceed the budget *before* parsing (add e2e robustness tests).

### P1 - Parser/XML resource budgets
- Add explicit limits during XML parsing: maximum nesting depth, maximum
  number of groups/entries/history items, maximum single string field size and
  maximum binary size (in addition to the existing header-field caps in
  `src/kdbx_header.cc:83`). Verified with hostile fixtures in
  `test/robustness.cc`.

### P2 - Enforce that protected content stays in secure containers
- Audit all `RandomObfuscator::Process` call sites so protected values never
  transit through plain `std::string`/`std::vector`. Deprecate and remove the
  non-`secure_string` overloads once the audit is clean.

### P2 - CLI credential hygiene
- `kpx -p <password>` and `KEEPASS_PASSWORD` leak the secret into `argv`/the
  environment (visible in `ps`/`/proc`). Add `--password-file`/`--stdin`
  (and a `getpass`-based prompt on Windows), and document the trade-off.

### P2 - Keyfile hardening
- Add fuzz coverage and size limits for keyfile parsing (XML/hex/raw modes),
  reject absurd keyfile sizes, and wipe keyfile-derived buffers on all error
  paths.

### P2 - Automated dependency vulnerability scanning
- Add OSV-Scanner/`conan audit` for the dependency graph and enable
  Dependabot for Conan/CMake/CI files. Keep the existing CodeQL workflow, and
  make sure the nightly security scan covers the CLI and tests.

---

## 3. Architecture

### P1 - Centralize duplicated secure/stream helpers
> ⚡
- [x] `WipeStream`/`WipeBuffer` were duplicated verbatim in `src/kdbx.cc`,
  `src/kdbx_header.cc`, `src/kdb.cc` and `src/kdbx_xml.cc`. They now live in
  the shared internal header `src/include/libkeepass/detail/secure_io.hh`
  (`keepass::detail`) and are used by the KDB, KDBX and KDBX XML/header codecs.
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
- Extract argument parsing, the remaining output formatters (CSV) and the
  edit commands (`add`/`update`/`rm`) so the CLI becomes a thin driver.
- **Status:** `ToJson()` is already public on `Database`/`Group`
  (`src/include/libkeepass/database.hh:321`,
  `src/include/libkeepass/group.hh:264`), but CSV output is still implemented
  inside the CLI (`cli/kpx.cc:523`).
- **Plan:** promote CSV serialization into the library as first-class
  `Database::ToCsv(Format)` (format-tunable) so consumers do not need the CLI
  binary.

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
- Signatures, cipher/KDF UUIDs, version constants and size limits are
  scattered across `kdbx_header.cc`, `kdbx_kdf.cc`, `kdb.cc` and `keepass.cc`.
  Move them into a single `detail/constants.hh`.

### P3 - Independent CMake components
- If consumer demand grows, expose `libkeepass` as optional components
  (model / kdb / kdbx / cli) via `find_package(... COMPONENTS ...)`.

---

## 5. Usability

### P1 - Synchronize the `kpx` version
> ⚡
- `cli/kpx.cc:45` hard-codes `0.2.0` while the library is at `0.3.0`. Derive
  the CLI version from `PROJECT_VERSION` at build time.

### P1 - Complete Open/Save API parity
- `KeePass::Open` supports paths and streams, but `SaveAs` only supports
  paths (`src/keepass.cc:157`). Add stream overloads for `SaveAs` and a
  consistent `KeePass::Save(dst, db, key)` so re-encrypting to a stream is
  possible.

### P2 - Clarify `KeePass::Create` semantics
- `KeePass::Create` takes a `password` argument that is ignored
  (`src/keepass.cc:174`). Either drop the parameter or make the returned
  database carry the key so a subsequent `Save` uses it (keeping the current
  behavior on the stream-based path).

### P2 - Extend the `kpx` command set
Most-wanted commands that users of a KeePass tool expect:
- `kpx create <file>` - create a brand-new empty database,
- `kpx passwd` - change the master password and/or KDF parameters in place,
- `kpx groups`/`--list-groups` - list groups without entries,
- `kpx move` - move entries/groups between groups,
- `kpx merge` / `kpx import` - merge a second database into the current one,
- `kpx history`/`purge` - manage and clear entry history,
- `kpx otp` - display/export TOTP seeds stored in custom fields.

### P2 - CLI output improvements
- CSV escaping is already RFC 4180-quoted (`CsvField`, `cli/kpx.cc:506`).
  Remaining: document the JSON/CSV field schema explicitly, support
  `--include-attachments`/base64 and a machine-readable `--format json` error
  output (structured errors).

### P2 - Better diagnostics and consistent exit codes
- Print context ("while parsing group X", "offset 0x1234") on failures and
  document a stable exit-code mapping per error category.

### P2 - API ergonomics
- Automatic invalidation of the cached transformed key on KDF parameter
  mutation is already implemented (`src/include/libkeepass/database.hh`).
  Remaining: `Key::FromStream`/`FromBytes` for in-memory keyfiles, a
  `KeePass::Open` overload taking a `const uint8_t*`/size pair and typed
  attachment accessors.

### P2 - Documentation and migration guides
- Format × feature support matrix (KDB / KDBX3 / KDBX4 × ciphers/KDFs/
  features), a 0.2 → 0.3 `secure_string` migration guide, worked examples for
  attachments, tags, recycle bin and stream round-trips, and a TOC for
  `CONTRIBUTING.md`.

### P3 - Language bindings
- Start with a C ABI (`libkeepass-c`) so Python/Go/Rust bindings and
  higher-level tools can be built without reimplementing the format logic.

---

## 6. Testing & Quality

### P1 - Cross-format round-trip property tests
- For every feature × format (KDB, KDBX3, KDBX4, and up-conversions), build a
  randomized database through the public API, export it, re-import it, and
  compare a canonical JSON/`ToJson()` snapshot. This is the highest-value gap
  in the current suite.

### P1 - Sanitizer CI job
- New CI matrix entry running all tests under ASan+UBSan (and LSan where
  supported) on Linux; consider MSan once the toolchain for dependencies is
  available.

### P2 - Broaden fuzzing
- Current targets cover KDB and KDBX **import** only. Add:
  - XML/protected-field mutation target (including inner-header and
    variant-dictionary fuzzing),
  - keyfile parsing,
  - export/save path (fuzz the model feeding `Export`),
  - KDB header field fuzzing (many paths are only covered by static seeds).
- Integrate with OSS-Fuzz for continuous corpus growth and coverage
  reporting; keep the in-repo corpus in sync.

### P2 - Adversarial fixtures
- Extend `test/robustness.cc` with a generated fixture set: truncated,
  oversized, unknown field ids, duplicate header fields, deep nesting, huge
  declared sizes, zip bombs, HMAC tampering and CBC bit-flips.

### P3 - Concurrency & resource tests
- Concurrent open of the same file, no leakage of the cached transformed key
  across `KeePass` instances, and `secure_alloc`/`secure_free` behavior under
  allocation failure.

### P2 - CodeQL/security triage loop
- Add a scheduled triage of CodeQL and nightly security scan findings into
  the repo (report file autogenerated on run).

---

## 7. Ecosystem & Infrastructure

### P2 - Finalize ConanCenter publishing
- The recipe migration to CCI v2 is done for 0.3.0; finish the ConanCenter
  submission so `libkeepass/0.3.x` becomes installable via `conan install`.

### P2 - Expand package coverage
- Add a vcpkg port, optional Homebrew formula and prebuilt binaries in GitHub
  Releases (TGZ/ZIP/DEB/RPM already produced by CPack). Ship checksums and an
  SBOM with each release and sign the artifacts where feasible.

### P1 - Release automation
- Tag-driven workflow that builds packages on all OSes, creates the GitHub
  Release, and verifies the Conan recipe with `conan create` and the
  `test_package` consumer before publishing.

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