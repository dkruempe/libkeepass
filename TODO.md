# libkeepass - Roadmap

> Prioritized list (P0 highest first) for further development. The old roadmap
> (security foundation, KDBX 4.1, kpx CLI, architecture, templates) is fully
> implemented, was removed here and is summarized below.

---

## Status v0.3.0

Completed foundation (details in `CHANGELOG.md`):

- **Security:** HMAC-/header integrity verified on import (encrypt-then-MAC),
  binary/attachment payloads and transient keys/plaintexts wiped, libFuzzer
  targets plus robustness/negative tests, cap limits against OOM/CPU-burn
- **Format:** KDB, KDBX 3, KDBX 4.0 and KDBX 4.1 read/write; 4.1 verified
  against KeePass-2.57 fixtures, version only written when needed
- **CLI (`kpx`):** text/JSON/CSV, export, keyfiles, `--search`/`--group`,
  `--generate`, `add`/`update`/`rm`, documented exit codes
- **Architecture:** `KdbxFile` split into `KdbxHeader`/`KdbxKdf`/`KdbxXml`,
  streamed KDBX-4 decryption, load benchmark in CI
- **Ecosystem:** CI on Linux/macOS/Windows, CodeQL, Doxygen/GitHub Pages,
  issue/PR templates; ConanCenter recipe raised to CCI-v2 conventions and
  submitted as PR
  ([conan-io/conan-center-index#30962](https://github.com/conan-io/conan-center-index/pull/30962)),
  `conanfile.py`/`test_package` verified locally via `conan create`

The focus shifts from "more features" to **release readiness and ecosystem
integration** plus targeted format extensions. The P0 items of the v0.4.0
release-readiness (C++17 standard policy, CHANGELOG/documentation wrap-up) are
implemented (see the last merge order) and were removed from this list.

---

## Legend

- **Feature** = feature / format compatibility
- **Security** = security
- **Architecture** = code/API structure
- **Reachability** = visibility / integration / usability
- **Performance** = performance

---

## P1 - Format & feature expansion (v0.4.x)

### 1. KeePassXC / Strongbox compatibility

**Category:** Feature
**Effort:** M
**Target version:** v0.4.x

Implemented and completed:

- [x] KeePassXC verification via a real test corpus (not generatable:
      `keepassxc-cli` needs GUI libs, therefore real fixtures from the
      `keepassxreboot/keepassxc` `tests/data/` were imported): KDBX 4.0
      ChaCha20+Argon2d+gzip, KDBX 3.1 protected strings, recycle bin; new test
      binary `libkeepass.compat` (`test/data/compat/`)
- [x] Divergences documented (`docs/interop.md`), incl. Strongbox: 16-byte
      Argon2 salt (covered fixture-side), Argon2 `K`/`A` parameters (ignored on
      import), keyfile formats (XML + 64-hex supported; 32-byte
      raw/digest-SHA256 fallback is a documented gap)
- [x] Bugfix triggered by verification: `RecycleBinUUID` pointed to an empty
      placeholder group instead of the group holding the entries (metadata is
      parsed before the group tree; `ParseGroup` now passes on the placeholder
      object)

### 2. `kpx`: password audit

**Category:** Reachability / usability
**Effort:** S-M
**Target version:** v0.4.x

Building on the existing search/traversal infrastructure:

- [x] `--audit`: detect weak (length/character set) and reused passwords
- [x] Output in text/JSON/CSV (for CI/scripting use)

Implemented and completed:

- `RunAudit` classifies entries as *empty*, *short (N)*, *single-character-class* /
  *digits-only*, *based-on-title* / *based-on-username* (>=4 characters),
  *common-password* (a blocklist of the most common passwords); reuse is
  reported as *reused (N entries)*
- Formats: text, JSON, CSV; the CLI `--group` restricts the scope to the
  subtree; `--with-passwords` shows passwords in the *Reused passwords* section
  (text) and in the JSON reuse array
- Tests cover all output formats, the group scope, the no-findings case and
  JSON with/without passwords

---

## P2 - Reachability / ecosystem

### 3. Hardware tokens / YubiKey (evaluation, long-term)

**Category:** Feature
**Effort:** XL
**Target version:** open

KeePass supports external key sources (YubiKey/challenge-response). No
immediate priority for libkeepass as a library; documented as a fundamental
decision, whether/how this fits the `Key` abstraction.

- [x] No time horizon; architecture hook in `key.hh` intentionally left open
- [x] Dependency and licensing effort evaluated (external dev lib), decision
      recorded here

Implemented and completed:

Decision: no hardware-token support in the foreseeable future. The `Key` model
stays open as an extension point (additional sub key in the composite hash,
analogous to password/keyfile); no KDBX format work is required. Documentation
incl. dependencies/licensing (BSD-2 compatible) and effort estimate in
`docs/hardware-tokens.md`.

---

## Decisions / open points

- [x] Tolerance policy for unknown/future XML fields and unknown
      KDF/cipher OIDs: decided and documented in `docs/interop.md`
      (integrity-relevant: error; optional/non-critical: ignore)
- [ ] OSS-Fuzz integration: evaluated and deferred (a hermetic
      non-Conan build is required); re-check as soon as the Conan build
      qualifies (cf. fuzz workflow in `.github/workflows/fuzz.yml`)
- [x] Entry history: API (`save_history`/`delete_history`) available;
      CLI/(.json?)-visibility **deliberately not** extended — decision: history
      is fully round-trippable but not part of the day-to-day view/the audit;
      interested parties use the public API directly (see the
      `Entry::history()` docstring)