# Third-party interoperability

Scope: this document records which real-world KeePass ecosystem files were
verified against libkeepass, and which provider-specific divergences are known.
"KeePass itself" (reference) is covered in `test/kdbx4.cc` (KeePass 2.57
fixtures); this document focuses on KeePassXC and Strongbox.

## Verified matrix

| Provider | File (in `test/data/compat/`) | Format | Cipher / KDF / compression | Master key | Verified expectations |
|---|---|---|---|---|---|
| KeePassXC (test corpus) | `Format400.kdbx` | KDBX 4.0 | ChaCha20 + Argon2d / gzip | `t` | Root group `Format400`, one entry with title/username/password `Format400`, attachment `Format400` → `"Format400\n"` |
| KeePassXC (test corpus) | `ProtectedStrings.kdbx` | KDBX 3.1 | AES-KDF (legacy) | `masterpw` | Entry `Sample Entry` (username `Protected User Name`, password `ProtectedPassword`) with per-field protection flags preserved: `TestProtected` (protected, `ABC`) vs `TestUnprotected` (unprotected, `DEF`) |
| KeePassXC (test corpus) | `RecycleBinWithData.kdbx` | KDBX 3.1 | AES-KDF (legacy) | `123` | Recycle-bin group resolves to the *same* group object that holds the deleted entries (`Obsolete e-mail`, `Old Wi-fi`) |

The KeePassXC fixtures are byte-identical copies of files published in
KeePassXC's own test corpus (`tests/data/`); their expected contents match what
KeePassXC's own unit tests assert. The dedicated test binary
`test/compat.cc` (`ctest -R compat`) verifies them and runs in CI.

Additional provider coverage is already embedded in `test/data/kdbx4/`:
- **KeePass 2.57**: KDBX 4.0/4.1 with AES + Argon2d/Argon2id, custom data,
  previous-parent-group migration, tags, history (`test/kdbx4.cc`).
- **Keyfiles**: password + 64-hex-text keyfile (`kdbx4-aes-argon2d-keyfile.kdbx`
  with `test.key`), without keyfile, and with a wrong keyfile/password.

## Provider divergences

### KeePassXC defaults differ from KeePass

KeePassXC writes KDBX 4.0 databases with **ChaCha20 + Argon2d + gzip** by
default, while KeePass defaults to **AES + Argon2d + gzip**. Both combinations
(and AES-KDF) are verified. The KDBX 4.1 `previous_parent_group` field is a
*KeePass* extension; KeePassXC emits it as well in recent versions.

### Strongbox

Strongbox (iOS/macOS) cannot be executed in this environment, so no
Strongbox-authored file is imported directly. Upstream divergence reports were
used instead, and each is mapped to libkeepass behavior/coverage:

- **Non-32-byte Argon2 salts** — Strongbox wrote 16-byte Argon2 salts until
  v1.19.3 (upstream issue
  [strongbox-password-safe/Strongbox#23](https://github.com/strongbox-password-safe/Strongbox/issues/23)).
  Argon2 allows salt lengths ≥ 8 bytes and does **not** require 32. libkeepass
  accepts arbitrary salt sizes from the KDF variant dictionary; the fixture set
  deliberately includes 16-byte-salt files
  (`kdbx4-aes-argon2d-gzip.kdbx`, `kdbx4-aes-argon2id.kdbx`,
  `kdbx4-aes-argon2d-keyfile.kdbx`).
- **Argon2 secret key / associated data** — some Strongbox versions emit the
  optional Argon2 parameters `K` (secret) and `A` (associated data) in the KDF
  variant dictionary. Like KeePass/KeePassXC, libkeepass ignores parameters it
  does not act upon instead of rejecting the file.
- **Keyfile variants** — upstream issue
  [strongbox-password-safe/Strongbox#241](https://github.com/strongbox-password-safe/Strongbox/issues/241)
  enumerates four keyfile specs: KeePass XML key file, 32-byte raw digest,
  64-hex-character text file, and the SHA-256 "hashing fallback" for arbitrary
  binary files. libkeepass supports the **XML key file** (32-byte base64
  `Data`) and the **64-hex-character text file**. Raw 32-byte binary digest
  files and the arbitrary-binary hashing fallback are **not** supported
  (`Key::SetKeyFile` rejects them) — this is a documented limitation, not a
  silent fallback.

## Tolerance policy

libkeepass applies the following policy to unknown / future data:

- **Unknown integrity-relevant header/KDF values** (unknown cipher UUID,
  unknown KDF OID, unknown compression) are a hard error (`FormatError`). This
  is deliberate: decrypting with wrong semantics is worse than failing loudly.
- **Unknown or optional XML fields** (e.g. future metadata attributes) are
  ignored on import. Custom Data blobs, unknown custom attributes and unknown
  Argon2 parameters fall into this category.
- **Parameter ranges** for supported KDFs are validated against the format
  spec (seed sizes, iteration counts, Argon2 bounds) to prevent CPU/memory
  burn on hostile files; values that are merely unusual (16-byte salt) are
  accepted.

This policy was confirmed/kept as part of the KeePassXC/Strongbox work and is
documented here so future format work has a single reference point.