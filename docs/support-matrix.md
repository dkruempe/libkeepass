# Format and feature support

This matrix describes what libkeepass reads and writes. It is kept in sync with
the importer/exporter tests (`test/kdb.cc`, `test/kdbx.cc`, `test/kdbx4.cc`,
`test/compat.cc`, `test/property.cc`).

Legend: **R** = read, **W** = write, **—** = not applicable/unsupported.

## Container formats

| Format | Read | Write | Notes |
|---|---|---|---|
| KDB (KeePass 1.x) | R | W | AES-256 + AES-KDF only; no attachments or KDBX-only features. |
| KDBX 3.x | R | W | AES cipher, AES-KDF, gzip or plain payload, hashed block stream. |
| KDBX 4.0 | R | W | AES/Twofish/ChaCha20, AES-KDF or Argon2d/Argon2id, HMAC block stream, inner header. |
| KDBX 4.1 | R | W | 4.0 plus tags, custom-data timestamps, previous-parent UUIDs, deletion tombstones, quality-check flag; written only when a 4.1-only feature is used. |

Auto-detection reads the 8-byte signature. KDB and KDBX3/4 are distinguished
without buffering a seekable stream; non-seekable streams fall back to an
in-memory copy.

## Ciphers and KDFs

| Capability | KDB | KDBX 3 | KDBX 4 |
|---|---|---|---|
| AES-256-CBC | R/W | R/W | R/W |
| Twofish-CBC | — | — | R/W |
| ChaCha20 | — | — | R/W |
| AES-KDF | R/W | R/W | R/W |
| Argon2d | — | — | R/W |
| Argon2id | — | — | R/W |
| gzip compression | — | R/W | R/W |
| Uncompressed payload | — | R/W | R/W |

KDBX 3 can only be written with AES + AES-KDF; selecting any other
combination through the unified API automatically selects KDBX 4.

## Object model features

| Feature | KDB | KDBX 3 | KDBX 4 | API |
|---|---|---|---|---|
| Groups/entries, standard fields | R/W | R/W | R/W | `Group`, `Entry` |
| Custom string fields | — | R/W | R/W | `Entry::custom_properties` |
| Protected (in-memory encrypted) strings | — | R/W | R/W | `Entry::password`, `protect<secure_string>` |
| Entry history | — | R/W | R/W | `Entry::history`, `Entry::delete_old_history` |
| Attachments / binaries | — | R/W | R/W | `Entry::attachments`, `Binary` |
| Custom icons | — | R/W | R/W | `Metadata::custom_icons` |
| Tags | — | — | R/W | `Entry`/`Group::tags` |
| Recycle bin | — | R/W | R/W | `Database::Trash*`, `EmptyRecycleBin` |
| Custom data | — | — | R/W | `Metadata::custom_data` |
| Deletion tombstones | — | — | R/W | `Metadata::deleted_objects` |
| TOTP seed fields | — | R/W* | R/W* | `TotpConfig`, `Totp`, `Entry::totp` |

\* TOTP seeds are preserved as ordinary custom string fields. `TotpConfig`
parses the `otp`/`TOTP Seed`/`TOTP Settings` variants and complete
`otpauth://totp/...` URIs; `Totp::Generate` produces RFC 6238 codes, and
`kpx otp --code` prints them. HOTP and Steam-specific alphabets are not
generated.

## Unified API behaviour

| Operation | Behaviour |
|---|---|
| `KeePass::Open(path/stream)` | Auto-detects KDB/KDBX3/KDBX4; rejects corrupt files with `FormatError` and wrong credentials with `PasswordError`. |
| `KeePass::Save(path, db)` | Chooses KDB from the `.kdb` extension, otherwise KDBX 4 for non-AES ciphers/KDFs and KDBX 3 for AES + AES-KDF. `SetFormat` overrides this. |
| `KeePass::Save(stream, db)` | Same format choice as above, except KDB cannot be selected without a file extension. |
| `KeePass::SaveAs(..., key)` | Re-encrypts with the supplied key, overriding any transformed key cached on the database. |
| `KeePass::Create(password, ...)` | Generates seeds and KDF parameters and caches the transformed key (except for KDB output). |
| `Database::ToCsv` | RFC 4180-compatible CSV with an optional password column. |
| `Database::ToJson` | Stable canonical snapshot used by the property tests. |

## Resource limits

Import is driven by untrusted length fields. The default budgets in
`libkeepass/detail/limits.hh` cap decompressed bytes, block counts/sizes, XML
depth, object counts, string-field bytes and binary sizes. Hostile inputs are
rejected with `FormatError` before allocating beyond the limits. Key files are
limited to `Key::kMaxKeyFileBytes` (1 MiB).
