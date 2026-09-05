# Key Derivation Process

This document explains how libkeepass turns a user password / key file into
the cryptographic keys that encrypt and authenticate a KDBX database. The
implementation lives in `src/key.cc` (with an SIMD fast path in
`src/aes_ni.cc`).

## User key components — `Key` and `CompositeKey`

`keepass::Key` (`src/include/libkeepass/key.hh`) holds two 32-byte sub keys:

| Component | Set via | Derivation |
|---|---|---|
| `password_key_` | `SetPassword()` | `SHA-256(password)` |
| `keyfile_key_` | `SetKeyFile()` | see below |

Both components may be present at the same time (a *composite key*).

### Key file parsing — `Key::SetKeyFile` (`src/key.cc:71`)

Two formats are accepted:

1.  **XML key file**: parsed with pugixml; the value of
    `<KeyFile><Key><Data>...</Data></Key>` is Base64-decoded and must be
    exactly 32 bytes.
2.  **Hex key file**: treated as a plain text file of 64 hex characters which
    are decoded to 32 bytes.

Anything else raises `FormatError: Unknown key file format`.

### Sub key resolution — `CompositeKey::Resolve` (`src/key.cc:37`)

`SubKeyResolution` selects how the sub keys are combined *before* the KDF runs:

*   `kHashSubKeys` — the present sub keys are always hashed together:
    `SHA-256(password_key || keyfile_key)` (skipping empty ones).
*   `kHashSubKeysOnlyIfCompositeKey` — a single sub key is used as-is; both
    sub keys are combined with `SHA-256` only when the key is truly composite.

Import uses `kHashSubKeys` for both KDBX 3 and KDBX 4
(`src/kdbx.cc:1131`, `:1328`).

## Key derivation functions

### AES-KDF (KDBX 3, and KDBX 4 with the AES KDF UUID)

`Key::Transform(seed, rounds, resolution)` (`src/key.cc:107`):

```
key = Resolve(resolution)                 # 32 bytes
for i in 0 .. rounds-1:
    key = AES-256-ECB(seed, key)          # two 16-byte ECB blocks
return SHA-256(key)
```

The 32-byte plaintext is encrypted with AES-256-ECB where `seed` (the header's
*transform seed*) is the key. Each iteration feeds back into the next. The
final iteration is hashed with SHA-256.

Two implementations of the core loop exist:

*   **OpenSSL path** (default, `src/key.cc:119`): one `EVP_CIPHER_CTX` is
    reused across all `rounds`; padding is disabled.
*   **AES-NI path** (`src/aes_ni.cc:154`): when the binary is built with
    `LIBKEEPASS_AES_NI` and the CPU advertises AES-NI, `aes_ni_supported()`
    is true and `aes_ni_transform_aes_kdf` runs the identical algorithm using
    the hardware AES instructions (`_mm_aesenc_si128`). The result is
    byte-for-byte equal to the OpenSSL path.

### Argon2 (KDBX 4)

`Key::TransformArgon2(kdf, salt, iterations, memory_bytes, parallelism, version, resolution)`
(`src/key.cc:150`):

```
key = Resolve(resolution)                 # 32 bytes (the "passwd")
out = Argon2(key, salt, iterations, memory, parallelism, type, version)  # 32 bytes
```

*   `type` is `Argon2_d` or `Argon2_id`, selected by the `Kdf` argument.
*   `memory_bytes` is converted to KiB before calling `argon2_hash`.
*   `version` accepts `0x10` (Argon2 1.0) or `0x13` (Argon2 1.3).

The parameters come from the KDBX 4 header's **KDF variant dictionary**
(`VariantDictionary` in `src/variantdictionary.cc`). Its `$UUID` entry selects
the KDF and the remaining entries carry the parameters:

| Key | Type | AES-KDF | Argon2d / Argon2id |
|---|---|---|---|
| `$UUID` | ByteArray | `7c 02 bb 82 79 a7 4a c0 92 7d 11 4a 00 64 82 38` (AES, KDBX4) | `ef 63 6d df 8c 29 44 4b 91 f7 a9 a4 03 e3 0a 0c` (d) / `9e 29 8b 19 56 db 47 73 b2 3d fc 3e c6 f0 a1 e6` (id) |
| `S` | ByteArray | transform seed | salt |
| `R` | UInt64 | rounds | — |
| `I` | UInt64 | — | iterations |
| `M` | UInt64 | — | memory in bytes |
| `P` | UInt32 | — | parallelism |
| `V` | UInt32 | — | Argon2 version |

Parsed in `KdbxFile::Import4` (`src/kdbx.cc:1258`) and written back in
`KdbxFile::Export4` (`src/kdbx.cc:1737`).

## Deriving the final keys (KDBX 3 / 4)

Starting from `transformed_key`, two keys are computed:

### Final encryption key

```
final_key = SHA-256(master_seed || transformed_key)
```

Used to instantiate the payload cipher (`src/kdbx.cc:1133` for KDBX 3,
`:1373` for KDBX 4).

### HMAC key (KDBX 4 only)

```
hmac_key          = SHA-512(master_seed || transformed_key || 0x01)
header_hmac_key   = SHA-512(0xFF x 8        || hmac_key)
```

*   `hmac_key` authenticates the HMAC blocks of the payload (`src/kdbx.cc:1342`).
*   `header_hmac_key` authenticates the header itself; the stored 32-byte header
    HMAC is `HMAC-SHA256(header_hmac_key, header_bytes)` (`src/kdbx.cc:1352`).
*   Per-block HMAC sub keys are derived lazily in `src/stream.cc` as
    `SHA-512(block_index || hmac_key)`.

## Transformed key caching

`Database::transformed_key()` / `has_transformed_key()` cache the derived key
(`src/kdbx.cc:1132`, `:1338`). `Export3` / `Export4` reuse the cached value
when present, so re-exporting an imported database does not rerun an
expensive KDF unless the KDF parameters changed (`src/kdbx.cc:1542`, `:1663`).

## Example: full KDBX 4 password-only flow

```
password
  -> SHA-256(password)                       password_key_
  -> (no key file)                           keyfile_key_ = {0}
  -> CompositeKey::Resolve(kHashSubKeys)     composite = SHA-256(password_key_)
  -> Argon2id(composite, salt, I, M, P, 0x13)  transformed_key
  -> final_key = SHA-256(master_seed || transformed_key)
  -> hmac_key  = SHA-512(master_seed || transformed_key || 0x01)
```