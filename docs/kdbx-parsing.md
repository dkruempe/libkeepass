# KDBX Parsing Pipeline

This document describes how libkeepass parses a KDBX database from bytes on
disk to an in-memory `Database` object (and back). The entry points are
`KdbxFile::Import` / `KdbxFile::Export` in `src/kdbx.cc`.

> The legacy KDB 1.x format uses a different binary layout and is implemented
> in `src/kdb.cc`; this document covers KDBX (KeePass 2).

## File layout

```
+--------------------------+
| Signature 0  (0x9aa2d903)|
| Signature 1  (0xb54bfb67)|
| Version (uint32)         |
+--------------------------+
| Header fields ...         |
+--------------------------+   <-- everything above is authenticated
| (KDBX 4) stored header
|   SHA-256 (32) + HMAC (32)|
+--------------------------+
| Stream framing ...        |
| Encrypted payload ...     |
+--------------------------+
```

The version's critical mask `0xffff0000` selects the parser
(`KdbxFile::Import`, `src/kdbx.cc:1008`):

*   `0x00030000` → `Import3` (KDBX 3)
*   `0x00040000` → `Import4` (KDBX 4)
*   anything else → `FormatError`

## Header fields

### KDBX 3 — `KdbxHeaderField { uint8 id; uint16 size; }`

Fields are read as `id(size) data`. Recognized IDs (`src/kdbx.cc:143`):

| ID | Field | Content |
|---|---|---|
| 2 | Cipher ID | 16-byte UUID; only AES (`31 c1 f2 e6 ...`) supported in KDBX 3 |
| 3 | Compression flags | `0` = none, `1` = gzip |
| 4 | Master seed | byte vector |
| 5 | Transform seed | 32 bytes |
| 6 | Transform rounds | uint64 |
| 7 | Encryption IV | 16 bytes |
| 8 | Inner random stream key | 32 bytes |
| 9 | Content stream start bytes | 32 bytes |
| 10 | Inner random stream ID | must be `1` (Salsa20) |
| 0 | End of header | — |

### KDBX 4 — `Kdbx4HeaderField { uint8 id; uint32 size; }`

| ID | Field | Content |
|---|---|---|
| 2 | Cipher ID | AES / Twofish / ChaCha20 UUID (see [encryption.md](encryption.md#cipher-implementations)) |
| 3 | Compression flags | as above |
| 4 | Master seed | byte vector |
| 7 | Encryption IV | 12 bytes (ChaCha20) or 16 bytes |
| 11 | KDF parameters | `VariantDictionary` (see [key-derivation.md](key-derivation.md#argon2-kdbx-4)) |
| 0 | End of header | — |

## Import pipeline

### `KdbxFile::Import` (`src/kdbx.cc:1008`)

1.  `Reset()` all internal pools (see below).
2.  Read and validate the signature + version.
3.  Delegate to `Import3` or `Import4`.

### `Import3` (`src/kdbx.cc:1038`)

1.  **Parse header fields** into a fresh `Database` (cipher, compression,
    seeds, IV, inner stream key, start bytes).
2.  **Header hash**: SHA-256 over all bytes from the start of the file up to
    (but not including) the end of the header.
3.  **Derive keys**: `transformed_key = AES-KDF(transform_seed, rounds)`;
    `final_key = SHA-256(master_seed || transformed_key)`
    (see [key-derivation.md](key-derivation.md)).
4.  **Decrypt** the payload with AES-256-CBC (PKCS #7).
5.  **Verify start bytes**: the first 32 decrypted bytes must equal the header's
    start bytes, otherwise `PasswordError`.
6.  **Unwrap blocks**: `hashed_istreambuf`, then optional `gzip_istreambuf`.
7.  **Parse XML** via `ParseXml`.
8.  **Verify stored header hash** against `<Meta><HeaderHash>`; this happens
    after the XML is parsed because the hash is stored inside the XML.

### `Import4` (`src/kdbx.cc:1200`)

1.  **Parse header fields**, including the KDF `VariantDictionary`
    (Argon2/AES parameters).
2.  Compute header SHA-256 and compare with the **stored header hash**.
3.  **Derive keys**: `transformed_key` = AES-KDF or Argon2;
    `hmac_key` and `header_hmac_key` per `key-derivation.md`.
4.  Verify the **stored header HMAC** (a wrong password fails here →
    `PasswordError`).
5.  `final_key = SHA-256(master_seed || transformed_key)`.
6.  **Read ciphertext through `hmac_istreambuf`** (HMAC framing is the outer
    layer, over the ciphertext).
7.  **Decrypt** (AES/Twofish CBC or ChaCha20 stream).
8.  Optional **gzip** decompress of the *entire* payload.
9.  **Parse inner header** (`src/kdbx.cc:1451`):

    | ID | Field | Content |
    |---|---|---|
    | 1 | Inner random stream ID | `1` = Salsa20, `3` = ChaCha20 |
    | 2 | Inner random stream key | 32 or 64 bytes |
    | 3 | Binaries | one entry per attachment: `flags u8` (`0x01` = protected) then data |
    | 0 | End | — |

    Binaries are collected into `binary_pool_` and later added to the
    database meta so they survive round-trips.
10. **Parse XML** (which follows the inner header in the same payload).

### `ParseXml` (`src/kdbx.cc:936`)

Uses **pugixml** (`parse_default | parse_trim_pcdata`). Required structure:

```
<KeePassFile>
  <Meta> ... </Meta>
  <Root>
    <Group> ... </Group>   <!-- the root group; parsed recursively -->
```

1.  `ParseMeta` (`src/kdbx.cc:335`) fills `Metadata`: generator, database
    name/description, memory protection flags, recycle bin, entry templates,
    history limits, custom icons and binaries, plus the stored `HeaderHash`.
2.  `ParseGroup` (`src/kdbx.cc:825`) recursively builds the group tree and
    calls `ParseEntry` (`src/kdbx.cc:593`).

    *   Groups are tracked in `group_pool_` (keyed by UUID string) so that
        cross-references such as `RecycleBinUUID` and the last-selected group
        resolve to shared objects.
    *   Entries are parsed into `Entry` objects including custom fields,
        attachments (resolved through `binary_pool_`) and history entries.
3.  Because `LastSelectedGroup` / `LastTopVisibleGroup` reference parsed
    groups, they are resolved only *after* the group tree is complete
    (`src/kdbx.cc:962`).

### Protected strings (`src/kdbx.cc:308`)

Fields marked `Protected="True"` are stored Base64-encoded and XORed with the
inner random stream. `ParseProtectedString` decodes and deobfuscates them into
`protect<std::string>`; `WriteProtectedString` does the reverse on export.
The obfuscator is a `RandomObfuscator` (`src/random.cc`) over Salsa20 (KDBX 3)
or Salsa20/ChaCha20 (KDBX 4).

## Export pipeline

### `KdbxFile::Export` (`src/kdbx.cc:1520`)

Writes KDBX 4 when forced via `set_write_kdbx4(true)` or when the database KDF
is not AES; otherwise writes KDBX 3.

### `Export3` (`src/kdbx.cc:1539`)

1.  Derive/reuse `transformed_key` and `final_key`.
2.  Serialize the header fields into an in-memory stream, compute the SHA-256
    header hash, write the header to the file.
3.  Build the content: `start_bytes(32) || hashed_ostreambuf( XML )`.
    XML is optionally gzip-compressed inside the hashed stream.
4.  `encrypt_cbc` the content stream.

### `Export4` (`src/kdbx.cc:1655`)

1.  Derive/reuse `transformed_key`; compute `final_key`, `hmac_key` and the
    header HMAC.
2.  Serialize the header (including the KDF `VariantDictionary`), compute and
    write header SHA-256 + HMAC.
3.  Collect all binaries used by entries into `binary_pool_` (deduplicated,
    in a stable order).
4.  Build the inner header: random stream ID (ChaCha20) + freshly generated
    random key + binary entries.
5.  Concatenate inner header and XML; optionally gzip the whole payload.
6.  Encrypt (`encrypt_cbc` or ChaCha20) the payload, then wrap the ciphertext
    in `hmac_ostreambuf`.

## Internal state — `KdbxFile`

One `KdbxFile` instance is stateful across a single import/export (`Reset()`,
`src/kdbx.cc:198`):

*   `binary_pool_`, `icon_pool_`, `group_pool_` — UUID-keyed caches used to
    preserve object identity across `<Meta>` fields and the group tree.
*   `header_hash_` — the last computed/stored header hash (written back into
    `<Meta><HeaderHash>` on export).
*   `kdbx4_` / `write_kdbx4_` — the active format and the forced-format flag.

The pools are intentionally *not* part of the public `Database` API; they are
bookkeeping that makes parsing and re-serialization faithful.