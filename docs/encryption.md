# Encryption Flow

This document describes how libkeepass encrypts the payload of a KDBX
database. See [key-derivation.md](key-derivation.md) for how the cryptographic
keys are produced and [kdbx-parsing.md](kdbx-parsing.md) for the surrounding
file format.

## Overview

A KDBX file consists of two layers:

```
+--------------------------------------------------------------+
| KDBX header (signature, version, cipher/KDF parameters, ...) |
+--------------------------------------------------------------+
| Stream framing   (Hashed blocks in KDBX 3,                   |
|                   HMAC blocks in KDBX 4)                     |
+--------------------------------------------------------------+
| Encrypted payload (AES-256-CBC / Twofish-CBC / ChaCha20)     |
+--------------------------------------------------------------+
| Plain content: inner header (KDBX 4) + XML document          |
+--------------------------------------------------------------+
```

The payload is encrypted with a *final key* derived from the user key:

```
final_key = SHA-256(master_seed || transformed_key)
```

*   `master_seed` comes from the KDBX header.
*   `transformed_key` is produced by the key-derivation function
    (AES-KDF for KDBX 3, AES-KDF or Argon2 for KDBX 4), see
    [key-derivation.md](key-derivation.md).

## Block ciphers — `src/cipher.cc`

The library works on fixed 16-byte blocks. `block_transform` (`src/cipher.cc:36`)
is a small helper that slices a stream into 16-byte blocks and feeds each
through a `BlockOperation` lambda.

Two operating modes are used:

*   **`encrypt_ecb` / `decrypt_ecb`** (`src/cipher.cc:66`, `:81`) — used only by
    the AES-KDF transform, never for the database payload itself.
*   **`encrypt_cbc` / `decrypt_cbc`** (`src/cipher.cc:126`, `:169`) — used for
    the actual payload in KDBX 3 and KDBX 4 (AES / Twofish).

ECB and CBC in this code base always operate on full 16-byte blocks with
OpenSSL padding disabled; CBC adds **PKCS #7** padding manually:

*   Encryption `encrypt_cbc`: the last partial block is padded to 16 bytes with
    the pad length as the padding byte value. A full block is always appended
    (padding `0x10 ... 0x10`) when the input length is an exact multiple of 16.
*   Decryption `decrypt_cbc`: reads the pad length from the last byte of the
    final block, validates every padding byte, and strips it.

### Cipher implementations

| Cipher | Constructor | Notes |
|---|---|---|
| `AesCipher` | `AesCipher(key[32], iv[16])` | Wraps OpenSSL `EVP_aes_256_ecb` with padding disabled; used for single-block crypto. |
| `TwofishCipher` | `TwofishCipher(key[32], iv[16])` | Pure software implementation (16 rounds, Reed-Solomon key schedule, MDS matrix, PHT). |
| `ChaCha20Cipher` | `ChaCha20Cipher(key[32], iv[12])` | Pure software implementation (20 rounds), used as a stream cipher in KDBX 4. |
| `Salsa20Cipher` | `Salsa20Cipher(key[32], iv[8])` | Pure software implementation (20 rounds), used for the inner random stream in KDBX 3 / KDBX 4 Salsa20. |

`ChaCha20` and `Salsa20` are stream ciphers: `Process()` XORs each 64-byte
block with the keystream and increments an internal counter (`src/cipher.cc:678`).
Because ChaCha20 needs no padding, the KDBX 4 payload is XORed directly.

## Stream framing — `src/stream.cc`

Stream buffers translate between the encrypted blocks on disk and a plain
byte stream consumed by the XML parser. They are layered `std::streambuf`
implementations.

### Hashed blocks (KDBX 3 and KDB 1.x)

`hashed_istreambuf` / `hashed_ostreambuf` split a stream into blocks. Each
block is stored as:

```
struct BlockHeader {
    uint32_t block_index;
    uint8_t  block_hash[32];   // SHA-256 of the block data
    uint32_t block_size;
};
```

*   Every block is integrity-checked with SHA-256 (`GetBlockHash()`).
*   A trailing block with `block_size == 0` and a zero hash signals end of
    stream; writing always ends with such a block.
*   The block index is validated and incremented while reading.

### HMAC blocks (KDBX 4)

`hmac_istreambuf` / `hmac_ostreambuf` protect the **ciphertext**. Each block
is framed as `HMAC-SHA256 (32) || block_size (4) || data`.

A fresh 64-byte HMAC key is derived per block:

```
block_hmac_key = SHA-512(block_index || hmac_key)
```

The MAC input is the concatenation `block_index (8 LE) || block_size (4 LE) || data`.
The base `hmac_key` itself is derived from the master seed and the transformed
key (see `key-derivation.md#hmac-key`).

### Gzip (optional)

`gzip_istreambuf` / `gzip_ostreambuf` wrap zlib's `inflate` / `deflate` when
the database's compression flag is `gzip`.

## KDBX 3 payload layout

Import path (`KdbxFile::Import3`, `src/kdbx.cc:1038`) — from ciphertext to XML:

```
Encrypted payload (AES-256-CBC, PKCS#7)
  -> decrypt_cbc
  -> prepended 32-byte "start bytes"  (must match the header value,
                                        otherwise PasswordError)
  -> hashed_istreambuf                 (block + SHA-256 framing)
  -> gzip_istreambuf  (optional)
  -> XML document
```

The plaintext begins with the 32-byte **content stream start bytes** stored in
the header. They are decrypted too and compared against the header value —
this doubles as a fast password check (`src/kdbx.cc:1164`).

## KDBX 4 payload layout

Import path (`KdbxFile::Import4`, `src/kdbx.cc:1200`) — from ciphertext to XML:

```
Encrypted payload (AES-256-CBC / Twofish-CBC / ChaCha20)
  <- wrapped in hmac_istreambuf         (HMAC-SHA256 over the ciphertext)
  -> decrypt (CBC with PKCS#7, or ChaCha20 stream XOR)
  -> gzip_istreambuf  (optional)
  -> inner header (random stream ID + key, binaries)
  -> XML document
```

Differences to KDBX 3:

*   The outer framing is HMAC, not plain hashed blocks.
*   ChaCha20 (or Twofish) can replace AES as the payload cipher.
*   The inner random stream key is transported *inside* the encrypted payload
    (inner header), not in the outer header.
*   There is no separate `content_start_bytes` check; the header HMAC already
    verifies integrity and the password.

Cipher IDs in the KDBX 4 header (`src/kdbx.cc:88`):

| Cipher | UUID |
|---|---|
| AES | `31 c1 f2 e6 bf 71 43 50 be 58 05 21 6a fc 5a ff` |
| ChaCha20 | `d6 03 8a 2b 8b 6f 4c b5 a5 24 33 9a 31 db b5 9a` |
| Twofish | `ad 68 f2 9f 57 6f 4b b9 a3 6a d4 7a f9 65 34 6c` |

## Export path

Export mirrors the import layers in reverse order:

*   `KdbxFile::Export3` (`src/kdbx.cc:1539`): write header → derive final key →
    serialize XML → optional gzip → `hashed_ostreambuf` → prepend start bytes →
    `encrypt_cbc` → write.
*   `KdbxFile::Export4` (`src/kdbx.cc:1655`): write header + stored hash + stored
    HMAC → serialize XML → optional gzip → encrypt (`encrypt_cbc` or ChaCha20) →
    wrap in `hmac_ostreambuf` → write.

Both exporters write the header to an in-memory stream first so that the
SHA-256 header hash (and the KDBX 4 HMAC) can be computed and stored with the
file.

## Integrity checks at a glance

| Step | KDBX 3 | KDBX 4 |
|---|---|---|
| Header integrity | SHA-256 hash stored in `<Meta><HeaderHash>`, verified after XML parse | SHA-256 hash + HMAC-SHA256 stored right after the header, verified immediately |
| Payload framing | hashed blocks (SHA-256/block) | HMAC blocks (HMAC-SHA256/block) |
| Password check | start bytes comparison | header HMAC verification |