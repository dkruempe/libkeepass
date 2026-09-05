# Architecture

This is the architecture documentation for **libkeepass**, a C++11 library for
importing and exporting [KeePass](https://keepass.info) password databases.

It complements the generated API reference
([Doxygen](https://dkruempe.github.io/libkeepass/)) by explaining *how the
pieces fit together*.

## Documents

- [Key Derivation Process](key-derivation.md) — how passwords / key files are
  turned into cryptographic keys (AES-KDF, Argon2, composite keys).
- [Encryption Flow](encryption.md) — how the database payload is encrypted,
  framed and integrity-protected (AES/Twofish/ChaCha20, hashed/HMAC blocks).
- [KDBX Parsing Pipeline](kdbx-parsing.md) — the byte-level file format,
  header parsing, XML parsing and export.

## High-level flow

A KDBX database is a layered file: a header with format parameters, followed
by an authenticated, encrypted payload whose plaintext is (optionally
compressed) XML.

```
                    Import                        Export
            +--------------------+         +--------------------+
 password   |                    |         |                    |
 + keyfile  v                    |         |                    v
   Key  --derive->  transformed_key   -->   transformed_key   (AES-KDF / Argon2)
                       |                        ^
                       +--> final_key = SHA-256(master_seed || transformed_key)
                            |                           |   HMAC key (KDBX4)
 file bytes ------> header parse ------> decrypt ------> XML (pugixml)
                           .                              |   Database
                     encrypted payload ---------> encrypt |
```

## Module reference

Source layout:

```
src/
├── include/libkeepass/   public headers (Doxygen-documented API)
├── aes_ni.cc             AES-NI accelerated AES-KDF core loop
├── cipher.cc             block/stream ciphers (AES, Twofish, Salsa20, ChaCha20)
├── entry.cc              Entry, Attachment, AutoType, history
├── group.cc              Group tree and ToJson() serialization
├── io.cc                 endian-aware read/write helpers (consume/conserve)
├── kdb.cc                legacy KDB 1.x importer/exporter
├── kdbx.cc               KDBX 2.x importer/exporter (import/export pipeline)
├── key.cc                user key handling and key derivation (AES-KDF, Argon2)
├── metadata.cc           Metadata (database meta, binaries, icons, custom data)
├── random.cc             inner random stream obfuscator (Salsa20 / ChaCha20)
├── stream.cc             streambufs: hashed blocks, HMAC blocks, gzip
├── util.cc               time formatting, UUID generation
└── variantdictionary.cc  KDBX 4 KDF parameter dictionary
```

Key entry points:

| Entry point | Purpose |
|---|---|
| `keepass::KdbxFile::Import` / `Export` | KDBX file → `Database` and back |
| `keepass::KdbFile::Import` / `Export` | legacy KDB format |
| `keepass::Key` | password / keyfile / KDF handling |

The graphical `kpx` CLI in `cli/` is a full consumer of the library and a good
starting point for examples.

## Layering

```
                      +------------------+
                      | Database / Group |
                      |  / Entry / Meta  |   public object model
                      +------------------+
                              |
                +-------------+-------------+
                |       kdbx.cc / kdb.cc    |   format import/export
                +-------------+-------------+
                              |
          +-------------------+-------------------+
          | cipher.cc | stream.cc | key.cc /        |
          |           | gzip      | random.cc       |   crypto & I/O
          +-------------------+--------------------+
                              |
          OpenSSL | zlib | pugixml | Argon2 | AES-NI
```

Dependencies (provided via Conan): OpenSSL (ciphers, hashes, HMAC), zlib
(gzip), pugixml (XML), Argon2, Google Test (unit tests only).