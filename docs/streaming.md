# Streaming Parsing Evaluation

Status: **decided** — see `Streaming decisions` below.

This page documents why libkeepass parses KDBX databases the way it does, in
particular where it streams and where it deliberately buffers, and how load
performance is tracked.

See [index.md](index.md) for the overall architecture and
[encryption.md](encryption.md) for the crypto layers.

## Why stream at all

A KeePass database can be large: thousands of entries, attachments and a long
metadata block push the payload well beyond a megabyte. The import pipeline is

```
file → header parse → HMAC framing (KDBX 4) / hashed blocks (KDBX 3)
     → decrypt → gzip → inner header (KDBX 4) → XML → Database
```

Each layer can in principle materialize its whole input. Before the streaming
work in P2, the KDBX 4 importer copied the *entire ciphertext* into a
`std::string` (`ciphertext`) before decrypting, so peak memory was roughly
`3 × payload size` (ciphertext copy + decrypted plaintext copy + DOM).

## What is streamed (P2)

*   **HMAC blocks**: `hmac_istreambuf` (`src/stream.cc`) already reads blocks
    on demand. The importer now consumes that stream directly.
*   **Decryption**: new `decrypt_cbc_stream` (`src/cipher.cc`) replaces the
    whole-string `decrypt_cbc` in the KDBX 4 CBC path. It reads the
    non-seekable `hmac_istreambuf` in 64-byte chunks, decrypts each complete
    16-byte CBC block as it arrives and hands it to the output stream. Only
    the *final* block is withheld until EOF so that its PKCS #7 padding can be
    validated and stripped. ChaCha20 decryption (`kdbx_import.cc`, `Import4`) is
    chunked the same way: 64 bytes at a time, one keystream block per chunk.
*   **Bounded buffers**: the only ciphertext held at any time is a 64-byte read
    chunk plus a sub-block remainder; the only plaintext is one pending block
    plus the downstream (decompression / parse) buffers.

The recorded exceptions behave exactly as before: a failed per-block HMAC or a
truncated block throws `IoError` (corruption, not a password problem); nothing
is buffered long enough to mask the location of the failure.

## Why XML stays DOM-based

The natural next step after streaming decryption would be to parse the XML
incrementally (SAX) instead of loading the whole document. This was evaluated
and **rejected**:

*   **pugixml is a DOM parser.** It offers `load_buffer` / `append_buffer`
    (incremental *feeding* of chunks) but still builds a complete in-memory
    tree; there is no SAX-style event API. Switching to Expat/SAX would add a
    dependency and a second parsing path.
*   **The DOM is the object model anyway.** The importer must produce a
    `Database` object graph (groups, entries, history, custom icons,
    binaries). A DOM tree is already a compact stepping stone to that graph;
    an event parser would build the same graph but with hand-rolled state.
*   **Payload vs. ciphertext.** For compressed databases the on-disk
    ciphertext can be far smaller than the decompressed XML; decompression
    already streams block-by-block via `gzip_istreambuf`. The memory that
    actually scales badly was the pre-P2 *ciphertext* copy, which is now gone.
*   **Bis-limits / drop-outs**: entries with oversized variant-dictionary or
    inner-header field sizes are rejected before they can be inflated (see
    `test/robustness.cc`), which bounds the DOM size for hostile input.

The remaining full-buffer points are deliberate: the *decrypted* content
(`std::stringstream`) and the pugixml DOM. Their combined size is comparable
to the legacy buffer, but the streaming change removes the largest wasteful
copy and decouples memory from the HMAC block size.

## Benchmark

`test/benchmark.cc` is a standalone (non-GTest) executable that generates a
deterministic database (`N = 2000` entries by default) and measures full
import time for each format/cipher/compression combination:

| Scenario | Cipher | Compression | Format |
|---|---|---|---|
| `kdbx3-aes-gzip` | AES | gzip | KDBX 3 |
| `kdbx4-aes-gzip` | AES | gzip | KDBX 4 |
| `kdbx4-aes-plain` | AES | none | KDBX 4 |
| `kdbx4-chacha20-gzip` | ChaCha20 | gzip | KDBX 4 |

It prints the on-disk size, wall-clock import time and a MiB/s figure. The
result is informative only — it is **not asserted** — and is registered as a
CI step with `continue-on-error: true` so a slow runner never fails the build.
Run it locally with `./bin/benchmark [<entries>]`.

Reproducibility notes: seeds and content are fixed (no random input), and the
AES-KDF round count is a constant `8192` so the measured time is dominated by
the content pipeline rather than by the key derivation.