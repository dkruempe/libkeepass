# Extension points: codecs, ciphers and KDFs

libkeepass exposes three registries so format/crypto extensions do not have to
modify the unified API. All registries are process-wide and use a
function-local static for construction, so registration order across
translation units does not matter.

## Format codecs (`detail::FormatCodecRegistry`)

A codec imports/exports one dialect and returns/accepts the object model:

```cpp
#include "libkeepass/detail/format_codec.hh"

class MyCodec : public keepass::detail::FormatCodec {
  std::unique_ptr<keepass::Database> Import(std::istream&, const keepass::Key&) override;
  void Export(std::ostream&, const keepass::Database&, const keepass::Key&) override;
};

keepass::detail::FormatCodecRegistry::Instance().Register(
    42, [](const keepass::detail::FormatCodecOptions&) {
      return std::make_unique<MyCodec>();
    });
```

The numeric ids for the built-ins are `detail::kFormatKdb` (1),
`detail::kFormatKdbx3` (2) and `detail::kFormatKdbx4` (3). A codec registered
for a new id can be used by extending the public `KeePass::Format` enum (or by
calling the registry directly).

## Block ciphers (`CipherRegistry`)

`libkeepass/cipher_registry.hh` maps a `Database::Cipher` id to a factory for a
16-byte block cipher. The core uses it for KDB and KDBX 3/4 AES/Twofish
payloads. ChaCha20 is a stream cipher and remains a dedicated code path because
its framing has no block padding.

```cpp
keepass::CipherRegistry::Instance().Register(
    keepass::Database::Cipher::kAes,
    [](const uint8_t* key, const std::array<uint8_t, 16>& iv) {
      return std::unique_ptr<keepass::Cipher<16>>(new MyAes(key, iv));
    });
```

## KDFs (`KdfRegistry`)

`libkeepass/kdf_registry.hh` maps a `Database::Kdf` id to a transform factory.
`KdbxKdf::Transform` (and therefore every KDBX import/export) resolves through
it. Built-ins are AES-KDF, Argon2d and Argon2id. A new KDF still needs its
parameter dictionary UUID/parse/serialize path in `KdbxKdf`; the registry
isolates the expensive transform itself.

## Compatibility

The built-in KDBX export chooses KDBX 3 (and therefore AES-KDF) whenever the
database uses AES + AES-KDF. Selecting KDBX 4 explicitly is required for
ChaCha20, Argon2 or KDBX-4-only features (`KeePass::SetFormat`).
