/*
 * libkeepass - KeePass key database importer/exporter
 * Copyright (C) 2014 Christian Kindahl
 * Copyright (C) 2024 Dominik Krümpelmann
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "libkeepass/kdbx.hh"

#include <algorithm>
#include <cassert>
#include <fstream>
#include <memory>
#include <sstream>
#include <vector>

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "kdbx_internal.hh"
#include "libkeepass/cipher.hh"
#include "libkeepass/detail/constant_time.hh"
#include "libkeepass/detail/secure_io.hh"
#include "libkeepass/exception.hh"
#include "libkeepass/format.hh"
#include "libkeepass/io.hh"
#include "libkeepass/kdbx_header.hh"
#include "libkeepass/kdbx_kdf.hh"
#include "libkeepass/key.hh"
#include "libkeepass/metadata.hh"
#include "libkeepass/random.hh"
#include "libkeepass/secure.hh"
#include "libkeepass/stream.hh"

namespace keepass {

namespace {

// WipeStream/WipeBuffer are shared with the other format codecs to keep the
// sensitive-data wiping logic in one place; see detail/secure_io.hh.
using keepass::detail::WipeBuffer;
using keepass::detail::WipeStream;

} // namespace

void KdbxFile::Reset() { xml_.Reset(); }

void KdbxFile::set_resource_limits(const detail::ResourceLimits& limits) {
  xml_.set_resource_limits(limits);
}

std::unique_ptr<Database> KdbxFile::Import(const std::string& path, const Key& key) {
  std::ifstream src(path, std::ios::binary);
  if (!src.is_open())
    throw FileNotFoundError();

  return Import(src, key);
}

std::unique_ptr<Database> KdbxFile::Import(std::istream& src, const Key& key) {
  Reset();

  // Read the signature and version prefix to dispatch to the right parser.
  const uint32_t version = KdbxHeader::ReadVersion(src);

  if (KdbxHeader::IsKdbx4(version)) {
    xml_.set_kdbx4(true);
    return Import4(src, key);
  }

  if ((version & KdbxHeader::kVersionCriticalMask) == KdbxHeader::kVersion3) {
    xml_.set_kdbx4(false);
    return Import3(src, key);
  }

  throw FormatError(std::string(Format() << "KDBX version " << version << " is not supported."));
}

std::unique_ptr<Database> KdbxFile::Import3(std::istream& src, const Key& key) {
  std::unique_ptr<Database> db(new Database());

  // Parse and validate the KDBX 3 outer header fields.
  const std::array<uint8_t, 32> content_start_bytes = KdbxHeader::Parse3(src, *db);

  // Compute the header hash.
  std::streampos header_end = src.tellg();
  src.seekg(0, std::ios::beg);
  std::vector<char> header_data;
  header_data.resize(static_cast<std::size_t>(header_end));
  src.read(header_data.data(), header_end);

  std::array<uint8_t, 32> header_hash{};
  EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
  EVP_DigestUpdate(mdctx, header_data.data(), header_data.size());
  unsigned int out_len = 0;
  EVP_DigestFinal_ex(mdctx, header_hash.data(), &out_len);
  EVP_MD_CTX_free(mdctx);
  WipeBuffer(&header_data);

  // Produce the final key used for encrypting the contents.
  SecureBuffer<32> transformed_key =
      KdbxKdf::Transform(key, *db, Key::SubKeyResolution::kHashSubKeys);
  db->set_transformed_key(transformed_key.Clone());
  std::array<uint8_t, 32> final_key{};

  mdctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
  EVP_DigestUpdate(mdctx, db->master_seed().data(), db->master_seed().size());
  EVP_DigestUpdate(mdctx, transformed_key.data(), transformed_key.size());
  EVP_DigestFinal_ex(mdctx, final_key.data(), &out_len);
  EVP_MD_CTX_free(mdctx);
  secure_zero(transformed_key.data(), transformed_key.size());

  std::unique_ptr<Cipher<16>> cipher;
  switch (db->cipher()) {
  case Database::Cipher::kAes:
    cipher = std::make_unique<AesCipher>(final_key.data(), db->init_vector());
    break;
  case Database::Cipher::kTwofish:
    cipher = std::make_unique<TwofishCipher>(final_key.data(), db->init_vector());
    break;
  default:
    assert(false);
    break;
  }
  secure_zero(final_key.data(), final_key.size());

  // Decrypt the content.
  std::stringstream content;

  try {
    decrypt_cbc(src, content, *cipher);
  } catch (std::exception&) {
    throw PasswordError();
  }

  std::array<uint8_t, 32> content_start_bytes_tst{};
  content.read(reinterpret_cast<char*>(content_start_bytes_tst.data()),
               content_start_bytes_tst.size());
  if (!content.good() ||
      !keepass::detail::constant_time_eq(content_start_bytes, content_start_bytes_tst))
    throw PasswordError();

  // Prepare deobfuscation stream.
  std::array<uint8_t, 32> final_inner_random_stream_key{};
  mdctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
  EVP_DigestUpdate(mdctx, db->inner_random_stream_key().data(),
                   db->inner_random_stream_key().size());
  EVP_DigestFinal_ex(mdctx, final_inner_random_stream_key.data(), &out_len);
  EVP_MD_CTX_free(mdctx);
  RandomObfuscator obfuscator(final_inner_random_stream_key, kKdbxInnerRandomStreamInitVec);
  secure_zero(final_inner_random_stream_key.data(), final_inner_random_stream_key.size());

  // Parse XML content.
  hashed_istreambuf hashed_streambuf(content, xml_.resource_limits());
  std::istream hashed_stream(&hashed_streambuf);

  if (db->compress()) {
    gzip_istreambuf gzip_streambuf(hashed_stream, xml_.resource_limits());
    std::istream gzip_stream(&gzip_streambuf);

    xml_.Parse(gzip_stream, obfuscator, *db);
    if (gzip_streambuf.BudgetExceeded())
      throw FormatError("Decompressed payload exceeds the configured size limit.");
  } else {
    xml_.Parse(hashed_stream, obfuscator, *db);
  }

  if (hashed_streambuf.BudgetExceeded())
    throw FormatError("Hashed block framing exceeds the configured resource budget.");

  // The content stream still holds the decrypted payload.
  WipeStream(content);

  // Validate header hash.
  if (!keepass::detail::constant_time_eq(xml_.header_hash(), header_hash))
    throw FormatError("Header checksum error in KDBX.");

  return db;
}

std::unique_ptr<Database> KdbxFile::Import4(std::istream& src, const Key& key) {
  std::unique_ptr<Database> db(new Database());

  // Parse and validate the KDBX 4 outer header fields.
  KdbxHeader::Parse4(src, *db);

  // Compute the header hash over all bytes up to (but not including) the
  // stored header hash and HMAC.
  std::streampos header_end = src.tellg();
  src.seekg(0, std::ios::beg);
  std::vector<char> header_data;
  header_data.resize(static_cast<std::size_t>(header_end));
  src.read(header_data.data(), header_end);

  std::array<uint8_t, 32> header_hash{};
  EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
  EVP_DigestUpdate(mdctx, header_data.data(), header_data.size());
  unsigned int out_len = 0;
  EVP_DigestFinal_ex(mdctx, header_hash.data(), &out_len);
  EVP_MD_CTX_free(mdctx);

  const std::array<uint8_t, 32> stored_header_hash = consume<std::array<uint8_t, 32>>(src);
  const std::array<uint8_t, 32> stored_header_hmac = consume<std::array<uint8_t, 32>>(src);

  if (!keepass::detail::constant_time_eq(stored_header_hash, header_hash))
    throw FormatError("Header checksum error in KDBX 4 database.");

  // Produce the transformed key used for both the final encryption key and
  // the HMAC verification key.
  SecureBuffer<32> transformed_key =
      KdbxKdf::Transform(key, *db, Key::SubKeyResolution::kHashSubKeys);
  db->set_transformed_key(transformed_key.Clone());

  // Compute the HMAC key for the header. The block index 0xFFFFFFFFFFFFFFFF
  // denotes the header in the HMAC key derivation.
  SecureBuffer<64> hmac_key;
  EVP_MD_CTX* mdctx512 = EVP_MD_CTX_new();
  EVP_DigestInit_ex(mdctx512, EVP_sha512(), nullptr);
  EVP_DigestUpdate(mdctx512, db->master_seed().data(), db->master_seed().size());
  EVP_DigestUpdate(mdctx512, transformed_key.data(), transformed_key.size());
  static constexpr uint8_t kKdbxHmacKeyIndex1 = 0x01;
  EVP_DigestUpdate(mdctx512, &kKdbxHmacKeyIndex1, 1);
  EVP_DigestFinal_ex(mdctx512, hmac_key.data(), &out_len);
  EVP_MD_CTX_free(mdctx512);

  SecureBuffer<64> header_hmac_key;
  const std::array<uint8_t, 8> kKdbxHeaderHmacIndex = {0xff, 0xff, 0xff, 0xff,
                                                       0xff, 0xff, 0xff, 0xff};
  mdctx512 = EVP_MD_CTX_new();
  EVP_DigestInit_ex(mdctx512, EVP_sha512(), nullptr);
  EVP_DigestUpdate(mdctx512, kKdbxHeaderHmacIndex.data(), kKdbxHeaderHmacIndex.size());
  EVP_DigestUpdate(mdctx512, hmac_key.data(), hmac_key.size());
  EVP_DigestFinal_ex(mdctx512, header_hmac_key.data(), &out_len);
  EVP_MD_CTX_free(mdctx512);

  unsigned char computed_hmac[EVP_MAX_MD_SIZE];
  unsigned int computed_hmac_len = 0;
  HMAC(EVP_sha256(), header_hmac_key.data(), static_cast<int>(header_hmac_key.size()),
       reinterpret_cast<const unsigned char*>(header_data.data()),
       KEEPASS_HMAC_DATA_LEN(header_data.size()), computed_hmac, &computed_hmac_len);
  if (!keepass::detail::constant_time_eq(computed_hmac, computed_hmac_len,
                                         stored_header_hmac.data(), stored_header_hmac.size())) {
    throw PasswordError();
  }

  // The header buffer transiently holds key material (master seed, KDF salt,
  // seed) and is no longer needed; zeroize it now that the hash and the HMAC
  // have been verified.
  WipeBuffer(&header_data);

  secure_zero(header_hmac_key.data(), header_hmac_key.size());
  secure_zero(computed_hmac, sizeof(computed_hmac));

  // Produce the final key used for encrypting the contents.
  std::array<uint8_t, 32> final_key{};
  mdctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
  EVP_DigestUpdate(mdctx, db->master_seed().data(), db->master_seed().size());
  EVP_DigestUpdate(mdctx, transformed_key.data(), transformed_key.size());
  EVP_DigestFinal_ex(mdctx, final_key.data(), &out_len);
  EVP_MD_CTX_free(mdctx);
  secure_zero(transformed_key.data(), transformed_key.size());

  std::unique_ptr<Cipher<16>> cipher;
  std::unique_ptr<ChaCha20Cipher> chacha_cipher;
  if (db->cipher() == Database::Cipher::kAes) {
    cipher = std::make_unique<AesCipher>(final_key.data(), db->init_vector());
  } else if (db->cipher() == Database::Cipher::kTwofish) {
    cipher = std::make_unique<TwofishCipher>(final_key.data(), db->init_vector());
  } else if (db->cipher() == Database::Cipher::kChaCha20) {
    std::array<uint8_t, 12> iv{};
    std::copy(db->init_vector().begin(), db->init_vector().begin() + 12, iv.begin());
    chacha_cipher = std::make_unique<ChaCha20Cipher>(final_key.data(), iv);
  }
  secure_zero(final_key.data(), final_key.size());

  // In KDBX 4 the content is first encrypted and the ciphertext is then
  // wrapped in HMAC protected blocks. Read the HMAC blocks from the file and
  // decrypt the payload inside them, block by block, so that a large database
  // never requires the whole ciphertext to be materialized in memory at once.
  hmac_istreambuf hmac_streambuf(src, hmac_key.data(), xml_.resource_limits());
  std::istream hmac_stream(&hmac_streambuf);

  secure_zero(hmac_key.data(), hmac_key.size());

  std::stringstream content;
  try {
    if (db->cipher() == Database::Cipher::kAes || db->cipher() == Database::Cipher::kTwofish) {
      decrypt_cbc_stream(hmac_stream, content, *cipher);
    } else if (db->cipher() == Database::Cipher::kChaCha20) {
      // ChaCha20 is a stream cipher: the ciphertext is XORed with the
      // keystream (RFC 8439, 96-bit nonce) and needs no padding. Generate one
      // 64-byte keystream block per 64 read ciphertext bytes and XOR the (final
      // partial) block in place.
      std::array<uint8_t, 64> chunk{}, pending{}, keystream{}, data{}, zero{};
      std::size_t pending_n = 0;
      while (true) {
        hmac_stream.read(reinterpret_cast<char*>(chunk.data()), chunk.size());
        const std::streamsize got = hmac_stream.gcount();
        if (got == 0)
          break;

        std::size_t off = 0;
        while (off < static_cast<std::size_t>(got)) {
          const std::size_t fill =
              std::min<std::size_t>(64 - pending_n, static_cast<std::size_t>(got) - off);
          std::copy_n(chunk.begin() + off, fill, pending.begin() + pending_n);
          pending_n += fill;
          off += fill;

          if (pending_n == 64) {
            chacha_cipher->Process(zero, keystream);
            for (std::size_t i = 0; i < pending_n; ++i)
              data[i] = static_cast<uint8_t>(pending[i] ^ keystream[i]);
            content.write(reinterpret_cast<const char*>(data.data()), 64);
            pending_n = 0;
          }
        }
      }

      if (pending_n > 0) {
        // The final partial block needs one more keystream block; only the
        // bytes that are actually present are written.
        chacha_cipher->Process(zero, keystream);
        for (std::size_t i = 0; i < pending_n; ++i)
          data[i] = static_cast<uint8_t>(pending[i] ^ keystream[i]);
        content.write(reinterpret_cast<const char*>(data.data()),
                      static_cast<std::streamsize>(pending_n));
      }

      // The block buffers transiently hold ciphertext and the decrypted
      // payload.
      secure_zero(chunk.data(), chunk.size());
      secure_zero(pending.data(), pending.size());
      secure_zero(keystream.data(), keystream.size());
      secure_zero(data.data(), data.size());
    } else {
      throw FormatError("Unknown cipher in KDBX 4 database.");
    }
  } catch (const IoError&) {
    // A failed HMAC verification or a truncated block signals corruption (not
    // a wrong password), so it must not be masked as a password error.
    if (hmac_streambuf.BudgetExceeded())
      throw FormatError("HMAC block framing exceeds the configured resource budget.");
    throw;
  } catch (std::exception&) {
    throw PasswordError();
  }

  if (hmac_streambuf.BudgetExceeded())
    throw FormatError("HMAC block framing exceeds the configured resource budget.");

  // In KDBX 4 the inner header and the XML document are both part of the same
  // (compressed) payload, so decompress the entire decrypted content first.
  std::stringstream plain;
  if (db->compress()) {
    gzip_istreambuf gzip_streambuf(content, xml_.resource_limits());
    std::istream gzip_stream(&gzip_streambuf);
    std::copy(std::istreambuf_iterator<char>(gzip_stream), std::istreambuf_iterator<char>(),
              std::ostreambuf_iterator<char>(plain));
    if (gzip_streambuf.BudgetExceeded())
      throw FormatError("Decompressed payload exceeds the configured size limit.");
  } else {
    // Move the data instead of copying through str(), which would leave an
    // un-wipeable temporary copy of the decrypted payload behind.
    std::copy(std::istreambuf_iterator<char>(content), std::istreambuf_iterator<char>(),
              std::ostreambuf_iterator<char>(plain));
  }
  std::stringstream& xml_source = plain;

  // Parse the KDBX 4 inner header containing the inner random stream
  // identifier, its key and the binary attachments.
  uint32_t inner_random_stream_id = 0;
  std::vector<uint8_t> inner_random_stream_key;
  std::vector<std::shared_ptr<Binary>> inner_binaries;

  bool inner_done = false;
  while (!inner_done && xml_source.good()) {
    auto inner_id = static_cast<kKdbxInnerHeader>(consume<uint8_t>(xml_source));
    uint32_t inner_size = consume<uint32_t>(xml_source);

    // Reject field sizes that cannot possibly fit into the remaining payload
    // instead of looping/allocating up to the declared length.
    if (static_cast<uint64_t>(inner_size) >
        static_cast<uint64_t>(std::max<std::streamsize>(0, RemainingBytes(xml_source))))
      throw FormatError("Corrupt inner header field size in KDBX 4 database.");

    // A single attachment is budgeted like the XML binaries and custom icons.
    if (inner_id == kKdbxInnerHeader::kBinaries &&
        static_cast<uint64_t>(inner_size) > xml_.resource_limits().max_binary_bytes)
      throw FormatError("Inner header binary exceeds the configured size limit.");

    switch (inner_id) {
    case kKdbxInnerHeader::kEnd:
      inner_done = true;
      break;
    case kKdbxInnerHeader::kInnerRandomStreamId:
      if (inner_size != 4)
        throw FormatError("Illegal inner random stream ID size in KDBX.");
      inner_random_stream_id = consume<uint32_t>(xml_source);
      break;
    case kKdbxInnerHeader::kInnerRandomStreamKey:
      if (inner_size != 32 && inner_size != 64)
        throw FormatError("Illegal inner random stream key size in KDBX.");
      inner_random_stream_key.resize(inner_size);
      xml_source.read(reinterpret_cast<char*>(inner_random_stream_key.data()),
                      static_cast<std::streamsize>(inner_size));
      if (!xml_source)
        throw IoError("Read error.");
      break;
    case kKdbxInnerHeader::kBinaries: {
      std::stringstream raw_stream;
      std::generate_n(std::ostreambuf_iterator<char>(raw_stream), inner_size,
                      [&xml_source]() { return static_cast<char>(xml_source.get()); });

      // The first byte holds the flags, the remaining bytes are the data.
      uint8_t flags = static_cast<uint8_t>(raw_stream.get());
      std::string data((std::istreambuf_iterator<char>(raw_stream)),
                       std::istreambuf_iterator<char>());

      std::shared_ptr<Binary> binary =
          std::make_shared<Binary>(protect<secure_string>(secure_string(data), (flags & 0x01)));
      inner_binaries.push_back(binary);

      secure_zero(data.data(), data.size());
      // The stream buffer transiently holds the raw attachment payload.
      WipeStream(raw_stream);

      xml_.binary_pool().insert(std::make_pair(std::to_string(xml_.binary_pool().size()), binary));
      break;
    }
    default:
      throw FormatError("Illegal inner header field in KDBX 4 database.");
    }
  }

  // Prepare deobfuscation stream.
  RandomObfuscator obfuscator(RandomObfuscator::Type::kSalsa20, inner_random_stream_key);
  try {
    switch (inner_random_stream_id) {
    case 2: // Salsa20
      obfuscator = RandomObfuscator(RandomObfuscator::Type::kSalsa20, inner_random_stream_key);
      break;
    case 3: // ChaCha20
      obfuscator = RandomObfuscator(RandomObfuscator::Type::kChaCha20, inner_random_stream_key);
      break;
    default:
      throw FormatError("Unknown inner random stream in KDBX 4 database.");
    }
  } catch (...) {
    // Unknown stream type or a failed obfuscator construction must not leave
    // the inner random stream key behind.
    secure_zero(inner_random_stream_key.data(), inner_random_stream_key.size());
    throw;
  }

  secure_zero(inner_random_stream_key.data(), inner_random_stream_key.size());

  // Parse the XML content, which follows the inner header in the same
  // (already decompressed) payload.
  xml_.Parse(xml_source, obfuscator, *db);

  // KDBX 4 attachments live in the inner header. Keep them in the meta so
  // that they are not lost when exporting to older formats.
  for (const auto& binary : inner_binaries)
    db->meta()->AddBinary(binary);

  // The streams still hold parts of the decrypted payload.
  WipeStream(plain);
  WipeStream(content);

  return db;
}

} // namespace keepass