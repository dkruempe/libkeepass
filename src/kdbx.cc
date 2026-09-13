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

#include "include/libkeepass/kdbx.hh"

#include <algorithm>
#include <cassert>
#include <cstring>
#include <fstream>
#include <sstream>

#include <openssl/evp.h>
#include <openssl/hmac.h>

// OpenSSL's HMAC takes the data length as size_t on POSIX but as int on MSVC.
#ifdef _MSC_VER
#define KEEPASS_HMAC_DATA_LEN(x) static_cast<int>(x)
#else
#define KEEPASS_HMAC_DATA_LEN(x) (x)
#endif

#include "libkeepass/cipher.hh"
#include "libkeepass/exception.hh"
#include "libkeepass/format.hh"
#include "libkeepass/io.hh"
#include "libkeepass/kdbx_header.hh"
#include "libkeepass/kdbx_kdf.hh"
#include "libkeepass/kdbx_xml.hh"
#include "libkeepass/key.hh"
#include "libkeepass/metadata.hh"
#include "libkeepass/random.hh"
#include "libkeepass/secure.hh"
#include "libkeepass/security.hh"
#include "libkeepass/stream.hh"

namespace keepass {

namespace {

// Zeroizes the buffered content of a stringstream in place, so that
// decrypted plaintext does not linger in the heap after parsing.
void WipeStream(std::stringstream& stream) {
  std::streambuf* buffer = stream.rdbuf();
  std::streamsize size =
      buffer->pubseekoff(0, std::ios_base::end, std::ios_base::in | std::ios_base::out);
  buffer->pubseekoff(0, std::ios_base::beg, std::ios_base::in | std::ios_base::out);

  static constexpr std::streamsize kChunkSize = 4096;
  char zeros[kChunkSize] = {};
  while (size > 0) {
    std::streamsize chunk = size < kChunkSize ? size : kChunkSize;
    if (buffer->sputn(zeros, chunk) != chunk)
      return;
    size -= chunk;
  }
}

// Zeroizes the contents of a contiguous container (std::string, std::string
// view or std::vector<char/uint8_t>) in place.
// std::string::data() returns a const pointer in C++11, so cast it away for
// the wipe; writing zeros never invalidates the container invariants.
template <typename Container> void WipeBuffer(Container* buffer) {
  if (buffer != nullptr && !buffer->empty()) {
    secure_zero(const_cast<typename Container::value_type*>(buffer->data()),
                buffer->size() * sizeof(typename Container::value_type));
  }
}

} // namespace

constexpr std::array<uint8_t, 8> kKdbxInnerRandomStreamInitVec = {0xe8, 0x30, 0x09, 0x4b,
                                                                  0x97, 0x20, 0x5d, 0x2a};

// Returns whether the group subtree contains KDBX 4.1-only features. Mirrors
// KeePass' KdbxFile.GetMinKdbxVersion.
bool GroupRequiresKdbx41(const std::shared_ptr<Group>& group) {
  if (!group->tags().empty())
    return true;

  for (const auto& entry : group->Entries()) {
    if (!entry->quality_check())
      return true;

    for (const auto& history : entry->history()) {
      if (!history->quality_check())
        return true;
    }
  }

  return std::any_of(group->Groups().begin(), group->Groups().end(), GroupRequiresKdbx41);
}

// Returns whether the database uses any KDBX 4.1-only features. Mirrors
// KeePass' KdbxFile.GetMinKdbxVersion (verified against KeePass 2.57):
// - previous-parent-group references do NOT enforce KDBX 4.1 and the element
//   is dropped from 4.0 output (KeePass' migration rule, KDBX 4.1 spec);
// - entry tags do NOT enforce KDBX 4.1 (they exist in the 4.0 XML schema);
// - any custom data item enforces KDBX 4.1, because every item carries a
//   LastModificationTime (a 4.1-only element).
bool RequiresKdbx41(const Database& db) {
  if (db.root() && GroupRequiresKdbx41(db.root()))
    return true;

  if (db.meta()) {
    for (const auto& icon : db.meta()->icons()) {
      if (!icon->name().empty() || icon->last_modification_time() != 0)
        return true;
    }

    if (!db.meta()->fields().empty())
      return true;
  }

  return false;
}

enum class kKdbxInnerHeader : uint8_t {
  kEnd = 0,
  kInnerRandomStreamId = 1,
  kInnerRandomStreamKey = 2,
  kBinaries = 3
};

void KdbxFile::Reset() { xml_.Reset(); }

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
  if (!content.good() || content_start_bytes != content_start_bytes_tst)
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
  hashed_istreambuf hashed_streambuf(content);
  std::istream hashed_stream(&hashed_streambuf);

  if (db->compress()) {
    gzip_istreambuf gzip_streambuf(hashed_stream);
    std::istream gzip_stream(&gzip_streambuf);

    xml_.Parse(gzip_stream, obfuscator, *db);
  } else {
    xml_.Parse(hashed_stream, obfuscator, *db);
  }

  // The content stream still holds the decrypted payload.
  WipeStream(content);

  // Validate header hash.
  if (xml_.header_hash() != header_hash)
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

  if (stored_header_hash != header_hash)
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
  if (computed_hmac_len != stored_header_hmac.size() ||
      std::memcmp(computed_hmac, stored_header_hmac.data(), stored_header_hmac.size()) != 0) {
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
  hmac_istreambuf hmac_streambuf(src, hmac_key.data());
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
    throw;
  } catch (std::exception&) {
    throw PasswordError();
  }

  // In KDBX 4 the inner header and the XML document are both part of the same
  // (compressed) payload, so decompress the entire decrypted content first.
  std::stringstream plain;
  if (db->compress()) {
    gzip_istreambuf gzip_streambuf(content);
    std::istream gzip_stream(&gzip_streambuf);
    std::copy(std::istreambuf_iterator<char>(gzip_stream), std::istreambuf_iterator<char>(),
              std::ostreambuf_iterator<char>(plain));
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

void KdbxFile::Export(const std::string& path, const Database& db, const Key& key) {
  std::ofstream dst(path, std::ios::out | std::ios::binary);
  if (!dst.is_open())
    throw IoError("Unable to open database for writing.");

  Export(dst, db, key);
}

void KdbxFile::Export(std::ostream& dst, const Database& db, const Key& key) {
  Reset();

  if (write_kdbx4_ || db.kdf() != Database::Kdf::kAes) {
    xml_.set_kdbx4(true);
    xml_.set_kdbx41(RequiresKdbx41(db));
    Export4(dst, db, key);
    return;
  }

  xml_.set_kdbx4(false);
  xml_.set_kdbx41(false);
  Export3(dst, db, key);
}

void KdbxFile::Export3(std::ostream& dst, const Database& db, const Key& key) {
  // Produce the final key used for encrypting the contents.
  SecureBuffer<32> transformed_key =
      db.has_transformed_key() ? db.transformed_key().Clone()
                               : KdbxKdf::Transform(key, db, Key::SubKeyResolution::kHashSubKeys);
  std::array<uint8_t, 32> final_key{};

  EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
  EVP_DigestUpdate(mdctx, db.master_seed().data(), db.master_seed().size());
  EVP_DigestUpdate(mdctx, transformed_key.data(), transformed_key.size());
  unsigned int out_len = 0;
  EVP_DigestFinal_ex(mdctx, final_key.data(), &out_len);
  EVP_MD_CTX_free(mdctx);
  secure_zero(transformed_key.data(), transformed_key.size());

  assert(db.cipher() == Database::Cipher::kAes);
  std::unique_ptr<Cipher<16>> cipher(new AesCipher(final_key.data(), db.init_vector()));
  secure_zero(final_key.data(), final_key.size());

  // Write header to a temporary buffer so that we can compute the hash of it.
  std::array<uint8_t, 32> content_start_bytes = random_array<32>();
  std::string header_data = KdbxHeader::Write3(db, content_start_bytes);

  // Compute the header hash.
  EVP_MD_CTX* mdctx2 = EVP_MD_CTX_new();
  EVP_DigestInit_ex(mdctx2, EVP_sha256(), nullptr);
  EVP_DigestUpdate(mdctx2, header_data.c_str(), header_data.size());
  unsigned int out_len2 = 0;
  EVP_DigestFinal_ex(mdctx2, xml_.header_hash().data(), &out_len2);
  EVP_MD_CTX_free(mdctx2);

  // Write header to file.
  dst.write(header_data.data(), static_cast<std::streamsize>(header_data.size()));

  // The header buffer transiently holds key material (master seed, transform
  // seed, inner random stream key).
  WipeBuffer(&header_data);

  // Prepare deobfuscation stream.
  std::array<uint8_t, 32> final_inner_random_stream_key{};
  EVP_MD_CTX* mdctx3 = EVP_MD_CTX_new();
  EVP_DigestInit_ex(mdctx3, EVP_sha256(), nullptr);
  EVP_DigestUpdate(mdctx3, db.inner_random_stream_key().data(),
                   db.inner_random_stream_key().size());
  unsigned int out_len3 = 0;
  EVP_DigestFinal_ex(mdctx3, final_inner_random_stream_key.data(), &out_len3);
  EVP_MD_CTX_free(mdctx3);
  RandomObfuscator obfuscator(final_inner_random_stream_key, kKdbxInnerRandomStreamInitVec);
  secure_zero(final_inner_random_stream_key.data(), final_inner_random_stream_key.size());

  // Write content to content stream.
  std::stringstream content_stream;
  conserve<std::array<uint8_t, 32>>(content_stream, content_start_bytes);

  hashed_ostreambuf hashed_streambuf(content_stream);
  std::ostream hashed_stream(&hashed_streambuf);

  if (db.compress()) {
    gzip_ostreambuf gzip_streambuf(hashed_stream);
    std::ostream gzip_stream(&gzip_streambuf);

    xml_.Write(gzip_stream, obfuscator, db);
    gzip_stream.flush();
  } else {
    xml_.Write(hashed_stream, obfuscator, db);
  }

  hashed_stream.flush();

  // Encrypt content.
  encrypt_cbc(content_stream, dst, *cipher);

  // The content stream still holds the plaintext payload.
  WipeStream(content_stream);
}

void KdbxFile::Export4(std::ostream& dst, const Database& db, const Key& key) {
  assert(db.cipher() == Database::Cipher::kAes || db.cipher() == Database::Cipher::kTwofish ||
         db.cipher() == Database::Cipher::kChaCha20);

  // Derive the transformed key used for the final encryption key and the HMAC
  // key. If the database was imported and the KDF parameters were not modified,
  // the cached key can be reused; otherwise recompute it.
  SecureBuffer<32> transformed_key =
      db.has_transformed_key() ? db.transformed_key().Clone()
                               : KdbxKdf::Transform(key, db, Key::SubKeyResolution::kHashSubKeys);

  std::array<uint8_t, 32> final_key{};
  EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
  EVP_DigestUpdate(mdctx, db.master_seed().data(), db.master_seed().size());
  EVP_DigestUpdate(mdctx, transformed_key.data(), transformed_key.size());
  unsigned int out_len = 0;
  EVP_DigestFinal_ex(mdctx, final_key.data(), &out_len);
  EVP_MD_CTX_free(mdctx);

  std::unique_ptr<Cipher<16>> cipher;
  std::unique_ptr<ChaCha20Cipher> chacha_cipher;
  if (db.cipher() == Database::Cipher::kAes) {
    cipher = std::make_unique<AesCipher>(final_key.data(), db.init_vector());
  } else if (db.cipher() == Database::Cipher::kTwofish) {
    cipher = std::make_unique<TwofishCipher>(final_key.data(), db.init_vector());
  } else if (db.cipher() == Database::Cipher::kChaCha20) {
    std::array<uint8_t, 12> iv{};
    std::copy(db.init_vector().begin(), db.init_vector().begin() + 12, iv.begin());
    chacha_cipher = std::make_unique<ChaCha20Cipher>(final_key.data(), iv);
  }
  secure_zero(final_key.data(), final_key.size());

  // Write header to a temporary buffer so that we can compute the hash and
  // HMAC of it.
  std::string header_data = KdbxHeader::Write4(db, xml_.kdbx41());

  // Compute the header hash and HMAC.
  EVP_MD_CTX* mdctx_h = EVP_MD_CTX_new();
  EVP_DigestInit_ex(mdctx_h, EVP_sha256(), nullptr);
  EVP_DigestUpdate(mdctx_h, header_data.c_str(), header_data.size());
  unsigned int out_len_h = 0;
  EVP_DigestFinal_ex(mdctx_h, xml_.header_hash().data(), &out_len_h);
  EVP_MD_CTX_free(mdctx_h);

  SecureBuffer<64> hmac_key;
  EVP_MD_CTX* mdctx512 = EVP_MD_CTX_new();
  EVP_DigestInit_ex(mdctx512, EVP_sha512(), nullptr);
  EVP_DigestUpdate(mdctx512, db.master_seed().data(), db.master_seed().size());
  EVP_DigestUpdate(mdctx512, transformed_key.data(), transformed_key.size());
  static constexpr uint8_t kKdbxHmacKeyIndex1 = 0x01;
  EVP_DigestUpdate(mdctx512, &kKdbxHmacKeyIndex1, 1);
  EVP_DigestFinal_ex(mdctx512, hmac_key.data(), &out_len_h);
  EVP_MD_CTX_free(mdctx512);

  secure_zero(transformed_key.data(), transformed_key.size());

  SecureBuffer<64> header_hmac_key;
  const std::array<uint8_t, 8> kKdbxHeaderHmacIndex = {0xff, 0xff, 0xff, 0xff,
                                                       0xff, 0xff, 0xff, 0xff};
  EVP_MD_CTX* mdctx512b = EVP_MD_CTX_new();
  EVP_DigestInit_ex(mdctx512b, EVP_sha512(), nullptr);
  EVP_DigestUpdate(mdctx512b, kKdbxHeaderHmacIndex.data(), kKdbxHeaderHmacIndex.size());
  EVP_DigestUpdate(mdctx512b, hmac_key.data(), hmac_key.size());
  EVP_DigestFinal_ex(mdctx512b, header_hmac_key.data(), &out_len_h);
  EVP_MD_CTX_free(mdctx512b);

  std::array<uint8_t, 32> header_hmac{};
  unsigned int header_hmac_len = 0;
  HMAC(EVP_sha256(), header_hmac_key.data(), static_cast<int>(header_hmac_key.size()),
       reinterpret_cast<const unsigned char*>(header_data.c_str()),
       KEEPASS_HMAC_DATA_LEN(header_data.size()), header_hmac.data(), &header_hmac_len);
  assert(header_hmac_len == header_hmac.size());

  secure_zero(header_hmac_key.data(), header_hmac_key.size());

  // Write header, stored hash and stored HMAC to the file.
  dst.write(header_data.data(), static_cast<std::streamsize>(header_data.size()));
  conserve<std::array<uint8_t, 32>>(dst, xml_.header_hash());
  conserve<std::array<uint8_t, 32>>(dst, header_hmac);

  // The header buffer transiently holds key material (master seed, KDF salt).
  WipeBuffer(&header_data);
  secure_zero(header_hmac.data(), header_hmac.size());

  // Prepare deobfuscation stream using a freshly generated inner random
  // stream key. KDBX 4 uses ChaCha20 for the inner random stream.
  std::array<uint8_t, 32> inner_random_stream_key = random_array<32>();
  RandomObfuscator obfuscator(RandomObfuscator::Type::kChaCha20, inner_random_stream_key);

  // Collect all binaries used by entries into the inner header pool.
  xml_.binary_pool().clear();
  std::vector<std::shared_ptr<Binary>> ordered_binaries;
  const auto collect = [&](const auto& self, const std::shared_ptr<Group>& group) -> void {
    for (const auto& entry : group->Entries()) {
      const auto collect_entry = [&](const std::shared_ptr<Entry>& e) -> void {
        for (const auto& att : e->attachments()) {
          if (auto binary = att->binary()) {
            bool found = false;
            for (const auto& existing : ordered_binaries) {
              if (existing == binary) {
                found = true;
                break;
              }
            }
            if (!found)
              ordered_binaries.push_back(binary);
          }
        }
      };
      collect_entry(entry);
      for (const auto& history_entry : entry->history())
        collect_entry(history_entry);
    }
    for (const auto& subgroup : group->Groups())
      self(self, subgroup);
  };
  collect(collect, db.root());

  for (std::size_t i = 0; i < ordered_binaries.size(); ++i) {
    xml_.binary_pool().insert(std::make_pair(std::to_string(i), ordered_binaries[i]));
  }

  // Write content stream: inner header followed by the (optionally gzip
  // compressed) XML document.
  std::stringstream inner_header_stream;

  conserve<uint8_t>(inner_header_stream,
                    static_cast<uint8_t>(kKdbxInnerHeader::kInnerRandomStreamId));
  conserve<uint32_t>(inner_header_stream, 4);
  conserve<uint32_t>(inner_header_stream, 3); // ChaCha20

  conserve<uint8_t>(inner_header_stream,
                    static_cast<uint8_t>(kKdbxInnerHeader::kInnerRandomStreamKey));
  conserve<uint32_t>(inner_header_stream, 32);
  conserve<std::array<uint8_t, 32>>(inner_header_stream, inner_random_stream_key);

  // The inner random stream key protects every protected field in the XML;
  // it must not linger in memory after the header has been serialized. The
  // obfuscator keeps its own derived copy, which is wiped on destruction.
  secure_zero(inner_random_stream_key.data(), inner_random_stream_key.size());

  for (const auto& binary : ordered_binaries) {
    std::stringstream bin_stream;
    uint8_t flags = binary->data().is_protected() ? 0x01 : 0x00;
    conserve<uint8_t>(bin_stream, flags);
    const secure_string& raw = binary->data().value();
    if (!raw.empty()) {
      bin_stream.write(raw.data(), static_cast<std::streamsize>(raw.size()));
    }

    // Build the payload copy incrementally so that every copy that exists is
    // reachable for wiping later on.
    std::string bin_data;
    std::copy(std::istreambuf_iterator<char>(bin_stream), std::istreambuf_iterator<char>(),
              std::back_inserter(bin_data));
    conserve<uint8_t>(inner_header_stream, static_cast<uint8_t>(kKdbxInnerHeader::kBinaries));
    conserve<uint32_t>(inner_header_stream, static_cast<uint32_t>(bin_data.size()));
    std::copy(bin_data.begin(), bin_data.end(),
              std::ostreambuf_iterator<char>(inner_header_stream));

    // Attachment data is sensitive; wipe the transient copies.
    WipeBuffer(&bin_data);
    WipeStream(bin_stream);
  }

  conserve<uint8_t>(inner_header_stream, static_cast<uint8_t>(kKdbxInnerHeader::kEnd));
  conserve<uint32_t>(inner_header_stream, 0);

  // Build the plaintext payload. In KDBX 4 the inner header and the XML
  // document are both part of the same compressed payload.
  std::stringstream plain_stream;

  if (db.compress()) {
    gzip_ostreambuf gzip_streambuf(plain_stream);
    std::ostream gzip_stream(&gzip_streambuf);

    std::copy(std::istreambuf_iterator<char>(inner_header_stream), std::istreambuf_iterator<char>(),
              std::ostreambuf_iterator<char>(gzip_stream));
    xml_.Write(gzip_stream, obfuscator, db);
    gzip_stream.flush();
  } else {
    std::copy(std::istreambuf_iterator<char>(inner_header_stream), std::istreambuf_iterator<char>(),
              std::ostreambuf_iterator<char>(plain_stream));
    xml_.Write(plain_stream, obfuscator, db);
  }

  // Encrypt the plaintext payload first ...
  std::stringstream cipher_input;
  std::stringstream hmac_input;
  if (db.cipher() == Database::Cipher::kAes || db.cipher() == Database::Cipher::kTwofish) {
    // Copy the plaintext into the input stream incrementally so that the copy
    // lives in a stream buffer that can be wiped afterwards.
    std::copy(std::istreambuf_iterator<char>(plain_stream), std::istreambuf_iterator<char>(),
              std::ostreambuf_iterator<char>(cipher_input));
    encrypt_cbc(cipher_input, hmac_input, *cipher);
  } else {
    std::string plain;
    std::copy(std::istreambuf_iterator<char>(plain_stream), std::istreambuf_iterator<char>(),
              std::back_inserter(plain));
    std::array<uint8_t, 64> keystream{}, data{};
    size_t offset = 0;
    while (offset < plain.size()) {
      std::array<uint8_t, 64> zero{};
      chacha_cipher->Process(zero, keystream);
      size_t n = std::min<size_t>(64, plain.size() - offset);
      for (size_t i = 0; i < n; ++i)
        data[i] = static_cast<uint8_t>(plain[offset + i]) ^ keystream[i];
      hmac_input.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(n));
      offset += n;
    }
    WipeBuffer(&plain);
    // The block buffers transiently hold the plaintext payload.
    secure_zero(data.data(), data.size());
    secure_zero(keystream.data(), keystream.size());
  }

  // ... and then wrap the ciphertext in HMAC protected blocks. In KDBX 4 the
  // HMAC is computed over the encrypted content, so the HMAC framing is the
  // outermost layer below the stored header.
  hmac_ostreambuf hmac_streambuf(dst, hmac_key.data());
  std::ostream hmac_stream(&hmac_streambuf);

  std::copy(std::istreambuf_iterator<char>(hmac_input), std::istreambuf_iterator<char>(),
            std::ostreambuf_iterator<char>(hmac_stream));
  hmac_stream.flush();

  // The streams still hold the plaintext payload (and copies of it).
  WipeStream(plain_stream);
  WipeStream(inner_header_stream);
  WipeStream(cipher_input);
  WipeStream(hmac_input);

  secure_zero(hmac_key.data(), hmac_key.size());
}

} // namespace keepass
