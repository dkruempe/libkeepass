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
#include <unordered_set>

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "kdbx_internal.hh"
#include "libkeepass/cipher.hh"
#include "libkeepass/detail/secure_io.hh"
#include "libkeepass/exception.hh"
#include "libkeepass/format.hh"
#include "libkeepass/group.hh"
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
      if (!icon->name().empty() || icon->last_modification_time().has_value())
        return true;
    }

    if (!db.meta()->fields().empty())
      return true;
  }

  return false;
}

} // namespace

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

  // Write content: the plaintext is encrypted as it is produced so that the
  // plaintext payload never exists in memory as a whole. A KDBX 3 content
  // stream starts with 32 random bytes (inside the encrypted region, outside
  // the hashed framing) followed by the hashed, optionally compressed XML.
  encrypt_ostreambuf encrypt_streambuf(dst, *cipher);
  std::ostream encrypt_stream(&encrypt_streambuf);

  encrypt_stream.write(reinterpret_cast<const char*>(content_start_bytes.data()),
                       static_cast<std::streamsize>(content_start_bytes.size()));
  secure_zero(content_start_bytes.data(), content_start_bytes.size());

  hashed_ostreambuf hashed_streambuf(encrypt_stream);
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
  encrypt_stream.flush();
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

  // Collect all binaries used by entries into the inner header pool. A set of
  // seen binaries (shared_ptr hashing compares the pointee address) makes the
  // deduplication O(n); the vector preserves the first-occurrence order so the
  // pool references stay stable.
  xml_.binary_pool().clear();
  std::vector<std::shared_ptr<Binary>> ordered_binaries;
  std::unordered_set<std::shared_ptr<Binary>> seen_binaries;
  const auto collect = [&](const auto& self, const std::shared_ptr<Group>& group) -> void {
    for (const auto& entry : group->Entries()) {
      const auto collect_entry = [&](const std::shared_ptr<Entry>& e) -> void {
        for (const auto& att : e->attachments()) {
          if (auto binary = att->binary()) {
            if (seen_binaries.insert(binary).second)
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
  // compressed) XML document. KDBX 4 attaches the HMAC framing around the
  // ciphertext, so the pipes are stacked outer-to-inner as
  //   gzip → encrypt → hmac → destination
  // and every stage writes its output directly to the next one. The plaintext
  // payload therefore never exists in memory as a whole.
  hmac_ostreambuf hmac_streambuf(dst, hmac_key.data());
  std::ostream hmac_stream(&hmac_streambuf);

  const auto write_payload = [&](std::ostream& inner_target) {
    conserve<uint8_t>(inner_target, static_cast<uint8_t>(kKdbxInnerHeader::kInnerRandomStreamId));
    conserve<uint32_t>(inner_target, 4);
    conserve<uint32_t>(inner_target, 3); // ChaCha20

    conserve<uint8_t>(inner_target, static_cast<uint8_t>(kKdbxInnerHeader::kInnerRandomStreamKey));
    conserve<uint32_t>(inner_target, 32);
    conserve<std::array<uint8_t, 32>>(inner_target, inner_random_stream_key);

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
      conserve<uint8_t>(inner_target, static_cast<uint8_t>(kKdbxInnerHeader::kBinaries));
      conserve<uint32_t>(inner_target, static_cast<uint32_t>(bin_data.size()));
      std::copy(bin_data.begin(), bin_data.end(), std::ostreambuf_iterator<char>(inner_target));

      // Attachment data is sensitive; wipe the transient copies.
      WipeBuffer(&bin_data);
      WipeStream(bin_stream);
    }

    conserve<uint8_t>(inner_target, static_cast<uint8_t>(kKdbxInnerHeader::kEnd));
    conserve<uint32_t>(inner_target, 0);

    xml_.Write(inner_target, obfuscator, db);
  };

  if (db.cipher() == Database::Cipher::kAes || db.cipher() == Database::Cipher::kTwofish) {
    encrypt_ostreambuf encrypt_streambuf(hmac_stream, *cipher);
    std::ostream encrypt_stream(&encrypt_streambuf);

    if (db.compress()) {
      gzip_ostreambuf gzip_streambuf(encrypt_stream);
      std::ostream gzip_stream(&gzip_streambuf);
      write_payload(gzip_stream);
      gzip_stream.flush();
    } else {
      write_payload(encrypt_stream);
    }

    encrypt_stream.flush();
  } else {
    encrypt_ostreambuf encrypt_streambuf(hmac_stream, *chacha_cipher);
    std::ostream encrypt_stream(&encrypt_streambuf);

    if (db.compress()) {
      gzip_ostreambuf gzip_streambuf(encrypt_stream);
      std::ostream gzip_stream(&gzip_streambuf);
      write_payload(gzip_stream);
      gzip_stream.flush();
    } else {
      write_payload(encrypt_stream);
    }

    encrypt_stream.flush();
  }

  hmac_stream.flush();

  secure_zero(hmac_key.data(), hmac_key.size());
}

} // namespace keepass