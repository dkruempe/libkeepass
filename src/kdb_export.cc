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

#include "libkeepass/kdb.hh"

#include <algorithm>
#include <cassert>
#include <fstream>
#include <limits>
#include <memory>
#include <sstream>

#include <openssl/evp.h>

#include "kdb_internal.hh"
#include "libkeepass/cipher.hh"
#include "libkeepass/database.hh"
#include "libkeepass/detail/secure_io.hh"
#include "libkeepass/entry.hh"
#include "libkeepass/exception.hh"
#include "libkeepass/group.hh"
#include "libkeepass/io.hh"
#include "libkeepass/key.hh"
#include "libkeepass/secure.hh"
#include "libkeepass/util.hh"

namespace keepass {

// WipeStream/WipeBuffer are shared with the other format codecs to keep the
// sensitive-data wiping logic in one place; see detail/secure_io.hh.
using keepass::detail::WipeStream;

void KdbFile::Export(const std::string& path, const Database& db, const Key& key) {
  std::ofstream dst(path, std::ios::out | std::ios::binary);
  if (!dst.is_open())
    throw IoError("Unable to open database for writing.");

  Export(dst, db, key);
}

void KdbFile::Export(std::ostream& dst, const Database& db, const Key& key) {
  // Extract database values in compatible formats.
  assert(db.master_seed().size() == 16);
  std::array<uint8_t, 16> master_seed{};
  std::copy(db.master_seed().begin(), db.master_seed().end(), master_seed.begin());

  // Produce the final key used for encrypting the contents.
  SecureBuffer<32> transformed_key =
      key.Transform(db.transform_seed(), db.transform_rounds(),
                    Key::SubKeyResolution::kHashSubKeysOnlyIfCompositeKey);
  std::array<uint8_t, 32> final_key{};

  EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
  EVP_DigestUpdate(mdctx, db.master_seed().data(), db.master_seed().size());
  EVP_DigestUpdate(mdctx, transformed_key.data(), transformed_key.size());
  unsigned int out_len = 0;
  EVP_DigestFinal_ex(mdctx, final_key.data(), &out_len);
  EVP_MD_CTX_free(mdctx);
  secure_zero(transformed_key.data(), transformed_key.size());

  std::unique_ptr<Cipher<16>> cipher;
  switch (db.cipher()) {
  case Database::Cipher::kAes:
    cipher.reset(new AesCipher(final_key.data(), db.init_vector()));
    break;
  case Database::Cipher::kTwofish:
    cipher.reset(new TwofishCipher(final_key.data(), db.init_vector()));
    break;
  default:
    assert(false);
    break;
  }
  secure_zero(final_key.data(), final_key.size());

  // Write unencrypted content to temporary stream.
  std::stringstream content;
  decltype(KdbHeader::num_groups) num_groups = 0;
  decltype(KdbHeader::num_entries) num_entries = 0;

  dfs<Group, &Group::Groups>(db.root(),
                             [&](const std::shared_ptr<Group>& group, std::size_t level) {
                               if (level > std::numeric_limits<uint16_t>::max()) {
                                 assert(false);
                                 throw InternalError("Group hierarchy exceeds KDB maximum.");
                               }

                               WriteGroup(content, group, num_groups, static_cast<uint16_t>(level));

                               if (num_groups == std::numeric_limits<decltype(num_groups)>::max()) {
                                 assert(false);
                                 throw InternalError("Group count exceeds KDB maximum.");
                               }
                               ++num_groups;
                             });

  num_groups = 0;
  dfs<Group, &Group::Groups>(db.root(), [&](const std::shared_ptr<Group>& group, std::size_t) {
    for (const auto& entry : group->Entries()) {
      WriteEntry(content, entry, num_groups);

      if (num_entries == std::numeric_limits<decltype(num_entries)>::max()) {
        assert(false);
        throw InternalError("Entry count exceeds KDB maximum.");
      }
      ++num_entries;
    }

    ++num_groups;
  });

  // Compute hash of content stream.
  std::array<uint8_t, 32> content_hash{};
  mdctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);

  uint8_t buffer[1024];
  while (content.good()) {
    content.read(reinterpret_cast<char*>(buffer), sizeof(buffer));
    std::streamsize read_bytes = content.gcount();

    EVP_DigestUpdate(mdctx, buffer, static_cast<std::size_t>(read_bytes));
  }

  EVP_DigestFinal_ex(mdctx, content_hash.data(), &out_len);
  EVP_MD_CTX_free(mdctx);

  // Reset stream.
  content.clear();
  content.seekg(0, std::ios::beg);

  // Write header.
  KdbHeader header{};
  header.signature0 = kKdbSignature0;
  header.signature1 = kKdbSignature1;
  header.flags = db.cipher() == Database::Cipher::kAes ? kKdbFlagRijndael : kKdbFlagTwofish;
  header.version = 0x00030000;
  header.master_seed = master_seed;
  header.init_vector = db.init_vector();
  header.num_groups = num_groups;
  header.num_entries = num_entries;
  header.content_hash = content_hash;
  std::copy(db.transform_seed().begin(), db.transform_seed().end(), header.transform_seed.begin());
  header.transform_rounds = static_cast<uint32_t>(db.transform_rounds());

  conserve<KdbHeader>(dst, header);

  // Encrypt the content.
  encrypt_cbc(content, dst, *cipher);

  // The content stream transiently holds the plaintext database.
  WipeStream(content);
}

} // namespace keepass