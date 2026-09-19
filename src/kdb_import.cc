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
#include <memory>
#include <sstream>
#include <tuple>
#include <unordered_map>

#include <openssl/evp.h>

#include "kdb_internal.hh"
#include "libkeepass/cipher.hh"
#include "libkeepass/database.hh"
#include "libkeepass/detail/constant_time.hh"
#include "libkeepass/detail/secure_io.hh"
#include "libkeepass/entry.hh"
#include "libkeepass/exception.hh"
#include "libkeepass/format.hh"
#include "libkeepass/group.hh"
#include "libkeepass/io.hh"
#include "libkeepass/key.hh"
#include "libkeepass/secure.hh"

namespace keepass {

// WipeStream/WipeBuffer are shared with the other format codecs to keep the
// sensitive-data wiping logic in one place; see detail/secure_io.hh.
using keepass::detail::WipeStream;

std::unique_ptr<Database> KdbFile::Import(const std::string& path, const Key& key) {
  std::ifstream src(path, std::ios::in | std::ios::binary);
  if (!src.is_open())
    throw FileNotFoundError();

  return Import(src, key);
}

std::unique_ptr<Database> KdbFile::Import(std::istream& src, const Key& key) {
  // Read header.
  KdbHeader header{};
  try {
    header = consume<KdbHeader>(src);
  } catch (std::exception&) {
    throw FormatError("Not a KDB database.");
  }
  if (header.signature0 != kKdbSignature0 || header.signature1 != kKdbSignature1)
    throw FormatError("Not a KDB database.");

  switch (header.version & 0xffffff00) {
  // Version 1.
  case 0x00010000:
    throw FormatError("KDB version 1 is not supported.");
    break;
  // Version 2.
  case 0x00020000:
    throw FormatError("KDB version 2 is not supported.");
    break;
  // Version 3.
  case 0x00030000:
    break;
  default:
    throw FormatError(std::string(Format() << "Unknown KDB version " << header.version << "."));
    break;
  }

  std::unique_ptr<Database> db(new Database());
  db->set_master_seed(header.master_seed);
  db->set_init_vector(header.init_vector);
  db->set_transform_seed(header.transform_seed);
  if (header.transform_rounds > Database::kMaxTransformRounds)
    throw FormatError("KDB header declares too many transform rounds.");
  db->set_transform_rounds(header.transform_rounds);

  // Produce the final key used for decrypting the contents.
  SecureBuffer<32> transformed_key =
      key.Transform(SecureBuffer<32>(header.transform_seed), header.transform_rounds,
                    Key::SubKeyResolution::kHashSubKeysOnlyIfCompositeKey);
  std::array<uint8_t, 32> final_key{};

  EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
  EVP_DigestUpdate(mdctx, header.master_seed.data(), header.master_seed.size());
  EVP_DigestUpdate(mdctx, transformed_key.data(), transformed_key.size());
  unsigned int out_len = 0;
  EVP_DigestFinal_ex(mdctx, final_key.data(), &out_len);
  EVP_MD_CTX_free(mdctx);
  secure_zero(transformed_key.data(), transformed_key.size());

  std::unique_ptr<Cipher<16>> cipher;
  if (header.flags & kKdbFlagRijndael) {
    db->set_cipher(Database::Cipher::kAes);

    cipher.reset(new AesCipher(final_key.data(), header.init_vector));
  } else if (header.flags & kKdbFlagTwofish) {
    db->set_cipher(Database::Cipher::kTwofish);

    cipher.reset(new TwofishCipher(final_key.data(), header.init_vector));
  } else {
    throw FormatError("Unknown cipher in KDB.");
  }
  secure_zero(final_key.data(), final_key.size());

  // Decrypt the content.
  std::stringstream content;

  try {
    decrypt_cbc(src, content, *cipher);
  } catch (std::exception&) {
    throw PasswordError();
  }

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

  // Check if contents was successfully decrypted using the specified password.
  if (!keepass::detail::constant_time_eq(content_hash, header.content_hash))
    throw PasswordError();

  // Read groups and entries.
  std::vector<std::tuple<std::shared_ptr<Group>, uint16_t>> groups;
  std::unordered_map<uint32_t, std::shared_ptr<Group>> group_map;
  for (decltype(header.num_groups) i = 0; i < header.num_groups; ++i) {
    uint32_t group_id = 0;
    uint16_t group_level = 0;
    std::shared_ptr<Group> group = ReadGroup(content, group_id, group_level);

    groups.emplace_back(group, group_level);
    assert(group_map.count(group_id) == 0);
    group_map[group_id] = group;
  }

  std::vector<std::tuple<std::shared_ptr<Entry>, uint32_t>> entries;
  for (decltype(header.num_entries) i = 0; i < header.num_entries; ++i) {
    uint32_t entry_group_id = 0;
    entries.emplace_back(ReadEntry(content, entry_group_id), entry_group_id);
  }

  // Construct the group and entry tree.
  std::shared_ptr<Group> group_root = std::make_shared<Group>();

  uint16_t last_group_level = 0;

  std::vector<std::shared_ptr<Group>> last_group_by_level;
  last_group_by_level.push_back(group_root);

  for (auto& group_data : groups) {
    std::shared_ptr<Group> group = std::get<0>(group_data);

    // Level of current group plus one, because we have inserted the root at
    // level zero.
    uint16_t group_level = std::get<1>(group_data) + 1;

    if (group_level > last_group_level) {
      if (group_level != last_group_level + 1)
        throw FormatError("Malformed group tree.");

      last_group_by_level[group_level - 1]->AddGroup(group);
      last_group_by_level.push_back(group);
    } else {
      last_group_by_level[group_level - 1]->AddGroup(group);
      last_group_by_level[group_level] = group;
    }

    last_group_level = group_level;
  }

  for (auto& entry_data : entries) {
    std::shared_ptr<Entry> entry = std::get<0>(entry_data);
    uint32_t entry_group_id = std::get<1>(entry_data);

    decltype(group_map)::const_iterator it = group_map.find(entry_group_id);
    if (it == group_map.end())
      throw FormatError("Database contains an orphaned entry.");

    it->second->AddEntry(entry);
  }

  db->set_root(group_root);
  WipeStream(content);

  return db;
}

} // namespace keepass