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

// libFuzzer target exercising the export/save path. The input bytes are turned
// into an in-memory model (titles, notes, custom fields, tags, attachments),
// which is then exported and re-imported. This complements the import-only
// fuzzers by mutating the data that reaches the XML and framing writers.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "libkeepass/database.hh"
#include "libkeepass/entry.hh"
#include "libkeepass/group.hh"
#include "libkeepass/kdbx.hh"
#include "libkeepass/key.hh"
#include "libkeepass/secure.hh"

namespace {

std::string Take(const uint8_t* data, std::size_t size, std::size_t& offset,
                 std::size_t max_length) {
  if (offset >= size)
    return {};
  const std::size_t length =
      std::min<std::size_t>(data[offset] % (max_length + 1), size - offset - 1);
  ++offset;
  std::string value(reinterpret_cast<const char*>(data + offset), length);
  offset += length;
  return value;
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, std::size_t size) {
  if (size == 0 || size > 64 * 1024)
    return 0;

  const bool kdbx4 = (data[0] & 0x01) != 0;
  const bool compress = (data[0] & 0x02) != 0;
  const std::size_t entry_count = (data[0] >> 2) % 6 + 1;
  std::size_t offset = 1;

  auto db = std::make_unique<keepass::Database>();
  db->set_cipher(keepass::Database::Cipher::kAes);
  db->set_kdf(keepass::Database::Kdf::kAes);
  db->set_compress(compress);
  db->set_transform_rounds(10);
  db->set_master_seed(
      std::array<uint8_t, 16>{{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}});
  db->set_init_vector(
      std::array<uint8_t, 16>{{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}});
  db->set_transform_seed(
      std::array<uint8_t, 32>{{0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15,
                               16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31}});
  db->set_inner_random_stream_key(
      std::array<uint8_t, 32>{{31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16,
                               15, 14, 13, 12, 11, 10, 9,  8,  7,  6,  5,  4,  3,  2,  1,  0}});

  auto root = keepass::Database::NewGroup(Take(data, size, offset, 32));
  for (std::size_t i = 0; i < entry_count; ++i) {
    auto entry = keepass::Database::NewEntry(Take(data, size, offset, 64));
    entry->set_username(keepass::protect<keepass::secure_string>(
        keepass::secure_string(Take(data, size, offset, 64)), false));
    entry->set_password(keepass::protect<keepass::secure_string>(
        keepass::secure_string(Take(data, size, offset, 64)), true));
    entry->set_url(keepass::protect<keepass::secure_string>(
        keepass::secure_string(Take(data, size, offset, 64)), false));
    entry->set_notes(keepass::protect<keepass::secure_string>(
        keepass::secure_string(Take(data, size, offset, 128)), false));
    entry->set_tags(Take(data, size, offset, 32));
    entry->set_custom_property("fuzz", Take(data, size, offset, 64));

    if (offset < size && (data[offset++] & 0x01) != 0) {
      const std::string name = Take(data, size, offset, 32);
      const std::string payload = Take(data, size, offset, 256);
      std::vector<uint8_t> bytes(payload.begin(), payload.end());
      entry->set_binary_property(name, bytes);
    }

    if (offset < size && (data[offset++] & 0x01) != 0)
      entry->save_history();

    keepass::Database::AddEntry(root, entry);
  }
  db->set_root(root);

  const keepass::Key key("password");
  std::ostringstream encrypted;
  keepass::KdbxFile exporter;
  exporter.set_write_kdbx4(kdbx4);
  try {
    exporter.Export(encrypted, *db, key);
  } catch (...) {
    return 0;
  }

  std::istringstream input(encrypted.str());
  keepass::KdbxFile importer;
  try {
    (void)importer.Import(input, key);
  } catch (...) {
    // A round-trip failure is a finding for the regular tests, not a memory
    // safety issue; keep fuzzing for sanitizer reports.
  }
  return 0;
}
