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

#include "libkeepass/variantdictionary.hh"

#include <cstring>

#include "libkeepass/exception.hh"

namespace keepass {

void VariantDictionary::Parse(std::istream &src) {
  uint16_t version = 0;
  src.read(reinterpret_cast<char *>(&version), sizeof(version));
  if (src.gcount() != sizeof(version))
    throw FormatError("Corrupt variant dictionary header.");

  // Only accept versions that we understand. The critical version mask
  // extracts the most significant nibble (format: 1.0 => 0x0100).
  constexpr uint16_t kMaxVersion = 0x0100;
  if ((version & 0xff00) > kMaxVersion)
    throw FormatError("Unsupported variant dictionary version.");

  entries_.clear();

  while (src.good()) {
    uint8_t type_byte = 0;
    src.read(reinterpret_cast<char *>(&type_byte), 1);
    if (src.gcount() != 1)
      throw FormatError("Corrupt variant dictionary entry.");

    if (type_byte == static_cast<uint8_t>(Type::kEnd))
      return;

    uint32_t key_len = 0;
    src.read(reinterpret_cast<char *>(&key_len), sizeof(key_len));
    if (src.gcount() != sizeof(key_len))
      throw FormatError("Corrupt variant dictionary key length.");

    std::string key(key_len, '\0');
    if (key_len > 0)
      src.read(&key[0], key_len);
    if (src.gcount() != static_cast<std::streamsize>(key_len))
      throw FormatError("Corrupt variant dictionary key.");

    uint32_t value_len = 0;
    src.read(reinterpret_cast<char *>(&value_len), sizeof(value_len));
    if (src.gcount() != sizeof(value_len))
      throw FormatError("Corrupt variant dictionary value length.");

    std::vector<uint8_t> value(value_len, 0);
    if (value_len > 0)
      src.read(reinterpret_cast<char *>(value.data()), value_len);
    if (src.gcount() != static_cast<std::streamsize>(value_len))
      throw FormatError("Corrupt variant dictionary value.");

    Entry entry;
    entry.type = static_cast<Type>(type_byte);
    entry.value = std::move(value);
    entries_[key] = std::move(entry);
  }

  throw FormatError("Unterminated variant dictionary.");
}

void VariantDictionary::Write(std::ostream &dst) const {
  constexpr uint16_t kVersion = 0x0100;
  dst.write(reinterpret_cast<const char *>(&kVersion), sizeof(kVersion));

  for (const auto &pair : entries_) {
    uint8_t type_byte = static_cast<uint8_t>(pair.second.type);
    dst.write(reinterpret_cast<const char *>(&type_byte), 1);

    uint32_t key_len = static_cast<uint32_t>(pair.first.size());
    dst.write(reinterpret_cast<const char *>(&key_len), sizeof(key_len));
    dst.write(pair.first.c_str(),
              static_cast<std::streamsize>(pair.first.size()));

    uint32_t value_len = static_cast<uint32_t>(pair.second.value.size());
    dst.write(reinterpret_cast<const char *>(&value_len), sizeof(value_len));
    if (!pair.second.value.empty())
      dst.write(reinterpret_cast<const char *>(pair.second.value.data()),
                static_cast<std::streamsize>(pair.second.value.size()));
  }

  uint8_t end = static_cast<uint8_t>(Type::kEnd);
  dst.write(reinterpret_cast<const char *>(&end), 1);
}

bool VariantDictionary::Has(const std::string &key) const {
  return entries_.find(key) != entries_.end();
}

const VariantDictionary::Entry &
VariantDictionary::Get(const std::string &key) const {
  auto it = entries_.find(key);
  if (it == entries_.end())
    throw FormatError("Missing variant dictionary key.");
  return it->second;
}

void VariantDictionary::Set(const std::string &key, Type type,
                            std::vector<uint8_t> &&value) {
  Entry entry;
  entry.type = type;
  entry.value = std::move(value);
  entries_[key] = std::move(entry);
}

std::vector<uint8_t>
VariantDictionary::GetBytes(const std::string &key) const {
  return Get(key).value;
}

uint32_t VariantDictionary::GetUInt32(const std::string &key) const {
  const Entry &entry = Get(key);
  if (entry.value.size() != 4)
    throw FormatError("Invalid variant dictionary UInt32 size.");
  uint32_t val = 0;
  std::memcpy(&val, entry.value.data(), 4);
  return val;
}

uint64_t VariantDictionary::GetUInt64(const std::string &key) const {
  const Entry &entry = Get(key);
  if (entry.value.size() != 8)
    throw FormatError("Invalid variant dictionary UInt64 size.");
  uint64_t val = 0;
  std::memcpy(&val, entry.value.data(), 8);
  return val;
}

} // namespace keepass