/*
 * libkeepass - KeePass key database importer/exporter
 * Copyright (C) 2014 Christian Kindahl
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

#pragma once
#include <cstdint>
#include <istream>
#include <map>
#include <ostream>
#include <string>
#include <vector>

namespace keepass {

/**
 * @brief A typed key-value store used in KDBX 4 header fields.
 *
 * Format reference: https://sseemayer.github.io/kdbx-compendium/
 */
class VariantDictionary final {
public:
  enum class Type : uint8_t {
    kEnd = 0x00,
    kUInt32 = 0x04,
    kUInt64 = 0x05,
    kBool = 0x08,
    kInt32 = 0x0c,
    kInt64 = 0x0d,
    kString = 0x18,
    kByteArray = 0x42
  };

  struct Entry {
    Type type = Type::kUInt32;
    std::vector<uint8_t> value;
  };

  void Parse(std::istream &src);
  void Write(std::ostream &dst) const;

  bool Has(const std::string &key) const;
  const Entry &Get(const std::string &key) const;
  void Set(const std::string &key, Type type, std::vector<uint8_t> &&value);

  std::vector<uint8_t> GetBytes(const std::string &key) const;
  uint32_t GetUInt32(const std::string &key) const;
  uint64_t GetUInt64(const std::string &key) const;

  std::map<std::string, Entry> entries() const { return entries_; }

private:
  std::map<std::string, Entry> entries_;
};

} // namespace keepass