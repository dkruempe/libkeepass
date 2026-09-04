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

/**
 * @file variantdictionary.hh
 * @brief A typed key-value store for KDBX 4 header fields.
 */

#pragma once
#include <cstdint>
#include <istream>
#include <map>
#include <ostream>
#include <string>
#include <vector>

#include "libkeepass/export.hh"

namespace keepass {

/**
 * @brief A typed key-value store used in KDBX 4 header fields.
 *
 * Format reference: https://sseemayer.github.io/kdbx-compendium/
 */
class LIBKEEPASS_API VariantDictionary final {
public:
  /// Type tags identifying the value kind stored in an entry.
  enum class Type : uint8_t {
    kEnd = 0x00,       ///< End-of-dictionary sentinel.
    kUInt32 = 0x04,    ///< Unsigned 32-bit integer.
    kUInt64 = 0x05,    ///< Unsigned 64-bit integer.
    kBool = 0x08,      ///< Boolean value.
    kInt32 = 0x0c,     ///< Signed 32-bit integer.
    kInt64 = 0x0d,     ///< Signed 64-bit integer.
    kString = 0x18,    ///< UTF-8 string.
    kByteArray = 0x42  ///< Raw byte array.
  };

  /**
   * @brief A single entry in the dictionary, holding a typed value.
   */
  struct Entry {
    Type type = Type::kUInt32;   ///< Data type of this entry.
    std::vector<uint8_t> value; ///< Raw serialized value bytes.
  };

  /**
   * @brief Deserializes the dictionary from a binary stream.
   * @param [in,out] src Input stream to read from.
   */
  void Parse(std::istream &src);

  /**
   * @brief Serializes the dictionary to a binary stream.
   * @param [out] dst Output stream to write to.
   */
  void Write(std::ostream &dst) const;

  /**
   * @brief Checks whether an entry with the given key exists.
   * @param [in] key Entry key to look up.
   * @return true if the key is present, false otherwise.
   */
  bool Has(const std::string &key) const;

  /**
   * @brief Returns the entry associated with @a key.
   * @param [in] key Entry key to look up.
   * @return Const reference to the matching entry.
   */
  const Entry &Get(const std::string &key) const;

  /**
   * @brief Inserts or replaces an entry in the dictionary.
   * @param [in] key Entry key.
   * @param [in] type Data type of the value.
   * @param [in] value Raw serialized value bytes (moved in).
   */
  void Set(const std::string &key, Type type, std::vector<uint8_t> &&value);

  /**
   * @brief Returns the raw value bytes of an entry.
   * @param [in] key Entry key to look up.
   * @return Copy of the value byte vector.
   */
  std::vector<uint8_t> GetBytes(const std::string &key) const;

  /**
   * @brief Returns the value of an entry interpreted as a uint32.
   * @param [in] key Entry key to look up.
   * @return The value as uint32_t.
   */
  uint32_t GetUInt32(const std::string &key) const;

  /**
   * @brief Returns the value of an entry interpreted as a uint64.
   * @param [in] key Entry key to look up.
   * @return The value as uint64_t.
   */
  uint64_t GetUInt64(const std::string &key) const;

  /**
   * @brief Returns a copy of all entries in the dictionary.
   * @return Map of key-value pairs.
   */
  std::map<std::string, Entry> entries() const { return entries_; }

private:
  std::map<std::string, Entry> entries_; ///< Internal entry storage.
};

} // namespace keepass