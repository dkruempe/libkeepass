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
 * @file kdbx_xml.hh
 * @brief KDBX XML body parser and serializer.
 */

#pragma once
#include <array>
#include <cstdint>
#include <istream>
#include <memory>
#include <ostream>
#include <string>
#include <unordered_map>

#include "libkeepass/database.hh"
#include "libkeepass/export.hh"
#include "libkeepass/secure.hh"

namespace pugi {
class xml_document;
class xml_node;
} // namespace pugi

namespace keepass {

class Binary;
class Entry;
class Group;
class Icon;
class Metadata;
class RandomObfuscator;

/**
 * @brief Parses and serializes the KDBX XML body.
 *
 * The KDBX XML body contains the metadata (including custom icons and, for
 * KDBX 3, the binary attachments), the groups with their entries and the
 * deleted-objects tombstones. This class owns the pools (binaries, icons and
 * groups by UUID reference) that are shared between the metadata, groups and
 * the KDBX 4 inner header handling in KdbxFile.
 *
 * The class is closely tied to KdbxFile, which drives the outer header,
 * decryption and inner-header processing; it is used only internally by the
 * library.
 */
class LIBKEEPASS_API KdbxXml final {
public:
  using BinaryPool = std::unordered_map<std::string, std::shared_ptr<Binary>>;

  using IconPool = std::unordered_map<std::string, std::weak_ptr<Icon>>;

  using GroupPool = std::unordered_map<std::string, std::shared_ptr<Group>>;

  /// True while reading or writing a KDBX 4 database.
  void set_kdbx4(bool kdbx4) { kdbx4_ = kdbx4; }
  bool kdbx4() const { return kdbx4_; }

  /// True while writing KDBX 4.1 (0x00040001).
  void set_kdbx41(bool kdbx41) { kdbx41_ = kdbx41; }
  bool kdbx41() const { return kdbx41_; }

  /// Resets all internal pools and state for a new import/export operation.
  void Reset();

  /// Binary attachments referenced by entries and collected by the KDBX 4
  /// inner-header processing in KdbxFile.
  BinaryPool& binary_pool() { return binary_pool_; }

  /// Header hash as carried inside the KDBX XML document (KDBX 3 only). The
  /// outer header processing in KdbxFile verifies resp. provides this value.
  std::array<uint8_t, 32>& header_hash() { return header_hash_; }
  const std::array<uint8_t, 32>& header_hash() const { return header_hash_; }

  /// Parses the full KDBX XML body from a stream.
  /**
   * @param src The input stream containing the XML body.
   * @param obfuscator The random stream obfuscator for decryption.
   * @param db The database to populate with parsed data.
   */
  void Parse(std::istream& src, RandomObfuscator& obfuscator, Database& db);

  /// Writes the full KDBX XML body to a stream.
  /**
   * @param dst The output stream to write the XML body to.
   * @param obfuscator The random stream obfuscator for encryption.
   * @param db The database to serialize.
   */
  void Write(std::ostream& dst, RandomObfuscator& obfuscator, const Database& db);

#ifdef DEBUG
  /// Prints an XML document tree to std::cout (debug builds only).
  void PrintXml(pugi::xml_document& doc);
#endif

private:
  BinaryPool binary_pool_;
  IconPool icon_pool_;
  GroupPool group_pool_;
  std::array<uint8_t, 32> header_hash_ = {{0}};

  bool kdbx4_ = false;
  bool kdbx41_ = false;

  /// Retrieves a group by its UUID string, creating it in the pool if needed.
  std::shared_ptr<Group> GetGroup(const std::string& uuid_str);

  /// Parses a KDBX datetime string into a std::time_t value.
  std::time_t ParseDateTime(const char* text) const;

  /// Converts a std::time_t value to a KDBX datetime string.
  std::string WriteDateTime(std::time_t time) const;

  /// Seconds since 0001-01-01 UTC representing the KDBX "never" date.
  static int64_t NeverSeconds();

  /// Parses a protected string value from an XML node.
  static protect<secure_string> ParseProtectedString(const pugi::xml_node& node, const char* name,
                                                     RandomObfuscator& obfuscator);

  /// Writes a protected string value to an XML node.
  static void WriteProtectedString(pugi::xml_node& node, const protect<secure_string>& str,
                                   RandomObfuscator& obfuscator);

  /// Parses the metadata section from the KDBX XML tree.
  std::shared_ptr<Metadata> ParseMeta(const pugi::xml_node& meta_node,
                                      RandomObfuscator& obfuscator);

  /// Writes the metadata section to the KDBX XML tree.
  void WriteMeta(pugi::xml_node& meta_node, RandomObfuscator& obfuscator,
                 const std::shared_ptr<Metadata>& meta);

  /// Parses an entry in the XML tree.
  /**
   * @param entry_node Entry XML node.
   * @param entry_uuid [out] Entry UUID.
   * @param obfuscator Random stream obfuscator.
   * @return Pointer to entry object.
   */
  std::shared_ptr<Entry> ParseEntry(const pugi::xml_node& entry_node,
                                    std::array<uint8_t, 16>& entry_uuid,
                                    RandomObfuscator& obfuscator);

  /// Writes an entry to an XML node.
  void WriteEntry(pugi::xml_node& entry_node, RandomObfuscator& obfuscator,
                  const std::shared_ptr<Entry>& entry);

  /// Parses a group from the XML tree.
  std::shared_ptr<Group> ParseGroup(const pugi::xml_node& group_node, RandomObfuscator& obfuscator);

  /// Writes a group to an XML node.
  void WriteGroup(pugi::xml_node& group_node, RandomObfuscator& obfuscator,
                  const std::shared_ptr<Group>& group);
};

} // namespace keepass