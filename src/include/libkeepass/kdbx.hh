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
 * @file kdbx.hh
 * @brief KDBX format database file import and export.
 */

#pragma once
#include <cstdint>
#include <istream>
#include <memory>
#include <string>
#include <unordered_map>

#include "database.hh"
#include "libkeepass/export.hh"
#include "security.hh"

namespace pugi {
class xml_document;
class xml_node;
} // namespace pugi

namespace keepass {

class Binary;
class Entry;
class Group;
class Icon;
class Key;
class Metadata;
class RandomObfuscator;

/**
 * @brief Keepass2 database file representation.
 */
class LIBKEEPASS_API KdbxFile final {
private:
  using BinaryPool = std::unordered_map<std::string, std::shared_ptr<Binary>>;

  using IconPool = std::unordered_map<std::string, std::weak_ptr<Icon>>;

  using GroupPool = std::unordered_map<std::string, std::shared_ptr<Group>>;

  BinaryPool binary_pool_;
  IconPool icon_pool_;
  GroupPool group_pool_;
  std::array<uint8_t, 32> header_hash_ = {{0}};

  /** True while reading or writing a KDBX 4 database. */
  bool kdbx4_ = false;

  /** Force KDBX 4 output even if the database could be written as KDBX 3. */
  bool write_kdbx4_ = false;

  /// Resets all internal pools and state for a new import/export operation.
  void Reset();

  /// Retrieves a group by its UUID string, creating it in the pool if needed.
  /**
   * @param uuid_str The UUID string of the group to look up.
   * @return Shared pointer to the group.
   */
  std::shared_ptr<Group> GetGroup(const std::string& uuid_str);

  /// Parses a KDBX datetime string into a std::time_t value.
  /**
   * @param text The datetime string in KDBX format.
   * @return The parsed time value.
   */
  std::time_t ParseDateTime(const char* text) const;

  /// Converts a std::time_t value to a KDBX datetime string.
  /**
   * @param time The time value to format.
   * @return The formatted datetime string.
   */
  std::string WriteDateTime(std::time_t time) const;
  /** Seconds since 0001-01-01 UTC representing the KDBX "never" date. */
  static int64_t NeverSeconds();

  /// Parses the KDF parameters header field of a KDBX 4 database.
  /**
   * @param field The stream containing the serialized KDF parameters.
   * @param db The database to populate with the parsed KDF settings.
   */
  static void ParseKdfParameters(std::istream& field, Database& db);

  /// Imports a KDBX 3 format database from a stream.
  /**
   * @param src The input stream containing the KDBX 3 database.
   * @param key The key used to decrypt the database.
   * @return A unique pointer to the imported Database object.
   */
  std::unique_ptr<Database> Import3(std::istream& src, const Key& key);

  /// Imports a KDBX 4 format database from a stream.
  /**
   * @param src The input stream containing the KDBX 4 database.
   * @param key The key used to decrypt the database.
   * @return A unique pointer to the imported Database object.
   */
  std::unique_ptr<Database> Import4(std::istream& src, const Key& key);

  /// Exports a database in KDBX 3 format to a stream.
  /**
   * @param dst The output stream to write the KDBX 3 database to.
   * @param db The database to export.
   * @param key The key used to encrypt the database.
   */
  void Export3(std::ostream& dst, const Database& db, const Key& key);

  /// Exports a database in KDBX 4 format to a stream.
  /**
   * @param dst The output stream to write the KDBX 4 database to.
   * @param db The database to export.
   * @param key The key used to encrypt the database.
   */
  void Export4(std::ostream& dst, const Database& db, const Key& key);

  /// Parses a protected string value from an XML node.
  /**
   * @param node The XML node containing the protected value.
   * @param name The attribute name of the protected value.
   * @param obfuscator The random stream obfuscator for decryption.
   * @return The decrypted protected string.
   */
  static protect<std::string> ParseProtectedString(const pugi::xml_node& node, const char* name,
                                                   RandomObfuscator& obfuscator);

  /// Writes a protected string value to an XML node.
  /**
   * @param node The XML node to write the protected value to.
   * @param str The protected string to encrypt and write.
   * @param obfuscator The random stream obfuscator for encryption.
   */
  static void WriteProtectedString(pugi::xml_node& node, const protect<std::string>& str,
                                   RandomObfuscator& obfuscator);

  /// Parses the metadata section from the KDBX XML tree.
  /**
   * @param meta_node The XML node containing the metadata.
   * @param obfuscator The random stream obfuscator for decryption.
   * @return A shared pointer to the parsed Metadata object.
   */
  std::shared_ptr<Metadata> ParseMeta(const pugi::xml_node& meta_node,
                                      RandomObfuscator& obfuscator);

  /// Writes the metadata section to the KDBX XML tree.
  /**
   * @param meta_node The XML node to write metadata into.
   * @param obfuscator The random stream obfuscator for encryption.
   * @param meta The metadata object to serialize.
   */
  void WriteMeta(pugi::xml_node& meta_node, RandomObfuscator& obfuscator,
                 const std::shared_ptr<Metadata>& meta);

  /**
   * Parses a an entry in the XML tree.
   * @param [in] entry_node Entry XML node.
   * @param [out] entry_uuid Entry UUID.
   * @param [in] obfuscator Random stream obfuscator.
   * @return Pointer to entry object.
   */
  std::shared_ptr<Entry> ParseEntry(const pugi::xml_node& entry_node,
                                    std::array<uint8_t, 16>& entry_uuid,
                                    RandomObfuscator& obfuscator);
  /// Writes an entry to an XML node.
  /**
   * @param entry_node The XML node to write the entry into.
   * @param obfuscator The random stream obfuscator for encryption.
   * @param entry The entry object to serialize.
   */
  void WriteEntry(pugi::xml_node& entry_node, RandomObfuscator& obfuscator,
                  const std::shared_ptr<Entry>& entry);

  /// Parses a group from the XML tree.
  /**
   * @param group_node The XML node containing the group.
   * @param obfuscator The random stream obfuscator for decryption.
   * @return A shared pointer to the parsed Group object.
   */
  std::shared_ptr<Group> ParseGroup(const pugi::xml_node& group_node, RandomObfuscator& obfuscator);

  /// Writes a group to an XML node.
  /**
   * @param group_node The XML node to write the group into.
   * @param obfuscator The random stream obfuscator for encryption.
   * @param group The group object to serialize.
   */
  void WriteGroup(pugi::xml_node& group_node, RandomObfuscator& obfuscator,
                  const std::shared_ptr<Group>& group);

  /// Parses the full KDBX XML body from a stream.
  /**
   * @param src The input stream containing the XML body.
   * @param obfuscator The random stream obfuscator for decryption.
   * @param db The database to populate with parsed data.
   */
  void ParseXml(std::istream& src, RandomObfuscator& obfuscator, Database& db);
#ifdef DEBUG
  void PrintXml(pugi::xml_document& doc);
#endif
  /// Writes the full KDBX XML body to a stream.
  /**
   * @param dst The output stream to write the XML body to.
   * @param obfuscator The random stream obfuscator for encryption.
   * @param db The database to serialize.
   */
  void WriteXml(std::ostream& dst, RandomObfuscator& obfuscator, const Database& db);

public:
  /// Imports a KDBX database from a file path.
  /**
   * @param path Path to the KDBX database file on disk.
   * @param key The key used to decrypt the database.
   * @return A unique pointer to the imported Database object.
   */
  std::unique_ptr<Database> Import(const std::string& path, const Key& key);

  /// Exports a database to a KDBX file.
  /**
   * @param path Path to the output file.
   * @param db The database to export.
   * @param key The key used to encrypt the database.
   */
  void Export(const std::string& path, const Database& db, const Key& key);

  /** Forces the exporter to produce a KDBX 4 format database. */
  void set_write_kdbx4(bool write_kdbx4) { write_kdbx4_ = write_kdbx4; }
};

} // namespace keepass
