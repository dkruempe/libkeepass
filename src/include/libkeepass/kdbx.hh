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

#pragma once
#include <cstdint>
#include <istream>
#include <memory>
#include <string>
#include <unordered_map>

#include "database.hh"
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
class KdbxFile final {
private:
  typedef std::unordered_map<std::string, std::shared_ptr<Binary>> BinaryPool;

  typedef std::unordered_map<std::string, std::weak_ptr<Icon>> IconPool;

  typedef std::unordered_map<std::string, std::shared_ptr<Group>> GroupPool;

private:
  BinaryPool binary_pool_;
  IconPool icon_pool_;
  GroupPool group_pool_;
  std::array<uint8_t, 32> header_hash_ = {{0}};

  /** True while reading or writing a KDBX 4 database. */
  bool kdbx4_ = false;

  /** Force KDBX 4 output even if the database could be written as KDBX 3. */
  bool write_kdbx4_ = false;

  void Reset();

  std::shared_ptr<Group> GetGroup(const std::string &uuid_str);

  std::time_t ParseDateTime(const char *text);
  std::string WriteDateTime(std::time_t time);
  /** Seconds since 0001-01-01 UTC representing the KDBX "never" date. */
  int64_t NeverSeconds() const;

  std::unique_ptr<Database> Import3(std::istream &src, const Key &key);
  std::unique_ptr<Database> Import4(std::istream &src, const Key &key);
  void Export3(std::ostream &dst, const Database &db, const Key &key);
  void Export4(std::ostream &dst, const Database &db, const Key &key);

  static protect<std::string> ParseProtectedString(const pugi::xml_node &node,
                                            const char *name,
                                            RandomObfuscator &obfuscator);
  static void WriteProtectedString(pugi::xml_node &node,
                            const protect<std::string> &str,
                            RandomObfuscator &obfuscator);

  std::shared_ptr<Metadata> ParseMeta(const pugi::xml_node &meta_node,
                                      RandomObfuscator &obfuscator);
  void WriteMeta(pugi::xml_node &meta_node, RandomObfuscator &obfuscator,
                 const std::shared_ptr<Metadata>& meta);

  /**
   * Parses a an entry in the XML tree.
   * @param [in] entry_node Entry XML node.
   * @param [out] entry_uuid Entry UUID.
   * @param [in] obfuscator Random stream obfuscator.
   * @return Pointer to entry object.
   */
  std::shared_ptr<Entry> ParseEntry(const pugi::xml_node &entry_node,
                                    std::array<uint8_t, 16> &entry_uuid,
                                    RandomObfuscator &obfuscator);
  void WriteEntry(pugi::xml_node &entry_node, RandomObfuscator &obfuscator,
                  const std::shared_ptr<Entry> &entry);

  std::shared_ptr<Group> ParseGroup(const pugi::xml_node &group_node,
                                    RandomObfuscator &obfuscator);
  void WriteGroup(pugi::xml_node &group_node, RandomObfuscator &obfuscator,
                  const std::shared_ptr<Group> &group);

  void ParseXml(std::istream &src, RandomObfuscator &obfuscator, Database &db);
#ifdef DEBUG
  void PrintXml(pugi::xml_document &doc);
#endif
  void WriteXml(std::ostream &dst, RandomObfuscator &obfuscator,
                const Database &db);

public:
  std::unique_ptr<Database> Import(const std::string &path, const Key &key);
  void Export(const std::string &path, const Database &db, const Key &key);

  /** Forces the exporter to produce a KDBX 4 format database. */
  void set_write_kdbx4(bool write_kdbx4) { write_kdbx4_ = write_kdbx4; }
};

} // namespace keepass
