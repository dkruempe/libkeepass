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
 * @file kdb.hh
 * @brief KDB (KeePass 1.x) format database file import and export.
 */

#pragma once
#include <cstdint>
#include <memory>
#include <string>

#include "database.hh"
#include "libkeepass/export.hh"

namespace keepass {

class Entry;
class Group;
class Key;

/**
 * @brief Keepass database file representation.
 */
class LIBKEEPASS_API KdbFile final {
private:
  /// Reads a group (and its subgroups) from a KDB stream.
  /**
   * @param src The input stream to read the group from.
   * @param id Output parameter receiving the group's id.
   * @param level Output parameter receiving the group's hierarchy level.
   * @return A shared pointer to the read Group object.
   */
  static std::shared_ptr<Group> ReadGroup(std::istream &src, uint32_t &id,
                                   uint16_t &level);

  /// Writes a group (and its subgroups) to a KDB stream.
  /**
   * @param dst The output stream to write the group to.
   * @param group The group object to serialize.
   * @param group_id The id to assign to the group.
   * @param level The hierarchy level of the group.
   */
  static void WriteGroup(std::ostream &dst, const std::shared_ptr<Group> &group,
                  uint32_t group_id, uint16_t level);

  /// Reads an entry from a KDB stream.
  /**
   * @param src The input stream to read the entry from.
   * @param group_id Output parameter receiving the id of the entry's group.
   * @return A shared pointer to the read Entry object.
   */
  static std::shared_ptr<Entry> ReadEntry(std::istream &src, uint32_t &group_id);

  /// Writes an entry to a KDB stream.
  /**
   * @param dst The output stream to write the entry to.
   * @param entry The entry object to serialize.
   * @param group_id The id of the group containing the entry.
   */
  static void WriteEntry(std::ostream &dst, const std::shared_ptr<Entry> &entry,
                  uint32_t group_id);

public:
  /// Imports a KDB database from a file path.
  /**
   * @param path Path to the KDB database file on disk.
   * @param key The key used to decrypt the database.
   * @return A unique pointer to the imported Database object.
   */
  static std::unique_ptr<Database> Import(const std::string &path, const Key &key);

  /// Exports a database to a KDB file.
  /**
   * @param path Path to the output file.
   * @param db The database to export.
   * @param key The key used to encrypt the database.
   */
  static void Export(const std::string &path, const Database &db, const Key &key);
};

} // namespace keepass
