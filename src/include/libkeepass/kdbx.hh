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
#include <ostream>
#include <string>

#include "database.hh"
#include "libkeepass/export.hh"
#include "libkeepass/kdbx_xml.hh"
#include "security.hh"

namespace keepass {

class Key;

/**
 * @brief Keepass2 database file representation.
 */
class LIBKEEPASS_API KdbxFile final {
private:
  /** Force KDBX 4 output even if the database could be written as KDBX 3. */
  bool write_kdbx4_ = false;

  /** KDBX XML body serializer/deserializer holding all per-operation state. */
  KdbxXml xml_;

  /// Resets all internal pools and state for a new import/export operation.
  void Reset();

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

public:
  /// Imports a KDBX database from a file path.
  /**
   * @param path Path to the KDBX database file on disk.
   * @param key The key used to decrypt the database.
   * @return A unique pointer to the imported Database object.
   */
  std::unique_ptr<Database> Import(const std::string& path, const Key& key);

  /// Imports a KDBX database from an input stream.
  /**
   * @param src The input stream containing the KDBX database.
   * @param key The key used to decrypt the database.
   * @return A unique pointer to the imported Database object.
   */
  std::unique_ptr<Database> Import(std::istream& src, const Key& key);

  /// Exports a database to a KDBX file.
  /**
   * @param path Path to the output file.
   * @param db The database to export.
   * @param key The key used to encrypt the database.
   */
  void Export(const std::string& path, const Database& db, const Key& key);

  /// Exports a database to an output stream in KDBX format.
  /**
   * @param dst The output stream to write the KDBX database to.
   * @param db The database to export.
   * @param key The key used to encrypt the database.
   */
  void Export(std::ostream& dst, const Database& db, const Key& key);

  /** Forces the exporter to produce a KDBX 4 format database. */
  void set_write_kdbx4(bool write_kdbx4) { write_kdbx4_ = write_kdbx4; }
};

} // namespace keepass