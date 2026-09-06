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
 * @file keepass.hh
 * @brief High-level unified KeePass database import/export API.
 */

#pragma once
#include <istream>
#include <memory>
#include <ostream>
#include <string>

#include "database.hh"
#include "kdbx.hh"
#include "key.hh"
#include "libkeepass/export.hh"

namespace keepass {

class KdbFile;

/**
 * @brief High-level entry point for opening and saving KeePass databases.
 *
 * KeePass unifies the KDB and KDBX importers/exporters behind a single
 * interface. The format is auto-detected on input; on output it can either be
 * selected explicitly via \ref SetFormat or derived from the database content
 * and the target file extension.
 */
class LIBKEEPASS_API KeePass final {
public:
  /// Database formats supported for reading and writing.
  enum class Format {
    kAuto,  ///< Auto-detect the format.
    kKdb,   ///< KeePass 1.x KDB format.
    kKdbx3, ///< KeePass 2.x KDBX 3 format.
    kKdbx4  ///< KeePass 2.x KDBX 4 format.
  };

  /// Constructs an importer/exporter with an empty key.
  KeePass();

  /// Constructs an importer/exporter with the given key.
  /**
   * @param key The key used to decrypt and encrypt databases.
   */
  explicit KeePass(const Key& key);

  /// Constructs an importer/exporter from a password and optional key file.
  /**
   * @param password The database password.
   * @param keyfile Path to a key file, or an empty string for none.
   */
  KeePass(const std::string& password, const std::string& keyfile = "");

  /// Opens a KeePass (KDB or KDBX) database file.
  /**
   * @param path Path to the database file on disk.
   * @return A unique pointer to the imported Database object.
   */
  std::unique_ptr<Database> Open(const std::string& path);

  /// Opens a KeePass database from a stream with format auto-detection.
  /**
   * @param src The input stream containing the database.
   * @return A unique pointer to the imported Database object.
   */
  std::unique_ptr<Database> Open(std::istream& src);

  /// Saves a database to a file.
  /**
   * The output format is taken from \ref SetFormat if set, otherwise derived
   * from the file extension and the database content.
   *
   * @param path Path to the output file.
   * @param db The database to save.
   */
  void Save(const std::string& path, const Database& db);

  /// Saves a database to a stream.
  /**
   * The output format is taken from \ref SetFormat if set, otherwise a KDBX
   * format is chosen based on the database KDF and cipher.
   *
   * @param dst The output stream.
   * @param db The database to save.
   */
  void Save(std::ostream& dst, const Database& db);

  /// Saves a database to a file using a new key.
  /**
   * @param path Path to the output file.
   * @param db The database to save.
   * @param new_key The key to encrypt the database with.
   */
  void SaveAs(const std::string& path, const Database& db, const Key& new_key);

  /// Saves a database to a file using a new password and optional key file.
  /**
   * @param path Path to the output file.
   * @param db The database to save.
   * @param password The new database password.
   * @param keyfile Path to a key file, or an empty string for none.
   */
  void SaveAs(const std::string& path, const Database& db, const std::string& password,
              const std::string& keyfile = "");

  /// Selects the output format.
  void SetFormat(Format format) { format_ = format; }

  /// Returns the configured output format.
  Format GetFormat() const { return format_; }

  /// Creates a new empty database with generated cryptographic material.
  /**
   * @param password Password of the new database (not required for creation).
   * @param format Preferred output format of the new database.
   * @param cipher Payload cipher to use.
   * @param kdf Key derivation function to use.
   * @return A unique pointer to the newly created Database object.
   */
  static std::unique_ptr<Database> Create(const std::string& password = "",
                                          Format format = Format::kKdbx4,
                                          Database::Cipher cipher = Database::Cipher::kAes,
                                          Database::Kdf kdf = Database::Kdf::kArgon2id);

private:
  void Save(std::ostream& dst, const Database& db, Format format);
  Format ResolveOutputFormat(const std::string& path, const Database& db) const;

  Key key_;
  Format format_ = Format::kAuto;
  KdbxFile kdbx_file_;
};

} // namespace keepass