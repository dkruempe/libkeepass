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
 * @file kdbx_kdf.hh
 * @brief Key derivation function dispatcher for the KDBX header.
 *
 * This module isolates the KDF-specific knowledge (AES-KDF, Argon2d/id, and
 * later BLAKE2b-Argon2) from the KDBX import/export pipeline: how the KDF
 * parameters are (de)serialized into a KDBX 4 variant dictionary and which
 * Key::Transform must be run for a given database.
 */

#pragma once
#include <cstdint>
#include <istream>
#include <ostream>

#include "libkeepass/database.hh"
#include "libkeepass/export.hh"
#include "libkeepass/key.hh"
#include "libkeepass/secure.hh"

namespace keepass {

/**
 * @brief Dispatches between the supported KDBX key derivation functions.
 *
 * All operations are static: the class carries no per-instance state and only
 * translates between the KDBX 4 variant dictionary representation, the
 * Database KDF settings and the Key transformation functions.
 */
class LIBKEEPASS_API KdbxKdf final {
public:
  /// Parses the KDF parameters header field of a KDBX 4 database.
  /**
   * Reads the serialized variant dictionary from @a field, identifies the KDF
   * by its UUID and populates the KDF settings on @a db.
   *
   * @param field Stream containing the serialized KDF parameters.
   * @param db The database to populate with the parsed KDF settings.
   */
  static void ParseParameters(std::istream& field, Database& db);

  /// Writes the KDF parameters of @a db into a variant dictionary stream.
  /**
   * @param dst Output stream to serialize the KDF parameters into.
   * @param db The database whose KDF settings to serialize.
   */
  static void WriteParameters(std::ostream& dst, const Database& db);

  /// Derives the transformed key using the database's configured KDF.
  /**
   * @param key The user key to transform (password / key file / composite).
   * @param db The database providing the KDF parameters.
   * @param resolution Strategy for resolving sub keys before the transform.
   * @return The derived 32-byte transformed key.
   */
  static SecureBuffer<32> Transform(const Key& key, const Database& db,
                                    Key::SubKeyResolution resolution);
};

} // namespace keepass