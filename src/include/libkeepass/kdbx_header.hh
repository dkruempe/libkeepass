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
 * @file kdbx_header.hh
 * @brief KDBX outer header parser and serializer (KDBX 3 and KDBX 4).
 *
 * This module isolates the KDBX outer header wire format from the rest of the
 * import/export pipeline: the file signature and version prefix, the
 * per-version header field layout, the cipher identifiers, the compression
 * and inner-random-stream enums and the size caps used against malformed
 * files. KdbxFile remains responsible for the cryptographic steps (key
 * derivation, decryption, integrity verification) that surround the header.
 */

#pragma once
#include <array>
#include <cstdint>
#include <istream>
#include <string>

#include "libkeepass/database.hh"
#include "libkeepass/export.hh"

namespace keepass {

/**
 * @brief Parses and serializes the outer header of a KDBX database.
 *
 * The outer header of a KDBX 3 and a KDBX 4 database differs in the field
 * layout (16-bit vs. 32-bit field sizes, different field IDs) and in the
 * stored parameters (KDBX 4 carries a KDF variant dictionary). This class
 * hides those differences behind a version-dispatched interface; all state is
 * kept in the @c Database that the header describes.
 *
 * All operations are static: the class carries no per-instance state.
 */
class LIBKEEPASS_API KdbxHeader final {
public:
  /// First magic value identifying a KDBX database.
  static constexpr uint32_t kSignature0 = 0x9aa2d903;
  /// Second magic value identifying a KDBX database.
  static constexpr uint32_t kSignature1 = 0xb54bfb67;

  /// Mask selecting the critical (major) part of the version field.
  static constexpr uint32_t kVersionCriticalMask = 0xffff0000;
  /// KDBX 3 critical version.
  static constexpr uint32_t kVersion3 = 0x00030000;
  /// KDBX 4 critical version.
  static constexpr uint32_t kVersion4 = 0x00040000;

  /// Reads the file signatures and version prefix of a KDBX database.
  /**
   * Verifies the two magic values and returns the raw version field of the
   * database. The caller dispatches on the critical version bits.
   *
   * @param src The input stream positioned at the start of the database.
   * @return The version field (e.g. 0x00040001 for KDBX 4.1).
   * @throws FormatError If the stream does not start with a KDBX signature.
   */
  static uint32_t ReadVersion(std::istream& src);

  /// Returns whether @a version denotes a KDBX 4 database.
  static bool IsKdbx4(uint32_t version) { return (version & kVersionCriticalMask) == kVersion4; }

  /// Parses the KDBX 3 outer header fields into @a db.
  /**
   * Reads and validates every header field of a KDBX 3 database and populates
   * the corresponding settings (cipher, compression, seeds, init vector, inner
   * random stream) on @a db.
   *
   * @param src The input stream positioned after the signature/version prefix.
   * @param db The database to populate with the parsed header settings.
   * @return The 32 content stream start bytes used to verify the decryption.
   * @throws FormatError If a header field is malformed or unknown.
   */
  static std::array<uint8_t, 32> Parse3(std::istream& src, Database& db);

  /// Parses the KDBX 4 outer header fields into @a db.
  /**
   * Reads and validates every header field of a KDBX 4 database, including the
   * KDF variant dictionary, and populates the corresponding settings on @a db.
   *
   * @param src The input stream positioned after the signature/version prefix.
   * @param db The database to populate with the parsed header settings.
   * @throws FormatError If a header field is malformed or unknown.
   */
  static void Parse4(std::istream& src, Database& db);

  /// Serializes a KDBX 3 outer header.
  /**
   * @param db The database whose settings to serialize.
   * @param content_start_bytes The 32 randomly chosen content stream start
   *        bytes that KdbxFile embeds in the header.
   * @return The raw header bytes (fits a KDBX 3.1 critical version).
   */
  static std::string Write3(const Database& db, const std::array<uint8_t, 32>& content_start_bytes);

  /// Serializes a KDBX 4 (or 4.1) outer header.
  /**
   * @param db The database whose settings to serialize.
   * @param kdbx41 True to write the KDBX 4.1 critical version (0x00040001).
   * @return The raw header bytes, without the trailing hash and HMAC values.
   */
  static std::string Write4(const Database& db, bool kdbx41);
};

} // namespace keepass