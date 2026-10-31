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
 * @file kdbx_internal.hh
 * @brief Internal KDBX on-disk framing types shared by the KDBX codec
 *        translation units (import and export).
 */

#pragma once
#include <array>
#include <cstdint>

#include "libkeepass/detail/constants.hh"
#include "libkeepass/kdbx.hh"

/// OpenSSL's HMAC takes the data length as size_t on POSIX but as int on MSVC.
#ifdef _MSC_VER
#define KEEPASS_HMAC_DATA_LEN(x) static_cast<int>(x)
#else
#define KEEPASS_HMAC_DATA_LEN(x) (x)
#endif

namespace keepass {

using detail::kKdbxInnerRandomStreamInitVec;

enum class kKdbxInnerHeader : uint8_t {
  kEnd = 0,
  kInnerRandomStreamId = 1,
  kInnerRandomStreamKey = 2,
  kBinaries = 3
};

/// Private state kept out of the public header so the ABI does not depend on
/// KdbxXml (and through it pugixml).
struct KdbxFile::Impl {
  /** Force KDBX 4 output even if the database could be written as KDBX 3. */
  bool write_kdbx4 = false;

  /** Reuse a transformed key cached on the Database instead of deriving it. */
  bool use_cached_key = true;

  /** KDBX XML body serializer/deserializer holding all per-operation state. */
  KdbxXml xml;
};

} // namespace keepass