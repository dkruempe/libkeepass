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

/// OpenSSL's HMAC takes the data length as size_t on POSIX but as int on MSVC.
#ifdef _MSC_VER
#define KEEPASS_HMAC_DATA_LEN(x) static_cast<int>(x)
#else
#define KEEPASS_HMAC_DATA_LEN(x) (x)
#endif

namespace keepass {

constexpr std::array<uint8_t, 8> kKdbxInnerRandomStreamInitVec = {0xe8, 0x30, 0x09, 0x4b,
                                                                  0x97, 0x20, 0x5d, 0x2a};

enum class kKdbxInnerHeader : uint8_t {
  kEnd = 0,
  kInnerRandomStreamId = 1,
  kInnerRandomStreamKey = 2,
  kBinaries = 3
};

} // namespace keepass