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
 * @file constants.hh
 * @brief On-disk signatures, version numbers, cipher/KDF UUIDs and framing
 *        limits shared by the KDB and KDBX codecs.
 */

#pragma once
#include <array>
#include <cstdint>

namespace keepass {
namespace detail {

// ---------------------------------------------------------------------------
// Signatures and versions
// ---------------------------------------------------------------------------

/// First signature word shared by KDB and KDBX.
constexpr uint32_t kKdbSignature0 = 0x9aa2d903;
/// Second signature word identifying a legacy KDB database.
constexpr uint32_t kKdbSignature1 = 0xb54bfb65;
/// First signature word of a KDBX database (same as KDB).
constexpr uint32_t kKdbxSignature0 = 0x9aa2d903;
/// Second signature word identifying a KDBX database.
constexpr uint32_t kKdbxSignature1 = 0xb54bfb67;

/// Lowest KDBX 3 version accepted/written.
constexpr uint32_t kKdbxVersion3 = 0x00030000;
/// Lowest KDBX 3 critical version (3.1).
constexpr uint32_t kKdbxVersionCriticalMin = 0x00030001;
/// KDBX 4.0 critical version.
constexpr uint32_t kKdbxVersion4 = 0x00040000;
/// KDBX 4.1 critical version.
constexpr uint32_t kKdbxVersion4_1 = 0x00040001;
/// Mask selecting the critical (major) part of a KDBX version field.
constexpr uint32_t kKdbxVersionCriticalMask = 0xffff0000;

// ---------------------------------------------------------------------------
// Cipher UUIDs (KDBX header)
// ---------------------------------------------------------------------------

constexpr std::array<uint8_t, 16> kKdbxCipherAes = {{0x31, 0xc1, 0xf2, 0xe6, 0xbf, 0x71, 0x43, 0x50,
                                                     0xbe, 0x58, 0x05, 0x21, 0x6a, 0xfc, 0x5a,
                                                     0xff}};
constexpr std::array<uint8_t, 16> kKdbxCipherChaCha20 = {{0xd6, 0x03, 0x8a, 0x2b, 0x8b, 0x6f, 0x4c,
                                                          0xb5, 0xa5, 0x24, 0x33, 0x9a, 0x31, 0xdb,
                                                          0xb5, 0x9a}};
constexpr std::array<uint8_t, 16> kKdbxCipherTwofish = {{0xad, 0x68, 0xf2, 0x9f, 0x57, 0x6f, 0x4b,
                                                         0xb9, 0xa3, 0x6a, 0xd4, 0x7a, 0xf9, 0x65,
                                                         0x34, 0x6c}};

// ---------------------------------------------------------------------------
// KDF UUIDs (KDBX 4 variant dictionary)
// ---------------------------------------------------------------------------

constexpr std::array<uint8_t, 16> kKdbxKdfAesKdbx4 = {{0x7c, 0x02, 0xbb, 0x82, 0x79, 0xa7, 0x4a,
                                                       0xc0, 0x92, 0x7d, 0x11, 0x4a, 0x00, 0x64,
                                                       0x82, 0x38}};
constexpr std::array<uint8_t, 16> kKdbxKdfAesKdbx3 = {{0xc9, 0xd9, 0xf3, 0x9a, 0x62, 0x8a, 0x44,
                                                       0x60, 0xbf, 0x74, 0x0d, 0x08, 0xc1, 0x8a,
                                                       0x4f, 0xea}};
constexpr std::array<uint8_t, 16> kKdbxKdfArgon2d = {{0xef, 0x63, 0x6d, 0xdf, 0x8c, 0x29, 0x44,
                                                      0x4b, 0x91, 0xf7, 0xa9, 0xa4, 0x03, 0xe3,
                                                      0x0a, 0x0c}};
constexpr std::array<uint8_t, 16> kKdbxKdfArgon2id = {{0x9e, 0x29, 0x8b, 0x19, 0x56, 0xdb, 0x47,
                                                       0x73, 0xb2, 0x3d, 0xfc, 0x3e, 0xc6, 0xf0,
                                                       0xa1, 0xe6}};

// ---------------------------------------------------------------------------
// Framing constants
// ---------------------------------------------------------------------------

/// Fixed Salsa20 IV used by the KDBX inner random stream.
constexpr std::array<uint8_t, 8> kKdbxInnerRandomStreamInitVec = {
    {0xe8, 0x30, 0x09, 0x4b, 0x97, 0x20, 0x5d, 0x2a}};

/// Upper bound for a single outer KDBX header field (1 MiB).
constexpr uint32_t kMaxOuterHeaderFieldSize = 1U << 20;

} // namespace detail
} // namespace keepass
