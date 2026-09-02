/*
 * libkeepass - KeePass key database importer/exporter
 * Copyright (C) 2014 Christian Kindahl
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

namespace keepass {

// Returns true if this CPU supports AES-NI hardware instructions.
bool aes_ni_supported();

// AES-KDF core loop using AES-NI intrinsics. This is the hardware-accelerated
// equivalent of the EVP loop in Key::Transform. The caller is responsible for
// the final SHA-256 hash of the result.
//
// seed:  32-byte AES-256 key (KDBX transform seed)
// in:    32-byte composite key to encrypt
// rounds: iteration count (KDBX transform rounds)
// out:   32-byte buffer receiving the encrypted result
void aes_ni_transform_aes_kdf(const uint8_t seed[32], const uint8_t in[32],
                              uint64_t rounds, uint8_t out[32]);

} // namespace keepass
