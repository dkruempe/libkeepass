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
 * @file constant_time.hh
 * @brief Constant-time byte comparisons for secrets and integrity values.
 */

#pragma once
#include <array>
#include <cstddef>
#include <cstdint>

#include <openssl/crypto.h>

namespace keepass {
namespace detail {

/// Compares two byte ranges in constant time.
/**
 * The comparison time does not depend on the content bytes: every pair of
 * bytes is always visited, so an early-exit on the first differing byte
 * cannot leak which position differs. The lengths are treated as public, so
 * mismatched lengths return false immediately. It is safe to compare secrets
 * (keys, derived keys) and integrity values (hashes, HMACs) with this helper.
 *
 * @param a First byte range.
 * @param a_size Size of the first byte range.
 * @param b Second byte range.
 * @param b_size Size of the second byte range.
 * @return Whether both ranges are identical.
 */
inline bool constant_time_eq(const void* a, std::size_t a_size, const void* b,
                             std::size_t b_size) noexcept {
  if (a_size != b_size)
    return false;
  if (a_size == 0)
    return true;
  return CRYPTO_memcmp(a, b, a_size) == 0;
}

/// Compares two fixed-size byte arrays in constant time.
/**
 * @param a First array.
 * @param b Second array.
 * @return Whether both arrays hold identical bytes.
 */
template <std::size_t N>
inline bool constant_time_eq(const std::array<uint8_t, N>& a,
                             const std::array<uint8_t, N>& b) noexcept {
  return constant_time_eq(a.data(), N, b.data(), N);
}

} // namespace detail
} // namespace keepass