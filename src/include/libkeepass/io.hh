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

/** @file io.hh
 *  @brief Low-level binary reading and writing helpers. */

#pragma once
#include <istream>
#include <memory>
#include <ostream>
#include <string>
#include <vector>

#include "exception.hh"
#include "libkeepass/export.hh"

namespace keepass {

/**
 * @brief Reads and returns a value of type T from the stream.
 *
 * @tparam T the type to read (POD by default, specialized for @c std::string
 *         and byte vectors).
 * @param src the input stream to read from.
 * @return the value read from the stream.
 * @throws IoError if the stream cannot be read.
 */
template <typename T> inline T consume(std::istream &src) {
  T val;
  src.read(reinterpret_cast<char *>(&val), sizeof(T));
  if (!src.good())
    throw IoError("Read error.");

  return val;
}

/// Reads a length-prefixed string from the stream.
template <> LIBKEEPASS_API std::string consume<std::string>(std::istream &src);

/// Reads a length-prefixed char vector from the stream.
template <>
LIBKEEPASS_API std::vector<char> consume<std::vector<char>>(std::istream &src);

/// Reads a length-prefixed byte vector from the stream.
template <>
LIBKEEPASS_API std::vector<uint8_t> consume<std::vector<uint8_t>>(std::istream &src);

/**
 * @brief Writes a value of type T to the stream.
 *
 * @tparam T the type to write (POD by default, specialized for @c std::string
 *         and byte vectors).
 * @param dst the output stream to write to.
 * @param val the value to write.
 */
template <typename T> void conserve(std::ostream &dst, const T &val) {
  dst.write(reinterpret_cast<const char *>(&val), sizeof(T));
}

/// Writes a length-prefixed string to the stream.
template <>
LIBKEEPASS_API void conserve<std::string>(std::ostream &dst,
                                          const std::string &val);

/// Writes a length-prefixed char vector to the stream.
template <>
LIBKEEPASS_API void conserve<std::vector<char>>(std::ostream &dst,
                                                const std::vector<char> &val);

/// Writes a length-prefixed byte vector to the stream.
template <>
LIBKEEPASS_API void conserve<std::vector<uint8_t>>(
    std::ostream &dst, const std::vector<uint8_t> &val);

} // namespace keepass
