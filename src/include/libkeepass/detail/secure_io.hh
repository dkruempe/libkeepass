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
 * @file secure_io.hh
 * @brief Sensitive-data wiping helpers.
 */

#pragma once
#include <cstddef>
#include <sstream>

#include "libkeepass/secure.hh"

namespace keepass {
namespace detail {

/// Zeroizes the buffered content of a stringstream in place, so that decrypted
/// plaintext or transient header material does not linger in the heap after
/// parsing or encrypting.
inline void WipeStream(std::stringstream& stream) {
  std::streambuf* buffer = stream.rdbuf();
  std::streamsize size =
      buffer->pubseekoff(0, std::ios_base::end, std::ios_base::in | std::ios_base::out);
  buffer->pubseekoff(0, std::ios_base::beg, std::ios_base::in | std::ios_base::out);

  static constexpr std::streamsize kChunkSize = 4096;
  char zeros[kChunkSize] = {};
  while (size > 0) {
    std::streamsize chunk = size < kChunkSize ? size : kChunkSize;
    if (buffer->sputn(zeros, chunk) != chunk)
      return;
    size -= chunk;
  }
}

/// Zeroizes the contents of a contiguous container (std::string, std::string
/// view or std::vector<char/uint8_t>) in place. std::string::data() returns a
/// const pointer in C++11, so cast it away for the wipe; writing zeros never
/// invalidates the container invariants.
template <typename Container> inline void WipeBuffer(Container* buffer) {
  if (buffer != nullptr && !buffer->empty()) {
    secure_zero(const_cast<typename Container::value_type*>(buffer->data()),
                buffer->size() * sizeof(typename Container::value_type));
  }
}

} // namespace detail
} // namespace keepass