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

// libFuzzer target exercising the key-file parsers (XML v1/v2, hexadecimal
// and raw 32-byte key files, both from memory and from a stream).

#include <cstddef>
#include <cstdint>
#include <sstream>
#include <vector>

#include "libkeepass/key.hh"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, std::size_t size) {
  // Keep per-iteration runtime bounded; larger inputs are rejected by the
  // parser anyway, but never let the fuzzer allocate an enormous buffer.
  if (size > 2 * 1024 * 1024)
    return 0;

  const std::vector<uint8_t> bytes(data, data + size);
  try {
    (void)keepass::Key::FromBytes("password", bytes);
  } catch (...) {
    // Arbitrary bytes are expected to be rejected.
  }

  std::stringstream stream(std::string(reinterpret_cast<const char*>(data), size));
  try {
    (void)keepass::Key::FromStream("password", stream);
  } catch (...) {
    // Arbitrary bytes are expected to be rejected.
  }

  return 0;
}
