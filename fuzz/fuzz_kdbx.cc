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

// libFuzzer target exercising the KDBX import path (KdbxFile::Import).
// Intended for local builds (LIBKEEPASS_BUILD_FUZZING) and OSS-Fuzz.
// Seed the corpus with real .kdbx databases (test/data/kdbx4/*.kdbx).

#include <cstddef>
#include <cstdint>
#include <sstream>
#include <string>

#include "libkeepass/kdbx.hh"
#include "libkeepass/key.hh"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, std::size_t size) {
  // Cap the input size to keep per-iteration runtime bounded.
  if (size > 1 * 1024 * 1024)
    return 0;

  std::stringstream input(std::string(reinterpret_cast<const char*>(data), size));

  keepass::KdbxFile file;
  keepass::Key key("password");
  try {
    (void)file.Import(input, key);
  } catch (...) {
    // Arbitrary bytes are expected to fail parsing.
  }
  return 0;
}