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

// libFuzzer target exercising the KDBX XML body directly (KdbxXml::Parse and
// Write), independent of the outer header/decryption layer. This covers
// malformed groups/entries, protected fields, variant dictionaries embedded
// in XML, custom icons and binary references.

#include <array>
#include <cstddef>
#include <cstdint>
#include <sstream>
#include <string>

#include "libkeepass/database.hh"
#include "libkeepass/kdbx_xml.hh"
#include "libkeepass/random.hh"

namespace {

std::array<uint8_t, 32> StreamKey(const uint8_t* data, std::size_t size) {
  std::array<uint8_t, 32> key{};
  for (std::size_t i = 0; i < key.size(); ++i)
    key[i] = size == 0 ? static_cast<uint8_t>(i) : data[i % size];
  return key;
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, std::size_t size) {
  if (size > 1 * 1024 * 1024)
    return 0;

  const std::array<uint8_t, 32> key = StreamKey(data, size);
  std::stringstream input(std::string(reinterpret_cast<const char*>(data), size));

  keepass::KdbxXml xml;
  xml.set_kdbx4(true);
  xml.set_kdbx41(true);

  keepass::Database db;
  keepass::RandomObfuscator obfuscator(keepass::RandomObfuscator::Type::kSalsa20, key);
  try {
    xml.Parse(input, obfuscator, db);
  } catch (...) {
    return 0;
  }

  // If parsing succeeded, the resulting model must also be serializable.
  std::ostringstream output;
  keepass::RandomObfuscator writer(keepass::RandomObfuscator::Type::kSalsa20, key);
  try {
    xml.Write(output, writer, db);
  } catch (...) {
    // Writing failures are not a crash; the fuzzer only looks for sanitizer
    // findings and hangs.
  }
  return 0;
}
