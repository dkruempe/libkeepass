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

#include <cstdint>
#include <cstring>
#include <fstream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "config.hh"
#include "libkeepass/database.hh"
#include "libkeepass/exception.hh"
#include "libkeepass/kdb.hh"
#include "libkeepass/kdbx.hh"
#include "libkeepass/key.hh"

using namespace keepass;

namespace {

std::string GetTestPath(const std::string& name) {
  return std::string(PROJECT_ROOT_PATH) + "/data/" + name;
}

std::vector<uint8_t> ReadFileBytes(const std::string& path) {
  std::ifstream file(path, std::ios::binary);
  if (!file.is_open())
    throw std::runtime_error("cannot open test fixture: " + path);
  return std::vector<uint8_t>(std::istreambuf_iterator<char>(file),
                              std::istreambuf_iterator<char>());
}

template <typename T> std::string ToBytesLE(T value) {
  std::string out(sizeof(T), '\0');
  for (std::size_t i = 0; i < out.size(); ++i) {
    out[i] = static_cast<char>(value & 0xff);
    value >>= 8;
  }
  return out;
}

// Locates the first occurrence of needle in haystack starting at begin.
std::size_t Find(const std::vector<uint8_t>& haystack, const std::string& needle,
                 std::size_t begin = 0) {
  auto it = std::search(haystack.begin() + begin, haystack.end(), needle.begin(), needle.end());
  if (it == haystack.end())
    throw std::runtime_error("pattern not found in fixture: " + needle);
  return static_cast<std::size_t>(it - haystack.begin());
}

std::vector<uint8_t> Patch(const std::vector<uint8_t>& data, std::size_t offset,
                           const std::string& bytes) {
  std::vector<uint8_t> out = data;
  if (offset + bytes.size() > out.size())
    throw std::runtime_error("patch out of range");
  std::memcpy(out.data() + offset, bytes.data(), bytes.size());
  return out;
}

template <typename Importer, typename... Args>
std::unique_ptr<Database> ImportBytes(Importer& importer, const std::vector<uint8_t>& data,
                                      const Args&... args) {
  std::stringstream stream(std::ios::in | std::ios::out | std::ios::binary);
  stream.write(reinterpret_cast<const char*>(data.data()), data.size());
  return importer.Import(stream, args...);
}

} // namespace

TEST(RobustnessTest, Kdbx4OversizedHeaderField) {
  // A KDBX 4 outer header field size is attacker-controlled; an oversized
  // value used to allocate up to 4 GiB before the header HMAC is verified.
  KdbxFile file;
  Key key("password");

  const std::vector<uint8_t> good = ReadFileBytes(GetTestPath("kdbx4/kdbx4-chacha20-aeskdf.kdbx"));
  EXPECT_NE(ImportBytes(file, good, key), nullptr);

  // MasterSeed field (id 4) is stored at offset 42, with its size at 43.
  const std::vector<uint8_t> bad =
      Patch(good, 43, ToBytesLE<uint32_t>(0x00f00000)); // 15 MiB, far beyond any header.
  EXPECT_THROW(ImportBytes(file, bad, key), FormatError);
}

TEST(RobustnessTest, Kdbx4OversizedVariantDictionaryValue) {
  // The KDF parameter dictionary is parsed from the unauthenticated outer
  // header; a bogus value length used to allocate/loop over gigabyte amounts.
  KdbxFile file;
  Key key("password");

  const std::vector<uint8_t> good = ReadFileBytes(GetTestPath("kdbx4/kdbx4-chacha20-aeskdf.kdbx"));

  // Inside the KDF field (id 11, data at 101), the byte-array seed "S" is
  // stored as type/key_len/'S'/value_len; its 32-byte length lives at the last
  // four bytes of the "S\x20\x00\x00\x00" pattern.
  const std::size_t s_len = Find(good, std::string("\x53\x20\x00\x00\x00", 5), 101);
  const std::vector<uint8_t> bad = Patch(good, s_len + 1, ToBytesLE<uint32_t>(0x80000000));
  EXPECT_THROW(ImportBytes(file, bad, key), FormatError);
}

TEST(RobustnessTest, Kdbx4AesKdfRoundsTooLarge) {
  // The AES-KDF round count "R" is unauthenticated but drives an O(rounds)
  // hot loop; huge values must be rejected instead of burning CPU.
  KdbxFile file;
  Key key("password");

  const std::vector<uint8_t> good = ReadFileBytes(GetTestPath("kdbx4/kdbx4-chacha20-aeskdf.kdbx"));

  // "R" is an 8-byte uint64; its value follows the "R\x08\x00\x00\x00" pattern.
  const std::size_t r_value = Find(good, std::string("\x52\x08\x00\x00\x00", 5), 101) + 5;
  const std::vector<uint8_t> bad = Patch(good, r_value, ToBytesLE<uint64_t>(1ULL << 31));
  EXPECT_THROW(ImportBytes(file, bad, key), FormatError);
}

TEST(RobustnessTest, Kdbx4TruncatedCiphertext) {
  // Truncating a valid database in the middle of the HMAC-protected ciphertext
  // must fail cleanly (block checksum/read error) rather than loop or leak.
  KdbxFile file;
  Key key("password");

  const std::vector<uint8_t> good = ReadFileBytes(GetTestPath("kdbx4/kdbx4-chacha20-aeskdf.kdbx"));
  const std::vector<uint8_t> truncated(good.begin(), good.begin() + good.size() / 2);
  EXPECT_THROW(ImportBytes(file, truncated, key), std::exception);
}

TEST(RobustnessTest, Kdbx3OversizedHeaderField) {
  // Same checks apply to the version-3 outer header, whose sizes are uint16.
  KdbxFile file;
  Key key("password");

  const std::vector<uint8_t> good = ReadFileBytes(GetTestPath("kdbx/groups-1-empty-pw-aes.kdbx"));
  EXPECT_NE(ImportBytes(file, good, key), nullptr);

  // MasterSeed field (id 4, uint16 size) is the first "04 20 00" sequence.
  const std::size_t size_off = Find(good, std::string("\x04\x20\x00", 3)) + 1;
  const std::vector<uint8_t> bad = Patch(good, size_off, std::string("\xff\xff", 2));
  EXPECT_THROW(ImportBytes(file, bad, key), FormatError);
}

TEST(RobustnessTest, KdbTransformRoundsTooLarge) {
  // The KDB (version 1) header stores its AES transform round count directly
  // at a fixed offset; a huge value used to stall the importer in the AES-KDF.
  KdbFile file;
  Key key("password");

  const std::vector<uint8_t> good = ReadFileBytes(GetTestPath("kdb/groups-1-empty-pw-aes.kdb"));
  EXPECT_NE(ImportBytes(file, good, key), nullptr);

  // Transform rounds live at byte 120 of the 124-byte header.
  const std::vector<uint8_t> bad = Patch(good, 120, ToBytesLE<uint32_t>(0x80000000));
  EXPECT_THROW(ImportBytes(file, bad, key), FormatError);
}