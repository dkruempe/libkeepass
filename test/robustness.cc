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

#include <array>
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
#include "libkeepass/binary.hh"
#include "libkeepass/database.hh"
#include "libkeepass/detail/limits.hh"
#include "libkeepass/entry.hh"
#include "libkeepass/exception.hh"
#include "libkeepass/group.hh"
#include "libkeepass/icon.hh"
#include "libkeepass/kdb.hh"
#include "libkeepass/kdbx.hh"
#include "libkeepass/keepass.hh"
#include "libkeepass/key.hh"
#include "libkeepass/metadata.hh"
#include "libkeepass/secure.hh"

using namespace keepass;

namespace {

std::string GetTestPath(const std::string& name) {
  return std::string(PROJECT_ROOT_PATH) + "/data/" + name;
}

std::vector<uint8_t> ReadFileBytes(const std::string& path) {
  std::ifstream file(path, std::ios::binary);
  if (!file.is_open())
    throw std::runtime_error("cannot open test fixture: " + path);
  return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
}

template <typename T> std::string ToBytesLE(T value) {
  std::string out(sizeof(T), '\0');
  for (auto& byte : out) {
    byte = static_cast<char>(value & 0xff);
    value >>= 8;
  }
  return out;
}

// Locates the first occurrence of needle in haystack starting at begin.
std::size_t Find(const std::vector<uint8_t>& haystack, const std::string& needle,
                 std::size_t begin = 0) {
  auto it = std::search(haystack.begin() + static_cast<std::ptrdiff_t>(begin), haystack.end(),
                        needle.begin(), needle.end());
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
  stream.write(reinterpret_cast<const char*>(data.data()),
               static_cast<std::streamsize>(data.size()));
  return importer.Import(stream, args...);
}

constexpr const char* kLimitPassword = "robustness-limit-pw";

std::vector<uint8_t> ToBytes(const std::string& payload) {
  std::vector<uint8_t> bytes;
  bytes.reserve(payload.size());
  bytes.insert(bytes.end(), payload.begin(), payload.end());
  return bytes;
}

// A fresh AES-KDF database (cheap transform rounds keep the round trips fast).
std::shared_ptr<Database> MakeLimitDb(bool compress) {
  auto db = std::make_shared<Database>();
  db->set_cipher(Database::Cipher::kAes);
  db->set_kdf(Database::Kdf::kAes);
  db->set_compress(compress);
  db->set_transform_rounds(8192);
  db->set_root(Database::NewGroup("root"));
  return db;
}

std::array<uint8_t, 16> UuidSeed(uint8_t byte) {
  std::array<uint8_t, 16> out{};
  out.fill(byte);
  return out;
}

std::shared_ptr<Entry> MakeEntry(const std::string& title = "") {
  auto entry = std::make_shared<Entry>();
  entry->set_uuid(UuidSeed(0x42));
  if (!title.empty())
    entry->set_title(protect<secure_string>(secure_string(title), false));
  return entry;
}

std::string SaveToBuffer(const std::shared_ptr<Database>& db, KeePass::Format format) {
  std::stringstream buffer;
  KeePass writer(kLimitPassword);
  writer.SetFormat(format);
  writer.Save(buffer, *db);
  return buffer.str();
}

// With the default budgets a generated hostile database is still valid: only
// the tight limits below must reject it.
void ExpectImportsOk(const std::string& payload) {
  KdbxFile file;
  Key key(kLimitPassword);
  EXPECT_NE(ImportBytes(file, ToBytes(payload), key), nullptr);
}

void ExpectImportThrows(const std::string& payload, const detail::ResourceLimits& limits) {
  KdbxFile file;
  file.set_resource_limits(limits);
  Key key(kLimitPassword);
  EXPECT_THROW(ImportBytes(file, ToBytes(payload), key), FormatError);
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
  const std::vector<uint8_t> truncated(good.begin(),
                                       good.begin() + static_cast<std::ptrdiff_t>(good.size() / 2));
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

// ---------------------------------------------------------------------------
// XML parser resource budgets (src/kdbx_xml_*.cc, detail::ResourceLimits).
//
// Each generated database is first imported with the default budgets (must be
// accepted) and then again with a single budget tightened (must be rejected
// with FormatError).
// ---------------------------------------------------------------------------

TEST(RobustnessTest, KdbxXmlDepthLimit) {
  auto db = MakeLimitDb(false);
  auto parent = db->root();
  for (int i = 0; i < 4; ++i) {
    auto child = Database::NewGroup("g" + std::to_string(i));
    parent->AddGroup(child);
    parent = child;
  }

  const std::string payload = SaveToBuffer(db, KeePass::Format::kKdbx4);
  ExpectImportsOk(payload);

  detail::ResourceLimits limits;
  limits.max_xml_depth = 2;
  ExpectImportThrows(payload, limits);
}

TEST(RobustnessTest, KdbxXmlGroupCountLimit) {
  auto db = MakeLimitDb(false);
  for (int i = 0; i < 4; ++i)
    db->root()->AddGroup(Database::NewGroup("g" + std::to_string(i)));

  const std::string payload = SaveToBuffer(db, KeePass::Format::kKdbx4);
  ExpectImportsOk(payload);

  detail::ResourceLimits limits;
  limits.max_groups = 3;
  ExpectImportThrows(payload, limits);
}

TEST(RobustnessTest, KdbxXmlEntryCountLimit) {
  auto db = MakeLimitDb(false);
  for (int i = 0; i < 3; ++i)
    db->root()->AddEntry(MakeEntry());

  const std::string payload = SaveToBuffer(db, KeePass::Format::kKdbx4);
  ExpectImportsOk(payload);

  detail::ResourceLimits limits;
  limits.max_entries = 2;
  ExpectImportThrows(payload, limits);
}

TEST(RobustnessTest, KdbxXmlHistoryItemLimit) {
  auto db = MakeLimitDb(false);
  auto entry = MakeEntry();
  entry->AddHistoryEntry(MakeEntry());
  entry->AddHistoryEntry(MakeEntry());
  db->root()->AddEntry(entry);

  const std::string payload = SaveToBuffer(db, KeePass::Format::kKdbx4);
  ExpectImportsOk(payload);

  detail::ResourceLimits limits;
  limits.max_history_items = 1;
  ExpectImportThrows(payload, limits);
}

TEST(RobustnessTest, KdbxXmlStringFieldLimit) {
  const std::string big(4096, 'A');

  // Plain (unprotected) value: rejected via the raw size check.
  auto db = MakeLimitDb(false);
  db->root()->AddEntry(MakeEntry(big));
  const std::string payload = SaveToBuffer(db, KeePass::Format::kKdbx4);
  ExpectImportsOk(payload);

  detail::ResourceLimits limits;
  limits.max_string_field_bytes = 1024;
  ExpectImportThrows(payload, limits);

  // Protected value: rejected via the base64-decoded size estimate before the
  // obfuscator even runs.
  auto db_prot = MakeLimitDb(false);
  auto entry = std::make_shared<Entry>();
  entry->set_uuid(UuidSeed(0x43));
  entry->set_title(protect<secure_string>(secure_string(big), true));
  db_prot->root()->AddEntry(entry);
  const std::string payload_prot = SaveToBuffer(db_prot, KeePass::Format::kKdbx4);
  ExpectImportsOk(payload_prot);
  ExpectImportThrows(payload_prot, limits);
}

TEST(RobustnessTest, KdbxXmlCustomIconBytesLimit) {
  auto db = MakeLimitDb(false);
  auto meta = std::make_shared<Metadata>();
  meta->AddIcon(std::make_shared<Icon>(UuidSeed(0x11), std::vector<uint8_t>(4096, 0xee)));
  db->set_meta(meta);

  const std::string payload = SaveToBuffer(db, KeePass::Format::kKdbx4);
  ExpectImportsOk(payload);

  detail::ResourceLimits limits;
  limits.max_binary_bytes = 1024;
  ExpectImportThrows(payload, limits);
}

TEST(RobustnessTest, Kdbx3BinaryPoolBytesLimit) {
  // KDBX 3 stores attachments in the XML Binaries element; the oversized
  // payload must be rejected while parsing <Meta>.
  auto db = MakeLimitDb(false);
  auto meta = std::make_shared<Metadata>();
  auto binary = std::make_shared<Binary>(
      protect<secure_string>(secure_string(std::string(4096, '\x39')), true));
  meta->AddBinary(binary);
  db->set_meta(meta);

  auto entry = MakeEntry();
  auto attachment = std::make_shared<Entry::Attachment>();
  attachment->set_name("data");
  attachment->set_binary(binary);
  entry->AddAttachment(attachment);
  db->root()->AddEntry(entry);

  const std::string payload = SaveToBuffer(db, KeePass::Format::kKdbx3);
  ExpectImportsOk(payload);

  detail::ResourceLimits limits;
  limits.max_binary_bytes = 1024;
  ExpectImportThrows(payload, limits);
}

TEST(RobustnessTest, KdbxGzipBombTotalBytesLimit) {
  // A small compressed member inflates beyond the budget: the gzip stream must
  // stop the XML parse instead of allocating the whole document.
  auto db = MakeLimitDb(true); // compress the content stream
  db->root()->AddEntry(MakeEntry(std::string(65536, 'A')));

  const std::string payload = SaveToBuffer(db, KeePass::Format::kKdbx4);
  ExpectImportsOk(payload);

  detail::ResourceLimits limits;
  limits.max_total_bytes = 4096;
  ExpectImportThrows(payload, limits);
}

TEST(RobustnessTest, Kdbx4HmacBlockSizeLimit) {
  auto db = MakeLimitDb(false);
  db->root()->AddEntry(MakeEntry(std::string(4096, 'A')));

  const std::string payload = SaveToBuffer(db, KeePass::Format::kKdbx4);
  ExpectImportsOk(payload);

  detail::ResourceLimits limits;
  limits.max_block_size = 512;
  ExpectImportThrows(payload, limits);
}

TEST(RobustnessTest, Kdbx4HmacBlockCountLimit) {
  // A payload larger than one 1 MiB block must trip the block-count budget.
  auto db = MakeLimitDb(false);
  db->root()->AddEntry(MakeEntry(std::string(1200000, 'A')));

  const std::string payload = SaveToBuffer(db, KeePass::Format::kKdbx4);
  ExpectImportsOk(payload);

  detail::ResourceLimits limits;
  limits.max_block_count = 1;
  ExpectImportThrows(payload, limits);
}
