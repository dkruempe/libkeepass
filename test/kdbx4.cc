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

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <sstream>

#include <gtest/gtest.h>
#include <openssl/evp.h>

#include "config.hh"
#include "libkeepass/aes_ni.hh"
#include "libkeepass/binary.hh"
#include "libkeepass/database.hh"
#include "libkeepass/entry.hh"
#include "libkeepass/exception.hh"
#include "libkeepass/group.hh"
#include "libkeepass/kdbx.hh"
#include "libkeepass/key.hh"
#include "libkeepass/metadata.hh"
#include "libkeepass/temporal.hh"

using namespace keepass;

namespace {

constexpr std::array<uint8_t, 16> kCipherAes = {
    {0x31, 0xc1, 0xf2, 0xe6, 0xbf, 0x71, 0x43, 0x50, 0xbe, 0x58, 0x05, 0x21,
     0x6a, 0xfc, 0x5a, 0xff}};
constexpr std::array<uint8_t, 16> kCipherChaCha20 = {
    {0xd6, 0x03, 0x8a, 0x2b, 0x8b, 0x6f, 0x4c, 0xb5, 0xa5, 0x24, 0x33, 0x9a,
     0x31, 0xdb, 0xb5, 0x9a}};
constexpr std::array<uint8_t, 16> kCipherTwofish = {
    {0xad, 0x68, 0xf2, 0x9f, 0x57, 0x6f, 0x4b, 0xb9, 0xa3, 0x6a, 0xd4, 0x7a,
     0xf9, 0x65, 0x34, 0x6c}};

constexpr std::array<uint8_t, 16> kKdfAesKdbx4 = {
    {0x7c, 0x02, 0xbb, 0x82, 0x79, 0xa7, 0x4a, 0xc0, 0x92, 0x7d, 0x11, 0x4a,
     0x00, 0x64, 0x82, 0x38}};
constexpr std::array<uint8_t, 16> kKdfAesKdbx3 = {
    {0xc9, 0xd9, 0xf3, 0x9a, 0x62, 0x8a, 0x44, 0x60, 0xbf, 0x74, 0x0d, 0x08,
     0xc1, 0x8a, 0x4f, 0xea}};
constexpr std::array<uint8_t, 16> kKdfArgon2d = {
    {0xef, 0x63, 0x6d, 0xdf, 0x8c, 0x29, 0x44, 0x4b, 0x91, 0xf7, 0xa9, 0xa4,
     0x03, 0xe3, 0x0a, 0x0c}};
constexpr std::array<uint8_t, 16> kKdfArgon2id = {
    {0x9e, 0x29, 0x8b, 0x19, 0x56, 0xdb, 0x47, 0x73, 0xb2, 0x3d, 0xfc, 0x3e,
     0xc6, 0xf0, 0xa1, 0xe6}};

constexpr uint32_t kKdbxSignature0 = 0x9aa2d903;
constexpr uint32_t kKdbxSignature1 = 0xb54bfb67;
constexpr uint32_t kKdbxVersion4 = 0x00040000;
constexpr uint32_t kKdbxVersionCriticalMask = 0xffff0000;

std::string GetTestPath(const std::string &name) {
  return std::string(PROJECT_ROOT_PATH) + "/data/kdbx4/" + name;
}

std::string GetKdbx3DataPath(const std::string &name) {
  return std::string(PROJECT_ROOT_PATH) + "/data/kdbx/" + name;
}

std::string GetTmpPath(const std::string &name) {
  return std::string(PROJECT_ROOT_PATH) + "/tmp/" + name;
}

std::string GetTestJson(const std::string &name) {
  std::ifstream file(GetTestPath(name));
  std::string file_str((std::istreambuf_iterator<char>(file)),
                       std::istreambuf_iterator<char>());

  // Compact the JSON by removing all white space not present in string
  // literals.
  char quote = '\0';
  std::string json;
  for (char c : file_str) {
    if (quote != '\0') {
      if (c == quote)
        quote = '\0';

      json.push_back(c);
    } else if (c == '"' || c == '\'') {
      quote = c;
      json.push_back(c);
    } else if (!std::isspace<char>(c, std::locale::classic())) {
      json.push_back(c);
    }
  }

  return json;
}

std::string ReadFile(const std::string &path) {
  std::ifstream file(path, std::ios::in | std::ios::binary);
  return std::string((std::istreambuf_iterator<char>(file)),
                     std::istreambuf_iterator<char>());
}

void WriteFile(const std::string &path, const std::string &data) {
  std::ofstream file(path, std::ios::out | std::ios::binary);
  file.write(data.data(), static_cast<std::streamsize>(data.size()));
}

uint32_t ReadU32(const char *p) {
  uint32_t v = 0;
  for (int i = 0; i < 4; ++i)
    v |= static_cast<uint32_t>(static_cast<uint8_t>(p[i])) << (8 * i);
  return v;
}

uint16_t ReadU16(const char *p) {
  uint16_t v = 0;
  for (int i = 0; i < 2; ++i)
    v |= static_cast<uint16_t>(static_cast<uint8_t>(p[i])) << (8 * i);
  return v;
}

struct HeaderInfo {
  uint32_t version = 0;
  uint32_t compression = 0;
  bool cipher_seen = false;
  std::array<uint8_t, 16> cipher = {{0}};
  bool kdf_seen = false;
  std::array<uint8_t, 16> kdf = {{0}};
};

// Parses the KDBX 4 header fields (cipher, compression, KDF $UUID) from a
// serialized file without decrypting anything.
HeaderInfo ReadHeader(const std::string &data) {
  HeaderInfo info;
  if (data.size() < 12)
    return info;

  info.version = ReadU32(data.data() + 8);

  size_t off = 12;
  while (off + 5 <= data.size()) {
    const uint8_t id = static_cast<uint8_t>(data[off]);
    const uint32_t size = ReadU32(data.data() + off + 1);
    off += 5;
    if (size > data.size() - off)
      break;

    const std::string value(data.data() + off, size);
    off += size;

    if (id == 2 && size == 16) {
      std::copy(value.begin(), value.end(), info.cipher.begin());
      info.cipher_seen = true;
    } else if (id == 3 && size == 4) {
      info.compression = ReadU32(value.data());
    } else if (id == 11) {
      // Variant dictionary, extract the $UUID entry.
      size_t i = 2;
      while (i + 1 <= value.size()) {
        const uint8_t type = static_cast<uint8_t>(value[i]);
        i += 1;
        if (type == 0)
          break;
        if (i + 4 > value.size())
          break;
        const uint32_t name_len = ReadU32(value.data() + i);
        i += 4;
        if (name_len > value.size() - i)
          break;
        const std::string name = value.substr(i, name_len);
        i += name_len;
        if (i + 4 > value.size())
          break;
        const uint32_t value_len = ReadU32(value.data() + i);
        i += 4;
        if (value_len > value.size() - i)
          break;
        if (name == "$UUID" && value_len == 16) {
          std::copy(value.data() + i, value.data() + i + 16,
                    info.kdf.begin());
          info.kdf_seen = true;
        }
        i += value_len;
      }
    } else if (id == 0) {
      break;
    }
  }

  return info;
}

void ConserveU32(std::ostream &dst, uint32_t value) {
  dst.write(reinterpret_cast<const char *>(&value), 4);
}

// Builds a syntactically valid KDBX 4 header (no content) with the given
// content cipher UUID and KDF variant dictionary.
std::string MakeKdbx4Header(const std::array<uint8_t, 16> &cipher,
                            const std::array<uint8_t, 16> &kdf) {
  std::stringstream ss;

  ConserveU32(ss, kKdbxSignature0);
  ConserveU32(ss, kKdbxSignature1);
  ConserveU32(ss, kKdbxVersion4);

  // Cipher ID.
  uint8_t id = 2;
  uint32_t size = 16;
  ss.put(static_cast<char>(id));
  ConserveU32(ss, size);
  ss.write(reinterpret_cast<const char *>(cipher.data()), cipher.size());

  // Compression: none.
  id = 3;
  size = 4;
  ss.put(static_cast<char>(id));
  ConserveU32(ss, size);
  ConserveU32(ss, 0);

  // Master seed (16 bytes).
  id = 4;
  size = 16;
  ss.put(static_cast<char>(id));
  ConserveU32(ss, size);
  for (int i = 0; i < 16; ++i)
    ss.put(static_cast<char>(0xab));

  // KDF parameters: version 0x0100, $UUID byte array, terminator.
  std::stringstream kdf_ss;
  uint16_t dict_version = 0x0100;
  kdf_ss.write(reinterpret_cast<const char *>(&dict_version), 2);
  uint8_t entry_type = 0x42;
  const char *uuid_name = "$UUID";
  uint32_t uuid_name_len = 5;
  uint32_t uuid_len = 16;
  kdf_ss.put(static_cast<char>(entry_type));
  ConserveU32(kdf_ss, uuid_name_len);
  kdf_ss.write(uuid_name, uuid_name_len);
  ConserveU32(kdf_ss, uuid_len);
  kdf_ss.write(reinterpret_cast<const char *>(kdf.data()), kdf.size());
  kdf_ss.put(static_cast<char>(0)); // Terminator.

  id = 11;
  size = static_cast<uint32_t>(kdf_ss.str().size());
  ss.put(static_cast<char>(id));
  ConserveU32(ss, size);
  ss << kdf_ss.str();

  // End of header.
  id = 0;
  size = 0;
  ss.put(static_cast<char>(id));
  ConserveU32(ss, size);

  return ss.str();
}

// Asserts that two databases contain identical structures, both via the
// strong equality operator and via the serialized JSON representation.
void ExpectSameDatabase(const Database &a, const Database &b) {
  EXPECT_TRUE(*a.root() == *b.root());
  EXPECT_EQ(a.root()->ToJson(), b.root()->ToJson());
}

// Builds a small deterministic database for programmatic export tests.
std::unique_ptr<Database> MakeDatabase(Database::Cipher cipher,
                                       Database::Kdf kdf, bool compress) {
  std::unique_ptr<Database> db(new Database());

  std::array<uint8_t, 16> master_seed = {
      {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
       0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}};
  db->set_master_seed(master_seed);

  std::array<uint8_t, 16> init_vector = {
      {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
       0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20}};
  db->set_init_vector(init_vector);

  db->set_cipher(cipher);
  db->set_kdf(kdf);
  db->set_compress(compress);

  if (kdf == Database::Kdf::kAes) {
    std::array<uint8_t, 32> transform_seed = {
        {0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
         0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
         0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
         0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40}};
    db->set_transform_seed(transform_seed);
    db->set_transform_rounds(8192);
  } else {
    db->set_argon2_salt(std::vector<uint8_t>(16, 0x42));
    db->set_argon2_iterations(2);
    db->set_argon2_memory(2 * 1024 * 1024);
    db->set_argon2_parallelism(1);
    db->set_argon2_version(0x13);
  }

  auto root = std::make_shared<Group>();
  root->set_name("Root");
  root->set_icon(48);
  root->set_creation_time(1700000000);
  root->set_modification_time(1700000001);
  root->set_access_time(1700000002);
  root->set_expiry_time(1700000003);
  root->set_move_time(1700000004);

  auto entry = std::make_shared<Entry>();
  entry->set_title(protect<std::string>("TestEntry", false));
  entry->set_url(protect<std::string>("https://example.com", false));
  entry->set_username(protect<std::string>("user", false));
  entry->set_password(protect<std::string>("secret", true));
  entry->set_notes(protect<std::string>("notes", false));
  entry->set_icon(0);
  entry->set_creation_time(1700000100);
  entry->set_modification_time(1700000101);
  entry->set_access_time(1700000102);
  entry->set_expiry_time(1700000103);
  root->AddEntry(entry);

  auto subgroup = std::make_shared<Group>();
  subgroup->set_name("Subgroup");
  subgroup->set_creation_time(1700000200);

  auto sub_entry = std::make_shared<Entry>();
  sub_entry->set_title(protect<std::string>("SubEntry", false));
  sub_entry->set_password(protect<std::string>("subsecret", true));
  sub_entry->set_creation_time(1700000300);
  subgroup->AddEntry(sub_entry);

  root->AddGroup(subgroup);

  db->set_root(root);

  auto meta = std::make_shared<Metadata>();
  meta->set_generator("libkeepass-test");
  meta->set_database_name(temporal<std::string>("TestDB", 1700000000));
  meta->set_database_desc(temporal<std::string>("Roundtrip test", 1700000000));
  meta->set_master_key_changed(1700000000);
  db->set_meta(meta);

  return db;
}

const char *CipherName(Database::Cipher cipher) {
  switch (cipher) {
  case Database::Cipher::kAes:
    return "aes";
  case Database::Cipher::kTwofish:
    return "twofish";
  case Database::Cipher::kChaCha20:
    return "chacha20";
  }
  return "?";
}

std::array<uint8_t, 16> CipherUuid(Database::Cipher cipher) {
  switch (cipher) {
  case Database::Cipher::kAes:
    return kCipherAes;
  case Database::Cipher::kTwofish:
    return kCipherTwofish;
  case Database::Cipher::kChaCha20:
    return kCipherChaCha20;
  }
  return {{0}};
}

std::array<uint8_t, 16> KdfUuid(Database::Kdf kdf) {
  switch (kdf) {
  case Database::Kdf::kAes:
    return kKdfAesKdbx4;
  case Database::Kdf::kArgon2d:
    return kKdfArgon2d;
  case Database::Kdf::kArgon2id:
    return kKdfArgon2id;
  }
  return {{0}};
}

} // namespace

TEST(Kdbx4Test, ImportSamples) {
  struct Sample {
    const char *file;
    Database::Cipher cipher;
    Database::Kdf kdf;
    bool compressed;
  };
  const std::vector<Sample> samples = {
      {"kdbx4-aes-argon2d.kdbx", Database::Cipher::kAes,
       Database::Kdf::kArgon2d, true},
      {"kdbx4-chacha20-argon2d.kdbx", Database::Cipher::kChaCha20,
       Database::Kdf::kArgon2d, true},
      {"kdbx4-twofish-argon2d.kdbx", Database::Cipher::kTwofish,
       Database::Kdf::kArgon2d, true},
      {"kdbx4-chacha20-aeskdf.kdbx", Database::Cipher::kChaCha20,
       Database::Kdf::kAes, true},
      {"kdbx4-aes-argon2id.kdbx", Database::Cipher::kAes,
       Database::Kdf::kArgon2id, false},
      {"kdbx4-aes-argon2d-gzip.kdbx", Database::Cipher::kAes,
       Database::Kdf::kArgon2d, true},
  };

  for (const auto &sample : samples) {
    SCOPED_TRACE(sample.file);

    std::string base = std::string(sample.file);
    base.erase(base.size() - std::string(".kdbx").size());

    Key key("password");
    KdbxFile file;
    std::unique_ptr<Database> db;
    EXPECT_NO_THROW({ db = file.Import(GetTestPath(sample.file), key); });

    ASSERT_NE(db, nullptr);
    EXPECT_EQ(db->cipher(), sample.cipher);
    EXPECT_EQ(db->kdf(), sample.kdf);
    EXPECT_EQ(db->compress(), sample.compressed);
    EXPECT_EQ(db->root()->ToJson(), GetTestJson(base + ".json"));
  }
}

TEST(Kdbx4Test, KeyfileImport) {
  std::string path = GetTestPath("kdbx4-aes-argon2d-keyfile.kdbx");

  // Without keyfile -> fails
  {
    Key password_only("password");
    KdbxFile kdbx;
    EXPECT_THROW(kdbx.Import(path, password_only), std::exception);
  }

  // With password + keyfile -> succeeds
  {
    Key key("password");
    key.SetKeyFile(GetTestPath("test.key"));
    KdbxFile kdbx;
    std::unique_ptr<Database> db(kdbx.Import(path, key));

    ASSERT_NE(db->root(), nullptr);
    ASSERT_EQ(db->root()->Entries().size(), 1u);

    std::string expected = GetTestJson("kdbx4-aes-argon2d-keyfile.json");
    EXPECT_EQ(db->root()->ToJson(), expected);
  }

  // Wrong keyfile -> fails
  {
    Key key("password");
    key.SetKeyFile(GetKdbx3DataPath("complex-1-key_pw-aes.key"));
    KdbxFile kdbx;
    EXPECT_THROW(kdbx.Import(path, key), std::exception);
  }

  // Correct keyfile but wrong password -> fails
  {
    Key key("wrong");
    key.SetKeyFile(GetTestPath("test.key"));
    KdbxFile kdbx;
    EXPECT_THROW(kdbx.Import(path, key), PasswordError);
  }
}

TEST(Kdbx4Test, KeyfileRoundtrip) {
  std::string path = GetTestPath("kdbx4-aes-argon2d-keyfile.kdbx");
  std::string tmp_path = GetTmpPath("kdbx4-keyfile-roundtrip.kdbx");

  // Import
  Key key("password");
  key.SetKeyFile(GetTestPath("test.key"));
  KdbxFile kdbx;
  std::unique_ptr<Database> db(kdbx.Import(path, key));
  ASSERT_NE(db->root(), nullptr);
  std::string original_json = db->root()->ToJson();

  // Export with same composite key
  kdbx.set_write_kdbx4(true);
  kdbx.Export(tmp_path, *db, key);

  // Reimport with same composite key -> succeeds
  {
    Key reimport_key("password");
    reimport_key.SetKeyFile(GetTestPath("test.key"));
    std::unique_ptr<Database> db2(kdbx.Import(tmp_path, reimport_key));
    EXPECT_EQ(db2->root()->ToJson(), original_json);
    EXPECT_EQ(db2->cipher(), Database::Cipher::kAes);
    EXPECT_EQ(db2->kdf(), Database::Kdf::kArgon2d);
  }

  // Reimport with only password -> fails
  {
    Key password_only("password");
    EXPECT_THROW(kdbx.Import(tmp_path, password_only), std::exception);
  }

  // Reimport with password + wrong keyfile -> fails
  {
    Key wrong_keyfile("password");
    wrong_keyfile.SetKeyFile(GetKdbx3DataPath("complex-1-key_pw-aes.key"));
    EXPECT_THROW(kdbx.Import(tmp_path, wrong_keyfile), std::exception);
  }

  std::remove(tmp_path.c_str());
}

TEST(Kdbx4Test, LegacyAesKdfUuidAccepted) {
  // The AES-KDF can be identified by the KDBX 3.1 UUID in a KDBX 4 file.
  // KeePassXC writes the legacy UUID here; the importer must accept both.
  std::string data = ReadFile(GetTestPath("kdbx4-chacha20-aeskdf.kdbx"));
  HeaderInfo header = ReadHeader(data);
  ASSERT_TRUE(header.kdf_seen);
  EXPECT_EQ(header.kdf, kKdfAesKdbx3);

  Key key("password");
  KdbxFile file;
  std::unique_ptr<Database> db;
  EXPECT_NO_THROW({ db = file.Import(GetTestPath("kdbx4-chacha20-aeskdf.kdbx"), key); });
  ASSERT_NE(db, nullptr);
  EXPECT_EQ(db->kdf(), Database::Kdf::kAes);
}

TEST(Kdbx4Test, WrongPassword) {
  const char *files[] = {
      "kdbx4-aes-argon2d.kdbx", "kdbx4-chacha20-argon2d.kdbx",
      "kdbx4-twofish-argon2d.kdbx", "kdbx4-chacha20-aeskdf.kdbx",
      "kdbx4-aes-argon2id.kdbx", "kdbx4-aes-argon2d-gzip.kdbx"};

  for (const char *file : files) {
    SCOPED_TRACE(file);

    Key key("wrong_password");
    KdbxFile kdbx_file;
    EXPECT_THROW(kdbx_file.Import(GetTestPath(file), key), PasswordError);
  }
}

TEST(Kdbx4Test, NotKdbx4File) {
  Key key("password");

  KdbxFile file;
  EXPECT_THROW(
      file.Import(std::string(PROJECT_ROOT_PATH) + "/data/gzip_stream-0", key),
      FormatError); // Too small to even contain a header.
  EXPECT_THROW(
      file.Import(std::string(PROJECT_ROOT_PATH) + "/data/hashed_stream-0", key),
      FormatError); // Fits the header but has no KDBX signature.
}

TEST(Kdbx4Test, TruncatedFile) {
  std::string data = ReadFile(GetTestPath("kdbx4-aes-argon2d.kdbx"));
  ASSERT_GT(data.size(), 100u);
  WriteFile(GetTmpPath("kdbx4-truncated.kdbx"), data.substr(0, 40));
  std::remove(GetTmpPath("kdbx4-truncated.kdbx").c_str());

  Key key("password");
  KdbxFile file;
  EXPECT_ANY_THROW(file.Import(GetTmpPath("kdbx4-truncated.kdbx"), key));
}

TEST(Kdbx4Test, UnknownCipherRejected) {
  std::array<uint8_t, 16> bogus = {{0x11}};
  WriteFile(GetTmpPath("kdbx4-bad-cipher.kdbx"),
            MakeKdbx4Header(bogus, kKdfArgon2d));

  Key key("password");
  KdbxFile file;
  EXPECT_THROW(file.Import(GetTmpPath("kdbx4-bad-cipher.kdbx"), key),
               FormatError);
  std::remove(GetTmpPath("kdbx4-bad-cipher.kdbx").c_str());
}

TEST(Kdbx4Test, UnknownKdfRejected) {
  std::array<uint8_t, 16> bogus = {{0x22}};
  WriteFile(GetTmpPath("kdbx4-bad-kdf.kdbx"),
            MakeKdbx4Header(kCipherAes, bogus));

  Key key("password");
  KdbxFile file;
  EXPECT_THROW(file.Import(GetTmpPath("kdbx4-bad-kdf.kdbx"), key),
               FormatError);
  std::remove(GetTmpPath("kdbx4-bad-kdf.kdbx").c_str());
}

TEST(Kdbx4Test, RoundtripSamples) {
  const char *files[] = {
      "kdbx4-aes-argon2d.kdbx", "kdbx4-chacha20-argon2d.kdbx",
      "kdbx4-twofish-argon2d.kdbx", "kdbx4-chacha20-aeskdf.kdbx",
      "kdbx4-aes-argon2id.kdbx", "kdbx4-aes-argon2d-gzip.kdbx"};

  for (const char *file : files) {
    SCOPED_TRACE(file);

    std::string base = std::string(file);
    base.erase(base.size() - std::string(".kdbx").size());

    Key key("password");
    KdbxFile exporter;
    KdbxFile importer;

    std::unique_ptr<Database> db =
        importer.Import(GetTestPath(file), key);
    const Database::Cipher cipher = db->cipher();
    const Database::Kdf kdf = db->kdf();
    const bool compress = db->compress();

    std::string dst_path = GetTmpPath("kdbx4-roundtrip-" + base + ".kdbx");

    exporter.set_write_kdbx4(true);
    EXPECT_NO_THROW(exporter.Export(dst_path, *db, key));

    // The exported file must be a KDBX 4 file with matching metadata.
    HeaderInfo header = ReadHeader(ReadFile(dst_path));
    EXPECT_EQ(header.version & kKdbxVersionCriticalMask, kKdbxVersion4);
    ASSERT_TRUE(header.cipher_seen);
    EXPECT_EQ(header.cipher, CipherUuid(cipher));
    ASSERT_TRUE(header.kdf_seen);
    EXPECT_EQ(header.kdf, KdfUuid(kdf));

    std::unique_ptr<Database> reimported;
    EXPECT_NO_THROW({ reimported = importer.Import(dst_path, key); });
    ASSERT_NE(reimported, nullptr);
    EXPECT_EQ(reimported->cipher(), cipher);
    EXPECT_EQ(reimported->kdf(), kdf);
    EXPECT_EQ(reimported->compress(), compress);
    ExpectSameDatabase(*db, *reimported);

    // Wrong password must not open the exported file.
    EXPECT_THROW(importer.Import(dst_path, Key("wrong_password")),
                 PasswordError);

    std::remove(dst_path.c_str());
  }
}

TEST(Kdbx4Test, MatrixRoundtrip) {
  // Full matrix: every content cipher, every KDF and both compression flags.
  const Database::Cipher ciphers[] = {Database::Cipher::kAes,
                                      Database::Cipher::kTwofish,
                                      Database::Cipher::kChaCha20};
  const Database::Kdf kdfs[] = {Database::Kdf::kAes, Database::Kdf::kArgon2d,
                                Database::Kdf::kArgon2id};
  const bool compression[] = {false, true};

  Key key("password");
  KdbxFile exporter;
  KdbxFile importer;

  std::string dst_path = GetTmpPath("kdbx4-matrix.kdbx");

  for (Database::Cipher cipher : ciphers) {
    for (Database::Kdf kdf : kdfs) {
      for (bool compress : compression) {
        SCOPED_TRACE(std::string(CipherName(cipher)) + " + " +
                     (kdf == Database::Kdf::kAes
                          ? "aes-kdf"
                          : (kdf == Database::Kdf::kArgon2d ? "argon2d"
                                                           : "argon2id")) +
                     (compress ? " + gzip" : ""));

        std::unique_ptr<Database> db =
            MakeDatabase(cipher, kdf, compress);

        exporter.set_write_kdbx4(true);
        EXPECT_NO_THROW(exporter.Export(dst_path, *db, key));

        HeaderInfo header = ReadHeader(ReadFile(dst_path));
        EXPECT_EQ(header.version & kKdbxVersionCriticalMask, kKdbxVersion4);
        ASSERT_TRUE(header.cipher_seen);
        EXPECT_EQ(header.cipher, CipherUuid(cipher));
        ASSERT_TRUE(header.kdf_seen);
        EXPECT_EQ(header.kdf, KdfUuid(kdf));
        EXPECT_EQ(header.compression,
                  compress ? 1u : 0u);

        std::unique_ptr<Database> reimported;
        EXPECT_NO_THROW({ reimported = importer.Import(dst_path, key); });
        ASSERT_NE(reimported, nullptr);
        EXPECT_EQ(reimported->cipher(), cipher);
        EXPECT_EQ(reimported->kdf(), kdf);
        EXPECT_EQ(reimported->compress(), compress);
        ExpectSameDatabase(*db, *reimported);
      }
    }
  }

  // The exported file must not open with a wrong password.
  std::unique_ptr<Database> db =
      MakeDatabase(Database::Cipher::kAes, Database::Kdf::kArgon2d, false);
  exporter.set_write_kdbx4(true);
  exporter.Export(dst_path, *db, key);
  EXPECT_THROW(importer.Import(dst_path, Key("wrong_password")),
               PasswordError);

  std::remove(dst_path.c_str());
}

TEST(Kdbx4Test, CompositeKey) {
  Key key("password");
  key.SetKeyFile(GetKdbx3DataPath("complex-1-key_pw-aes.key"));

  std::unique_ptr<Database> db =
      MakeDatabase(Database::Cipher::kAes, Database::Kdf::kArgon2d, false);

  std::string dst_path = GetTmpPath("kdbx4-composite.kdbx");
  KdbxFile exporter;
  exporter.set_write_kdbx4(true);
  EXPECT_NO_THROW(exporter.Export(dst_path, *db, key));

  // Import with the same composite key succeeds.
  KdbxFile importer;
  std::unique_ptr<Database> reimported;
  EXPECT_NO_THROW({ reimported = importer.Import(dst_path, key); });
  ASSERT_NE(reimported, nullptr);
  ExpectSameDatabase(*db, *reimported);

  // Import with the password alone must fail; the key differs from the
  // composite key used for encryption.
  EXPECT_THROW(importer.Import(dst_path, Key("password")), PasswordError);

  std::remove(dst_path.c_str());
}

TEST(Kdbx4Test, AttachmentRoundtrip) {
  std::unique_ptr<Database> db =
      MakeDatabase(Database::Cipher::kAes, Database::Kdf::kArgon2d, false);

  // Attach a binary to the first entry; KDBX 4 stores it in the inner header.
  auto entry = db->root()->Entries().front();
  std::shared_ptr<Binary> binary(new Binary(
      protect<std::string>("attachment payload", true)));
  binary->set_compress(false);

  auto attachment = std::make_shared<Entry::Attachment>();
  attachment->set_name("file.bin");
  attachment->set_binary(binary);
  entry->AddAttachment(attachment);

  std::string dst_path = GetTmpPath("kdbx4-attachment.kdbx");
  KdbxFile exporter;
  exporter.set_write_kdbx4(true);
  Key key("password");
  EXPECT_NO_THROW(exporter.Export(dst_path, *db, key));

  KdbxFile importer;
  std::unique_ptr<Database> reimported;
  EXPECT_NO_THROW({ reimported = importer.Import(dst_path, key); });
  ASSERT_NE(reimported, nullptr);

  const auto &attachments = reimported->root()->Entries().front()->attachments();
  ASSERT_EQ(attachments.size(), 1u);
  EXPECT_EQ(attachments[0]->name(), "file.bin");
  ASSERT_NE(attachments[0]->binary(), nullptr);
  EXPECT_EQ(*attachments[0]->binary()->data(), "attachment payload");

  std::remove(dst_path.c_str());
}

TEST(Kdbx4Test, ComplexStructureRoundtrip) {
  std::unique_ptr<Database> db =
      MakeDatabase(Database::Cipher::kChaCha20, Database::Kdf::kArgon2id,
                   true);

  // Add another entry with a custom field and a history entry.
  auto entry = db->root()->Entries().front();
  std::string field_key = "CustomField";
  entry->AddCustomField(field_key, protect<std::string>("custom value", true));

  auto history = std::make_shared<Entry>();
  history->set_title(protect<std::string>("OldTitle", false));
  history->set_password(protect<std::string>("oldsecret", true));
  history->set_creation_time(1690000000);
  entry->AddHistoryEntry(history);

  std::string dst_path = GetTmpPath("kdbx4-complex.kdbx");
  KdbxFile exporter;
  exporter.set_write_kdbx4(true);
  Key key("password");
  EXPECT_NO_THROW(exporter.Export(dst_path, *db, key));

  KdbxFile importer;
  std::unique_ptr<Database> reimported;
  EXPECT_NO_THROW({ reimported = importer.Import(dst_path, key); });
  ASSERT_NE(reimported, nullptr);
  ExpectSameDatabase(*db, *reimported);

  const auto &reimported_entry =
      reimported->root()->Entries().front();
  const auto &custom_fields = reimported_entry->custom_fields();
  ASSERT_EQ(custom_fields.size(), 1u);
  EXPECT_EQ(custom_fields[0].key(), "CustomField");
  EXPECT_EQ(std::string(*custom_fields[0].value()), "custom value");
  ASSERT_EQ(reimported_entry->history().size(), 1u);
  EXPECT_EQ(std::string(*reimported_entry->history()[0]->password()),
            "oldsecret");

  std::remove(dst_path.c_str());
}

TEST(KdbxAesNi, TransformMatchesEVPReference) {
  std::array<uint8_t, 32> seed = {
      {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
       0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
       0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
       0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20}};
  std::array<uint8_t, 32> composite = {
      {0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33,
       0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
       0xcc, 0xdd, 0xee, 0xff, 0x12, 0x34, 0x56, 0x78,
       0x9a, 0xbc, 0xde, 0xf0, 0x0f, 0x1e, 0x2d, 0x3c}};
  const uint64_t rounds = 1000;

  std::array<uint8_t, 32> evp_result = composite;
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  ASSERT_NE(ctx, nullptr);
  ASSERT_EQ(EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), nullptr, seed.data(),
                               nullptr),
            1);
  EVP_CIPHER_CTX_set_padding(ctx, 0);
  std::array<uint8_t, 32> buf{};
  for (uint64_t i = 0; i < rounds; ++i) {
    int outl = 0;
    ASSERT_EQ(EVP_EncryptUpdate(ctx, buf.data(), &outl, evp_result.data(),
                                evp_result.size()),
              1);
    ASSERT_EQ(outl, 32);
    evp_result = buf;
  }
  EVP_CIPHER_CTX_free(ctx);

  std::array<uint8_t, 32> aeni_result{};
  aes_ni_transform_aes_kdf(seed.data(), composite.data(), rounds,
                           aeni_result.data());

  EXPECT_EQ(aeni_result, evp_result);
}

TEST(KdbxAesNi, SupportedFlagConsistent) {
  bool supported = aes_ni_supported();
  EXPECT_EQ(supported, aes_ni_supported());
}
