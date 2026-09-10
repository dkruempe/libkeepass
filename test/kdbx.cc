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

#include <fstream>

#include <gtest/gtest.h>

#include "config.hh"
#include "libkeepass/exception.hh"
#include "libkeepass/kdbx.hh"
#include "libkeepass/key.hh"

using namespace keepass;

namespace {

std::string GetTestPath(const std::string& name) {
  return std::string(PROJECT_ROOT_PATH) + "/data/kdbx/" + name;
}

std::string GetTmpPath(const std::string& name) {
  return std::string(PROJECT_ROOT_PATH) + "/tmp/" + name;
}

std::string ReadFile(const std::string& path) {
  std::ifstream file(path, std::ios::in | std::ios::binary);
  return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
}

void WriteFile(const std::string& path, const std::string& data) {
  std::ofstream file(path, std::ios::out | std::ios::binary);
  file.write(data.data(), static_cast<std::streamsize>(data.size()));
}

// Locates the first byte after the KDBX 3 header fields, i.e. the start of
// the hashed content blocks.
size_t FindKdbx3HeaderEnd(const std::string& data) {
  size_t off = 12;
  while (off + 3 <= data.size()) {
    const uint8_t id = static_cast<uint8_t>(data[off]);
    const uint16_t size = static_cast<uint16_t>(static_cast<uint8_t>(data[off + 1])) |
                          (static_cast<uint16_t>(static_cast<uint8_t>(data[off + 2])) << 8);
    off += 3;
    if (size > data.size() - off)
      break;
    off += size;
    if (id == 0)
      break; // End of header.
  }
  return off;
}

// Returns the offset of the value bytes of the first header field with the
// given id, or data.size() if no such field is present.
size_t FindKdbx3FieldData(const std::string& data, uint8_t wanted_id) {
  size_t off = 12;
  while (off + 3 <= data.size()) {
    const uint8_t id = static_cast<uint8_t>(data[off]);
    const uint16_t size = static_cast<uint16_t>(static_cast<uint8_t>(data[off + 1])) |
                          (static_cast<uint16_t>(static_cast<uint8_t>(data[off + 2])) << 8);
    off += 3;
    if (id == 0)
      return data.size();
    if (size > data.size() - off)
      break;
    if (id == wanted_id)
      return off;
    off += size;
  }
  return data.size();
}

std::string GetTestJson(const std::string& name) {
  std::ifstream file(GetTestPath(name));
  std::string file_str((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

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

} // namespace

TEST(KdbxTest, NonExistingFile) {
  Key key("password");

  KdbxFile file;
  EXPECT_THROW(file.Import(GetTestPath("_.kdbx"), key), FileNotFoundError);
}

TEST(KdbxTest, NonKdbxFile) {
  Key key("password");

  KdbxFile file;
  EXPECT_THROW(file.Import(std::string(PROJECT_ROOT_PATH) + "/data/gzip_stream-0", key),
               FormatError); // Too small to even contain header.
  EXPECT_THROW(file.Import(std::string(PROJECT_ROOT_PATH) + "/data/hashed_stream-0", key),
               FormatError); // Fits header but doesn't have signature.
}

TEST(KdbxTest, CorrectPassword) {
  Key key("password");

  KdbxFile file;
  EXPECT_NO_THROW(file.Import(GetTestPath("groups-1-empty-pw-aes.kdbx"), key));
}

TEST(KdbxTest, InvalidPassword) {
  Key key("wrong_password");

  KdbxFile file;
  EXPECT_THROW(file.Import(GetTestPath("groups-1-empty-pw-aes.kdbx"), key), PasswordError);
}

TEST(KdbxTest, ImportGroups1) {
  Key key("password");

  KdbxFile file;
  std::unique_ptr<Database> db;
  EXPECT_NO_THROW({ db = file.Import(GetTestPath("groups-1-empty-pw-aes.kdbx"), key); });
  std::shared_ptr<Group> root = db->root();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-1-empty-pw-aes.json"));

  EXPECT_NO_THROW({ db = file.Import(GetTestPath("groups-1-random_entry-1-pw-aes.kdbx"), key); });
  root = db->root();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-1-random_entry-1-pw-aes.json"));

  EXPECT_NO_THROW({ db = file.Import(GetTestPath("groups-1-random_entry-2-pw-aes.kdbx"), key); });
  root = db->root();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-1-random_entry-2-pw-aes.json"));

  EXPECT_NO_THROW({ db = file.Import(GetTestPath("groups-1-random_entry-3-pw-aes.kdbx"), key); });
  root = db->root();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-1-random_entry-3-pw-aes.json"));
}

TEST(KdbxTest, ImportGroups2) {
  Key key("password");

  KdbxFile file;
  std::unique_ptr<Database> db;
  EXPECT_NO_THROW({ db = file.Import(GetTestPath("groups-2-empty-pw-aes.kdbx"), key); });
  std::shared_ptr<Group> root = db->root();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-2-empty-pw-aes.json"));

  EXPECT_NO_THROW({ db = file.Import(GetTestPath("groups-2-random_entry-1-pw-aes.kdbx"), key); });
  root = db->root();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-2-random_entry-1-pw-aes.json"));

  EXPECT_NO_THROW({ db = file.Import(GetTestPath("groups-2-random_entry-2-pw-aes.kdbx"), key); });
  root = db->root();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-2-random_entry-2-pw-aes.json"));

  EXPECT_NO_THROW({ db = file.Import(GetTestPath("groups-2-random_entry-3-pw-aes.kdbx"), key); });
  root = db->root();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-2-random_entry-3-pw-aes.json"));

  EXPECT_NO_THROW({ db = file.Import(GetTestPath("groups-2-random_entry-4-pw-aes.kdbx"), key); });
  root = db->root();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-2-random_entry-4-pw-aes.json"));
}

TEST(KdbxTest, ImportGroups3) {
  Key key("password");

  KdbxFile file;
  std::unique_ptr<Database> db;
  EXPECT_NO_THROW({ db = file.Import(GetTestPath("groups-3-empty-pw-aes.kdbx"), key); });
  std::shared_ptr<Group> root = db->root();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-3-empty-pw-aes.json"));

  EXPECT_NO_THROW({ db = file.Import(GetTestPath("groups-3-random_entry-1-pw-aes.kdbx"), key); });
  root = db->root();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-3-random_entry-1-pw-aes.json"));
}

TEST(KdbxTest, ImportGroups4) {
  Key key("password");

  KdbxFile file;
  std::unique_ptr<Database> db;
  EXPECT_NO_THROW({ db = file.Import(GetTestPath("groups-4-empty-pw-aes.kdbx"), key); });
  std::shared_ptr<Group> root = db->root();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-4-empty-pw-aes.json"));

  EXPECT_NO_THROW({ db = file.Import(GetTestPath("groups-4-random_entry-1-pw-aes.kdbx"), key); });
  root = db->root();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-4-random_entry-1-pw-aes.json"));

  EXPECT_NO_THROW({ db = file.Import(GetTestPath("groups-4-random_entry-2-pw-aes.kdbx"), key); });
  root = db->root();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-4-random_entry-2-pw-aes.json"));

  EXPECT_NO_THROW({ db = file.Import(GetTestPath("groups-4-random_entry-3-pw-aes.kdbx"), key); });
  root = db->root();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-4-random_entry-3-pw-aes.json"));
}

TEST(KdbxTest, ImportGroups5) {
  Key key("password");

  KdbxFile file;
  std::unique_ptr<Database> db;
  EXPECT_NO_THROW({ db = file.Import(GetTestPath("groups-5-empty-pw-aes.kdbx"), key); });
  std::shared_ptr<Group> root = db->root();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-5-empty-pw-aes.json"));

  EXPECT_NO_THROW({ db = file.Import(GetTestPath("groups-5-random_entry-1-pw-aes.kdbx"), key); });
  root = db->root();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-5-random_entry-1-pw-aes.json"));

  EXPECT_NO_THROW({ db = file.Import(GetTestPath("groups-5-random_entry-2-pw-aes.kdbx"), key); });
  root = db->root();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-5-random_entry-2-pw-aes.json"));

  EXPECT_NO_THROW({ db = file.Import(GetTestPath("groups-5-random_entry-3-pw-aes.kdbx"), key); });
  root = db->root();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-5-random_entry-3-pw-aes.json"));
}

TEST(KdbxTest, ImportGroups6) {
  Key key("password");

  KdbxFile file;
  std::unique_ptr<Database> db;
  EXPECT_NO_THROW({ db = file.Import(GetTestPath("groups-6-empty-pw-aes.kdbx"), key); });
  std::shared_ptr<Group> root = db->root();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-6-empty-pw-aes.json"));

  EXPECT_NO_THROW({ db = file.Import(GetTestPath("groups-6-random_entry-1-pw-aes.kdbx"), key); });
  root = db->root();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-6-random_entry-1-pw-aes.json"));

  EXPECT_NO_THROW({ db = file.Import(GetTestPath("groups-6-random_entry-2-pw-aes.kdbx"), key); });
  root = db->root();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-6-random_entry-2-pw-aes.json"));

  EXPECT_NO_THROW({ db = file.Import(GetTestPath("groups-6-random_entry-3-pw-aes.kdbx"), key); });
  root = db->root();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-6-random_entry-3-pw-aes.json"));
}

TEST(KdbxTest, ImportGroups7) {
  Key key("password");

  KdbxFile file;
  std::unique_ptr<Database> db;
  EXPECT_NO_THROW({ db = file.Import(GetTestPath("groups-7-empty-pw-aes.kdbx"), key); });
  std::shared_ptr<Group> root = db->root();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-7-empty-pw-aes.json"));

  EXPECT_NO_THROW({ db = file.Import(GetTestPath("groups-7-random_entry-1-pw-aes.kdbx"), key); });
  root = db->root();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-7-random_entry-1-pw-aes.json"));

  EXPECT_NO_THROW({ db = file.Import(GetTestPath("groups-7-random_entry-2-pw-aes.kdbx"), key); });
  root = db->root();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-7-random_entry-2-pw-aes.json"));

  EXPECT_NO_THROW({ db = file.Import(GetTestPath("groups-7-random_entry-3-pw-aes.kdbx"), key); });
  root = db->root();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-7-random_entry-3-pw-aes.json"));
}

TEST(KdbxTest, ImportGroups8) {
  Key key("password");

  KdbxFile file;
  std::unique_ptr<Database> db;
  EXPECT_NO_THROW({ db = file.Import(GetTestPath("groups-8-empty-pw-aes.kdbx"), key); });
  std::shared_ptr<Group> root = db->root();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-8-empty-pw-aes.json"));
}

TEST(KdbxTest, ImportGroups9) {
  Key key("password");

  KdbxFile file;
  std::unique_ptr<Database> db;
  EXPECT_NO_THROW({ db = file.Import(GetTestPath("groups-9-default-pw-aes.kdbx"), key); });
  std::shared_ptr<Group> root = db->root();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-9-default-pw-aes.json"));
}

TEST(KdbxTest, ImportComplex1) {
  Key key("password");

  KdbxFile file;
  std::unique_ptr<Database> db;
  EXPECT_NO_THROW({ db = file.Import(GetTestPath("complex-1-pw-aes.kdbx"), key); });

  std::shared_ptr<Group> root = db->root();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("complex-1-pw-aes.json"));
}

TEST(KdbxTest, ImportComplex1Compressed) {
  Key key("password");

  KdbxFile file;
  std::unique_ptr<Database> db;
  EXPECT_NO_THROW({ db = file.Import(GetTestPath("complex-1-pw-aes-gzip.kdbx"), key); });

  std::shared_ptr<Group> root = db->root();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("complex-1-pw-aes-gzip.json"));
}

TEST(KdbxTest, ImportComplex1KeyFile) {
  Key key;
  key.SetKeyFile(GetTestPath("complex-1-key-aes.key"));

  KdbxFile file;
  std::unique_ptr<Database> db;
  EXPECT_NO_THROW({ db = file.Import(GetTestPath("complex-1-key-aes.kdbx"), key); });

  std::shared_ptr<Group> root = db->root();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("complex-1-key-aes.json"));
}

TEST(KdbxTest, ImportComplex1KeyFileCompressed) {
  Key key;
  key.SetKeyFile(GetTestPath("complex-1-key-aes-gzip.key"));

  KdbxFile file;
  std::unique_ptr<Database> db;
  EXPECT_NO_THROW({ db = file.Import(GetTestPath("complex-1-key-aes-gzip.kdbx"), key); });

  std::shared_ptr<Group> root = db->root();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("complex-1-key-aes-gzip.json"));
}

TEST(KdbxTest, ImportComplex1KeyFileAndPassword) {
  Key key("password");
  key.SetKeyFile(GetTestPath("complex-1-key_pw-aes.key"));

  KdbxFile file;
  std::unique_ptr<Database> db;
  EXPECT_NO_THROW({ db = file.Import(GetTestPath("complex-1-key_pw-aes.kdbx"), key); });

  std::shared_ptr<Group> root = db->root();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("complex-1-key_pw-aes.json"));
}

TEST(KdbxTest, ExportGroups1) {
  Key key("password");

  KdbxFile file;
  std::unique_ptr<Database> db;

  struct TestFiles {
    std::string src_path;
    std::string dst_path;
    std::string json;
  };
  std::array<TestFiles, 4> test_files = {
      {{GetTestPath("groups-1-empty-pw-aes.kdbx"), GetTmpPath("groups-1-empty-pw-aes.kdbx"),
        GetTestJson("groups-1-empty-pw-aes.json")},
       {GetTestPath("groups-1-random_entry-1-pw-aes.kdbx"),
        GetTmpPath("groups-1-random_entry-1-pw-aes.kdbx"),
        GetTestJson("groups-1-random_entry-1-pw-aes.json")},
       {GetTestPath("groups-1-random_entry-2-pw-aes.kdbx"),
        GetTmpPath("groups-1-random_entry-2-pw-aes.kdbx"),
        GetTestJson("groups-1-random_entry-2-pw-aes.json")},
       {GetTestPath("groups-1-random_entry-3-pw-aes.kdbx"),
        GetTmpPath("groups-1-random_entry-3-pw-aes.kdbx"),
        GetTestJson("groups-1-random_entry-3-pw-aes.json")}}};

  for (auto& t : test_files) {
    EXPECT_NO_THROW({ db = file.Import(t.src_path, key); });
    file.Export(t.dst_path, *db, key);
    EXPECT_NO_THROW({ db = file.Import(t.dst_path, key); });
    std::remove(t.dst_path.c_str());

    std::shared_ptr<Group> root = db->root();
    EXPECT_NE(root, nullptr);
    EXPECT_EQ(root->ToJson(), t.json);
  }
}

TEST(KdbxTest, ExportGroups2) {
  Key key("password");

  KdbxFile file;
  std::unique_ptr<Database> db;

  struct TestFiles {
    std::string src_path;
    std::string dst_path;
    std::string json;
  };
  std::array<TestFiles, 5> test_files = {
      {{GetTestPath("groups-2-empty-pw-aes.kdbx"), GetTmpPath("groups-2-empty-pw-aes.kdbx"),
        GetTestJson("groups-2-empty-pw-aes.json")},
       {GetTestPath("groups-2-random_entry-1-pw-aes.kdbx"),
        GetTmpPath("groups-2-random_entry-1-pw-aes.kdbx"),
        GetTestJson("groups-2-random_entry-1-pw-aes.json")},
       {GetTestPath("groups-2-random_entry-2-pw-aes.kdbx"),
        GetTmpPath("groups-2-random_entry-2-pw-aes.kdbx"),
        GetTestJson("groups-2-random_entry-2-pw-aes.json")},
       {GetTestPath("groups-2-random_entry-3-pw-aes.kdbx"),
        GetTmpPath("groups-2-random_entry-3-pw-aes.kdbx"),
        GetTestJson("groups-2-random_entry-3-pw-aes.json")},
       {GetTestPath("groups-2-random_entry-4-pw-aes.kdbx"),
        GetTmpPath("groups-2-random_entry-4-pw-aes.kdbx"),
        GetTestJson("groups-2-random_entry-4-pw-aes.json")}}};

  for (auto& t : test_files) {
    EXPECT_NO_THROW({ db = file.Import(t.src_path, key); });
    file.Export(t.dst_path, *db, key);
    EXPECT_NO_THROW({ db = file.Import(t.dst_path, key); });
    std::remove(t.dst_path.c_str());

    std::shared_ptr<Group> root = db->root();
    EXPECT_NE(root, nullptr);
    EXPECT_EQ(root->ToJson(), t.json);
  }
}

TEST(KdbxTest, ExportGroups3) {
  Key key("password");

  KdbxFile file;
  std::unique_ptr<Database> db;

  struct TestFiles {
    std::string src_path;
    std::string dst_path;
    std::string json;
  };
  std::array<TestFiles, 2> test_files = {
      {{GetTestPath("groups-3-empty-pw-aes.kdbx"), GetTmpPath("groups-3-empty-pw-aes.kdbx"),
        GetTestJson("groups-3-empty-pw-aes.json")},
       {GetTestPath("groups-3-random_entry-1-pw-aes.kdbx"),
        GetTmpPath("groups-3-random_entry-1-pw-aes.kdbx"),
        GetTestJson("groups-3-random_entry-1-pw-aes.json")}}};

  for (auto& t : test_files) {
    EXPECT_NO_THROW({ db = file.Import(t.src_path, key); });
    file.Export(t.dst_path, *db, key);
    EXPECT_NO_THROW({ db = file.Import(t.dst_path, key); });
    std::remove(t.dst_path.c_str());

    std::shared_ptr<Group> root = db->root();
    EXPECT_NE(root, nullptr);
    EXPECT_EQ(root->ToJson(), t.json);
  }
}

TEST(KdbxTest, ExportGroups4) {
  Key key("password");

  KdbxFile file;
  std::unique_ptr<Database> db;

  struct TestFiles {
    std::string src_path;
    std::string dst_path;
    std::string json;
  };
  std::array<TestFiles, 4> test_files = {
      {{GetTestPath("groups-4-empty-pw-aes.kdbx"), GetTmpPath("groups-4-empty-pw-aes.kdbx"),
        GetTestJson("groups-4-empty-pw-aes.json")},
       {GetTestPath("groups-4-random_entry-1-pw-aes.kdbx"),
        GetTmpPath("groups-4-random_entry-1-pw-aes.kdbx"),
        GetTestJson("groups-4-random_entry-1-pw-aes.json")},
       {GetTestPath("groups-4-random_entry-2-pw-aes.kdbx"),
        GetTmpPath("groups-4-random_entry-2-pw-aes.kdbx"),
        GetTestJson("groups-4-random_entry-2-pw-aes.json")},
       {GetTestPath("groups-4-random_entry-3-pw-aes.kdbx"),
        GetTmpPath("groups-4-random_entry-3-pw-aes.kdbx"),
        GetTestJson("groups-4-random_entry-3-pw-aes.json")}}};

  for (auto& t : test_files) {
    EXPECT_NO_THROW({ db = file.Import(t.src_path, key); });
    file.Export(t.dst_path, *db, key);
    EXPECT_NO_THROW({ db = file.Import(t.dst_path, key); });
    std::remove(t.dst_path.c_str());

    std::shared_ptr<Group> root = db->root();
    EXPECT_NE(root, nullptr);
    EXPECT_EQ(root->ToJson(), t.json);
  }
}

TEST(KdbxTest, ExportGroups5) {
  Key key("password");

  KdbxFile file;
  std::unique_ptr<Database> db;

  struct TestFiles {
    std::string src_path;
    std::string dst_path;
    std::string json;
  };
  std::array<TestFiles, 4> test_files = {
      {{GetTestPath("groups-5-empty-pw-aes.kdbx"), GetTmpPath("groups-5-empty-pw-aes.kdbx"),
        GetTestJson("groups-5-empty-pw-aes.json")},
       {GetTestPath("groups-5-random_entry-1-pw-aes.kdbx"),
        GetTmpPath("groups-5-random_entry-1-pw-aes.kdbx"),
        GetTestJson("groups-5-random_entry-1-pw-aes.json")},
       {GetTestPath("groups-5-random_entry-2-pw-aes.kdbx"),
        GetTmpPath("groups-5-random_entry-2-pw-aes.kdbx"),
        GetTestJson("groups-5-random_entry-2-pw-aes.json")},
       {GetTestPath("groups-5-random_entry-3-pw-aes.kdbx"),
        GetTmpPath("groups-5-random_entry-3-pw-aes.kdbx"),
        GetTestJson("groups-5-random_entry-3-pw-aes.json")}}};

  for (auto& t : test_files) {
    EXPECT_NO_THROW({ db = file.Import(t.src_path, key); });
    file.Export(t.dst_path, *db, key);
    EXPECT_NO_THROW({ db = file.Import(t.dst_path, key); });
    std::remove(t.dst_path.c_str());

    std::shared_ptr<Group> root = db->root();
    EXPECT_NE(root, nullptr);
    EXPECT_EQ(root->ToJson(), t.json);
  }
}

TEST(KdbxTest, ExportGroups6) {
  Key key("password");

  KdbxFile file;
  std::unique_ptr<Database> db;

  struct TestFiles {
    std::string src_path;
    std::string dst_path;
    std::string json;
  };
  std::array<TestFiles, 4> test_files = {
      {{GetTestPath("groups-6-empty-pw-aes.kdbx"), GetTmpPath("groups-6-empty-pw-aes.kdbx"),
        GetTestJson("groups-6-empty-pw-aes.json")},
       {GetTestPath("groups-6-random_entry-1-pw-aes.kdbx"),
        GetTmpPath("groups-6-random_entry-1-pw-aes.kdbx"),
        GetTestJson("groups-6-random_entry-1-pw-aes.json")},
       {GetTestPath("groups-6-random_entry-2-pw-aes.kdbx"),
        GetTmpPath("groups-6-random_entry-2-pw-aes.kdbx"),
        GetTestJson("groups-6-random_entry-2-pw-aes.json")},
       {GetTestPath("groups-6-random_entry-3-pw-aes.kdbx"),
        GetTmpPath("groups-6-random_entry-3-pw-aes.kdbx"),
        GetTestJson("groups-6-random_entry-3-pw-aes.json")}}};

  for (auto& t : test_files) {
    EXPECT_NO_THROW({ db = file.Import(t.src_path, key); });
    file.Export(t.dst_path, *db, key);
    EXPECT_NO_THROW({ db = file.Import(t.dst_path, key); });
    std::remove(t.dst_path.c_str());

    std::shared_ptr<Group> root = db->root();
    EXPECT_NE(root, nullptr);
    EXPECT_EQ(root->ToJson(), t.json);
  }
}

TEST(KdbxTest, ExportGroups7) {
  Key key("password");

  KdbxFile file;
  std::unique_ptr<Database> db;

  struct TestFiles {
    std::string src_path;
    std::string dst_path;
    std::string json;
  };
  std::array<TestFiles, 4> test_files = {
      {{GetTestPath("groups-7-empty-pw-aes.kdbx"), GetTmpPath("groups-7-empty-pw-aes.kdbx"),
        GetTestJson("groups-7-empty-pw-aes.json")},
       {GetTestPath("groups-7-random_entry-1-pw-aes.kdbx"),
        GetTmpPath("groups-7-random_entry-1-pw-aes.kdbx"),
        GetTestJson("groups-7-random_entry-1-pw-aes.json")},
       {GetTestPath("groups-7-random_entry-2-pw-aes.kdbx"),
        GetTmpPath("groups-7-random_entry-2-pw-aes.kdbx"),
        GetTestJson("groups-7-random_entry-2-pw-aes.json")},
       {GetTestPath("groups-7-random_entry-3-pw-aes.kdbx"),
        GetTmpPath("groups-7-random_entry-3-pw-aes.kdbx"),
        GetTestJson("groups-7-random_entry-3-pw-aes.json")}}};

  for (auto& t : test_files) {
    EXPECT_NO_THROW({ db = file.Import(t.src_path, key); });
    file.Export(t.dst_path, *db, key);
    EXPECT_NO_THROW({ db = file.Import(t.dst_path, key); });
    std::remove(t.dst_path.c_str());

    std::shared_ptr<Group> root = db->root();
    EXPECT_NE(root, nullptr);
    EXPECT_EQ(root->ToJson(), t.json);
  }
}

TEST(KdbxTest, ExportGroups8) {
  Key key("password");

  KdbxFile file;
  std::unique_ptr<Database> db;

  struct TestFiles {
    std::string src_path;
    std::string dst_path;
    std::string json;
  };
  std::array<TestFiles, 1> test_files = {
      {{GetTestPath("groups-8-empty-pw-aes.kdbx"), GetTmpPath("groups-8-empty-pw-aes.kdbx"),
        GetTestJson("groups-8-empty-pw-aes.json")}}};

  for (auto& t : test_files) {
    EXPECT_NO_THROW({ db = file.Import(t.src_path, key); });
    file.Export(t.dst_path, *db, key);
    EXPECT_NO_THROW({ db = file.Import(t.dst_path, key); });
    std::remove(t.dst_path.c_str());

    std::shared_ptr<Group> root = db->root();
    EXPECT_NE(root, nullptr);
    EXPECT_EQ(root->ToJson(), t.json);
  }
}

TEST(KdbxTest, ExportGroups9) {
  Key key("password");

  KdbxFile file;
  std::unique_ptr<Database> db;

  struct TestFiles {
    std::string src_path;
    std::string dst_path;
    std::string json;
  };
  std::array<TestFiles, 1> test_files = {
      {{GetTestPath("groups-9-default-pw-aes.kdbx"), GetTmpPath("groups-9-default-pw-aes.kdbx"),
        GetTestJson("groups-9-default-pw-aes.json")}}};

  for (auto& t : test_files) {
    EXPECT_NO_THROW({ db = file.Import(t.src_path, key); });
    file.Export(t.dst_path, *db, key);
    EXPECT_NO_THROW({ db = file.Import(t.dst_path, key); });
    std::remove(t.dst_path.c_str());

    std::shared_ptr<Group> root = db->root();
    EXPECT_NE(root, nullptr);
    EXPECT_EQ(root->ToJson(), t.json);
  }
}

TEST(KdbxTest, ExportComplex1) {
  Key key("password");

  std::string src_path = GetTestPath("complex-1-pw-aes.kdbx");
  std::string dst_path = GetTmpPath("complex-1-pw-aes.kdbx");
  std::string json = GetTestJson("complex-1-pw-aes.json");

  KdbxFile file;
  std::unique_ptr<Database> db;

  EXPECT_NO_THROW({ db = file.Import(src_path, key); });
  file.Export(dst_path, *db, key);
  EXPECT_NO_THROW({ db = file.Import(dst_path, key); });
  std::remove(dst_path.c_str());

  std::shared_ptr<Group> root = db->root();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), json);
}

TEST(KdbxTest, ExportComplex1Compressed) {
  Key key("password");

  std::string src_path = GetTestPath("complex-1-pw-aes-gzip.kdbx");
  std::string dst_path = GetTmpPath("complex-1-pw-aes-gzip.kdbx");
  std::string json = GetTestJson("complex-1-pw-aes-gzip.json");

  KdbxFile file;
  std::unique_ptr<Database> db;

  EXPECT_NO_THROW({ db = file.Import(src_path, key); });
  file.Export(dst_path, *db, key);
  EXPECT_NO_THROW({ db = file.Import(dst_path, key); });
  std::remove(dst_path.c_str());

  std::shared_ptr<Group> root = db->root();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), json);
}

TEST(KdbxTest, ExportComplex1KeyFile) {
  Key key;
  key.SetKeyFile(GetTestPath("complex-1-key-aes.key"));

  std::string src_path = GetTestPath("complex-1-key-aes.kdbx");
  std::string dst_path = GetTmpPath("complex-1-key-aes.kdbx");
  std::string json = GetTestJson("complex-1-key-aes.json");

  KdbxFile file;
  std::unique_ptr<Database> db;

  EXPECT_NO_THROW({ db = file.Import(src_path, key); });
  file.Export(dst_path, *db, key);
  EXPECT_NO_THROW({ db = file.Import(dst_path, key); });
  std::remove(dst_path.c_str());

  std::shared_ptr<Group> root = db->root();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), json);
}

TEST(KdbxTest, ExportComplex1KeyFileCompressed) {
  Key key;
  key.SetKeyFile(GetTestPath("complex-1-key-aes-gzip.key"));

  std::string src_path = GetTestPath("complex-1-key-aes-gzip.kdbx");
  std::string dst_path = GetTmpPath("complex-1-key-aes-gzip.kdbx");
  std::string json = GetTestJson("complex-1-key-aes-gzip.json");

  KdbxFile file;
  std::unique_ptr<Database> db;

  EXPECT_NO_THROW({ db = file.Import(src_path, key); });
  file.Export(dst_path, *db, key);
  EXPECT_NO_THROW({ db = file.Import(dst_path, key); });
  std::remove(dst_path.c_str());

  std::shared_ptr<Group> root = db->root();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), json);
}

TEST(KdbxTest, CorruptionDetected) {
  const std::string data = ReadFile(GetTestPath("groups-1-empty-pw-aes.kdbx"));
  ASSERT_GT(data.size(), 200U);

  const size_t header_end = FindKdbx3HeaderEnd(data);
  ASSERT_GT(header_end, 12U);
  ASSERT_LE(header_end + 40, data.size()) << "file too short for a content block";

  Key key("password");

  // The master seed takes part in the key derivation; flipping it must make
  // decryption fail instead of accepting a tampered header.
  {
    const size_t seed_off = FindKdbx3FieldData(data, 4);
    ASSERT_LT(seed_off, data.size()) << "master seed field missing";
    std::string corrupt = data;
    corrupt[seed_off] ^= 0x01;
    WriteFile(GetTmpPath("kdbx3-corrupt-seed.kdbx"), corrupt);
    KdbxFile file;
    EXPECT_THROW(file.Import(GetTmpPath("kdbx3-corrupt-seed.kdbx"), key), PasswordError);
    std::remove(GetTmpPath("kdbx3-corrupt-seed.kdbx").c_str());
  }

  // A flipped byte in the inner random stream key field does not break
  // decryption but changes the header hash stored in <HeaderHash>.
  {
    const size_t key_off = FindKdbx3FieldData(data, 8);
    ASSERT_LT(key_off, data.size()) << "inner random stream key field missing";
    std::string corrupt = data;
    corrupt[key_off] ^= 0x01;
    WriteFile(GetTmpPath("kdbx3-corrupt-innerkey.kdbx"), corrupt);
    KdbxFile file;
    EXPECT_THROW(file.Import(GetTmpPath("kdbx3-corrupt-innerkey.kdbx"), key), FormatError);
    std::remove(GetTmpPath("kdbx3-corrupt-innerkey.kdbx").c_str());
  }

  // A flipped byte in the first content block header fails the SHA-256 block
  // checksum. The hashed stream raises IoError, but the XML parser reads
  // through a std::istream whose default exception mask suppresses the
  // streambuf exception, so the import reports the corruption as a malformed
  // XML document instead.
  {
    std::string corrupt = data;
    corrupt[header_end + 4 + 32 + 4] ^= 0x01;
    WriteFile(GetTmpPath("kdbx3-corrupt-block.kdbx"), corrupt);
    KdbxFile file;
    EXPECT_THROW(file.Import(GetTmpPath("kdbx3-corrupt-block.kdbx"), key), FormatError);
    std::remove(GetTmpPath("kdbx3-corrupt-block.kdbx").c_str());
  }
}

TEST(KdbxTest, ExportComplex1KeyFileAndPassword) {
  Key key("password");
  key.SetKeyFile(GetTestPath("complex-1-key_pw-aes.key"));

  std::string src_path = GetTestPath("complex-1-key_pw-aes.kdbx");
  std::string dst_path = GetTmpPath("complex-1-key_pw-aes.kdbx");
  std::string json = GetTestJson("complex-1-key_pw-aes.json");

  KdbxFile file;
  std::unique_ptr<Database> db;

  EXPECT_NO_THROW({ db = file.Import(src_path, key); });
  file.Export(dst_path, *db, key);
  EXPECT_NO_THROW({ db = file.Import(dst_path, key); });
  std::remove(dst_path.c_str());

  std::shared_ptr<Group> root = db->root();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), json);
}
