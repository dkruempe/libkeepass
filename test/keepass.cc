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
#include <cstdio>
#include <ctime>
#include <fstream>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "config.hh"
#include "libkeepass/database.hh"
#include "libkeepass/entry.hh"
#include "libkeepass/exception.hh"
#include "libkeepass/group.hh"
#include "libkeepass/keepass.hh"
#include "libkeepass/key.hh"
#include "libkeepass/visitor.hh"

using namespace keepass;

namespace {

const std::string kTmpOutput = std::string(PROJECT_ROOT_PATH) + "/tmp/keepass-";

std::string GetDataPath(const std::string& name) {
  return std::string(PROJECT_ROOT_PATH) + "/data/kdbx/" + name;
}

std::string GetKdbDataPath(const std::string& name) {
  return std::string(PROJECT_ROOT_PATH) + "/data/kdb/" + name;
}

std::string GetTmpPath(const std::string& name) { return kTmpOutput + name; }

std::string ReadFile(const std::string& path) {
  std::ifstream file(path, std::ios::in | std::ios::binary);
  return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
}

void WriteFile(const std::string& path, const std::string& data) {
  std::ofstream file(path, std::ios::out | std::ios::binary);
  file.write(data.data(), static_cast<std::streamsize>(data.size()));
}

// Compacts JSON by removing all white space that is not inside a string
// literal.
std::string CompactJson(const std::string& json) {
  char quote = '\0';
  std::string compact;
  for (char c : json) {
    if (quote != '\0') {
      if (c == quote)
        quote = '\0';
      compact.push_back(c);
    } else if (c == '"' || c == '\'') {
      quote = c;
      compact.push_back(c);
    } else if (!std::isspace<char>(c, std::locale::classic())) {
      compact.push_back(c);
    }
  }
  return compact;
}

std::string GetTestJson(const std::string& name) {
  return CompactJson(ReadFile(GetDataPath(name)));
}

std::string GetKdbTestJson(const std::string& name) {
  return CompactJson(ReadFile(std::string(PROJECT_ROOT_PATH) + "/data/kdb/" + name));
}

// Asserts that two databases contain identical structures.
void ExpectSameDatabase(const Database& a, const Database& b) {
  EXPECT_TRUE(*a.root() == *b.root());
  EXPECT_EQ(a.root()->ToJson(), b.root()->ToJson());
}

// Builds a small deterministic database for programmatic export tests.
std::unique_ptr<Database> MakeDatabase(Database::Cipher cipher, Database::Kdf kdf, bool compress) {
  std::unique_ptr<Database> db(new Database());

  std::array<uint8_t, 16> master_seed = {{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
                                          0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}};
  db->set_master_seed(master_seed);

  std::array<uint8_t, 16> init_vector = {{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
                                          0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20}};
  db->set_init_vector(init_vector);

  db->set_cipher(cipher);
  db->set_kdf(kdf);
  db->set_compress(compress);

  if (kdf == Database::Kdf::kAes) {
    std::array<uint8_t, 32> transform_seed = {{0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
                                               0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
                                               0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                                               0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40}};
    db->set_transform_seed(transform_seed);
    db->set_transform_rounds(8192);
  } else {
    db->set_argon2_salt(std::vector<uint8_t>(16, 0x42));
    db->set_argon2_iterations(2);
    db->set_argon2_memory(static_cast<uint64_t>(2) * 1024 * 1024);
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
  db->set_root(root);

  auto alpha = std::make_shared<Entry>();
  alpha->set_title(protect<std::string>("Alpha", false));
  alpha->set_url(protect<std::string>("https://alpha.example", false));
  alpha->set_username(protect<std::string>("alice", false));
  alpha->set_password(protect<std::string>("secret", true));
  alpha->set_creation_time(1700000100);
  root->AddEntry(alpha);

  auto subgroup = std::make_shared<Group>();
  subgroup->set_name("Subgroup");
  subgroup->set_creation_time(1700000200);
  root->AddGroup(subgroup);

  auto beta = std::make_shared<Entry>();
  beta->set_title(protect<std::string>("Beta", false));
  beta->set_username(protect<std::string>("bob", false));
  beta->set_creation_time(1700000300);
  subgroup->AddEntry(beta);

  return db;
}

// Visitor that counts the visited groups and entries.
class CountingVisitor : public Visitor {
public:
  void Visit(Group& group) override {
    ++groups;
    EXPECT_TRUE(group.is_root_group() || !group.parent().expired());
  }

  void Visit(Entry& entry) override { ++entries; }

  size_t groups = 0;
  size_t entries = 0;
};

// Returns the same database as MakeDatabase, but only with entries in
// subgroups. The pre-existing KDB exporter skips the database root group and
// its entries entirely (KeePass 1.x insists entries live in groups), so a KDB
// roundtrip is only structure-preserving when the root carries no entries.
std::unique_ptr<Database> MakeKdbDatabase() {
  std::unique_ptr<Database> db = MakeDatabase(Database::Cipher::kAes, Database::Kdf::kAes, true);
  auto root = db->root();
  for (const auto& entry : root->Entries())
    root->RemoveEntry(entry);
  return db;
}

class KeePassTest : public ::testing::Test {
protected:
  static void TearDownTestSuite() {
    for (const char* name : {"kdbx4.kdbx", "kdbx3.kdbx", "stream.kdbx", "forced.kdb", "forced.kdbx",
                             "saveas.kdbx", "create.kdbx"}) {
      std::remove(GetTmpPath(name).c_str());
    }
  }
};

// ---------- KeePass unifed API ----------

TEST_F(KeePassTest, OpenKdbxAutoDetect) {
  KeePass kp("password");
  std::unique_ptr<Database> db = kp.Open(GetDataPath("groups-2-random_entry-4-pw-aes.kdbx"));
  ASSERT_TRUE(db);
  EXPECT_EQ(db->root()->ToJson(), GetTestJson("groups-2-random_entry-4-pw-aes.json"));
  EXPECT_NE(nullptr, db->FindEntry("semper tellus"));
  EXPECT_NE(nullptr, db->FindGroup("1"));
}

TEST_F(KeePassTest, OpenKdbAutoDetect) {
  KeePass kp("password");
  std::unique_ptr<Database> db = kp.Open(GetKdbDataPath("groups-2-random_entry-4-pw-aes.kdb"));
  ASSERT_TRUE(db);
  EXPECT_EQ(db->root()->ToJson(), GetKdbTestJson("groups-2-random_entry-4-pw-aes.json"));
  EXPECT_NE(nullptr, db->FindEntry("semper tellus"));
}

TEST_F(KeePassTest, OpenFromStream) {
  const std::string data = ReadFile(GetDataPath("groups-2-random_entry-4-pw-aes.kdbx"));
  std::istringstream src(data);
  KeePass kp("password");
  std::unique_ptr<Database> db = kp.Open(src);
  ASSERT_TRUE(db);
  EXPECT_EQ(db->root()->ToJson(), GetTestJson("groups-2-random_entry-4-pw-aes.json"));
}

TEST_F(KeePassTest, OpenMissingFileThrows) {
  KeePass kp("password");
  EXPECT_THROW(kp.Open(GetTmpPath("does-not-exist.kdbx")), FileNotFoundError);
}

TEST_F(KeePassTest, SaveAndReopenKdbx4) {
  std::unique_ptr<Database> db =
      MakeDatabase(Database::Cipher::kAes, Database::Kdf::kArgon2id, true);
  const std::string out = GetTmpPath("kdbx4.kdbx");

  KeePass kp("password");
  kp.Save(out, *db);

  KeePass input("password");
  std::unique_ptr<Database> reopened = input.Open(out);
  ASSERT_TRUE(reopened);
  ExpectSameDatabase(*db, *reopened);
}

TEST_F(KeePassTest, SaveAndReopenKdbx3) {
  std::unique_ptr<Database> db = MakeDatabase(Database::Cipher::kAes, Database::Kdf::kAes, true);
  const std::string out = GetTmpPath("kdbx3.kdbx");

  KeePass kp("password");
  kp.Save(out, *db);

  KeePass input("password");
  std::unique_ptr<Database> reopened = input.Open(out);
  ASSERT_TRUE(reopened);
  ExpectSameDatabase(*db, *reopened);
}

TEST_F(KeePassTest, SaveToStreamAndOpen) {
  std::unique_ptr<Database> db = MakeDatabase(Database::Cipher::kAes, Database::Kdf::kAes, false);

  std::ostringstream dst;
  KeePass kp("password");
  kp.Save(dst, *db);

  std::istringstream src(dst.str());
  std::unique_ptr<Database> reopened = kp.Open(src);
  ASSERT_TRUE(reopened);
  ExpectSameDatabase(*db, *reopened);
}

TEST_F(KeePassTest, SaveToKdbWithoutExtension) {
  std::unique_ptr<Database> db = MakeKdbDatabase();

  KeePass kp("password");
  kp.SetFormat(KeePass::Format::kKdb);
  const std::string out = GetTmpPath("forced.kdb");
  kp.Save(out, *db);
  EXPECT_EQ(KeePass::Format::kKdb, kp.GetFormat());

  KeePass input("password");
  std::unique_ptr<Database> reopened = input.Open(out);
  ASSERT_TRUE(reopened);
  EXPECT_EQ(reopened->EntryCount(), db->EntryCount());
  EXPECT_EQ(reopened->GroupCount(), db->GroupCount());
  EXPECT_NE(nullptr, reopened->FindEntry("Beta"));
}

TEST_F(KeePassTest, SetFormatOverridesExtension) {
  std::unique_ptr<Database> db = MakeKdbDatabase();

  KeePass kp("password");
  kp.SetFormat(KeePass::Format::kKdb);
  const std::string out = GetTmpPath("forced.kdbx");
  kp.Save(out, *db);

  KeePass input("password");
  std::unique_ptr<Database> reopened = input.Open(out);
  ASSERT_TRUE(reopened);
  EXPECT_EQ(reopened->EntryCount(), db->EntryCount());
}

TEST_F(KeePassTest, SaveAsChangesKey) {
  std::unique_ptr<Database> db = MakeDatabase(Database::Cipher::kAes, Database::Kdf::kAes, true);
  const std::string out = GetTmpPath("saveas.kdbx");

  {
    KeePass kp("old_password");
    kp.Save(out, *db);
  }

  {
    KeePass rekey("unused");
    rekey.SaveAs(out, *db, "new_password");
  }

  {
    KeePass old("old_password");
    EXPECT_THROW(old.Open(out), PasswordError);
  }

  KeePass fresh("new_password");
  std::unique_ptr<Database> reopened = fresh.Open(out);
  ASSERT_TRUE(reopened);
  ExpectSameDatabase(*db, *reopened);
}

TEST_F(KeePassTest, CreateDefaults) {
  std::unique_ptr<Database> db = KeePass::Create("password", KeePass::Format::kKdbx4,
                                                 Database::Cipher::kAes, Database::Kdf::kArgon2id);
  ASSERT_TRUE(db);
  ASSERT_TRUE(db->root());
  EXPECT_TRUE(db->root()->is_root_group());
  EXPECT_EQ(Database::Cipher::kAes, db->cipher());
  EXPECT_EQ(Database::Kdf::kArgon2id, db->kdf());
  EXPECT_TRUE(db->compress());
  EXPECT_EQ(64ull * 1024 * 1024, db->argon2_memory());
  EXPECT_EQ(10u, db->argon2_iterations());
  EXPECT_EQ(2u, db->argon2_parallelism());
  EXPECT_EQ(0x13u, db->argon2_version());
  EXPECT_EQ(16u, db->master_seed().size());
  EXPECT_NE(0u, std::count_if(db->master_seed().begin(), db->master_seed().end(),
                              [](uint8_t b) { return b != 0; }));
  EXPECT_NE(0u, std::count_if(db->transform_seed().begin(), db->transform_seed().end(),
                              [](uint8_t b) { return b != 0; }));
  EXPECT_EQ(0u, db->EntryCount());
  EXPECT_EQ(1u, db->GroupCount());
}

TEST_F(KeePassTest, CreateAesUsesTransformRounds) {
  std::unique_ptr<Database> db = KeePass::Create("password", KeePass::Format::kKdbx3,
                                                 Database::Cipher::kAes, Database::Kdf::kAes);
  ASSERT_TRUE(db);
  EXPECT_EQ(600000u, db->transform_rounds());
}

TEST_F(KeePassTest, CreateAndSaveRoundtrip) {
  std::unique_ptr<Database> db = KeePass::Create("password", KeePass::Format::kKdbx3,
                                                 Database::Cipher::kAes, Database::Kdf::kAes);
  db->set_transform_rounds(8192);
  auto entry = db->NewEntry("Roundtrip");
  entry->set_username(protect<std::string>("userA", false));
  entry->set_password(protect<std::string>("pw123", true));
  db->AddEntry(db->root(), entry);

  const std::string out = GetTmpPath("create.kdbx");
  KeePass kp("password");
  kp.Save(out, *db);

  KeePass input("password");
  std::unique_ptr<Database> reopened = input.Open(out);
  ASSERT_TRUE(reopened);
  ExpectSameDatabase(*db, *reopened);
}

// ---------- Key convenience constructors ----------

TEST_F(KeePassTest, CompositeKey) {
  const std::string database = GetDataPath("complex-1-key_pw-aes.kdbx");
  const std::string keyfile = GetDataPath("complex-1-key_pw-aes.key");

  KeePass kp(Key("password", keyfile));
  std::unique_ptr<Database> db = kp.Open(database);
  ASSERT_TRUE(db);

  EXPECT_THROW(
      {
        KeePass bad(Key("wrong", keyfile));
        bad.Open(database);
      },
      PasswordError);
}

TEST_F(KeePassTest, TransformedKey) {
  const std::string path = GetDataPath("groups-2-random_entry-4-pw-aes.kdbx");

  {
    KeePass kp("password");
    std::unique_ptr<Database> db = kp.Open(path);
    ASSERT_TRUE(db);

    Key key("password");
    std::array<uint8_t, 32> transformed = key.Transform(
        db->transform_seed(), db->transform_rounds(), Key::SubKeyResolution::kHashSubKeys);
    std::vector<uint8_t> bytes(transformed.begin(), transformed.end());

    Key derived(bytes);
    KeePass via_derived(derived);
    std::unique_ptr<Database> reopened = via_derived.Open(path);
    ASSERT_TRUE(reopened);
    EXPECT_NE(nullptr, reopened->FindEntry("semper tellus"));
  }
}

// ---------- Database convenience API ----------

TEST_F(KeePassTest, FindEntriesAndGroups) {
  std::unique_ptr<Database> db = MakeDatabase(Database::Cipher::kAes, Database::Kdf::kAes, true);

  EXPECT_EQ(1u, db->FindEntries("alpha").size());
  EXPECT_EQ(1u, db->FindEntries("ALPHA").size());
  EXPECT_EQ(0u, db->FindEntries("not-there").size());
  EXPECT_EQ(2u, db->FindEntries("a").size());
  EXPECT_EQ(1u, db->FindEntries("^alpha$", true).size());
  EXPECT_EQ(1u, db->FindEntries("^BETA$", true).size());

  EXPECT_EQ(1u, db->FindGroups("subgroup").size());
  EXPECT_EQ(1u, db->FindGroups("^SUB.*", true).size());

  EXPECT_NE(nullptr, db->FindEntry("Alpha"));
  EXPECT_EQ(nullptr, db->FindEntry("Nope"));
  EXPECT_NE(nullptr, db->FindGroup("Subgroup"));
  EXPECT_EQ(nullptr, db->FindGroup("Nope"));

  EXPECT_EQ(2u, db->EntryCount());
  EXPECT_EQ(2u, db->GroupCount());
}

TEST_F(KeePassTest, NewAddDeleteEntry) {
  std::unique_ptr<Database> db = MakeDatabase(Database::Cipher::kAes, Database::Kdf::kAes, true);
  const size_t before = db->EntryCount();

  std::shared_ptr<Entry> entry = db->NewEntry("Added");
  db->AddEntry(db->root(), entry);
  ASSERT_TRUE(entry);
  EXPECT_EQ(before + 1, db->EntryCount());
  EXPECT_FALSE(entry->parent().expired());
  EXPECT_EQ("/Root/Added", entry->path());

  db->DeleteEntry(entry->uuid());
  EXPECT_EQ(before, db->EntryCount());
  EXPECT_EQ(nullptr, db->FindEntry("Added"));
}

TEST_F(KeePassTest, NewAddDeleteGroup) {
  std::unique_ptr<Database> db = MakeDatabase(Database::Cipher::kAes, Database::Kdf::kAes, true);
  const size_t before = db->GroupCount();

  std::shared_ptr<Group> group = db->NewGroup("NewGroup");
  db->AddGroup(db->root(), group);
  ASSERT_TRUE(group);
  EXPECT_EQ(before + 1, db->GroupCount());
  EXPECT_FALSE(group->is_root_group());
  EXPECT_EQ("/Root/NewGroup", group->path());

  db->DeleteGroup(group->uuid());
  EXPECT_EQ(before, db->GroupCount());
  EXPECT_EQ(nullptr, db->FindGroup("NewGroup"));
}

TEST_F(KeePassTest, MoveEntry) {
  std::unique_ptr<Database> db = MakeDatabase(Database::Cipher::kAes, Database::Kdf::kAes, true);
  std::shared_ptr<Entry> alpha = db->FindEntry("Alpha");
  std::shared_ptr<Group> subgroup = db->FindGroup("Subgroup");
  ASSERT_TRUE(alpha);
  ASSERT_TRUE(subgroup);

  db->MoveEntry(alpha, subgroup);
  EXPECT_EQ("/Root/Subgroup/Alpha", alpha->path());
  EXPECT_EQ(0u, db->root()->entries_count());
  EXPECT_EQ(2u, subgroup->entries_count());
}

TEST_F(KeePassTest, MoveGroup) {
  std::unique_ptr<Database> db = MakeDatabase(Database::Cipher::kAes, Database::Kdf::kAes, true);
  std::shared_ptr<Group> subgroup = db->FindGroup("Subgroup");

  std::shared_ptr<Group> container = db->NewGroup("Container");
  db->AddGroup(db->root(), container);
  EXPECT_EQ("/Root/Container", container->path());

  db->MoveGroup(subgroup, container);
  EXPECT_EQ("/Root/Container/Subgroup", subgroup->path());

  // A group must not be moved into its own subtree; this is a no-op.
  db->MoveGroup(container, subgroup);
  EXPECT_EQ("/Root/Container", container->path());
  EXPECT_EQ("/Root/Container/Subgroup", subgroup->path());
}

TEST_F(KeePassTest, RecycleBin) {
  std::unique_ptr<Database> db = MakeDatabase(Database::Cipher::kAes, Database::Kdf::kAes, true);
  EXPECT_FALSE(db->IsRecycleBinEnabled());
  db->EnableRecycleBin(true);
  EXPECT_TRUE(db->IsRecycleBinEnabled());
  EXPECT_EQ(3u, db->GroupCount());

  std::shared_ptr<Entry> alpha = db->FindEntry("Alpha");
  ASSERT_TRUE(alpha);
  db->TrashEntry(alpha);
  EXPECT_EQ(1u, db->FindGroup("Recycle Bin")->entries_count());

  std::shared_ptr<Group> subgroup = db->FindGroup("Subgroup");
  ASSERT_TRUE(subgroup);
  db->TrashGroup(subgroup);
  EXPECT_EQ("/Root/Recycle Bin/Subgroup", subgroup->path());
  EXPECT_EQ(1u, db->FindGroup("Recycle Bin")->groups_count());

  db->EmptyRecycleBin();
  EXPECT_EQ(0u, db->FindGroup("Recycle Bin")->entries_count());
  EXPECT_EQ(0u, db->FindGroup("Recycle Bin")->groups_count());
  EXPECT_EQ(0u, db->EntryCount());
}

TEST_F(KeePassTest, DeleteGroupRemovesSubtree) {
  std::unique_ptr<Database> db = MakeDatabase(Database::Cipher::kAes, Database::Kdf::kAes, true);
  std::shared_ptr<Group> subgroup = db->FindGroup("Subgroup");
  ASSERT_TRUE(subgroup);

  db->DeleteGroup(subgroup->uuid());
  EXPECT_EQ(nullptr, db->FindGroup("Subgroup"));
  EXPECT_EQ(nullptr, db->FindEntry("Beta"));
  EXPECT_EQ(1u, db->EntryCount());
  EXPECT_EQ(1u, db->GroupCount());
}

TEST_F(KeePassTest, ToJsonAndVisit) {
  std::unique_ptr<Database> db = MakeDatabase(Database::Cipher::kAes, Database::Kdf::kAes, true);

  std::string json = db->ToJson();
  EXPECT_EQ('{', json[0]);
  EXPECT_NE(std::string::npos, json.find("Alpha"));

  CountingVisitor visitor;
  db->Visit(visitor);
  EXPECT_EQ(2u, visitor.groups);
  EXPECT_EQ(2u, visitor.entries);

  // The free-function visitor over the root behaves identically.
  CountingVisitor direct;
  Visit(*db->root(), direct);
  EXPECT_EQ(visitor.groups, direct.groups);
  EXPECT_EQ(visitor.entries, direct.entries);
}

TEST_F(KeePassTest, PrintVisitorOutput) {
  std::unique_ptr<Database> db = MakeDatabase(Database::Cipher::kAes, Database::Kdf::kAes, true);

  std::ostringstream os;
  PrintVisitor printer(os);
  db->Visit(printer);

  const std::string output = os.str();
  EXPECT_NE(std::string::npos, output.find("Root"));
  EXPECT_NE(std::string::npos, output.find("Subgroup/Beta"));
}

// ---------- Entry convenience API ----------

TEST_F(KeePassTest, EntryCustomProperties) {
  std::unique_ptr<Database> db = MakeDatabase(Database::Cipher::kAes, Database::Kdf::kAes, true);
  std::shared_ptr<Entry> entry = db->FindEntry("Alpha");
  ASSERT_TRUE(entry);

  EXPECT_TRUE(entry->HasString("Title"));
  EXPECT_EQ("Alpha", entry->GetString("Title"));
  EXPECT_EQ("alice", entry->GetString("UserName"));
  EXPECT_FALSE(entry->HasString("MyField"));
  EXPECT_EQ("", entry->GetString("MyField"));

  entry->set_custom_property("MyField", "my-value");
  EXPECT_TRUE(entry->HasString("MyField"));
  EXPECT_EQ("my-value", entry->GetString("MyField"));
  EXPECT_EQ("my-value", entry->custom_properties()["MyField"]);

  entry->set_custom_property("MyField", "updated");
  EXPECT_EQ("updated", entry->GetString("MyField"));
  EXPECT_EQ(1u, entry->custom_properties().size());

  entry->delete_custom_property("MyField");
  EXPECT_FALSE(entry->HasString("MyField"));
  EXPECT_EQ(0u, entry->custom_properties().size());
}

TEST_F(KeePassTest, EntryBinaryProperties) {
  std::unique_ptr<Database> db = MakeDatabase(Database::Cipher::kAes, Database::Kdf::kAes, true);
  std::shared_ptr<Entry> entry = db->FindEntry("Alpha");
  ASSERT_TRUE(entry);

  const std::vector<uint8_t> data = {{0xde, 0xad, 0xbe, 0xef}};
  EXPECT_TRUE(entry->get_binary_property("att").empty());

  entry->set_binary_property("att", data);
  EXPECT_EQ(data, entry->get_binary_property("att"));

  const std::vector<uint8_t> other = {{0x01, 0x02}};
  entry->set_binary_property("att", other);
  EXPECT_EQ(other, entry->get_binary_property("att"));

  entry->delete_binary_property("att");
  EXPECT_TRUE(entry->get_binary_property("att").empty());
}

TEST_F(KeePassTest, EntryHistoryAndTouch) {
  std::unique_ptr<Database> db = MakeDatabase(Database::Cipher::kAes, Database::Kdf::kAes, true);
  std::shared_ptr<Entry> entry = db->FindEntry("Alpha");
  ASSERT_TRUE(entry);

  EXPECT_EQ(0u, entry->history().size());
  entry->save_history();
  EXPECT_EQ(1u, entry->history().size());
  EXPECT_EQ(0, entry->history()[0]->parent().use_count());
  EXPECT_EQ(0u, entry->history()[0]->history().size());

  entry->delete_history();
  EXPECT_EQ(0u, entry->history().size());

  const std::time_t before_access = entry->access_time();
  entry->touch();
  EXPECT_GE(entry->access_time(), before_access);

  const std::time_t before_modify = entry->modification_time();
  entry->touch(true);
  EXPECT_GE(entry->modification_time(), before_modify);
}

// ---------- Group convenience API ----------

TEST_F(KeePassTest, GroupPathAndParent) {
  std::unique_ptr<Database> db = MakeDatabase(Database::Cipher::kAes, Database::Kdf::kAes, true);

  std::shared_ptr<Group> root = db->root();
  ASSERT_TRUE(root);
  EXPECT_TRUE(root->is_root_group());
  EXPECT_EQ("/Root", root->path());
  EXPECT_TRUE(root->parent().expired());

  std::shared_ptr<Group> subgroup = db->FindGroup("Subgroup");
  ASSERT_TRUE(subgroup);
  EXPECT_FALSE(subgroup->is_root_group());
  EXPECT_EQ("/Root/Subgroup", subgroup->path());
  ASSERT_FALSE(subgroup->parent().expired());
  EXPECT_TRUE(subgroup->parent().lock() == root);

  std::shared_ptr<Entry> beta = db->FindEntry("Beta");
  ASSERT_TRUE(beta);
  EXPECT_EQ("/Root/Subgroup/Beta", beta->path());
  ASSERT_FALSE(beta->parent().expired());
  EXPECT_TRUE(beta->parent().lock() == subgroup);

  // Entries directly in the root only carry the root in their path.
  std::shared_ptr<Entry> alpha = db->FindEntry("Alpha");
  ASSERT_TRUE(alpha);
  EXPECT_EQ("/Root/Alpha", alpha->path());
}

TEST_F(KeePassTest, GroupFindEntriesNonRecursive) {
  std::unique_ptr<Database> db = MakeDatabase(Database::Cipher::kAes, Database::Kdf::kAes, true);

  EXPECT_EQ(2u, db->root()->FindEntries("a").size());
  EXPECT_EQ(1u, db->root()->FindEntries("a", false, false).size());
  EXPECT_EQ(1u, db->FindGroup("Subgroup")->FindEntries("beta").size());
  EXPECT_EQ(0u, db->FindGroup("Subgroup")->FindEntries("alpha", false, false).size());
}

} // namespace