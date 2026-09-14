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

#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "config.hh"
#include "libkeepass/database.hh"
#include "libkeepass/entry.hh"
#include "libkeepass/group.hh"
#include "libkeepass/keepass.hh"
#include "libkeepass/key.hh"
#include "libkeepass/metadata.hh"

using namespace keepass;

namespace {

// Path prefix for third-party interop fixtures under data/compat/. The files
// are unmodified copies of fixtures published by the respective applications.
std::string GetCompatPath(const std::string& name) {
  return std::string(PROJECT_ROOT_PATH) + "/data/compat/" + name;
}

const std::vector<std::shared_ptr<Entry>>& Entries(const std::shared_ptr<Group>& group) {
  return group->Entries();
}

std::shared_ptr<Group> FindGroup(const std::shared_ptr<Group>& root, const std::string& name) {
  for (const auto& group : root->Groups()) {
    if (group->name() == name)
      return group;
  }
  return nullptr;
}

} // namespace

// Format400.kdbx is a fixture from KeePassXC's test suite (tests/data/), see
// keepassxreboot/keepassxc TestKdbx4::testFormat400. KeePassXC writes KDBX 4.0
// databases with ChaCha20 + Argon2d and Gzip compression by default, which
// differs from KeePass' own AES + Argon2 defaults.
TEST(CompatTest, KeePassXcFormat400) {
  KeePass keeper(Key("t"));
  std::unique_ptr<Database> db;
  EXPECT_NO_THROW({ db = keeper.Open(GetCompatPath("Format400.kdbx")); });

  ASSERT_NE(db, nullptr);
  EXPECT_EQ(db->cipher(), Database::Cipher::kChaCha20);
  EXPECT_EQ(db->kdf(), Database::Kdf::kArgon2d);
  EXPECT_EQ(db->compress(), true);

  ASSERT_TRUE(db->root());
  EXPECT_EQ(db->root()->name(), "Format400");

  const auto& entries = Entries(db->root());
  ASSERT_EQ(entries.size(), 1U);
  const auto& entry = entries.front();

  EXPECT_EQ(entry->title().value().str(), "Format400");
  EXPECT_EQ(entry->username().value().str(), "Format400");
  EXPECT_EQ(entry->password().value().str(), "Format400");

  const auto& attachments = entry->attachments();
  ASSERT_EQ(attachments.size(), 1U);
  EXPECT_EQ(attachments[0]->name(), "Format400");
  ASSERT_NE(attachments[0]->binary(), nullptr);
  EXPECT_EQ(*attachments[0]->binary()->data(), "Format400\n");
}

// ProtectedStrings.kdbx is a fixture from KeePassXC's test suite (tests/data/),
// see keepassxreboot/keepassxc TestKdbx3::testProtectedStrings. The database is
// a KDBX 3.1 file that stores custom attributes with a per-field protection
// flag and a protected password field.
TEST(CompatTest, KeePassXcProtectedStrings) {
  KeePass keeper(Key("masterpw"));
  std::unique_ptr<Database> db;
  EXPECT_NO_THROW({ db = keeper.Open(GetCompatPath("ProtectedStrings.kdbx")); });

  ASSERT_NE(db, nullptr);
  EXPECT_EQ(db->cipher(), Database::Cipher::kAes);
  EXPECT_EQ(db->kdf(), Database::Kdf::kAes);

  ASSERT_TRUE(db->root());
  const auto& entries = Entries(db->root());
  ASSERT_EQ(entries.size(), 1U);
  const auto& entry = entries.front();

  EXPECT_EQ(entry->title().value().str(), "Sample Entry");
  EXPECT_EQ(entry->username().value().str(), "Protected User Name");
  EXPECT_EQ(entry->password().value().str(), "ProtectedPassword");

  bool saw_protected = false;
  bool saw_unprotected = false;
  for (const auto& field : entry->custom_fields()) {
    if (field.key() == "TestProtected") {
      EXPECT_EQ(field.value().value().str(), "ABC");
      EXPECT_EQ(field.value().is_protected(), true);
      saw_protected = true;
    } else if (field.key() == "TestUnprotected") {
      EXPECT_EQ(field.value().value().str(), "DEF");
      EXPECT_EQ(field.value().is_protected(), false);
      saw_unprotected = true;
    }
  }
  EXPECT_TRUE(saw_protected);
  EXPECT_TRUE(saw_unprotected);
}

// RecycleBinWithData.kdbx is a fixture from KeePassXC's test suite
// (tests/data/), see keepassxreboot/keepassxc TestDatabase. The database keeps
// a configured recycle bin group that already contains deleted entries, which
// must be returned as ordinary entries of a regular group.
TEST(CompatTest, KeePassXcRecycleBinWithData) {
  KeePass keeper(Key("123"));
  std::unique_ptr<Database> db;
  EXPECT_NO_THROW({ db = keeper.Open(GetCompatPath("RecycleBinWithData.kdbx")); });

  ASSERT_NE(db, nullptr);
  ASSERT_TRUE(db->root());

  ASSERT_TRUE(db->meta());
  const auto& bin = db->meta()->recycle_bin();
  ASSERT_NE(bin, nullptr);
  EXPECT_EQ(bin->name(), "Recycle Bin");

  const auto& bin_entries = Entries(bin);
  ASSERT_EQ(bin_entries.size(), 2U);
  EXPECT_EQ(bin_entries[0]->title().value().str(), "Obsolete e-mail");
  EXPECT_EQ(bin_entries[1]->title().value().str(), "Old Wi-fi");

  for (const std::string& group_name : {"Mail", "Network", "Computer logins"}) {
    const auto& group = FindGroup(db->root(), group_name);
    ASSERT_NE(group, nullptr) << group_name;
    EXPECT_FALSE(Entries(group).empty()) << group_name;
  }
}