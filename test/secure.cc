/*
 * libkeepass - KeePass key database importer/exporter
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
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include "libkeepass/binary.hh"
#include "libkeepass/entry.hh"
#include "libkeepass/secure.hh"
#include "libkeepass/security.hh"

using namespace keepass;

TEST(SecureZeroTest, WipesBuffer) {
  uint8_t buf[8];
  std::memset(buf, 0xAB, sizeof(buf));
  secure_zero(buf, sizeof(buf));
  for (uint8_t byte : buf)
    EXPECT_EQ(byte, 0U);
}

TEST(SecureZeroTest, HandlesZeroLength) {
  uint8_t buf[4] = {1, 2, 3, 4};
  secure_zero(buf, 0);
  EXPECT_EQ(buf[0], 1U);
}

TEST(SecureStringTest, DefaultConstruction) {
  secure_string s;
  EXPECT_TRUE(s.empty());
  EXPECT_EQ(s.size(), 0U);
  EXPECT_STREQ(s.c_str(), "");
}

TEST(SecureStringTest, CStringConstruction) {
  secure_string s("hello");
  EXPECT_FALSE(s.empty());
  EXPECT_EQ(s.size(), 5U);
  EXPECT_STREQ(s.c_str(), "hello");
}

TEST(SecureStringTest, StdStringConstruction) {
  std::string orig("world");
  secure_string s(orig);
  EXPECT_EQ(s.size(), 5U);
  EXPECT_STREQ(s.c_str(), "world");
}

TEST(SecureStringTest, CopyAndCompare) {
  secure_string a("alpha");
  secure_string b(a);
  b.data()[0] = 'z';
  EXPECT_NE(a, b);
  EXPECT_EQ(a.size(), b.size());

  secure_string c;
  c = b;
  EXPECT_EQ(b, c);
}

TEST(SecureStringTest, MoveSemantics) {
  secure_string a("test");
  secure_string b(std::move(a));
  EXPECT_EQ(b, "test");
}

TEST(SecureStringTest, StrMethod) {
  secure_string s("value");
  std::string out = s.str();
  EXPECT_EQ(out, "value");
}

TEST(SecureStringTest, ComparisonsAgainstStrings) {
  secure_string s("abc");
  EXPECT_EQ(s, "abc");
  EXPECT_EQ(s, std::string("abc"));
  EXPECT_NE(s, "xyz");
  EXPECT_NE(s, std::string("xyz"));
  EXPECT_TRUE(s == "abc");
  EXPECT_TRUE(s != "xyz");
}

TEST(SecureStringTest, BeginEndIterators) {
  secure_string s("abcd");
  EXPECT_NE(s.begin(), s.end());
  EXPECT_EQ(s.end() - s.begin(), static_cast<std::ptrdiff_t>(s.size()));

  std::size_t i = 0;
  for (auto* it = s.begin(); it != s.end(); ++it)
    ++i;
  EXPECT_EQ(i, s.size());
}

TEST(SecureStringTest, OstreamOutput) {
  secure_string s("output");
  std::ostringstream oss;
  oss << s;
  EXPECT_EQ(oss.str(), "output");
}

TEST(SecureBufferTest, MoveConstruction) {
  SecureBuffer<32> a;
  std::array<uint8_t, 32> ref{};
  ref[0] = 0x42;
  std::memcpy(a.data(), ref.data(), 32);

  SecureBuffer<32> b(std::move(a));
  EXPECT_EQ(b[0], 0x42);
}

TEST(SecureBufferTest, MoveAssignment) {
  SecureBuffer<32> a;
  a[5] = 0x99;
  SecureBuffer<32> b;
  b = std::move(a);
  EXPECT_EQ(b[5], 0x99);
}

TEST(SecureBufferTest, CloneDeepCopy) {
  SecureBuffer<16> a;
  a.fill(0xAB);
  SecureBuffer<16> b = a.Clone();
  EXPECT_EQ(b[0], 0xAB);
  b[0] = 0x00;
  EXPECT_EQ(a[0], 0xAB);
}

TEST(SecureBufferTest, FillAndAccess) {
  SecureBuffer<64> buf;
  buf.fill(0xFF);
  for (uint8_t byte : buf)
    EXPECT_EQ(byte, 0xFFU);
}

TEST(SecureBufferTest, BeginEnd) {
  SecureBuffer<16> buf;
  buf.fill(0x10);
  EXPECT_NE(buf.begin(), buf.end());
  EXPECT_EQ(buf.end() - buf.begin(), 16);
  *buf.begin() = 0x20;
  EXPECT_EQ(buf[0], 0x20);
}

TEST(SecureBufferTest, SizeConsistency) {
  SecureBuffer<32> buf;
  EXPECT_EQ(buf.size(), 32U);
  EXPECT_EQ(static_cast<std::size_t>(buf.end() - buf.begin()), buf.size());
}

TEST(SecureBufferTest, MoveConstructionWipesSource) {
  SecureBuffer<32> a;
  a.fill(0x7F);
  SecureBuffer<32> b(std::move(a));
  EXPECT_EQ(b[0], 0x7FU);
  for (uint8_t byte : a) // NOLINT(bugprone-use-after-move, clang-analyzer-cplusplus.Move)
    EXPECT_EQ(byte, 0U);
}

TEST(SecureBufferTest, MoveAssignmentWipesSource) {
  SecureBuffer<32> a;
  a.fill(0x5A);
  SecureBuffer<32> b;
  b.fill(0xFF);
  b = std::move(a);
  EXPECT_EQ(b[0], 0x5AU);
  for (uint8_t byte : a) // NOLINT(bugprone-use-after-move, clang-analyzer-cplusplus.Move)
    EXPECT_EQ(byte, 0U);
}

TEST(SecureStringTest, MoveWipesSource) {
  secure_string a("sensitive-value");
  secure_string b(std::move(a));
  EXPECT_EQ(b, "sensitive-value");
  EXPECT_TRUE(a.empty()); // NOLINT(bugprone-use-after-move)
}

TEST(SecureStringTest, ClearWipesContent) {
  secure_string s("top-secret");
  s.clear();
  EXPECT_TRUE(s.empty());
}

TEST(ProtectTest, FlagAndValueRoundtrip) {
  protect<secure_string> p(secure_string("secret"), true);
  EXPECT_TRUE(p.is_protected());
  EXPECT_EQ(p.value(), "secret");

  p.set_value(secure_string("other"));
  EXPECT_EQ(p.value(), "other");
  EXPECT_TRUE(p.is_protected());

  p.set_protected(false);
  EXPECT_FALSE(p.is_protected());
}

TEST(BinaryTest, ConstructStoresProtectedData) {
  protect<secure_string> payload(secure_string("attachment bytes"), true);
  Binary binary(payload);

  EXPECT_EQ(binary.Size(), static_cast<std::size_t>(16));
  EXPECT_FALSE(binary.Empty());
  EXPECT_EQ(*binary.data(), "attachment bytes");
  EXPECT_TRUE(binary.data().is_protected());
  EXPECT_FALSE(binary.compress());
}

TEST(BinaryTest, CompressFlagRoundtrip) {
  Binary binary(protect<secure_string>(secure_string("abc"), true));
  EXPECT_FALSE(binary.compress());
  binary.set_compress(true);
  EXPECT_TRUE(binary.compress());
}

TEST(BinaryTest, SetDataReplacesPayload) {
  const std::string replacement(200, 'x');
  Binary binary(protect<secure_string>(secure_string("sensitive payload"), true));
  ASSERT_EQ(*binary.data(), "sensitive payload");
  ASSERT_EQ(binary.Size(), static_cast<std::size_t>(17));

  // A new allocation must be made for the replacement value; the old buffer
  // is handed to secure_free(), which zeroizes it, before the new one is
  // stored (see secure_string::Allocate/Release).
  const char* old_storage = binary.data()->c_str();

  binary.set_data(protect<secure_string>(secure_string(replacement), true));
  EXPECT_EQ(*binary.data(), replacement);
  EXPECT_EQ(binary.Size(), replacement.size());
  EXPECT_NE(binary.data()->c_str(), old_storage);
}

TEST(BinaryTest, EmptySetDataMarksEmpty) {
  Binary binary(protect<secure_string>(secure_string("data"), true));
  EXPECT_FALSE(binary.Empty());

  binary.set_data(protect<secure_string>(secure_string(), true));
  EXPECT_TRUE(binary.Empty());
  EXPECT_EQ(binary.Size(), 0U);
}

TEST(AttachmentTest, SetAndGetBinaryProperty) {
  Entry entry;

  const std::vector<uint8_t> payload = {0x50, 0x4b, 0x03, 0x04, 0x00, 0x2a};
  entry.set_binary_property("file.zip", payload);

  ASSERT_TRUE(entry.HasAttachment());
  ASSERT_EQ(entry.attachments().size(), 1U);
  EXPECT_EQ(entry.attachments()[0]->name(), "file.zip");
  ASSERT_NE(entry.attachments()[0]->binary(), nullptr);
  EXPECT_TRUE(entry.attachments()[0]->binary()->data().is_protected());
  EXPECT_EQ(entry.attachments()[0]->binary()->data().value().str(),
            std::string(payload.begin(), payload.end()));

  EXPECT_EQ(entry.get_binary_property("file.zip"), payload);
  EXPECT_TRUE(entry.get_binary_property("missing.bin").empty());
}

TEST(AttachmentTest, ReplaceBinaryPropertyKeepsSingleAttachment) {
  const std::vector<uint8_t> replacement(200, 0x7a);
  Entry entry;
  entry.set_binary_property("file.bin", std::vector<uint8_t>({'o', 'l', 'd'}));

  const char* old_storage = entry.attachments()[0]->binary()->data()->c_str();

  entry.set_binary_property("file.bin", replacement);

  ASSERT_EQ(entry.attachments().size(), 1U);
  EXPECT_EQ(entry.attachments()[0]->binary()->data().value().str(),
            std::string(replacement.begin(), replacement.end()));
  EXPECT_NE(entry.attachments()[0]->binary()->data()->c_str(), old_storage);
}

TEST(AttachmentTest, DeleteBinaryPropertyRemovesAttachment) {
  Entry entry;
  entry.set_binary_property("file.bin", std::vector<uint8_t>({0x01, 0x02}));
  ASSERT_TRUE(entry.HasAttachment());

  entry.delete_binary_property("file.bin");
  EXPECT_FALSE(entry.HasAttachment());
  EXPECT_TRUE(entry.attachments().empty());
  EXPECT_TRUE(entry.get_binary_property("file.bin").empty());
}
