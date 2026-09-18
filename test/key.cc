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
#include <cstdlib>
#include <fstream>
#include <string>
#include <vector>

#ifndef _WIN32
#include <unistd.h>
#endif

#include <gtest/gtest.h>

#include "config.hh"
#include "libkeepass/exception.hh"
#include "libkeepass/key.hh"
#include "libkeepass/secure.hh"

using namespace keepass;

namespace {

std::string GetTmpPath(const std::string& name) {
  return std::string(PROJECT_ROOT_PATH) + "/tmp/" + name;
}

void SetEnv(const char* name, const char* value) {
#ifdef _WIN32
  _putenv_s(name, value);
#else
  setenv(name, value, 1);
#endif
}

void UnsetEnv(const char* name) {
#ifdef _WIN32
  _putenv_s(name, "");
#else
  unsetenv(name);
#endif
}

void WriteFile(const std::string& path, const std::string& content) {
  std::ofstream file(path, std::ios::out | std::ios::binary | std::ios::trunc);
  file << content;
}

SecureBuffer<32> TransformSeed() {
  const std::array<uint8_t, 32> seed = {{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                         0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                                         0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                                         0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}};
  return {seed};
}

std::vector<uint8_t> DeterministicKeyBytes() {
  std::vector<uint8_t> bytes;
  bytes.reserve(32);
  for (std::size_t i = 0; i < 32; ++i)
    bytes.push_back(static_cast<uint8_t>(0x80 + i));
  return bytes;
}

void WriteHexKeyfile(const std::string& path, bool uppercase) {
  static constexpr const char* kHex = "0123456789abcdef";
  static constexpr const char* kHexUpper = "0123456789ABCDEF";
  std::string content;
  content.reserve(64);
  for (int i = 0; i < 32; ++i) {
    const int byte = (i * 37 + 11) & 0xff;
    const char* table = uppercase ? kHexUpper : kHex;
    content.push_back(table[byte >> 4]);
    content.push_back(table[byte & 0x0f]);
  }
  WriteFile(path, content);
}

} // namespace

TEST(KeyTest, TransformedKeyShortCircuitsDerivation) {
  const std::vector<uint8_t> key_bytes = DeterministicKeyBytes();
  const std::vector<uint8_t> salt_bytes(16, 0x2a);
  Key key(key_bytes);

  const SecureBuffer<32> aes =
      key.Transform(TransformSeed(), 1000, Key::SubKeyResolution::kHashSubKeys);
  EXPECT_TRUE(std::equal(key_bytes.begin(), key_bytes.end(), aes.begin()));

  const SecureBytes salt(salt_bytes);
  const SecureBuffer<32> argon2 = key.TransformArgon2(Key::Kdf::kArgon2id, salt, 2, 1 << 20, 2,
                                                      0x13, Key::SubKeyResolution::kHashSubKeys);
  EXPECT_TRUE(std::equal(key_bytes.begin(), key_bytes.end(), argon2.begin()));
}

TEST(KeyTest, TransformedKeyRejectsInvalidSize) {
  EXPECT_THROW(Key(std::vector<uint8_t>(31, 0)), FormatError);
  EXPECT_THROW(Key(std::vector<uint8_t>(33, 0)), FormatError);
}

TEST(KeyTest, CopiesPreserveTransformedKey) {
  const std::vector<uint8_t> key_bytes = DeterministicKeyBytes();
  Key original(key_bytes);

  // Copy construction of a transformed key keeps the short-circuit behavior.
  Key copy(original); // NOLINT(performance-unnecessary-copy-initialization): intentional copy
  const SecureBuffer<32> copy_out =
      copy.Transform(TransformSeed(), 1000, Key::SubKeyResolution::kHashSubKeys);
  EXPECT_TRUE(std::equal(key_bytes.begin(), key_bytes.end(), copy_out.begin()));

  // Copy assignment of a transformed key does the same.
  Key assigned("password");
  assigned = original;
  const SecureBuffer<32> assigned_out =
      assigned.Transform(TransformSeed(), 1000, Key::SubKeyResolution::kHashSubKeys);
  EXPECT_TRUE(std::equal(key_bytes.begin(), key_bytes.end(), assigned_out.begin()));

  // Copying a plain password key (no transformed key) takes the other branch.
  Key plain("password");
  Key plain_copy(plain); // NOLINT(performance-unnecessary-copy-initialization): intentional copy
  Key plain_assigned("other");
  plain_assigned = plain;
  EXPECT_NO_THROW(
      { (void)plain_copy.Transform(TransformSeed(), 10, Key::SubKeyResolution::kHashSubKeys); });
  EXPECT_NO_THROW({
    (void)plain_assigned.TransformArgon2(Key::Kdf::kArgon2d, SecureBytes(DeterministicKeyBytes()),
                                         3, 1 << 20, 2, 0x10, Key::SubKeyResolution::kHashSubKeys);
  });
}

TEST(KeyTest, SetKeyFileMissingFileThrows) {
  Key key("password");
  EXPECT_THROW(key.SetKeyFile(GetTmpPath("key-test-does-not-exist.key")), FileNotFoundError);
}

TEST(KeyTest, SetKeyFileUnknownFormatThrows) {
  const std::string path = GetTmpPath("key-test-short.key");
  WriteFile(path, "not-a-key-file");
  Key key("password");
  EXPECT_THROW(key.SetKeyFile(path), FormatError);
}

TEST(KeyTest, SetKeyFileInvalidHexThrows) {
  const std::string path = GetTmpPath("key-test-badhex.key");
  WriteFile(path, std::string(64, 'g'));
  Key key("password");
  EXPECT_THROW(key.SetKeyFile(path), FormatError);
}

TEST(KeyTest, SetKeyFileXmlWrongKeySizeThrows) {
  const std::string path = GetTmpPath("key-test-badxml.key");
  WriteFile(path, "<?xml version=\"1.0\"?><KeyFile><Key><Data>AAAA</Data></Key></KeyFile>");
  Key key("password");
  EXPECT_THROW(key.SetKeyFile(path), FormatError);
}

TEST(KeyTest, UppercaseHexKeyfileMatchesLowercase) {
  const std::string lower = GetTmpPath("key-test-lower.key");
  const std::string upper = GetTmpPath("key-test-upper.key");
  WriteHexKeyfile(lower, false);
  WriteHexKeyfile(upper, true);

  Key key_lower("", lower);
  Key key_upper("", upper);
  const SecureBuffer<32> lower_out = key_lower.Transform(
      TransformSeed(), 10, Key::SubKeyResolution::kHashSubKeysOnlyIfCompositeKey);
  const SecureBuffer<32> upper_out = key_upper.Transform(
      TransformSeed(), 10, Key::SubKeyResolution::kHashSubKeysOnlyIfCompositeKey);
  EXPECT_TRUE(std::equal(lower_out.begin(), lower_out.end(), upper_out.begin()));
}

TEST(KeyTest, Argon2InvalidParametersThrow) {
  Key key("password");
  const SecureBytes salt(std::vector<uint8_t>(16, 0x42));
  EXPECT_THROW(key.TransformArgon2(Key::Kdf::kArgon2id, salt, 1, 1 << 20, 0, 0x13,
                                   Key::SubKeyResolution::kHashSubKeys),
               InternalError);
}

TEST(KeyTest, EvpAesKdfFallbackMatchesAesNi) {
  // The AES-NI and the portable EVP paths must produce bit-identical results.
  // The documented LIBKEEPASS_AES_NI=0 override forces the EVP fallback even on
  // AES-NI-capable hosts, so this comparison exercises both implementations.
  Key key("password");
  const SecureBuffer<32> accelerated =
      key.Transform(TransformSeed(), 1000, Key::SubKeyResolution::kHashSubKeys);

  SetEnv("LIBKEEPASS_AES_NI", "0");
  const SecureBuffer<32> fallback =
      key.Transform(TransformSeed(), 1000, Key::SubKeyResolution::kHashSubKeys);
  UnsetEnv("LIBKEEPASS_AES_NI");

  EXPECT_TRUE(std::equal(accelerated.begin(), accelerated.end(), fallback.begin()));
}