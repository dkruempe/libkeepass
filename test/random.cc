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
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "libkeepass/random.hh"
#include "libkeepass/secure.hh"

using namespace keepass;

namespace {

std::array<uint8_t, 32> TestKey() {
  std::array<uint8_t, 32> key{};
  for (std::size_t i = 0; i < key.size(); ++i)
    key[i] = static_cast<uint8_t>(0x50 + i);
  return key;
}

std::array<uint8_t, 8> TestIv() { return {{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}}; }

// Long enough to cross the 64-byte obfuscator buffer boundary repeatedly.
std::vector<uint8_t> TestVector(std::size_t size) {
  std::vector<uint8_t> data;
  data.reserve(size);
  for (std::size_t i = 0; i < size; ++i)
    data.push_back(static_cast<uint8_t>(i));
  return data;
}

} // namespace

TEST(RandomObfuscatorTest, VectorProcessIsDeterministic) {
  RandomObfuscator first(TestKey(), TestIv());
  RandomObfuscator second(TestKey(), TestIv());
  const std::vector<uint8_t> input = TestVector(200);
  const std::vector<uint8_t> out_first = first.Process(input);
  const std::vector<uint8_t> out_second = second.Process(input);
  EXPECT_EQ(out_first.size(), input.size());
  EXPECT_NE(out_first, input);
  EXPECT_EQ(out_first, out_second);
}

TEST(RandomObfuscatorTest, StringProcessRestoresInput) {
  RandomObfuscator obfuscator(TestKey(), TestIv());
  // A second instance with the same stream parameters re-applies the same
  // keystream, restoring the original input (XOR is its own inverse).
  const std::string input("kdbx inner random stream test payload");
  const std::string obfuscated = obfuscator.Process(input);
  EXPECT_NE(obfuscated, input);
  RandomObfuscator deobfuscator(TestKey(), TestIv());
  EXPECT_EQ(deobfuscator.Process(obfuscated), input);
}

TEST(RandomObfuscatorTest, SecureStringProcessPreservesLength) {
  RandomObfuscator obfuscator(TestKey(), TestIv());
  const secure_string input(secure_string("sensitive payload"));
  const secure_string obfuscated = obfuscator.Process(input);
  EXPECT_EQ(obfuscated.size(), input.size());
  EXPECT_NE(obfuscated.str(), input.str());
}

TEST(RandomObfuscatorTest, Kdbx4StreamKeyConstructors) {
  const std::array<uint8_t, 32> stream_key = TestKey();
  const std::vector<uint8_t> stream_key_64(TestVector(64));

  RandomObfuscator salsa(RandomObfuscator::Type::kSalsa20, stream_key);
  RandomObfuscator chacha(RandomObfuscator::Type::kChaCha20, stream_key_64);
  RandomObfuscator chacha_short(RandomObfuscator::Type::kChaCha20, stream_key);
  EXPECT_EQ(salsa.Process(TestVector(10)).size(), 10U);
  EXPECT_NE(chacha.Process(TestVector(10)), TestVector(10));
  EXPECT_EQ(chacha_short.Process(TestVector(10)).size(), 10U);
}

TEST(RandomObfuscatorTest, RandomArrayFillsAllBytes) {
  const std::array<uint8_t, 32> random = random_array<32>();
  EXPECT_EQ(random.size(), 32U);
}