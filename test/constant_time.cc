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

#include <gtest/gtest.h>

#include "libkeepass/detail/constant_time.hh"
#include "libkeepass/secure.hh"

using keepass::secure_string;
using keepass::detail::constant_time_eq;

TEST(ConstantTimeEqTest, EqualRanges) {
  EXPECT_TRUE(
      constant_time_eq("correct horse battery staple", 29, "correct horse battery staple", 29));
}

TEST(ConstantTimeEqTest, DifferingPrefix) {
  EXPECT_FALSE(
      constant_time_eq("correct horse battery staple", 29, "arrect horse battery staple", 29));
}

TEST(ConstantTimeEqTest, DifferingMiddle) {
  EXPECT_FALSE(
      constant_time_eq("correct horse battery staple", 29, "correct horse bettery staple", 29));
}

TEST(ConstantTimeEqTest, DifferingSuffix) {
  EXPECT_FALSE(
      constant_time_eq("correct horse battery staple", 29, "correct horse battery stapla", 29));
}

TEST(ConstantTimeEqTest, DifferentLengths) { EXPECT_FALSE(constant_time_eq("abc", 3, "abcd", 4)); }

TEST(ConstantTimeEqTest, EmptyRanges) {
  EXPECT_TRUE(constant_time_eq(nullptr, 0, nullptr, 0));
  EXPECT_FALSE(constant_time_eq("abc", 3, nullptr, 0));
  EXPECT_FALSE(constant_time_eq(nullptr, 0, "abc", 3));
}

TEST(ConstantTimeEqTest, ArrayOverload) {
  std::array<uint8_t, 32> a;
  a.fill(0x5a);
  std::array<uint8_t, 32> b = a;
  EXPECT_TRUE(constant_time_eq(a, b));

  b[16] ^= 0x01;
  EXPECT_FALSE(constant_time_eq(a, b));
}

TEST(ConstantTimeEqTest, SecureStringEqualityIsConstantTimeBacked) {
  const secure_string a = "correct horse battery staple";
  const secure_string b = "correct horse battery staple";
  EXPECT_TRUE(a == b);
  EXPECT_FALSE(a != b);

  const secure_string c = "correct horse battery stapla";
  EXPECT_FALSE(a == c);
  EXPECT_TRUE(a != c);
}