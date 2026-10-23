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

#include <gtest/gtest.h>

#include "libkeepass/entry.hh"
#include "libkeepass/totp.hh"

namespace keepass {
namespace {

constexpr const char* kSha1Secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
constexpr const char* kSha256Secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA====";
constexpr const char* kSha512Secret =
    "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZD"
    "GNBVGY3TQOJQGEZDGNA=";

TEST(Totp, Rfc6238Sha1Vectors) {
  const TotpConfig config(secure_string(kSha1Secret), 30, 8);
  ASSERT_EQ(8U, config.digits());

  EXPECT_EQ("94287082", Totp::Generate(config, 59));
  EXPECT_EQ("07081804", Totp::Generate(config, 1111111109));
  EXPECT_EQ("14050471", Totp::Generate(config, 1111111111));
  EXPECT_EQ("89005924", Totp::Generate(config, 1234567890));
  EXPECT_EQ("69279037", Totp::Generate(config, 2000000000));
  EXPECT_EQ("65353130", Totp::Generate(config, 20000000000LL));
}

TEST(Totp, Rfc6238Sha256AndSha512Vectors) {
  const TotpConfig sha256(secure_string(kSha256Secret), 30, 8, TotpConfig::Algorithm::kSha256);
  EXPECT_EQ("46119246", Totp::Generate(sha256, 59));
  EXPECT_EQ("68084774", Totp::Generate(sha256, 1111111109));
  EXPECT_EQ("67062674", Totp::Generate(sha256, 1111111111));
  EXPECT_EQ("91819424", Totp::Generate(sha256, 1234567890));
  EXPECT_EQ("90698825", Totp::Generate(sha256, 2000000000));
  EXPECT_EQ("77737706", Totp::Generate(sha256, 20000000000LL));

  const TotpConfig sha512(secure_string(kSha512Secret), 30, 8, TotpConfig::Algorithm::kSha512);
  EXPECT_EQ("90693936", Totp::Generate(sha512, 59));
  EXPECT_EQ("25091201", Totp::Generate(sha512, 1111111109));
  EXPECT_EQ("99943326", Totp::Generate(sha512, 1111111111));
  EXPECT_EQ("93441116", Totp::Generate(sha512, 1234567890));
  EXPECT_EQ("38618901", Totp::Generate(sha512, 2000000000));
  EXPECT_EQ("47863826", Totp::Generate(sha512, 20000000000LL));
}

TEST(Totp, ParsesUriAndSettings) {
  const auto uri = TotpConfig::Parse(
      "otpauth://totp/Example:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&period=60&digits=7"
      "&algorithm=SHA256");
  ASSERT_TRUE(uri.has_value());
  if (uri.has_value()) {
    EXPECT_EQ("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", uri->secret().str());
    EXPECT_EQ(60U, uri->period());
    EXPECT_EQ(7U, uri->digits());
    EXPECT_EQ(TotpConfig::Algorithm::kSha256, uri->algorithm());
  }

  const auto positional = TotpConfig::Parse(kSha1Secret, "30;8");
  ASSERT_TRUE(positional.has_value());
  if (positional.has_value()) {
    EXPECT_EQ(30U, positional->period());
    EXPECT_EQ(8U, positional->digits());
  }

  const auto named = TotpConfig::Parse(kSha1Secret, "period=60&digits=8&algorithm=SHA512");
  ASSERT_TRUE(named.has_value());
  if (named.has_value()) {
    EXPECT_EQ(60U, named->period());
    EXPECT_EQ(8U, named->digits());
    EXPECT_EQ(TotpConfig::Algorithm::kSha512, named->algorithm());
  }

  EXPECT_FALSE(TotpConfig::Parse(""));
  EXPECT_FALSE(TotpConfig::Parse("not base32!"));
  EXPECT_FALSE(TotpConfig::Parse("otpauth://hotp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"));
}

TEST(Totp, EntryHelpersAndRemainingSeconds) {
  Entry entry;
  EXPECT_FALSE(entry.totp());
  EXPECT_TRUE(entry.totp_code(59).empty());

  entry.set_custom_property("otp", kSha1Secret);
  entry.set_custom_property("TOTP Settings", "30;8;SHA1");
  const auto config = entry.totp();
  ASSERT_TRUE(config.has_value());
  if (config.has_value()) {
    EXPECT_EQ(8U, config->digits());
    EXPECT_EQ("94287082", entry.totp_code(59));
    EXPECT_EQ(1U, Totp::SecondsRemaining(*config, 59));
    EXPECT_EQ(30U, Totp::SecondsRemaining(*config, 60));
  }
}

} // namespace
} // namespace keepass
