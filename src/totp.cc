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

#include "libkeepass/totp.hh"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <vector>

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "libkeepass/entry.hh"
#include "libkeepass/secure.hh"

namespace keepass {

namespace {

std::string Lower(std::string value) {
  for (char& c : value)
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return value;
}

/// Decodes an RFC 4648 Base32 string, ignoring whitespace, hyphens and
/// trailing padding. Returns an empty vector for invalid input.
std::vector<uint8_t> Base32Decode(const secure_string& secret) {
  std::vector<uint8_t> decoded;
  uint32_t buffer = 0;
  unsigned bits = 0;
  bool saw_data = false;

  for (const char c : secret) {
    if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '-')
      continue;
    if (c == '=')
      break;

    uint32_t value = 0;
    if (c >= 'A' && c <= 'Z')
      value = static_cast<uint32_t>(c - 'A');
    else if (c >= 'a' && c <= 'z')
      value = static_cast<uint32_t>(c - 'a');
    else if (c >= '2' && c <= '7')
      value = static_cast<uint32_t>(c - '2' + 26);
    else
      return {};

    saw_data = true;
    buffer = (buffer << 5) | value;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      decoded.push_back(static_cast<uint8_t>((buffer >> bits) & 0xff));
    }
  }

  if (!saw_data)
    return {};
  return decoded;
}

std::optional<uint32_t> ParseUInt32(const std::string& value) {
  if (value.empty())
    return std::nullopt;
  char* end = nullptr;
  const unsigned long parsed = std::strtoul(value.c_str(), &end, 10);
  if (end == value.c_str() || *end != '\0' || parsed > 0xffffffffUL)
    return std::nullopt;
  return static_cast<uint32_t>(parsed);
}

std::string UriDecode(const std::string& value) {
  std::string decoded;
  decoded.reserve(value.size());
  for (std::size_t i = 0; i < value.size(); ++i) {
    if (value[i] == '%' && i + 2 < value.size()) {
      const auto hex = [](char c) -> int {
        if (c >= '0' && c <= '9')
          return c - '0';
        if (c >= 'a' && c <= 'f')
          return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
          return c - 'A' + 10;
        return -1;
      };
      const int hi = hex(value[i + 1]);
      const int lo = hex(value[i + 2]);
      if (hi >= 0 && lo >= 0) {
        decoded.push_back(static_cast<char>((hi << 4) | lo));
        i += 2;
        continue;
      }
    }
    decoded.push_back(value[i] == '+' ? ' ' : value[i]);
  }
  return decoded;
}

void SplitParameters(const std::string& value, std::vector<std::string>& tokens) {
  std::string current;
  for (const char c : value) {
    if (c == '&' || c == ';' || c == ',') {
      if (!current.empty())
        tokens.push_back(current);
      current.clear();
    } else {
      current.push_back(c);
    }
  }
  if (!current.empty())
    tokens.push_back(current);
}

void ApplyParameter(TotpConfig& config, std::string key, std::string value) {
  key = Lower(key);
  while (!key.empty() && std::isspace(static_cast<unsigned char>(key.front())))
    key.erase(key.begin());
  while (!key.empty() && std::isspace(static_cast<unsigned char>(key.back())))
    key.pop_back();
  while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front())))
    value.erase(value.begin());
  while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back())))
    value.pop_back();

  if (key == "period" || key == "interval" || key == "step") {
    if (const auto period = ParseUInt32(value))
      config.set_period(*period);
  } else if (key == "digits" || key == "length") {
    if (const auto digits = ParseUInt32(value))
      config.set_digits(*digits);
  } else if (key == "algorithm" || key == "algo" || key == "hash") {
    const std::string algorithm = Lower(value);
    if (algorithm == "sha1" || algorithm == "sha-1")
      config.set_algorithm(TotpConfig::Algorithm::kSha1);
    else if (algorithm == "sha256" || algorithm == "sha-256")
      config.set_algorithm(TotpConfig::Algorithm::kSha256);
    else if (algorithm == "sha512" || algorithm == "sha-512")
      config.set_algorithm(TotpConfig::Algorithm::kSha512);
  }
}

bool ParseOtpAuthUri(const std::string& uri, TotpConfig& config) {
  const std::string lower = Lower(uri);
  constexpr const char* kScheme = "otpauth://";
  if (lower.compare(0, sizeof("otpauth://") - 1, kScheme) != 0)
    return false;

  const std::size_t type_start = sizeof("otpauth://") - 1;
  std::size_t type_end = uri.find_first_of("/?", type_start);
  if (type_end == std::string::npos)
    type_end = uri.size();
  const std::string type = Lower(uri.substr(type_start, type_end - type_start));
  if (type != "totp")
    return false;

  const std::size_t query_start = uri.find('?', type_end);
  if (query_start == std::string::npos)
    return false;

  std::vector<std::string> parameters;
  SplitParameters(uri.substr(query_start + 1), parameters);

  secure_string secret;
  bool has_secret = false;
  for (const auto& parameter : parameters) {
    const std::size_t separator = parameter.find('=');
    if (separator == std::string::npos)
      continue;
    const std::string key = Lower(parameter.substr(0, separator));
    const std::string value = UriDecode(parameter.substr(separator + 1));
    if (key == "secret") {
      secret = secure_string(value);
      has_secret = !secret.empty();
    } else {
      ApplyParameter(config, key, value);
    }
  }

  if (!has_secret)
    return false;
  config.set_secret(secret);
  return true;
}

void ApplySettings(TotpConfig& config, const std::string& settings) {
  if (settings.empty())
    return;

  std::vector<std::string> tokens;
  SplitParameters(settings, tokens);

  unsigned positional = 0;
  for (const auto& token : tokens) {
    const std::size_t separator = token.find_first_of("=:");
    if (separator != std::string::npos) {
      ApplyParameter(config, token.substr(0, separator), token.substr(separator + 1));
      continue;
    }

    // KeePass2Android/KeeOtp occasionally store the settings as positional
    // "period;digits" (or "period;digits;SHA1").
    if (const auto number = ParseUInt32(token)) {
      if (positional == 0)
        config.set_period(*number);
      else if (positional == 1)
        config.set_digits(*number);
      ++positional;
    } else if (positional >= 2) {
      ApplyParameter(config, "algorithm", token);
    }
  }
}

const EVP_MD* DigestFor(TotpConfig::Algorithm algorithm) {
  switch (algorithm) {
  case TotpConfig::Algorithm::kSha1:
    return EVP_sha1();
  case TotpConfig::Algorithm::kSha256:
    return EVP_sha256();
  case TotpConfig::Algorithm::kSha512:
    return EVP_sha512();
  }
  return EVP_sha1();
}

std::time_t ResolveTime(std::time_t time) { return time == 0 ? std::time(nullptr) : time; }

} // namespace

TotpConfig::TotpConfig(secure_string secret, uint32_t period, uint32_t digits, Algorithm algorithm)
    : secret_(std::move(secret)), period_(period == 0 ? 1 : period), algorithm_(algorithm) {
  set_digits(digits);
}

std::optional<TotpConfig> TotpConfig::Parse(const std::string& seed_field,
                                            const std::string& settings_field) {
  TotpConfig config;
  bool has_secret = false;

  if (!seed_field.empty()) {
    if (Lower(seed_field).rfind("otpauth://", 0) == 0) {
      has_secret = ParseOtpAuthUri(seed_field, config);
    } else {
      config.set_secret(secure_string(seed_field));
      has_secret = !config.secret().empty();
    }
  }

  if (!settings_field.empty()) {
    if (!has_secret && Lower(settings_field).rfind("otpauth://", 0) == 0)
      has_secret = ParseOtpAuthUri(settings_field, config);
    else
      ApplySettings(config, settings_field);
  }

  if (!has_secret || config.secret().empty())
    return std::nullopt;

  // Reject seeds that cannot be decoded instead of returning codes for an
  // accidental/garbage custom field.
  std::vector<uint8_t> decoded = Base32Decode(config.secret());
  const bool valid = !decoded.empty();
  secure_zero(decoded.data(), decoded.size());
  if (!valid)
    return std::nullopt;

  return config;
}

std::optional<TotpConfig> TotpConfig::FromEntry(const Entry& entry) {
  secure_string seed;
  std::string settings;

  for (const auto& field : entry.custom_fields()) {
    const std::string key = Lower(field.key());
    if (key == "otp" || key == "totp seed" || key == "otp seed" || key == "totpsecret" ||
        key == "totp_secret" || key == "totp") {
      seed = *field.value();
    } else if (key == "totp settings" || key == "otp settings" || key == "totp_settings") {
      settings = field.value()->str();
    }
  }

  if (seed.empty())
    return std::nullopt;

  const std::optional<TotpConfig> config = Parse(seed.str(), settings);
  secure_zero(settings.data(), settings.size());
  return config;
}

std::string Totp::Generate(const TotpConfig& config, std::time_t time) {
  if (config.empty() || config.period() == 0)
    return {};

  std::vector<uint8_t> key = Base32Decode(config.secret());
  if (key.empty())
    return {};

  const std::time_t now = ResolveTime(time);
  const uint64_t counter =
      now <= 0 ? 0 : static_cast<uint64_t>(now) / static_cast<uint64_t>(config.period());

  std::array<uint8_t, 8> message{};
  for (std::size_t i = 0; i < message.size(); ++i)
    message[message.size() - 1 - i] = static_cast<uint8_t>((counter >> (i * 8)) & 0xff);

  std::array<uint8_t, EVP_MAX_MD_SIZE> digest{};
  unsigned int digest_size = 0;
  const unsigned char* result =
      HMAC(DigestFor(config.algorithm()), key.data(), static_cast<int>(key.size()), message.data(),
           message.size(), digest.data(), &digest_size);

  secure_zero(key.data(), key.size());
  if (result == nullptr || digest_size < 4) {
    secure_zero(digest.data(), digest.size());
    return {};
  }

  const std::size_t offset = digest[digest_size - 1] & 0x0f;
  if (offset + 4 > digest_size) {
    secure_zero(digest.data(), digest.size());
    return {};
  }

  uint32_t binary = (static_cast<uint32_t>(digest[offset]) & 0x7f) << 24;
  binary |= static_cast<uint32_t>(digest[offset + 1]) << 16;
  binary |= static_cast<uint32_t>(digest[offset + 2]) << 8;
  binary |= static_cast<uint32_t>(digest[offset + 3]);

  secure_zero(digest.data(), digest.size());

  uint64_t modulus = 1;
  for (uint32_t i = 0; i < config.digits(); ++i)
    modulus *= 10;

  std::string code = std::to_string(static_cast<uint64_t>(binary) % modulus);
  if (code.size() < config.digits())
    code.insert(0, config.digits() - code.size(), '0');
  return code;
}

std::string Totp::Generate(const Entry& entry, std::time_t time) {
  const std::optional<TotpConfig> config = TotpConfig::FromEntry(entry);
  if (!config)
    return {};
  return Generate(*config, time);
}

uint32_t Totp::SecondsRemaining(const TotpConfig& config, std::time_t time) {
  if (config.empty() || config.period() == 0)
    return 0;

  const std::time_t now = ResolveTime(time);
  if (now <= 0)
    return config.period();

  const uint64_t period = config.period();
  const uint64_t elapsed = static_cast<uint64_t>(now) % period;
  return static_cast<uint32_t>(period - elapsed);
}

} // namespace keepass

namespace keepass {

std::optional<TotpConfig> Entry::totp() const { return TotpConfig::FromEntry(*this); }

std::string Entry::totp_code(std::time_t time) const {
  const std::optional<TotpConfig> config = TotpConfig::FromEntry(*this);
  if (!config)
    return {};
  return Totp::Generate(*config, time);
}

} // namespace keepass
