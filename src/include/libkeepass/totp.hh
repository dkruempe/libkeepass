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

/** @file totp.hh
 *  @brief Helpers for the KeePass TOTP custom fields and time-based one-time
 *         password generation. */

#pragma once

#include <cstdint>
#include <ctime>
#include <optional>
#include <string>

#include "libkeepass/export.hh"
#include "libkeepass/secure.hh"

namespace keepass {

class Entry;

/**
 * @brief Parsed TOTP parameters from an entry's custom fields.
 *
 * KeePass implementations store TOTP settings in different ways:
 * - the `otp`/`TOTP Seed`/`otp seed` fields hold either a Base32 secret or a
 *   complete `otpauth://totp/...` URI,
 * - the `TOTP Settings` field holds `period;digits`, comma/ampersand separated
 *   `key=value` pairs (`period=30&digits=6&algorithm=SHA1`) or an `otpauth`
 *   URI.
 *
 * The secret is kept in a wiped @ref secure_string.
 */
class LIBKEEPASS_API TotpConfig final {
public:
  /// Hash algorithms used by the HMAC-based TOTP construction.
  enum class Algorithm { kSha1, kSha256, kSha512 };

private:
  secure_string secret_;
  uint32_t period_ = 30;
  uint32_t digits_ = 6;
  Algorithm algorithm_ = Algorithm::kSha1;

public:
  /// Creates an empty (invalid) configuration.
  TotpConfig() = default;

  /**
   * @param secret Base32-encoded shared secret.
   * @param period Time step in seconds (default 30).
   * @param digits Number of output digits (default 6).
   * @param algorithm HMAC algorithm (default SHA-1, as used by most clients).
   */
  explicit TotpConfig(secure_string secret, uint32_t period = 30, uint32_t digits = 6,
                      Algorithm algorithm = Algorithm::kSha1);

  /// Returns the Base32 shared secret.
  const secure_string& secret() const { return secret_; }

  /// Replaces the Base32 shared secret.
  void set_secret(const secure_string& secret) { secret_ = secret; }

  /// Returns the time step in seconds.
  uint32_t period() const { return period_; }

  /// Sets the time step in seconds (clamped to at least one second).
  void set_period(uint32_t period) { period_ = period == 0 ? 1 : period; }

  /// Returns the number of output digits.
  uint32_t digits() const { return digits_; }

  /// Sets the number of output digits (supported range 1-10).
  void set_digits(uint32_t digits) { digits_ = digits < 1 ? 1 : (digits > 10 ? 10 : digits); }

  /// Returns the HMAC algorithm.
  Algorithm algorithm() const { return algorithm_; }

  /// Sets the HMAC algorithm.
  void set_algorithm(Algorithm algorithm) { algorithm_ = algorithm; }

  /// Returns whether a secret is present.
  bool empty() const { return secret_.empty(); }

  /**
   * @brief Parses a TOTP seed/URI plus optional settings string.
   *
   * @param seed_field Value of `otp`, `TOTP Seed` or a similar custom field.
   * @param settings_field Optional `TOTP Settings` value.
   * @return The parsed configuration, or @c std::nullopt if the seed is
   *         missing/invalid or describes an unsupported (HOTP) token.
   */
  static std::optional<TotpConfig> Parse(const std::string& seed_field,
                                         const std::string& settings_field = {});

  /// Extracts and parses the TOTP fields of an entry.
  static std::optional<TotpConfig> FromEntry(const Entry& entry);
};

/**
 * @brief TOTP code generation (RFC 6238).
 */
class LIBKEEPASS_API Totp final {
public:
  /**
   * @brief Generates the current TOTP code.
   *
   * @param config Parsed parameters.
   * @param time Unix time to use; 0 means the current system time.
   * @return The zero-padded code, or an empty string if the secret is invalid.
   */
  static std::string Generate(const TotpConfig& config, std::time_t time = 0);

  /// Generates a code for the TOTP fields of an entry.
  /**
   * @param entry Entry whose custom fields are inspected.
   * @param time Unix time to use; 0 means the current system time.
   * @return The code, or an empty string if the entry has no valid TOTP field.
   */
  static std::string Generate(const Entry& entry, std::time_t time = 0);

  /// Returns the number of seconds until the current time step expires.
  /**
   * @param config Parsed parameters.
   * @param time Unix time to use; 0 means the current system time.
   * @return Seconds until the next code, or 0 if the parameters are invalid.
   */
  static uint32_t SecondsRemaining(const TotpConfig& config, std::time_t time = 0);
};

} // namespace keepass
