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

/**
 * @file key.hh
 * @brief Database encryption key management for KDB and KDBX formats.
 */

#pragma once
#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "libkeepass/export.hh"

namespace keepass {

/**
 * @brief Manages database encryption keys for KDB and KDBX formats.
 *
 * Supports password-based keys, key file-based keys, and composite keys
 * (password + key file combined). Provides key derivation via AES-KDF or
 * Argon2 for KDBX 4 databases.
 */
class LIBKEEPASS_API Key final {
public:
  /**
   * Strategies for how to resolve sub keys before applying the
   * transformation.
   */
  enum class SubKeyResolution {
    /** All sub keys will be hashed together into a single hash. Single sub
     * keys will be hashed despite not being part of a composite key. */
    kHashSubKeys,

    /** All sub keys will be hashed together into a single hash. If there is
     * only a single sub key, that sub key will be processed as is without any
     * additional hashing. */
    kHashSubKeysOnlyIfCompositeKey
  };

  /**
   * Key derivation functions supported for KDBX 4 databases.
   */
  enum class Kdf {
    /** AES-KDF (repeated AES-ECB, used by KDBX 3). */
    kAes,

    /** Argon2d. */
    kArgon2d,

    /** Argon2id. */
    kArgon2id
  };

private:
  struct CompositeKey {
    std::array<uint8_t, 32> password_key_ = {{0}};
    std::array<uint8_t, 32> keyfile_key_ = {{0}};

    std::array<uint8_t, 32> Resolve(SubKeyResolution resolution) const;
  } key_;

public:
  /// Default constructor. Creates an empty key with no password or key file.
  Key() = default;

  /// Constructs a key with the given password.
  /**
   * @param password The password string used to derive the encryption key.
   */
  explicit Key(const std::string& password);

  /// Sets the password used to derive the encryption key.
  /**
   * @param password The password string used to derive the encryption key.
   */
  void SetPassword(const std::string& password);

  /// Loads a key file and derives the key file component from it.
  /**
   * @param path Path to the key file on disk.
   */
  void SetKeyFile(const std::string& path);

  /// Derives the composite key using AES-KDF for KDBX 3 databases.
  /**
   * @param seed The key derivation seed (master seed).
   * @param rounds Number of AES-KDF transformation rounds.
   * @param resolution Strategy for resolving sub keys before transformation.
   * @return The derived 32-byte composite key.
   */
  std::array<uint8_t, 32> Transform(const std::array<uint8_t, 32>& seed, uint64_t rounds,
                                    SubKeyResolution resolution) const;

  /// Derives the composite key using Argon2 for KDBX 4 databases.
  /**
   * @param kdf The Argon2 variant to use (Argon2d or Argon2id).
   * @param salt The salt for the key derivation.
   * @param iterations Number of Argon2 iterations (time cost).
   * @param memory_bytes Memory cost in bytes for Argon2.
   * @param parallelism Degree of parallelism for Argon2.
   * @param argon2_version Argon2 algorithm version (0x10 for 1.0, 0x13 for 1.3).
   * @param resolution Strategy for resolving sub keys before transformation.
   * @return The derived 32-byte composite key.
   */
  std::array<uint8_t, 32> TransformArgon2(Kdf kdf, const std::vector<uint8_t>& salt,
                                          uint64_t iterations, uint64_t memory_bytes,
                                          uint32_t parallelism, uint32_t argon2_version,
                                          SubKeyResolution resolution) const;
};

} // namespace keepass
