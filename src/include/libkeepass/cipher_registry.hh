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

/** @file cipher_registry.hh @brief Registrable payload block ciphers. */

#pragma once

#include <array>
#include <functional>
#include <map>
#include <memory>
#include <mutex>

#include "database.hh"
#include "libkeepass/cipher.hh"
#include "libkeepass/export.hh"

namespace keepass {

/**
 * @brief Process-wide registry for 16-byte block ciphers.
 *
 * The built-in AES and Twofish factories are registered by the registry
 * constructor. External implementations can be added with Register() and are
 * then usable anywhere the core creates a block cipher (KDB/KDBX import and
 * export). ChaCha20 is a stream cipher with its own code path; it is not a
 * block-cipher registration.
 */
class LIBKEEPASS_API CipherRegistry final {
public:
  /// Creates a block cipher for the given 32-byte key and IV.
  using Factory = std::function<std::unique_ptr<Cipher<16>>(
      const uint8_t* key, const std::array<uint8_t, 16>& init_vector)>;

  /// Returns the process-wide registry.
  static CipherRegistry& Instance();

  /// Registers/overwrites the factory for a payload cipher id.
  void Register(Database::Cipher cipher, Factory factory);

  /// Creates a block cipher, or throws UnsupportedFeatureError.
  std::unique_ptr<Cipher<16>> Create(Database::Cipher cipher, const uint8_t* key,
                                     const std::array<uint8_t, 16>& init_vector) const;

  /// Returns whether a block-cipher factory is registered for @p cipher.
  bool Contains(Database::Cipher cipher) const;

private:
  CipherRegistry();

  mutable std::mutex mutex_;
  std::map<Database::Cipher, Factory> factories_;
};

} // namespace keepass
