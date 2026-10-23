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

/** @file kdf_registry.hh @brief Registrable key-derivation functions. */

#pragma once

#include <functional>
#include <map>
#include <mutex>

#include "database.hh"
#include "libkeepass/export.hh"
#include "libkeepass/key.hh"
#include "libkeepass/secure.hh"

namespace keepass {

/**
 * @brief Process-wide registry for key-derivation functions.
 *
 * Built-in AES-KDF/Argon2d/Argon2id factories are registered by the registry
 * constructor. External implementations can be registered and are used by
 * KdbxKdf::Transform for every KDBX import/export.
 */
class LIBKEEPASS_API KdfRegistry final {
public:
  /// Derives the transformed 32-byte key.
  using Factory =
      std::function<SecureBuffer<32>(const Key&, const Database&, Key::SubKeyResolution)>;

  /// Returns the process-wide registry.
  static KdfRegistry& Instance();

  /// Registers/overwrites the factory for a KDF id.
  void Register(Database::Kdf kdf, Factory factory);

  /// Derives the transformed key, or throws UnsupportedFeatureError.
  SecureBuffer<32> Transform(Database::Kdf kdf, const Key& key, const Database& db,
                             Key::SubKeyResolution resolution) const;

  /// Returns whether a factory is registered for @p kdf.
  bool Contains(Database::Kdf kdf) const;

private:
  KdfRegistry();

  mutable std::mutex mutex_;
  std::map<Database::Kdf, Factory> factories_;
};

} // namespace keepass
