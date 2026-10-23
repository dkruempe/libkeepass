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

#include "libkeepass/kdf_registry.hh"

#include <utility>

#include "libkeepass/exception.hh"

namespace keepass {

KdfRegistry& KdfRegistry::Instance() {
  static KdfRegistry registry;
  return registry;
}

KdfRegistry::KdfRegistry() {
  Register(Database::Kdf::kAes,
           [](const Key& key, const Database& db, Key::SubKeyResolution resolution) {
             return key.Transform(db.transform_seed(), db.transform_rounds(), resolution);
           });
  Register(Database::Kdf::kArgon2d,
           [](const Key& key, const Database& db, Key::SubKeyResolution resolution) {
             return key.TransformArgon2(Key::Kdf::kArgon2d, db.argon2_salt(),
                                        db.argon2_iterations(), db.argon2_memory(),
                                        db.argon2_parallelism(), db.argon2_version(), resolution);
           });
  Register(Database::Kdf::kArgon2id,
           [](const Key& key, const Database& db, Key::SubKeyResolution resolution) {
             return key.TransformArgon2(Key::Kdf::kArgon2id, db.argon2_salt(),
                                        db.argon2_iterations(), db.argon2_memory(),
                                        db.argon2_parallelism(), db.argon2_version(), resolution);
           });
}

void KdfRegistry::Register(Database::Kdf kdf, Factory factory) {
  std::lock_guard<std::mutex> lock(mutex_);
  factories_[kdf] = std::move(factory);
}

SecureBuffer<32> KdfRegistry::Transform(Database::Kdf kdf, const Key& key, const Database& db,
                                        Key::SubKeyResolution resolution) const {
  Factory factory;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto it = factories_.find(kdf);
    if (it == factories_.end())
      throw UnsupportedFeatureError("No KDF implementation registered.");
    factory = it->second;
  }
  return factory(key, db, resolution);
}

bool KdfRegistry::Contains(Database::Kdf kdf) const {
  std::lock_guard<std::mutex> lock(mutex_);
  return factories_.find(kdf) != factories_.end();
}

} // namespace keepass
