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

#include "libkeepass/cipher_registry.hh"

#include <utility>

#include "libkeepass/exception.hh"

namespace keepass {

CipherRegistry& CipherRegistry::Instance() {
  static CipherRegistry registry;
  return registry;
}

CipherRegistry::CipherRegistry() {
  Register(Database::Cipher::kAes, [](const uint8_t* key, const std::array<uint8_t, 16>& iv) {
    return std::unique_ptr<Cipher<16>>(new AesCipher(key, iv));
  });
  Register(Database::Cipher::kTwofish, [](const uint8_t* key, const std::array<uint8_t, 16>& iv) {
    return std::unique_ptr<Cipher<16>>(new TwofishCipher(key, iv));
  });
}

void CipherRegistry::Register(Database::Cipher cipher, Factory factory) {
  std::scoped_lock lock(mutex_);
  factories_[cipher] = std::move(factory);
}

std::unique_ptr<Cipher<16>>
CipherRegistry::Create(Database::Cipher cipher, const uint8_t* key,
                       const std::array<uint8_t, 16>& init_vector) const {
  Factory factory;
  {
    std::scoped_lock lock(mutex_);
    const auto it = factories_.find(cipher);
    if (it == factories_.end())
      throw UnsupportedFeatureError("No block-cipher implementation registered.");
    factory = it->second;
  }
  return factory(key, init_vector);
}

bool CipherRegistry::Contains(Database::Cipher cipher) const {
  std::scoped_lock lock(mutex_);
  return factories_.find(cipher) != factories_.end();
}

} // namespace keepass
