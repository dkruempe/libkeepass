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

#include "include/libkeepass/kdbx_kdf.hh"

#include <array>
#include <cstring>
#include <vector>

#include "libkeepass/exception.hh"
#include "libkeepass/variantdictionary.hh"

namespace keepass {

namespace {

constexpr std::array<uint8_t, 16> kKdbxKdfAesKdbx4 = {{0x7c, 0x02, 0xbb, 0x82, 0x79, 0xa7, 0x4a,
                                                       0xc0, 0x92, 0x7d, 0x11, 0x4a, 0x00, 0x64,
                                                       0x82, 0x38}};
constexpr std::array<uint8_t, 16> kKdbxKdfAesKdbx3 = {{0xc9, 0xd9, 0xf3, 0x9a, 0x62, 0x8a, 0x44,
                                                       0x60, 0xbf, 0x74, 0x0d, 0x08, 0xc1, 0x8a,
                                                       0x4f, 0xea}};
constexpr std::array<uint8_t, 16> kKdbxKdfArgon2d = {{0xef, 0x63, 0x6d, 0xdf, 0x8c, 0x29, 0x44,
                                                      0x4b, 0x91, 0xf7, 0xa9, 0xa4, 0x03, 0xe3,
                                                      0x0a, 0x0c}};
constexpr std::array<uint8_t, 16> kKdbxKdfArgon2id = {{0x9e, 0x29, 0x8b, 0x19, 0x56, 0xdb, 0x47,
                                                       0x73, 0xb2, 0x3d, 0xfc, 0x3e, 0xc6, 0xf0,
                                                       0xa1, 0xe6}};

} // namespace

void KdbxKdf::ParseParameters(std::istream& field, Database& db) {
  VariantDictionary vdict;
  vdict.Parse(field);

  const VariantDictionary::Entry& uuid_entry = vdict.Get("$UUID");
  if (uuid_entry.type != VariantDictionary::Type::kByteArray || uuid_entry.value.size() != 16) {
    throw FormatError("Illegal KDF UUID in KDBX 4 database.");
  }

  std::array<uint8_t, 16> uuid{};
  std::copy(uuid_entry.value.begin(), uuid_entry.value.end(), uuid.begin());

  if (uuid == kKdbxKdfAesKdbx4 || uuid == kKdbxKdfAesKdbx3) {
    db.set_kdf(Database::Kdf::kAes);

    std::vector<uint8_t> seed = vdict.GetBytes("S");
    if (seed.size() != 32)
      throw FormatError("Illegal KDF seed size in KDBX 4 database.");
    std::array<uint8_t, 32> seed_arr{};
    std::copy(seed.begin(), seed.end(), seed_arr.begin());
    db.set_transform_seed(seed_arr);
    const uint64_t transform_rounds = vdict.GetUInt64("R");
    if (transform_rounds > Database::kMaxTransformRounds)
      throw FormatError("KDF parameters declare too many transform rounds.");
    db.set_transform_rounds(transform_rounds);
  } else if (uuid == kKdbxKdfArgon2d || uuid == kKdbxKdfArgon2id) {
    db.set_kdf(uuid == kKdbxKdfArgon2d ? Database::Kdf::kArgon2d : Database::Kdf::kArgon2id);

    db.set_argon2_salt(vdict.GetBytes("S"));
    const uint64_t argon2_iterations = vdict.GetUInt64("I");
    const uint64_t argon2_memory = vdict.GetUInt64("M");
    if (argon2_iterations > Database::kMaxArgon2Iterations ||
        argon2_memory > (Database::kMaxArgon2MemoryKiB << 10))
      throw FormatError("Argon2 KDF parameters are out of bounds.");
    db.set_argon2_iterations(argon2_iterations);
    db.set_argon2_memory(argon2_memory);
    db.set_argon2_parallelism(vdict.GetUInt32("P"));
    db.set_argon2_version(vdict.GetUInt32("V"));
  } else {
    throw FormatError("Unknown KDF in KDBX 4 database.");
  }
}

void KdbxKdf::WriteParameters(std::ostream& dst, const Database& db) {
  VariantDictionary vdict;

  if (db.kdf() == Database::Kdf::kAes) {
    std::array<uint8_t, 16> uuid = kKdbxKdfAesKdbx4;
    std::vector<uint8_t> uuid_vec(uuid.begin(), uuid.end());
    vdict.Set("$UUID", VariantDictionary::Type::kByteArray, std::move(uuid_vec));

    std::array<uint8_t, 32> seed = db.transform_seed();
    std::vector<uint8_t> seed_vec(seed.begin(), seed.end());
    vdict.Set("S", VariantDictionary::Type::kByteArray, std::move(seed_vec));

    std::vector<uint8_t> rounds(sizeof(uint64_t), 0);
    const uint64_t rounds_val = db.transform_rounds();
    std::memcpy(rounds.data(), &rounds_val, sizeof(rounds_val));
    vdict.Set("R", VariantDictionary::Type::kUInt64, std::move(rounds));
  } else {
    const std::array<uint8_t, 16> kdf_uuid =
        db.kdf() == Database::Kdf::kArgon2d ? kKdbxKdfArgon2d : kKdbxKdfArgon2id;

    std::array<uint8_t, 16> uuid = kdf_uuid;
    std::vector<uint8_t> uuid_vec(uuid.begin(), uuid.end());
    vdict.Set("$UUID", VariantDictionary::Type::kByteArray, std::move(uuid_vec));

    std::vector<uint8_t> salt = db.argon2_salt();
    vdict.Set("S", VariantDictionary::Type::kByteArray, std::move(salt));

    std::vector<uint8_t> iterations(sizeof(uint64_t), 0);
    const uint64_t iterations_val = db.argon2_iterations();
    std::memcpy(iterations.data(), &iterations_val, sizeof(iterations_val));
    vdict.Set("I", VariantDictionary::Type::kUInt64, std::move(iterations));

    std::vector<uint8_t> memory(sizeof(uint64_t), 0);
    const uint64_t memory_val = db.argon2_memory();
    std::memcpy(memory.data(), &memory_val, sizeof(memory_val));
    vdict.Set("M", VariantDictionary::Type::kUInt64, std::move(memory));

    std::vector<uint8_t> parallelism(sizeof(uint32_t), 0);
    const uint32_t parallelism_val = db.argon2_parallelism();
    std::memcpy(parallelism.data(), &parallelism_val, sizeof(parallelism_val));
    vdict.Set("P", VariantDictionary::Type::kUInt32, std::move(parallelism));

    std::vector<uint8_t> version(sizeof(uint32_t), 0);
    const uint32_t version_val = db.argon2_version();
    std::memcpy(version.data(), &version_val, sizeof(version_val));
    vdict.Set("V", VariantDictionary::Type::kUInt32, std::move(version));
  }

  vdict.Write(dst);
}

SecureBuffer<32> KdbxKdf::Transform(const Key& key, const Database& db,
                                    Key::SubKeyResolution resolution) {
  switch (db.kdf()) {
  case Database::Kdf::kAes:
    return key.Transform(db.transform_seed(), db.transform_rounds(), resolution);
  case Database::Kdf::kArgon2d:
  case Database::Kdf::kArgon2id:
    return key.TransformArgon2(db.kdf() == Database::Kdf::kArgon2d ? Key::Kdf::kArgon2d
                                                                   : Key::Kdf::kArgon2id,
                               db.argon2_salt(), db.argon2_iterations(), db.argon2_memory(),
                               db.argon2_parallelism(), db.argon2_version(), resolution);
  }
  return SecureBuffer<32>{};
}

} // namespace keepass