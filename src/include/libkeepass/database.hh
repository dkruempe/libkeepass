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
 * @file database.hh
 * @brief In-memory representation of a KeePass database.
 */

#pragma once
#include <array>
#include <memory>
#include <vector>

#include "group.hh"
#include "libkeepass/export.hh"

namespace keepass {

class Metadata;

/**
 * @brief Represents a KeePass (KDB/KDBX) database.
 *
 * A Database holds the root \ref Group of entries and groups, the chosen
 * cipher and key derivation function, and the cryptographic material
 * (master seed, init vector, transform seed, ...) needed to encrypt and
 * decrypt the payload. Metadata such as the database name and custom icons is
 * stored separately via \ref meta().
 */
class LIBKEEPASS_API Database final {
public:
  /// Cipher algorithms supported for encrypting the database payload.
  enum class Cipher { kAes, kTwofish, kChaCha20 };

  /// Key derivation functions supported by the importer/exporter.
  enum class Kdf { kAes, kArgon2d, kArgon2id };

private:
  std::shared_ptr<Group> root_;
  Cipher cipher_ = Cipher::kAes;
  Kdf kdf_ = Kdf::kAes;
  std::vector<uint8_t> master_seed_;
  std::array<uint8_t, 16> init_vector_ = {{0}};
  std::array<uint8_t, 32> transform_seed_{{0}};
  std::array<uint8_t, 32> inner_random_stream_key_ = {{0}};
  uint64_t transform_rounds_ = 8192;
  uint64_t argon2_memory_ = 0;
  uint32_t argon2_parallelism_ = 0;
  uint32_t argon2_version_ = 0;
  std::vector<uint8_t> argon2_salt_;
  uint64_t argon2_iterations_ = 0;
  bool compress_ = false;
  std::shared_ptr<Metadata> meta_;
  std::array<uint8_t, 32> transformed_key_{{0}};
  bool has_transformed_key_ = false;

public:
  /// Returns the root group of the database.
  std::shared_ptr<Group> root() const { return root_; }

  /// Sets the root group of the database.
  void set_root(std::shared_ptr<Group> root) { root_ = std::move(root); }

  /// Returns the cipher used to encrypt the database payload.
  Cipher cipher() const { return cipher_; }

  /// Sets the cipher used to encrypt the database payload.
  void set_cipher(Cipher cipher) { cipher_ = cipher; }

  /// Returns the key derivation function used to derive the master key.
  Kdf kdf() const { return kdf_; }

  /// Sets the key derivation function, invalidating any cached transformed key.
  void set_kdf(Kdf kdf) {
    if (kdf_ != kdf) {
      kdf_ = kdf;
      clear_transformed_key();
    }
  }

  /// Returns the master seed.
  const std::vector<uint8_t> &master_seed() const { return master_seed_; }

  /// Sets the master seed from a fixed 16-byte array.
  void set_master_seed(const std::array<uint8_t, 16> &master_seed) {
    master_seed_.resize(16);
    std::copy(master_seed.begin(), master_seed.end(), master_seed_.begin());
  }

  /// Sets the master seed from an arbitrary byte vector.
  void set_master_seed(const std::vector<uint8_t> &master_seed) {
    master_seed_ = master_seed;
  }

  /// Returns the initialization vector.
  const std::array<uint8_t, 16> &init_vector() const { return init_vector_; }

  /// Sets the initialization vector.
  void set_init_vector(const std::array<uint8_t, 16> &init_vector) {
    init_vector_ = init_vector;
  }

  /// Returns the transform seed used for key derivation.
  const std::array<uint8_t, 32> &transform_seed() const {
    return transform_seed_;
  }

  /// Sets the transform seed, invalidating any cached transformed key.
  void set_transform_seed(const std::array<uint8_t, 32> &transform_seed) {
    transform_seed_ = transform_seed;
    clear_transformed_key();
  }

  /// Returns the inner random stream key.
  const std::array<uint8_t, 32> &inner_random_stream_key() const {
    return inner_random_stream_key_;
  }

  /// Sets the inner random stream key.
  void set_inner_random_stream_key(const std::array<uint8_t, 32> &key) {
    inner_random_stream_key_ = key;
  }

  /// Returns the number of AES key-transform rounds.
  uint64_t transform_rounds() const { return transform_rounds_; }

  /// Sets the number of AES key-transform rounds, invalidating the cached key.
  void set_transform_rounds(uint64_t transform_rounds) {
    transform_rounds_ = transform_rounds;
    clear_transformed_key();
  }

  /// Returns the Argon2 memory cost in KiB.
  uint64_t argon2_memory() const { return argon2_memory_; }

  /// Sets the Argon2 memory cost in KiB, invalidating the cached key.
  void set_argon2_memory(uint64_t argon2_memory) {
    argon2_memory_ = argon2_memory;
    clear_transformed_key();
  }

  /// Returns the Argon2 parallelism (degree of parallelism).
  uint32_t argon2_parallelism() const { return argon2_parallelism_; }

  /// Sets the Argon2 parallelism, invalidating the cached key.
  void set_argon2_parallelism(uint32_t argon2_parallelism) {
    argon2_parallelism_ = argon2_parallelism;
    clear_transformed_key();
  }

  /// Returns the Argon2 version number.
  uint32_t argon2_version() const { return argon2_version_; }

  /// Sets the Argon2 version number, invalidating the cached key.
  void set_argon2_version(uint32_t argon2_version) {
    argon2_version_ = argon2_version;
    clear_transformed_key();
  }

  /// Returns the Argon2 salt.
  const std::vector<uint8_t> &argon2_salt() const { return argon2_salt_; }

  /// Sets the Argon2 salt, invalidating the cached key.
  void set_argon2_salt(const std::vector<uint8_t> &salt) {
    argon2_salt_ = salt;
    clear_transformed_key();
  }

  /// Returns the Argon2 iteration count.
  uint64_t argon2_iterations() const { return argon2_iterations_; }

  /// Sets the Argon2 iteration count, invalidating the cached key.
  void set_argon2_iterations(uint64_t iterations) {
    argon2_iterations_ = iterations;
    clear_transformed_key();
  }

  /// Returns whether the payload is compressed.
  bool compress() const { return compress_; }

  /// Sets whether the payload is compressed.
  void set_compress(bool compress) { compress_ = compress; }

  /// Returns the transformed master key (if present).
  const std::array<uint8_t, 32> &transformed_key() const {
    return transformed_key_;
  }

  /// Returns whether a transformed key has been computed.
  bool has_transformed_key() const { return has_transformed_key_; }

  /// Sets the transformed master key and marks it as present.
  void set_transformed_key(const std::array<uint8_t, 32> &key) {
    transformed_key_ = key;
    has_transformed_key_ = true;
  }

  /// Clears any cached transformed key.
  void clear_transformed_key() { has_transformed_key_ = false; }

  /// Returns the database metadata.
  std::shared_ptr<Metadata> meta() const { return meta_; }

  /// Sets the database metadata.
  void set_meta(std::shared_ptr<Metadata> meta) { meta_ = std::move(meta); }
};

} // namespace keepass
