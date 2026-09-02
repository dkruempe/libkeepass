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

#pragma once
#include <array>
#include <memory>
#include <vector>

#include "group.hh"

namespace keepass {

class Metadata;

class Database final {
public:
  enum class Cipher { kAes, kTwofish, kChaCha20 };

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
  std::shared_ptr<Group> root() const { return root_; }
  void set_root(std::shared_ptr<Group> root) { root_ = std::move(root); }

  Cipher cipher() const { return cipher_; }
  void set_cipher(Cipher cipher) { cipher_ = cipher; }

  Kdf kdf() const { return kdf_; }
  void set_kdf(Kdf kdf) {
    if (kdf_ != kdf) {
      kdf_ = kdf;
      clear_transformed_key();
    }
  }

  const std::vector<uint8_t> &master_seed() const { return master_seed_; }
  void set_master_seed(const std::array<uint8_t, 16> &master_seed) {
    master_seed_.resize(16);
    std::copy(master_seed.begin(), master_seed.end(), master_seed_.begin());
  }
  void set_master_seed(const std::vector<uint8_t> &master_seed) {
    master_seed_ = master_seed;
  }

  const std::array<uint8_t, 16> &init_vector() const { return init_vector_; }
  void set_init_vector(const std::array<uint8_t, 16> &init_vector) {
    init_vector_ = init_vector;
  }

  const std::array<uint8_t, 32> &transform_seed() const {
    return transform_seed_;
  }
  void set_transform_seed(const std::array<uint8_t, 32> &transform_seed) {
    transform_seed_ = transform_seed;
    clear_transformed_key();
  }

  const std::array<uint8_t, 32> &inner_random_stream_key() const {
    return inner_random_stream_key_;
  }
  void set_inner_random_stream_key(const std::array<uint8_t, 32> &key) {
    inner_random_stream_key_ = key;
  }

  uint64_t transform_rounds() const { return transform_rounds_; }
  void set_transform_rounds(uint64_t transform_rounds) {
    transform_rounds_ = transform_rounds;
    clear_transformed_key();
  }

  uint64_t argon2_memory() const { return argon2_memory_; }
  void set_argon2_memory(uint64_t argon2_memory) {
    argon2_memory_ = argon2_memory;
    clear_transformed_key();
  }

  uint32_t argon2_parallelism() const { return argon2_parallelism_; }
  void set_argon2_parallelism(uint32_t argon2_parallelism) {
    argon2_parallelism_ = argon2_parallelism;
    clear_transformed_key();
  }

  uint32_t argon2_version() const { return argon2_version_; }
  void set_argon2_version(uint32_t argon2_version) {
    argon2_version_ = argon2_version;
    clear_transformed_key();
  }

  const std::vector<uint8_t> &argon2_salt() const { return argon2_salt_; }
  void set_argon2_salt(const std::vector<uint8_t> &salt) {
    argon2_salt_ = salt;
    clear_transformed_key();
  }

  uint64_t argon2_iterations() const { return argon2_iterations_; }
  void set_argon2_iterations(uint64_t iterations) {
    argon2_iterations_ = iterations;
    clear_transformed_key();
  }

  bool compress() const { return compress_; }
  void set_compress(bool compress) { compress_ = compress; }

  const std::array<uint8_t, 32> &transformed_key() const {
    return transformed_key_;
  }
  bool has_transformed_key() const { return has_transformed_key_; }
  void set_transformed_key(const std::array<uint8_t, 32> &key) {
    transformed_key_ = key;
    has_transformed_key_ = true;
  }
  void clear_transformed_key() { has_transformed_key_ = false; }

  std::shared_ptr<Metadata> meta() const { return meta_; }
  void set_meta(std::shared_ptr<Metadata> meta) { meta_ = std::move(meta); }
};

} // namespace keepass
