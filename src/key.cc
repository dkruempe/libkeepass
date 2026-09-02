/*
 * libkeepass - KeePass key database importer/exporter
 * Copyright (C) 2014 Christian Kindahl
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

#include "libkeepass/key.hh"

#include <algorithm>
#include <fstream>
#include <memory>

#include <argon2.h>
#include <openssl/evp.h>
#include <pugixml.hpp>

#include "libkeepass/aes_ni.hh"
#include "libkeepass/base64.hh"
#include "libkeepass/cipher.hh"
#include "libkeepass/exception.hh"

namespace keepass {

std::array<uint8_t, 32>
Key::CompositeKey::Resolve(SubKeyResolution resolution) const {
  static const std::array<uint8_t, 32> kEmptyKey = {{0}};

  if (resolution == SubKeyResolution::kHashSubKeys) {
    std::array<uint8_t, 32> key{};

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
    if (password_key_ != kEmptyKey)
      EVP_DigestUpdate(mdctx, password_key_.data(), password_key_.size());
    if (keyfile_key_ != kEmptyKey)
      EVP_DigestUpdate(mdctx, keyfile_key_.data(), keyfile_key_.size());
    unsigned int out_len = 0;
    EVP_DigestFinal_ex(mdctx, key.data(), &out_len);
    EVP_MD_CTX_free(mdctx);

    return key;
  } else {
    if (password_key_ != kEmptyKey) {
      if (keyfile_key_ != kEmptyKey) {
        std::array<uint8_t, 32> key{};

        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
        EVP_DigestUpdate(mdctx, password_key_.data(), password_key_.size());
        EVP_DigestUpdate(mdctx, keyfile_key_.data(), keyfile_key_.size());
        unsigned int out_len = 0;
        EVP_DigestFinal_ex(mdctx, key.data(), &out_len);
        EVP_MD_CTX_free(mdctx);

        return key;
      } else {
        return password_key_;
      }
    } else {
      return keyfile_key_;
    }
  }
}

Key::Key(const std::string &password) { SetPassword(password); }

void Key::SetPassword(const std::string &password) {
  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
  EVP_DigestUpdate(mdctx, reinterpret_cast<const uint8_t *>(password.c_str()),
                   password.size());
  unsigned int out_len = 0;
  EVP_DigestFinal_ex(mdctx, key_.password_key_.data(), &out_len);
  EVP_MD_CTX_free(mdctx);
}

void Key::SetKeyFile(const std::string &path) {
  std::ifstream src(path, std::ios::in | std::ios::binary);
  if (!src.is_open())
    throw FileNotFoundError();

  // First, try to parse the key file as XML.
  pugi::xml_document doc;
  if (doc.load(src, pugi::parse_default | pugi::parse_trim_pcdata)) {
    std::string key_str =
        base64_decode(doc.child("KeyFile").child("Key").child_value("Data"));
    if (key_str.size() != 32)
      throw FormatError("Invalid key size in key file.");

    std::copy(key_str.begin(), key_str.end(), key_.keyfile_key_.begin());
    return;
  }

  // If not XML, reset stream and try to parse as text.
  src.seekg(0, std::ios::beg);

  std::vector<char> data;
  std::copy(std::istreambuf_iterator<char>(src),
            std::istreambuf_iterator<char>(), std::back_inserter(data));
  if (data.size() != 64)
    throw FormatError("Unknown key file format.");

  for (std::size_t i = 0; i < key_.keyfile_key_.size(); ++i) {
    char c[2] = {data[i * 2], data[i * 2 + 1]};

    if (!std::isxdigit(c[0]) || !std::isxdigit(c[1]))
      throw FormatError("Unknown key file format.");

    uint8_t v = static_cast<uint8_t>(std::stoi(std::string(c, 2), nullptr, 16));
    key_.keyfile_key_[i] = v;
  }
}

std::array<uint8_t, 32> Key::Transform(const std::array<uint8_t, 32> &seed,
                                       uint64_t rounds,
                                       SubKeyResolution resolution) const {
  std::array<uint8_t, 32> transformed_key = key_.Resolve(resolution);
  std::array<uint8_t, 32> encrypted{};

  if (aes_ni_supported()) {
    aes_ni_transform_aes_kdf(seed.data(), transformed_key.data(), rounds,
                             encrypted.data());
    transformed_key = encrypted;
  } else {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr ||
        EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), nullptr, seed.data(),
                           nullptr) != 1) {
      if (ctx != nullptr)
        EVP_CIPHER_CTX_free(ctx);
      throw InternalError("Failed to initialize AES-KDF.");
    }
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    for (uint64_t i = 0; i < rounds; ++i) {
      int outl = 0;
      if (EVP_EncryptUpdate(ctx, encrypted.data(), &outl,
                            transformed_key.data(),
                            transformed_key.size()) != 1 ||
          outl != static_cast<int>(transformed_key.size())) {
        EVP_CIPHER_CTX_free(ctx);
        throw InternalError("AES-KDF transform failed.");
      }
      transformed_key = encrypted;
    }
    EVP_CIPHER_CTX_free(ctx);
  }

  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
  EVP_DigestUpdate(mdctx, transformed_key.data(), transformed_key.size());
  unsigned int out_len = 0;
  EVP_DigestFinal_ex(mdctx, transformed_key.data(), &out_len);
  EVP_MD_CTX_free(mdctx);
  return transformed_key;
}

std::array<uint8_t, 32> Key::TransformArgon2(
    Kdf kdf, const std::vector<uint8_t> &salt, uint64_t iterations,
    uint64_t memory_bytes, uint32_t parallelism, uint32_t argon2_version,
    SubKeyResolution resolution) const {
  std::array<uint8_t, 32> transformed_key{};
  std::array<uint8_t, 32> composite_key = key_.Resolve(resolution);

  uint32_t memory_kib =
      static_cast<uint32_t>(memory_bytes / 1024ULL);

  uint32_t version = argon2_version == 0x10 ? ARGON2_VERSION_10
                                            : ARGON2_VERSION_13;

  argon2_type type = kdf == Kdf::kArgon2d ? Argon2_d : Argon2_id;

  int rc = argon2_hash(static_cast<uint32_t>(iterations), memory_kib,
                       parallelism, composite_key.data(),
                       composite_key.size(), salt.data(), salt.size(),
                       transformed_key.data(), transformed_key.size(), nullptr,
                       0, type, version);

  if (rc != ARGON2_OK)
    throw InternalError(std::string("Argon2 error: ") + argon2_error_message(rc));

  return transformed_key;
}

} // namespace keepass
