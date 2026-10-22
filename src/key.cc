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

#include "libkeepass/key.hh"

#include <algorithm>
#include <array>
#include <cstring>
#include <fstream>
#include <istream>
#include <memory>

#include <argon2.h>
#include <openssl/evp.h>
#include <pugixml.hpp>

#include "libkeepass/aes_ni.hh"
#include "libkeepass/base64.hh"
#include "libkeepass/cipher.hh"
#include "libkeepass/exception.hh"

namespace keepass {

namespace {

/// Returns whether a secure buffer contains only zero bytes.
bool IsZeroKey(const SecureBuffer<32>& key) {
  uint8_t diff = 0;
  for (uint8_t byte : key)
    diff |= byte;
  return diff == 0;
}

/// Decodes a single hexadecimal digit.
int HexValue(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

/// Wipes a byte range when leaving the scope, including exceptional paths.
class WipeGuard {
public:
  WipeGuard(void* data, std::size_t size) : data_(data), size_(size) {}
  ~WipeGuard() { secure_zero(data_, size_); }

  WipeGuard(const WipeGuard&) = delete;
  WipeGuard& operator=(const WipeGuard&) = delete;

private:
  void* data_;
  std::size_t size_;
};

} // namespace

void Key::CompositeKey::Resolve(SubKeyResolution resolution, SecureBuffer<32>& out) const {
  out.fill(0);

  const bool password_present = !IsZeroKey(password_key_);
  const bool keyfile_present = !IsZeroKey(keyfile_key_);
  const bool hash_sub_keys =
      resolution == SubKeyResolution::kHashSubKeys || (password_present && keyfile_present);
  if (!hash_sub_keys) {
    if (password_present)
      std::memcpy(out.data(), password_key_.data(), out.size());
    else if (keyfile_present)
      std::memcpy(out.data(), keyfile_key_.data(), out.size());
    return;
  }

  EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
  if (password_present)
    EVP_DigestUpdate(mdctx, password_key_.data(), password_key_.size());
  if (keyfile_present)
    EVP_DigestUpdate(mdctx, keyfile_key_.data(), keyfile_key_.size());
  unsigned int out_len = 0;
  EVP_DigestFinal_ex(mdctx, out.data(), &out_len);
  EVP_MD_CTX_free(mdctx);
}

Key::Key(const Key& other) {
  key_.password_key_ = other.key_.password_key_.Clone();
  key_.keyfile_key_ = other.key_.keyfile_key_.Clone();
  has_transformed_key_ = other.has_transformed_key_;
  if (other.has_transformed_key_)
    transformed_key_ = other.transformed_key_.Clone();
}

Key& Key::operator=(const Key& other) {
  if (this != &other) {
    key_.password_key_ = other.key_.password_key_.Clone();
    key_.keyfile_key_ = other.key_.keyfile_key_.Clone();
    has_transformed_key_ = other.has_transformed_key_;
    if (other.has_transformed_key_)
      transformed_key_ = other.transformed_key_.Clone();
    else
      has_transformed_key_ = false;
  }
  return *this;
}

Key::Key(const std::string& password) { SetPassword(password); }

Key::Key(const std::string& password, const std::string& keyfile) {
  SetPassword(password);
  if (!keyfile.empty())
    SetKeyFile(keyfile);
}

Key::Key(const std::vector<uint8_t>& transformed_key) {
  if (transformed_key.size() != 32)
    throw FormatError("Invalid transformed key size.");

  std::copy(transformed_key.begin(), transformed_key.end(), transformed_key_.data());
  has_transformed_key_ = true;
}

void Key::SetPassword(const std::string& password) {
  EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
  EVP_DigestUpdate(mdctx, reinterpret_cast<const uint8_t*>(password.c_str()), password.size());
  unsigned int out_len = 0;
  EVP_DigestFinal_ex(mdctx, key_.password_key_.data(), &out_len);
  EVP_MD_CTX_free(mdctx);
}

void Key::SetKeyFile(const std::string& path) {
  std::ifstream src(path, std::ios::in | std::ios::binary);
  if (!src.is_open())
    throw FileNotFoundError();

  src.seekg(0, std::ios::end);
  const std::streamoff size = src.tellg();
  if (size > static_cast<std::streamoff>(kMaxKeyFileBytes))
    throw FormatError("Key file too large.");
  src.seekg(0, std::ios::beg);
  if (!src.good()) {
    src.clear();
    src.seekg(0, std::ios::beg);
  }

  SetKeyFile(src);
}

void Key::SetKeyFile(std::istream& src) {
  std::vector<uint8_t> data;
  std::array<uint8_t, 4096> chunk{};

  while (src.good()) {
    src.read(reinterpret_cast<char*>(chunk.data()), static_cast<std::streamsize>(chunk.size()));
    const std::streamsize count = src.gcount();
    if (count <= 0)
      continue;

    if (data.size() + static_cast<std::size_t>(count) > kMaxKeyFileBytes) {
      secure_zero(chunk.data(), chunk.size());
      secure_zero(data.data(), data.size());
      throw FormatError("Key file too large.");
    }
    data.insert(data.end(), chunk.begin(), chunk.begin() + count);
  }
  secure_zero(chunk.data(), chunk.size());

  const bool read_failed = src.bad();
  if (read_failed) {
    secure_zero(data.data(), data.size());
    throw IoError("Unable to read key file.");
  }

  WipeGuard guard(data.data(), data.size());
  SetKeyFileData(data.data(), data.size());
}

void Key::SetKeyFileData(const uint8_t* data, std::size_t size) {
  if (data == nullptr || size == 0)
    throw FormatError("Unknown key file format.");
  if (size > kMaxKeyFileBytes)
    throw FormatError("Key file too large.");

  // First, try to parse the key file as XML.
  pugi::xml_document doc;
  if (doc.load_buffer(data, size, pugi::parse_default | pugi::parse_trim_pcdata)) {
    std::string key_str = base64_decode(doc.child("KeyFile").child("Key").child_value("Data"));
    WipeGuard guard(key_str.data(), key_str.size());
    if (key_str.size() != 32)
      throw FormatError("Invalid key size in key file.");

    std::memcpy(key_.keyfile_key_.data(), key_str.data(), key_str.size());
    return;
  }

  // If not XML, try to parse as a 64-character hexadecimal key.
  if (size != 64)
    throw FormatError("Unknown key file format.");

  for (std::size_t i = 0; i < key_.keyfile_key_.size(); ++i) {
    const int hi = HexValue(static_cast<char>(data[i * 2]));
    const int lo = HexValue(static_cast<char>(data[i * 2 + 1]));

    if (hi < 0 || lo < 0)
      throw FormatError("Unknown key file format.");

    key_.keyfile_key_[i] = static_cast<uint8_t>((hi << 4) | lo);
  }
}

Key Key::FromBytes(const std::string& password, const std::vector<uint8_t>& keyfile) {
  Key key(password);
  key.SetKeyFileData(keyfile.data(), keyfile.size());
  return key;
}

Key Key::FromStream(const std::string& password, std::istream& keyfile) {
  Key key(password);
  key.SetKeyFile(keyfile);
  return key;
}

SecureBuffer<32> Key::Transform(const SecureBuffer<32>& seed, uint64_t rounds,
                                SubKeyResolution resolution) const {
  if (has_transformed_key_)
    return transformed_key_.Clone();

  SecureBuffer<32> transformed_key;
  key_.Resolve(resolution, transformed_key);
  SecureBuffer<32> encrypted;

#if LIBKEEPASS_AES_NI
  if (aes_ni_supported()) {
    aes_ni_transform_aes_kdf(seed.data(), transformed_key.data(), rounds, encrypted.data());
    transformed_key = std::move(encrypted);
  } else
#endif
  {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr ||
        EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), nullptr, seed.data(), nullptr) != 1) {
      if (ctx != nullptr)
        EVP_CIPHER_CTX_free(ctx);
      throw InternalError("Failed to initialize AES-KDF.");
    }
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    for (uint64_t i = 0; i < rounds; ++i) {
      int outl = 0;
      if (EVP_EncryptUpdate(ctx, encrypted.data(), &outl, transformed_key.data(),
                            static_cast<int>(transformed_key.size())) != 1 ||
          outl != static_cast<int>(transformed_key.size())) {
        EVP_CIPHER_CTX_free(ctx);
        throw InternalError("AES-KDF transform failed.");
      }
      transformed_key = encrypted.Clone();
    }
    EVP_CIPHER_CTX_free(ctx);
  }

  EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
  EVP_DigestUpdate(mdctx, transformed_key.data(), transformed_key.size());
  unsigned int out_len = 0;
  EVP_DigestFinal_ex(mdctx, transformed_key.data(), &out_len);
  EVP_MD_CTX_free(mdctx);
  return transformed_key;
}

SecureBuffer<32> Key::TransformArgon2(Kdf kdf, const SecureBytes& salt, uint64_t iterations,
                                      uint64_t memory_bytes, uint32_t parallelism,
                                      uint32_t argon2_version, SubKeyResolution resolution) const {
  if (has_transformed_key_)
    return transformed_key_.Clone();

  SecureBuffer<32> transformed_key;
  SecureBuffer<32> composite_key;
  key_.Resolve(resolution, composite_key);

  uint32_t memory_kib = static_cast<uint32_t>(memory_bytes / 1024ULL);

  uint32_t version = argon2_version == 0x10 ? ARGON2_VERSION_10 : ARGON2_VERSION_13;

  argon2_type type = kdf == Kdf::kArgon2d ? Argon2_d : Argon2_id;

  int rc = argon2_hash(static_cast<uint32_t>(iterations), memory_kib, parallelism,
                       composite_key.data(), composite_key.size(), salt.data(), salt.size(),
                       transformed_key.data(), transformed_key.size(), nullptr, 0, type, version);

  if (rc != ARGON2_OK)
    throw InternalError(std::string("Argon2 error: ") + argon2_error_message(rc));

  return transformed_key;
}

} // namespace keepass
