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

#include "libkeepass/random.hh"

#include <algorithm>
#include <cstring>

#include <openssl/evp.h>

#include "libkeepass/secure.hh"

namespace keepass {

namespace {
constexpr std::array<uint8_t, 8> kSalsa20Iv = {0xe8, 0x30, 0x09, 0x4b, 0x97, 0x20, 0x5d, 0x2a};
} // namespace

RandomObfuscator::RandomObfuscator(const std::array<uint8_t, 32>& key,
                                   const std::array<uint8_t, 8>& init_vec)
    : salsa_cipher_(key.data(), init_vec), chacha_cipher_(nullptr, std::array<uint8_t, 12>()) {}

RandomObfuscator::RandomObfuscator(Type type, const std::array<uint8_t, 32>& stream_key)
    : RandomObfuscator(type, std::vector<uint8_t>(stream_key.begin(), stream_key.end())) {}

RandomObfuscator::RandomObfuscator(Type type, const std::vector<uint8_t>& stream_key)
    : type_(type), salsa_cipher_(nullptr, std::array<uint8_t, 8>()),
      chacha_cipher_(nullptr, std::array<uint8_t, 12>()) {
  if (type_ == Type::kChaCha20) {
    std::array<uint8_t, 64> key_iv{};

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha512(), nullptr);
    EVP_DigestUpdate(mdctx, stream_key.data(), stream_key.size());
    unsigned int out_len = 0;
    EVP_DigestFinal_ex(mdctx, key_iv.data(), &out_len);
    EVP_MD_CTX_free(mdctx);

    std::array<uint8_t, 32> key{};
    std::copy(key_iv.begin(), key_iv.begin() + 32, key.begin());

    std::array<uint8_t, 12> iv{};
    std::copy(key_iv.begin() + 32, key_iv.begin() + 44, iv.begin());

    chacha_cipher_ = ChaCha20Cipher(key.data(), iv);
    secure_zero(key_iv.data(), key_iv.size());
    secure_zero(key.data(), key.size());
  } else {
    std::array<uint8_t, 32> key{};

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(mdctx, stream_key.data(), stream_key.size());
    unsigned int out_len = 0;
    EVP_DigestFinal_ex(mdctx, key.data(), &out_len);
    EVP_MD_CTX_free(mdctx);

    salsa_cipher_ = Salsa20Cipher(key.data(), kSalsa20Iv);
    secure_zero(key.data(), key.size());
  }
}

RandomObfuscator::~RandomObfuscator() { secure_zero(buffer_.data(), buffer_.size()); }

void RandomObfuscator::FillBuffer() {
  static constexpr std::array<uint8_t, 64> kZeroBlock = {0};

  assert(buffer_pos_ == buffer_.size());

  if (type_ == Type::kChaCha20)
    chacha_cipher_.Process(kZeroBlock, buffer_);
  else
    salsa_cipher_.Process(kZeroBlock, buffer_);

  buffer_pos_ = 0;
}

void RandomObfuscator::ProcessBytes(uint8_t* data, std::size_t size) {
  // Consume the keystream in whole 64-byte blocks and XOR word-wise where
  // possible. memcpy keeps the accesses both alignment-safe and endian-safe:
  // the same byte order is used for both operands and the result.
  constexpr std::size_t kWordSize = sizeof(uint64_t);

  while (size > 0) {
    if (buffer_pos_ == buffer_.size())
      FillBuffer();

    const std::size_t count = std::min(size, buffer_.size() - buffer_pos_);
    const uint8_t* keystream = buffer_.data() + buffer_pos_;

    std::size_t i = 0;
    for (; i + kWordSize <= count; i += kWordSize) {
      uint64_t value = 0;
      uint64_t key = 0;
      std::memcpy(&value, data + i, kWordSize);
      std::memcpy(&key, keystream + i, kWordSize);
      value ^= key;
      std::memcpy(data + i, &value, kWordSize);
    }
    for (; i < count; ++i)
      data[i] ^= keystream[i];

    buffer_pos_ += count;
    data += count;
    size -= count;
  }
}

std::vector<uint8_t> RandomObfuscator::Process(const std::vector<uint8_t>& data) {
  std::vector<uint8_t> obfuscated_data(data);
  ProcessBytes(obfuscated_data.data(), obfuscated_data.size());
  return obfuscated_data;
}

std::string RandomObfuscator::Process(const std::string& data) {
  std::string obfuscated_data(data);
  ProcessBytes(reinterpret_cast<uint8_t*>(obfuscated_data.data()), obfuscated_data.size());
  return obfuscated_data;
}

secure_string RandomObfuscator::Process(const secure_string& data) {
  secure_string obfuscated_data(data);
  ProcessBytes(reinterpret_cast<uint8_t*>(obfuscated_data.data()), obfuscated_data.size());
  return obfuscated_data;
}

} // namespace keepass
