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

#include <openssl/evp.h>

namespace keepass {

namespace {
constexpr std::array<uint8_t, 8> kSalsa20Iv = {0xe8, 0x30, 0x09, 0x4b, 0x97, 0x20, 0x5d, 0x2a};
} // namespace

RandomObfuscator::RandomObfuscator(const std::array<uint8_t, 32>& key,
                                   const std::array<uint8_t, 8>& init_vec)
    : salsa_cipher_(key, init_vec), chacha_cipher_({0}, {0}) {}

RandomObfuscator::RandomObfuscator(Type type, const std::array<uint8_t, 32>& stream_key)
    : RandomObfuscator(type, std::vector<uint8_t>(stream_key.begin(), stream_key.end())) {}

RandomObfuscator::RandomObfuscator(Type type, const std::vector<uint8_t>& stream_key)
    : type_(type), salsa_cipher_({0}, {0}), chacha_cipher_({0}, {0}) {
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

    chacha_cipher_ = ChaCha20Cipher(key, iv);
  } else {
    std::array<uint8_t, 32> key{};

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(mdctx, stream_key.data(), stream_key.size());
    unsigned int out_len = 0;
    EVP_DigestFinal_ex(mdctx, key.data(), &out_len);
    EVP_MD_CTX_free(mdctx);

    salsa_cipher_ = Salsa20Cipher(key, kSalsa20Iv);
  }
}

void RandomObfuscator::FillBuffer() {
  static constexpr std::array<uint8_t, 64> kZeroBlock = {0};

  assert(buffer_pos_ == buffer_.size());

  if (type_ == Type::kChaCha20)
    chacha_cipher_.Process(kZeroBlock, buffer_);
  else
    salsa_cipher_.Process(kZeroBlock, buffer_);

  buffer_pos_ = 0;
}

std::vector<uint8_t> RandomObfuscator::Process(const std::vector<uint8_t>& data) {
  std::vector<uint8_t> obfuscated_data;
  obfuscated_data.resize(data.size());

  for (std::size_t i = 0; i < data.size(); ++i) {
    if (buffer_pos_ == buffer_.size())
      FillBuffer();

    obfuscated_data[i] = data[i] ^ buffer_[buffer_pos_++];
  }

  return obfuscated_data;
}

std::string RandomObfuscator::Process(const std::string& data) {
  std::string obfuscated_data;
  obfuscated_data.resize(data.size());

  for (std::size_t i = 0; i < data.size(); ++i) {
    if (buffer_pos_ == buffer_.size())
      FillBuffer();

    obfuscated_data[i] = static_cast<char>(data[i] ^ buffer_[buffer_pos_++]);
  }

  return obfuscated_data;
}

} // namespace keepass
