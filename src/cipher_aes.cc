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

#include "libkeepass/cipher.hh"

#include <cassert>

#include "libkeepass/exception.hh"

namespace keepass {

AesCipher::AesCipher(const uint8_t* key, const std::array<uint8_t, 16>& init_vec)
    : init_vec_(init_vec) {
  if (key == nullptr) {
    assert(false);
    throw InternalError("Invalid AES key.");
  }
  ctx_dec_ = EVP_CIPHER_CTX_new();
  ctx_enc_ = EVP_CIPHER_CTX_new();
  if (!ctx_dec_ || !ctx_enc_) {
    if (ctx_dec_)
      EVP_CIPHER_CTX_free(ctx_dec_);
    if (ctx_enc_)
      EVP_CIPHER_CTX_free(ctx_enc_);
    assert(false);
    throw InternalError("Failed to create AES cipher context.");
  }
  if (EVP_DecryptInit_ex(ctx_dec_, EVP_aes_256_ecb(), nullptr, key, nullptr) != 1 ||
      EVP_EncryptInit_ex(ctx_enc_, EVP_aes_256_ecb(), nullptr, key, nullptr) != 1) {
    EVP_CIPHER_CTX_free(ctx_dec_);
    EVP_CIPHER_CTX_free(ctx_enc_);
    assert(false);
    throw InternalError("Failed to initialize AES cipher.");
  }
  EVP_CIPHER_CTX_set_padding(ctx_dec_, 0);
  EVP_CIPHER_CTX_set_padding(ctx_enc_, 0);
}

AesCipher::~AesCipher() {
  if (ctx_dec_)
    EVP_CIPHER_CTX_free(ctx_dec_);
  if (ctx_enc_)
    EVP_CIPHER_CTX_free(ctx_enc_);
}

void AesCipher::Decrypt(const std::array<uint8_t, 16>& src, std::array<uint8_t, 16>& dst) const {
  int outl = 0;
  EVP_DecryptUpdate(ctx_dec_, dst.data(), &outl, src.data(), static_cast<int>(src.size()));
}

void AesCipher::Encrypt(const std::array<uint8_t, 16>& src, std::array<uint8_t, 16>& dst) const {
  int outl = 0;
  EVP_EncryptUpdate(ctx_enc_, dst.data(), &outl, src.data(), static_cast<int>(src.size()));
}

} // namespace keepass