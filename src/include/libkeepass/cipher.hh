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

/** @file cipher.hh @brief Block and stream cipher abstractions for KeePass encryption. */

#pragma once
#include <array>
#include <cassert>
#include <cstdint>
#include <iostream>
#include <memory>

#include <openssl/evp.h>

#include "libkeepass/export.hh"

namespace keepass {

template <std::size_t N> class Cipher;

/**
 * @brief Encrypts a 32-byte block using ECB mode with the given cipher.
 *
 * @param src The 32-byte plaintext block (two 16-byte blocks).
 * @param cipher The block cipher to use for encryption.
 * @return The 32-byte ciphertext block.
 */
LIBKEEPASS_API std::array<uint8_t, 32> encrypt_ecb(const std::array<uint8_t, 32>& src,
                                                   const Cipher<16>& cipher);

/**
 * @brief Decrypts a 32-byte block using ECB mode with the given cipher.
 *
 * @param src The 32-byte ciphertext block (two 16-byte blocks).
 * @param cipher The block cipher to use for decryption.
 * @return The 32-byte plaintext block.
 */
LIBKEEPASS_API std::array<uint8_t, 32> decrypt_ecb(const std::array<uint8_t, 32>& src,
                                                   const Cipher<16>& cipher);

/**
 * @brief Encrypts a stream using CBC mode with PKCS #7 padding.
 *
 * Reads from @p src, encrypts block-by-block using @p cipher, and writes
 * the ciphertext to @p dst. An initialization vector is obtained from the
 * cipher. A full PKCS #7 padding block is always appended.
 *
 * @param src Input stream containing the plaintext.
 * @param dst Output stream receiving the ciphertext.
 * @param cipher The block cipher used for each block encryption.
 * @throws IoError If an I/O error occurs.
 * @throws InternalError If an internal error occurs.
 */
LIBKEEPASS_API void encrypt_cbc(std::istream& src, std::ostream& dst, const Cipher<16>& cipher);

/**
 * @brief Decrypts a stream using CBC mode with PKCS #7 padding removal.
 *
 * Reads from @p src, decrypts block-by-block using @p cipher, and writes
 * the plaintext to @p dst. The initialization vector is obtained from the
 * cipher. PKCS #7 padding is validated and stripped from the last block.
 *
 * @param src Input stream containing the ciphertext.
 * @param dst Output stream receiving the plaintext.
 * @param cipher The block cipher used for each block decryption.
 * @throws IoError If decryption fails, padding is invalid, or an I/O error occurs.
 */
LIBKEEPASS_API void decrypt_cbc(std::istream& src, std::ostream& dst, const Cipher<16>& cipher);

/**
 * @brief Abstract base class for 16-byte block ciphers.
 *
 * @tparam N The block size in bytes (always 16 for the ciphers in this library).
 */
template <std::size_t N> class Cipher {
public:
  virtual ~Cipher() = default;

  /**
   * @brief Returns the initialization vector used by this cipher instance.
   * @return A reference to the 16-byte initialization vector.
   */
  virtual const std::array<uint8_t, N>& InitializationVector() const = 0;

  /**
   * @brief Decrypts a single block.
   *
   * @param src The ciphertext block to decrypt.
   * @param dst The resulting plaintext block.
   */
  virtual void Decrypt(const std::array<uint8_t, N>& src, std::array<uint8_t, N>& dst) const = 0;

  /**
   * @brief Encrypts a single block.
   *
   * @param src The plaintext block to encrypt.
   * @param dst The resulting ciphertext block.
   */
  virtual void Encrypt(const std::array<uint8_t, N>& src, std::array<uint8_t, N>& dst) const = 0;
};

/**
 * @brief AES-256-ECB block cipher using OpenSSL's EVP interface.
 */
class LIBKEEPASS_API AesCipher final : public Cipher<16> {
private:
  const std::array<uint8_t, 16> init_vec_;
  EVP_CIPHER_CTX* ctx_dec_ = nullptr;
  EVP_CIPHER_CTX* ctx_enc_ = nullptr;

public:
  /**
   * @brief Constructs an AES cipher with a zero initialization vector.
   *
   * @param key The 256-bit (32-byte) encryption key.
   */
  explicit AesCipher(const std::array<uint8_t, 32>& key) : AesCipher(key, {0}) {}

  /**
   * @brief Constructs an AES cipher with a given initialization vector.
   *
   * @param key The 256-bit (32-byte) encryption key.
   * @param init_vec The 16-byte initialization vector.
   * @throws InternalError If the OpenSSL cipher context cannot be created or initialized.
   */
  AesCipher(const std::array<uint8_t, 32>& key, const std::array<uint8_t, 16>& init_vec);

  /// Destroys the cipher and frees the OpenSSL contexts.
  ~AesCipher();

  /// @brief Returns the initialization vector.
  const std::array<uint8_t, 16>& InitializationVector() const override { return init_vec_; }

  /**
   * @brief Decrypts a single 16-byte block using AES-256-ECB.
   *
   * @param src The ciphertext block to decrypt.
   * @param dst The resulting plaintext block.
   */
  void Decrypt(const std::array<uint8_t, 16>& src, std::array<uint8_t, 16>& dst) const override;

  /**
   * @brief Encrypts a single 16-byte block using AES-256-ECB.
   *
   * @param src The plaintext block to encrypt.
   * @param dst The resulting ciphertext block.
   */
  void Encrypt(const std::array<uint8_t, 16>& src, std::array<uint8_t, 16>& dst) const override;
};

/**
 * @brief Twofish-256 block cipher implementation.
 */
class LIBKEEPASS_API TwofishCipher final : public Cipher<16> {
private:
  static const uint8_t kNumRounds = 16;

  struct Key {
    /** Key bits used for S-boxes. */
    uint32_t sbox_keys[4];
    /** Round subkeys, input/output whitening bits. */
    uint32_t sub_keys[40];
  } key_{};

  const std::array<uint8_t, 16> init_vec_;

  static inline uint32_t RotateLeft(uint32_t v, uint32_t n) {
    return (v << (n & 0x1f)) | (v >> (32 - (n & 0x1f)));
  }

  static inline uint32_t RotateRight(uint32_t v, uint32_t n) {
    return (v >> (n & 0x1f)) | (v << (32 - (n & 0x1f)));
  }

  /**
   * @brief Computes a Reed-Solomon encoding for the key schedule.
   *
   * @param k0 First 32-bit key half.
   * @param k1 Second 32-bit key half.
   * @return The 32-bit Reed-Solomon codeword.
   */
  static uint32_t ReedSolomonEncode(uint32_t k0, uint32_t k1);

  /**
   * @brief Evaluates the Twofish Pseudo-Hadamard Transform F function.
   *
   * @param x Input value.
   * @param k32 Pointer to four 32-bit key words.
   * @return The 32-bit output of the F function.
   */
  static uint32_t F32(uint32_t x, const uint32_t* k32);

  /// Initializes the Twofish key schedule from the given 256-bit key.
  void InitializeKey(const std::array<uint8_t, 32>& key);

public:
  /**
   * @brief Constructs a Twofish cipher with a zero initialization vector.
   *
   * @param key The 256-bit (32-byte) encryption key.
   */
  explicit TwofishCipher(const std::array<uint8_t, 32>& key) : TwofishCipher(key, {0}) {}

  /**
   * @brief Constructs a Twofish cipher with a given initialization vector.
   *
   * @param key The 256-bit (32-byte) encryption key.
   * @param init_vec The 16-byte initialization vector.
   */
  TwofishCipher(const std::array<uint8_t, 32>& key, const std::array<uint8_t, 16>& init_vec);

  /// @brief Returns the initialization vector.
  const std::array<uint8_t, 16>& InitializationVector() const override { return init_vec_; }

  /**
   * @brief Decrypts a single 16-byte block using Twofish-256.
   *
   * @param src The ciphertext block to decrypt.
   * @param dst The resulting plaintext block.
   */
  void Decrypt(const std::array<uint8_t, 16>& src, std::array<uint8_t, 16>& dst) const override;

  /**
   * @brief Encrypts a single 16-byte block using Twofish-256.
   *
   * @param src The plaintext block to encrypt.
   * @param dst The resulting ciphertext block.
   */
  void Encrypt(const std::array<uint8_t, 16>& src, std::array<uint8_t, 16>& dst) const override;
};

/**
 * @brief Salsa20 stream cipher implementation.
 */
class LIBKEEPASS_API Salsa20Cipher final {
private:
  std::array<uint32_t, 16> input_ = {{0}};

  static inline uint32_t RotateLeft(uint32_t v, uint32_t n) {
    return (v << (n & 0x1f)) | (v >> (32 - (n & 0x1f)));
  }

  /**
   * @brief Produces one 64-byte keystream block from the current state.
   *
   * @param input The 16-word cipher state.
   * @return A 64-byte array of keystream bytes.
   */
  static std::array<uint8_t, 64> WordToByte(const std::array<uint32_t, 16>& input);

public:
  /**
   * @brief Constructs a Salsa20 cipher with a zero nonce.
   *
   * @param key The 256-bit (32-byte) encryption key.
   */
  explicit Salsa20Cipher(const std::array<uint8_t, 32>& key) : Salsa20Cipher(key, {0}) {}

  /**
   * @brief Constructs a Salsa20 cipher with a given 64-bit nonce.
   *
   * @param key The 256-bit (32-byte) encryption key.
   * @param init_vec The 8-byte nonce (initialization vector).
   */
  Salsa20Cipher(const std::array<uint8_t, 32>& key, const std::array<uint8_t, 8>& init_vec);

  /**
   * @brief Encrypts or decrypts a single 64-byte block.
   *
   * Because Salsa20 is a stream cipher, encryption and decryption are
   * the same XOR operation. The internal counter is advanced after each call.
   *
   * @param src The 64-byte input block (plaintext or ciphertext).
   * @param dst The 64-byte output block (ciphertext or plaintext).
   */
  void Process(const std::array<uint8_t, 64>& src, std::array<uint8_t, 64>& dst);
};

/**
 * @brief ChaCha20 stream cipher implementation (RFC 8439, 32-bit counter).
 */
class LIBKEEPASS_API ChaCha20Cipher final {
private:
  std::array<uint32_t, 16> state_ = {{0}};

  static inline uint32_t RotateLeft(uint32_t v, uint32_t n) {
    return (v << (n & 0x1f)) | (v >> (32 - (n & 0x1f)));
  }

  /**
   * @brief Produces one 64-byte keystream block from the current state.
   *
   * @param state The 16-word cipher state.
   * @return A 64-byte array of keystream bytes.
   */
  static std::array<uint8_t, 64> BlockFunction(const std::array<uint32_t, 16>& state);

public:
  /**
   * @brief Constructs a ChaCha20 cipher with the given key and nonce.
   *
   * @param key The 256-bit (32-byte) encryption key.
   * @param init_vec The 12-byte nonce (initialization vector).
   */
  ChaCha20Cipher(const std::array<uint8_t, 32>& key, const std::array<uint8_t, 12>& init_vec);

  /**
   * @brief Encrypts or decrypts a single 64-byte block.
   *
   * Because ChaCha20 is a stream cipher, encryption and decryption are
   * the same XOR operation. The internal counter is advanced after each call.
   *
   * @param src The 64-byte input block (plaintext or ciphertext).
   * @param dst The 64-byte output block (ciphertext or plaintext).
   */
  void Process(const std::array<uint8_t, 64>& src, std::array<uint8_t, 64>& dst);
};

} // namespace keepass
