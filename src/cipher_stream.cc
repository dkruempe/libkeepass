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

#include "libkeepass/secure.hh"

namespace keepass {

Salsa20Cipher::Salsa20Cipher(const uint8_t* key, const std::array<uint8_t, 8>& init_vec) {
  static const char* kSigma = "expand 32-byte k";
  static const std::array<uint8_t, 32> kZeroKey = {{0}};

  if (key == nullptr)
    key = kZeroKey.data();
  const uint8_t* key_ptr = key;

  input_[1] = *reinterpret_cast<const uint32_t*>(key_ptr + 0);
  input_[2] = *reinterpret_cast<const uint32_t*>(key_ptr + 4);
  input_[3] = *reinterpret_cast<const uint32_t*>(key_ptr + 8);
  input_[4] = *reinterpret_cast<const uint32_t*>(key_ptr + 12);

  input_[11] = *reinterpret_cast<const uint32_t*>(key_ptr + 16);
  input_[12] = *reinterpret_cast<const uint32_t*>(key_ptr + 20);
  input_[13] = *reinterpret_cast<const uint32_t*>(key_ptr + 24);
  input_[14] = *reinterpret_cast<const uint32_t*>(key_ptr + 28);
  input_[0] = *reinterpret_cast<const uint32_t*>(kSigma + 0);
  input_[5] = *reinterpret_cast<const uint32_t*>(kSigma + 4);
  input_[10] = *reinterpret_cast<const uint32_t*>(kSigma + 8);
  input_[15] = *reinterpret_cast<const uint32_t*>(kSigma + 12);

  input_[6] = *reinterpret_cast<const uint32_t*>(init_vec.data() + 0);
  input_[7] = *reinterpret_cast<const uint32_t*>(init_vec.data() + 4);
  input_[8] = 0;
  input_[9] = 0;
}

Salsa20Cipher::~Salsa20Cipher() { secure_zero(input_.data(), input_.size() * sizeof(uint32_t)); }

std::array<uint8_t, 64> Salsa20Cipher::WordToByte(const std::array<uint32_t, 16>& input) {
  uint32_t x[16];

  for (std::size_t i = 0; i < 16; ++i)
    x[i] = input[i];

  for (std::size_t i = 0; i < 10; ++i) {
    x[4] ^= RotateLeft(x[0] + x[12], 7);
    x[8] ^= RotateLeft(x[4] + x[0], 9);
    x[12] ^= RotateLeft(x[8] + x[4], 13);
    x[0] ^= RotateLeft(x[12] + x[8], 18);
    x[9] ^= RotateLeft(x[5] + x[1], 7);
    x[13] ^= RotateLeft(x[9] + x[5], 9);
    x[1] ^= RotateLeft(x[13] + x[9], 13);
    x[5] ^= RotateLeft(x[1] + x[13], 18);
    x[14] ^= RotateLeft(x[10] + x[6], 7);
    x[2] ^= RotateLeft(x[14] + x[10], 9);
    x[6] ^= RotateLeft(x[2] + x[14], 13);
    x[10] ^= RotateLeft(x[6] + x[2], 18);
    x[3] ^= RotateLeft(x[15] + x[11], 7);
    x[7] ^= RotateLeft(x[3] + x[15], 9);
    x[11] ^= RotateLeft(x[7] + x[3], 13);
    x[15] ^= RotateLeft(x[11] + x[7], 18);
    x[1] ^= RotateLeft(x[0] + x[3], 7);
    x[2] ^= RotateLeft(x[1] + x[0], 9);
    x[3] ^= RotateLeft(x[2] + x[1], 13);
    x[0] ^= RotateLeft(x[3] + x[2], 18);
    x[6] ^= RotateLeft(x[5] + x[4], 7);
    x[7] ^= RotateLeft(x[6] + x[5], 9);
    x[4] ^= RotateLeft(x[7] + x[6], 13);
    x[5] ^= RotateLeft(x[4] + x[7], 18);
    x[11] ^= RotateLeft(x[10] + x[9], 7);
    x[8] ^= RotateLeft(x[11] + x[10], 9);
    x[9] ^= RotateLeft(x[8] + x[11], 13);
    x[10] ^= RotateLeft(x[9] + x[8], 18);
    x[12] ^= RotateLeft(x[15] + x[14], 7);
    x[13] ^= RotateLeft(x[12] + x[15], 9);
    x[14] ^= RotateLeft(x[13] + x[12], 13);
    x[15] ^= RotateLeft(x[14] + x[13], 18);
  }

  for (std::size_t i = 0; i < 16; ++i)
    x[i] = x[i] + input[i];

  std::array<uint8_t, 64> output{};
  for (std::size_t i = 0; i < 16; ++i)
    *reinterpret_cast<uint32_t*>(output.data() + 4 * i) = x[i];

  return output;
}

void Salsa20Cipher::Process(const std::array<uint8_t, 64>& src, std::array<uint8_t, 64>& dst) {
  std::array<uint8_t, 64> output = WordToByte(input_);

  input_[8]++;
  if (!input_[8])
    input_[9]++;

  for (std::size_t i = 0; i < src.size(); ++i)
    dst[i] = src[i] ^ output[i];
}

ChaCha20Cipher::ChaCha20Cipher(const uint8_t* key, const std::array<uint8_t, 12>& init_vec) {
  static const char* kSigma = "expand 32-byte k";
  static const std::array<uint8_t, 32> kZeroKey = {{0}};

  state_[0] = *reinterpret_cast<const uint32_t*>(kSigma + 0);
  state_[1] = *reinterpret_cast<const uint32_t*>(kSigma + 4);
  state_[2] = *reinterpret_cast<const uint32_t*>(kSigma + 8);
  state_[3] = *reinterpret_cast<const uint32_t*>(kSigma + 12);

  if (key == nullptr)
    key = kZeroKey.data();
  const uint8_t* key_ptr = key;
  for (std::size_t i = 0; i < 8; ++i)
    state_[4 + i] = *reinterpret_cast<const uint32_t*>(key_ptr + 4 * i);

  state_[12] = 0;

  const uint8_t* nounce_ptr = init_vec.data();
  for (std::size_t i = 0; i < 3; ++i)
    state_[13 + i] = *reinterpret_cast<const uint32_t*>(nounce_ptr + 4 * i);
}

ChaCha20Cipher::~ChaCha20Cipher() { secure_zero(state_.data(), state_.size() * sizeof(uint32_t)); }

// Runs the ChaCha20 round function (20 rounds, RFC 8439 quarter-rounds,
// column then diagonal) on the given 16-word state and adds the input state
// back to produce the 64-byte keystream block.
std::array<uint8_t, 64> ChaCha20Cipher::BlockFunction(const std::array<uint32_t, 16>& state) {
  // Work on a copy so the original state remains available for the final addition.
  uint32_t x[16];
  for (std::size_t i = 0; i < 16; ++i)
    x[i] = state[i];

  // 20 rounds = 10 double rounds; each double round runs four column
  // quarter-rounds followed by four diagonal quarter-rounds.
  for (std::size_t i = 0; i < 10; ++i) {
    x[0] += x[4];
    x[12] ^= x[0];
    x[12] = RotateLeft(x[12], 16);
    x[8] += x[12];
    x[4] ^= x[8];
    x[4] = RotateLeft(x[4], 12);
    x[0] += x[4];
    x[12] ^= x[0];
    x[12] = RotateLeft(x[12], 8);
    x[8] += x[12];
    x[4] ^= x[8];
    x[4] = RotateLeft(x[4], 7);

    x[1] += x[5];
    x[13] ^= x[1];
    x[13] = RotateLeft(x[13], 16);
    x[9] += x[13];
    x[5] ^= x[9];
    x[5] = RotateLeft(x[5], 12);
    x[1] += x[5];
    x[13] ^= x[1];
    x[13] = RotateLeft(x[13], 8);
    x[9] += x[13];
    x[5] ^= x[9];
    x[5] = RotateLeft(x[5], 7);

    x[2] += x[6];
    x[14] ^= x[2];
    x[14] = RotateLeft(x[14], 16);
    x[10] += x[14];
    x[6] ^= x[10];
    x[6] = RotateLeft(x[6], 12);
    x[2] += x[6];
    x[14] ^= x[2];
    x[14] = RotateLeft(x[14], 8);
    x[10] += x[14];
    x[6] ^= x[10];
    x[6] = RotateLeft(x[6], 7);

    x[3] += x[7];
    x[15] ^= x[3];
    x[15] = RotateLeft(x[15], 16);
    x[11] += x[15];
    x[7] ^= x[11];
    x[7] = RotateLeft(x[7], 12);
    x[3] += x[7];
    x[15] ^= x[3];
    x[15] = RotateLeft(x[15], 8);
    x[11] += x[15];
    x[7] ^= x[11];
    x[7] = RotateLeft(x[7], 7);

    // Diagonal quarter-rounds (second half of each double round).
    x[0] += x[5];
    x[15] ^= x[0];
    x[15] = RotateLeft(x[15], 16);
    x[10] += x[15];
    x[5] ^= x[10];
    x[5] = RotateLeft(x[5], 12);
    x[0] += x[5];
    x[15] ^= x[0];
    x[15] = RotateLeft(x[15], 8);
    x[10] += x[15];
    x[5] ^= x[10];
    x[5] = RotateLeft(x[5], 7);

    x[1] += x[6];
    x[12] ^= x[1];
    x[12] = RotateLeft(x[12], 16);
    x[11] += x[12];
    x[6] ^= x[11];
    x[6] = RotateLeft(x[6], 12);
    x[1] += x[6];
    x[12] ^= x[1];
    x[12] = RotateLeft(x[12], 8);
    x[11] += x[12];
    x[6] ^= x[11];
    x[6] = RotateLeft(x[6], 7);

    x[2] += x[7];
    x[13] ^= x[2];
    x[13] = RotateLeft(x[13], 16);
    x[8] += x[13];
    x[7] ^= x[8];
    x[7] = RotateLeft(x[7], 12);
    x[2] += x[7];
    x[13] ^= x[2];
    x[13] = RotateLeft(x[13], 8);
    x[8] += x[13];
    x[7] ^= x[8];
    x[7] = RotateLeft(x[7], 7);

    x[3] += x[4];
    x[14] ^= x[3];
    x[14] = RotateLeft(x[14], 16);
    x[9] += x[14];
    x[4] ^= x[9];
    x[4] = RotateLeft(x[4], 12);
    x[3] += x[4];
    x[14] ^= x[3];
    x[14] = RotateLeft(x[14], 8);
    x[9] += x[14];
    x[4] ^= x[9];
    x[4] = RotateLeft(x[4], 7);
  }

  // Add the original input state back to produce the keystream block.
  for (std::size_t i = 0; i < 16; ++i)
    x[i] += state[i];

  std::array<uint8_t, 64> output{};
  for (std::size_t i = 0; i < 16; ++i)
    *reinterpret_cast<uint32_t*>(output.data() + 4 * i) = x[i];

  return output;
}

void ChaCha20Cipher::Process(const std::array<uint8_t, 64>& src, std::array<uint8_t, 64>& dst) {
  std::array<uint8_t, 64> output = BlockFunction(state_);

  state_[12]++;
  if (!state_[12])
    state_[13]++;

  for (std::size_t i = 0; i < src.size(); ++i)
    dst[i] = src[i] ^ output[i];
}

} // namespace keepass