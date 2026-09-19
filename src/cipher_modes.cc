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

#include <algorithm>
#include <cassert>
#include <functional>
#include <vector>

#include "libkeepass/exception.hh"
#include "libkeepass/secure.hh"
#include "libkeepass/stream.hh"
#include "libkeepass/util.hh"

namespace {

template <std::size_t N>
using BlockOperation = std::function<std::size_t(const std::array<uint8_t, N>&,
                                                 std::array<uint8_t, N>&, std::size_t, bool)>;

template <std::size_t N>
void block_transform(std::istream& src, std::ostream& dst, BlockOperation<N>&& op) {
  std::array<uint8_t, N> src_block{}, dst_block{};

  std::streampos pos = src.tellg();
  src.seekg(0, std::ios::end);
  std::streampos end = src.tellg();
  src.seekg(pos, std::ios::beg);

  std::streamsize remaining = end - pos;

  while (src.good()) {
    src.read(reinterpret_cast<char*>(src_block.data()), src_block.size());
    if (src.eof() && src.gcount() == 0)
      break;

    std::streamsize read_bytes = src.gcount();
    remaining -= read_bytes;

    std::size_t dst_bytes =
        op(src_block, dst_block, static_cast<unsigned long>(read_bytes), remaining == 0);

    dst.write(reinterpret_cast<const char*>(dst_block.data()),
              static_cast<std::streamsize>(dst_bytes));

    // The block buffers transiently hold plaintext (encrypt input and decrypt
    // output), so zeroize them after each block.
    keepass::secure_zero(src_block.data(), src_block.size());
    keepass::secure_zero(dst_block.data(), dst_block.size());
  }
}

} // namespace

namespace keepass {

std::array<uint8_t, 32> encrypt_ecb(const std::array<uint8_t, 32>& src, const Cipher<16>& cipher) {
  std::array<uint8_t, 32> dst{};

  std::array<uint8_t, 16> src_block{}, dst_block{};
  std::copy_n(src.begin(), 16, src_block.begin());
  cipher.Encrypt(src_block, dst_block);
  std::copy(dst_block.begin(), dst_block.end(), dst.begin());

  std::copy_n(src.begin() + 16, 16, src_block.begin());
  cipher.Encrypt(src_block, dst_block);
  std::copy(dst_block.begin(), dst_block.end(), dst.begin() + 16);

  secure_zero(src_block.data(), src_block.size());
  secure_zero(dst_block.data(), dst_block.size());

  return dst;
}

std::array<uint8_t, 32> decrypt_ecb(const std::array<uint8_t, 32>& src, const Cipher<16>& cipher) {
  std::array<uint8_t, 32> dst{};

  std::array<uint8_t, 16> src_block{}, dst_block{};
  std::copy_n(src.begin(), 16, src_block.begin());
  cipher.Decrypt(src_block, dst_block);
  std::copy(dst_block.begin(), dst_block.end(), dst.begin());

  std::copy_n(src.begin() + 16, 16, src_block.begin());
  cipher.Decrypt(src_block, dst_block);
  std::copy(dst_block.begin(), dst_block.end(), dst.begin() + 16);

  secure_zero(src_block.data(), src_block.size());
  secure_zero(dst_block.data(), dst_block.size());

  return dst;
}

void encrypt_cbc(std::istream& src, std::ostream& dst, const Cipher<16>& cipher) {
  std::array<uint8_t, 16> prv = cipher.InitializationVector();

  uint32_t pad_len = 0;
  block_transform<16>(src, dst,
                      [&](const std::array<uint8_t, 16>& block_in,
                          std::array<uint8_t, 16>& block_out, std::size_t src_len,
                          bool) -> std::size_t {
                        std::array<uint8_t, 16> src_xor_iv{};
                        for (std::size_t i = 0; i < src_xor_iv.size(); ++i)
                          src_xor_iv[i] = static_cast<uint8_t>(block_in[i] ^ prv[i]);

                        if (src_len != 16) {
                          // Handle PKCS #7 padding for the last block.
                          assert(src_len <= 16);
                          pad_len = 16 - static_cast<uint32_t>(src_len);
                          assert(pad_len > 0 && pad_len <= 16);

                          for (std::size_t i = 16 - pad_len; i < 16; i++) {
                            src_xor_iv[i] = static_cast<uint8_t>(pad_len) ^ prv[i];
                          }
                        }

                        cipher.Encrypt(src_xor_iv, block_out);
                        prv = block_out;

                        return 16;
                      });

  // We must always apply padding.
  if (pad_len == 0) {
    std::array<uint8_t, 16> src_block{}, dst_block{};
    std::array<uint8_t, 16> src_block_xor_iv{};

    std::fill(src_block.begin(), src_block.end(), static_cast<uint8_t>(16));
    for (std::size_t i = 0; i < src_block_xor_iv.size(); ++i)
      src_block_xor_iv[i] = static_cast<uint8_t>(src_block[i] ^ prv[i]);

    cipher.Encrypt(src_block_xor_iv, dst_block);
    dst.write(reinterpret_cast<const char*>(dst_block.data()), dst_block.size());
  }
}

void decrypt_cbc(std::istream& src, std::ostream& dst, const Cipher<16>& cipher) {
  std::array<uint8_t, 16> prv = cipher.InitializationVector();

  block_transform<16>(src, dst,
                      [&](const std::array<uint8_t, 16>& block_in,
                          std::array<uint8_t, 16>& block_out, std::size_t src_len,
                          bool last) -> std::size_t {
                        if (src_len != 16)
                          throw IoError("Decryption error.");

                        cipher.Decrypt(block_in, block_out);

                        for (std::size_t i = 0; i < block_out.size(); ++i)
                          block_out[i] = static_cast<uint8_t>(block_out[i] ^ prv[i]);

                        if (last) {
                          // Handle PKCS #7 padding for the last block.
                          uint32_t pad_len = block_out[15];
                          if (pad_len > 16)
                            throw IoError("Decryption error.");

                          for (std::size_t i = 16 - pad_len; i < 16; ++i) {
                            if (block_out[i] != pad_len)
                              throw IoError("Decryption error.");
                          }

                          return 16 - pad_len;
                        }

                        prv = block_in;
                        return 16;
                      });
}

void decrypt_cbc_stream(std::istream& src, std::ostream& dst, const Cipher<16>& cipher) {
  std::array<uint8_t, 16> prv = cipher.InitializationVector();

  // The plaintext of a block is only written once the next ciphertext block is
  // in hand, so that the final block can be validated and its PKCS #7 padding
  // stripped before it reaches the output.
  std::array<uint8_t, 16> pending_out{};
  bool have_pending = false;

  // Ciphertext bytes not yet grouped into a full (16-byte) block.
  std::vector<uint8_t> bytes;
  bytes.reserve(64 + 16);

  std::array<uint8_t, 64> chunk{};
  while (true) {
    src.read(reinterpret_cast<char*>(chunk.data()), chunk.size());
    const std::streamsize got = src.gcount();
    if (got == 0)
      break;
    bytes.insert(bytes.end(), chunk.begin(), chunk.begin() + got);

    // Decrypt every complete block read so far.
    std::size_t consumed = 0;
    while (bytes.size() - consumed >= 16) {
      std::array<uint8_t, 16> block_in{};
      std::array<uint8_t, 16> block_out{};
      std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(consumed), 16, block_in.begin());
      consumed += 16;

      cipher.Decrypt(block_in, block_out);
      for (std::size_t i = 0; i < block_out.size(); ++i)
        block_out[i] = static_cast<uint8_t>(block_out[i] ^ prv[i]);

      if (have_pending) {
        dst.write(reinterpret_cast<const char*>(pending_out.data()), pending_out.size());
        secure_zero(pending_out.data(), pending_out.size());
      }
      pending_out = block_out;
      have_pending = true;
      prv = block_in;

      // The block buffers transiently hold plaintext and ciphertext.
      secure_zero(block_out.data(), block_out.size());
      secure_zero(block_in.data(), block_in.size());
    }

    if (consumed > 0)
      bytes.erase(bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(consumed));
  }

  // A trailing amount that does not fill a complete block is malformed.
  if (!bytes.empty())
    throw IoError("Decryption error.");
  secure_zero(bytes.data(), bytes.size());
  secure_zero(chunk.data(), chunk.size());

  // Strip PKCS #7 padding from the final block.
  if (have_pending) {
    uint32_t pad_len = pending_out[15];
    if (pad_len > 16)
      throw IoError("Decryption error.");

    for (std::size_t i = 16 - pad_len; i < 16; ++i) {
      if (pending_out[i] != pad_len)
        throw IoError("Decryption error.");
    }

    dst.write(reinterpret_cast<const char*>(pending_out.data()), 16 - pad_len);
    secure_zero(pending_out.data(), pending_out.size());
  }

  secure_zero(prv.data(), prv.size());
}

} // namespace keepass