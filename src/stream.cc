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

#include "libkeepass/stream.hh"

#include <cassert>

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "libkeepass/exception.hh"
#include "libkeepass/format.hh"

namespace keepass {

std::array<uint8_t, 32> hashed_basic_streambuf::GetBlockHash() const {
  std::array<uint8_t, 32> block_hash{};

  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
  EVP_DigestUpdate(mdctx, block_.data(), block_.size());
  unsigned int out_len = 0;
  EVP_DigestFinal_ex(mdctx, block_hash.data(), &out_len);
  EVP_MD_CTX_free(mdctx);

  return block_hash;
}

int hashed_istreambuf::underflow() {
  static constexpr std::array<uint8_t, 32> kEmptyHash = {{0}};

  if (gptr() == egptr()) {
    BlockHeader header;
    src_.read(reinterpret_cast<char *>(&header), sizeof(BlockHeader));

    if (header.block_index != block_index_)
      throw IoError("Block index mismatch.");
    block_index_++;

    block_.clear();
    block_.resize(header.block_size);
    src_.read(block_.data(), static_cast<std::streamsize>(header.block_size));
    if (src_.gcount() != static_cast<std::streamsize>(header.block_size))
      throw IoError("Block read error.");

    if (header.block_size == 0) {
      if (header.block_hash != kEmptyHash)
        throw IoError("Corrupt EOS block.");

      return std::char_traits<char>::eof();
    }

    // Verify the block integrity.
    if (GetBlockHash() != header.block_hash)
      throw IoError("Block checksum error.");

    setg(block_.data(), block_.data(), block_.data() + block_.size());
  }

  return gptr() == egptr() ? std::char_traits<char>::eof()
                           : std::char_traits<char>::to_int_type(*gptr());
}

bool hashed_ostreambuf::FlushBlock() {
  static constexpr std::array<uint8_t, 32> kEmptyHash = {{0}};

  // Write block header and data.
  BlockHeader header;
  header.block_index = block_index_++;
  header.block_hash = block_.empty() ? kEmptyHash : GetBlockHash();
  header.block_size = static_cast<uint32_t>(block_.size());

  dst_.write(reinterpret_cast<const char *>(&header), sizeof(BlockHeader));
  dst_.write(block_.data(), static_cast<std::streamsize>(block_.size()));
  if (!dst_.good())
    return false;

  block_.clear();
  return true;
}

int hashed_ostreambuf::overflow(int c) {
  if (c == std::char_traits<char>::eof())
    return c;

  if (c > 0xff) {
    assert(false);
    throw InternalError("Trying to write multiple bytes to stream.");
  }

  block_.push_back(static_cast<char>(c));

  if (block_.size() == block_size_) {
    if (!FlushBlock())
      return std::char_traits<char>::eof();
  }

  return std::char_traits<char>::to_int_type(static_cast<char>(c));
}

int hashed_ostreambuf::sync() {
  if (!block_.empty()) {
    if (!FlushBlock())
      return -1;
  }

  // Write the trailing empty block.
  return FlushBlock() ? 0 : -1;
}

std::array<uint8_t, 64> hmac_istreambuf::GetCurrentHmacKey() const {
  std::array<uint8_t, 64> hmac_key{};

  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(mdctx, EVP_sha512(), nullptr);
  uint8_t index_bytes[8];
  uint64_t block_index = block_index_;
  for (std::size_t i = 0; i < 8; ++i) {
    index_bytes[i] = static_cast<uint8_t>(block_index & 0xff);
    block_index >>= 8;
  }
  EVP_DigestUpdate(mdctx, index_bytes, 8);
  EVP_DigestUpdate(mdctx, hmac_key_.data(), hmac_key_.size());
  unsigned int out_len = 0;
  EVP_DigestFinal_ex(mdctx, hmac_key.data(), &out_len);
  EVP_MD_CTX_free(mdctx);

  return hmac_key;
}

int hmac_istreambuf::underflow() {
  if (gptr() == egptr()) {
    std::array<uint8_t, 32> block_hmac{};
    src_.read(reinterpret_cast<char *>(block_hmac.data()), block_hmac.size());
    if (src_.gcount() != static_cast<std::streamsize>(block_hmac.size()))
      throw IoError("Block read error.");

    uint32_t block_size = 0;
    src_.read(reinterpret_cast<char *>(&block_size), sizeof(block_size));
    if (src_.gcount() != static_cast<std::streamsize>(sizeof(block_size)))
      throw IoError("Block read error.");

    // The HMAC is computed over index ‖ block size ‖ block data.
    std::array<uint8_t, 64> key_64 = GetCurrentHmacKey();

    uint8_t index_bytes[8];
    uint64_t index = block_index_;
    for (std::size_t i = 0; i < 8; ++i) {
      index_bytes[i] = static_cast<uint8_t>(index & 0xff);
      index >>= 8;
    }

    std::vector<uint8_t> mac_input;
    mac_input.reserve(12 + block_size);
    mac_input.insert(mac_input.end(), index_bytes, index_bytes + 8);
    mac_input.insert(mac_input.end(), reinterpret_cast<uint8_t *>(&block_size),
                     reinterpret_cast<uint8_t *>(&block_size) + 4);
    if (block_size > 0) {
      block_.clear();
      block_.resize(block_size);
      src_.read(block_.data(), static_cast<std::streamsize>(block_size));
      if (src_.gcount() != static_cast<std::streamsize>(block_size))
        throw IoError("Block read error.");
      mac_input.insert(mac_input.end(), block_.begin(), block_.end());
    }

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    HMAC(EVP_sha256(), key_64.data(), key_64.size(), mac_input.data(),
         mac_input.size(), digest, &digest_len);

    std::array<uint8_t, 32> computed{};
    std::copy(digest, digest + 32, computed.begin());
    if (block_hmac != computed)
      throw IoError("Block checksum error.");

    ++block_index_;

    if (block_size == 0)
      return std::char_traits<char>::eof();

    setg(block_.data(), block_.data(), block_.data() + block_.size());
  }

  return gptr() == egptr() ? std::char_traits<char>::eof()
                           : std::char_traits<char>::to_int_type(*gptr());
}

std::array<uint8_t, 64> hmac_ostreambuf::GetCurrentHmacKey() const {
  std::array<uint8_t, 64> hmac_key{};

  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(mdctx, EVP_sha512(), nullptr);
  uint8_t index_bytes[8];
  uint64_t block_index = block_index_;
  for (std::size_t i = 0; i < 8; ++i) {
    index_bytes[i] = static_cast<uint8_t>(block_index & 0xff);
    block_index >>= 8;
  }
  EVP_DigestUpdate(mdctx, index_bytes, 8);
  EVP_DigestUpdate(mdctx, hmac_key_.data(), hmac_key_.size());
  unsigned int out_len = 0;
  EVP_DigestFinal_ex(mdctx, hmac_key.data(), &out_len);
  EVP_MD_CTX_free(mdctx);

  return hmac_key;
}

bool hmac_ostreambuf::FlushBlock() {
  std::array<uint8_t, 64> key_64 = GetCurrentHmacKey();

  uint32_t block_size = static_cast<uint32_t>(block_.size());
  uint64_t index = block_index_;
  uint8_t index_bytes[8];
  for (std::size_t i = 0; i < 8; ++i) {
    index_bytes[i] = static_cast<uint8_t>(index & 0xff);
    index >>= 8;
  }

  std::vector<uint8_t> mac_input;
  mac_input.reserve(12 + block_.size());
  mac_input.insert(mac_input.end(), index_bytes, index_bytes + 8);
  mac_input.insert(mac_input.end(), reinterpret_cast<uint8_t *>(&block_size),
                   reinterpret_cast<uint8_t *>(&block_size) + 4);
  mac_input.insert(mac_input.end(), block_.begin(), block_.end());

  unsigned char digest[EVP_MAX_MD_SIZE];
  unsigned int digest_len = 0;
  HMAC(EVP_sha256(), key_64.data(), key_64.size(), mac_input.data(),
       mac_input.size(), digest, &digest_len);

  dst_.write(reinterpret_cast<const char *>(digest), 32);
  dst_.write(reinterpret_cast<const char *>(&block_size), 4);
  if (!block_.empty())
    dst_.write(block_.data(), static_cast<std::streamsize>(block_.size()));
  if (!dst_.good())
    return false;

  ++block_index_;
  block_.clear();
  return true;
}

int hmac_ostreambuf::overflow(int c) {
  if (c == std::char_traits<char>::eof())
    return c;

  if (c > 0xff) {
    assert(false);
    throw InternalError("Trying to write multiple bytes to stream.");
  }

  block_.push_back(static_cast<char>(c));

  if (block_.size() == block_size_) {
    if (!FlushBlock())
      return std::char_traits<char>::eof();
  }

  return std::char_traits<char>::to_int_type(static_cast<char>(c));
}

int hmac_ostreambuf::sync() {
  if (!block_.empty()) {
    if (!FlushBlock())
      return -1;
  }

  // Write the trailing empty block.
  return FlushBlock() ? 0 : -1;
}

gzip_istreambuf::gzip_istreambuf(std::istream &src) : src_(src) {
  z_stream_.zalloc = Z_NULL;
  z_stream_.zfree = Z_NULL;
  z_stream_.opaque = Z_NULL;
  z_stream_.avail_in = 0;
  z_stream_.next_in = reinterpret_cast<uint8_t *>(input_.data());
  z_stream_.avail_out = static_cast<uInt>(output_.size());
  z_stream_.next_out = reinterpret_cast<uint8_t *>(output_.data());

  if (inflateInit2(&z_stream_, 16 + MAX_WBITS) != Z_OK) {
    assert(false);
    throw InternalError("Failed to initialize the gzip decompressor.");
  }
}

gzip_istreambuf::~gzip_istreambuf() { inflateEnd(&z_stream_); }

int gzip_istreambuf::underflow() {
  if (gptr() == egptr()) {
    // Check if we need to feed the z-stream more input data.
    if (z_stream_.avail_in == 0) {
      if (!src_.good())
        return std::char_traits<char>::eof();

      src_.read(input_.data(), static_cast<std::streamsize>(input_.size()));

      z_stream_.avail_in = static_cast<uInt>(src_.gcount());
      z_stream_.next_in = reinterpret_cast<uint8_t *>(input_.data());

      if (z_stream_.avail_in < 1)
        return std::char_traits<char>::eof();
    }

    z_stream_.avail_out = static_cast<uInt>(output_.size());
    z_stream_.next_out = reinterpret_cast<uint8_t *>(output_.data());

    int res = inflate(&z_stream_, Z_NO_FLUSH);
    assert(res != Z_STREAM_ERROR);
    if (res < 0) {
      throw IoError(std::string(Format() << "Gzip inflation error (" << res << ")."));
    }

    std::size_t output_bytes = output_.size() - z_stream_.avail_out;
    setg(output_.data(), output_.data(), output_.data() + output_bytes);
  }

  return gptr() == egptr() ? std::char_traits<char>::eof()
                           : std::char_traits<char>::to_int_type(*gptr());
}

gzip_ostreambuf::gzip_ostreambuf(std::ostream &dst) : dst_(dst) {
  z_stream_.zalloc = Z_NULL;
  z_stream_.zfree = Z_NULL;
  z_stream_.opaque = Z_NULL;
  z_stream_.avail_in = 0;
  z_stream_.next_in = Z_NULL;
  z_stream_.avail_out = 0;
  z_stream_.next_out = Z_NULL;

  if (deflateInit2(&z_stream_, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
                   16 + MAX_WBITS, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
    assert(false);
    throw InternalError("Failed to initialize the gzip compressor.");
  }
}

gzip_ostreambuf::~gzip_ostreambuf() { deflateEnd(&z_stream_); }

bool gzip_ostreambuf::WriteOutput(bool flush) {
  std::array<char, kBufferSize> out{};

  z_stream_.avail_in = static_cast<uInt>(buffer_.size());
  z_stream_.next_in = reinterpret_cast<uint8_t *>(buffer_.data());

  do {
    z_stream_.avail_out = out.size();
    z_stream_.next_out = reinterpret_cast<uint8_t *>(out.data());

    int res = deflate(&z_stream_, flush ? Z_FINISH : Z_NO_FLUSH);
    assert(res != Z_STREAM_ERROR);
    if (res < 0)
      return false;

    std::size_t output_bytes = out.size() - z_stream_.avail_out;
    dst_.write(out.data(), static_cast<std::streamsize>(output_bytes));
    if (!dst_.good())
      return false;
  } while (z_stream_.avail_out == 0);

  assert(z_stream_.avail_in == 0);
  buffer_.clear();

  return true;
}

int gzip_ostreambuf::overflow(int c) {
  if (c == std::char_traits<char>::eof())
    return c;

  if (c > 0xff) {
    assert(false);
    throw InternalError("Trying to write multiple bytes to stream.");
  }

  buffer_.push_back(static_cast<char>(c));

  if (buffer_.size() == kBufferSize) {
    if (!WriteOutput(false))
      throw IoError("Gzip deflation error.");
  }

  return std::char_traits<char>::to_int_type(static_cast<char>(c));
}

int gzip_ostreambuf::sync() { return WriteOutput(true) ? 0 : -1; }

} // namespace keepass
