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

/** @file stream.hh @brief Stream buffer adapters for hashed, HMAC, and gzip I/O. */

#pragma once
#include <algorithm>
#include <array>
#include <cassert>
#include <istream>
#include <memory>
#include <ostream>
#include <vector>

#include <zlib.h>

#include "libkeepass/export.hh"
#include "util.hh"

namespace keepass {

/**
 * @brief A std::streambuf backed by a fixed-size std::array.
 *
 * Provides random-access read/write capability over an in-memory
 * byte array, suitable for use with std::istream and std::ostream.
 *
 * @tparam N The size of the backing array in bytes.
 */
template <std::size_t N>
class array_iostreambuf : public std::basic_streambuf<char, std::char_traits<char>> {
private:
  std::array<uint8_t, N>& buffer_;

protected:
  std::streampos seekoff(std::streamoff off, std::ios_base::seekdir way,
                         std::ios_base::openmode which) override {
    if (which == 0)
      return {std::streamoff(-1)};

    off = clamp<std::streamoff>(0, static_cast<long long>(buffer_.size()), off);

    std::streamoff lin_off = 0;
    switch (way) {
    case std::ios_base::beg:
      lin_off = clamp<std::streamoff>(0, static_cast<long long>(buffer_.size()), off);
      break;
    case std::ios_base::cur:
      lin_off = clamp<std::streamoff>(0, static_cast<long long>(buffer_.size()),
                                      (gptr() - eback()) + off);
      break;
    case std::ios_base::end:
      lin_off = clamp<std::streamoff>(0, static_cast<std::streamoff>(buffer_.size()),
                                      static_cast<std::streamoff>(buffer_.size()) - off);
      break;
    default:
      assert(false);
      break;
    };

    if (which & std::ios_base::in) {
      char* buffer_ptr = reinterpret_cast<char*>(buffer_.data());
      setg(buffer_ptr, buffer_ptr + lin_off, buffer_ptr + buffer_.size());
    }

    return lin_off;
  }

  std::streampos seekpos(std::streampos sp, std::ios_base::openmode which) override {
    if (which == 0 || sp < 0 || sp >= static_cast<std::streamoff>(buffer_.size())) {
      return {std::streamoff(-1)};
      ;
    }

    if (which & std::ios_base::in) {
      char* buffer_ptr = reinterpret_cast<char*>(buffer_.data());
      setg(buffer_ptr, buffer_ptr + sp, buffer_ptr + buffer_.size());
    }

    return sp;
  }

public:
  /**
   * @brief Constructs a streambuf over the given array.
   *
   * @param buffer The backing array to read from and write to.
   */
  explicit array_iostreambuf(std::array<uint8_t, N>& buffer) : buffer_(buffer) {
    char* buffer_ptr = reinterpret_cast<char*>(buffer.data());
    setg(buffer_ptr, buffer_ptr, buffer_ptr + buffer.size());
    setp(buffer_ptr, buffer_ptr + buffer.size());
  }
};

/**
 * @brief Base class providing SHA-256 hashing for block-oriented stream buffers.
 *
 * Used internally by hashed_istreambuf and hashed_ostreambuf to compute
 * and verify block integrity checksums.
 */
class hashed_basic_streambuf {
protected:
  /**
   * @brief Header written before each data block in the hashed stream format.
   */
  struct BlockHeader {
    uint32_t block_index{};
    std::array<uint8_t, 32> block_hash{};
    uint32_t block_size = 0;
  };

  uint32_t block_index_ = 0;
  std::vector<char> block_;

  /// Computes the SHA-256 hash of the current block.
  std::array<uint8_t, 32> GetBlockHash() const;

public:
  virtual ~hashed_basic_streambuf() = default;
};

/**
 * @brief Input streambuf that reads SHA-256-hashed, block-structured data.
 *
 * Each block consists of a BlockHeader followed by the raw data. The hash
 * in the header is verified against the data on read. An empty block with
 * a zero hash signals end-of-stream.
 */
class LIBKEEPASS_API hashed_istreambuf final
    : private hashed_basic_streambuf,
      public std::basic_streambuf<char, std::char_traits<char>> {
private:
  std::istream& src_;

public:
  /**
   * @brief Constructs an input streambuf that reads from the given stream.
   *
   * @param src The input stream to read hashed blocks from.
   */
  explicit hashed_istreambuf(std::istream& src) : src_(src) {}

  /// Reads and verifies the next block when the get area is exhausted.
  int underflow() override;
};

/**
 * @brief Output streambuf that writes SHA-256-hashed, block-structured data.
 *
 * Data is accumulated into blocks of a configurable size. Each block is
 * flushed with a BlockHeader containing its SHA-256 hash. A trailing
 * empty block is written on sync to signal end-of-stream.
 */
class LIBKEEPASS_API hashed_ostreambuf final
    : private hashed_basic_streambuf,
      public std::basic_streambuf<char, std::char_traits<char>> {
private:
  static constexpr uint32_t kDefaultBlockSize = 1024 * 1024;

  std::ostream& dst_;
  const uint32_t block_size_;

  /// Writes the current block (header + data) to the output stream.
  bool FlushBlock();

public:
  /**
   * @brief Constructs an output streambuf with the default 1 MiB block size.
   *
   * @param dst The output stream to write hashed blocks to.
   */
  explicit hashed_ostreambuf(std::ostream& dst) : dst_(dst), block_size_(kDefaultBlockSize) {}

  /**
   * @brief Constructs an output streambuf with a custom block size.
   *
   * @param dst The output stream to write hashed blocks to.
   * @param block_size The maximum number of data bytes per block.
   */
  hashed_ostreambuf(std::ostream& dst, uint32_t block_size) : dst_(dst), block_size_(block_size) {}

  /// Buffers a character; flushes the current block when it reaches capacity.
  int overflow(int c) override;

  /// Flushes any buffered data and writes the trailing empty end-of-stream block.
  int sync() override;
};

/**
 * @brief Input streambuf that reads HMAC-verified, block-structured data (KDBX4 format).
 *
 * Each block is preceded by a 32-byte HMAC-SHA256 computed over the block
 * index, block size, and block data. An empty block (size 0) signals
 * end-of-stream.
 */
class LIBKEEPASS_API hmac_istreambuf final
    : public std::basic_streambuf<char, std::char_traits<char>> {
private:
  std::istream& src_;
  const std::array<uint8_t, 64> hmac_key_;

  uint64_t block_index_ = 0;
  std::vector<char> block_;

  /// Derives the per-block HMAC key by hashing the block index with the master key.
  std::array<uint8_t, 64> GetCurrentHmacKey() const;

public:
  /**
   * @brief Constructs an HMAC-verifying input streambuf.
   *
   * @param src The input stream to read HMAC-protected blocks from.
   * @param hmac_key The 512-bit master HMAC key.
   */
  hmac_istreambuf(std::istream& src, const std::array<uint8_t, 64>& hmac_key)
      : src_(src), hmac_key_(hmac_key) {}

  /// Reads and HMAC-verifies the next block when the get area is exhausted.
  int underflow() override;
};

/**
 * @brief Output streambuf that writes HMAC-authenticated, block-structured data (KDBX4 format).
 *
 * Each block is written with a 32-byte HMAC-SHA256 over the block index,
 * block size, and block data. A trailing empty block is written on sync
 * to signal end-of-stream.
 */
class LIBKEEPASS_API hmac_ostreambuf final
    : public std::basic_streambuf<char, std::char_traits<char>> {
private:
  static constexpr uint32_t kDefaultBlockSize = 1024 * 1024;

  std::ostream& dst_;
  const std::array<uint8_t, 64> hmac_key_;
  const uint32_t block_size_;

  uint64_t block_index_ = 0;
  std::vector<char> block_;

  /// Derives the per-block HMAC key by hashing the block index with the master key.
  std::array<uint8_t, 64> GetCurrentHmacKey() const;

  /// Computes the HMAC and writes the block (HMAC + size + data) to the output stream.
  bool FlushBlock();

public:
  /**
   * @brief Constructs an HMAC-signing output streambuf with the default 1 MiB block size.
   *
   * @param dst The output stream to write HMAC-protected blocks to.
   * @param hmac_key The 512-bit master HMAC key.
   */
  hmac_ostreambuf(std::ostream& dst, const std::array<uint8_t, 64>& hmac_key)
      : dst_(dst), hmac_key_(hmac_key), block_size_(kDefaultBlockSize) {}

  /**
   * @brief Constructs an HMAC-signing output streambuf with a custom block size.
   *
   * @param dst The output stream to write HMAC-protected blocks to.
   * @param hmac_key The 512-bit master HMAC key.
   * @param block_size The maximum number of data bytes per block.
   */
  hmac_ostreambuf(std::ostream& dst, const std::array<uint8_t, 64>& hmac_key, uint32_t block_size)
      : dst_(dst), hmac_key_(hmac_key), block_size_(block_size) {}

  /// Buffers a character; flushes the current block when it reaches capacity.
  int overflow(int c) override;

  /// Flushes any buffered data and writes the trailing empty end-of-stream block.
  int sync() override;
};

/**
 * @brief Input streambuf that decompresses gzip-compressed data on the fly.
 *
 * Reads compressed data from the underlying stream and inflates it into
 * an internal output buffer. Uses zlib's inflate with gzip decoding.
 */
class LIBKEEPASS_API gzip_istreambuf final
    : public std::basic_streambuf<char, std::char_traits<char>> {
private:
  static const std::size_t kBufferSize = 16384;

  std::istream& src_;
  z_stream z_stream_{};

  /** Input buffer for feeding the decompressor. */
  std::array<char, kBufferSize> input_ = {{0}};
  /** Output buffer for the decompressor to write to. */
  std::array<char, kBufferSize> output_ = {{0}};

public:
  /**
   * @brief Constructs a gzip-decompressing streambuf.
   *
   * @param src The input stream containing gzip-compressed data.
   * @throws InternalError If the zlib inflate context cannot be initialized.
   */
  explicit gzip_istreambuf(std::istream& src);

  /// Destroys the streambuf and releases the zlib inflate context.
  ~gzip_istreambuf() override;

  /// Inflates compressed data into the output buffer when the get area is exhausted.
  int underflow() override;
};

/**
 * @brief Output streambuf that compresses data with gzip on the fly.
 *
 * Accumulates data in an internal buffer and deflates it using zlib.
 * The gzip stream is finalized when the streambuf is destroyed or sync is called.
 */
class LIBKEEPASS_API gzip_ostreambuf final
    : public std::basic_streambuf<char, std::char_traits<char>> {
private:
  static const std::size_t kBufferSize = 16384;

  std::ostream& dst_;
  z_stream z_stream_{};

  std::vector<char> buffer_;

  /**
   * @brief Compresses the buffered data and writes it to the output stream.
   *
   * @param flush If true, finalizes the gzip stream with Z_FINISH.
   * @return true on success, false on error.
   */
  bool WriteOutput(bool flush);

public:
  /**
   * @brief Constructs a gzip-compressing streambuf.
   *
   * @param dst The output stream to write compressed data to.
   * @throws InternalError If the zlib deflate context cannot be initialized.
   */
  explicit gzip_ostreambuf(std::ostream& dst);

  /// Destroys the streambuf, finalizing the gzip stream and releasing the zlib context.
  ~gzip_ostreambuf() override;

  /// Buffers a character; deflates and writes the buffer when it reaches capacity.
  int overflow(int c) override;

  /// Flushes any buffered data and finalizes the gzip stream.
  int sync() override;
};

} // namespace keepass
