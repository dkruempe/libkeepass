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

/** @file mapped_file.hh
 *  @brief Read-only memory-mapped file and stream buffer helpers. */

#pragma once

#include <cstddef>
#include <streambuf>
#include <string>

#include "libkeepass/export.hh"

namespace keepass {
namespace detail {

/**
 * @brief Read-only memory mapping of a file.
 *
 * On POSIX systems the file is mapped with @c mmap; on Windows a read-only
 * file mapping is created with @c CreateFileMapping/@c MapViewOfFile. The
 * mapping is released when the object is destroyed. The file must not be
 * truncated while the mapping is alive (the operating system may deliver
 * @c SIGBUS/raise an exception on access to the missing pages).
 */
class MappedFile final {
public:
  /// Opens and maps the file at @p path.
  /**
   * @throws FileNotFoundError if the path does not exist.
   * @throws IoError if the file cannot be opened or mapped.
   */
  explicit MappedFile(const std::string& path);

  /// Unmaps the file and releases all handles.
  ~MappedFile();

  MappedFile(const MappedFile&) = delete;
  MappedFile& operator=(const MappedFile&) = delete;
  MappedFile(MappedFile&&) = delete;
  MappedFile& operator=(MappedFile&&) = delete;

  /// Returns a pointer to the first mapped byte (nullptr for an empty file).
  const char* data() const noexcept { return static_cast<const char*>(data_); }

  /// Returns the size of the mapping in bytes.
  std::size_t size() const noexcept { return size_; }

  /// Returns whether the file is empty.
  bool empty() const noexcept { return size_ == 0; }

private:
  void* data_ = nullptr;
  std::size_t size_ = 0;

#ifdef _WIN32
  void* file_ = nullptr;
  void* mapping_ = nullptr;
#else
  int fd_ = -1;
#endif
};

/**
 * @brief Streambuf over a read-only memory region.
 *
 * The entire mapping is exposed as the get area, so normal sequential and
 * seekable stream operations avoid any additional copies.
 */
class mapped_istreambuf final : public std::streambuf {
public:
  /**
   * @param data Pointer to the first byte.
   * @param size Number of bytes in the region.
   */
  mapped_istreambuf(const char* data, std::size_t size) {
    // A zero-sized mapping has no valid pointer; use a static sentinel so the
    // stream buffer never forms a pointer past nullptr.
    static char empty = 0;
    begin_ = size == 0 ? &empty : const_cast<char*>(data);
    end_ = begin_ + size;
    setg(begin_, begin_, end_);
  }

protected:
  std::streampos seekoff(std::streamoff off, std::ios_base::seekdir way,
                         std::ios_base::openmode which) override;
  std::streampos seekpos(std::streampos sp, std::ios_base::openmode which) override;

private:
  char* begin_ = nullptr;
  char* end_ = nullptr;
};

} // namespace detail
} // namespace keepass
