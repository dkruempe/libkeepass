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

/**
 * @file secure.hh
 * @brief Secure memory handling: zeroization, locked allocations and
 * sensitive value containers.
 */

#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iosfwd>
#include <string>

#include "libkeepass/export.hh"

namespace keepass {

/// Securely erases a memory region by overwriting it with zero bytes.
/**
 * The write is performed through a volatile pointer so that optimizing
 * compilers cannot elide the operation.
 *
 * @param data Pointer to the region to erase.
 * @param size Number of bytes to erase.
 */
LIBKEEPASS_API void secure_zero(void* data, std::size_t size) noexcept;

/// Allocates a memory region that is best-effort locked in RAM.
/**
 * Locking the pages prevents them from being swapped out to disk. Locking is
 * best-effort: it may fail (for example when the process runs out of the
 * mlock allowance) and the call still succeeds with an unlocked allocation.
 * Regardless of locking, always wipe the memory with secure_zero() before
 * calling secure_free().
 *
 * @param size Number of bytes to allocate (at least one byte is allocated).
 * @return Pointer to the allocated memory or nullptr on allocation failure.
 */
LIBKEEPASS_API void* secure_alloc(std::size_t size) noexcept;

/// Erases and releases memory obtained from secure_alloc().
/**
 * @param data Pointer returned by secure_alloc(), or nullptr.
 * @param size Size that was passed to secure_alloc().
 */
LIBKEEPASS_API void secure_free(void* data, std::size_t size) noexcept;

/**
 * @brief Fixed-size byte buffer that is zeroized on destruction.
 *
 * SecureBuffer owns a fixed number of key-material bytes. The content is
 * overwritten with zeros when the buffer is destroyed, moved-from or
 * assigned over. SecureBuffer is move-only; use Clone() to create an explicit
 * deep copy.
 *
 * @tparam N The number of bytes in the buffer.
 */
template <std::size_t N> class SecureBuffer {
public:
  /// Default-constructs a zero-filled buffer.
  SecureBuffer() = default;

  /// Zeroizes the stored bytes.
  ~SecureBuffer() { secure_zero(data_.data(), data_.size()); }

  /// No implicit copies of key material.
  SecureBuffer(const SecureBuffer&) = delete;

  /// No implicit copies of key material.
  SecureBuffer& operator=(const SecureBuffer&) = delete;

  /// Move-constructs by copying the bytes and wiping the source.
  SecureBuffer(SecureBuffer&& other) noexcept {
    std::memcpy(data_.data(), other.data_.data(), N);
    other.Wipe();
  }

  /// Move-assigns by copying the bytes and wiping the source. The previous
  /// content is fully overwritten.
  SecureBuffer& operator=(SecureBuffer&& other) noexcept {
    if (this != &other) {
      std::memcpy(data_.data(), other.data_.data(), N);
      other.Wipe();
    }
    return *this;
  }

  /// Returns a pointer to the raw bytes.
  uint8_t* data() noexcept { return data_.data(); }

  /// Returns a const pointer to the raw bytes.
  const uint8_t* data() const noexcept { return data_.data(); }

  /// Returns the size of the buffer in bytes.
  std::size_t size() const noexcept { return N; }

  /// Returns an iterator to the first byte.
  uint8_t* begin() noexcept { return data_.data(); }

  /// Returns an iterator past the last byte.
  uint8_t* end() noexcept { return data_.data() + N; }

  /// Returns a const iterator to the first byte.
  const uint8_t* begin() const noexcept { return data_.data(); }

  /// Returns a const iterator past the last byte.
  const uint8_t* end() const noexcept { return data_.data() + N; }

  /// Returns the byte at the given index.
  uint8_t& operator[](std::size_t index) noexcept { return data_[index]; }

  /// Returns the byte at the given index.
  const uint8_t& operator[](std::size_t index) const noexcept { return data_[index]; }

  /// Fills the buffer with the given byte value.
  void fill(uint8_t value) noexcept { data_.fill(value); }

  /// Returns an explicit deep copy of the buffer.
  SecureBuffer Clone() const {
    SecureBuffer copy;
    std::memcpy(copy.data_.data(), data_.data(), N);
    return copy;
  }

private:
  void Wipe() noexcept { secure_zero(data_.data(), data_.size()); }

  std::array<uint8_t, N> data_ = {{0}};
};

/**
 * @brief String that is stored in wiped and best-effort locked memory.
 *
 * Unlike std::string, the value is never held in inline (SSO) storage; it is
 * always kept in a separately allocated, zeroized buffer. The memory is
 * erased when the string is destroyed, cleared or overwritten.
 *
 * The string does not implicitly convert to std::string in order to avoid
 * silently producing unsecured copies of sensitive data. Use str() when an
 * explicit std::string copy is required.
 */
class LIBKEEPASS_API secure_string {
public:
  /// Constructs an empty string.
  secure_string();

  /// Constructs a string from a NUL-terminated C string.
  secure_string(const char* str);

  /// Constructs a string from a std::string.
  explicit secure_string(const std::string& str);

  /// Copy-constructs by allocating a fresh wiped buffer.
  secure_string(const secure_string& other);

  /// Move-constructs, wiping the moved-from string.
  secure_string(secure_string&& other) noexcept;

  /// Copy-assigns by allocating a fresh wiped buffer.
  secure_string& operator=(const secure_string& other);

  /// Move-assigns, wiping the previous content and the moved-from string.
  secure_string& operator=(secure_string&& other) noexcept;

  /// Assigns from a NUL-terminated C string.
  secure_string& operator=(const char* str) {
    assign(str);
    return *this;
  }

  /// Assigns from a std::string.
  secure_string& operator=(const std::string& str) {
    assign(str);
    return *this;
  }

  /// Zeroizes and releases the stored memory.
  ~secure_string();

  /// Returns a pointer to the (NUL-terminated) character data.
  const char* data() const noexcept { return data_; }

  /// Returns a pointer to the character data for in-place modification.
  char* data() noexcept { return data_; }

  /// Returns an iterator to the first character.
  char* begin() noexcept { return data_; }

  /// Returns an iterator to the first character.
  const char* begin() const noexcept { return data_; }

  /// Returns an iterator past the last character.
  char* end() noexcept { return data_ + size_; }

  /// Returns an iterator past the last character.
  const char* end() const noexcept { return data_ + size_; }

  /// Returns the number of characters (excluding the trailing NUL).
  std::size_t size() const noexcept { return size_; }

  /// Returns the number of characters.
  std::size_t length() const noexcept { return size_; }

  /// Returns whether the string is empty.
  bool empty() const noexcept { return size_ == 0; }

  /// Returns a NUL-terminated pointer to the character data.
  const char* c_str() const noexcept { return data_; }

  /// Returns an explicit std::string copy of the value.
  std::string str() const;

  /// Erases the content, wiping the memory.
  void clear();

  /// Replaces the value with a NUL-terminated C string.
  void assign(const char* str);

  /// Replaces the value with a std::string.
  void assign(const std::string& str);

private:
  void Allocate(const char* data, std::size_t size);
  void Release() noexcept;

  char* data_ = nullptr;
  std::size_t size_ = 0;
};

/// Returns whether two secure strings hold the same bytes.
bool operator==(const secure_string& lhs, const secure_string& rhs);

/// Returns whether two secure strings hold different bytes.
bool operator!=(const secure_string& lhs, const secure_string& rhs);

/// Returns whether a secure string matches a std::string.
bool operator==(const secure_string& lhs, const std::string& rhs);

/// Returns whether a std::string matches a secure string.
bool operator==(const std::string& lhs, const secure_string& rhs);

/// Returns whether a secure string differs from a std::string.
bool operator!=(const secure_string& lhs, const std::string& rhs);

/// Returns whether a std::string differs from a secure string.
bool operator!=(const std::string& lhs, const secure_string& rhs);

/// Returns whether a secure string matches a NUL-terminated C string.
bool operator==(const secure_string& lhs, const char* rhs);

/// Returns whether a NUL-terminated C string matches a secure string.
bool operator==(const char* lhs, const secure_string& rhs);

/// Returns whether a secure string differs from a NUL-terminated C string.
bool operator!=(const secure_string& lhs, const char* rhs);

/// Returns whether a NUL-terminated C string differs from a secure string.
bool operator!=(const char* lhs, const secure_string& rhs);

/// Writes the string content to a stream.
LIBKEEPASS_API std::ostream& operator<<(std::ostream& os, const secure_string& str);

} // namespace keepass