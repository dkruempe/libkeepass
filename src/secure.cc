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

#include "libkeepass/secure.hh"

#include <cstdlib>
#include <new>
#include <ostream>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#endif

namespace keepass {

void secure_zero(void* data, std::size_t size) noexcept {
  volatile uint8_t* byte = static_cast<volatile uint8_t*>(data);
  for (std::size_t i = 0; i < size; ++i)
    byte[i] = 0;
}

void* secure_alloc(std::size_t size) noexcept {
  if (size == 0)
    size = 1;

  void* data = std::malloc(size);
  if (data == nullptr)
    return nullptr;

#ifdef _WIN32
  VirtualLock(data, size);
#else
  mlock(data, size);
#endif

  return data;
}

void secure_free(void* data, std::size_t size) noexcept {
  if (data == nullptr)
    return;

  secure_zero(data, size);

#ifdef _WIN32
  VirtualUnlock(data, size);
#else
  munlock(data, size);
#endif

  std::free(data);
}

namespace {

/// Returns whether two byte ranges of equal length are identical.
bool ByteEqual(const char* a, std::size_t a_size, const char* b, std::size_t b_size) {
  return a_size == b_size && (a_size == 0 || std::memcmp(a, b, a_size) == 0);
}

} // namespace

secure_string::secure_string() { Allocate("", 0); }

secure_string::secure_string(const char* str) {
  if (str == nullptr)
    Allocate("", 0);
  else
    Allocate(str, std::strlen(str));
}

secure_string::secure_string(const std::string& str) { Allocate(str.data(), str.size()); }

secure_string::secure_string(const secure_string& other) {
  if (other.data_ != nullptr)
    Allocate(other.data_, other.size_);
  else
    Allocate("", 0);
}

secure_string::secure_string(secure_string&& other) noexcept {
  data_ = other.data_;
  size_ = other.size_;
  other.data_ = nullptr;
  other.size_ = 0;
}

secure_string& secure_string::operator=(const secure_string& other) {
  if (this != &other) {
    if (other.data_ != nullptr)
      Allocate(other.data_, other.size_);
    else
      Allocate("", 0);
  }
  return *this;
}

secure_string& secure_string::operator=(secure_string&& other) noexcept {
  if (this != &other) {
    Release();
    data_ = other.data_;
    size_ = other.size_;
    other.data_ = nullptr;
    other.size_ = 0;
  }
  return *this;
}

secure_string::~secure_string() { Release(); }

std::string secure_string::str() const {
  return data_ != nullptr ? std::string(data_, size_) : std::string();
}

void secure_string::clear() { Allocate("", 0); }

void secure_string::assign(const char* str) {
  if (str == nullptr)
    Allocate("", 0);
  else
    Allocate(str, std::strlen(str));
}

void secure_string::assign(const std::string& str) { Allocate(str.data(), str.size()); }

void secure_string::Allocate(const char* data, std::size_t size) {
  char* new_data = static_cast<char*>(secure_alloc(size + 1));
  if (new_data == nullptr)
    throw std::bad_alloc();
  if (size > 0)
    std::memcpy(new_data, data, size);
  new_data[size] = '\0';

  Release();
  data_ = new_data;
  size_ = size;
}

void secure_string::Release() noexcept {
  if (data_ != nullptr) {
    secure_free(data_, size_ + 1);
    data_ = nullptr;
    size_ = 0;
  }
}

bool operator==(const secure_string& lhs, const secure_string& rhs) {
  return ByteEqual(lhs.data(), lhs.size(), rhs.data(), rhs.size());
}

bool operator!=(const secure_string& lhs, const secure_string& rhs) { return !(lhs == rhs); }

bool operator==(const secure_string& lhs, const std::string& rhs) {
  return ByteEqual(lhs.data(), lhs.size(), rhs.data(), rhs.size());
}

bool operator==(const std::string& lhs, const secure_string& rhs) {
  return ByteEqual(lhs.data(), lhs.size(), rhs.data(), rhs.size());
}

bool operator!=(const secure_string& lhs, const std::string& rhs) { return !(lhs == rhs); }

bool operator!=(const std::string& lhs, const secure_string& rhs) { return !(lhs == rhs); }

bool operator==(const secure_string& lhs, const char* rhs) {
  return ByteEqual(lhs.data(), lhs.size(), rhs, rhs != nullptr ? std::strlen(rhs) : 0);
}

bool operator==(const char* lhs, const secure_string& rhs) {
  return ByteEqual(lhs, lhs != nullptr ? std::strlen(lhs) : 0, rhs.data(), rhs.size());
}

bool operator!=(const secure_string& lhs, const char* rhs) { return !(lhs == rhs); }

bool operator!=(const char* lhs, const secure_string& rhs) { return !(lhs == rhs); }

std::ostream& operator<<(std::ostream& os, const secure_string& str) {
  if (!str.empty())
    os.write(str.data(), static_cast<std::streamsize>(str.size()));
  return os;
}

} // namespace keepass