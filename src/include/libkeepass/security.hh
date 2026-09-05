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
 * @file security.hh
 * @brief Wrapper type for protecting sensitive KeePass field values.
 */

#pragma once

namespace keepass {

/**
 * @brief Wrapper that marks a value as sensitive and tracks the protection
 * flag of a KeePass field.
 *
 * The wrapped value is stored in plaintext; protection here means that the
 * value is flagged as sensitive (e.g. a password) and is written to the KDBX
 * output obfuscated through the inner random stream (Salsa20/ChaCha20). The
 * item is not encrypted in heap memory.
 *
 * @tparam T The wrapped value type.
 */
template <typename T> class protect {
private:
  T value_;                ///< The stored value.
  bool protected_ = false; ///< Whether the value is marked as sensitive.

public:
  /// Default-constructs an empty protected wrapper.
  protect() = default;

  /**
   * @brief Constructs a protected wrapper with an explicit protection flag.
   * @param [in] val Initial value.
   * @param [in] prot Whether the value is sensitive.
   */
  protect(const T& val, bool prot) : value_(val), protected_(prot) {}

  /**
   * @brief Copy-constructs from another protected wrapper.
   * @param [in] other Source wrapper.
   */
  protect(const protect<T>& other) {
    value_ = other.value_;
    protected_ = other.protected_;
  }

  /**
   * @brief Move-constructs from another protected wrapper.
   * @param [in,out] other Source wrapper (moved from).
   */
  protect(protect<T>&& other) noexcept {
    value_ = std::move(other.value_);
    protected_ = std::move(other.protected_);
  }

  /**
   * @brief Returns whether the value is marked as sensitive.
   * @return true if the value is protected, false otherwise.
   */
  bool is_protected() const { return protected_; }

  /**
   * @brief Sets the protection flag.
   * @param [in] prot New protection state.
   */
  void set_protected(bool prot) { protected_ = prot; }

  /**
   * @brief Returns a const reference to the stored value.
   * @return Const reference to the value.
   */
  const T& value() const { return value_; }

  /**
   * @brief Replaces the stored value.
   * @param [in] val New value.
   */
  void set_value(const T& val) { value_ = val; }

  /**
   * @brief Copy-assigns from another protected wrapper.
   * @param [in] other Source wrapper.
   * @return Reference to this object.
   */
  protect<T>& operator=(const protect<T>& other) {
    value_ = other.value_;
    protected_ = other.protected_;
    return *this;
  }

  /**
   * @brief Move-assigns from another protected wrapper.
   * @param [in,out] other Source wrapper (moved from).
   * @return Reference to this object.
   */
  protect<T>& operator=(protect<T>&& other) noexcept {
    value_ = std::move(other.value_);
    protected_ = std::move(other.protected_);
    return *this;
  }

  /**
   * @brief Explicit conversion operator to the wrapped type.
   * @return Const reference to the value.
   */
  explicit operator const T&() const { return value_; }

  /**
   * @brief Arrow operator forwarding to the stored value.
   * @return Pointer to the value.
   */
  const T* operator->() const { return &value_; }

  /**
   * @brief Dereference operator forwarding to the stored value.
   * @return Const reference to the value.
   */
  const T& operator*() const { return value_; }

  /**
   * @brief Equality comparison of two protected wrappers.
   * @param [in] other Right-hand side.
   * @return true if both value and protection flag are equal.
   */
  bool operator==(const protect<T>& other) const {
    return value_ == other.value_ && protected_ == other.protected_;
  }

  /**
   * @brief Inequality comparison of two protected wrappers.
   * @param [in] other Right-hand side.
   * @return true if the wrappers are not equal.
   */
  bool operator!=(const protect<T>& other) const { return !(*this == other); }
};

} // namespace keepass
