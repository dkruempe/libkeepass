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
 * @file temporal.hh
 * @brief Template class for tracking modification timestamps of values.
 */

#pragma once
#include <ctime>

namespace keepass {

/**
 * @brief Template class for keeping track of when a variable is modified.
 *
 * @tparam T The type of the tracked value.
 */
template <typename T> class temporal {
private:
  T value_;              ///< The tracked value.
  std::time_t time_ = 0; ///< Timestamp of the last modification.

public:
  /// Default-constructs an empty temporal wrapper.
  temporal() = default;

  /**
   * @brief Constructs a temporal wrapper with an explicit timestamp.
   * @param [in] value Initial value.
   * @param [in] time Timestamp of the value.
   */
  temporal(const T& value, std::time_t time) : value_(value), time_(time) {}

  /**
   * @brief Copy-constructs from another temporal wrapper.
   * @param [in] other Source wrapper.
   */
  temporal(const temporal<T>& other) {
    value_ = other.value_;
    time_ = other.time_;
  }

  /**
   * @brief Move-constructs from another temporal wrapper.
   * @param [in,out] other Source wrapper (moved from).
   */
  temporal(temporal<T>&& other) noexcept {
    value_ = std::move(other.value_);
    time_ = std::move(other.time_);
  }

  /**
   * @brief Returns a const reference to the stored value.
   * @return Const reference to the value.
   */
  const T& value() const { return value_; }

  /**
   * @brief Returns the modification timestamp.
   * @return Timestamp as std::time_t.
   */
  std::time_t time() const { return time_; }

  /**
   * @brief Sets the modification timestamp without changing the value.
   * @param [in] time New timestamp.
   */
  void set_time(std::time_t time) { time_ = time; }

  /**
   * @brief Replaces the stored value and updates the timestamp to now.
   * @param [in] val New value.
   */
  void Set(const T& val) {
    value_ = val;
    time_ = std::time(nullptr);
  }

  /**
   * @brief Assigns a plain value, updating the timestamp to now.
   * @param [in] value New value.
   * @return Reference to this object.
   */
  temporal<T>& operator=(const T& value) {
    value_ = value;
    time_ = std::time(nullptr);
    return *this;
  }

  /**
   * @brief Copy-assigns from another temporal wrapper.
   * @param [in] other Source wrapper.
   * @return Reference to this object.
   */
  temporal<T>& operator=(const temporal<T>& other) {
    value_ = other.value_;
    time_ = other.time_;
    return *this;
  }

  /**
   * @brief Move-assigns from another temporal wrapper.
   * @param [in,out] other Source wrapper (moved from).
   * @return Reference to this object.
   */
  temporal<T>& operator=(temporal<T>&& other) noexcept {
    value_ = std::move(other.value_);
    time_ = std::move(other.time_);
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
};

} // namespace keepass
