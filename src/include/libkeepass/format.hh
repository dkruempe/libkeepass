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

/** @file format.hh @brief Convenience string-building helper. */

#pragma once
#include <ostream>
#include <sstream>

/**
 * @brief Streams values into a built-in string builder.
 *
 * Format accumulates values via @c operator<< and converts to @c std::string or an
 * output stream, avoiding manual formatting with snprintf-style calls.
 */
class Format {
private:
  std::stringstream str_;

public:
  /// Non-copyable.
  Format(const Format& rhs) = delete;

  /// Non-copyable.
  Format& operator=(const Format& rhs) = delete;

  /// Creates an empty builder.
  Format() = default;

  /// Appends a value to the builder.
  template <typename T> Format& operator<<(const T& val) {
    str_ << val;
    return *this;
  }

  /// Converts the builder to a string.
  explicit operator std::string() const { return str_.str(); }

  /// Writes the builder's contents to an output stream.
  friend std::ostream& operator<<(std::ostream& os, const Format& format) {
    os << format.str_.str();
    return os;
  }
};
