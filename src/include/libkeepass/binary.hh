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

/** @file binary.hh @brief Type representing a binary blob stored in a database. */

#pragma once
#include <string>

#include "security.hh"

namespace keepass {

/**
 * @brief A binary blob (e.g. an attachment payload) with an optional
 * compression flag.
 */
class Binary final {
private:
  protect<std::string> data_;
  bool compress_ = false;

public:
  /// Creates a binary from the given protected data.
  explicit Binary(const protect<std::string>& data) : data_(data) {}

  /// Returns whether the binary data is empty.
  bool Empty() const { return data_->empty(); }

  /// Returns the size in bytes of the binary data.
  std::size_t Size() const { return data_->size(); }

  /// Returns the binary data.
  const protect<std::string>& data() const { return data_; }

  /// Sets the binary data.
  void set_data(const protect<std::string>& data) { data_ = data; }

  /// Returns whether the binary is stored compressed.
  bool compress() const { return compress_; }

  /// Sets whether the binary is stored compressed.
  void set_compress(bool compress) { compress_ = compress; }

  /// Equality comparison.
  bool operator==(const Binary& other) const { return data_ == other.data_; }

  /// Inequality comparison.
  bool operator!=(const Binary& other) const { return !(*this == other); }
};

} // namespace keepass
