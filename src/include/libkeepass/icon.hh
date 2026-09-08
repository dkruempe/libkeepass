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

/** @file icon.hh @brief Type representing a custom database icon. */

#pragma once
#include <array>
#include <ctime>
#include <string>
#include <vector>

namespace keepass {

/**
 * @brief A custom icon stored in the database.
 *
 * An Icon is identified by a UUID and holds the raw icon file data (e.g. a PNG
 * or image format supported by KeePass).
 */
class Icon final {
private:
  std::array<uint8_t, 16> uuid_;
  std::vector<uint8_t> data_;
  std::string name_;
  std::time_t last_modification_time_ = 0;

public:
  /// Creates an icon with the given UUID and raw data.
  Icon(const std::array<uint8_t, 16>& uuid, std::vector<uint8_t> data)
      : uuid_(uuid), data_(std::move(data)) {}

  /// Returns the icon UUID.
  const std::array<uint8_t, 16>& uuid() const { return uuid_; }

  /// Returns the raw icon data.
  const std::vector<uint8_t>& data() const { return data_; }

  /// Sets the raw icon data.
  void set_data(const std::vector<uint8_t>& data) { data_ = data; }

  /// Returns the icon name (KDBX 4.1).
  const std::string& name() const { return name_; }

  /// Sets the icon name (KDBX 4.1).
  void set_name(const std::string& name) { name_ = name; }

  /// Returns the icon last modification time (KDBX 4.1); 0 if unset.
  std::time_t last_modification_time() const { return last_modification_time_; }

  /// Sets the icon last modification time (KDBX 4.1); 0 to unset.
  void set_last_modification_time(std::time_t time) { last_modification_time_ = time; }

  /// Equality comparison (based on data).
  bool operator==(const Icon& other) const {
    return data_ == other.data_ && name_ == other.name_ &&
           last_modification_time_ == other.last_modification_time_;
  }

  /// Inequality comparison.
  bool operator!=(const Icon& other) const { return !(*this == other); }
};

} // namespace keepass
