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

#include <cstddef>
#include <memory>
#include <mutex>
#include <ostream>
#include <string>

#include "libkeepass/detail/binary_source.hh"
#include "secure.hh"
#include "security.hh"

namespace keepass {

/**
 * @brief A binary blob (e.g. an attachment payload) with an optional
 * compression flag.
 *
 * A binary can either own its payload directly or reference a shared
 * @ref detail::BinarySource. Lazy binaries (used by the KDBX 4 importer for
 * inner-header attachments) only copy their payload into secure memory when
 * @ref data is first accessed; @ref WriteTo streams directly from the source.
 */
class Binary final {
private:
  mutable std::mutex mutex_;
  mutable protect<secure_string> data_;
  mutable bool loaded_ = true;
  bool protected_ = false;
  bool compress_ = false;
  std::size_t size_ = 0;
  std::shared_ptr<const detail::BinarySource> source_;

public:
  /// Creates a binary from the given protected data.
  explicit Binary(const protect<secure_string>& data);

  /**
   * @brief Creates a lazy binary backed by a shared source.
   *
   * @param source Payload source (must not be null).
   * @param protected_data Whether the payload is flagged as protected.
   * @param compress Whether the binary should be written compressed (KDBX 3).
   */
  Binary(std::shared_ptr<const detail::BinarySource> source, bool protected_data,
         bool compress = false);

  /// Copy-constructs the payload/source state.
  Binary(const Binary& other);

  /// Copy-assigns the payload/source state.
  Binary& operator=(const Binary& other);

  /// Returns whether the binary data is empty.
  bool Empty() const;

  /// Returns the size in bytes of the binary data.
  std::size_t Size() const;

  /// Returns the binary data, loading it first if necessary.
  const protect<secure_string>& data() const;

  /// Sets the binary data, replacing any lazy source.
  void set_data(const protect<secure_string>& data);

  /// Loads a lazy payload into secure memory (no-op for materialized data).
  void load() const;

  /// Returns whether the payload is currently materialized in memory.
  bool is_loaded() const { return loaded_; }

  /// Returns whether the payload is backed by a lazy source.
  bool is_lazy() const { return source_ != nullptr; }

  /// Returns whether the payload was stored with the protected flag.
  bool is_protected() const { return protected_; }

  /// Writes the payload to @p dst, streaming it when it is still lazy.
  void WriteTo(std::ostream& dst) const;

  /// Returns whether the binary is stored compressed.
  bool compress() const { return compress_; }

  /// Sets whether the binary is stored compressed.
  void set_compress(bool compress) { compress_ = compress; }

  /// Equality comparison (materializes lazy payloads).
  bool operator==(const Binary& other) const;

  /// Inequality comparison.
  bool operator!=(const Binary& other) const { return !(*this == other); }
};

} // namespace keepass
