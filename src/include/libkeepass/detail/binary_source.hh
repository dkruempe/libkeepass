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

/** @file binary_source.hh
 *  @brief Lazy backing store for binary attachment payloads. */

#pragma once

#include <cstddef>
#include <memory>
#include <ostream>

#include "libkeepass/export.hh"
#include "libkeepass/secure.hh"

namespace keepass {
namespace detail {

/**
 * @brief Read-only source for an attachment payload.
 *
 * A source owns or shares the (already decrypted) bytes and exposes them
 * without forcing the object model to materialize a per-attachment copy. The
 * KDBX 4 importer stores all inner-header binaries in one shared, zeroized
 * buffer and creates a small source view for each attachment.
 */
class LIBKEEPASS_API BinarySource {
public:
  virtual ~BinarySource() = default;

  /// Returns the payload size in bytes.
  virtual std::size_t size() const noexcept = 0;

  /// Copies @p size bytes starting at @p offset into @p dst.
  /**
   * @throws IoError if the requested range is outside the source.
   */
  virtual void Read(std::size_t offset, void* dst, std::size_t size) const = 0;

  /// Writes the whole payload to @p dst without materializing a copy.
  /**
   * @throws IoError on write failure.
   */
  virtual void WriteTo(std::ostream& dst) const = 0;
};

/**
 * @brief Binary source backed by a shared secure byte buffer.
 */
class LIBKEEPASS_API BufferBinarySource final : public BinarySource {
public:
  /**
   * @param buffer Shared buffer holding the payload (and possibly other
   *               binaries).
   * @param offset Offset of this payload inside @p buffer.
   * @param size Payload size in bytes.
   */
  BufferBinarySource(std::shared_ptr<const SecureBytes> buffer, std::size_t offset,
                     std::size_t size);

  std::size_t size() const noexcept override { return size_; }

  void Read(std::size_t offset, void* dst, std::size_t size) const override;
  void WriteTo(std::ostream& dst) const override;

private:
  std::shared_ptr<const SecureBytes> buffer_;
  std::size_t offset_ = 0;
  std::size_t size_ = 0;
};

} // namespace detail
} // namespace keepass
