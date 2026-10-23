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

#include "libkeepass/detail/binary_source.hh"

#include <algorithm>
#include <cstring>

#include "libkeepass/exception.hh"

namespace keepass::detail {

BufferBinarySource::BufferBinarySource(std::shared_ptr<const SecureBytes> buffer,
                                       std::size_t offset, std::size_t size)
    : buffer_(std::move(buffer)), offset_(offset), size_(size) {
  if (!buffer_ || offset_ > buffer_->size() || size_ > buffer_->size() - offset_)
    throw IoError("Binary source range is outside its backing buffer.");
}

void BufferBinarySource::Read(std::size_t offset, void* dst, std::size_t size) const {
  if (offset > size_ || size > size_ - offset)
    throw IoError("Binary source read is outside the payload.");
  if (size == 0)
    return;
  std::memcpy(dst, buffer_->data() + offset_ + offset, size);
}

void BufferBinarySource::WriteTo(std::ostream& dst) const {
  if (size_ == 0)
    return;
  dst.write(reinterpret_cast<const char*>(buffer_->data() + offset_),
            static_cast<std::streamsize>(size_));
  if (!dst.good())
    throw IoError("Write error.");
}

} // namespace keepass::detail
