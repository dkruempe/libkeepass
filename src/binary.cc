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

#include "libkeepass/binary.hh"

#include <utility>
#include <vector>

#include "libkeepass/exception.hh"

namespace keepass {

Binary::Binary(const protect<secure_string>& data)
    : data_(data), protected_(data.is_protected()), size_(data->size()) {}

Binary::Binary(std::shared_ptr<const detail::BinarySource> source, bool protected_data,
               bool compress)
    : loaded_(false), protected_(protected_data), compress_(compress),
      size_(source ? source->size() : 0), source_(std::move(source)) {
  if (!source_)
    loaded_ = true;
}

Binary::Binary(const Binary& other) {
  std::scoped_lock lock(other.mutex_);
  data_ = other.data_;
  loaded_ = other.loaded_;
  protected_ = other.protected_;
  compress_ = other.compress_;
  size_ = other.size_;
  source_ = other.source_;
}

Binary& Binary::operator=(const Binary& other) {
  if (this == &other)
    return *this;
  std::scoped_lock lock(mutex_, other.mutex_);
  data_ = other.data_;
  loaded_ = other.loaded_;
  protected_ = other.protected_;
  compress_ = other.compress_;
  size_ = other.size_;
  source_ = other.source_;
  return *this;
}

bool Binary::Empty() const { return Size() == 0; }

std::size_t Binary::Size() const {
  if (!loaded_ && source_)
    return source_->size();
  return size_;
}

const protect<secure_string>& Binary::data() const {
  load();
  return data_;
}

void Binary::load() const {
  std::scoped_lock lock(mutex_);
  if (loaded_)
    return;
  if (!source_) {
    loaded_ = true;
    return;
  }

  std::vector<uint8_t> bytes(source_->size());
  if (!bytes.empty())
    source_->Read(0, bytes.data(), bytes.size());

  secure_string value;
  value.assign(reinterpret_cast<const char*>(bytes.data()), bytes.size());
  secure_zero(bytes.data(), bytes.size());

  data_ = protect<secure_string>(std::move(value), protected_);
  loaded_ = true;
}

void Binary::set_data(const protect<secure_string>& data) {
  std::scoped_lock lock(mutex_);
  data_ = data;
  protected_ = data.is_protected();
  size_ = data->size();
  loaded_ = true;
  source_.reset();
}

void Binary::WriteTo(std::ostream& dst) const {
  std::shared_ptr<const detail::BinarySource> source;
  {
    std::scoped_lock lock(mutex_);
    if (!loaded_)
      source = source_;
  }

  if (source) {
    source->WriteTo(dst);
    return;
  }

  const protect<secure_string>& value = data();
  if (!value->empty()) {
    dst.write(value->data(), static_cast<std::streamsize>(value->size()));
    if (!dst.good())
      throw IoError("Write error.");
  }
}

bool Binary::operator==(const Binary& other) const { return data() == other.data(); }

} // namespace keepass
