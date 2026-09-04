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

/** @file iterator.hh @brief Bounds-checked output iterator helper. */

#pragma once
#include <iterator>
#include <exception>

namespace keepass {

/**
 * @brief An output iterator that throws on writing past the end of a container.
 *
 * The iterator wraps a range of a container and throws @c std::out_of_range
 * whenever an assignment would exceed the container's bounds.
 *
 * @tparam C the underlying container type.
 */
template <typename C>
class bounds_checked_iterator {
protected:
  typename C::iterator first_;
  typename C::iterator last_;

public:
  using iterator_category = std::output_iterator_tag;
  using value_type = void;
  using difference_type = void;
  using pointer = void;
  using reference = void;

  /**
   * Creates a bounds-checked iterator over the given container.
   * @param container the container to iterate over.
   */
  explicit bounds_checked_iterator(C &container)
      : first_(container.begin()), last_(container.end()) {}

  /// Assigns a value through the iterator, throwing if the end is exceeded.
  bounds_checked_iterator &operator=(const typename C::value_type &value) {
    if (first_ == last_)
      throw std::out_of_range("assigning outside container limits.");

    *first_ = value;
    return *this;
  }

  /// Move-assigns a value through the iterator, throwing if the end is exceeded.
  bounds_checked_iterator &operator=(typename C::value_type &&value) {
    if (first_ == last_)
      throw std::out_of_range("assigning outside container limits.");

    *first_ = std::move(value);
    return *this;
  }

  bounds_checked_iterator &operator*() { return *this; }

  bounds_checked_iterator &operator++() {
    first_++;
    return *this;
  }

  bounds_checked_iterator operator++(int) {
    ++first_;
    return *this;
  }
};

/**
 * @brief Convenience factory that creates a bounds-checked iterator.
 * @tparam C the container type.
 * @param container the container to iterate over.
 * @return a bounds-checked iterator over the container.
 */
template <typename C>
inline bounds_checked_iterator<C> bounds_checked(C &container) {
  return bounds_checked_iterator<C>(container);
}

} // namespace keepass
