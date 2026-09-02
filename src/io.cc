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

#include "libkeepass/io.hh"

namespace keepass {

template <> std::string consume<std::string>(std::istream &src) {
  // Don't read the stream into a string directly. We want to make sure that we
  // get a clean string.
  std::vector<char> str_data;
  std::copy(std::istreambuf_iterator<char>(src),
            std::istreambuf_iterator<char>(), std::back_inserter(str_data));
  if (!src.good())
    throw IoError("Read error.");

  if (str_data.empty())
    throw IoError("Couldn't read zero length string.");

  std::string str;
  str.reserve(str_data.size());
  for (char c : str_data) {
    if (c == '\0')
      break;
    str.push_back(c);
  }

  return str;
}

template <> std::vector<char> consume<std::vector<char>>(std::istream &src) {
  std::vector<char> data;
  std::copy(std::istreambuf_iterator<char>(src),
            std::istreambuf_iterator<char>(), std::back_inserter(data));
  if (!src.good())
    throw IoError("Read error.");

  return data;
}

template <>
std::vector<uint8_t> consume<std::vector<uint8_t>>(std::istream &src) {
  std::streampos pos = src.tellg();
  src.seekg(0, std::ios::end);
  std::streamsize size = src.tellg() - pos;
  src.seekg(pos, std::ios::beg);

  if (size < 0)
    throw IoError("Read error.");

  std::vector<uint8_t> data(static_cast<std::size_t>(size));
  src.read(reinterpret_cast<char *>(data.data()), size);
  if (!src.good())
    throw IoError("Read error.");

  return data;
}

template <>
void conserve<std::string>(std::ostream &dst, const std::string &val) {
  // KDB strings are NUL-terminated: consumers read up to (but not including)
  // the first NUL, so embedded NUL bytes cannot round-trip. Reject them
  // explicitly instead of silently corrupting the written stream.
  if (val.find('\0') != std::string::npos)
    throw IoError("String contains an embedded NUL character.");

  // Writes the string contents plus its terminating NUL.
  dst.write(val.c_str(), static_cast<std::streamsize>(val.size() + 1));
  if (!dst.good())
    throw IoError("Write error.");
}

template <>
void conserve<std::vector<char>>(std::ostream &dst,
                                 const std::vector<char> &val) {
  dst.write(val.data(), static_cast<std::streamsize>(val.size()));
  if (!dst.good())
    throw IoError("Write error.");
}

template <>
void conserve<std::vector<uint8_t>>(std::ostream &dst,
                                    const std::vector<uint8_t> &val) {
  dst.write(reinterpret_cast<const char *>(val.data()),
            static_cast<std::streamsize>(val.size()));
  if (!dst.good())
    throw IoError("Write error.");
}

} // namespace keepass
