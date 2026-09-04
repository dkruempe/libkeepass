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
 * @file base64.hh
 * @brief Base64 encoding and decoding helpers.
 */

#pragma once
#include <algorithm>
#include <locale>
#include <string>
#include <type_traits>

#include "exception.hh"

namespace keepass {

/**
 * @brief Encodes a range of bytes into a base64 string.
 *
 * @tparam InputIterator the iterator type over the input bytes.
 * @param first begin iterator of the byte range.
 * @param last end iterator of the byte range.
 * @return the base64-encoded string.
 */
template <typename InputIterator>
std::string base64_encode(InputIterator first, InputIterator last) {
  static const std::string kBase64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                     "abcdefghijklmnopqrstuvwxyz"
                                     "0123456789+/";

  std::string dst;

  while (first != last) {
    auto c0 = static_cast<uint8_t>(*first++);
    if (first == last) {
      dst.push_back(kBase64[static_cast<std::string::size_type>(c0 >> 2)]);
      dst.push_back(
          kBase64[static_cast<std::string::size_type>(((c0 & 0x3) << 4))]);
      dst.push_back('=');
      dst.push_back('=');
    } else {
      auto c1 = static_cast<uint8_t>(*first++);
      if (first == last) {
        dst.push_back(kBase64[static_cast<std::string::size_type>(c0 >> 2)]);
        dst.push_back(kBase64[static_cast<std::string::size_type>(
            ((c0 & 0x3) << 4) | (c1 >> 4))]);
        dst.push_back(
            kBase64[static_cast<std::string::size_type>(((c1 & 0xf) << 2))]);
        dst.push_back('=');
      } else {
        auto c2 = static_cast<uint8_t>(*first++);
        dst.push_back(kBase64[static_cast<std::string::size_type>(c0 >> 2)]);
        dst.push_back(kBase64[static_cast<std::string::size_type>(
            ((c0 & 0x3) << 4) | (c1 >> 4))]);
        dst.push_back(kBase64[static_cast<std::string::size_type>(
            ((c1 & 0xf) << 2) | (c2 >> 6))]);
        dst.push_back(kBase64[static_cast<std::string::size_type>(c2 & 0x3f)]);
      }
    }
  }

  return dst;
}

/**
 * @brief Decodes a base64 string into an output sequence.
 *
 * @tparam OutputIterator the output iterator type receiving the decoded bytes.
 * @tparam Type the value type written to the output iterator.
 * @param src the base64 string to decode.
 * @param result output iterator receiving the decoded bytes.
 * @throws FormatError if the input is not valid base64.
 */
template <typename OutputIterator, typename Type>
void base64_decode(const std::string &src, OutputIterator result) {
  static const std::string kBase64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                     "abcdefghijklmnopqrstuvwxyz"
                                     "0123456789+/";

  std::string src_trimmed;
  std::copy_if(src.begin(), src.end(),
               std::back_inserter<std::string>(src_trimmed),
               [](char c) { return !std::isspace(c, std::locale::classic()); });

  if (src_trimmed.size() % 4 != 0)
    throw FormatError("Base64 data must be a multiple of four in size.");

  uint32_t bits24 = 0;
  std::size_t i = 0;

  for (char c : src_trimmed) {
    if (c == '=') {
      *result = static_cast<Type>(bits24 >> 16);
      ++result;
      if (i > 2) {
        *result = static_cast<Type>((bits24 >> 8) & 0xff);
        ++result;
      }
      if (i > 3) {
        *result = static_cast<Type>(bits24 & 0xff);
        ++result;
      }
      break;
    }

    std::size_t v = kBase64.find(c);
    if (v == std::string::npos)
      throw FormatError("Illegal character in base64 stream.");

    bits24 |= static_cast<uint32_t>(v) << (18 - i++ * 6);
    if (i == 4) {
      *result = static_cast<Type>(bits24 >> 16);
      ++result;
      *result = static_cast<Type>((bits24 >> 8) & 0xff);
      ++result;
      *result = static_cast<Type>(bits24 & 0xff);
      ++result;

      bits24 = 0;
      i = 0;
    }
  }
}

/// Convenience overload that encodes an entire @c std::string.
inline std::string base64_encode(const std::string &src) {
  return base64_encode(src.begin(), src.end());
}

/// Convenience overload that decodes a base64 string into a @c std::string.
inline std::string base64_decode(const std::string &src) {
  std::string dst;
  base64_decode<std::back_insert_iterator<std::string>, char>(
      src, std::back_inserter(dst));
  return dst;
}

} // namespace keepass
