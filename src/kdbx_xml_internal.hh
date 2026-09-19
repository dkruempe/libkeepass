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
 * @file kdbx_xml_internal.hh
 * @brief Small helpers shared by the KDBX XML codec translation units
 *        (meta, group, entry and top-level document handling).
 */

#pragma once
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <string>

namespace keepass {

/** Seconds between 0001-01-01 and the Unix epoch (1970-01-01). */
constexpr int64_t kKdbxEpochBias = 62135596800LL;

// Returns whether all UUID bytes are zero. Used to keep the KDBX 4.1
// previous-parent-group element out of the output when it is not set.
inline bool IsZeroUuid(const std::array<uint8_t, 16>& uuid) {
  return std::all_of(uuid.begin(), uuid.end(), [](uint8_t byte) { return byte == 0; });
}

// Returns whether the decoded base64 text can exceed the given byte limit.
// base64_decode consumes whole quadruples, so the upper bound (len / 4) * 3 is
// exact for inputs whose length is a multiple of four, which is all the
// decoder accepts. This avoids decoding (and allocating) hostile blobs.
inline bool ExceedsBase64DecodedSize(const char* text, uint64_t limit) {
  if (text == nullptr)
    return false;
  return (std::strlen(text) / 4) * 3 > limit;
}

// Returns whether a raw (unencoded) text exceeds the given byte limit.
inline bool ExceedsTextSize(const char* text, uint64_t limit) {
  if (text == nullptr)
    return false;
  return std::strlen(text) > limit;
}

// KeePass 2.48+ stores entry and group tags as a semicolon-separated list in
// the XML document (verified against KeePass 2.57). The public API contract is
// space-separated, so the two representations are converted at the XML
// boundary. Tag names cannot contain spaces or semicolons in KeePass.
inline std::string TagsFromXml(const char* xml_tags) {
  std::string out;
  bool pending_space = false;
  for (const char* p = xml_tags; *p != '\0'; ++p) {
    if (*p == ';') {
      pending_space = !out.empty();
    } else {
      if (pending_space) {
        out.push_back(' ');
        pending_space = false;
      }
      out.push_back(*p);
    }
  }
  return out;
}

inline std::string TagsToXml(const std::string& api_tags) {
  std::string out;
  bool pending_semicolon = false;
  for (char c : api_tags) {
    if (c == ' ') {
      pending_semicolon = !out.empty();
    } else {
      if (pending_semicolon) {
        out.push_back(';');
        pending_semicolon = false;
      }
      out.push_back(c);
    }
  }
  return out;
}

} // namespace keepass