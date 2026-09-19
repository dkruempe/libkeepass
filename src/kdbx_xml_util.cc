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

#include "libkeepass/kdbx_xml.hh"

#include <cassert>
#include <ctime>
#include <string_view>

#include <pugixml.hpp>

#ifdef _MSC_VER
#include <cstdio>
namespace {
char* portable_strptime(const char* buf, const char* /*format*/, std::tm* tm) {
  int year, month, day, hour, min, sec;
  if (sscanf_s(buf, "%d-%d-%dT%d:%d:%d", &year, &month, &day, &hour, &min, &sec) == 6) {
    tm->tm_year = year - 1900;
    tm->tm_mon = month - 1;
    tm->tm_mday = day;
    tm->tm_hour = hour;
    tm->tm_min = min;
    tm->tm_sec = sec;
    tm->tm_isdst = 0;
    const char* p = buf;
    while (*p && *p != 'Z' && *p != '\0')
      ++p;
    return const_cast<char*>(p);
  }
  return nullptr;
}
} // namespace
#define strptime portable_strptime
#endif

#include "kdbx_xml_internal.hh"
#include "libkeepass/base64.hh"

namespace keepass {

int64_t KdbxXml::NeverSeconds() {
  // The KDBX "never" marker is the fixed timestamp 2999-12-28T22:59:59Z.
  static const int64_t kNeverSeconds = []() {
    std::tm tm{};
    strptime("2999-12-28T22:59:59Z", "%Y-%m-%dT%H:%M:%S", &tm);
#ifdef _MSC_VER
    return _mkgmtime(&tm) + kKdbxEpochBias;
#else
    return timegm(&tm) + kKdbxEpochBias;
#endif
  }();

  return kNeverSeconds;
}

std::time_t KdbxXml::ParseDateTime(const char* text) const {
  std::string_view str(text);

  // Check for the special KeePass 1x "never" timestamp.
  if (str == "2999-12-28T22:59:59Z")
    return 0;

  if (kdbx4_) {
    // KDBX 4 stores times as a Base64 encoded Int64 value of the number of
    // seconds elapsed since 0001-01-01 00:00:00 UTC, little-endian.
    std::string raw = base64_decode(str);
    if (raw.size() < 8)
      return 0;

    uint64_t secs = 0;
    for (std::size_t i = 0; i < 8; ++i)
      secs |= static_cast<uint64_t>(static_cast<uint8_t>(raw[i])) << (8 * i);

    if (static_cast<int64_t>(secs) == NeverSeconds())
      return 0;

    return static_cast<int64_t>(secs) - kKdbxEpochBias;
  }

  std::tm tm{};
  char* res = strptime(text, "%Y-%m-%dT%H:%M:%S", &tm);
  if (res == nullptr) {
    assert(false);
    return 0;
  }

  // Format is expected to always be in UTC.
  assert(*res == 'Z' || *res == '\0');

#ifdef _MSC_VER
  return _mkgmtime(&tm);
#else
  return timegm(&tm);
#endif
}

std::string KdbxXml::WriteDateTime(std::time_t time) const {
  if (kdbx4_) {
    int64_t secs = time == 0 ? NeverSeconds() : static_cast<int64_t>(time) + kKdbxEpochBias;

    uint8_t bytes[8];
    uint64_t val = static_cast<uint64_t>(secs);
    for (uint8_t& byte : bytes) {
      byte = static_cast<uint8_t>(val & 0xff);
      val >>= 8;
    }

    return base64_encode(bytes, bytes + 8);
  }

  if (time == 0)
    return "2999-12-28T22:59:59Z";

  char buffer[128];
#ifdef _MSC_VER
  std::tm time_buf{};
  gmtime_s(&time_buf, &time);
  std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &time_buf);
#else
  std::tm time_buf{};
  gmtime_r(&time, &time_buf);
  std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &time_buf);
#endif
  return buffer;
}

} // namespace keepass