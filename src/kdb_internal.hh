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
 * @file kdb_internal.hh
 * @brief Internal KDB (KeePass 1.x) on-disk types shared by the KDB codec
 *        translation units (field parsing, import and export).
 */

#pragma once
#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <ctime>

namespace keepass {

const uint32_t kKdbSignature0 = 0x9aa2d903;
const uint32_t kKdbSignature1 = 0xb54bfb65;
// The legacy KDB header flags also reserve bits for SHA-256 (0x00000001) and
// ARC FOUR (0x00000004), which this library does not implement.
const uint32_t kKdbFlagRijndael = 0x00000002;
const uint32_t kKdbFlagTwofish = 0x00000008;

#pragma pack(push, 1)
struct KdbHeader {
  uint32_t signature0;
  uint32_t signature1;
  uint32_t flags;
  uint32_t version;
  std::array<uint8_t, 16> master_seed;
  std::array<uint8_t, 16> init_vector;
  uint32_t num_groups;
  uint32_t num_entries;
  std::array<uint8_t, 32> content_hash;
  std::array<uint8_t, 32> transform_seed;
  uint32_t transform_rounds;
};
static_assert(sizeof(KdbHeader) == 124, "bad packing of header structure.");

/**
 * @brief KDB time entry.
 *
 * Five bytes in a packed format:
 * 00YYYYYY YYYYYYMM MMDDDDDH HHHHMMMM MMSSSSSS
 */
struct KdbTime {
  std::array<uint8_t, 5> packed = {{0}};

  KdbTime() = default;

  explicit KdbTime(std::time_t time) {
    static constexpr std::array<uint8_t, 5> kNeverTimeConstant = {0x2e, 0xdf, 0x39, 0x7e, 0xfb};
    if (time == -1) {
      packed = kNeverTimeConstant;
    } else {
#ifdef _MSC_VER
      std::tm time_buf{};
      gmtime_s(&time_buf, &time);
      std::tm* time_ptr = &time_buf;
#else
      std::tm time_buf{};
      gmtime_r(&time, &time_buf);
      std::tm* time_ptr = &time_buf;
#endif

      uint32_t year = static_cast<uint32_t>(time_ptr->tm_year) + 1900;
      uint32_t month = static_cast<uint32_t>(time_ptr->tm_mon) + 1;
      auto day = static_cast<uint32_t>(time_ptr->tm_mday);
      auto hour = static_cast<uint32_t>(time_ptr->tm_hour);
      auto minute = static_cast<uint32_t>(time_ptr->tm_min);
      auto second = static_cast<uint32_t>(time_ptr->tm_sec);

      packed[0] = static_cast<uint8_t>(year >> 6);
      packed[1] = static_cast<uint8_t>(((year & 0x3f) << 2) | (month >> 2));
      packed[2] = static_cast<uint8_t>(((month & 0x3) << 6) | (day << 1) | (hour >> 4));
      packed[3] = static_cast<uint8_t>(((hour & 0xf) << 4) | (minute >> 2));
      packed[4] = static_cast<uint8_t>(((minute & 0x3) << 6) | second);
    }
  }

  std::time_t ToTime() const {
    static constexpr std::array<uint8_t, 5> kNeverTimeConstant = {0x2e, 0xdf, 0x39, 0x7e, 0xfb};

    // Expand the bytes to 16-bits so that we can shift freely.
    std::array<uint16_t, 5> packed16{};
    std::copy(packed.begin(), packed.end(), packed16.begin());

    uint32_t year =
        (static_cast<uint32_t>(packed16[0] << 6)) | (static_cast<uint32_t>(packed16[1] >> 2));
    uint32_t month = ((static_cast<uint32_t>(packed16[1]) & 0x0003) << 2) |
                     (static_cast<uint32_t>(packed16[2]) >> 6);
    uint32_t day = (static_cast<uint32_t>(packed16[2]) >> 1) & 0x001f;
    uint32_t hour = ((static_cast<uint32_t>(packed16[2]) & 0x0001) << 4) |
                    (static_cast<uint32_t>(packed16[3]) >> 4);
    uint32_t minute = ((static_cast<uint32_t>(packed16[3]) & 0x000f) << 2) |
                      (static_cast<uint32_t>(packed16[4]) >> 6);
    uint32_t second = packed16[4] & 0x003f;

    if (packed == kNeverTimeConstant)
      return 0;

    assert(second <= 60);
    assert(minute <= 59);
    assert(hour <= 23);
    assert(day >= 1 && day <= 31);
    assert(month >= 1 && month <= 12);
    assert(year >= 1900);

    std::tm time{};
    time.tm_sec = static_cast<int32_t>(second);
    time.tm_min = static_cast<int32_t>(minute);
    time.tm_hour = static_cast<int32_t>(hour);
    time.tm_mday = static_cast<int32_t>(day);
    time.tm_mon = static_cast<int32_t>(month) - 1; // [0,11]
    time.tm_year = static_cast<int32_t>(year) - 1900;
    time.tm_wday = 0;   // Ignored by timegm().
    time.tm_yday = 0;   // Ignored by timegm().
    time.tm_isdst = -1; // Ignored by timegm().

#ifdef _MSC_VER
    std::time_t res = _mkgmtime(&time);
#else
    std::time_t res = timegm(&time);
#endif
    if (res == -1) {
      assert(false);
      return 0;
    }

    return res;
  }
};
static_assert(sizeof(KdbTime) == 5, "bad packing of time structure.");
#pragma pack(pop)

enum class KdbGroupFieldType : uint16_t {
  kEmpty,            ///< 0 bytes.
  kId,               ///< 4 bytes.
  kName,             ///< N bytes.
  kCreationTime,     ///< 5 bytes.
  kModificationTime, ///< 5 bytes.
  kAccessTime,       ///< 5 bytes.
  kExpiryTime,       ///< 5 bytes.
  kIcon,             ///< 4 bytes.
  kLevel,            ///< 2 bytes.
  kFlags,            ///< 2 bytes.
  kEnd = 0xffff      ///< 0 bytes.
};

enum class KdbEntryFieldType : uint16_t {
  kEmpty,            ///< 0 bytes.
  kUuid,             ///< 16 bytes.
  kGroupId,          ///< 4 bytes.
  kIcon,             ///< 4 bytes.
  kTitle,            ///< N bytes.
  kUrl,              ///< N bytes.
  kUsername,         ///< N bytes.
  kPassword,         ///< N bytes.
  kNotes,            ///< N bytes.
  kCreationTime,     ///< 5 bytes.
  kModificationTime, ///< 5 bytes.
  kAccessTime,       ///< 5 bytes.
  kExpiryTime,       ///< 5 bytes.
  kAttachmentName,   ///< N bytes.
  kAttachmentData,   ///< N bytes.
  kEnd = 0xffff
};

} // namespace keepass