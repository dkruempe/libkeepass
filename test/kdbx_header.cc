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

#include <streambuf>
#include <string>

#include <gtest/gtest.h>

#include "libkeepass/database.hh"

#include "libkeepass/exception.hh"
#include "libkeepass/kdbx_header.hh"

using namespace keepass;

namespace {

constexpr uint8_t kUnknownFieldId = 0x7f;

// Serializes one KDBX 3 header field (1-byte id, 2-byte little-endian size).
std::string Field3(uint8_t id, uint16_t size, const std::string& payload) {
  std::string out;
  out += static_cast<char>(id);
  out += static_cast<char>(size & 0xff);
  out += static_cast<char>((size >> 8) & 0xff);
  out += payload;
  return out;
}

// Serializes one KDBX 4 header field (1-byte id, 4-byte little-endian size).
std::string Field4(uint8_t id, uint32_t size, const std::string& payload) {
  std::string out;
  out += static_cast<char>(id);
  out += static_cast<char>(size & 0xff);
  out += static_cast<char>((size >> 8) & 0xff);
  out += static_cast<char>((size >> 16) & 0xff);
  out += static_cast<char>((size >> 24) & 0xff);
  out += payload;
  return out;
}

// A stream that claims to hold `declared` bytes from the current position but
// only delivers the buffered data; reading beyond it yields EOF. This models a
// truncated file whose size cannot be determined from the seekable stream and
// exercises the "read error" guard in the header parsers.
class ShortReadBuf : public std::streambuf {
private:
  std::string data_;
  std::streamoff declared_;
  std::streamoff pos_ = 0;

  std::streamoff CurrentPos() const {
    if (gptr() != nullptr && !data_.empty())
      return gptr() - data_.data();
    return pos_;
  }

protected:
  std::streampos seekoff(std::streamoff off, std::ios_base::seekdir way,
                         std::ios_base::openmode /*which*/) override {
    std::streamoff base = 0;
    if (way == std::ios_base::end) {
      base = declared_;
    } else if (way == std::ios_base::cur) {
      base = CurrentPos();
    }
    const std::streamoff target = base + off;
    return seekpos(std::streampos(target), std::ios_base::in);
  }

  std::streampos seekpos(std::streampos pos, std::ios_base::openmode /*which*/) override {
    const std::streamoff target = static_cast<std::streamoff>(pos);
    if (target < 0 || target > declared_) {
      const std::streampos invalid(-1);
      return invalid;
    }
    pos_ = target;
    if (target <= static_cast<std::streamoff>(data_.size())) {
      setg(data_.data() + target, data_.data() + target, data_.data() + data_.size());
    } else {
      setg(nullptr, nullptr, nullptr);
    }
    return pos;
  }

  int_type underflow() override {
    if (!data_.empty() && gptr() != nullptr && gptr() < egptr())
      return traits_type::to_int_type(*gptr());
    return traits_type::eof();
  }

public:
  ShortReadBuf(const std::string& data, std::streamoff declared)
      : data_(data), declared_(declared) {
    if (!data_.empty()) {
      setg(data_.data(), data_.data(), data_.data() + data_.size());
      pos_ = 0;
    }
  }
};

} // namespace

TEST(KdbxHeaderTest, Parse3RejectsUnknownField) {
  Database db;
  std::stringstream src(Field3(kUnknownFieldId, 0, ""), std::ios::in | std::ios::binary);
  EXPECT_THROW(KdbxHeader::Parse3(src, db), FormatError);
}

TEST(KdbxHeaderTest, Parse3RejectsUnknownCipher) {
  Database db;
  std::stringstream src(Field3(0x02, 16, std::string(16, static_cast<char>(0xff))),
                        std::ios::in | std::ios::binary);
  EXPECT_THROW(KdbxHeader::Parse3(src, db), FormatError);
}

TEST(KdbxHeaderTest, Parse3RejectsUnknownCompression) {
  Database db;
  const std::string payload{3, 0, 0, 0};
  std::stringstream src(Field3(0x03, 4, payload), std::ios::in | std::ios::binary);
  EXPECT_THROW(KdbxHeader::Parse3(src, db), FormatError);
}

TEST(KdbxHeaderTest, Parse3RejectsIllegalTransformSeedSize) {
  Database db;
  std::stringstream src(Field3(0x05, 1, "x"), std::ios::in | std::ios::binary);
  EXPECT_THROW(KdbxHeader::Parse3(src, db), FormatError);
}

TEST(KdbxHeaderTest, Parse3RejectsTooManyTransformRounds) {
  Database db;
  const std::string payload{0, 0, 0, 0x20};
  std::stringstream src(Field3(0x06, 4, payload), std::ios::in | std::ios::binary);
  EXPECT_THROW(KdbxHeader::Parse3(src, db), FormatError);
}

TEST(KdbxHeaderTest, Parse3RejectsIllegalInitVectorSize) {
  Database db;
  std::stringstream src(Field3(0x07, 4, std::string(4, '\0')), std::ios::in | std::ios::binary);
  EXPECT_THROW(KdbxHeader::Parse3(src, db), FormatError);
}

TEST(KdbxHeaderTest, Parse3RejectsIllegalRandomStreamKeySize) {
  Database db;
  std::stringstream src(Field3(0x08, 16, std::string(16, '\0')), std::ios::in | std::ios::binary);
  EXPECT_THROW(KdbxHeader::Parse3(src, db), FormatError);
}

TEST(KdbxHeaderTest, Parse3RejectsIllegalStreamStartByteCount) {
  Database db;
  std::stringstream src(Field3(0x09, 16, std::string(16, '\0')), std::ios::in | std::ios::binary);
  EXPECT_THROW(KdbxHeader::Parse3(src, db), FormatError);
}

TEST(KdbxHeaderTest, Parse3RejectsUnknownRandomStream) {
  Database db;
  const std::string payload{1, 0, 0, 0};
  std::stringstream src(Field3(0x0a, 4, payload), std::ios::in | std::ios::binary);
  EXPECT_THROW(KdbxHeader::Parse3(src, db), FormatError);
}

TEST(KdbxHeaderTest, Parse3ReadError) {
  // The master-seed field declares 16 bytes, the stream grants that many but
  // delivers none; the parser must surface an I/O error instead of reading
  // beyond the field.
  ShortReadBuf buf(Field3(0x04, 16, ""), 3 + 16);
  std::istream src(&buf);
  Database db;
  EXPECT_THROW(KdbxHeader::Parse3(src, db), IoError);
}

TEST(KdbxHeaderTest, Parse4RejectsUnknownField) {
  Database db;
  std::stringstream src(Field4(kUnknownFieldId, 0, ""), std::ios::in | std::ios::binary);
  EXPECT_THROW(KdbxHeader::Parse4(src, db), FormatError);
}

TEST(KdbxHeaderTest, Parse4RejectsIllegalInitVectorSize) {
  Database db;
  std::stringstream src(Field4(0x07, 13, std::string(13, '\0')), std::ios::in | std::ios::binary);
  EXPECT_THROW(KdbxHeader::Parse4(src, db), FormatError);
}

TEST(KdbxHeaderTest, Parse4RejectsUnknownCompression) {
  Database db;
  const std::string payload{3, 0, 0, 0};
  std::stringstream src(Field4(0x03, 4, payload), std::ios::in | std::ios::binary);
  EXPECT_THROW(KdbxHeader::Parse4(src, db), FormatError);
}

TEST(KdbxHeaderTest, Parse4ReadError) {
  // The master-seed field declares 16 bytes, the stream grants that many but
  // delivers none; the parser must surface an I/O error instead of reading
  // beyond the field.
  ShortReadBuf buf(Field4(0x04, 16, ""), 5 + 16);
  std::istream src(&buf);
  Database db;
  EXPECT_THROW(KdbxHeader::Parse4(src, db), IoError);
}