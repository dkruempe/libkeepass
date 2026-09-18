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

#include "libkeepass/kdbx_header.hh"

#include <algorithm>
#include <cassert>
#include <sstream>

#include "libkeepass/detail/secure_io.hh"
#include "libkeepass/exception.hh"
#include "libkeepass/io.hh"
#include "libkeepass/kdbx_kdf.hh"
#include "libkeepass/random.hh"
#include "libkeepass/secure.hh"

namespace keepass {

namespace {

// WipeStream/WipeBuffer are shared with the other format codecs to keep the
// sensitive-data wiping logic in one place; see detail/secure_io.hh.
using keepass::detail::WipeBuffer;
using keepass::detail::WipeStream;

constexpr std::uint32_t kKdbxVersionCriticalMin = 0x00030001;
constexpr std::uint32_t kKdbxVersion4_1 = 0x00040001;

constexpr std::array<uint8_t, 16> kKdbxCipherAes = {{0x31, 0xc1, 0xf2, 0xe6, 0xbf, 0x71, 0x43, 0x50,
                                                     0xbe, 0x58, 0x05, 0x21, 0x6a, 0xfc, 0x5a,
                                                     0xff}};
constexpr std::array<uint8_t, 16> kKdbxCipherChaCha20 = {{0xd6, 0x03, 0x8a, 0x2b, 0x8b, 0x6f, 0x4c,
                                                          0xb5, 0xa5, 0x24, 0x33, 0x9a, 0x31, 0xdb,
                                                          0xb5, 0x9a}};
constexpr std::array<uint8_t, 16> kKdbxCipherTwofish = {{0xad, 0x68, 0xf2, 0x9f, 0x57, 0x6f, 0x4b,
                                                         0xb9, 0xa3, 0x6a, 0xd4, 0x7a, 0xf9, 0x65,
                                                         0x34, 0x6c}};

/**
 * Upper bound for a single outer header field. Real KDBX headers only contain
 * short fields (cipher id, seeds, KDF parameters); the cap exists to reject
 * crafted files whose declared field lengths would trigger unbounded
 * allocations or reads before the header integrity check runs.
 */
constexpr uint32_t kMaxOuterHeaderFieldSize = 1U << 20;

enum class kKdbxCompressionFlags : uint32_t {
  kNone,
  kGzip,

  kCount
};

enum class kKdbxRandomStream : uint32_t {
  kNone,
  kArcFourVariant,
  kSalsa20,

  kCount
};

#pragma pack(push, 1)
struct KdbxHeaderPrefix {
  uint32_t signature0;
  uint32_t signature1;
  uint32_t version;
};
static_assert(sizeof(KdbxHeaderPrefix) == 12, "bad packing of header structure.");

struct KdbxHeaderField {
  enum Id : uint8_t {
    kEndOfHeader = 0,
    // kComment = 1,
    kCipherId = 2,
    kCompressionFlags = 3,
    kMasterSeed = 4,
    kTransformSeed = 5,
    kTransformRounds = 6,
    kExcryptionInitVec = 7,
    kInnerRandomStreamKey = 8,
    kContentStreamStartBytes = 9,
    kInnerRandomStreamId = 10
  } id = kEndOfHeader;

  uint16_t size = 0;

  KdbxHeaderField() = default;
  KdbxHeaderField(Id new_id, uint16_t new_size) : id(new_id), size(new_size) {}
  KdbxHeaderField(KdbxHeaderField&& other) noexcept {
    id = other.id;
    size = other.size;
  }
};
static_assert(sizeof(KdbxHeaderField) == 3, "bad packing of bitfield header structure.");

struct Kdbx4HeaderField {
  enum Id : uint8_t {
    kEndOfHeader = 0,
    kComment = 1,
    kCipherId = 2,
    kCompressionFlags = 3,
    kMasterSeed = 4,
    kEncryptionIv = 7,
    kKdfParameters = 11
  } id = kEndOfHeader;

  uint32_t size = 0;

  Kdbx4HeaderField() = default;
  Kdbx4HeaderField(Id new_id, uint32_t new_size) : id(new_id), size(new_size) {}
  Kdbx4HeaderField(Kdbx4HeaderField&& other) noexcept {
    id = other.id;
    size = other.size;
  }
};
static_assert(sizeof(Kdbx4HeaderField) == 5, "bad packing of header structure.");
#pragma pack(pop)

} // namespace

uint32_t KdbxHeader::ReadVersion(std::istream& src) {
  KdbxHeaderPrefix header{};
  try {
    header = consume<KdbxHeaderPrefix>(src);
  } catch (std::exception&) {
    throw FormatError("Not a KDBX database.");
  }
  if (header.signature0 != kSignature0 || header.signature1 != kSignature1)
    throw FormatError("Not a KDBX database.");

  return header.version;
}

std::array<uint8_t, 32> KdbxHeader::Parse3(std::istream& src, Database& db) {
  std::array<uint8_t, 32> content_start_bytes = {{0}};

  bool done = false;
  while (!done && src.good()) {
    auto header_field = consume<KdbxHeaderField>(src);

    // Read the header field into a separate buffer before parsing. This is to
    // guard against reading outside the field as well as for making sure to
    // read the complete field regardless of how much of it that we parse.
    // KDBX 3 field sizes are 16 bit and thus always below the cap.
    if (static_cast<uint64_t>(header_field.size) >
        static_cast<uint64_t>(std::max<std::streamsize>(0, RemainingBytes(src))))
      throw FormatError("Corrupt header field size in KDBX.");
    std::stringstream field;
    std::generate_n(std::ostreambuf_iterator<char>(field), header_field.size,
                    [&src]() { return static_cast<char>(src.get()); });
    if (!src.good())
      throw IoError("Read error.");

    assert(field.str().size() == header_field.size);

    switch (header_field.id) {
    case KdbxHeaderField::kEndOfHeader:
      done = true;
      break;
    case KdbxHeaderField::kCipherId:
      if (consume<std::array<uint8_t, 16>>(field) != kKdbxCipherAes)
        throw FormatError("Unknown cipher in KDBX.");
      db.set_cipher(Database::Cipher::kAes);
      break;
    case KdbxHeaderField::kCompressionFlags: {
      auto comp_flags = consume<uint32_t>(field);
      if (comp_flags > static_cast<uint32_t>(kKdbxCompressionFlags::kCount))
        throw FormatError("Unknown compression method in KDBX.");
      db.set_compress(comp_flags == static_cast<uint32_t>(kKdbxCompressionFlags::kGzip));
      break;
    }
    case KdbxHeaderField::kMasterSeed:
      db.set_master_seed(consume<std::vector<uint8_t>>(field));
      break;
    case KdbxHeaderField::kTransformSeed:
      if (header_field.size != 32)
        throw FormatError("Illegal transform seed size in KDBX.");
      db.set_transform_seed(consume<std::array<uint8_t, 32>>(field));
      break;
    case KdbxHeaderField::kTransformRounds: {
      const uint32_t transform_rounds = consume<uint32_t>(field);
      if (transform_rounds > Database::kMaxTransformRounds)
        throw FormatError("KDBX header declares too many transform rounds.");
      db.set_transform_rounds(transform_rounds);
      break;
    }
    case KdbxHeaderField::kExcryptionInitVec:
      if (header_field.size != 16)
        throw FormatError("Illegal initialization vector size in KDBX.");
      db.set_init_vector(consume<std::array<uint8_t, 16>>(field));
      break;
    case KdbxHeaderField::kInnerRandomStreamKey:
      if (header_field.size != 32)
        throw FormatError("Illegal protected stream key size in KDBX.");
      db.set_inner_random_stream_key(consume<std::array<uint8_t, 32>>(field));
      break;
    case KdbxHeaderField::kContentStreamStartBytes:
      if (header_field.size != 32)
        throw FormatError("Illegal stream start sequence size in KDBX.");
      content_start_bytes = consume<std::array<uint8_t, 32>>(field);
      break;
    case KdbxHeaderField::kInnerRandomStreamId: {
      auto inner_random_stream_id = consume<uint32_t>(field);
      if (inner_random_stream_id != static_cast<uint32_t>(kKdbxRandomStream::kSalsa20)) {
        throw FormatError("Unknown random stream in KDBX.");
      }
      break;
    }
    default:
      throw FormatError("Illegal header field in KDBX.");
      break;
    }

    // The field stream transiently holds header material (master seed, key
    // material) that is not part of the exported database object.
    WipeStream(field);
  }

  return content_start_bytes;
}

void KdbxHeader::Parse4(std::istream& src, Database& db) {
  bool done = false;
  while (!done && src.good()) {
    auto header_field = consume<Kdbx4HeaderField>(src);

    // Read the header field into a separate buffer before parsing.
    if (header_field.size > kMaxOuterHeaderFieldSize ||
        static_cast<uint64_t>(header_field.size) >
            static_cast<uint64_t>(std::max<std::streamsize>(0, RemainingBytes(src))))
      throw FormatError("Corrupt header field size in KDBX 4 database.");
    std::stringstream field;
    std::generate_n(std::ostreambuf_iterator<char>(field), header_field.size,
                    [&src]() { return static_cast<char>(src.get()); });
    if (!src.good())
      throw IoError("Read error.");

    switch (header_field.id) {
    case Kdbx4HeaderField::kEndOfHeader:
      done = true;
      break;
    case Kdbx4HeaderField::kCipherId: {
      auto uuid = consume<std::array<uint8_t, 16>>(field);
      if (uuid == kKdbxCipherChaCha20) {
        db.set_cipher(Database::Cipher::kChaCha20);
      } else if (uuid == kKdbxCipherAes) {
        db.set_cipher(Database::Cipher::kAes);
      } else if (uuid == kKdbxCipherTwofish) {
        db.set_cipher(Database::Cipher::kTwofish);
      } else {
        throw FormatError("Unknown cipher in KDBX 4 database.");
      }
      break;
    }
    case Kdbx4HeaderField::kCompressionFlags: {
      auto comp_flags = consume<uint32_t>(field);
      if (comp_flags > static_cast<uint32_t>(kKdbxCompressionFlags::kCount))
        throw FormatError("Unknown compression method in KDBX.");
      db.set_compress(comp_flags == static_cast<uint32_t>(kKdbxCompressionFlags::kGzip));
      break;
    }
    case Kdbx4HeaderField::kMasterSeed:
      db.set_master_seed(consume<std::vector<uint8_t>>(field));
      break;
    case Kdbx4HeaderField::kEncryptionIv:
      if (header_field.size == 16) {
        db.set_init_vector(consume<std::array<uint8_t, 16>>(field));
      } else if (header_field.size == 12) {
        std::array<uint8_t, 16> iv{};
        field.read(reinterpret_cast<char*>(iv.data()), 12);
        if (!field)
          throw IoError("Read error.");
        db.set_init_vector(iv);
      } else {
        throw FormatError("Illegal initialization vector size in KDBX.");
      }
      break;
    case Kdbx4HeaderField::kKdfParameters:
      KdbxKdf::ParseParameters(field, db);
      break;
    default:
      throw FormatError("Illegal header field in KDBX.");
    }

    // The field stream transiently holds header material (KDF salt, seed).
    WipeStream(field);
  }
}

std::string KdbxHeader::Write3(const Database& db,
                               const std::array<uint8_t, 32>& content_start_bytes) {
  KdbxHeaderPrefix header{};
  header.signature0 = kSignature0;
  header.signature1 = kSignature1;
  header.version = kKdbxVersionCriticalMin;

  std::stringstream header_stream;
  conserve<KdbxHeaderPrefix>(header_stream, header);

  conserve<KdbxHeaderField>(header_stream, KdbxHeaderField(KdbxHeaderField::kCipherId, 16));
  conserve<std::array<uint8_t, 16>>(header_stream, kKdbxCipherAes);

  conserve<KdbxHeaderField>(header_stream, KdbxHeaderField(KdbxHeaderField::kCompressionFlags, 4));
  conserve<uint32_t>(header_stream,
                     db.compress() ? static_cast<uint32_t>(kKdbxCompressionFlags::kGzip) : 0);

  if (db.master_seed().size() > std::numeric_limits<decltype(KdbxHeaderField::size)>::max()) {
    assert(false);
    throw InternalError("Master seed size exceeds KDBX maximum.");
  }
  conserve<KdbxHeaderField>(header_stream,
                            KdbxHeaderField(KdbxHeaderField::kMasterSeed,
                                            static_cast<uint16_t>(db.master_seed().size())));
  if (!db.master_seed().empty())
    header_stream.write(reinterpret_cast<const char*>(db.master_seed().data()),
                        static_cast<std::streamsize>(db.master_seed().size()));

  conserve<KdbxHeaderField>(header_stream, KdbxHeaderField(KdbxHeaderField::kTransformSeed, 32));
  header_stream.write(reinterpret_cast<const char*>(db.transform_seed().data()),
                      static_cast<std::streamsize>(db.transform_seed().size()));

  conserve<KdbxHeaderField>(header_stream, KdbxHeaderField(KdbxHeaderField::kTransformRounds, 8));
  conserve<uint64_t>(header_stream, db.transform_rounds());

  conserve<KdbxHeaderField>(header_stream,
                            KdbxHeaderField(KdbxHeaderField::kExcryptionInitVec, 16));
  conserve<std::array<uint8_t, 16>>(header_stream, db.init_vector());

  conserve<KdbxHeaderField>(header_stream,
                            KdbxHeaderField(KdbxHeaderField::kInnerRandomStreamKey, 32));
  header_stream.write(reinterpret_cast<const char*>(db.inner_random_stream_key().data()), 32);

  conserve<KdbxHeaderField>(header_stream,
                            KdbxHeaderField(KdbxHeaderField::kContentStreamStartBytes, 32));
  conserve<std::array<uint8_t, 32>>(header_stream, content_start_bytes);

  conserve<KdbxHeaderField>(header_stream,
                            KdbxHeaderField(KdbxHeaderField::kInnerRandomStreamId, 4));
  conserve<uint32_t>(header_stream, static_cast<uint32_t>(kKdbxRandomStream::kSalsa20));

  conserve<KdbxHeaderField>(header_stream, KdbxHeaderField(KdbxHeaderField::kEndOfHeader, 0));

  std::string header_data = header_stream.str();

  // The header buffer transiently holds key material (master seed, transform
  // seed, inner random stream key).
  WipeStream(header_stream);

  return header_data;
}

std::string KdbxHeader::Write4(const Database& db, bool kdbx41) {
  KdbxHeaderPrefix header{};
  header.signature0 = kSignature0;
  header.signature1 = kSignature1;
  header.version = kdbx41 ? kKdbxVersion4_1 : kVersion4;

  std::stringstream header_stream;
  conserve<KdbxHeaderPrefix>(header_stream, header);

  conserve<Kdbx4HeaderField>(header_stream, Kdbx4HeaderField(Kdbx4HeaderField::kCipherId, 16));

  const std::array<uint8_t, 16>* cipher_id = &kKdbxCipherAes;
  if (db.cipher() == Database::Cipher::kChaCha20)
    cipher_id = &kKdbxCipherChaCha20;
  else if (db.cipher() == Database::Cipher::kTwofish)
    cipher_id = &kKdbxCipherTwofish;

  conserve<std::array<uint8_t, 16>>(header_stream, *cipher_id);

  conserve<Kdbx4HeaderField>(header_stream,
                             Kdbx4HeaderField(Kdbx4HeaderField::kCompressionFlags, 4));
  conserve<uint32_t>(header_stream,
                     db.compress() ? static_cast<uint32_t>(kKdbxCompressionFlags::kGzip) : 0);

  if (db.master_seed().size() > std::numeric_limits<decltype(Kdbx4HeaderField::size)>::max()) {
    assert(false);
    throw InternalError("Master seed size exceeds KDBX maximum.");
  }
  conserve<Kdbx4HeaderField>(header_stream,
                             Kdbx4HeaderField(Kdbx4HeaderField::kMasterSeed,
                                              static_cast<uint32_t>(db.master_seed().size())));
  if (!db.master_seed().empty())
    header_stream.write(reinterpret_cast<const char*>(db.master_seed().data()),
                        static_cast<std::streamsize>(db.master_seed().size()));

  // Serialize the KDF variant dictionary.
  std::stringstream kdf_stream;
  KdbxKdf::WriteParameters(kdf_stream, db);

  std::string kdf_data = kdf_stream.str();
  conserve<Kdbx4HeaderField>(
      header_stream,
      Kdbx4HeaderField(Kdbx4HeaderField::kKdfParameters, static_cast<uint32_t>(kdf_data.size())));
  std::copy(kdf_data.begin(), kdf_data.end(), std::ostreambuf_iterator<char>(header_stream));

  // The KDF serialization transiently holds the salt/seed material.
  WipeBuffer(&kdf_data);
  WipeStream(kdf_stream);

  conserve<Kdbx4HeaderField>(
      header_stream, Kdbx4HeaderField(Kdbx4HeaderField::kEncryptionIv,
                                      db.cipher() == Database::Cipher::kChaCha20 ? 12 : 16));
  if (db.cipher() == Database::Cipher::kChaCha20) {
    header_stream.write(reinterpret_cast<const char*>(db.init_vector().data()), 12);
  } else {
    conserve<std::array<uint8_t, 16>>(header_stream, db.init_vector());
  }

  conserve<Kdbx4HeaderField>(header_stream, Kdbx4HeaderField(Kdbx4HeaderField::kEndOfHeader, 0));

  std::string header_data = header_stream.str();

  // The header buffer transiently holds key material (master seed, KDF salt).
  WipeStream(header_stream);

  return header_data;
}

} // namespace keepass