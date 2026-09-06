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

#include "libkeepass/keepass.hh"

#include <cctype>
#include <cstdint>
#include <fstream>
#include <sstream>

#include "libkeepass/exception.hh"
#include "libkeepass/kdb.hh"
#include "libkeepass/metadata.hh"
#include "libkeepass/random.hh"

namespace keepass {

namespace {

constexpr uint32_t kKdbSignature0 = 0x9aa2d903;
constexpr uint32_t kKdbSignature1 = 0xb54bfb65;
constexpr uint32_t kKdbxSignature0 = 0x9aa2d903;
constexpr uint32_t kKdbxSignature1 = 0xb54bfb67;

} // namespace

KeePass::KeePass() = default;

KeePass::KeePass(const Key& key) : key_(key) {}

KeePass::KeePass(const std::string& password, const std::string& keyfile)
    : key_(password, keyfile) {}

std::unique_ptr<Database> KeePass::Open(const std::string& path) {
  std::ifstream src(path, std::ios::in | std::ios::binary);
  if (!src.is_open())
    throw FileNotFoundError();

  return Open(src);
}

std::unique_ptr<Database> KeePass::Open(std::istream& src) {
  // Buffer the input so that the format signature can be inspected even if the
  // stream is not seekable.
  std::string data((std::istreambuf_iterator<char>(src)), std::istreambuf_iterator<char>());
  std::istringstream stream(data);

  Format format = format_;
  if (format == Format::kAuto) {
    uint32_t sig0 = 0;
    uint32_t sig1 = 0;
    stream.read(reinterpret_cast<char*>(&sig0), sizeof(sig0));
    stream.read(reinterpret_cast<char*>(&sig1), sizeof(sig1));
    if (!stream.good())
      throw FormatError("Not a KeePass database.");

    if ((sig0 != kKdbSignature0 && sig0 != kKdbxSignature0) ||
        (sig1 != kKdbSignature1 && sig1 != kKdbxSignature1)) {
      throw FormatError("Not a KeePass database.");
    }

    // The KDB and KDBX formats share signature 0 and differ only in the
    // lowest byte of signature 1 (0x65 vs 0x67).
    format = sig1 == kKdbSignature1 ? Format::kKdb : Format::kKdbx4;

    stream.clear();
    stream.seekg(0, std::ios::beg);
  }

  switch (format) {
  case Format::kKdb:
    return KdbFile::Import(stream, key_);
  case Format::kKdbx3:
  case Format::kKdbx4:
    return kdbx_file_.Import(stream, key_);
  default:
    throw FormatError("Unknown KeePass database format.");
  }
}

void KeePass::Save(const std::string& path, const Database& db) {
  std::ofstream dst(path, std::ios::out | std::ios::binary);
  if (!dst.is_open())
    throw IoError("Unable to open database for writing.");

  Save(dst, db, ResolveOutputFormat(path, db));
}

void KeePass::Save(std::ostream& dst, const Database& db) {
  if (format_ != Format::kAuto) {
    Save(dst, db, format_);
    return;
  }

  if (db.kdf() != Database::Kdf::kAes || db.cipher() != Database::Cipher::kAes) {
    Save(dst, db, Format::kKdbx4);
  } else {
    Save(dst, db, Format::kKdbx3);
  }
}

void KeePass::Save(std::ostream& dst, const Database& db, Format format) {
  switch (format) {
  case Format::kKdb:
    KdbFile::Export(dst, db, key_);
    break;
  case Format::kKdbx3:
    kdbx_file_.set_write_kdbx4(false);
    kdbx_file_.Export(dst, db, key_);
    break;
  case Format::kKdbx4:
    kdbx_file_.set_write_kdbx4(true);
    kdbx_file_.Export(dst, db, key_);
    break;
  default:
    throw FormatError("Unsupported output format.");
  }
}

KeePass::Format KeePass::ResolveOutputFormat(const std::string& path, const Database& db) const {
  if (format_ != Format::kAuto)
    return format_;

  std::string ext;
  std::string::size_type pos = path.rfind('.');
  if (pos != std::string::npos && pos + 1 < path.size())
    ext = path.substr(pos + 1);

  for (auto& c : ext)
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

  if (ext == "kdb")
    return Format::kKdb;

  // KDBX 3 only supports the AES cipher with the AES-KDF.
  if (db.kdf() != Database::Kdf::kAes || db.cipher() != Database::Cipher::kAes)
    return Format::kKdbx4;
  return Format::kKdbx3;
}

void KeePass::SaveAs(const std::string& path, const Database& db, const Key& new_key) {
  Key old_key = key_;
  key_ = new_key;
  try {
    Save(path, db);
  } catch (...) {
    key_ = old_key;
    throw;
  }
  key_ = old_key;
}

void KeePass::SaveAs(const std::string& path, const Database& db, const std::string& password,
                     const std::string& keyfile) {
  SaveAs(path, db, Key(password, keyfile));
}

std::unique_ptr<Database> KeePass::Create(const std::string& password, Format format,
                                          Database::Cipher cipher, Database::Kdf kdf) {
  (void)password;
  (void)format;

  std::unique_ptr<Database> db(new Database());
  db->set_meta(std::make_shared<Metadata>());
  db->set_cipher(cipher);
  db->set_kdf(kdf);
  db->set_compress(true);

  if (kdf == Database::Kdf::kArgon2d || kdf == Database::Kdf::kArgon2id) {
    std::array<uint8_t, 32> salt = random_array<32>();
    db->set_argon2_salt(std::vector<uint8_t>(salt.begin(), salt.end()));
    db->set_argon2_iterations(10);
    db->set_argon2_memory(64ULL * 1024 * 1024);
    db->set_argon2_parallelism(2);
    db->set_argon2_version(0x13);
  } else {
    db->set_transform_rounds(600000);
  }

  db->set_master_seed(random_array<16>());
  db->set_transform_seed(random_array<32>());
  db->set_init_vector(random_array<16>());
  db->set_inner_random_stream_key(random_array<32>());

  db->set_root(std::make_shared<Group>());
  return db;
}

} // namespace keepass