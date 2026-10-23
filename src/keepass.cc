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

#include "libkeepass/detail/constants.hh"
#include "libkeepass/detail/format_codec.hh"
#include "libkeepass/detail/mapped_file.hh"
#include "libkeepass/exception.hh"
#ifdef LIBKEEPASS_WITH_KDBX
#include "libkeepass/kdbx_kdf.hh"
#endif
#include "libkeepass/metadata.hh"
#include "libkeepass/random.hh"

namespace keepass {

namespace {

using detail::kKdbSignature0;
using detail::kKdbSignature1;
using detail::kKdbxSignature0;
using detail::kKdbxSignature1;

} // namespace

KeePass::KeePass() = default;

KeePass::KeePass(const Key& key) : key_(key) {}

KeePass::KeePass(const std::string& password, const std::string& keyfile)
    : key_(password, keyfile) {}

std::unique_ptr<Database> KeePass::Open(const std::string& path) {
  // Map the file read-only instead of copying it through an ifstream buffer.
  // The importer only needs a seekable view for signature sniffing and the
  // header rewind, which the mapped stream buffer provides for free.
  try {
    detail::MappedFile file(path);
    if (!file.empty()) {
      detail::mapped_istreambuf buffer(file.data(), file.size());
      std::istream src(&buffer);
      return Open(src);
    }
  } catch (const FileNotFoundError&) {
    throw;
  } catch (const IoError&) {
    // Mapping can be unavailable (32-bit address space, restrictive
    // sandboxes, special files). Fall back to a regular buffered stream.
  }

  std::ifstream src(path, std::ios::in | std::ios::binary);
  if (!src.is_open())
    throw FileNotFoundError();
  return Open(src);
}

std::unique_ptr<Database> KeePass::Open(std::istream& src) {
  Format format = format_;

  if (format == Format::kAuto) {
    // Sniff only the 8-byte format signature; seekable streams are then
    // rewound and handed directly to the format importer without buffering
    // the whole input.
    uint32_t sig0 = 0;
    uint32_t sig1 = 0;
    src.read(reinterpret_cast<char*>(&sig0), sizeof(sig0));
    src.read(reinterpret_cast<char*>(&sig1), sizeof(sig1));
    if (!src.good())
      throw FormatError("Not a KeePass database.");

    if ((sig0 != kKdbSignature0 && sig0 != kKdbxSignature0) ||
        (sig1 != kKdbSignature1 && sig1 != kKdbxSignature1)) {
      throw FormatError("Not a KeePass database.");
    }

    // The KDB and KDBX formats share signature 0 and differ only in the
    // lowest byte of signature 1 (0x65 vs 0x67).
    format = sig1 == kKdbSignature1 ? Format::kKdb : Format::kKdbx4;

    src.clear();
    src.seekg(0, std::ios::beg);
    if (!src.fail())
      return Import(src, format);

    // Non-seekable stream: reconstruct the input in memory, prepending the
    // signature bytes that have already been consumed.
    src.clear();
    std::string data(reinterpret_cast<char*>(&sig0), sizeof(sig0));
    data.append(reinterpret_cast<char*>(&sig1), sizeof(sig1));
    data.append(std::istreambuf_iterator<char>(src), std::istreambuf_iterator<char>());
    std::istringstream stream(data);
    return Import(stream, format);
  }

  // An explicitly selected format needs no signature sniffing; rewind
  // seekable streams and fall back to buffering the whole input otherwise.
  src.clear();
  src.seekg(0, std::ios::beg);
  if (!src.fail())
    return Import(src, format);

  src.clear();
  std::string data((std::istreambuf_iterator<char>(src)), std::istreambuf_iterator<char>());
  std::istringstream stream(data);
  return Import(stream, format);
}

std::unique_ptr<Database> KeePass::Open(const uint8_t* data, std::size_t size) {
  if (data == nullptr && size != 0)
    throw FormatError("Not a KeePass database.");

  const std::string bytes(reinterpret_cast<const char*>(data), size);
  std::istringstream src(bytes);
  return Open(src);
}

std::unique_ptr<Database> KeePass::Import(std::istream& src, Format format) {
  if (format == Format::kAuto)
    throw FormatError("Unknown KeePass database format.");
  detail::FormatCodecOptions options;
  return detail::FormatCodecRegistry::Instance()
      .Create(static_cast<int>(format), options)
      ->Import(src, key_);
}

void KeePass::Save(const std::string& path, const Database& db) {
  std::ofstream dst(path, std::ios::out | std::ios::binary);
  if (!dst.is_open())
    throw IoError("Unable to open database for writing.");

  Save(dst, db, ResolveOutputFormat(path, db));
}

KeePass::Format KeePass::ResolveStreamFormat(const Database& db) const {
  if (format_ != Format::kAuto)
    return format_;

  // KDBX 3 only supports AES + AES-KDF; everything else needs KDBX 4.
  if (db.kdf() != Database::Kdf::kAes || db.cipher() != Database::Cipher::kAes)
    return Format::kKdbx4;
  return Format::kKdbx3;
}

void KeePass::Save(std::ostream& dst, const Database& db) {
  SaveWithOptions(dst, db, key_, ResolveStreamFormat(db), true);
}

void KeePass::Save(std::ostream& dst, const Database& db, const Key& key) {
  // An explicitly supplied key must take precedence over a transformed key
  // cached on the database (for example after Create or Import); otherwise
  // SaveAs would silently keep encrypting with the old key.
  SaveWithOptions(dst, db, key, ResolveStreamFormat(db), false);
}

void KeePass::Save(std::ostream& dst, const Database& db, Format format) {
  SaveWithOptions(dst, db, key_, format, true);
}

void KeePass::SaveWithOptions(std::ostream& dst, const Database& db, const Key& key, Format format,
                              bool use_cached_key) {
  if (format == Format::kAuto)
    throw UnsupportedFeatureError("Unsupported output format.");

  detail::FormatCodecOptions options;
  options.write_kdbx4 = format == Format::kKdbx4;
  options.use_cached_key = use_cached_key;
  detail::FormatCodecRegistry::Instance()
      .Create(static_cast<int>(format), options)
      ->Export(dst, db, key);
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
  std::ofstream dst(path, std::ios::out | std::ios::binary);
  if (!dst.is_open())
    throw IoError("Unable to open database for writing.");

  SaveAs(dst, db, new_key);
}

void KeePass::SaveAs(std::ostream& dst, const Database& db, const Key& new_key) {
  Save(dst, db, new_key);
}

void KeePass::SaveAs(const std::string& path, const Database& db, const std::string& password,
                     const std::string& keyfile) {
  SaveAs(path, db, Key(password, keyfile));
}

void KeePass::SaveAs(std::ostream& dst, const Database& db, const std::string& password,
                     const std::string& keyfile) {
  Save(dst, db, Key(password, keyfile));
}

std::unique_ptr<Database> KeePass::Create(const std::string& password, Format format,
                                          Database::Cipher cipher, Database::Kdf kdf) {
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

  // Pre-derive and cache the transformed key so that a subsequent KDBX Save
  // can use the password supplied here even when the KeePass instance doing
  // the save was constructed without a key. KDB (1.x) export nevertheless
  // requires an explicit key because the legacy format derives its key
  // differently.
#ifdef LIBKEEPASS_WITH_KDBX
  if (!password.empty() && format != Format::kKdb) {
    const Key key(password);
    db->set_transformed_key(KdbxKdf::Transform(key, *db, Key::SubKeyResolution::kHashSubKeys));
  }
#endif

  return db;
}

} // namespace keepass