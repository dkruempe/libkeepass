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

#include "include/libkeepass/kdbx.hh"

#include <algorithm>
#include <cassert>
#include <cstring>
#include <fstream>
#ifdef DEBUG
#include <iostream>
#endif

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <pugixml.hpp>

#include "libkeepass/base64.hh"
#include "libkeepass/cipher.hh"
#include "libkeepass/exception.hh"
#include "libkeepass/format.hh"
#include "libkeepass/icon.hh"
#include "libkeepass/io.hh"
#include "libkeepass/iterator.hh"
#include "libkeepass/key.hh"
#include "libkeepass/metadata.hh"
#include "libkeepass/random.hh"
#include "libkeepass/security.hh"
#include "libkeepass/stream.hh"
#include "libkeepass/variantdictionary.hh"

namespace keepass {

constexpr uint32_t kKdbxSignature0 = 0x9aa2d903;
constexpr uint32_t kKdbxSignature1 = 0xb54bfb67;
constexpr uint32_t kKdbxVersionCriticalMask = 0xffff0000;
constexpr uint32_t kKdbxVersion3 = 0x00030000;
constexpr uint32_t kKdbxVersionCriticalMin = 0x00030001;
constexpr uint32_t kKdbxVersion4 = 0x00040000;

constexpr std::array<uint8_t, 16> kKdbxCipherAes = {
    {0x31, 0xc1, 0xf2, 0xe6, 0xbf, 0x71, 0x43, 0x50, 0xbe, 0x58, 0x05, 0x21,
     0x6a, 0xfc, 0x5a, 0xff}};

constexpr std::array<uint8_t, 16> kKdbxCipherChaCha20 = {
    {0xd6, 0x03, 0x8a, 0x2b, 0x8b, 0x6f, 0x4c, 0xb5, 0xa5, 0x24, 0x33, 0x9a,
     0x31, 0xdb, 0xb5, 0x9a}};

constexpr std::array<uint8_t, 16> kKdbxCipherTwofish = {
    {0xad, 0x68, 0xf2, 0x9f, 0x57, 0x6f, 0x4b, 0xb9, 0xa3, 0x6a, 0xd4, 0x7a,
     0xf9, 0x65, 0x34, 0x6c}};

constexpr std::array<uint8_t, 16> kKdbxKdfAesKdbx4 = {
    {0x7c, 0x02, 0xbb, 0x82, 0x79, 0xa7, 0x4a, 0xc0, 0x92, 0x7d, 0x11, 0x4a,
     0x00, 0x64, 0x82, 0x38}};
[[maybe_unused]] constexpr std::array<uint8_t, 16> kKdbxKdfAesKdbx3 = {
    {0xc9, 0xd9, 0xf3, 0x9a, 0x62, 0x8a, 0x44, 0x60, 0xbf, 0x74, 0x0d, 0x08,
     0xc1, 0x8a, 0x4f, 0xea}};
constexpr std::array<uint8_t, 16> kKdbxKdfArgon2d = {
    {0xef, 0x63, 0x6d, 0xdf, 0x8c, 0x29, 0x44, 0x4b, 0x91, 0xf7, 0xa9, 0xa4,
     0x03, 0xe3, 0x0a, 0x0c}};
constexpr std::array<uint8_t, 16> kKdbxKdfArgon2id = {
    {0x9e, 0x29, 0x8b, 0x19, 0x56, 0xdb, 0x47, 0x73, 0xb2, 0x3d, 0xfc, 0x3e,
     0xc6, 0xf0, 0xa1, 0xe6}};

constexpr std::array<uint8_t, 8> kKdbxInnerRandomStreamInitVec = {
    0xe8, 0x30, 0x09, 0x4b, 0x97, 0x20, 0x5d, 0x2a};

/** Seconds between 0001-01-01 and the Unix epoch (1970-01-01). */
constexpr int64_t kKdbxEpochBias = 62135596800LL;

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
struct KdbxHeader {
  uint32_t signature0;
  uint32_t signature1;
  uint32_t version;
};
static_assert(sizeof(KdbxHeader) == 12, "bad packing of header structure.");

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
  KdbxHeaderField(KdbxHeaderField &&other) noexcept {
    id = other.id;
    size = other.size;
  }
};
static_assert(sizeof(KdbxHeaderField) == 3,
              "bad packing of bitfield header structure.");

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
  Kdbx4HeaderField(Id new_id, uint32_t new_size)
      : id(new_id), size(new_size) {}
  Kdbx4HeaderField(Kdbx4HeaderField &&other) noexcept {
    id = other.id;
    size = other.size;
  }
};
static_assert(sizeof(Kdbx4HeaderField) == 5,
              "bad packing of header structure.");

enum class kKdbxInnerHeader : uint8_t {
  kEnd = 0,
  kInnerRandomStreamId = 1,
  kInnerRandomStreamKey = 2,
  kBinaries = 3
};
#pragma pack(pop)

void KdbxFile::Reset() {
  binary_pool_.clear();
  icon_pool_.clear();
  group_pool_.clear();
  header_hash_ = {0};
}

std::shared_ptr<Group> KdbxFile::GetGroup(const std::string &uuid_str) {
  if (uuid_str.empty())
    return nullptr;

  auto it = group_pool_.find(uuid_str);
  if (it != group_pool_.end())
    return it->second;

  std::array<uint8_t, 16> uuid{};
  base64_decode<bounds_checked_iterator<std::array<uint8_t, 16>>,
                unsigned char>(uuid_str, bounds_checked(uuid));

  std::shared_ptr<Group> group = std::make_shared<Group>();
  group->set_uuid(uuid);

  group_pool_.insert(std::make_pair(uuid_str, group));
  return group;
}

int64_t KdbxFile::NeverSeconds() const {
  // The KDBX "never" marker is the fixed timestamp 2999-12-28T22:59:59Z.
  static const int64_t kNeverSeconds = []() {
    std::tm tm{};
    strptime("2999-12-28T22:59:59Z", "%Y-%m-%dT%H:%M:%S", &tm);
    return timegm(&tm) + kKdbxEpochBias;
  }();

  return kNeverSeconds;
}

std::time_t KdbxFile::ParseDateTime(const char *text) {
  std::string str(text);

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
  char *res = strptime(text, "%Y-%m-%dT%H:%M:%S", &tm);
  if (res == nullptr) {
    assert(false);
    return 0;
  }

  // Format is expected to always be in UTC.
  assert(*res == 'Z' || *res == '\0');

  return timegm(&tm);
}

std::string KdbxFile::WriteDateTime(std::time_t time) {
  if (kdbx4_) {
    int64_t secs =
        time == 0 ? NeverSeconds() : static_cast<int64_t>(time) + kKdbxEpochBias;

    uint8_t bytes[8];
    uint64_t val = static_cast<uint64_t>(secs);
    for (std::size_t i = 0; i < 8; ++i) {
      bytes[i] = static_cast<uint8_t>(val & 0xff);
      val >>= 8;
    }

    return base64_encode(bytes, bytes + 8);
  }

  if (time == 0)
    return "2999-12-28T22:59:59Z";

  char buffer[128];
  std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ",
                std::gmtime(&time));
  return buffer;
}

protect<std::string>
KdbxFile::ParseProtectedString(const pugi::xml_node &node, const char *name,
                               RandomObfuscator &obfuscator) {
  pugi::xml_node val_node = node.child(name);
  if (val_node) {
    bool prot = val_node.attribute("Protected").as_bool();
    if (prot) {
      std::string val = base64_decode(val_node.text().as_string());
      if (!val.empty())
        return {obfuscator.Process(val), true};
    }

    return {val_node.text().as_string(),
            prot || val_node.attribute("ProtectedInMemory").as_bool()};
  }

  return {std::string(), false};
}

void KdbxFile::WriteProtectedString(pugi::xml_node &node,
                                    const protect<std::string> &str,
                                    RandomObfuscator &obfuscator) {
  if (str.is_protected()) {
    node.append_attribute("Protected").set_value("True");
    node.text().set(base64_encode(obfuscator.Process(*str)).c_str());
  } else {
    node.text().set(str->c_str());
  }
}

std::shared_ptr<Metadata> KdbxFile::ParseMeta(const pugi::xml_node &meta_node,
                                              RandomObfuscator &obfuscator) {
  std::shared_ptr<Metadata> meta = std::make_shared<Metadata>();

  // Parse header hash and store in member for checking later.
  base64_decode<bounds_checked_iterator<std::array<uint8_t, 32>>,
                unsigned char>(meta_node.child_value("HeaderHash"),
                               bounds_checked(header_hash_));

  meta->set_generator(meta_node.child_value("Generator"));
  meta->set_database_name(temporal<std::string>(
      meta_node.child_value("DatabaseName"),
      ParseDateTime(meta_node.child_value("DatabaseNameChanged"))));
  meta->set_database_desc(temporal<std::string>(
      meta_node.child_value("DatabaseDescription"),
      ParseDateTime(meta_node.child_value("DatabaseDescriptionChanged"))));
  meta->set_default_username(temporal<std::string>(
      meta_node.child_value("DefaultUserName"),
      ParseDateTime(meta_node.child_value("DefaultUserNameChanged"))));
  meta->set_maintenance_hist_days(
      meta_node.child("MaintenanceHistoryDays").text().as_uint(365));
  meta->set_database_color(meta_node.child_value("Color"));
  meta->set_master_key_changed(
      ParseDateTime(meta_node.child_value("MasterKeyChanged")));
  meta->set_master_key_change_rec(
      meta_node.child("MasterKeyChangeRec").text().as_llong(-1));
  meta->set_master_key_change_force(
      meta_node.child("MasterKeyChangeForce").text().as_llong(-1));

  pugi::xml_node mp_node = meta_node.child("MemoryProtection");
  meta->memory_protection().set_title(
      mp_node.child("ProtectTitle").text().as_bool());
  meta->memory_protection().set_username(
      mp_node.child("ProtectUserName").text().as_bool());
  meta->memory_protection().set_password(
      mp_node.child("ProtectPassword").text().as_bool(true));
  meta->memory_protection().set_url(
      mp_node.child("ProtectURL").text().as_bool());
  meta->memory_protection().set_notes(
      mp_node.child("ProtectNotes").text().as_bool());

  if (meta_node.child("RecycleBinEnabled").text().as_bool(true))
    meta->set_recycle_bin(GetGroup(meta_node.child_value("RecycleBinUUID")));
  else
    meta->set_recycle_bin(std::shared_ptr<Group>());
  meta->set_recycle_bin_changed(
      ParseDateTime(meta_node.child_value("RecycleBinChanged")));

  meta->set_entry_templates(
      GetGroup(meta_node.child_value("EntryTemplatesGroup")));
  meta->set_entry_templates_changed(
      ParseDateTime(meta_node.child_value("EntryTemplatesGroupChanged")));

  meta->set_history_max_items(
      meta_node.child("HistoryMaxItems").text().as_int(-1));
  meta->set_history_max_size(
      meta_node.child("HistoryMaxSize").text().as_llong(-1));

  // Note that we're not parsing "LastSelectedGroup" and "LastTopVisibleGroup"
  // here. They will be parsed later by ParseXml(). The reason is that we need
  // to parse all groups first.

  pugi::xml_node icons_node = meta_node.child("CustomIcons");
  if (icons_node) {
    for (pugi::xml_node icon_node = icons_node.child("Icon"); icon_node;
         icon_node = icon_node.next_sibling("Icon")) {
      std::vector<uint8_t> data;
      base64_decode<std::back_insert_iterator<std::vector<uint8_t>>,
                    unsigned char>(icon_node.child_value("Data"),
                                   std::back_inserter(data));
      if (data.empty())
        continue;

      std::array<uint8_t, 16> uuid{};
      base64_decode<bounds_checked_iterator<std::array<uint8_t, 16>>,
                    unsigned char>(icon_node.child_value("UUID"),
                                   bounds_checked(uuid));

      std::shared_ptr<Icon> icon = std::make_shared<Icon>(uuid, data);
      meta->AddIcon(icon);

      icon_pool_.insert(std::make_pair(icon_node.child_value("UUID"), icon));
    }
  }

  pugi::xml_node bins_node = meta_node.child("Binaries");
  if (bins_node) {
    for (pugi::xml_node bin_node = bins_node.child("Binary"); bin_node;
         bin_node = bin_node.next_sibling("Binary")) {
      std::string id = bin_node.attribute("ID").value();

      protect<std::string> data;

      bool compressed = false;
      if (bin_node.attribute("Protected").as_bool()) {
        data = protect<std::string>(
            obfuscator.Process(base64_decode(bin_node.text().as_string())),
            true);
      } else {
        if (bin_node.attribute("Compressed").as_bool()) {
          compressed = true;
          std::stringstream raw_stream(
              base64_decode(bin_node.text().as_string()));
          gzip_istreambuf gzip_streambuf(raw_stream);
          std::istream gzip_stream(&gzip_streambuf);

          data = protect<std::string>(
              consume<std::string>(gzip_stream),
              bin_node.attribute("ProtectedInMemory").as_bool());
        } else {
          data = protect<std::string>(
              base64_decode(bin_node.text().as_string()),
              bin_node.attribute("ProtectedInMemory").as_bool());
        }
      }

      std::shared_ptr<Binary> binary = std::make_shared<Binary>(data);
      binary->set_compress(compressed);
      meta->AddBinary(binary);

      binary_pool_.insert(std::make_pair(id, binary));
    }
  }

  pugi::xml_node data_node = meta_node.child("CustomData");
  if (data_node) {
    for (pugi::xml_node item_node = data_node.child("Item"); item_node;
         item_node = item_node.next_sibling("Item")) {
      std::string key = item_node.child_value("Key");
      std::string value = item_node.child_value("Value");
      if (key.empty()) {
        assert(false);
        continue;
      }

      meta->AddField(key, value);
    }
  }

  return meta;
}

void KdbxFile::WriteMeta(pugi::xml_node &meta_node,
                         RandomObfuscator &obfuscator,
                         const std::shared_ptr<Metadata> &meta) {
  // In KDBX 4 the header hash is stored in the KDBX header instead of in the
  // XML document.
  if (!kdbx4_) {
    meta_node.append_child("HeaderHash")
        .text()
        .set(base64_encode(header_hash_.begin(), header_hash_.end()).c_str());
  }
  meta_node.append_child("Generator").text().set(meta->generator().c_str());
  meta_node.append_child("DatabaseName")
      .text()
      .set(meta->database_name()->c_str());
  meta_node.append_child("DatabaseNameChanged")
      .text()
      .set(WriteDateTime(meta->database_name().time()).c_str());
  meta_node.append_child("DatabaseDescription")
      .text()
      .set(meta->database_desc()->c_str());
  meta_node.append_child("DatabaseDescriptionChanged")
      .text()
      .set(WriteDateTime(meta->database_desc().time()).c_str());
  meta_node.append_child("DefaultUserName")
      .text()
      .set(meta->default_username()->c_str());
  meta_node.append_child("DefaultUserNameChanged")
      .text()
      .set(WriteDateTime(meta->default_username().time()).c_str());
  meta_node.append_child("MaintenanceHistoryDays")
      .text()
      .set(meta->maintenance_hist_days());
  meta_node.append_child("Color").text().set(meta->database_color().c_str());
  meta_node.append_child("MasterKeyChanged")
      .text()
      .set(WriteDateTime(meta->master_key_changed()).c_str());
  meta_node.append_child("MasterKeyChangeRec")
      .text()
      .set(static_cast<long long>(meta->master_key_change_rec()));
  meta_node.append_child("MasterKeyChangeForce")
      .text()
      .set(static_cast<long long>(meta->master_key_change_force()));

  pugi::xml_node mp_node = meta_node.append_child("MemoryProtection");
  mp_node.append_child("ProtectTitle")
      .text()
      .set(meta->memory_protection().title());
  mp_node.append_child("ProtectUserName")
      .text()
      .set(meta->memory_protection().username());
  mp_node.append_child("ProtectPassword")
      .text()
      .set(meta->memory_protection().password());
  mp_node.append_child("ProtectURL")
      .text()
      .set(meta->memory_protection().url());
  mp_node.append_child("ProtectNotes")
      .text()
      .set(meta->memory_protection().notes());

  if (meta->recycle_bin()) {
    meta_node.append_child("RecycleBinEnabled").text().set(true);
    meta_node.append_child("RecycleBinUUID")
        .text()
        .set(base64_encode(meta->recycle_bin()->uuid().begin(),
                           meta->recycle_bin()->uuid().end())
                 .c_str());
  } else {
    meta_node.append_child("RecycleBinEnabled").text().set(false);
  }
  meta_node.append_child("RecycleBinChanged")
      .text()
      .set(WriteDateTime(meta->recycle_bin_changed()).c_str());

  if (meta->entry_templates()) {
    meta_node.append_child("EntryTemplatesGroup")
        .text()
        .set(base64_encode(meta->entry_templates()->uuid().begin(),
                           meta->entry_templates()->uuid().end())
                 .c_str());
  }
  meta_node.append_child("EntryTemplatesGroupChanged")
      .text()
      .set(WriteDateTime(meta->entry_templates_changed()).c_str());

  meta_node.append_child("HistoryMaxItems")
      .text()
      .set(meta->history_max_items());
  meta_node.append_child("HistoryMaxSize")
      .text()
      .set(static_cast<long long>(meta->history_max_size()));

  if (auto group = meta->last_selected_group().lock()) {
    meta_node.append_child("LastSelectedGroup")
        .text()
        .set(base64_encode(group->uuid().begin(), group->uuid().end()).c_str());
  }

  if (auto group = meta->last_visible_group().lock()) {
    meta_node.append_child("LastTopVisibleGroup")
        .text()
        .set(base64_encode(group->uuid().begin(), group->uuid().end()).c_str());
  }

  pugi::xml_node icons_node = meta_node.append_child("CustomIcons");
  for (const auto &icon : meta->icons()) {
    pugi::xml_node icon_node = icons_node.append_child("Icon");
    icon_node.append_child("UUID").text().set(
        base64_encode(icon->uuid().begin(), icon->uuid().end()).c_str());
    icon_node.append_child("Data").text().set(
        base64_encode(icon->data().begin(), icon->data().end()).c_str());
  }

  // In KDBX 4 the binary attachments are stored in the KDBX inner header
  // instead of in the XML document. Their pool is filled by Export4().
  if (!kdbx4_) {
    uint32_t binary_id = 0;
    pugi::xml_node bins_node = meta_node.append_child("Binaries");
    for (const auto &binary : meta->binaries()) {
      pugi::xml_node bin_node = bins_node.append_child("Binary");
      bin_node.append_attribute("ID").set_value(binary_id);

      if (binary->data().is_protected()) {
        bin_node.append_attribute("Protected").set_value("True");
        bin_node.text().set(
            base64_encode(obfuscator.Process(*binary->data())).c_str());
      } else {
        if (binary->compress()) {
          bin_node.append_attribute("Compressed").set_value("True");
          std::stringstream compressed_data;

          gzip_ostreambuf gzip_streambuf(compressed_data);
          std::ostream gzip_stream(&gzip_streambuf);
          std::copy(binary->data()->begin(), binary->data()->end(),
                    std::ostreambuf_iterator<char>(gzip_stream));
          gzip_stream.flush();

          bin_node.text().set(
              base64_encode(std::istreambuf_iterator<char>(compressed_data),
                            std::istreambuf_iterator<char>())
                  .c_str());
        } else {
          bin_node.text().set(base64_encode(*binary->data()).c_str());
        }
      }

      binary_pool_.insert(std::make_pair(std::to_string(binary_id), binary));

      ++binary_id;
    }
  }

  pugi::xml_node data_node = meta_node.append_child("CustomData");
  for (const auto &field : meta->fields()) {
    pugi::xml_node item_node = data_node.append_child("Item");
    item_node.append_child("Key").text().set(field.key().c_str());
    item_node.append_child("Value").text().set(field.value().c_str());
  }
}

std::shared_ptr<Entry> KdbxFile::ParseEntry(const pugi::xml_node &entry_node,
                                            std::array<uint8_t, 16> &entry_uuid,
                                            RandomObfuscator &obfuscator) {
  std::shared_ptr<Entry> entry = std::make_shared<Entry>();

  base64_decode<bounds_checked_iterator<std::array<uint8_t, 16>>,
                unsigned char>(entry_node.child_value("UUID"),
                               bounds_checked(entry_uuid));

  entry->set_uuid(entry_uuid);
  entry->set_icon(entry_node.child("IconID").text().as_uint());
  entry->set_fg_color(entry_node.child_value("ForegroundColor"));
  entry->set_bg_color(entry_node.child_value("BackgroundColor"));
  entry->set_override_url(entry_node.child_value("OverrideURL"));
  entry->set_tags(entry_node.child_value("Tags"));

  if (entry_node.child("CustomIconUUID")) {
    auto it = icon_pool_.find(entry_node.child_value("CustomIconUUID"));
    if (it != icon_pool_.end()) {
      entry->set_custom_icon(it->second);
    } else {
      assert(false);
    }
  }

  pugi::xml_node times_node = entry_node.child("Times");
  if (times_node) {
    entry->set_creation_time(
        ParseDateTime(times_node.child_value("CreationTime")));
    entry->set_modification_time(
        ParseDateTime(times_node.child_value("LastModificationTime")));
    entry->set_access_time(
        ParseDateTime(times_node.child_value("LastAccessTime")));
    entry->set_expiry_time(ParseDateTime(times_node.child_value("ExpiryTime")));
    entry->set_move_time(
        ParseDateTime(times_node.child_value("LocationChanged")));
    entry->set_expires(times_node.child("Expires").text().as_bool());
    entry->set_usage_count(times_node.child("UsageCount").text().as_uint());
  }

  // Auto type.
  pugi::xml_node autotype_node = entry_node.child("AutoType");
  if (autotype_node) {
    entry->auto_type().set_enabled(
        autotype_node.child("Enabled").text().as_bool());
    entry->auto_type().set_obfuscation(
        autotype_node.child("DataTransferObfuscation").text().as_uint());
    entry->auto_type().set_sequence(
        autotype_node.child_value("DefaultSequence"));

    for (pugi::xml_node ass_node = autotype_node.child("Association"); ass_node;
         ass_node = ass_node.next_sibling("Association")) {
      entry->auto_type().AddAssociation(
          ass_node.child_value("Window"),
          ass_node.child_value("KeystrokeSequence"));
    }
  }

  // Read string fields.
  for (pugi::xml_node str_node = entry_node.child("String"); str_node;
       str_node = str_node.next_sibling("String")) {
    std::string key = str_node.child_value("Key");
    protect<std::string> val =
        ParseProtectedString(str_node, "Value", obfuscator);

    if (key == "Title") {
      entry->set_title(val);
    } else if (key == "URL") {
      entry->set_url(val);
    } else if (key == "UserName") {
      entry->set_username(val);
    } else if (key == "Password") {
      entry->set_password(val);
    } else if (key == "Notes") {
      entry->set_notes(val);
    } else {
      entry->AddCustomField(key, val);
    }
  }

  // Read binary fields.
  for (pugi::xml_node bin_node = entry_node.child("Binary"); bin_node;
       bin_node = bin_node.next_sibling("Binary")) {
    std::string key = bin_node.child_value("Key");
    std::shared_ptr<Binary> binary;

    pugi::xml_node val_node = bin_node.child("Value");
    if (val_node) {
      pugi::xml_attribute ref_attr = val_node.attribute("Ref");
      if (ref_attr) {
        auto it = binary_pool_.find(ref_attr.value());
        if (it == binary_pool_.end()) {
          throw FormatError(
              "Entry attachment refers to non-existing binary data.");
        }

        binary = it->second;
      } else {
        protect<std::string> prot_val;

        if (bin_node.attribute("Protected").as_bool()) {
          prot_val = protect<std::string>(
              obfuscator.Process(base64_decode(bin_node.text().as_string())),
              true);
        } else {
          if (bin_node.attribute("Compressed").as_bool()) {
            std::stringstream raw_stream(
                base64_decode(bin_node.text().as_string()));
            gzip_istreambuf gzip_streambuf(raw_stream);
            std::istream gzip_stream(&gzip_streambuf);

            prot_val = protect<std::string>(
                consume<std::string>(gzip_stream),
                bin_node.attribute("ProtectedInMemory").as_bool());
          } else {
            prot_val = protect<std::string>(
                base64_decode(bin_node.text().as_string()),
                bin_node.attribute("ProtectedInMemory").as_bool());
          }
        }

        binary = std::make_shared<Binary>(prot_val);
      }
    }

    std::shared_ptr<Entry::Attachment> attachment =
        std::make_shared<Entry::Attachment>();
    attachment->set_name(key);
    attachment->set_binary(binary);

    entry->AddAttachment(attachment);
  }

  // Read history entries.
  pugi::xml_node history_node = entry_node.child("History");
  if (history_node) {
    for (pugi::xml_node subentry_node = history_node.child("Entry");
         subentry_node; subentry_node = subentry_node.next_sibling("Entry")) {
      std::array<uint8_t, 16> subentry_uuid = {0};
      entry->AddHistoryEntry(
          ParseEntry(subentry_node, subentry_uuid, obfuscator));
    }
  }

  return entry;
}

void KdbxFile::WriteEntry(pugi::xml_node &entry_node,
                          RandomObfuscator &obfuscator,
                          const std::shared_ptr<Entry> &entry) {
  entry_node.append_child("UUID").text().set(
      base64_encode(entry->uuid().begin(), entry->uuid().end()).c_str());
  entry_node.append_child("IconID").text().set(entry->icon());
  entry_node.append_child("ForegroundColor")
      .text()
      .set(entry->fg_color().c_str());
  entry_node.append_child("BackgroundColor")
      .text()
      .set(entry->bg_color().c_str());
  entry_node.append_child("OverrideURL")
      .text()
      .set(entry->override_url().c_str());
  entry_node.append_child("Tags").text().set(entry->tags().c_str());

  if (auto icon = entry->custom_icon().lock()) {
    entry_node.append_child("CustomIconUUID")
        .text()
        .set(base64_encode(icon->uuid().begin(), icon->uuid().end()).c_str());
  }

  pugi::xml_node times_node = entry_node.append_child("Times");
  times_node.append_child("CreationTime")
      .text()
      .set(WriteDateTime(entry->creation_time()).c_str());
  times_node.append_child("LastModificationTime")
      .text()
      .set(WriteDateTime(entry->modification_time()).c_str());
  times_node.append_child("LastAccessTime")
      .text()
      .set(WriteDateTime(entry->access_time()).c_str());
  times_node.append_child("ExpiryTime")
      .text()
      .set(WriteDateTime(entry->expiry_time()).c_str());
  times_node.append_child("LocationChanged")
      .text()
      .set(WriteDateTime(entry->move_time()).c_str());
  times_node.append_child("Expires").text().set(entry->expires());
  times_node.append_child("UsageCount").text().set(entry->usage_count());

  pugi::xml_node autotype_node = entry_node.append_child("AutoType");
  autotype_node.append_child("Enabled").text().set(
      entry->auto_type().enabled());
  autotype_node.append_child("DataTransferObfuscation")
      .text()
      .set(entry->auto_type().obfuscation());
  autotype_node.append_child("DefaultSequence")
      .text()
      .set(entry->auto_type().sequence().c_str());

  for (const auto &ass : entry->auto_type().associations()) {
    pugi::xml_node ass_node = autotype_node.append_child("Association");
    ass_node.append_child("Window").text().set(ass.window().c_str());
    ass_node.append_child("KeystrokeSequence")
        .text()
        .set(ass.sequence().c_str());
  }

  // Write string fields.
  pugi::xml_node str_node = entry_node.append_child("String");
  str_node.append_child("Key").text().set("Title");
  pugi::xml_node val_node = str_node.append_child("Value");
  WriteProtectedString(val_node, entry->title(), obfuscator);

  str_node = entry_node.append_child("String");
  str_node.append_child("Key").text().set("URL");
  val_node = str_node.append_child("Value");
  WriteProtectedString(val_node, entry->url(), obfuscator);

  str_node = entry_node.append_child("String");
  str_node.append_child("Key").text().set("UserName");
  val_node = str_node.append_child("Value");
  WriteProtectedString(val_node, entry->username(), obfuscator);

  str_node = entry_node.append_child("String");
  str_node.append_child("Key").text().set("Password");
  val_node = str_node.append_child("Value");
  WriteProtectedString(val_node, entry->password(), obfuscator);

  str_node = entry_node.append_child("String");
  str_node.append_child("Key").text().set("Notes");
  val_node = str_node.append_child("Value");
  WriteProtectedString(val_node, entry->notes(), obfuscator);

  for (const auto &field : entry->custom_fields()) {
    str_node = entry_node.append_child("String");
    str_node.append_child("Key").text().set(field.key().c_str());
    val_node = str_node.append_child("Value");
    WriteProtectedString(val_node, field.value(), obfuscator);
  }

  // Write binary fields.
  for (const auto &attachment : entry->attachments()) {
    pugi::xml_node bin_node = entry_node.append_child("Binary");
    bin_node.append_child("Key").text().set(attachment->name().c_str());

    bool found_in_pool = false;
    for (const auto &it : binary_pool_) {
      if (it.second == attachment->binary()) {
        bin_node.append_child("Value").append_attribute("Ref").set_value(
            it.first.c_str());
        found_in_pool = true;
        break;
      }
    }

    if (!found_in_pool) {
      bin_node.append_child("Value").text().set(
          base64_encode(attachment->binary()->data().value()).c_str());
    }
  }

  // Write history entries.
  pugi::xml_node history_node = entry_node.append_child("History");
  for (const auto &histentry : entry->history()) {
    pugi::xml_node histentry_node = history_node.append_child("Entry");
    WriteEntry(histentry_node, obfuscator, histentry);
  }
}

std::shared_ptr<Group> KdbxFile::ParseGroup(const pugi::xml_node &group_node,
                                            RandomObfuscator &obfuscator) {
  std::shared_ptr<Group> group = std::make_shared<Group>();
  group_pool_.insert(std::make_pair(group_node.child_value("UUID"), group));

  std::array<uint8_t, 16> uuid = {0};
  base64_decode<bounds_checked_iterator<std::array<uint8_t, 16>>,
                unsigned char>(group_node.child_value("UUID"),
                               bounds_checked(uuid));

  group->set_uuid(uuid);
  group->set_name(group_node.child_value("Name"));
  group->set_notes(group_node.child_value("Notes"));
  group->set_icon(group_node.child("IconID").text().as_uint());

  if (group_node.child("CustomIconUUID")) {
    auto icon = icon_pool_.find(group_node.child_value("CustomIconUUID"));
    if (icon != icon_pool_.end()) {
      group->set_custom_icon(icon->second);
    } else {
      assert(false);
    }
  }

  pugi::xml_node times_node = group_node.child("Times");
  if (times_node) {
    group->set_creation_time(
        ParseDateTime(times_node.child_value("CreationTime")));
    group->set_modification_time(
        ParseDateTime(times_node.child_value("LastModificationTime")));
    group->set_access_time(
        ParseDateTime(times_node.child_value("LastAccessTime")));
    group->set_expiry_time(ParseDateTime(times_node.child_value("ExpiryTime")));
    group->set_move_time(
        ParseDateTime(times_node.child_value("LocationChanged")));
    group->set_expires(times_node.child("Expires").text().as_bool());
    group->set_usage_count(times_node.child("UsageCount").text().as_uint());
  }

  group->set_expanded(group_node.child("IsExpanded").text().as_bool());
  group->set_default_autotype_sequence(
      group_node.child_value("DefaultAutoTypeSequence"));
  group->set_autotype(group_node.child("EnableAutoType").text().as_bool());
  group->set_search(group_node.child("EnableSearching").text().as_bool());

  base64_decode<bounds_checked_iterator<std::array<uint8_t, 16>>,
                unsigned char>(group_node.child_value("LastTopVisibleEntry"),
                               bounds_checked(uuid));

  for (pugi::xml_node entry_node = group_node.child("Entry"); entry_node;
       entry_node = entry_node.next_sibling("Entry")) {
    std::array<uint8_t, 16> entry_uuid = {0};
    std::shared_ptr<Entry> entry =
        ParseEntry(entry_node, entry_uuid, obfuscator);
    group->AddEntry(entry);

    if (entry_uuid == uuid) {
      assert(group->last_visible_entry().expired());
      group->set_last_visible_entry(entry);
    }
  }

  for (pugi::xml_node subgroup_node = group_node.child("Group"); subgroup_node;
       subgroup_node = subgroup_node.next_sibling("Group")) {
    group->AddGroup(ParseGroup(subgroup_node, obfuscator));
  }

  return group;
}

void KdbxFile::WriteGroup(pugi::xml_node &group_node,
                          RandomObfuscator &obfuscator,
                          const std::shared_ptr<Group> &group) {
  group_node.append_child("UUID").text().set(
      base64_encode(group->uuid().begin(), group->uuid().end()).c_str());
  group_node.append_child("Name").text().set(group->name().c_str());
  group_node.append_child("Notes").text().set(group->notes().c_str());
  group_node.append_child("IconID").text().set(group->icon());

  if (auto icon = group->custom_icon().lock()) {
    group_node.append_child("CustomIconUUID")
        .text()
        .set(base64_encode(icon->uuid().begin(), icon->uuid().end()).c_str());
  }

  pugi::xml_node times_node = group_node.append_child("Times");
  times_node.append_child("CreationTime")
      .text()
      .set(WriteDateTime(group->creation_time()).c_str());
  times_node.append_child("LastModificationTime")
      .text()
      .set(WriteDateTime(group->modification_time()).c_str());
  times_node.append_child("LastAccessTime")
      .text()
      .set(WriteDateTime(group->access_time()).c_str());
  times_node.append_child("ExpiryTime")
      .text()
      .set(WriteDateTime(group->expiry_time()).c_str());
  times_node.append_child("LocationChanged")
      .text()
      .set(WriteDateTime(group->move_time()).c_str());
  times_node.append_child("Expires").text().set(group->expires());
  times_node.append_child("UsageCount").text().set(group->usage_count());

  group_node.append_child("IsExpanded").text().set(group->expanded());
  group_node.append_child("DefaultAutoTypeSequence")
      .text()
      .set(group->default_autotype_sequence().c_str());
  group_node.append_child("EnableAutoType").text().set(group->autotype());
  group_node.append_child("EnableSearching").text().set(group->search());

  if (auto entry = group->last_visible_entry().lock()) {
    group_node.append_child("LastTopVisibleEntry")
        .text()
        .set(base64_encode(entry->uuid().begin(), entry->uuid().end()).c_str());
  }

  for (const auto &entry : group->Entries()) {
    pugi::xml_node entry_node = group_node.append_child("Entry");
    WriteEntry(entry_node, obfuscator, entry);
  }

  for (const auto &subgroup : group->Groups()) {
    pugi::xml_node subgroup_node = group_node.append_child("Group");
    WriteGroup(subgroup_node, obfuscator, subgroup);
  }
}

void KdbxFile::ParseXml(std::istream &src, RandomObfuscator &obfuscator,
                        Database &db) {
  pugi::xml_document doc;
  if (!doc.load(src, pugi::parse_default | pugi::parse_trim_pcdata))
    throw FormatError("Malformed XML in KDBX.");

  pugi::xml_node kpf_node = doc.child("KeePassFile");
  if (!kpf_node)
    throw FormatError("No \"KeePassFile\" element in KDBX XML.");

  pugi::xml_node meta_node = kpf_node.child("Meta");
  if (!meta_node)
    throw FormatError("No \"Meta\" element in KDBX XML.");

  pugi::xml_node group_node = kpf_node.child("Root").child("Group");
  if (!group_node)
    throw FormatError(R"(No "Root" or "Group" element in KDBX XML.)");

  std::shared_ptr<Metadata> meta = ParseMeta(meta_node, obfuscator);
  std::shared_ptr<Group> root = ParseGroup(group_node, obfuscator);

  db.set_meta(meta);
  db.set_root(root);

  // When first parsing the meta data we haven't yet parsed all groups so we
  // have to wait until every group is parsed before parsing the final parts of
  // the meta data.
  auto it = group_pool_.find(meta_node.child_value("LastSelectedGroup"));
  if (it != group_pool_.end()) {
    meta->set_last_selected_group(it->second);
  }

  it = group_pool_.find(meta_node.child_value("LastTopVisibleGroup"));
  if (it != group_pool_.end()) {
    meta->set_last_visible_group(it->second);
  }
}

#ifdef DEBUG
void KdbxFile::PrintXml(pugi::xml_document &doc) {
  static const char *kNodeTypeNames[] = {"null",   "document",   "element",
                                         "pcdata", "cdata",      "comment",
                                         "pi",     "declaration"};

  struct XmlTreeWalker : pugi::xml_tree_walker {
  public:
    virtual bool for_each(pugi::xml_node &node) override {
      for (int i = 0; i < depth(); ++i)
        std::cout << "  ";

      std::cout << kNodeTypeNames[node.type()] << ": name=\"" << node.name()
                << "\"; value=\"" << node.value() << "\"" << std::endl;
      return true;
    }
  };

  XmlTreeWalker walker;
  doc.traverse(walker);
}
#endif

void KdbxFile::WriteXml(std::ostream &dst, RandomObfuscator &obfuscator,
                        const Database &db) {
  pugi::xml_document doc;

  pugi::xml_node kpf_node = doc.append_child("KeePassFile");
  pugi::xml_node meta_node = kpf_node.append_child("Meta");
  pugi::xml_node group_node =
      kpf_node.append_child("Root").append_child("Group");

  WriteMeta(meta_node, obfuscator, db.meta());
  WriteGroup(group_node, obfuscator, db.root());

  doc.save(dst);
}

std::unique_ptr<Database> KdbxFile::Import(const std::string &path,
                                           const Key &key) {
  Reset();

  std::ifstream src(path, std::ios::binary);
  if (!src.is_open())
    throw FileNotFoundError();

  // Read header.
  KdbxHeader header{};
  try {
    header = consume<KdbxHeader>(src);
  } catch (std::exception &e) {
    throw FormatError("Not a KDBX database.");
  }
  if (header.signature0 != kKdbxSignature0 ||
      header.signature1 != kKdbxSignature1) {
    throw FormatError("Not a KDBX database.");
  }

  switch (header.version & kKdbxVersionCriticalMask) {
  case kKdbxVersion3:
    return Import3(src, key);
  case kKdbxVersion4:
    kdbx4_ = true;
    return Import4(src, key);
  default:
    throw FormatError(std::string(Format() << "KDBX version " << header.version
                                           << " is not supported."));
  }
}

std::unique_ptr<Database> KdbxFile::Import3(std::istream &src, const Key &key) {
  std::array<uint8_t, 32> content_start_bytes = {{0}};

  std::unique_ptr<Database> db(new Database());

  // Read header fields.
  bool done = false;
  while (!done && src.good()) {
    auto header_field = consume<KdbxHeaderField>(src);

    // Read the header field into a separate buffer before parsing. This is to
    // guard against reading outside the field as well as for making sure to
    // read the complete field regardless of how much of it that we parse.
    std::stringstream field;
    std::generate_n(std::ostreambuf_iterator<char>(field), header_field.size,
                    [&src]() { return src.get(); });
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
      db->set_cipher(Database::Cipher::kAes);
      break;
    case KdbxHeaderField::kCompressionFlags: {
      auto comp_flags = consume<uint32_t>(field);
      if (comp_flags > static_cast<uint32_t>(kKdbxCompressionFlags::kCount))
        throw FormatError("Unknown compression method in KDBX.");
      db->set_compress(comp_flags ==
                       static_cast<uint32_t>(kKdbxCompressionFlags::kGzip));
      break;
    }
    case KdbxHeaderField::kMasterSeed:
      db->set_master_seed(consume<std::vector<uint8_t>>(field));
      break;
    case KdbxHeaderField::kTransformSeed:
      if (header_field.size != 32)
        throw FormatError("Illegal transform seed size in KDBX.");
      db->set_transform_seed(consume<std::array<uint8_t, 32>>(field));
      break;
    case KdbxHeaderField::kTransformRounds:
      db->set_transform_rounds(consume<uint32_t>(field));
      break;
    case KdbxHeaderField::kExcryptionInitVec:
      if (header_field.size != 16)
        throw FormatError("Illegal initialization vector size in KDBX.");
      db->set_init_vector(consume<std::array<uint8_t, 16>>(field));
      break;
    case KdbxHeaderField::kInnerRandomStreamKey:
      if (header_field.size != 32)
        throw FormatError("Illegal protected stream key size in KDBX.");
      db->set_inner_random_stream_key(consume<std::array<uint8_t, 32>>(field));
      break;
    case KdbxHeaderField::kContentStreamStartBytes:
      if (header_field.size != 32)
        throw FormatError("Illegal stream start sequence size in KDBX.");
      content_start_bytes = consume<std::array<uint8_t, 32>>(field);
      break;
    case KdbxHeaderField::kInnerRandomStreamId: {
      auto inner_random_stream_id = consume<uint32_t>(field);
      if (inner_random_stream_id !=
          static_cast<uint32_t>(kKdbxRandomStream::kSalsa20)) {
        throw FormatError("Unknown random stream in KDBX.");
      }
      break;
    }
    default:
      throw FormatError("Illegal header field in KDBX.");
      break;
    }
  }

  // Compute the header hash.
  std::streampos header_end = src.tellg();
  src.seekg(0, std::ios::beg);
  std::vector<char> header_data;
  header_data.resize(static_cast<std::size_t>(header_end));
  src.read(header_data.data(), header_end);

  std::array<uint8_t, 32> header_hash{};
  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
  EVP_DigestUpdate(mdctx, header_data.data(), header_data.size());
  unsigned int out_len = 0;
  EVP_DigestFinal_ex(mdctx, header_hash.data(), &out_len);
  EVP_MD_CTX_free(mdctx);

  // Produce the final key used for encrypting the contents.
  std::array<uint8_t, 32> transformed_key =
      key.Transform(db->transform_seed(), db->transform_rounds(),
                    Key::SubKeyResolution::kHashSubKeys);
  db->set_transformed_key(transformed_key);
  std::array<uint8_t, 32> final_key{};

  mdctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
  EVP_DigestUpdate(mdctx, db->master_seed().data(), db->master_seed().size());
  EVP_DigestUpdate(mdctx, transformed_key.data(), transformed_key.size());
  EVP_DigestFinal_ex(mdctx, final_key.data(), &out_len);
  EVP_MD_CTX_free(mdctx);

  std::unique_ptr<Cipher<16>> cipher;
  switch (db->cipher()) {
  case Database::Cipher::kAes:
    cipher = std::make_unique<AesCipher>(final_key, db->init_vector());
    break;
  case Database::Cipher::kTwofish:
    cipher = std::make_unique<TwofishCipher>(final_key, db->init_vector());
    break;
  default:
    assert(false);
    break;
  }

  // Decrypt the content.
  std::stringstream content;

  try {
    decrypt_cbc(src, content, *cipher);
  } catch (std::exception &e) {
    throw PasswordError();
  }

  std::array<uint8_t, 32> content_start_bytes_tst{};
  content.read(reinterpret_cast<char *>(content_start_bytes_tst.data()),
               content_start_bytes_tst.size());
  if (!content.good() || content_start_bytes != content_start_bytes_tst)
    throw PasswordError();

  // Prepare deobfuscation stream.
  std::array<uint8_t, 32> final_inner_random_stream_key{};
  mdctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
  EVP_DigestUpdate(mdctx, db->inner_random_stream_key().data(),
                   db->inner_random_stream_key().size());
  EVP_DigestFinal_ex(mdctx, final_inner_random_stream_key.data(), &out_len);
  EVP_MD_CTX_free(mdctx);
  RandomObfuscator obfuscator(final_inner_random_stream_key,
                              kKdbxInnerRandomStreamInitVec);

  // Parse XML content.
  hashed_istreambuf hashed_streambuf(content);
  std::istream hashed_stream(&hashed_streambuf);

  if (db->compress()) {
    gzip_istreambuf gzip_streambuf(hashed_stream);
    std::istream gzip_stream(&gzip_streambuf);

    ParseXml(gzip_stream, obfuscator, *db);
  } else {
    ParseXml(hashed_stream, obfuscator, *db);
  }

  // Validate header hash.
  if (header_hash_ != header_hash)
    throw FormatError("Header checksum error in KDBX.");

  return db;
}

std::unique_ptr<Database> KdbxFile::Import4(std::istream &src, const Key &key) {
  std::unique_ptr<Database> db(new Database());

  std::vector<uint8_t> argon2_salt;
  uint64_t argon2_iterations = 0;

  // Read header fields.
  bool done = false;
  while (!done && src.good()) {
    auto header_field = consume<Kdbx4HeaderField>(src);

    // Read the header field into a separate buffer before parsing.
    std::stringstream field;
    std::generate_n(std::ostreambuf_iterator<char>(field), header_field.size,
                    [&src]() { return src.get(); });
    if (!src.good())
      throw IoError("Read error.");

    switch (header_field.id) {
    case Kdbx4HeaderField::kEndOfHeader:
      done = true;
      break;
    case Kdbx4HeaderField::kCipherId: {
      auto uuid = consume<std::array<uint8_t, 16>>(field);
      if (uuid == kKdbxCipherChaCha20) {
        db->set_cipher(Database::Cipher::kChaCha20);
      } else if (uuid == kKdbxCipherAes) {
        db->set_cipher(Database::Cipher::kAes);
      } else if (uuid == kKdbxCipherTwofish) {
        db->set_cipher(Database::Cipher::kTwofish);
      } else {
        throw FormatError("Unknown cipher in KDBX 4 database.");
      }
      break;
    }
    case Kdbx4HeaderField::kCompressionFlags: {
      auto comp_flags = consume<uint32_t>(field);
      if (comp_flags > static_cast<uint32_t>(kKdbxCompressionFlags::kCount))
        throw FormatError("Unknown compression method in KDBX.");
      db->set_compress(comp_flags ==
                       static_cast<uint32_t>(kKdbxCompressionFlags::kGzip));
      break;
    }
    case Kdbx4HeaderField::kMasterSeed:
      db->set_master_seed(consume<std::vector<uint8_t>>(field));
      break;
    case Kdbx4HeaderField::kEncryptionIv:
      if (header_field.size == 16) {
        db->set_init_vector(consume<std::array<uint8_t, 16>>(field));
      } else if (header_field.size == 12) {
        std::array<uint8_t, 16> iv{};
        field.read(reinterpret_cast<char *>(iv.data()), 12);
        if (!field)
          throw IoError("Read error.");
        db->set_init_vector(iv);
      } else {
        throw FormatError("Illegal initialization vector size in KDBX.");
      }
      break;
    case Kdbx4HeaderField::kKdfParameters: {
      VariantDictionary vdict;
      vdict.Parse(field);

      const VariantDictionary::Entry &uuid_entry = vdict.Get("$UUID");
      if (uuid_entry.type != VariantDictionary::Type::kByteArray ||
          uuid_entry.value.size() != 16) {
        throw FormatError("Illegal KDF UUID in KDBX 4 database.");
      }

      std::array<uint8_t, 16> uuid{};
      std::copy(uuid_entry.value.begin(), uuid_entry.value.end(), uuid.begin());

      if (uuid == kKdbxKdfAesKdbx4 || uuid == kKdbxKdfAesKdbx3) {
        db->set_kdf(Database::Kdf::kAes);

        std::vector<uint8_t> seed = vdict.GetBytes("S");
        if (seed.size() != 32)
          throw FormatError("Illegal KDF seed size in KDBX 4 database.");
        std::array<uint8_t, 32> seed_arr{};
        std::copy(seed.begin(), seed.end(), seed_arr.begin());
        db->set_transform_seed(seed_arr);
        db->set_transform_rounds(vdict.GetUInt64("R"));
      } else if (uuid == kKdbxKdfArgon2d || uuid == kKdbxKdfArgon2id) {
        db->set_kdf(uuid == kKdbxKdfArgon2d ? Database::Kdf::kArgon2d
                                            : Database::Kdf::kArgon2id);

        argon2_salt = vdict.GetBytes("S");
        argon2_iterations = vdict.GetUInt64("I");
        db->set_argon2_salt(argon2_salt);
        db->set_argon2_iterations(argon2_iterations);
        db->set_argon2_memory(vdict.GetUInt64("M"));
        db->set_argon2_parallelism(vdict.GetUInt32("P"));
        db->set_argon2_version(vdict.GetUInt32("V"));
      } else {
        throw FormatError("Unknown KDF in KDBX 4 database.");
      }
      break;
    }
    default:
      throw FormatError("Illegal header field in KDBX.");
    }
  }

  // Compute the header hash over all bytes up to (but not including) the
  // stored header hash and HMAC.
  std::streampos header_end = src.tellg();
  src.seekg(0, std::ios::beg);
  std::vector<char> header_data;
  header_data.resize(static_cast<std::size_t>(header_end));
  src.read(header_data.data(), header_end);

  std::array<uint8_t, 32> header_hash{};
  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
  EVP_DigestUpdate(mdctx, header_data.data(), header_data.size());
  unsigned int out_len = 0;
  EVP_DigestFinal_ex(mdctx, header_hash.data(), &out_len);
  EVP_MD_CTX_free(mdctx);

  const std::array<uint8_t, 32> stored_header_hash =
      consume<std::array<uint8_t, 32>>(src);
  const std::array<uint8_t, 32> stored_header_hmac =
      consume<std::array<uint8_t, 32>>(src);

  if (stored_header_hash != header_hash)
    throw FormatError("Header checksum error in KDBX 4 database.");

  // Produce the transformed key used for both the final encryption key and
  // the HMAC verification key.
  std::array<uint8_t, 32> transformed_key{};
  switch (db->kdf()) {
  case Database::Kdf::kAes:
    transformed_key = key.Transform(db->transform_seed(),
                                    db->transform_rounds(),
                                    Key::SubKeyResolution::kHashSubKeys);
    break;
  case Database::Kdf::kArgon2d:
  case Database::Kdf::kArgon2id:
    transformed_key = key.TransformArgon2(
        db->kdf() == Database::Kdf::kArgon2d ? Key::Kdf::kArgon2d
                                             : Key::Kdf::kArgon2id,
        argon2_salt, argon2_iterations, db->argon2_memory(),
        db->argon2_parallelism(), db->argon2_version(),
        Key::SubKeyResolution::kHashSubKeys);
    break;
  }
  db->set_transformed_key(transformed_key);

  // Compute the HMAC key for the header. The block index 0xFFFFFFFFFFFFFFFF
  // denotes the header in the HMAC key derivation.
  std::array<uint8_t, 64> hmac_key{};
  EVP_MD_CTX *mdctx512 = EVP_MD_CTX_new();
  EVP_DigestInit_ex(mdctx512, EVP_sha512(), nullptr);
  EVP_DigestUpdate(mdctx512, db->master_seed().data(), db->master_seed().size());
  EVP_DigestUpdate(mdctx512, transformed_key.data(), transformed_key.size());
  static constexpr uint8_t kKdbxHmacKeyIndex1 = 0x01;
  EVP_DigestUpdate(mdctx512, &kKdbxHmacKeyIndex1, 1);
  EVP_DigestFinal_ex(mdctx512, hmac_key.data(), &out_len);
  EVP_MD_CTX_free(mdctx512);

  std::array<uint8_t, 64> header_hmac_key{};
  const std::array<uint8_t, 8> kKdbxHeaderHmacIndex = {
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  mdctx512 = EVP_MD_CTX_new();
  EVP_DigestInit_ex(mdctx512, EVP_sha512(), nullptr);
  EVP_DigestUpdate(mdctx512, kKdbxHeaderHmacIndex.data(),
                   kKdbxHeaderHmacIndex.size());
  EVP_DigestUpdate(mdctx512, hmac_key.data(), hmac_key.size());
  EVP_DigestFinal_ex(mdctx512, header_hmac_key.data(), &out_len);
  EVP_MD_CTX_free(mdctx512);

  unsigned char computed_hmac[EVP_MAX_MD_SIZE];
  unsigned int computed_hmac_len = 0;
  HMAC(EVP_sha256(), header_hmac_key.data(), header_hmac_key.size(),
       reinterpret_cast<const unsigned char *>(header_data.data()),
       header_data.size(), computed_hmac, &computed_hmac_len);
  if (computed_hmac_len != stored_header_hmac.size() ||
      std::memcmp(computed_hmac, stored_header_hmac.data(),
                  stored_header_hmac.size()) != 0) {
    throw PasswordError();
  }

  // Produce the final key used for encrypting the contents.
  std::array<uint8_t, 32> final_key{};
  mdctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
  EVP_DigestUpdate(mdctx, db->master_seed().data(), db->master_seed().size());
  EVP_DigestUpdate(mdctx, transformed_key.data(), transformed_key.size());
  EVP_DigestFinal_ex(mdctx, final_key.data(), &out_len);
  EVP_MD_CTX_free(mdctx);

  std::unique_ptr<Cipher<16>> cipher;
  std::unique_ptr<ChaCha20Cipher> chacha_cipher;
  if (db->cipher() == Database::Cipher::kAes) {
    cipher = std::make_unique<AesCipher>(final_key, db->init_vector());
  } else if (db->cipher() == Database::Cipher::kTwofish) {
    cipher = std::make_unique<TwofishCipher>(final_key, db->init_vector());
  } else if (db->cipher() == Database::Cipher::kChaCha20) {
    std::array<uint8_t, 12> iv{};
    std::copy(db->init_vector().begin(), db->init_vector().begin() + 12,
              iv.begin());
    chacha_cipher = std::make_unique<ChaCha20Cipher>(final_key, iv);
  }

  // In KDBX 4 the content is first encrypted and the ciphertext is then
  // wrapped in HMAC protected blocks. Read the HMAC blocks from the file and
  // decrypt the payload inside them.
  hmac_istreambuf hmac_streambuf(src, hmac_key);
  std::istream hmac_stream(&hmac_streambuf);

  std::string ciphertext((std::istreambuf_iterator<char>(hmac_stream)),
                         std::istreambuf_iterator<char>());

  std::stringstream content;
  try {
    if (db->cipher() == Database::Cipher::kAes ||
        db->cipher() == Database::Cipher::kTwofish) {
      std::stringstream cipher_input(ciphertext);
      decrypt_cbc(cipher_input, content, *cipher);
    } else if (db->cipher() == Database::Cipher::kChaCha20) {
      // ChaCha20 is a stream cipher: the ciphertext is XORed with the
      // keystream (RFC 8439, 96-bit nonce) and needs no padding.
      std::stringstream plaintext;
      std::array<uint8_t, 64> keystream{}, data{};
      size_t offset = 0;
      while (offset < ciphertext.size()) {
        std::array<uint8_t, 64> zero{};
        chacha_cipher->Process(zero, keystream);
        size_t n = std::min<size_t>(64, ciphertext.size() - offset);
        for (size_t i = 0; i < n; ++i)
          data[i] = static_cast<uint8_t>(ciphertext[offset + i]) ^ keystream[i];
        plaintext.write(reinterpret_cast<const char *>(data.data()),
                        static_cast<std::streamsize>(n));
        offset += n;
      }
      content.str(plaintext.str());
    } else {
      throw FormatError("Unknown cipher in KDBX 4 database.");
    }
  } catch (std::exception &e) {
    throw PasswordError();
  }

  // In KDBX 4 the inner header and the XML document are both part of the same
  // (compressed) payload, so decompress the entire decrypted content first.
  std::stringstream plain;
  if (db->compress()) {
    gzip_istreambuf gzip_streambuf(content);
    std::istream gzip_stream(&gzip_streambuf);
    std::copy(std::istreambuf_iterator<char>(gzip_stream),
              std::istreambuf_iterator<char>(),
              std::ostreambuf_iterator<char>(plain));
  } else {
    plain.str(content.str());
  }
  std::stringstream &xml_source = plain;

  // Parse the KDBX 4 inner header containing the inner random stream
  // identifier, its key and the binary attachments.
  uint32_t inner_random_stream_id = 0;
  std::vector<uint8_t> inner_random_stream_key;
  std::vector<std::shared_ptr<Binary>> inner_binaries;

  bool inner_done = false;
  while (!inner_done && xml_source.good()) {
    auto inner_id = static_cast<kKdbxInnerHeader>(consume<uint8_t>(xml_source));
    uint32_t inner_size = consume<uint32_t>(xml_source);

    switch (inner_id) {
    case kKdbxInnerHeader::kEnd:
      inner_done = true;
      break;
    case kKdbxInnerHeader::kInnerRandomStreamId:
      if (inner_size != 4)
        throw FormatError("Illegal inner random stream ID size in KDBX.");
      inner_random_stream_id = consume<uint32_t>(xml_source);
      break;
    case kKdbxInnerHeader::kInnerRandomStreamKey:
      if (inner_size != 32 && inner_size != 64)
        throw FormatError("Illegal inner random stream key size in KDBX.");
      inner_random_stream_key.resize(inner_size);
      xml_source.read(reinterpret_cast<char *>(inner_random_stream_key.data()),
                      static_cast<std::streamsize>(inner_size));
      if (!xml_source)
        throw IoError("Read error.");
      break;
    case kKdbxInnerHeader::kBinaries: {
      std::stringstream raw_stream;
      std::generate_n(std::ostreambuf_iterator<char>(raw_stream), inner_size,
                      [&xml_source]() { return xml_source.get(); });

      // The first byte holds the flags, the remaining bytes are the data.
      uint8_t flags = static_cast<uint8_t>(raw_stream.get());
      std::string data((std::istreambuf_iterator<char>(raw_stream)),
                       std::istreambuf_iterator<char>());

      std::shared_ptr<Binary> binary =
          std::make_shared<Binary>(protect<std::string>(data, (flags & 0x01)));
      inner_binaries.push_back(binary);

      binary_pool_.insert(
          std::make_pair(std::to_string(binary_pool_.size()), binary));
      break;
    }
    default:
      throw FormatError("Illegal inner header field in KDBX 4 database.");
    }
  }

  // Prepare deobfuscation stream.
  RandomObfuscator obfuscator(RandomObfuscator::Type::kSalsa20,
                              inner_random_stream_key);
  switch (inner_random_stream_id) {
  case static_cast<uint32_t>(kKdbxRandomStream::kSalsa20):
    obfuscator = RandomObfuscator(RandomObfuscator::Type::kSalsa20,
                                  inner_random_stream_key);
    break;
  case 3: // ChaCha20
    obfuscator = RandomObfuscator(RandomObfuscator::Type::kChaCha20,
                                  inner_random_stream_key);
    break;
  default:
    throw FormatError("Unknown inner random stream in KDBX 4 database.");
  }

  // Parse the XML content, which follows the inner header in the same
  // (already decompressed) payload.
  ParseXml(xml_source, obfuscator, *db);

  // KDBX 4 attachments live in the inner header. Keep them in the meta so
  // that they are not lost when exporting to older formats.
  for (const auto &binary : inner_binaries)
    db->meta()->AddBinary(binary);

  return db;
}

void KdbxFile::Export(const std::string &path, const Database &db,
                      const Key &key) {
  Reset();

  if (write_kdbx4_ || db.kdf() != Database::Kdf::kAes) {
    kdbx4_ = true;
    std::ofstream dst(path, std::ios::out | std::ios::binary);
    if (!dst.is_open())
      throw IoError("Unable to open database for writing.");
    Export4(dst, db, key);
    return;
  }

  kdbx4_ = false;
  std::ofstream dst(path, std::ios::out | std::ios::binary);
  if (!dst.is_open())
    throw IoError("Unable to open database for writing.");
  Export3(dst, db, key);
}

void KdbxFile::Export3(std::ostream &dst, const Database &db,
                       const Key &key) {
  // Produce the final key used for encrypting the contents.
  std::array<uint8_t, 32> transformed_key =
      db.has_transformed_key()
          ? db.transformed_key()
          : key.Transform(db.transform_seed(), db.transform_rounds(),
                          Key::SubKeyResolution::kHashSubKeys);
  std::array<uint8_t, 32> final_key{};

  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
  EVP_DigestUpdate(mdctx, db.master_seed().data(), db.master_seed().size());
  EVP_DigestUpdate(mdctx, transformed_key.data(), transformed_key.size());
  unsigned int out_len = 0;
  EVP_DigestFinal_ex(mdctx, final_key.data(), &out_len);
  EVP_MD_CTX_free(mdctx);

  assert(db.cipher() == Database::Cipher::kAes);
  std::unique_ptr<Cipher<16>> cipher(
      new AesCipher(final_key, db.init_vector()));

  // Write header to temporary stream so that we can compute the hash of it.
  KdbxHeader header{};
  header.signature0 = kKdbxSignature0;
  header.signature1 = kKdbxSignature1;
  header.version = kKdbxVersionCriticalMin;

  std::stringstream header_stream;
  conserve<KdbxHeader>(header_stream, header);

  conserve<KdbxHeaderField>(header_stream,
                            KdbxHeaderField(KdbxHeaderField::kCipherId, 16));
  conserve<std::array<uint8_t, 16>>(header_stream, kKdbxCipherAes);

  conserve<KdbxHeaderField>(
      header_stream, KdbxHeaderField(KdbxHeaderField::kCompressionFlags, 4));
  conserve<uint32_t>(
      header_stream,
      db.compress() ? static_cast<uint32_t>(kKdbxCompressionFlags::kGzip) : 0);

  if (db.master_seed().size() >
      std::numeric_limits<decltype(KdbxHeaderField::size)>::max()) {
    assert(false);
    throw InternalError("Master seed size exceeds KDBX maximum.");
  }
  conserve<KdbxHeaderField>(
      header_stream,
      KdbxHeaderField(KdbxHeaderField::kMasterSeed,
                      static_cast<uint16_t>(db.master_seed().size())));
  conserve<std::vector<uint8_t>>(header_stream, db.master_seed());

  conserve<KdbxHeaderField>(
      header_stream, KdbxHeaderField(KdbxHeaderField::kTransformSeed, 32));
  conserve<std::array<uint8_t, 32>>(header_stream, db.transform_seed());

  conserve<KdbxHeaderField>(
      header_stream, KdbxHeaderField(KdbxHeaderField::kTransformRounds, 8));
  conserve<uint64_t>(header_stream, db.transform_rounds());

  conserve<KdbxHeaderField>(
      header_stream, KdbxHeaderField(KdbxHeaderField::kExcryptionInitVec, 16));
  conserve<std::array<uint8_t, 16>>(header_stream, db.init_vector());

  conserve<KdbxHeaderField>(
      header_stream,
      KdbxHeaderField(KdbxHeaderField::kInnerRandomStreamKey, 32));
  conserve<std::array<uint8_t, 32>>(header_stream,
                                    db.inner_random_stream_key());

  std::array<uint8_t, 32> content_start_bytes = random_array<32>();
  conserve<KdbxHeaderField>(
      header_stream,
      KdbxHeaderField(KdbxHeaderField::kContentStreamStartBytes, 32));
  conserve<std::array<uint8_t, 32>>(header_stream, content_start_bytes);

  conserve<KdbxHeaderField>(
      header_stream, KdbxHeaderField(KdbxHeaderField::kInnerRandomStreamId, 4));
  conserve<uint32_t>(header_stream,
                     static_cast<uint32_t>(kKdbxRandomStream::kSalsa20));

  conserve<KdbxHeaderField>(header_stream,
                            KdbxHeaderField(KdbxHeaderField::kEndOfHeader, 0));

  // Compute the header hash.
  std::string header_data = header_stream.str();
  EVP_MD_CTX *mdctx2 = EVP_MD_CTX_new();
  EVP_DigestInit_ex(mdctx2, EVP_sha256(), nullptr);
  EVP_DigestUpdate(mdctx2, header_data.c_str(), header_data.size());
  unsigned int out_len2 = 0;
  EVP_DigestFinal_ex(mdctx2, header_hash_.data(), &out_len2);
  EVP_MD_CTX_free(mdctx2);

  // Write header to file.
  std::copy(std::istreambuf_iterator<char>(header_stream),
            std::istreambuf_iterator<char>(),
            std::ostreambuf_iterator<char>(dst));

  // Prepare deobfuscation stream.
  std::array<uint8_t, 32> final_inner_random_stream_key{};
  EVP_MD_CTX *mdctx3 = EVP_MD_CTX_new();
  EVP_DigestInit_ex(mdctx3, EVP_sha256(), nullptr);
  EVP_DigestUpdate(mdctx3, db.inner_random_stream_key().data(),
                   db.inner_random_stream_key().size());
  unsigned int out_len3 = 0;
  EVP_DigestFinal_ex(mdctx3, final_inner_random_stream_key.data(), &out_len3);
  EVP_MD_CTX_free(mdctx3);
  RandomObfuscator obfuscator(final_inner_random_stream_key,
                              kKdbxInnerRandomStreamInitVec);

  // Write content to content stream.
  std::stringstream content_stream;
  conserve<std::array<uint8_t, 32>>(content_stream, content_start_bytes);

  hashed_ostreambuf hashed_streambuf(content_stream);
  std::ostream hashed_stream(&hashed_streambuf);

  if (db.compress()) {
    gzip_ostreambuf gzip_streambuf(hashed_stream);
    std::ostream gzip_stream(&gzip_streambuf);

    WriteXml(gzip_stream, obfuscator, db);
    gzip_stream.flush();
  } else {
    WriteXml(hashed_stream, obfuscator, db);
  }

  hashed_stream.flush();

  // Encrypt content.
  encrypt_cbc(content_stream, dst, *cipher);
}

void KdbxFile::Export4(std::ostream &dst, const Database &db,
                       const Key &key) {
  assert(db.cipher() == Database::Cipher::kAes ||
         db.cipher() == Database::Cipher::kTwofish ||
         db.cipher() == Database::Cipher::kChaCha20);

  // Derive the transformed key used for the final encryption key and the HMAC
  // key. If the database was imported and the KDF parameters were not modified,
  // the cached key can be reused; otherwise recompute it.
  std::array<uint8_t, 32> transformed_key{};
  if (db.has_transformed_key()) {
    transformed_key = db.transformed_key();
  } else {
    switch (db.kdf()) {
    case Database::Kdf::kAes:
      transformed_key = key.Transform(db.transform_seed(),
                                      db.transform_rounds(),
                                      Key::SubKeyResolution::kHashSubKeys);
      break;
    case Database::Kdf::kArgon2d:
    case Database::Kdf::kArgon2id:
      // The Argon2 parameters are stored in the KDF variant dictionary below.
      transformed_key = key.TransformArgon2(
          db.kdf() == Database::Kdf::kArgon2d ? Key::Kdf::kArgon2d
                                              : Key::Kdf::kArgon2id,
          db.argon2_salt(), db.argon2_iterations(), db.argon2_memory(),
          db.argon2_parallelism(), db.argon2_version(),
          Key::SubKeyResolution::kHashSubKeys);
      break;
    }
  }

  std::array<uint8_t, 32> final_key{};
  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
  EVP_DigestUpdate(mdctx, db.master_seed().data(), db.master_seed().size());
  EVP_DigestUpdate(mdctx, transformed_key.data(), transformed_key.size());
  unsigned int out_len = 0;
  EVP_DigestFinal_ex(mdctx, final_key.data(), &out_len);
  EVP_MD_CTX_free(mdctx);

  std::unique_ptr<Cipher<16>> cipher;
  std::unique_ptr<ChaCha20Cipher> chacha_cipher;
  if (db.cipher() == Database::Cipher::kAes) {
    cipher = std::make_unique<AesCipher>(final_key, db.init_vector());
  } else if (db.cipher() == Database::Cipher::kTwofish) {
    cipher = std::make_unique<TwofishCipher>(final_key, db.init_vector());
  } else if (db.cipher() == Database::Cipher::kChaCha20) {
    std::array<uint8_t, 12> iv{};
    std::copy(db.init_vector().begin(), db.init_vector().begin() + 12,
              iv.begin());
    chacha_cipher = std::make_unique<ChaCha20Cipher>(final_key, iv);
  }

  // Write header to a temporary stream so that we can compute the hash and
  // HMAC of it.
  KdbxHeader header{};
  header.signature0 = kKdbxSignature0;
  header.signature1 = kKdbxSignature1;
  header.version = kKdbxVersion4;

  std::stringstream header_stream;
  conserve<KdbxHeader>(header_stream, header);

  conserve<Kdbx4HeaderField>(header_stream,
                             Kdbx4HeaderField(Kdbx4HeaderField::kCipherId, 16));
  conserve<std::array<uint8_t, 16>>(
      header_stream,
      db.cipher() == Database::Cipher::kChaCha20
          ? kKdbxCipherChaCha20
          : (db.cipher() == Database::Cipher::kTwofish ? kKdbxCipherTwofish
                                                       : kKdbxCipherAes));

  conserve<Kdbx4HeaderField>(
      header_stream,
      Kdbx4HeaderField(Kdbx4HeaderField::kCompressionFlags, 4));
  conserve<uint32_t>(
      header_stream,
      db.compress() ? static_cast<uint32_t>(kKdbxCompressionFlags::kGzip) : 0);

  if (db.master_seed().size() >
      std::numeric_limits<decltype(Kdbx4HeaderField::size)>::max()) {
    assert(false);
    throw InternalError("Master seed size exceeds KDBX maximum.");
  }
  conserve<Kdbx4HeaderField>(
      header_stream,
      Kdbx4HeaderField(Kdbx4HeaderField::kMasterSeed,
                       static_cast<uint32_t>(db.master_seed().size())));
  conserve<std::vector<uint8_t>>(header_stream, db.master_seed());

  // Serialize the KDF variant dictionary.
  std::stringstream kdf_stream;
  {
    VariantDictionary vdict;

    if (db.kdf() == Database::Kdf::kAes) {
      std::array<uint8_t, 16> uuid = kKdbxKdfAesKdbx4;
      std::vector<uint8_t> uuid_vec(uuid.begin(), uuid.end());
      vdict.Set("$UUID", VariantDictionary::Type::kByteArray,
                std::move(uuid_vec));

      std::array<uint8_t, 32> seed = db.transform_seed();
      std::vector<uint8_t> seed_vec(seed.begin(), seed.end());
      vdict.Set("S", VariantDictionary::Type::kByteArray, std::move(seed_vec));

      std::vector<uint8_t> rounds(sizeof(uint64_t), 0);
      const uint64_t rounds_val = db.transform_rounds();
      std::memcpy(rounds.data(), &rounds_val, sizeof(rounds_val));
      vdict.Set("R", VariantDictionary::Type::kUInt64, std::move(rounds));
    } else {
      const std::array<uint8_t, 16> kdf_uuid =
          db.kdf() == Database::Kdf::kArgon2d ? kKdbxKdfArgon2d
                                              : kKdbxKdfArgon2id;

      std::array<uint8_t, 16> uuid = kdf_uuid;
      std::vector<uint8_t> uuid_vec(uuid.begin(), uuid.end());
      vdict.Set("$UUID", VariantDictionary::Type::kByteArray,
                std::move(uuid_vec));

      std::vector<uint8_t> salt = db.argon2_salt();
      vdict.Set("S", VariantDictionary::Type::kByteArray, std::move(salt));

      std::vector<uint8_t> iterations(sizeof(uint64_t), 0);
      const uint64_t iterations_val = db.argon2_iterations();
      std::memcpy(iterations.data(), &iterations_val, sizeof(iterations_val));
      vdict.Set("I", VariantDictionary::Type::kUInt64,
                std::move(iterations));

      std::vector<uint8_t> memory(sizeof(uint64_t), 0);
      const uint64_t memory_val = db.argon2_memory();
      std::memcpy(memory.data(), &memory_val, sizeof(memory_val));
      vdict.Set("M", VariantDictionary::Type::kUInt64, std::move(memory));

      std::vector<uint8_t> parallelism(sizeof(uint32_t), 0);
      const uint32_t parallelism_val = db.argon2_parallelism();
      std::memcpy(parallelism.data(), &parallelism_val, sizeof(parallelism_val));
      vdict.Set("P", VariantDictionary::Type::kUInt32,
                std::move(parallelism));

      std::vector<uint8_t> version(sizeof(uint32_t), 0);
      const uint32_t version_val = db.argon2_version();
      std::memcpy(version.data(), &version_val, sizeof(version_val));
      vdict.Set("V", VariantDictionary::Type::kUInt32, std::move(version));
    }

    vdict.Write(kdf_stream);
  }

  std::string kdf_data = kdf_stream.str();
  conserve<Kdbx4HeaderField>(header_stream,
                             Kdbx4HeaderField(Kdbx4HeaderField::kKdfParameters,
                                              static_cast<uint32_t>(
                                                  kdf_data.size())));
  std::copy(kdf_data.begin(), kdf_data.end(),
            std::ostreambuf_iterator<char>(header_stream));

conserve<Kdbx4HeaderField>(
      header_stream,
      Kdbx4HeaderField(Kdbx4HeaderField::kEncryptionIv,
                       db.cipher() == Database::Cipher::kChaCha20 ? 12 : 16));
  if (db.cipher() == Database::Cipher::kChaCha20) {
    header_stream.write(reinterpret_cast<const char *>(db.init_vector().data()),
                        12);
  } else {
    conserve<std::array<uint8_t, 16>>(header_stream, db.init_vector());
  }

  conserve<Kdbx4HeaderField>(header_stream,
                             Kdbx4HeaderField(Kdbx4HeaderField::kEndOfHeader,
                                              0));

  // Compute the header hash and HMAC.
  std::string header_data = header_stream.str();

  EVP_MD_CTX *mdctx_h = EVP_MD_CTX_new();
  EVP_DigestInit_ex(mdctx_h, EVP_sha256(), nullptr);
  EVP_DigestUpdate(mdctx_h, header_data.c_str(), header_data.size());
  unsigned int out_len_h = 0;
  EVP_DigestFinal_ex(mdctx_h, header_hash_.data(), &out_len_h);
  EVP_MD_CTX_free(mdctx_h);

  std::array<uint8_t, 64> hmac_key{};
  EVP_MD_CTX *mdctx512 = EVP_MD_CTX_new();
  EVP_DigestInit_ex(mdctx512, EVP_sha512(), nullptr);
  EVP_DigestUpdate(mdctx512, db.master_seed().data(), db.master_seed().size());
  EVP_DigestUpdate(mdctx512, transformed_key.data(), transformed_key.size());
  static constexpr uint8_t kKdbxHmacKeyIndex1 = 0x01;
  EVP_DigestUpdate(mdctx512, &kKdbxHmacKeyIndex1, 1);
  EVP_DigestFinal_ex(mdctx512, hmac_key.data(), &out_len_h);
  EVP_MD_CTX_free(mdctx512);

  std::array<uint8_t, 64> header_hmac_key{};
  const std::array<uint8_t, 8> kKdbxHeaderHmacIndex = {
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  EVP_MD_CTX *mdctx512b = EVP_MD_CTX_new();
  EVP_DigestInit_ex(mdctx512b, EVP_sha512(), nullptr);
  EVP_DigestUpdate(mdctx512b, kKdbxHeaderHmacIndex.data(),
                   kKdbxHeaderHmacIndex.size());
  EVP_DigestUpdate(mdctx512b, hmac_key.data(), hmac_key.size());
  EVP_DigestFinal_ex(mdctx512b, header_hmac_key.data(), &out_len_h);
  EVP_MD_CTX_free(mdctx512b);

  std::array<uint8_t, 32> header_hmac{};
  unsigned int header_hmac_len = 0;
  HMAC(EVP_sha256(), header_hmac_key.data(), header_hmac_key.size(),
       reinterpret_cast<const unsigned char *>(header_data.c_str()),
       header_data.size(), header_hmac.data(), &header_hmac_len);
  assert(header_hmac_len == header_hmac.size());

  // Write header, stored hash and stored HMAC to the file.
  std::copy(std::istreambuf_iterator<char>(header_stream),
            std::istreambuf_iterator<char>(),
            std::ostreambuf_iterator<char>(dst));
  conserve<std::array<uint8_t, 32>>(dst, header_hash_);
  conserve<std::array<uint8_t, 32>>(dst, header_hmac);

  // Prepare deobfuscation stream using a freshly generated inner random
  // stream key. KDBX 4 uses ChaCha20 for the inner random stream.
  std::array<uint8_t, 32> inner_random_stream_key = random_array<32>();
  RandomObfuscator obfuscator(RandomObfuscator::Type::kChaCha20,
                              inner_random_stream_key);

  // Collect all binaries used by entries into the inner header pool.
  binary_pool_.clear();
  std::vector<std::shared_ptr<Binary>> ordered_binaries;
  const auto collect = [&](const auto &self,
                           const std::shared_ptr<Group> &group) -> void {
    for (const auto &entry : group->Entries()) {
      const auto collect_entry =
          [&](const std::shared_ptr<Entry> &e) -> void {
        for (const auto &att : e->attachments()) {
          if (auto binary = att->binary()) {
            bool found = false;
            for (const auto &existing : ordered_binaries) {
              if (existing == binary) {
                found = true;
                break;
              }
            }
            if (!found)
              ordered_binaries.push_back(binary);
          }
        }
      };
      collect_entry(entry);
      for (const auto &history_entry : entry->history())
        collect_entry(history_entry);
    }
    for (const auto &subgroup : group->Groups())
      self(self, subgroup);
  };
  collect(collect, db.root());

  for (std::size_t i = 0; i < ordered_binaries.size(); ++i) {
    binary_pool_.insert(
        std::make_pair(std::to_string(i), ordered_binaries[i]));
  }

  // Write content stream: inner header followed by the (optionally gzip
  // compressed) XML document.
  std::stringstream inner_header_stream;

  conserve<uint8_t>(inner_header_stream,
                    static_cast<uint8_t>(kKdbxInnerHeader::
                                             kInnerRandomStreamId));
  conserve<uint32_t>(inner_header_stream, 4);
  conserve<uint32_t>(inner_header_stream, 3); // ChaCha20

  conserve<uint8_t>(inner_header_stream,
                    static_cast<uint8_t>(kKdbxInnerHeader::
                                             kInnerRandomStreamKey));
  conserve<uint32_t>(inner_header_stream, 32);
  conserve<std::array<uint8_t, 32>>(inner_header_stream,
                                    inner_random_stream_key);

  for (const auto &binary : ordered_binaries) {
    std::stringstream bin_stream;
    uint8_t flags = binary->data().is_protected() ? 0x01 : 0x00;
    conserve<uint8_t>(bin_stream, flags);
    const std::string &raw = binary->data().value();
    if (!raw.empty()) {
      bin_stream.write(raw.data(), static_cast<std::streamsize>(raw.size()));
    }

    std::string bin_data = bin_stream.str();
    conserve<uint8_t>(inner_header_stream,
                      static_cast<uint8_t>(kKdbxInnerHeader::kBinaries));
    conserve<uint32_t>(
        inner_header_stream,
        static_cast<uint32_t>(bin_data.size()));
    std::copy(bin_data.begin(), bin_data.end(),
              std::ostreambuf_iterator<char>(inner_header_stream));
  }

  conserve<uint8_t>(inner_header_stream,
                    static_cast<uint8_t>(kKdbxInnerHeader::kEnd));
  conserve<uint32_t>(inner_header_stream, 0);

  // Build the plaintext payload. In KDBX 4 the inner header and the XML
  // document are both part of the same compressed payload.
  std::stringstream plain_stream;

  if (db.compress()) {
    gzip_ostreambuf gzip_streambuf(plain_stream);
    std::ostream gzip_stream(&gzip_streambuf);

    std::copy(std::istreambuf_iterator<char>(inner_header_stream),
              std::istreambuf_iterator<char>(),
              std::ostreambuf_iterator<char>(gzip_stream));
    WriteXml(gzip_stream, obfuscator, db);
    gzip_stream.flush();
  } else {
    std::copy(std::istreambuf_iterator<char>(inner_header_stream),
              std::istreambuf_iterator<char>(),
              std::ostreambuf_iterator<char>(plain_stream));
    WriteXml(plain_stream, obfuscator, db);
  }

  // Encrypt the plaintext payload first ...
  std::stringstream cipher_input(plain_stream.str());
  std::stringstream hmac_input;
  if (db.cipher() == Database::Cipher::kAes ||
      db.cipher() == Database::Cipher::kTwofish) {
    encrypt_cbc(cipher_input, hmac_input, *cipher);
  } else {
    std::string plain = plain_stream.str();
    std::array<uint8_t, 64> keystream{}, data{};
    size_t offset = 0;
    while (offset < plain.size()) {
      std::array<uint8_t, 64> zero{};
      chacha_cipher->Process(zero, keystream);
      size_t n = std::min<size_t>(64, plain.size() - offset);
      for (size_t i = 0; i < n; ++i)
        data[i] = static_cast<uint8_t>(plain[offset + i]) ^ keystream[i];
      hmac_input.write(reinterpret_cast<const char *>(data.data()),
                       static_cast<std::streamsize>(n));
      offset += n;
    }
  }

  // ... and then wrap the ciphertext in HMAC protected blocks. In KDBX 4 the
  // HMAC is computed over the encrypted content, so the HMAC framing is the
  // outermost layer below the stored header.
  hmac_ostreambuf hmac_streambuf(dst, hmac_key);
  std::ostream hmac_stream(&hmac_streambuf);

  std::copy(std::istreambuf_iterator<char>(hmac_input),
            std::istreambuf_iterator<char>(),
            std::ostreambuf_iterator<char>(hmac_stream));
  hmac_stream.flush();
}

} // namespace keepass
