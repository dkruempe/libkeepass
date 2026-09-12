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

#include "include/libkeepass/kdbx_xml.hh"

#include <algorithm>
#include <cassert>
#include <ctime>
#include <sstream>
#ifdef DEBUG
#include <iostream>
#endif

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

#include "libkeepass/base64.hh"
#include "libkeepass/exception.hh"
#include "libkeepass/icon.hh"
#include "libkeepass/io.hh"
#include "libkeepass/iterator.hh"
#include "libkeepass/metadata.hh"
#include "libkeepass/random.hh"
#include "libkeepass/secure.hh"
#include "libkeepass/stream.hh"

namespace keepass {

namespace {

// Zeroizes the buffered content of a stringstream in place, so that
// decrypted plaintext does not linger in the heap after parsing.
void WipeStream(std::stringstream& stream) {
  std::streambuf* buffer = stream.rdbuf();
  std::streamsize size =
      buffer->pubseekoff(0, std::ios_base::end, std::ios_base::in | std::ios_base::out);
  buffer->pubseekoff(0, std::ios_base::beg, std::ios_base::in | std::ios_base::out);

  static constexpr std::streamsize kChunkSize = 4096;
  char zeros[kChunkSize] = {};
  while (size > 0) {
    std::streamsize chunk = size < kChunkSize ? size : kChunkSize;
    if (buffer->sputn(zeros, chunk) != chunk)
      return;
    size -= chunk;
  }
}

// Zeroizes the contents of a contiguous container (std::string, std::string
// view or std::vector<char/uint8_t>) in place.
// std::string::data() returns a const pointer in C++11, so cast it away for
// the wipe; writing zeros never invalidates the container invariants.
template <typename Container> void WipeBuffer(Container* buffer) {
  if (buffer != nullptr && !buffer->empty()) {
    secure_zero(const_cast<typename Container::value_type*>(buffer->data()),
                buffer->size() * sizeof(typename Container::value_type));
  }
}

// KeePass 2.48+ stores entry and group tags as a semicolon-separated list in
// the XML document (verified against KeePass 2.57). The public API contract is
// space-separated, so the two representations are converted at the XML
// boundary. Tag names cannot contain spaces or semicolons in KeePass.
std::string TagsFromXml(const char* xml_tags) {
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

std::string TagsToXml(const std::string& api_tags) {
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

/** Seconds between 0001-01-01 and the Unix epoch (1970-01-01). */
constexpr int64_t kKdbxEpochBias = 62135596800LL;

// Returns whether all UUID bytes are zero. Used to keep the KDBX 4.1
// previous-parent-group element out of the output when it is not set.
bool IsZeroUuid(const std::array<uint8_t, 16>& uuid) {
  return std::all_of(uuid.begin(), uuid.end(), [](uint8_t byte) { return byte == 0; });
}

} // namespace

void KdbxXml::Reset() {
  binary_pool_.clear();
  icon_pool_.clear();
  group_pool_.clear();
  header_hash_ = {0};
  kdbx41_ = false;
}

std::shared_ptr<Group> KdbxXml::GetGroup(const std::string& uuid_str) {
  if (uuid_str.empty())
    return nullptr;

  auto it = group_pool_.find(uuid_str);
  if (it != group_pool_.end())
    return it->second;

  std::array<uint8_t, 16> uuid{};
  base64_decode<bounds_checked_iterator<std::array<uint8_t, 16>>, unsigned char>(
      uuid_str, bounds_checked(uuid));

  std::shared_ptr<Group> group = std::make_shared<Group>();
  group->set_uuid(uuid);

  group_pool_.insert(std::make_pair(uuid_str, group));
  return group;
}

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

protect<secure_string> KdbxXml::ParseProtectedString(const pugi::xml_node& node, const char* name,
                                                     RandomObfuscator& obfuscator) {
  pugi::xml_node val_node = node.child(name);
  if (val_node) {
    bool prot = val_node.attribute("Protected").as_bool();
    if (prot) {
      std::string val = base64_decode(val_node.text().as_string());
      if (!val.empty()) {
        secure_string decrypted = obfuscator.Process(secure_string(val));
        secure_zero(val.data(), val.size());
        return {std::move(decrypted), true};
      }
    }

    return {secure_string(val_node.text().as_string()),
            prot || val_node.attribute("ProtectedInMemory").as_bool()};
  }

  return {secure_string(), false};
}

void KdbxXml::WriteProtectedString(pugi::xml_node& node, const protect<secure_string>& str,
                                   RandomObfuscator& obfuscator) {
  if (str.is_protected()) {
    node.append_attribute("Protected").set_value("True");
    node.text().set(base64_encode(obfuscator.Process(*str).str()).c_str());
  } else {
    node.text().set(str->c_str());
  }
}

std::shared_ptr<Metadata> KdbxXml::ParseMeta(const pugi::xml_node& meta_node,
                                             RandomObfuscator& obfuscator) {
  std::shared_ptr<Metadata> meta = std::make_shared<Metadata>();

  // Parse header hash and store in member for checking later.
  base64_decode<bounds_checked_iterator<std::array<uint8_t, 32>>, unsigned char>(
      meta_node.child_value("HeaderHash"), bounds_checked(header_hash_));

  meta->set_generator(meta_node.child_value("Generator"));
  meta->set_database_name(
      temporal<std::string>(meta_node.child_value("DatabaseName"),
                            ParseDateTime(meta_node.child_value("DatabaseNameChanged"))));
  meta->set_database_desc(
      temporal<std::string>(meta_node.child_value("DatabaseDescription"),
                            ParseDateTime(meta_node.child_value("DatabaseDescriptionChanged"))));
  meta->set_default_username(
      temporal<std::string>(meta_node.child_value("DefaultUserName"),
                            ParseDateTime(meta_node.child_value("DefaultUserNameChanged"))));
  meta->set_maintenance_hist_days(meta_node.child("MaintenanceHistoryDays").text().as_uint(365));
  meta->set_database_color(meta_node.child_value("Color"));
  meta->set_master_key_changed(ParseDateTime(meta_node.child_value("MasterKeyChanged")));
  meta->set_master_key_change_rec(meta_node.child("MasterKeyChangeRec").text().as_llong(-1));
  meta->set_master_key_change_force(meta_node.child("MasterKeyChangeForce").text().as_llong(-1));

  pugi::xml_node mp_node = meta_node.child("MemoryProtection");
  meta->memory_protection().set_title(mp_node.child("ProtectTitle").text().as_bool());
  meta->memory_protection().set_username(mp_node.child("ProtectUserName").text().as_bool());
  meta->memory_protection().set_password(mp_node.child("ProtectPassword").text().as_bool(true));
  meta->memory_protection().set_url(mp_node.child("ProtectURL").text().as_bool());
  meta->memory_protection().set_notes(mp_node.child("ProtectNotes").text().as_bool());

  if (meta_node.child("RecycleBinEnabled").text().as_bool(true))
    meta->set_recycle_bin(GetGroup(meta_node.child_value("RecycleBinUUID")));
  else
    meta->set_recycle_bin(std::shared_ptr<Group>());
  meta->set_recycle_bin_changed(ParseDateTime(meta_node.child_value("RecycleBinChanged")));

  meta->set_entry_templates(GetGroup(meta_node.child_value("EntryTemplatesGroup")));
  meta->set_entry_templates_changed(
      ParseDateTime(meta_node.child_value("EntryTemplatesGroupChanged")));

  meta->set_history_max_items(meta_node.child("HistoryMaxItems").text().as_int(-1));
  meta->set_history_max_size(meta_node.child("HistoryMaxSize").text().as_llong(-1));

  // Note that we're not parsing "LastSelectedGroup" and "LastTopVisibleGroup"
  // here. They will be parsed later by Parse(). The reason is that we need
  // to parse all groups first.

  pugi::xml_node icons_node = meta_node.child("CustomIcons");
  if (icons_node) {
    for (pugi::xml_node icon_node = icons_node.child("Icon"); icon_node;
         icon_node = icon_node.next_sibling("Icon")) {
      std::vector<uint8_t> data;
      base64_decode<std::back_insert_iterator<std::vector<uint8_t>>, unsigned char>(
          icon_node.child_value("Data"), std::back_inserter(data));
      if (data.empty())
        continue;

      std::array<uint8_t, 16> uuid{};
      base64_decode<bounds_checked_iterator<std::array<uint8_t, 16>>, unsigned char>(
          icon_node.child_value("UUID"), bounds_checked(uuid));

      std::shared_ptr<Icon> icon = std::make_shared<Icon>(uuid, data);
      icon->set_name(icon_node.child_value("Name"));
      icon->set_last_modification_time(
          ParseDateTime(icon_node.child_value("LastModificationTime")));
      meta->AddIcon(icon);

      icon_pool_.insert(std::make_pair(icon_node.child_value("UUID"), icon));
    }
  }

  pugi::xml_node bins_node = meta_node.child("Binaries");
  if (bins_node) {
    for (pugi::xml_node bin_node = bins_node.child("Binary"); bin_node;
         bin_node = bin_node.next_sibling("Binary")) {
      std::string id = bin_node.attribute("ID").value();

      protect<secure_string> data;

      bool compressed = false;
      if (bin_node.attribute("Protected").as_bool()) {
        std::string encoded = base64_decode(bin_node.text().as_string());
        data = protect<secure_string>(obfuscator.Process(secure_string(encoded)), true);
        WipeBuffer(&encoded);
      } else {
        if (bin_node.attribute("Compressed").as_bool()) {
          compressed = true;
          std::string encoded = base64_decode(bin_node.text().as_string());
          std::stringstream raw_stream(encoded);
          gzip_istreambuf gzip_streambuf(raw_stream);
          std::istream gzip_stream(&gzip_streambuf);

          std::string decompressed = consume<std::string>(gzip_stream);
          data = protect<secure_string>(secure_string(decompressed),
                                        bin_node.attribute("ProtectedInMemory").as_bool());
          WipeBuffer(&decompressed);
          WipeBuffer(&encoded);
          WipeStream(raw_stream);
        } else {
          std::string decoded = base64_decode(bin_node.text().as_string());
          data = protect<secure_string>(secure_string(decoded),
                                        bin_node.attribute("ProtectedInMemory").as_bool());
          WipeBuffer(&decoded);
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

      Metadata::Field field(key, value);
      field.set_last_modification_time(
          ParseDateTime(item_node.child_value("LastModificationTime")));
      meta->AddField(field);
    }
  }

  return meta;
}

void KdbxXml::WriteMeta(pugi::xml_node& meta_node, RandomObfuscator& obfuscator,
                        const std::shared_ptr<Metadata>& meta) {
  // In KDBX 4 the header hash is stored in the KDBX header instead of in the
  // XML document.
  if (!kdbx4_) {
    meta_node.append_child("HeaderHash")
        .text()
        .set(base64_encode(header_hash_.begin(), header_hash_.end()).c_str());
  }
  meta_node.append_child("Generator").text().set(meta->generator().c_str());
  meta_node.append_child("DatabaseName").text().set(meta->database_name()->c_str());
  meta_node.append_child("DatabaseNameChanged")
      .text()
      .set(WriteDateTime(meta->database_name().time()).c_str());
  meta_node.append_child("DatabaseDescription").text().set(meta->database_desc()->c_str());
  meta_node.append_child("DatabaseDescriptionChanged")
      .text()
      .set(WriteDateTime(meta->database_desc().time()).c_str());
  meta_node.append_child("DefaultUserName").text().set(meta->default_username()->c_str());
  meta_node.append_child("DefaultUserNameChanged")
      .text()
      .set(WriteDateTime(meta->default_username().time()).c_str());
  meta_node.append_child("MaintenanceHistoryDays").text().set(meta->maintenance_hist_days());
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
  mp_node.append_child("ProtectTitle").text().set(meta->memory_protection().title());
  mp_node.append_child("ProtectUserName").text().set(meta->memory_protection().username());
  mp_node.append_child("ProtectPassword").text().set(meta->memory_protection().password());
  mp_node.append_child("ProtectURL").text().set(meta->memory_protection().url());
  mp_node.append_child("ProtectNotes").text().set(meta->memory_protection().notes());

  if (meta->recycle_bin()) {
    meta_node.append_child("RecycleBinEnabled").text().set(true);
    meta_node.append_child("RecycleBinUUID")
        .text()
        .set(base64_encode(meta->recycle_bin()->uuid().begin(), meta->recycle_bin()->uuid().end())
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

  meta_node.append_child("HistoryMaxItems").text().set(meta->history_max_items());
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
  for (const auto& icon : meta->icons()) {
    pugi::xml_node icon_node = icons_node.append_child("Icon");
    icon_node.append_child("UUID").text().set(
        base64_encode(icon->uuid().begin(), icon->uuid().end()).c_str());
    icon_node.append_child("Data").text().set(
        base64_encode(icon->data().begin(), icon->data().end()).c_str());

    if (kdbx41_) {
      if (!icon->name().empty())
        icon_node.append_child("Name").text().set(icon->name().c_str());
      if (icon->last_modification_time() != 0)
        icon_node.append_child("LastModificationTime")
            .text()
            .set(WriteDateTime(icon->last_modification_time()).c_str());
    }
  }

  // In KDBX 4 the binary attachments are stored in the KDBX inner header
  // instead of in the XML document. Their pool is filled by Export4().
  if (!kdbx4_) {
    uint32_t binary_id = 0;
    pugi::xml_node bins_node = meta_node.append_child("Binaries");
    for (const auto& binary : meta->binaries()) {
      pugi::xml_node bin_node = bins_node.append_child("Binary");
      bin_node.append_attribute("ID").set_value(binary_id);

      if (binary->data().is_protected()) {
        bin_node.append_attribute("Protected").set_value("True");
        // The obfuscated secure_string wipes itself; only the base64 copy of
        // the (obfuscated) payload must be released explicitly.
        secure_string obfuscated = obfuscator.Process(*binary->data());
        std::string encoded = base64_encode(obfuscated.str());
        bin_node.text().set(encoded.c_str());
        WipeBuffer(&encoded);
      } else {
        if (binary->compress()) {
          bin_node.append_attribute("Compressed").set_value("True");
          std::stringstream compressed_data;

          gzip_ostreambuf gzip_streambuf(compressed_data);
          std::ostream gzip_stream(&gzip_streambuf);
          std::copy(binary->data()->begin(), binary->data()->end(),
                    std::ostreambuf_iterator<char>(gzip_stream));
          gzip_stream.flush();

          std::string encoded = base64_encode(std::istreambuf_iterator<char>(compressed_data),
                                              std::istreambuf_iterator<char>());
          bin_node.text().set(encoded.c_str());
          WipeBuffer(&encoded);
          WipeStream(compressed_data);
        } else {
          std::string payload = (*binary->data()).str();
          std::string encoded = base64_encode(payload);
          bin_node.text().set(encoded.c_str());
          WipeBuffer(&payload);
          WipeBuffer(&encoded);
        }
      }

      binary_pool_.insert(std::make_pair(std::to_string(binary_id), binary));

      ++binary_id;
    }
  }

  pugi::xml_node data_node = meta_node.append_child("CustomData");
  for (const auto& field : meta->fields()) {
    pugi::xml_node item_node = data_node.append_child("Item");
    item_node.append_child("Key").text().set(field.key().c_str());
    item_node.append_child("Value").text().set(field.value().c_str());

    if (kdbx41_ && field.last_modification_time() != 0)
      item_node.append_child("LastModificationTime")
          .text()
          .set(WriteDateTime(field.last_modification_time()).c_str());
  }
}

std::shared_ptr<Entry> KdbxXml::ParseEntry(const pugi::xml_node& entry_node,
                                           std::array<uint8_t, 16>& entry_uuid,
                                           RandomObfuscator& obfuscator) {
  std::shared_ptr<Entry> entry = std::make_shared<Entry>();

  base64_decode<bounds_checked_iterator<std::array<uint8_t, 16>>, unsigned char>(
      entry_node.child_value("UUID"), bounds_checked(entry_uuid));

  entry->set_uuid(entry_uuid);
  entry->set_icon(entry_node.child("IconID").text().as_uint());
  entry->set_fg_color(entry_node.child_value("ForegroundColor"));
  entry->set_bg_color(entry_node.child_value("BackgroundColor"));
  entry->set_override_url(entry_node.child_value("OverrideURL"));
  entry->set_quality_check(entry_node.child("QualityCheck").text().as_bool(true));
  entry->set_tags(TagsFromXml(entry_node.child_value("Tags")));

  if (entry_node.child("PreviousParentGroup")) {
    std::array<uint8_t, 16> prev_parent = {{0}};
    base64_decode<bounds_checked_iterator<std::array<uint8_t, 16>>, unsigned char>(
        entry_node.child_value("PreviousParentGroup"), bounds_checked(prev_parent));
    entry->set_previous_parent_group(prev_parent);
  }

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
    entry->set_creation_time(ParseDateTime(times_node.child_value("CreationTime")));
    entry->set_modification_time(ParseDateTime(times_node.child_value("LastModificationTime")));
    entry->set_access_time(ParseDateTime(times_node.child_value("LastAccessTime")));
    entry->set_expiry_time(ParseDateTime(times_node.child_value("ExpiryTime")));
    entry->set_move_time(ParseDateTime(times_node.child_value("LocationChanged")));
    entry->set_expires(times_node.child("Expires").text().as_bool());
    entry->set_usage_count(times_node.child("UsageCount").text().as_uint());
  }

  // Auto type.
  pugi::xml_node autotype_node = entry_node.child("AutoType");
  if (autotype_node) {
    entry->auto_type().set_enabled(autotype_node.child("Enabled").text().as_bool());
    entry->auto_type().set_obfuscation(
        autotype_node.child("DataTransferObfuscation").text().as_uint());
    entry->auto_type().set_sequence(autotype_node.child_value("DefaultSequence"));

    for (pugi::xml_node ass_node = autotype_node.child("Association"); ass_node;
         ass_node = ass_node.next_sibling("Association")) {
      entry->auto_type().AddAssociation(ass_node.child_value("Window"),
                                        ass_node.child_value("KeystrokeSequence"));
    }
  }

  // Read string fields.
  for (pugi::xml_node str_node = entry_node.child("String"); str_node;
       str_node = str_node.next_sibling("String")) {
    std::string key = str_node.child_value("Key");
    protect<secure_string> val = ParseProtectedString(str_node, "Value", obfuscator);

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
          throw FormatError("Entry attachment refers to non-existing binary data.");
        }

        binary = it->second;
      } else {
        protect<secure_string> prot_val;

        if (bin_node.attribute("Protected").as_bool()) {
          std::string encoded = base64_decode(bin_node.text().as_string());
          prot_val = protect<secure_string>(obfuscator.Process(secure_string(encoded)), true);
          WipeBuffer(&encoded);
        } else {
          if (bin_node.attribute("Compressed").as_bool()) {
            std::string encoded = base64_decode(bin_node.text().as_string());
            std::stringstream raw_stream(encoded);
            gzip_istreambuf gzip_streambuf(raw_stream);
            std::istream gzip_stream(&gzip_streambuf);

            std::string decompressed = consume<std::string>(gzip_stream);
            prot_val = protect<secure_string>(secure_string(decompressed),
                                              bin_node.attribute("ProtectedInMemory").as_bool());
            WipeBuffer(&decompressed);
            WipeBuffer(&encoded);
            WipeStream(raw_stream);
          } else {
            std::string decoded = base64_decode(bin_node.text().as_string());
            prot_val = protect<secure_string>(secure_string(decoded),
                                              bin_node.attribute("ProtectedInMemory").as_bool());
            WipeBuffer(&decoded);
          }
        }

        binary = std::make_shared<Binary>(prot_val);
      }
    }

    std::shared_ptr<Entry::Attachment> attachment = std::make_shared<Entry::Attachment>();
    attachment->set_name(key);
    attachment->set_binary(binary);

    entry->AddAttachment(attachment);
  }

  // Read history entries.
  pugi::xml_node history_node = entry_node.child("History");
  if (history_node) {
    for (pugi::xml_node subentry_node = history_node.child("Entry"); subentry_node;
         subentry_node = subentry_node.next_sibling("Entry")) {
      std::array<uint8_t, 16> subentry_uuid = {0};
      entry->AddHistoryEntry(ParseEntry(subentry_node, subentry_uuid, obfuscator));
    }
  }

  return entry;
}

void KdbxXml::WriteEntry(pugi::xml_node& entry_node, RandomObfuscator& obfuscator,
                         const std::shared_ptr<Entry>& entry) {
  entry_node.append_child("UUID").text().set(
      base64_encode(entry->uuid().begin(), entry->uuid().end()).c_str());
  entry_node.append_child("IconID").text().set(entry->icon());
  entry_node.append_child("ForegroundColor").text().set(entry->fg_color().c_str());
  entry_node.append_child("BackgroundColor").text().set(entry->bg_color().c_str());
  entry_node.append_child("OverrideURL").text().set(entry->override_url().c_str());
  if (!entry->quality_check())
    entry_node.append_child("QualityCheck").text().set(false);
  entry_node.append_child("Tags").text().set(TagsToXml(entry->tags()).c_str());
  if (kdbx41_ && !IsZeroUuid(entry->previous_parent_group()))
    entry_node.append_child("PreviousParentGroup")
        .text()
        .set(base64_encode(entry->previous_parent_group().begin(),
                           entry->previous_parent_group().end())
                 .c_str());

  if (auto icon = entry->custom_icon().lock()) {
    entry_node.append_child("CustomIconUUID")
        .text()
        .set(base64_encode(icon->uuid().begin(), icon->uuid().end()).c_str());
  }

  pugi::xml_node times_node = entry_node.append_child("Times");
  times_node.append_child("CreationTime").text().set(WriteDateTime(entry->creation_time()).c_str());
  times_node.append_child("LastModificationTime")
      .text()
      .set(WriteDateTime(entry->modification_time()).c_str());
  times_node.append_child("LastAccessTime").text().set(WriteDateTime(entry->access_time()).c_str());
  times_node.append_child("ExpiryTime").text().set(WriteDateTime(entry->expiry_time()).c_str());
  times_node.append_child("LocationChanged").text().set(WriteDateTime(entry->move_time()).c_str());
  times_node.append_child("Expires").text().set(entry->expires());
  times_node.append_child("UsageCount").text().set(entry->usage_count());

  pugi::xml_node autotype_node = entry_node.append_child("AutoType");
  autotype_node.append_child("Enabled").text().set(entry->auto_type().enabled());
  autotype_node.append_child("DataTransferObfuscation")
      .text()
      .set(entry->auto_type().obfuscation());
  autotype_node.append_child("DefaultSequence").text().set(entry->auto_type().sequence().c_str());

  for (const auto& ass : entry->auto_type().associations()) {
    pugi::xml_node ass_node = autotype_node.append_child("Association");
    ass_node.append_child("Window").text().set(ass.window().c_str());
    ass_node.append_child("KeystrokeSequence").text().set(ass.sequence().c_str());
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

  for (const auto& field : entry->custom_fields()) {
    str_node = entry_node.append_child("String");
    str_node.append_child("Key").text().set(field.key().c_str());
    val_node = str_node.append_child("Value");
    WriteProtectedString(val_node, field.value(), obfuscator);
  }

  // Write binary fields.
  for (const auto& attachment : entry->attachments()) {
    pugi::xml_node bin_node = entry_node.append_child("Binary");
    bin_node.append_child("Key").text().set(attachment->name().c_str());

    bool found_in_pool = false;
    for (const auto& it : binary_pool_) {
      if (it.second == attachment->binary()) {
        bin_node.append_child("Value").append_attribute("Ref").set_value(it.first.c_str());
        found_in_pool = true;
        break;
      }
    }

    if (!found_in_pool) {
      // Attachment data is sensitive; wipe the transient copies.
      std::string payload = attachment->binary()->data().value().str();
      std::string encoded = base64_encode(payload);
      bin_node.append_child("Value").text().set(encoded.c_str());
      WipeBuffer(&payload);
      WipeBuffer(&encoded);
    }
  }

  // Write history entries.
  pugi::xml_node history_node = entry_node.append_child("History");
  for (const auto& histentry : entry->history()) {
    pugi::xml_node histentry_node = history_node.append_child("Entry");
    WriteEntry(histentry_node, obfuscator, histentry);
  }
}

std::shared_ptr<Group> KdbxXml::ParseGroup(const pugi::xml_node& group_node,
                                           RandomObfuscator& obfuscator) {
  std::shared_ptr<Group> group = std::make_shared<Group>();
  group_pool_.insert(std::make_pair(group_node.child_value("UUID"), group));

  std::array<uint8_t, 16> uuid = {0};
  base64_decode<bounds_checked_iterator<std::array<uint8_t, 16>>, unsigned char>(
      group_node.child_value("UUID"), bounds_checked(uuid));

  group->set_uuid(uuid);
  group->set_name(group_node.child_value("Name"));
  group->set_notes(group_node.child_value("Notes"));
  group->set_tags(TagsFromXml(group_node.child_value("Tags")));

  if (group_node.child("PreviousParentGroup")) {
    std::array<uint8_t, 16> prev_parent = {{0}};
    base64_decode<bounds_checked_iterator<std::array<uint8_t, 16>>, unsigned char>(
        group_node.child_value("PreviousParentGroup"), bounds_checked(prev_parent));
    group->set_previous_parent_group(prev_parent);
  }

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
    group->set_creation_time(ParseDateTime(times_node.child_value("CreationTime")));
    group->set_modification_time(ParseDateTime(times_node.child_value("LastModificationTime")));
    group->set_access_time(ParseDateTime(times_node.child_value("LastAccessTime")));
    group->set_expiry_time(ParseDateTime(times_node.child_value("ExpiryTime")));
    group->set_move_time(ParseDateTime(times_node.child_value("LocationChanged")));
    group->set_expires(times_node.child("Expires").text().as_bool());
    group->set_usage_count(times_node.child("UsageCount").text().as_uint());
  }

  group->set_expanded(group_node.child("IsExpanded").text().as_bool());
  group->set_default_autotype_sequence(group_node.child_value("DefaultAutoTypeSequence"));
  group->set_autotype(group_node.child("EnableAutoType").text().as_bool());
  group->set_search(group_node.child("EnableSearching").text().as_bool());

  base64_decode<bounds_checked_iterator<std::array<uint8_t, 16>>, unsigned char>(
      group_node.child_value("LastTopVisibleEntry"), bounds_checked(uuid));

  for (pugi::xml_node entry_node = group_node.child("Entry"); entry_node;
       entry_node = entry_node.next_sibling("Entry")) {
    std::array<uint8_t, 16> entry_uuid = {0};
    std::shared_ptr<Entry> entry = ParseEntry(entry_node, entry_uuid, obfuscator);
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

void KdbxXml::WriteGroup(pugi::xml_node& group_node, RandomObfuscator& obfuscator,
                         const std::shared_ptr<Group>& group) {
  group_node.append_child("UUID").text().set(
      base64_encode(group->uuid().begin(), group->uuid().end()).c_str());
  group_node.append_child("Name").text().set(group->name().c_str());
  group_node.append_child("Notes").text().set(group->notes().c_str());
  if (kdbx41_ && !IsZeroUuid(group->previous_parent_group()))
    group_node.append_child("PreviousParentGroup")
        .text()
        .set(base64_encode(group->previous_parent_group().begin(),
                           group->previous_parent_group().end())
                 .c_str());
  if (!group->tags().empty())
    group_node.append_child("Tags").text().set(TagsToXml(group->tags()).c_str());
  group_node.append_child("IconID").text().set(group->icon());

  if (auto icon = group->custom_icon().lock()) {
    group_node.append_child("CustomIconUUID")
        .text()
        .set(base64_encode(icon->uuid().begin(), icon->uuid().end()).c_str());
  }

  pugi::xml_node times_node = group_node.append_child("Times");
  times_node.append_child("CreationTime").text().set(WriteDateTime(group->creation_time()).c_str());
  times_node.append_child("LastModificationTime")
      .text()
      .set(WriteDateTime(group->modification_time()).c_str());
  times_node.append_child("LastAccessTime").text().set(WriteDateTime(group->access_time()).c_str());
  times_node.append_child("ExpiryTime").text().set(WriteDateTime(group->expiry_time()).c_str());
  times_node.append_child("LocationChanged").text().set(WriteDateTime(group->move_time()).c_str());
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

  for (const auto& entry : group->Entries()) {
    pugi::xml_node entry_node = group_node.append_child("Entry");
    WriteEntry(entry_node, obfuscator, entry);
  }

  for (const auto& subgroup : group->Groups()) {
    pugi::xml_node subgroup_node = group_node.append_child("Group");
    WriteGroup(subgroup_node, obfuscator, subgroup);
  }
}

void KdbxXml::Parse(std::istream& src, RandomObfuscator& obfuscator, Database& db) {
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

  for (pugi::xml_node object_node =
           kpf_node.child("Root").child("DeletedObjects").child("DeletedObject");
       object_node; object_node = object_node.next_sibling("DeletedObject")) {
    std::array<uint8_t, 16> uuid = {{0}};
    base64_decode<bounds_checked_iterator<std::array<uint8_t, 16>>, unsigned char>(
        object_node.child_value("UUID"), bounds_checked(uuid));
    meta->AddDeletedObject(
        Metadata::DeletedObject(uuid, ParseDateTime(object_node.child_value("DeletionTime"))));
  }

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
void KdbxXml::PrintXml(pugi::xml_document& doc) {
  static const char* kNodeTypeNames[] = {"null",  "document", "element", "pcdata",
                                         "cdata", "comment",  "pi",      "declaration"};

  struct XmlTreeWalker : pugi::xml_tree_walker {
  public:
    virtual bool for_each(pugi::xml_node& node) override {
      for (int i = 0; i < depth(); ++i)
        std::cout << "  ";

      std::cout << kNodeTypeNames[node.type()] << ": name=\"" << node.name() << "\"; value=\""
                << node.value() << "\"" << std::endl;
      return true;
    }
  };

  XmlTreeWalker walker;
  doc.traverse(walker);
}
#endif

void KdbxXml::Write(std::ostream& dst, RandomObfuscator& obfuscator, const Database& db) {
  pugi::xml_document doc;

  pugi::xml_node kpf_node = doc.append_child("KeePassFile");
  pugi::xml_node meta_node = kpf_node.append_child("Meta");
  pugi::xml_node root_node = kpf_node.append_child("Root");
  pugi::xml_node group_node = root_node.append_child("Group");

  // A freshly created database may lack metadata or a root group; export a
  // default placeholder in that case instead of dereferencing a null pointer.
  if (!db.meta()) {
    static const std::shared_ptr<Metadata> empty_meta = std::make_shared<Metadata>();
    WriteMeta(meta_node, obfuscator, empty_meta);
  } else {
    WriteMeta(meta_node, obfuscator, db.meta());

    if (!db.meta()->deleted_objects().empty()) {
      pugi::xml_node del_node = root_node.append_child("DeletedObjects");
      for (const auto& object : db.meta()->deleted_objects()) {
        pugi::xml_node object_node = del_node.append_child("DeletedObject");
        object_node.append_child("UUID").text().set(
            base64_encode(object.uuid().begin(), object.uuid().end()).c_str());
        object_node.append_child("DeletionTime")
            .text()
            .set(WriteDateTime(object.deletion_time()).c_str());
      }
    }
  }

  static const std::shared_ptr<Group> empty_root = std::make_shared<Group>();
  WriteGroup(group_node, obfuscator, db.root() ? db.root() : empty_root);

  doc.save(dst);
}

} // namespace keepass