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
#include <sstream>
#include <vector>

#include <pugixml.hpp>

#include "kdbx_xml_internal.hh"
#include "libkeepass/base64.hh"
#include "libkeepass/detail/secure_io.hh"
#include "libkeepass/exception.hh"
#include "libkeepass/icon.hh"
#include "libkeepass/io.hh"
#include "libkeepass/iterator.hh"
#include "libkeepass/metadata.hh"
#include "libkeepass/random.hh"
#include "libkeepass/secure.hh"
#include "libkeepass/stream.hh"

namespace keepass {

// WipeStream/WipeBuffer are shared with the other format codecs to keep the
// sensitive-data wiping logic in one place; see detail/secure_io.hh.
using keepass::detail::WipeBuffer;
using keepass::detail::WipeStream;

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
      if (ExceedsBase64DecodedSize(icon_node.child_value("Data"),
                                   resource_limits_.max_binary_bytes))
        throw FormatError("Custom icon exceeds the configured size limit.");

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
      if (icon_node.child("LastModificationTime"))
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
        if (ExceedsBase64DecodedSize(bin_node.text().as_string(),
                                     resource_limits_.max_binary_bytes))
          throw FormatError("Binary attachment exceeds the configured size limit.");

        std::string encoded = base64_decode(bin_node.text().as_string());
        data = protect<secure_string>(obfuscator.Process(secure_string(encoded)), true);
        WipeBuffer(&encoded);
      } else {
        if (bin_node.attribute("Compressed").as_bool()) {
          compressed = true;
          if (ExceedsBase64DecodedSize(bin_node.text().as_string(),
                                       resource_limits_.max_binary_bytes))
            throw FormatError("Compressed binary attachment exceeds the configured size limit.");

          std::string encoded = base64_decode(bin_node.text().as_string());
          std::stringstream raw_stream(encoded);
          gzip_istreambuf gzip_streambuf(raw_stream, resource_limits_);
          std::istream gzip_stream(&gzip_streambuf);

          // The gzip streambuf enforces the decompressed size budget while
          // inflating; the decoded payload bounds the compressed side above.
          std::string decompressed = consume<std::string>(gzip_stream);
          data = protect<secure_string>(secure_string(decompressed),
                                        bin_node.attribute("ProtectedInMemory").as_bool());
          WipeBuffer(&decompressed);
          WipeBuffer(&encoded);
          WipeStream(raw_stream);
        } else {
          if (ExceedsBase64DecodedSize(bin_node.text().as_string(),
                                       resource_limits_.max_binary_bytes))
            throw FormatError("Binary attachment exceeds the configured size limit.");

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
      if (item_node.child("LastModificationTime"))
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
      const auto& mod_time = icon->last_modification_time();
      if (mod_time.has_value()) {
        icon_node.append_child("LastModificationTime")
            .text()
            .set(WriteDateTime(mod_time.value()).c_str());
      }
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

    const auto& mod_time = field.last_modification_time();
    if (kdbx41_ && mod_time.has_value()) {
      item_node.append_child("LastModificationTime")
          .text()
          .set(WriteDateTime(mod_time.value()).c_str());
    }
  }
}

} // namespace keepass