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

#include <array>
#include <cassert>
#include <sstream>
#include <string>

#include <pugixml.hpp>

#include "kdbx_xml_internal.hh"
#include "libkeepass/base64.hh"
#include "libkeepass/detail/secure_io.hh"
#include "libkeepass/entry.hh"
#include "libkeepass/exception.hh"
#include "libkeepass/icon.hh"
#include "libkeepass/io.hh"
#include "libkeepass/iterator.hh"
#include "libkeepass/random.hh"
#include "libkeepass/secure.hh"
#include "libkeepass/stream.hh"

namespace keepass {

// WipeStream/WipeBuffer are shared with the other format codecs to keep the
// sensitive-data wiping logic in one place; see detail/secure_io.hh.
using keepass::detail::WipeBuffer;
using keepass::detail::WipeStream;

protect<secure_string> KdbxXml::ParseProtectedString(const pugi::xml_node& node, const char* name,
                                                     RandomObfuscator& obfuscator) const {
  pugi::xml_node val_node = node.child(name);
  if (val_node) {
    bool prot = val_node.attribute("Protected").as_bool();
    if (prot) {
      // The decoded value length is attacker-controlled via the base64 text;
      // reject oversized fields before allocating and decoding them.
      if (ExceedsBase64DecodedSize(val_node.text().as_string(),
                                   resource_limits_.max_string_field_bytes))
        throw FormatError("Protected string field exceeds the configured size limit.");

      std::string val = base64_decode(val_node.text().as_string());
      if (!val.empty()) {
        if (val.size() > resource_limits_.max_string_field_bytes)
          throw FormatError("Protected string field exceeds the configured size limit.");

        secure_string decrypted = obfuscator.Process(secure_string(val));
        secure_zero(val.data(), val.size());
        return {std::move(decrypted), true};
      }
    }

    if (ExceedsTextSize(val_node.text().as_string(), resource_limits_.max_string_field_bytes))
      throw FormatError("String field exceeds the configured size limit.");

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

std::shared_ptr<Entry> KdbxXml::ParseEntry(const pugi::xml_node& entry_node,
                                           std::array<uint8_t, 16>& entry_uuid,
                                           RandomObfuscator& obfuscator) {
  // Budget the total number of entries (including history entries) so that a
  // hostile document cannot force unbounded per-entry allocations.
  if (entries_seen_ >= resource_limits_.max_entries)
    throw FormatError("Too many entries in KDBX XML.");
  ++entries_seen_;

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
          if (ExceedsBase64DecodedSize(bin_node.text().as_string(),
                                       resource_limits_.max_binary_bytes))
            throw FormatError("Binary attachment exceeds the configured size limit.");

          std::string encoded = base64_decode(bin_node.text().as_string());
          prot_val = protect<secure_string>(obfuscator.Process(secure_string(encoded)), true);
          WipeBuffer(&encoded);
        } else {
          if (bin_node.attribute("Compressed").as_bool()) {
            if (ExceedsBase64DecodedSize(bin_node.text().as_string(),
                                         resource_limits_.max_binary_bytes))
              throw FormatError("Compressed binary attachment exceeds the configured size limit.");

            std::string encoded = base64_decode(bin_node.text().as_string());
            std::stringstream raw_stream(encoded);
            gzip_istreambuf gzip_streambuf(raw_stream, resource_limits_);
            std::istream gzip_stream(&gzip_streambuf);

            std::string decompressed = consume<std::string>(gzip_stream);
            prot_val = protect<secure_string>(secure_string(decompressed),
                                              bin_node.attribute("ProtectedInMemory").as_bool());
            WipeBuffer(&decompressed);
            WipeBuffer(&encoded);
            WipeStream(raw_stream);
          } else {
            if (ExceedsBase64DecodedSize(bin_node.text().as_string(),
                                         resource_limits_.max_binary_bytes))
              throw FormatError("Binary attachment exceeds the configured size limit.");

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
      if (history_items_seen_ >= resource_limits_.max_history_items)
        throw FormatError("Too many history items in KDBX XML.");
      ++history_items_seen_;

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
  const auto& previous_parent_group = entry->previous_parent_group();
  if (kdbx41_ && previous_parent_group.has_value() && !IsZeroUuid(previous_parent_group.value())) {
    entry_node.append_child("PreviousParentGroup")
        .text()
        .set(base64_encode(previous_parent_group->begin(), previous_parent_group->end()).c_str());
  }

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

} // namespace keepass