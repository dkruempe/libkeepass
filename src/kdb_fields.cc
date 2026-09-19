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

#include "libkeepass/kdb.hh"

#include <algorithm>
#include <cassert>
#include <sstream>

#include "kdb_internal.hh"
#include "libkeepass/detail/secure_io.hh"
#include "libkeepass/entry.hh"
#include "libkeepass/exception.hh"
#include "libkeepass/group.hh"
#include "libkeepass/io.hh"
#include "libkeepass/secure.hh"

namespace keepass {

// WipeBuffer is shared with the other format codecs to keep the sensitive-data
// wiping logic in one place; see detail/secure_io.hh.
using keepass::detail::WipeBuffer;

std::shared_ptr<Group> KdbFile::ReadGroup(std::istream& src, uint32_t& id, uint16_t& level) {
  std::shared_ptr<Group> group = std::make_shared<Group>();

  while (src.good()) {
    auto field_type = consume<uint16_t>(src);
    auto field_size = consume<uint32_t>(src);

    // Reject field sizes that cannot fit into the remaining stream instead of
    // looping up to the declared length.
    if (static_cast<uint64_t>(field_size) >
        static_cast<uint64_t>(std::max<std::streamsize>(0, RemainingBytes(src))))
      throw FormatError("Corrupt group field size in KDB database.");

    // Read the complete group field into a separate buffer before parsing.
    // This is to guard against reading outside the field as well as for making
    // sure to read the complete field regardless of how much of it that we
    // parse.
    std::stringstream field;
    std::generate_n(std::ostreambuf_iterator<char>(field), field_size,
                    [&src]() { return static_cast<char>(src.get()); });
    if (!src.good())
      throw IoError("Read error.");

    assert(field.str().size() == field_size);

    // Parse the group field.
    switch (static_cast<KdbGroupFieldType>(field_type)) {
    case KdbGroupFieldType::kEmpty:
      break;
    case KdbGroupFieldType::kId:
      id = consume<uint32_t>(field);
      break;
    case KdbGroupFieldType::kName:
      group->set_name(consume<std::string>(field));
      break;
    case KdbGroupFieldType::kCreationTime:
      group->set_creation_time(consume<KdbTime>(field).ToTime());
      break;
    case KdbGroupFieldType::kModificationTime:
      group->set_modification_time(consume<KdbTime>(field).ToTime());
      break;
    case KdbGroupFieldType::kAccessTime:
      group->set_access_time(consume<KdbTime>(field).ToTime());
      break;
    case KdbGroupFieldType::kExpiryTime:
      group->set_expiry_time(consume<KdbTime>(field).ToTime());
      break;
    case KdbGroupFieldType::kIcon:
      group->set_icon(consume<uint32_t>(field));
      break;
    case KdbGroupFieldType::kLevel:
      level = consume<uint16_t>(field);
      break;
    case KdbGroupFieldType::kFlags:
      group->set_flags(consume<uint16_t>(field));
      break;
    case KdbGroupFieldType::kEnd:
      return group;
    default:
      throw FormatError("Illegal group field in KDB.");
      break;
    }
  }

  throw FormatError("Missing EOF in KDB group.");
  return group;
}

void KdbFile::WriteGroup(std::ostream& dst, const std::shared_ptr<Group>& group, uint32_t group_id,
                         uint16_t level) {
  conserve<uint16_t>(dst, static_cast<uint16_t>(KdbGroupFieldType::kId));
  conserve<uint32_t>(dst, 4);
  conserve<uint32_t>(dst, group_id);

  conserve<uint16_t>(dst, static_cast<uint16_t>(KdbGroupFieldType::kName));
  conserve<uint32_t>(dst, static_cast<uint32_t>(group->name().size()) + 1);
  conserve<std::string>(dst, group->name());

  KdbTime creation_time(group->creation_time());
  conserve<uint16_t>(dst, static_cast<uint16_t>(KdbGroupFieldType::kCreationTime));
  conserve<uint32_t>(dst, sizeof(KdbTime));
  conserve<KdbTime>(dst, creation_time);

  KdbTime modification_time(group->modification_time());
  conserve<uint16_t>(dst, static_cast<uint16_t>(KdbGroupFieldType::kModificationTime));
  conserve<uint32_t>(dst, sizeof(KdbTime));
  conserve<KdbTime>(dst, modification_time);

  KdbTime access_time(group->access_time());
  conserve<uint16_t>(dst, static_cast<uint16_t>(KdbGroupFieldType::kAccessTime));
  conserve<uint32_t>(dst, sizeof(KdbTime));
  conserve<KdbTime>(dst, access_time);

  KdbTime expiry_time(group->expiry_time());
  conserve<uint16_t>(dst, static_cast<uint16_t>(KdbGroupFieldType::kExpiryTime));
  conserve<uint32_t>(dst, sizeof(KdbTime));
  conserve<KdbTime>(dst, expiry_time);

  conserve<uint16_t>(dst, static_cast<uint16_t>(KdbGroupFieldType::kIcon));
  conserve<uint32_t>(dst, 4);
  conserve<uint32_t>(dst, group->icon());

  conserve<uint16_t>(dst, static_cast<uint16_t>(KdbGroupFieldType::kLevel));
  conserve<uint32_t>(dst, 2);
  conserve<uint16_t>(dst, level);

  conserve<uint16_t>(dst, static_cast<uint16_t>(KdbGroupFieldType::kFlags));
  conserve<uint32_t>(dst, 2);
  conserve<uint16_t>(dst, group->flags());

  conserve<uint16_t>(dst, static_cast<uint16_t>(KdbGroupFieldType::kEnd));
  conserve<uint32_t>(dst, 0);
}

std::shared_ptr<Entry> KdbFile::ReadEntry(std::istream& src, uint32_t& group_id) {
  std::shared_ptr<Entry> entry = std::make_shared<Entry>();
  std::shared_ptr<Entry::Attachment> attachment;

  while (src.good()) {
    auto field_type = consume<uint16_t>(src);
    auto field_size = consume<uint32_t>(src);

    // Reject field sizes that cannot fit into the remaining stream instead of
    // looping up to the declared length.
    if (static_cast<uint64_t>(field_size) >
        static_cast<uint64_t>(std::max<std::streamsize>(0, RemainingBytes(src))))
      throw FormatError("Corrupt entry field size in KDB database.");

    // Read the complete entry field into a separate buffer before parsing.
    // This is to guard against reading outside the field as well as for making
    // sure to read the complete field regardless of how much of it that we
    // parse.
    std::stringstream field;
    std::generate_n(std::ostreambuf_iterator<char>(field), field_size,
                    [&src]() { return static_cast<char>(src.get()); });
    if (!src.good())
      throw IoError("Read error.");

    assert(field.str().size() == field_size);

    // Parse the entry field.
    switch (static_cast<KdbEntryFieldType>(field_type)) {
    case KdbEntryFieldType::kEmpty:
      break;
    case KdbEntryFieldType::kUuid:
      entry->set_uuid(consume<std::array<uint8_t, 16>>(field));
      break;
    case KdbEntryFieldType::kGroupId:
      group_id = consume<uint32_t>(field);
      break;
    case KdbEntryFieldType::kIcon:
      entry->set_icon(consume<uint32_t>(field));
      break;
    case KdbEntryFieldType::kTitle:
      entry->set_title(protect<secure_string>(secure_string(consume<std::string>(field)), false));
      break;
    case KdbEntryFieldType::kUrl:
      entry->set_url(protect<secure_string>(secure_string(consume<std::string>(field)), false));
      break;
    case KdbEntryFieldType::kUsername:
      entry->set_username(
          protect<secure_string>(secure_string(consume<std::string>(field)), false));
      break;
    case KdbEntryFieldType::kPassword: {
      std::string password = consume<std::string>(field);
      entry->set_password(protect<secure_string>(secure_string(password), false));
      WipeBuffer(&password);
      break;
    }
    case KdbEntryFieldType::kNotes:
      entry->set_notes(protect<secure_string>(secure_string(consume<std::string>(field)), false));
      break;
    case KdbEntryFieldType::kCreationTime:
      entry->set_creation_time(consume<KdbTime>(field).ToTime());
      break;
    case KdbEntryFieldType::kModificationTime:
      entry->set_modification_time(consume<KdbTime>(field).ToTime());
      break;
    case KdbEntryFieldType::kAccessTime:
      entry->set_access_time(consume<KdbTime>(field).ToTime());
      break;
    case KdbEntryFieldType::kExpiryTime:
      entry->set_expiry_time(consume<KdbTime>(field).ToTime());
      break;
    case KdbEntryFieldType::kAttachmentName: {
      std::string name = consume<std::string>(field);
      // Keepass 1.x seems to add attachment name fields with only a
      // NULL-character when unused.
      if (name.empty())
        continue;

      if (!attachment)
        attachment = std::make_shared<Entry::Attachment>();
      attachment->set_name(name);
      break;
    }
    case KdbEntryFieldType::kAttachmentData:
      if (field_size > 0) {
        if (!attachment)
          attachment = std::make_shared<Entry::Attachment>();

        std::vector<char> data = consume<std::vector<char>>(field);
        std::string payload(data.begin(), data.end());
        std::shared_ptr<Binary> binary =
            std::make_shared<Binary>(protect<secure_string>(secure_string(payload), false));
        attachment->set_binary(binary);
        WipeBuffer(&payload);
        WipeBuffer(&data);
      }
      break;
    case KdbEntryFieldType::kEnd:
      if (attachment)
        entry->AddAttachment(attachment);
      return entry;
    default:
      throw FormatError("Illegal entry field in KDB.");
      break;
    }
  }

  throw FormatError("Missing EOF in KDB entry.");
  return entry;
}

void KdbFile::WriteEntry(std::ostream& dst, const std::shared_ptr<Entry>& entry,
                         uint32_t group_id) {
  conserve<uint16_t>(dst, static_cast<uint16_t>(KdbEntryFieldType::kUuid));
  conserve<uint32_t>(dst, 16);
  conserve<std::array<uint8_t, 16>>(dst, entry->uuid());

  conserve<uint16_t>(dst, static_cast<uint16_t>(KdbEntryFieldType::kGroupId));
  conserve<uint32_t>(dst, 4);
  conserve<uint32_t>(dst, group_id);

  conserve<uint16_t>(dst, static_cast<uint16_t>(KdbEntryFieldType::kIcon));
  conserve<uint32_t>(dst, 4);
  conserve<uint32_t>(dst, entry->icon());

  conserve<uint16_t>(dst, static_cast<uint16_t>(KdbEntryFieldType::kTitle));
  conserve<uint32_t>(dst, static_cast<uint32_t>(entry->title()->size()) + 1);
  conserve<std::string>(dst, entry->title().value().str());

  conserve<uint16_t>(dst, static_cast<uint16_t>(KdbEntryFieldType::kUrl));
  conserve<uint32_t>(dst, static_cast<uint32_t>(entry->url()->size()) + 1);
  conserve<std::string>(dst, entry->url().value().str());

  conserve<uint16_t>(dst, static_cast<uint16_t>(KdbEntryFieldType::kUsername));
  conserve<uint32_t>(dst, static_cast<uint32_t>(entry->username()->size()) + 1);
  conserve<std::string>(dst, entry->username().value().str());

  conserve<uint16_t>(dst, static_cast<uint16_t>(KdbEntryFieldType::kPassword));
  conserve<uint32_t>(dst, static_cast<uint32_t>(entry->password()->size()) + 1);
  std::string password = entry->password().value().str();
  conserve<std::string>(dst, password);
  WipeBuffer(&password);

  conserve<uint16_t>(dst, static_cast<uint16_t>(KdbEntryFieldType::kNotes));
  conserve<uint32_t>(dst, static_cast<uint32_t>(entry->notes()->size()) + 1);
  conserve<std::string>(dst, entry->notes().value().str());

  KdbTime creation_time(entry->creation_time());
  conserve<uint16_t>(dst, static_cast<uint16_t>(KdbEntryFieldType::kCreationTime));
  conserve<uint32_t>(dst, sizeof(KdbTime));
  conserve<KdbTime>(dst, creation_time);

  KdbTime modification_time(entry->modification_time());
  conserve<uint16_t>(dst, static_cast<uint16_t>(KdbEntryFieldType::kModificationTime));
  conserve<uint32_t>(dst, sizeof(KdbTime));
  conserve<KdbTime>(dst, modification_time);

  KdbTime access_time(entry->access_time());
  conserve<uint16_t>(dst, static_cast<uint16_t>(KdbEntryFieldType::kAccessTime));
  conserve<uint32_t>(dst, sizeof(KdbTime));
  conserve<KdbTime>(dst, access_time);

  KdbTime expiry_time(entry->expiry_time());
  conserve<uint16_t>(dst, static_cast<uint16_t>(KdbEntryFieldType::kExpiryTime));
  conserve<uint32_t>(dst, sizeof(KdbTime));
  conserve<KdbTime>(dst, expiry_time);

  if (entry->HasAttachment()) {
    assert(entry->attachments().size() == 1);
    std::shared_ptr<Entry::Attachment> attachment = entry->attachments()[0];
    if (!attachment->name().empty()) {
      conserve<uint16_t>(dst, static_cast<uint16_t>(KdbEntryFieldType::kAttachmentName));
      conserve<uint32_t>(dst, static_cast<uint32_t>(attachment->name().size()) + 1);
      conserve<std::string>(dst, attachment->name());
    }

    if (!attachment->binary()->Empty()) {
      conserve<uint16_t>(dst, static_cast<uint16_t>(KdbEntryFieldType::kAttachmentData));
      conserve<uint32_t>(dst, static_cast<uint32_t>(attachment->binary()->Size()));

      // Attachment data is sensitive; wipe the transient copy.
      std::vector<char> data;
      data.resize(attachment->binary()->Size());
      std::copy(attachment->binary()->data()->begin(), attachment->binary()->data()->end(),
                data.begin());
      conserve<std::vector<char>>(dst, data);
      WipeBuffer(&data);
    }
  }

  conserve<uint16_t>(dst, static_cast<uint16_t>(KdbEntryFieldType::kEnd));
  conserve<uint32_t>(dst, 0);
}

} // namespace keepass