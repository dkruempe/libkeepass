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

#include <pugixml.hpp>

#include "kdbx_xml_internal.hh"
#include "libkeepass/base64.hh"
#include "libkeepass/group.hh"
#include "libkeepass/icon.hh"
#include "libkeepass/iterator.hh"

namespace keepass {

std::shared_ptr<Group> KdbxXml::ParseGroup(const pugi::xml_node& group_node,
                                           RandomObfuscator& obfuscator, uint32_t depth) {
  // Budget the nesting depth and the total number of groups so that hostile
  // documents cannot force unbounded recursion or allocations.
  if (depth > resource_limits_.max_xml_depth)
    throw FormatError("Group nesting exceeds the configured depth limit.");
  if (groups_seen_ >= resource_limits_.max_groups)
    throw FormatError("Too many groups in KDBX XML.");
  ++groups_seen_;

  // Metadata-referenced groups (RecycleBinUUID, EntryTemplatesGroup) may have
  // been created as placeholders by GetGroup before the tree is parsed. Reuse
  // that instance so the metadata link stays valid; otherwise the parsed tree
  // group would differ from the group the metadata points to.
  std::shared_ptr<Group> group;
  auto pool_it = group_pool_.find(group_node.child_value("UUID"));
  if (pool_it == group_pool_.end()) {
    group = std::make_shared<Group>();
    group_pool_.insert(std::make_pair(group_node.child_value("UUID"), group));
  } else {
    group = pool_it->second;
  }

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
    group->AddGroup(ParseGroup(subgroup_node, obfuscator, depth + 1));
  }

  return group;
}

void KdbxXml::WriteGroup(pugi::xml_node& group_node, RandomObfuscator& obfuscator,
                         const std::shared_ptr<Group>& group) {
  group_node.append_child("UUID").text().set(
      base64_encode(group->uuid().begin(), group->uuid().end()).c_str());
  group_node.append_child("Name").text().set(group->name().c_str());
  group_node.append_child("Notes").text().set(group->notes().c_str());
  const auto& previous_parent_group = group->previous_parent_group();
  if (kdbx41_ && previous_parent_group.has_value() && !IsZeroUuid(previous_parent_group.value())) {
    group_node.append_child("PreviousParentGroup")
        .text()
        .set(base64_encode(previous_parent_group->begin(), previous_parent_group->end()).c_str());
  }
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

} // namespace keepass