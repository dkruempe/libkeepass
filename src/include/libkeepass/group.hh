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

/**
 * @file group.hh
 * @brief Type representing a KeePass group (a container for entries and subgroups).
 */

#pragma once
#include <ctime>
#include <memory>
#include <vector>

#include "entry.hh"
#include "libkeepass/export.hh"

namespace keepass {

class Icon;

/**
 * @brief A KeePass group (a folder) that contains entries and subgroups.
 *
 * A Group forms the hierarchical structure of a database. Every database has a
 * root group; groups can contain \ref Entry objects and nested groups.
 */
class LIBKEEPASS_API Group final {
private:
  std::array<uint8_t, 16> uuid_;
  uint32_t icon_ = 0;
  std::weak_ptr<Icon> custom_icon_;
  std::string name_;
  std::string notes_;
  std::time_t creation_time_ = 0;
  std::time_t modification_time_ = 0;
  std::time_t access_time_ = 0;
  std::time_t expiry_time_ = 0;
  std::time_t move_time_ = 0;
  uint16_t flags_ = 0;
  bool expires_ = false;
  bool expanded_ = false;
  uint32_t usage_count_ = 0;
  std::string default_autotype_sequence_;
  bool autotype_ = false;
  bool search_ = false;
  std::weak_ptr<Entry> last_visible_entry_;

  std::vector<std::shared_ptr<Group>> groups_;
  std::vector<std::shared_ptr<Entry>> entries_;

public:
  /// Creates an empty group.
  Group();

  /// Returns the group's unique identifier (UUID).
  const std::array<uint8_t, 16>& uuid() const { return uuid_; }

  /// Sets the group's unique identifier (UUID).
  void set_uuid(const std::array<uint8_t, 16>& uuid) { uuid_ = uuid; }

  /// Returns the index of the stock icon.
  uint32_t icon() const { return icon_; }

  /// Sets the index of the stock icon.
  void set_icon(const uint32_t& icon) { icon_ = icon; }

  /// Returns a weak reference to the custom icon (if any).
  std::weak_ptr<Icon> custom_icon() const { return custom_icon_; }

  /// Sets the custom icon.
  void set_custom_icon(std::weak_ptr<Icon> icon) { custom_icon_ = std::move(icon); }

  /// Returns the group name.
  const std::string& name() const { return name_; }

  /// Sets the group name.
  void set_name(const std::string& name) { name_ = name; }

  /// Returns the group notes.
  const std::string& notes() const { return notes_; }

  /// Sets the group notes.
  void set_notes(const std::string& notes) { notes_ = notes; }

  /// Returns the creation time.
  std::time_t creation_time() const { return creation_time_; }

  /// Sets the creation time.
  void set_creation_time(const std::time_t& time) { creation_time_ = time; }

  /// Returns the last modification time.
  std::time_t modification_time() const { return modification_time_; }

  /// Sets the last modification time.
  void set_modification_time(const std::time_t& time) { modification_time_ = time; }

  /// Returns the last access time.
  std::time_t access_time() const { return access_time_; }

  /// Sets the last access time.
  void set_access_time(const std::time_t& time) { access_time_ = time; }

  /// Returns the expiry time.
  std::time_t expiry_time() const { return expiry_time_; }

  /// Sets the expiry time.
  void set_expiry_time(const std::time_t& time) { expiry_time_ = time; }

  /// Returns the last move time.
  std::time_t move_time() const { return move_time_; }

  /// Sets the last move time.
  void set_move_time(const std::time_t& time) { move_time_ = time; }

  /// Returns the group flags.
  uint16_t flags() const { return flags_; }

  /// Sets the group flags.
  void set_flags(const uint16_t& flags) { flags_ = flags; }

  /// Returns whether the group expires.
  bool expires() const { return expires_; }

  /// Sets whether the group expires.
  void set_expires(bool expires) { expires_ = expires; }

  /// Returns whether the group is expanded in the UI.
  bool expanded() const { return expanded_; }

  /// Sets whether the group is expanded in the UI.
  void set_expanded(bool expanded) { expanded_ = expanded; }

  /// Returns the usage count.
  uint32_t usage_count() const { return usage_count_; }

  /// Sets the usage count.
  void set_usage_count(uint32_t usage_count) { usage_count_ = usage_count; }

  /// Returns the default auto-type sequence.
  const std::string& default_autotype_sequence() const { return default_autotype_sequence_; }

  /// Sets the default auto-type sequence.
  void set_default_autotype_sequence(std::string sequence) {
    default_autotype_sequence_ = std::move(sequence);
  }

  /// Returns whether auto-type is enabled for this group.
  bool autotype() const { return autotype_; }

  /// Sets whether auto-type is enabled for this group.
  void set_autotype(bool autotype) { autotype_ = autotype; }

  /// Returns whether search is enabled for this group.
  bool search() const { return search_; }

  /// Sets whether search is enabled for this group.
  void set_search(bool search) { search_ = search; }

  /// Returns a weak reference to the last visible entry.
  std::weak_ptr<Entry> last_visible_entry() const { return last_visible_entry_; }

  /// Sets the last visible entry.
  void set_last_visible_entry(std::weak_ptr<Entry> entry) {
    last_visible_entry_ = std::move(entry);
  }

  /// Returns the list of subgroups.
  const std::vector<std::shared_ptr<Group>>& Groups() const;

  /// Returns the list of entries in this group.
  const std::vector<std::shared_ptr<Entry>>& Entries() const;

  /// Adds a subgroup to this group.
  void AddGroup(const std::shared_ptr<Group>& group);

  /// Adds an entry to this group.
  void AddEntry(const std::shared_ptr<Entry>& entry);

  /// Returns whether the group contains any non-metadata entries.
  bool HasNonMetaEntries() const;

  /// Serializes the group to a JSON object.
  std::string ToJson() const;

  /// Equality comparison.
  bool operator==(const Group& other) const;

  /// Inequality comparison.
  bool operator!=(const Group& other) const;
};

} // namespace keepass
