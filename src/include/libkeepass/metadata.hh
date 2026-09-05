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
 * @file metadata.hh
 * @brief Database metadata such as name, memory protection, binaries and icons.
 */

#pragma once
#include <ctime>
#include <memory>
#include <string>
#include <vector>

#include "binary.hh"
#include "icon.hh"
#include "libkeepass/export.hh"
#include "temporal.hh"

namespace keepass {

class Group;

/**
 * @brief Metadata describing a KeePass database.
 *
 * Metadata stores database-level information that is independent of the actual
 * entry and group hierarchy: the generator application, database name and
 * description, memory protection settings, recycle bin, custom binaries and
 * icons, and arbitrary custom fields.
 */
class LIBKEEPASS_API Metadata final {
public:
  /**
   * @brief Flags which fields get cleared from memory when read or written.
   */
  class MemoryProtection final {
  private:
    bool title_ = false;
    bool username_ = false;
    bool password_ = true;
    bool url_ = false;
    bool notes_ = false;

  public:
    /// Returns whether the title is memory-protected.
    bool title() const { return title_; }

    /// Sets whether the title is memory-protected.
    void set_title(bool title) { title_ = title; }

    /// Returns whether the username is memory-protected.
    bool username() const { return username_; }

    /// Sets whether the username is memory-protected.
    void set_username(bool username) { username_ = username; }

    /// Returns whether the password is memory-protected.
    bool password() const { return password_; }

    /// Sets whether the password is memory-protected.
    void set_password(bool password) { password_ = password; }

    /// Returns whether the URL is memory-protected.
    bool url() const { return url_; }

    /// Sets whether the URL is memory-protected.
    void set_url(bool url) { url_ = url; }

    /// Returns whether the notes are memory-protected.
    bool notes() const { return notes_; }

    /// Sets whether the notes are memory-protected.
    void set_notes(bool notes) { notes_ = notes; }
  };

  /**
   * @brief An arbitrary metadata key/value field.
   */
  class Field final {
  private:
    std::string key_;
    std::string value_;

  public:
    /// Creates a metadata field with the given key and value.
    Field(std::string key, std::string value) : key_(std::move(key)), value_(std::move(value)) {}

    /// Copy constructor.
    Field(const Field& other) {
      key_ = other.key_;
      value_ = other.value_;
    }

    /// Move constructor.
    Field(Field&& other) noexcept {
      key_ = std::move(other.key_);
      value_ = std::move(other.value_);
    }

    /// Returns the field key.
    const std::string& key() const { return key_; }

    /// Returns the field value.
    const std::string& value() const { return value_; }

    /// Copy assignment.
    Field& operator=(const Field& other) = default;

    /// Move assignment.
    Field& operator=(Field&& other) noexcept {
      key_ = std::move(other.key_);
      value_ = std::move(other.value_);
      return *this;
    }
  };

private:
  std::string generator_;
  temporal<std::string> database_name_;
  temporal<std::string> database_desc_;
  temporal<std::string> default_username_;
  uint32_t maintenance_hist_days_ = 365;
  std::string database_color_;
  std::time_t master_key_changed_ = 0;
  int64_t master_key_change_rec_ = -1;
  int64_t master_key_change_force_ = -1;
  MemoryProtection memory_protection_;
  std::shared_ptr<Group> recycle_bin_;
  std::time_t recycle_bin_changed_;
  std::shared_ptr<Group> entry_templates_;
  std::time_t entry_templates_changed_;
  int32_t history_max_items_ = -1;
  int64_t history_max_size_ = -1;
  std::weak_ptr<Group> last_selected_group_;
  std::weak_ptr<Group> last_visible_group_;

  std::vector<std::shared_ptr<Binary>> binaries_;
  std::vector<std::shared_ptr<Icon>> icons_;
  std::vector<Field> fields_;

public:
  /// Returns the name of the application that generated the database.
  const std::string& generator() const { return generator_; }

  /// Sets the name of the application that generated the database.
  void set_generator(const std::string& generator) { generator_ = generator; }

  /// Returns the database name (with change timestamp).
  const temporal<std::string>& database_name() const { return database_name_; }

  /// Sets the database name.
  void set_database_name(const temporal<std::string>& name) { database_name_ = name; }

  /// Returns the database description (with change timestamp).
  const temporal<std::string>& database_desc() const { return database_desc_; }

  /// Sets the database description.
  void set_database_desc(const temporal<std::string>& desc) { database_desc_ = desc; }

  /// Returns the default username used for new entries.
  const temporal<std::string>& default_username() const { return default_username_; }

  /// Sets the default username used for new entries.
  void set_default_username(const temporal<std::string>& username) { default_username_ = username; }

  /// Returns the number of days to keep maintenance history.
  uint32_t maintenance_hist_days() const { return maintenance_hist_days_; }

  /// Sets the number of days to keep maintenance history.
  void set_maintenance_hist_days(uint32_t days) { maintenance_hist_days_ = days; }

  /// Returns the database color.
  const std::string& database_color() const { return database_color_; }

  /// Sets the database color.
  void set_database_color(const std::string& color) { database_color_ = color; }

  /// Returns the time the master key was last changed.
  std::time_t master_key_changed() const { return master_key_changed_; }

  /// Sets the time the master key was last changed.
  void set_master_key_changed(std::time_t time) { master_key_changed_ = time; }

  /// Returns days before a master key change is recommended.
  int64_t master_key_change_rec() const { return master_key_change_rec_; }

  /// Sets days before a master key change is recommended.
  void set_master_key_change_rec(int64_t rec) { master_key_change_rec_ = rec; }

  /// Returns days before a master key change is forced.
  int64_t master_key_change_force() const { return master_key_change_force_; }

  /// Sets days before a master key change is forced.
  void set_master_key_change_force(int64_t force) { master_key_change_force_ = force; }

  /// Returns the memory protection settings.
  MemoryProtection& memory_protection() { return memory_protection_; }

  /// Returns the recycle bin group.
  std::shared_ptr<Group> recycle_bin() const { return recycle_bin_; }

  /// Sets the recycle bin group.
  void set_recycle_bin(std::shared_ptr<Group> bin) { recycle_bin_ = std::move(bin); }

  /// Returns when the recycle bin was last changed.
  std::time_t recycle_bin_changed() const { return recycle_bin_changed_; }

  /// Sets when the recycle bin was last changed.
  void set_recycle_bin_changed(std::time_t time) { recycle_bin_changed_ = time; }

  /// Returns the entry templates group.
  std::shared_ptr<Group> entry_templates() const { return entry_templates_; }

  /// Sets the entry templates group.
  void set_entry_templates(std::shared_ptr<Group> entry_templates) {
    entry_templates_ = std::move(entry_templates);
  }

  /// Returns when the entry templates were last changed.
  std::time_t entry_templates_changed() const { return entry_templates_changed_; }

  /// Sets when the entry templates were last changed.
  void set_entry_templates_changed(std::time_t time) { entry_templates_changed_ = time; }

  /// Returns the maximum number of history items kept per entry.
  int32_t history_max_items() const { return history_max_items_; }

  /// Sets the maximum number of history items kept per entry.
  void set_history_max_items(int32_t max) { history_max_items_ = max; }

  /// Returns the maximum total size of an entry's history.
  int64_t history_max_size() const { return history_max_size_; }

  /// Sets the maximum total size of an entry's history.
  void set_history_max_size(int64_t max) { history_max_size_ = max; }

  /// Returns the last selected group.
  std::weak_ptr<Group> last_selected_group() const { return last_selected_group_; }

  /// Sets the last selected group.
  void set_last_selected_group(std::weak_ptr<Group> group) {
    last_selected_group_ = std::move(group);
  }

  /// Returns the last visible group.
  std::weak_ptr<Group> last_visible_group() const { return last_visible_group_; }

  /// Sets the last visible group.
  void set_last_visible_group(std::weak_ptr<Group> group) {
    last_visible_group_ = std::move(group);
  }

  /// Returns the list of custom binaries.
  const std::vector<std::shared_ptr<Binary>>& binaries() const { return binaries_; }

  /// Returns the list of custom icons.
  const std::vector<std::shared_ptr<Icon>>& icons() const { return icons_; }

  /// Returns the list of arbitrary metadata fields.
  const std::vector<Field>& fields() const { return fields_; }

  /// Adds a custom binary to the metadata.
  void AddBinary(const std::shared_ptr<Binary>& binary);

  /// Adds a custom icon to the metadata.
  void AddIcon(const std::shared_ptr<Icon>& icon);

  /// Adds an arbitrary metadata field.
  void AddField(const std::string& key, const std::string& value);
};

} // namespace keepass
