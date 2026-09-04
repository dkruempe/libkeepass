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
 * @file entry.hh
 * @brief Type representing a single KeePass entry.
 */

#pragma once
#include <ctime>
#include <memory>
#include <string>
#include <vector>

#include "binary.hh"
#include "libkeepass/export.hh"
#include "security.hh"
#include "util.hh"

namespace keepass {

class Icon;

/**
 * @brief A single KeePass entry (a username/password record).
 *
 * An Entry stores the standard fields of a password record (title, username,
 * password, url, notes), timestamps, custom fields, attachments, auto-type
 * configuration, and an entry history. Passwords and other sensitive fields are
 * held in a memory-zeroing \ref protect wrapper.
 */
class LIBKEEPASS_API Entry final {
public:
  /**
   * @brief A file attachment of an entry.
   *
   * Associates a name with a binary payload.
   */
  class LIBKEEPASS_API Attachment final {
  private:
    std::string name_;
    std::shared_ptr<Binary> binary_;

  public:
    /// Returns the attachment name.
    const std::string &name() const { return name_; }

    /// Sets the attachment name.
    void set_name(const std::string &name) { name_ = name; }

    /// Returns the attachment binary payload.
    std::shared_ptr<Binary> binary() const { return binary_; }

    /// Sets the attachment binary payload.
    void set_binary(std::shared_ptr<Binary> binary) { binary_ = std::move(binary); }

    /// Serializes the attachment to a JSON fragment.
    std::string ToJson() const;

    /// Equality comparison.
    bool operator==(const Attachment &other) const {
      return name_ == other.name_ && indirect_equal(binary_, other.binary_);
    }

    /// Inequality comparison.
    bool operator!=(const Attachment &other) const { return !(*this == other); }
  };

  /**
   * @brief Keystroke-sending (auto-type) configuration for an entry.
   */
  class AutoType final {
  public:
    /**
     * @brief Association between a target window and a keystroke sequence.
     */
    class Association final {
    private:
      std::string window_;
      std::string sequence_;

    public:
      /// Creates an association for the given window and sequence.
      Association(std::string window, std::string sequence)
          : window_(std::move(window)), sequence_(std::move(sequence)) {}

      /// Returns the target window title.
      const std::string& window() const { return window_; }

      /// Returns the keystroke sequence sent to the window.
      const std::string& sequence() const { return sequence_; }

      /// Equality comparison.
      bool operator==(const Association &other) const {
        return window_ == other.window_ && sequence_ == other.sequence_;
      }

      /// Inequality comparison.
      bool operator!=(const Association &other) const {
        return !(*this == other);
      }
    };

  private:
    bool enabled_ = false;
    uint32_t obfuscation_ = 0;
    std::string sequence_;
    std::vector<Association> associations_;

  public:
    /// Returns whether auto-type is enabled.
    bool enabled() const { return enabled_; }

    /// Sets whether auto-type is enabled.
    void set_enabled(bool enabled) { enabled_ = enabled; }

    /// Returns the obfuscation level.
    uint32_t obfuscation() const { return obfuscation_; }

    /// Sets the obfuscation level.
    void set_obfuscation(bool obfuscation) { obfuscation_ = obfuscation; }

    /// Returns the default keystroke sequence.
    const std::string &sequence() const { return sequence_; }

    /// Sets the default keystroke sequence.
    void set_sequence(const std::string &sequence) { sequence_ = sequence; }

    /// Returns the window/sequence associations.
    const std::vector<Association> &associations() const {
      return associations_;
    }

    /// Adds an association between a window and a keystroke sequence.
    void AddAssociation(const std::string &window,
                        const std::string &sequence) {
      associations_.emplace_back(Association(window, sequence));
    }

    /// Equality comparison.
    bool operator==(const AutoType &other) const {
      return enabled_ == other.enabled_ && obfuscation_ == other.obfuscation_ &&
             sequence_ == other.sequence_ &&
             associations_ == other.associations_;
    }

    /// Inequality comparison.
    bool operator!=(const AutoType &other) const { return !(*this == other); }
  };

  /**
   * @brief An arbitrary custom string (key/value) field.
   */
  class Field final {
  private:
    std::string key_;
    protect<std::string> value_;

  public:
    /// Creates a field with the given key and protected value.
    Field(std::string key, protect<std::string> value)
        : key_(std::move(key)), value_(std::move(value)) {}

    /// Copy constructor.
    Field(const Field &other) {
      key_ = other.key_;
      value_ = other.value_;
    }

    /// Move constructor.
    Field(Field &&other) noexcept {
      key_ = std::move(other.key_);
      value_ = std::move(other.value_);
    }

    /// Returns the field key.
    const std::string &key() const { return key_; }

    /// Returns the field value.
    const protect<std::string> &value() const { return value_; }

    /// Copy assignment.
    Field &operator=(const Field &other) = default;

    /// Move assignment.
    Field &operator=(Field &&other) noexcept {
      key_ = std::move(other.key_);
      value_ = std::move(other.value_);
      return *this;
    }

    /// Equality comparison.
    bool operator==(const Field &other) const {
      return key_ == other.key_ && value_ == other.value_;
    }

    /// Inequality comparison.
    bool operator!=(const Field &other) const { return !(*this == other); }
  };

private:
  std::array<uint8_t, 16> uuid_;
  uint32_t icon_ = 0;
  std::weak_ptr<Icon> custom_icon_;
  protect<std::string> title_;
  protect<std::string> url_;
  std::string override_url_;
  protect<std::string> username_;
  protect<std::string> password_;
  protect<std::string> notes_;
  std::string tags_;
  std::time_t creation_time_ = 0;
  std::time_t modification_time_ = 0;
  std::time_t access_time_ = 0;
  std::time_t expiry_time_ = 0;
  std::time_t move_time_ = 0;
  bool expires_ = false;
  uint32_t usage_count_ = 0;
  std::string bg_color_;
  std::string fg_color_;
  AutoType auto_type_;
  std::vector<std::shared_ptr<Attachment>> attachments_;
  std::vector<std::shared_ptr<Entry>> history_;
  std::vector<Field> custom_fields_;

public:
  /// Creates an empty entry.
  Entry();

  /// Returns the entry's unique identifier (UUID).
  const std::array<uint8_t, 16> &uuid() const { return uuid_; }

  /// Sets the entry's unique identifier (UUID).
  void set_uuid(const std::array<uint8_t, 16> &uuid) { uuid_ = uuid; }

  /// Returns the index of the stock icon.
  uint32_t icon() const { return icon_; }

  /// Sets the index of the stock icon.
  void set_icon(const uint32_t &icon) { icon_ = icon; }

  /// Returns a weak reference to the custom icon (if any).
  std::weak_ptr<Icon> custom_icon() const { return custom_icon_; }

  /// Sets the custom icon.
  void set_custom_icon(std::weak_ptr<Icon> icon) { custom_icon_ = std::move(icon); }

  /// Returns the entry title.
  const protect<std::string> &title() const { return title_; }

  /// Sets the entry title.
  void set_title(const protect<std::string> &title) { title_ = title; }

  /// Returns the URL.
  const protect<std::string> &url() const { return url_; }

  /// Sets the URL.
  void set_url(const protect<std::string> &url) { url_ = url; }

  /// Returns the override URL.
  const std::string &override_url() const { return override_url_; }

  /// Sets the override URL.
  void set_override_url(const std::string &url) { override_url_ = url; }

  /// Returns the username.
  const protect<std::string> &username() const { return username_; }

  /// Sets the username.
  void set_username(const protect<std::string> &username) {
    username_ = username;
  }

  /// Returns the password.
  const protect<std::string> &password() const { return password_; }

  /// Sets the password.
  void set_password(const protect<std::string> &password) {
    password_ = password;
  }

  /// Returns the notes.
  const protect<std::string> &notes() const { return notes_; }

  /// Sets the notes.
  void set_notes(const protect<std::string> &notes) { notes_ = notes; }

  /// Returns the tags (space-separated).
  const std::string &tags() const { return tags_; }

  /// Sets the tags (space-separated).
  void set_tags(const std::string &tags) { tags_ = tags; }

  /// Returns the creation time.
  std::time_t creation_time() const { return creation_time_; }

  /// Sets the creation time.
  void set_creation_time(const std::time_t &time) { creation_time_ = time; }

  /// Returns the last modification time.
  std::time_t modification_time() const { return modification_time_; }

  /// Sets the last modification time.
  void set_modification_time(const std::time_t &time) {
    modification_time_ = time;
  }

  /// Returns the last access time.
  std::time_t access_time() const { return access_time_; }

  /// Sets the last access time.
  void set_access_time(const std::time_t &time) { access_time_ = time; }

  /// Returns the expiry time.
  std::time_t expiry_time() const { return expiry_time_; }

  /// Sets the expiry time.
  void set_expiry_time(const std::time_t &time) { expiry_time_ = time; }

  /// Returns the last move time.
  std::time_t move_time() const { return move_time_; }

  /// Sets the last move time.
  void set_move_time(const std::time_t &time) { move_time_ = time; }

  /// Returns whether the entry expires.
  bool expires() const { return expires_; }

  /// Sets whether the entry expires.
  void set_expires(bool expires) { expires_ = expires; }

  /// Returns the usage count.
  uint32_t usage_count() const { return usage_count_; }

  /// Sets the usage count.
  void set_usage_count(uint32_t usage_count) { usage_count_ = usage_count; }

  /// Returns the background color.
  const std::string &bg_color() const { return bg_color_; }

  /// Sets the background color.
  void set_bg_color(const std::string &bg_color) { bg_color_ = bg_color; }

  /// Returns the foreground color.
  const std::string &fg_color() const { return fg_color_; }

  /// Sets the foreground color.
  void set_fg_color(const std::string &fg_color) { fg_color_ = fg_color; }

  /// Returns the auto-type configuration.
  AutoType &auto_type() { return auto_type_; }

  /// Returns the list of attachments.
  const std::vector<std::shared_ptr<Attachment>> &attachments() const {
    return attachments_;
  }

  /// Returns the list of historical (previous) versions of this entry.
  const std::vector<std::shared_ptr<Entry>> &history() const {
    return history_;
  }

  /// Returns the list of custom fields.
  const std::vector<Field> &custom_fields() const { return custom_fields_; }

  /// Adds an attachment to the entry.
  void AddAttachment(const std::shared_ptr<Attachment> &attachment);

  /// Returns whether the entry has at least one attachment.
  bool HasAttachment() const;

  /// Adds a previous version of this entry to its history.
  void AddHistoryEntry(const std::shared_ptr<Entry> &entry);

  /// Adds a custom field with the given key and value.
  void AddCustomField(std::string &key, const protect<std::string> &value);

  /// Returns whether the auto-type settings differ from the defaults.
  bool HasNonDefaultAutoTypeSettings() const;

  /// Returns whether the entry is a KeePassX metadata entry.
  bool IsMetaEntry() const;

  /// Serializes the entry to a JSON object.
  std::string ToJson() const;

  /// Equality comparison.
  bool operator==(const Entry &other) const;

  /// Inequality comparison.
  bool operator!=(const Entry &other) const;
};

} // namespace keepass
