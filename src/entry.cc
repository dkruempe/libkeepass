/*
 * libkeepass - KeePass key database importer/exporter
 * Copyright (C) 2014 Christian Kindahl
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

#include "libkeepass/entry.hh"

#include <sstream>

#include "libkeepass/util.hh"

namespace keepass {

Entry::Entry() : uuid_(generate_uuid()) {}

void Entry::AddAttachment(const std::shared_ptr<Attachment> &attachment) {
  attachments_.push_back(attachment);
}

bool Entry::HasAttachment() const { return !attachments_.empty(); }

void Entry::AddHistoryEntry(const std::shared_ptr<Entry> &entry) {
  history_.push_back(entry);
}

void Entry::AddCustomField(std::string &key,
                           const protect<std::string> &value) {
  custom_fields_.emplace_back(key, value);
}

bool Entry::HasNonDefaultAutoTypeSettings() const {
  return auto_type_ != AutoType();
}

bool Entry::IsMetaEntry() const {
  bool has_binstream_attachment = false;
  for (auto &attachment : attachments_) {
    if (attachment->name() == "bin-stream") {
      has_binstream_attachment = true;
      break;
    }
  }

  return *title_ == "Meta-Info" && *url_ == "$" && *username_ == "SYSTEM" &&
         !notes_->empty() && has_binstream_attachment;
}

std::string Entry::Attachment::ToJson() const {
  std::stringstream json;

  json << "{";
  if (!name_.empty())
    json << R"("name":")" << name_ << "\"";
  if (!binary_->Empty()) {
    json << (name_.empty() ? "" : ",") << R"("data":")" << *binary_->data()
         << "\"";
  }
  json << "}";

  return json.str();
}

std::string Entry::ToJson() const {
  std::stringstream json;

  json << "{";
  json << "\"icon\":" << icon_;
  if (!title_->empty())
    json << R"(,"title":")" << *title_ << "\"";
  if (!url_->empty())
    json << R"(,"url":")" << *url_ << "\"";
  if (!username_->empty())
    json << R"(,"username":")" << *username_ << "\"";
  if (!password_->empty())
    json << R"(,"password":")" << *password_ << "\"";
  if (!notes_->empty())
    json << R"(,"notes":")" << *notes_ << "\"";
  if (creation_time_ != 0)
    json << R"(,"creation_time":")" << time_to_str(creation_time_) << "\"";
  if (modification_time_ != 0) {
    json << R"(,"modification_time":")" << time_to_str(modification_time_)
         << "\"";
  }
  if (access_time_ != 0)
    json << R"(,"access_time":")" << time_to_str(access_time_) << "\"";
  if (expiry_time_ != 0)
    json << R"(,"expiry_time":")" << time_to_str(expiry_time_) << "\"";
  for (auto &attachment : attachments_) {
    json << ",\"attachment\":" << attachment->ToJson();
  }
  json << "}";

  return json.str();
}

bool Entry::operator==(const Entry &other) const {
  if (custom_icon_.lock() != nullptr != (other.custom_icon_.lock() != nullptr))
    return false;

  bool same_custom_icon =
      !custom_icon_.lock() ||
      custom_icon_.lock().get() == other.custom_icon_.lock().get();

  return uuid_ == other.uuid_ && icon_ == other.icon_ && same_custom_icon &&
         title_ == other.title_ && url_ == other.url_ &&
         override_url_ == other.override_url_ && username_ == other.username_ &&
         password_ == other.password_ && notes_ == other.notes_ &&
         tags_ == other.tags_ && creation_time_ == other.creation_time_ &&
         modification_time_ == other.modification_time_ &&
         access_time_ == other.access_time_ &&
         expiry_time_ == other.expiry_time_ && move_time_ == other.move_time_ &&
         expires_ == other.expires_ && usage_count_ == other.usage_count_ &&
         bg_color_ == other.bg_color_ && fg_color_ == other.fg_color_ &&
         auto_type_ == other.auto_type_ &&
         indirect_equal<std::shared_ptr<Attachment>>(attachments_,
                                                     other.attachments_) &&
         indirect_equal<std::shared_ptr<Entry>>(history_, other.history_) &&
         custom_fields_ == other.custom_fields_;
}

bool Entry::operator!=(const Entry &other) const { return !(*this == other); }

} // namespace keepass
