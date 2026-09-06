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

#include "libkeepass/group.hh"

#include <cctype>
#include <regex>
#include <sstream>

#include "libkeepass/util.hh"

namespace keepass {

namespace {

bool Matches(const std::string& text, const std::string& query, bool regex) {
  if (regex) {
    try {
      return std::regex_search(text, std::regex(query, std::regex::icase));
    } catch (const std::regex_error&) {
      return false;
    }
  }

  if (query.empty())
    return true;

  auto it = std::search(text.begin(), text.end(), query.begin(), query.end(),
                        [](char a, char b) { return std::tolower(a) == std::tolower(b); });
  return it != text.end();
}

} // namespace

Group::Group() : uuid_(generate_uuid()) {}

const std::vector<std::shared_ptr<Group>>& Group::Groups() const { return groups_; }

const std::vector<std::shared_ptr<Entry>>& Group::Entries() const { return entries_; }

std::string Group::path() const {
  std::vector<std::string> names;
  std::shared_ptr<Group> current = parent_.lock();
  while (current) {
    if (!current->name().empty())
      names.push_back(current->name());
    current = current->parent().lock();
  }

  std::string path;
  for (auto it = names.rbegin(); it != names.rend(); ++it)
    path += "/" + *it;

  if (!name_.empty())
    path += "/" + name_;

  return path.empty() ? "/" : path;
}

std::vector<std::shared_ptr<Entry>> Group::FindEntries(const std::string& query, bool regex,
                                                       bool recursive) const {
  std::vector<std::shared_ptr<Entry>> result;

  std::function<void(const Group&)> collect = [&](const Group& group) {
    for (const auto& entry : group.entries_) {
      if (Matches(*entry->title(), query, regex))
        result.push_back(entry);
    }
    if (recursive) {
      for (const auto& child : group.groups_)
        collect(*child);
    }
  };

  collect(*this);
  return result;
}

std::vector<std::shared_ptr<Group>> Group::FindGroups(const std::string& query, bool regex,
                                                      bool recursive) const {
  std::vector<std::shared_ptr<Group>> result;

  std::function<void(const Group&)> collect = [&](const Group& group) {
    for (const auto& child : group.groups_) {
      if (Matches(child->name(), query, regex))
        result.push_back(child);
      if (recursive)
        collect(*child);
    }
  };

  collect(*this);
  return result;
}

void Group::AddGroup(const std::shared_ptr<Group>& group) {
  group->set_parent(shared_from_this());
  groups_.push_back(group);
}

void Group::RemoveGroup(const std::shared_ptr<Group>& group) {
  for (auto it = groups_.begin(); it != groups_.end(); ++it) {
    if (*it == group) {
      group->set_parent({});
      groups_.erase(it);
      return;
    }
  }
}

void Group::AddEntry(const std::shared_ptr<Entry>& entry) {
  entry->set_parent(shared_from_this());
  entries_.push_back(entry);
}

void Group::RemoveEntry(const std::shared_ptr<Entry>& entry) {
  for (auto it = entries_.begin(); it != entries_.end(); ++it) {
    if (*it == entry) {
      entry->set_parent({});
      entries_.erase(it);
      return;
    }
  }
}

bool Group::HasNonMetaEntries() const {
  return std::find_if(entries_.begin(), entries_.end(), [](const std::shared_ptr<Entry>& entry) {
           return !entry->IsMetaEntry();
         }) != entries_.end();
}

std::string Group::ToJson() const {
  std::stringstream json;

  json << "{";
  json << "\"icon\":" << icon_;
  if (custom_icon_.lock())
    json << R"(,"custom_icon":")" << true << "\"";
  if (!name_.empty())
    json << R"(,"name":")" << name_ << "\"";
  if (!notes_.empty())
    json << R"(,"notes":")" << notes_ << "\"";
  if (creation_time_ != 0)
    json << R"(,"creation_time":")" << time_to_str(creation_time_) << "\"";
  if (modification_time_ != 0) {
    json << R"(,"modification_time":")" << time_to_str(modification_time_) << "\"";
  }
  if (access_time_ != 0)
    json << R"(,"access_time":")" << time_to_str(access_time_) << "\"";
  if (expiry_time_ != 0)
    json << R"(,"expiry_time":")" << time_to_str(expiry_time_) << "\"";
  if (move_time_ != 0)
    json << R"(,"move_time":")" << time_to_str(move_time_) << "\"";
  if (flags_ != 0)
    json << ",\"flags\":" << flags_;
  if (!groups_.empty()) {
    json << ",\"groups\":[";

    std::string sep;
    for (const auto& group : groups_) {
      json << sep << group->ToJson();
      sep = ",";
    }

    json << "]";
  }
  if (HasNonMetaEntries()) {
    json << ",\"entries\":[";

    std::string sep;
    for (const auto& entry : entries_) {
      if (entry->IsMetaEntry())
        continue;

      json << sep << entry->ToJson();
      sep = ",";
    }

    json << "]";
  }
  json << "}";

  return json.str();
}

bool Group::operator==(const Group& other) const {
  return uuid_ == other.uuid_ && icon_ == other.icon_ &&
         custom_icon_.lock() == other.custom_icon_.lock() && name_ == other.name_ &&
         notes_ == other.notes_ && creation_time_ == other.creation_time_ &&
         modification_time_ == other.modification_time_ && access_time_ == other.access_time_ &&
         expiry_time_ == other.expiry_time_ && move_time_ == other.move_time_ &&
         flags_ == other.flags_ && expires_ == other.expires_ && expanded_ == other.expanded_ &&
         usage_count_ == other.usage_count_ &&
         default_autotype_sequence_ == other.default_autotype_sequence_ &&
         autotype_ == other.autotype_ && search_ == other.search_ &&
         last_visible_entry_.lock() == other.last_visible_entry_.lock() &&
         indirect_equal<std::shared_ptr<Group>>(groups_, other.groups_) &&
         indirect_equal<std::shared_ptr<Entry>>(entries_, other.entries_);
}

bool Group::operator!=(const Group& other) const { return !(*this == other); }

} // namespace keepass
