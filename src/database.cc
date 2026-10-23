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

#include "libkeepass/database.hh"

#include <ctime>
#include <limits>
#include <map>
#include <sstream>

#include "libkeepass/entry.hh"
#include "libkeepass/group.hh"
#include "libkeepass/metadata.hh"
#include "libkeepass/visitor.hh"

namespace keepass {

namespace {

/// Calls the given function for every group in the subtree (including the root).
template <typename F> void Dfs(const std::shared_ptr<Group>& current, F&& function) {
  function(current);
  for (const auto& child : current->Groups())
    Dfs(child, function);
}

std::string JsonEscape(const std::string& value) {
  std::string escaped;
  escaped.reserve(value.size());
  for (const char c : value) {
    switch (c) {
    case '"':
      escaped += "\\\"";
      break;
    case '\\':
      escaped += "\\\\";
      break;
    case '\n':
      escaped += "\\n";
      break;
    case '\r':
      escaped += "\\r";
      break;
    case '\t':
      escaped += "\\t";
      break;
    default:
      escaped.push_back(c);
      break;
    }
  }
  return escaped;
}

std::string UuidHex(const std::array<uint8_t, 16>& uuid) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string text;
  text.reserve(uuid.size() * 2);
  for (const uint8_t byte : uuid) {
    text.push_back(kHex[byte >> 4]);
    text.push_back(kHex[byte & 0x0f]);
  }
  return text;
}

using EntryMap = std::map<std::array<uint8_t, 16>, std::pair<std::shared_ptr<Entry>, std::string>>;

void CollectEntries(const std::shared_ptr<Group>& group, EntryMap& entries) {
  for (const auto& entry : group->Entries())
    entries.emplace(entry->uuid(), std::make_pair(entry, entry->path()));
  for (const auto& child : group->Groups())
    CollectEntries(child, entries);
}

} // namespace

std::vector<std::shared_ptr<Entry>> Database::FindEntries(const std::string& query,
                                                          bool regex) const {
  if (!root_)
    return {};
  return root_->FindEntries(query, regex);
}

std::vector<std::shared_ptr<Group>> Database::FindGroups(const std::string& query,
                                                         bool regex) const {
  if (!root_)
    return {};
  return root_->FindGroups(query, regex);
}

std::shared_ptr<Entry> Database::FindEntry(const std::string& title) const {
  if (!root_)
    return nullptr;

  for (const auto& entry : root_->FindEntries(title, false))
    if (*entry->title() == title)
      return entry;
  return nullptr;
}

std::shared_ptr<Group> Database::FindGroup(const std::string& name) const {
  if (!root_)
    return nullptr;

  for (const auto& group : root_->FindGroups(name, false))
    if (group->name() == name)
      return group;
  return nullptr;
}

std::shared_ptr<Entry> Database::NewEntry(const std::string& title) {
  auto entry = std::make_shared<Entry>();
  entry->set_creation_time(std::time(nullptr));
  entry->set_modification_time(std::time(nullptr));
  if (!title.empty())
    entry->set_title(protect<secure_string>(secure_string(title), false));
  return entry;
}

std::shared_ptr<Group> Database::NewGroup(const std::string& name) {
  auto group = std::make_shared<Group>();
  group->set_creation_time(std::time(nullptr));
  group->set_modification_time(std::time(nullptr));
  if (!name.empty())
    group->set_name(name);
  return group;
}

void Database::AddEntry(const std::shared_ptr<Group>& group, const std::shared_ptr<Entry>& entry) {
  if (group)
    group->AddEntry(entry);
}

void Database::AddGroup(const std::shared_ptr<Group>& parent, const std::shared_ptr<Group>& group) {
  if (parent)
    parent->AddGroup(group);
}

void Database::DeleteOldHistory() {
  if (!root_)
    return;

  const std::size_t max_items = meta_ && meta_->history_max_items() >= 0
                                    ? static_cast<std::size_t>(meta_->history_max_items())
                                    : std::numeric_limits<std::size_t>::max();
  const std::size_t max_bytes = meta_ && meta_->history_max_size() >= 0
                                    ? static_cast<std::size_t>(meta_->history_max_size())
                                    : std::numeric_limits<std::size_t>::max();

  const auto apply = [&](const auto& self, const std::shared_ptr<Group>& group) -> void {
    for (const auto& entry : group->Entries())
      entry->delete_old_history(max_items, max_bytes);
    for (const auto& child : group->Groups())
      self(self, child);
  };
  apply(apply, root_);
}

DatabaseDelta Database::DeltaSince(const Database& previous) const {
  DatabaseDelta delta;
  if (!root_)
    return delta;

  EntryMap current_entries;
  CollectEntries(root_, current_entries);

  EntryMap previous_entries;
  if (previous.root_)
    CollectEntries(previous.root_, previous_entries);

  for (const auto& [uuid, current] : current_entries) {
    const auto it = previous_entries.find(uuid);
    if (it == previous_entries.end()) {
      delta.added.push_back({current.first, current.second});
      continue;
    }

    const auto& old = it->second;
    if (old.second != current.second || old.first->ToJson() != current.first->ToJson())
      delta.modified.push_back({current.first, current.second});
  }

  for (const auto& [uuid, old] : previous_entries) {
    if (current_entries.find(uuid) == current_entries.end()) {
      delta.deleted.push_back(uuid);
      delta.deleted_paths.push_back(old.second);
    }
  }

  return delta;
}

std::string DatabaseDelta::ToJson() const {
  std::ostringstream json;
  const auto write_entries = [&json](const std::vector<EntryDelta>& entries) {
    bool first = true;
    for (const auto& change : entries) {
      if (!first)
        json << ',';
      first = false;
      json << R"({"path":")" << JsonEscape(change.group_path) << R"(","uuid":")"
           << UuidHex(change.entry->uuid()) << R"(","entry":)" << change.entry->ToJson() << '}';
    }
  };

  json << R"({"added":[)";
  write_entries(added);
  json << R"(],"modified":[)";
  write_entries(modified);
  json << R"(],"deleted":[)";
  for (std::size_t i = 0; i < deleted.size(); ++i) {
    if (i != 0)
      json << ',';
    json << R"({"path":")" << JsonEscape(i < deleted_paths.size() ? deleted_paths[i] : "")
         << R"(","uuid":")" << UuidHex(deleted[i]) << R"("})";
  }
  json << "]}";
  return json.str();
}

void Database::DeleteEntry(const std::array<uint8_t, 16>& uuid) {
  if (!root_)
    return;

  std::shared_ptr<Group> parent;
  Dfs(root_, [&](const std::shared_ptr<Group>& group) {
    if (parent)
      return;
    for (const auto& entry : group->Entries()) {
      if (entry->uuid() == uuid) {
        parent = group;
        return;
      }
    }
  });

  if (!parent)
    return;

  for (const auto& entry : parent->Entries()) {
    if (entry->uuid() == uuid) {
      parent->RemoveEntry(entry);
      return;
    }
  }
}

void Database::DeleteGroup(const std::array<uint8_t, 16>& uuid) {
  if (!root_)
    return;

  if (root_->uuid() == uuid) {
    root_ = std::make_shared<Group>();
    return;
  }

  std::shared_ptr<Group> parent;
  std::shared_ptr<Group> target;
  Dfs(root_, [&](const std::shared_ptr<Group>& group) {
    if (parent)
      return;
    for (const auto& child : group->Groups()) {
      if (child->uuid() == uuid) {
        parent = group;
        target = child;
        return;
      }
    }
  });

  if (parent)
    parent->RemoveGroup(target);
}

void Database::MoveEntry(const std::shared_ptr<Entry>& entry,
                         const std::shared_ptr<Group>& new_group) {
  if (!entry || !new_group)
    return;

  const auto old_parent = entry->parent().lock();
  if (old_parent == new_group)
    return;
  if (old_parent)
    old_parent->RemoveEntry(entry);

  new_group->AddEntry(entry);
}

void Database::MoveGroup(const std::shared_ptr<Group>& group,
                         const std::shared_ptr<Group>& new_parent) {
  if (!group || !new_parent)
    return;

  // Reject moving a group into its own subtree.
  for (std::shared_ptr<Group> ancestor = new_parent; ancestor;
       ancestor = ancestor->parent().lock()) {
    if (ancestor == group)
      return;
  }

  const auto old_parent = group->parent().lock();
  if (old_parent == new_parent)
    return;
  if (old_parent)
    old_parent->RemoveGroup(group);

  new_parent->AddGroup(group);
}

void Database::TrashEntry(const std::shared_ptr<Entry>& entry) {
  if (!entry)
    return;

  auto bin = meta_ ? meta_->recycle_bin() : nullptr;
  if (!bin) {
    DeleteEntry(entry->uuid());
    return;
  }

  MoveEntry(entry, bin);
}

void Database::TrashGroup(const std::shared_ptr<Group>& group) {
  if (!group)
    return;

  auto bin = meta_ ? meta_->recycle_bin() : nullptr;
  if (!bin) {
    DeleteGroup(group->uuid());
    return;
  }

  MoveGroup(group, bin);
}

void Database::EmptyRecycleBin() {
  auto bin = meta_ ? meta_->recycle_bin() : nullptr;
  if (!bin)
    return;

  for (const auto& group : bin->Groups())
    bin->RemoveGroup(group);
  for (const auto& entry : bin->Entries())
    bin->RemoveEntry(entry);
}

bool Database::IsRecycleBinEnabled() const { return meta_ && meta_->recycle_bin(); }

void Database::EnableRecycleBin(bool enable) {
  if (!meta_)
    meta_ = std::make_shared<Metadata>();

  if (!enable) {
    meta_->set_recycle_bin(nullptr);
    return;
  }

  if (meta_->recycle_bin())
    return;

  if (!root_)
    root_ = std::make_shared<Group>();

  auto bin = std::make_shared<Group>();
  bin->set_name("Recycle Bin");
  root_->AddGroup(bin);
  meta_->set_recycle_bin(bin);
  meta_->set_recycle_bin_changed(std::time(nullptr));
}

std::string Database::ToJson(bool include_attachments) const {
  return root_ ? root_->ToJson(include_attachments) : "{}";
}

namespace {

// Escapes a string for inclusion as a single CSV field following RFC 4180.
std::string CsvField(const std::string& value) {
  if (value.find(',') == std::string::npos && value.find('"') == std::string::npos &&
      value.find('\n') == std::string::npos)
    return value;

  std::string escaped;
  escaped.reserve(value.size() + 2);
  escaped.push_back('"');
  for (const char c : value) {
    if (c == '"')
      escaped.push_back('"');
    escaped.push_back(c);
  }
  escaped.push_back('"');
  return escaped;
}

// Writes the CSV rows of the subtree rooted at group, where @p path is the
// '/'-joined group path above the current group (the root's name is appended
// here, so entries directly in the root group appear under its name).
std::string CustomFieldsCsv(const Entry& entry) {
  std::string fields;
  for (const auto& field : entry.custom_fields()) {
    if (!fields.empty())
      fields += "; ";
    fields += field.key();
    fields += "=";
    fields += field.value()->str();
  }
  return fields;
}

void ToCsvGroup(std::ostringstream& os, const std::shared_ptr<Group>& group,
                const std::string& path, CsvFormat format) {
  std::string group_path = path;
  if (!group->name().empty()) {
    if (!group_path.empty())
      group_path += "/";
    group_path += group->name();
  }

  for (const auto& entry : group->Entries()) {
    if (entry->IsMetaEntry())
      continue;

    if (format == CsvFormat::kCsvKeePass2) {
      // KeePass 2.x "KeePass CSV" compatibility: Account, Login Name,
      // Password, Web Site, Comments.
      os << CsvField(entry->title().value().str()) << ","
         << CsvField(entry->username().value().str()) << ","
         << CsvField(entry->password().value().str()) << "," << CsvField(entry->url().value().str())
         << "," << CsvField(entry->notes().value().str()) << "\n";
      continue;
    }

    const bool with_passwords = format == CsvFormat::kCsvWithPasswords;
    os << CsvField(group_path) << "," << CsvField(entry->title().value().str()) << ","
       << CsvField(entry->username().value().str()) << ","
       << (with_passwords ? CsvField(entry->password().value().str()) : std::string()) << ","
       << CsvField(entry->url().value().str()) << "," << CsvField(entry->notes().value().str());
    if (format == CsvFormat::kCsvWithCustomFields)
      os << "," << CsvField(CustomFieldsCsv(*entry));
    os << "\n";
  }
  for (const auto& child : group->Groups())
    ToCsvGroup(os, child, group_path, format);
}

} // namespace

std::string Database::ToCsv(CsvFormat format) const {
  std::ostringstream os;
  if (format == CsvFormat::kCsvKeePass2)
    os << "Account,Login Name,Password,Web Site,Comments\n";
  else if (format == CsvFormat::kCsvWithCustomFields)
    os << "Group,Title,Username,Password,Url,Notes,CustomFields\n";
  else
    os << "Group,Title,Username,Password,Url,Notes\n";

  if (root_)
    ToCsvGroup(os, root_, std::string(), format);
  return os.str();
}

size_t Database::EntryCount() const {
  if (!root_)
    return 0;

  size_t count = 0;
  Dfs(root_, [&](const std::shared_ptr<Group>& group) { count += group->Entries().size(); });
  return count;
}

size_t Database::GroupCount() const {
  if (!root_)
    return 0;

  size_t count = 0;
  Dfs(root_, [&](const std::shared_ptr<Group>&) { ++count; });
  return count;
}

void Database::Visit(Visitor& visitor) const {
  if (root_)
    ::keepass::Visit(*root_, visitor);
}

} // namespace keepass