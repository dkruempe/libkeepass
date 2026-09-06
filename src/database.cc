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
    entry->set_title(protect<std::string>(title, false));
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

void Database::AddEntry(std::shared_ptr<Group> group, std::shared_ptr<Entry> entry) {
  if (group)
    group->AddEntry(std::move(entry));
}

void Database::AddGroup(std::shared_ptr<Group> parent, std::shared_ptr<Group> group) {
  if (parent)
    parent->AddGroup(std::move(group));
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

void Database::MoveEntry(std::shared_ptr<Entry> entry, std::shared_ptr<Group> new_group) {
  if (!entry || !new_group)
    return;

  std::shared_ptr<Group> old_parent = entry->parent().lock();
  if (old_parent == new_group)
    return;
  if (old_parent)
    old_parent->RemoveEntry(entry);

  new_group->AddEntry(std::move(entry));
}

void Database::MoveGroup(std::shared_ptr<Group> group, std::shared_ptr<Group> new_parent) {
  if (!group || !new_parent)
    return;

  // Reject moving a group into its own subtree.
  for (std::shared_ptr<Group> ancestor = new_parent; ancestor;
       ancestor = ancestor->parent().lock()) {
    if (ancestor == group)
      return;
  }

  std::shared_ptr<Group> old_parent = group->parent().lock();
  if (old_parent == new_parent)
    return;
  if (old_parent)
    old_parent->RemoveGroup(group);

  new_parent->AddGroup(std::move(group));
}

void Database::TrashEntry(std::shared_ptr<Entry> entry) {
  if (!entry)
    return;

  auto bin = meta_ ? meta_->recycle_bin() : nullptr;
  if (!bin) {
    DeleteEntry(entry->uuid());
    return;
  }

  MoveEntry(std::move(entry), bin);
}

void Database::TrashGroup(std::shared_ptr<Group> group) {
  if (!group)
    return;

  auto bin = meta_ ? meta_->recycle_bin() : nullptr;
  if (!bin) {
    DeleteGroup(group->uuid());
    return;
  }

  MoveGroup(std::move(group), bin);
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

std::string Database::ToJson() const { return root_ ? root_->ToJson() : "{}"; }

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