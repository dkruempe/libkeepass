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

#include "edit.hh"

#include <iostream>
#include <vector>

#include "libkeepass/database.hh"
#include "libkeepass/keepass.hh"

#include "output.hh"

namespace kpx {

// Applies the --generate length to the given database edit, either filling
// the password with a generated value or returning the configured password.
std::string ResolveNewPassword(const Options& opt) {
  if (opt.has_pass)
    return opt.entry_password;
  if (opt.generate > 0)
    return GeneratePassword(opt.generate);
  return {};
}

// Wraps a plain-text string in a protected secure string for the entry setters.
keepass::protect<keepass::secure_string> Prot(const std::string& s, bool protected_value) {
  return {keepass::secure_string(s), protected_value};
}

int RunAdd(const Options& opt, keepass::KeePass& keeper, keepass::Database* db) {
  std::shared_ptr<keepass::Group> group = db->root();
  if (!group) {
    std::cerr << "error: database has no root group\n";
    return 1;
  }
  if (!opt.group.empty()) {
    group = db->FindGroup(opt.group);
    if (!group) {
      std::cerr << "error: group '" << opt.group << "' not found\n";
      return 1;
    }
  }

  std::shared_ptr<keepass::Entry> entry = keepass::Database::NewEntry(opt.title);
  if (opt.has_user)
    entry->set_username(Prot(opt.user, false));
  if (opt.has_url)
    entry->set_url(Prot(opt.url, false));
  if (opt.has_notes)
    entry->set_notes(Prot(opt.notes, false));
  const std::string password = ResolveNewPassword(opt);
  if (!password.empty())
    entry->set_password(Prot(password, true));

  keepass::Database::AddEntry(group, entry);
  keeper.Save(opt.input, *db);
  std::cout << "added entry '" << opt.title << "' to '" << group->name() << "'\n";
  return 0;
}

int RunUpdate(const Options& opt, keepass::KeePass& keeper, keepass::Database* db) {
  if (opt.search.empty()) {
    std::cerr << "error: update requires --search <query>\n";
    return 1;
  }
  if (!opt.has_title && !opt.has_user && !opt.has_pass && !opt.has_url && !opt.has_notes) {
    std::cerr << "error: update requires at least one of --title, --user, --pass, --url, --notes\n";
    return 1;
  }

  std::vector<std::shared_ptr<keepass::Entry>> matches =
      SearchEntries(db->root(), opt.search, opt.regex, false);
  if (matches.empty()) {
    std::cerr << "error: no entries match '" << opt.search << "'\n";
    return 1;
  }

  for (const auto& entry : matches) {
    if (opt.has_title)
      entry->set_title(Prot(opt.title, false));
    if (opt.has_user)
      entry->set_username(Prot(opt.user, false));
    if (opt.has_pass)
      entry->set_password(Prot(opt.entry_password, true));
    if (opt.has_url)
      entry->set_url(Prot(opt.url, false));
    if (opt.has_notes)
      entry->set_notes(Prot(opt.notes, false));
  }

  keeper.Save(opt.input, *db);
  std::cout << "updated " << matches.size() << " entr" << (matches.size() == 1 ? "y" : "ies")
            << "\n";
  return 0;
}

int RunRemove(const Options& opt, keepass::KeePass& keeper, keepass::Database* db) {
  if (!opt.group.empty()) {
    std::shared_ptr<keepass::Group> group = db->FindGroup(opt.group);
    if (!group) {
      std::cerr << "error: group '" << opt.group << "' not found\n";
      return 1;
    }
    db->DeleteGroup(group->uuid());
    keeper.Save(opt.input, *db);
    std::cout << "removed group '" << opt.group << "'\n";
    return 0;
  }

  if (opt.search.empty() && !opt.has_title) {
    std::cerr << "error: rm requires --title <title>, --search <query> or --group <name>\n";
    return 1;
  }

  std::vector<std::shared_ptr<keepass::Entry>> matches =
      opt.has_title ? SearchEntries(db->root(), opt.title, false, true)
                    : SearchEntries(db->root(), opt.search, opt.regex, false);
  if (matches.empty()) {
    std::cerr << "error: no matching entries\n";
    return 1;
  }

  for (const auto& entry : matches)
    db->DeleteEntry(entry->uuid());
  keeper.Save(opt.input, *db);
  std::cout << "removed " << matches.size() << " entr" << (matches.size() == 1 ? "y" : "ies")
            << "\n";
  return 0;
}

} // namespace kpx