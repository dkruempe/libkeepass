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

#include <array>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "libkeepass/database.hh"
#include "libkeepass/exception.hh"
#include "libkeepass/keepass.hh"
#include "libkeepass/random.hh"
#include "libkeepass/util.hh"

#include "kpx.hh"
#include "output.hh"

namespace kpx {

namespace {

/// Parses a --kdf value. Returns false for unknown names.
bool ParseKdf(const std::string& value, keepass::Database::Kdf& kdf) {
  if (value == "aes") {
    kdf = keepass::Database::Kdf::kAes;
    return true;
  }
  if (value == "argon2d") {
    kdf = keepass::Database::Kdf::kArgon2d;
    return true;
  }
  if (value == "argon2id") {
    kdf = keepass::Database::Kdf::kArgon2id;
    return true;
  }
  return false;
}

/// Applies a fresh set of KDF parameters after switching or rekeying.
void ApplyFreshKdfParameters(keepass::Database& db, keepass::Database::Kdf kdf) {
  if (kdf == keepass::Database::Kdf::kAes) {
    db.set_transform_rounds(600000);
    return;
  }

  std::array<uint8_t, 32> salt = keepass::random_array<32>();
  db.set_argon2_salt(std::vector<uint8_t>(salt.begin(), salt.end()));
  db.set_argon2_iterations(10);
  db.set_argon2_memory(64ULL * 1024 * 1024);
  db.set_argon2_parallelism(2);
  db.set_argon2_version(0x13);
}

/// Writes the database to a temporary file next to path and replaces path
/// only after a successful save, so a failed re-encryption keeps the original.
void SaveReplacing(const std::string& path, const keepass::Database& db, const keepass::Key& key,
                   keepass::KeePass::Format format) {
  const std::string tmp = path + ".tmp";
  try {
    keepass::KeePass keeper(key);
    keeper.SetFormat(format);
    keeper.SaveAs(tmp, db, key);
  } catch (...) {
    std::remove(tmp.c_str());
    throw;
  }

  if (std::rename(tmp.c_str(), path.c_str()) != 0) {
#ifdef _WIN32
    std::remove(path.c_str());
    if (std::rename(tmp.c_str(), path.c_str()) == 0)
      return;
#endif
    std::remove(tmp.c_str());
    throw keepass::IoError("Unable to replace database file.");
  }
}

/// Resolves the new master password for the passwd command. An empty result
/// means that no new password was requested.
keepass::secure_string ResolveNewMasterPassword(const Options& opt) {
  if (!opt.new_password.empty())
    return opt.new_password;
  if (!opt.new_password_file.empty())
    return ReadPasswordFile(opt.new_password_file);
  if (opt.new_password_stdin)
    return ReadPasswordStdin();
  return {};
}

// Applies the --generate length to the given database edit, either filling
// the password with a generated value or returning the configured password.
std::string ResolveEntryPassword(const Options& opt) {
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

/// Gives an entry (and its history) fresh UUIDs so a merge cannot collide
/// with an object already in the target database.
void ReassignEntryUuids(const std::shared_ptr<keepass::Entry>& entry) {
  entry->set_uuid(keepass::generate_uuid());
  for (const auto& history : entry->history())
    ReassignEntryUuids(history);
}

void ReassignGroupUuids(const std::shared_ptr<keepass::Group>& group) {
  group->set_uuid(keepass::generate_uuid());
  for (const auto& entry : group->Entries())
    ReassignEntryUuids(entry);
  for (const auto& child : group->Groups())
    ReassignGroupUuids(child);
}

} // namespace

int RunCreate(const Options& opt) {
  if (opt.input.empty()) {
    std::cerr << "error: create requires a database path\n";
    return 1;
  }

  if (!opt.force) {
    std::ifstream existing(opt.input, std::ios::in | std::ios::binary);
    if (existing.is_open()) {
      std::cerr << "error: '" << opt.input << "' already exists (use --force to overwrite)\n";
      return 1;
    }
  }

  const keepass::secure_string password = ResolvePassword(opt);
  const keepass::KeePass::Format format =
      IsKdbPath(opt.input) ? keepass::KeePass::Format::kKdb : keepass::KeePass::Format::kKdbx4;

  keepass::Database::Kdf kdf = format == keepass::KeePass::Format::kKdb
                                   ? keepass::Database::Kdf::kAes
                                   : keepass::Database::Kdf::kArgon2id;
  if (!opt.kdf.empty() && !ParseKdf(opt.kdf, kdf)) {
    std::cerr << "error: unknown KDF '" << opt.kdf << "' (expected aes, argon2d or argon2id)\n";
    return 1;
  }
  if (format == keepass::KeePass::Format::kKdb && kdf != keepass::Database::Kdf::kAes) {
    std::cerr << "error: KDB databases only support the aes KDF\n";
    return 1;
  }

  // A key file is part of the composite key, so it cannot be represented by
  // the password-only transformed-key cache produced by Create.
  const std::string create_password = opt.keyfile.empty() ? password.str() : std::string();
  std::unique_ptr<keepass::Database> db =
      keepass::KeePass::Create(create_password, format, keepass::Database::Cipher::kAes, kdf);

  const keepass::Key key(password.str(), opt.keyfile);
  keepass::KeePass keeper(key);
  keeper.SetFormat(format);
  keeper.Save(opt.input, *db);

  std::cout << "created '" << opt.input << "'\n";
  return 0;
}

int RunPasswd(const Options& opt, const keepass::secure_string& old_password,
              keepass::KeePass& keeper, keepass::Database* db) {
  (void)keeper;
  const bool new_password_given =
      !opt.new_password.empty() || !opt.new_password_file.empty() || opt.new_password_stdin;
  const bool kdf_given = !opt.kdf.empty();
  if (!new_password_given && !kdf_given) {
    std::cerr << "error: passwd requires --new-password/--new-password-file/"
                 "--new-password-stdin and/or --kdf\n";
    return 1;
  }

  if (!opt.new_password.empty() && (!opt.new_password_file.empty() || opt.new_password_stdin)) {
    std::cerr << "error: use only one of --new-password, --new-password-file and "
                 "--new-password-stdin\n";
    return 1;
  }
  if (!opt.new_password_file.empty() && opt.new_password_stdin) {
    std::cerr << "error: use only one of --new-password-file and --new-password-stdin\n";
    return 1;
  }

  keepass::Database::Kdf kdf = db->kdf();
  if (kdf_given && !ParseKdf(opt.kdf, kdf)) {
    std::cerr << "error: unknown KDF '" << opt.kdf << "' (expected aes, argon2d or argon2id)\n";
    return 1;
  }

  const bool is_kdb = IsKdbPath(opt.input);
  if (is_kdb && kdf != keepass::Database::Kdf::kAes) {
    std::cerr << "error: KDB databases only support the aes KDF\n";
    return 1;
  }

  const bool kdf_changed = kdf != db->kdf();
  if (kdf_changed)
    db->set_kdf(kdf);
  if (kdf_changed ||
      (!is_kdb && db->transform_rounds() == 0 && kdf == keepass::Database::Kdf::kAes))
    ApplyFreshKdfParameters(*db, kdf);

  keepass::secure_string new_password = ResolveNewMasterPassword(opt);
  if (new_password.empty() && !new_password_given)
    new_password = old_password;

  const keepass::Key new_key(new_password.str(), opt.keyfile);
  const keepass::KeePass::Format format =
      is_kdb ? keepass::KeePass::Format::kKdb : keepass::KeePass::Format::kKdbx4;
  SaveReplacing(opt.input, *db, new_key, format);

  std::cout << "changed master credentials for '" << opt.input << "'\n";
  return 0;
}

int RunMove(const Options& opt, keepass::KeePass& keeper, keepass::Database* db) {
  if (opt.to.empty()) {
    std::cerr << "error: move requires --to <group>\n";
    return 1;
  }
  std::shared_ptr<keepass::Group> target = db->FindGroup(opt.to);
  if (!target) {
    std::cerr << "error: group '" << opt.to << "' not found\n";
    return 1;
  }

  if (!opt.group.empty()) {
    std::shared_ptr<keepass::Group> source = db->FindGroup(opt.group);
    if (!source) {
      std::cerr << "error: group '" << opt.group << "' not found\n";
      return 1;
    }
    if (source == db->root()) {
      std::cerr << "error: cannot move the root group\n";
      return 1;
    }
    if (source == target || source->parent().lock() == target) {
      std::cerr << "error: group '" << opt.group << "' is already in '" << opt.to << "'\n";
      return 1;
    }
    for (std::shared_ptr<keepass::Group> ancestor = target; ancestor;
         ancestor = ancestor->parent().lock()) {
      if (ancestor == source) {
        std::cerr << "error: cannot move a group into its own subtree\n";
        return 1;
      }
    }

    keepass::Database::MoveGroup(source, target);
    keeper.Save(opt.input, *db);
    std::cout << "moved group '" << opt.group << "' to '" << opt.to << "'\n";
    return 0;
  }

  if (opt.search.empty() && !opt.has_title) {
    std::cerr << "error: move requires --title <title>, --search <query> or --group <name>\n";
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
    keepass::Database::MoveEntry(entry, target);
  keeper.Save(opt.input, *db);
  std::cout << "moved " << matches.size() << " entr" << (matches.size() == 1 ? "y" : "ies")
            << " to '" << opt.to << "'\n";
  return 0;
}

int RunPurge(const Options& opt, keepass::KeePass& keeper, keepass::Database* db) {
  if (!opt.all && opt.search.empty() && !opt.has_title) {
    std::cerr << "error: purge requires --title <title>, --search <query> or --all\n";
    return 1;
  }

  std::shared_ptr<keepass::Group> start = db->root();
  if (!opt.group.empty()) {
    start = db->FindGroup(opt.group);
    if (!start) {
      std::cerr << "error: group '" << opt.group << "' not found\n";
      return 1;
    }
  }

  const auto entries = SelectEntries(opt, start);
  std::size_t purged = 0;
  for (const auto& entry : entries) {
    if (entry->history().empty())
      continue;
    entry->delete_history();
    ++purged;
  }

  keeper.Save(opt.input, *db);
  std::cout << "purged history of " << purged << " entr" << (purged == 1 ? "y" : "ies") << "\n";
  return 0;
}

int RunMerge(const Options& opt, const keepass::secure_string& password, keepass::KeePass& keeper,
             keepass::Database* db) {
  if (opt.from.empty()) {
    std::cerr << "error: merge requires --from <database>\n";
    return 1;
  }
  if (opt.from == opt.input) {
    std::cerr << "error: source and target database are the same file\n";
    return 1;
  }

  std::shared_ptr<keepass::Group> target = db->root();
  if (!opt.to.empty()) {
    target = db->FindGroup(opt.to);
    if (!target) {
      std::cerr << "error: group '" << opt.to << "' not found\n";
      return 1;
    }
  }
  if (!target) {
    std::cerr << "error: database has no root group\n";
    return 1;
  }

  keepass::KeePass source_keeper(password.str(), opt.keyfile);
  std::unique_ptr<keepass::Database> source = source_keeper.Open(opt.from);
  if (!source || !source->root()) {
    std::cerr << "error: source database is empty\n";
    return 1;
  }

  const std::vector<std::shared_ptr<keepass::Group>> groups = source->root()->Groups();
  const std::vector<std::shared_ptr<keepass::Entry>> entries = source->root()->Entries();
  for (const auto& group : groups) {
    ReassignGroupUuids(group);
    keepass::Database::MoveGroup(group, target);
  }
  for (const auto& entry : entries) {
    ReassignEntryUuids(entry);
    keepass::Database::MoveEntry(entry, target);
  }

  keeper.Save(opt.input, *db);
  std::cout << "merged " << entries.size() << " entr" << (entries.size() == 1 ? "y" : "ies")
            << " and " << groups.size() << " group" << (groups.size() == 1 ? "" : "s") << " from '"
            << opt.from << "'\n";
  return 0;
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
  const std::string password = ResolveEntryPassword(opt);
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
