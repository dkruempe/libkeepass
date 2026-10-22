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

#pragma once

#include "args.hh"

namespace keepass {
class Database;
class KeePass;
} // namespace keepass

namespace kpx {

/// Creates a new empty database at opt.input, refusing to overwrite an
/// existing file unless --force is given. Returns the process exit code.
int RunCreate(const Options& opt);

/// Changes the master password and/or KDF of the database at opt.input in
/// place. Returns the process exit code.
int RunPasswd(const Options& opt, const keepass::secure_string& old_password,
              keepass::KeePass& keeper, keepass::Database* db);

/// Moves entries or a group to the group named by --to. Returns the process
/// exit code.
int RunMove(const Options& opt, keepass::KeePass& keeper, keepass::Database* db);

/// Clears entry history for the selected entries (--title/--search) or the
/// whole database (--all). Returns the process exit code.
int RunPurge(const Options& opt, keepass::KeePass& keeper, keepass::Database* db);

/// Creates a new entry from the --title/--user/--pass/--url/--notes options
/// and saves the database. Returns the process exit code.
int RunAdd(const Options& opt, keepass::KeePass& keeper, keepass::Database* db);

/// Updates the entries matching --search with the given field options and
/// saves the database. Returns the process exit code.
int RunUpdate(const Options& opt, keepass::KeePass& keeper, keepass::Database* db);

/// Removes the selected group, or the entries selected by --title or --search,
/// and saves the database. Returns the process exit code.
int RunRemove(const Options& opt, keepass::KeePass& keeper, keepass::Database* db);

} // namespace kpx