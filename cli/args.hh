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

#include <string>

#include "libkeepass/secure.hh"

namespace kpx {

// Default and maximum length for --generate.
constexpr int kDefaultGenerateLength = 16;
constexpr int kMaxGenerateLength = 256;

// Ambiguity-free character set used by --generate.
extern const char* const kGenerateCharset;

/// Command-line options as parsed by kpx::ParseArgs.
struct Options {
  std::string input;
  keepass::secure_string password;
  std::string keyfile;
  std::string format = "text";
  std::string output;
  std::string export_path;
  std::string command; // "" | "add" | "update" | "rm"
  std::string search;  // --search query
  bool regex = false;  // --regex
  std::string group;   // --group name
  int generate = 0;    // --generate[=n]; 0 = disabled, -1 = invalid
  bool audit = false;  // --audit
  std::string title;   // entry field
  std::string user;
  std::string entry_password;
  std::string url;
  std::string notes;
  bool has_title = false;
  bool has_user = false;
  bool has_pass = false;
  bool has_url = false;
  bool has_notes = false;
  bool with_passwords = false;
  bool verbose = false;
  bool help = false;
  bool show_version = false;
};

/// Parses the command-line arguments into opt. Supports long options
/// (--password, --keyfile, --format, --output, --export, --with-passwords,
/// --search, --regex, --group, --generate, --audit, --title, --user, --pass,
/// --url, --notes, --verbose, --help, --version, both with '=' and as separate
/// value arguments), combined short options (-p, -k) and the "--" separator.
/// The first positional argument may be the "add", "update" or "rm" command;
/// the following positional argument is the database path. Returns false and
/// prints an error if an argument is unknown or malformed.
bool ParseArgs(int argc, const char* argv[], Options& opt);

/// Generates a random password of the given length from a printable character
/// set guarded against ambiguity between look-alike characters.
std::string GeneratePassword(int length);

/// Returns a lowercase copy of s.
std::string Lower(const std::string& s);

} // namespace kpx