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

#include <iosfwd>
#include <string>

#include "libkeepass/database.hh"
#include "libkeepass/key.hh"
#include "libkeepass/secure.hh"

namespace kpx {

extern const char* const kVersion;

/// Command-line options as parsed by kpx::ParseArgs.
struct Options {
  std::string input;
  keepass::secure_string password;
  std::string keyfile;
  std::string format = "text";
  std::string output;
  std::string export_path;
  bool with_passwords = false;
  bool verbose = false;
  bool help = false;
  bool show_version = false;
};

/// Parses the command-line arguments into opt. Supports long options
/// (--password, --keyfile, --format, --output, --export, --with-passwords,
/// --verbose, --help, --version, both with '=' and as separate value
/// arguments), combined short options (-p, -k) and the "--" separator.
/// Returns false and prints an error if an argument is unknown or malformed.
bool ParseArgs(int argc, const char* argv[], Options& opt);

/// Resolves the master password: the -p value, the KEEPASS_PASSWORD
/// environment variable or, on a terminal, an interactive prompt.
keepass::secure_string ResolvePassword(const Options& opt);

/// Returns true if the path names a KDB (legacy) key database.
bool IsKdbPath(const std::string& path);

/// Prints the command-line usage text to os.
void PrintUsage(const char* prog, std::ostream& os);

/// Exports db to path, dispatching on .kdb versus .kdbx format.
void ExportDatabase(const std::string& path, const keepass::Database& db, const keepass::Key& key);

/// Executes the kpx command with the given options. Returns the process exit
/// code.
int Run(const Options& opt, const char* argv0);

/// Program entry point without the surrounding main(); testable in-process.
int kpx_main(int argc, const char* argv[]);

} // namespace kpx