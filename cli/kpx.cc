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

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>

#ifndef _WIN32
#include <unistd.h>
#endif

#include "libkeepass/entry.hh"
#include "libkeepass/group.hh"
#include "libkeepass/keepass.hh"
#include "libkeepass/key.hh"

#include "kpx.hh"

#ifndef KPX_VERSION
#define KPX_VERSION "0.0.0"
#endif

namespace kpx {

const char* const kVersion = KPX_VERSION;

bool IsKdbPath(const std::string& path) {
  const std::string ext = Lower(path.substr(path.rfind('.') + 1));
  return ext == "kdb";
}

keepass::secure_string ResolvePassword(const Options& opt) {
  if (!opt.password.empty())
    return opt.password;

  const char* env = std::getenv("KEEPASS_PASSWORD");
  if (env != nullptr && *env != '\0')
    return {env};

#ifndef _WIN32
  if (isatty(STDIN_FILENO))
    return {getpass("Master password: ")};
#endif

  return {};
}

std::unique_ptr<keepass::Database> ImportDatabase(const std::string& path,
                                                  const keepass::Key& key) {
  keepass::KeePass keeper(key);
  return keeper.Open(path);
}

void ExportDatabase(const std::string& path, const keepass::Database& db, const keepass::Key& key) {
  keepass::KeePass keeper(key);
  keeper.Save(path, db);
}

int RunGenerate(const Options& opt) {
  std::ofstream file;
  if (!OpenOutput(opt, file))
    return 1;
  OutputStream(opt, file) << GeneratePassword(opt.generate) << "\n";
  return 0;
}

int Run(const Options& opt, const char* argv0) {
  if (opt.help) {
    PrintUsage(argv0, std::cout);
    return 0;
  }

  if (opt.show_version) {
    std::cout << argv0 << " " << kVersion << " (libkeepass)\n";
    return 0;
  }

  if (opt.generate > 0 && opt.command.empty() && opt.input.empty())
    return RunGenerate(opt);

  if (opt.input.empty()) {
    PrintUsage(argv0, std::cerr);
    return 1;
  }

  if (opt.command == "add" && (opt.title.empty() || !opt.has_title)) {
    std::cerr << "error: add requires --title <title>\n";
    return 1;
  }

  if (opt.format != "text" && opt.format != "json" && opt.format != "csv") {
    std::cerr << "error: unknown format '" << opt.format << "' (expected text, json or csv)\n";
    return 1;
  }

  if (opt.verbose) {
    std::cerr << argv0 << ": reading '" << opt.input << "' ("
              << (IsKdbPath(opt.input) ? "kdb" : "kdbx") << ")\n";
  }

  const keepass::secure_string password = ResolvePassword(opt);
  // KeePass stores the password in a wiped buffer and receives it here as a
  // transient std::string copy kept only until the constructor returns.
  keepass::KeePass keeper(password.str(), opt.keyfile);

  std::unique_ptr<keepass::Database> db = keeper.Open(opt.input);
  if (!db) {
    std::cerr << "error: could not open database\n";
    return 1;
  }

  if (opt.command == "add")
    return RunAdd(opt, keeper, db.get());
  if (opt.command == "update")
    return RunUpdate(opt, keeper, db.get());
  if (opt.command == "rm")
    return RunRemove(opt, keeper, db.get());

  if (opt.audit) {
    std::shared_ptr<keepass::Group> start = db->root();
    if (!opt.group.empty()) {
      start = db->FindGroup(opt.group);
      if (!start) {
        std::cerr << "error: group '" << opt.group << "' not found\n";
        return 1;
      }
    }
    return RunAudit(opt, start);
  }

  if (!opt.export_path.empty()) {
    keeper.Save(opt.export_path, *db);
    if (opt.verbose)
      std::cerr << argv0 << ": exported to '" << opt.export_path << "'\n";
    return 0;
  }

  std::shared_ptr<keepass::Group> start = db->root();
  if (!opt.group.empty()) {
    start = db->FindGroup(opt.group);
    if (!start) {
      std::cerr << "error: group '" << opt.group << "' not found\n";
      return 1;
    }
  }
  if (!opt.search.empty())
    start = PrunedRoot(start, opt.search, opt.regex);

  return RunPrint(opt, start);
}

int kpx_main(int argc, const char* argv[]) {
  try {
    Options opt;
    if (!ParseArgs(argc, argv, opt))
      return 1;
    return Run(opt, argv[0]);
  } catch (const std::exception& e) {
    std::cerr << "error: " << e.what() << "\n";
    return 1;
  }
}

} // namespace kpx

#ifndef KPX_NO_MAIN
int main(int argc, const char* argv[]) { return kpx::kpx_main(argc, argv); }
#endif