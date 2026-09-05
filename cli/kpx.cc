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

#include <cctype>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#ifndef _WIN32
#include <unistd.h>
#endif

#include "libkeepass/entry.hh"
#include "libkeepass/group.hh"
#include "libkeepass/kdb.hh"
#include "libkeepass/kdbx.hh"
#include "libkeepass/key.hh"

namespace {

const char* kVersion = "0.2.0";

struct Options {
  std::string input;
  std::string password;
  std::string keyfile;
  std::string format = "text";
  std::string output;
  std::string export_path;
  bool with_passwords = false;
  bool verbose = false;
  bool help = false;
  bool show_version = false;
};

void PrintUsage(const char* prog, std::ostream& os) {
  os << "Usage: " << prog << " [options] <database>\n"
     << "\n"
     << "Reads a KeePass database (KDB or KDBX) and either prints its entries\n"
     << "or exports it to a new KeePass file.\n"
     << "\n"
     << "Options:\n"
     << "  -p, --password <pw>   master password (env: KEEPASS_PASSWORD;\n"
     << "                        prompted if not given and stdin is a terminal)\n"
     << "  -k, --keyfile <path>  keyfile used together with the password\n"
     << "  -f, --format <fmt>    print format: text (default), json, csv\n"
     << "  -o, --output <path>   write print output to <path> instead of stdout\n"
     << "  -e, --export <path>   export the database to <path> (.kdb or .kdbx)\n"
     << "      --with-passwords  include passwords in text/csv output\n"
     << "  -v, --verbose         print diagnostics to stderr\n"
     << "  -h, --help            show this help and exit\n"
     << "      --version         print version and exit\n";
}

bool NextValue(int argc, const char* argv[], int& i, const std::string& name, bool has_value,
               const std::string& value, std::string& out) {
  if (has_value) {
    out = value;
    return true;
  }
  if (i + 1 >= argc) {
    std::cerr << "error: option '" << name << "' requires a value\n";
    return false;
  }
  out = argv[++i];
  return true;
}

std::string Lower(const std::string& s) {
  std::string lower;
  lower.reserve(s.size());
  for (const char c : s)
    lower.push_back(static_cast<char>(std::tolower(c)));
  return lower;
}

bool IsKdbPath(const std::string& path) {
  const std::string ext = Lower(path.substr(path.rfind('.') + 1));
  return ext == "kdb";
}

// Parses the command-line arguments into @p opt. Supports long options
// (--password, --keyfile, --format, --output, --export, --with-passwords,
// --verbose, --help, --version, both with '=' and as separate value
// arguments), combined short options (-p, -k) and the "--" separator.
// Returns false and prints an error if an argument is unknown or malformed.
bool ParseArgs(int argc, const char* argv[], Options& opt) {
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];

    if (arg == "--") {
      for (++i; i < argc; ++i) {
        if (!opt.input.empty()) {
          std::cerr << "error: unexpected extra argument '" << argv[i] << "'\n";
          return false;
        }
        opt.input = argv[i];
      }
      break;
    }

    if (arg.size() > 2 && arg.compare(0, 2, "--") == 0) {
      std::string name = arg.substr(2);
      std::string value;
      bool has_value = false;
      const std::size_t eq = name.find('=');
      if (eq != std::string::npos) {
        value = name.substr(eq + 1);
        name = name.substr(0, eq);
        has_value = true;
      }

      if (name == "password") {
        if (!NextValue(argc, argv, i, "--password", has_value, value, opt.password))
          return false;
      } else if (name == "keyfile") {
        if (!NextValue(argc, argv, i, "--keyfile", has_value, value, opt.keyfile))
          return false;
      } else if (name == "format") {
        if (!NextValue(argc, argv, i, "--format", has_value, value, opt.format))
          return false;
      } else if (name == "output") {
        if (!NextValue(argc, argv, i, "--output", has_value, value, opt.output))
          return false;
      } else if (name == "export") {
        if (!NextValue(argc, argv, i, "--export", has_value, value, opt.export_path))
          return false;
      } else if (name == "with-passwords") {
        opt.with_passwords = true;
      } else if (name == "verbose") {
        opt.verbose = true;
      } else if (name == "help") {
        opt.help = true;
      } else if (name == "version") {
        opt.show_version = true;
      } else {
        std::cerr << "error: unknown option '--" << name << "'\n";
        return false;
      }
      continue;
    }

    if (arg.size() > 1 && arg[0] == '-') {
      for (std::size_t j = 1; j < arg.size(); ++j) {
        const char c = arg[j];
        switch (c) {
        case 'p':
          if (j + 1 < arg.size()) {
            opt.password = arg.substr(j + 1);
            j = arg.size();
          } else if (i + 1 < argc) {
            opt.password = argv[++i];
          } else {
            std::cerr << "error: option '-p' requires a value\n";
            return false;
          }
          break;
        case 'k':
          if (j + 1 < arg.size()) {
            opt.keyfile = arg.substr(j + 1);
            j = arg.size();
          } else if (i + 1 < argc) {
            opt.keyfile = argv[++i];
          } else {
            std::cerr << "error: option '-k' requires a value\n";
            return false;
          }
          break;
        case 'f':
          if (j + 1 < arg.size()) {
            opt.format = arg.substr(j + 1);
            j = arg.size();
          } else if (i + 1 < argc) {
            opt.format = argv[++i];
          } else {
            std::cerr << "error: option '-f' requires a value\n";
            return false;
          }
          break;
        case 'o':
          if (j + 1 < arg.size()) {
            opt.output = arg.substr(j + 1);
            j = arg.size();
          } else if (i + 1 < argc) {
            opt.output = argv[++i];
          } else {
            std::cerr << "error: option '-o' requires a value\n";
            return false;
          }
          break;
        case 'e':
          if (j + 1 < arg.size()) {
            opt.export_path = arg.substr(j + 1);
            j = arg.size();
          } else if (i + 1 < argc) {
            opt.export_path = argv[++i];
          } else {
            std::cerr << "error: option '-e' requires a value\n";
            return false;
          }
          break;
        case 'v':
          opt.verbose = true;
          break;
        case 'h':
          opt.help = true;
          break;
        default:
          std::cerr << "error: unknown option '-" << c << "'\n";
          return false;
        }
      }
      continue;
    }

    if (!opt.input.empty()) {
      std::cerr << "error: unexpected extra argument '" << arg << "'\n";
      return false;
    }
    opt.input = arg;
  }
  return true;
}

std::string ResolvePassword(const Options& opt) {
  if (!opt.password.empty())
    return opt.password;

  const char* env = std::getenv("KEEPASS_PASSWORD");
  if (env != nullptr && *env != '\0')
    return env;

#ifndef _WIN32
  if (isatty(STDIN_FILENO))
    return getpass("Master password: ");
#endif

  return {};
}

std::unique_ptr<keepass::Database> ImportDatabase(const std::string& path,
                                                  const keepass::Key& key) {
  if (IsKdbPath(path))
    return keepass::KdbFile::Import(path, key);

  keepass::KdbxFile file;
  return file.Import(path, key);
}

void ExportDatabase(const std::string& path, const keepass::Database& db, const keepass::Key& key) {
  if (IsKdbPath(path)) {
    keepass::KdbFile::Export(path, db, key);
    return;
  }

  keepass::KdbxFile file;
  file.Export(path, db, key);
}

void PrintTextEntry(std::ostream& os, const std::shared_ptr<keepass::Entry>& entry,
                    const std::string& indent, bool with_passwords) {
  os << indent << "- " << *entry->title();
  if (!entry->username()->empty())
    os << " (" << *entry->username() << ")";
  if (!entry->url()->empty())
    os << " [" << *entry->url() << "]";
  os << "\n";

  if (with_passwords) {
    if (!entry->password()->empty())
      os << indent << "    password: " << *entry->password() << "\n";
    if (!entry->notes()->empty())
      os << indent << "    notes: " << *entry->notes() << "\n";
  }
}

void PrintTextGroup(std::ostream& os, const std::shared_ptr<keepass::Group>& group,
                    const std::string& indent, bool with_passwords) {
  os << indent << group->name() << "/\n";

  const std::string child_indent = indent + "    ";
  for (const auto& entry : group->Entries()) {
    if (entry->IsMetaEntry())
      continue;
    PrintTextEntry(os, entry, child_indent, with_passwords);
  }
  for (const auto& child : group->Groups())
    PrintTextGroup(os, child, child_indent, with_passwords);
}

void PrintText(std::ostream& os, const std::shared_ptr<keepass::Group>& root, bool with_passwords) {
  if (!root->name().empty())
    os << root->name() << "/\n";

  for (const auto& entry : root->Entries()) {
    if (entry->IsMetaEntry())
      continue;
    PrintTextEntry(os, entry, root->name().empty() ? "" : "    ", with_passwords);
  }
  for (const auto& group : root->Groups())
    PrintTextGroup(os, group, root->name().empty() ? "" : "    ", with_passwords);
}

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

void PrintCsvGroup(std::ostream& os, const std::shared_ptr<keepass::Group>& group,
                   const std::string& path, bool with_passwords) {
  std::string group_path = path;
  if (!group->name().empty()) {
    if (!group_path.empty())
      group_path += "/";
    group_path += group->name();
  }

  for (const auto& entry : group->Entries()) {
    if (entry->IsMetaEntry())
      continue;

    os << CsvField(group_path) << "," << CsvField(*entry->title()) << ","
       << CsvField(*entry->username()) << ","
       << (with_passwords ? CsvField(*entry->password()) : std::string()) << ","
       << CsvField(*entry->url()) << "," << CsvField(*entry->notes()) << "\n";
  }
  for (const auto& child : group->Groups())
    PrintCsvGroup(os, child, group_path, with_passwords);
}

void PrintCsv(std::ostream& os, const std::shared_ptr<keepass::Group>& root, bool with_passwords) {
  os << "Group,Title,Username,Password,Url,Notes\n";
  PrintCsvGroup(os, root, std::string(), with_passwords);
}

bool OpenOutput(const Options& opt, std::ofstream& file, std::ostream*& out) {
  if (opt.output.empty()) {
    out = &std::cout;
    return true;
  }

  file.open(opt.output.c_str());
  if (!file.is_open()) {
    std::cerr << "error: cannot open output file '" << opt.output << "'\n";
    return false;
  }
  out = &file;
  return true;
}

} // namespace

int Run(const Options& opt, const char* argv0) {
  if (opt.help) {
    PrintUsage(argv0, std::cout);
    return 0;
  }

  if (opt.show_version) {
    std::cout << argv0 << " " << kVersion << " (libkeepass)\n";
    return 0;
  }

  if (opt.input.empty()) {
    PrintUsage(argv0, std::cerr);
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

  const std::string password = ResolvePassword(opt);
  keepass::Key key(password);
  if (!opt.keyfile.empty())
    key.SetKeyFile(opt.keyfile);

  std::unique_ptr<keepass::Database> db = ImportDatabase(opt.input, key);
  if (!db) {
    std::cerr << "error: could not open database\n";
    return 1;
  }

  if (!opt.export_path.empty()) {
    ExportDatabase(opt.export_path, *db, key);
    if (opt.verbose)
      std::cerr << argv0 << ": exported to '" << opt.export_path << "'\n";
    return 0;
  }

  std::ofstream file;
  std::ostream* out = nullptr;
  if (!OpenOutput(opt, file, out))
    return 1;

  if (opt.format == "json") {
    *out << db->root()->ToJson() << "\n";
  } else if (opt.format == "csv") {
    PrintCsv(*out, db->root(), opt.with_passwords);
  } else {
    PrintText(*out, db->root(), opt.with_passwords);
  }
  return 0;
}

int main(int argc, const char* argv[]) {
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