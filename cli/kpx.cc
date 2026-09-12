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

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <functional>
#include <iostream>
#include <memory>
#include <random>
#include <regex>
#include <string>
#include <vector>

#ifndef _WIN32
#include <unistd.h>
#endif

#include "libkeepass/entry.hh"
#include "libkeepass/group.hh"
#include "libkeepass/keepass.hh"
#include "libkeepass/key.hh"

#include "kpx.hh"

namespace kpx {

const char* const kVersion = "0.2.0";

const char* const kGenerateCharset = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
                                     "!@#$%^&*()-_=+[]{};:,.?";

void PrintUsage(const char* prog, std::ostream& os) {
  os << "Usage: " << prog << " [options] <database>\n"
     << "       " << prog << " [options] <command> <database>\n"
     << "\n"
     << "Reads a KeePass database (KDB or KDBX) and prints its entries, exports\n"
     << "it to a new KeePass file, or edits it in place (add/update/rm).\n"
     << "\n"
     << "Options:\n"
     << "  -p, --password <pw>   master password (env: KEEPASS_PASSWORD;\n"
     << "                        prompted if not given and stdin is a terminal)\n"
     << "  -k, --keyfile <path>  keyfile used together with the password\n"
     << "  -f, --format <fmt>    print format: text (default), json, csv\n"
     << "  -o, --output <path>   write print output to <path> instead of stdout\n"
     << "  -e, --export <path>   export the database to <path> (.kdb or .kdbx)\n"
     << "      --with-passwords  include passwords in text/csv output\n"
     << "      --search <query>  only print entries matching <query> (title,\n"
     << "                        username, URL or notes; case-insensitive substring)\n"
     << "      --regex           treat --search as a regular expression\n"
     << "      --group <name>    only print the subtree of the named group\n"
     << "      --generate[=n]    print a generated random password (default\n"
     << "                        length 16, max 256); with `add`, sets the new\n"
     << "                        entry password when --pass is absent\n"
     << "  -v, --verbose         print diagnostics to stderr\n"
     << "  -h, --help            show this help and exit\n"
     << "      --version         print version and exit\n"
     << "\n"
     << "Commands (first positional argument; default: print):\n"
     << "  add    create an entry (--group <name>, --title, --user, --pass,\n"
     << "         --url, --notes)\n"
     << "  update modify matching entries (--search <query> and at least one\n"
     << "         of --title, --user, --pass, --url, --notes)\n"
     << "  rm     delete the entry with an exact title (--title), all entries\n"
     << "         matching --search <query>, or a whole group (--group <name>)\n"
     << "\n"
     << "Exit code: 0 on success, 1 on any error.\n";
}

template <typename T>
bool NextValue(int argc, const char* argv[], int& i, const std::string& name, bool has_value,
               const std::string& value, T& out) {
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

// The edit commands are recognized as the first positional argument.
bool IsCommand(const std::string& arg) { return arg == "add" || arg == "update" || arg == "rm"; }

// Parses the --generate length, printing an error and returning -1 on invalid
// input. Lengths are clamped to [1, kMaxGenerateLength].
int ParseGenerateLength(const std::string& value, const std::string& option) {
  char* end = nullptr;
  const long length = std::strtol(value.c_str(), &end, 10);
  if (end == value.c_str() || *end != '\0' || length <= 0 || length > kMaxGenerateLength) {
    std::cerr << "error: option '" << option << "' expects a length between 1 and "
              << kMaxGenerateLength << "\n";
    return -1;
  }
  return static_cast<int>(length);
}

// Case-insensitive containment of needle_lower in haystack.
bool ContainsLower(const std::string& haystack, const std::string& needle_lower) {
  return Lower(haystack).find(needle_lower) != std::string::npos;
}

// Returns whether the string consists entirely of decimal digits.
bool IsNumeric(const std::string& s) {
  return !s.empty() && std::all_of(s.begin(), s.end(), [](char c) {
    return std::isdigit(static_cast<unsigned char>(c));
  });
}

// Returns whether an entry matches the search query. By default a
// case-insensitive substring search over title, username, URL and notes;
// with regex, std::regex_search on the same fields. With exact_title only the
// exact title is compared.
bool EntryMatches(const std::shared_ptr<keepass::Entry>& entry, const std::string& query,
                  bool regex, bool exact_title) {
  if (exact_title)
    return entry->title()->str() == query;

  if (regex) {
    try {
      const std::regex re(query);
      return std::regex_search(entry->title()->str(), re) ||
             std::regex_search(entry->username()->str(), re) ||
             std::regex_search(entry->url()->str(), re) ||
             std::regex_search(entry->notes()->str(), re);
    } catch (const std::regex_error& e) {
      throw std::invalid_argument(std::string("invalid regular expression: ") + e.what());
    }
  }

  const std::string needle = Lower(query);
  return ContainsLower(entry->title()->str(), needle) ||
         ContainsLower(entry->username()->str(), needle) ||
         ContainsLower(entry->url()->str(), needle) || ContainsLower(entry->notes()->str(), needle);
}

// Collects all entries under the given group that match the query.
std::vector<std::shared_ptr<keepass::Entry>>
SearchEntries(const std::shared_ptr<keepass::Group>& start, const std::string& query, bool regex,
              bool exact_title) {
  std::vector<std::shared_ptr<keepass::Entry>> result;
  std::function<void(const std::shared_ptr<keepass::Group>&)> collect =
      [&](const std::shared_ptr<keepass::Group>& group) {
        for (const auto& entry : group->Entries()) {
          if (EntryMatches(entry, query, regex, exact_title))
            result.push_back(entry);
        }
        for (const auto& child : group->Groups())
          collect(child);
      };
  collect(start);
  return result;
}

// Builds a lightweight copy of the group tree that contains only the entries
// matching the query and their ancestor groups. The copied groups only carry
// their names; the entries are the original objects. Used to feed the regular
// print pipeline when --search filters the output.
std::shared_ptr<keepass::Group> PrunedRoot(const std::shared_ptr<keepass::Group>& src,
                                           const std::string& query, bool regex) {
  std::shared_ptr<keepass::Group> pruned = std::make_shared<keepass::Group>();
  pruned->set_name(src->name());

  for (const auto& child : src->Groups()) {
    std::shared_ptr<keepass::Group> pruned_child = PrunedRoot(child, query, regex);
    if (!pruned_child->Groups().empty() || !pruned_child->Entries().empty())
      pruned->AddGroup(pruned_child);
  }
  for (const auto& entry : src->Entries()) {
    if (EntryMatches(entry, query, regex, false))
      pruned->AddEntry(entry);
  }
  return pruned;
}

// Generates a random password of the given length from a printable character
// set guarded against ambiguity between look-alike characters.
std::string GeneratePassword(int length) {
  const std::string chars(kGenerateCharset);
  const std::size_t count = chars.size();

  std::mt19937 rng(std::random_device{}());
  std::uniform_int_distribution<std::size_t> dist(0, count - 1);

  std::string password;
  password.reserve(length);
  for (int i = 0; i < length; ++i)
    password.push_back(chars[dist(rng)]);
  return password;
}

// Parses the command-line arguments into @p opt. Supports long options
// (--password, --keyfile, --format, --output, --export, --with-passwords,
// --verbose, --help, --version, both with '=' and as separate value
// arguments), combined short options (-p, -k) and the "--" separator.
// Returns false and prints an error if an argument is unknown or malformed.
bool ParseArgs(int argc, const char* argv[], Options& opt) {
  bool skip_next = false;
  for (int i = 1; i < argc; ++i) {
    if (skip_next) {
      // This element was already consumed as the value of a short option.
      skip_next = false;
      continue;
    }

    const std::string arg = argv[i];

    // "--" ends option parsing; every remaining element is the input path.
    if (arg == "--") {
      for (int rest_idx = i + 1; rest_idx < argc; ++rest_idx) {
        if (opt.command.empty() && IsCommand(argv[rest_idx])) {
          opt.command = argv[rest_idx];
        } else if (opt.input.empty()) {
          opt.input = argv[rest_idx];
        } else {
          std::cerr << "error: unexpected extra argument '" << argv[rest_idx] << "'\n";
          return false;
        }
      }
      break;
    }

    // Long options, either as "--name=value" or as "--name value".
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
      } else if (name == "search") {
        if (!NextValue(argc, argv, i, "--search", has_value, value, opt.search))
          return false;
      } else if (name == "group") {
        if (!NextValue(argc, argv, i, "--group", has_value, value, opt.group))
          return false;
      } else if (name == "generate") {
        if (has_value) {
          opt.generate = ParseGenerateLength(value, "--generate");
          if (opt.generate < 0)
            return false;
        } else if (i + 1 < argc && IsNumeric(argv[i + 1])) {
          // A following bare number is consumed as the optional length.
          opt.generate = ParseGenerateLength(argv[++i], "--generate");
          if (opt.generate < 0)
            return false;
        } else {
          opt.generate = kDefaultGenerateLength;
        }
      } else if (name == "regex") {
        opt.regex = true;
      } else if (name == "title") {
        opt.has_title = true;
        if (!NextValue(argc, argv, i, "--title", has_value, value, opt.title))
          return false;
      } else if (name == "user") {
        opt.has_user = true;
        if (!NextValue(argc, argv, i, "--user", has_value, value, opt.user))
          return false;
      } else if (name == "pass") {
        opt.has_pass = true;
        if (!NextValue(argc, argv, i, "--pass", has_value, value, opt.entry_password))
          return false;
      } else if (name == "url") {
        opt.has_url = true;
        if (!NextValue(argc, argv, i, "--url", has_value, value, opt.url))
          return false;
      } else if (name == "notes") {
        opt.has_notes = true;
        if (!NextValue(argc, argv, i, "--notes", has_value, value, opt.notes))
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

    // Short options may be combined; a value-taking option consumes the rest
    // of the argument or, if empty, the following argument.
    if (arg.size() > 1 && arg[0] == '-') {
      bool consumed_rest = false;
      for (std::size_t j = 1; j < arg.size(); ++j) {
        const char c = arg[j];
        switch (c) {
        case 'p':
          if (j + 1 < arg.size()) {
            opt.password = arg.substr(j + 1);
            consumed_rest = true;
          } else if (i + 1 < argc) {
            opt.password = argv[i + 1];
            skip_next = true;
          } else {
            std::cerr << "error: option '-p' requires a value\n";
            return false;
          }
          break;
        case 'k':
          if (j + 1 < arg.size()) {
            opt.keyfile = arg.substr(j + 1);
            consumed_rest = true;
          } else if (i + 1 < argc) {
            opt.keyfile = argv[i + 1];
            skip_next = true;
          } else {
            std::cerr << "error: option '-k' requires a value\n";
            return false;
          }
          break;
        case 'f':
          if (j + 1 < arg.size()) {
            opt.format = arg.substr(j + 1);
            consumed_rest = true;
          } else if (i + 1 < argc) {
            opt.format = argv[i + 1];
            skip_next = true;
          } else {
            std::cerr << "error: option '-f' requires a value\n";
            return false;
          }
          break;
        case 'o':
          if (j + 1 < arg.size()) {
            opt.output = arg.substr(j + 1);
            consumed_rest = true;
          } else if (i + 1 < argc) {
            opt.output = argv[i + 1];
            skip_next = true;
          } else {
            std::cerr << "error: option '-o' requires a value\n";
            return false;
          }
          break;
        case 'e':
          if (j + 1 < arg.size()) {
            opt.export_path = arg.substr(j + 1);
            consumed_rest = true;
          } else if (i + 1 < argc) {
            opt.export_path = argv[i + 1];
            skip_next = true;
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
        if (consumed_rest)
          break;
      }
      continue;
    }

    if (opt.command.empty() && IsCommand(arg)) {
      opt.command = arg;
    } else if (opt.input.empty()) {
      opt.input = arg;
    } else {
      std::cerr << "error: unexpected extra argument '" << arg << "'\n";
      return false;
    }
  }
  return true;
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

    os << CsvField(group_path) << "," << CsvField(entry->title()->str()) << ","
       << CsvField(entry->username()->str()) << ","
       << (with_passwords ? CsvField(entry->password()->str()) : std::string()) << ","
       << CsvField(entry->url()->str()) << "," << CsvField(entry->notes()->str()) << "\n";
  }
  for (const auto& child : group->Groups())
    PrintCsvGroup(os, child, group_path, with_passwords);
}

void PrintCsv(std::ostream& os, const std::shared_ptr<keepass::Group>& root, bool with_passwords) {
  os << "Group,Title,Username,Password,Url,Notes\n";
  PrintCsvGroup(os, root, std::string(), with_passwords);
}

// Opens the output stream for the print commands. When --output is given the
// stream is opened in the provided file object; otherwise stdout is used and
// no file is opened. Returns false and prints an error if the file cannot be
// opened.
bool OpenOutput(const Options& opt, std::ofstream& file) {
  if (opt.output.empty())
    return true;

  file.open(opt.output.c_str());
  if (!file.is_open()) {
    std::cerr << "error: cannot open output file '" << opt.output << "'\n";
    return false;
  }
  return true;
}

std::ostream& OutputStream(const Options& opt, std::ofstream& file) {
  return opt.output.empty() ? static_cast<std::ostream&>(std::cout)
                            : static_cast<std::ostream&>(file);
}

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

int RunGenerate(const Options& opt) {
  std::ofstream file;
  if (!OpenOutput(opt, file))
    return 1;
  OutputStream(opt, file) << GeneratePassword(opt.generate) << "\n";
  return 0;
}

int RunPrint(const Options& opt, const std::shared_ptr<keepass::Group>& root) {
  std::ofstream file;
  if (!OpenOutput(opt, file))
    return 1;
  std::ostream& out = OutputStream(opt, file);

  if (opt.format == "json") {
    out << root->ToJson() << "\n";
  } else if (opt.format == "csv") {
    PrintCsv(out, root, opt.with_passwords);
  } else {
    PrintText(out, root, opt.with_passwords);
  }
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