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

#include "output.hh"

#include <cctype>
#include <ctime>
#include <functional>
#include <iostream>
#include <map>
#include <regex>
#include <utility>

#include "libkeepass/database.hh"
#include "libkeepass/entry.hh"
#include "libkeepass/group.hh"

namespace kpx {

void PrintUsage(const char* prog, std::ostream& os) {
  os << "Usage: " << prog << " [options] <database>\n"
     << "       " << prog << " [options] <command> <database>\n"
     << "\n"
     << "Reads a KeePass database (KDB or KDBX) and prints its entries, exports\n"
     << "it to a new KeePass file, or edits it in place (add/update/rm).\n"
     << "\n"
     << "Options:\n"
     << "  -p, --password <pw>   master password (visible in the process list;\n"
     << "                        prefer --password-file or --password-stdin)\n"
     << "      --password-file <path>\n"
     << "                        read the master password from <path> (\"-\" for\n"
     << "                        stdin; a trailing line break is stripped)\n"
     << "      --password-stdin  read the master password from stdin\n"
     << "      --new-password <pw>\n"
     << "                        new master password for the passwd command\n"
     << "      --new-password-file <path>\n"
     << "                        read the new master password from <path> (\"-\"\n"
     << "                        for stdin)\n"
     << "      --new-password-stdin\n"
     << "                        read the new master password from stdin\n"
     << "  -k, --keyfile <path>  keyfile used together with the password\n"
     << "      --kdf <name>      change the KDF: aes, argon2d or argon2id\n"
     << "      --to <group>      destination group for move/merge\n"
     << "      --from <path>     source database for merge/import\n"
     << "      --all             select all entries (purge)\n"
     << "      --force           overwrite an existing file for the create command\n"
     << "      (fallback: KEEPASS_PASSWORD; interactive prompt when stdin is a\n"
     << "       terminal and no other password source is given)\n"
     << "  -f, --format <fmt>    print format: text (default), json, csv\n"
     << "  -o, --output <path>   write print output to <path> instead of stdout\n"
     << "  -e, --export <path>   export the database to <path> (.kdb or .kdbx)\n"
     << "      --with-passwords  include passwords in text/csv output\n"
     << "      --include-attachments\n"
     << "                        include attachment payloads as base64 in JSON\n"
     << "      --search <query>  only print entries matching <query> (title,\n"
     << "                        username, URL or notes; case-insensitive substring)\n"
     << "      --regex           treat --search as a regular expression\n"
     << "      --group <name>    only print the subtree of the named group\n"
     << "      --audit           audit passwords: report weak (short,\n"
     << "                        single-class, common, based on title/username)\n"
     << "                        and reused passwords (text/json/csv)\n"
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
     << "  groups list all groups (or the --group subtree) without entries\n"
     << "  create create a new empty database at <path> (--force to overwrite)\n"
     << "  passwd change the master password and/or KDF in place\n"
     << "         (--new-password*, --kdf)\n"
     << "  move   move entries (--title/--search) or a group (--group) to --to\n"
     << "  history print entry history versions (--title/--search/--group)\n"
     << "  purge  clear entry history (--title/--search/--group or --all)\n"
     << "  otp    print TOTP seeds/settings stored in custom fields\n"
     << "  merge  merge a second database (--from <path>, optional --to <group>)\n"
     << "         into the target; both use the same password/keyfile\n"
     << "  import alias for merge\n"
     << "\n"
     << "Exit codes: 0 success, 1 command/usage error, 3 wrong password/key,\n"
     << "            4 corrupt/unsupported database, 5 I/O or missing file.\n"
     << "Errors are printed as {\"error\":{\"category\":...,\"message\":...}} when\n"
     << "--format json is selected.\n";
}

// Case-insensitive containment of needle_lower in haystack.
bool ContainsLower(const std::string& haystack, const std::string& needle_lower) {
  return Lower(haystack).find(needle_lower) != std::string::npos;
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

std::vector<std::shared_ptr<keepass::Entry>>
CollectEntries(const std::shared_ptr<keepass::Group>& start) {
  std::vector<std::shared_ptr<keepass::Entry>> result;
  std::function<void(const std::shared_ptr<keepass::Group>&)> collect =
      [&](const std::shared_ptr<keepass::Group>& group) {
        for (const auto& entry : group->Entries())
          result.push_back(entry);
        for (const auto& child : group->Groups())
          collect(child);
      };
  if (start)
    collect(start);
  return result;
}

std::vector<std::shared_ptr<keepass::Entry>>
SelectEntries(const Options& opt, const std::shared_ptr<keepass::Group>& start) {
  if (opt.has_title)
    return SearchEntries(start, opt.title, false, true);
  if (!opt.search.empty())
    return SearchEntries(start, opt.search, opt.regex, false);
  return CollectEntries(start);
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

// Escapes a string for inclusion as a single CSV field.
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

// Serializes the database as CSV, reusing the library serializer.
void PrintCsv(std::ostream& os, const std::shared_ptr<keepass::Group>& root, bool with_passwords) {
  keepass::Database db;
  if (root)
    db.set_root(root);
  os << db.ToCsv(with_passwords ? keepass::CsvFormat::kCsvWithPasswords : keepass::CsvFormat::kCsv);
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

// The shortest password that is not flagged as "short".
constexpr std::size_t kMinAuditPasswordLength = 12;

// Well-known weak passwords checked independently of length and character
// classes. Kept deliberately small and curated; the audit is a heuristic.
constexpr const char* const kCommonPasswords[] = {
    "123456", "password",  "12345678", "123456789", "qwerty",   "1234567890", "1234567",
    "111111", "123123",    "abc123",   "admin",     "letmein",  "000000",     "monkey",
    "dragon", "password1", "iloveyou", "sunshine",  "princess", "football",   "welcome",
    "shadow", "superman",  "michael",  "654321",    "1234",     "12345"};

// A single audited entry with the group path relative to the audit root and
// the findings produced by AuditClassify and the reuse detection.
struct AuditEntry {
  std::string path;
  std::shared_ptr<keepass::Entry> entry;
  std::vector<std::string> issues;

  std::string DisplayPath() const {
    std::string full = path;
    if (!full.empty())
      full += "/";
    full += entry->title()->str();
    return full;
  }
};

// A password value used by two or more audited entries.
struct AuditReuse {
  std::string password;
  std::vector<size_t> rows;
};

// Collects audit candidates below @p group. @p path accumulates the group
// path relative to the audit root; meta entries are skipped like the print
// commands skip them.
void AuditCollect(const std::shared_ptr<keepass::Group>& group, const std::string& path,
                  std::vector<AuditEntry>& rows) {
  for (const auto& entry : group->Entries()) {
    if (entry->IsMetaEntry())
      continue;
    AuditEntry row;
    row.path = path;
    row.entry = entry;
    rows.emplace_back(std::move(row));
  }
  for (const auto& child : group->Groups()) {
    const std::string child_path = path.empty() ? child->name() : path + "/" + child->name();
    AuditCollect(child, child_path, rows);
  }
}

// Heuristic findings for a single entry password: empty, too short, a single
// character class, a password derived from the title/username, or an entry of
// the common-password list. The "reused" finding is added separately after all
// passwords have been collected.
std::vector<std::string> AuditClassify(const std::shared_ptr<keepass::Entry>& entry) {
  const std::string password = entry->password()->str();
  std::vector<std::string> issues;

  if (password.empty()) {
    issues.emplace_back("empty");
    return issues;
  }

  if (password.size() < kMinAuditPasswordLength)
    issues.emplace_back("short (" + std::to_string(password.size()) + ")");

  bool lower = false;
  bool upper = false;
  bool digit = false;
  bool other = false;
  for (const unsigned char c : password) {
    if (std::islower(c)) {
      lower = true;
    } else if (std::isupper(c)) {
      upper = true;
    } else if (std::isdigit(c)) {
      digit = true;
    } else {
      other = true;
    }
  }
  const int variety = static_cast<int>(lower) + static_cast<int>(upper) + static_cast<int>(digit) +
                      static_cast<int>(other);
  if (variety == 1)
    issues.emplace_back(digit ? "digits-only" : "single-character-class");

  const std::string lower_password = Lower(password);
  const std::string title = Lower(entry->title()->str());
  if (title.size() >= 4 && lower_password.find(title) != std::string::npos)
    issues.emplace_back("based-on-title");
  const std::string user = Lower(entry->username()->str());
  if (user.size() >= 4 && lower_password.find(user) != std::string::npos)
    issues.emplace_back("based-on-username");

  for (const char* common : kCommonPasswords) {
    if (password == common) {
      issues.emplace_back("common-password");
      break;
    }
  }

  return issues;
}

// Escapes a string for inclusion in the JSON output of the audit.
std::string JsonEscape(const std::string& s) {
  std::string out;
  out.reserve(s.size());
  for (const char c : s) {
    switch (c) {
    case '"':
      out += "\\\"";
      break;
    case '\\':
      out += "\\\\";
      break;
    case '\n':
      out += "\\n";
      break;
    case '\r':
      out += "\\r";
      break;
    case '\t':
      out += "\\t";
      break;
    default:
      out += c;
    }
  }
  return out;
}

// Joins the given items with the separator.
std::string Join(const std::vector<std::string>& items, const std::string& separator) {
  std::string out;
  for (std::size_t i = 0; i < items.size(); ++i) {
    if (i != 0)
      out += separator;
    out += items[i];
  }
  return out;
}

int RunAudit(const Options& opt, const std::shared_ptr<keepass::Group>& start) {
  std::vector<AuditEntry> rows;
  AuditCollect(start, start->name(), rows);

  // Reuse detection: group the row indices by (non-empty) password value.
  std::map<std::string, std::vector<size_t>> reuse;
  for (size_t i = 0; i < rows.size(); ++i) {
    const std::string password = rows[i].entry->password()->str();
    if (!password.empty())
      reuse[password].emplace_back(i);
  }

  // Classify every row and append a reuse finding when two or more entries
  // share the password. Consecutive rows with the same password are coalesced
  // into a single AuditReuse group for the summary output.
  std::vector<AuditReuse> reused;
  int with_issues = 0;
  for (AuditEntry& row : rows) {
    row.issues = AuditClassify(row.entry);

    const std::string password = row.entry->password()->str();
    const auto reuse_it = reuse.find(password);
    if (reuse_it != reuse.end() && reuse_it->second.size() > 1) {
      row.issues.emplace_back("reused (" + std::to_string(reuse_it->second.size()) + " entries)");
      if (reused.empty() || reused.back().password != password) {
        AuditReuse group;
        group.password = password;
        group.rows = reuse_it->second;
        reused.emplace_back(std::move(group));
      }
    }
    if (!row.issues.empty())
      ++with_issues;
  }

  std::ofstream file;
  if (!OpenOutput(opt, file))
    return 1;
  std::ostream& out = OutputStream(opt, file);

  // Emit the report in the requested format. JSON and CSV stream every affected
  // entry and the reused-password groups; the text fallback prints a summary.
  if (opt.format == "json") {
    out << "{\"audited\":" << rows.size() << ",\"issues\":[";
    bool first = true;
    for (const auto& row : rows) {
      if (row.issues.empty())
        continue;
      if (!first)
        out << ",";
      first = false;
      out << R"({"group":")" << JsonEscape(row.path) << '"' << ',' << R"("title":")"
          << JsonEscape(row.entry->title()->str()) << '"' << ","
          << "\"issues\":[";
      for (std::size_t j = 0; j < row.issues.size(); ++j) {
        if (j != 0)
          out << ",";
        out << "\"" << JsonEscape(row.issues[j]) << "\"";
      }
      out << "]";
      if (opt.with_passwords)
        out << R"(,"password":")" << JsonEscape(row.entry->password()->str()) << '"';
      out << "}";
    }
    out << "],\"reused\":[";
    first = true;
    for (const auto& group : reused) {
      if (!first)
        out << ",";
      first = false;
      out << "{\"password\":";
      if (opt.with_passwords)
        out << "\"" << JsonEscape(group.password) << "\"";
      else
        out << "null";
      out << ",\"entries\":[";
      for (std::size_t j = 0; j < group.rows.size(); ++j) {
        if (j != 0)
          out << ",";
        out << "\"" << JsonEscape(rows[group.rows[j]].DisplayPath()) << "\"";
      }
      out << "]}";
    }
    out << "]}\n";
  } else if (opt.format == "csv") {
    if (opt.with_passwords)
      out << "Group,Title,Issues,Password\n";
    else
      out << "Group,Title,Issues\n";
    for (const auto& row : rows) {
      if (row.issues.empty())
        continue;
      out << CsvField(row.path) << "," << CsvField(row.entry->title()->str()) << ","
          << CsvField(Join(row.issues, ";"));
      if (opt.with_passwords)
        out << "," << CsvField(row.entry->password()->str());
      out << "\n";
    }
    return 0;
  }

  if (rows.empty()) {
    out << "No entries to audit.\n";
    return 0;
  }
  if (with_issues == 0) {
    out << "No issues found (" << rows.size() << " entr" << (rows.size() == 1 ? "y" : "ies")
        << " audited).\n";
    return 0;
  }

  out << "Issues found:\n";
  for (const auto& row : rows) {
    if (row.issues.empty())
      continue;
    out << "  " << row.DisplayPath() << ": " << Join(row.issues, "; ") << "\n";
  }

  if (!reused.empty() && opt.with_passwords) {
    out << "\nReused passwords:\n";
    for (const auto& group : reused) {
      out << "  " << group.password << " (" << group.rows.size() << " entries): ";
      for (std::size_t j = 0; j < group.rows.size(); ++j) {
        if (j != 0)
          out << "; ";
        out << rows[group.rows[j]].DisplayPath();
      }
      out << "\n";
    }
  }

  out << "\nSummary: " << with_issues << " of " << rows.size() << " entries have issues, "
      << reused.size() << " reused password" << (reused.size() == 1 ? "" : "s") << ".\n";
  return 0;
}

int RunGroups(const Options& opt, const std::shared_ptr<keepass::Group>& root) {
  std::ofstream file;
  if (!OpenOutput(opt, file))
    return 1;
  std::ostream& out = OutputStream(opt, file);

  std::vector<std::shared_ptr<keepass::Group>> groups;
  std::function<void(const std::shared_ptr<keepass::Group>&)> collect =
      [&](const std::shared_ptr<keepass::Group>& group) {
        groups.push_back(group);
        for (const auto& child : group->Groups())
          collect(child);
      };
  if (root)
    collect(root);

  if (opt.format == "json") {
    out << "[";
    for (std::size_t i = 0; i < groups.size(); ++i) {
      if (i != 0)
        out << ",";
      out << R"({"path":")" << JsonEscape(groups[i]->path()) << R"(","entries":)"
          << groups[i]->entries_count() << R"(,"groups":)" << groups[i]->groups_count() << "}";
    }
    out << "]\n";
  } else if (opt.format == "csv") {
    out << "Path,Entries,Groups\n";
    for (const auto& group : groups)
      out << CsvField(group->path()) << ',' << group->entries_count() << ','
          << group->groups_count() << "\n";
  } else {
    for (const auto& group : groups)
      out << group->path() << "\n";
  }
  return 0;
}

std::string FormatTimestamp(std::time_t time) {
  if (time <= 0)
    return {};
  const std::tm* tm = std::gmtime(&time);
  if (tm == nullptr)
    return std::to_string(time);
  char buffer[32];
  if (std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", tm) == 0)
    return std::to_string(time);
  return buffer;
}

int RunHistory(const Options& opt, const std::shared_ptr<keepass::Group>& start) {
  std::ofstream file;
  if (!OpenOutput(opt, file))
    return 1;
  std::ostream& out = OutputStream(opt, file);

  const auto entries = SelectEntries(opt, start);

  if (opt.format == "json") {
    bool first = true;
    out << "[";
    for (const auto& entry : entries) {
      if (entry->history().empty())
        continue;
      if (!first)
        out << ",";
      first = false;
      out << R"({"path":")" << JsonEscape(entry->path()) << R"(","history":[)";
      for (std::size_t i = 0; i < entry->history().size(); ++i) {
        const auto& history = entry->history()[i];
        if (i != 0)
          out << ",";
        out << R"({"title":")" << JsonEscape(history->title()->str()) << R"(","username":")"
            << JsonEscape(history->username()->str()) << R"(","modification_time":")"
            << FormatTimestamp(history->modification_time()) << "\"}";
      }
      out << "]}";
    }
    out << "]\n";
    return 0;
  }

  if (opt.format == "csv") {
    out << "Path,Title,Username,ModificationTime\n";
    for (const auto& entry : entries) {
      for (const auto& history : entry->history()) {
        out << CsvField(entry->path()) << ',' << CsvField(history->title()->str()) << ','
            << CsvField(history->username()->str()) << ','
            << CsvField(FormatTimestamp(history->modification_time())) << "\n";
      }
    }
    return 0;
  }

  for (const auto& entry : entries) {
    if (entry->history().empty())
      continue;
    out << entry->path() << " (" << entry->history().size() << " history "
        << (entry->history().size() == 1 ? "entry" : "entries") << ")\n";
    for (const auto& history : entry->history()) {
      out << "  [" << FormatTimestamp(history->modification_time()) << "] "
          << history->title()->str();
      if (!history->username()->empty())
        out << " (" << history->username()->str() << ")";
      out << "\n";
    }
  }
  return 0;
}

int RunOtp(const Options& opt, const std::shared_ptr<keepass::Group>& start) {
  struct OtpRow {
    std::string path;
    std::string seed;
    std::string settings;
  };

  std::vector<OtpRow> rows;
  for (const auto& entry : SelectEntries(opt, start)) {
    const auto properties = entry->custom_properties();
    std::string seed;
    std::string settings;
    for (const auto& [key, value] : properties) {
      const std::string lower = Lower(key);
      if (lower == "otp" || lower == "totp seed" || lower == "otp seed" || lower == "totpsecret" ||
          lower == "totp_secret") {
        seed = value;
      } else if (lower == "totp settings" || lower == "otp settings") {
        settings = value;
      }
    }
    if (!seed.empty())
      rows.push_back({entry->path(), seed, settings});
  }

  std::ofstream file;
  if (!OpenOutput(opt, file))
    return 1;
  std::ostream& out = OutputStream(opt, file);

  if (opt.format == "json") {
    out << "[";
    for (std::size_t i = 0; i < rows.size(); ++i) {
      if (i != 0)
        out << ",";
      out << R"({"path":")" << JsonEscape(rows[i].path) << R"(","seed":")"
          << JsonEscape(rows[i].seed) << R"(","settings":")" << JsonEscape(rows[i].settings)
          << "\"}";
    }
    out << "]\n";
    return 0;
  }

  if (opt.format == "csv") {
    out << "Path,Seed,Settings\n";
    for (const auto& row : rows)
      out << CsvField(row.path) << ',' << CsvField(row.seed) << ',' << CsvField(row.settings)
          << "\n";
    return 0;
  }

  for (const auto& row : rows) {
    out << row.path << ": " << row.seed;
    if (!row.settings.empty())
      out << " [" << row.settings << "]";
    out << "\n";
  }
  return 0;
}

int RunPrint(const Options& opt, const std::shared_ptr<keepass::Group>& root) {
  std::ofstream file;
  if (!OpenOutput(opt, file))
    return 1;
  std::ostream& out = OutputStream(opt, file);

  if (opt.format == "json") {
    out << root->ToJson(opt.include_attachments) << "\n";
  } else if (opt.format == "csv") {
    PrintCsv(out, root, opt.with_passwords);
  } else {
    PrintText(out, root, opt.with_passwords);
  }
  return 0;
}

} // namespace kpx