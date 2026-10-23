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
#else
#include <conio.h>
#include <io.h>
#endif

#include "libkeepass/entry.hh"
#include "libkeepass/exception.hh"
#include "libkeepass/group.hh"
#include "libkeepass/keepass.hh"
#include "libkeepass/key.hh"
#include "libkeepass/secure.hh"

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

namespace {

// Largest password file accepted. Password files are expected to contain a
// single line; the cap keeps a hostile path from exhausting memory.
constexpr std::size_t kMaxPasswordFileBytes = 1024ULL * 1024ULL;

keepass::secure_string ReadPassword(std::istream& src, const char* what) {
  std::string data((std::istreambuf_iterator<char>(src)), std::istreambuf_iterator<char>());
  if (src.bad() || data.size() > kMaxPasswordFileBytes) {
    keepass::secure_zero(data.data(), data.size());
    throw keepass::IoError(std::string("Unable to read ") + what + ".");
  }

  // A trailing line ending is not part of the password.
  while (!data.empty() && (data.back() == '\n' || data.back() == '\r'))
    data.pop_back();

  keepass::secure_string password(data);
  keepass::secure_zero(data.data(), data.size());
  return password;
}

keepass::secure_string PromptPassword() {
#ifdef _WIN32
  std::cout << "Master password: ";
  std::cout.flush();
  std::string password;
  for (;;) {
    const int ch = _getch();
    if (ch == '\r' || ch == '\n')
      break;
    if ((ch == '\b' || ch == 127) && !password.empty()) {
      password.pop_back();
      continue;
    }
    if (ch >= 32 && ch < 127)
      password.push_back(static_cast<char>(ch));
  }
  std::cout << "\n";
  keepass::secure_string result(password);
  keepass::secure_zero(password.data(), password.size());
  return result;
#else
  return {getpass("Master password: ")};
#endif
}

bool HasTerminalInput() {
#ifdef _WIN32
  return _isatty(_fileno(stdin)) != 0;
#else
  return isatty(STDIN_FILENO) != 0;
#endif
}

std::string JsonEscape(const std::string& value) {
  std::string escaped;
  escaped.reserve(value.size());
  for (const char c : value) {
    switch (c) {
    case '"':
      escaped += "\\\"";
      break;
    case '\\':
      escaped += "\\\\";
      break;
    case '\n':
      escaped += "\\n";
      break;
    case '\r':
      escaped += "\\r";
      break;
    case '\t':
      escaped += "\\t";
      break;
    default:
      escaped.push_back(c);
      break;
    }
  }
  return escaped;
}

// Returns whether the command line asked for JSON output, so errors can use
// the same machine-readable shape even when parsing fails later.
bool WantsJsonErrors(int argc, const char* argv[]) {
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    if (arg == "--")
      break;
    if (arg == "--format=json" || arg == "-fjson")
      return true;
    if ((arg == "--format" || arg == "-f") && i + 1 < argc && std::string(argv[i + 1]) == "json")
      return true;
  }
  return false;
}

int ReportError(bool json, const char* category, const std::string& message, ExitCode code) {
  if (json)
    std::cerr << R"({"error":{"category":")" << category << R"(","message":")"
              << JsonEscape(message) << R"("}})" << '\n';
  else
    std::cerr << "error: " << message << "\n";
  return static_cast<int>(code);
}

} // namespace

keepass::secure_string ReadPasswordFile(const std::string& path) {
  if (path == "-")
    return ReadPassword(std::cin, "password from stdin");

  std::ifstream file(path, std::ios::in | std::ios::binary);
  if (!file.is_open())
    throw keepass::FileNotFoundError();
  return ReadPassword(file, "password file");
}

keepass::secure_string ReadPasswordStdin() { return ReadPassword(std::cin, "password from stdin"); }

keepass::secure_string ResolvePassword(const Options& opt) {
  if (!opt.password.empty())
    return opt.password;

  if (!opt.password_file.empty())
    return ReadPasswordFile(opt.password_file);

  if (opt.password_stdin)
    return ReadPasswordStdin();

  const char* env = std::getenv("KEEPASS_PASSWORD");
  if (env != nullptr && *env != '\0')
    return {env};

  if (HasTerminalInput())
    return PromptPassword();

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

  if (!opt.password.empty() && (!opt.password_file.empty() || opt.password_stdin)) {
    std::cerr << "error: use only one of --password, --password-file and --password-stdin\n";
    return 1;
  }
  if (!opt.password_file.empty() && opt.password_stdin) {
    std::cerr << "error: use only one of --password-file and --password-stdin\n";
    return 1;
  }

  if (opt.input.empty()) {
    PrintUsage(argv0, std::cerr);
    return 1;
  }

  if (opt.command == "create")
    return RunCreate(opt);

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
  if (opt.command == "passwd")
    return RunPasswd(opt, password, keeper, db.get());
  if (opt.command == "move")
    return RunMove(opt, keeper, db.get());
  if (opt.command == "merge" || opt.command == "import")
    return RunMerge(opt, password, keeper, db.get());
  if (opt.command == "purge")
    return RunPurge(opt, keeper, db.get());
  if (opt.command == "history" || opt.command == "otp") {
    std::shared_ptr<keepass::Group> start = db->root();
    if (!opt.group.empty()) {
      start = db->FindGroup(opt.group);
      if (!start) {
        std::cerr << "error: group '" << opt.group << "' not found\n";
        return 1;
      }
    }
    return opt.command == "history" ? RunHistory(opt, start) : RunOtp(opt, start);
  }

  if (opt.command == "groups") {
    std::shared_ptr<keepass::Group> start = db->root();
    if (!opt.group.empty()) {
      start = db->FindGroup(opt.group);
      if (!start) {
        std::cerr << "error: group '" << opt.group << "' not found\n";
        return 1;
      }
    }
    return RunGroups(opt, start);
  }

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
  const bool json_errors = WantsJsonErrors(argc, argv);
  try {
    Options opt;
    if (!ParseArgs(argc, argv, opt))
      return static_cast<int>(ExitCode::kError);
    return Run(opt, argv[0]);
  } catch (const keepass::Error& e) {
    switch (e.category()) {
    case keepass::ErrorCategory::kAuthentication:
      return ReportError(json_errors, "auth", e.what(), ExitCode::kAuth);
    case keepass::ErrorCategory::kIo:
      return ReportError(json_errors, "io", e.what(), ExitCode::kIo);
    case keepass::ErrorCategory::kFormat:
    case keepass::ErrorCategory::kUnsupported:
    case keepass::ErrorCategory::kResourceLimit:
      return ReportError(json_errors, "format", e.what(), ExitCode::kFormat);
    case keepass::ErrorCategory::kInternal:
      break;
    }
    return ReportError(json_errors, "error", e.what(), ExitCode::kError);
  } catch (const std::exception& e) {
    return ReportError(json_errors, "error", e.what(), ExitCode::kError);
  }
}

} // namespace kpx

#ifndef KPX_NO_MAIN
int main(int argc, const char* argv[]) { return kpx::kpx_main(argc, argv); }
#endif