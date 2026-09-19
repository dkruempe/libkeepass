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

#include "args.hh"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <iostream>
#include <random>

namespace kpx {

const char* const kGenerateCharset = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
                                     "!@#$%^&*()-_=+[]{};:,.?";

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

// Returns whether the string consists entirely of decimal digits.
bool IsNumeric(const std::string& s) {
  return !s.empty() && std::all_of(s.begin(), s.end(), [](char c) {
    return std::isdigit(static_cast<unsigned char>(c));
  });
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
          opt.generate = ParseGenerateLength(argv[i + 1], "--generate");
          if (opt.generate < 0)
            return false;
          skip_next = true;
        } else {
          opt.generate = kDefaultGenerateLength;
        }
      } else if (name == "regex") {
        opt.regex = true;
      } else if (name == "audit") {
        opt.audit = true;
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

} // namespace kpx