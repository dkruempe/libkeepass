/*
 * libkeepass - KeePass key database importer/exporter
 * Copyright (C) 2014 Christian Kindahl
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

#include <chrono>
#include <iostream>

#include "libkeepass/kdb.hh"
#include "libkeepass/kdbx.hh"
#include "libkeepass/key.hh"

class StopWatch {
private:
  std::chrono::time_point<std::chrono::system_clock> start =
      std::chrono::system_clock::now();

public:
  StopWatch() = default;

  void stop() {
    auto end = std::chrono::system_clock::now();
    std::cout << "Duration: "
              << std::chrono::duration_cast<std::chrono::milliseconds>(end -
                                                                       start)
                     .count()
              << "ms\n";
  }

  ~StopWatch() {
    auto end = std::chrono::system_clock::now();
    std::cout << "Duration: "
              << std::chrono::duration_cast<std::chrono::milliseconds>(end -
                                                                       start)
                     .count()
              << "ms\n";
  }
};

using namespace keepass;

int main(int argc, const char *argv[]) {
  if (argc < 2) {
    std::cerr << "usage: sample <file> [password] [--keyfile <path>]" << std::endl;
    return 1;
  }

  std::string password = "password";
  std::string keyfile_path;
  for (int i = 2; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--keyfile" && i + 1 < argc) {
      keyfile_path = argv[++i];
    } else {
      password = arg;
    }
  }

  StopWatch stopWatch{};
  try {
    Key key(password);
    if (!keyfile_path.empty()) {
      key.SetKeyFile(keyfile_path);
    }

    bool kdbx = true; // Assume KDBX by default.

    // Check if KDB file.
    std::string path = argv[1];
    std::size_t ext_delim = path.rfind('.');
    if (ext_delim != std::string::npos) {
      if (path.substr(ext_delim, path.size() - ext_delim) == ".kdb") {
        kdbx = false;
      }
    }

    if (kdbx) {
      KdbxFile file;
      std::unique_ptr<Database> database = file.Import(path, key);
      std::cout << database->root()->ToJson() << "\n";
    } else {
      KdbFile file;
      std::cout << keepass::KdbFile::Import(path, key)->root()->ToJson()
                << std::endl;
    }
  } catch (std::exception &e) {
    std::cerr << "error: " << e.what() << std::endl;
  }

  return 0;
}
