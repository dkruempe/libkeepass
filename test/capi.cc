/*
 * libkeepass - KeePass key database importer/exporter
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

#include <cstdio>
#include <cstring>

#include "libkeepass-c.h"

namespace {

int Fail(const char* message) {
  std::fprintf(stderr, "capi test failed: %s (%s)\n", message, kp_last_error());
  return 1;
}

} // namespace

int main() {
  const char* path = "capi-test.kdbx";
  std::remove(path);

  kp_database* created = kp_database_create("password");
  if (created == nullptr)
    return Fail("kp_database_create");
  if (kp_database_add_entry(created, nullptr, "C API entry", "alice", "secret",
                            "https://example.com", "created through the C ABI") != KP_STATUS_OK)
    return Fail("kp_database_add_entry");
  if (kp_database_entry_count(created) != 1)
    return Fail("entry count");
  if (kp_database_group_count(created) != 1)
    return Fail("group count");

  kp_keepass* writer = kp_keepass_create("password", nullptr);
  if (writer == nullptr)
    return Fail("kp_keepass_create writer");
  if (kp_keepass_save(writer, created, path) != KP_STATUS_OK)
    return Fail("kp_keepass_save");

  kp_keepass* reader = kp_keepass_create("password", nullptr);
  kp_database* reopened = nullptr;
  if (kp_keepass_open(reader, path, &reopened) != KP_STATUS_OK)
    return Fail("kp_keepass_open");

  char* title = nullptr;
  char* password = nullptr;
  if (kp_database_find_entry(reopened, "C API entry", &title, nullptr, &password, nullptr,
                             nullptr) != KP_STATUS_OK)
    return Fail("kp_database_find_entry");
  if (title == nullptr || std::strcmp(title, "C API entry") != 0)
    return Fail("title round-trip");
  if (password == nullptr || std::strcmp(password, "secret") != 0)
    return Fail("password round-trip");

  char* json = nullptr;
  if (kp_database_to_json(reopened, 0, &json) != KP_STATUS_OK || json == nullptr)
    return Fail("kp_database_to_json");
  if (std::strstr(json, "C API entry") == nullptr)
    return Fail("json contents");

  char* csv = nullptr;
  if (kp_database_to_csv(reopened, 1, &csv) != KP_STATUS_OK || csv == nullptr)
    return Fail("kp_database_to_csv");
  if (std::strstr(csv, "secret") == nullptr)
    return Fail("csv contents");

  kp_free_string(title);
  kp_free_string(password);
  kp_free_string(json);
  kp_free_string(csv);
  kp_database_destroy(reopened);
  kp_database_destroy(created);
  kp_keepass_destroy(reader);
  kp_keepass_destroy(writer);
  std::remove(path);

  // Missing files map to the documented IO status.
  kp_keepass* missing = kp_keepass_create("password", nullptr);
  kp_database* absent = nullptr;
  if (kp_keepass_open(missing, "capi-does-not-exist.kdbx", &absent) != KP_STATUS_IO)
    return Fail("missing file status");
  if (std::strlen(kp_last_error()) == 0)
    return Fail("last error message");
  kp_keepass_destroy(missing);

  return 0;
}
