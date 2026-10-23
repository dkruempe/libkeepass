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

/**
 * @file demo.cc
 * @brief Minimal Emscripten entry point for the client-side WASM demo.
 *
 * The database never leaves the browser: JavaScript passes the encrypted file
 * bytes and the master password to `demo_open`, and receives the decrypted
 * database JSON. The page must be served over a secure origin (HTTPS or
 * localhost); see wasm/README.md.
 */

#include <cstdlib>
#include <cstring>
#include <string>

#include <emscripten/emscripten.h>

#include "libkeepass-c.h"

namespace {

char* g_result = nullptr;

void SetResult(const std::string& value) {
  std::free(g_result);
  g_result = static_cast<char*>(std::malloc(value.size() + 1));
  if (g_result != nullptr)
    std::memcpy(g_result, value.c_str(), value.size() + 1);
}

std::string ErrorJson() {
  std::string message = kp_last_error();
  std::string escaped;
  for (const char c : message) {
    if (c == '"' || c == '\\')
      escaped.push_back('\\');
    if (c == '\n')
      escaped += "\\n";
    else
      escaped.push_back(c);
  }
  return std::string(R"({"error":")") + escaped + "\"}";
}

} // namespace

extern "C" {

/// Opens @p size bytes of an encrypted database and returns JSON.
EMSCRIPTEN_KEEPALIVE
const char* demo_open(const unsigned char* data, int size, const char* password) {
  kp_keepass* handle = kp_keepass_create(password == nullptr ? "" : password, nullptr);
  if (handle == nullptr) {
    SetResult(ErrorJson());
    return g_result;
  }

  kp_database* database = nullptr;
  const kp_status status =
      kp_keepass_open_bytes(handle, data, static_cast<size_t>(size), &database);
  if (status != KP_STATUS_OK) {
    SetResult(ErrorJson());
    kp_keepass_destroy(handle);
    return g_result;
  }

  char* json = nullptr;
  if (kp_database_to_json(database, 0, &json) != KP_STATUS_OK) {
    SetResult(ErrorJson());
  } else {
    SetResult(json == nullptr ? "" : json);
  }

  kp_free_string(json);
  kp_database_destroy(database);
  kp_keepass_destroy(handle);
  return g_result;
}

/// Releases the string returned by the previous demo_open call.
EMSCRIPTEN_KEEPALIVE
void demo_free(void) {
  std::free(g_result);
  g_result = nullptr;
}

EMSCRIPTEN_KEEPALIVE
const char* demo_version(void) { return kp_version(); }

} // extern "C"
