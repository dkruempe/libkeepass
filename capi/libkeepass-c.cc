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

#include "libkeepass-c.h"

#include <cstdlib>
#include <cstring>
#include <memory>
#include <new>
#include <string>

#include "libkeepass/database.hh"
#include "libkeepass/entry.hh"
#include "libkeepass/exception.hh"
#include "libkeepass/group.hh"
#include "libkeepass/keepass.hh"
#include "libkeepass/key.hh"

#ifndef LIBKEEPASS_VERSION
#define LIBKEEPASS_VERSION "0.0.0"
#endif

struct kp_keepass {
  std::unique_ptr<keepass::KeePass> keeper;
};

struct kp_database {
  std::unique_ptr<keepass::Database> database;
};

namespace {

thread_local std::string g_last_error;

void SetError(const std::string& message) { g_last_error = message; }

kp_status StatusFor(keepass::ErrorCategory category) {
  switch (category) {
  case keepass::ErrorCategory::kAuthentication:
    return KP_STATUS_AUTHENTICATION;
  case keepass::ErrorCategory::kFormat:
    return KP_STATUS_FORMAT;
  case keepass::ErrorCategory::kUnsupported:
    return KP_STATUS_UNSUPPORTED;
  case keepass::ErrorCategory::kResourceLimit:
    return KP_STATUS_RESOURCE_LIMIT;
  case keepass::ErrorCategory::kIo:
    return KP_STATUS_IO;
  case keepass::ErrorCategory::kInternal:
    return KP_STATUS_INTERNAL;
  }
  return KP_STATUS_INTERNAL;
}

template <typename F> kp_status Guard(F&& function) {
  try {
    function();
    SetError("");
    return KP_STATUS_OK;
  } catch (const keepass::Error& error) {
    SetError(error.what());
    return StatusFor(error.category());
  } catch (const std::bad_alloc&) {
    SetError("Out of memory.");
    return KP_STATUS_INTERNAL;
  } catch (const std::exception& error) {
    SetError(error.what());
    return KP_STATUS_INTERNAL;
  } catch (...) {
    SetError("Unknown error.");
    return KP_STATUS_INTERNAL;
  }
}

char* CopyString(const std::string& value) {
  char* text = static_cast<char*>(std::malloc(value.size() + 1));
  if (text == nullptr)
    return nullptr;
  std::memcpy(text, value.c_str(), value.size() + 1);
  return text;
}

kp_status CopyOut(const std::string& value, char** out) {
  if (out == nullptr)
    return KP_STATUS_INVALID_ARGUMENT;
  *out = CopyString(value);
  if (*out == nullptr) {
    SetError("Out of memory.");
    return KP_STATUS_INTERNAL;
  }
  return KP_STATUS_OK;
}

} // namespace

extern "C" {

const char* kp_version(void) { return LIBKEEPASS_VERSION; }

const char* kp_last_error(void) { return g_last_error.c_str(); }

kp_keepass* kp_keepass_create(const char* password, const char* keyfile) {
  try {
    auto handle = std::make_unique<kp_keepass>();
    handle->keeper = std::make_unique<keepass::KeePass>(password == nullptr ? "" : password,
                                                        keyfile == nullptr ? "" : keyfile);
    SetError("");
    return handle.release();
  } catch (const std::exception& error) {
    SetError(error.what());
    return nullptr;
  } catch (...) {
    SetError("Unknown error.");
    return nullptr;
  }
}

void kp_keepass_destroy(kp_keepass* handle) { delete handle; }

kp_status kp_keepass_set_format(kp_keepass* handle, int format) {
  if (handle == nullptr)
    return KP_STATUS_INVALID_ARGUMENT;
  if (format < 0 || format > 3) {
    SetError("Invalid output format.");
    return KP_STATUS_INVALID_ARGUMENT;
  }

  handle->keeper->SetFormat(static_cast<keepass::KeePass::Format>(format));
  SetError("");
  return KP_STATUS_OK;
}

kp_status kp_keepass_open(kp_keepass* handle, const char* path, kp_database** out) {
  if (handle == nullptr || path == nullptr || out == nullptr)
    return KP_STATUS_INVALID_ARGUMENT;
  *out = nullptr;

  return Guard([&] {
    auto database = std::make_unique<kp_database>();
    database->database = handle->keeper->Open(path);
    *out = database.release();
  });
}

kp_status kp_keepass_open_bytes(kp_keepass* handle, const unsigned char* data, size_t size,
                                kp_database** out) {
  if (handle == nullptr || (data == nullptr && size != 0) || out == nullptr)
    return KP_STATUS_INVALID_ARGUMENT;
  *out = nullptr;

  return Guard([&] {
    auto database = std::make_unique<kp_database>();
    database->database = handle->keeper->Open(data, size);
    *out = database.release();
  });
}

kp_status kp_keepass_save(kp_keepass* handle, const kp_database* database, const char* path) {
  if (handle == nullptr || database == nullptr || database->database == nullptr || path == nullptr)
    return KP_STATUS_INVALID_ARGUMENT;

  return Guard([&] { handle->keeper->Save(path, *database->database); });
}

void kp_database_destroy(kp_database* database) { delete database; }

kp_database* kp_database_create(const char* password) {
  try {
    auto database = std::make_unique<kp_database>();
    database->database = keepass::KeePass::Create(password == nullptr ? "" : password);
    SetError("");
    return database.release();
  } catch (const std::exception& error) {
    SetError(error.what());
    return nullptr;
  } catch (...) {
    SetError("Unknown error.");
    return nullptr;
  }
}

size_t kp_database_entry_count(const kp_database* database) {
  if (database == nullptr || database->database == nullptr)
    return 0;
  return database->database->EntryCount();
}

size_t kp_database_group_count(const kp_database* database) {
  if (database == nullptr || database->database == nullptr)
    return 0;
  return database->database->GroupCount();
}

kp_status kp_database_to_json(const kp_database* database, int include_attachments, char** out) {
  if (database == nullptr || database->database == nullptr || out == nullptr)
    return KP_STATUS_INVALID_ARGUMENT;
  *out = nullptr;
  return Guard([&] {
    const kp_status status = CopyOut(database->database->ToJson(include_attachments != 0), out);
    if (status != KP_STATUS_OK)
      throw keepass::InternalError(g_last_error);
  });
}

kp_status kp_database_to_csv(const kp_database* database, int format, char** out) {
  if (database == nullptr || database->database == nullptr || out == nullptr)
    return KP_STATUS_INVALID_ARGUMENT;
  if (format < 0 || format > 3) {
    SetError("Invalid CSV format.");
    return KP_STATUS_INVALID_ARGUMENT;
  }
  *out = nullptr;

  return Guard([&] {
    const auto csv_format = static_cast<keepass::CsvFormat>(format);
    const kp_status status = CopyOut(database->database->ToCsv(csv_format), out);
    if (status != KP_STATUS_OK)
      throw keepass::InternalError(g_last_error);
  });
}

kp_status kp_database_find_entry(const kp_database* database, const char* title, char** title_out,
                                 char** username_out, char** password_out, char** url_out,
                                 char** notes_out) {
  if (database == nullptr || database->database == nullptr || title == nullptr)
    return KP_STATUS_INVALID_ARGUMENT;

  if (title_out != nullptr)
    *title_out = nullptr;
  if (username_out != nullptr)
    *username_out = nullptr;
  if (password_out != nullptr)
    *password_out = nullptr;
  if (url_out != nullptr)
    *url_out = nullptr;
  if (notes_out != nullptr)
    *notes_out = nullptr;

  return Guard([&] {
    const auto entry = database->database->FindEntry(title);
    if (!entry)
      throw keepass::FormatError("Entry not found.");

    if (title_out != nullptr && CopyOut(entry->title()->str(), title_out) != KP_STATUS_OK)
      throw keepass::InternalError(g_last_error);
    if (username_out != nullptr && CopyOut(entry->username()->str(), username_out) != KP_STATUS_OK)
      throw keepass::InternalError(g_last_error);
    if (password_out != nullptr && CopyOut(entry->password()->str(), password_out) != KP_STATUS_OK)
      throw keepass::InternalError(g_last_error);
    if (url_out != nullptr && CopyOut(entry->url()->str(), url_out) != KP_STATUS_OK)
      throw keepass::InternalError(g_last_error);
    if (notes_out != nullptr && CopyOut(entry->notes()->str(), notes_out) != KP_STATUS_OK)
      throw keepass::InternalError(g_last_error);
  });
}

kp_status kp_database_add_entry(kp_database* database, const char* group_path, const char* title,
                                const char* username, const char* password, const char* url,
                                const char* notes) {
  if (database == nullptr || database->database == nullptr || title == nullptr)
    return KP_STATUS_INVALID_ARGUMENT;

  return Guard([&] {
    std::shared_ptr<keepass::Group> group = database->database->root();
    if (group_path != nullptr && group_path[0] != '\0') {
      group = database->database->FindGroup(group_path);
      if (!group)
        throw keepass::FormatError("Group not found.");
    }
    if (!group)
      throw keepass::FormatError("Database has no root group.");

    auto entry = keepass::Database::NewEntry(title);
    entry->set_username(keepass::protect<keepass::secure_string>(
        keepass::secure_string(username == nullptr ? "" : username), false));
    entry->set_password(keepass::protect<keepass::secure_string>(
        keepass::secure_string(password == nullptr ? "" : password), true));
    entry->set_url(keepass::protect<keepass::secure_string>(
        keepass::secure_string(url == nullptr ? "" : url), false));
    entry->set_notes(keepass::protect<keepass::secure_string>(
        keepass::secure_string(notes == nullptr ? "" : notes), false));
    keepass::Database::AddEntry(group, entry);
  });
}

kp_status kp_database_delete_entry(kp_database* database, const char* title) {
  if (database == nullptr || database->database == nullptr || title == nullptr)
    return KP_STATUS_INVALID_ARGUMENT;

  return Guard([&] {
    const auto entry = database->database->FindEntry(title);
    if (!entry)
      throw keepass::FormatError("Entry not found.");
    database->database->DeleteEntry(entry->uuid());
  });
}

void kp_free_string(char* text) { std::free(text); }

} // extern "C"
