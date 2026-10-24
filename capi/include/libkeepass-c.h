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
 * @file libkeepass-c.h
 * @brief Stable C ABI for language bindings and FFI consumers.
 *
 * All strings returned through an out-parameter are allocated by the library
 * and must be released with kp_free_string(). Errors are reported through the
 * kp_status return value and kp_last_error(); the last error is thread-local.
 */

#ifndef LIBKEEPASS_C_H
#define LIBKEEPASS_C_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Status codes returned by the C API.
#ifdef __cplusplus
enum kp_status {
  KP_STATUS_OK = 0,
  KP_STATUS_INVALID_ARGUMENT = 1,
  KP_STATUS_AUTHENTICATION = 2,
  KP_STATUS_FORMAT = 3,
  KP_STATUS_IO = 4,
  KP_STATUS_UNSUPPORTED = 5,
  KP_STATUS_RESOURCE_LIMIT = 6,
  KP_STATUS_INTERNAL = 7
};
#else
typedef enum kp_status {
  KP_STATUS_OK = 0,
  KP_STATUS_INVALID_ARGUMENT = 1,
  KP_STATUS_AUTHENTICATION = 2,
  KP_STATUS_FORMAT = 3,
  KP_STATUS_IO = 4,
  KP_STATUS_UNSUPPORTED = 5,
  KP_STATUS_RESOURCE_LIMIT = 6,
  KP_STATUS_INTERNAL = 7
} kp_status;
#endif

/// Opaque handle for a KeePass importer/exporter.
#ifdef __cplusplus
struct kp_keepass;
#else
typedef struct kp_keepass kp_keepass;
#endif

/// Opaque handle for an imported or created database.
#ifdef __cplusplus
struct kp_database;
#else
typedef struct kp_database kp_database;
#endif

/// Returns the library version string.
const char* kp_version(void);

/// Returns the last error message for the calling thread (never NULL).
const char* kp_last_error(void);

/// Creates an importer/exporter with the given password and optional keyfile.
kp_keepass* kp_keepass_create(const char* password, const char* keyfile);

/// Destroys an importer/exporter handle.
void kp_keepass_destroy(kp_keepass* handle);

/// Selects the output format: 0 auto, 1 KDB, 2 KDBX 3, 3 KDBX 4.
kp_status kp_keepass_set_format(kp_keepass* handle, int format);

/// Opens a database from a file path.
kp_status kp_keepass_open(kp_keepass* handle, const char* path, kp_database** out);

/// Opens a database from an in-memory byte range.
kp_status kp_keepass_open_bytes(kp_keepass* handle, const unsigned char* data, size_t size,
                                kp_database** out);

/// Saves a database to a file path using the handle's key and format settings.
kp_status kp_keepass_save(kp_keepass* handle, const kp_database* database, const char* path);

/// Destroys a database handle.
void kp_database_destroy(kp_database* database);

/// Creates a new empty KDBX 4 database with the given password.
kp_database* kp_database_create(const char* password);

/// Returns the total number of entries.
size_t kp_database_entry_count(const kp_database* database);

/// Returns the total number of groups (including the root).
size_t kp_database_group_count(const kp_database* database);

/// Serializes the database to JSON; release *out with kp_free_string().
kp_status kp_database_to_json(const kp_database* database, int include_attachments, char** out);

/// Serializes the database to CSV; release *out with kp_free_string().
kp_status kp_database_to_csv(const kp_database* database, int format, char** out);

/// Finds an entry by exact title and returns copies of its standard fields.
/**
 * Any out parameter may be NULL. Each non-NULL string is allocated by the
 * library and must be released with kp_free_string().
 */
kp_status kp_database_find_entry(const kp_database* database, const char* title, char** title_out,
                                 char** username_out, char** password_out, char** url_out,
                                 char** notes_out);

/// Adds an entry to a group (empty/NULL group_path means the root group).
kp_status kp_database_add_entry(kp_database* database, const char* group_path, const char* title,
                                const char* username, const char* password, const char* url,
                                const char* notes);

/// Deletes the entry with the exact title (first match).
kp_status kp_database_delete_entry(kp_database* database, const char* title);

/// Releases a string returned by the C API.
void kp_free_string(char* text);

#ifdef __cplusplus
} // extern "C"
#endif

#endif /* LIBKEEPASS_C_H */
