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

/**
 * @file limits.hh
 * @brief Resource budgets enforced while importing (and parsing) databases.
 *
 * Import is driven by untrusted length fields: a hostile or corrupt file can
 * declare block sizes, binary sizes, entry counts or nesting depths that would
 * otherwise make the importer loop or allocate unbounded amounts of memory.
 * The importer enforces these budgets while it reads, rejecting the file with
 * a @c FormatError as soon as a limit is exceeded.
 */

#pragma once
#include <cstdint>

namespace keepass {
namespace detail {

/**
 * @brief Configurable resource budgets for database import and XML parsing.
 *
 * All limits are upper bounds; a value of zero disables nothing (any payload
 * still counts) but is a valid explicit budget. The defaults are chosen so
 * that genuine databases are unaffected while zip bombs and hostile XML
 * documents are rejected early.
 */
struct ResourceLimits {
  /** Max total bytes produced by gzip inflation and hashed/HMAC blocks. */
  uint64_t max_total_bytes = (1ULL << 32);

  /** Max number of non-empty hashed/HMAC data blocks. */
  uint64_t max_block_count = 100000;

  /** Max declared payload size of a single hashed/HMAC block. */
  uint32_t max_block_size = 1024 * 1024;

  /** Max XML group nesting depth (the root group has depth 0). */
  uint32_t max_xml_depth = 128;

  /** Max number of groups in the XML document. */
  uint32_t max_groups = 100000;

  /** Max number of entries (including history entries) in the XML document. */
  uint32_t max_entries = 100000;

  /** Max number of entry history items in the XML document. */
  uint32_t max_history_items = 10000;

  /** Max bytes of a single string field value (empty strings are free). */
  uint64_t max_string_field_bytes = 16ULL * 1024 * 1024;

  /** Max bytes of a single binary attachment or custom icon. */
  uint64_t max_binary_bytes = 128ULL * 1024 * 1024;
};

} // namespace detail
} // namespace keepass