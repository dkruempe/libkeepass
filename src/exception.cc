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

#include "libkeepass/exception.hh"

namespace keepass {

const char* ErrorCategoryName(ErrorCategory category) noexcept {
  switch (category) {
  case ErrorCategory::kAuthentication:
    return "authentication";
  case ErrorCategory::kFormat:
    return "format";
  case ErrorCategory::kUnsupported:
    return "unsupported";
  case ErrorCategory::kResourceLimit:
    return "resource-limit";
  case ErrorCategory::kIo:
    return "io";
  case ErrorCategory::kInternal:
    return "internal";
  }
  return "unknown";
}

} // namespace keepass
