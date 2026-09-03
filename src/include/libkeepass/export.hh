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

#pragma once

// On Windows the public classes and functions of this shared library are
// exported/imported explicitly with __declspec(dllexport/dllimport). The
// LIBKEEPASS_EXPORTS macro is defined automatically by CMake while building the
// libkeepass target itself (via the libkeepass_EXPORTS define). On other
// platforms visibility is default and the macro expands to nothing.
#if defined(_WIN32) && (defined(LIBKEEPASS_EXPORTS) || defined(libkeepass_EXPORTS))
#define LIBKEEPASS_API __declspec(dllexport)
#elif defined(_WIN32)
#define LIBKEEPASS_API __declspec(dllimport)
#else
#define LIBKEEPASS_API
#endif
