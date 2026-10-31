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

/** @file export.hh @brief Visibility/export macro for the shared library. */

#pragma once

// The library is compiled with hidden visibility (-fvisibility=hidden and
// -fvisibility-inlines-hidden, see src/CMakeLists.txt), so only symbols marked
// with LIBKEEPASS_API are part of the public ABI. On Windows the same macro
// maps to __declspec(dllexport/dllimport). A static build (LIBKEEPASS_STATIC,
// defined by CMake for the static target) still compiles with hidden
// visibility so a static archive does not re-export its symbols when linked
// into another shared object, but the macro expands to nothing because no
// dynamic import/export attributes are needed.

/**
 * @def LIBKEEPASS_API
 * @brief Marks a class, function or variable as part of the public ABI.
 *
 * Expands to @c __declspec(dllexport) when building the shared library on
 * Windows, to @c __declspec(dllimport) when consuming it on Windows, to
 * @c __attribute__((visibility("default"))) on GCC/Clang so the symbol stays
 * exported despite the target's hidden default visibility, and to nothing for
 * static builds or compilers without visibility support.
 *
 * Only declarations that are implemented out of line (or that need exported
 * RTTI/vtables) should carry this macro. Header-only templates and inline
 * helpers must not be marked.
 */
#if defined(LIBKEEPASS_STATIC)
#define LIBKEEPASS_API
#elif defined(_WIN32) && (defined(LIBKEEPASS_EXPORTS) || defined(libkeepass_EXPORTS))
#define LIBKEEPASS_API __declspec(dllexport)
#elif defined(_WIN32)
#define LIBKEEPASS_API __declspec(dllimport)
#elif defined(__GNUC__) || defined(__clang__)
#define LIBKEEPASS_API __attribute__((visibility("default")))
#else
#define LIBKEEPASS_API
#endif
