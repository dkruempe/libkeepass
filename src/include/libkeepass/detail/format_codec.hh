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

/** @file format_codec.hh
 *  @brief Registrable format codecs used by the unified KeePass API. */

#pragma once

#include <functional>
#include <istream>
#include <map>
#include <memory>
#include <mutex>
#include <ostream>

#include "libkeepass/export.hh"

namespace keepass {

class Database;
class Key;
class KdbFile;

namespace detail {

// Numeric ids must match the values of KeePass::Format (kKdb=1, kKdbx3=2,
// kKdbx4=3). They are duplicated here to keep this header independent of the
// unified API header and its include graph.
constexpr int kFormatKdb = 1;
constexpr int kFormatKdbx3 = 2;
constexpr int kFormatKdbx4 = 3;

/// Options that influence codec construction.
struct FormatCodecOptions {
  /// Force KDBX 4 output (KDBX 3 otherwise) for the KDBX codec.
  bool write_kdbx4 = false;

  /// Allow the KDBX codec to reuse a transformed key cached on the Database.
  bool use_cached_key = true;
};

/**
 * @brief Imports/exports one database dialect.
 *
 * Implementations are cheap to construct and own all per-operation state.
 * `KeePass` only looks codecs up in the registry by numeric format id, so a
 * new dialect can be added by registering a factory without touching the
 * unified API.
 */
class LIBKEEPASS_API FormatCodec {
public:
  virtual ~FormatCodec() = default;

  /// Imports a database from @p src using @p key.
  virtual std::unique_ptr<Database> Import(std::istream& src, const Key& key) = 0;

  /// Exports @p db to @p dst using @p key.
  virtual void Export(std::ostream& dst, const Database& db, const Key& key) = 0;
};

/// Serializer-facing alias for the format codec abstraction. `Database` owns
/// only object-model state; all KDB/KDBX/XML knowledge lives in a codec.
using DatabaseSerializer = FormatCodec;

using FormatCodecFactory = std::function<std::unique_ptr<FormatCodec>(const FormatCodecOptions&)>;

/**
 * @brief Process-wide registry of format codec factories.
 *
 * The built-in KDB and KDBX codecs are registered by the registry constructor
 * (function-local static initialization, so there is no cross-translation-unit
 * static initialization order problem). Additional dialects may be registered
 * before opening a database.
 */
class LIBKEEPASS_API FormatCodecRegistry final {
public:
  /// Returns the process-wide registry.
  static FormatCodecRegistry& Instance();

  /// Registers/overwrites the factory for a numeric format id.
  void Register(int format, FormatCodecFactory factory);

  /// Creates a codec for @p format, or throws UnsupportedFeatureError.
  std::unique_ptr<FormatCodec> Create(int format, const FormatCodecOptions& options) const;

  /// Returns whether a factory is registered for @p format.
  bool Contains(int format) const;

private:
  FormatCodecRegistry();

  mutable std::mutex mutex_;
  std::map<int, FormatCodecFactory> factories_;
};

} // namespace detail
} // namespace keepass
