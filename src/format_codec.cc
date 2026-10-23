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

#include "libkeepass/detail/format_codec.hh"

#include <utility>

#include "libkeepass/database.hh"
#include "libkeepass/exception.hh"
#include "libkeepass/key.hh"
#ifdef LIBKEEPASS_WITH_KDB
#include "libkeepass/kdb.hh"
#endif
#ifdef LIBKEEPASS_WITH_KDBX
#include "libkeepass/kdbx.hh"
#endif

namespace keepass::detail {

namespace {

#ifdef LIBKEEPASS_WITH_KDB
class KdbFormatCodec final : public FormatCodec {
public:
  std::unique_ptr<Database> Import(std::istream& src, const Key& key) override {
    return KdbFile::Import(src, key);
  }

  void Export(std::ostream& dst, const Database& db, const Key& key) override {
    KdbFile::Export(dst, db, key);
  }
};
#endif

#ifdef LIBKEEPASS_WITH_KDBX
class KdbxFormatCodec final : public FormatCodec {
public:
  explicit KdbxFormatCodec(const FormatCodecOptions& options) {
    file_.set_write_kdbx4(options.write_kdbx4);
    file_.set_use_cached_key(options.use_cached_key);
  }

  std::unique_ptr<Database> Import(std::istream& src, const Key& key) override {
    return file_.Import(src, key);
  }

  void Export(std::ostream& dst, const Database& db, const Key& key) override {
    file_.Export(dst, db, key);
  }

private:
  KdbxFile file_;
};
#endif

} // namespace

FormatCodecRegistry& FormatCodecRegistry::Instance() {
  static FormatCodecRegistry registry;
  return registry;
}

FormatCodecRegistry::FormatCodecRegistry() {
#ifdef LIBKEEPASS_WITH_KDB
  Register(kFormatKdb, [](const FormatCodecOptions&) -> std::unique_ptr<FormatCodec> {
    return std::make_unique<KdbFormatCodec>();
  });
#endif
#ifdef LIBKEEPASS_WITH_KDBX
  Register(kFormatKdbx3, [](const FormatCodecOptions& options) -> std::unique_ptr<FormatCodec> {
    FormatCodecOptions kdbx3 = options;
    kdbx3.write_kdbx4 = false;
    return std::make_unique<KdbxFormatCodec>(kdbx3);
  });
  Register(kFormatKdbx4, [](const FormatCodecOptions& options) -> std::unique_ptr<FormatCodec> {
    FormatCodecOptions kdbx4 = options;
    kdbx4.write_kdbx4 = true;
    return std::make_unique<KdbxFormatCodec>(kdbx4);
  });
#endif
}

void FormatCodecRegistry::Register(int format, FormatCodecFactory factory) {
  std::scoped_lock lock(mutex_);
  factories_[format] = std::move(factory);
}

std::unique_ptr<FormatCodec> FormatCodecRegistry::Create(int format,
                                                         const FormatCodecOptions& options) const {
  FormatCodecFactory factory;
  {
    std::scoped_lock lock(mutex_);
    const auto it = factories_.find(format);
    if (it == factories_.end())
      throw UnsupportedFeatureError("No codec registered for this database format.");
    factory = it->second;
  }
  return factory(options);
}

bool FormatCodecRegistry::Contains(int format) const {
  std::scoped_lock lock(mutex_);
  return factories_.find(format) != factories_.end();
}

} // namespace keepass::detail
