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
 * @file benchmark.cc
 * @brief Reproducible import/load benchmark for the KDBX formats.
 *
 * The benchmark generates a deterministic database with a configurable number
 * of entries, exports it in the different supported formats and measures how
 * long it takes to import (load) each variant. The result is printed only; it
 * is not asserted, so it can be run continuously by the CI without gating the
 * build on machine-dependent timings.
 *
 * Usage: benchmark [<number-of-entries>]   (default: 2000)
 */

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <memory>
#include <string>

#ifdef _WIN32
#include <windows.h>

#include <psapi.h>
#else
#include <sys/resource.h>
#endif

#include "config.hh"
#include "libkeepass/database.hh"
#include "libkeepass/entry.hh"
#include "libkeepass/group.hh"
#include "libkeepass/kdbx.hh"
#include "libkeepass/key.hh"
#include "libkeepass/security.hh"

using namespace keepass;

namespace {

using Clock = std::chrono::steady_clock;

constexpr std::array<uint8_t, 16> kMasterSeed = {{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                                  0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}};
constexpr std::array<uint8_t, 16> kInitVector = {{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                                                  0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20}};
constexpr std::array<uint8_t, 32> kTransformSeed = {
    {0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
     0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
     0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40}};
constexpr uint64_t kTransformRounds = 8192;

std::string GetTmpPath(const std::string& name) {
  return std::string(PROJECT_ROOT_PATH) + "/tmp/" + name;
}

/// Builds a deterministic database with \a entry_count entries and a fixed
/// (repetitive) payload so that the result is reproducible across runs.
std::unique_ptr<Database> MakeDatabase(std::size_t entry_count) {
  std::unique_ptr<Database> db(new Database());

  db->set_master_seed(kMasterSeed);
  db->set_init_vector(kInitVector);
  db->set_cipher(Database::Cipher::kAes);
  db->set_kdf(Database::Kdf::kAes);
  db->set_compress(true);
  db->set_transform_seed(kTransformSeed);
  db->set_transform_rounds(kTransformRounds);

  auto root = std::make_shared<Group>();
  root->set_name("Root");
  root->set_icon(48);
  root->set_creation_time(1700000000);
  root->set_modification_time(1700000001);
  root->set_access_time(1700000002);
  root->set_expiry_time(1700000003);
  root->set_move_time(1700000004);

  const char kNotes[] = "Benchmark payload: a long but fixed notes string used to grow the XML "
                        "document so that encryption, HMAC protection, decompression and XML "
                        "parsing all operate on a realistic amount of data.";
  const std::size_t notes_size = sizeof(kNotes) - 1;

  for (std::size_t i = 0; i < entry_count; ++i) {
    // Repeat the notes until it spans several hundred bytes.
    std::string notes;
    notes.reserve(notes_size * 2);
    for (int r = 0; r < 2; ++r)
      notes += kNotes;
    notes += "\n#" + std::to_string(i);

    auto entry = std::make_shared<Entry>();
    entry->set_title(
        protect<secure_string>(secure_string("Benchmark entry " + std::to_string(i)), false));
    entry->set_url(
        protect<secure_string>(secure_string("https://example.com/" + std::to_string(i)), false));
    entry->set_username(protect<secure_string>(secure_string("user" + std::to_string(i)), false));
    entry->set_password(protect<secure_string>(secure_string("secret-" + std::to_string(i)), true));
    entry->set_notes(protect<secure_string>(secure_string(notes), false));
    root->AddEntry(entry);
  }

  db->set_root(std::move(root));
  return db;
}

/// Returns the exported database's on-disk size in bytes.
std::size_t FileSize(const std::string& path) {
  std::ifstream file(path, std::ios::in | std::ios::binary);
  file.seekg(0, std::ios::end);
  return static_cast<std::size_t>(file.tellg());
}

struct Result {
  std::size_t bytes;
  double export_ms;
  double import_ms;
};

/// Returns the process peak resident set size in KiB (0 if unavailable).
std::size_t PeakRssKiB() {
#ifdef _WIN32
  PROCESS_MEMORY_COUNTERS info{};
  if (GetProcessMemoryInfo(GetCurrentProcess(), &info, sizeof(info)))
    return static_cast<std::size_t>(info.PeakWorkingSetSize / 1024);
#else
  struct rusage usage{};
  if (getrusage(RUSAGE_SELF, &usage) == 0)
    return static_cast<std::size_t>(usage.ru_maxrss); // Linux reports KiB.
#endif
  return 0;
}

/// Exports \a db to \a path with the given configured exporter, then imports
/// it again, measuring both directions.
Result MeasureRoundTrip(const std::string& path, const Database& db, const Key& key,
                        KdbxFile& exporter) {
  Clock::time_point start = Clock::now();
  exporter.Export(path, db, key);
  const double export_ms = std::chrono::duration<double, std::milli>(Clock::now() - start).count();

  const std::size_t bytes = FileSize(path);

  KdbxFile importer;
  start = Clock::now();
  std::unique_ptr<Database> loaded = importer.Import(path, key);
  const double import_ms = std::chrono::duration<double, std::milli>(Clock::now() - start).count();

  // Functional check: the round trip must not lose any entries.
  const std::size_t loaded_entries = db.root()->entries_count();
  if (loaded->root()->entries_count() != loaded_entries) {
    std::fprintf(stderr, "benchmark: entry count mismatch after import\n");
    std::exit(1);
  }

  std::remove(path.c_str());
  return {bytes, export_ms, import_ms};
}

} // namespace

int main(int argc, char** argv) {
  std::size_t entry_count = 2000;
  bool json = false;
  for (int i = 1; i < argc; ++i) {
    if (std::strcmp(argv[i], "--json") == 0) {
      json = true;
      continue;
    }
    char* end = nullptr;
    const long long value = std::strtoll(argv[i], &end, 10);
    if (end != argv[i] && *end == '\0' && value > 0)
      entry_count = static_cast<std::size_t>(value);
  }

  const std::unique_ptr<Database> db = MakeDatabase(entry_count);
  const Key key("password");

  struct Scenario {
    const char* name;
    Database::Cipher cipher;
    bool compress;
    bool kdbx4;
  };

  const Scenario scenarios[] = {
      {"kdbx3-aes-gzip", Database::Cipher::kAes, true, false},
      {"kdbx4-aes-gzip", Database::Cipher::kAes, true, true},
      {"kdbx4-aes-plain", Database::Cipher::kAes, false, true},
      {"kdbx4-chacha20-gzip", Database::Cipher::kChaCha20, true, true},
  };

  struct Measurement {
    const char* name;
    Result result;
  };
  std::array<Measurement, 4> measurements{};

  double worst_export = 0.0;
  double worst_import = 0.0;
  for (std::size_t i = 0; i < std::size(scenarios); ++i) {
    const Scenario& scenario = scenarios[i];
    // The database is reused for every scenario; per-scenario settings are
    // applied just before export.
    db->set_cipher(scenario.cipher);
    db->set_compress(scenario.compress);

    const std::string path = GetTmpPath(std::string("benchmark-") + scenario.name + ".kdbx");

    KdbxFile exporter;
    exporter.set_write_kdbx4(scenario.kdbx4);

    measurements[i] = {scenario.name, MeasureRoundTrip(path, *db, key, exporter)};
    worst_export = std::max(worst_export, measurements[i].result.export_ms);
    worst_import = std::max(worst_import, measurements[i].result.import_ms);
  }

  const std::size_t peak_rss = PeakRssKiB();

  if (json) {
    std::printf(R"({"entries":%zu,"peak_rss_kib":%zu,"scenarios":{)", entry_count, peak_rss);
    for (std::size_t i = 0; i < measurements.size(); ++i) {
      const Measurement& m = measurements[i];
      if (i != 0)
        std::printf(",");
      std::printf(R"("%s":{"bytes":%zu,"export_ms":%.3f,"import_ms":%.3f})", m.name, m.result.bytes,
                  m.result.export_ms, m.result.import_ms);
    }
    std::printf("}}\n");
    return 0;
  }

  std::printf("libkeepass load/export benchmark (%zu entries)\n", entry_count);
  std::printf(
      "scenario                   bytes  export_ms  import_ms  export MiB/s  import MiB/s\n");
  for (const Measurement& m : measurements) {
    const double mib = static_cast<double>(m.result.bytes) / (1024.0 * 1024.0);
    const double export_mibs = mib / (m.result.export_ms / 1000.0);
    const double import_mibs = mib / (m.result.import_ms / 1000.0);
    std::printf("%-24s %8zu %10.2f %10.2f %13.2f %13.2f\n", m.name, m.result.bytes,
                m.result.export_ms, m.result.import_ms, export_mibs, import_mibs);
  }

  std::printf("worst-case export: %.2f ms\n", worst_export);
  std::printf("worst-case import: %.2f ms\n", worst_import);
  if (peak_rss != 0)
    std::printf("peak RSS: %zu KiB\n", peak_rss);
  return 0;
}