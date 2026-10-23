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

#include <atomic>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include "config.hh"
#include "libkeepass/database.hh"
#include "libkeepass/exception.hh"
#include "libkeepass/keepass.hh"
#include "libkeepass/secure.hh"

using namespace keepass;

namespace {

std::string GetDataPath(const std::string& name) {
  return std::string(PROJECT_ROOT_PATH) + "/data/kdbx/" + name;
}

} // namespace

TEST(ConcurrencyTest, ConcurrentOpenOfSameFile) {
  const std::string path = GetDataPath("groups-2-random_entry-4-pw-aes.kdbx");

  // Capture the canonical snapshot once, then compare every concurrent import
  // against it. Each worker owns its KeePass instance, so no transformed key
  // or parser state is shared.
  std::string expected;
  {
    KeePass kp("password");
    std::unique_ptr<Database> db = kp.Open(path);
    ASSERT_TRUE(db);
    expected = db->ToJson();
  }

  std::atomic<int> failures{0};
  std::vector<std::thread> workers;
  workers.reserve(8);
  for (int t = 0; t < 8; ++t) {
    workers.emplace_back([&]() {
      for (int i = 0; i < 10; ++i) {
        try {
          KeePass kp("password");
          std::unique_ptr<Database> db = kp.Open(path);
          if (!db || db->ToJson() != expected)
            ++failures;
        } catch (...) {
          ++failures;
        }
      }
    });
  }
  for (std::thread& worker : workers)
    worker.join();

  EXPECT_EQ(0, failures.load());
}

TEST(ConcurrencyTest, KeysAreNotSharedAcrossInstances) {
  const std::string path = GetDataPath("groups-2-random_entry-4-pw-aes.kdbx");

  KeePass wrong("wrong-password");
  EXPECT_THROW(wrong.Open(path), PasswordError);

  // The failed import must not leave a cached key in the instance or leak one
  // into a second instance with the correct password.
  KeePass right("password");
  std::unique_ptr<Database> db = right.Open(path);
  ASSERT_TRUE(db);

  KeePass independent("another-wrong-password");
  EXPECT_THROW(independent.Open(path), PasswordError);
  EXPECT_EQ(db->ToJson(), right.Open(path)->ToJson());
}

TEST(ConcurrencyTest, SecureAllocationFailurePaths) {
  // Zero-sized allocations are valid and freeable, and null is a no-op.
  secure_free(nullptr, 0);

  void* zero = secure_alloc(0);
  ASSERT_NE(nullptr, zero);
  secure_free(zero, 0);

  // A range of sizes (including non-word multiples) must be usable and wiped
  // without sanitizer findings.
  for (std::size_t size : {1U, 7U, 32U, 4096U}) {
    auto* bytes = static_cast<unsigned char*>(secure_alloc(size));
    ASSERT_NE(nullptr, bytes);
    for (std::size_t i = 0; i < size; ++i)
      bytes[i] = 0xa5;
    secure_free(bytes, size);
  }
}
