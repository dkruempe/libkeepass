/*
 * libkeepass - KeePass key database importer/exporter
 * Copyright (C) 2014 Christian Kindahl
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

#include "libkeepass/util.hh"

#include <cassert>
#include <random>

namespace keepass {

std::string time_to_str(const std::time_t &time) {
  const std::tm *local_time = std::localtime(&time);
  assert(local_time != nullptr);

  char buffer[128];
  strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", local_time);
  return buffer;
}

std::array<uint8_t, 16> generate_uuid() {
  std::random_device rd;
  std::mt19937 engine(rd());

  std::uniform_int_distribution<uint8_t> uniform_dist(0, 255);

  // Fill block with random values.
  std::array<uint8_t, 16> uuid{};
  for (std::size_t i = 0; i < 16; ++i)
    uuid[i] = uniform_dist(engine);

  return uuid;
}

} // namespace keepass
