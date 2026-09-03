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

#include "libkeepass/export.hh"

namespace keepass {

class LIBKEEPASS_API PasswordError final : public std::exception {
public:
  explicit PasswordError() = default;

  const char *what() const noexcept override { return "Invalid password."; }
};

class LIBKEEPASS_API FormatError final : public std::exception {
private:
  const std::string msg_{};

public:
  explicit FormatError(std::string msg) : msg_(std::move(msg)) {}

  const char *what() const noexcept override { return msg_.c_str(); }
};

/**
 * @brief Used for the same class of errors as asserts but for release builds.
 */
class LIBKEEPASS_API InternalError : public std::exception {
private:
  const std::string msg_{};

public:
  explicit InternalError(std::string msg) : msg_(std::move(msg)) {}

  const char *what() const noexcept override { return msg_.c_str(); }
};

class LIBKEEPASS_API IoError : public std::exception {
private:
  const std::string msg_{};

public:
  explicit IoError(std::string msg) : msg_(std::move(msg)) {}

  const char *what() const noexcept override { return msg_.c_str(); }
};

class LIBKEEPASS_API FileNotFoundError final : public IoError {
public:
  FileNotFoundError() : IoError("File not found.") {}
};

} // namespace keepass
