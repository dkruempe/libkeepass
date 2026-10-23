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

/** @file exception.hh @brief Exception types thrown by the library. */

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <utility>

#include "libkeepass/export.hh"

namespace keepass {

/**
 * @brief Coarse error category shared by all library exceptions.
 *
 * The category is stable API: it can be used by callers (and the CLI) to map
 * failures to user-facing exit codes or messages without relying on the exact
 * exception class or the message text.
 */
enum class ErrorCategory {
  kAuthentication, ///< Wrong password, key file or key.
  kFormat,         ///< Corrupt, truncated or otherwise invalid database.
  kUnsupported,    ///< A valid but unsupported format feature/version.
  kResourceLimit,  ///< A parser/decompression resource budget was exceeded.
  kIo,             ///< Reading or writing failed.
  kInternal        ///< An internal invariant or allocation failed.
};

/// Returns a stable, lowercase name for an error category.
LIBKEEPASS_API const char* ErrorCategoryName(ErrorCategory category) noexcept;

/**
 * @brief Common base class for all libkeepass exceptions.
 */
class LIBKEEPASS_API Error : public std::exception {
public:
  /// Returns the coarse category of this error.
  virtual ErrorCategory category() const noexcept = 0;
};

/**
 * @brief Thrown when an invalid password is supplied while opening a database.
 */
class LIBKEEPASS_API PasswordError final : public Error {
public:
  explicit PasswordError() = default;

  const char* what() const noexcept override { return "Invalid password."; }

  ErrorCategory category() const noexcept override { return ErrorCategory::kAuthentication; }
};

/**
 * @brief Thrown when a database or stream has an invalid format.
 *
 * The optional @ref offset can point at the first byte that failed validation,
 * which is useful for diagnostics in large or truncated files.
 */
class LIBKEEPASS_API FormatError : public Error {
private:
  const std::string msg_{};
  std::optional<uint64_t> offset_{};

public:
  explicit FormatError(std::string msg) : msg_(std::move(msg)) {}

  /**
   * @param msg Human-readable description (must not contain key material).
   * @param offset Byte offset in the input at which the error was detected.
   */
  FormatError(std::string msg, uint64_t offset) : msg_(std::move(msg)), offset_(offset) {}

  const char* what() const noexcept override { return msg_.c_str(); }

  /// Returns the byte offset of the failure, if known.
  std::optional<uint64_t> offset() const noexcept { return offset_; }

  ErrorCategory category() const noexcept override { return ErrorCategory::kFormat; }
};

/**
 * @brief Thrown when a database uses a valid but unsupported format feature.
 *
 * This derives from @ref FormatError so existing callers that treat all
 * format problems alike keep working, while new callers can distinguish an
 * unsupported KDBX version, cipher or KDF from actual corruption.
 */
class LIBKEEPASS_API UnsupportedFeatureError final : public FormatError {
public:
  explicit UnsupportedFeatureError(std::string msg) : FormatError(std::move(msg)) {}

  UnsupportedFeatureError(std::string msg, uint64_t offset) : FormatError(std::move(msg), offset) {}

  ErrorCategory category() const noexcept override { return ErrorCategory::kUnsupported; }
};

/**
 * @brief Thrown when a parser, decompressor or XML budget is exceeded.
 */
class LIBKEEPASS_API ResourceLimitError final : public FormatError {
public:
  explicit ResourceLimitError(std::string msg) : FormatError(std::move(msg)) {}

  ResourceLimitError(std::string msg, uint64_t offset) : FormatError(std::move(msg), offset) {}

  ErrorCategory category() const noexcept override { return ErrorCategory::kResourceLimit; }
};

/**
 * @brief Thrown for the same class of errors as asserts, but in release builds.
 */
class LIBKEEPASS_API InternalError : public Error {
private:
  const std::string msg_{};

public:
  explicit InternalError(std::string msg) : msg_(std::move(msg)) {}

  const char* what() const noexcept override { return msg_.c_str(); }

  ErrorCategory category() const noexcept override { return ErrorCategory::kInternal; }
};

/**
 * @brief Thrown for input/output errors while reading or writing databases.
 */
class LIBKEEPASS_API IoError : public Error {
private:
  const std::string msg_{};

public:
  explicit IoError(std::string msg) : msg_(std::move(msg)) {}

  const char* what() const noexcept override { return msg_.c_str(); }

  ErrorCategory category() const noexcept override { return ErrorCategory::kIo; }
};

/**
 * @brief Thrown when a requested file does not exist.
 */
class LIBKEEPASS_API FileNotFoundError final : public IoError {
public:
  FileNotFoundError() : IoError("File not found.") {}
};

} // namespace keepass
