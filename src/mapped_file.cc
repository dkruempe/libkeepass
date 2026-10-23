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

#include "libkeepass/detail/mapped_file.hh"

#include <algorithm>
#include <cerrno>

#include "libkeepass/exception.hh"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace keepass {
namespace detail {

MappedFile::MappedFile(const std::string& path) {
#ifdef _WIN32
  HANDLE file = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (file == INVALID_HANDLE_VALUE) {
    const DWORD error = GetLastError();
    if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND)
      throw FileNotFoundError();
    throw IoError("Unable to open database file.");
  }
  file_ = file;

  LARGE_INTEGER file_size{};
  if (!GetFileSizeEx(file, &file_size)) {
    CloseHandle(file);
    file_ = nullptr;
    throw IoError("Unable to determine database file size.");
  }
  if (file_size.QuadPart == 0)
    return;

  // Map the whole file read-only. The mapping is independent of the file
  // handle, so the handle can be closed as soon as the view exists.
  HANDLE mapping = CreateFileMappingA(file, nullptr, PAGE_READONLY, 0, 0, nullptr);
  if (mapping == nullptr) {
    CloseHandle(file);
    file_ = nullptr;
    throw IoError("Unable to map database file.");
  }
  mapping_ = mapping;

  void* view = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
  if (view == nullptr) {
    CloseHandle(mapping);
    mapping_ = nullptr;
    CloseHandle(file);
    file_ = nullptr;
    throw IoError("Unable to map database file.");
  }

  data_ = view;
  size_ = static_cast<std::size_t>(file_size.QuadPart);

  CloseHandle(mapping);
  mapping_ = nullptr;
  CloseHandle(file);
  file_ = nullptr;
#else
  const int fd = ::open(path.c_str(), O_RDONLY);
  if (fd < 0) {
    if (errno == ENOENT || errno == ENOTDIR)
      throw FileNotFoundError();
    throw IoError("Unable to open database file.");
  }

  struct stat status{};
  if (::fstat(fd, &status) != 0) {
    ::close(fd);
    throw IoError("Unable to determine database file size.");
  }
  if (status.st_size <= 0) {
    ::close(fd);
    return;
  }

  const std::size_t size = static_cast<std::size_t>(status.st_size);
  void* data = ::mmap(nullptr, size, PROT_READ, MAP_PRIVATE, fd, 0);
  ::close(fd);
  if (data == MAP_FAILED)
    throw IoError("Unable to map database file.");

  data_ = data;
  size_ = size;
#endif
}

MappedFile::~MappedFile() {
#ifdef _WIN32
  if (data_ != nullptr)
    UnmapViewOfFile(data_);
  if (mapping_ != nullptr)
    CloseHandle(static_cast<HANDLE>(mapping_));
  if (file_ != nullptr)
    CloseHandle(static_cast<HANDLE>(file_));
#else
  if (data_ != nullptr)
    ::munmap(data_, size_);
  if (fd_ >= 0)
    ::close(fd_);
#endif
}

std::streampos mapped_istreambuf::seekoff(std::streamoff off, std::ios_base::seekdir way,
                                          std::ios_base::openmode which) {
  if ((which & std::ios_base::in) == 0)
    return std::streampos(std::streamoff(-1));

  std::streamoff base = 0;
  switch (way) {
  case std::ios_base::beg:
    base = 0;
    break;
  case std::ios_base::cur:
    base = gptr() - eback();
    break;
  case std::ios_base::end:
    base = end_ - begin_;
    break;
  default:
    return std::streampos(std::streamoff(-1));
  }

  const std::streamoff position = base + off;
  if (position < 0 || position > end_ - begin_)
    return std::streampos(std::streamoff(-1));

  setg(begin_, begin_ + position, end_);
  return std::streampos(position);
}

std::streampos mapped_istreambuf::seekpos(std::streampos sp, std::ios_base::openmode which) {
  if ((which & std::ios_base::in) == 0 || sp < 0 || sp > end_ - begin_)
    return std::streampos(std::streamoff(-1));

  setg(begin_, begin_ + static_cast<std::streamoff>(sp), end_);
  return sp;
}

} // namespace detail
} // namespace keepass
