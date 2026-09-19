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

#include <fstream>
#include <iosfwd>
#include <memory>
#include <string>
#include <vector>

#include "args.hh"

namespace keepass {
class Entry;
class Group;
} // namespace keepass

namespace kpx {

/// Prints the command-line usage text to os.
void PrintUsage(const char* prog, std::ostream& os);

/// Collects all entries under the given group that match the query.
std::vector<std::shared_ptr<keepass::Entry>>
SearchEntries(const std::shared_ptr<keepass::Group>& start, const std::string& query, bool regex,
              bool exact_title);

/// Builds a lightweight copy of the group tree that contains only the entries
/// matching the query and their ancestor groups. The copied groups only carry
/// their names; the entries are the original objects.
std::shared_ptr<keepass::Group> PrunedRoot(const std::shared_ptr<keepass::Group>& src,
                                           const std::string& query, bool regex);

/// Opens the output stream for the print commands. When --output is given the
/// stream is opened in the provided file object; otherwise stdout is used and
/// no file is opened. Returns false and prints an error if the file cannot be
/// opened.
bool OpenOutput(const Options& opt, std::ofstream& file);

/// Returns the stream to which the print commands should write.
std::ostream& OutputStream(const Options& opt, std::ofstream& file);

/// Runs the audit command against the given subtree and writes the findings
/// in the configured format. Returns the process exit code.
int RunAudit(const Options& opt, const std::shared_ptr<keepass::Group>& start);

/// Runs the print command for the given group tree (possibly a pruned search
/// result or a --group subtree) in the configured format.
int RunPrint(const Options& opt, const std::shared_ptr<keepass::Group>& root);

} // namespace kpx