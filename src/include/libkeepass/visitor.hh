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
 * @file visitor.hh
 * @brief Visitor pattern for traversing KeePass group and entry trees.
 */

#pragma once
#include <iosfwd>

#include "libkeepass/export.hh"

namespace keepass {

class Entry;
class Group;

/**
 * @brief Visitor pattern over a KeePass group/entry tree.
 *
 * Traversal is depth-first. Groups and entries are visited in document order;
 * the entries of a group are visited immediately after that group and before
 * its subgroups.
 */
class LIBKEEPASS_API Visitor {
public:
  virtual ~Visitor() = default;

  /// Called for every group during traversal.
  virtual void Visit(Group& group);

  /// Called for every entry during traversal.
  virtual void Visit(Entry& entry);
};

/**
 * @brief Visitor that prints the path of every group and entry to a stream.
 */
class LIBKEEPASS_API PrintVisitor : public Visitor {
public:
  /// Creates a visitor that writes to the given output stream.
  explicit PrintVisitor(std::ostream& os) : os_(os) {}

  void Visit(Group& group) override;
  void Visit(Entry& entry) override;

private:
  std::ostream& os_;
};

/// Traverses the tree rooted at the given group, visiting every group and entry.
/**
 * @param group The group whose subtree is traversed.
 * @param visitor The visitor to notify during traversal.
 */
LIBKEEPASS_API void Visit(Group& group, Visitor& visitor);

} // namespace keepass