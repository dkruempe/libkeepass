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

#include "libkeepass/visitor.hh"

#include <ostream>

#include "libkeepass/entry.hh"
#include "libkeepass/group.hh"

namespace keepass {

void Visitor::Visit(Group&) {}

void Visitor::Visit(Entry&) {}

void PrintVisitor::Visit(Group& group) { os_ << group.path() << "\n"; }

void PrintVisitor::Visit(Entry& entry) { os_ << entry.path() << "\n"; }

void Visit(Group& group, Visitor& visitor) {
  visitor.Visit(group);
  for (const auto& entry : group.Entries())
    visitor.Visit(*entry);
  for (const auto& child : group.Groups())
    Visit(*child, visitor);
}

} // namespace keepass