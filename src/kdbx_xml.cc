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

#include "libkeepass/kdbx_xml.hh"

#include <array>
#include <cassert>
#ifdef DEBUG
#include <iostream>
#endif

#include <pugixml.hpp>

#include "libkeepass/base64.hh"
#include "libkeepass/exception.hh"
#include "libkeepass/iterator.hh"
#include "libkeepass/group.hh"
#include "libkeepass/metadata.hh"

namespace keepass {

void KdbxXml::Reset() {
  binary_pool_.clear();
  icon_pool_.clear();
  group_pool_.clear();
  header_hash_ = {0};
  groups_seen_ = 0;
  entries_seen_ = 0;
  history_items_seen_ = 0;
  kdbx41_ = false;
}

std::shared_ptr<Group> KdbxXml::GetGroup(const std::string& uuid_str) {
  if (uuid_str.empty())
    return nullptr;

  auto it = group_pool_.find(uuid_str);
  if (it != group_pool_.end())
    return it->second;

  std::array<uint8_t, 16> uuid{};
  base64_decode<bounds_checked_iterator<std::array<uint8_t, 16>>, unsigned char>(
      uuid_str, bounds_checked(uuid));

  std::shared_ptr<Group> group = std::make_shared<Group>();
  group->set_uuid(uuid);

  group_pool_.insert(std::make_pair(uuid_str, group));
  return group;
}

void KdbxXml::Parse(std::istream& src, RandomObfuscator& obfuscator, Database& db) {
  pugi::xml_document doc;
  if (!doc.load(src, pugi::parse_default | pugi::parse_trim_pcdata))
    throw FormatError("Malformed XML in KDBX.");

  pugi::xml_node kpf_node = doc.child("KeePassFile");
  if (!kpf_node)
    throw FormatError("No \"KeePassFile\" element in KDBX XML.");

  pugi::xml_node meta_node = kpf_node.child("Meta");
  if (!meta_node)
    throw FormatError("No \"Meta\" element in KDBX XML.");

  pugi::xml_node group_node = kpf_node.child("Root").child("Group");
  if (!group_node)
    throw FormatError(R"(No "Root" or "Group" element in KDBX XML.)");

  std::shared_ptr<Metadata> meta = ParseMeta(meta_node, obfuscator);
  std::shared_ptr<Group> root = ParseGroup(group_node, obfuscator);

  for (pugi::xml_node object_node =
           kpf_node.child("Root").child("DeletedObjects").child("DeletedObject");
       object_node; object_node = object_node.next_sibling("DeletedObject")) {
    std::array<uint8_t, 16> uuid = {{0}};
    base64_decode<bounds_checked_iterator<std::array<uint8_t, 16>>, unsigned char>(
        object_node.child_value("UUID"), bounds_checked(uuid));
    meta->AddDeletedObject(
        Metadata::DeletedObject(uuid, ParseDateTime(object_node.child_value("DeletionTime"))));
  }

  db.set_meta(meta);
  db.set_root(root);

  // When first parsing the meta data we haven't yet parsed all groups so we
  // have to wait until every group is parsed before parsing the final parts of
  // the meta data.
  auto it = group_pool_.find(meta_node.child_value("LastSelectedGroup"));
  if (it != group_pool_.end()) {
    meta->set_last_selected_group(it->second);
  }

  it = group_pool_.find(meta_node.child_value("LastTopVisibleGroup"));
  if (it != group_pool_.end()) {
    meta->set_last_visible_group(it->second);
  }
}

#ifdef DEBUG
void KdbxXml::PrintXml(pugi::xml_document& doc) {
  static const char* kNodeTypeNames[] = {"null",  "document", "element", "pcdata",
                                         "cdata", "comment",  "pi",      "declaration"};

  struct XmlTreeWalker : pugi::xml_tree_walker {
  public:
    virtual bool for_each(pugi::xml_node& node) override {
      for (int i = 0; i < depth(); ++i)
        std::cout << "  ";

      std::cout << kNodeTypeNames[node.type()] << ": name=\"" << node.name() << "\"; value=\""
                << node.value() << "\"" << std::endl;
      return true;
    }
  };

  XmlTreeWalker walker;
  doc.traverse(walker);
}
#endif

void KdbxXml::Write(std::ostream& dst, RandomObfuscator& obfuscator, const Database& db) {
  pugi::xml_document doc;

  pugi::xml_node kpf_node = doc.append_child("KeePassFile");
  pugi::xml_node meta_node = kpf_node.append_child("Meta");
  pugi::xml_node root_node = kpf_node.append_child("Root");
  pugi::xml_node group_node = root_node.append_child("Group");

  // A freshly created database may lack metadata or a root group; export a
  // default placeholder in that case instead of dereferencing a null pointer.
  if (!db.meta()) {
    static const std::shared_ptr<Metadata> empty_meta = std::make_shared<Metadata>();
    WriteMeta(meta_node, obfuscator, empty_meta);
  } else {
    WriteMeta(meta_node, obfuscator, db.meta());

    if (!db.meta()->deleted_objects().empty()) {
      pugi::xml_node del_node = root_node.append_child("DeletedObjects");
      for (const auto& object : db.meta()->deleted_objects()) {
        pugi::xml_node object_node = del_node.append_child("DeletedObject");
        object_node.append_child("UUID").text().set(
            base64_encode(object.uuid().begin(), object.uuid().end()).c_str());
        object_node.append_child("DeletionTime")
            .text()
            .set(WriteDateTime(object.deletion_time()).c_str());
      }
    }
  }

  static const std::shared_ptr<Group> empty_root = std::make_shared<Group>();
  WriteGroup(group_node, obfuscator, db.root() ? db.root() : empty_root);

  doc.save(dst);
}

} // namespace keepass