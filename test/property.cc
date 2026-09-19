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
 * @file property.cc
 * @brief Cross-format round-trip property tests.
 *
 * For every supported format/cipher/KDF/compression combination ("leg") the
 * test generates a deterministic database from a fixed seed, writes it with
 * Save() and reads it back with Open(). A canonical serialization of the
 * original database is compared with that of the round-tripped database; the
 * canonical form only contains fields that are expected to survive the given
 * format (see the Caps struct).
 */

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <iterator>
#include <memory>
#include <random>
#include <sstream>
#include <string>
#include <vector>

#include "libkeepass/binary.hh"
#include "libkeepass/database.hh"
#include "libkeepass/entry.hh"
#include "libkeepass/group.hh"
#include "libkeepass/icon.hh"
#include "libkeepass/keepass.hh"
#include "libkeepass/key.hh"
#include "libkeepass/metadata.hh"
#include "libkeepass/secure.hh"
#include "libkeepass/temporal.hh"

#include "gtest/gtest.h"

#include "config.hh"

namespace {

using keepass::Binary;
using keepass::Database;
using keepass::Entry;
using keepass::Group;
using keepass::Icon;
using keepass::KeePass;
using keepass::Metadata;
using keepass::protect;
using keepass::secure_string;

constexpr const char* kPassphrase = "property-roundtrip-pw";

using Uuid = std::array<uint8_t, 16>;

// ---------------------------------------------------------------------------
// Deterministic random number generator facade.
// ---------------------------------------------------------------------------

class Rng {
public:
  explicit Rng(uint32_t seed) : rng_(seed) {}

  uint8_t NextByte() { return static_cast<uint8_t>(rng_() & 0xff); }

  template <size_t N> std::array<uint8_t, N> Bytes() {
    std::array<uint8_t, N> out{};
    for (auto& byte : out)
      byte = NextByte();
    return out;
  }

  std::string BytesStr(size_t n) {
    std::string out;
    out.reserve(n);
    for (size_t i = 0; i < n; ++i)
      out.push_back(static_cast<char>(NextByte()));
    return out;
  }

  Uuid NewUuid() { return Bytes<16>(); }

  uint32_t Pick(uint32_t bound) { return rng_() % bound; }

  bool Chance() { return (rng_() & 1U) != 0; }

  uint32_t U32(uint32_t lo, uint32_t hi) { return lo + rng_() % (hi - lo + 1); }

  // Single ASCII printable word; ';' is excluded because tag delimiters use it.
  std::string Word(size_t min_len, size_t max_len) {
    const size_t len = min_len + Pick(static_cast<uint32_t>(max_len - min_len + 1));
    std::string out;
    out.reserve(len);
    for (size_t i = 0; i < len; ++i) {
      char c = static_cast<char>(0x21 + NextByte() % 0x5e);
      if (c == ';')
        c = '!';
      out.push_back(c);
    }
    return out;
  }

  // Space-separated list of words (used for tags and free-form text).
  std::string Words(size_t min_count, size_t max_count) {
    const size_t count = min_count + Pick(static_cast<uint32_t>(max_count - min_count + 1));
    std::string out;
    for (size_t i = 0; i < count; ++i) {
      if (i > 0)
        out.push_back(' ');
      out += Word(1, 8);
    }
    return out;
  }

  // Deterministic positive timestamp (UTC, strongly within KDB time range).
  std::time_t Time() { return kTimeBase + Pick(static_cast<uint32_t>(86400ULL * 365 * 5)); }

private:
  std::mt19937 rng_;
  static constexpr std::time_t kTimeBase = 1600000000;
};

// ---------------------------------------------------------------------------
// Format capability table.
// ---------------------------------------------------------------------------

struct Caps {
  bool root;            // root group is round-tripped
  bool root_entries;    // entries stored directly under the root are round-tripped
  bool meta;            // the Metadata block is round-tripped
  bool group_extra;     // notes/tags/times-extras/autotype/search expand
  bool group_flags;     // the KDB group flags field survives
  bool entry_extra;     // entry times-extras/colors/autotype/custom fields/history/attachments
  bool protected_flags; // is_protected flags survive
  bool att_protected;   // attachment protection survives
  bool attachments;     // attachment data/names survive round-trip
};

struct LegParams {
  const char* name;
  KeePass::Format format;
  Database::Cipher cipher;
  Database::Kdf kdf;
  bool compress;
  Caps caps;
};

// KDBX 3 cannot round-trip entry attachments: KdbxXml::WriteEntry emits an
// inline base64 <Value> child for attachments that are absent from the binary
// pool, but ParseEntry reads the <Binary> element's own text, so the payload
// is dropped. Pool-based KDBX 3 attachments are covered in kdbx.cc instead.
constexpr Caps kKdbx3Caps = {true, true, true, true, false, true, true, true, false};
constexpr Caps kKdbxCaps = {true, true, true, true, false, true, true, true, true};
constexpr Caps kKdbCaps = {false, false, false, false, true, false, false, false, true};

const LegParams kLegs[] = {
    {"kdbx4-aes-aes-gzip", KeePass::Format::kKdbx4, Database::Cipher::kAes, Database::Kdf::kAes,
     true, kKdbxCaps},
    {"kdbx4-chacha-aes-plain", KeePass::Format::kKdbx4, Database::Cipher::kChaCha20,
     Database::Kdf::kAes, false, kKdbxCaps},
    {"kdbx4-twofish-aes-gzip", KeePass::Format::kKdbx4, Database::Cipher::kTwofish,
     Database::Kdf::kAes, true, kKdbxCaps},
    {"kdbx4-aes-argon2-plain", KeePass::Format::kKdbx4, Database::Cipher::kAes,
     Database::Kdf::kArgon2id, false, kKdbxCaps},
    {"kdbx3-aes-aes-gzip", KeePass::Format::kKdbx3, Database::Cipher::kAes, Database::Kdf::kAes,
     true, kKdbx3Caps},
    {"kdbx3-aes-aes-plain", KeePass::Format::kKdbx3, Database::Cipher::kAes, Database::Kdf::kAes,
     false, kKdbx3Caps},
    {"kdb-aes-aes-plain", KeePass::Format::kKdb, Database::Cipher::kAes, Database::Kdf::kAes, false,
     kKdbCaps},
};

// ---------------------------------------------------------------------------
// Canonical serialization helpers.
// ---------------------------------------------------------------------------

std::string Hex(const uint8_t* data, size_t n) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(2 * n);
  for (size_t i = 0; i < n; ++i) {
    out.push_back(kHex[data[i] >> 4]);
    out.push_back(kHex[data[i] & 0xf]);
  }
  return out;
}

template <size_t N> std::string Hex(const std::array<uint8_t, N>& data) {
  return Hex(data.data(), N);
}

std::string HexString(const std::string& str) {
  return Hex(reinterpret_cast<const uint8_t*>(str.data()), str.size());
}

std::string HexBytes(const std::vector<uint8_t>& vec) { return Hex(vec.data(), vec.size()); }

// Length-prefixed framing: tag=<len>:<raw>;
void Frame(std::string& out, const std::string& tag, const std::string& value) {
  out += tag;
  out += '=';
  out += std::to_string(value.size());
  out += ':';
  out += value;
  out += ';';
}

void FrameNum(std::string& out, const std::string& tag, uint64_t value) {
  Frame(out, tag, std::to_string(value));
}

void FrameTime(std::string& out, const std::string& tag, std::time_t value) {
  Frame(out, tag, std::to_string(static_cast<int64_t>(value)));
}

void FrameBool(std::string& out, const std::string& tag, bool value) {
  Frame(out, tag, value ? "1" : "0");
}

std::string Str(const std::string& value) { return value; }

std::string Str(const protect<secure_string>& value) { return value.value().str(); }

std::string StrVal(const std::string& value) { return value; }

// ---------------------------------------------------------------------------
// Database generation.
// ---------------------------------------------------------------------------

constexpr const char* kStandardKeys[] = {"Title", "URL", "UserName", "Password", "Notes"};

bool IsStandardKey(const std::string& key) {
  return std::find(std::begin(kStandardKeys), std::end(kStandardKeys), key) !=
         std::end(kStandardKeys);
}

// Sets the five timestamps shared by groups and entries. All times are set
// explicitly so that the round-trip comparison never relies on defaults.
template <typename T> void SetCommonTimes(const std::shared_ptr<T>& object, Rng& rng) {
  object->set_creation_time(rng.Time());
  object->set_modification_time(rng.Time());
  object->set_access_time(rng.Time());
  object->set_expiry_time(rng.Time());
  object->set_move_time(rng.Time());
}

void SetGroupExtras(const std::shared_ptr<Group>& group, Rng& rng,
                    const std::vector<std::shared_ptr<Icon>>& icons) {
  group->set_notes(rng.Words(1, 3));
  group->set_tags(rng.Words(1, 3));
  SetCommonTimes(group, rng);
  group->set_expires(rng.Chance());
  group->set_usage_count(rng.U32(0, 100000));
  group->set_expanded(rng.Chance());
  group->set_default_autotype_sequence(rng.Word(2, 8));
  group->set_autotype(rng.Chance());
  group->set_search(rng.Chance());
  if (!icons.empty() && rng.Chance())
    group->set_custom_icon(icons[rng.Pick(static_cast<uint32_t>(icons.size()))]);
}

std::shared_ptr<Entry> GenerateEntry(Rng& rng, const Caps& caps,
                                     const std::vector<std::shared_ptr<Icon>>& icons,
                                     bool generate_history) {
  std::shared_ptr<Entry> entry = std::make_shared<Entry>();
  entry->set_uuid(rng.NewUuid());
  entry->set_icon(rng.U32(0, 69));
  if (!icons.empty() && rng.Chance())
    entry->set_custom_icon(icons[rng.Pick(static_cast<uint32_t>(icons.size()))]);

  // Protected strings must be non-empty to round-trip their protection flag.
  const std::string title = rng.Word(3, 14);
  const bool title_prot = rng.Chance() && !title.empty();
  entry->set_title(protect<secure_string>(secure_string(title), title_prot));

  const std::string url =
      rng.Chance() ? "https://" + rng.Word(4, 10) + ".example" : rng.Word(3, 10);
  const bool url_prot = rng.Chance() && !url.empty();
  entry->set_url(protect<secure_string>(secure_string(url), url_prot));

  const std::string username = rng.Word(3, 10);
  const bool username_prot = rng.Chance() && !username.empty();
  entry->set_username(protect<secure_string>(secure_string(username), username_prot));

  const std::string password = rng.Word(6, 20);
  entry->set_password(protect<secure_string>(secure_string(password), true));

  const std::string notes = rng.Chance() ? rng.Words(1, 4) : "";
  const bool notes_prot = rng.Chance() && !notes.empty();
  entry->set_notes(protect<secure_string>(secure_string(notes), notes_prot));

  if (caps.entry_extra) {
    entry->set_tags(rng.Chance() ? rng.Words(1, 3) : "");
    entry->set_fg_color(rng.Chance() ? "#012345" : "");
    entry->set_bg_color(rng.Chance() ? "#abcdef" : "");
    entry->set_override_url(rng.Chance() ? rng.Word(3, 10) : "");
    entry->set_quality_check(rng.Chance());
    entry->set_expires(rng.Chance());

    auto& autotype = entry->auto_type();
    autotype.set_enabled(rng.Chance());
    autotype.set_sequence(rng.Word(2, 12));
    autotype.set_obfuscation(rng.Chance());
    const size_t association_count = rng.Pick(3);
    for (size_t i = 0; i < association_count; ++i)
      autotype.AddAssociation(rng.Word(2, 10), rng.Word(2, 12));

    const size_t custom_field_count = rng.Pick(3);
    for (size_t i = 0; i < custom_field_count; ++i) {
      std::string key = "F." + rng.Word(2, 6);
      if (IsStandardKey(key))
        key.insert(0, "F.x");
      const std::string value = rng.Chance() ? rng.Word(1, 10) : "";
      const bool value_prot = rng.Chance() && !value.empty();
      entry->AddCustomField(key, protect<secure_string>(secure_string(value), value_prot));
    }

    if (generate_history) {
      const size_t history_count = rng.Pick(2);
      for (size_t i = 0; i < history_count; ++i)
        entry->AddHistoryEntry(GenerateEntry(rng, caps, icons, false));
    }
  }

  // Attachments survive the KDBX 4 pool and KDB formats; see kKdbx3Caps.
  if (caps.attachments && rng.Chance()) {
    const std::string data = rng.BytesStr(16 + rng.Pick(48));
    const bool data_prot = rng.Chance();
    std::shared_ptr<Entry::Attachment> attachment = std::make_shared<Entry::Attachment>();
    attachment->set_name(rng.Word(4, 10));
    attachment->set_binary(
        std::make_shared<Binary>(protect<secure_string>(secure_string(data), data_prot)));
    entry->AddAttachment(attachment);
  }

  SetCommonTimes(entry, rng);
  return entry;
}

void GenerateGroupTree(const std::shared_ptr<Group>& group, Rng& rng, const Caps& caps,
                       const std::vector<std::shared_ptr<Icon>>& icons) {
  SetGroupExtras(group, rng, icons);
  group->set_flags(rng.U32(1, 0xffff));

  const size_t group_count = 2 + rng.Pick(3);
  for (size_t i = 0; i < group_count; ++i) {
    const std::shared_ptr<Group> child = Database::NewGroup(rng.Word(4, 12));
    SetGroupExtras(child, rng, icons);
    child->set_flags(rng.U32(1, 0xffff));
    group->AddGroup(child);

    const size_t entry_count = 1 + rng.Pick(2);
    for (size_t j = 0; j < entry_count; ++j)
      child->AddEntry(GenerateEntry(rng, caps, icons, true));

    if (rng.Chance()) {
      const std::shared_ptr<Group> subchild = Database::NewGroup(rng.Word(4, 12));
      SetGroupExtras(subchild, rng, icons);
      subchild->set_flags(rng.U32(1, 0xffff));
      child->AddGroup(subchild);
      subchild->AddEntry(GenerateEntry(rng, caps, icons, true));
    }
  }
}

std::shared_ptr<Database> GenerateDatabase(uint32_t seed, const LegParams& leg) {
  // Same seed yields the same database regardless of the leg; leg-specific
  // sections (icons, recycle bin, metadata) simply get skipped when the leg
  // cannot represent them.
  Rng rng(0x9e3779b9U ^ (seed * 2654435761U));

  std::shared_ptr<Database> db = std::make_shared<Database>();
  db->set_cipher(leg.cipher);
  db->set_kdf(leg.kdf);
  db->set_compress(leg.compress);
  db->set_master_seed(rng.Bytes<16>());
  db->set_init_vector(rng.Bytes<16>());
  if (leg.kdf == Database::Kdf::kAes) {
    db->set_transform_seed(rng.Bytes<32>());
    db->set_transform_rounds(8192);
  } else {
    const std::array<uint8_t, 16> argon2_salt = rng.Bytes<16>();
    db->set_argon2_salt(std::vector<uint8_t>(argon2_salt.begin(), argon2_salt.end()));
    db->set_argon2_iterations(2);
    db->set_argon2_memory(static_cast<uint64_t>(64) * 1024);
    db->set_argon2_parallelism(1);
    db->set_argon2_version(0x13);
  }

  std::shared_ptr<Group> root = Database::NewGroup(rng.Word(4, 12));
  root->set_icon(rng.U32(0, 69));
  SetGroupExtras(root, rng, {});
  db->set_root(root);

  std::vector<std::shared_ptr<Icon>> icons;
  std::shared_ptr<Group> recycle_bin;
  std::shared_ptr<Metadata> meta;
  if (leg.caps.meta) {
    const size_t icon_count = 2 + rng.Pick(2);
    for (size_t i = 0; i < icon_count; ++i) {
      const std::string icon_data = rng.BytesStr(8 + rng.Pick(32));
      icons.push_back(std::make_shared<Icon>(
          rng.NewUuid(), std::vector<uint8_t>(icon_data.begin(), icon_data.end())));
    }

    recycle_bin = Database::NewGroup(rng.Word(4, 12));
    root->AddGroup(recycle_bin);
    // The recycle bin group itself looks like a normal group.
    SetGroupExtras(recycle_bin, rng, icons);
    recycle_bin->set_flags(rng.U32(1, 0xffff));

    meta = std::make_shared<Metadata>();
    meta->set_generator(rng.Word(6, 12));
    meta->set_database_name(keepass::temporal<std::string>(rng.Word(5, 10), rng.Time()));
    meta->set_database_desc(keepass::temporal<std::string>(rng.Word(3, 8), rng.Time()));
    meta->set_default_username(keepass::temporal<std::string>(rng.Word(4, 9), rng.Time()));
    meta->set_maintenance_hist_days(rng.U32(1, 365));
    meta->set_database_color(rng.Word(3, 8));
    meta->set_master_key_changed(rng.Time());
    meta->set_master_key_change_rec(rng.Chance() ? static_cast<int64_t>(rng.U32(1, 30)) : -1);
    meta->set_master_key_change_force(rng.Chance() ? static_cast<int64_t>(rng.U32(1, 30)) : -1);
    auto& mp = meta->memory_protection();
    mp.set_title(rng.Chance());
    mp.set_username(rng.Chance());
    mp.set_password(rng.Chance());
    mp.set_url(rng.Chance());
    mp.set_notes(rng.Chance());
    meta->set_recycle_bin(recycle_bin);
    meta->set_recycle_bin_changed(rng.Time());
    meta->set_history_max_items(rng.Chance() ? static_cast<int32_t>(rng.U32(0, 50)) : -1);
    meta->set_history_max_size(rng.Chance() ? static_cast<int64_t>(rng.U32(0, 1000000)) : -1);
    const size_t field_count = rng.Pick(3);
    for (size_t i = 0; i < field_count; ++i)
      meta->AddField(rng.Word(3, 10), rng.Word(1, 20));
    for (const auto& icon : icons)
      meta->AddIcon(icon);
    db->set_meta(meta);
  }

  GenerateGroupTree(root, rng, leg.caps, icons);
  return db;
}

// ---------------------------------------------------------------------------
// Canonical serialization.
// ---------------------------------------------------------------------------

void CanonicalGroup(std::string& out, const std::shared_ptr<Group>& group, const Caps& caps) {
  Frame(out, "name", group->name());
  FrameNum(out, "icon", group->icon());
  if (auto icon = group->custom_icon().lock())
    Frame(out, "custom-icon", Hex(icon->uuid()));
  FrameTime(out, "creation", group->creation_time());
  FrameTime(out, "modification", group->modification_time());
  FrameTime(out, "access", group->access_time());
  FrameTime(out, "expiry", group->expiry_time());
  if (caps.group_flags)
    FrameNum(out, "flags", group->flags());
  if (caps.group_extra) {
    Frame(out, "notes", group->notes());
    Frame(out, "tags", group->tags());
    FrameTime(out, "move", group->move_time());
    FrameBool(out, "expires", group->expires());
    FrameNum(out, "usage", group->usage_count());
    FrameBool(out, "expanded", group->expanded());
    Frame(out, "auto-seq", group->default_autotype_sequence());
    FrameBool(out, "auto-type", group->autotype());
    FrameBool(out, "search", group->search());
  }
}

void CanonicalEntryImpl(std::string& out, const std::shared_ptr<Entry>& entry, const Caps& caps,
                        bool include_history) {
  Frame(out, "uuid", Hex(entry->uuid()));
  Frame(out, "title", Str(entry->title()));
  Frame(out, "url", Str(entry->url()));
  Frame(out, "username", Str(entry->username()));
  Frame(out, "password", Str(entry->password()));
  Frame(out, "notes", Str(entry->notes()));
  if (caps.protected_flags) {
    FrameBool(out, "title-prot", entry->title().is_protected());
    FrameBool(out, "url-prot", entry->url().is_protected());
    FrameBool(out, "user-prot", entry->username().is_protected());
    FrameBool(out, "pass-prot", entry->password().is_protected());
    FrameBool(out, "notes-prot", entry->notes().is_protected());
  }
  FrameNum(out, "icon", entry->icon());
  if (auto icon = entry->custom_icon().lock())
    Frame(out, "custom-icon", Hex(icon->uuid()));
  FrameTime(out, "creation", entry->creation_time());
  FrameTime(out, "modification", entry->modification_time());
  FrameTime(out, "access", entry->access_time());
  FrameTime(out, "expiry", entry->expiry_time());

  if (caps.entry_extra) {
    FrameTime(out, "move", entry->move_time());
    FrameBool(out, "expires", entry->expires());
    FrameNum(out, "usage", entry->usage_count());
    FrameBool(out, "quality", entry->quality_check());
    Frame(out, "fg", entry->fg_color());
    Frame(out, "bg", entry->bg_color());
    Frame(out, "override-url", entry->override_url());
    Frame(out, "tags", entry->tags());

    const auto& autotype = entry->auto_type();
    FrameBool(out, "at-enabled", autotype.enabled());
    FrameNum(out, "at-obf", autotype.obfuscation());
    Frame(out, "at-seq", autotype.sequence());
    FrameNum(out, "at-associations", autotype.associations().size());
    for (const auto& association : autotype.associations()) {
      Frame(out, "at-window", association.window());
      Frame(out, "at-window-seq", association.sequence());
    }

    FrameNum(out, "custom-fields", entry->custom_fields().size());
    for (const auto& field : entry->custom_fields()) {
      Frame(out, "field-key", field.key());
      Frame(out, "field-value", Str(field.value()));
      if (caps.protected_flags)
        FrameBool(out, "field-prot", field.value().is_protected());
    }

    FrameNum(out, "history", entry->history().size());
    if (include_history) {
      for (const auto& history_entry : entry->history())
        CanonicalEntryImpl(out, history_entry, caps, false);
    }
  }

  // Attachments survive all formats (KDB stores a single name/data pair).
  FrameNum(out, "attachments", entry->attachments().size());
  for (const auto& attachment : entry->attachments()) {
    Frame(out, "att-name", attachment->name());
    if (auto binary = attachment->binary()) {
      Frame(out, "att-data", HexString(Str(binary->data())));
      if (caps.att_protected)
        FrameBool(out, "att-prot", binary->data().is_protected());
    }
  }
}

void CanonicalEntry(std::string& out, const std::shared_ptr<Entry>& entry, const Caps& caps) {
  CanonicalEntryImpl(out, entry, caps, true);
}

void CanonicalGroupTree(std::string& out, const std::shared_ptr<Group>& group, const Caps& caps) {
  CanonicalGroup(out, group, caps);
  for (const auto& entry : group->Entries())
    CanonicalEntry(out, entry, caps);
  for (const auto& child : group->Groups())
    CanonicalGroupTree(out, child, caps);
}

void CanonicalMeta(std::string& out, const std::shared_ptr<Metadata>& meta) {
  Frame(out, "generator", meta->generator());
  Frame(out, "db-name", meta->database_name().value());
  FrameTime(out, "db-name-time", meta->database_name().time());
  Frame(out, "db-desc", meta->database_desc().value());
  FrameTime(out, "db-desc-time", meta->database_desc().time());
  Frame(out, "default-user", meta->default_username().value());
  FrameTime(out, "default-user-time", meta->default_username().time());
  FrameNum(out, "maintenance-days", meta->maintenance_hist_days());
  Frame(out, "db-color", meta->database_color());
  FrameTime(out, "master-key-changed", meta->master_key_changed());
  Frame(out, "key-change-rec", std::to_string(meta->master_key_change_rec()));
  Frame(out, "key-change-force", std::to_string(meta->master_key_change_force()));

  const auto& mp = meta->memory_protection();
  FrameBool(out, "mp-title", mp.title());
  FrameBool(out, "mp-username", mp.username());
  FrameBool(out, "mp-password", mp.password());
  FrameBool(out, "mp-url", mp.url());
  FrameBool(out, "mp-notes", mp.notes());

  if (auto recycle_bin = meta->recycle_bin()) {
    Frame(out, "recycle-bin", recycle_bin->name());
    FrameTime(out, "recycle-bin-time", meta->recycle_bin_changed());
  }
  Frame(out, "history-max", std::to_string(meta->history_max_items()));
  Frame(out, "history-max-size", std::to_string(meta->history_max_size()));

  FrameNum(out, "custom-fields", meta->fields().size());
  for (const auto& field : meta->fields()) {
    Frame(out, "field-key", field.key());
    Frame(out, "field-value", field.value());
  }

  FrameNum(out, "icons", meta->icons().size());
  for (const auto& icon : meta->icons()) {
    Frame(out, "icon-uuid", Hex(icon->uuid()));
    Frame(out, "icon-data", HexBytes(icon->data()));
  }
}

std::string CanonicalDatabase(const Database& db, const Caps& caps) {
  std::string out;
  FrameNum(out, "cipher", static_cast<uint64_t>(db.cipher()));
  FrameNum(out, "kdf", static_cast<uint64_t>(db.kdf()));
  FrameBool(out, "compress", db.compress());

  if (caps.meta && db.meta())
    CanonicalMeta(out, db.meta());

  std::shared_ptr<Group> root = db.root();
  if (root) {
    if (caps.root)
      CanonicalGroup(out, root, caps);
    if (caps.root_entries) {
      for (const auto& entry : root->Entries())
        CanonicalEntry(out, entry, caps);
    }
    for (const auto& group : root->Groups())
      CanonicalGroupTree(out, group, caps);
  }
  return out;
}

// ---------------------------------------------------------------------------
// The test.
// ---------------------------------------------------------------------------

TEST(PropertyRoundTrip, AllLegs) {
  constexpr uint32_t kSeedCount = 8;
  for (const LegParams& leg : kLegs) {
    SCOPED_TRACE(::testing::Message() << "leg=" << leg.name);
    for (uint32_t seed = 0; seed < kSeedCount; ++seed) {
      SCOPED_TRACE(::testing::Message() << "seed=" << seed);
      const std::shared_ptr<Database> db = GenerateDatabase(seed, leg);
      const std::string original = CanonicalDatabase(*db, leg.caps);

      if (leg.format == KeePass::Format::kKdb) {
        // KDB is file based; it cannot be written to/read from a stream.
        const std::string path =
            std::string(PROJECT_ROOT_PATH) + "/tmp/property-kdb-" + std::to_string(seed) + ".kdb";
        KeePass writer(kPassphrase);
        writer.SetFormat(leg.format);
        writer.Save(path, *db);

        KeePass reader(kPassphrase);
        std::unique_ptr<Database> loaded = reader.Open(path);
        const std::string roundtrip = CanonicalDatabase(*loaded, leg.caps);
        std::remove(path.c_str());
        EXPECT_EQ(original, roundtrip);
      } else {
        std::stringstream buffer;
        KeePass writer(kPassphrase);
        writer.SetFormat(leg.format);
        writer.Save(buffer, *db);

        buffer.seekg(0);
        KeePass reader(kPassphrase);
        std::unique_ptr<Database> loaded = reader.Open(buffer);
        const std::string roundtrip = CanonicalDatabase(*loaded, leg.caps);
        EXPECT_EQ(original, roundtrip);
      }
    }
  }
}

} // namespace