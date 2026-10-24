# Worked examples

The snippets below use the public API from `libkeepass/keepass.hh`,
`database.hh`, `group.hh`, `entry.hh` and `key.hh`. They assume C++17.

## Round-trip through memory streams

```cpp
#include <sstream>
#include "libkeepass/keepass.hh"

using namespace keepass;

KeePass reader("correct horse battery staple");
std::unique_ptr<Database> db = reader.Open("vault.kdbx");

std::ostringstream encrypted;
reader.Save(encrypted, *db); // KDBX 3 or 4 chosen from KDF/cipher

std::istringstream input(encrypted.str());
KeePass reopened("correct horse battery staple");
std::unique_ptr<Database> copy = reopened.Open(input);
```

Non-seekable streams are buffered internally; seekable streams are parsed
directly after an 8-byte signature sniff.

## Create a database and change its password

```cpp
auto db = KeePass::Create("initial password", KeePass::Format::kKdbx4);
Database::AddGroup(db->root(), Database::NewGroup("Internet"));

// The transformed key is cached on db, so a keyless save works.
KeePass keyless;
keyless.SetFormat(KeePass::Format::kKdbx4);
keyless.Save("new.kdbx", *db);

// Re-encrypt an existing database with a new key. SaveAs overrides any
// transformed key cached on the database.
KeePass rekey;
rekey.SaveAs("new.kdbx", *db, "new password");
```

The CLI equivalents are `kpx create` and `kpx passwd`.

## Attachments

```cpp
Entry::Attachment attachment;
attachment.set_name("notes.txt");
attachment.set_binary(std::make_shared<Binary>(
    protect<secure_string>(secure_string("payload"), false)));

auto entry = Database::NewEntry("Document");
entry->AddAttachment(std::make_shared<Entry::Attachment>(attachment));
Database::AddEntry(db->root(), entry);
```

The convenience helpers use raw byte vectors and are easier for binary data:

```cpp
entry->set_binary_property("report.pdf", file_bytes);
std::vector<uint8_t> restored = entry->get_binary_property("report.pdf");
entry->delete_binary_property("report.pdf");
```

Attachments are preserved through KDBX 3/4 import and export; KDB (1.x) has no
attachment support.

## Tags and custom fields

```cpp
auto group = Database::NewGroup("Work");
group->set_tags("work internal"); // space-separated in the API
Database::AddGroup(db->root(), group);

auto entry = Database::NewEntry("Mail");
entry->set_tags("mail 2fa");
entry->set_custom_property("otp", "otpauth://totp/...");
std::string seed = entry->GetString("otp");
```

On the wire, KeePass 2.48+ stores tags semicolon-separated; the conversion is
done at the XML boundary.

## Recycle bin and history

```cpp
db->EnableRecycleBin(true);
db->TrashEntry(entry);          // move to the recycle bin (delete if disabled)
db->EmptyRecycleBin();

entry->save_history();          // snapshot the current field values
entry->set_notes(protect<secure_string>(secure_string("changed"), false));
entry->delete_old_history(10);  // keep only the 10 newest versions
entry->delete_history();        // clear all previous versions
```

Entry history is preserved by import/export but hidden from the `kpx` print and
audit output; use `Entry::history()` when you need it. `Database::DeleteOldHistory()`
applies the `HistoryMaxItems`/`HistoryMaxSize` metadata limits to every entry,
and `kpx purge --keep <n>` exposes the same policy on the command line.

## TOTP custom fields

`Entry::totp()` parses the KeePass field variants (`otp`, `TOTP Seed`,
`TOTP Settings`, including complete `otpauth://totp/...` URIs), and
`Totp::Generate()` produces the current code:

```cpp
if (auto config = entry->totp()) {
    std::string code = Totp::Generate(*config);
    uint32_t remaining = Totp::SecondsRemaining(*config);
    std::cout << code << " (" << remaining << "s)\n";
}
```

`kpx otp --code` uses the same helpers.

## Incremental backups

`Database::DeltaSince()` matches entries by UUID and compares their canonical
JSON representation, so a backup tool can export only changed records:

```cpp
DatabaseDelta delta = current->DeltaSince(*previous);
if (!delta.empty()) {
    std::ofstream out("delta.json");
    out << delta.ToJson();
}
```

`added`/`modified` carry the current entry object plus its group path; deleted
entries are reported by UUID and path.

## CSV layouts

`Database::ToCsv()` supports four schemas: `kCsv` (no passwords),
`kCsvWithPasswords`, `kCsvWithCustomFields` (appends `CustomFields`) and
`kCsvKeePass2` (`Account,Login Name,Password,Web Site,Comments`).

## Lazy attachments

KDBX 4 attachments are imported as views into one shared secure buffer.
`Binary::data()` materializes a single payload on first access, while
`Binary::WriteTo()` streams it without copying during export:

```cpp
if (auto binary = entry->FindAttachment("large.bin")) {
    std::ofstream out("large.bin", std::ios::binary);
    binary->WriteTo(out);
}
```

## Streams and resource limits

`KdbxFile` exposes the import budgets from
`libkeepass/detail/limits.hh`. Tighten them for untrusted uploads:

```cpp
detail::ResourceLimits limits;
limits.max_total_bytes = 64ULL * 1024 * 1024;
limits.max_binary_bytes = 16ULL * 1024 * 1024;
limits.max_xml_depth = 32;

KdbxFile file;
file.set_resource_limits(limits);
auto db = file.Import(stream, Key("password"));
```

Violations, including gzip bombs and oversized key files, surface as
`FormatError`.

## Error handling

```cpp
try {
  KeePass kp(password);
  auto db = kp.Open(path);
} catch (const PasswordError&) {
  // wrong password / composite key
} catch (const FormatError& error) {
  // corrupt or unsupported database: error.what() has context
} catch (const IoError&) {
  // file not found, truncated stream, write failure
}
```

`what()` never contains password or key material.
