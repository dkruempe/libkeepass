# Migrating from 0.2 to 0.3

libkeepass 0.3.0 is a source-compatible update for most users but contains a
few deliberate breaking changes, mostly around secret handling and the minimum
language standard. This guide lists the changes and the smallest migration for
each.

## Language standard: C++11 → C++17

The library now requires C++17 (`target_compile_features(... cxx_std_17)` and
`check_min_cppstd` in the Conan recipes). Consumers using CMake get the
requirement through the imported target; other build systems must compile with
`-std=c++17` (or `/std:c++17`).

## `protect<secure_string>` replaces `protect<std::string>`

Entry string fields and KDBX protected values are stored in
`keepass::protect<keepass::secure_string>` instead of plain strings. This
prevents the value from ever living in an unprotected `std::string` inside the
object model.

Before (0.2):

```cpp
entry->set_password(keepass::protect<std::string>("secret", true));
std::string password = *entry->password();
```

After (0.3):

```cpp
using keepass::protect;
using keepass::secure_string;

entry->set_password(protect<secure_string>(secure_string("secret"), true));
std::string password = entry->password()->str(); // explicit copy
```

The `protect` wrapper's `operator*`/`operator->` still gives access to the
`secure_string`; use `.str()` only at the boundary where a plain string is
unavoidable. `secure_string` has no implicit conversion to `std::string` so
copies are visible in code review.

## Optional KDBX 4.1 fields

Absent XML elements used to map to sentinel values; they now map to
`std::optional`:

| Member | New type |
|---|---|
| `Icon::last_modification_time` | `std::optional<std::time_t>` |
| `Metadata::Field::last_modification_time` | `std::optional<std::time_t>` |
| `Entry::previous_parent_group` | `std::optional<std::array<uint8_t, 16>>` |
| `Group::previous_parent_group` | `std::optional<std::array<uint8_t, 16>>` |

Use `.has_value()`/`.value_or()` instead of comparing against zero.

## Seed material moved into secure containers

`Database::master_seed` and `Database::argon2_salt` now return
`const SecureBytes&`; `Database::transform_seed` returns
`const SecureBuffer<32>&`. `SecureBytes`/`SecureBuffer` are move-only and wipe
their contents on destruction. Code that copied the returned values must use
`.Clone()` or the explicit setter overloads:

```cpp
keepass::SecureBytes copy = db.master_seed().Clone();
db.set_master_seed(std::move(copy));
```

`Key::Transform` and `Key::TransformArgon2` accept these containers directly.

## Cipher constructors

`AesCipher`, `TwofishCipher`, `Salsa20Cipher` and `ChaCha20Cipher` take the raw
key as `const uint8_t*` (null-safe) rather than a `std::string`/vector, and wipe
their key state on destruction. Pass `key.data()` and ensure the source buffer
outlives the constructor call.

## Save/SaveAs and cached keys

A database imported with `KeePass::Open` carries the derived transformed key in
wiped memory. `SaveAs(path, db, new_key)` now always uses the supplied key
instead of silently reusing that cache. This fixes password changes for
imported databases. `KeePass::Create(password, ...)` caches the derived key so
a keyless `Save` works for the returned database (KDB output still needs an
explicit key).

## CLI changes

- `kpx` version output is derived from `PROJECT_VERSION`; the hard-coded `0.2.0`
  string is gone.
- `KeePass::Save` accepts streams, so `kpx` and embedders no longer need a
  temporary file to re-encrypt.
- New safe password sources: `--password-file`, `--password-stdin`, plus
  `--new-password*` for `passwd`.
- New commands: `create`, `groups`, `passwd`, `move`.

## New resource limits

Hostile KDB/KDBX inputs are rejected earlier. If you import intentionally huge
databases, the limits in `libkeepass/detail/limits.hh` are configurable through
`KdbxFile::set_resource_limits`. Defaults allow normal KeePass files while
bounding decompression, block counts, XML depth and binary sizes.
