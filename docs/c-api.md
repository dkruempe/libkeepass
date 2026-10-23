# C ABI (`libkeepass-c`)

The C ABI is a deliberately small, stable surface for FFI and language
bindings. The header is `capi/include/libkeepass-c.h`; it is built by default
and can be disabled with `-DLIBKEEPASS_BUILD_C_API=OFF`.

## Handles

- `kp_keepass` owns the key and output-format selection.
- `kp_database` owns an imported or created `Database`.
- Both are opaque; destroy them with `kp_keepass_destroy` / `kp_database_destroy`.

## Errors

Every fallible function returns a `kp_status`:

| Status | Meaning |
|---|---|
| `KP_STATUS_OK` | success |
| `KP_STATUS_INVALID_ARGUMENT` | null/invalid argument |
| `KP_STATUS_AUTHENTICATION` | wrong password/key |
| `KP_STATUS_FORMAT` | corrupt or invalid database |
| `KP_STATUS_IO` | open/read/write failure |
| `KP_STATUS_UNSUPPORTED` | unsupported format feature |
| `KP_STATUS_RESOURCE_LIMIT` | parser/decompression budget exceeded |
| `KP_STATUS_INTERNAL` | allocation or internal error |

`kp_last_error()` returns a thread-local message; returned strings must be
released with `kp_free_string()`.

## Example

```c
kp_keepass* kp = kp_keepass_create("password", NULL);
kp_database* db = NULL;

if (kp_keepass_open(kp, "database.kdbx", &db) != KP_STATUS_OK) {
    fprintf(stderr, "%s\n", kp_last_error());
    return 1;
}

char* json = NULL;
kp_database_to_json(db, 0, &json);
puts(json);

kp_free_string(json);
kp_database_destroy(db);
kp_keepass_destroy(kp);
```

Supported operations: open from path/bytes, save, create an empty KDBX 4
database, count entries/groups, JSON/CSV output, exact-title lookup, add an
entry to a group and delete an entry by title. Editing operations mutate the
in-memory database; call `kp_keepass_save` afterwards.

## Threading

Handles are not safe for concurrent mutation. The error message is
thread-local, so separate handles can be used from separate threads. See
`docs/ownership.md` for the object-model rules.
