# `kpx` output schemas

`kpx` supports `--format text` (default), `json` and `csv` for the print,
`groups`, `history`, `otp` and `--audit` commands. The schemas below are
stable; new fields may be added, existing fields are not renamed without a
major release.

## Print (`kpx [options] <database>`)

### Text

```
root/
    Internet/
        - Title (username) [url]
```

`--with-passwords` adds `password:` and `notes:` lines below each entry.

### JSON

The print command emits the group tree from `Database::ToJson()`:

```json
{
  "name": "root",
  "groups": [
    {
      "name": "Internet",
      "entries": [
        {"title": "mail", "username": "alice", "url": "https://example.com"}
      ]
    }
  ]
}
```

Passwords and protected values are omitted from the print JSON. The exact
field set is defined by `Group::ToJson`/`Entry::ToJson` and covered by the
property tests.

### CSV

Header: `Group,Title,Username,Password,Url,Notes`

- `Group` is the `/`-joined path including the root group name.
- `Password` is empty unless `--with-passwords` is given.
- Fields containing `,`, `"` or a newline are quoted per RFC 4180 with doubled
  embedded quotes.

## `groups`

Text: one group path per line (for example `/root/Internet`).

JSON:

```json
[{"path": "/root/Internet", "entries": 3, "groups": 1}]
```

CSV header: `Path,Entries,Groups`

## `history`

Text: one line per entry with history, followed by its versions.

JSON:

```json
[{"path": "/root/Internet/mail", "history": [
  {"title": "mail", "username": "alice", "modification_time": "2026-01-02T03:04:05Z"}
]}]
```

CSV header: `Path,Title,Username,ModificationTime`

## `otp`

Text: `<path>: <seed> [<settings>]`. With `--code`:
`<path>: <seed> [<settings>] => <code> (<seconds>s)`.

JSON:

```json
[{"path": "/root/Internet/mail", "seed": "JBSWY3DPEHPK3PXP", "settings": "30;6",
  "code": "123456", "remaining": 17}]
```

CSV header: `Path,Seed,Settings` (without `--code`), otherwise
`Path,Seed,Settings,Code,Remaining`.

Without `--code` the command displays the stored seed and settings. With
`--code` it parses the seed/`otpauth://` URI and emits the current TOTP code
plus the seconds until it expires. Entries without a valid TOTP configuration
simply omit the `code`/`remaining` members (JSON) or leave the cells empty
(CSV).

## `--audit`

Text: one line per finding, an optional reused-password section with
`--with-passwords`, and a summary.

JSON:

```json
{
  "audited": 12,
  "issues": [
    {"group": "/root/Internet", "title": "mail", "issues": ["short", "reused"],
     "password": "..."}
  ],
  "reused": [
    {"password": "...", "entries": ["/root/Internet/mail"]}
  ]
}
```

The per-entry `password` field is present only with `--with-passwords`; the
reused-password `password` field is `null` without it.

CSV header: `Group,Title,Issues,Password` (password column only with
`--with-passwords`).

## Errors and exit codes

Errors go to stderr. With `--format json` they are machine-readable:

```json
{"error":{"category":"auth","message":"Invalid password."}}
```

Categories: `auth`, `format`, `io`, `error`.

| Exit code | Meaning |
|---|---|
| 0 | success |
| 1 | command/usage error (missing option, unknown group, nothing selected, ...) |
| 3 | wrong password or key |
| 4 | corrupt or unsupported database |
| 5 | I/O error or missing file |

## Attachments

Print JSON lists attachment names by default:

```json
"attachments": [{"name": "note.txt"}]
```

With `--include-attachments` each attachment also carries its payload as
base64:

```json
"attachments": [{"name": "note.txt", "data_base64": "aGkh"}]
```

CSV/text output does not include payloads. Library consumers can use
`Entry::attachment_names`, `Entry::FindAttachment` and
`get_binary_property`.
