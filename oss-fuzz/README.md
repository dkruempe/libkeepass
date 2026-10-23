# OSS-Fuzz integration

The files in this directory are the project recipe for
[OSS-Fuzz](https://github.com/google/oss-fuzz). They are kept in-tree so the
build can be tested before submitting the project to the OSS-Fuzz repository.

## Submitting

1. Copy `Dockerfile`, `build.sh` and `project.yaml` to
   `oss-fuzz/projects/libkeepass/` in a fork of `google/oss-fuzz`.
2. Set a valid `primary_contact` in `project.yaml`.
3. Open a pull request against `google/oss-fuzz`; the OSS-Fuzz CI builds the
   project and starts continuous fuzzing.

The recipe builds all in-tree libFuzzer targets:

| Target | Input |
|---|---|
| `fuzz_kdbx` | whole KDBX files |
| `fuzz_kdb` | whole KDB files |
| `fuzz_keyfile` | XML/hex/raw key files from memory and streams |
| `fuzz_xml` | KDBX XML bodies |
| `fuzz_export` | arbitrary model bytes through the export/save path |

## Corpus sync

`build.sh` seeds the corpora from `test/data/` plus small synthetic inputs.
`sync_corpus.sh` is a convenient local helper that rebuilds the seed corpora
from the repository (for example before uploading regression inputs to the
OSS-Fuzz corpus bucket):

```sh
./oss-fuzz/sync_corpus.sh /tmp/libkeepass-corpus
```

Regression inputs found by fuzzing should be committed under `test/data/fuzz/`
and added to the seed-copy lists in `build.sh`.
