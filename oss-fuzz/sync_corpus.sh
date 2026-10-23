#!/bin/sh
#
# Rebuild the local OSS-Fuzz seed corpora from test/data. The output layout
# matches the *_seed_corpus directories produced by build.sh.
set -eu

out=${1:-oss-fuzz-corpus}
mkdir -p "$out/fuzz_kdbx_seed_corpus" "$out/fuzz_kdb_seed_corpus" \
  "$out/fuzz_keyfile_seed_corpus" "$out/fuzz_xml_seed_corpus" \
  "$out/fuzz_export_seed_corpus"

cp test/data/kdbx4/*.kdbx test/data/kdbx/*.kdbx test/data/compat/*.kdbx \
  "$out/fuzz_kdbx_seed_corpus/" 2>/dev/null || true
cp test/data/kdb/*.kdb "$out/fuzz_kdb_seed_corpus/" 2>/dev/null || true
cp test/data/*.key test/data/kdbx4/*.key "$out/fuzz_keyfile_seed_corpus/" 2>/dev/null || true
printf '%s' '<?xml version="1.0"?><KeePassFile><Meta><Generator>seed</Generator></Meta><Root><Group><UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID><Name>Root</Name></Group></Root></KeePassFile>' \
  > "$out/fuzz_xml_seed_corpus/seed.xml"
printf '%s' 'seed-entry' > "$out/fuzz_export_seed_corpus/seed"

echo "seed corpora written to $out"
