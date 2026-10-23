#!/bin/bash -eu
#
# OSS-Fuzz build script for libkeepass.
#
# Copy this directory to oss-fuzz/projects/libkeepass/ (or use it as the
# project template) and let OSS-Fuzz clone the repository into
# $SRC/libkeepass.

cd "$SRC/libkeepass"

cmake -B build-oss-fuzz \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_CXX_COMPILER="$CXX" \
  -DCMAKE_C_COMPILER="$CC" \
  -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
  -DCMAKE_C_FLAGS="$CFLAGS" \
  -DBUILD_TESTING=OFF \
  -DLIBKEEPASS_BUILD_FUZZING=ON \
  -DLIBKEEPASS_BUILD_C_API=OFF

cmake --build build-oss-fuzz --target fuzz_kdbx fuzz_kdb fuzz_keyfile fuzz_xml fuzz_export -j "$(nproc)"

for target in fuzz_kdbx fuzz_kdb fuzz_keyfile fuzz_xml fuzz_export; do
  cp "bin/${target}" "${OUT}/${target}"
done

# Seed corpora: real KDB/KDBX/keyfile/XML samples plus the small XML seed.
mkdir -p "${OUT}/fuzz_kdbx_seed_corpus"
cp test/data/kdbx4/*.kdbx test/data/kdbx/*.kdbx test/data/compat/*.kdbx \
  "${OUT}/fuzz_kdbx_seed_corpus/" 2>/dev/null || true

mkdir -p "${OUT}/fuzz_kdb_seed_corpus"
cp test/data/kdb/*.kdb "${OUT}/fuzz_kdb_seed_corpus/" 2>/dev/null || true

mkdir -p "${OUT}/fuzz_keyfile_seed_corpus"
cp test/data/*.key test/data/kdbx4/*.key "${OUT}/fuzz_keyfile_seed_corpus/" 2>/dev/null || true
printf '%s' '<?xml version="1.0"?><KeyFile><Key><Data>AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=</Data></Key></KeyFile>' \
  > "${OUT}/fuzz_keyfile_seed_corpus/xml.key"
printf '%s' '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f' \
  > "${OUT}/fuzz_keyfile_seed_corpus/hex.key"

mkdir -p "${OUT}/fuzz_xml_seed_corpus"
printf '%s' '<?xml version="1.0"?><KeePassFile><Meta><Generator>oss-fuzz</Generator></Meta><Root><Group><UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID><Name>Root</Name><Entry><UUID>AQEBAQEBAQEBAQEBAQEBAQ==</UUID><String><Key>Title</Key><Value>seed</Value></String></Entry></Group></Root></KeePassFile>' \
  > "${OUT}/fuzz_xml_seed_corpus/seed.xml"

mkdir -p "${OUT}/fuzz_export_seed_corpus"
printf '%s' 'seed-entry' > "${OUT}/fuzz_export_seed_corpus/seed"
