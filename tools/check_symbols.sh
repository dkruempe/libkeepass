#!/usr/bin/env bash
#
# Checks the exported dynamic symbol surface of the shared library.
#
# A public declaration that forgets LIBKEEPASS_API is silently hidden and only
# fails for external consumers, so this gate asserts a few public anchors and
# rejects leaked internal/third-party symbols. Usage:
#
#   tools/check_symbols.sh [build-dir]
#
# Requires nm and c++filt (binutils); runs on ELF only.

set -euo pipefail

build_dir="${1:-build}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
lib=""
# Reject an explicitly selected static build early instead of silently
# validating a stale shared library from an earlier build.
if [[ -f "$build_dir/CMakeCache.txt" ]] && grep -q '^LIBKEEPASS_BUILD_SHARED:BOOL=OFF' "$build_dir/CMakeCache.txt"; then
  echo "error: $build_dir is a static build; no shared library to inspect" >&2
  exit 1
fi
# CMake writes the libraries to <repo>/bin; other generators may use
# build/bin or build/lib, so check all of them.
for candidate in "$build_dir/bin" "$build_dir/lib" "$build_dir" "$script_dir/../bin"; do
  lib="$(find "$candidate" -maxdepth 1 \
    \( -name 'libkeepass.so*' -o -name 'liblibkeepass.so*' \) 2>/dev/null | head -n 1 || true)"
  [[ -n "$lib" ]] && break
done

if [[ -z "$lib" ]]; then
  echo "error: no libkeepass shared library found below $build_dir" >&2
  exit 1
fi

symbols="$(nm -D --defined-only --extern-only "$lib" | c++filt)"

status=0

require() {
  if ! grep -qF -- "$1" <<<"$symbols"; then
    echo "error: required public symbol missing: $1" >&2
    status=1
  fi
}

forbid() {
  if grep -qE -- "$1" <<<"$symbols"; then
    echo "error: forbidden symbol exported ($1):" >&2
    grep -E -- "$1" <<<"$symbols" >&2
    status=1
  fi
}

# Public anchors: one from each major surface. The C ABI lives in a separate
# shared library and is checked below.
require "keepass::KeePass::Open(std::"
require "keepass::Database::ToJson"
require "keepass::Entry::Entry()"

# Third-party and internal implementation symbols must not leak.
forbid "(^| )pugi::"
forbid "(^| )EVP_"
forbid "(^| )argon2_"
forbid "(^| )(inflate|deflate|crc32|adler32|zlibVersion)"

# Most keepass::detail helpers are internal. BinarySource (and its buffer
# implementation) stay exported because Binary owns it via shared_ptr, so the
# virtual destructor and deleter must resolve in consumer translation units.
leaked_detail="$(awk '
  {
    # Drop "<address> <type> " so only the demangled symbol remains.
    sub(/^[0-9a-fA-F]+[[:space:]]+[A-Za-z][[:space:]]+/, "")
    # RTTI/vtable/thunk entries carry a prefix that would otherwise bypass the
    # detail:: check (e.g. "vtable for keepass::detail::FormatCodec").
    sub(/^(vtable|VTT|typeinfo name|typeinfo|construction vtable|guard variable|non-virtual thunk to|virtual thunk to) for /, "")
    if ($0 ~ /^keepass::detail::/ &&
        $0 !~ /^keepass::detail::(Buffer)?BinarySource/) print
  }
' <<<"$symbols")"

if [[ -n "$leaked_detail" ]]; then
  echo "error: internal keepass::detail symbols exported:" >&2
  echo "$leaked_detail" >&2
  status=1
fi

# The C ABI is a separate shared library; it must keep exporting its entry
# points even though the C++ library hides everything by default.
capi_lib=""
for candidate in "$build_dir/bin" "$build_dir/lib" "$build_dir" "$script_dir/../bin"; do
  capi_lib="$(find "$candidate" -maxdepth 1 -name 'liblibkeepass-c.so*' 2>/dev/null | head -n 1 || true)"
  [[ -n "$capi_lib" ]] && break
done
if [[ -z "$capi_lib" ]]; then
  echo "error: no liblibkeepass-c shared library found (disable this check with" >&2
  echo "       CHECK_SYMBOLS_ALLOW_MISSING_CAPI=1 if the C API is intentionally off)" >&2
  [[ "${CHECK_SYMBOLS_ALLOW_MISSING_CAPI:-0}" == "1" ]] || status=1
else
  capi_symbols="$(nm -D --defined-only --extern-only "$capi_lib" | c++filt)"
  for symbol in kp_keepass_open kp_last_error; do
    if ! grep -qF -- "$symbol" <<<"$capi_symbols"; then
      echo "error: required C ABI symbol missing from $capi_lib: $symbol" >&2
      status=1
    fi
  done
fi

if [[ $status -eq 0 ]]; then
  echo "OK: exported symbol surface of $lib looks correct"
fi
exit $status
