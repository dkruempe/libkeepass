# WebAssembly demo

This directory contains the client-side WASM demo. The browser sends only the
encrypted bytes and the password to the compiled module; decryption and the JSON
model stay in the tab.

## Prerequisites

- [Emscripten](https://emscripten.org/) (`emcmake`, `em++`)
- wasm32 builds of the dependencies: OpenSSL (Crypto), zlib, pugixml and Argon2

The Emscripten port manager provides zlib. OpenSSL and Argon2 are not available
as portable Emscripten ports, so a full build needs prebuilt/ported archives or
an Emscripten build of those projects. The in-tree `vcpkg` port is a useful
starting point:

```sh
vcpkg install openssl:wasm32-emscripten zlib:wasm32-emscripten \
              pugixml:wasm32-emscripten argon2:wasm32-emscripten \
              --overlay-ports=ports
emcmake cmake -S wasm -B build-wasm \
  -DCMAKE_TOOLCHAIN_FILE="$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake" \
  -DVCPKG_TARGET_TRIPLET=wasm32-emscripten \
  -DLIBKEEPASS_CONAN_CREATE=ON
cmake --build build-wasm -j
```

Serve the generated `build-wasm/web` over HTTPS or localhost:

```sh
python3 -m http.server --directory build-wasm/web 8080
```

Then open <http://localhost:8080/>.

## Scope

The demo only exposes read-only inspection (`libkeepass-c` open + JSON). Editing
and saving from the browser are intentionally out of scope; a production
integration should also add CSP, Subresource Integrity for the generated
JavaScript and a worker to keep large imports off the main thread.
