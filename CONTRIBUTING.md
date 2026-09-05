# Contributing to libkeepass

Thanks for considering contributing to libkeepass! This document describes how to build the project, the code style we follow, and what to keep in mind when opening issues or pull requests.

## Getting Started

The project is a C++ library (C++11 target, built with C++17 in CI) using [CMake](https://cmake.org/) and [Conan](https://conan.io/) for dependency management. The public API lives in `src/include/libkeepass/`.

### Prerequisites

- A C++11 compatible compiler (GCC 10+, Clang 12+, MSVC 19.20+)
- CMake >= 3.16
- Conan 2 (`pip install "conan>=2"`)

### Building and Testing

Dependencies (OpenSSL, zlib, pugixml, Argon2, Google Test) are fetched and built automatically by the Conan provider during configuration:

```sh
conan profile detect --force

# Configure (Conan dependencies are provisioned automatically)
cmake -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_STANDARD=17

# Build
cmake --build build -j $(nproc)

# Run the unit tests
ctest --test-dir build --output-on-failure
```

> **Note:** On macOS with Homebrew OpenSSL installed, a locally found `/usr/local/include` may shadow the Conan OpenSSL headers and break the `-Werror -Wold-style-cast` build. In that case configure with `-DCMAKE_OSX_SYSROOT="$(xcrun --show-sdk-path)"`.

The `kpx` command line tool is built from `cli/` and the tests from `test/`; a full build also verifies that the library links correctly in both.

### Before You Submit

1. The whole test suite must pass: `ctest --test-dir build --output-on-failure`.
2. The formatting and static analysis checks must pass locally (see below).
3. New public API must be documented (see [Documentation](#documentation)).

## Code Style

We use two tools to keep the code consistent, both enforced by the CI workflow `.github/workflows/lint.yml`:

| Tool | Config | Purpose |
|------|--------|---------|
| `clang-format` | `.clang-format` | Formatting (2-space indent, LLVM style base, 100 column limit) |
| `clang-tidy` | `.clang-tidy` | Static analysis (`bugprone-*`, `performance-*`, `modernize-*`, `readability-*`) |

### Checking Formatting

```sh
clang-format --dry-run --Werror $(git ls-files '*.cc' '*.hh')
```

To apply the formatting to changed files instead:

```sh
clang-format -i <changed files>
```

### Static Analysis

`: run-clang-tidy` needs the compile commands, so configure the build first. Use the same toolchain version as CI (see `.github/workflows/lint.yml` for the pinned versions):

```sh
cmake -B build-lint -DCMAKE_BUILD_TYPE=Debug -DCMAKE_CXX_STANDARD=17
run-clang-tidy -p build-lint -extra-arg=-Wno-unknown-warning-option src cli test
```

> The `-extra-arg` option is only needed when the compile database was
> generated for GCC (it prevents clang from erroring on GCC-only warning
> flags); clang-generated databases do not require it.

> `clang-format` and `clang-tidy` from the current LLVM releases (e.g. `22.1.8`) can be installed through Homebrew (`llvm`), a Linux package manager, or as Python packages (`pip install "clang-format==22.1.8" "clang-tidy==22.1.8"`).

### Suppressing Checks

If a check flags a place where the code is deliberately written that way, suppress it *locally* with a comment rather than disabling the check project-wide:

```cpp
cipher.Decrypt(dst_block, tst_block); // NOLINT(readability-suspicious-call-argument)
```

## Documentation

- The public API in `src/include/libkeepass/*.hh` is documented with Doxygen comments (`///` or `/** */`) and a hosted version is published to GitHub Pages on every push to `main`.
- User-facing changes go into `CHANGELOG.md` following the [Keep a Changelog](https://keepachangelog.com/) format. Add a `[Unreleased]` entry or a new section depending on where the `[Unreleased]` link of the previous section points.

## Opening an Issue

Use GitHub Issues to report bugs or request features. Before opening one, search the existing issues to avoid duplicates. When reporting a bug, include:

- The libkeepass version or commit you are using
- The `kpx` command line (or API snippet) that reproduces the problem
- The expected and the actual behaviour

## Submitting a Pull Request

1. [Fork](https://github.com/dkruempe/libkeepass/fork) the repository and create a feature branch from `master`.
2. Make focused, self-contained changes. Keep commits small with descriptive messages in the style of the existing history (e.g. `Fix off-by-one in KDBX header parsing`).
3. Run the tests and the checks described in [Before You Submit](#before-you-submit).
4. Open the pull request against `master` and summarize your changes; reference the issue it fixes, if any.
5. The CI workflows (build on Linux/macOS/Windows, lint, and docs) must pass.

## License and Legal

libkeepass is licensed under the [GNU General Public License v3](LICENSE). Your contributions are accepted under the same license. Keep the existing copyright and license headers at the top of modified files; if you add significantly new files, copy the header and adjust the copyright line accordingly.

---

Thank you for contributing! If anything in this guide is unclear, feel free to ask in your issue or pull request.