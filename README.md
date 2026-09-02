# libkeepass

C++11 Bibliothek zum Importieren und Exportieren von [KeePass](http://keepass.info) Passwort-Datenbanken.

Dieses Projekt ist ein Fork von [libkeepass](https://github.com/nickvdyck/libkeepass) von Christian Kindahl.

## Features

- **Formate:** KDB (Legacy) und KDBX (KeePass2)
- **Cipher:** AES, Twofish, ChaCha20
- **KDFs:** AES-KDF, Argon2d, Argon2id
- **Schlüssel:** Passwort, Keyfile, Composite Keys
- **Plattformen:** Linux, macOS, Windows

## Voraussetzungen

- C++11 kompatibler Compiler (GCC 10+, Clang 12+, MSVC 19.20+)
- CMake >= 3.16
- [Conan](https://conan.io/) Packetmanager

### Abhängigkeiten (automatisch via Conan installiert)

- [OpenSSL](https://www.openssl.org/)
- [zlib](http://zlib.net)
- [pugixml](https://pugixml.org)
- [Argon2](https://github.com/P-H-C/phc-winner-argon2)
- [Google Test](https://github.com/google/googletest) (für Unit Tests)

## Build

```sh
# Dependencies installieren
conan install . --output-folder=build --build=missing

# CMake konfigurieren (Release)
cmake -B build -DCMAKE_TOOLCHAIN_FILE=build/Release/generators/conan_toolchain.cmake -DCMAKE_BUILD_TYPE=Release

# Bauen
cmake --build build --config Release
```

### Unit Tests ausführen

```sh
cd build
ctest --output-on-failure
```

## Verwendung

### KDBX (KeePass2)

```cpp
#include "libkeepass/kdbx.hh"
#include "libkeepass/key.hh"

keepass::Key key("password");
// Optional: Keyfile hinzufügen
// key.SetKeyFile("/pfad/zur/keyfile.key");

keepass::KdbxFile file;
std::unique_ptr<keepass::Database> db = file.Import("database.kdbx", key);

// Datenbank manipulieren...
auto root = db->root();
for (const auto& entry : root->Entries()) {
    std::cout << entry->title().get() << std::endl;
}

// Exportieren
file.Export("output.kdbx", *db, key);
```

### KDB (Legacy)

```cpp
#include "libkeepass/kdb.hh"
#include "libkeepass/key.hh"

keepass::Key key("password");
std::unique_ptr<keepass::Database> db = keepass::KdbFile::Import("database.kdb", key);

// Datenbank manipulieren...

keepass::KdbFile::Export("output.kdb", *db, key);
```

### Datenbank-Klasse

Die `Database`-Klasse bietet Zugriff auf:

- `root()` - Root-Gruppe der Datenbank
- `cipher()` / `set_cipher()` - Verschlüsselungsalgorithmus
- `kdf()` / `set_kdf()` - Key Derivation Function
- `compress()` / `set_compress()` - XML-Komprimierung

### Gruppen und Einträge

```cpp
auto root = db->root();

// Neue Gruppe hinzufügen
auto group = std::make_shared<keepass::Group>();
group->set_name("Meine Gruppe");
root->AddGroup(group);

// Neuen Eintrag hinzufügen
auto entry = std::make_shared<keepass::Entry>();
entry->set_title("Mein Eintrag");
entry->set_username("benutzer");
entry->set_password("geheim");
entry->set_url("https://example.com");
group->AddEntry(entry);
```

## Projektstruktur

```
libkeepass/
├── src/                    # Quellcode der Bibliothek
│   ├── include/libkeepass/ # Header-Dateien
│   ├── kdb.cc              # KDB Format Implementation
│   ├── kdbx.cc             # KDBX Format Implementation
│   ├── key.cc              # Schlüssel-Verwaltung
│   ├── cipher.cc           # Verschlüsselung
│   └── ...
├── test/                   # Unit Tests
├── sample/                 # Beispiel-Anwendung
├── cmake/                  # CMake Konfiguration
└── .github/workflows/      # CI/CD
```

## CI/CD

GitHub Actions führt automatisch Builds und Tests auf folgenden Plattformen aus:

- **Ubuntu** (GCC)
- **macOS** (Clang)
- **Windows** (MSVC)

Jede Plattform wird in Debug- und Release-Konfiguration getestet.

## Lizenz

Dieses Projekt basiert auf [libkeepass](https://github.com/nickvdyck/libkeepass) von Christian Kindahl.

Copyright (C) 2014 Christian Kindahl
Copyright (C) 2024 Dominik Krümpelmann

Lizenziert unter der [GNU General Public License v3.0](COPYING).
