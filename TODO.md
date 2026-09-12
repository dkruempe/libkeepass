# libkeepass - Roadmap

> Priorisierte Liste (P0 höchste zuerst) für die weitere Entwicklung. Die
> erledigten Aufgaben aus der initialen TODO-Liste (Doku, CI, Versionierung,
> Packaging, Doxygen, CodeQL, ...) sind abgeschlossen und wurden entfernt.

---

## Legende

- **Feat** = Feature / Format-Kompatibilität
- **Sicherheit** = Security
- **Architektur** = Code-/API-Struktur
- **Erreichbarkeit** = Sichtbarkeit / Integration / Nutzbarkeit
- **Performance** = Leistung

---

## P0 - Sicherheit von Grund auf

Ein solides, verifizierendes und speicher-schonendes Fundament als
Voraussetzung für alle nachgelagerten Features.

### 1. HMAC-/Header-Integrität beim Import verifizieren

**Kategorie:** Sicherheit
**Aufwand:** S (Rest), Großteil erledigt
**Ziel-Version:** v0.3.0

**Status: implementiert.** Beim Import wird verifiziert, bevor entschlüsselt/
geparst wird (Encrypt-then-MAC):

- [x] Block-Checksummen KDBX 3 (`hashed_istreambuf`, `src/stream.cc`)
- [x] Block-HMACs KDBX 4 (`hmac_istreambuf`, `src/stream.cc`) - wirft bei Manipulation
- [x] Header-Hash KDBX 3 (`KdbxFile::Import3`, `src/kdbx.cc`)
- [x] Header-Hash + Header-HMAC KDBX 4 (`KdbxFile::Import4`, `src/kdbx.cc`)

Korruptions-Testfälle: in `test/robustness.cc` abgedeckt (siehe #3).

### 2. Binary-/Attachment-Payloads vollständig wipen

**Kategorie:** Sicherheit
**Aufwand:** S (Rest), Großteil erledigt
**Ziel-Version:** v0.3.0

**Status: implementiert.** `Binary` speichert seine Payloads bereits in
`protect<secure_string>` (`src/include/libkeepass/binary.hh`), also in
gewipter, best-effort gelockter Memory. Transiente Schlüssel/HMAC-Keys werden
nach letzter Nutzung gezeroist.

Verbleibende Prüfung:

- [x] Transiente Puffer im Import-/Export-Pfad auditieren (insb. `kdbx.cc`/`stream.cc`);
      Review abgeschlossen, Fixes ausgerollt: Inner-random-stream-Key KDBX-4-Import
      (exception-sicher) + Export (gewipt), entschlüsselter Klartext-Stream in
      `kdb.cc` Import/Export gewipt
- [x] Restliche Audit-Funde schließen: KDB-Entry-Felder (`consume<std::string>`,
      `.str()`-Kopien), Binary-/Base64-Temporaries in `kdbx.cc`/`kdb.cc` gewipt
      (KDBX-3-Meta-/Entry-Binaries Import+Export, KDB-Passwort/Attachment Import+Export,
      KDBX-4-Binaries bereits behandelt); `Database`-Seeds
      (`master_seed_`/`argon2_salt_`/`transform_seed_`) auf sichere Container noch offen
      (größerer Umbau, bewusst zurückgestellt)
- [x] `test/secure.cc`/KDBX-Tests um Attachment-Roundtrip inkl. Wipe-Verifikation
      erweitern (Binary-/Attachment-Suites in `test/secure.cc`, KDBX-3-Roundtrip in
      `test/kdbx.cc`; KDBX-4-Roundtrips bereits vorhanden)

### 3. Fuzzing + negative Test-Fixtures

**Kategorie:** Sicherheit
**Aufwand:** M-L
**Ziel-Version:** kontinuierlich

Für eine Parsing-Bibliothek ist dynamische Eingabe-Absicherung wichtig
(CodeQL deckt nur statisch ab):

**Status: Kern erledigt** (Commits `359e15b`, Format-/Tidy-Fixes):

- [x] `libFuzzer`-Targets für Import (`fuzz/fuzz_kdbx.cc`, `fuzz/fuzz_kdb.cc`)
- [x] CI-Workflow `.github/workflows/fuzz.yml` (zwei Jobs, Seeds aus `test/data/`, 60s Laufzeit)
- [x] Negative/"corrupted"-Tests in `test/robustness.cc` (oversized Header/Variant-Dict,
      AES-KDF-/Argon2-Caps, truncated Ciphertext; KDB/KDBX3/KDBX4)
- [x] Cap-Limits gegen CPU-Burn-/OOM-DoS (Header-Feld 1 MiB, Variant-Dict 16 MiB,
      Transform-Rounds 2^28, Argon2 1 GiB / 2^20 Iterationen), siehe
      `src/include/libkeepass/database.hh` + `src/variantdictionary.cc`
- [x] Memory-Leak-Fix im KDBX-4-Import (Ciphertext-Puffer), `src/kdbx.cc`
- [x] Block-größen-Bound in HMAC-/Hashed-Streams gegen OOM, `src/stream.cc`
- [ ] OSS-Fuzz-Integration evaluieren (offen)

---

## P1 - KDBX 4.1-Support (Format-Core)

### 4. KDBX 4.1 lesen und schreiben

**Kategorie:** Feat / Erreichbarkeit
**Aufwand:** M (L mit allen Feinschliffen)
**Ziel-Version:** v0.3.0

KeePass 2.48+ speichert bei bestimmten Features im Format 4.1 (`0x00040001`).
KDBX 4.1 ändert gegenüber 4.0 **nur das XML-Body-Schema** - Container,
Header, HMAC, Verschlüsselung und Inner-Stream (Salsa20/ChaCha20) sind
identisch. Der in der früheren Planung angenommene SHA-256-Inner-Stream
**existiert nicht** (verifiziert gegen KeePass 2.61.1:
`CryptoRandomStream.cs` unterstützt nur ArcFourVariant=1, Salsa20=2,
ChaCha20=3). Version `0x00040001` ist bereits importierbar; der Export
schreibt die Version passend zu den enthaltenen Features (wie KeePass'
`GetMinKdbxVersion`).

- [x] Group-`<Tags>` serialisieren/parsen (`Group::tags`/`set_tags`)
- [x] Entry-`<QualityCheck>` (DE) serialisieren/parsen (`Entry::quality_check`/`set_quality_check`)
- [x] `<PreviousParentGroup>` für Entries und Groups
- [x] `Name`/`LastModificationTime` für CustomIcons; Deletion-Tombstones (`<DeletedObjects>`)
- [x] `LastModificationTime` für CustomData-Items
- [x] Version `0x00040001` schreiben, wenn 4.1-Features vorhanden sind
- [x] Roundtrip-Tests für alle 4.1-Features (inkl. Version-Verifikation)
- [x] Test-Vektoren gegen echte KeePass-2.48+-Dateien: Fixtures von KeePass 2.57
      (`test/data/kdbx4/kdbx41/`, Generator `tools/kdbx41_fixturegen/`) mit neuen
      Import-Tests in `test/kdbx4.cc`. Dabei empirisch verifiziert gegen KeePass:
      `PreviousParentGroup` erzwingt **kein** 4.1 (File bleibt 4.0, Element wird
      verworfen), jedes `<CustomData>`-Item erzwingt 4.1, Entry-Tags erzwingen
      kein 4.1; Tags sind im XML `;`-getrennt (API bleibt space-getrennt,
      Konvertierung an der XML-Grenze). `RequiresKdbx41`/`GroupRequiresKdbx41`
      entsprechend an KeePass' `GetMinKdbxVersion` angeglichen.

Entscheidung zur Migrationsstrategie (getroffen): **Wie KeePass selbst wird
4.1 nur geschrieben, wenn 4.1-Features tatsächlich genutzt werden**; ohne
solche Features bleibt es bei `0x00040000`. Damit bleiben 4.0-Reader maximal
kompatibel und es gibt keine automatische Migration des Formats.

---

## P1 - CLI-Features (Erreichbarkeit)

### 5. `kpx` um Such-, Generierungs- und Editier-Befehle erweitern

**Kategorie:** Erreichbarkeit / Nutzbarkeit
**Aufwand:** M
**Ziel-Version:** v0.3.0

Das CLI ist bereits solide (Text/JSON/CSV, Export, Keyfile). Erweiterungen
mit viel Alltagsnutzen für Scripting- und CLI-Workflows:

- [ ] Suche/Filtern: `--search <query>`, `--group <name>`
- [ ] Passwort-Generator: `--generate [länge]`
- [ ] Einträge anlegen/ändern/löschen: `add`, `update`, `rm`
- [ ] Exit-Codes und strukturierte Fehlermeldungen für Scripting dokumentieren/prüfen
- [ ] Tests in `test/kpx.cc` für die neuen Optionen ergänzen

---

## P2 - Architektur

### 6. `KdbxFile` in verantwortliche Module zerlegen

**Kategorie:** Architektur
**Aufwand:** L
**Ziel-Version:** v0.3.x (Vor-/Begleitmaßnahme zu #4)

`KdbxFile` ist eine monolithische Klasse (~28 private Methoden, Binary-/Icon-/
Group-Pools, Import/Export3/4). Aufteilung in kleinere Verantwortlichkeiten
verbessert Testbarkeit und Wartbarkeit und ist Voraussetzung für einen
sauberen 4.1-Support:

- [ ] Header-Parser ausgliedern (KDBX 3 vs. 4)
- [ ] KDF-Dispatcher (AES-KDF, Argon2d/id, später BLAKE2b-Argon2)
- [ ] XML-Serializer (Meta/Gruppen/Einträge/geschützte Strings) isolieren
- [ ] Öffentliche Fläche (`libkeepass/*.hh`) stabil halten (ABI-kompatibel erweitern)

### 7. Streaming statt Voll-Import + Benchmark

**Kategorie:** Performance / Architektur
**Aufwand:** M-L
**Ziel-Version:** v0.3.x

`Open(std::istream)` lädt potenziell alles in den Speicher (XML via pugixml
in-memory). Für große Datenbanken und Netzwerk-/in-memory-I/O:

- [ ] Strom-basiertes Parsen evaluieren (pugixml ohne komplettes DOM)
- [ ] HMAC-Blöcke nicht komplett puffern
- [ ] Reproduzierbarer Benchmark (`test/benchmark.cc`) als Referenz und Anti-Regression
- [ ] Einen Load-Benchmark in CI-Schritt (wird nicht hart bewertet)

---

## P3 - Erreichbarkeit / Ökosystem

### 8. ConanCenter-Veröffentlichung

**Kategorie:** Erreichbarkeit
**Aufwand:** M
**Ziel-Version:** v0.3.0

Das CCI-Rezept liegt vorbereitet in `conan-center-index/`; die Einreichung
als PR an `conan-io/conan-center-index` fehlt noch.

- [ ] Rezept reviewen und auf den aktuellen Stand bringen
- [ ] PR an `conan-io/conan-center-index` einreichen
- [ ] `conanfile.py`/`test_package` im Repo mitführen (parallel zum CCI-Rezept)

### 9. GitHub Issue- und PR-Templates

**Kategorie:** Erreichbarkeit
**Aufwand:** S
**Ziel-Version:** v0.3.0

Strukturiertes Feedback von Nutzern und Contributors ermöglichen.

- [x] Bug-Report-Template (`.github/ISSUE_TEMPLATE/bug_report.md`)
- [x] Feature-Request-Template (`.github/ISSUE_TEMPLATE/feature_request.md`)
- [x] PR-Template (`.github/PULL_REQUEST_TEMPLATE.md`)
- [x] Issue-Templates in `CONTRIBUTING.md` erwähnen

### 10. Codecov-Account verbinden

**Kategorie:** Erreichbarkeit
**Aufwand:** S
**Ziel-Version:** v0.3.0

Coverage wird bereits via `lcov/gcov` in der CI erzeugt und hochgeladen.

- [ ] Codecov-Account anlegen und Repository verbinden
- [ ] Badge-Status im README prüfen

---

## Entscheidungen / Offene Punkte

- [x] KDBX 4.1-Migrationsstrategie (gelöst: 4.1 nur bei Bedarf schreiben, wie KeePass), siehe #4
- [ ] C++-Standard-Politik dokumentieren (aktuell C++11; bleibt das, oder 14/17 für Streams/optional?)
- [ ] Changelog-Einträge pro Roadmap-Item (Keep a Changelog + SemVer)
- [ ] Nach Umsetzung von #4: `CHANGELOG.md` und `docs/kdbx-parsing.md` aktualisieren