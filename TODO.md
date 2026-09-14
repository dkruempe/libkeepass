# libkeepass - Roadmap

> Priorisierte Liste (P0 höchste zuerst) für die weitere Entwicklung. Die alte
> Roadmap (Sicherheits-Fundament, KDBX 4.1, kpx-CLI, Architektur, Templates) ist
> vollständig umgesetzt, wurde hier entfernt und nachfolgend zusammengefasst.

---

## Stand v0.3.0

Abgeschlossene Grundlage (Details siehe `CHANGELOG.md`):

- **Sicherheit:** HMAC-/Header-Integrität beim Import verifiziert
  (Encrypt-then-MAC), Binary-/Attachment-Payloads und transiente
  Schlüssel/Klartexte gewipt, libFuzzer-Targets + Robustheits-/Negative-Tests,
  Cap-Limits gegen OOM/CPU-Burn
- **Format:** KDB, KDBX 3, KDBX 4.0 und KDBX 4.1 read/write; 4.1 gegen
  KeePass-2.57-Fixtures verifiziert, Version nur bei Bedarf geschrieben
- **CLI (`kpx`):** Text/JSON/CSV, Export, Keyfiles, `--search`/`--group`,
  `--generate`, `add`/`update`/`rm`, dokumentierte Exit-Codes
- **Architektur:** `KdbxFile` in `KdbxHeader`/`KdbxKdf`/`KdbxXml` zerlegt,
  gestreamte KDBX-4-Entschlüsselung, Load-Benchmark in der CI
- **Ökosystem:** CI auf Linux/macOS/Windows, CodeQL, Doxygen/GitHub Pages,
  Issue-/PR-Templates

Der Fokus verschiebt sich von "mehr Features" auf **Release-Reife und
Ökosystem-Integration** (v0.4.0) sowie gezielte Formatausbauten.

---

## Legende

- **Feat** = Feature / Format-Kompatibilität
- **Sicherheit** = Security
- **Architektur** = Code-/API-Struktur
- **Erreichbarkeit** = Sichtbarkeit / Integration / Nutzbarkeit
- **Performance** = Leistung

---

## P0 - Release-Reife (v0.4.0)

### 1. ConanCenter-Veröffentlichung

**Kategorie:** Erreichbarkeit
**Aufwand:** M
**Ziel-Version:** v0.4.0

Das CCI-Rezept wurde auf v0.3.0 angehoben und auf die CCI-v2-Konventionen
angeglichen (Branch `feature/conan-center`). Die Einreichung steht aus.

- [ ] Rezept final reviewen (Varianten static/shared, `test_package`, Header-Pfade)
- [ ] PR an `conan-io/conan-center-index` einreichen
- [ ] `conanfile.py`/`test_package` im Repo mitführen und bei Releases abgleichen

### 2. C++-Standard-Politik festlegen und dokumentieren

**Kategorie:** Architektur
**Aufwand:** S-M
**Ziel-Version:** v0.4.0

Offene Grundsatzfrage: aktuell C++11. Entscheidung treffen (11 belassen vs.
14/17 für `std::optional`, bessere Stream-/String-Handling) und in
`CONTRIBUTING.md`/`docs/` dokumentieren.

- [ ] Pro/Contra bewerten (ABI-/Compiler-Basis, Conan 2-Keinstellung, STL-Unterbau)
- [ ] Entscheidung dokumentieren; bei Wechsel: Migration planen und im Changelog als Breaking kennzeichnen

### 3. Doku & Changelog für v0.3.0 abschließen

**Kategorie:** Erreichbarkeit
**Aufwand:** S
**Ziel-Version:** v0.4.0

- [x] `docs/kdbx-parsing.md` an die modulare Architektur angepasst
      (Branch `docs/kdbx-parsing`, Mergen nach Review)
- [ ] Changelog-Einträge je Roadmap-Item prüfen (Keep a Changelog + SemVer),
      v0.3.0-Releasenotes aus `[Unreleased]` ziehen und v0.3.0 taggen

---

## P1 - Sicherheit & Architektur (v0.4.x)

### 4. `Database`-Seeds auf sichere Container umstellen

**Kategorie:** Sicherheit
**Aufwand:** M-L
**Ziel-Version:** v0.4.x

Bewusst zurückgestellter Restposten aus der RAM-Wiping-Aktion (v0.3.0):
`master_seed_`/`argon2_salt_` (beide `std::vector<uint8_t>`) und
`transform_seed_` (`std::array<uint8_t,32>`) liegen weiter auf ungeschütztem
Speicher (`TestData`-seitig auch auf der wipbaren Fläche). Kandidaten für
KDF-Salts/Seeds, Wiping nach Release wünschenswert.

- [ ] Seeds in `protect<SecureBuffer>` o.ä. überführen, Getter-Semantik klären
      (vgl. `Database::set_master_seed` etc. in `src/include/libkeepass/database.hh`)
- [ ] ABI-/API-Verträglichkeit der öffentlichen Setter/Getter beachten
- [ ] Wipe-Verifikation in `test/secure.cc` ergänzen

### 5. BLAKE2b-Argon2-KDF evaluieren

**Kategorie:** Feat / Sicherheit
**Aufwand:** M (nach Evaluation)
**Ziel-Version:** v0.4.x

Im KDF-Dispatcher (`KdbxKdf`, `src/include/libkeepass/kdbx_kdf.hh`) für "später"
vorgemerkt. KeePass-Quellcode interpretert BLAKE2 in der Referenzumsatz;
Verfügbarkeit/Bedeutung erst gegen KeePass 2.6x empirisch verifizieren
(wie bei CryptoRandomStream/`GetMinKdbxVersion`), bevor implementiert wird.

- [ ] Referenzverhalten gegen KeePass prüfen (tatsächlich genutzte KDF-OIDs?)
- [ ] Bei Bestätigung: Argon2-Variante mit BLAKE2b im Random-Obfuscator/Im- und Export testen
- [ ] Fixtures + Roundtrip-Tests in `test/kdbx4.cc`

---

## P1 - Format- & Feature-Ausbau (v0.4.x)

### 6. Kompatibilität mit KeePassXC / Strongbox verifizieren

**Kategorie:** Feat
**Aufwand:** M
**Ziel-Version:** v0.4.x

Bisherige Format-Verifikation basiert auf KeePass-Referenzdaten. Für breite
Einsetzbarkeit die beiden anderen großen Ökosysteme abprüfen.

- [ ] KeePassXC-Fixtures erzeugen (KDBX 4.1, Argon2-Parameter-Randfälle, Keyfiles, Recycle-Bin)
- [ ] Strongbox-/Mobile-Fixtures prüfen (abweichende Feld-Behandlung/Fehlerfälle)
- [ ] Abweichungen dokumentieren und ggf. Toleranz-Politik (s. Entscheidungen) schärfen

### 7. `kpx`: Passwort-Audit

**Kategorie:** Erreichbarkeit / Nutzbarkeit
**Aufwand:** S-M
**Ziel-Version:** v0.4.x

Auf der vorhandenen Such-/Traversal-Infrastruktur aufbauend:

- [ ] `--audit`: schwache (Länge/Zeichensatz) und wiederverwendete Passwörter erkennen
- [ ] Ausgabe in Text/JSON/CSV (für CI-/Scripting-Nutzung)

---

## P2 - Erreichbarkeit / Ökosystem

### 8. Hardware-Token / YubiKey (Evaluation, langfristig)

**Kategorie:** Feat
**Aufwand:** XL
**Ziel-Version:** offen

KeePass unterstützt externe Key-Quellen (YubiKey/Challenge-Response). Für
libkeepass als Library keine unmittelbare Priorität; als Grundsatzentscheidung
dokumentieren, ob/wie das in die `Key`-Abstraktion passt.

- [ ] Kein zeitlicher Horizont; Architektur-Hook in `key.hh` bewusst offen lassen
- [ ] Abhängigkeits- und Lizenzaufwand evaluieren (externer Dev-Lib), Entscheidung hier festhalten

---

## Entscheidungen / Offene Punkte

- [ ] C++-Standard-Politik (11 belassen vs. 14/17), siehe #2
- [ ] Toleranz-Politik bei unbekannten/zukünftigen XML-Feldern und unbekannten
      KDF-/Cipher-OIDs: Fehler vs. ignorieren (relevant für #6)
- [ ] OSS-Fuzz-Integration: bewertet und zurückgestellt (hermetischer
      Non-Conan-Build nötig); erneut prüfen, sobald der Conan-Build dafür
      taugt (vgl. Fuzz-Workflow in `.github/workflows/fuzz.yml`)
- [ ] Entry-History: API (`save_history`/`delete_history`) vorhanden, CLI-/(.json?)-
      Sichtbarkeit bewusst noch nicht erweitert