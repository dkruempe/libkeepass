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
  Issue-/PR-Templates; ConanCenter-Rezept auf CCI-v2-Konventionen gehoben und
  als PR eingereicht
  ([conan-io/conan-center-index#30962](https://github.com/conan-io/conan-center-index/pull/30962)),
  `conanfile.py`/`test_package` lokal via `conan create` verifiziert

Der Fokus verschiebt sich von "mehr Features" auf **Release-Reife und
Ökosystem-Integration** sowie gezielte Formatausbauten. Die P0-Items der
v0.4.0-Release-Reife (C++17-Standard-Politik, CHANGELOG-/Doku-Abschluss) sind
umgesetzt (vergl. letzte Merge-Reihenfolge) und wurden aus dieser Liste
entfernt.

---

## Legende

- **Feat** = Feature / Format-Kompatibilität
- **Sicherheit** = Security
- **Architektur** = Code-/API-Struktur
- **Erreichbarkeit** = Sichtbarkeit / Integration / Nutzbarkeit
- **Performance** = Leistung

---

## P1 - Sicherheit & Architektur (v0.4.x)

### 1. BLAKE2b-Argon2-KDF evaluieren

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

### 2. Kompatibilität mit KeePassXC / Strongbox verifizieren

**Kategorie:** Feat
**Aufwand:** M
**Ziel-Version:** v0.4.x

Bisherige Format-Verifikation basiert auf KeePass-Referenzdaten. Für breite
Einsetzbarkeit die beiden anderen großen Ökosysteme abprüfen.

- [ ] KeePassXC-Fixtures erzeugen (KDBX 4.1, Argon2-Parameter-Randfälle, Keyfiles, Recycle-Bin)
- [ ] Strongbox-/Mobile-Fixtures prüfen (abweichende Feld-Behandlung/Fehlerfälle)
- [ ] Abweichungen dokumentieren und ggf. Toleranz-Politik (s. Entscheidungen) schärfen

### 3. `kpx`: Passwort-Audit

**Kategorie:** Erreichbarkeit / Nutzbarkeit
**Aufwand:** S-M
**Ziel-Version:** v0.4.x

Auf der vorhandenen Such-/Traversal-Infrastruktur aufbauend:

- [ ] `--audit`: schwache (Länge/Zeichensatz) und wiederverwendete Passwörter erkennen
- [ ] Ausgabe in Text/JSON/CSV (für CI-/Scripting-Nutzung)

---

## P2 - Erreichbarkeit / Ökosystem

### 4. Hardware-Token / YubiKey (Evaluation, langfristig)

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

- [ ] Toleranz-Politik bei unbekannten/zukünftigen XML-Feldern und unbekannten
      KDF-/Cipher-OIDs: Fehler vs. ignorieren (relevant für #2)
- [ ] OSS-Fuzz-Integration: bewertet und zurückgestellt (hermetischer
      Non-Conan-Build nötig); erneut prüfen, sobald der Conan-Build dafür
      taugt (vgl. Fuzz-Workflow in `.github/workflows/fuzz.yml`)
- [ ] Entry-History: API (`save_history`/`delete_history`) vorhanden, CLI-/(.json?)-
      Sichtbarkeit bewusst noch nicht erweitert