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

## P1 - Format- & Feature-Ausbau (v0.4.x)

### 1. Kompatibilität mit KeePassXC / Strongbox

**Kategorie:** Feat
**Aufwand:** M
**Ziel-Version:** v0.4.x

Umgesetzt und abgeschlossen:

- [x] KeePassXC-Verifikation über reales Testkorpus (nicht generierbar: `keepassxc-cli`
      braucht GUI-Libs, daher echte Fixtures aus `keepassxreboot/keepassxc` `tests/data/`
      eingepflegt): KDBX 4.0 ChaCha20+Argon2d+gzip, KDBX 3.1 Protected-Strings,
      Recycle-Bin; neues Testbinary `libkeepass.compat` (`test/data/compat/`)
- [x] Abweichungen dokumentiert (`docs/interop.md`), inkl. Strongbox: 16-Byte-Argon2-Salz
      (fixture-seitig abgedeckt), Argon2-`K`/`A`-Parameter (werden importseitig ignoriert),
      Keyfile-Formate (XML + 64-Hex unterstützt; 32-Byte-Raw/Digest-SHA256-Fallback eine
      dokumentierte Lücke)
- [x] Von der Verifikation ausgelöster Bugfix: `RecycleBinUUID` zeigte auf eine leere
      Platzhalter-Gruppe statt auf die Gruppe mit den Einträgen (Metadata wird vor dem
      Gruppenbaum geparst; `ParseGroup` reicht das Platzhalter-Objekt nun weiter)

### 2. `kpx`: Passwort-Audit

**Kategorie:** Erreichbarkeit / Nutzbarkeit
**Aufwand:** S-M
**Ziel-Version:** v0.4.x

Auf der vorhandenen Such-/Traversal-Infrastruktur aufbauend:

- [x] `--audit`: schwache (Länge/Zeichensatz) und wiederverwendete Passwörter erkennen
- [x] Ausgabe in Text/JSON/CSV (für CI-/Scripting-Nutzung)

Umgesetzt und abgeschlossen:

- `RunAudit` klassifiziert Einträge als *empty*, *short (N)*, *single-character-class* /
  *digits-only*, *based-on-title* / *based-on-username* (>=4 Zeichen),
  *common-password* (eine Ausschlussliste der häufigsten Passwörter); Wieder-
  verwendung wird als *reused (N entries)* gemeldet
- Formate: Text, JSON, CSV; CLI `--group` begrenzt den Geltungsbereich auf den
  Untergeordneten Baum; `--with-passwords` zeigt Passwörter im Abschnitt
  *Reused passwords* (Text) und im JSON-Array der Wiederverwendung
- Tests decken alle Ausgabeformate, den Gruppenbereich, ohne-Fund und JSON
  mit/ohne Passwörter ab

---

## P2 - Erreichbarkeit / Ökosystem

### 3. Hardware-Token / YubiKey (Evaluation, langfristig)

**Kategorie:** Feat
**Aufwand:** XL
**Ziel-Version:** offen

KeePass unterstützt externe Key-Quellen (YubiKey/Challenge-Response). Für
libkeepass als Library keine unmittelbare Priorität; als Grundsatzentscheidung
dokumentieren, ob/wie das in die `Key`-Abstraktion passt.

- [x] Kein zeitlicher Horizont; Architektur-Hook in `key.hh` bewusst offen lassen
- [x] Abhängigkeits- und Lizenzaufwand evaluieren (externer Dev-Lib), Entscheidung hier festhalten

Umgesetzt und abgeschlossen:

Entscheidung: kein Hardware-Token-Support in absehbarer Zeit. Das `Key`-Modell
bleibt offen als Erweiterungspunkt (weiterer Sub-Key im Composite-Hash, analog
Password/Keyfile); ein KDBX-Format-Bedarf besteht nicht. Dokumentation inkl.
Abhängigkeiten/Lizenz (BSD-2-kompatibel) und Aufwandseinschätzung in
`docs/hardware-tokens.md`.

---

## Entscheidungen / Offene Punkte

- [x] Toleranz-Politik bei unbekannten/zukünftigen XML-Feldern und unbekannten
      KDF-/Cipher-OIDs: festgelegt und in `docs/interop.md` dokumentiert
      (integrritätsrelevant: Fehler; optional/unkritisch: ignorieren)
- [ ] OSS-Fuzz-Integration: bewertet und zurückgestellt (hermetischer
      Non-Conan-Build nötig); erneut prüfen, sobald der Conan-Build dafür
      taugt (vgl. Fuzz-Workflow in `.github/workflows/fuzz.yml`)
- [x] Entry-History: API (`save_history`/`delete_history`) vorhanden;
      CLI-/(.json?)-Sichtbarkeit **bewusst nicht** erweitert — Entscheidung:
      History vollständig roundtrip-fähig, aber nicht Teil der
      Tagesansicht/des Audits; Interessenten nutzen die öffentliche API
      direkt (siehe Docstring von `Entry::history()`)