# Hardware Tokens / YubiKey

**Entscheidung** (festgehalten am 14.09.2026): Ein Hardware-Token-Support
(YubiKey Challenge-Response, FIDO2, ...) wird **vorerst nicht implementiert**.
Die `Key`-Abstraktion bleibt bewusst offen für eine spätere Erweiterung als
weitere Sub-Key-Quelle; ein Format-seitiger Eingriff ist dafür nicht nötig.

## Ausgangslage

KeePass unterstützt Hardware-Token über Plugins, insbesondere YubiKey
Challenge-Response (HMAC-SHA1): Der Nutzer legt Anwendungsschlüssel in einer
KeePass-Ini/Plugin-Config ab, beim Öffnen schickt der Client eine
25-Byte-Challenge an den Token und verknüpft die 160-Bit-Antwort mit den
sub-keys (Passwort/Keyfile), bevor die KDF-Transformation angewendet wird.
Die Token-Konfiguration wird ausschließlich client-/plugins-seitig verwaltet;
im KDBX-Header oder in den Meta-Daten existiert dafür kein kanonischer,
übergreifend verstandener Speicherort.

Bekannte Portal-Implementierungen:

- **KeePass (Windows):** Plugins (`YubiKeyChallendgeResponse` etc.), HMAC-SHA1
  über die proprietäre (aber quelloffene) YubiKey-API/U2F-Treiber
- **KeePassXC:** Challenge-Response über die Bibliothek `libyubikey`/`yubikey`
  (via `ykpers`); Funktionalität ist an die GUI (Setup-/Slot-Umschaltung)
  gebunden, im `keepassxc-cli` nicht nutzbar
- **Strongbox (iOS/macOS):** kein YubiKey-Support

## Einordnung für libkeepass

- Als **Library** ist der passende Erweiterungspunkt die Klasse
  `keepass::Key` (`key.hh`): Sie kombiniert bereits Passwort- und
  Keyfile-Sub-Keys zu einem Composite-Key
  (`Key::SubKeyResolution::kHashSubKeys...`). Ein Hardware-Sub-Key würde an
  derselben Stelle einlaufen: der Client liefert die Token-Antwort als weitere
  20-Byte-Secret-Komponente, `Resolve()` hasht sie in den Composite-Hash ein.
- **Kein Format-Bedarf:** Der KDBX-Standard kennt keine Header-/Meta-Felder
  für Token-Slots. Das Öffnen einer mit Token geschützten Datei ist ohne
  Plugin/Token-Hardware nicht möglich — das gilt auch für KeePass selbst und
  ist keine Lücke von libkeepass.
- **CLI (`kpx`):** Kein realisierbarer Setup-Flow ohne interaktiven
  Slot-/Challenge-Austausch. Wenn später umgesetzt, wäre der erste Schritt ein
  sekundärer Sub-Key-Eingang in `Key`, dann ein `--yubikey-slot N`-Flag am CLI.

## Aufwand / Abhängigkeiten / Lizenz

- Yubico-Bibliotheken (`libyubikey`, `libykpers`, `yubikey-personalization`,
  `yubico-c`) sind in C gehalten (BSD-2-lizenziert) und auf Linux/macOS ohne
  größere Probleme als Conan-Packages abbildbar; GPL-3.0-libkeepass ist mit
  BSD-2 kompatibel. Ein neuer Conan-Peers/eingebetteter Build wäre der
  Hauptaufwand, nicht die Lizenzfrage.
- HMAC-SHA1 selbst ist in OpenSSL bereits vorhanden — eine reine
  Challenge-Response-Verarbeitung bräuchte nur die Token-Anfrage-/Antwort-
  Logik, nicht neue Krypto.
- **Entscheidung:** Aufgrund fehlender Nutzungsperspektive (CLI-basiert,
  KeepassXC-CLI ohne Support, kein Strongbox-Pendant) und des
  Plattform-Aufwands (FIDO2/normalisierte OTP-Zugänge + Treiber auf Windows)
  liegt der Aufwand nicht im Verhältnis; erneute Prüfung erst bei konkreter
  Nachfrage.