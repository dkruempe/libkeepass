# Hardware Tokens / YubiKey

**Decision** (recorded on 2026-09-14): Hardware-token support (YubiKey
challenge-response, FIDO2, ...) will **not be implemented for the time being**.
The `Key` abstraction intentionally stays open for a later extension as an
additional sub-key source; no format-level work is required for that.

## Background

KeePass supports hardware tokens through plugins, in particular YubiKey
challenge-response (HMAC-SHA1): the user stores application secrets in a
KeePass ini/plugin configuration; on open the client sends a 25-byte challenge
to the token and combines the 160-bit response with the sub keys
(password/keyfile) before applying the KDF transformation. The token
configuration is managed exclusively client-/plugin-side; the KDBX header and
metadata do not contain a canonical location for it that other tools
understand.

Known reference implementations:

- **KeePass (Windows):** plugins (e.g. `YubiKeyChallengeResponse`), HMAC-SHA1
  through the proprietary (but open source) YubiKey API / U2F drivers
- **KeePassXC:** challenge-response via `libyubikey`/`yubikey` (through
  `ykpers`); the functionality is tied to the GUI (setup/slot switching) and is
  not usable from `keepassxc-cli`
- **Strongbox (iOS/macOS):** no YubiKey support

## Placement in libkeepass

- As a **library**, the natural extension point is the `keepass::Key` class
  (`key.hh`): it already combines password and keyfile sub keys into a
  composite key (`Key::SubKeyResolution::kHashSubKeys...`). A hardware sub key
  would enter at the same place: the client supplies the token response as an
  additional 20-byte secret component, and `Resolve()` hashes it into the
  composite hash.
- **No format work needed:** the KDBX standard has no header/meta fields for
  token slots. Opening a token-protected file is impossible without the
  plugin/token hardware — this also holds for KeePass itself and is not a
  gap in libkeepass.
- **CLI (`kpx`):** no viable setup flow without interactive
  slot/challenge exchange. If implemented later, the first step would be a
  secondary sub-key input in `Key`, then a `--yubikey-slot N` flag on the CLI.

## Effort / Dependencies / Licensing

- The Yubico libraries (`libyubikey`, `libykpers`,
  `yubikey-personalization`, `yubico-c`) are C (BSD-2 licensed) and can be
  integrated on Linux/macOS as Conan packages without major issues;
  GPL-3.0 libkeepass is compatible with BSD-2. A new Conan peer/embedded build
  would be the main effort, not the licensing question.
- HMAC-SHA1 itself is already available in OpenSSL — pure
  challenge-response processing would only need the token request/response
  logic, not new crypto.
- **Decision:** because of the missing usage perspective (CLI-based; the
  KeePassXC CLI has no support; no Strongbox counterpart) and the platform
  effort (FIDO2/normalized OTP access plus drivers on Windows), the costs do
  not justify the benefit; re-evaluate only when there is concrete demand.