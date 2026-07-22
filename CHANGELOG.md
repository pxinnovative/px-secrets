# Changelog

All notable changes to PX Secrets are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/). Versions follow [Semantic Versioning](https://semver.org/).

---

## [1.8.0] — 2026-07-22

### Added
- **Biometric unlock** — unlock with Touch ID, Face ID or Windows Hello instead of re-typing the master password at every idle timeout. This is the follow-up promised in [#19](../../issues/19). Built on WebAuthn platform authenticators: the private key never leaves the device's secure enclave, and `userVerification` is **required** both in the request options and re-checked server-side in the authenticator-data flags, so a mere presence tap cannot substitute for a biometric. Enrolment requires an already-unlocked session, which prevents someone at your keyboard from enrolling their own finger while you are away. The master password always remains available as the recovery path, so a lost or reset device can never lock you out. Enable in **Settings → Biometric Unlock**.
  - **No new dependencies.** Attestation objects are never parsed: the browser's `getPublicKey()` returns the key as SPKI DER, which `cryptography` consumes directly. That removes a CBOR dependency and an entire class of parsing bugs. Attestation is deliberately not verified — this authenticates "the same authenticator that enrolled" on a local single-user app; it is not enterprise device-provenance.
  - Credential metadata lives in `~/.px-secrets/webauthn.json` (mode 0600). Only credential IDs and **public** keys are stored.

### Fixed
- **Vault switcher was invisible whenever the app lock was enabled** — `initApp()` returns early while locked, and the unlock path called `loadVault()` (contents) but never `loadVaults()` (the switcher list). The `<select>` therefore stayed `display:none` forever: you could create vaults but never see or switch between them. Both unlock paths now populate it. ([#21](../../issues/21))
- **`loadVaults()` swallowed every error in an empty `catch`** — a failed vault list looked identical to "this feature does not exist", which is exactly what hid the bug above. Failures now log to the console and surface a toast.

### Changed
- **Responsive toolbar** — the toolbar was a single non-wrapping flex row, so adding the vault switcher pushed **Export** outside the viewport with no way to scroll to it. It now wraps; the search field takes its own full-width row below 760px; buttons and the vault selector shrink at narrow widths; long vault names ellipsize instead of dictating row width; and the search placeholder shortens on small screens. These are the first media queries in the project.

## [1.7.0] — 2026-06-08

### Added
- **Inline edit** — every secret now has an **Edit** button to change its value (and note) in place, instead of delete-then-re-add. Service and key are locked during edit; the write only sends `overwrite=true` in this explicit flow, so an accidental Add over an existing key stays protected. ([#12](../../issues/12))
- **App lock** — optional master-password lock screen with idle auto-lock. Protects the vault against a human at the keyboard with the app already running (lent laptop, unattended desk) — a layer neither the AGE key nor the bearer token covers. Off by default; enable in **Settings → App Lock**. The master password is scrypt-hashed in `~/.px-secrets/lock.json` (mode 0600); sessions are in-memory with a sliding idle timeout (default 5 min). Machine callers with a valid bearer token bypass the UI lock. Password method ships now; biometric (Touch ID / WebAuthn) is a planned follow-up. ([#19](../../issues/19))

### Fixed
- **Vault writes failed under a path-scoped `.sops.yaml`** — `encrypt_vault` wrote its plaintext temp file to the system temp dir, which matched no `creation_rules` `path_regex`, so `sops encrypt` failed with *"no matching creation rules found"* and the UI could not save any secret. The temp file is now created next to the vault (mode 0600) so it inherits the vault's own SOPS rule and re-encrypts to the configured recipients.

## [1.4.1] — 2026-04-05

### Added
- **macOS app identity** — process shows as "PX Secrets" in Activity Monitor and menu bar instead of "Python" ([#10](../../issues/10) Phase 1)
- **Dock icon hidden in headless mode** — background server no longer shows Python rocket icon in macOS Dock ([#10](../../issues/10) Phase 1)

### Technical
- Uses PyObjC (`NSProcessInfo`, `NSBundle`, `NSApplication`) — ships with macOS system Python, no extra install
- Gracefully skips on Linux or if PyObjC is unavailable

---

## [1.4.0] — 2026-04-04

### Added
- **One-command installer** (`install.sh`) — interactive 7-step setup for macOS/Linux with dependency checks, AGE key generation, and automatic install ([#1](../../issues/1))
- **Masked sensitive values in Settings** — AGE Public Key and Key File path are hidden by default with Copy and Show/Hide toggle buttons ([#9](../../issues/9))

### Changed
- **Header icons** — gear icon sized consistently at 16px, star moved from header to footer alongside "Free & open source" attribution ([#8](../../issues/8))
- Footer now uses `REPO_URL` constant instead of hardcoded GitHub URL

---

## [1.3.0] — 2026-03-29

### Added
- **Built-in key & password generator** — 9 categories (API key, UUID, hex, base64, passphrase, PIN, alphanumeric, URL-safe, custom), cryptographically secure using Python `secrets` module ([#4](../../issues/4))
- **Import/export secrets** — supports `.env`, JSON, and YAML formats with auto-detection ([#6](../../issues/6))

### Changed
- Toolbar redesigned — Settings, Browser, and Star moved to header icon row
- Community section, author credit, and footer updated to match PX Dictate style

---

## [1.2.0] — 2026-03-21

### Added
- Dark-themed web GUI with search and accordion service cards
- CLI access (`--list`, `--get`) for scripting and automation
- Headless mode (`--headless`) for background service operation
- Native window mode (`--native`) via pywebview
- Clipboard auto-clear after 30 seconds
- Notes per secret (expiration dates, rotation info, etc.)
- Configurable vault path, AGE key file, and port via Settings UI
- SOPS + AGE encryption — industry-standard, fully local
- Privacy by design — no telemetry, no network calls, no cloud
- Code of Conduct, Contributing guide, Security policy, and Trademark notice

---

[1.4.1]: https://github.com/pxinnovative/px-secrets/compare/v1.4.0...v1.4.1
[1.4.0]: https://github.com/pxinnovative/px-secrets/releases/tag/v1.4.0
[1.3.0]: https://github.com/pxinnovative/px-secrets/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/pxinnovative/px-secrets/releases/tag/v1.2.0
