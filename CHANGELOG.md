# Changelog

All notable changes to PX Secrets are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/). Versions follow [Semantic Versioning](https://semver.org/).

---

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
