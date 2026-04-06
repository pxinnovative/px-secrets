# Changelog

All notable changes to PX Secrets are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/). Versions follow [Semantic Versioning](https://semver.org/).

---

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
