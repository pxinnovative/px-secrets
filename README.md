# PX Secrets

### Stop hardcoding your API keys. Stop leaking secrets to GitHub. Stop paying for a vault you don't need.

**PX Secrets** is a free, open-source secrets manager that runs entirely on your machine. Beautiful dark UI, CLI access, and a local API your AI agents can query at runtime — so your keys never touch code, `.env` files, or git history.

Encrypted with [SOPS](https://github.com/getsops/sops) + [AGE](https://github.com/FiloSottile/age) — the same encryption trusted by DevOps teams worldwide. No cloud. No subscription. No telemetry. **Your secrets stay on your machine, period.**

```bash
# Your agent fetches secrets at runtime — nothing hardcoded, nothing leaked
export OPENAI_API_KEY=$(python3 px_secrets.py --get openai api_key)
```

Perfect for developers, AI builders, homelabbers, and sysadmins who want real encryption without the complexity of HashiCorp Vault or the recurring cost of 1Password.

> If PX Secrets helps you sleep better at night, give it a star — it helps others find it and keeps us building free tools.

<!-- TODO: Add screenshot here -->
<!-- ![PX Secrets UI](screenshot.png) -->

---

## Why PX Secrets?

| | PX Secrets | 1Password / Bitwarden | HashiCorp Vault | .env files |
|---|---|---|---|---|
| **Cost** | Free forever | Subscription | Free (complex) | Free |
| **Data location** | Your machine only | Their cloud | Your server | Your machine |
| **Encryption** | SOPS + AGE (industry standard) | Proprietary | Proprietary | None |
| **Setup time** | 2 minutes | Account creation | Hours | Seconds |
| **Network required** | Never | Always | Yes (server) | No |
| **GUI** | Yes (web + native) | Yes | No | No |
| **CLI** | Yes | Yes | Yes | Manual |
| **Open source** | AGPL-3.0 | Partial | BSL | N/A |

PX Secrets fills the gap between "I keep my secrets in `.env` files" and "I need a full enterprise vault." It gives you real encryption, a clean UI, and CLI access — without any cloud dependency or complex setup.

---

## Features

- **Local encryption** — SOPS + AGE encrypt your vault on disk. Zero data leaves your machine.
- **Dark GUI** — Clean, dark-themed web UI with search, service grouping, and accordion cards.
- **CLI access** — List services, retrieve secrets by name, pipe to scripts.
- **Native window** — Optional pywebview mode for a desktop-app experience.
- **Clipboard auto-clear** — Copied secrets are wiped from clipboard after 30 seconds.
- **Notes per secret** — Attach context to any key (expiration dates, rotation info, etc.).
- **Settings UI** — Configure vault path, AGE key file, and public key from the GUI.
- **Headless mode** — Run as a background server for automation and LaunchAgents.
- **macOS native identity** — Shows as "PX Secrets" in Activity Monitor and menu bar; Dock icon hidden in headless mode.
- **Single file** — One Python file, no build step, no complex setup.
- **Privacy by design** — No telemetry, no analytics, no network calls. Ever.

## System Requirements

- **Python** 3.9+
- **macOS** or **Linux** (Windows may work but is untested)
- **SOPS** — `brew install sops` or [install from GitHub](https://github.com/getsops/sops)
- **AGE** — `brew install age` or [install from GitHub](https://github.com/FiloSottile/age)

## Quick Start

### 1. Install dependencies

```bash
# macOS (Homebrew)
brew install sops age
pip3 install flask pyyaml

# Linux
# Install sops and age from their GitHub releases, then:
pip3 install flask pyyaml
```

Or install from the repo (handles Python dependencies automatically):

```bash
git clone https://github.com/pxinnovative/px-secrets.git
cd px-secrets
pip3 install .
```

### 2. Generate an AGE key (if you don't have one)

```bash
mkdir -p ~/.config/sops/age
age-keygen -o ~/.config/sops/age/keys.txt
```

This prints your **public key** (starts with `age1...`) and saves your **private key** to the file.

> **IMPORTANT: Back up your private key NOW.** Open `~/.config/sops/age/keys.txt`, copy the entire contents, and save it in your password manager (1Password, Bitwarden, KeePass, etc.). If you lose this key, **your encrypted secrets cannot be recovered. Ever.** There is no reset, no recovery, no backdoor. The private key is the only way to decrypt your vault.

### 3. Run PX Secrets and configure

```bash
python3 px_secrets.py
```

Your browser opens automatically to `http://127.0.0.1:9999`.

**Important — first-time setup:**
1. Click **Settings**
2. Paste your AGE **public key** into the "AGE Public Key" field
3. Click **Save**

This tells SOPS which key to use for encryption. Without it, adding secrets will fail.

### 4. Add your first secret

Click **+ Add**, enter a service name (e.g., `github`), a key name (e.g., `token`), and the secret value. PX Secrets creates an encrypted vault at `~/secrets/vault.enc.yaml`.

## Deploy as a service

PX Secrets can also run headless as a long-lived background service — useful when scripts, agents, or other tools on the same host need to fetch secrets from the local API without you keeping a desktop session open.

### Run in a container

A `Dockerfile` is included in the repo. Build and run:

```bash
docker build -t px-secrets:dev .

docker run -d --name px-secrets \
  -p 127.0.0.1:9999:9999 \
  -v /path/to/your/vault.enc.yaml:/vault/vault.enc.yaml:ro \
  -v /path/to/your/age-key:/app/.config/sops/age/keys.txt:ro \
  -e PX_SECRETS_HOST=0.0.0.0 \
  -e PX_SECRETS_READ_ONLY=1 \
  px-secrets:dev
```

The image carries no secrets — your vault file and AGE key are bind-mounted at runtime. Make sure the AGE key file is mode `0400` on the host so the runtime user (uid `10001`) can read it but nothing else can.

### Environment overrides

| Variable | Purpose | Default |
|---|---|---|
| `PX_SECRETS_HOST` | Bind address. Set to `0.0.0.0` inside a container so port mapping works; leave unset on a workstation to keep the listener on localhost. | unset (binds to localhost) |
| `PX_SECRETS_READ_ONLY` | When set to `1` / `true` / `yes`, the six mutating endpoints (`POST/DELETE /api/secret`, `DELETE /api/service`, `POST /api/note`, `POST /api/settings`, `POST /api/import`) return HTTP 403. Reading endpoints continue to work. Useful for daemon mode. | unset (writes allowed) |
| `PX_SECRETS_AUTH_TOKEN` | When set, every request to `/api/*` must include `Authorization: Bearer <token>` (constant-time compared). Useful for multi-process hosts where you want a non-human caller (script, agent, sidecar) to authenticate against the API on the same loopback port. The UI prompts for the token on the first 401 and caches it in `sessionStorage` for the rest of the tab. | unset (open API on loopback) |

### When to use read-only mode

- **Long-lived daemon** serving secrets to scripts on the same host: enable `PX_SECRETS_READ_ONLY=1`. Do edits from a separate, short-lived interactive session.
- **Container behind a reverse proxy** with no UI auth: enable read-only at minimum; consider also fronting with an auth gateway since the API has no built-in authentication.
- **Interactive desktop use**: leave read-only off.

### Security reminder

The local API is **unauthenticated by default** — its security boundary is the host itself. **Never expose port `9999` outside the local host or a trusted private network without authentication.** Two options for hardening:

1. Set `PX_SECRETS_AUTH_TOKEN` (see env table above) so every `/api/*` request must carry a matching `Authorization: Bearer` header. Suitable for multi-process hosts where you trust the host but not every process on it.
2. For internet exposure, front with an authentication gateway (Authelia, oauth2-proxy) plus a TLS-terminating reverse proxy. The bearer token can stack on top so the API rejects requests even if the gateway is bypassed.

## Usage

### GUI (default)

```bash
python3 px_secrets.py              # Opens in browser
python3 px_secrets.py --native     # Opens in native window (requires pywebview)
python3 px_secrets.py --headless   # Server only, no browser
python3 px_secrets.py --port 8888  # Custom port
```

### CLI

```bash
python3 px_secrets.py --list               # List all services and keys
python3 px_secrets.py --get github token   # Print a secret value (for scripting)
```

Pipe to clipboard:
```bash
python3 px_secrets.py --get aws secret_key | pbcopy   # macOS
python3 px_secrets.py --get aws secret_key | xclip     # Linux
```

### Configuration

On first run, click **Settings** to configure:

| Setting | Default | Description |
|---------|---------|-------------|
| Vault File Path | `~/secrets/vault.enc.yaml` | Where your encrypted vault lives |
| AGE Key File | `~/.config/sops/age/keys.txt` | Your private AGE key for decryption |
| AGE Public Key | *(empty — must be set)* | Your public AGE key for encryption |

Settings are saved to `~/.px-secrets/config.json`.

## How It Works

1. You add a secret through the UI or API
2. PX Secrets writes the data to a temporary YAML file
3. SOPS encrypts the file using your AGE public key
4. The encrypted vault is saved to disk
5. The temporary file is deleted immediately

Reading secrets reverses the process — SOPS decrypts using your AGE private key, PX Secrets parses the YAML, and the decrypted data is only ever held in memory.

**Your AGE private key never leaves `~/.config/sops/age/keys.txt`.** SOPS reads it directly — PX Secrets never touches it.

## Privacy & Security

- **No network calls** — PX Secrets never contacts any server, ever
- **No telemetry** — No analytics, no usage tracking, no crash reports
- **No cloud** — Your vault is a local file, encrypted with keys you control
- **Clipboard auto-clear** — Secrets copied to clipboard are wiped after 30 seconds
- **Temp file cleanup** — Decrypted data is never written to disk permanently
- **127.0.0.1 only** — The web server binds to localhost, inaccessible from the network

## Use with AI Agents and Scripts

PX Secrets isn't just for humans — it's designed to keep your **AI agents, automation scripts, and CI/CD pipelines** safe from secret leaks.

### The problem

Every day, API keys and tokens end up exposed because developers:
- Hardcode them in scripts (`OPENAI_API_KEY = "sk-..."`)
- Store them in `.env` files that accidentally get committed to GitHub
- Pass them as environment variables that show up in logs
- Copy-paste them into AI agent configs that get shared or versioned

**One leaked key can cost thousands of dollars or compromise your entire infrastructure.**

### The solution

Run PX Secrets in headless mode and let your agents query secrets at runtime — nothing is ever written to code, `.env` files, or git history.

#### CLI — perfect for shell scripts and agents

```bash
# Your agent fetches the key at runtime — never stored in code
export OPENAI_API_KEY=$(python3 px_secrets.py --get openai api_key)

# Use in any script
curl -H "Authorization: Bearer $(python3 px_secrets.py --get github token)" \
  https://api.github.com/user
```

#### API — perfect for Python agents and automation

```python
import requests

# Your agent queries PX Secrets locally — no .env file needed
vault = requests.get("http://127.0.0.1:9999/api/vault").json()
api_key = vault["openai"]["api_key"]

# Use the key — it only exists in memory, never on disk
client = OpenAI(api_key=api_key)
```

#### Why this matters

| Without PX Secrets | With PX Secrets |
|---|---|
| `sk-abc123...` hardcoded in your script | Secret fetched at runtime, never in code |
| `.env` file with all your keys | No `.env` file needed |
| Keys in git history forever (even after deletion) | Nothing to commit — vault is separate and encrypted |
| Agent configs with plaintext tokens | Agent queries localhost API, gets key in memory only |
| One leaked `.env` = all secrets exposed | Vault is encrypted — useless without your AGE key |

> **Tip:** Run `python3 px_secrets.py --headless` as a background service. Your agents can query `http://127.0.0.1:9999/api/vault` whenever they need a secret — zero risk of leaking credentials into code or logs.

## Optional: Native Window

For a desktop-app experience without a browser tab:

```bash
pip3 install pywebview
python3 px_secrets.py --native
```

## Optional: Run at Login (macOS)

Create a LaunchAgent to start PX Secrets automatically:

```bash
cat > ~/Library/LaunchAgents/com.pxsecrets.headless.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.pxsecrets.headless</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/python3</string>
        <string>/path/to/px_secrets.py</string>
        <string>--headless</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
EOF

launchctl load ~/Library/LaunchAgents/com.pxsecrets.headless.plist
```

## Community

- Star this repo if PX Secrets is useful to you
- Join the conversation in [GitHub Discussions](../../discussions)
- Report bugs or request features in [GitHub Issues](../../issues)
- Share your experience — we want to hear how you use it
- PRs welcome — see [CONTRIBUTING.md](CONTRIBUTING.md)

We're building in public and we want your input. PX Secrets is part of [PX Open Suite](https://github.com/pxinnovative) — a collection of free, local-first tools for developers and creators.

## Roadmap

**v1.2.0 — Initial Release**
- [x] Dark GUI with search and service grouping
- [x] CLI access (`--list`, `--get`)
- [x] Headless mode for background service
- [x] Native window mode (pywebview)
- [x] Clipboard auto-clear (30s)
- [x] Notes per secret
- [x] Configurable vault path, AGE key, and port

**v1.3.0 — Generator & Import/Export**
- [x] [Built-in key & password generator](../../issues/4) — 9 categories, cryptographically secure
- [x] [Import/export secrets](../../issues/6) — .env, JSON, YAML (auto-detect)

**v1.4.0 — Installer & UI Improvements**
- [x] [One-command installer (`install.sh`)](../../issues/1)
- [x] [Settings: mask sensitive values (AGE key, key file path)](../../issues/9)
- [x] [Header icon sizing + star moved to footer](../../issues/8)

**v1.4.1 — macOS Native Identity & About Dialog**
- [x] [macOS app identity — process name, menu bar, Activity Monitor](../../issues/10)
- [x] [Dock icon hidden in headless mode](../../issues/10)
- [x] About dialog with version, runtime, and system info
- [x] Keyboard shortcuts (Cmd+K search, Escape close, Cmd+N add)

**v1.5.0 — Headless / Container deployment** *(shipped in v1.5.1 release)*
- [x] [Official Docker image with PX_SECRETS_HOST env](../../issues/14)
- [x] [Read-only mode via PX_SECRETS_READ_ONLY](../../issues/15)
- [x] [Deploy-as-a-service README section](../../issues/16)
- [x] [Refuse silent overwrite of existing secrets](../../issues/11)

**v1.5.1 — Data integrity and UI honesty**
- [x] [Case-insensitive service dedup on add/delete/note/import](../../issues/24)
- [x] Service names render with their stored casing — the UI no longer force-uppercases display, so what you see in the list matches exactly what was saved

**v1.6.0 — Foundation: self-update + API auth**
- [x] [Self-update from the GitHub Releases API](../../issues/3) — `Check for updates` button in the About dialog, single-file replacement, backup-on-rollback, process restart via LaunchAgent / systemd `KeepAlive`
- [x] [Bearer token authentication for `/api/*` via `PX_SECRETS_AUTH_TOKEN`](../../issues/17) — unblocks safe API exposure for non-human callers on multi-process hosts; UI prompts on 401 and caches the token in sessionStorage

**v1.6.1 — Auth-exempt health endpoints**
- [x] Adds `/healthz` (liveness) and `/readyz` (readiness, exercises the SOPS+AGE decrypt chain) outside the `/api/` prefix so Kubernetes / systemd probes don't 401 when `PX_SECRETS_AUTH_TOKEN` is set

**v1.6.2 — Dockerfile no longer hard-codes read-only mode**
- [x] `PX_SECRETS_READ_ONLY` removed as a Dockerfile `ENV` default — security policy is a deployment concern, not an image concern. Writable is the default; pass `-e PX_SECRETS_READ_ONLY=1` (or set in the K8s manifest) when you want a read-only sidecar. Previously the bake-in made it impossible to deploy a writable pod without an explicit override-to-empty in every manifest.

**Future**

*Data model & UX*
- [ ] [Nested secrets with multiple fields, multi-account services, ordered sequences](../../issues/18)
- [ ] [Typed secrets with filter, sort, and selective import/export per type](../../issues/20)
- [ ] [Inline edit for key_name, value, and new key_type field](../../issues/12)
- [ ] [Multiple named vaults with per-vault access control](../../issues/21)

*Security & key management*
- [ ] [AGE key custody flow at onboarding + key rotation support](../../issues/22)
- [ ] [Optional UI unlock layer (Touch ID / Face ID / password) with auto-lock on idle](../../issues/19)
- [ ] [Per-secret rotation with safety confirmation](../../issues/5)
- [ ] [2FA backup codes (TOTP recovery codes)](../../issues/13)
- [ ] [Bearer token for multi-process hosts (discussion)](../../issues/17)

*Platform & distribution*
- [ ] [Native macOS .app bundle with custom icon (Phase 2)](../../issues/10)
- [ ] [Onboarding wizard (first-run setup with key generation)](../../issues/2)
- [ ] [Self-update from GitHub](../../issues/3)
- [ ] Homebrew cask (`brew install --cask px-secrets`)

See [Issues](../../issues) for the full list.

## Support

- **Bug reports:** [GitHub Issues](../../issues)
- **Questions & ideas:** [GitHub Discussions](../../discussions)
- **Buy me a coffee:** [buymeacoffee.com/pxinnovative](https://buymeacoffee.com/pxinnovative)
- **Star the repo** — it helps more than you think

## License

[AGPL-3.0](LICENSE) — free to use, modify, and distribute. If you distribute a modified version, you must share the source.

"PX Secrets" is a trademark of PX Innovative Solutions Inc. — see [TRADEMARK.md](TRADEMARK.md).

---

Made with 🔐 by [Victor Kerber](https://github.com/pxinnovative) @ [PX Innovative Solutions Inc.](https://pxinnovative.com)
