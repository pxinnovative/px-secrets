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

**Next**
- [ ] [One-command installer (`install.sh`)](../../issues/1)
- [ ] [Onboarding wizard (first-run setup with key generation)](../../issues/2)
- [ ] [Self-update from GitHub](../../issues/3)
- [ ] [Per-secret rotation with safety confirmation](../../issues/5)

**Future**
- [ ] About dialog with version info
- [ ] Key rotation support
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
