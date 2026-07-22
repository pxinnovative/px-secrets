#!/usr/bin/env python3
"""
PX Secrets — SOPS + AGE Vault Manager

A single-file Flask app with embedded HTML/CSS/JS for managing
encrypted secrets locally. No cloud, no telemetry, no network calls.
All encryption handled by SOPS + AGE on your machine.
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import webbrowser

import base64
import secrets
import string
import uuid

import yaml
from flask import Flask, jsonify, make_response, request

import px_vaults  # multi-vault layer (Issue #21)
import px_webauthn  # biometric unlock (Touch ID / Face ID / Windows Hello)

# ---------------------------------------------------------------------------
# macOS App Identity (Phase 1 of Issue #10)
# ---------------------------------------------------------------------------


def _configure_macos_identity(headless=False):
    """Set proper app name and optionally hide Dock icon on macOS.

    Uses PyObjC (ships with macOS system Python) to:
    - Set the process name to APP_NAME in Activity Monitor
    - Hide the Dock icon when running in headless/server mode

    Silently skips on Linux or if PyObjC is unavailable.
    """
    if sys.platform != "darwin":
        return

    try:
        from Foundation import NSBundle, NSProcessInfo  # type: ignore
        from AppKit import NSApplication, NSApplicationActivationPolicyProhibited, NSApplicationActivationPolicyRegular  # type: ignore  # noqa: E501

        # Set process name for Activity Monitor / ps output
        NSProcessInfo.processInfo().setProcessName_(APP_NAME)

        # Override the bundle name so macOS menu bar shows "PX Secrets"
        # instead of "Python". This works by patching the main bundle's
        # Info.plist in memory — does not modify any files on disk.
        bundle = NSBundle.mainBundle()
        info = bundle.localizedInfoDictionary() or bundle.infoDictionary()
        if info is not None:
            info["CFBundleName"] = APP_NAME
            info["CFBundleDisplayName"] = APP_NAME

        if headless:
            # Hide Dock icon — headless mode should be invisible
            ns_app = NSApplication.sharedApplication()
            ns_app.setActivationPolicy_(NSApplicationActivationPolicyProhibited)
        else:
            # Ensure Dock icon is visible in GUI modes
            ns_app = NSApplication.sharedApplication()
            ns_app.setActivationPolicy_(NSApplicationActivationPolicyRegular)

    except ImportError:
        # PyObjC not available — skip silently
        pass
    except Exception:
        # Don't let app identity setup crash the actual server
        pass

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

APP_NAME = "PX Secrets"
VERSION = "1.8.2"
REPO_URL = "https://github.com/pxinnovative/px-secrets"
SUPPORT_URL = "https://buymeacoffee.com/pxinnovative"
GITHUB_API_BASE = "https://api.github.com/repos/pxinnovative/px-secrets"
GITHUB_RAW_BASE = "https://raw.githubusercontent.com/pxinnovative/px-secrets"

# Network
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 9999

# Environment overrides for container deployment.
# Set PX_SECRETS_HOST=0.0.0.0 to bind all interfaces (e.g. for container port mapping).
# Set PX_SECRETS_READ_ONLY=1 to disable mutating endpoints (vault read-only mode).
# Set PX_SECRETS_AUTH_TOKEN=<token> to require Authorization: Bearer <token> on /api/*.
HOST_OVERRIDE = os.environ.get("PX_SECRETS_HOST")
LOOPBACK_BROWSE_HOST = "localhost"


def browse_host(bind_host):
    """Hostname to put in the URL we open, given the address we bound to.

    We bind to a loopback IP by default, but a page served from http://127.0.0.1
    cannot use WebAuthn at all: an RP ID must be a valid *domain*, and an IP literal
    is not one. Registration fails with "SecurityError: The effective domain of the
    document is not a valid domain". `localhost` is the one non-registrable name the
    spec allows, and it resolves to the same socket, so browsing there costs nothing
    and makes biometric unlock work.

    Only loopback (and 0.0.0.0, which includes loopback) is rewritten. If someone
    bound to a specific LAN address on purpose, we must open THAT address or the
    window would point at a socket the server is not listening on.
    """
    if not bind_host or bind_host in ("0.0.0.0", "::", "::1") or bind_host.startswith("127."):
        return LOOPBACK_BROWSE_HOST
    return bind_host


READ_ONLY = os.environ.get("PX_SECRETS_READ_ONLY", "").lower() in ("1", "true", "yes")
AUTH_TOKEN = os.environ.get("PX_SECRETS_AUTH_TOKEN", "")

# Native window dimensions (pywebview)
NATIVE_WINDOW_WIDTH = 750
NATIVE_WINDOW_HEIGHT = 850

# Clipboard auto-clear delay in milliseconds
CLIPBOARD_CLEAR_MS = 30000

# Toast notification duration in milliseconds
TOAST_DURATION_MS = 3000

# Delay before opening browser after server starts (seconds)
BROWSER_OPEN_DELAY = 1.0

# ---------------------------------------------------------------------------
# Configuration — user-specific paths stored in ~/.px-secrets/config.json
# ---------------------------------------------------------------------------

CONFIG_DIR = os.path.expanduser("~/.px-secrets")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")

DEFAULTS = {
    "vault_path": os.path.expanduser("~/secrets/vault.enc.yaml"),
    "age_key_file": os.path.expanduser("~/.config/sops/age/keys.txt"),
    "age_public_key": "",
}

VAULT_PATH = DEFAULTS["vault_path"]
AGE_KEY_FILE = DEFAULTS["age_key_file"]
AGE_PUBLIC_KEY = DEFAULTS["age_public_key"]


def load_config():
    """Load user configuration from disk, falling back to defaults."""
    global VAULT_PATH, AGE_KEY_FILE, AGE_PUBLIC_KEY
    cfg = dict(DEFAULTS)
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                cfg.update(json.load(f))
        except Exception:
            pass
    VAULT_PATH = os.path.expanduser(cfg.get("vault_path", DEFAULTS["vault_path"]))
    AGE_KEY_FILE = os.path.expanduser(cfg.get("age_key_file", DEFAULTS["age_key_file"]))
    AGE_PUBLIC_KEY = cfg.get("age_public_key", DEFAULTS["age_public_key"])


def save_config(cfg: dict):
    """Persist user configuration to disk."""
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)


load_config()

# Multi-vault (Issue #21): on first run, seed a "Default" vault from the legacy single file (by COPY;
# the original is left intact). No-op once any vault exists or if no recipient is configured.
if AGE_PUBLIC_KEY:
    try:
        px_vaults.migrate_legacy(VAULT_PATH, [AGE_PUBLIC_KEY])
    except Exception:
        pass

# ---------------------------------------------------------------------------
# SOPS helpers
# ---------------------------------------------------------------------------


def _active_vault_id():
    """Resolve which vault the current request targets: the `X-Vault` header or `?vault=` param,
    else the default. Returns None when no vaults exist yet (legacy single-file mode)."""
    from flask import has_request_context
    vaults = px_vaults.list_vaults()
    if not vaults:
        return None
    ids = {v["id"] for v in vaults}
    if has_request_context():
        sel = request.headers.get("X-Vault") or request.args.get("vault")
        if sel and sel in ids:
            return sel
    return "default" if "default" in ids else vaults[0]["id"]


def decrypt_vault() -> dict:
    """Decrypt the active vault (multi-vault) or the legacy single file, return its contents."""
    vid = _active_vault_id()
    if vid is not None:
        return px_vaults.decrypt(vid, AGE_KEY_FILE)
    if not os.path.exists(VAULT_PATH):
        return {}
    env = os.environ.copy()
    env["SOPS_AGE_KEY_FILE"] = AGE_KEY_FILE
    result = subprocess.run(
        ["sops", "decrypt", VAULT_PATH],
        capture_output=True, text=True, env=env,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip())
    return yaml.safe_load(result.stdout) or {}


def encrypt_vault(data: dict):
    """Encrypt data to the active vault (multi-vault) or the legacy single file."""
    vid = _active_vault_id()
    if vid is not None:
        px_vaults.encrypt(vid, data, AGE_KEY_FILE)
        return
    env = os.environ.copy()
    env["SOPS_AGE_KEY_FILE"] = AGE_KEY_FILE
    if AGE_PUBLIC_KEY:
        env["SOPS_AGE_RECIPIENTS"] = AGE_PUBLIC_KEY

    vault_dir = os.path.dirname(VAULT_PATH) or "."
    os.makedirs(vault_dir, exist_ok=True)

    # Write the plaintext temp file in the SAME directory as the vault (not the
    # system /tmp dir) so that path-scoped .sops.yaml creation_rules — e.g.
    # `path_regex: secrets/.*\.enc\.yaml$` — still match it. A temp file
    # under /tmp matches no such rule and `sops encrypt` fails with
    # "error loading config: no matching creation rules found" (even when AGE
    # recipients are supplied via flag/env). The temp is created mode 0600 and
    # removed immediately after encryption.
    fd, tmp_path = tempfile.mkstemp(prefix=".pxsecrets-tmp-", suffix=".enc.yaml", dir=vault_dir)
    try:
        with os.fdopen(fd, "w") as tmp:
            yaml.dump(data, tmp, default_flow_style=False)
        result = subprocess.run(
            ["sops", "encrypt", "--input-type", "yaml", "--output-type", "yaml", tmp_path],
            capture_output=True, text=True, env=env,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip())
        with open(VAULT_PATH, "w") as f:
            f.write(result.stdout)
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------

app = Flask(__name__)


def _readonly_guard():
    """Return a 403 response tuple if PX_SECRETS_READ_ONLY env is set.

    Mutating endpoints call this at entry; if the env flag is on, the request
    is rejected before touching the vault. Returns None when writes are allowed.
    """
    if READ_ONLY:
        return jsonify({"error": "Vault is read-only (PX_SECRETS_READ_ONLY=1)"}), 403
    return None


@app.before_request
def _bearer_auth_guard():
    """Optional bearer token authentication for the JSON API.

    Off by default for backward compat with single-user desktop deployments.
    When PX_SECRETS_AUTH_TOKEN is set in the environment, every request to
    /api/* must include `Authorization: Bearer <token>` matching the env value
    (constant-time compared). Requests outside /api/* — the UI shell, static
    assets — are not gated, so a browser visit still works and the UI can
    prompt for the token in JavaScript.

    Designed for multi-process hosts where a non-human caller (script, agent,
    sidecar container) needs to talk to the API but you don't want a free-for-
    all on the loopback port. Tracking issue: #17.
    """
    if not AUTH_TOKEN:
        return None
    if not request.path.startswith("/api/"):
        return None
    if request.path in ("/api/lock/status", "/api/session", "/api/lock/setup",
                         "/api/webauthn/status", "/api/webauthn/auth/begin",
                         "/api/webauthn/auth/finish"):
        return None
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer ") and secrets.compare_digest(auth_header[7:].strip(), AUTH_TOKEN):
        return None
    # A valid UI session (the human unlocked the app lock) also satisfies auth,
    # so the browser can rely on the session cookie instead of carrying the bearer.
    if _session_valid(request.cookies.get(SESSION_COOKIE, "")):
        return None
    return jsonify({"error": "Authorization Bearer token required"}), 401


# ---------------------------------------------------------------------------
# UI session lock (issue #19) — optional master-password gate + idle auto-lock.
# A SEPARATE layer from the AGE key and the bearer token: it protects the UI/API
# against a human at the keyboard with the app already running (lent laptop,
# unattended desk, shared box). Off until the user sets it up. The master
# password is scrypt-hashed in ~/.px-secrets/lock.json (mode 0600), never stored
# or logged in plaintext. Sessions are in-memory tokens with a sliding idle TTL.
# ---------------------------------------------------------------------------

LOCK_FILE = os.path.join(CONFIG_DIR, "lock.json")
SESSION_COOKIE = "px_secrets_session"
DEFAULT_IDLE_TIMEOUT_S = 300
_SESSIONS = {}  # token -> last-activity epoch seconds


def _load_lock():
    try:
        with open(LOCK_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def _lock_enabled():
    return bool(_load_lock().get("hash"))


def _hash_password(password, salt):
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=16384, r=8, p=1, dklen=32).hex()


def _set_master_password(password, idle_timeout_s=DEFAULT_IDLE_TIMEOUT_S):
    salt = os.urandom(16)
    cfg = {"version": 1, "salt": salt.hex(), "hash": _hash_password(password, salt),
           "idle_timeout_s": int(idle_timeout_s)}
    os.makedirs(CONFIG_DIR, exist_ok=True)
    fd = os.open(LOCK_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(cfg, f, indent=2)


def _verify_password(password):
    cfg = _load_lock()
    if not cfg.get("hash"):
        return False
    return secrets.compare_digest(_hash_password(password, bytes.fromhex(cfg["salt"])), cfg["hash"])


def _idle_timeout_s():
    return int(_load_lock().get("idle_timeout_s", DEFAULT_IDLE_TIMEOUT_S))


def _new_session():
    token = secrets.token_urlsafe(32)
    _SESSIONS[token] = time.time()
    return token


def _session_valid(token):
    if not token or token not in _SESSIONS:
        return False
    if time.time() - _SESSIONS[token] > _idle_timeout_s():
        _SESSIONS.pop(token, None)
        return False
    _SESSIONS[token] = time.time()  # sliding refresh on activity
    return True


@app.before_request
def _ui_lock_guard():
    """Gate /api/* behind the UI session when an app lock is configured.

    Exempt: non-/api/ paths, the lock/session endpoints themselves, and any
    request bearing a valid PX_SECRETS_AUTH_TOKEN (machine callers authenticate
    with the bearer token and bypass the human UI lock). Everything else needs a
    valid, non-idle session cookie established via POST /api/session.
    """
    if not _lock_enabled():
        return None
    path = request.path
    if not path.startswith("/api/"):
        return None
    if path in ("/api/lock/status", "/api/session", "/api/lock/setup",
                         "/api/webauthn/status", "/api/webauthn/auth/begin",
                         "/api/webauthn/auth/finish"):
        return None
    if AUTH_TOKEN:
        ah = request.headers.get("Authorization", "")
        if ah.startswith("Bearer ") and secrets.compare_digest(ah[7:].strip(), AUTH_TOKEN):
            return None
    if _session_valid(request.cookies.get(SESSION_COOKIE, "")):
        return None
    return jsonify({"error": "locked", "locked": True}), 401


@app.route("/api/lock/status")
def api_lock_status():
    cfg = _load_lock()
    enabled = bool(cfg.get("hash"))
    locked = enabled and not _session_valid(request.cookies.get(SESSION_COOKIE, ""))
    return jsonify({"enabled": enabled, "locked": locked,
                    "idle_timeout_s": int(cfg.get("idle_timeout_s", DEFAULT_IDLE_TIMEOUT_S))})


@app.route("/api/lock/setup", methods=["POST"])
def api_lock_setup():
    guard = _readonly_guard()
    if guard:
        return guard
    body = request.json or {}
    password = body.get("password", "")
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400
    if _lock_enabled():
        token = request.cookies.get(SESSION_COOKIE, "")
        if not _session_valid(token) and not _verify_password(body.get("current_password", "")):
            return jsonify({"error": "Unlock first, or send current_password to change the lock"}), 401
    _set_master_password(password, int(body.get("idle_timeout_s", DEFAULT_IDLE_TIMEOUT_S)))
    resp = make_response(jsonify({"ok": True}))
    resp.set_cookie(SESSION_COOKIE, _new_session(), httponly=True, samesite="Strict")
    return resp


@app.route("/api/session", methods=["POST"])
def api_session_create():
    if not _lock_enabled():
        return jsonify({"error": "App lock is not configured"}), 400
    if not _verify_password((request.json or {}).get("password", "")):
        return jsonify({"error": "Incorrect password"}), 401
    resp = make_response(jsonify({"ok": True}))
    resp.set_cookie(SESSION_COOKIE, _new_session(), httponly=True, samesite="Strict")
    return resp


# --------------------------------------------------------------------------- WebAuthn
# Biometric unlock (Touch ID / Face ID / Windows Hello). This AUGMENTS the master
# password; it never replaces it, so a lost device can never lock you out.
# Enrolment requires an already-unlocked session — you cannot bootstrap a credential
# from a locked app, which is what stops someone at the keyboard enrolling their own
# finger while you are away.

def _webauthn_rp_and_origin():
    """Derive the Relying Party ID and expected origin from the request host.

    Two requirements are easy to conflate:

    * SECURE CONTEXT: both http://localhost and http://127.0.0.1 qualify, so either
      will happily run WebAuthn JavaScript.
    * VALID RP ID: stricter. An RP ID must be a *domain*, and an IP literal is not one.
      `localhost` is the single non-registrable name the spec permits. A page served
      from 127.0.0.1 therefore fails at registration with
      "SecurityError: The effective domain of the document is not a valid domain",
      which is why browse_host() opens `localhost` rather than the loopback IP.

    Any loopback address is mapped to `localhost`, so someone who typed the IP by hand
    still gets a working ceremony as long as the document itself is on localhost.
    """
    host = (request.host or f"{LOOPBACK_BROWSE_HOST}:{DEFAULT_PORT}").split(":")[0]
    if host in ("::1", "0.0.0.0") or host.startswith("127."):
        host = LOOPBACK_BROWSE_HOST
    return host, request.headers.get("Origin") or f"{request.scheme}://{request.host}"


@app.route("/api/webauthn/status")
def api_webauthn_status():
    return jsonify({"enrolled": px_webauthn.is_enrolled(),
                    "credentials": px_webauthn.list_credentials()})


def _webauthn_unusable_reason(rp_id):
    """Explain, in the user's terms, why a biometric cannot be enrolled here.

    Reached when the app is opened over a LAN address or a container port map. The
    browser would otherwise throw a bare SecurityError that says nothing actionable.
    """
    import ipaddress
    try:
        ipaddress.ip_address(rp_id)
    except ValueError:
        return None          # a hostname: fine
    return ("Biometric unlock needs the app opened at http://localhost:%d, not an IP "
            "address. WebAuthn requires a real domain name, and an IP is not one." % DEFAULT_PORT)


@app.route("/api/webauthn/register/begin", methods=["POST"])
def api_webauthn_register_begin():
    if not _session_valid(request.cookies.get(SESSION_COOKIE, "")):
        return jsonify({"error": "Unlock the app before enrolling a biometric"}), 401
    rp_id, _ = _webauthn_rp_and_origin()
    reason = _webauthn_unusable_reason(rp_id)
    if reason:
        return jsonify({"error": reason}), 400
    return jsonify(px_webauthn.registration_options(rp_id))


@app.route("/api/webauthn/register/finish", methods=["POST"])
def api_webauthn_register_finish():
    if not _session_valid(request.cookies.get(SESSION_COOKIE, "")):
        return jsonify({"error": "Unlock the app before enrolling a biometric"}), 401
    rp_id, origin = _webauthn_rp_and_origin()
    try:
        return jsonify({"ok": True, "credential": px_webauthn.verify_registration(
            request.json or {}, rp_id, origin)})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/webauthn/auth/begin", methods=["POST"])
def api_webauthn_auth_begin():
    if not _lock_enabled():
        return jsonify({"error": "App lock is not configured"}), 400
    try:
        return jsonify(px_webauthn.authentication_options())
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/webauthn/auth/finish", methods=["POST"])
def api_webauthn_auth_finish():
    if not _lock_enabled():
        return jsonify({"error": "App lock is not configured"}), 400
    rp_id, origin = _webauthn_rp_and_origin()
    try:
        cred = px_webauthn.verify_authentication(request.json or {}, rp_id, origin)
    except ValueError as e:
        return jsonify({"error": str(e)}), 401
    resp = make_response(jsonify({"ok": True, "credential": cred}))
    resp.set_cookie(SESSION_COOKIE, _new_session(), httponly=True, samesite="Strict")
    return resp


@app.route("/api/webauthn/credential", methods=["DELETE"])
def api_webauthn_delete():
    if not _session_valid(request.cookies.get(SESSION_COOKIE, "")):
        return jsonify({"error": "Unlock the app first"}), 401
    cred_id = (request.json or {}).get("id", "")
    return jsonify({"ok": px_webauthn.delete_credential(cred_id)})


@app.route("/api/session", methods=["DELETE"])
def api_session_delete():
    _SESSIONS.pop(request.cookies.get(SESSION_COOKIE, ""), None)
    resp = make_response(jsonify({"ok": True}))
    resp.delete_cookie(SESSION_COOKIE)
    return resp


@app.route("/api/lock/disable", methods=["POST"])
def api_lock_disable():
    token = request.cookies.get(SESSION_COOKIE, "")
    if not _session_valid(token) and not _verify_password((request.json or {}).get("password", "")):
        return jsonify({"error": "Unlock or send password to disable the lock"}), 401
    try:
        os.unlink(LOCK_FILE)
    except FileNotFoundError:
        pass
    _SESSIONS.clear()
    return jsonify({"ok": True})


def _resolve_service_case(service: str, data: dict) -> str:
    """Return the canonical service key for case-insensitive match.

    If `service` matches an existing top-level key case-insensitively, return the
    existing key's exact casing so the new write lands in the same bucket. If no
    match exists, return `service` unchanged so the user-typed case is preserved.

    Prevents the duplicate-by-case bug where typing "test" while "Test" already
    exists creates two separate entries that look identical in the UI (CSS
    uppercases the display).
    """
    if service in data:
        return service
    lower = service.lower()
    for existing in data:
        if existing.lower() == lower:
            return existing
    return service


@app.route("/")
def index():
    """Serve the single-page UI."""
    return HTML_PAGE


@app.route("/healthz")
def healthz():
    """Liveness probe — deliberately outside the /api/ prefix so the bearer-token
    guard exempts it. Returns 200 if the process is alive; does not touch the
    vault. Use this from Kubernetes / systemd liveness probes when
    PX_SECRETS_AUTH_TOKEN is set, otherwise the probe would 401 and the
    supervisor would kill a healthy pod.
    """
    return jsonify({"status": "ok", "version": VERSION})


@app.route("/readyz")
def readyz():
    """Readiness probe — exercises the full SOPS+AGE decrypt chain so a 200
    means everything the pod needs (vault mount, AGE key, sops binary, yaml
    parser) is wired up correctly. Returns 500 with the failure reason
    otherwise. Also auth-exempt by virtue of being outside /api/.
    """
    try:
        decrypt_vault()
        return jsonify({"status": "ready"})
    except Exception as e:
        return jsonify({"status": "not-ready", "error": str(e)}), 500


@app.route("/api/vault")
def api_vault():
    """Return all secrets grouped by service (of the active vault)."""
    try:
        data = decrypt_vault()
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/vaults", methods=["GET"])
def api_list_vaults():
    """List named vaults (Issue #21). Each: id, name, agent_access, human_unlock_required."""
    return jsonify({"vaults": px_vaults.list_vaults()})


@app.route("/api/vaults", methods=["POST"])
def api_create_vault():
    """Create a named vault with its own recipients + access policy."""
    guard = _readonly_guard()
    if guard:
        return guard
    body = request.get_json(force=True, silent=True) or {}
    name = (body.get("name") or "").strip()
    if not name:
        return jsonify({"error": "name required"}), 400
    recipients = body.get("recipients") or ([AGE_PUBLIC_KEY] if AGE_PUBLIC_KEY else [])
    try:
        vid = px_vaults.create_vault(
            name, recipients,
            agent_access=body.get("agent_access", "read_write"),
            human_unlock_required=bool(body.get("human_unlock_required", False)),
        )
    except (ValueError, FileExistsError) as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"ok": True, "id": vid}), 201


@app.route("/api/vaults/move", methods=["POST"])
def api_move_secret():
    """Move or copy a secret between vaults (Issue #31). Body: src, dst, path[], copy?, dry_run?."""
    guard = _readonly_guard()
    if guard:
        return guard
    b = request.get_json(force=True, silent=True) or {}
    src, dst, path = b.get("src"), b.get("dst"), b.get("path")
    if not (src and dst and isinstance(path, list) and path):
        return jsonify({"error": "src, dst, path[] required"}), 400
    try:
        res = px_vaults.move_secret(src, dst, path, AGE_KEY_FILE,
                                    copy=bool(b.get("copy")), dry_run=bool(b.get("dry_run")))
    except KeyError as e:
        return jsonify({"error": f"not found: {e}"}), 404
    except (ValueError, FileExistsError) as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({"ok": True, "result": res})


@app.before_request
def _vault_policy_guard():
    """Enforce per-vault agent_access for automation (Bearer) callers on vault-data routes.
    Humans / the local UI are unrestricted here (still subject to the UI lock). Policy:
    read_write = full, read = GET/HEAD only, deny = blocked. Legacy single-file mode = no policy."""
    p = request.path
    if not (p == "/api/vault" or p.startswith("/api/secret") or p.startswith("/api/note")):
        return None
    vid = _active_vault_id()
    if vid is None:
        return None
    if not request.headers.get("Authorization", "").startswith("Bearer "):
        return None  # not an agent bearer call — treat as human/local
    policy = px_vaults.read_config(vid).get("agent_access", "read_write")
    if policy == "read_write" or (policy == "read" and request.method in ("GET", "HEAD")):
        return None
    return jsonify({"error": f"vault '{vid}' denies agent {request.method} (agent_access={policy})"}), 403


def _walk_to_parent(data: dict, path: list, create: bool = False):
    """Resolve (parent_dict, leaf_key) for a nested path list (e.g.
    ["telephony", "master", "auth_token"]). With create=True, builds missing
    intermediate group dicts. Returns (None, leaf) if an intermediate is missing
    and create=False. Raises ValueError if an intermediate exists but is not a group."""
    parent = data
    for seg in path[:-1]:
        if seg in parent:
            if not isinstance(parent[seg], dict):
                raise ValueError(f"path segment '{seg}' is not a group")
            parent = parent[seg]
        elif create:
            parent[seg] = {}
            parent = parent[seg]
        else:
            return None, path[-1]
    return parent, path[-1]


def _prune_empty_groups(data: dict, segments: list):
    """Delete now-empty group dicts along `segments`, deepest first — so deleting
    a nested leaf that empties its tenant (and the service) cleans up, matching
    the flat-delete behavior of removing an emptied service."""
    for i in range(len(segments), 0, -1):
        prefix = segments[:i]
        node = data
        ok = True
        for s in prefix:
            if isinstance(node, dict) and s in node:
                node = node[s]
            else:
                ok = False
                break
        if ok and isinstance(node, dict) and not node:
            par = data
            for s in prefix[:-1]:
                par = par[s]
            par.pop(prefix[-1], None)


def _validate_path(path):
    """Return an error-response tuple if path is not a clean list of non-empty,
    non-reserved string segments; else None."""
    if not isinstance(path, list) or len(path) < 1 or not all(isinstance(s, str) and s for s in path):
        return jsonify({"error": "Invalid path"}), 400
    if any(s.endswith("__note") for s in path):
        return jsonify({"error": "Reserved key suffix '__note'"}), 400
    return None


@app.route("/api/secret", methods=["POST"])
def api_add_secret():
    """Add or update a secret in the vault.

    Refuses to overwrite an existing key unless the caller explicitly opts in
    via `overwrite=true` (body field or query param). Silent overwrites are a
    data-loss footgun for non-rotatable credentials like long-lived API keys.
    """
    guard = _readonly_guard()
    if guard:
        return guard
    try:
        body = request.json
        overwrite = (
            body.get("overwrite") is True
            or request.args.get("overwrite", "").lower() in ("1", "true", "yes")
        )
        # Nested/path write (e.g. telephony -> tenant -> auth_token). Same vault,
        # same SOPS-encrypted file as a flat write — just at depth.
        path = body.get("path")
        if path is not None:
            bad = _validate_path(path)
            if bad:
                return bad
            value = body["value"]
            note = body.get("note", "")
            data = decrypt_vault()
            parent, leaf = _walk_to_parent(data, path, create=True)
            if not overwrite and leaf in parent:
                return jsonify({"error": "Key already exists. Resend with overwrite=true to replace.", "path": path}), 409
            parent[leaf] = value
            if note:
                parent[f"{leaf}__note"] = note
            encrypt_vault(data)
            return jsonify({"ok": True})

        service = body["service"].strip()
        key = body["key"]
        value = body["value"]
        note = body.get("note", "")

        data = decrypt_vault()
        service = _resolve_service_case(service, data)
        if not overwrite and service in data and key in data[service]:
            return jsonify({
                "error": "Key already exists. Resend with overwrite=true to replace.",
                "service": service,
                "key": key,
            }), 409
        if service not in data:
            data[service] = {}
        data[service][key] = value
        if note:
            data[service][f"{key}__note"] = note
        encrypt_vault(data)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/secret", methods=["DELETE"])
def api_delete_secret():
    """Delete a single secret (and its note) from the vault."""
    guard = _readonly_guard()
    if guard:
        return guard
    try:
        body = request.json
        data = decrypt_vault()
        path = body.get("path")
        if path is not None:
            bad = _validate_path(path)
            if bad:
                return bad
            parent, leaf = _walk_to_parent(data, path, create=False)
            if parent is not None:
                parent.pop(leaf, None)
                parent.pop(f"{leaf}__note", None)
                _prune_empty_groups(data, path[:-1])
            encrypt_vault(data)
            return jsonify({"ok": True})

        service = body["service"].strip()
        key = body["key"]
        service = _resolve_service_case(service, data)
        if service in data:
            data[service].pop(key, None)
            data[service].pop(f"{key}__note", None)
            if not data[service]:
                del data[service]
        encrypt_vault(data)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/service/<svc>", methods=["DELETE"])
def api_delete_service(svc):
    """Delete an entire service and all its secrets from the vault."""
    guard = _readonly_guard()
    if guard:
        return guard
    try:
        data = decrypt_vault()
        svc = _resolve_service_case(svc.strip(), data)
        if svc in data:
            del data[svc]
        encrypt_vault(data)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/note", methods=["POST"])
def api_add_note():
    """Add or update a note attached to a secret."""
    guard = _readonly_guard()
    if guard:
        return guard
    try:
        body = request.json
        note = body["note"]
        data = decrypt_vault()
        path = body.get("path")
        if path is not None:
            bad = _validate_path(path)
            if bad:
                return bad
            parent, leaf = _walk_to_parent(data, path, create=False)
            if parent is None:
                return jsonify({"error": "Path not found"}), 404
            if note:
                parent[f"{leaf}__note"] = note
            else:
                parent.pop(f"{leaf}__note", None)
            encrypt_vault(data)
            return jsonify({"ok": True})

        service = body["service"].strip()
        key = body["key"]
        service = _resolve_service_case(service, data)
        if service not in data:
            return jsonify({"error": "Service not found"}), 404
        if note:
            data[service][f"{key}__note"] = note
        else:
            data[service].pop(f"{key}__note", None)
        encrypt_vault(data)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/settings", methods=["GET"])
def api_get_settings():
    """Return current vault and key configuration."""
    return jsonify({
        "vault_path": VAULT_PATH,
        "age_key_file": AGE_KEY_FILE,
        "age_public_key": AGE_PUBLIC_KEY,
    })


@app.route("/api/settings", methods=["POST"])
def api_save_settings():
    """Save new vault and key configuration."""
    guard = _readonly_guard()
    if guard:
        return guard
    try:
        body = request.json
        cfg = {
            "vault_path": body.get("vault_path", VAULT_PATH),
            "age_key_file": body.get("age_key_file", AGE_KEY_FILE),
            "age_public_key": body.get("age_public_key", AGE_PUBLIC_KEY),
        }
        save_config(cfg)
        load_config()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/open-browser")
def api_open_browser():
    """Open the UI in the system's default browser."""
    port = app.config.get("port", DEFAULT_PORT)
    webbrowser.open(f"http://{browse_host(HOST_OVERRIDE or DEFAULT_HOST)}:{port}")
    return jsonify({"ok": True})


@app.route("/api/generate")
def api_generate():
    """Generate cryptographically secure random keys and passwords."""
    results = {}

    # Memorable (word-like, easy to type)
    wordchars = string.ascii_lowercase
    results["memorable"] = [
        "-".join("".join(secrets.choice(wordchars) for _ in range(secrets.randbelow(4) + 4)) for _ in range(4))
        for _ in range(4)
    ]

    # Strong 16 chars
    strong_chars = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    results["strong"] = [
        "".join(secrets.choice(strong_chars) for _ in range(16))
        for _ in range(4)
    ]

    # Fort Knox 32 chars
    fort_chars = string.ascii_letters + string.digits + string.punctuation
    results["fort_knox"] = [
        "".join(secrets.choice(fort_chars) for _ in range(32))
        for _ in range(4)
    ]

    # Alphanumeric 24 chars
    alnum = string.ascii_letters + string.digits
    results["alphanumeric"] = [
        "".join(secrets.choice(alnum) for _ in range(24))
        for _ in range(4)
    ]

    # Hex 128-bit
    results["hex_128"] = [secrets.token_hex(16) for _ in range(4)]

    # Hex 256-bit
    results["hex_256"] = [secrets.token_hex(32) for _ in range(4)]

    # UUID v4
    results["uuid_v4"] = [str(uuid.uuid4()) for _ in range(4)]

    # API Keys (sk_live_ prefix)
    results["api_keys"] = [
        "sk_live_" + "".join(secrets.choice(alnum) for _ in range(40))
        for _ in range(4)
    ]

    # JWT Secrets (base64, 64 chars)
    results["jwt_secret"] = [
        base64.urlsafe_b64encode(secrets.token_bytes(48)).decode()[:64]
        for _ in range(4)
    ]

    return jsonify(results)


@app.route("/api/export")
def api_export():
    """Export vault in the requested format."""
    fmt = request.args.get("format", "env")
    try:
        data = decrypt_vault()
        if fmt == "json":
            return jsonify(data)
        elif fmt == "yaml":
            return app.response_class(
                yaml.dump(data, default_flow_style=False),
                mimetype="text/yaml",
                headers={"Content-Disposition": "attachment; filename=secrets.yaml"}
            )
        else:  # .env format
            lines = []
            for svc in sorted(data.keys()):
                lines.append(f"# {svc}")
                for key in sorted(data[svc].keys()):
                    if key.endswith("__note"):
                        continue
                    val = data[svc][key]
                    env_key = f"{svc.upper()}_{key.upper()}"
                    lines.append(f'{env_key}="{val}"')
                lines.append("")
            return app.response_class(
                "\n".join(lines),
                mimetype="text/plain",
                headers={"Content-Disposition": "attachment; filename=.env"}
            )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/import", methods=["POST"])
def api_import():
    """Import secrets from .env, JSON, or YAML format."""
    guard = _readonly_guard()
    if guard:
        return guard
    try:
        body = request.json
        text = body.get("text", "")
        fmt = body.get("format", "auto")
        service = body.get("service", "").strip()

        imported = {}

        if fmt == "auto":
            text_stripped = text.strip()
            if text_stripped.startswith("{"):
                fmt = "json"
            elif ":" in text_stripped.split("\n")[0] and "=" not in text_stripped.split("\n")[0]:
                fmt = "yaml"
            else:
                fmt = "env"

        if fmt == "json":
            imported = json.loads(text)
        elif fmt == "yaml":
            imported = yaml.safe_load(text) or {}
        else:  # .env
            svc_name = service or "imported"
            env_secrets = {}
            for line in text.split("\n"):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    k, v = line.split("=", 1)
                    k = k.strip()
                    v = v.strip().strip('"').strip("'")
                    if k and v:
                        env_secrets[k.lower()] = v
            if env_secrets:
                imported = {svc_name: env_secrets}

        if not imported:
            return jsonify({"error": "No secrets found in input"}), 400

        # Merge into vault
        data = decrypt_vault()
        count = 0
        for svc, keys in imported.items():
            if not isinstance(keys, dict):
                continue
            svc = _resolve_service_case(svc.strip(), data)
            if svc not in data:
                data[svc] = {}
            for k, v in keys.items():
                if k.endswith("__note"):
                    data[svc][k] = v
                else:
                    data[svc][k] = str(v)
                    count += 1

        encrypt_vault(data)
        return jsonify({"ok": True, "imported": count})
    except json.JSONDecodeError:
        return jsonify({"error": "Invalid JSON format"}), 400
    except yaml.YAMLError:
        return jsonify({"error": "Invalid YAML format"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/about")
def api_about():
    """Return version, runtime, and system information."""
    import platform

    return jsonify({
        "app": APP_NAME,
        "version": VERSION,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "arch": platform.machine(),
        "repo": REPO_URL,
        "license": "AGPL-3.0",
        "auth_required": bool(AUTH_TOKEN),
        "read_only": READ_ONLY,
    })


def _version_tuple(v: str) -> tuple:
    """Convert 'v1.6.0' or '1.6.0' to (1, 6, 0) for comparison.

    Non-numeric or malformed parts collapse to 0 so pre-release tags like
    '1.6.0-rc1' don't crash the comparison. Returns an empty tuple on total
    parse failure so callers see a 'no update' verdict by default.
    """
    try:
        cleaned = v.lstrip("v").split("-")[0].split("+")[0]
        return tuple(int(p) for p in cleaned.split("."))
    except (ValueError, AttributeError):
        return ()


@app.route("/api/check-update")
def api_check_update():
    """Check the GitHub Releases API for a newer published version.

    Read-only, network-touching, no auth required to GitHub (anonymous rate
    limit is plenty for occasional checks). Returns current vs. latest plus a
    boolean verdict so the UI can render a single 'Update available' badge
    without doing its own version math. Tracking issue: #3.
    """
    import urllib.request
    import urllib.error
    try:
        req = urllib.request.Request(
            f"{GITHUB_API_BASE}/releases/latest",
            headers={
                "User-Agent": f"px-secrets/{VERSION}",
                "Accept": "application/vnd.github+json",
            },
        )
        with urllib.request.urlopen(req, timeout=10) as response:
            release = json.loads(response.read())
        latest = release.get("tag_name", "").lstrip("v")
        has_update = _version_tuple(latest) > _version_tuple(VERSION)
        return jsonify({
            "current": VERSION,
            "latest": latest,
            "has_update": has_update,
            "release_url": release.get("html_url", ""),
            "release_name": release.get("name", ""),
            "release_notes": (release.get("body") or "")[:2000],
            "published_at": release.get("published_at", ""),
        })
    except urllib.error.URLError as e:
        return jsonify({"error": f"Network error: {e.reason}"}), 502
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/apply-update", methods=["POST"])
def api_apply_update():
    """Download the latest px_secrets.py from the published release tag and replace this file.

    Single-file replacement only — the OSS distribution is intentionally one
    Python file precisely so updates can be atomic. After write, the process
    exits with code 0 so a supervising LaunchAgent / systemd unit with
    KeepAlive restarts it on the new code. Returns the backup path so a
    rollback is just `mv backup current && restart`.

    Refuses to apply if the downloaded file is suspiciously small or missing
    the expected sentinels — a safety net against a hijacked CDN serving HTML
    or a truncated download. Tracking issue: #3.

    Honors PX_SECRETS_READ_ONLY: if the vault is read-only, updates are
    refused too, on the theory that a sidecar serving a read-only mirror
    should be deployed by the same pipeline that builds the image, not by
    pulling code from GitHub at runtime.
    """
    guard = _readonly_guard()
    if guard:
        return guard

    import urllib.request
    import urllib.error
    try:
        # Resolve the latest tag
        req = urllib.request.Request(
            f"{GITHUB_API_BASE}/releases/latest",
            headers={"User-Agent": f"px-secrets/{VERSION}"},
        )
        with urllib.request.urlopen(req, timeout=10) as response:
            release = json.loads(response.read())
        tag = release.get("tag_name", "")
        if not tag:
            return jsonify({"error": "Latest release has no tag"}), 500
        latest = tag.lstrip("v")
        if not _version_tuple(latest) > _version_tuple(VERSION):
            return jsonify({
                "ok": False,
                "message": "Already on latest version",
                "current": VERSION,
                "latest": latest,
            })

        # Fetch the px_secrets.py at that tag from raw.githubusercontent.com
        raw_req = urllib.request.Request(
            f"{GITHUB_RAW_BASE}/{tag}/px_secrets.py",
            headers={"User-Agent": f"px-secrets/{VERSION}"},
        )
        with urllib.request.urlopen(raw_req, timeout=30) as response:
            new_code = response.read().decode("utf-8")

        # Sanity-check the payload before overwriting ourselves
        if len(new_code) < 5000:
            return jsonify({"error": "Downloaded file is suspiciously small"}), 500
        if "VERSION =" not in new_code or "from flask import" not in new_code:
            return jsonify({"error": "Downloaded file does not look like px_secrets.py"}), 500

        current_path = os.path.abspath(__file__)
        backup_path = f"{current_path}.bak-v{VERSION}"
        with open(current_path, "rb") as src, open(backup_path, "wb") as dst:
            dst.write(src.read())

        with open(current_path, "w") as f:
            f.write(new_code)

        # Restart by exiting — LaunchAgent / systemd with KeepAlive brings us back
        # on the new code. Run the exit on a delayed daemon thread so the HTTP
        # response gets flushed to the caller first.
        def _delayed_exit():
            import time
            time.sleep(1)
            os._exit(0)

        threading.Thread(target=_delayed_exit, daemon=True).start()

        return jsonify({
            "ok": True,
            "from": VERSION,
            "to": latest,
            "backup": backup_path,
            "message": "Update written. Restarting process — reload the page in ~3 seconds.",
        })
    except urllib.error.URLError as e:
        return jsonify({"error": f"Network error: {e.reason}"}), 502
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# Embedded HTML/CSS/JS
# ---------------------------------------------------------------------------

HTML_PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>""" + APP_NAME + r"""</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#1a1a1a;--card:#252525;--accent:#4fc3f7;--success:#66bb6a;--danger:#ef5350;--text:#e0e0e0;--muted:#888;--border:#333;--radius:10px}
body{background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,"SF Pro Text","Segoe UI",Roboto,sans-serif;font-size:15px;padding:16px;max-width:800px;margin:0 auto}
code,pre,.mono{font-family:"SF Mono",SFMono-Regular,Menlo,Consolas,monospace}
h1{font-size:22px;font-weight:600;color:var(--accent)}
.header{display:flex;align-items:baseline;gap:8px;margin-bottom:10px;position:relative}
.header small{color:var(--muted);font-size:13px}
.header-icons{position:absolute;right:0;top:0;display:flex;gap:6px;align-items:center}
.icon-btn{background:transparent;border:none;color:var(--muted);font-size:16px;cursor:pointer;padding:4px;transition:color .15s;text-decoration:none;line-height:1}
.icon-btn:hover{color:var(--accent)}
.icon-btn[title]:hover::after{content:attr(title)}
/* Toolbar wraps instead of overflowing. Before this, a single nowrap flex row pushed
   Export outside the viewport as soon as the vault switcher became visible. */
.toolbar{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:10px;align-items:center}
.toolbar input[type=text]{flex:1 1 180px;min-width:140px;background:var(--card);border:1px solid var(--border);color:var(--text);padding:8px 12px;border-radius:6px;font-size:14px;outline:none}
.toolbar input[type=text]:focus{border-color:var(--accent)}
/* A vault name can be arbitrarily long: cap and ellipsize it rather than let it
   dictate the width of the whole toolbar row. */
#vault-switcher{max-width:170px;background:var(--card);border:1px solid var(--border);color:var(--text);padding:7px 8px;border-radius:6px;font-size:13px;outline:none;text-overflow:ellipsis}

/* Narrow windows: shrink controls, and give search its own full-width row, before
   anything is ever allowed to overflow. */
@media (max-width:760px){
  .toolbar{gap:5px}
  .toolbar .btn{padding:6px 9px;font-size:12px}
  #vault-switcher{max-width:130px;font-size:12px}
  .toolbar input[type=text]{flex:1 1 100%;order:-1}
}
@media (max-width:480px){
  .toolbar .btn{flex:1 1 auto;text-align:center;padding:7px 6px}
  #vault-switcher{flex:1 1 auto;max-width:none}
  .header-icons{flex-wrap:wrap}
}
.btn{background:transparent;color:var(--text);border:1px solid var(--border);padding:6px 12px;border-radius:6px;cursor:pointer;font-size:13px;white-space:nowrap;transition:all .15s}
.btn:hover{border-color:var(--accent);color:var(--accent)}
.btn-accent{border-color:var(--accent);color:var(--accent)}
.btn-danger{border-color:var(--danger);color:var(--danger)}
.btn-danger:hover{background:var(--danger);color:#fff}
.btn-sm{padding:3px 9px;font-size:12px}
.cards{display:flex;flex-direction:column;gap:6px}
.card{background:var(--card);border-radius:var(--radius);overflow:hidden}
.card-header{display:flex;align-items:center;padding:10px 14px;cursor:pointer;user-select:none;gap:8px}
.card-header:hover{background:#2a2a2a}
.arrow{color:var(--muted);font-size:10px;transition:transform .2s;width:12px;text-align:center}
.arrow.open{transform:rotate(90deg)}
.svc-name{color:var(--accent);font-weight:600;font-size:15px}
.key-count{color:var(--muted);font-size:13px;margin-left:auto}
.card-body{display:none;padding:4px 12px 10px}
.card-body.open{display:block}
.key-row{padding:6px 0;border-bottom:1px solid #2a2a2a}
.key-row:last-child{border-bottom:none}
.key-top{display:flex;align-items:center;gap:6px}
.key-name{font-weight:500;min-width:120px;font-size:14px;flex-shrink:0}
.key-value{font-family:"SF Mono",monospace;font-size:13px;color:#bbb;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.key-value.revealed{color:var(--text);white-space:normal;word-break:break-all}
.key-actions{display:flex;gap:4px;flex-shrink:0}
.key-note{color:var(--muted);font-style:italic;font-size:12px;margin-top:8px;padding-left:0;cursor:pointer;transition:color .15s}
.key-note:hover{color:var(--accent)}
.key-group{margin:4px 0;border-left:2px solid #333;padding-left:8px}
.key-group-head{display:flex;align-items:center;gap:8px;padding:6px 0;cursor:pointer;user-select:none}
.key-group-head:hover .group-name{color:var(--accent)}
.group-name{font-weight:600;font-size:14px;color:#ddd}
.group-desc{color:var(--muted);font-style:italic;font-size:12px;margin:0 0 4px 20px}
.key-group-body{display:none;padding-left:12px}
.key-group-body.open{display:block}
.ro-tag{color:var(--muted);font-size:11px;font-style:italic;align-self:center;padding:0 4px;border:1px solid #333;border-radius:4px}
.status-bar{margin-top:12px;color:var(--muted);font-size:13px;text-align:center}
.cli-ref{margin-top:4px;color:var(--muted);font-size:11px;text-align:center}
/* Modals */
.modal-overlay{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,.6);z-index:100;justify-content:center;align-items:center}
.modal-overlay.show{display:flex}
.modal{background:var(--card);border-radius:var(--radius);padding:20px;width:90%;max-width:420px;border:1px solid var(--border)}
.modal h2{font-size:17px;margin-bottom:14px;color:var(--accent)}
.modal label{display:block;font-size:13px;color:var(--muted);margin-bottom:4px;margin-top:10px}
.modal input,.modal textarea{width:100%;background:var(--bg);border:1px solid var(--border);color:var(--text);padding:8px 10px;border-radius:6px;font-size:14px;outline:none;font-family:inherit}
.svc-chips{display:flex;flex-wrap:wrap;gap:5px;margin-top:6px}
.svc-chip{background:var(--bg);border:1px solid var(--border);color:var(--accent);padding:3px 10px;border-radius:12px;font-size:12px;cursor:pointer;transition:all .15s}
.svc-chip:hover{border-color:var(--accent);background:#1a2a3a}
.modal input:focus,.modal textarea:focus{border-color:var(--accent)}
.modal textarea{resize:vertical;min-height:90px}
.modal-actions{display:flex;gap:8px;margin-top:14px;justify-content:flex-end}
.masked-field{display:flex;align-items:center;gap:4px}.masked-field input{flex:1;min-width:0}.masked-btn{background:none;border:none;color:var(--muted);font-size:15px;cursor:pointer;padding:2px 4px;line-height:1;transition:color .15s}.masked-btn:hover{color:var(--text)}
/* Toast */
.toast-container{position:fixed;bottom:16px;right:16px;z-index:200;display:flex;flex-direction:column;gap:6px}
.toast{background:rgba(102,187,106,0.15);color:var(--success);border:1px solid rgba(102,187,106,0.3);padding:10px 20px;border-radius:10px;font-size:13px;opacity:0;transform:translateY(10px);transition:all .3s;backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);pointer-events:none}
.toast.show{opacity:1;transform:translateY(0)}
/* Failures were rendering in the success green, which reads as "it worked" at a
   glance and is exactly backwards. Errors get the danger colour. */
.toast.toast-error{background:rgba(229,83,75,0.15);color:var(--danger);border-color:rgba(229,83,75,0.35)}
/* Generator */
.gen-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:10px;max-height:55vh;overflow-y:auto;padding-right:4px}
.gen-category{background:var(--bg);border:1px solid var(--border);border-radius:var(--radius);padding:10px}
.gen-category h3{font-size:13px;color:var(--accent);margin-bottom:6px;display:flex;justify-content:space-between;align-items:center}
.gen-category h3 span{color:var(--muted);font-weight:400;font-size:11px}
.gen-item{font-family:"SF Mono",monospace;font-size:12px;color:var(--text);padding:5px 8px;background:#1a1a1a;border-radius:4px;margin-bottom:4px;cursor:pointer;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;transition:all .15s;border:1px solid transparent}
.gen-item:hover{border-color:var(--accent);color:var(--accent)}
/* Import/Export */
.import-textarea{width:100%;min-height:150px;background:var(--bg);border:1px solid var(--border);color:var(--text);padding:10px;border-radius:6px;font-family:"SF Mono",monospace;font-size:13px;resize:vertical}
.format-select{background:var(--bg);border:1px solid var(--border);color:var(--text);padding:6px 10px;border-radius:6px;font-size:13px}
#lock-screen{position:fixed;inset:0;background:var(--bg);z-index:10000;display:none;align-items:center;justify-content:center}
.lock-box{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:32px;width:330px;max-width:90vw;text-align:center;box-shadow:0 12px 48px rgba(0,0,0,.45)}
.lock-box .lock-emoji{font-size:44px;margin-bottom:6px}
.lock-box h2{margin:0 0 6px}
.lock-box input{width:100%;margin:8px 0;padding:11px;background:var(--bg);border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:14px}
.lock-box input:focus{outline:none;border-color:#3b82f6}
</style>
</head>
<body>

<div id="lock-screen">
  <div class="lock-box">
    <div class="lock-emoji">&#128274;</div>
    <h2 id="lock-title">Locked</h2>
    <p id="lock-sub" style="color:var(--muted);font-size:13px;margin:0 0 10px"></p>
    <input id="lock-pass" type="password" placeholder="Master password" autocomplete="off" onkeydown="if(event.key==='Enter')lockSubmit()">
    <input id="lock-pass2" type="password" placeholder="Confirm password" autocomplete="off" style="display:none" onkeydown="if(event.key==='Enter')lockSubmit()">
    <div id="lock-err" style="color:#e5534b;font-size:12px;min-height:15px;margin:2px 0"></div>
    <button class="btn btn-accent" style="width:100%" id="lock-btn" onclick="lockSubmit()">Unlock</button>
    <!-- Only rendered when an authenticator is enrolled. The master password stays
         above as the recovery path, so a lost device can never lock you out. -->
    <button class="btn" style="width:100%;margin-top:8px;display:none" id="bio-btn" onclick="bioUnlock()">&#128075; Unlock with Touch ID / Face ID</button>
  </div>
</div>

<div class="header">
  <h1>""" + APP_NAME + r"""</h1>
  <small>v""" + VERSION + r"""</small>
  <small style="color:var(--muted)">SOPS + AGE</small>
  <div class="header-icons">
    <a class="icon-btn" onclick="lockApp()" title="Lock now" id="lock-icon" style="display:none">&#128274;</a>
    <a class="icon-btn" onclick="showAboutModal()" title="About">&#8505;&#65039;</a>
    <a class="icon-btn" onclick="showSettingsModal()" title="Settings">&#9881;&#65039;</a>
    <a class="icon-btn" onclick="fetch('/api/open-browser')" title="Open in browser">&#127760;</a>
  </div>
</div>

<div class="toolbar">
  <select id="vault-switcher" onchange="switchVault(this.value)" title="Active vault" style="display:none"></select>
  <button class="btn" onclick="createVaultPrompt()" title="Create a new vault">+ Vault</button>
  <input type="text" id="search" placeholder="Search services or keys...">
  <button class="btn btn-accent" onclick="showAddModal()">+ Add</button>
  <button class="btn" onclick="loadVault()">Refresh</button>
  <button class="btn" onclick="showGenerateModal()">Generate</button>
  <button class="btn" onclick="showImportModal()">Import</button>
  <button class="btn" onclick="showExportModal()">Export</button>
</div>

<div class="cards" id="cards"></div>

<div class="status-bar" id="status-bar">Loading...</div>
<div class="cli-ref mono">CLI: px_secrets.py --list | --get SERVICE KEY | --help</div>
<div style="margin-top:6px;text-align:center;font-size:11px;color:var(--muted)">Free &amp; open source &hearts; <a href='""" + SUPPORT_URL + r"""' target="_blank" rel="noopener" style="color:var(--muted);text-decoration:none;border-bottom:1px dotted var(--border)">support the project</a> &nbsp;&middot;&nbsp; <a href='""" + REPO_URL + r"""' target="_blank" rel="noopener" style="color:var(--muted);text-decoration:none;border-bottom:1px dotted var(--border)">&#11088; star on GitHub</a></div>

<!-- Add Secret Modal -->
<div class="modal-overlay" id="add-modal">
  <div class="modal">
    <h2 id="add-modal-title">Add Secret</h2>
    <label>Service</label>
    <div class="svc-chips" id="svc-chips"></div>
    <input id="add-service" placeholder="New service or click one above" style="margin-top:6px">
    <label>Key Name</label>
    <input id="add-key" placeholder="e.g. access_key_id">
    <label>Value</label>
    <input id="add-value" type="password" placeholder="secret value">
    <label>Note (optional)</label>
    <textarea id="add-note" placeholder="optional note"></textarea>
    <div class="modal-actions">
      <button class="btn" onclick="closeModal('add-modal')">Cancel</button>
      <button class="btn btn-accent" onclick="addSecret()">Save</button>
    </div>
  </div>
</div>

<!-- Note Modal -->
<div class="modal-overlay" id="note-modal">
  <div class="modal">
    <h2>Edit Note</h2>
    <textarea id="note-text" placeholder="Enter note..."></textarea>
    <input type="hidden" id="note-service">
    <input type="hidden" id="note-key">
    <div class="modal-actions">
      <button class="btn" onclick="closeModal('note-modal')">Cancel</button>
      <button class="btn btn-accent" onclick="saveNote()">Save</button>
    </div>
  </div>
</div>

<!-- Settings Modal -->
<div class="modal-overlay" id="settings-modal">
  <div class="modal">
    <h2>Settings</h2>
    <div style="border-bottom:1px solid var(--border);padding-bottom:12px;margin-bottom:14px">
      <label>App Lock</label>
      <div style="font-size:11px;color:var(--muted);margin:2px 0 8px">Password to open the app + auto-lock when idle. Protects the vault from anyone using this machine. Separate from your AGE key.</div>
      <div style="display:flex;gap:8px;align-items:center">
        <button class="btn" id="lock-enable-btn" onclick="closeModal('settings-modal');enableLock()">Enable</button>
        <button class="btn btn-danger" id="lock-disable-btn" onclick="disableLock()" style="display:none">Disable</button>
        <span id="lock-state" style="font-size:12px;color:var(--muted)"></span>
      </div>
      <label style="margin-top:12px">Biometric Unlock</label>
      <div style="font-size:11px;color:var(--muted);margin:2px 0 8px">Unlock with Touch&nbsp;ID, Face&nbsp;ID or Windows&nbsp;Hello instead of typing the master password every time. The key never leaves this device's secure enclave, and the password always stays available as a fallback.</div>
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
        <button class="btn" id="bio-enroll-btn" onclick="bioEnroll()" style="display:none">Enable biometric</button>
        <button class="btn btn-danger" id="bio-remove-btn" onclick="bioRemove()" style="display:none">Remove</button>
        <span id="bio-state" style="font-size:12px;color:var(--muted)"></span>
      </div>
    </div>
    <label>Vault File Path</label>
    <input id="set-vault">
    <label>AGE Key File</label>
    <div class="masked-field">
      <input id="set-keyfile" type="password" autocomplete="off">
      <button class="masked-btn" onclick="copyMasked('set-keyfile')" title="Copy">&#128203;</button>
      <button class="masked-btn" onclick="toggleMasked('set-keyfile','eye-keyfile')" title="Show/hide" id="eye-keyfile">&#128065;</button>
    </div>
    <label>AGE Public Key</label>
    <div class="masked-field">
      <input id="set-pubkey" type="password" autocomplete="off">
      <button class="masked-btn" onclick="copyMasked('set-pubkey')" title="Copy">&#128203;</button>
      <button class="masked-btn" onclick="toggleMasked('set-pubkey','eye-pubkey')" title="Show/hide" id="eye-pubkey">&#128065;</button>
    </div>
    <div class="modal-actions">
      <button class="btn" onclick="closeModal('settings-modal')">Cancel</button>
      <button class="btn btn-accent" onclick="saveSettings()">Save</button>
    </div>
  </div>
</div>

<!-- Confirm Modal -->
<div class="modal-overlay" id="confirm-modal">
  <div class="modal" style="text-align:center">
    <p id="confirm-msg" style="font-size:15px;margin-bottom:18px"></p>
    <div class="modal-actions" style="justify-content:center">
      <button class="btn" onclick="confirmResolve(false)">Cancel</button>
      <button class="btn btn-danger" onclick="confirmResolve(true)">Delete</button>
    </div>
  </div>
</div>

<!-- Generate Modal -->
<div class="modal-overlay" id="generate-modal">
  <div class="modal" style="max-width:700px;max-height:85vh;display:flex;flex-direction:column">
    <div style="display:flex;justify-content:space-between;align-items:center;flex-shrink:0">
      <h2>Generate Keys &amp; Passwords</h2>
      <button class="btn btn-accent" onclick="regenerateAll()">Regenerate</button>
    </div>
    <div style="margin-top:4px;font-size:11px;color:var(--muted);flex-shrink:0">Click any key to copy. All generation is local using Python <code>secrets</code> module.</div>
    <div class="gen-grid" id="gen-grid"></div>
    <div class="modal-actions">
      <button class="btn" onclick="closeModal('generate-modal')">Close</button>
    </div>
  </div>
</div>

<!-- Import Modal -->
<div class="modal-overlay" id="import-modal">
  <div class="modal" style="max-width:500px">
    <h2>Import Secrets</h2>
    <label>Format</label>
    <select class="format-select" id="import-format">
      <option value="auto">Auto-detect</option>
      <option value="env">.env (KEY=value)</option>
      <option value="json">JSON</option>
      <option value="yaml">YAML</option>
    </select>
    <label>Service name (for .env import)</label>
    <input id="import-service" placeholder="e.g. aws, github (leave empty for 'imported')">
    <label>Paste your secrets</label>
    <textarea class="import-textarea" id="import-text" placeholder="API_KEY=sk-abc123&#10;DATABASE_URL=postgres://...&#10;&#10;or paste JSON/YAML"></textarea>
    <div class="modal-actions">
      <button class="btn" onclick="closeModal('import-modal')">Cancel</button>
      <button class="btn btn-accent" onclick="doImport()">Import</button>
    </div>
  </div>
</div>

<!-- Export Modal -->
<div class="modal-overlay" id="export-modal">
  <div class="modal">
    <h2>Export Vault</h2>
    <p style="font-size:13px;color:var(--danger);margin-bottom:10px">This will create a file with your secrets in plaintext. Handle with care.</p>
    <label>Format</label>
    <select class="format-select" id="export-format">
      <option value="env">.env</option>
      <option value="json">JSON</option>
      <option value="yaml">YAML</option>
    </select>
    <div class="modal-actions">
      <button class="btn" onclick="closeModal('export-modal')">Cancel</button>
      <button class="btn btn-accent" onclick="doExport()">Download</button>
    </div>
  </div>
</div>

<!-- About Modal -->
<div class="modal-overlay" id="about-modal">
  <div class="modal">
    <h2>About</h2>
    <div id="about-content" style="font-size:13px;line-height:1.8">Loading...</div>
    <div class="modal-actions" style="margin-top:16px">
      <a class="btn" href='""" + REPO_URL + r"""' target="_blank" rel="noopener">GitHub</a>
      <a class="btn" href='""" + SUPPORT_URL + r"""' target="_blank" rel="noopener">&hearts; Support</a>
      <button class="btn btn-accent" onclick="closeModal('about-modal')">Close</button>
    </div>
  </div>
</div>

<div class="toast-container" id="toasts"></div>

<script>
const CLIPBOARD_CLEAR_MS = """ + str(CLIPBOARD_CLEAR_MS) + r""";
const TOAST_DURATION_MS = """ + str(TOAST_DURATION_MS) + r""";

let vaultData = {};
let revealedKeys = {};

// Bearer token wrapper — inject Authorization header for /api/* if the server requires
// auth (set via PX_SECRETS_AUTH_TOKEN env). On a 401 the user is prompted once; the
// token is then cached in sessionStorage for the rest of the tab's lifetime so it
// doesn't follow the user across browser restarts.
(function(){
  const _origFetch = window.fetch;
  window.fetch = function(url, options){
    const u = typeof url === 'string' ? url : (url && url.url);
    if (u && u.startsWith('/api/')) {
      const token = sessionStorage.getItem('px_secrets_token');
      if (token) {
        options = options || {};
        options.headers = Object.assign({}, options.headers || {}, {'Authorization': 'Bearer ' + token});
      }
    }
    return _origFetch.call(this, url, options).then(function(resp){
      if (resp.status === 401 && u && u.startsWith('/api/') && !u.startsWith('/api/session') && !u.startsWith('/api/lock')) {
        return _origFetch.call(window, '/api/lock/status').then(function(r){return r.json();}).then(function(st){
          if (st && st.enabled) { if (typeof showLockScreen === 'function') showLockScreen(st, 'unlock'); return resp; }
          sessionStorage.removeItem('px_secrets_token');
          const token = prompt('API authentication required. Paste your PX_SECRETS_AUTH_TOKEN:');
          if (token) { sessionStorage.setItem('px_secrets_token', token.trim()); location.reload(); }
          return resp;
        }).catch(function(){ return resp; });
      }
      return resp;
    });
  };
})();
let openCards = new Set();
let openGroups = new Set();

// ---- Biometric unlock (Touch ID / Face ID / Windows Hello) ----
// Base64URL <-> ArrayBuffer, because WebAuthn speaks ArrayBuffer and JSON does not.
function _b64uToBuf(s){
  const pad = '='.repeat((4 - s.length % 4) % 4);
  const bin = atob((s + pad).replace(/-/g,'+').replace(/_/g,'/'));
  const b = new Uint8Array(bin.length);
  for (let i=0;i<bin.length;i++) b[i] = bin.charCodeAt(i);
  return b.buffer;
}
function _bufToB64u(buf){
  const b = new Uint8Array(buf); let s = '';
  for (let i=0;i<b.length;i++) s += String.fromCharCode(b[i]);
  return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
function bioSupported(){
  return !!(window.PublicKeyCredential && navigator.credentials && navigator.credentials.create);
}

// The WebAuthn API existing is NOT the same as a usable fingerprint/face sensor.
// Embedded webviews and "add to dock" web apps expose the API but have no platform
// authenticator behind it, so navigator.credentials.create() rejects instantly with
// NotAllowedError — indistinguishable from the user hitting Cancel. Ask first.
async function bioPlatformAvailable(){
  if (!bioSupported()) return false;
  try {
    return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  } catch(e){ return false; }
}

// Reveal the lock-screen biometric button only when something is actually enrolled.
async function refreshBioUI(){
  const btn = document.getElementById('bio-btn');
  const st  = document.getElementById('bio-state');
  const enr = document.getElementById('bio-enroll-btn');
  const rem = document.getElementById('bio-remove-btn');
  let d = {enrolled:false, credentials:[]};
  try { d = await (await window.fetch('/api/webauthn/status')).json(); } catch(e){}
  const hasApi = bioSupported();
  const usable = await bioPlatformAvailable();
  if (btn) btn.style.display = (d.enrolled && usable) ? '' : 'none';
  if (st){
    if (!hasApi)       st.textContent = 'Not supported by this browser';
    else if (!usable)  st.textContent = 'No fingerprint/face sensor available in this window. Open the app in Safari or Chrome at http://localhost:' + location.port + ' to enrol.';
    else if (d.enrolled) st.textContent = 'ON — ' + d.credentials.map(c=>c.label).join(', ');
    else               st.textContent = 'OFF';
  }
  if (enr) enr.style.display = (usable && !d.enrolled) ? '' : 'none';
  if (rem) rem.style.display = d.enrolled ? '' : 'none';
  return d;
}

async function bioUnlock(){
  const err = document.getElementById('lock-err');
  try {
    const opts = await (await window.fetch('/api/webauthn/auth/begin', {method:'POST'})).json();
    if (opts.error){ if(err) err.textContent = opts.error; return; }
    const assertion = await navigator.credentials.get({publicKey: {
      challenge: _b64uToBuf(opts.challenge),
      timeout: opts.timeout,
      userVerification: opts.userVerification,
      allowCredentials: (opts.allowCredentials||[]).map(c=>({type:'public-key', id:_b64uToBuf(c.id)})),
    }});
    const r = await (await window.fetch('/api/webauthn/auth/finish', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({
        id: assertion.id,
        clientDataJSON:    _bufToB64u(assertion.response.clientDataJSON),
        authenticatorData: _bufToB64u(assertion.response.authenticatorData),
        signature:         _bufToB64u(assertion.response.signature),
      })})).json();
    if (r.error){ if(err) err.textContent = r.error; return; }
    hideLockScreen(); startIdleWatch(); await loadVaults(); loadVault();
  } catch(e){
    // A user cancelling the prompt is not an error worth shouting about.
    if (err) err.textContent = (e && e.name === 'NotAllowedError') ? 'Biometric cancelled' : ('Biometric failed: ' + e);
  }
}

async function bioEnroll(){
  // Check for a real sensor first. Without this, an embedded webview rejects with
  // NotAllowedError and the user just sees "Enrolment cancelled" forever, with no
  // hint that the window itself is the problem rather than their finger.
  if (!(await bioPlatformAvailable())){
    toast('This window has no fingerprint or face sensor available. Open the app in Safari or Chrome at http://localhost:' + location.port + ' and enrol there.', 'error');
    return;
  }
  try {
    const opts = await (await window.fetch('/api/webauthn/register/begin', {method:'POST'})).json();
    if (opts.error){ toast(opts.error, 'error'); return; }
    const cred = await navigator.credentials.create({publicKey: {
      challenge: _b64uToBuf(opts.challenge),
      rp: opts.rp,
      user: {id:_b64uToBuf(opts.user.id), name:opts.user.name, displayName:opts.user.displayName},
      pubKeyCredParams: opts.pubKeyCredParams,
      timeout: opts.timeout,
      attestation: opts.attestation,
      authenticatorSelection: opts.authenticatorSelection,
      excludeCredentials: (opts.excludeCredentials||[]).map(c=>({type:'public-key', id:_b64uToBuf(c.id)})),
    }});
    // getPublicKey() hands us SPKI DER directly — no CBOR attestation parsing needed.
    const spki = cred.response.getPublicKey ? cred.response.getPublicKey() : null;
    if (!spki){ toast('This browser cannot export the public key (needs a newer version)', 'error'); return; }
    const r = await (await window.fetch('/api/webauthn/register/finish', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({
        id: cred.id,
        clientDataJSON: _bufToB64u(cred.response.clientDataJSON),
        publicKey: _bufToB64u(spki),
        label: (navigator.platform || 'this device'),
      })})).json();
    if (r.error){ toast(r.error, 'error'); return; }
    toast('Biometric unlock enabled');
    await refreshBioUI();
  } catch(e){
    toast((e && e.name === 'NotAllowedError') ? 'Enrolment cancelled' : ('Enrolment failed: ' + e), 'error');
  }
}

async function bioRemove(){
  const d = await (await window.fetch('/api/webauthn/status')).json();
  for (const c of (d.credentials||[])){
    await window.fetch('/api/webauthn/credential', {method:'DELETE',
      headers:{'Content-Type':'application/json'}, body: JSON.stringify({id:c.id})});
  }
  toast('Biometric unlock removed');
  await refreshBioUI();
}

// ---- App lock (issue #19): master-password gate + idle auto-lock ----
let _lockMode = 'unlock';
let _idleTimer = null, _idleMs = 300000, _idleBound = false;

async function refreshLockUI(){
  let st = {enabled:false, locked:false, idle_timeout_s:300};
  try { st = await (await window.fetch('/api/lock/status')).json(); } catch(e) {}
  _idleMs = (st.idle_timeout_s || 300) * 1000;
  const ic = document.getElementById('lock-icon');
  if (ic) ic.style.display = st.enabled ? '' : 'none';
  const en = document.getElementById('lock-enable-btn');
  const dis = document.getElementById('lock-disable-btn');
  const ls = document.getElementById('lock-state');
  if (en) en.style.display = st.enabled ? 'none' : '';
  if (dis) dis.style.display = st.enabled ? '' : 'none';
  if (ls) ls.textContent = st.enabled ? ('ON — auto-locks after ' + Math.round((st.idle_timeout_s||300)/60) + ' min idle') : 'OFF';
  refreshBioUI();
  return st;
}

function showLockScreen(st, mode){
  _lockMode = mode || 'unlock';
  const setup = _lockMode === 'setup';
  document.getElementById('lock-title').textContent = setup ? 'Set app lock' : 'Locked';
  document.getElementById('lock-sub').textContent = setup
    ? 'Choose a master password (min 6 chars). It opens the app and auto-locks when idle. Separate from your AGE key.'
    : 'Enter your master password to view the vault.';
  document.getElementById('lock-pass2').style.display = setup ? '' : 'none';
  document.getElementById('lock-btn').textContent = setup ? 'Enable lock' : 'Unlock';
  document.getElementById('lock-err').textContent = '';
  document.getElementById('lock-pass').value = '';
  document.getElementById('lock-pass2').value = '';
  document.getElementById('lock-screen').style.display = 'flex';
  setTimeout(function(){ document.getElementById('lock-pass').focus(); }, 50);
}

function hideLockScreen(){ document.getElementById('lock-screen').style.display = 'none'; }

async function lockSubmit(){
  const pass = document.getElementById('lock-pass').value;
  const err = document.getElementById('lock-err');
  if (_lockMode === 'setup'){
    const pass2 = document.getElementById('lock-pass2').value;
    if (pass.length < 6){ err.textContent = 'Password must be at least 6 characters'; return; }
    if (pass !== pass2){ err.textContent = 'Passwords do not match'; return; }
    const d = await (await fetch('/api/lock/setup', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({password:pass})})).json();
    if (d.error){ err.textContent = d.error; return; }
    // loadVaults() must run here too: initApp() returns early while the app is
    // locked, so this is the only place the vault switcher gets populated after
    // an unlock. Without it the switcher stays display:none and the user can
    // create vaults but never see or switch between them.
    hideLockScreen(); await refreshLockUI(); startIdleWatch(); toast('App lock enabled'); await loadVaults(); loadVault();
  } else {
    const d = await (await fetch('/api/session', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({password:pass})})).json();
    if (d.error){ err.textContent = d.error || 'Incorrect password'; return; }
    hideLockScreen(); startIdleWatch(); await loadVaults(); loadVault();
  }
}

async function lockApp(){
  try { await fetch('/api/session', {method:'DELETE'}); } catch(e) {}
  clearTimeout(_idleTimer);
  showLockScreen({}, 'unlock');
}

function enableLock(){ showLockScreen({}, 'setup'); }

async function disableLock(){
  if (!confirm('Disable the app lock? Anyone who opens the app on this machine will see the vault.')) return;
  const d = await (await fetch('/api/lock/disable', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({})})).json();
  if (d.error){ toast(d.error); return; }
  clearTimeout(_idleTimer);
  await refreshLockUI(); toast('App lock disabled');
}

function startIdleWatch(){
  clearTimeout(_idleTimer);
  const reset = function(){ clearTimeout(_idleTimer); _idleTimer = setTimeout(lockApp, _idleMs); };
  if (!_idleBound){ ['mousemove','keydown','click','touchstart'].forEach(function(ev){ document.addEventListener(ev, reset, {passive:true}); }); _idleBound = true; }
  reset();
}

// --- multi-vault (Issue #21): active vault + X-Vault header on data calls ---
let currentVault = null;
function vfetch(url, opts){
  opts = opts || {};
  opts.headers = Object.assign({}, opts.headers || {}, currentVault ? {'X-Vault': currentVault} : {});
  return fetch(url, opts);
}
async function loadVaults(){
  try {
    const d = await (await fetch('/api/vaults')).json();
    const vs = d.vaults || [];
    const sel = document.getElementById('vault-switcher');
    if (!sel) return;
    if (!vs.length){ sel.style.display='none'; currentVault = null; return; }
    if (!currentVault || !vs.find(v=>v.id===currentVault))
      currentVault = (vs.find(v=>v.id==='default') || vs[0]).id;
    sel.innerHTML = vs.map(v =>
      `<option value="${v.id}"${v.id===currentVault?' selected':''}>${v.name}${v.agent_access==='deny'?' \u{1F512}':''}</option>`
    ).join('');
    sel.style.display='';
  } catch(e){
    // Never swallow this silently: an empty catch here is why a hidden switcher
    // looked like "the feature does not exist" instead of "the call failed".
    console.error('loadVaults failed:', e);
    toast('Could not load vault list: ' + (e && e.message ? e.message : e), 'error');
  }
}
async function switchVault(id){ currentVault = id; await loadVault(); }
async function createVaultPrompt(){
  const name = prompt('New vault name (e.g. Work, Personal):');
  if (!name) return;
  const d = await (await fetch('/api/vaults', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({name})})).json();
  if (d.error){ toast(d.error); return; }
  currentVault = d.id;
  toast('Vault "' + name + '" created');
  await loadVaults();
  await loadVault();
}

// CSS cannot rewrite a placeholder, so shorten it in JS on narrow viewports.
// "Search services or keys..." is the single widest item in the toolbar.
function adaptSearchPlaceholder(){
  const s = document.getElementById('search');
  if (!s) return;
  const w = window.innerWidth;
  s.placeholder = w < 480 ? 'Search...' : (w < 760 ? 'Search keys...' : 'Search services or keys...');
}
window.addEventListener('resize', adaptSearchPlaceholder);

async function initApp(){
  adaptSearchPlaceholder();
  const st = await refreshLockUI();
  if (st.enabled && st.locked){ showLockScreen(st, 'unlock'); return; }
  if (st.enabled){ startIdleWatch(); }
  await loadVaults();
  loadVault();
}

async function loadVault() {
  try {
    const r = await vfetch('/api/vault');
    const d = await r.json();
    if (d.error) { toast(d.error); return; }
    vaultData = d;
    render();
  } catch(e) { toast('Failed to load vault'); }
}

function valIsObject(v){ return v !== null && typeof v === 'object' && !Array.isArray(v); }
// Walk vaultData along an array path [svc, ...keys]. No string parsing, so key
// names containing the legacy '::' separator can never resolve the wrong node.
function resolveByPath(path){
  let cur = vaultData;
  for (const s of path){ if (cur == null) return undefined; cur = cur[s]; }
  return cur;
}
// Stable, unambiguous UI-state key for a path (arrays of strings serialize 1:1).
function pkey(path){ return JSON.stringify(path); }

// Count scalar leaves under obj. 'description' is metadata only when nested (a
// group caption); at the flat service level (depth 1) it is a normal key.
function countLeaves(obj, depth){
  let n = 0;
  for (const k of Object.keys(obj)){
    if (k.endsWith('__note')) continue;
    if (depth > 1 && k === 'description') continue;
    if (valIsObject(obj[k])) n += countLeaves(obj[k], depth + 1); else n += 1;
  }
  return n;
}
// Match a query against key names + description/note TEXT only — never against
// secret values (matching values would silently reveal whether a value contains q).
function groupMatches(obj, q){
  for (const k of Object.keys(obj)){
    if (k.toLowerCase().includes(q)) return true;
    const v = obj[k];
    if (valIsObject(v)){ if (groupMatches(v, q)) return true; }
    else if (typeof v === 'string' && (k === 'description' || k.endsWith('__note')) && v.toLowerCase().includes(q)) return true;
  }
  return false;
}

// Per-render registry: integer id -> structured path array. Reset every render().
// All interactions are wired through ONE delegated click handler that reads the
// integer data-idx and looks up the path here — NO secret/key/service text is ever
// interpolated into an onclick / JS-string sink. This removes the HTML-attribute
// breakout XSS class entirely AND the '::'/gid string-collision hazards.
let renderPaths = [];

// Recursively render an object's entries. pathArr = segments from service to obj.
// depth 1 = service-level (flat secrets keep full CRUD); depth>1 = nested provider
// structures, rendered read-only (Show/Copy) — writes stay in SOPS, the source of truth.
function renderEntries(obj, pathArr, depth){
  if (depth > 8) return '';  // guard against pathological nesting depth
  let html = '';
  // 'description' is the group caption (shown above the rows) only when nested.
  const keys = Object.keys(obj).filter(k => !k.endsWith('__note') && !(depth > 1 && k === 'description'));
  for (const k of keys){
    const val = obj[k];
    const path = pathArr.concat([k]);
    const idx = renderPaths.push(path) - 1;
    if (valIsObject(val)){
      const childKeys = Object.keys(val).filter(x => !x.endsWith('__note') && x !== 'description');
      const desc = (typeof val.description === 'string') ? val.description : '';
      const gOpen = openGroups.has(pkey(path));
      html += `<div class="key-group">
        <div class="key-group-head" data-act="group" data-idx="${idx}">
          <span class="arrow ${gOpen ? 'open' : ''}">&#9654;</span>
          <span class="group-name">${esc(k)}</span>
          <span class="key-count">${childKeys.length} field${childKeys.length!==1?'s':''}</span>
        </div>
        ${desc ? `<div class="group-desc">${esc(desc)}</div>` : ''}
        <div class="key-group-body ${gOpen ? 'open' : ''}">
          ${renderEntries(val, path, depth + 1)}
        </div>
      </div>`;
    } else {
      const note = obj[k + '__note'] || '';
      const shown = revealedKeys[pkey(path)];
      const displayVal = shown ? esc(String(val)) : '••••••••';
      html += `<div class="key-row">
        <div class="key-top">
          <span class="key-name">${esc(k)}</span>
          <span class="key-value ${shown ? 'revealed' : ''}">${displayVal}</span>
          <span class="key-actions">
            <button class="btn btn-sm" data-act="reveal" data-idx="${idx}">${shown ? 'Hide' : 'Show'}</button>
            <button class="btn btn-sm" data-act="copy" data-idx="${idx}">Copy</button>
            <button class="btn btn-sm" data-act="edit" data-idx="${idx}">Edit</button>
            <button class="btn btn-sm" data-act="note" data-idx="${idx}">Note</button>
            <button class="btn btn-danger btn-sm" data-act="del" data-idx="${idx}">Del</button>
          </span>
        </div>
        ${note ? `<div class="key-note" data-act="note" data-idx="${idx}">${esc(note)}</div>` : ''}
      </div>`;
    }
  }
  return html;
}

function render() {
  const q = document.getElementById('search').value.toLowerCase();
  const container = document.getElementById('cards');
  container.innerHTML = '';
  renderPaths = [];
  let svcCount = 0, keyCount = 0;
  const services = Object.keys(vaultData).sort();
  for (const svc of services) {
    if (q && !svc.toLowerCase().includes(q) && !groupMatches(vaultData[svc], q)) continue;
    svcCount++;
    const leaves = countLeaves(vaultData[svc], 1);
    keyCount += leaves;

    const card = document.createElement('div');
    card.className = 'card';
    const cidx = renderPaths.push([svc]) - 1;
    const isOpen = openCards.has(svc);

    let headerHTML = `<div class="card-header" data-act="card" data-idx="${cidx}">
      <span class="arrow ${isOpen ? 'open' : ''}">&#9654;</span>
      <span class="svc-name">${esc(svc)}</span>
      <span class="key-count">${leaves} key${leaves!==1?'s':''}</span>
      <button class="btn btn-danger btn-sm" data-act="delsvc" data-idx="${cidx}">Del</button>
    </div>`;

    let bodyHTML = `<div class="card-body ${isOpen ? 'open' : ''}">`;
    bodyHTML += renderEntries(vaultData[svc], [svc], 1);
    bodyHTML += '</div>';
    card.innerHTML = headerHTML + bodyHTML;
    container.appendChild(card);
  }
  document.getElementById('status-bar').textContent = `${svcCount} service${svcCount!==1?'s':''}, ${keyCount} key${keyCount!==1?'s':''} — encrypted with AGE`;
  updateServiceHints();
}

// Single delegated handler for every vault interaction. It reads the integer
// data-idx, looks up the structured path, and dispatches by data-act. Because the
// handler is bound to the (stable) #cards container, it survives the innerHTML
// rebuilds that render() performs on each toggle.
async function onCardsClick(e){
  const el = e.target.closest('[data-act]');
  if (!el) return;
  const act = el.dataset.act;
  const path = renderPaths[+el.dataset.idx];
  if (!path) return;
  if (act === 'card'){ if (openCards.has(path[0])) openCards.delete(path[0]); else openCards.add(path[0]); render(); return; }
  if (act === 'group'){ const pk = pkey(path); if (openGroups.has(pk)) openGroups.delete(pk); else openGroups.add(pk); render(); return; }
  if (act === 'reveal'){ const pk = pkey(path); revealedKeys[pk] = !revealedKeys[pk]; render(); return; }
  if (act === 'copy'){
    const v = resolveByPath(path);
    if (v === undefined || valIsObject(v)) { toast('Cannot copy a group'); return; }
    await navigator.clipboard.writeText(String(v));
    toast('Copied to clipboard — auto-clears in ' + (CLIPBOARD_CLEAR_MS / 1000) + 's');
    setTimeout(() => navigator.clipboard.writeText('').catch(()=>{}), CLIPBOARD_CLEAR_MS);
    return;
  }
  if (act === 'edit'){ showEditModal(path); return; }
  if (act === 'note'){ showNoteModal(path); return; }
  if (act === 'del'){ deleteKey(path); return; }
  if (act === 'delsvc'){ deleteService(path[0]); return; }
}

async function copyVal(svc, key) {
  const val = String(vaultData[svc][key]);
  await navigator.clipboard.writeText(val);
  toast('Copied to clipboard \u2014 auto-clears in ' + (CLIPBOARD_CLEAR_MS / 1000) + 's');
  setTimeout(() => navigator.clipboard.writeText('').catch(()=>{}), CLIPBOARD_CLEAR_MS);
}

function updateServiceHints() {
  const chips = document.getElementById('svc-chips');
  if (!chips) return;
  const services = Object.keys(vaultData).sort();
  chips.innerHTML = services.map(s =>
    `<span class="svc-chip" onclick="document.getElementById('add-service').value='${escAttr(s)}'">${esc(s)}</span>`
  ).join('');
}

let editMode = false;
let editPath = null;   // full path array of the secret being edited (flat or nested)
let notePath = null;   // full path array for the note modal
// Resolve the existing note text for a leaf path: parent[leaf + '__note'].
function noteAt(path){
  const parent = resolveByPath(path.slice(0, -1));
  const leaf = path[path.length - 1];
  return (parent && parent[leaf + '__note']) || '';
}

function showAddModal() {
  editMode = false;
  editPath = null;
  document.getElementById('add-modal-title').textContent = 'Add Secret';
  document.getElementById('add-service').value = '';
  document.getElementById('add-key').value = '';
  document.getElementById('add-value').value = '';
  document.getElementById('add-note').value = '';
  document.getElementById('add-service').readOnly = false;
  document.getElementById('add-key').readOnly = false;
  document.getElementById('add-value').placeholder = 'secret value';
  updateServiceHints();
  document.getElementById('add-modal').classList.add('show');
  document.getElementById('add-service').focus();
}

function showEditModal(path) {
  editMode = true;
  editPath = path;
  document.getElementById('add-modal-title').textContent = 'Edit Secret';
  // Location is read-only (edit value/note only). For nested paths the parent
  // chain is shown as "service / tenant" and the leaf key separately.
  document.getElementById('add-service').value = path.slice(0, -1).join(' / ');
  document.getElementById('add-key').value = path[path.length - 1];
  document.getElementById('add-value').value = '';
  document.getElementById('add-note').value = noteAt(path);
  document.getElementById('add-service').readOnly = true;
  document.getElementById('add-key').readOnly = true;
  document.getElementById('add-value').placeholder = 'new value (replaces current)';
  document.getElementById('add-modal').classList.add('show');
  document.getElementById('add-value').focus();
}

async function addSecret() {
  const val = document.getElementById('add-value').value;
  const note = document.getElementById('add-note').value.trim();
  let payload;
  if (editMode && editPath) {
    if (!val) { toast('A new value is required'); return; }
    payload = {path: editPath, value: val, note, overwrite: true};
  } else {
    const svc = document.getElementById('add-service').value.trim();
    const key = document.getElementById('add-key').value.trim();
    if (!svc || !key || !val) { toast('Service, key, and value are required'); return; }
    payload = {service: svc, key, value: val, note};
  }
  const r = await vfetch('/api/secret', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload)});
  const d = await r.json();
  if (d.error) { toast(d.error); return; }
  closeModal('add-modal');
  toast(editMode ? 'Secret updated in vault' : 'Secret added successfully to vault');
  loadVault();
}

let _confirmCb = null;
function confirmResolve(val) {
  document.getElementById('confirm-modal').classList.remove('show');
  if (_confirmCb) { _confirmCb(val); _confirmCb = null; }
}
function showConfirm(msg) {
  return new Promise(resolve => {
    _confirmCb = resolve;
    document.getElementById('confirm-msg').textContent = msg;
    document.getElementById('confirm-modal').classList.add('show');
  });
}

async function deleteKey(path) {
  const ok = await showConfirm(`Delete ${path.join(' / ')}?`);
  if (!ok) return;
  const r = await vfetch('/api/secret', {method:'DELETE', headers:{'Content-Type':'application/json'}, body:JSON.stringify({path})});
  const d = await r.json();
  if (d.error) { toast(d.error); return; }
  toast('Secret deleted successfully');
  loadVault();
}

async function deleteService(svc) {
  const ok = await showConfirm(`Delete entire service "${svc}" and all its keys?`);
  if (!ok) return;
  const r = await vfetch('/api/service/' + encodeURIComponent(svc), {method:'DELETE'});
  const d = await r.json();
  if (d.error) { toast(d.error); return; }
  toast('Service and all keys deleted successfully');
  loadVault();
}

function showNoteModal(path) {
  notePath = path;
  document.getElementById('note-text').value = noteAt(path);
  document.getElementById('note-modal').classList.add('show');
}

async function saveNote() {
  if (!notePath) { toast('No secret selected'); return; }
  const note = document.getElementById('note-text').value.trim();
  const r = await vfetch('/api/note', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({path: notePath, note})});
  const d = await r.json();
  if (d.error) { toast(d.error); return; }
  closeModal('note-modal');
  toast('Note saved successfully');
  loadVault();
}

function showSettingsModal() {
  fetch('/api/settings').then(r=>r.json()).then(d => {
    document.getElementById('set-vault').value = d.vault_path || '';
    const kf = document.getElementById('set-keyfile');
    const pk = document.getElementById('set-pubkey');
    kf.value = d.age_key_file || '';
    pk.value = d.age_public_key || '';
    kf.type = 'password'; document.getElementById('eye-keyfile').style.color = '';
    pk.type = 'password'; document.getElementById('eye-pubkey').style.color = '';
    document.getElementById('settings-modal').classList.add('show');
  });
}

async function saveSettings() {
  const cfg = {
    vault_path: document.getElementById('set-vault').value.trim(),
    age_key_file: document.getElementById('set-keyfile').value.trim(),
    age_public_key: document.getElementById('set-pubkey').value.trim(),
  };
  const r = await fetch('/api/settings', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(cfg)});
  const d = await r.json();
  if (d.error) { toast(d.error); return; }
  closeModal('settings-modal');
  toast('Settings saved \u2014 vault reloaded');
  loadVault();
}

function closeModal(id) { document.getElementById(id).classList.remove('show'); }

function copyMasked(inputId) {
  const val = document.getElementById(inputId).value;
  if (!val) { toast('Nothing to copy'); return; }
  navigator.clipboard.writeText(val).then(() => toast('Copied \u2014 will clear in 30s'));
  setTimeout(() => navigator.clipboard.writeText(''), 30000);
}

function toggleMasked(inputId, eyeId) {
  const el = document.getElementById(inputId);
  const btn = document.getElementById(eyeId);
  if (el.type === 'password') { el.type = 'text'; btn.style.color = 'var(--accent)'; }
  else { el.type = 'password'; btn.style.color = ''; }
}

// kind: 'ok' (default) or 'error'. Callers that report a failure MUST pass 'error',
// otherwise the message renders in success green and reads as if it worked.
function toast(msg, kind) {
  const c = document.getElementById('toasts');
  const t = document.createElement('div');
  // Heuristic safety net for existing call sites that never learned about `kind`:
  // if the text plainly announces a failure, colour it as one.
  const looksBad = /\b(fail(ed|ure)?|error|denied|cannot|could not|invalid|unable|refused|not supported)\b/i.test(String(msg));
  t.className = 'toast' + ((kind === 'error' || (kind === undefined && looksBad)) ? ' toast-error' : '');
  t.textContent = msg;
  c.appendChild(t);
  requestAnimationFrame(() => t.classList.add('show'));
  setTimeout(() => { t.classList.remove('show'); setTimeout(() => t.remove(), 300); }, TOAST_DURATION_MS);
}

function esc(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
// Escape a value used as a JS string literal inside a DOUBLE-quoted HTML attribute
// (e.g. onclick="fn('VALUE')"). Two layers: JS-string-escape (\\ and ') FIRST, then
// HTML-attribute-escape (&, ", <, >) so the value cannot break out of the attribute
// or the JS string. The browser HTML-decodes the entities back to literals inside the
// (single-quoted) JS string, where they are harmless. Vault rows no longer use this
// (they go through data-idx + delegated dispatch); kept for the generator's inline onclick.
function escAttr(s) { return String(s).replace(/\\/g,'\\\\').replace(/'/g,"\\'").replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

document.getElementById('search').addEventListener('input', render);
document.getElementById('cards').addEventListener('click', onCardsClick);

// Close modals on overlay click
document.querySelectorAll('.modal-overlay').forEach(el => {
  el.addEventListener('click', e => { if (e.target === el) el.classList.remove('show'); });
});

// Generator
const GEN_LABELS = {
  memorable: ['Memorable', '~20 chars'],
  strong: ['Strong', '16 chars'],
  fort_knox: ['Fort Knox', '32 chars'],
  alphanumeric: ['Alphanumeric', '24 chars'],
  hex_128: ['128-bit Hex', '32 hex'],
  hex_256: ['256-bit Hex', '64 hex'],
  uuid_v4: ['UUID v4', '36 chars'],
  api_keys: ['API Keys', '48 chars'],
  jwt_secret: ['JWT Secret', '64 chars']
};

let genData = {};

function showGenerateModal() {
  document.getElementById('generate-modal').classList.add('show');
  regenerateAll();
}

async function regenerateAll() {
  const r = await fetch('/api/generate');
  genData = await r.json();
  renderGenerator();
}

function renderGenerator() {
  const grid = document.getElementById('gen-grid');
  grid.innerHTML = '';
  for (const [cat, [label, size]] of Object.entries(GEN_LABELS)) {
    const vals = genData[cat] || [];
    let html = `<div class="gen-category"><h3>${label} <span>${size}</span></h3>`;
    for (const v of vals) {
      html += `<div class="gen-item" onclick="copyGenKey(this, '${escAttr(v)}')" title="Click to copy">${esc(v)}</div>`;
    }
    html += '</div>';
    grid.innerHTML += html;
  }
}

async function copyGenKey(el, val) {
  await navigator.clipboard.writeText(val);
  el.style.borderColor = 'var(--success)';
  el.style.color = 'var(--success)';
  toast('Copied to clipboard');
  setTimeout(() => { el.style.borderColor = ''; el.style.color = ''; }, 1000);
}

// Import
function showImportModal() {
  document.getElementById('import-text').value = '';
  document.getElementById('import-service').value = '';
  document.getElementById('import-format').value = 'auto';
  document.getElementById('import-modal').classList.add('show');
}

async function doImport() {
  const text = document.getElementById('import-text').value.trim();
  const fmt = document.getElementById('import-format').value;
  const service = document.getElementById('import-service').value.trim();
  if (!text) { toast('Paste some secrets first'); return; }
  const r = await fetch('/api/import', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({text, format: fmt, service})});
  const d = await r.json();
  if (d.error) { toast(d.error); return; }
  closeModal('import-modal');
  toast(`Imported ${d.imported} secret${d.imported !== 1 ? 's' : ''} successfully`);
  loadVault();
}

// Export
function showExportModal() {
  document.getElementById('export-format').value = 'env';
  document.getElementById('export-modal').classList.add('show');
}

function doExport() {
  const fmt = document.getElementById('export-format').value;
  closeModal('export-modal');
  window.open('/api/export?format=' + fmt, '_blank');
}

async function showAboutModal() {
  const el = document.getElementById('about-content');
  el.textContent = 'Loading...';
  document.getElementById('about-modal').classList.add('show');
  try {
    const r = await fetch('/api/about');
    const d = await r.json();
    const authBadge = d.auth_required ? '<span style="color:var(--accent);font-size:11px">&#128274; auth required</span>' : '';
    const roBadge = d.read_only ? '<span style="color:var(--muted);font-size:11px">read-only</span>' : '';
    el.innerHTML = `
      <div style="display:grid;grid-template-columns:auto 1fr;gap:4px 12px">
        <span style="color:var(--muted)">App</span><span style="color:var(--accent);font-weight:600">${d.app} ${authBadge} ${roBadge}</span>
        <span style="color:var(--muted)">Version</span><span>${d.version}</span>
        <span style="color:var(--muted)">License</span><span>${d.license}</span>
        <span style="color:var(--muted)">Python</span><span class="mono">${d.python}</span>
        <span style="color:var(--muted)">Platform</span><span class="mono" style="font-size:12px">${d.platform}</span>
        <span style="color:var(--muted)">Arch</span><span class="mono">${d.arch}</span>
      </div>
      <p style="margin-top:12px;color:var(--muted);font-size:12px">
        No telemetry. No cloud. No network calls.<br>
        Your secrets stay on your machine, period.
      </p>
      <div style="margin-top:14px;padding-top:12px;border-top:1px solid var(--border)">
        <button class="btn btn-accent" onclick="checkForUpdates()">Check for updates</button>
        <div id="update-status" style="margin-top:8px;font-size:12px;color:var(--muted)"></div>
      </div>`;
  } catch(e) { el.textContent = 'Error loading info'; }
}

async function checkForUpdates() {
  const status = document.getElementById('update-status');
  status.style.color = 'var(--muted)';
  status.textContent = 'Checking GitHub...';
  try {
    const r = await fetch('/api/check-update');
    const d = await r.json();
    if (d.error) {
      status.style.color = '#e88';
      status.textContent = 'Error: ' + d.error;
      return;
    }
    if (d.has_update) {
      status.style.color = 'var(--accent)';
      status.innerHTML = `<strong>Update available:</strong> v${d.current} &rarr; v${d.latest}<br>
        <a href="${d.release_url}" target="_blank" rel="noopener" style="color:var(--accent);text-decoration:underline">Release notes</a><br>
        <button class="btn btn-accent" style="margin-top:8px" onclick="applyUpdate('${d.latest}')">Update now</button>`;
    } else {
      status.style.color = 'var(--muted)';
      status.textContent = 'You are on the latest version (v' + d.current + ').';
    }
  } catch(e) {
    status.style.color = '#e88';
    status.textContent = 'Failed: ' + e.message;
  }
}

async function applyUpdate(toVersion) {
  if (!confirm('Replace this app with v' + toVersion + '? The server will restart and the page will reload automatically.')) return;
  const status = document.getElementById('update-status');
  status.style.color = 'var(--muted)';
  status.textContent = 'Downloading and applying...';
  try {
    const r = await fetch('/api/apply-update', {method:'POST'});
    const d = await r.json();
    if (d.ok) {
      status.style.color = 'var(--accent)';
      status.innerHTML = '<strong>Updated to v' + d.to + '.</strong> Restarting server...<br>Backup at: <span class="mono" style="font-size:11px">' + d.backup + '</span><br><em>Reloading in 3 seconds.</em>';
      setTimeout(function(){ location.reload(); }, 3500);
    } else {
      status.style.color = '#e88';
      status.textContent = 'Error: ' + (d.error || d.message || 'Unknown failure');
    }
  } catch(e) {
    status.style.color = '#e88';
    status.textContent = 'Failed: ' + e.message;
  }
}

// Keyboard shortcuts
document.addEventListener('keydown', function(e) {
  // Escape — close any open modal
  if (e.key === 'Escape') {
    document.querySelectorAll('.modal-overlay.show').forEach(m => m.classList.remove('show'));
    return;
  }
  // Cmd/Ctrl+K — focus search
  if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
    e.preventDefault();
    document.getElementById('search').focus();
    return;
  }
  // Cmd/Ctrl+N — add secret
  if ((e.metaKey || e.ctrlKey) && e.key === 'n') {
    if (!document.querySelector('.modal-overlay.show')) {
      e.preventDefault();
      showAddModal();
    }
  }
});

initApp();
</script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# CLI mode
# ---------------------------------------------------------------------------


def cli_list():
    """Print all services and their keys to stdout."""
    data = decrypt_vault()
    if not data:
        print("Vault is empty.")
        return
    for svc in sorted(data.keys()):
        keys = [k for k in data[svc] if not k.endswith("__note")]
        print(f"\n  {svc}")
        for k in sorted(keys):
            print(f"    - {k}")
    print()


def cli_get(service: str, key: str):
    """Print a single secret value to stdout (for scripting/piping)."""
    data = decrypt_vault()
    if service not in data:
        print(f"Service '{service}' not found.")
        sys.exit(1)
    if key not in data[service]:
        print(f"Key '{key}' not found in '{service}'.")
        sys.exit(1)
    print(data[service][key])


def cli_help():
    """Print usage information."""
    print(f"""{APP_NAME} v{VERSION} — SOPS + AGE Vault Manager

Usage:
  px_secrets.py                  Launch in browser (default)
  px_secrets.py --native         Launch native window (pywebview)
  px_secrets.py --headless       Server only, no browser
  px_secrets.py --port 8888      Use a custom port
  px_secrets.py --list           List all services and keys
  px_secrets.py --get SVC KEY    Get a specific secret value
  px_secrets.py --help           Show this help
""")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    """Parse CLI arguments and launch the appropriate mode."""
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--get", nargs=2, metavar=("SERVICE", "KEY"))
    parser.add_argument("--native", action="store_true")
    parser.add_argument("--headless", action="store_true")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--help", "-h", action="store_true")
    args = parser.parse_args()

    if args.help:
        cli_help()
        return

    if args.list:
        cli_list()
        return

    if args.get:
        cli_get(args.get[0], args.get[1])
        return

    # GUI mode
    host = HOST_OVERRIDE or DEFAULT_HOST
    port = args.port

    # Store port in app config so /api/open-browser can read it
    app.config["port"] = port

    # Configure macOS app identity (process name, Dock visibility)
    _configure_macos_identity(headless=args.headless)

    if args.native:
        try:
            import webview  # type: ignore
        except ImportError:
            print("pywebview not installed. Install with: pip install pywebview")
            sys.exit(1)

        t = threading.Thread(
            target=lambda: app.run(host=host, port=port, debug=False),
            daemon=True,
        )
        t.start()

        webview.create_window(
            APP_NAME,
            # browse_host(): loopback becomes "localhost" so WebAuthn works, but a
            # deliberate LAN bind is preserved so the window points at a live socket.
            f"http://{browse_host(host)}:{port}",
            width=NATIVE_WINDOW_WIDTH,
            height=NATIVE_WINDOW_HEIGHT,
        )
        webview.start()
    elif args.headless:
        app.run(host=host, port=port, debug=False)
    else:
        threading.Timer(
            BROWSER_OPEN_DELAY,
            lambda: webbrowser.open(f"http://{host}:{port}"),
        ).start()
        app.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    main()
