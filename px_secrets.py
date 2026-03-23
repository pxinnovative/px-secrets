#!/usr/bin/env python3
"""
PX Secrets — SOPS + AGE Vault Manager

A single-file Flask app with embedded HTML/CSS/JS for managing
encrypted secrets locally. No cloud, no telemetry, no network calls.
All encryption handled by SOPS + AGE on your machine.
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
import threading
import webbrowser

import yaml
from flask import Flask, jsonify, request

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

APP_NAME = "PX Secrets"
VERSION = "1.2.0"
SUPPORT_URL = "https://buymeacoffee.com/pxinnovative"

# Network
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 9999

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

# ---------------------------------------------------------------------------
# SOPS helpers
# ---------------------------------------------------------------------------


def decrypt_vault() -> dict:
    """Decrypt the SOPS vault and return its contents as a dict."""
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
    """Encrypt data and write it to the SOPS vault file."""
    env = os.environ.copy()
    env["SOPS_AGE_KEY_FILE"] = AGE_KEY_FILE
    if AGE_PUBLIC_KEY:
        env["SOPS_AGE_RECIPIENTS"] = AGE_PUBLIC_KEY

    os.makedirs(os.path.dirname(VAULT_PATH), exist_ok=True)

    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as tmp:
        yaml.dump(data, tmp, default_flow_style=False)
        tmp_path = tmp.name

    try:
        result = subprocess.run(
            ["sops", "encrypt", "--input-type", "yaml", "--output-type", "yaml", tmp_path],
            capture_output=True, text=True, env=env,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip())
        with open(VAULT_PATH, "w") as f:
            f.write(result.stdout)
    finally:
        os.unlink(tmp_path)


# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------

app = Flask(__name__)


@app.route("/")
def index():
    """Serve the single-page UI."""
    return HTML_PAGE


@app.route("/api/vault")
def api_vault():
    """Return all secrets grouped by service."""
    try:
        data = decrypt_vault()
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/secret", methods=["POST"])
def api_add_secret():
    """Add or update a secret in the vault."""
    try:
        body = request.json
        service = body["service"]
        key = body["key"]
        value = body["value"]
        note = body.get("note", "")

        data = decrypt_vault()
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
    try:
        body = request.json
        service = body["service"]
        key = body["key"]
        data = decrypt_vault()
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
    try:
        data = decrypt_vault()
        if svc in data:
            del data[svc]
        encrypt_vault(data)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/note", methods=["POST"])
def api_add_note():
    """Add or update a note attached to a secret."""
    try:
        body = request.json
        service = body["service"]
        key = body["key"]
        note = body["note"]
        data = decrypt_vault()
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
    webbrowser.open(f"http://{DEFAULT_HOST}:{port}")
    return jsonify({"ok": True})


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
.header{display:flex;align-items:baseline;gap:8px;margin-bottom:10px}
.header small{color:var(--muted);font-size:13px}
.toolbar{display:flex;gap:6px;margin-bottom:10px;align-items:center}
.toolbar input[type=text]{flex:1;background:var(--card);border:1px solid var(--border);color:var(--text);padding:8px 12px;border-radius:6px;font-size:14px;outline:none}
.toolbar input[type=text]:focus{border-color:var(--accent)}
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
.svc-name{color:var(--accent);font-weight:600;font-size:15px;text-transform:uppercase;letter-spacing:.5px}
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
/* Toast */
.toast-container{position:fixed;bottom:16px;right:16px;z-index:200;display:flex;flex-direction:column;gap:6px}
.toast{background:rgba(102,187,106,0.15);color:var(--success);border:1px solid rgba(102,187,106,0.3);padding:10px 20px;border-radius:10px;font-size:13px;opacity:0;transform:translateY(10px);transition:all .3s;backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);pointer-events:none}
.toast.show{opacity:1;transform:translateY(0)}
</style>
</head>
<body>

<div class="header">
  <h1>""" + APP_NAME + r"""</h1>
  <small>v""" + VERSION + r"""</small>
  <small style="color:var(--muted)">SOPS + AGE</small>
</div>

<div class="toolbar">
  <input type="text" id="search" placeholder="Search services or keys...">
  <button class="btn btn-accent" onclick="showAddModal()">+ Add</button>
  <button class="btn" onclick="loadVault()">Refresh</button>
  <button class="btn" onclick="showSettingsModal()">Settings</button>
  <button class="btn" onclick="fetch('/api/open-browser')">Browser</button>
  <a class="btn" href=\"""" + SUPPORT_URL + r"""\" target="_blank" rel="noopener" style="text-decoration:none;color:var(--success);border-color:var(--success)">Support</a>
</div>

<div class="cards" id="cards"></div>

<div class="status-bar" id="status-bar">Loading...</div>
<div class="cli-ref mono">CLI: px_secrets.py --list | --get SERVICE KEY | --help</div>
<div style="margin-top:6px;text-align:center;font-size:11px;color:var(--muted)">Open source &mdash; <a href=\"""" + SUPPORT_URL + r"""\" target="_blank" rel="noopener" style="color:var(--accent);text-decoration:none">Buy me a coffee</a> if you find this useful</div>

<!-- Add Secret Modal -->
<div class="modal-overlay" id="add-modal">
  <div class="modal">
    <h2>Add Secret</h2>
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
    <label>Vault File Path</label>
    <input id="set-vault">
    <label>AGE Key File</label>
    <input id="set-keyfile">
    <label>AGE Public Key</label>
    <input id="set-pubkey">
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

<div class="toast-container" id="toasts"></div>

<script>
const CLIPBOARD_CLEAR_MS = """ + str(CLIPBOARD_CLEAR_MS) + r""";
const TOAST_DURATION_MS = """ + str(TOAST_DURATION_MS) + r""";

let vaultData = {};
let revealedKeys = {};
let openCards = new Set();

async function loadVault() {
  try {
    const r = await fetch('/api/vault');
    const d = await r.json();
    if (d.error) { toast(d.error); return; }
    vaultData = d;
    render();
  } catch(e) { toast('Failed to load vault'); }
}

function render() {
  const q = document.getElementById('search').value.toLowerCase();
  const container = document.getElementById('cards');
  container.innerHTML = '';
  let svcCount = 0, keyCount = 0;
  const services = Object.keys(vaultData).sort();
  for (const svc of services) {
    const keys = Object.keys(vaultData[svc]).filter(k => !k.endsWith('__note'));
    const filteredKeys = keys.filter(k => {
      if (!q) return true;
      return svc.toLowerCase().includes(q) || k.toLowerCase().includes(q);
    });
    if (q && filteredKeys.length === 0 && !svc.toLowerCase().includes(q)) continue;
    const displayKeys = q ? filteredKeys : keys;
    svcCount++;
    keyCount += displayKeys.length;

    const card = document.createElement('div');
    card.className = 'card';
    const headerId = 'svc-' + svc.replace(/[^a-zA-Z0-9]/g, '_');
    const isOpen = openCards.has(headerId);

    let headerHTML = `<div class="card-header" onclick="toggleCard('${headerId}')">
      <span class="arrow ${isOpen ? 'open' : ''}" id="arrow-${headerId}">&#9654;</span>
      <span class="svc-name">${esc(svc)}</span>
      <span class="key-count">${displayKeys.length} key${displayKeys.length!==1?'s':''}</span>
      <button class="btn btn-danger btn-sm" onclick="event.stopPropagation();deleteService('${esc(svc)}')">Del</button>
    </div>`;

    let bodyHTML = `<div class="card-body ${isOpen ? 'open' : ''}" id="body-${headerId}">`;
    for (const k of displayKeys) {
      const noteKey = k + '__note';
      const note = vaultData[svc][noteKey] || '';
      const val = vaultData[svc][k];
      const rid = svc + '::' + k;
      const shown = revealedKeys[rid];
      const displayVal = shown ? esc(String(val)) : '••••••••';
      bodyHTML += `<div class="key-row">
        <div class="key-top">
          <span class="key-name">${esc(k)}</span>
          <span class="key-value ${shown ? 'revealed' : ''}">${displayVal}</span>
          <span class="key-actions">
            <button class="btn btn-sm" onclick="event.stopPropagation();toggleReveal('${escAttr(rid)}')">${shown ? 'Hide' : 'Show'}</button>
            <button class="btn btn-sm" onclick="event.stopPropagation();copyVal('${escAttr(svc)}','${escAttr(k)}')">Copy</button>
            <button class="btn btn-sm" onclick="event.stopPropagation();showNoteModal('${escAttr(svc)}','${escAttr(k)}')">Note</button>
            <button class="btn btn-danger btn-sm" onclick="event.stopPropagation();deleteKey('${escAttr(svc)}','${escAttr(k)}')">Del</button>
          </span>
        </div>
        ${note ? `<div class="key-note" onclick="event.stopPropagation();showNoteModal('${escAttr(svc)}','${escAttr(k)}')">${esc(note)}</div>` : ''}
      </div>`;
    }
    bodyHTML += '</div>';
    card.innerHTML = headerHTML + bodyHTML;
    container.appendChild(card);
  }
  document.getElementById('status-bar').textContent = `${svcCount} service${svcCount!==1?'s':''}, ${keyCount} key${keyCount!==1?'s':''} \u2014 encrypted with AGE`;
  updateServiceHints();
}

function toggleCard(id) {
  const body = document.getElementById('body-' + id);
  const arrow = document.getElementById('arrow-' + id);
  body.classList.toggle('open');
  arrow.classList.toggle('open');
  if (openCards.has(id)) openCards.delete(id); else openCards.add(id);
}

function toggleReveal(rid) {
  revealedKeys[rid] = !revealedKeys[rid];
  render();
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
    `<span class="svc-chip" onclick="document.getElementById('add-service').value='${esc(s)}'">${esc(s)}</span>`
  ).join('');
}

function showAddModal() {
  document.getElementById('add-service').value = '';
  document.getElementById('add-key').value = '';
  document.getElementById('add-value').value = '';
  document.getElementById('add-note').value = '';
  updateServiceHints();
  document.getElementById('add-modal').classList.add('show');
  document.getElementById('add-service').focus();
}

async function addSecret() {
  const svc = document.getElementById('add-service').value.trim();
  const key = document.getElementById('add-key').value.trim();
  const val = document.getElementById('add-value').value;
  const note = document.getElementById('add-note').value.trim();
  if (!svc || !key || !val) { toast('Service, key, and value are required'); return; }
  const r = await fetch('/api/secret', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({service:svc,key,value:val,note})});
  const d = await r.json();
  if (d.error) { toast(d.error); return; }
  closeModal('add-modal');
  toast('Secret added successfully to vault');
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

async function deleteKey(svc, key) {
  const ok = await showConfirm(`Delete ${svc}.${key}?`);
  if (!ok) return;
  const r = await fetch('/api/secret', {method:'DELETE', headers:{'Content-Type':'application/json'}, body:JSON.stringify({service:svc,key})});
  const d = await r.json();
  if (d.error) { toast(d.error); return; }
  toast('Secret deleted successfully');
  loadVault();
}

async function deleteService(svc) {
  const ok = await showConfirm(`Delete entire service "${svc}" and all its keys?`);
  if (!ok) return;
  const r = await fetch('/api/service/' + encodeURIComponent(svc), {method:'DELETE'});
  const d = await r.json();
  if (d.error) { toast(d.error); return; }
  toast('Service and all keys deleted successfully');
  loadVault();
}

function showNoteModal(svc, key) {
  document.getElementById('note-service').value = svc;
  document.getElementById('note-key').value = key;
  const noteKey = key + '__note';
  document.getElementById('note-text').value = (vaultData[svc] && vaultData[svc][noteKey]) || '';
  document.getElementById('note-modal').classList.add('show');
}

async function saveNote() {
  const svc = document.getElementById('note-service').value;
  const key = document.getElementById('note-key').value;
  const note = document.getElementById('note-text').value.trim();
  const r = await fetch('/api/note', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({service:svc,key,note})});
  const d = await r.json();
  if (d.error) { toast(d.error); return; }
  closeModal('note-modal');
  toast('Note saved successfully');
  loadVault();
}

function showSettingsModal() {
  fetch('/api/settings').then(r=>r.json()).then(d => {
    document.getElementById('set-vault').value = d.vault_path || '';
    document.getElementById('set-keyfile').value = d.age_key_file || '';
    document.getElementById('set-pubkey').value = d.age_public_key || '';
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

function toast(msg) {
  const c = document.getElementById('toasts');
  const t = document.createElement('div');
  t.className = 'toast';
  t.textContent = msg;
  c.appendChild(t);
  requestAnimationFrame(() => t.classList.add('show'));
  setTimeout(() => { t.classList.remove('show'); setTimeout(() => t.remove(), 300); }, TOAST_DURATION_MS);
}

function esc(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
function escAttr(s) { return s.replace(/\\/g,'\\\\').replace(/'/g,"\\'"); }

document.getElementById('search').addEventListener('input', render);

// Close modals on overlay click
document.querySelectorAll('.modal-overlay').forEach(el => {
  el.addEventListener('click', e => { if (e.target === el) el.classList.remove('show'); });
});

loadVault();
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
    host = DEFAULT_HOST
    port = args.port

    # Store port in app config so /api/open-browser can read it
    app.config["port"] = port

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
            f"http://{host}:{port}",
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
