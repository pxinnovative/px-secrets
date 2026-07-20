#!/usr/bin/env python3
"""PX Secrets — multi-vault layer (Issue #21).

Named vaults, each self-contained with its OWN AGE recipients and access policy:

    ~/.px-secrets/vaults/<vault-id>/
        vault.enc.yaml      # SOPS+AGE encrypted secrets (same shape as the legacy single file)
        vault.config.json   # plaintext: name, recipients[], agent_access, human_unlock_required

Design goals (from the issue):
- Each vault encrypts to its OWN recipients (a "couple" vault can add a spouse's key; "personal"
  encrypts to just the owner). Independent per vault.
- `agent_access`: "deny" | "read" | "read_write" — a defense-in-depth signal enforced at the API layer.
- Backward compatible: a legacy single-file vault auto-migrates to a vault named "Default" (by COPY,
  never destroying the original).

This module is deliberately self-contained and free of Flask so it can be unit-tested in isolation.
Encryption uses `sops encrypt --age <recipients>` explicitly, so it does not depend on a matching
.sops.yaml creation rule for the (new) vaults directory.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile

import yaml

VAULTS_ROOT = os.path.expanduser("~/.px-secrets/vaults")
_SLUG_OK = set("abcdefghijklmnopqrstuvwxyz0123456789-_")

AGENT_ACCESS = ("deny", "read", "read_write")


def slugify(name: str) -> str:
    s = "".join(c if c in _SLUG_OK else "-" for c in name.strip().lower())
    while "--" in s:
        s = s.replace("--", "-")
    return s.strip("-") or "vault"


def vault_dir(vault_id: str) -> str:
    return os.path.join(VAULTS_ROOT, vault_id)


def enc_path(vault_id: str) -> str:
    return os.path.join(vault_dir(vault_id), "vault.enc.yaml")


def config_path(vault_id: str) -> str:
    return os.path.join(vault_dir(vault_id), "vault.config.json")


def read_config(vault_id: str) -> dict:
    p = config_path(vault_id)
    if not os.path.exists(p):
        return {}
    with open(p, "r") as f:
        return json.load(f)


def write_config(vault_id: str, cfg: dict) -> None:
    os.makedirs(vault_dir(vault_id), exist_ok=True)
    tmp = config_path(vault_id) + ".tmp"
    with open(tmp, "w") as f:
        json.dump(cfg, f, indent=2)
    os.replace(tmp, config_path(vault_id))


def list_vaults() -> list[dict]:
    """Return [{id, name, agent_access, human_unlock_required, recipients_count}], sorted by name."""
    if not os.path.isdir(VAULTS_ROOT):
        return []
    out = []
    for vid in sorted(os.listdir(VAULTS_ROOT)):
        if not os.path.isdir(vault_dir(vid)):
            continue
        cfg = read_config(vid)
        out.append({
            "id": vid,
            "name": cfg.get("name", vid),
            "agent_access": cfg.get("agent_access", "read_write"),
            "human_unlock_required": bool(cfg.get("human_unlock_required", False)),
            "recipients_count": len(cfg.get("recipients", [])),
        })
    out.sort(key=lambda v: v["name"].lower())
    return out


def create_vault(name: str, recipients: list[str], agent_access: str = "read_write",
                 human_unlock_required: bool = False, vault_id: str | None = None) -> str:
    if agent_access not in AGENT_ACCESS:
        raise ValueError(f"agent_access must be one of {AGENT_ACCESS}")
    if not recipients:
        raise ValueError("a vault needs at least one AGE recipient")
    vid = vault_id or slugify(name)
    if os.path.exists(vault_dir(vid)):
        raise FileExistsError(f"vault '{vid}' already exists")
    os.makedirs(vault_dir(vid), exist_ok=True)
    write_config(vid, {
        "name": name,
        "recipients": list(recipients),
        "agent_access": agent_access,
        "human_unlock_required": bool(human_unlock_required),
    })
    encrypt(vid, {}, _age_key_file())  # initialize an empty encrypted vault
    return vid


def _age_key_file() -> str:
    return os.path.expanduser(os.environ.get("SOPS_AGE_KEY_FILE",
                                             "~/.config/sops/age/keys.txt"))


def decrypt(vault_id: str, age_key_file: str | None = None) -> dict:
    p = enc_path(vault_id)
    if not os.path.exists(p):
        return {}
    env = os.environ.copy()
    env["SOPS_AGE_KEY_FILE"] = os.path.expanduser(age_key_file or _age_key_file())
    r = subprocess.run(["sops", "decrypt", p], capture_output=True, text=True, env=env)
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip())
    return yaml.safe_load(r.stdout) or {}


def encrypt(vault_id: str, data: dict, age_key_file: str | None = None) -> None:
    cfg = read_config(vault_id)
    recipients = cfg.get("recipients", [])
    if not recipients:
        raise RuntimeError(f"vault '{vault_id}' has no recipients configured")
    env = os.environ.copy()
    env["SOPS_AGE_KEY_FILE"] = os.path.expanduser(age_key_file or _age_key_file())
    d = vault_dir(vault_id)
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".pxsecrets-tmp-", suffix=".enc.yaml", dir=d)
    try:
        with os.fdopen(fd, "w") as f:
            yaml.dump(data, f, default_flow_style=False)
        # Explicit --age recipients: does not depend on a .sops.yaml creation rule for this path.
        r = subprocess.run(
            ["sops", "encrypt", "--age", ",".join(recipients),
             "--input-type", "yaml", "--output-type", "yaml", tmp],
            capture_output=True, text=True, env=env,
        )
        if r.returncode != 0:
            raise RuntimeError(r.stderr.strip())
        with open(enc_path(vault_id), "w") as f:
            f.write(r.stdout)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def migrate_legacy(legacy_vault_path: str, recipients: list[str], name: str = "Default") -> str | None:
    """If no vaults exist yet and a legacy single-file vault is present, seed a 'Default' vault from
    it by COPYING the encrypted file (the original is left untouched). Returns the new vault id or None.
    """
    if list_vaults():
        return None
    legacy = os.path.expanduser(legacy_vault_path)
    if not os.path.exists(legacy):
        return None
    vid = slugify(name)
    os.makedirs(vault_dir(vid), exist_ok=True)
    write_config(vid, {
        "name": name,
        "recipients": list(recipients),
        "agent_access": "read_write",
        "human_unlock_required": False,
    })
    shutil.copy2(legacy, enc_path(vid))  # copy, never move — original stays intact
    return vid


# --- move / copy secrets between vaults (Issue #31) ---------------------------------------

def _get_at(data: dict, path: list):
    node = data
    for seg in path:
        if not isinstance(node, dict) or seg not in node:
            return False, None
        node = node[seg]
    return True, node


def _set_at(data: dict, path: list, value) -> None:
    node = data
    for seg in path[:-1]:
        nxt = node.setdefault(seg, {})
        if not isinstance(nxt, dict):
            raise ValueError(f"path segment '{seg}' is not a group")
        node = nxt
    node[path[-1]] = value


def _del_at(data: dict, path: list) -> None:
    node = data
    parents = [data]
    for seg in path[:-1]:
        if not isinstance(node.get(seg), dict):
            return
        node = node[seg]
        parents.append(node)
    node.pop(path[-1], None)
    # prune now-empty parent groups, deepest first (matches the app's flat/group cleanup)
    for i in range(len(path) - 1, 0, -1):
        parent, key = parents[i - 1], path[i - 1]
        if isinstance(parent.get(key), dict) and not parent[key]:
            parent.pop(key, None)


def move_secret(src_vault: str, dst_vault: str, path: list, age_key_file: str | None = None,
                copy: bool = False, dry_run: bool = False) -> dict:
    """Move (or copy) a secret at `path` from one vault to another.

    Safe-by-default: writes + re-decrypts the destination to confirm the round-trip BEFORE deleting
    from the source. If anything fails, the source is left intact. `dry_run=True` validates only.
    """
    if src_vault == dst_vault:
        raise ValueError("source and destination vaults are the same")
    if not (isinstance(path, list) and path and all(isinstance(s, str) and s for s in path)):
        raise ValueError("path must be a non-empty list of non-empty strings")

    src_data = decrypt(src_vault, age_key_file)
    found, value = _get_at(src_data, path)
    if not found:
        raise KeyError(f"path {path} not found in vault '{src_vault}'")
    dst_data = decrypt(dst_vault, age_key_file)
    if _get_at(dst_data, path)[0]:
        raise FileExistsError(f"path {path} already exists in vault '{dst_vault}'")

    if dry_run:
        return {"dry_run": True, "path": path, "from": src_vault, "to": dst_vault, "copy": copy}

    _set_at(dst_data, path, value)
    encrypt(dst_vault, dst_data, age_key_file)

    # verify the destination round-trips before touching the source
    ok, back = _get_at(decrypt(dst_vault, age_key_file), path)
    if not (ok and back == value):
        raise RuntimeError("post-write verification failed; source left intact")

    if not copy:
        _del_at(src_data, path)
        encrypt(src_vault, src_data, age_key_file)
    return {"path": path, "from": src_vault, "to": dst_vault, "copy": copy}
