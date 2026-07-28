"""WebAuthn platform-authenticator unlock for PX Secrets (Touch ID / Face ID / Windows Hello).

Why this exists
---------------
The app lock is good security but re-typing a master password every idle timeout is
enough friction that people either disable the lock or pick a weak password. A platform
authenticator gives the same "a human is present at this device" proof with a fingerprint
or a face scan, and the private key never leaves the device's secure enclave.

Design notes
------------
* This layer AUGMENTS the master password, it never replaces it. The password stays as
  the recovery path: if the enrolled device is lost, you can still get in. Enrolment
  therefore requires an already-unlocked session — you cannot bootstrap a credential
  from a locked app.
* We deliberately avoid parsing CBOR attestation objects. Modern browsers expose
  `getPublicKey()` on the registration response, which hands us the public key already
  in SPKI DER — exactly what `cryptography` consumes. That removes an entire class of
  parsing bugs and a dependency.
* Attestation is NOT verified. We are authenticating "the same authenticator that
  enrolled" on a local, single-user app; we are not an enterprise verifying device
  provenance. Requesting attestation would add complexity with no benefit here.
* User verification (`UV`) is REQUIRED, both in the request options and re-checked in
  the authenticator-data flags server-side. Without that check a platform authenticator
  could satisfy the ceremony with mere presence (a tap) instead of biometrics.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import struct
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.exceptions import InvalidSignature

STORE_DIR = os.path.expanduser("~/.px-secrets")
STORE_PATH = os.path.join(STORE_DIR, "webauthn.json")

CHALLENGE_TTL = 120          # seconds; a ceremony that takes longer than this is stale
_pending: dict[str, float] = {}   # challenge(b64url) -> issued_at


# --------------------------------------------------------------------------- helpers
def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _read_store() -> dict:
    if not os.path.exists(STORE_PATH):
        return {"credentials": []}
    try:
        with open(STORE_PATH) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {"credentials": []}


def _write_store(data: dict) -> None:
    os.makedirs(STORE_DIR, exist_ok=True)
    tmp = STORE_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, STORE_PATH)


def list_credentials() -> list[dict]:
    """Public metadata only — never the key material."""
    return [
        {"id": c["id"], "label": c.get("label", "device"), "created": c.get("created"),
         "last_used": c.get("last_used")}
        for c in _read_store().get("credentials", [])
    ]


def is_enrolled() -> bool:
    return bool(_read_store().get("credentials"))


def delete_credential(cred_id: str) -> bool:
    store = _read_store()
    before = len(store.get("credentials", []))
    store["credentials"] = [c for c in store.get("credentials", []) if c["id"] != cred_id]
    _write_store(store)
    return len(store["credentials"]) < before


def _new_challenge() -> str:
    now = time.time()
    for ch, ts in list(_pending.items()):          # opportunistic expiry sweep
        if now - ts > CHALLENGE_TTL:
            _pending.pop(ch, None)
    ch = b64url_encode(secrets.token_bytes(32))
    _pending[ch] = now
    return ch


def _consume_challenge(ch: str) -> bool:
    """Single-use: a replayed challenge must fail even inside the TTL."""
    issued = _pending.pop(ch, None)
    return issued is not None and (time.time() - issued) <= CHALLENGE_TTL


# --------------------------------------------------------------- ceremony: registration
def registration_options(rp_id: str, user_name: str = "px-secrets") -> dict:
    existing = [{"type": "public-key", "id": c["id"]} for c in _read_store().get("credentials", [])]
    return {
        "challenge": _new_challenge(),
        "rp": {"id": rp_id, "name": "PX Secrets"},
        "user": {
            # Stable, non-identifying handle. Deliberately not an email or a real name:
            # this value is stored on the authenticator and can surface in OS UI.
            "id": b64url_encode(b"px-secrets-local-user"),
            "name": user_name,
            "displayName": "PX Secrets (local)",
        },
        "pubKeyCredParams": [{"type": "public-key", "alg": -7},     # ES256
                             {"type": "public-key", "alg": -257}],  # RS256
        "timeout": CHALLENGE_TTL * 1000,
        "attestation": "none",
        "excludeCredentials": existing,
        "authenticatorSelection": {
            "authenticatorAttachment": "platform",   # Touch ID / Face ID / Hello, not a roaming key
            "userVerification": "required",          # biometric or device passcode, never mere presence
            "residentKey": "preferred",
        },
    }


def verify_registration(body: dict, rp_id: str, origin: str) -> dict:
    """Validate the create() response and persist the credential. Raises ValueError."""
    cred_id = body.get("id")
    client_data_b64 = body.get("clientDataJSON")
    pubkey_b64 = body.get("publicKey")           # SPKI DER, from response.getPublicKey()
    label = (body.get("label") or "this device")[:60]
    if not (cred_id and client_data_b64 and pubkey_b64):
        raise ValueError("incomplete registration response")

    client_data = json.loads(b64url_decode(client_data_b64))
    if client_data.get("type") != "webauthn.create":
        raise ValueError("wrong ceremony type")
    if not _consume_challenge(client_data.get("challenge", "")):
        raise ValueError("unknown or expired challenge")
    if client_data.get("origin") != origin:
        raise ValueError(f"origin mismatch: {client_data.get('origin')}")

    spki = b64url_decode(pubkey_b64)
    try:
        load_der_public_key(spki)                # fail now, not at first unlock
    except Exception as e:
        raise ValueError(f"unusable public key: {e}")

    store = _read_store()
    store.setdefault("credentials", [])
    store["credentials"] = [c for c in store["credentials"] if c["id"] != cred_id]
    store["credentials"].append({
        "id": cred_id,
        "public_key": pubkey_b64,
        "sign_count": 0,
        "rp_id": rp_id,
        "label": label,
        "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "last_used": None,
    })
    _write_store(store)
    return {"id": cred_id, "label": label}


# ------------------------------------------------------------- ceremony: authentication
def authentication_options() -> dict:
    creds = _read_store().get("credentials", [])
    if not creds:
        raise ValueError("no enrolled authenticator")
    return {
        "challenge": _new_challenge(),
        "timeout": CHALLENGE_TTL * 1000,
        "userVerification": "required",
        "allowCredentials": [{"type": "public-key", "id": c["id"]} for c in creds],
    }


def verify_authentication(body: dict, rp_id: str, origin: str) -> dict:
    """Validate the get() response. Returns the credential on success; raises ValueError."""
    cred_id = body.get("id")
    client_data_b64 = body.get("clientDataJSON")
    auth_data_b64 = body.get("authenticatorData")
    sig_b64 = body.get("signature")
    if not (cred_id and client_data_b64 and auth_data_b64 and sig_b64):
        raise ValueError("incomplete assertion")

    store = _read_store()
    cred = next((c for c in store.get("credentials", []) if c["id"] == cred_id), None)
    if cred is None:
        raise ValueError("unknown credential")

    client_data_raw = b64url_decode(client_data_b64)
    client_data = json.loads(client_data_raw)
    if client_data.get("type") != "webauthn.get":
        raise ValueError("wrong ceremony type")
    if not _consume_challenge(client_data.get("challenge", "")):
        raise ValueError("unknown or expired challenge")
    if client_data.get("origin") != origin:
        raise ValueError(f"origin mismatch: {client_data.get('origin')}")

    auth_data = b64url_decode(auth_data_b64)
    if len(auth_data) < 37:
        raise ValueError("malformed authenticator data")
    if auth_data[:32] != hashlib.sha256(rp_id.encode()).digest():
        raise ValueError("RP ID hash mismatch")
    flags = auth_data[32]
    if not flags & 0x01:
        raise ValueError("user presence flag not set")
    if not flags & 0x04:
        # The whole point of this feature: a fingerprint/face, not just a tap.
        raise ValueError("user verification flag not set (biometric or device PIN required)")

    signed = auth_data + hashlib.sha256(client_data_raw).digest()
    pub = load_der_public_key(b64url_decode(cred["public_key"]))
    try:
        if isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(b64url_decode(sig_b64), signed, ec.ECDSA(hashes.SHA256()))
        elif isinstance(pub, rsa.RSAPublicKey):
            pub.verify(b64url_decode(sig_b64), signed, padding.PKCS1v15(), hashes.SHA256())
        else:
            raise ValueError("unsupported key type")
    except InvalidSignature:
        raise ValueError("signature verification failed")

    # Cloned-authenticator detection. Many platform authenticators keep the counter at
    # zero; only enforce monotonicity when the authenticator actually uses it.
    new_count = struct.unpack(">I", auth_data[33:37])[0]
    if new_count and cred.get("sign_count") and new_count <= cred["sign_count"]:
        raise ValueError("signature counter did not increase (possible cloned authenticator)")

    cred["sign_count"] = new_count
    cred["last_used"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    _write_store(store)
    return {"id": cred_id, "label": cred.get("label")}
