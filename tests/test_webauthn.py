"""Tests for px_webauthn.

Written after shipping this module on an unverified claim that it had been exercised
end to end. It had not. These cover the parts that can be asserted without a physical
authenticator: the options we emit, challenge handling, and every rejection path in
assertion verification.
"""

import base64
import hashlib
import json
import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import px_webauthn  # noqa: E402

from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

RP_ID = "localhost"
ORIGIN = "http://localhost:9999"


def b64u(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


class _Store(unittest.TestCase):
    """Redirect the credential store at a temp file so tests never touch real state."""

    def setUp(self):
        import tempfile
        self._tmp = tempfile.mkdtemp()
        self._orig = px_webauthn.STORE_PATH
        px_webauthn.STORE_PATH = os.path.join(self._tmp, "webauthn.json")
        px_webauthn._pending.clear()

    def tearDown(self):
        px_webauthn.STORE_PATH = self._orig
        px_webauthn._pending.clear()


class TestRegistrationOptions(_Store):

    def test_rp_id_is_passed_through(self):
        o = px_webauthn.registration_options(RP_ID)
        self.assertEqual(o["rp"]["id"], RP_ID)

    def test_requires_platform_authenticator_and_user_verification(self):
        # Both matter: "platform" keeps it on-device, and user verification is what
        # makes it a biometric rather than a presence tap.
        sel = px_webauthn.registration_options(RP_ID)["authenticatorSelection"]
        self.assertEqual(sel["authenticatorAttachment"], "platform")
        self.assertEqual(sel["userVerification"], "required")

    def test_offers_es256_and_rs256(self):
        algs = [p["alg"] for p in px_webauthn.registration_options(RP_ID)["pubKeyCredParams"]]
        self.assertIn(-7, algs)
        self.assertIn(-257, algs)

    def test_challenge_is_fresh_and_long_enough(self):
        a = px_webauthn.registration_options(RP_ID)["challenge"]
        b = px_webauthn.registration_options(RP_ID)["challenge"]
        self.assertNotEqual(a, b)
        self.assertGreaterEqual(len(px_webauthn.b64url_decode(a)), 32)

    def test_user_handle_carries_no_identity(self):
        # This value is stored on the authenticator and can appear in OS UI, so it
        # must never be an email or a real name.
        u = px_webauthn.registration_options(RP_ID)["user"]
        handle = px_webauthn.b64url_decode(u["id"]).decode()
        self.assertNotIn("@", handle)
        self.assertNotIn("@", u["name"])


class TestChallenges(_Store):

    def test_challenge_is_single_use(self):
        ch = px_webauthn.registration_options(RP_ID)["challenge"]
        self.assertTrue(px_webauthn._consume_challenge(ch))
        self.assertFalse(px_webauthn._consume_challenge(ch), "replay must be rejected")

    def test_unknown_challenge_is_rejected(self):
        self.assertFalse(px_webauthn._consume_challenge(b64u(b"never issued")))


class TestAuthentication(_Store):
    """Build a real assertion with a real key, then break one thing at a time."""

    def setUp(self):
        super().setUp()
        self.key = ec.generate_private_key(ec.SECP256R1())
        spki = self.key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)
        opts = px_webauthn.registration_options(RP_ID)
        client_data = json.dumps({"type": "webauthn.create",
                                  "challenge": opts["challenge"],
                                  "origin": ORIGIN}).encode()
        px_webauthn.verify_registration(
            {"id": "cred-1", "clientDataJSON": b64u(client_data),
             "publicKey": b64u(spki), "label": "test"}, RP_ID, ORIGIN)

    def _assertion(self, flags=0x05, rp_id=RP_ID, origin=ORIGIN, counter=1, challenge=None):
        ch = challenge or px_webauthn.authentication_options()["challenge"]
        client_data = json.dumps({"type": "webauthn.get",
                                  "challenge": ch, "origin": origin}).encode()
        auth_data = (hashlib.sha256(rp_id.encode()).digest()
                     + bytes([flags]) + struct.pack(">I", counter))
        sig = self.key.sign(auth_data + hashlib.sha256(client_data).digest(),
                            ec.ECDSA(hashes.SHA256()))
        return {"id": "cred-1", "clientDataJSON": b64u(client_data),
                "authenticatorData": b64u(auth_data), "signature": b64u(sig)}

    def test_valid_assertion_is_accepted(self):
        r = px_webauthn.verify_authentication(self._assertion(), RP_ID, ORIGIN)
        self.assertEqual(r["id"], "cred-1")

    def test_missing_user_verification_flag_is_rejected(self):
        # 0x01 = user present only. This is the check that stops a mere tap from
        # standing in for a fingerprint.
        with self.assertRaises(ValueError) as e:
            px_webauthn.verify_authentication(self._assertion(flags=0x01), RP_ID, ORIGIN)
        self.assertIn("user verification", str(e.exception))

    def test_wrong_origin_is_rejected(self):
        with self.assertRaises(ValueError) as e:
            px_webauthn.verify_authentication(
                self._assertion(origin="http://evil.example"), RP_ID, ORIGIN)
        self.assertIn("origin", str(e.exception))

    def test_rp_id_hash_mismatch_is_rejected(self):
        with self.assertRaises(ValueError) as e:
            px_webauthn.verify_authentication(
                self._assertion(rp_id="evil.example"), RP_ID, ORIGIN)
        self.assertIn("RP ID", str(e.exception))

    def test_tampered_signature_is_rejected(self):
        a = self._assertion()
        a["signature"] = b64u(b"\x00" * 70)
        with self.assertRaises(ValueError):
            px_webauthn.verify_authentication(a, RP_ID, ORIGIN)

    def test_replayed_challenge_is_rejected(self):
        a = self._assertion()
        px_webauthn.verify_authentication(a, RP_ID, ORIGIN)
        with self.assertRaises(ValueError) as e:
            px_webauthn.verify_authentication(a, RP_ID, ORIGIN)
        self.assertIn("challenge", str(e.exception))

    def test_unknown_credential_is_rejected(self):
        a = self._assertion()
        a["id"] = "not-enrolled"
        with self.assertRaises(ValueError) as e:
            px_webauthn.verify_authentication(a, RP_ID, ORIGIN)
        self.assertIn("unknown credential", str(e.exception))

    def test_non_increasing_counter_is_rejected(self):
        px_webauthn.verify_authentication(self._assertion(counter=5), RP_ID, ORIGIN)
        with self.assertRaises(ValueError) as e:
            px_webauthn.verify_authentication(self._assertion(counter=5), RP_ID, ORIGIN)
        self.assertIn("counter", str(e.exception))

    def test_stored_credential_never_holds_private_material(self):
        for c in px_webauthn.list_credentials():
            self.assertNotIn("public_key", c)
            self.assertNotIn("private", json.dumps(c).lower())


if __name__ == "__main__":
    unittest.main()
