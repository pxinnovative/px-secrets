"""Integration test: the Flask routes are vault-aware.

FULLY ISOLATED: HOME is redirected to a throwaway temp dir BEFORE importing the app, so ~/.px-secrets,
~/secrets, the lock file and the real config are never read or touched. Uses a throwaway AGE key.
Run: python tests/test_app_vaults.py
"""
import os
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main() -> int:
    tmp = tempfile.mkdtemp()
    os.environ["HOME"] = tmp  # isolate ALL ~-relative paths (config, vault, lock, vaults root)
    key_file = os.path.join(tmp, "keys.txt")
    r = subprocess.run(["age-keygen", "-o", key_file], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    pub = [l.split(":", 1)[1].strip() for l in (r.stderr + r.stdout).splitlines()
           if "public key" in l.lower()][0]
    os.environ["SOPS_AGE_KEY_FILE"] = key_file

    sys.path.insert(0, REPO)
    import px_secrets  # imports px_vaults; with the temp HOME, no real config/lock is read
    px_secrets.AGE_KEY_FILE = key_file
    px_secrets.AGE_PUBLIC_KEY = pub
    import px_vaults

    c = px_secrets.app.test_client()

    assert c.get("/api/vaults").get_json()["vaults"] == [], "should list no vaults"

    r = c.post("/api/vaults", json={"name": "Work", "recipients": [pub], "agent_access": "read"})
    assert r.status_code == 201, r.get_json()
    vs = c.get("/api/vaults").get_json()["vaults"]
    assert len(vs) == 1 and vs[0]["id"] == "work" and vs[0]["agent_access"] == "read", vs

    px_vaults.encrypt("work", {"github": {"token": "s3cr3t"}}, key_file)
    assert c.get("/api/vault", headers={"X-Vault": "work"}).get_json() == {"github": {"token": "s3cr3t"}}

    r = c.post("/api/vaults", json={"name": "PX", "recipients": [pub]})
    assert r.status_code == 201
    assert c.get("/api/vault", headers={"X-Vault": "px"}).get_json() == {}, "vaults must be isolated"

    assert c.post("/api/vaults", json={"name": "Work", "recipients": [pub]}).status_code == 400
    assert c.post("/api/vaults", json={"name": "X", "recipients": [pub], "agent_access": "bad"}).status_code == 400

    # agent_access enforcement: a 'deny' vault blocks Bearer (agent) callers, allows humans
    assert c.post("/api/vaults", json={"name": "Personal", "recipients": [pub], "agent_access": "deny"}).status_code == 201
    assert c.get("/api/vault", headers={"X-Vault": "personal", "Authorization": "Bearer x"}).status_code == 403
    assert c.get("/api/vault", headers={"X-Vault": "personal"}).status_code == 200  # human ok

    # move via the API: work.github.token -> px
    r = c.post("/api/vaults/move", json={"src": "work", "dst": "px", "path": ["github", "token"]})
    assert r.status_code == 200, r.get_json()
    assert c.get("/api/vault", headers={"X-Vault": "px"}).get_json().get("github", {}).get("token") == "s3cr3t"
    assert "github" not in c.get("/api/vault", headers={"X-Vault": "work"}).get_json()  # moved out

    print("FLASK MULTI-VAULT INTEGRATION PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
