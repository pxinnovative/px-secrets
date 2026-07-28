"""Isolated tests for the multi-vault layer (px_vaults). Uses a throwaway AGE key + temp dir;
never touches the user's real vaults. Run: python tests/test_vaults.py
"""
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import px_vaults as V  # noqa: E402


def _age_keygen(tmp: str) -> tuple[str, str]:
    key_file = os.path.join(tmp, "keys.txt")
    r = subprocess.run(["age-keygen", "-o", key_file], capture_output=True, text=True)
    assert r.returncode == 0, f"age-keygen failed: {r.stderr}"
    # public recipient is printed to stderr as "Public key: age1..."
    pub = ""
    for line in (r.stderr + r.stdout).splitlines():
        if "public key:" in line.lower():
            pub = line.split(":", 1)[1].strip()
    assert pub.startswith("age1"), f"no public key parsed from: {r.stderr}"
    return key_file, pub


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        V.VAULTS_ROOT = os.path.join(tmp, "vaults")
        key_file, pub = _age_keygen(tmp)
        os.environ["SOPS_AGE_KEY_FILE"] = key_file

        assert V.list_vaults() == [], "should start empty"

        # create + round-trip
        vid = V.create_vault("Work", [pub], agent_access="read")
        assert vid == "work"
        V.encrypt(vid, {"github": {"token": "s3cr3t-value"}}, key_file)
        got = V.decrypt(vid, key_file)
        assert got == {"github": {"token": "s3cr3t-value"}}, f"round-trip mismatch: {got}"

        # config + listing
        vs = V.list_vaults()
        assert len(vs) == 1 and vs[0]["name"] == "Work" and vs[0]["agent_access"] == "read", vs

        # a second vault, own recipients
        V.create_vault("Personal", [pub], agent_access="deny", human_unlock_required=True)
        vs = V.list_vaults()
        assert len(vs) == 2
        personal = [v for v in vs if v["id"] == "personal"][0]
        assert personal["agent_access"] == "deny" and personal["human_unlock_required"] is True

        # validation
        try:
            V.create_vault("Bad", [pub], agent_access="bogus")
            assert False, "should reject bad agent_access"
        except ValueError:
            pass
        try:
            V.create_vault("NoRecipients", [])
            assert False, "should reject empty recipients"
        except ValueError:
            pass

        # migrate_legacy: seed 'Default' from a legacy file by COPY (original intact)
        V.VAULTS_ROOT = os.path.join(tmp, "vaults2")  # fresh root so list is empty
        legacy = os.path.join(tmp, "legacy.enc.yaml")
        # make a legacy encrypted file by encrypting into a temp vault then copying its enc file out
        V.create_vault("tmpsrc", [pub])
        V.encrypt("tmpsrc", {"legacy": {"k": "v"}}, key_file)
        import shutil
        shutil.copy2(V.enc_path("tmpsrc"), legacy)
        V.VAULTS_ROOT = os.path.join(tmp, "vaults3")  # empty root for migration
        newid = V.migrate_legacy(legacy, [pub], name="Default")
        assert newid == "default", newid
        assert os.path.exists(legacy), "legacy original must remain (copy, not move)"
        assert V.decrypt("default", key_file) == {"legacy": {"k": "v"}}

        # move / copy between vaults (Issue #31)
        V.VAULTS_ROOT = os.path.join(tmp, "vaults4")
        V.create_vault("Src", [pub])
        V.create_vault("Dst", [pub])
        V.encrypt("src", {"github": {"token": "AAA"}, "aws": {"pin": "BBB"}}, key_file)

        # dry-run changes nothing
        res = V.move_secret("src", "dst", ["github", "token"], key_file, dry_run=True)
        assert res["dry_run"] is True
        assert V.decrypt("dst", key_file) == {}, "dry-run must not write"

        # copy: value ends up in BOTH
        V.move_secret("src", "dst", ["github", "token"], key_file, copy=True)
        assert V.decrypt("src", key_file).get("github", {}).get("token") == "AAA"
        assert V.decrypt("dst", key_file).get("github", {}).get("token") == "AAA"

        # move: value leaves src, lands in dst
        V.move_secret("src", "dst", ["aws", "pin"], key_file)
        assert "aws" not in V.decrypt("src", key_file), "move must delete from source"
        assert V.decrypt("dst", key_file)["aws"]["pin"] == "BBB"

        # error cases
        for bad in [
            lambda: V.move_secret("src", "src", ["x"], key_file),               # same vault
            lambda: V.move_secret("src", "dst", ["nope", "nope"], key_file),     # not found
            lambda: V.move_secret("src", "dst", ["github", "token"], key_file, copy=True),  # exists in dst
        ]:
            try:
                bad(); assert False, "expected an error"
            except (ValueError, KeyError, FileExistsError):
                pass

    print("ALL VAULT TESTS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
