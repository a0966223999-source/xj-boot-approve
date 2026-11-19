"""Host acceptance test for xjboot.py — no browser, no network.

A software P-256 authenticator builds WebAuthn assertions in exactly the format the
approval page sends (authenticatorData, clientDataJSON, DER ECDSA signature).
One extra case replays the Owner's real Samsung-phone signature from 2026-11-19:
it must pass signature verification and then be refused only because it is EXPIRED,
and a one-bit change to it must be refused as BAD_SIGNATURE.

Usage: python3 -I host_test.py /path/to/dir/with/xjboot.py
"""
import base64, hashlib, json, os, re, secrets, shutil, struct, subprocess, sys, tempfile, time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

SRC = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.abspath(__file__)))
RP_ID = "a0966223999-source.github.io"
ORIGIN = "https://a0966223999-source.github.io"

REAL_SAMSUNG_FIXTURE = {
    "pending_text_b64": "eGotYm9vdC1hcHByb3ZhbCB2MQpob3N0PWJveC1waG9uZS10ZXN0Cm1hbmlmZXN0X3NoYTI1Nj0xMzgyZDg3ODY4MjA4YzA2MGNjZDUwN2Q0MzA5MTI4YjlkMzVkNTY4YzJmYzBhY2JiODJkYWRlYTgyZDVhNTI0Cm5vbmNlPTNjNTRiN2U0NmM3YjUzMWUxMjNiNjcyZGUwNzg0MWVlCmV4cGlyZXNfdW5peD0xNzk1MDkwNTg0Cg==",
    "payload": {
        "v": 1,
        "nonce": "3c54b7e46c7b531e123b672de07841ee",
        "approval": "eGotYm9vdC1hcHByb3ZhbCB2MQpob3N0PWJveC1waG9uZS10ZXN0Cm1hbmlmZXN0X3NoYTI1Nj0xMzgyZDg3ODY4MjA4YzA2MGNjZDUwN2Q0MzA5MTI4YjlkMzVkNTY4YzJmYzBhY2JiODJkYWRlYTgyZDVhNTI0Cm5vbmNlPTNjNTRiN2U0NmM3YjUzMWUxMjNiNjcyZGUwNzg0MWVlCmV4cGlyZXNfdW5peD0xNzk1MDkwNTg0Cg",
        "credential_id": "6rgOdr4EsTRXQZe3jHto1u0zD_ViVFpxtUMb9CrCm2g",
        "authenticator_data": "mkmnZ13yOPVm6x3bOtj45tJSm8bF7UukPavxrLCWeO0dAAAAAA",
        "client_data_json": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoicFptYWtZbnpnaFlGeVVLTFQwdWhCTmJaeUs1SjcxUkVKM0NvS3FKYWFFbyIsIm9yaWdpbiI6Imh0dHBzOi8vYTA5NjYyMjM5OTktc291cmNlLmdpdGh1Yi5pbyIsImNyb3NzT3JpZ2luIjpmYWxzZX0",
        "signature": "MEUCIQDHaPZbCJlCAqotCvo4hSzexEMFaxnirfTTh0WeaKrlqgIgfRVfU4wkmhnY5Ls0cNiF_iEhqZfu82SRqlRrnPsFIJI",
    },
    "registration": {
        "v": 1, "label": "owner-2026-11-19", "rp_id": RP_ID, "origin": ORIGIN,
        "credential_id": "6rgOdr4EsTRXQZe3jHto1u0zD_ViVFpxtUMb9CrCm2g", "alg": -7,
        "public_key_spki": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAElFttl7TtcFVycXpfLGTXvjNbhIiubHg5RiWJKmb0INe6m92UvLEWode6DWicagXZm-Je79GEwq7mTEsFWhUORw",
    },
}

results = []


def check(name, got, want):
    ok = got == want
    results.append(ok)
    print(("PASS " if ok else "FAIL ") + f"{name}: got={got} want={want}", flush=True)


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def unb64u(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class SoftAuthenticator:
    def __init__(self, label):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.cred_id = secrets.token_bytes(32)
        self.label = label

    def registration(self, rp_id=RP_ID, origin=ORIGIN):
        spki = self.key.public_key().public_bytes(serialization.Encoding.DER,
                                                  serialization.PublicFormat.SubjectPublicKeyInfo)
        return {"v": 1, "label": self.label, "rp_id": rp_id, "origin": origin,
                "credential_id": b64u(self.cred_id), "alg": -7, "public_key_spki": b64u(spki)}

    def assertion(self, text, nonce, *, rp_id=RP_ID, origin=ORIGIN, uv=True, up=True,
                  typ="webauthn.get", challenge_text=None):
        cd = json.dumps({"type": typ, "challenge": b64u(hashlib.sha256(challenge_text or text).digest()),
                         "origin": origin, "crossOrigin": False}, separators=(",", ":")).encode()
        flags = (0x01 if up else 0) | (0x04 if uv else 0)
        auth = hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + struct.pack(">I", 0)
        sig = self.key.sign(auth + hashlib.sha256(cd).digest(), ec.ECDSA(hashes.SHA256()))
        return {"v": 1, "nonce": nonce, "approval": b64u(text), "credential_id": b64u(self.cred_id),
                "authenticator_data": b64u(auth), "client_data_json": b64u(cd), "signature": b64u(sig)}


WORK = tempfile.mkdtemp(prefix="xjboot-host-")
os.makedirs(os.path.join(WORK, "code", "pkg"))
CODE_A = os.path.join(WORK, "code", "app.py")
CODE_B = os.path.join(WORK, "code", "pkg", "lib.py")
with open(CODE_A, "w") as f:
    f.write("print('gateway app v1')\n")
with open(CODE_B, "w") as f:
    f.write("VALUE = 1\n")
manifest = os.path.join(WORK, "MANIFEST")


def write_manifest(extra=""):
    with open(manifest, "w") as f:
        for rel in ("code/app.py", "code/pkg/lib.py"):
            f.write("%s  %s\n" % (hashlib.sha256(open(os.path.join(WORK, rel), "rb").read()).hexdigest(), rel))
        f.write(extra)


write_manifest()
GOOD_MANIFEST = open(manifest).read()
cfg = {
    "rp_id": RP_ID, "origin": ORIGIN, "host": "gateway-host-test", "manifest_path": manifest,
    "manifest_root": WORK,
    "start_cmd": [sys.executable, "-c", "import time; time.sleep(600)"],
    "state_dir": os.path.join(WORK, "state"), "trusted_keys": os.path.join(WORK, "trusted_keys.json"),
    "page_url": ORIGIN + "/xj-boot-approve/", "relay_post": "http://localhost:9/unused",
    "relay_poll": "http://localhost:9/unused", "max_ttl_seconds": 600,
}
CFG = os.path.join(WORK, "xjboot.json")
json.dump(cfg, open(CFG, "w"))
PF = os.path.join(WORK, "payload.json")


def xj(*args, cfgpath=CFG):
    p = subprocess.run([sys.executable, "-I", os.path.join(SRC, "xjboot.py"), "--config", cfgpath, *args],
                       capture_output=True, text=True, timeout=60)
    try:
        return json.loads(p.stdout.strip().splitlines()[-1])
    except Exception:
        return {"result": "CRASH", "stdout": p.stdout[-400:], "stderr": p.stderr[-800:]}


def start_with(payload, nonce, cfgpath=CFG):
    json.dump(payload, open(PF, "w"))
    return xj("start", "--nonce", nonce, "--assertion-file", PF, cfgpath=cfgpath)


def new_request(ttl=None):
    r = xj("request", *(["--ttl", str(ttl)] if ttl else []))
    n = r["nonce"]
    return n, open(os.path.join(cfg["state_dir"], "pending", n), "rb").read()


def alive(pid):
    try:
        os.kill(pid, 0); return True
    except ProcessLookupError:
        return False


def reset():
    xj("stop", "--grace", "3"); xj("clear-stop")


import cryptography
print(f"python {sys.version.split()[0]}  cryptography {cryptography.__version__}  xjboot.py sha256 "
      f"{hashlib.sha256(open(os.path.join(SRC, 'xjboot.py'), 'rb').read()).hexdigest()}")

owner = SoftAuthenticator("soft-owner")
regf = os.path.join(WORK, "reg.json")
json.dump(owner.registration(), open(regf, "w"))
check("register owner key", xj("add-key", regf)["result"], "PASS")

# 1-2 valid start, STOP stops it
n1, t1 = new_request()
st = start_with(owner.assertion(t1, n1), n1)
check("valid approval starts once", st["result"], "PASS")
pid = st.get("started_pid")
check("service running", bool(pid and alive(pid)), True)
xj("stop", "--grace", "3"); time.sleep(0.3)
check("STOP stops running service", alive(pid) if pid else None, False)

# 3-5 STOP present denies without consuming; replay denied
n2, t2 = new_request(); a2 = owner.assertion(t2, n2)
check("STOP present -> deny", start_with(a2, n2).get("reason"), "STOP_PRESENT")
xj("clear-stop")
check("replay used approval -> deny", start_with(owner.assertion(t1, n1), n1).get("reason"), "REPLAY")
check("approval not consumed by STOP deny", start_with(a2, n2)["result"], "PASS")
reset()

# 6 concurrency: 4 parallel starts on one approval -> exactly 1 PASS
n3, t3 = new_request(); json.dump(owner.assertion(t3, n3), open(PF, "w"))
cmd = [sys.executable, "-I", os.path.join(SRC, "xjboot.py"), "--config", CFG, "start", "--nonce", n3,
       "--assertion-file", PF]
procs = [subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True) for _ in range(4)]
outs = [json.loads(p.communicate()[0].strip()) for p in procs]
check("4 concurrent starts -> exactly 1 PASS", sum(o["result"] == "PASS" for o in outs), 1)
reset()

# 7-15 denials on a fresh, otherwise-valid request (none may consume it)
n4, t4 = new_request(); good = owner.assertion(t4, n4)
bad = dict(good); s = bytearray(unb64u(good["signature"])); s[-1] ^= 1; bad["signature"] = b64u(bytes(s))
check("tampered signature -> deny", start_with(bad, n4).get("reason"), "BAD_SIGNATURE")
n5, _ = new_request(); sw = dict(good); sw["nonce"] = n5
check("signature for another request -> deny", start_with(sw, n5).get("reason"), "APPROVAL_TEXT_MISMATCH")
check("no fingerprint (UV=0) -> deny", start_with(owner.assertion(t4, n4, uv=False), n4).get("reason"), "USER_NOT_VERIFIED")
check("no user presence (UP=0) -> deny", start_with(owner.assertion(t4, n4, up=False), n4).get("reason"), "USER_NOT_PRESENT")
check("wrong origin -> deny", start_with(owner.assertion(t4, n4, origin="https://evil.example"), n4).get("reason"), "ORIGIN_MISMATCH")
check("wrong rpId -> deny", start_with(owner.assertion(t4, n4, rp_id="evil.example"), n4).get("reason"), "RP_ID_MISMATCH")
check("registration-type data -> deny", start_with(owner.assertion(t4, n4, typ="webauthn.create"), n4).get("reason"), "CLIENT_DATA_TYPE")
check("challenge of other text -> deny",
      start_with(owner.assertion(t4, n4, challenge_text=b"something else"), n4).get("reason"), "CHALLENGE_MISMATCH")
stranger = SoftAuthenticator("stranger")
check("unregistered key -> deny", start_with(stranger.assertion(t4, n4), n4).get("reason"), "UNKNOWN_KEY")

with open(CODE_B, "w") as f:
    f.write("VALUE = 2  # edited, manifest untouched\n")
check("code edited, manifest untouched -> deny", start_with(good, n4).get("reason"), "CODE_CHANGED")
check("request refused while code differs from manifest", xj("request").get("reason"), "CODE_CHANGED")
st_bad = xj("status")["code"]
check("status reports changed file", (st_bad["ok"], st_bad.get("path")), (False, "code/pkg/lib.py"))
with open(CODE_B, "w") as f:
    f.write("VALUE = 1\n")
os.rename(CODE_A, CODE_A + ".gone")
check("listed code file deleted -> deny", start_with(good, n4).get("reason"), "CODE_MISSING")
os.rename(CODE_A + ".gone", CODE_A)
write_manifest(extra="%s  code/new_module.py\n" % ("0" * 64))
check("manifest file edited -> deny", start_with(good, n4).get("reason"), "MANIFEST_CHANGED")
open(manifest, "w").write(GOOD_MANIFEST)
CFG_B = os.path.join(WORK, "b.json"); json.dump(dict(cfg, host="other-host"), open(CFG_B, "w"))
check("host mismatch -> deny", start_with(good, n4, cfgpath=CFG_B).get("reason"), "HOST_MISMATCH")
check("valid approval still usable after denials", start_with(good, n4)["result"], "PASS")
reset()

# 16 expiry (30 s TTL)
n6, t6 = new_request(ttl=30); a6 = owner.assertion(t6, n6)
print("   waiting 31s for expiry…", flush=True); time.sleep(31)
check("expired approval -> deny", start_with(a6, n6).get("reason"), "EXPIRED")

# 17-18 the Owner's real Samsung signature: verifies, then refused only as EXPIRED
real = REAL_SAMSUNG_FIXTURE
realreg = os.path.join(WORK, "real_reg.json"); json.dump(real["registration"], open(realreg, "w"))
xj("add-key", realreg)
rn = real["payload"]["nonce"]
with open(os.path.join(cfg["state_dir"], "pending", rn), "wb") as f:
    f.write(base64.b64decode(real["pending_text_b64"]))
check("real Samsung signature verifies (then EXPIRED)", start_with(real["payload"], rn).get("reason"), "EXPIRED")
rb = dict(real["payload"]); s = bytearray(unb64u(rb["signature"])); s[-1] ^= 1; rb["signature"] = b64u(bytes(s))
check("real Samsung signature, 1 bit changed -> deny", start_with(rb, rn).get("reason"), "BAD_SIGNATURE")

# ---------------------------------------------------------------- v2 standing grant
print("--- standing (long-term) approval ---", flush=True)
reset()
GRANT = os.path.join(cfg["state_dir"], "standing_grant.json")


def standing_request(days=30):
    r = xj("request", "--standing-days", str(days))
    n = r["nonce"]
    return n, open(os.path.join(cfg["state_dir"], "pending", n), "rb").read()


def crafted_pending(sign_by, grant_until):
    n = secrets.token_hex(16)
    text = ("xj-boot-approval v2\nmode=standing\nhost=%s\nmanifest_sha256=%s\nnonce=%s\n"
            "sign_by_unix=%d\ngrant_until_unix=%d\n" % (
                cfg["host"], hashlib.sha256(open(manifest, "rb").read() + b"\x00start_cmd=" + json.dumps(cfg["start_cmd"], separators=(",", ":"), ensure_ascii=False).encode()).hexdigest(), n,
                sign_by, grant_until)).encode()
    with open(os.path.join(cfg["state_dir"], "pending", n), "wb") as f:
        f.write(text)
    return n, text


def start_standing():
    return xj("start", "--standing")


check("no grant yet -> standing start denied", start_standing().get("reason"), "NO_STANDING_GRANT")
s1, st1 = standing_request(30)
check("standing approval without fingerprint (UV=0) -> deny",
      start_with(owner.assertion(st1, s1, uv=False), s1).get("reason"), "USER_NOT_VERIFIED")
r = start_with(owner.assertion(st1, s1), s1)
check("standing approval: first start PASS", (r["result"], r.get("mode")), ("PASS", "standing"))
stt = xj("status")["standing_grant"] or {}
check("status shows active standing grant", (stt.get("active"), stt.get("nonce")), (True, s1))
check("standing start while running -> deny", start_standing().get("reason"), "ALREADY_RUNNING")
reset()
r = start_standing()
check("restart under standing grant, no new fingerprint -> PASS", r["result"], "PASS")
xj("stop", "--grace", "3")
check("STOP present -> standing start denied", start_standing().get("reason"), "STOP_PRESENT")
xj("clear-stop")
r = start_standing(); reset()
check("restart again after clear-stop -> PASS", r["result"], "PASS")
check("standing approval nonce cannot be claimed twice",
      start_with(owner.assertion(st1, s1), s1).get("reason"), "REPLAY")

with open(CODE_A, "w") as f:
    f.write("print('gateway app v2 - silently changed')\n")
check("code edited, manifest untouched -> standing grant refused", start_standing().get("reason"), "CODE_CHANGED")
with open(CODE_A, "w") as f:
    f.write("print('gateway app v1')\n")
with open(manifest, "a") as f:
    f.write("%s  code/pkg/lib.py\n" % hashlib.sha256(b"VALUE = 1\n").hexdigest())
check("manifest file edited -> standing grant void", start_standing().get("reason"), "MANIFEST_CHANGED")
open(manifest, "w").write(GOOD_MANIFEST)
check("code restored to approved version -> standing start PASS", start_standing()["result"], "PASS")
reset()
CFG_C = os.path.join(WORK, "c.json")
json.dump(dict(cfg, start_cmd=[sys.executable, "-c", "print('swapped program')"]), open(CFG_C, "w"))
check("start command changed -> standing grant void",
      xj("start", "--standing", cfgpath=CFG_C).get("reason"), "MANIFEST_CHANGED")
check("standing grant on another host -> deny",
      xj("start", "--standing", cfgpath=CFG_B).get("reason"), "HOST_MISMATCH")

good_grant = open(GRANT).read()
g = json.loads(good_grant); sb = bytearray(unb64u(g["payload"]["signature"])); sb[-1] ^= 1
g["payload"]["signature"] = b64u(bytes(sb)); open(GRANT, "w").write(json.dumps(g))
check("grant file with altered signature -> deny", start_standing().get("reason"), "BAD_SIGNATURE")
g = json.loads(good_grant)
longer = re.sub(rb"grant_until_unix=\d+\n", b"grant_until_unix=4102444800\n", unb64u(g["approval_b64"]))
g["approval_b64"] = b64u(longer); g["payload"]["approval"] = b64u(longer)
open(GRANT, "w").write(json.dumps(g))
check("grant file with extended expiry -> deny", start_standing().get("reason"), "CHALLENGE_MISMATCH")
open(GRANT, "w").write(good_grant)
check("original grant file restored -> PASS", start_standing()["result"], "PASS")
reset()

rv = xj("revoke")
check("revoke removes grant", (rv["result"], rv.get("had_grant")), ("REVOKED", True))
check("after revoke -> standing start denied", start_standing().get("reason"), "NO_STANDING_GRANT")
open(GRANT, "w").write(good_grant)
check("restoring a revoked grant file -> deny", start_standing().get("reason"), "GRANT_REVOKED")
os.unlink(GRANT)

s2, st2 = standing_request(7)
r = start_with(owner.assertion(st2, s2), s2); reset()
check("new standing approval after revoke -> PASS", r["result"], "PASS")
grant2 = open(GRANT).read()
s3, st3 = standing_request(7)
r = start_with(owner.assertion(st3, s3), s3); reset()
check("newer standing approval replaces older -> PASS", r["result"], "PASS")
open(GRANT, "w").write(grant2)
check("superseded older grant restored -> deny", start_standing().get("reason"), "GRANT_REVOKED")
xj("revoke")

n7, t7 = crafted_pending(int(time.time()) + 300, int(time.time()) + 300)
p7 = owner.assertion(t7, n7)
fake = {"v": 1, "created_at": time.time(), "approval_b64": b64u(t7), "payload": p7, "nonce": n7}
open(GRANT, "w").write(json.dumps(fake))
check("signed but never-claimed approval planted as grant -> deny", start_standing().get("reason"), "GRANT_NOT_CLAIMED")
os.unlink(GRANT)

n8, t8 = crafted_pending(int(time.time()) + 300, int(time.time()) + 60 * 86400)
check("standing approval longer than 30 days -> deny",
      start_with(owner.assertion(t8, n8), n8).get("reason"), "GRANT_TOO_LONG")
try:
    os.unlink(os.path.join(cfg["state_dir"], "used", n8))
except FileNotFoundError:
    pass
check("request refuses >30 days", xj("request", "--standing-days", "31")["result"], "CRASH")

n9, t9 = crafted_pending(int(time.time()) + 30, int(time.time()) + 38)
r = start_with(owner.assertion(t9, n9), n9); reset()
check("short standing grant: first start PASS", r["result"], "PASS")
print("   waiting 40s for standing grant expiry…", flush=True); time.sleep(40)
check("standing grant expired -> deny", start_standing().get("reason"), "STANDING_EXPIRED")

xj("stop", "--grace", "3")
shutil.rmtree(WORK, ignore_errors=True)
failed = results.count(False)
print(f"\nTOTAL {len(results)}  PASS {len(results) - failed}  FAIL {failed}")
sys.exit(1 if failed else 0)
