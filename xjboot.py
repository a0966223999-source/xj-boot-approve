#!/usr/bin/env python3
"""XJ Boot launcher: start a service only with the Owner's passkey (fingerprint) approval.

Commands:
  request              issue a one-time approval request, print the phone link
  start --nonce N      verify the Owner's signed approval and start the service once
  stop                 write STOP and terminate the running service
  status               show STOP / running state
  clear-stop           remove STOP (Owner action on the host)
  add-key FILE         register a passkey public key produced by the approval page

Every state-changing step runs under one exclusive flock (state_dir/boot.lock),
shared by start and stop, so STOP is always checked right before the start.
"""
import argparse
import base64
import fcntl
import hashlib
import json
import os
import re
import secrets
import signal
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from contextlib import contextmanager

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

APPROVAL_RE = re.compile(
    rb"^xj-boot-approval v1\nhost=([A-Za-z0-9._-]{1,64})\nmanifest_sha256=([0-9a-f]{64})\n"
    rb"nonce=([0-9a-f]{32})\nexpires_unix=([0-9]{10})\n\Z"
)
NONCE_RE = re.compile(r"^[0-9a-f]{32}$")
FLAG_UP, FLAG_UV = 0x01, 0x04


class Deny(Exception):
    pass


def b64u_dec(s):
    if not isinstance(s, str) or not re.fullmatch(r"[A-Za-z0-9_-]*", s):
        raise Deny("BAD_ENCODING")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64u_enc(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def load_config(path):
    with open(path, encoding="utf-8") as f:
        cfg = json.load(f)
    for k in ("rp_id", "origin", "host", "manifest_path", "start_cmd", "state_dir",
              "trusted_keys", "page_url", "relay_post", "relay_poll"):
        if k not in cfg:
            raise SystemExit(f"config missing {k}")
    cfg.setdefault("max_ttl_seconds", 600)
    os.makedirs(os.path.join(cfg["state_dir"], "pending"), mode=0o700, exist_ok=True)
    os.makedirs(os.path.join(cfg["state_dir"], "used"), mode=0o700, exist_ok=True)
    return cfg


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def fsync_dir(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def create_exclusive(path, data):
    """O_EXCL create + file and directory fsync. Raises FileExistsError if present."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    fsync_dir(os.path.dirname(path))


@contextmanager
def boot_lock(cfg):
    fd = os.open(os.path.join(cfg["state_dir"], "boot.lock"), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def out(result, **kw):
    print(json.dumps({"result": result, **kw}, ensure_ascii=False))


# ---------------------------------------------------------------- keys

def load_keys(cfg):
    try:
        with open(cfg["trusted_keys"], encoding="utf-8") as f:
            keys = json.load(f)
    except FileNotFoundError:
        return {}
    return {k["credential_id"]: k for k in keys}


def key_fingerprint(spki_der):
    return "SHA256:" + b64u_enc(hashlib.sha256(spki_der).digest())


def cmd_add_key(cfg, path):
    with open(path, encoding="utf-8") as f:
        reg = json.load(f)
    if reg.get("alg") != -7:
        raise SystemExit("only ES256 (-7) keys are accepted")
    if reg.get("rp_id") != cfg["rp_id"] or reg.get("origin") != cfg["origin"]:
        raise SystemExit("key was registered for a different site")
    spki = b64u_dec(reg["public_key_spki"])
    pub = serialization.load_der_public_key(spki)
    if not isinstance(pub, ec.EllipticCurvePublicKey) or pub.curve.name != "secp256r1":
        raise SystemExit("not a P-256 public key")
    b64u_dec(reg["credential_id"])
    keys = list(load_keys(cfg).values())
    if any(k["credential_id"] == reg["credential_id"] for k in keys):
        raise SystemExit("key already registered")
    keys.append({k: reg[k] for k in ("label", "rp_id", "origin", "credential_id", "alg", "public_key_spki")})
    tmp = cfg["trusted_keys"] + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(keys, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, cfg["trusted_keys"])
    out("PASS", added=reg.get("label"), fingerprint=key_fingerprint(spki), total_keys=len(keys))


# ---------------------------------------------------------------- request

def cmd_request(cfg, ttl):
    ttl = int(ttl or cfg["max_ttl_seconds"])
    if not 30 <= ttl <= cfg["max_ttl_seconds"]:
        raise SystemExit(f"ttl must be 30..{cfg['max_ttl_seconds']}")
    nonce = secrets.token_hex(16)
    text = (
        "xj-boot-approval v1\n"
        f"host={cfg['host']}\n"
        f"manifest_sha256={sha256_file(cfg['manifest_path'])}\n"
        f"nonce={nonce}\n"
        f"expires_unix={int(time.time()) + ttl}\n"
    ).encode()
    assert APPROVAL_RE.match(text)
    create_exclusive(os.path.join(cfg["state_dir"], "pending", nonce), text)
    frag = urllib.parse.urlencode({"a": b64u_enc(text), "r": cfg["relay_post"]})
    url = f"{cfg['page_url']}#{frag}"
    notified = False
    if cfg.get("notify_url"):
        req = urllib.request.Request(
            cfg["notify_url"], data=f"Gateway {cfg['host']} 等你批准啟動".encode(),
            headers={"Title": "XJ Boot", "Click": url, "Priority": "high"}, method="POST")
        try:
            urllib.request.urlopen(req, timeout=10).read()
            notified = True
        except OSError as e:
            print(f"notify failed: {e}", file=sys.stderr)
    out("REQUESTED", nonce=nonce, url=url, notified=notified, expires_in=ttl)


# ---------------------------------------------------------------- verify

def verify_assertion(cfg, keys, pending_text, payload):
    """Return the parsed approval fields if the Owner's passkey signed exactly pending_text."""
    if not isinstance(payload, dict) or payload.get("v") != 1:
        raise Deny("BAD_PAYLOAD")
    if b64u_dec(payload.get("approval", "")) != pending_text:
        raise Deny("APPROVAL_TEXT_MISMATCH")
    m = APPROVAL_RE.match(pending_text)
    if not m:
        raise Deny("APPROVAL_FORMAT")
    key = keys.get(payload.get("credential_id"))
    if key is None:
        raise Deny("UNKNOWN_KEY")
    if key["rp_id"] != cfg["rp_id"] or key["origin"] != cfg["origin"]:
        raise Deny("KEY_SITE_MISMATCH")

    cdj_raw = b64u_dec(payload.get("client_data_json", ""))
    try:
        cdj = json.loads(cdj_raw)
    except ValueError:
        raise Deny("CLIENT_DATA_JSON")
    if cdj.get("type") != "webauthn.get":
        raise Deny("CLIENT_DATA_TYPE")
    if cdj.get("challenge") != b64u_enc(hashlib.sha256(pending_text).digest()):
        raise Deny("CHALLENGE_MISMATCH")
    if cdj.get("origin") != cfg["origin"]:
        raise Deny("ORIGIN_MISMATCH")
    if cdj.get("crossOrigin") is True:
        raise Deny("CROSS_ORIGIN")

    auth = b64u_dec(payload.get("authenticator_data", ""))
    if len(auth) < 37:
        raise Deny("AUTH_DATA_SHORT")
    if auth[:32] != hashlib.sha256(cfg["rp_id"].encode()).digest():
        raise Deny("RP_ID_MISMATCH")
    flags = auth[32]
    if not flags & FLAG_UP:
        raise Deny("USER_NOT_PRESENT")
    if not flags & FLAG_UV:
        raise Deny("USER_NOT_VERIFIED")

    pub = serialization.load_der_public_key(b64u_dec(key["public_key_spki"]))
    signed = auth + hashlib.sha256(cdj_raw).digest()
    try:
        pub.verify(b64u_dec(payload.get("signature", "")), signed, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise Deny("BAD_SIGNATURE")
    host, manifest, nonce, expires = (g.decode() for g in m.groups())
    return {"host": host, "manifest_sha256": manifest, "nonce": nonce,
            "expires_unix": int(expires), "key": key.get("label")}


def poll_relay(cfg, nonce, wait):
    """Fetch the Owner's assertion for this nonce from the (untrusted) relay."""
    deadline = time.time() + wait
    while True:
        try:
            with urllib.request.urlopen(cfg["relay_poll"], timeout=15) as r:
                body = r.read().decode("utf-8", "replace")
        except OSError as e:
            body = ""
            print(f"relay poll failed: {e}", file=sys.stderr)
        for line in body.splitlines():
            try:
                evt = json.loads(line)
                msg = evt.get("message", line) if isinstance(evt, dict) and "message" in evt else line
                payload = json.loads(msg) if isinstance(msg, str) else msg
            except ValueError:
                continue
            if isinstance(payload, dict) and payload.get("nonce") == nonce:
                return payload
        if time.time() >= deadline:
            raise Deny("NO_APPROVAL_RECEIVED")
        time.sleep(3)


def pid_alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def read_pid(cfg):
    try:
        with open(os.path.join(cfg["state_dir"], "service.pid")) as f:
            return int(f.read().strip())
    except (FileNotFoundError, ValueError):
        return None


def cmd_start(cfg, nonce, assertion_file, wait):
    if not NONCE_RE.match(nonce or ""):
        raise Deny("BAD_NONCE")
    try:
        with open(os.path.join(cfg["state_dir"], "pending", nonce), "rb") as f:
            pending_text = f.read()
    except FileNotFoundError:
        raise Deny("UNKNOWN_REQUEST")
    if assertion_file:
        with open(assertion_file, encoding="utf-8") as f:
            payload = json.load(f)
    else:
        payload = poll_relay(cfg, nonce, wait)
    keys = load_keys(cfg)

    with boot_lock(cfg):
        state = cfg["state_dir"]
        if os.path.exists(os.path.join(state, "STOP")):
            raise Deny("STOP_PRESENT")
        fields = verify_assertion(cfg, keys, pending_text, payload)
        now = time.time()
        if fields["expires_unix"] <= now:
            raise Deny("EXPIRED")
        if fields["expires_unix"] > now + cfg["max_ttl_seconds"] + 5:
            raise Deny("TTL_TOO_LONG")
        if fields["host"] != cfg["host"]:
            raise Deny("HOST_MISMATCH")
        if fields["manifest_sha256"] != sha256_file(cfg["manifest_path"]):
            raise Deny("MANIFEST_CHANGED")
        old = read_pid(cfg)
        if old and pid_alive(old):
            raise Deny("ALREADY_RUNNING")
        try:
            create_exclusive(os.path.join(state, "used", nonce),
                             json.dumps({"claimed_at": now, **fields}).encode())
        except FileExistsError:
            raise Deny("REPLAY")
        log = open(os.path.join(state, "service.log"), "ab")
        proc = subprocess.Popen(cfg["start_cmd"], stdout=log, stderr=subprocess.STDOUT,
                                stdin=subprocess.DEVNULL, start_new_session=True)
        tmp = os.path.join(state, "service.pid.tmp")
        with open(tmp, "w") as f:
            f.write(str(proc.pid))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, os.path.join(state, "service.pid"))
    out("PASS", started_pid=proc.pid, approved_by=fields["key"], nonce=nonce,
        manifest_sha256=fields["manifest_sha256"])


def cmd_stop(cfg, grace):
    with boot_lock(cfg):
        stop_path = os.path.join(cfg["state_dir"], "STOP")
        try:
            create_exclusive(stop_path, str(time.time()).encode())
        except FileExistsError:
            pass
        pid = read_pid(cfg)
        killed = False
        if pid and pid_alive(pid):
            try:
                os.killpg(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            deadline = time.time() + grace
            while pid_alive(pid) and time.time() < deadline:
                try:
                    os.waitpid(pid, os.WNOHANG)
                except ChildProcessError:
                    pass
                time.sleep(0.2)
            if pid_alive(pid):
                try:
                    os.killpg(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            killed = True
    out("STOPPED", pid=pid, killed=killed)


def cmd_status(cfg):
    pid = read_pid(cfg)
    out("STATUS", stop=os.path.exists(os.path.join(cfg["state_dir"], "STOP")),
        pid=pid, running=bool(pid and pid_alive(pid)),
        keys=[{"label": k.get("label"), "fingerprint": key_fingerprint(b64u_dec(k["public_key_spki"]))}
              for k in load_keys(cfg).values()])


def cmd_clear_stop(cfg):
    with boot_lock(cfg):
        p = os.path.join(cfg["state_dir"], "STOP")
        if os.path.exists(p):
            os.unlink(p)
            fsync_dir(cfg["state_dir"])
    out("STOP_CLEARED")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", default=os.environ.get("XJBOOT_CONFIG", "xjboot.json"))
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("request"); r.add_argument("--ttl", type=int)
    s = sub.add_parser("start"); s.add_argument("--nonce", required=True)
    s.add_argument("--assertion-file"); s.add_argument("--wait", type=int, default=300)
    t = sub.add_parser("stop"); t.add_argument("--grace", type=float, default=10)
    sub.add_parser("status"); sub.add_parser("clear-stop")
    k = sub.add_parser("add-key"); k.add_argument("file")
    a = ap.parse_args(argv)
    cfg = load_config(a.config)
    try:
        if a.cmd == "request":
            cmd_request(cfg, a.ttl)
        elif a.cmd == "start":
            cmd_start(cfg, a.nonce, a.assertion_file, a.wait)
        elif a.cmd == "stop":
            cmd_stop(cfg, a.grace)
        elif a.cmd == "status":
            cmd_status(cfg)
        elif a.cmd == "clear-stop":
            cmd_clear_stop(cfg)
        elif a.cmd == "add-key":
            cmd_add_key(cfg, a.file)
    except Deny as e:
        out("DENY", reason=str(e))
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
