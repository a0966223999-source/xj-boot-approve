"""End-to-end test of xjboot with a real WebAuthn flow in Chromium (CDP virtual authenticator)."""
import base64, hashlib, json, os, shutil, subprocess, sys, tempfile, threading, time
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from playwright.sync_api import sync_playwright

SRC = sys.argv[1]  # directory with index.html and xjboot.py
WORK = tempfile.mkdtemp(prefix="xjboot-e2e-")
RELAY = os.path.join(WORK, "relay.jsonl")
open(RELAY, "w").close()
results = []


def check(name, got, want):
    ok = got == want
    results.append((name, ok, got, want))
    print(("PASS " if ok else "FAIL ") + f"{name}: got={got} want={want}", flush=True)


class H(SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=SRC, **kw)

    def log_message(self, *a):
        pass

    def do_POST(self):
        if self.path != "/relay":
            self.send_error(404); return
        body = self.rfile.read(int(self.headers["Content-Length"])).decode()
        with open(RELAY, "a") as f:
            f.write(json.dumps({"message": body}) + "\n")
        self.send_response(200); self.send_header("Access-Control-Allow-Origin", "*"); self.end_headers()

    def do_GET(self):
        if self.path.startswith("/relay"):
            data = open(RELAY, "rb").read()
            self.send_response(200); self.end_headers(); self.wfile.write(data); return
        super().do_GET()


srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
PORT = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()
ORIGIN = f"http://localhost:{PORT}"

manifest = os.path.join(WORK, "manifest.txt")
open(manifest, "w").write("gateway build 1\n")
cfg = {
    "rp_id": "localhost", "origin": ORIGIN, "host": "gateway-test",
    "manifest_path": manifest,
    "start_cmd": [sys.executable, "-c", "import time; time.sleep(600)"],
    "state_dir": os.path.join(WORK, "state"),
    "trusted_keys": os.path.join(WORK, "trusted_keys.json"),
    "page_url": f"{ORIGIN}/index.html",
    "relay_post": f"{ORIGIN}/relay", "relay_poll": f"{ORIGIN}/relay",
    "max_ttl_seconds": 600,
}
CFG = os.path.join(WORK, "xjboot.json")
json.dump(cfg, open(CFG, "w"))


def xj(*args, cfgpath=CFG):
    p = subprocess.run([sys.executable, "-I", os.path.join(SRC, "xjboot.py"), "--config", cfgpath, *args],
                       capture_output=True, text=True, timeout=120)
    try:
        return json.loads(p.stdout.strip().splitlines()[-1])
    except Exception:
        return {"result": "CRASH", "stdout": p.stdout, "stderr": p.stderr[-800:]}


def alive(pid):
    try:
        os.kill(pid, 0); return True
    except ProcessLookupError:
        return False


def relay_payload(nonce):
    for line in open(RELAY):
        msg = json.loads(json.loads(line)["message"])
        if msg.get("nonce") == nonce:
            return msg


with sync_playwright() as pw:
    browser = pw.chromium.launch()
    ctx = browser.new_context()
    page = ctx.new_page()
    page.on("pageerror", lambda e: print("   pageerror:", e, flush=True))
    cdp = ctx.new_cdp_session(page)
    cdp.send("WebAuthn.enable", {"enableUI": False})
    auth = cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {
        "protocol": "ctap2", "transport": "internal", "hasResidentKey": True,
        "hasUserVerification": True, "isUserVerified": True,
        "automaticPresenceSimulation": True}})["authenticatorId"]

    def register():
        page.goto("about:blank")
        page.goto(f"{ORIGIN}/index.html#m=register")
        page.click("#btn-register", timeout=5000)
        page.wait_for_selector("#register-out:not(.hidden)", timeout=15000)
        return page.input_value("#register-out")

    def approve(url):
        page.goto("about:blank")
        page.goto(url)
        page.click("#btn-approve")
        page.wait_for_function("document.getElementById('approve-msg').textContent.length > 4"
                               " && !document.getElementById('approve-msg').textContent.startsWith('等待')",
                               timeout=15000)
        return page.text_content("#approve-msg")

    # --- register Owner key
    reg = register()
    regf = os.path.join(WORK, "reg.json"); open(regf, "w").write(reg)
    r = xj("add-key", regf)
    check("register owner passkey", r["result"], "PASS")
    print("   key fingerprint:", r.get("fingerprint"))

    # 1. happy path: request -> fingerprint -> start once
    rq = xj("request"); n1 = rq["nonce"]
    msg = approve(rq["url"])
    check("page shows approved", "已批准" in (msg or ""), True)
    st = xj("start", "--nonce", n1, "--wait", "10")
    check("valid approval starts once", st["result"], "PASS")
    pid1 = st.get("started_pid")
    check("service process running", bool(pid1 and alive(pid1)), True)

    # 2. STOP stops the running service
    sp = xj("stop", "--grace", "3")
    time.sleep(0.3)
    check("STOP stops running service", alive(pid1) if pid1 else None, False)

    # 3. STOP present blocks a new, valid approval (and does not consume it)
    rq2 = xj("request"); n2 = rq2["nonce"]; approve(rq2["url"])
    check("STOP present -> deny", xj("start", "--nonce", n2, "--wait", "10").get("reason"), "STOP_PRESENT")
    xj("clear-stop")

    # 4. replay of the already-used approval
    check("replay used approval -> deny", xj("start", "--nonce", n1, "--wait", "5").get("reason"), "REPLAY")

    # 5. the approval refused by STOP is still usable once after clear-stop
    st2 = xj("start", "--nonce", n2, "--wait", "5")
    check("approval not consumed by STOP deny", st2["result"], "PASS")
    xj("stop", "--grace", "3"); xj("clear-stop")

    # 6. concurrent double start on one approval -> exactly one PASS
    rq3 = xj("request"); n3 = rq3["nonce"]; approve(rq3["url"])
    pf = os.path.join(WORK, "p3.json"); json.dump(relay_payload(n3), open(pf, "w"))
    cmd = [sys.executable, "-I", os.path.join(SRC, "xjboot.py"), "--config", CFG, "start", "--nonce", n3,
           "--assertion-file", pf]
    procs = [subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True) for _ in range(4)]
    outs = [json.loads(p.communicate()[0].strip()) for p in procs]
    check("4 concurrent starts -> exactly 1 PASS", sum(o["result"] == "PASS" for o in outs), 1)
    xj("stop", "--grace", "3"); xj("clear-stop")

    # 7. tampered signature / swapped approval text
    rq4 = xj("request"); n4 = rq4["nonce"]; approve(rq4["url"])
    good = relay_payload(n4)
    bad = dict(good); sig = bytearray(base64.urlsafe_b64decode(good["signature"] + "=="))
    sig[-1] ^= 1; bad["signature"] = base64.urlsafe_b64encode(bytes(sig)).rstrip(b"=").decode()
    json.dump(bad, open(pf, "w"))
    check("tampered signature -> deny", xj("start", "--nonce", n4, "--assertion-file", pf).get("reason"), "BAD_SIGNATURE")
    rq5 = xj("request"); n5 = rq5["nonce"]
    swapped = dict(good); swapped["nonce"] = n5   # signature for n4 presented against request n5
    json.dump(swapped, open(pf, "w"))
    check("signature for another request -> deny",
          xj("start", "--nonce", n5, "--assertion-file", pf).get("reason"), "APPROVAL_TEXT_MISMATCH")

    # 8. manifest changed after approval
    open(manifest, "w").write("gateway build 2 (changed)\n")
    json.dump(good, open(pf, "w"))
    check("manifest changed -> deny", xj("start", "--nonce", n4, "--assertion-file", pf).get("reason"), "MANIFEST_CHANGED")
    open(manifest, "w").write("gateway build 1\n")

    # 9. wrong host config
    cfg_b = dict(cfg, host="other-host"); CFG_B = os.path.join(WORK, "b.json"); json.dump(cfg_b, open(CFG_B, "w"))
    check("host mismatch -> deny",
          xj("start", "--nonce", n4, "--assertion-file", pf, cfgpath=CFG_B).get("reason"), "HOST_MISMATCH")
    # n4 still unused and valid -> prove the denials consumed nothing
    check("valid approval still usable after denials", xj("start", "--nonce", n4, "--assertion-file", pf)["result"], "PASS")
    xj("stop", "--grace", "3"); xj("clear-stop")

    # 10. no fingerprint (user verification off) -> deny
    rq6 = xj("request"); n6 = rq6["nonce"]
    text = open(os.path.join(cfg["state_dir"], "pending", n6), "rb").read()
    cdp.send("WebAuthn.setUserVerified", {"authenticatorId": auth, "isUserVerified": False})
    page.goto(f"{ORIGIN}/index.html#m=none")
    payload = page.evaluate("""async (a) => {
        const dec = s => Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/') + '==='.slice((s.length+3)%4)), c => c.charCodeAt(0));
        const enc = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');
        const bytes = dec(a.approval);
        const cred = await navigator.credentials.get({publicKey:{challenge: await crypto.subtle.digest('SHA-256', bytes),
            rpId: location.hostname, userVerification: 'discouraged'}});
        const r = cred.response;
        return {v:1, nonce:a.nonce, approval:a.approval, credential_id:enc(cred.rawId),
                authenticator_data:enc(r.authenticatorData), client_data_json:enc(r.clientDataJSON), signature:enc(r.signature)};
    }""", {"approval": base64.urlsafe_b64encode(text).rstrip(b"=").decode(), "nonce": n6})
    json.dump(payload, open(pf, "w"))
    check("no fingerprint (UV=0) -> deny", xj("start", "--nonce", n6, "--assertion-file", pf).get("reason"), "USER_NOT_VERIFIED")
    cdp.send("WebAuthn.setUserVerified", {"authenticatorId": auth, "isUserVerified": True})

    # 11. a passkey that was never registered
    cdp.send("WebAuthn.removeVirtualAuthenticator", {"authenticatorId": auth})
    cdp_auth = [None]
    cdp_auth[0] = cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {
        "protocol": "ctap2", "transport": "internal", "hasResidentKey": True,
        "hasUserVerification": True, "isUserVerified": True, "automaticPresenceSimulation": True}})["authenticatorId"]
    register()  # created but NOT added to trusted keys
    rq7 = xj("request"); n7 = rq7["nonce"]; approve(rq7["url"])
    check("unregistered passkey -> deny", xj("start", "--nonce", n7, "--wait", "5").get("reason"), "UNKNOWN_KEY")

    # 12. expired approval
    rq8 = xj("request", "--ttl", "30"); n8 = rq8["nonce"]
    # fresh authenticator holding only one, newly trusted key
    for a in cdp.send("WebAuthn.getCredentials", {"authenticatorId": cdp_auth[0]})["credentials"]:
        pass
    cdp.send("WebAuthn.removeVirtualAuthenticator", {"authenticatorId": cdp_auth[0]})
    cdp_auth[0] = cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {
        "protocol": "ctap2", "transport": "internal", "hasResidentKey": True,
        "hasUserVerification": True, "isUserVerified": True, "automaticPresenceSimulation": True}})["authenticatorId"]
    reg2 = register(); open(regf, "w").write(reg2); xj("add-key", regf)
    approve(rq8["url"])
    print("   waiting 31s for expiry…", flush=True); time.sleep(31)
    check("expired approval -> deny", xj("start", "--nonce", n8, "--wait", "5").get("reason"), "EXPIRED")

    # 13. tampered link: page refuses a malformed approval
    page.goto("about:blank")
    page.goto(f"{ORIGIN}/index.html#a=eGotYm9vdA&r={ORIGIN}/relay")
    check("page rejects malformed link", page.is_visible("#invalid"), True)

    # 14-17 standing (long-term) approval through the real page
    xj("stop", "--grace", "3"); xj("clear-stop")
    rqs = xj("request", "--standing-days", "30"); ns = rqs["nonce"]
    page.goto("about:blank"); page.goto(rqs["url"])
    check("page shows long-term banner", page.is_visible("#standing-banner") and page.is_visible("#f-until"), True)
    check("page title says long-term", page.text_content("#approve h1"), "批准長期授權")
    page.click("#btn-approve")
    page.wait_for_function("document.getElementById('approve-msg').textContent.includes('已批准')", timeout=15000)
    st = xj("start", "--nonce", ns, "--wait", "10")
    check("standing approval via real WebAuthn -> PASS", (st["result"], st.get("mode")), ("PASS", "standing"))
    xj("stop", "--grace", "3"); xj("clear-stop")
    check("restart under standing grant -> PASS", xj("start", "--standing")["result"], "PASS")
    xj("stop", "--grace", "3")

    browser.close()

srv.shutdown()
failed = [r for r in results if not r[1]]
print(f"\nTOTAL {len(results)}  PASS {len(results)-len(failed)}  FAIL {len(failed)}")
shutil.rmtree(WORK, ignore_errors=True)
sys.exit(1 if failed else 0)
