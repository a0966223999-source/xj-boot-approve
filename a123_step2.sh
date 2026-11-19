#!/usr/bin/env bash
# A123 step 2 (steps 1-4): verify, configure, register Owner key, preflight, request approval.
# Usage:
#   bash a123_step2.sh --backend <Gateway backend dir> --launcher-dir <dir with xjboot.py> \
#        --start-cmd-json '["/path/to/start", "arg"]'
# Writes only under $HOME/.xj-boot. Never modifies the backend. Stops at the first mismatch.
set -euo pipefail

# ---- fixed expectations (Owner-approved values; do not edit) ----
EXP_XJBOOT=db9f7675c15ac1e9cddc8eb6d93886d3a6ae76d8af1d10d24399380c02eebdc2
EXP_APP=7dae7f688aec3210bfc709152f29ecc990992a19c1438980b7cb9ff840365ecb
EXP_CONSENT=195eef2cd57a3c5b8e406ac7393ea30745556d6cd29ff134c406ddd7bee1328a
EXP_KEYFILE=16610dd285e2451dfae680edc2560c770509904b1f9e950d56ba21469b156e11
EXP_FINGERPRINT=SHA256:kiqTGaSVZ_cBKpzk8HrV0fwZf-ZvdOCdpg_vu_BTslY
OWNER_KEY_B64=eyJ2IjoxLCJsYWJlbCI6Im93bmVyLTIwMjYtMTEtMTkiLCJycF9pZCI6ImEwOTY2MjIzOTk5LXNvdXJjZS5naXRodWIuaW8iLCJvcmlnaW4iOiJodHRwczovL2EwOTY2MjIzOTk5LXNvdXJjZS5naXRodWIuaW8iLCJjcmVkZW50aWFsX2lkIjoiNnJnT2RyNEVzVFJYUVplM2pIdG8xdTB6RF9WaVZGcHh0VU1iOUNyQ20yZyIsImFsZyI6LTcsInB1YmxpY19rZXlfc3BraSI6Ik1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRWxGdHRsN1R0Y0ZWeWNYcGZMR1RYdmpOYmhJaXViSGc1UmlXSkttYjBJTmU2bTkyVXZMRVdvZGU2RFdpY2FnWFptLUplNzlHRXdxN21URXNGV2hVT1J3In0=
RELAY=https://ntfy.sh/xjb-r-14e43c87f05189e5cf389d25
NOTIFY=https://ntfy.sh/xjb-n-32dd4d84efe70246b1799a9d
PAGE=https://a0966223999-source.github.io/xj-boot-approve/
RP_ID=a0966223999-source.github.io
ORIGIN=https://a0966223999-source.github.io
XJ_HOME="${XJ_HOME:-$HOME/.xj-boot}"

die() { echo "STOP: $*" >&2; exit 2; }
ok()  { echo "OK   $*"; }
sha() { sha256sum "$1" | cut -d' ' -f1; }

BACKEND= LAUNCHER= START_JSON=
while [ $# -gt 0 ]; do
  case "$1" in
    --backend) BACKEND="$2"; shift 2;;
    --launcher-dir) LAUNCHER="$2"; shift 2;;
    --start-cmd-json) START_JSON="$2"; shift 2;;
    *) die "unknown argument $1";;
  esac
done
[ -n "$BACKEND" ] && [ -n "$LAUNCHER" ] && [ -n "$START_JSON" ] || die "need --backend, --launcher-dir, --start-cmd-json"
BACKEND="$(cd "$BACKEND" && pwd)"; LAUNCHER="$(cd "$LAUNCHER" && pwd)"

echo "== 1. launcher and Gateway source =="
[ "$(sha "$LAUNCHER/xjboot.py")" = "$EXP_XJBOOT" ] || die "xjboot.py SHA256 mismatch: $(sha "$LAUNCHER/xjboot.py")"
ok "xjboot.py $EXP_XJBOOT"
[ -f "$BACKEND/app/gateway/app.py" ] || die "not found: $BACKEND/app/gateway/app.py (wrong --backend?)"
[ "$(sha "$BACKEND/app/gateway/app.py")" = "$EXP_APP" ] || die "app/gateway/app.py SHA256 $(sha "$BACKEND/app/gateway/app.py") != $EXP_APP"
ok "app/gateway/app.py $EXP_APP"
[ "$(sha "$BACKEND/gateway_agent_consent.py")" = "$EXP_CONSENT" ] || die "gateway_agent_consent.py SHA256 $(sha "$BACKEND/gateway_agent_consent.py") != $EXP_CONSENT"
ok "gateway_agent_consent.py $EXP_CONSENT"

echo "== 2. start command =="
python3 -I - "$START_JSON" <<'PY' || exit 2
import json, os, sys
try:
    cmd = json.loads(sys.argv[1])
except ValueError as e:
    sys.exit(f"STOP: --start-cmd-json is not valid JSON: {e}")
if not (isinstance(cmd, list) and cmd and all(isinstance(x, str) and x for x in cmd)):
    sys.exit("STOP: --start-cmd-json must be a non-empty JSON list of strings")
if not os.path.isabs(cmd[0]):
    sys.exit("STOP: first element of start command must be an absolute path")
print("OK   start_cmd", json.dumps(cmd))
PY

echo "== 3. new manifest (old MANIFEST.json untouched) =="
mkdir -p "$XJ_HOME/state"; chmod 700 "$XJ_HOME" "$XJ_HOME/state"
MAN="$XJ_HOME/gateway-manifest-20261119.txt"
START0="$(python3 -I -c 'import json,sys;print(json.loads(sys.argv[1])[0])' "$START_JSON")"
{
  (cd "$BACKEND" && { find app/gateway -type f -name '*.py' -print; echo gateway_agent_consent.py; } \
     | LC_ALL=C sort -u | while read -r f; do printf '%s  backend/%s\n' "$(sha256sum "$f" | cut -d' ' -f1)" "$f"; done)
  if [ -f "$START0" ]; then printf '%s  %s\n' "$(sha "$START0")" "$START0"; fi
} > "$MAN.tmp"
grep -q "^$EXP_APP  backend/app/gateway/app.py\$" "$MAN.tmp" || die "manifest does not contain expected app.py line"
grep -q "^$EXP_CONSENT  backend/gateway_agent_consent.py\$" "$MAN.tmp" || die "manifest does not contain expected consent line"
mv "$MAN.tmp" "$MAN"
MAN_SHA="$(sha "$MAN")"
ok "manifest $(wc -l < "$MAN") files, SHA256 $MAN_SHA"

echo "== 4. config =="
CFG="$XJ_HOME/xjboot.json"
python3 -I - "$CFG" "$MAN" "$START_JSON" "$XJ_HOME" "$RP_ID" "$ORIGIN" "$PAGE" "$RELAY" "$NOTIFY" <<'PY' || exit 2
import json, socket, sys
cfg_path, man, start_json, home, rp, origin, page, relay, notify = sys.argv[1:]
cfg = {"rp_id": rp, "origin": origin, "host": socket.gethostname().split(".")[0],
       "manifest_path": man, "start_cmd": json.loads(start_json),
       "state_dir": home + "/state", "trusted_keys": home + "/trusted_keys.json",
       "page_url": page, "relay_post": relay,
       "relay_poll": relay + "/json?poll=1&since=15m", "notify_url": notify, "max_ttl_seconds": 600}
with open(cfg_path, "w") as f:
    json.dump(cfg, f, indent=2, ensure_ascii=False)
print("OK   host", cfg["host"])
PY
chmod 600 "$CFG"
ok "xjboot.json SHA256 $(sha "$CFG")"
XJ=(python3 -I "$LAUNCHER/xjboot.py" --config "$CFG")

echo "== 5. Owner public key =="
KEYF="$XJ_HOME/owner-reg.json"
echo "$OWNER_KEY_B64" | base64 -d > "$KEYF"
[ "$(sha "$KEYF")" = "$EXP_KEYFILE" ] || die "owner-reg.json SHA256 mismatch"
ok "owner-reg.json $EXP_KEYFILE"
if [ ! -f "$XJ_HOME/trusted_keys.json" ]; then
  out="$("${XJ[@]}" add-key "$KEYF")"; echo "     $out"
  echo "$out" | grep -q "\"fingerprint\": \"$EXP_FINGERPRINT\"" || die "fingerprint mismatch after add-key"
fi
st="$("${XJ[@]}" status)"
python3 -I -c '
import json,sys
d=json.loads(sys.argv[1]); fp=[k["fingerprint"] for k in d["keys"]]
if fp!=[sys.argv[2]]: sys.exit("STOP: trusted keys must be exactly the Owner key, got %s" % fp)
if d["running"] or d["stop"]: sys.exit("STOP: launcher not idle: %s" % d)
print("OK   exactly 1 trusted key", fp[0], "; idle")' "$st" "$EXP_FINGERPRINT" || exit 2

echo "== 6. network preflight =="
python3 -I -c "import urllib.request,sys;r=urllib.request.urlopen(sys.argv[1]+'/json?poll=1&since=1m',timeout=15);print('OK   ntfy relay HTTP',r.status)" "$RELAY" \
  || die "cannot reach ntfy relay (do not install packages or change network; report this output)"

echo "== 7. approval request =="
req="$("${XJ[@]}" request)"
python3 -I -c '
import json,sys,time
d=json.loads(sys.argv[1]); assert d["result"]=="REQUESTED", d
if not d["notified"]: sys.exit("STOP: phone notification was not sent")
exp=time.time()+d["expires_in"]
print("=================== REPORT TO OWNER ===================")
print("host            :", sys.argv[2])
print("manifest_sha256 :", sys.argv[3])
print("nonce           :", d["nonce"])
print("expires (UTC)   :", time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(exp)))
print("expires (Taipei):", time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(exp+8*3600)))
print("========================================================")
print("NEXT (run now, waits for the Owner fingerprint):")
print("  " + " ".join(sys.argv[4:]) + " start --nonce " + d["nonce"] + " --wait 590")
' "$req" "$(python3 -I -c 'import json,sys;print(json.load(open(sys.argv[1]))["host"])' "$CFG")" "$MAN_SHA" "${XJ[@]}"
echo "ALL CHECKS PASS"
