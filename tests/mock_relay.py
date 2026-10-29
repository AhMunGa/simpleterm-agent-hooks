#!/usr/bin/env python3
"""Mock SimpleTerm relay for testing plugins/simpleterm/scripts (stdlib only).

Run with `python3 -I mock_relay.py [--port N]`. It prints `PORT <n>` on stdout
and serves the relay's host endpoints (protocol v1):

  POST /v1/ingest                 records the request, answers {"ok":true,"push":...}
  GET  /v1/decision?rid=&wait=    long-polls; answers pending or decided

It also plays the device: for a link configured with a decision it decrypts the
envelope with `openssl` (the enc key is part of the test config), checks the MAC
and `nh == sha256(nonce)`, and signs the decision with the link's mac key
(`dmac`), exactly as the app would before calling /v1/decide.

Test control endpoints (no auth, loopback only):
  POST /_ctl/config   {"links":{id:{secret,enc,mac,push,decision,after,decisions,
                        revoked,decision_http,ingest_delay}}}
  GET  /_ctl/records  every request seen, with decrypted plaintext and checks
  POST /_ctl/reset
"""

import argparse
import base64
import hashlib
import hmac
import json
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

LOCK = threading.Lock()
STATE = {"links": {}, "records": [], "requests": {}}
OPENSSL = "openssl"


def decrypt(env, enc_hex, mac_hex):
    """Returns (plaintext or None, mac_ok)."""
    msg = ("st1." + env["iv"] + "." + env["ct"]).encode("ascii")
    expect = hmac.new(bytes.fromhex(mac_hex), msg, hashlib.sha256).hexdigest()
    mac_ok = hmac.compare_digest(expect, env.get("mac", ""))
    if not mac_ok:
        return None, False
    out = subprocess.run(
        [OPENSSL, "enc", "-d", "-aes-256-cbc", "-K", enc_hex, "-iv", env["iv"]],
        input=base64.b64decode(env["ct"]),
        capture_output=True,
        check=False,
    )
    if out.returncode != 0:
        return None, True
    return out.stdout.decode("utf-8"), True


def dmac_for(mac_hex, rid, decision, nonce):
    msg = ("st1-dec." + rid + "." + decision + "." + nonce).encode("ascii")
    return hmac.new(bytes.fromhex(mac_hex), msg, hashlib.sha256).hexdigest()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # keep test output clean
        pass

    def _send(self, code, obj):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _auth(self):
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer ") or "." not in auth:
            return None, None
        lid, secret = auth[7:].split(".", 1)
        with LOCK:
            link = STATE["links"].get(lid)
        if not link or hashlib.sha256(secret.encode()).hexdigest() != hashlib.sha256(
            link["secret"].encode()
        ).hexdigest():
            return None, None
        return lid, link

    def do_POST(self):
        url = urlparse(self.path)
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b""
        if url.path == "/_ctl/config":
            cfg = json.loads(raw or b"{}")
            with LOCK:
                STATE["links"] = cfg.get("links", {})
            return self._send(200, {"ok": True})
        if url.path == "/_ctl/reset":
            with LOCK:
                STATE["records"].clear()
                STATE["requests"].clear()
            return self._send(200, {"ok": True})
        if url.path != "/v1/ingest":
            return self._send(404, {"ok": False, "error": "not-found"})
        received = time.time()
        lid, link = self._auth()
        rec = {
            "path": url.path,
            "link": lid,
            "received": received,
            "auth_ok": bool(lid),
            "ua": self.headers.get("User-Agent", ""),
            "size": len(raw),
        }
        if not lid:
            rec["status"] = 401
            with LOCK:
                STATE["records"].append(rec)
            return self._send(401, {"ok": False, "error": "unauthorized"})
        if link.get("revoked"):
            rec["status"] = 410
            with LOCK:
                STATE["records"].append(rec)
            return self._send(410, {"ok": False, "error": "revoked"})
        if len(raw) > 4096:
            rec["status"] = 413
            with LOCK:
                STATE["records"].append(rec)
            return self._send(413, {"ok": False, "error": "too-large"})
        body = json.loads(raw)
        rec["body"] = body
        plain, mac_ok = decrypt(body["env"], link["enc"], link["mac"])
        rec["mac_ok"] = mac_ok
        rec["plain"] = plain
        nonce = None
        if plain:
            p = json.loads(plain)
            rec["plain_json"] = p
            nonce = p.get("nonce")
            if nonce is not None:
                rec["nh_ok"] = (
                    hashlib.sha256(nonce.encode()).hexdigest() == body.get("nh")
                )
        with LOCK:
            req = {"created": received, "nonce": nonce, "ev": body.get("ev")}
            # Optional per-request plan: links[id].decisions = [{"decision", "after"}, ...]
            if nonce is not None and link.get("decisions"):
                plan = link["decisions"].pop(0)
                req["decision"], req["after"] = plan.get("decision"), plan.get("after", 0)
            STATE["requests"][(lid, body["rid"])] = req
        time.sleep(float(link.get("ingest_delay", 0)))
        rec["status"] = 200
        rec["responded"] = time.time()
        with LOCK:
            STATE["records"].append(rec)
        return self._send(200, {"ok": True, "push": link.get("push", "sent")})

    def do_GET(self):
        url = urlparse(self.path)
        if url.path == "/_ctl/records":
            with LOCK:
                recs = list(STATE["records"])
            return self._send(200, {"records": recs})
        if url.path != "/v1/decision":
            return self._send(404, {"ok": False, "error": "not-found"})
        q = parse_qs(url.query)
        rid = q.get("rid", [""])[0]
        wait = min(int(q.get("wait", ["0"])[0] or 0), 25)
        lid, link = self._auth()
        rec = {"path": url.path, "link": lid, "received": time.time(), "rid": rid, "wait": wait}
        with LOCK:
            STATE["records"].append(rec)
        if not lid:
            return self._send(401, {"ok": False, "error": "unauthorized"})
        if link.get("decision_http"):
            return self._send(int(link["decision_http"]), {"ok": False, "error": link.get("decision_error", "expired")})
        with LOCK:
            req = STATE["requests"].get((lid, rid))
        if not req:
            return self._send(404, {"ok": False, "error": "not-found"})
        decision = req["decision"] if "decision" in req else link.get("decision")
        after = req["after"] if "after" in req else link.get("after", 0)
        end = time.time() + wait
        while True:
            ready = decision and time.time() >= req["created"] + float(after)
            if ready and req["nonce"]:
                mac_key = link["mac"]
                if decision == "bad_dmac":
                    d, mac_key = "allow", "ff" * 32
                else:
                    d = decision
                return self._send(
                    200,
                    {
                        "ok": True,
                        "status": "decided",
                        "decision": d,
                        "dmac": dmac_for(mac_key, rid, d, req["nonce"]),
                    },
                )
            if time.time() >= end:
                return self._send(200, {"ok": True, "status": "pending"})
            time.sleep(0.1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--openssl", default="openssl")
    args = ap.parse_args()
    global OPENSSL
    OPENSSL = args.openssl
    srv = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    srv.handle_error = lambda request, client_address: None  # hooks kill curl on exit
    srv.daemon_threads = True
    print("PORT", srv.server_address[1], flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    sys.exit(0)


if __name__ == "__main__":
    main()
