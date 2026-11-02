#!/usr/bin/env python3
"""Tests for plugins/simpleterm/scripts (stdlib only). Run with `python3 -I`.

  python3 -I tests/run_tests.py                 # sh hook, every shell found
  python3 -I tests/run_tests.py --shell /bin/dash
  python3 -I tests/run_tests.py --pwsh /path/to/pwsh   # PowerShell hook
  python3 -I tests/run_tests.py --hook old/agent-hook.sh # another sh hook (baseline)

Each suite gets its own temporary HOME (with ~/.simpleterm/links/*.conf) and
its own mock_relay.py process. The sh hook is run once per shell × openssl
(macOS LibreSSL at /usr/bin/openssl and OpenSSL 3 when found).

The hook's test-only overrides (SIMPLETERM_HOOK_TEST=1 with
SIMPLETERM_HOOK_TEST_IV/NONCE/RID/TS) pin the random values so the envelope
can be compared byte for byte with the relay protocol v1 test vectors.
"""

import argparse
import base64
import hashlib
import json
import os
import pty
import re
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
HOOK_SH = ROOT / "plugins" / "simpleterm" / "scripts" / "agent-hook.sh"
SCRIPTS = HOOK_SH.parent
HOOK_PS1 = ROOT / "plugins" / "simpleterm" / "scripts" / "agent-hook.ps1"
MOCK = HERE / "mock_relay.py"

# Relay protocol v1 test vectors (envelope: AES-256-CBC + HMAC-SHA256).
V_ENC = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
V_MAC = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
V_IV = "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
V_RID = "0123456789abcdef"
V_NONCE = "ffeeddccbbaa99887766554433221100"
V_TS = "1793232000"
V_PLAIN = (
    '{"v":1,"rid":"0123456789abcdef","ev":"permission","app":"claude-code",'
    '"host":"dev-box","cwd":"api","msg":"approve Bash: npm test",'
    '"nonce":"ffeeddccbbaa99887766554433221100","ts":1793232000}'
)
V_CT = (
    "IGcJ0hpKHLKXKqAWqhkBIR2M6Gc8O2mQra4nw0Hz/qfz1C4SvySV5tTcWcK5OB4dBICpB9xR4O1eOSrg5Ceu"
    "vPBqSNVjaSuAMb4gBkA35l6UWiZJb1LF/FqwPOfCFzrDYkodY4UQDejIMzlOND+3ZZJRXRskJzplFr7gCIeF"
    "3aM6Jsv2QMi3LLkXHWshS7kxPOgkw4PQs3W4gVOChnOYD2g+jneeuRSS0JNRNjoIBtcszk7kOrRoNyoVbuX5mNfI"
)
V_ENV_MAC = "d67fad9ec88c5aa9193c98f5078d811249fd6f0013f3713fad3dcfeeb72b539b"
V_NH = "5d0b193317e951a7444b9bd4c632e0f1793fcbdfad115ae4caeba4f7ae39cca5"

LINK_A = {"id": "a1" * 16, "secret": "b2" * 32, "enc": V_ENC, "mac": V_MAC, "label": "dev-box"}
LINK_B = {"id": "c3" * 16, "secret": "d4" * 32, "enc": "e5" * 32, "mac": "f6" * 32, "label": "box-b"}
# The app's end of an SSH tunnel (kind=tunnel); its file sorts after LINK_A.
LINK_T = {"id": "e7" * 16, "secret": "f8" * 32, "enc": "a9" * 32, "mac": "ba" * 32, "label": "dev-box"}

# Utilities the sh hook needs apart from curl and openssl. printf is there
# as on any real system; the hook must still use the shell's builtin.
SH_UTILS = [
    "awk", "head", "date", "tr", "sed", "cut", "cksum", "wc", "tail", "mv", "rm",
    "mkdir", "chmod", "find", "sleep", "cat", "dd", "ls", "ps", "printf", "touch",
]


def perm_input(command="npm test", cwd="/home/u/api", session="sess-1", tool="Bash", event="PermissionRequest"):
    return json.dumps({
        "session_id": session,
        "transcript_path": "/home/u/.claude/projects/x/t.jsonl",
        "cwd": cwd,
        "permission_mode": "default",
        "hook_event_name": event,
        "tool_name": tool,
        "tool_input": {"command": command, "description": "Run tests"},
        "permission_suggestions": [{"type": "addRules", "behavior": "allow"}],
    })


class Suite:
    """One hook runtime (shell or pwsh) × openssl, with its own HOME and relay."""

    def __init__(self, name, argv, openssl=None, kind="sh"):
        self.name = name
        self.argv = argv
        self.openssl = openssl
        self.kind = kind
        self.results = []
        self.tmp = Path(tempfile.mkdtemp(prefix="st-hooktest-"))
        self.home = self.tmp / "home"
        self.bin = self.tmp / "bin"
        self.bare = self.tmp / "bare"  # no curl / openssl
        for d in (self.home, self.bin, self.bare):
            d.mkdir()
        for u in SH_UTILS:
            src = shutil.which(u, path="/usr/bin:/bin")
            if src:
                os.symlink(src, self.bare / u)
                os.symlink(src, self.bin / u)
        os.symlink("/usr/bin/curl", self.bin / "curl")
        os.symlink(openssl or "/usr/bin/openssl", self.bin / "openssl")
        if kind == "sh":  # `sh` (the simpleterm command, a status line command) is the shell under test
            os.symlink(argv[0], self.bin / "sh")
            os.symlink(argv[0], self.bare / "sh")
        self.relay = None
        self.start_relay()

    def start_relay(self):
        """A fresh relay on a new port: a background send left over from the previous case
        (late under load) then fails instead of landing in this case's records."""
        if self.relay:
            self.relay.terminate()
            self.relay.wait(5)
        self.relay = subprocess.Popen(
            [sys.executable, "-I", str(MOCK), "--openssl", self.openssl or "/usr/bin/openssl"],
            stdout=subprocess.PIPE, text=True,
        )
        self.port = int(self.relay.stdout.readline().split()[1])
        self.url = "http://127.0.0.1:%d" % self.port

    def close(self):
        self.relay.terminate()
        self.relay.wait(5)
        shutil.rmtree(self.tmp, ignore_errors=True)

    # --- relay control ----------------------------------------------------
    def ctl(self, path, obj=None):
        data = None if obj is None else json.dumps(obj).encode()
        req = urllib.request.Request(self.url + path, data=data, method="POST" if data is not None else "GET")
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read())

    def records(self, path=None):
        recs = self.ctl("/_ctl/records")["records"]
        return [r for r in recs if path is None or r["path"] == path]

    def setup(self, links, conf=None, relay_extra=None):
        """Writes link files and configures the relay. links: [(link, opts)]."""
        st = self.home / ".simpleterm"
        shutil.rmtree(st, ignore_errors=True)
        (st / "links").mkdir(parents=True)
        self.start_relay()
        cfg = {}
        for link, opts in links:
            lines = [
                "v=1", "relay=" + opts.get("relay_url", self.url), "link=" + link["id"], "secret=" + link["secret"],
                "enc=" + link["enc"], "mac=" + link["mac"], "label=" + link["label"], "device=Test iPad",
            ]
            if opts.get("kind"):
                lines.append("kind=" + opts["kind"])
            if opts.get("fmt"):
                lines.append("fmt=" + str(opts["fmt"]))
            text = "\n".join(lines + [""])
            p = st / "links" / (link["id"] + ".conf")
            p.write_text(text)
            p.chmod(0o600)
            cfg[link["id"]] = dict(link, **opts)
        # A done waits done_delay seconds for a newer event (done_later); the suite runs with 0 so
        # that timing checks stay short. conf={"done_delay": None} leaves the shipped default (3).
        conf = dict({"done_delay": 0}, **(conf or {}))
        conf_lines = ["poll_wait=2"] + ["%s=%s" % kv for kv in conf.items() if kv[1] is not None]
        (st / "agent-hook.conf").write_text("\n".join(conf_lines) + "\n")
        self.ctl("/_ctl/reset", {})
        self.ctl("/_ctl/config", {"links": cfg})

    def spawn_mock(self):
        """Another mock relay (the app's end of a tunnel); returns (process, ctl)."""
        proc = subprocess.Popen(
            [sys.executable, "-I", str(MOCK), "--openssl", self.openssl or "/usr/bin/openssl"],
            stdout=subprocess.PIPE, text=True,
        )
        url = "http://127.0.0.1:%d" % int(proc.stdout.readline().split()[1])

        def ctl(path, obj=None):
            data = None if obj is None else json.dumps(obj).encode()
            req = urllib.request.Request(url + path, data=data, method="POST" if data is not None else "GET")
            with urllib.request.urlopen(req, timeout=10) as r:
                return json.loads(r.read())

        ctl.url = url
        return proc, ctl

    def log_text(self):
        p = self.home / ".simpleterm" / "agent-hook.log"
        return p.read_text() if p.exists() else ""

    # --- running the hook ---------------------------------------------------
    def env(self, extra=None, bare=False):
        env = {
            "HOME": str(self.home),
            "PATH": str(self.bare if bare else self.bin),
            "LANG": "en_US.UTF-8",
            "TMPDIR": str(self.tmp),
        }
        if self.kind == "ps1":
            # pwsh is run by its path; the hook needs nothing from PATH, and no agent the user has
            # installed (grok, opencode, agy: the version cache runs `--version`) may be found.
            env["PATH"] = "/usr/bin:/bin:/usr/sbin:/sbin"
            env["POWERSHELL_TELEMETRY_OPTOUT"] = "1"
            env["POWERSHELL_UPDATECHECK"] = "Off"
        env.update(extra or {})
        return env

    def start(self, agent, stdin="", extra=None, bare=False, args=()):
        cmd = list(self.argv) + [agent] + list(args)
        p = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=self.env(extra, bare), cwd=str(self.tmp),
        )
        p.t0 = time.time()
        if stdin:
            try:
                p.stdin.write(stdin.encode())
            except BrokenPipeError:
                pass
        p.stdin.close()
        p.stdin = None
        return p

    def finish(self, p, timeout=90):
        out, err = p.communicate(timeout=timeout)
        return p.returncode, out.decode(), err.decode(), time.time() - p.t0

    def run(self, agent, stdin="", extra=None, bare=False, args=(), timeout=90):
        return self.finish(self.start(agent, stdin, extra, bare, args), timeout)

    def check(self, name, cond, detail=""):
        self.results.append((name, bool(cond), detail))


def wait_for(fn, timeout=10, step=0.1):
    end = time.time() + timeout
    while time.time() < end:
        v = fn()
        if v:
            return v
        time.sleep(step)
    return fn()


def decision_json(out):
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                return json.loads(line)
            except ValueError:
                return {"_invalid": line}
    return None


# --- test cases ----------------------------------------------------------------

def openssl_seal(plain, enc, mac, iv, openssl, prefix="st1."):
    """The envelope of `plain` under the vector keys, made with openssl itself (the reference)."""
    import hmac as _hmac
    ct = subprocess.run([openssl, "enc", "-aes-256-cbc", "-K", enc, "-iv", iv, "-a", "-A"], input=plain.encode("utf-8"),
                        capture_output=True, check=True).stdout.decode().strip()
    m = _hmac.new(bytes.fromhex(mac), (prefix + iv + "." + ct).encode("ascii"), hashlib.sha256).hexdigest()
    return ct, m


def t_vectors(s):
    """Relay protocol v1 vectors (section 5.2): the v1 fields of the plaintext are those of the vector,
    byte for byte, and the v2 fields come after them, before `ts` (TDS_AGENT_EVENTS_V2 section 3);
    the envelope is what openssl makes of the plaintext with the vector keys and IV."""
    s.setup([(LINK_A, {"push": "disabled"})])
    extra = {
        "SIMPLETERM_HOOK_TEST": "1", "SIMPLETERM_HOOK_TEST_IV": V_IV,
        "SIMPLETERM_HOOK_TEST_NONCE": V_NONCE, "SIMPLETERM_HOOK_TEST_RID": V_RID,
        "SIMPLETERM_HOOK_TEST_TS": V_TS,
    }
    rc, out, err, el = s.run("claude", perm_input(), extra)
    recs = s.records("/v1/ingest")
    s.check("vectors: one ingest", len(recs) == 1, str(recs)[:300])
    if not recs:
        return
    body = recs[0]["body"]
    plain = recs[0]["plain"] or ""
    v1 = V_PLAIN[:V_PLAIN.index(',"ts":')]
    s.check("vectors: v1 fields as the vector", plain.startswith(v1 + ',"fmt":2,') and plain.endswith(',"ts":%s}' % V_TS), plain)
    ct, mac = openssl_seal(plain, V_ENC, V_MAC, V_IV, s.openssl or "/usr/bin/openssl")
    s.check("vectors: ct", body["env"]["ct"] == ct, body["env"]["ct"])
    s.check("vectors: mac", body["env"]["mac"] == mac, body["env"]["mac"])
    s.check("vectors: the v1 vector itself", openssl_seal(V_PLAIN, V_ENC, V_MAC, V_IV, s.openssl or "/usr/bin/openssl") == (V_CT, V_ENV_MAC))
    s.check("vectors: iv", body["env"]["iv"] == V_IV)
    s.check("vectors: nh", body.get("nh") == V_NH, body.get("nh"))
    s.check("vectors: rid/ev", body["rid"] == V_RID and body["ev"] == "permission")
    s.check("vectors: push disabled -> no decision, no poll", out.strip() == "" and not s.records("/v1/decision"), out)
    s.check("vectors: exit 0", rc == 0, err)


def t_background(s):
    s.setup([(LINK_A, {"ingest_delay": 3})])
    stop = json.dumps({"session_id": "s2", "cwd": "/w/proj", "hook_event_name": "Stop",
                       "stop_hook_active": False, "last_assistant_message": "All tests pass."})
    rc, out, err, el = s.run("claude", stop)
    s.check("background: hook returns before the relay answers", el < 2.0, "%.2fs" % el)
    s.check("background: no stdout without SIMPLETERM", out == "", out)
    rec = wait_for(lambda: [r for r in s.records("/v1/ingest") if r.get("status") == 200], 30)
    s.check("background: ingest completed after exit", rec, str(s.records())[:300])
    if rec:
        p = rec[0].get("plain_json") or {}
        s.check("background: ev done + msg", p.get("ev") == "done" and p.get("msg") == "All tests pass." and p.get("cwd") == "proj", str(p))
        s.check("background: no nonce/nh for done", "nonce" not in p and "nh" not in rec[0]["body"])
    s.check("background: log has result",
            wait_for(lambda: "ingest ev=done" in s.log_text(), 5), s.log_text())


def t_allow_deny(s):
    for verdict in ("allow", "deny"):
        s.setup([(LINK_A, {"decision": verdict, "after": 1})])
        rc, out, err, el = s.run("claude", perm_input(), {"SIMPLETERM": "1"})
        d = decision_json(out) or {}
        beh = d.get("hookSpecificOutput", {}).get("decision", {}).get("behavior")
        s.check("permission %s: decision printed" % verdict, beh == verdict, out + err)
        s.check("permission %s: hookEventName" % verdict,
                d.get("hookSpecificOutput", {}).get("hookEventName") == "PermissionRequest")
        if verdict == "deny":
            s.check("permission deny: message", d["hookSpecificOutput"]["decision"].get("message") == "Denied from SimpleTerm" if beh else False)
        s.check("permission %s: terminalSequence running (SIMPLETERM=1)" % verdict,
                d.get("terminalSequence") == "\x1b]9;simpleterm:state=running\x07", repr(d.get("terminalSequence")))
        # Typically ~2.2 s; the bound only shows it did not wait out claude_wait (slow under parallel load).
        s.check("permission %s: within time" % verdict, el < 20, "%.2fs" % el)
        recs = s.records("/v1/ingest")
        s.check("permission %s: nh matches nonce" % verdict, recs and recs[0].get("nh_ok") is True, str(recs)[:200])


def t_codex_allow(s):
    s.setup([(LINK_A, {"decision": "allow", "after": 1})])
    inp = json.dumps({"session_id": "c1", "turn_id": "t1", "transcript_path": None, "cwd": "/w/repo",
                      "hook_event_name": "PermissionRequest", "model": "m", "permission_mode": "default",
                      "tool_name": "Bash", "tool_input": {"command": "echo hi > x", "description": "May I run it?"}})
    rc, out, err, el = s.run("codex", inp, {"SIMPLETERM": "1"})
    d = decision_json(out) or {}
    s.check("codex: allow printed", d.get("hookSpecificOutput", {}).get("decision", {}).get("behavior") == "allow", out + err)
    s.check("codex: no terminalSequence (schema forbids it)", "terminalSequence" not in d, out)
    recs = s.records("/v1/ingest")
    p = recs[0].get("plain_json", {}) if recs else {}
    s.check("codex: app=codex", p.get("app") == "codex" and p.get("msg") == "approve Bash: echo hi > x", str(p))


def t_invalid_dmac(s):
    s.setup([(LINK_A, {"decision": "bad_dmac", "after": 1})])
    rc, out, err, el = s.run("claude", perm_input())
    s.check("invalid dmac: no decision", out.strip() == "", out)
    s.check("invalid dmac: logged", "result=invalid" in s.log_text(), s.log_text())
    s.check("invalid dmac: returns promptly", el < 20, "%.2fs" % el)


def t_timeout(s):
    s.setup([(LINK_A, {})], conf={"claude_wait": 3})
    rc, out, err, el = s.run("claude", perm_input())
    s.check("timeout: no decision", out.strip() == "", out)
    s.check("timeout: honours claude_wait", 1.5 < el < 9, "%.2fs" % el)
    s.check("timeout: logged", "permission timeout" in s.log_text(), s.log_text())
    s.check("timeout: polled", len(s.records("/v1/decision")) >= 1)


def t_multi_link(s):
    s.setup([(LINK_A, {}), (LINK_B, {"decision": "allow", "after": 1})])
    rc, out, err, el = s.run("claude", perm_input())
    d = decision_json(out) or {}
    s.check("multi-link: decision from second device", d.get("hookSpecificOutput", {}).get("decision", {}).get("behavior") == "allow", out + err)
    recs = s.records("/v1/ingest")
    links = sorted(r["link"] for r in recs)
    s.check("multi-link: one ingest per link", links == sorted([LINK_A["id"], LINK_B["id"]]), str(links))
    hosts = sorted((r.get("plain_json") or {}).get("host", "") for r in recs)
    s.check("multi-link: per-link labels", hosts == ["box-b", "dev-box"], str(hosts))
    s.check("multi-link: distinct nonces", len({(r.get("plain_json") or {}).get("nonce") for r in recs}) == 2)
    s.check("multi-link: same rid", len({r["body"]["rid"] for r in recs}) == 1)


def t_tunnel(s):
    tun, tctl = s.spawn_mock()
    try:
        def tunnel(opts, conf=None, more=()):
            s.setup([(LINK_T, {"kind": "tunnel", "relay_url": tctl.url})] + list(more), conf)
            tctl("/_ctl/reset", {})
            tctl("/_ctl/config", {"links": {LINK_T["id"]: dict(LINK_T, **opts)}})

        def tunnel_ingests():
            return [r for r in tctl("/_ctl/records")["records"] if r["path"] == "/v1/ingest"]

        tunnel({"decision": "allow", "after": 1})
        rc, out, err, el = s.run("claude", perm_input())
        d = decision_json(out) or {}
        s.check("tunnel: the app's decision is printed",
                d.get("hookSpecificOutput", {}).get("decision", {}).get("behavior") == "allow", out + err)

        # The app's connection ends while the hook waits: stop, don't wait out claude_wait.
        tunnel({}, conf={"claude_wait": 40})
        p = s.start("claude", perm_input())
        s.check("tunnel gone: request reached the tunnel", wait_for(tunnel_ingests, 10))
        tun.terminate()
        tun.wait(5)
        rc, out, err, el = s.finish(p, 60)
        s.check("tunnel gone: no decision", out.strip() == "", out)
        s.check("tunnel gone: stops waiting soon", el < 25, "%.2fs" % el)
        s.check("tunnel gone: logged", "tunnel-gone" in s.log_text(), s.log_text())
    finally:
        tun.terminate()
        tun.wait(5)

    # A dead tunnel (nothing on the port) does not hold up the relay's device.
    probe = __import__("socket").socket()
    probe.bind(("127.0.0.1", 0))
    closed = probe.getsockname()[1]
    probe.close()
    s.setup([(LINK_T, {"kind": "tunnel", "relay_url": "http://127.0.0.1:%d" % closed}),
             (LINK_A, {"decision": "allow", "after": 1})])
    rc, out, err, el = s.run("claude", perm_input())
    d = decision_json(out) or {}
    s.check("dead tunnel: relay decision still arrives",
            d.get("hookSpecificOutput", {}).get("decision", {}).get("behavior") == "allow", out + err)
    s.check("dead tunnel: within time", el < 20, "%.2fs" % el)

    # Background events reach a tunnel before the relay, which holds its answer.
    tun, tctl = s.spawn_mock()
    try:
        s.setup([(LINK_A, {"ingest_delay": 3}), (LINK_T, {"kind": "tunnel", "relay_url": tctl.url})])
        tctl("/_ctl/config", {"links": {LINK_T["id"]: dict(LINK_T)}})
        stop = json.dumps({"session_id": "s3", "cwd": "/w/proj", "hook_event_name": "Stop",
                           "stop_hook_active": False, "last_assistant_message": "done"})
        t0 = time.time()
        s.run("claude", stop)
        got = wait_for(lambda: [r for r in tctl("/_ctl/records")["records"] if r["path"] == "/v1/ingest"], 10, 0.05)
        el = time.time() - t0
        s.check("tunnel first: background event reaches the tunnel before the relay answers",
                got and el < 2.5, "%.2fs" % el)
        s.check("tunnel first: relay still gets it",
                wait_for(lambda: s.records("/v1/ingest"), 20), str(s.records())[:200])
    finally:
        tun.terminate()
        tun.wait(5)


def t_revoked(s):
    s.setup([(LINK_A, {"revoked": True}), (LINK_B, {"push": "disabled"})])
    rc, out, err, el = s.run("claude", perm_input())
    s.check("revoked: 410 logged", "http=410" in s.log_text(), s.log_text())
    s.check("revoked: marker written", (s.home / ".simpleterm" / "run" / (LINK_A["id"] + ".revoked")).exists())
    s.ctl("/_ctl/reset", {})
    s.run("claude", perm_input())
    links = [r["link"] for r in s.records("/v1/ingest")]
    s.check("revoked: link skipped next time", links == [LINK_B["id"]], str(links))


def t_missing_deps(s):
    s.setup([(LINK_A, {"decision": "allow"})])
    rc, out, err, el = s.run("claude", perm_input(), bare=True)
    s.check("missing deps: exit 0, no output", rc == 0 and out == "", out + err)
    s.check("missing deps: logged", "missing curl" in s.log_text() or "missing openssl" in s.log_text(), s.log_text())
    s.check("missing deps: nothing sent", not s.records("/v1/ingest"))
    stop = json.dumps({"session_id": "s", "hook_event_name": "Stop", "cwd": "/x"})
    rc, out, err, el = s.run("claude", stop, {"SIMPLETERM": "1"}, bare=True)
    s.check("missing deps: terminal sequence still works", "simpleterm:state=done" in out, out + err)


def t_simpleterm_gating(s):
    s.setup([(LINK_A, {"push": "disabled"})])
    stop = json.dumps({"session_id": "s", "hook_event_name": "Stop", "cwd": "/x", "last_assistant_message": "ok"})
    _, out1, _, _ = s.run("claude", stop)
    _, out2, _, _ = s.run("claude", stop, {"SIMPLETERM": "1"})
    s.check("gating: nothing without SIMPLETERM", out1 == "", out1)
    try:
        j = json.loads(out2)
    except ValueError:
        j = {}
    s.check("gating: done sequence with SIMPLETERM=1", j.get("terminalSequence") == "\x1b]9;simpleterm:state=done\x07", out2)
    _, out3, _, _ = s.run("claude", perm_input(), {"SIMPLETERM": "1"}, args=("signal",))
    try:
        j3 = json.loads(out3)
    except ValueError:
        j3 = {}
    s.check("gating: signal handler prints waiting at once",
            j3.get("terminalSequence") == "\x1b]9;simpleterm:state=waiting approve Bash: npm test\x07", out3)
    _, out4, _, _ = s.run("codex", stop, {"SIMPLETERM": "1"})
    s.check("gating: codex never prints a sequence", out4 == "", out4)
    s.ctl("/_ctl/reset", {})
    shutil.rmtree(s.home / ".simpleterm" / "links")
    _, out5, _, el = s.run("claude", stop, {"SIMPLETERM": "1"})
    s.check("gating: no links + SIMPLETERM=1 still signals", "state=done" in out5, out5)
    _, out6, _, el6 = s.run("claude", stop)
    s.check("gating: no links + no SIMPLETERM is a quick no-op", out6 == "" and el6 < 1.5, "%.2fs" % el6)


def t_local_answer(s):
    s.setup([(LINK_A, {})], conf={"claude_wait": 60})
    p = s.start("claude", perm_input(command="make deploy", session="loc-1"))
    wait_for(lambda: s.records("/v1/decision"), 15)
    other = perm_input(command="ls", session="loc-1", event="PostToolUse")
    s.run("claude", other)
    time.sleep(2.5)
    s.check("local answer: other tool does not cancel", p.poll() is None)
    same = perm_input(command="make deploy", session="loc-1", event="PostToolUse")
    t = time.time()
    s.run("claude", same)
    rc, out, err, el = s.finish(p, 30)
    s.check("local answer: same tool cancels the wait", time.time() - t < 5 and out == "", "%.2fs %s" % (time.time() - t, out))
    s.check("local answer: logged", "answered-at-terminal" in s.log_text(), s.log_text())
    # A new prompt also ends the wait.
    p = s.start("claude", perm_input(command="make deploy", session="loc-2"))
    wait_for(lambda: len(s.records("/v1/decision")) > 1, 15)
    time.sleep(0.5)
    t = time.time()
    s.run("claude", json.dumps({"session_id": "loc-2", "hook_event_name": "UserPromptSubmit", "prompt": "next", "cwd": "/x"}))
    rc, out, err, el = s.finish(p, 30)
    s.check("local answer: new prompt cancels the wait", time.time() - t < 5 and out == "", "%.2fs" % (time.time() - t))


def t_same_second_prompt(s):
    # The prompt that started the turn and the permission request can land in
    # the same wall-clock second: that prompt must not read as "answered at
    # the terminal" (plugin measurement 2026-10-29).
    s.setup([(LINK_A, {"decision": "allow", "after": 1})])
    while time.time() % 1 > 0.3:
        time.sleep(0.01)
    s.run("claude", json.dumps({"session_id": "same-1", "hook_event_name": "UserPromptSubmit", "prompt": "go", "cwd": "/x"}))
    rc, out, err, el = s.run("claude", perm_input(session="same-1"))
    d = decision_json(out) or {}
    beh = d.get("hookSpecificOutput", {}).get("decision", {}).get("behavior")
    s.check("same-second prompt: still waits for the device decision", beh == "allow", out + err + s.log_text())


def t_notifications(s):
    """One relay event per agent wait: permission waits come only from PermissionRequest."""
    s.setup([(LINK_A, {})], conf={"claude_wait": 20})
    p = s.start("claude", perm_input(session="nd-1"))
    wait_for(lambda: s.records("/v1/decision"), 15)
    note = json.dumps({"session_id": "nd-1", "hook_event_name": "Notification", "cwd": "/x",
                       "message": "Claude needs your permission", "notification_type": "permission_prompt"})
    _, out, _, _ = s.run("claude", note, {"SIMPLETERM": "1"})
    time.sleep(1.5)
    evs = [r["body"]["ev"] for r in s.records("/v1/ingest") if r.get("body")]
    s.check("notification: permission_prompt adds no relay event", evs == ["permission"], str(evs))
    s.check("notification: permission_prompt prints nothing", out == "", out)
    s.run("claude", json.dumps({"session_id": "nd-1", "hook_event_name": "UserPromptSubmit", "prompt": "x"}))
    s.finish(p, 30)
    s.ctl("/_ctl/reset", {})
    s.run("claude", note.replace("nd-1", "nd-2"))
    time.sleep(1.5)
    s.check("notification: permission_prompt ignored without a waiting hook too", not s.records("/v1/ingest"))
    s.ctl("/_ctl/reset", {})
    _, out, _, _ = s.run("claude", json.dumps({"session_id": "q", "hook_event_name": "Notification",
                                               "message": "Claude is waiting for your input", "notification_type": "idle_prompt"}),
                         {"SIMPLETERM": "1"})
    rec = wait_for(lambda: s.records("/v1/ingest"), 20)
    s.check("notification: idle_prompt -> question", rec and rec[0]["body"]["ev"] == "question"
            and rec[0]["plain_json"].get("msg") == "Claude is waiting for your input", str(rec)[:200])
    s.check("notification: idle_prompt keeps the done badge (no sequence)", out == "", out)
    s.ctl("/_ctl/reset", {})
    _, out, _, _ = s.run("claude", json.dumps({"session_id": "q", "hook_event_name": "Notification", "message": "MCP needs input",
                                               "notification_type": "elicitation_dialog"}), {"SIMPLETERM": "1"})
    rec = wait_for(lambda: s.records("/v1/ingest"), 20)
    s.check("notification: elicitation -> question", rec and rec[0]["body"]["ev"] == "question", str(rec)[:200])
    s.check("notification: elicitation -> waiting", "state=waiting" in out, out)


def t_background_work(s):
    """A Claude Code turn that ends with background work in flight is not done.

    Measured on Claude Code 2.1.316: the Stop after `run_in_background` lists the
    shell in `background_tasks`, idle_prompt follows 60 s later while it runs, the
    shell's completion comes back as a UserPromptSubmit, and the Stop after that
    has `background_tasks: []`."""
    s.setup([(LINK_A, {})])
    st = {"SIMPLETERM": "1"}
    sid = "bgw"

    def ev(name, **kw):
        return json.dumps(dict({"session_id": sid, "cwd": "/w/proj", "hook_event_name": name}, **kw))

    shell = {"id": "bhk40d9z9", "type": "shell", "status": "running",
             "description": "Run the test suite", "command": "npm test"}
    agent = {"id": "a1b2c3d4e", "type": "subagent", "status": "running",
             "description": "Review the diff", "agent_type": "code-reviewer"}
    _, out, _, _ = s.run("claude", ev("Stop", stop_hook_active=False, last_assistant_message="Waiting for the tests.",
                                      background_tasks=[shell, agent], session_crons=[]), st)
    s.check("background work: Stop shows a background state, not done",
            seqs(out) == "\x1b]9;simpleterm:state=background shell: Run the test suite (+1 more)\x07", repr(out))
    _, out2, _, _ = s.run("claude", ev("Notification", notification_type="idle_prompt",
                                       message="Claude is waiting for your input"), st)
    _, out3, _, _ = s.run("claude", ev("PostToolUse", tool_name="Read", tool_input={"file_path": "/w/proj/a.dart"}), st)
    s.check("background work: idle_prompt meanwhile prints nothing", out2 == "", out2)
    s.check("background work: a background subagent's tool keeps the background state",
            seqs(out3).startswith("\x1b]9;simpleterm:state=background shell: Run the test suite"), repr(out3))
    time.sleep(1.5)
    s.check("background work: no relay event for that Stop or idle_prompt", not ingests(s), str(ingests(s))[:300])

    _, out4, _, _ = s.run("claude", ev("UserPromptSubmit", prompt="<task-notification>\n<status>completed</status>"), st)
    s.check("background work: the wake-up turn is running", seqs(out4) == "\x1b]9;simpleterm:state=running\x07", repr(out4))
    _, out5, _, _ = s.run("claude", ev("Stop", stop_hook_active=False, last_assistant_message="Tests pass.",
                                       background_tasks=[], session_crons=[]), st)
    s.check("background work: the Stop with nothing in flight is done",
            seqs(out5) == "\x1b]9;simpleterm:state=done\x07", repr(out5))
    rec = wait_for(lambda: ingests(s, "done"), 20)
    s.check("background work: one done event, with the last message",
            len(rec) == 1 and rec[0]["plain_json"].get("msg") == "Tests pass.", str(ingests(s))[:300])
    s.ctl("/_ctl/reset", {})
    s.run("claude", ev("Notification", notification_type="idle_prompt", message="Claude is waiting for your input"), st)
    time.sleep(1.5)
    s.check("background work: idle_prompt after a done turn repeats it: no question", not ingests(s), str(ingests(s))[:200])

    many = [dict(shell, id="b%08d" % i) for i in range(12)]
    _, out6, _, _ = s.run("claude", ev("Stop", stop_hook_active=False, last_assistant_message="x",
                                       background_tasks=many), st)
    s.check("background work: ten or more tasks", seqs(out6).endswith("(+9 or more)\x07"), repr(out6))
    s.run("claude", ev("StopFailure", error="server_error", last_assistant_message="x"), st)
    s.ctl("/_ctl/reset", {})
    s.run("claude", ev("Notification", notification_type="idle_prompt", message="Claude is waiting for your input"), st)
    s.check("background work: a failed turn ends the pause", wait_for(lambda: ingests(s, "question"), 20))


def t_background_work_kinds(s):
    """Which background work holds back `done` (Claude Code 2.1.316 type labels)."""
    s.setup([(LINK_A, {})], conf={"bg_done_after": 2})
    st = {"SIMPLETERM": "1"}

    def stop(sid, tasks, last="x"):
        return s.run("claude", json.dumps({"session_id": sid, "cwd": "/w/proj", "hook_event_name": "Stop",
                                           "last_assistant_message": last, "background_tasks": tasks}), st)[1]

    def task(kind, desc, **kw):
        return dict({"id": "t" + kind.replace(" ", ""), "type": kind, "status": "running", "description": desc}, **kw)

    # Housekeeping that never wakes the agent: done at once.
    out = stop("k1", [task("dream", "Consolidate memory"), task("auto-mode scan", "Scan")], last="All set.")
    s.check("kinds: dream and auto-mode scan only -> done", seqs(out) == "\x1b]9;simpleterm:state=done\x07", repr(out))
    s.check("kinds: ... and the done event", wait_for(lambda: ingests(s, "done"), 20))
    s.ctl("/_ctl/reset", {})
    # The first task that counts names the pause.
    out = stop("k2", [task("dream", "Consolidate memory"), task("subagent", "Review the diff", agent_type="code-reviewer")])
    s.check("kinds: the message skips housekeeping", seqs(out) == "\x1b]9;simpleterm:state=background subagent: Review the diff\x07",
            repr(out))
    # A shell alone may run for good (a dev server): done once after bg_done_after.
    s.ctl("/_ctl/reset", {})
    t0 = time.time()
    stop("k3", [task("shell", "Start the dev server", command="node worker.js")], last="The server is up.")
    time.sleep(1)
    s.check("kinds: a shell alone -> nothing at first", not ingests(s), str(ingests(s))[:200])
    rec = wait_for(lambda: ingests(s, "done"), 20)
    s.check("kinds: ... then done once after bg_done_after, saying what runs",
            len(rec) == 1 and rec[0]["received"] - t0 >= 1.8
            and rec[0]["plain_json"].get("msg") == "The server is up. (still running in the background: shell: Start the dev server)",
            str([(r["plain_json"].get("msg"), round(r["received"] - t0, 2)) for r in rec]))
    time.sleep(1)
    s.check("kinds: ... and only once", len(ingests(s, "done")) == 1, str(ingests(s))[:200])
    # A subagent alongside: it reports back, so no time limit.
    s.ctl("/_ctl/reset", {})
    stop("k4", [task("shell", "Run tests", command="npm test"), task("subagent", "Review")])
    time.sleep(3.5)
    s.check("kinds: a subagent left -> no time limit", not ingests(s), str(ingests(s))[:200])
    # A new turn before the limit ends the wait.
    s.ctl("/_ctl/reset", {})
    stop("k5", [task("monitor", "Watch the deploy")])
    s.run("claude", json.dumps({"session_id": "k5", "hook_event_name": "UserPromptSubmit", "prompt": "<task-notification>"}), st)
    time.sleep(3.5)
    s.check("kinds: a new turn before the limit -> no late done", not ingests(s), str(ingests(s))[:200])


def t_background_work_7501(s):
    """Claude Code 2.1.295+ reports `done` for its own turn through OSC 7501 even
    while a background shell runs (measured on 2.1.316: the Stop hook's output
    lands 12 ms before that `done`). The hook adds an OSC 7501 `working` record
    of its own, only where Claude Code speaks OSC 7501, and takes it back at the
    next turn."""
    s.setup([(LINK_A, {})])
    shell = {"id": "bhk40d9z9", "type": "shell", "status": "running",
             "description": "Run the test suite", "command": "npm test"}

    def transcript(version):
        return write(s.tmp / ("t-%s.jsonl" % version), "\n".join(
            json.dumps({"type": t, "version": version, "message": {"role": t, "content": "x"}})
            for t in ("user", "assistant")) + "\n")

    def stop(sid, tr, extra=None, tasks=(shell,)):
        ev = {"session_id": sid, "cwd": "/w/proj", "hook_event_name": "Stop", "stop_hook_active": False,
              "last_assistant_message": "x", "transcript_path": str(tr), "background_tasks": list(tasks)}
        return s.run("claude", json.dumps(ev), dict({"SIMPLETERM": "1"}, **(extra or {})))[1]

    working = ("\x1b]7501;state=working:id=simpleterm-bg:msg=%s\x07"
               % base64.b64encode(b"shell: Run the test suite").decode())
    out = stop("b75", transcript("2.1.316"))
    s.check("7501: Claude Code 2.1.316 -> a working record after the background state",
            seqs(out) == "\x1b]9;simpleterm:state=background shell: Run the test suite\x07" + working, repr(out))
    _, out2, _, _ = s.run("claude", json.dumps({"session_id": "b75", "hook_event_name": "UserPromptSubmit", "prompt": "x"}),
                          {"SIMPLETERM": "1"})
    s.check("7501: the next turn takes the record back",
            seqs(out2) == "\x1b]9;simpleterm:state=running\x07\x1b]7501;state=clear:id=simpleterm-bg\x07", repr(out2))
    _, out3, _, _ = s.run("claude", json.dumps({"session_id": "b75", "hook_event_name": "UserPromptSubmit", "prompt": "y"}),
                          {"SIMPLETERM": "1"})
    s.check("7501: taken back once", seqs(out3) == "\x1b]9;simpleterm:state=running\x07", repr(out3))

    for label, tr, extra in (("2.1.294 (no OSC 7501 of its own)", transcript("2.1.294"), None),
                             ("inside tmux", transcript("2.1.316"), {"TMUX": "/tmp/tmux-1/default,1,0"}),
                             ("terminal title writes off", transcript("2.1.316"), {"CLAUDE_CODE_DISABLE_TERMINAL_TITLE": "1"}),
                             ("no transcript", s.tmp / "missing.jsonl", None)):
        out = stop("b75-" + label.split()[0], tr, extra)
        s.check("7501: none for %s" % label, "7501" not in seqs(out) and "state=background" in seqs(out), repr(out))
        _, out4, _, _ = s.run("claude", json.dumps({"session_id": "b75-" + label.split()[0], "hook_event_name": "Stop",
                                                    "last_assistant_message": "x", "background_tasks": []}),
                              dict({"SIMPLETERM": "1"}, **(extra or {})))
        s.check("7501: nothing to take back for %s" % label, seqs(out4) == "\x1b]9;simpleterm:state=done\x07", repr(out4))

    out = stop("b75-esc", transcript("2.1.316"),
               tasks=[dict(shell, description='Run "npm test" \u2014 all')])  # JSON: \" and \u2014
    s.check("7501: a message with other escapes goes without msg",
            seqs(out).endswith("\x1b]7501;state=working:id=simpleterm-bg\x07"), repr(out))


def t_codex_goal(s):
    """Codex `/goal`: while a goal is active Codex starts the next turn itself; each
    turn's Stop is not done (measured on Codex 0.165.0 with a local model stub)."""
    s.setup([(LINK_A, {})], conf={"codex_goal_check": 2})
    sid = "019a0000-0000-7000-8000-000000000001"
    goal = {"type": "event_msg", "payload": {"type": "thread_goal_updated", "threadId": sid,
                                             "goal": {"threadId": sid, "objective": "finish", "status": "active"}}}
    call = {"type": "response_item", "payload": {"type": "function_call", "name": "update_goal",
                                                 "arguments": "{\"status\": \"complete\"}", "call_id": "g1"}}
    meta = {"type": "session_meta", "payload": {"id": sid}}
    tr = s.tmp / "rollout-goal.jsonl"

    def stop(lines, then=None, wait=4):
        tr.write_text("".join(json.dumps(x, separators=(",", ":")) + "\n" for x in lines))
        s.ctl("/_ctl/reset", {})
        s.run("codex", json.dumps({"session_id": sid, "turn_id": "t", "transcript_path": str(tr), "cwd": "/w/repo",
                                   "hook_event_name": "Stop", "last_assistant_message": "step done"}))
        if then:  # Codex starts the goal's next turn within milliseconds
            with open(tr, "a") as fh:
                fh.write("".join(json.dumps(x, separators=(",", ":")) + "\n" for x in then))
        return wait_for(lambda: ingests(s, "done"), wait)

    s.check("codex goal: no done while the goal is active (next turn started)",
            not stop([meta, goal], then=[{"type": "event_msg", "payload": {"type": "task_started", "turn_id": "t2"}}]))
    s.check("codex goal: done when no next turn starts (blocked, budget, cleared)", stop([meta, goal], wait=6))
    s.check("codex goal: done after update_goal", stop([meta, goal, call]))
    s.check("codex goal: a later goal is active again", not stop([meta, goal, call, goal],
                                                                 then=[{"type": "event_msg", "payload": {"type": "task_started"}}]))
    s.check("codex goal: done without a goal", stop([meta]))
    paused = json.loads(json.dumps(goal))
    paused["payload"]["goal"]["status"] = "paused"
    s.check("codex goal: done when the goal is not active", stop([meta, goal, paused]))


def cc_event(sid, name, **kw):
    """A Claude Code hook event (the shapes captured from 2.1.316 are in hooks.jsonl of the research notes)."""
    return json.dumps(dict({"session_id": sid, "cwd": "/w/proj", "hook_event_name": name}, **kw))


def cc_transcript(s, version="2.1.316"):
    return write(s.tmp / ("tr-%s.jsonl" % version), "\n".join(
        json.dumps({"type": t, "version": version, "message": {"role": t, "content": "x"}}) for t in ("user", "assistant")) + "\n")


def b64(text):
    return base64.b64encode(text.encode()).decode()


SUBAGENT = {"id": "a42a3936ffcdae563", "type": "subagent", "status": "running", "description": "Review the diff",
            "agent_type": "code-reviewer"}
SHELL = {"id": "b4y66jodr", "type": "shell", "status": "running", "description": "Sleep 45 seconds then echo shell-done",
         "command": "sleep 45; echo shell-done"}


def t_question_while_background(s):
    """The agent ends its turn with a question while background work runs: the user is told (question),
    not left waiting for work that cannot finish before they answer."""
    s.setup([(LINK_A, {})], conf={"bg_done_after": 2})
    st = {"SIMPLETERM": "1"}

    def stop(sid, last, tasks=(SUBAGENT,), env=None, ascii_json=True):
        ev = cc_event(sid, "Stop", stop_hook_active=False, last_assistant_message=last, background_tasks=list(tasks), session_crons=[])
        if not ascii_json:
            ev = json.dumps(json.loads(ev), ensure_ascii=False)
        return s.run("claude", ev, dict(st, **(env or {})))[1]

    q = "The reviewer is still running. Should I also fix the lint warnings meanwhile?"
    out = stop("qb1", q)
    s.check("question while waiting: the badge says waiting, with the question",
            seqs(out) == "\x1b]9;simpleterm:state=waiting " + q + "\x07", repr(out))
    rec = wait_for(lambda: ingests(s, "question"), 20)
    s.check("question while waiting: a question event with the message",
            len(rec) == 1 and rec[0]["plain_json"].get("msg") == q, str(ingests(s))[:300])
    _, out2, _, _ = s.run("claude", cc_event("qb1", "Notification", notification_type="idle_prompt",
                                             message="Claude is waiting for your input"), st)
    s.check("question while waiting: idle_prompt meanwhile prints nothing", out2 == "", out2)
    time.sleep(1.5)
    s.check("question while waiting: no done and no second question", len(ingests(s)) == 1, str(ingests(s))[:300])

    # Claude Code 2.1.295+: a blocked (question) record of the hook instead of the working one; taken back at the next turn.
    s.ctl("/_ctl/reset", {})
    tr = cc_transcript(s)
    out = s.run("claude", cc_event("qb2", "Stop", stop_hook_active=False, last_assistant_message=q, background_tasks=[SUBAGENT],
                                   session_crons=[], transcript_path=str(tr)), st)[1]
    s.check("question while waiting: OSC 7501 blocked/question record, no working record",
            seqs(out) == "\x1b]9;simpleterm:state=waiting " + q + "\x07\x1b]7501;state=blocked:id=simpleterm-bg:kind=question:msg="
            + b64(q) + "\x07", repr(out))
    wait_for(lambda: ingests(s, "question"), 20)  # its send must land before the reset below
    _, out3, _, _ = s.run("claude", cc_event("qb2", "UserPromptSubmit", prompt="yes, fix them"), st)
    s.check("question while waiting: the next turn takes the record back",
            seqs(out3) == "\x1b]9;simpleterm:state=running\x07\x1b]7501;state=clear:id=simpleterm-bg\x07", repr(out3))

    # Not a question: silent as before, whatever else is in the message.
    s.ctl("/_ctl/reset", {})
    for name, last in (("plain report", "The reviewer is still running."),
                       ("question in a code block", "Waiting.\n```\nwhy = a ?\n```\nStanding by."),
                       ("question older than the last two sentences", "Should I continue? I will. Meanwhile the tests run. Standing by."),
                       ("url with a query", "See https://example.com/?a=1 for the details of the run."),
                       ("English sign-off", "The reviewer is running. Let me know if you need anything else."),
                       ("Korean wait", "리뷰가 끝나면 알려드릴게요. 잠시만 기다려 주세요."),
                       ("Korean for reference", "자세한 내용은 문서를 참고해 주세요."),
                       ("Korean bear with us", "작업이 길어지고 있습니다. 양해 바랍니다."),
                       ("English offer after if you", "The reviewer is running. Let me know if you want me to adjust anything."),
                       ("question mark in inline code", "The helper returns `user?.name` while the reviewer runs."),
                       ("question mark in inline code at the end", "The reviewer is running. Is it `a ?`"),
                       ("question mark in a table cell", "Results so far:\n| check | ok? |\n| lint | yes |"),
                       ("optional chaining", "The reviewer checks a?.b for me."),
                       ("Korean polite FYI 1", "자세한 내용은 README를 참고하시기 바랍니다."),
                       ("Korean polite FYI 2", "결과는 로그를 참고해 주시기 바랍니다."),
                       ("Korean polite wait", "잠시 기다려 주시기 바랍니다."),
                       ("Korean polite pardon", "양해해 주시기 바랍니다."),
                       ("Korean polite note", "배포 전에 이 점 유의하시기 바랍니다."),
                       ("Korean pardon request", "작업이 길어지고 있습니다. 양해 부탁드립니다.")):
        out = stop("qb3", last)
        s.check("question while waiting: %s -> background" % name,
                seqs(out).startswith("\x1b]9;simpleterm:state=background subagent: Review the diff"), repr(out))
    time.sleep(1.5)
    s.check("question while waiting: ... and no event", not ingests(s), str(ingests(s))[:300])

    # Korean and English asks that are not marked with a question mark.
    for name, last, ascii_json in (
            ("Korean ? (escaped)", "리뷰어가 아직 돌고 있습니다. 린트 경고도 고칠까요?", True),
            ("Korean request (escaped)", "리뷰가 끝나면 결과를 확인해 주세요.", True),
            ("Korean request (raw UTF-8)", "리뷰가 끝나면 결과를 확인해 주세요", False),
            ("Korean polite ask without a mark", "진행하시겠습니까", False),
            ("English let me know", "The reviewer is running. Let me know which option you prefer.", True),
            ("English would you like", "Part one is done. Would you like part two now", True),
            ("full-width question mark", "리뷰가 돌고 있습니다？", True),
            ("Korean real request after an FYI word", "리뷰가 돌고 있습니다. 참고해서 결정해 주세요.", True),
            ("Korean butakdeurimnida", "리뷰가 돌고 있습니다. 선택 부탁드립니다.", True)):
        s.ctl("/_ctl/reset", {})
        out = stop("qb4", last, ascii_json=ascii_json)
        rec = wait_for(lambda: ingests(s, "question"), 20)
        s.check("question while waiting: %s" % name, len(rec) == 1 and "state=waiting" in seqs(out), str(ingests(s))[:200] + repr(out))

    # Work that may run for good (a shell): the question replaces the late done.
    s.ctl("/_ctl/reset", {})
    out = stop("qb5", "The server is up. Should I open the browser?", tasks=(dict(SHELL, command="node worker.js"),))
    wait_for(lambda: ingests(s, "question"), 20)
    time.sleep(3.5)
    s.check("question while waiting: shell only -> question, and no late done",
            [r["body"]["ev"] for r in ingests(s)] == ["question"], str([r["body"]["ev"] for r in ingests(s)]))

    # Grok Build: camelCase, lastAssistantMessage, backgroundTasks.
    s.ctl("/_ctl/reset", {})
    gtask = {"id": "48d7f629-d7ca-4ac8-94ac-419eb88970a7", "type": "subagent", "status": "running", "description": "sleep sub",
             "agentType": "general-purpose"}
    inp, env = grok_input("Stop", reason="end_turn", promptId="g1", timestamp="2026-11-02T10:00:00.000Z",
                          lastAssistantMessage="Subagent still running. Want me to start on the docs?", backgroundTasks=[gtask], sessionCrons=[])
    s.run("claude", inp, env)
    rec = wait_for(lambda: ingests(s, "question"), 20)
    s.check("question while waiting: Grok Build", len(rec) == 1 and rec[0]["plain_json"].get("app") == "grok-build"
            and rec[0]["plain_json"].get("msg") == "Subagent still running. Want me to start on the docs?", str(ingests(s))[:300])


def t_service_shells(s):
    """A shell that is a service (dev server, watcher, follower) is not waited for: done at once, saying what runs."""
    s.setup([(LINK_A, {})])
    st = {"SIMPLETERM": "1"}

    def shell(cmd, desc="Start the dev server"):
        return dict(SHELL, id="s" + str(abs(hash(cmd)) % 10**8), description=desc, command=cmd)

    def stop(sid, tasks, last="Server started.", extra=None, env=None, amp=False):
        ev = cc_event(sid, "Stop", stop_hook_active=False, last_assistant_message=last, background_tasks=tasks, session_crons=[],
                      **(extra or {}))
        if amp:
            ev = ev.replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e")
        return s.run("claude", ev, dict(st, **(env or {})))[1]

    out = stop("sv1", [shell("npm run dev")])
    s.check("service shell: done state, not background", seqs(out) == "\x1b]9;simpleterm:state=done\x07", repr(out))
    rec = wait_for(lambda: ingests(s, "done"), 20)
    s.check("service shell: done at once, saying what runs", len(rec) == 1 and rec[0]["plain_json"].get("msg")
            == "Server started. (still running in the background: shell: Start the dev server)", str(ingests(s))[:300])
    # A long last message gives way; the note of what runs stays.
    s.ctl("/_ctl/reset", {})
    stop("sv2", [shell("yarn start")], last="All of this was done. " * 40)
    rec = wait_for(lambda: ingests(s, "done"), 20)
    msg = rec[0]["plain_json"].get("msg", "") if rec else ""
    s.check("service shell: a long message keeps the note whole", rec and msg.endswith("(still running in the background: shell: Start the dev server)")
            and len(msg) <= 200, repr(msg))
    # The commands the table knows, and some it must leave alone.
    s.ctl("/_ctl/reset", {})
    # One table (SVC_AWK): a command is a service only at the command position of the last list element and when
    # (tool, subcommand) is known; when in doubt it is not one (a wrong service sends an early done). A third
    # field 'amp' sends the command the way Go writes JSON (& < > as \u0026 \u003c \u003e).
    for cmd, service, *flag in (
            ('npm run dev -- --port 3000', True), ('pnpm run watch', True), ('next dev', True),
            ('python3 -m http.server 8000', True), ('python manage.py runserver 0.0.0.0:8000', True), ('bin/rails server', True),
            ('flask --app app run', True), ('uvicorn app:app --reload', True), ('docker compose up', True),
            ('tail -f /var/log/app.log', True), ('tsc --watch', True), ('cd web && npm start', True),
            ('docker compose up -d', False), ('tail -n 20 app.log', False), ('npm test', False), ('vite build', False),
            ('grep -w main src/app.dart', False), ('sleep 45; echo shell-done', False), ('npm install && npm run dev', True),
            ('tsc -w', True), ('npm test -- --watchAll=false', False), ('npx jest --watch=false', False),
            ('npm test -- --no-watch', False), ('python -W ignore -m pytest', False), ('make -w all', False),
            ('docker exec -w /app api pytest', False), ('pip install flask && npm run build', False),
            ('tail -n 50 build.log | cut -f 2', False), ('kubectl get pods -w', True), ('vite &', True), ('npx vite &', True),
            ('npx vite | tee vite.log', True), ('npx tsc -w', True), ('npx webpack -w', True),
            ('npx tailwindcss -i a.css -o b.css -w', True), ('docker logs -f api', True), ('kubectl logs -f web-1', True),
            ('journalctl -f', True), ('vitest run', False), ('npx vitest --run', False), ('docker logs api', False),
            ('vitest', False), ('npx vitest', False), ('npx vitest -w', True), ('npx vitest --watch', True),
            ('npx vite 2>&1', True), ('npx vite > vite.log 2>&1 &', True), ('vite 2>&1 | tee vite.log', True),
            ('npx vite >vite.log', True), ('npm create vite@latest', False), ('pnpm --filter web dev', True),
            ('pnpm -F web dev', True), ('pnpm install', False), ('turbo dev', True), ('nx serve', True), ('ng serve', True),
            ('astro dev', True), ('nuxt dev', True), ('npx expo start', True), ('storybook dev', True),
            ('php artisan serve', True), ('hugo server', True), ('bundle exec jekyll serve', True), ('npx serve', True),
            ('npx http-server', True), ('gunicorn app:app', True), ('kubectl port-forward svc/api 8080:80', True),
            ('kubectl rollout status deploy/api -w', False),
            ('until curl -s -o /dev/null -w "%{http_code}" localhost:3000; do sleep 1; done', False),
            ('pnpm prisma migrate dev --name init', False), ('pnpm sst deploy --stage dev', False),
            ('pnpm build --mode dev', False), ('nx build web -c dev', False), ('nx run-many -t build --configuration dev', False),
            ('turbo run deploy -- --stage dev', False), ('pnpm add -D vite @vitejs/plugin-react', False),
            ('yarn create vite my-app', False), ('npm install vite react', False), ('npm i -g http-server serve', False),
            ('kubectl -n prod rollout status deploy/api -w', False), ("curl -w '%{http_code}' x", False), ('vitest dev', True),
            ('vitest watch', True), ('watchexec -w src -- gcc -o a a.c', True), ('npm run dev:web', True), ('turbo run dev', True),
            ('nx run web:serve', True), ('FOO=1 npm run dev', True), ('sudo -u x npm run dev', False),
            ('kubectl -n prod get pods --watch', True), ('tail -F x', True), ('watch -n 1 ls', True), ('cargo watch -x run', True),
            ('docker-compose up', True), ('docker compose -f a.yml up', True), ('yarn workspace web dev', True),
            ('jest --watch', True), ('python -m flask run', True), ('vite --port 3000', True), ('vite --version', False),
            ('npm --prefix web run dev', True), ('sudo npm run dev', True), ('env FOO=1 npm run dev', True),
            ('./node_modules/.bin/vite', True), ('npx -y vite', True), ('uv run flask run', True), ('pnpm dlx serve', True),
            ('pnpm exec vite', True), ('npm run -- dev', False), ('tsc --noEmit -- -w', False),
            ('sass --watch a.scss b.css', True), ('sass -w a.scss b.css', True), ('npx jest -w 4', False),
            ('jest -w 2 --ci', False), ('npx jest --maxWorkers=2', False), ('npx jest --watchAll=false -w 2', False),
            ('jest --watchAll', True), ('tsx scripts/gen.ts -w', False), ('tsx watch src/index.ts', True),
            ('node scripts/gen.js --watch', False), ('python script.py -m http.server', False),
            ('docker compose up --abort-on-container-exit --exit-code-from tests', False),
            ('docker compose up --build --exit-code-from e2e', False), ('docker compose up --wait', False),
            ('docker compose up -d --wait', False),
            ('docker-compose -f docker-compose.test.yml up --abort-on-container-exit', False),
            ('docker compose up --no-start', False), ('docker compose up --dry-run', False),
            ('docker compose up --build \\\n  -d', False), ('docker compose up --build \\\n  --abort-on-container-exit', False),
            ('vite \\\n  build', False), ('docker compose up --build', True),
            ("cat > start.sh <<'EOF2'\n#!/bin/sh\nnpm run dev\nEOF2\nsh -n start.sh", False),
            ('grep -E "error|watch" app.log', False), ('grep -rE "TODO|vite" src/app.ts', False),
            ('until grep -qE "Ready|serve" server.log; do sleep 1; done', False),
            ('git commit -m "fix; npm run dev now works"', False), ('echo "step 1; tail -f log next"', False),
            ('node -e "const w = 1; watch(\'src\')"', False), ("printf 'Run:\\nnpm run dev\\n'", False),
            ("bash -c 'npm run build; npm test'", False), ('sh -c "cd web && npm run dev"', False),
            ('timeout 120 npm run dev', False), ('npm run dev & npx wait-on http://localhost:3000 && npx playwright test', False),
            ('npm run dev > dev.log 2>&1 & sleep 8 && curl -sf localhost:3000 && npm run test:e2e', False),
            ('python -m http.server 8000 & sleep 2; curl -s localhost:8000 | head', False), ('cd web && npm run dev', True),
            ('npm run dev &', True), ('python3 -m http.server 8000 &', True), ('npm run dev:setup', False),
            ('npm run dev:seed', False), ('pnpm start:db', False), ('yarn dev:migrate', False), ('turbo run dev:setup', False),
            ('npm run start:prod', True), ('kubectl logs -f job/db-migrate', False),
            ('kubectl -n prod logs --follow job/seed', False), ('kubectl logs -f jobs/x', False),
            ('kubectl logs -f deploy/api', True), ('docker compose logs -f migrate', True),
            ('tail -f build.log --pid=1234', False), ('watch -g ls', False), ("watch -g 'kubectl get pods'", False),
            ('npm --tag dev publish', False), ('yarn --frozen-lockfile dev', False), ('pnpm -w dev', False),
            ('pnpm --filter "@app/*" dev', True), ('pnpm dev --filter web', True), ('npx live-server', True),
            ('browser-sync start --server', True), ('node --watch server.js', True), ('bun --watch run index.ts', True),
            ('deno run --watch main.ts', True), ('hugo serve', True), ('astro preview', True), ('nuxt preview', True),
            ('storybook start', True), ('webpack serve', True), ('npx webpack-dev-server', True), ('rails server -d', False),
            ('rails s', True), ('vite optimize', False), ('vite build --watch', False), ('npx vite@5', False),
            ('bunx --bun vite', False), ('npm exec vite', False), ('php -S localhost:8000', False), ('make dev', False),
            ('./gradlew bootRun', False), ('go run ./cmd/server', False), ('mocha -w', True), ('cargo watch -x test', True),
            ('nx run web:serve-static', False), ('npx vite --open', True), ('python -m pytest tests -m uvicorn', False),
            ('npm test -- -w 4', False), ('npx jest --watch', True), ("cat <<EOF > notes\ndon't stop\nEOF\nnpm run dev", True),
            ('npm run dev \\\n  -- --port 3000', True), ('npm run build  # build & watch for type errors', False),
            ('npm run build  # then: preview & serve', False), ('pnpm test  # unit tests; npm run dev is separate', False),
            ('npm run lint\n# next: start dev & watch', False), ('curl http://x/#/a && npm test', False),
            ('npm run dev -- --name "<<web>>" &\nsleep 5 && npm run test:e2e', False),
            ("npm run dev  # it's the dev server", True), ('echo ${#a[@]}; npm run dev', True),
            ("npm run dev &  # it's the dev server\nnpx playwright test", False), ('npm run dev # comment \\\nsleep 1', False),
            ('echo a#b; npm run dev', True), ('tail -n 50 -f server.log | grep -m1 "ready"', False),
            ('docker compose logs -f api | grep -q "listening"', False), ('tail -f build.log | head -n 20', False),
            ('tail -f build.log | grep error', True), ('tail -f build.log | tee out.log', True), ('npm run dev | cat', True),
            ("printf $'don\\'t; npm run dev\\n' > notes.txt", False), ("echo 'it'\\''s; npm run dev'", False),
            ('cat <<-EOF > x\n\tnpm run dev\n\tEOF\nnpm test', False), ('cat <<"EOF" > x\nnpm run dev\nEOF\nnpm test', False),
            ("cat << 'EOF' > x\nnpm run dev\nEOF\nnpm test", False), ('cat <<\\EOF > x\nnpm run dev\nEOF\nnpm test', False),
            ('cat <<END-OF-FILE > x\nnpm run dev\nEND-OF-FILE\nnpm test', False),
            ('npm run dev > dev.log 2>&1 &\necho "waiting for <<READY>> marker"\nnpx wait-on http://localhost:3000 && npm run test:e2e', False),
            ('python3 -c "print(1 << SHIFT)"\nnpm test', False), ('( cd web && npm run dev ) &', True),
            ('{ npm run dev; } &', True), ('nohup npm run dev > /dev/null 2>&1 &', True), ('exec npm run dev', True),
            ('time npm run dev', True), ('time npm run build', False), ('npm run dev 2>&1 | tee dev.log', True),
            ('npm test 2>&1 | tee test.log', False), ('npm run dev |& tee dev.log', True), ('npm run dev &> dev.log &', True),
            ('vite --host', True), ('npx vite --host', True), ('vite --host 0.0.0.0', True), ('vite --host --port 3000', True),
            ('deno run -A --watch main.ts', True), ('webpack w', True), ('webpack server', True), ('webpack s', True),
            ('parcel src/index.html', True), ('parcel serve src/index.html', True), ('parcel watch src/index.html', True),
            ('parcel build src/index.html', False), ('npm run dev:deploy', False), ('npm run dev:typecheck', False),
            ('npm run dev:format', False), ('docker compose up -dV', False), ('docker compose up --detach=true', False),
            ('kubectl logs -f job.batch/migrate', False), ('kubectl logs -f -l job-name=migrate', False),
            ('gunicorn --check-config app:app', False), ('node run --watch', False), ('flask -A app run', False),
            ('npm run dev & npx wait-on http://localhost:3000 && npx playwright test', False, 'amp'),
            ('npm run dev &', True, 'amp'), ('cd web && npm run dev', True, 'amp'), ("printf $'it\\'s'; npm run dev", True),
            ('x=$((1<<3)); npm run dev &\nnpx wait-on http://localhost:3000 && npx playwright test', False),
            ('(( n <<= 1 )); npm run dev &\nsleep 5 && npm test', False), ('x=$((1<<3))\nnpm run dev', True),
            ('git commit -m "$(cat <<\'EOF\'\nFix "quoted bug\nEOF\n)" && npm run dev', True),
            ('git commit -m "$(cat <<\'EOF\'\nFix: start npm run dev\nEOF\n)" && npm test', False),
            ('esbuild --watch=forever src/app.js', True), ('esbuild --watch src/app.js', True)):
        s.ctl("/_ctl/reset", {})
        out = stop("sv3-%d" % abs(hash(cmd)), [shell(cmd, "Run it")], amp=bool(flag))
        got = seqs(out).startswith("\x1b]9;simpleterm:state=done")
        s.check("service shell: %r -> %s" % (cmd, "service" if service else "waits"), got == service, repr(out))
    # A command over 64 KiB is not looked at: not a service (the hook has seconds to answer).
    s.ctl("/_ctl/reset", {})
    out = stop("sv-big", [shell("echo " + "x" * 70000 + "; npm run dev", "Run it")])
    s.check("service shell: a command over 64 KiB is not looked at", seqs(out).startswith("\x1b]9;simpleterm:state=background"), repr(out)[:200])
    time.sleep(1)
    # Mixes: only services (and the agent's own housekeeping) count as services.
    s.ctl("/_ctl/reset", {})
    out = stop("sv4", [shell("npm run dev"), shell("tail -f app.log", "Follow the log")])
    s.check("service shell: two services -> done", seqs(out).startswith("\x1b]9;simpleterm:state=done"), repr(out))
    out = stop("sv5", [dict(SUBAGENT, type="dream", description="Consolidate memory"), shell("npm run dev")])
    s.check("service shell: housekeeping beside a service -> done", seqs(out).startswith("\x1b]9;simpleterm:state=done"), repr(out))
    out = stop("sv6", [shell("npm run dev"), SUBAGENT])
    s.check("service shell: a subagent beside a service -> waits", seqs(out).startswith("\x1b]9;simpleterm:state=background"), repr(out))
    out = stop("sv7", [shell("npm run dev"), shell("npm test", "Run the tests")])
    s.check("service shell: another shell beside a service -> waits", seqs(out).startswith("\x1b]9;simpleterm:state=background"), repr(out))
    # No hook record of its own where the service is not waited for (Claude Code reports done itself).
    out = stop("sv8", [shell("npm run dev")], extra={"transcript_path": str(cc_transcript(s))})
    s.check("service shell: no OSC 7501 working record", seqs(out) == "\x1b]9;simpleterm:state=done\x07", repr(out))
    # Grok Build.
    time.sleep(1.5)  # the sends of the cases above have landed
    s.ctl("/_ctl/reset", {})
    gt = {"id": "9f1d0a52-6c55-4a5a-8d2c-1d7e3c0c5b11", "type": "shell", "status": "running", "command": "python3 -m http.server 8000"}
    inp, env = grok_input("Stop", reason="end_turn", promptId="sv-g", timestamp="2026-11-02T10:01:00.000Z",
                          lastAssistantMessage="Serving on 8000.", backgroundTasks=[gt], sessionCrons=[])
    s.run("claude", inp, env)
    rec = wait_for(lambda: ingests(s, "done"), 20)
    s.check("service shell: Grok Build", rec and rec[0]["plain_json"].get("msg")
            == "Serving on 8000. (still running in the background: shell: python3 -m http.server 8000)", str(ingests(s))[:300])


def t_user_prompt_old_tasks(s):
    """A turn a person started, with only tasks that ran before it left: done. A turn the agent started
    itself (a task's report, a schedule) keeps waiting. (cmux issue 24387: a question answered while an
    older task runs is not held back.)"""
    s.setup([(LINK_A, {})])
    st = {"SIMPLETERM": "1"}
    old = dict(SUBAGENT)
    new = dict(SUBAGENT, id="n9n9n9n9n", description="Write the docs")

    def run(sid, name, **kw):
        return s.run("claude", cc_event(sid, name, **kw), st)[1]

    def stop(sid, tasks, last="Report."):
        return run(sid, "Stop", stop_hook_active=False, last_assistant_message=last, background_tasks=tasks, session_crons=[])

    def waits(out):
        return seqs(out).startswith("\x1b]9;simpleterm:state=background")

    # Turn 1 starts the subagent: waits. Turn 2, typed by the person, ends with only that subagent left: done.
    run("uo1", "UserPromptSubmit", prompt="review the diff in the background")
    s.check("user turn: the turn that starts the task waits", waits(stop("uo1", [old])))
    run("uo1", "UserPromptSubmit", prompt="what is the status?", prompt_id="p2")
    out = stop("uo1", [old], last="The reviewer is still working.")
    s.check("user turn: typed prompt, only the older task left -> done", seqs(out) == "\x1b]9;simpleterm:state=done\x07", repr(out))
    rec = wait_for(lambda: ingests(s, "done"), 20)
    s.check("user turn: ... with the note of what runs", len(rec) == 1 and rec[0]["plain_json"].get("msg")
            == "The reviewer is still working. (still running in the background: subagent: Review the diff)", str(ingests(s))[:300])
    # A task started by that turn keeps it waiting.
    s.ctl("/_ctl/reset", {})
    run("uo1", "UserPromptSubmit", prompt="also write the docs")
    s.check("user turn: a task started by this turn -> waits", waits(stop("uo1", [old, new])))
    # A turn started by the task's report (no source in 2.1.316): waits for the other task.
    run("uo1", "UserPromptSubmit", prompt="<task-notification>\n<task-id>a42a3936ffcdae563</task-id>\n<status>completed</status>")
    s.check("auto turn: task-notification prompt -> waits for the rest", waits(stop("uo1", [new])))
    run("uo1", "UserPromptSubmit", prompt="<agent-message from=\"n9n9n9n9n\">\n[Subagent hand-back] ...")
    s.check("auto turn: agent-message prompt -> waits", waits(stop("uo1", [new])))
    time.sleep(1.5)
    s.check("auto turn: no event from the waiting turns", not ingests(s), str(ingests(s))[:300])
    # The `source` field, where Claude Code sends it.
    for source, expect_wait in (("loop_wakeup", True), ("schedule_wakeup", True), ("system", True), ("poll_event", True),
                                ("user", False), ("sdk", False)):
        s.ctl("/_ctl/reset", {})
        run("uo2", "UserPromptSubmit", prompt="start")
        stop("uo2", [old])
        run("uo2", "UserPromptSubmit", prompt="next", source=source)
        out = stop("uo2", [old])
        s.check("source %s: %s" % (source, "waits" if expect_wait else "done"), waits(out) == expect_wait, repr(out))
    # Tasks without an id cannot be proven old: waits (older Claude Code).
    s.ctl("/_ctl/reset", {})
    noid = {k: v for k, v in old.items() if k != "id"}
    run("uo3", "UserPromptSubmit", prompt="start")
    stop("uo3", [noid])
    run("uo3", "UserPromptSubmit", prompt="status?")
    s.check("user turn: tasks without an id -> waits", waits(stop("uo3", [noid])))
    # A turn whose start the hook never saw is a person's, but its tasks are all new: waits.
    s.check("user turn: no earlier Stop -> the tasks are new -> waits", waits(stop("uo-fresh", [old])))
    # A schedule's own prompt, found by the prompt listed at the last Stop (no `source`, no marker).
    s.ctl("/_ctl/reset", {})
    cron = {"id": "c1", "schedule": "*/5 * * * *", "recurring": True, "prompt": "check the deploy and report"}
    run("uo4", "UserPromptSubmit", prompt="every 5 minutes check the deploy")
    run("uo4", "Stop", stop_hook_active=False, last_assistant_message="Scheduled.", background_tasks=[old], session_crons=[cron])
    run("uo4", "UserPromptSubmit", prompt="check the deploy and report")
    out = run("uo4", "Stop", stop_hook_active=False, last_assistant_message="Still deploying.", background_tasks=[old], session_crons=[cron])
    s.check("auto turn: a prompt equal to a schedule's -> waits", waits(out), repr(out))
    # Grok Build: the prompt id says who started the turn.
    time.sleep(2)  # the sends of the cases above have landed
    s.ctl("/_ctl/reset", {})
    gt = {"id": "48d7f629-d7ca-4ac8-94ac-419eb88970a7", "type": "subagent", "status": "running", "description": "sleep sub",
          "agentType": "general-purpose"}

    def gstop(promptid, ts):
        inp, env = grok_input("Stop", reason="end_turn", promptId=promptid, timestamp=ts, lastAssistantMessage="Report from grok.",
                              backgroundTasks=[gt], sessionCrons=[])
        s.run("claude", inp, env)

    def gprompt(promptid, ts):
        inp, env = grok_input("UserPromptSubmit", promptId=promptid, timestamp=ts, prompt="x")
        s.run("claude", inp, dict(env, GROK_HOOK_EVENT="user_prompt_submit"))

    gprompt("0773d809-9300-4d94-aa8b-bed0ee67f947", "2026-11-02T10:10:00.000Z")
    gstop("0773d809-9300-4d94-aa8b-bed0ee67f947", "2026-11-02T10:10:05.000Z")
    time.sleep(1)
    s.check("grok user turn: the turn that starts the task waits", not ingests(s), str(ingests(s))[:200])
    gprompt("scheduler-fired-7", "2026-11-02T10:11:00.000Z")
    gstop("scheduler-fired-7", "2026-11-02T10:11:05.000Z")
    time.sleep(1)
    s.check("grok scheduled turn: waits", not ingests(s), str(ingests(s))[:200])
    gprompt("11111111-9300-4d94-aa8b-bed0ee67f947", "2026-11-02T10:12:00.000Z")
    gstop("11111111-9300-4d94-aa8b-bed0ee67f947", "2026-11-02T10:12:05.000Z")
    rec = wait_for(lambda: ingests(s, "done"), 20)
    s.check("grok user turn: only the older task left -> done", len(rec) == 1 and rec[0]["plain_json"].get("msg")
            == "Report from grok. (still running in the background: subagent: sleep sub)", str(ingests(s))[:300])


def t_schedules(s):
    """/loop, CronCreate and ScheduleWakeup (session_crons / sessionCrons): the turns a schedule starts do not
    each send done. A person's own prompt always does; the Stop that finds the schedule gone is the done."""
    s.setup([(LINK_A, {})])
    st = {"SIMPLETERM": "1"}
    cron = [{"id": "c1", "schedule": "*/5 * * * *", "recurring": True, "prompt": "check the deploy"},
            {"id": "c2", "schedule": "0 9 * * 1-5", "recurring": True, "prompt": "morning report"}]

    def stop(sid, crons, last, extra=None):
        return s.run("claude", cc_event(sid, "Stop", stop_hook_active=False, last_assistant_message=last, background_tasks=[],
                                        session_crons=crons, **(extra or {})), st)[1]

    s.run("claude", cc_event("sc1", "UserPromptSubmit", prompt="/loop 5m check the deploy"), st)
    out = stop("sc1", cron, "Scheduled the check.")
    s.check("schedule: typed turn with a schedule -> done as usual", seqs(out) == "\x1b]9;simpleterm:state=done\x07", repr(out))
    rec = wait_for(lambda: ingests(s, "done"), 20)
    s.check("schedule: ... one done event", len(rec) == 1, str(ingests(s))[:300])
    s.ctl("/_ctl/reset", {})
    for i in range(3):
        s.run("claude", cc_event("sc1", "UserPromptSubmit", prompt="check the deploy", source="schedule_wakeup"), st)
        out = stop("sc1", cron, "Deploy still running (%d)." % i)
        s.check("schedule: iteration %d (source) -> background, scheduled" % i,
                seqs(out) == "\x1b]9;simpleterm:state=background scheduled: */5 * * * * (+1 more)\x07", repr(out))
    # The prompt alone says it too (no `source`, as 2.1.316).
    s.run("claude", cc_event("sc1", "UserPromptSubmit", prompt="morning report"), st)
    out = stop("sc1", cron, "Report.")
    s.check("schedule: a prompt equal to a schedule's -> background", seqs(out).startswith("\x1b]9;simpleterm:state=background scheduled:"), repr(out))
    time.sleep(1.5)
    s.check("schedule: no event from the scheduled turns", not ingests(s), str(ingests(s))[:300])
    # Claude Code 2.1.295+: a working record, with the schedule as its text; taken back at the next turn.
    tr = cc_transcript(s)
    s.run("claude", cc_event("sc2", "UserPromptSubmit", prompt="x", source="loop_wakeup"), st)
    out = stop("sc2", cron[:1], "Check.", extra={"transcript_path": str(tr)})
    s.check("schedule: OSC 7501 working record", seqs(out) == "\x1b]9;simpleterm:state=background scheduled: */5 * * * *\x07"
            "\x1b]7501;state=working:id=simpleterm-bg:msg=" + b64("scheduled: */5 * * * *") + "\x07", repr(out))
    # A question in a scheduled turn is still told.
    s.ctl("/_ctl/reset", {})
    s.run("claude", cc_event("sc3", "UserPromptSubmit", prompt="x", source="schedule_wakeup"), st)
    out = stop("sc3", cron[:1], "The deploy failed. Should I roll back?")
    rec = wait_for(lambda: ingests(s, "question"), 20)
    s.check("schedule: a question in a scheduled turn -> question", len(rec) == 1 and "state=waiting" in seqs(out), str(ingests(s))[:300])
    # The Stop that finds the schedule gone is the done, once.
    s.ctl("/_ctl/reset", {})
    s.run("claude", cc_event("sc3", "UserPromptSubmit", prompt="x", source="loop_wakeup"), st)
    out = stop("sc3", [], "The deploy finished; the loop ended.")
    rec = wait_for(lambda: ingests(s, "done"), 20)
    s.check("schedule: no schedule left -> done once", len(rec) == 1 and seqs(out) == "\x1b]9;simpleterm:state=done\x07", str(ingests(s))[:300])
    # Grok Build.
    s.ctl("/_ctl/reset", {})
    gcron = [{"id": "g1", "schedule": "every 5 minutes", "recurring": True, "prompt": "check it"}]
    inp, env = grok_input("UserPromptSubmit", promptId="scheduler-fired-1", timestamp="2026-11-02T11:00:00.000Z", prompt="check it")
    s.run("claude", inp, dict(env, GROK_HOOK_EVENT="user_prompt_submit"))
    inp, env = grok_input("Stop", reason="end_turn", promptId="scheduler-fired-1", timestamp="2026-11-02T11:00:03.000Z",
                          lastAssistantMessage="Still fine.", backgroundTasks=[], sessionCrons=gcron)
    s.run("claude", inp, env)
    time.sleep(1.5)
    s.check("schedule: Grok Build scheduled turn -> nothing", not ingests(s), str(ingests(s))[:200])
    inp, env = grok_input("UserPromptSubmit", promptId="22222222-9300-4d94-aa8b-bed0ee67f947", timestamp="2026-11-02T11:05:00.000Z", prompt="hi")
    s.run("claude", inp, dict(env, GROK_HOOK_EVENT="user_prompt_submit"))
    inp, env = grok_input("Stop", reason="end_turn", promptId="22222222-9300-4d94-aa8b-bed0ee67f947", timestamp="2026-11-02T11:05:03.000Z",
                          lastAssistantMessage="Hello.", backgroundTasks=[], sessionCrons=gcron)
    s.run("claude", inp, env)
    s.check("schedule: Grok Build typed turn -> done", wait_for(lambda: ingests(s, "done"), 20))


def t_done_delay(s):
    """A done waits done_delay seconds (default 3) for another Stop hook that keeps the agent going."""
    s.setup([(LINK_A, {})], conf={"done_delay": None})
    t0 = time.time()
    stop = cc_event("dd1", "Stop", stop_hook_active=False, last_assistant_message="Implemented it.", background_tasks=[], session_crons=[])
    rc, out, err, el = s.run("claude", stop, {"SIMPLETERM": "1"})
    s.check("done delay: the badge changes at once", seqs(out) == "\x1b]9;simpleterm:state=done\x07" and el < 2, "%r %.2fs" % (out, el))
    time.sleep(1.2)
    s.check("done delay: no event yet after 1.2 s", not ingests(s), str(ingests(s))[:200])
    rec = wait_for(lambda: ingests(s, "done"), 20)
    s.check("done delay: sent after about 3 s", len(rec) == 1 and 2.7 <= rec[0]["received"] - t0 <= 12,
            str([round(r["received"] - t0, 2) for r in rec]))
    s.check("done delay: the event is made then (its time is the send time)",
            rec and abs(rec[0]["plain_json"]["ts"] - rec[0]["received"]) < 3, str(rec[0].get("plain_json") if rec else None))
    # Another Stop hook blocked, the agent works on: any newer event of the session ends the wait.
    s.ctl("/_ctl/reset", {})
    s.run("claude", stop, {"SIMPLETERM": "1"})
    s.run("claude", cc_event("dd1", "PostToolUse", tool_name="Bash", tool_input={"command": "npm test"}), {"SIMPLETERM": "1"})
    time.sleep(4.5)
    s.check("done delay: a newer event of the session -> no done", not ingests(s), str(ingests(s))[:200])
    # ... and the Stop that follows replaces it: one done, with its message.
    s.ctl("/_ctl/reset", {})
    s.run("claude", cc_event("dd2", "Stop", stop_hook_active=False, last_assistant_message="First.", background_tasks=[], session_crons=[]))
    s.run("claude", cc_event("dd2", "Stop", stop_hook_active=True, last_assistant_message="Second.", background_tasks=[], session_crons=[]))
    rec = wait_for(lambda: ingests(s, "done"), 20)
    time.sleep(4)
    d = ingests(s, "done")
    s.check("done delay: a second Stop replaces the first", len(d) == 1 and d[0]["plain_json"].get("msg") == "Second.", str(d)[:300])
    s.check("done delay: stop_hook_active is passed on", d and d[0]["plain_json"].get("stop_hook_active") is True, str(d[0].get("plain") if d else None))
    # Another session's events do not cancel it.
    s.ctl("/_ctl/reset", {})
    s.run("claude", cc_event("dd3", "Stop", stop_hook_active=False, last_assistant_message="Mine.", background_tasks=[], session_crons=[]))
    s.run("claude", cc_event("dd4", "PostToolUse", tool_name="Bash", tool_input={"command": "ls"}))
    rec = wait_for(lambda: ingests(s, "done"), 20)
    s.check("done delay: another session's event does not cancel it", len(rec) == 1 and rec[0]["plain_json"].get("msg") == "Mine.", str(ingests(s))[:200])
    s.check("done delay: no stop_hook_active when it was not set", "stop_hook_active" not in (rec[0]["plain"] if rec else "x"), str(rec[0].get("plain") if rec else None))
    # Codex and Grok send it the same way; done_delay=0 sends at once.
    s.setup([(LINK_A, {})], conf={"done_delay": 0})
    t0 = time.time()
    s.run("claude", stop)
    rec = wait_for(lambda: ingests(s, "done"), 20)
    s.check("done delay: done_delay=0 -> at once", rec and rec[0]["received"] - t0 < 2.5, str([round(r["received"] - t0, 2) for r in rec]))
    s.setup([(LINK_A, {})], conf={"done_delay": None})
    t0 = time.time()
    # Codex registers no event that would come within moments to cancel the wait: at once (0), the flag still passed on.
    s.run("codex", json.dumps({"session_id": "dd-cx", "turn_id": "t", "transcript_path": None, "cwd": "/w/repo",
                               "hook_event_name": "Stop", "last_assistant_message": "Codex done.", "stop_hook_active": True}))
    # (a newer event of the session would have cancelled a pending done: it is not pending)
    s.run("codex", json.dumps({"session_id": "dd-cx", "hook_event_name": "SessionStart", "cwd": "/w/repo", "transcript_path": None}))
    rec = wait_for(lambda: ingests(s, "done"), 20)
    s.check("done delay: Codex has no wait by default (nothing could cancel it)",
            rec and rec[0]["plain_json"].get("stop_hook_active") is True, str([round(r["received"] - t0, 2) for r in rec]))
    # Grok Build keeps the wait (its other events come within moments).
    s.ctl("/_ctl/reset", {})
    t0 = time.time()
    inp, env = grok_input("Stop", reason="end_turn", promptId="dd-g", timestamp="2026-11-02T10:20:00.000Z",
                          lastAssistantMessage="Grok done.", backgroundTasks=[], sessionCrons=[])
    s.run("claude", inp, env)
    rec = wait_for(lambda: ingests(s, "done"), 20)
    s.check("done delay: Grok Build keeps the 3 s wait", rec and rec[0]["received"] - t0 >= 2.7, str([round(r["received"] - t0, 2) for r in rec]))


def t_background_events_and_badges(s):
    """Review findings: a background subagent's own events must not eat the done of a typed turn, a question
    stays `waiting` when a subagent runs a tool, and an interrupted subagent tool is not the main turn's end."""
    st = {"SIMPLETERM": "1"}
    old = dict(SUBAGENT)

    def run(sid, name, **kw):
        return s.run("claude", cc_event(sid, name, **kw), st)[1]

    def stop(sid, tasks, last="Report."):
        return run(sid, "Stop", stop_hook_active=False, last_assistant_message=last, background_tasks=tasks, session_crons=[])

    # H1: the shipped 3 s done_delay; the tool call of the old subagent (same session id, agent_id set) that
    # follows a typed turn's done must not cancel it.
    s.setup([(LINK_A, {})], conf={"done_delay": None})
    run("bev1", "UserPromptSubmit", prompt="review the diff in the background")
    stop("bev1", [old])
    run("bev1", "UserPromptSubmit", prompt="what is the status?")
    t0 = time.time()
    stop("bev1", [old], last="The reviewer is still working.")
    run("bev1", "PostToolUse", tool_name="Read", tool_input={"file_path": "/w/proj/a.dart"}, agent_id="a42a3936ffcdae563")
    rec = wait_for(lambda: ingests(s, "done"), 20)
    time.sleep(4)
    d = ingests(s, "done")
    s.check("typed turn, old task left: a background subagent's tool call does not cancel the done",
            len(d) == 1 and d[0]["received"] - t0 < 8 and "still running in the background" in d[0]["plain_json"].get("msg", ""),
            str([(r["plain_json"].get("msg"), round(r["received"] - t0, 2)) for r in d]))

    # A Stop another Stop hook blocks (the agent goes on) while an old task is left: the main thread's next
    # event cancels the done, the next Stop sends it once (no done before and another after).
    s.setup([(LINK_A, {})], conf={"done_delay": None})
    run("bev4", "UserPromptSubmit", prompt="start")
    stop("bev4", [old])
    run("bev4", "UserPromptSubmit", prompt="status?")
    stop("bev4", [old], last="First.")
    run("bev4", "PostToolUse", tool_name="Bash", tool_input={"command": "npm test"})
    run("bev4", "Stop", stop_hook_active=True, last_assistant_message="Second.", background_tasks=[old], session_crons=[])
    wait_for(lambda: ingests(s, "done"), 20)
    time.sleep(4)
    d = ingests(s, "done")
    s.check("blocked Stop with an old task left: one done, for the real end",
            len(d) == 1 and d[0]["plain_json"].get("msg", "").startswith("Second."), str([r["plain_json"].get("msg") for r in d]))

    # A run dir that cannot be written (here: a file where the directory belongs; the hook re-chmods a real
    # directory itself): the hook still exits 0 and prints the badge (a failed redirection of the special
    # builtin `:` would end the shell: exit 2 is "block and continue" for Claude Code's Stop).
    s.setup([(LINK_A, {"push": "disabled"})])
    rd = s.home / ".simpleterm" / "run"
    shutil.rmtree(rd, ignore_errors=True)
    rd.write_text("")
    try:
        rc, out, err, el = s.run("claude", cc_event("bev9", "Stop", stop_hook_active=False, last_assistant_message="Done.",
                                                     background_tasks=[], session_crons=[]), st)
    finally:
        rd.unlink()
    s.check("unwritable run dir: Stop exits 0 and prints the badge", rc == 0 and seqs(out) == "\x1b]9;simpleterm:state=done\x07",
            "%s %r %r" % (rc, out, err[-200:]))

    # A turn that ends with a question is done, with the question as its text; idle_prompt 60 s later adds none.
    s.setup([(LINK_A, {"push": "disabled"})])
    qd = "Should I deploy to staging now?"
    stop("bev7", [], last=qd)
    wait_for(lambda: ingests(s, "done"), 20)
    run("bev7", "Notification", notification_type="idle_prompt", message="Claude is waiting for your input")
    time.sleep(1.5)
    evs = ingests(s)
    s.check("question-ended turn: done carries the question, idle_prompt adds no question",
            [r["body"]["ev"] for r in evs] == ["done"] and evs[0]["plain_json"].get("msg") == qd, str([r["plain_json"].get("msg") for r in evs]))

    # idle_prompt (60 s after a turn) repeats a done that was sent: no question and no badge change. Without a done
    # (the turn ended by an interrupt) it stays the safety net; a new prompt takes the mark back.
    idle = dict(notification_type="idle_prompt", message="Claude is waiting for your input")
    s.setup([(LINK_A, {"push": "disabled"})])
    stop("bev5", [], last="Finished.")
    wait_for(lambda: ingests(s, "done"), 20)
    s.ctl("/_ctl/reset", {})
    out = run("bev5", "Notification", **idle)
    time.sleep(1.5)
    s.check("idle_prompt after a done: no question, no badge change", out == "" and not ingests(s), repr(out) + str(ingests(s))[:200])
    run("bev5", "UserPromptSubmit", prompt="next")
    run("bev5", "PostToolUseFailure", tool_name="Bash", tool_input={"command": "ls"}, is_interrupt=True, error="interrupted")
    run("bev5", "Notification", **idle)
    rec = wait_for(lambda: ingests(s, "question"), 20)
    s.check("idle_prompt after an interrupt (no done): question as before", len(rec) == 1, str(ingests(s))[:200])

    # nit 1: the turn paused on a question; a subagent's tool call keeps the badge `waiting`.
    s.setup([(LINK_A, {"push": "disabled"})])
    q = "The reviewer is still running. Should I also fix the lint warnings meanwhile?"
    out = stop("bev2", [old], last=q)
    out2 = run("bev2", "PostToolUse", tool_name="Read", tool_input={"file_path": "/w/a"}, agent_id="a42a3936ffcdae563")
    s.check("question while waiting: a subagent's tool call keeps the badge waiting",
            seqs(out) == "\x1b]9;simpleterm:state=waiting " + q + "\x07" and seqs(out2) == "\x1b]9;simpleterm:state=waiting " + q + "\x07",
            repr(out) + repr(out2))
    out3 = stop("bev3", [old], last="The reviewer is still running.")
    out4 = run("bev3", "PostToolUse", tool_name="Read", tool_input={"file_path": "/w/a"}, agent_id="a42a3936ffcdae563")
    s.check("no question: a subagent's tool call keeps the badge background",
            seqs(out4).startswith("\x1b]9;simpleterm:state=background subagent: Review the diff"), repr(out4))
    # nit 4: Esc on a tool of a background subagent (agent_id) is not the end of the main turn; Esc on the main one is.
    out5 = run("bev3", "PostToolUseFailure", tool_name="Bash", tool_input={"command": "ls"}, is_interrupt=True,
               error="interrupted", agent_id="a42a3936ffcdae563")
    s.check("interrupted subagent tool: the wait goes on (background, not idle)",
            seqs(out5).startswith("\x1b]9;simpleterm:state=background subagent: Review the diff"), repr(out5))
    out6 = run("bev3", "PostToolUseFailure", tool_name="Bash", tool_input={"command": "ls"}, is_interrupt=True, error="interrupted")
    s.check("interrupted main tool: idle", seqs(out6) == "\x1b]9;simpleterm:state=idle\x07", repr(out6))


def t_small_audit_fixes(s):
    """AskUserQuestion once, Gemini without an answer, agent_needs_input, Esc during a tool call."""
    s.setup([(LINK_A, {})])
    st = {"SIMPLETERM": "1"}
    q = {"questions": [{"question": "Which database should I use?", "header": "DB", "options": [{"label": "Postgres"}], "multiSelect": False}]}
    s.run("claude", cc_event("au1", "PreToolUse", tool_name="AskUserQuestion", tool_input=q), st)
    s.run("claude", cc_event("au1", "PermissionRequest", tool_name="AskUserQuestion", tool_input=q), st)
    time.sleep(1.5)
    qs = ingests(s, "question")
    s.check("AskUserQuestion: one alert for PreToolUse + PermissionRequest", len(qs) == 1 and qs[0]["plain_json"].get("msg") == "Which database should I use?",
            str(ingests(s))[:300])
    q2 = {"questions": [{"question": "And which cache?", "header": "Cache", "options": [{"label": "Redis"}], "multiSelect": False}]}
    s.run("claude", cc_event("au1", "PermissionRequest", tool_name="AskUserQuestion", tool_input=q2), st)
    s.run("claude", cc_event("au1", "PreToolUse", tool_name="AskUserQuestion", tool_input=q2), st)
    s.run("claude", cc_event("au2", "PreToolUse", tool_name="AskUserQuestion", tool_input=q), st)
    wait_for(lambda: len(ingests(s, "question")) >= 3, 20)
    time.sleep(1)
    s.check("AskUserQuestion: another question or another session is another alert", len(ingests(s, "question")) == 3,
            str([r["plain_json"].get("msg") for r in ingests(s)]))
    _, out, _, _ = s.run("claude", cc_event("au1", "PreToolUse", tool_name="AskUserQuestion", tool_input=q), st)
    s.check("AskUserQuestion: the badge still says waiting for the repeat", seqs(out) == "\x1b]9;simpleterm:state=waiting\x07", repr(out))

    # Gemini CLI: AfterAgent with "[no response text]" is an API error, a cancel or a loop, not a finished answer.
    s.ctl("/_ctl/reset", {})
    base = {"session_id": "gm9", "cwd": "/w/site", "hook_event_name": "AfterAgent", "prompt": "refactor x", "stop_hook_active": False}
    s.run("gemini", json.dumps(dict(base, prompt_response="[no response text]")))
    rec = wait_for(lambda: ingests(s), 20)
    s.check("gemini: no response text -> error, not done", rec and rec[0]["body"]["ev"] == "error" and not ingests(s, "done"), str(ingests(s))[:300])
    s.ctl("/_ctl/reset", {})
    s.run("gemini", json.dumps(dict(base, prompt_response="Refactored.")))
    s.check("gemini: an answer -> done", wait_for(lambda: ingests(s, "done"), 20))

    # Claude Code: agent_needs_input is another background session's: the alert, but this tab's badge stays.
    s.ctl("/_ctl/reset", {})
    _, out, _, _ = s.run("claude", cc_event("an1", "Notification", notification_type="agent_needs_input",
                                            message="Background session 'deploy' needs input"), st)
    rec = wait_for(lambda: ingests(s, "question"), 20)
    s.check("agent_needs_input: the alert is sent", rec and rec[0]["plain_json"].get("msg") == "Background session 'deploy' needs input", str(ingests(s))[:200])
    s.check("agent_needs_input: this tab's state does not change", out == "", out)

    # Esc during a tool call (PostToolUseFailure is_interrupt): the turn is over, the badge is not running.
    _, out, _, _ = s.run("claude", cc_event("ei1", "PostToolUseFailure", tool_name="Bash", tool_input={"command": "sleep 100"},
                                            error="Interrupted", is_interrupt=True), st)
    s.check("interrupt: idle, not running", seqs(out) == "\x1b]9;simpleterm:state=idle\x07", repr(out))
    _, out, _, _ = s.run("claude", cc_event("ei1", "PostToolUseFailure", tool_name="Bash", tool_input={"command": "false"},
                                            error="Exit code 1", is_interrupt=False), st)
    s.check("tool failure without interrupt: still running", seqs(out) == "\x1b]9;simpleterm:state=running\x07", repr(out))
    # The interrupt ends a background pause the way a new turn does.
    tr = cc_transcript(s)
    s.run("claude", cc_event("ei2", "Stop", stop_hook_active=False, last_assistant_message="Waiting.", background_tasks=[SUBAGENT],
                             session_crons=[], transcript_path=str(tr)), st)
    _, out, _, _ = s.run("claude", cc_event("ei2", "PostToolUseFailure", tool_name="Bash", tool_input={"command": "sleep 100"},
                                            error="Interrupted", is_interrupt=True), st)
    s.check("interrupt: takes the background record back", seqs(out) == "\x1b]9;simpleterm:state=idle\x07\x1b]7501;state=clear:id=simpleterm-bg\x07", repr(out))


AGENT_PY = (
    "import subprocess, sys\n"
    "p = subprocess.Popen(sys.argv[2:], stdin=subprocess.PIPE)\n"
    "p.stdin.write(sys.argv[1].encode()); p.stdin.close()\n"
    "print(p.pid, flush=True)\n"
    "p.wait()\n"
)


def t_agent_gone(s):
    """The agent process exits while the hook waits: stop polling, print nothing."""
    s.setup([(LINK_A, {})], conf={"claude_wait": 60})
    cmd = [sys.executable, "-I", "-c", AGENT_PY, perm_input(session="gone")] + list(s.argv) + ["claude"]
    agent = subprocess.Popen(cmd, stdout=subprocess.PIPE, env=s.env(), cwd=str(s.tmp))
    hook_pid = int(agent.stdout.readline())
    wait_for(lambda: s.records("/v1/decision"), 15)
    agent.kill()
    agent.wait(5)
    def gone():
        try:
            os.kill(hook_pid, 0)
            return False
        except OSError:
            return True
    s.check("agent gone: hook exits", wait_for(gone, 20), "pid %d" % hook_pid)
    s.check("agent gone: logged", wait_for(lambda: "permission agent-gone" in s.log_text(), 3), s.log_text())
    n = len(s.records("/v1/decision"))
    time.sleep(3)
    s.check("agent gone: polling stopped", len(s.records("/v1/decision")) == n)


def t_events(s):
    s.setup([(LINK_A, {})])
    cases = [
        ("claude", {"session_id": "e", "hook_event_name": "StopFailure", "error": "rate_limit",
                    "last_assistant_message": "API Error: Rate limit reached"}, "error"),
        ("claude", {"session_id": "e", "hook_event_name": "StopFailure", "error": "authentication_failed"}, "auth"),
        ("claude", {"session_id": "e", "hook_event_name": "PreToolUse", "tool_name": "AskUserQuestion",
                    "tool_input": {"questions": [{"question": "Which DB?", "options": []}]}}, "question"),
        ("codex", {"session_id": "e", "turn_id": "t", "hook_event_name": "Stop", "cwd": "/r", "model": "m",
                   "permission_mode": "default", "stop_hook_active": False, "transcript_path": None,
                   "last_assistant_message": "Done."}, "done"),
    ]
    for agent, inp, ev in cases:
        s.ctl("/_ctl/reset", {})
        rc, out, err, el = s.run(agent, json.dumps(inp))
        rec = wait_for(lambda: s.records("/v1/ingest"), 20)
        got = rec[0]["body"]["ev"] if rec else None
        s.check("events: %s %s -> %s" % (agent, inp["hook_event_name"], ev), got == ev, "%s %s" % (got, err))
        if ev == "question" and rec:
            s.check("events: question text", rec[0]["plain_json"].get("msg") == "Which DB?", str(rec[0].get("plain_json")))
    s.ctl("/_ctl/reset", {})
    s.run("codex", json.dumps({"session_id": "e", "hook_event_name": "Stop", "last_assistant_message": '{"title":"Fix tests"}'}))
    time.sleep(1.5)
    s.check("events: codex title-generation Stop filtered", not s.records("/v1/ingest"))
    for first, expect in (("Generate a concise, single-line task title for this", 0), ("Fix the tests", 1)):
        s.ctl("/_ctl/reset", {})
        j = json.dumps({"type": "agent-turn-complete", "thread-id": "x", "turn-id": "y", "cwd": "/r",
                        "client": "codex-tui", "input-messages": [first], "last-assistant-message": "done"})
        s.run("codex-notify", "", args=(j,))
        if expect:
            wait_for(lambda: s.records("/v1/ingest"), 20)
        time.sleep(1.5)
        s.check("events: codex notify %s" % ("filtered" if expect == 0 else "sent"),
                len(s.records("/v1/ingest")) == expect, str(s.records("/v1/ingest"))[:200])


def t_hostile_input(s):
    s.setup([(LINK_A, {"push": "disabled"})])
    marker = s.tmp / "PWNED"
    cmd = ('한글 테스트 😀 \'quoted\' \\back\\slash \x1b]0;evil\x07 echo "$(touch %s)" `touch %s` %s'
           % (marker, marker, "x" * 400))
    rc, out, err, el = s.run("claude", perm_input(command=cmd, cwd="/home/u/프로젝트/"))
    s.check("hostile: nothing executed", not marker.exists())
    rec = s.records("/v1/ingest")
    p = rec[0].get("plain_json") if rec else None
    s.check("hostile: plaintext is valid JSON", isinstance(p, dict), str(rec)[:300])
    if isinstance(p, dict):
        msg = p.get("msg", "")
        s.check("hostile: msg <= 200 chars", len(msg) <= 200, str(len(msg)))
        s.check("hostile: control chars removed", not any(ord(c) < 32 or 127 <= ord(c) < 160 for c in msg), repr(msg[:120]))
        s.check("hostile: text kept", "$(touch" in msg and "한글 테스트 😀" in msg and '"' in msg and "\\back" in msg, repr(msg[:160]))
        s.check("hostile: cwd base", p.get("cwd") == "프로젝트", p.get("cwd"))
    s.check("hostile: body within relay limit", rec and rec[0]["size"] <= 4096, str(rec[0]["size"] if rec else None))
    # Very large input (a Write of 1 MiB) is cut at the input limit and still handled.
    big = json.dumps({"session_id": "b", "cwd": "/x", "hook_event_name": "PermissionRequest", "tool_name": "Write",
                      "tool_input": {"file_path": "/x/big.txt", "content": "A" * (1 << 20)}})
    s.ctl("/_ctl/reset", {})
    rc, out, err, el = s.run("claude", big)
    rec = s.records("/v1/ingest")
    s.check("large input: handled quickly", el < 5, "%.2fs" % el)
    s.check("large input: msg from file_path", rec and rec[0].get("plain_json", {}).get("msg") == "approve Write: /x/big.txt",
            str(rec[0].get("plain_json") if rec else None))
    s.ctl("/_ctl/reset", {})
    rc, out, err, el = s.run("claude", "not json at all {{{")
    s.check("garbage input: exit 0, silent", rc == 0 and out == "" and not s.records("/v1/ingest"), out + err)


def t_log(s):
    s.setup([(LINK_A, {"push": "disabled"})])
    logp = s.home / ".simpleterm" / "agent-hook.log"
    logp.write_text("".join("old line %d\n" % i for i in range(300)))
    s.run("claude", perm_input(command="secret-command --token abc"))
    text = s.log_text()
    s.check("log: capped at 200 lines", len(text.splitlines()) <= 200, str(len(text.splitlines())))
    s.check("log: newest kept", "ingest ev=permission" in text)
    s.check("log: no message bodies", "secret-command" not in text and "dev-box" not in text, text[-300:])
    if s.kind == "sh":  # the PowerShell hook targets Windows, where profile ACLs apply
        st = s.home / ".simpleterm"
        mode = st.stat().st_mode & 0o777
        s.check("files: ~/.simpleterm is 700", mode == 0o700, oct(mode))


CURL_SPY = """#!/bin/sh
# Records curl's argv (what `ps` shows other users) and the request body file's mode.
for a in "$@"; do
  printf '%%s\\n' "$a" >>'%(log)s'
  case $a in @*) /bin/ls -l "${a#@}" >>'%(log)s.mode' 2>&1 ;; esac
done
exec /usr/bin/curl "$@"
"""


def t_argv(s):
    """Nothing that would let another local user read or forge an event is on curl's command line."""
    if s.kind != "sh":
        return
    log = s.tmp / "curl-argv.log"
    spy = s.tmp / "curl-spy"
    spy.write_text(CURL_SPY % {"log": log})
    spy.chmod(0o755)
    (s.bin / "curl").unlink()
    os.symlink(spy, s.bin / "curl")
    try:
        s.setup([(LINK_A, {"decision": "allow", "after": 1})])
        extra = {"SIMPLETERM_HOOK_TEST": "1", "SIMPLETERM_HOOK_TEST_IV": V_IV, "SIMPLETERM_HOOK_TEST_NONCE": V_NONCE,
                 "SIMPLETERM_HOOK_TEST_RID": V_RID, "SIMPLETERM_HOOK_TEST_TS": V_TS}
        rc, out, err, el = s.run("claude", perm_input(), extra)
        argv = log.read_text() if log.exists() else ""
        modes = (s.tmp / "curl-argv.log.mode").read_text() if (s.tmp / "curl-argv.log.mode").exists() else ""
        recs = s.records("/v1/ingest")
        s.check("argv: event still delivered", recs and recs[0].get("mac_ok") and (recs[0].get("plain_json") or {}).get("rid") == V_RID, str(recs)[:200])
        s.check("argv: decision still read", "allow" in out, out + err)
        ct = recs[0]["body"]["env"]["ct"] if recs else "-"
        s.check("argv: no ciphertext, secret or body", argv and ct[:40] not in argv and LINK_A["secret"] not in argv
                and '"env"' not in argv, argv[-600:])
        s.check("argv: body from a 600 file", "@" in argv and modes.startswith("-rw-------"), modes + argv[-300:])
        run = s.home / ".simpleterm" / "run"
        left = [p.name for p in run.iterdir() if p.name.endswith(".req")] if run.exists() else []
        s.check("argv: body file removed", not left, str(left))
    finally:
        (s.bin / "curl").unlink()
        os.symlink("/usr/bin/curl", s.bin / "curl")


def t_external_printf(s):
    """OpenBSD sh/ksh and mksh run printf from /usr/bin: secrets would show in `ps`, so no relay."""
    shell = os.path.basename(s.argv[0])
    if s.kind != "sh" or shell not in ("bash", "zsh"):
        return  # only these two can switch the builtin off for the test
    rc_dir = s.tmp / "rc"
    rc_dir.mkdir(exist_ok=True)
    (rc_dir / "bashenv").write_text("enable -n printf\n")
    (rc_dir / ".zshenv").write_text("disable printf\n")
    extra = {"BASH_ENV": str(rc_dir / "bashenv")} if shell == "bash" else {"ZDOTDIR": str(rc_dir)}
    s.setup([(LINK_A, {"decision": "allow", "after": 1})])
    rc, out, err, el = s.run("claude", perm_input(), dict(extra, SIMPLETERM="1"))
    s.check("external printf: nothing sent", not s.records("/v1/ingest"), str(s.records())[:200])
    s.check("external printf: no decision, exit 0", rc == 0 and out.strip() == "", out + err)
    s.check("external printf: logged", "printf is not a shell builtin; relay disabled" in s.log_text(), s.log_text())
    stop = json.dumps({"session_id": "s", "hook_event_name": "Stop", "cwd": "/x", "last_assistant_message": "ok"})
    rc, out, err, el = s.run("claude", stop, dict(extra, SIMPLETERM="1"))
    s.check("external printf: terminal sequence still works", "simpleterm:state=done" in out, out + err)
    time.sleep(1)
    s.check("external printf: no background send either", not s.records("/v1/ingest"))


# --- usage fixtures (keys and numbers only; no real conversation) -------------

def claude_line(model="claude-opus-5-5", inp=10, cc=0, cr=5000, e5=100, e1=200, side=False, decoy=True):
    text = 'decoy \\"usage\\":{\\"input_tokens\\":999999} \\"type\\":\\"assistant\\"' if decoy else "x"
    return json.dumps({
        "parentUuid": "p", "isSidechain": side,
        "message": {"model": model, "id": "m", "type": "message", "role": "assistant",
                    "content": [{"type": "text", "text": json.loads('"%s"' % text)}],
                    "usage": {"input_tokens": inp, "cache_creation_input_tokens": cc, "cache_read_input_tokens": cr,
                              "cache_creation": {"ephemeral_5m_input_tokens": e5, "ephemeral_1h_input_tokens": e1},
                              "output_tokens": 50, "iterations": [{"input_tokens": 77}]}},
        "requestId": "r", "type": "assistant", "uuid": "a", "timestamp": "t", "sessionId": "s",
    }, separators=(",", ":"))


def claude_user_line(size=40):
    return json.dumps({"parentUuid": "p", "isSidechain": False, "type": "user",
                       "message": {"role": "user", "content": "u" * size}, "uuid": "u"}, separators=(",", ":"))


COMPACT_LINE = json.dumps({"parentUuid": None, "isSidechain": False, "type": "system", "subtype": "compact_boundary",
                           "content": "Conversation compacted", "compactMetadata": {"trigger": "auto", "preTokens": 180000,
                                                                                     "postTokens": 42000}}, separators=(",", ":"))


def codex_token_line(total=15159, window=258400, rl=True, reached=None):
    rate = None
    if rl:
        rate = {"limit_id": "codex", "limit_name": None,
                "primary": {"used_percent": 4.0, "window_minutes": 300, "resets_at": 1795746291},
                "secondary": {"used_percent": 12.5, "window_minutes": 10080, "resets_at": 1796000000},
                "credits": None, "plan_type": "plus", "rate_limit_reached_type": reached}
    info = None if total is None else {"total_token_usage": {"total_tokens": 99999},
                                       "last_token_usage": {"input_tokens": total - 159, "cached_input_tokens": 0,
                                                            "output_tokens": 159, "total_tokens": total},
                                       "model_context_window": window}
    return json.dumps({"timestamp": "t", "ordinal": 1, "type": "event_msg",
                       "payload": {"type": "token_count", "info": info, "rate_limits": rate}}, separators=(",", ":"))


GEMINI_JSONL = "\n".join([
    json.dumps({"id": "1", "timestamp": "t", "type": "user", "content": [{"text": "q"}]}, separators=(",", ":")),
    json.dumps({"id": "2", "timestamp": "t", "type": "gemini", "content": "a", "thoughts": [],
                "tokens": {"input": 33435, "output": 185, "cached": 0, "thoughts": 0, "tool": 0, "total": 33620},
                "model": "gemini-3.1-pro-preview"}, separators=(",", ":")),
]) + "\n"

GEMINI_PRETTY = json.dumps({"sessionId": "s", "messages": [
    {"id": "1", "type": "user", "content": "q"},
    {"id": "2", "type": "gemini", "content": "a", "thoughts": [],
     "tokens": {"input": 7682, "output": 56, "cached": 3287, "thoughts": 163, "tool": 0, "total": 7901},
     "model": "gemini-3.1-pro-preview"}]}, indent=2) + "\n"

STATUSLINE = {
    "session_id": "u-claude", "transcript_path": "/x/t.jsonl", "model": {"id": "claude-opus-5-5", "display_name": "Opus"},
    "context_window": {"total_input_tokens": 15500, "total_output_tokens": 1200, "context_window_size": 200000,
                       "used_percentage": 8, "current_usage": {"input_tokens": 8500, "output_tokens": 1200,
                                                               "cache_creation_input_tokens": 5000,
                                                               "cache_read_input_tokens": 2000}},
    "rate_limits": {"five_hour": {"used_percentage": 23.5, "resets_at": 4102444800},
                    "seven_day": {"used_percentage": 41.2, "resets_at": 4102444800},
                    "spend_limit": {"used_percentage": 3, "resets_at": 1000}},
}


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def ingests(s, ev=None, ctl=None):
    recs = [r for r in (ctl("/_ctl/records")["records"] if ctl else s.records()) if r["path"] == "/v1/ingest"]
    return [r for r in recs if ev is None or (r.get("body") or {}).get("ev") == ev]


def seqs(out):
    j = decision_json(out) or {}
    return j.get("terminalSequence", "")


USAGE_OSC_CLAUDE = "\x1b]9;simpleterm:usage v=1 agent=claude-code ctx=5310 win=1000000 src=transcript est=1\x07"


def t_usage_claude(s):
    """Context from the transcript: OSC 9 on the terminal, `usage` to the tunnel (#342)."""
    s.setup([(LINK_A, {"push": "disabled", "kind": "tunnel"})])
    tr = write(s.tmp / "claude" / "t1.jsonl", "\n".join([
        claude_user_line(), claude_line(inp=1, cr=1, model="claude-opus-5-5"), claude_line(),
        claude_line(model="claude-opus-5-5", inp=3, side=True), claude_line(model="<synthetic>", inp=0, cr=0, e5=0, e1=0),
        claude_user_line()]) + "\n")
    stop = {"session_id": "u-claude", "transcript_path": str(tr), "cwd": "/w/app", "hook_event_name": "Stop",
            "last_assistant_message": "Done."}
    rc, out, err, el = s.run("claude", json.dumps(stop), {"SIMPLETERM": "1"})
    s.check("usage claude: done + usage sequences in one terminalSequence",
            seqs(out) == "\x1b]9;simpleterm:state=done\x07" + USAGE_OSC_CLAUDE, repr(out))
    rec = wait_for(lambda: ingests(s, "usage"), 20)
    p = rec[0].get("plain_json", {}) if rec else {}
    s.check("usage claude: usage event to the tunnel",
            p.get("ctx") == {"used": 5310, "win": 1000000, "src": "transcript", "est": True} and p.get("lims") == []
            and p.get("app") == "claude-code" and p.get("cwd") == "app" and "msg" not in p, str(p))
    s.check("usage claude: plaintext field order", rec and rec[0]["plain"].startswith(
        '{"v":1,"rid":"%s","ev":"usage","app":"claude-code","host":"dev-box","cwd":"app","ctx":{' % p.get("rid")),
        rec[0]["plain"] if rec else "")
    s.check("usage claude: own rid", rec and len({r["body"]["rid"] for r in ingests(s)}) == 2, str(ingests(s))[:300])
    # Unchanged: nothing more (no sequence, no event).
    s.ctl("/_ctl/reset", {})
    rc, out, err, el = s.run("claude", json.dumps(stop), {"SIMPLETERM": "1"})
    time.sleep(1.5)
    s.check("usage claude: unchanged usage is not repeated",
            seqs(out) == "\x1b]9;simpleterm:state=done\x07" and not ingests(s, "usage"), repr(out))
    # A compaction after the last response: its postTokens.
    with open(tr, "a") as f:
        f.write(COMPACT_LINE + "\n")
    s.ctl("/_ctl/reset", {})
    rc, out, err, el = s.run("claude", json.dumps(dict(stop, hook_event_name="PostCompact", trigger="auto")), {"SIMPLETERM": "1"})
    s.check("usage claude: PostCompact uses postTokens",
            seqs(out) == "\x1b]9;simpleterm:usage v=1 agent=claude-code ctx=42000 win=1000000 src=transcript est=1\x07", repr(out))
    # SessionStart (resume) and PostModelSwitch report context_tokens themselves.
    rc, out, err, el = s.run("claude", json.dumps({"session_id": "u-claude", "hook_event_name": "PostModelSwitch",
                                                   "transcript_path": str(tr), "to_model": "claude-sonnet-4-6",
                                                   "context_tokens": 51000, "source": "command"}), {"SIMPLETERM": "1"})
    s.check("usage claude: PostModelSwitch context_tokens + new model window",
            seqs(out) == "\x1b]9;simpleterm:usage v=1 agent=claude-code ctx=51000 win=200000 src=hook est=1\x07", repr(out))
    rc, out, err, el = s.run("claude", json.dumps({"session_id": "u-claude", "hook_event_name": "PostModelSwitch",
                                                   "to_model": "claude-sonnet-4-6", "context_tokens": 52000}),
                             {"SIMPLETERM": "1", "CLAUDE_CODE_MAX_CONTEXT_TOKENS": "1000000"})
    s.check("usage claude: CLAUDE_CODE_MAX_CONTEXT_TOKENS is exact",
            seqs(out) == "\x1b]9;simpleterm:usage v=1 agent=claude-code ctx=52000 win=1000000 src=hook\x07", repr(out))
    rc, out, err, el = s.run("claude", json.dumps({"session_id": "u-claude", "hook_event_name": "SessionStart", "source": "resume",
                                                   "model": "claude-opus-4-6[1m]", "context_tokens": 54000}), {"SIMPLETERM": "1"})
    s.check("usage claude: a [1m] model is 1M, exact",
            seqs(out) == "\x1b]9;simpleterm:usage v=1 agent=claude-code ctx=54000 win=1000000 src=hook\x07", repr(out))
    rc, out, err, el = s.run("claude", json.dumps({"session_id": "u-claude", "hook_event_name": "PostModelSwitch",
                                                   "to_model": "claude-opus-5-5", "context_tokens": 53000}),
                             {"SIMPLETERM": "1", "CLAUDE_CODE_DISABLE_1M_CONTEXT": "1"})
    s.check("usage claude: CLAUDE_CODE_DISABLE_1M_CONTEXT=1 is 200K",
            "ctx=53000 win=200000 src=hook\x07" in seqs(out), repr(out))
    # Rate limit reached (StopFailure rate_limit). A session of its own: the cases above set
    # environment variables per hook, which one real session does not.
    s.ctl("/_ctl/reset", {})
    rc, out, err, el = s.run("claude", json.dumps({"session_id": "u-claude-rl", "transcript_path": str(tr), "hook_event_name": "StopFailure",
                                                   "error": "rate_limit", "last_assistant_message": "API Error"}), {"SIMPLETERM": "1"})
    s.check("usage claude: StopFailure rate_limit -> lim=reached",
            seqs(out) == "\x1b]9;simpleterm:state=done\x07\x1b]9;simpleterm:usage v=1 agent=claude-code ctx=42000 win=1000000"
                          " src=transcript est=1 lim=reached\x07", repr(out))
    # Earlier cases' background sends may still land here: pick the event by content.
    rec = wait_for(lambda: [r for r in ingests(s, "usage") if {"id": "reached"} in (r.get("plain_json") or {}).get("lims", [])], 20)
    s.check("usage claude: reached in the event", rec and rec[0]["plain_json"].get("lims") == [{"id": "reached"}]
            and rec[0]["plain_json"]["ctx"].get("used") == 42000, str(ingests(s, "usage"))[:300])
    # No SimpleTerm session: no sequence, the link still gets it.
    s.ctl("/_ctl/reset", {})
    rc, out, err, el = s.run("claude", json.dumps({"session_id": "u-c2", "transcript_path": str(tr), "hook_event_name": "Stop",
                                                   "last_assistant_message": "ok"}))
    s.check("usage claude: no output without SIMPLETERM", out == "", out)
    s.check("usage claude: the tunnel gets it without SIMPLETERM", wait_for(lambda: ingests(s, "usage"), 20))
    # usage=0 turns it off.
    s.setup([(LINK_A, {"push": "disabled", "kind": "tunnel"})], conf={"usage": 0})
    rc, out, err, el = s.run("claude", json.dumps(dict(stop, session_id="u-off")), {"SIMPLETERM": "1"})
    time.sleep(1.5)
    s.check("usage claude: usage=0 sends nothing", seqs(out) == "\x1b]9;simpleterm:state=done\x07" and not ingests(s, "usage"), out)


def t_usage_window(s):
    """A session keeps the window it showed; a guess below the context in use becomes 1M (#342)."""
    s.setup([(LINK_A, {"push": "disabled", "kind": "tunnel"})])
    big = write(s.tmp / "claude" / "w46.jsonl", claude_line(model="claude-sonnet-4-6", inp=10, cr=300000, e5=0, e1=0) + "\n")
    small = write(s.tmp / "claude" / "w46s.jsonl", claude_line(model="claude-sonnet-4-6", inp=10, cr=100000, e5=0, e1=0) + "\n")
    compacted = write(s.tmp / "claude" / "w46c.jsonl", big.read_text() + COMPACT_LINE + "\n")

    def osc(sid, event, path=None, env=None, **kw):
        j = dict({"session_id": sid, "hook_event_name": event}, **kw)
        if path:
            j["transcript_path"] = str(path)
        rc, out, err, el = s.run("claude", json.dumps(j), dict({"SIMPLETERM": "1"}, **(env or {})))
        q = seqs(out)
        return q[q.find("simpleterm:usage"):].rstrip("\x07")

    U = "simpleterm:usage v=1 agent=claude-code "
    # A [1m] session: SessionStart names the model, the transcript does not.
    got = osc("w1", "SessionStart", source="resume", model="claude-sonnet-4-6[1m]", context_tokens=54000)
    s.check("usage window: SessionStart [1m] is 1M, exact", got == U + "ctx=54000 win=1000000 src=hook", got)
    got = osc("w1", "Stop", big, last_assistant_message="ok")
    s.check("usage window: the same session keeps 1M past 200K", got == U + "ctx=300010 win=1000000 src=transcript", got)
    got = osc("w1", "PostCompact", compacted)
    s.check("usage window: and below 200K again (no flip to 200K)", got == U + "ctx=42000 win=1000000 src=transcript", got)
    # No SessionStart seen: a guess of 200K under 300K of context is wrong.
    got = osc("w2", "Stop", big, last_assistant_message="ok")
    s.check("usage window: a guess below the context becomes 1M", got == U + "ctx=300010 win=1000000 src=transcript est=1", got)
    got = osc("w2", "PostCompact", compacted)
    s.check("usage window: the corrected guess stays", got == U + "ctx=42000 win=1000000 src=transcript est=1", got)
    # A model switch starts over.
    got = osc("w1", "PostModelSwitch", to_model="claude-sonnet-4-6", context_tokens=51000)
    s.check("usage window: PostModelSwitch drops what the session knew", got == U + "ctx=51000 win=200000 src=hook est=1", got)
    got = osc("w1", "Stop", small, last_assistant_message="ok")
    s.check("usage window: no old 1M after the switch", got == U + "ctx=100010 win=200000 src=transcript est=1", got)
    # A status line saved before a switch shows the old model's window.
    sl = s.home / ".simpleterm" / "run" / "usage.w3.json"
    sl.write_text("%d\n" % (time.time() - 5) + json.dumps(dict(STATUSLINE, session_id="w3",
                                                                 context_window=dict(STATUSLINE["context_window"], context_window_size=1000000))) + "\n")
    got = osc("w3", "Stop", small, last_assistant_message="ok")
    s.check("usage window: the status line's window is exact", got.startswith(U + "ctx=100010 win=1000000 src=transcript lim="), got)
    got = osc("w3", "PostModelSwitch", to_model="claude-sonnet-4-6", context_tokens=51000)
    s.check("usage window: not the status line saved before the switch", got.startswith(U + "ctx=51000 win=200000 src=hook est=1 lim="), got)
    # CLAUDE_CODE_MAX_CONTEXT_TOKENS with a leading zero is still a JSON number.
    s.ctl("/_ctl/reset", {})
    got = osc("w4", "PostModelSwitch", env={"CLAUDE_CODE_MAX_CONTEXT_TOKENS": "0200000"}, to_model="claude-opus-5-5", context_tokens=52000)
    rec = wait_for(lambda: ingests(s, "usage"), 20)
    p = rec[0].get("plain_json") if rec else None
    s.check("usage window: a leading zero in CLAUDE_CODE_MAX_CONTEXT_TOKENS is dropped",
            got == U + "ctx=52000 win=200000 src=hook" and isinstance(p, dict) and p["ctx"].get("win") == 200000,
            "%s %s" % (got, rec[0].get("plain") if rec else None))


def t_usage_claude_big(s):
    """Only the transcript's end is read; the record can be up to 2 MiB from the end."""
    s.setup([], conf={})
    near = write(s.tmp / "claude" / "near.jsonl", claude_user_line(3 << 20) + "\n" + claude_line(inp=7) + "\n" + claude_user_line() + "\n")
    far = write(s.tmp / "claude" / "far.jsonl", claude_line(inp=8) + "\n" + claude_user_line(1 << 20) + "\n")
    gone = write(s.tmp / "claude" / "gone.jsonl", claude_line(inp=9) + "\n" + claude_user_line(3 << 20) + "\n")
    for name, path, want in (("near", near, "ctx=5307 "), ("1 MiB back", far, "ctx=5308 "), ("beyond 2 MiB", gone, None)):
        rc, out, err, el = s.run("claude", json.dumps({"session_id": "big-" + name.split()[0], "transcript_path": str(path),
                                                       "hook_event_name": "PostCompact"}), {"SIMPLETERM": "1"})
        if want:
            s.check("usage big: %s" % name, want in seqs(out), repr(out)[:200])
        else:
            s.check("usage big: %s gives nothing" % name, out == "", repr(out)[:200])
        s.check("usage big: %s quick" % name, el < 3, "%.2fs" % el)


def big_tool_line(kib, model="claude-opus-5-5", side=False, inp=10, decoy=False):
    """An assistant line of about `kib` KiB: a tool input dense with escapes (an Edit of code),
    in message.content and again in wireToolInputs, as Claude Code 2.1.312 writes it."""
    unit = 'x = "a\\\\b";\n'
    tool = {"file_path": "/w/a.py", "old_string": "x", "new_string": ""}
    if decoy:  # a tool input with a "usage" key of its own, before and after the real one
        tool["usage"] = {"input_tokens": 999999, "output_tokens": 1}

    def line(text):
        t = dict(tool, new_string=text)
        return json.dumps({
            "parentUuid": "p", "isSidechain": side,
            "message": {"model": model, "id": "m", "type": "message", "role": "assistant",
                        "content": [{"type": "tool_use", "id": "t1", "name": "Edit", "input": t}],
                        "stop_reason": "tool_use", "stop_sequence": None,
                        "usage": {"input_tokens": inp, "cache_creation_input_tokens": 0, "cache_read_input_tokens": 5000,
                                  "cache_creation": {"ephemeral_5m_input_tokens": 100, "ephemeral_1h_input_tokens": 200},
                                  "output_tokens": 50, "iterations": [{"input_tokens": 77, "output_tokens": 1}]}},
            "wireToolInputs": {"t1": t}, "requestId": "r", "type": "assistant", "uuid": "a", "timestamp": "t",
        }, separators=(",", ":"))
    per = 2 * (len(json.dumps(unit)) - 2)
    return line(unit * max(0, (kib * 1024 - len(line(""))) // per + 1))


def t_usage_claude_huge(s):
    """A very long transcript line (a large Edit) is read in linear time, with the same result (#342)."""
    s.setup([], conf={})

    def ctx_of(name, lines):
        tr = write(s.tmp / "claude" / ("huge-%s.jsonl" % name), "\n".join([claude_user_line()] + lines) + "\n")
        rc, out, err, el = s.run("claude", json.dumps({"session_id": "huge-" + name, "transcript_path": str(tr),
                                                       "hook_event_name": "PostCompact"}), {"SIMPLETERM": "1"})
        q = seqs(out)
        return q[q.find("ctx="):q.find(" src=")], el

    got, el = ctx_of("1m", [big_tool_line(1024)])
    s.check("usage huge: a 1 MiB line is read quickly", got == "ctx=5310 win=1000000" and el < 5, "%r %.2fs" % (got, el))
    got, el = ctx_of("side", [big_tool_line(100, inp=20), big_tool_line(100, inp=3, side=True),
                              big_tool_line(100, model="<synthetic>", inp=0)])
    s.check("usage huge: sidechain and synthetic lines are skipped", got == "ctx=5320 win=1000000", got)
    got, el = ctx_of("decoy", [big_tool_line(100, decoy=True)])
    s.check("usage huge: a tool input's own \"usage\" key is not the response's", got == "ctx=5310 win=1000000", got)
    got, el = ctx_of("compact", [big_tool_line(100), COMPACT_LINE])
    s.check("usage huge: a compaction after it gives postTokens", got == "ctx=42000 win=1000000", got)


def t_usage_statusline(s):
    """The optional status line tap adds the window size and the 5-hour/7-day limits."""
    s.setup([(LINK_A, {"push": "disabled", "kind": "tunnel"})])
    tap = SCRIPTS / "statusline-tap.sh"
    p = subprocess.run([s.argv[0], str(tap), "cat"], input=json.dumps(STATUSLINE).encode(), capture_output=True,
                       env=s.env(), timeout=20)
    s.check("statusline: passes the input to the user's command", p.stdout.decode() == json.dumps(STATUSLINE), p.stdout[:200])
    saved = s.home / ".simpleterm" / "run" / "usage.u-claude.json"
    s.check("statusline: saved for the hooks", saved.exists() and saved.read_text().split("\n", 1)[1].strip() == json.dumps(STATUSLINE))
    # Claude Code runs a status line command with /bin/sh -c (spawn shell: true), not $SHELL or
    # the first sh on PATH: the user's command must see the same interpreter behind the tap.
    p = subprocess.run([s.argv[0], str(tap), 'echo "$0"'], input=b"{}", capture_output=True,
                       env=s.env({"SHELL": "/bin/zsh"}), timeout=20)
    s.check("statusline: the user's command runs with /bin/sh, as in Claude Code", p.stdout == b"/bin/sh\n", p.stdout)
    p = subprocess.run([s.argv[0], str(tap)], input=b"{}", capture_output=True, env=s.env(), timeout=20)
    s.check("statusline: no command and no data prints nothing", p.stdout == b"" and p.returncode == 0, p.stdout)
    p = subprocess.run([s.argv[0], str(tap)], input=json.dumps(STATUSLINE).encode(), capture_output=True, env=s.env(), timeout=20)
    s.check("statusline: no command prints a short line of its own",
            p.stdout.decode() == "Opus · context 8% · 5h 23% · 7d 41%\n", p.stdout)
    tr = write(s.tmp / "claude" / "sl.jsonl", claude_line() + "\n")
    rc, out, err, el = s.run("claude", json.dumps({"session_id": "u-claude", "transcript_path": str(tr), "hook_event_name": "Stop",
                                                   "last_assistant_message": "ok"}), {"SIMPLETERM": "1"})
    s.check("statusline: exact window and limits (expired window dropped)",
            seqs(out).endswith("\x1b]9;simpleterm:usage v=1 agent=claude-code ctx=5310 win=200000 src=transcript"
                               " lim=five_hour:23.5:300:4102444800 lim=seven_day:41.2:10080:4102444800\x07"), repr(out))
    rec = wait_for(lambda: ingests(s, "usage"), 20)
    s.check("statusline: limits in the event", rec and rec[0]["plain_json"].get("lims") == [
        {"id": "five_hour", "pct": 23.5, "win_min": 300, "resets_at": 4102444800},
        {"id": "seven_day", "pct": 41.2, "win_min": 10080, "resets_at": 4102444800}], str(rec[0].get("plain_json") if rec else None))
    old = "1000\n" + json.dumps(STATUSLINE) + "\n"
    saved.write_text(old)
    rc, out, err, el = s.run("claude", json.dumps({"session_id": "u-claude", "transcript_path": str(tr), "hook_event_name": "PostCompact"}),
                             {"SIMPLETERM": "1"})
    # A stale file gives no limits; the window it showed for this session (same model) stays.
    s.check("statusline: stale file: no limits, the window it showed stays",
            seqs(out) == "\x1b]9;simpleterm:usage v=1 agent=claude-code ctx=5310 win=200000 src=transcript\x07", repr(out))
    rc, out, err, el = s.run("claude", json.dumps({"session_id": "u-claude-2", "transcript_path": str(tr), "hook_event_name": "PostCompact"}),
                             {"SIMPLETERM": "1"})
    s.check("statusline: another session's file is not used", "lim=" not in seqs(out) and "est=1" in seqs(out), repr(out))


def t_usage_relay_policy(s):
    """Usage goes to tunnel links only (the relay does not push it); PostToolUse looks every 20 s."""
    tun, tctl = s.spawn_mock()
    try:
        s.setup([(LINK_A, {"push": "disabled"}), (LINK_T, {"kind": "tunnel", "relay_url": tctl.url})])
        tctl("/_ctl/config", {"links": {LINK_T["id"]: dict(LINK_T)}})
        tr = write(s.tmp / "claude" / "pol.jsonl", claude_line() + "\n")
        base = {"session_id": "pol", "transcript_path": str(tr), "cwd": "/w/x"}
        s.run("claude", json.dumps(dict(base, hook_event_name="PostToolUse", tool_name="Bash", tool_input={"command": "ls"})))
        s.check("usage policy: mid-turn update reaches the tunnel", wait_for(lambda: ingests(s, "usage", tctl), 20))
        with open(tr, "a") as f:
            f.write(claude_line(inp=20) + "\n")
        s.run("claude", json.dumps(dict(base, hook_event_name="PostToolUse", tool_name="Bash", tool_input={"command": "ls"})))
        time.sleep(1.5)
        s.check("usage policy: PostToolUse at most every 20 s", len(ingests(s, "usage", tctl)) == 1, str(len(ingests(s, "usage", tctl))))
        s.run("claude", json.dumps(dict(base, hook_event_name="Stop", last_assistant_message="ok")))
        s.check("usage policy: turn end reaches the tunnel (changed)", wait_for(lambda: len(ingests(s, "usage", tctl)) == 2, 20))
        got = (ingests(s, "usage", tctl)[-1].get("plain_json") or {}).get("ctx", {}) if ingests(s, "usage", tctl) else {}
        s.check("usage policy: the turn's last value", got.get("used") == 5320, str(got))
        s.check("usage policy: the relay gets done", wait_for(lambda: ingests(s, "done"), 20))
        time.sleep(1)
        s.check("usage policy: the relay gets no usage at all", not ingests(s, "usage"), str(ingests(s, "usage"))[:200])
    finally:
        tun.terminate()
        tun.wait(5)


def relink(s, link, url):
    """Points an existing link file at another address (the app reconnected on a new port)."""
    f = s.home / ".simpleterm" / "links" / (link["id"] + ".conf")
    f.write_text("".join("relay=%s\n" % url if l.startswith("relay=") else l for l in f.read_text().splitlines(True)))


def t_usage_delivery(s):
    """A usage report counts as sent only once SimpleTerm got it: unchanged values go again until then."""
    probe = __import__("socket").socket()
    probe.bind(("127.0.0.1", 0))
    closed = probe.getsockname()[1]
    probe.close()
    ro = write(s.tmp / "codex" / "rollout-dl.jsonl", codex_token_line(total=15159) + "\n")
    stop = json.dumps({"session_id": "dl", "turn_id": "t", "transcript_path": str(ro), "cwd": "/w/repo", "hook_event_name": "Stop",
                       "last_assistant_message": "Done."})
    s.setup([(LINK_T, {"kind": "tunnel", "relay_url": "http://127.0.0.1:%d" % closed})])
    s.run("codex", stop)
    wait_for(lambda: "ingest ev=usage" in s.log_text(), 10)
    tun, tctl = s.spawn_mock()
    try:
        tctl("/_ctl/config", {"links": {LINK_T["id"]: dict(LINK_T)}})
        relink(s, LINK_T, tctl.url)
        s.run("codex", stop)
        s.check("usage delivery: unchanged usage goes again once the tunnel is back",
                wait_for(lambda: ingests(s, "usage", tctl), 20), s.log_text()[-300:])
        n = len(ingests(s, "usage", tctl))
        s.run("codex", stop)
        time.sleep(1.5)
        s.check("usage delivery: and not again after it got there", len(ingests(s, "usage", tctl)) == n,
                str(len(ingests(s, "usage", tctl))))
    finally:
        tun.terminate()
        tun.wait(5)
    # Claude Code outside SimpleTerm with only a relay link: nothing shows it, so a later
    # SimpleTerm session still gets the same value on its terminal.
    s.setup([(LINK_A, {"push": "disabled"})])
    tr = write(s.tmp / "claude" / "dl.jsonl", claude_line() + "\n")
    stop = json.dumps({"session_id": "dl-c", "transcript_path": str(tr), "hook_event_name": "Stop", "last_assistant_message": "ok"})
    s.run("claude", stop)
    rc, out, err, el = s.run("claude", stop, {"SIMPLETERM": "1"})
    s.check("usage delivery: shown on the terminal although unchanged since a run outside SimpleTerm",
            USAGE_OSC_CLAUDE in seqs(out), repr(out))


def t_usage_codex(s):
    s.setup([(LINK_A, {"push": "disabled", "kind": "tunnel"})])
    ro = write(s.tmp / "codex" / "rollout.jsonl", "\n".join([
        codex_token_line(total=9000), codex_token_line(total=15159), codex_token_line(total=None, rl=False)]) + "\n")
    inp = {"session_id": "cx", "turn_id": "t", "transcript_path": str(ro), "cwd": "/w/repo", "hook_event_name": "Stop",
           "model": "gpt-5.5", "permission_mode": "default", "stop_hook_active": False, "last_assistant_message": "Done."}
    rc, out, err, el = s.run("codex", json.dumps(inp), {"SIMPLETERM": "1"})
    s.check("usage codex: nothing on stdout (schema)", out == "", out)
    rec = wait_for(lambda: ingests(s, "usage"), 20)
    p = rec[0].get("plain_json", {}) if rec else {}
    s.check("usage codex: rollout context, window, baseline",
            p.get("ctx") == {"used": 15159, "win": 258400, "baseline": 12000, "src": "rollout"} and p.get("app") == "codex", str(p))
    s.check("usage codex: limits and plan", p.get("lims") == [
        {"id": "codex.primary", "pct": 4.0, "win_min": 300, "resets_at": 1795746291},
        {"id": "codex.secondary", "pct": 12.5, "win_min": 10080, "resets_at": 1796000000}] and p.get("plan") == "plus", str(p))
    s.check("usage codex: done still sent", wait_for(lambda: ingests(s, "done"), 20))
    tun, tctl = s.spawn_mock()
    try:
        s.setup([(LINK_A, {"push": "disabled"}), (LINK_T, {"kind": "tunnel", "relay_url": tctl.url})])
        tctl("/_ctl/config", {"links": {LINK_T["id"]: dict(LINK_T)}})
        write(ro, codex_token_line(total=16000, reached="primary") + "\n")
        s.run("codex", json.dumps(dict(inp, hook_event_name="SessionStart", source="resume")))
        rec = wait_for(lambda: ingests(s, "usage", tctl), 20)
        p = rec[0].get("plain_json", {}) if rec else {}
        s.check("usage codex: SessionStart to the tunnel, reached",
                p.get("ctx", {}).get("used") == 16000 and {"id": "reached"} in p.get("lims", []), str(p))
        s.check("usage codex: SessionStart not to the relay", not ingests(s, "usage"))
    finally:
        tun.terminate()
        tun.wait(5)
    s.ctl("/_ctl/reset", {})
    s.run("codex", json.dumps(dict(inp, transcript_path=None, session_id="cx2")))
    wait_for(lambda: ingests(s, "done"), 20)
    time.sleep(1.5)
    s.check("usage codex: null transcript_path -> no usage", not ingests(s, "usage") and ingests(s, "done"))


CODEX_HOOKS = ROOT / "plugins" / "simpleterm" / "hooks" / "codex-hooks.json"


def t_codex_hooks(s):
    """Codex 0.165 adds a SessionStart hook's plain standard output to the session as developer
    context: the plugin's runs only for resumed or forked sessions and its commands print nothing."""
    import re
    hooks = json.loads(CODEX_HOOKS.read_text())["hooks"]
    m = hooks["SessionStart"][0].get("matcher") or ""
    runs = {src: bool(m) and re.search(m, src) is not None for src in ("startup", "resume", "clear", "compact", "fork")}
    s.check("codex hooks: SessionStart only for resumed and forked sessions",
            runs == {"startup": False, "resume": True, "clear": False, "compact": False, "fork": True}, str(runs))
    # Codex runs `$SHELL -c '<command>'` with ${PLUGIN_ROOT} replaced (the shell under test here).
    noisy = s.tmp / "noisy-plugin"
    write(noisy / "scripts" / "agent-hook.sh", "echo noise\n")
    for ev in ("SessionStart", "PostCompact", "Stop"):
        cmd = hooks[ev][0]["hooks"][0]["command"].replace("${PLUGIN_ROOT}", str(noisy))
        p = subprocess.run([s.argv[0], "-c", cmd], input=b"{}", capture_output=True, env=s.env(), timeout=20)
        s.check("codex hooks: %s command prints nothing, whatever the script writes" % ev,
                p.returncode == 0 and p.stdout == b"", p.stdout)
    s.setup([(LINK_A, {"push": "disabled", "kind": "tunnel"})])
    ro = write(s.tmp / "codex" / "rollout-ss.jsonl", codex_token_line(total=15159) + "\n")
    cmd = hooks["SessionStart"][0]["hooks"][0]["command"].replace("${PLUGIN_ROOT}", str(SCRIPTS.parent))
    inp = json.dumps({"session_id": "cx-ss", "transcript_path": str(ro), "cwd": "/w/repo", "hook_event_name": "SessionStart",
                      "source": "resume", "model": "gpt-5.5"})
    p = subprocess.run([s.argv[0], "-c", cmd], input=inp.encode(), capture_output=True, env=s.env({"SIMPLETERM": "1"}), timeout=30)
    rec = wait_for(lambda: ingests(s, "usage"), 20)
    s.check("codex hooks: SessionStart through its command still reports usage",
            p.stdout == b"" and rec and rec[0]["plain_json"]["ctx"].get("used") == 15159, "%r %s" % (p.stdout, str(rec)[:200]))


def t_gemini(s):
    # Gemini CLI waits for the Notification hook before it shows its prompt: the hook must not
    # wait for the network. The link answers after 4 s, so a send in the foreground shows.
    s.setup([(LINK_A, {"push": "disabled", "kind": "tunnel", "ingest_delay": 4})])
    tr = write(s.tmp / "gemini" / "chats" / "session-1.jsonl", GEMINI_JSONL)
    base = {"session_id": "gm", "transcript_path": str(tr), "cwd": "/w/site", "timestamp": "2026-10-29T00:00:00Z"}
    note = dict(base, hook_event_name="Notification", notification_type="ToolPermission",
                message="Tool Confirm Shell Command requires execution",
                details={"type": "exec", "title": "Confirm Shell Command", "command": "rm -rf build", "rootCommand": "rm"})
    rc, out, err, el = s.run("gemini", json.dumps(note), {"SIMPLETERM": "1"})
    s.check("gemini: Notification prints nothing", out == "", out)
    s.check("gemini: Notification returns at once", el < 2, "%.2fs" % el)
    rec = wait_for(lambda: ingests(s), 20)
    p = rec[0].get("plain_json", {}) if rec else {}
    s.check("gemini: ToolPermission -> question (alert only)",
            rec and rec[0]["body"]["ev"] == "question" and p.get("app") == "gemini-cli" and p.get("msg") == "approve rm: rm -rf build"
            and "nonce" not in p and not s.records("/v1/decision"), str(p))
    s.setup([(LINK_A, {"push": "disabled", "kind": "tunnel"})])
    edit = dict(note, details={"type": "edit", "title": "Confirm Edit", "fileName": "a.txt", "filePath": "/w/site/a.txt",
                               "fileDiff": "@@", "originalContent": "x" * 5000, "newContent": "y"})
    s.run("gemini", json.dumps(edit))
    rec = wait_for(lambda: ingests(s), 20)
    s.check("gemini: edit permission names the file", rec and rec[0]["plain_json"].get("msg") == "approve edit: /w/site/a.txt",
            str(rec[0].get("plain_json") if rec else None))
    s.ctl("/_ctl/reset", {})
    after = dict(base, hook_event_name="AfterAgent", prompt="p", prompt_response="All green.", stop_hook_active=False)
    rc, out, err, el = s.run("gemini", json.dumps(after), {"SIMPLETERM": "1"})
    s.check("gemini: AfterAgent prints nothing (no block)", out == "", out)
    rec = wait_for(lambda: ingests(s, "done"), 20)
    s.check("gemini: AfterAgent -> done", rec and rec[0]["plain_json"].get("msg") == "All green.", str(rec)[:200])
    rec = wait_for(lambda: ingests(s, "usage"), 20)
    s.check("gemini: usage from the chat record", rec and rec[0]["plain_json"].get("ctx") == {"used": 33435, "win": 1048576, "src": "transcript"},
            str(rec[0].get("plain_json") if rec else None))
    s.ctl("/_ctl/reset", {})
    old = write(s.tmp / "gemini" / "chats" / "session-old.json", GEMINI_PRETTY)
    s.run("gemini", json.dumps(dict(after, session_id="gm-old", transcript_path=str(old))))
    rec = wait_for(lambda: ingests(s, "usage"), 20)
    s.check("gemini: older pretty JSON record", rec and rec[0]["plain_json"].get("ctx", {}).get("used") == 7682,
            str(rec[0].get("plain_json") if rec else None))
    s.ctl("/_ctl/reset", {})
    s.run("gemini", json.dumps(dict(base, hook_event_name="BeforeAgent", prompt="p")))
    s.run("gemini", json.dumps(dict(note, notification_type="Other")))
    time.sleep(1.5)
    s.check("gemini: other events send nothing", not ingests(s))

    # Gemini CLI registers no event that would come within moments to cancel a wait: no wait by default.
    s.setup([(LINK_A, {"push": "disabled", "kind": "tunnel"})], conf={"done_delay": None})
    t0 = time.time()
    s.run("gemini", json.dumps(dict(after, session_id="gm-fast", stop_hook_active=True)))
    s.run("gemini", json.dumps(dict(note, session_id="gm-fast", notification_type="Other")))  # would cancel a pending done
    rec = wait_for(lambda: ingests(s, "done"), 20)
    s.check("gemini: done_delay defaults to 0 (nothing could cancel it), stop_hook_active passed on",
            rec and rec[0]["plain_json"].get("stop_hook_active") is True,
            str([(round(r["received"] - t0, 2), r["plain_json"]) for r in rec]))


def notify_pty(s, args, extra=None):
    """Runs `simpleterm-notify.sh` on a terminal; returns (exit code, terminal output)."""
    env = s.env(extra)
    pid, fd = pty.fork()
    if pid == 0:
        try:
            os.chdir(str(s.tmp))
            os.execve(s.argv[0], [s.argv[0], str(SCRIPTS / "simpleterm-notify.sh")] + list(args), env)
        finally:
            os._exit(127)
    out = b""
    end = time.time() + 15
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.2)
        if r:
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                break
            if not chunk:
                break
            out += chunk
        else:
            done, status = os.waitpid(pid, os.WNOHANG)
            if done:
                break
    try:
        _, status = os.waitpid(pid, 0)
    except ChildProcessError:
        status = 0
    os.close(fd)
    return os.waitstatus_to_exitcode(status), out


def t_notify_no_tty(s):
    """`simpleterm notify` with SIMPLETERM=1 and no controlling terminal still sends its event (the probe of
    /dev/tty used a special builtin: dash ended the whole script when it could not open it)."""
    s.setup([(LINK_A, {"push": "disabled"})])
    p = subprocess.run([s.argv[0], str(SCRIPTS / "simpleterm-notify.sh"), "notify", "no tty title", "body"], capture_output=True,
                       env=s.env({"SIMPLETERM": "1"}), cwd=str(s.tmp), timeout=30, start_new_session=True, stdin=subprocess.DEVNULL)
    rec = wait_for(lambda: ingests(s, "notify"), 20)
    s.check("notify without a terminal: exit 0 and the event is sent", p.returncode == 0 and rec and rec[0]["plain_json"].get("title") == "no tty title",
            "%s %s %s" % (p.returncode, p.stderr[-200:], str(ingests(s))[:200]))


def t_notify(s):
    """`simpleterm notify`: OSC 777 on a SimpleTerm terminal, `notify` to every link."""
    tun, tctl = s.spawn_mock()
    try:
        s.setup([(LINK_A, {"push": "disabled"}), (LINK_T, {"kind": "tunnel", "relay_url": tctl.url})])
        tctl("/_ctl/config", {"links": {LINK_T["id"]: dict(LINK_T)}})
        rc, tty = notify_pty(s, ["notify", "Build done", "exit 0; 한글 \x1b]0;x\x07"], {"SIMPLETERM": "1"})
        s.check("notify: exit 0", rc == 0, str(rc))
        s.check("notify: OSC 777 on the terminal, control characters removed, `;` as `,`",
                b"\x1b]777;notify;Build done;exit 0, \xed\x95\x9c\xea\xb8\x80 ]0,x\x07" in tty, repr(tty))
        rec = wait_for(lambda: ingests(s, "notify"), 20)
        p = rec[0].get("plain_json", {}) if rec else {}
        s.check("notify: relay event", p.get("app") == "script" and p.get("title") == "Build done"
                and p.get("msg") == "exit 0, 한글 ]0,x" and p.get("host") == "dev-box", str(p))
        s.check("notify: plaintext order", rec and rec[0]["plain"].startswith(
            '{"v":1,"rid":"%s","ev":"notify","app":"script","host":"dev-box","cwd":"%s","title":"Build done","msg":"'
            % (p.get("rid"), s.tmp.name)), rec[0]["plain"] if rec else "")
        s.check("notify: tunnel event", wait_for(lambda: ingests(s, "notify", tctl), 20))
        s.ctl("/_ctl/reset", {})
        # The terminal and the event get the same text (the app tells two copies of one
        # notification from two notifications by it): whitespace runs, line breaks included,
        # become one space; other control characters (C0, DEL, C1: U+009C is ST, U+009B CSI)
        # and invalid UTF-8 go; `;` (OSC 777's field separator) becomes `,`; leading and
        # trailing spaces go; title 64 and body 200 characters (256 and 800 bytes).
        for n, (title, body, want_t, want_b) in enumerate((
                ("Tests\nfinished", "line one\nline  two\r\n\tlast  ", "Tests finished", "line one line two last"),
                ("  pad  ", " a \x01 b ", "pad", "a b"),
                ("T" * 70, "x" * 250, "T" * 64, "x" * 200),
                ('"' * 100, "\\" * 300, '"' * 64, "\\" * 200),
                ("한" * 70, "😀" * 201, "한" * 64, "😀" * 200),
                ("C1", "a\u009cb\u009b2Jc\u0085d\u2028e\u2029f", "C1", "ab2Jc d e f"),
                (b"bad", b"ok \xff\xc3( \xe2\x82 end", "bad", "ok ( end"),
                ("a;b", "c;d; e", "a,b", "c,d, e"))):
            s.ctl("/_ctl/reset", {})
            rc, tty = notify_pty(s, ["notify", title, body], {"SIMPLETERM": "1"})
            i = tty.find(b"\x1b]777;notify;")
            osc = tty[i + 13:tty.find(b"\x07", i)] if i >= 0 else b""
            screen = osc.split(b";", 1) + [b""]
            rec = wait_for(lambda: ingests(s, "notify"), 20)
            ev = rec[0].get("plain_json") or {} if rec else {}
            got = (screen[0].decode("utf-8", "replace"), screen[1].decode("utf-8", "replace"), ev.get("title"), ev.get("msg"))
            s.check("notify: case %d, the same normalized text on the terminal and in the event" % n,
                    got == (want_t, want_b, want_t, want_b), repr(got)[:300])
        s.ctl("/_ctl/reset", {})
        rc, tty = notify_pty(s, ["notify", "   ", "\n\t "], {"SIMPLETERM": "1"})
        time.sleep(1.5)
        s.check("notify: only whitespace sends nothing", rc == 0 and b"\x1b]777" not in tty and not ingests(s, "notify"),
                repr(tty))
        s.ctl("/_ctl/reset", {})
        rc, tty = notify_pty(s, ["notify", "Only title"])
        s.check("notify: no sequence outside SimpleTerm", b"\x1b]777" not in tty, repr(tty))
        s.check("notify: still sent to links", wait_for(lambda: ingests(s, "notify"), 20))
        rc, tty = notify_pty(s, ["notify"])
        s.check("notify: usage error without a title", rc == 2 and b"usage: simpleterm notify" in tty, repr(tty))
        rc, tty = notify_pty(s, ["bogus"])
        s.check("notify: unknown command", rc == 2, str(rc))
        shutil.rmtree(s.home / ".simpleterm" / "links")
        rc, tty = notify_pty(s, ["notify", "x"])
        s.check("notify: nothing to send says so", rc == 0 and b"nothing sent" in tty, repr(tty))
    finally:
        tun.terminate()
        tun.wait(5)


def t_cli_wrapper(s):
    """The hooks keep ~/.simpleterm/bin/simpleterm pointing at the plugin."""
    s.setup([(LINK_A, {"push": "disabled"})])
    w = s.home / ".simpleterm" / "bin" / "simpleterm"
    s.run("claude", json.dumps({"session_id": "w", "hook_event_name": "Stop", "last_assistant_message": "ok"}))
    text = w.read_text() if w.exists() else ""
    s.check("cli: written on Stop", "s='%s'" % (SCRIPTS / "simpleterm-notify.sh") in text and os.access(w, os.X_OK), text)
    s.ctl("/_ctl/reset", {})
    p = subprocess.run([str(w), "notify", "via wrapper"], capture_output=True, env=s.env(), timeout=20)
    s.check("cli: wrapper runs notify", p.returncode == 0 and wait_for(lambda: ingests(s, "notify"), 20), p.stderr)
    w.write_text(text.replace(str(SCRIPTS), "/nonexistent/old-version"))
    p = subprocess.run([str(w), "notify", "x"], capture_output=True, env=s.env(), timeout=20)
    s.check("cli: a moved plugin is reported", p.returncode == 1 and b"is gone" in p.stderr, p.stderr)
    s.run("claude", json.dumps({"session_id": "w", "hook_event_name": "SessionStart", "source": "startup"}))
    s.check("cli: rewritten when its script is gone", str(SCRIPTS) in w.read_text())
    current = w.read_text()
    w.write_text(current.replace("#!/bin/sh\n", "#!/bin/sh\n# mine\n", 1))
    s.run("claude", json.dumps({"session_id": "w", "hook_event_name": "SessionStart", "source": "startup"}))
    s.check("cli: a current one is left alone", "# mine" in w.read_text())
    # After an update the agent may keep the old version's folder for a while: the newer
    # hook re-points the command. A copy of the same or a newer release is left alone.
    ver = hook_version()
    other = write(s.tmp / "plugin-cache" / "other" / "scripts" / "simpleterm-notify.sh", "#!/bin/sh\n")

    def wrapper(version, rev=None):
        text = current.replace(str(SCRIPTS / "simpleterm-notify.sh"), str(other))
        text = "".join(l for l in text.splitlines(True) if not l.startswith("# version="))
        if rev is not None:
            text = "".join("# rev=%s\n" % rev if l.startswith("# rev=") else l for l in text.splitlines(True))
        if version:
            text = text.replace("\ns=", "\n# version=%s\ns=" % version, 1)
        w.write_text(text)

    for label, version, rev, kept in (("an older release's folder that is still there", "0.2.9", None, False),
                                      ("a 0.3.0 command without a version line", None, 1, False),
                                      ("a newer release's copy", "9.9.9", None, True),
                                      ("another copy of the same release", ver, None, True)):
        wrapper(version, rev)
        s.run("claude", json.dumps({"session_id": "w", "hook_event_name": "Stop", "last_assistant_message": "ok"}))
        text = w.read_text()
        points = "s='%s'" % (SCRIPTS / "simpleterm-notify.sh") in text
        s.check("cli: %s is %s" % (label, "left alone" if kept else "re-pointed"),
                points != kept and (kept or "# version=%s\n" % ver in text), text)


def hook_version():
    """The release the sh hook under test says it belongs to (0.3.0 before the constant)."""
    import re
    m = re.search(r"^HOOK_VERSION=([0-9.]+)$", HOOK_SH.read_text(), re.M)
    return m.group(1) if m else "0.3.0"


def agy_input(tool="run_command", args=None, extra=None):
    j = {"conversationId": "conv-1", "workspacePaths": ["/w/agyproj"], "transcriptPath": "/x/transcript.jsonl",
         "artifactDirectoryPath": "/x/art", "modelName": "gemini-3-pro", "stepIdx": 3,
         "toolCall": {"name": tool, "args": args if args is not None else
                      {"CommandLine": "npm test", "Cwd": "/w/agyproj", "WaitMsBeforeAsync": 5000}}}
    j.update(extra or {})
    return json.dumps(j)


def agy_stop(**kw):
    j = {"conversationId": "conv-1", "workspacePaths": ["/w/agyproj"], "transcriptPath": "/x/t.jsonl", "modelName": "m",
         "executionNum": 2, "terminationReason": "NO_TOOL_CALL", "fullyIdle": True}
    j.update(kw)
    return json.dumps({k: v for k, v in j.items() if v is not None})


COPILOT_HOOKS = ROOT / "plugins" / "copilot" / "hooks.json"


def t_copilot_hooks(s):
    """The Copilot plugin (section 12, #381): its own hooks file in Copilot's format; every command
    finds the plugin's script (PLUGIN_ROOT, or where `copilot plugin install` puts it) and never one
    of another plugin or of the project; with none it prints nothing and exits 0."""
    if s.kind != "sh":
        return
    h = json.loads(COPILOT_HOOKS.read_text())
    s.check("copilot hooks: version 1, the events", h.get("version") == 1 and sorted(h["hooks"]) == sorted(
        ["sessionStart", "userPromptSubmitted", "preToolUse", "notification", "agentStop", "subagentStart", "subagentStop", "errorOccurred", "sessionEnd"]),
        str(sorted(h["hooks"])))
    s.check("copilot hooks: no permissionRequest until M9; preToolUse only for the plan and ask_user",
            "permissionRequest" not in h["hooks"] and h["hooks"]["preToolUse"][0].get("matcher") == "exit_plan_mode|ask_user")
    man = json.loads((ROOT / "plugins" / "copilot" / "plugin.json").read_text())
    s.check("copilot plugin.json: name and hooks file", man.get("name") == "simpleterm-copilot" and man.get("hooks") == "hooks.json", str(man))
    tmp = s.tmp / "copilot-paths"
    shutil.rmtree(tmp, ignore_errors=True)
    proj = tmp / "project"
    write(proj / "scripts" / "agent-hook.sh", STUB % "project")
    write(proj / "plugin.json", '{"name": "simpleterm-copilot"}')
    cop = tmp / "copilot-home"
    root = tmp / "root"
    write(root / "scripts" / "agent-hook.sh", STUB % "root")
    write(root / "plugin.json", '{"name": "simpleterm-copilot"}')

    def run(event, env):
        cmd = h["hooks"][event][0]["bash"]
        p = subprocess.run(["/bin/bash", "-c", cmd], input=b"{}", capture_output=True, cwd=str(proj), env=s.env(dict({"COPILOT_HOME": str(cop)}, **env)), timeout=60)
        return p.returncode, p.stdout.decode()
    rc, out = run("notification", {"PLUGIN_ROOT": str(root)})
    s.check("copilot paths: PLUGIN_ROOT", rc == 0 and out.strip() == "root copilot notification", "%d %r" % (rc, out))
    rc, out = run("agentStop", {})
    s.check("copilot paths: nothing installed -> nothing, exit 0 (not the project's script)", rc == 0 and out == "", "%d %r" % (rc, out))
    write(cop / "installed-plugins" / "_direct" / "other" / "scripts" / "agent-hook.sh", STUB % "other")
    write(cop / "installed-plugins" / "_direct" / "other" / "plugin.json", '{"name": "another-plugin"}')
    rc, out = run("agentStop", {})
    s.check("copilot paths: another plugin's script never runs", rc == 0 and out == "", "%d %r" % (rc, out))
    write(cop / "installed-plugins" / "_direct" / "x1" / "scripts" / "agent-hook.sh", STUB % "direct")
    write(cop / "installed-plugins" / "_direct" / "x1" / "plugin.json", '{"name": "simpleterm-copilot"}')
    rc, out = run("sessionEnd", {})
    s.check("copilot paths: a direct install", rc == 0 and out.strip() == "direct copilot sessionEnd", "%d %r" % (rc, out))
    write(cop / "installed-plugins" / "simpleterm-agent-hooks" / "simpleterm-copilot" / "scripts" / "agent-hook.sh", STUB % "market")
    write(cop / "installed-plugins" / "simpleterm-agent-hooks" / "simpleterm-copilot" / "plugin.json", '{"name": "simpleterm-copilot"}')
    rc, out = run("preToolUse", {})
    s.check("copilot paths: a marketplace install first", rc == 0 and out.strip() == "market copilot preToolUse", "%d %r" % (rc, out))


def t_copilot(s):
    """GitHub Copilot CLI 1.0.105 (measured with a local model stub): errors Copilot retries are
    not alerts, the error that ends a session is; a subagent's own agentStop is not the session's
    done; a turn started by a background report is the task's."""
    if s.kind != "sh":
        return
    tun, tctl = s.spawn_mock()
    try:
        s.setup([(LINK_T, {"kind": "tunnel", "relay_url": tctl.url, "fmt": 2}), (LINK_A, {"fmt": 2, "push": "disabled"})])
        tctl("/_ctl/reset", {})
        tctl("/_ctl/config", {"links": {LINK_T["id"]: dict(LINK_T, push="suppressed", unknown_error="unknown")}})
        env = {"COPILOT_CLI": "1", "COPILOT_CLI_BINARY_VERSION": "1.0.105"}
        base = {"sessionId": "cop-1", "timestamp": 1793635914148, "cwd": "/w/proj"}
        err = dict(base, errorContext="model_call", recoverable=True, error={"message": "Failed native model HTTP request", "name": "Error"})
        for _ in range(3):
            s.run("copilot", json.dumps(err), env, args=("errorOccurred",))
        s.run("copilot", json.dumps(dict(base, errorContext="tool_execution", recoverable=False, error={"message": "exit 1", "name": "Error"})), env, args=("errorOccurred",))
        time.sleep(1.5)
        s.check("copilot: retried and tool errors are no alerts", not ingests(s) and not ingests(s, ctl=tctl), str(ingests(s, ctl=tctl))[:200])
        s.run("copilot", json.dumps(dict(base, reason="error")), env, args=("sessionEnd",))
        e = wait_for(lambda: ingests(s, "error", ctl=tctl), 10)
        s.check("copilot: sessionEnd reason error -> one error with the last try's message",
                len(ingests(s, "error", ctl=tctl)) == 1 and e[0]["plain_json"].get("msg") == "Error: Failed native model HTTP request", str(e)[:300])
        st = [r["plain_json"].get("st") for r in ingests(s, "state", ctl=tctl)]
        s.check("copilot: and the state ended, under another rid", "ended" in st
                and len({r["body"]["rid"] for r in ingests(s, ctl=tctl)}) == len(ingests(s, ctl=tctl)), str(st))
        tctl("/_ctl/reset", {})
        s.ctl("/_ctl/reset", {})
        s.run("copilot", json.dumps(dict(base, stopReason="end_turn", agentId="ag-1", agentType="explore", parentAgentId="")), env, args=("agentStop",))
        st = wait_for(lambda: ingests(s, "state", ctl=tctl), 10)
        s.check("copilot: a subagent's agentStop -> sub_stop, no done", st and st[0]["plain_json"].get("st") == "sub_stop"
                and st[0]["plain_json"].get("sub") == {"id": "ag-1", "type": "explore"} and not ingests(s, "done", ctl=tctl), str(st)[:300])
        s.run("copilot", json.dumps(dict(base, prompt="<system_notification>Shell command \"bg sleep\" has completed.</system_notification>")), env, args=("userPromptSubmitted",))
        turn = (s.home / ".simpleterm" / "run" / "cop-1.turn").read_text().split("\n")[0]
        s.check("copilot: a system notification's turn is the task's", turn == "task", turn)
    finally:
        tun.terminate()
        tun.wait(5)


def t_agy(s):
    """Antigravity: PreToolUse always answers with a decision (what agy does with `{}` or no
    answer is not documented); device waits are opt-in."""
    s.setup([(LINK_A, {"decision": "allow", "after": 1})])
    rc, out, err, el = s.run("agy", agy_input(), args=("PreToolUse",))
    s.check("agy: no wait by default -> allow (policy decides)", out.strip() == '{"decision":"allow"}', out + err)
    s.check("agy: no wait by default -> nothing sent", not ingests(s) and el < 3, "%.2fs" % el)
    for verdict, want in (("allow", '{"decision":"auto_approve"}'), ("deny", '{"decision":"deny","reason":"Denied from SimpleTerm"}')):
        s.setup([(LINK_A, {"decision": verdict, "after": 1})], conf={"agy_wait": 30})
        rc, out, err, el = s.run("agy", agy_input(), args=("PreToolUse",))
        s.check("agy: device %s -> %s" % (verdict, want), out.strip() == want, out + err)
        rec = ingests(s, "permission")
        p = rec[0].get("plain_json", {}) if rec else {}
        s.check("agy: %s request" % verdict, p.get("app") == "antigravity" and p.get("msg") == "approve run_command: npm test"
                and p.get("cwd") == "agyproj" and rec[0].get("nh_ok") is True, str(p))
    s.setup([(LINK_A, {})], conf={"agy_wait": 3})
    rc, out, err, el = s.run("agy", agy_input(), args=("PreToolUse",))
    s.check("agy: no answer in agy_wait -> allow", out.strip() == '{"decision":"allow"}' and 1.5 < el < 30, "%s %.2fs" % (out, el))
    s.setup([(LINK_A, {"push": "disabled"})])
    q = agy_input("ask_question", {"questions": [{"question": "Which port?", "options": ["80", "8080"], "is_multi_select": False}]})
    rc, out, err, el = s.run("agy", q, args=("PreToolUse",))
    rec = wait_for(lambda: ingests(s, "question"), 20)
    s.check("agy: ask_question -> question alert, allow", out.strip() == '{"decision":"allow"}' and rec
            and rec[0]["plain_json"].get("msg") == "Which port?", out + str(rec)[:200])
    s.ctl("/_ctl/reset", {})
    rc, out, err, el = s.run("agy", agy_stop(fullyIdle=False), args=("Stop",))
    time.sleep(1.5)
    s.check("agy: Stop not fully idle -> nothing", out.strip() == "{}" and not ingests(s), out)
    rc, out, err, el = s.run("agy", agy_stop(), args=("Stop",))
    rec = wait_for(lambda: ingests(s, "done"), 20)
    s.check("agy: Stop fully idle -> done, {}", out.strip() == "{}" and rec and rec[0]["plain_json"].get("app") == "antigravity", out)
    s.ctl("/_ctl/reset", {})
    s.run("agy", agy_stop(error="quota exceeded", terminationReason="ERROR"), args=("Stop",))
    rec = wait_for(lambda: ingests(s), 20)
    s.check("agy: Stop with error -> error", rec and rec[0]["body"]["ev"] == "error"
            and rec[0]["plain_json"].get("msg") == "ERROR: quota exceeded", str(rec)[:200])
    shutil.rmtree(s.home / ".simpleterm" / "links")
    rc, out, err, el = s.run("agy", agy_input(), args=("PreToolUse",))
    s.check("agy: nothing set up still answers allow", out.strip() == '{"decision":"allow"}' and rc == 0, out)
    rc, out, err, el = s.run("agy", "garbage {{", args=("PreToolUse",), extra={"SIMPLETERM": "1"})
    s.check("agy: garbage input still answers allow", out.strip() == '{"decision":"allow"}', out)


AGY_HOOKS = ROOT / "plugins" / "antigravity" / "hooks.json"
STUB = "#!/bin/sh\nprintf '%s %%s %%s\\n' \"$1\" \"$2\"\n"


def agy_command(event):
    hooks = json.loads(AGY_HOOKS.read_text())["simpleterm-agent-hooks"][event]
    return hooks[0]["hooks"][0]["command"] if "hooks" in hooks[0] else hooks[0]["command"]


def t_agy_paths(s):
    """agy's hook commands find the script without relying on the working directory, and never
    run one from it: agy may run hooks in the workspace, a repository that can hold its own
    scripts/agent-hook.sh."""
    s.setup([])
    tmp = s.tmp / "agy-paths"
    shutil.rmtree(tmp, ignore_errors=True)
    root, workspace, elsewhere = tmp / "plugin-root", tmp / "workspace", tmp / "elsewhere"
    places = {
        "PLUGIN_ROOT": root,
        "installed": s.home / ".gemini" / "config" / "plugins" / "simpleterm-antigravity",
        "old-installed": s.home / ".gemini" / "antigravity-cli" / "plugins" / "simpleterm-antigravity",
        "clone": s.home / ".simpleterm" / "src" / "plugins" / "simpleterm",
    }
    for name, d in places.items():
        write(d / "scripts" / "agent-hook.sh", STUB % name)
    ran = tmp / "workspace-script-ran"
    write(workspace / "scripts" / "agent-hook.sh",
          "#!/bin/sh\n: >'%s'\nprintf 'workspace %%s %%s\\n' \"$1\" \"$2\"\n" % ran)
    elsewhere.mkdir(parents=True)

    def run(event, where, env=None, substitute=False, stdin=b"{}"):
        cmd = agy_command(event)
        if substitute:  # agy replacing ${PLUGIN_ROOT} itself
            cmd = cmd.replace("${PLUGIN_ROOT}", str(root))
        p = subprocess.run([s.argv[0], "-c", cmd], input=stdin, capture_output=True, cwd=str(where),
                           env=s.env(env), timeout=60)
        return p.returncode, p.stdout.decode()

    for label, env, sub, want in (
        ("${PLUGIN_ROOT} replaced", None, True, "PLUGIN_ROOT agy PreToolUse"),
        ("PLUGIN_ROOT in the environment", {"PLUGIN_ROOT": str(root)}, False, "PLUGIN_ROOT agy PreToolUse"),
        ("CLAUDE_PLUGIN_ROOT in the environment", {"CLAUDE_PLUGIN_ROOT": str(root)}, False, "PLUGIN_ROOT agy PreToolUse"),
        ("no variable: the installed copy", None, False, "installed agy PreToolUse"),
    ):
        rc, out = run("PreToolUse", workspace, env, sub)
        s.check("agy paths: %s" % label, rc == 0 and out.strip() == want, "%d %r" % (rc, out))
    shutil.rmtree(places["installed"])
    rc, out = run("Stop", workspace)
    s.check("agy paths: the old install folder (~/.gemini/antigravity-cli/plugins) next",
            rc == 0 and out.strip() == "old-installed agy Stop", "%d %r" % (rc, out))
    shutil.rmtree(places["old-installed"])
    rc, out = run("Stop", workspace)
    s.check("agy paths: the app's clone next", rc == 0 and out.strip() == "clone agy Stop", "%d %r" % (rc, out))
    shutil.rmtree(places["clone"])
    # Nothing installed: PreToolUse still ends with a decision (as the script does), Stop
    # prints nothing, and the workspace's own scripts/agent-hook.sh does not run.
    for event, want in (("PreToolUse", '{"decision":"allow"}\n'), ("Stop", "")):
        for where in (workspace, elsewhere):
            rc, out = run(event, where)
            s.check("agy paths: no script installed -> %s, exit 0 (%s from %s)" % (want.strip() or "no output", event, where.name),
                    rc == 0 and out == want, "%d %r" % (rc, out))
    s.check("agy paths: the workspace's scripts/agent-hook.sh never runs", not ran.exists(), "ran from %s" % workspace)
    # agy runs a plugin's hooks in the plugin's folder and gives no PLUGIN_ROOT (measured on
    # 1.4.12): the folder the hook runs in counts, only when its plugin.json names this plugin.
    pf = tmp / "plugin-folder"
    write(pf / "scripts" / "agent-hook.sh", STUB % "cwd-plugin")
    write(pf / "plugin.json", '{"name": "simpleterm-antigravity", "version": "x"}')
    for event in ("PreToolUse", "PostToolUse", "Stop"):
        rc, out = run(event, pf)
        s.check("agy paths: run in this plugin's folder -> its script (%s)" % event, rc == 0 and out.strip() == "cwd-plugin agy %s" % event, "%d %r" % (rc, out))
    write(workspace / "plugin.json", '{"name": "a-workspace-plugin"}')
    rc, out = run("PreToolUse", workspace)
    s.check("agy paths: a folder whose plugin.json names another plugin -> not run", rc == 0 and out == '{"decision":"allow"}\n' and not ran.exists(), "%d %r" % (rc, out))
    (workspace / "plugin.json").unlink()
    hj = json.loads(AGY_HOOKS.read_text())["simpleterm-agent-hooks"]
    s.check("agy hooks: the tools whose prompts can be answered, no ask_permission (#381)",
            hj["PreToolUse"][0]["matcher"] == "run_command|ask_question|write_file|edit_file|read_file|call_mcp_tool", str(hj["PreToolUse"][0]["matcher"]))
    s.check("agy hooks: write_file's PostToolUse (a plan for review), Stop timeout above agy_wait (110)",
            hj["PostToolUse"][0]["matcher"] == "write_file" and hj["Stop"][0]["timeout"] > 110 and hj["PreToolUse"][0]["hooks"][0]["timeout"] > 110, str(hj)[:300])
    # The real plugin installed where agy puts it, run from the workspace. The device's answer
    # shows that the plugin's script ran (with nothing found the command answers allow too).
    shutil.copytree(ROOT / "plugins" / "antigravity", places["installed"])
    s.setup([(LINK_A, {"decision": "allow", "after": 1})], conf={"agy_wait": 30})
    if ran.exists():  # reported above; this case looks at its own run only
        ran.unlink()
    rc, out = run("PreToolUse", workspace, stdin=agy_input().encode())
    s.check("agy paths: the installed plugin answers from any folder",
            rc == 0 and out.strip() == '{"decision":"auto_approve"}' and not ran.exists(), "%d %r" % (rc, out))
    shutil.rmtree(s.home / ".gemini", ignore_errors=True)
    shutil.rmtree(tmp, ignore_errors=True)


def grok_input(event, **kw):
    snake = {"Notification": "notification", "Stop": "stop", "StopFailure": "stop_failure",
             "UserPromptSubmit": "user_prompt_submit"}[event]
    j = {"hookEventName": snake, "sessionId": "gk-1", "cwd": "/w/grokproj", "workspaceRoot": "/w/grokproj",
         "timestamp": kw.pop("timestamp", "2026-10-29T10:00:00.000Z"), "hook_event_name": event, "session_id": "gk-1"}
    j.update(kw)
    return json.dumps(j), {"GROK_HOOK_EVENT": snake, "SIMPLETERM": "1"}


def t_grok(s):
    """Grok Build runs the Claude Code hooks (`claude`) with GROK_HOOK_EVENT set."""
    s.setup([(LINK_A, {"push": "disabled"})])
    inp, env = grok_input("Stop", reason="end_turn", promptId="p1", stopHookActive=False, lastAssistantMessage="Grok done.")
    rc, out, err, el = s.run("claude", inp, env)
    rec = wait_for(lambda: ingests(s, "done"), 20)
    p = rec[0].get("plain_json", {}) if rec else {}
    s.check("grok: claude mode switches to grok-build", p.get("app") == "grok-build" and p.get("msg") == "Grok done."
            and p.get("cwd") == "grokproj", str(p))
    s.check("grok: no terminal output (Grok has no terminalSequence)", out == "", out)
    s.ctl("/_ctl/reset", {})
    rc, out, err, el = s.run("claude", inp, env)
    time.sleep(1.5)
    s.check("grok: the same event twice (two copies of the hook) -> one alert", not ingests(s), str(ingests(s))[:200])
    s.check("grok: duplicate logged", "duplicate Stop" in s.log_text(), s.log_text()[-300:])
    inp2, _ = grok_input("Stop", reason="end_turn", promptId="p2", timestamp="2026-10-29T10:05:00.000Z", lastAssistantMessage="Grok done.")
    s.run("claude", inp2, env)
    s.check("grok: a later turn with the same text is sent", wait_for(lambda: ingests(s, "done"), 20))
    s.ctl("/_ctl/reset", {})
    for reason in ("channel_closed", "shutdown"):
        inp3, _ = grok_input("Stop", reason=reason, timestamp="2026-10-29T10:09:%02d.000Z" % len(reason), lastAssistantMessage="x")
        s.run("claude", inp3, env)
    time.sleep(1.5)
    s.check("grok: session-end Stop is not a turn end", not ingests(s), str(ingests(s))[:200])
    note, nenv = grok_input("Notification", notificationType="permission_prompt", message="Tool permission requested", level="info")
    s.run("claude", note, dict(nenv, GROK_HOOK_EVENT="notification"))
    rec = wait_for(lambda: ingests(s, "question"), 20)
    s.check("grok: permission_prompt -> question (alert only)", rec and rec[0]["plain_json"].get("msg") == "Tool permission requested"
            and not s.records("/v1/decision"), str(rec)[:200])
    s.ctl("/_ctl/reset", {})
    note2, _ = grok_input("Notification", notificationType="task_complete", message="Background task completed: t1",
                          timestamp="2026-10-29T10:10:00.000Z")
    s.run("claude", note2, dict(nenv, GROK_HOOK_EVENT="notification"))
    time.sleep(1.5)
    s.check("grok: other notifications ignored", not ingests(s))
    fail, fenv = grok_input("StopFailure", error="rate_limit", errorDetails="429", lastAssistantMessage="Rate limited",
                            timestamp="2026-10-29T10:11:00.000Z")
    s.run("claude", fail, dict(fenv, GROK_HOOK_EVENT="stop_failure"))
    rec = wait_for(lambda: ingests(s), 20)
    s.check("grok: StopFailure -> error", rec and rec[0]["body"]["ev"] == "error"
            and rec[0]["plain_json"].get("msg") == "rate_limit: Rate limited", str(rec)[:200])
    s.ctl("/_ctl/reset", {})
    only_camel = json.dumps({"hookEventName": "stop", "sessionId": "gk-2", "cwd": "/w/g", "timestamp": "t9", "reason": "end_turn",
                             "lastAssistantMessage": "camel only"})
    s.run("grok", only_camel)
    rec = wait_for(lambda: ingests(s, "done"), 20)
    s.check("grok: grok mode, camelCase-only input", rec and rec[0]["plain_json"].get("msg") == "camel only", str(rec)[:200])

    # Grok 1.0.70 (measured with a local model stub): the Stop after starting a
    # background shell lists it in backgroundTasks; its completion starts a turn
    # (promptId task-completed-<id>); that turn's Stop has backgroundTasks [].
    s.ctl("/_ctl/reset", {})
    task = {"id": "48d7f629-d7ca-4ac8-94ac-419eb88970a7", "type": "shell", "status": "running",
            "command": "sleep 20; echo bgdone > bgdone.txt"}
    bg, benv = grok_input("Stop", reason="end_turn", promptId="b1", timestamp="2026-10-29T10:20:00.000Z",
                          lastAssistantMessage="Started the job in the background.", backgroundTasks=[task], sessionCrons=[])
    s.run("claude", bg, benv)
    idle, ienv = grok_input("Notification", notificationType="idle_prompt", message="Waiting for input",
                            timestamp="2026-10-29T10:21:00.000Z")
    s.run("claude", idle, dict(ienv, GROK_HOOK_EVENT="notification"))
    time.sleep(1.5)
    s.check("grok background: no done and no idle question while the shell runs", not ingests(s), str(ingests(s))[:200])
    wake, wenv = grok_input("UserPromptSubmit", promptId="task-completed-" + task["id"], timestamp="2026-10-29T10:22:00.000Z")
    s.run("claude", wake, dict(wenv, GROK_HOOK_EVENT="user_prompt_submit"))
    end, eenv = grok_input("Stop", reason="end_turn", promptId="task-completed-" + task["id"], timestamp="2026-10-29T10:22:01.000Z",
                           lastAssistantMessage="The background job finished.", backgroundTasks=[], sessionCrons=[])
    s.run("claude", end, eenv)
    rec = wait_for(lambda: ingests(s, "done"), 20)
    s.check("grok background: done after the turn it reported back in", rec and rec[0]["plain_json"].get("msg")
            == "The background job finished.", str(ingests(s))[:200])
    # idle_prompt after that done repeats it: no question.
    s.ctl("/_ctl/reset", {})
    idle2, ienv2 = grok_input("Notification", notificationType="idle_prompt", message="Waiting for input",
                              timestamp="2026-10-29T10:23:00.000Z")
    s.run("claude", idle2, dict(ienv2, GROK_HOOK_EVENT="notification"))
    time.sleep(1.5)
    s.check("grok: idle_prompt after a done repeats it (no question)", not ingests(s, "question"), str(ingests(s))[:200])


def t_opencode_sh(s):
    """OpenCode's bridge runs `opencode` with Claude-shaped JSON and maps the answer to once/reject."""
    for verdict in ("allow", "deny"):
        s.setup([(LINK_A, {"decision": verdict, "after": 1})])
        rc, out, err, el = s.run("opencode", perm_input(tool="bash", command="rm -rf dist", cwd="/w/ocproj", session="oc-1"),
                                 {"SIMPLETERM": "1"})
        s.check("opencode sh: %s" % verdict, out.strip() == '{"decision":"%s"}' % verdict, out + err)
        rec = ingests(s, "permission")
        s.check("opencode sh: %s request" % verdict, rec and rec[0]["plain_json"].get("app") == "opencode"
                and rec[0]["plain_json"].get("msg") == "approve bash: rm -rf dist", str(rec)[:200])
    # A failed turn ends the pause of the Stop before it: an error, and no done from the pause's timer.
    s.setup([(LINK_A, {"push": "disabled"})], conf={"bg_done_after": 2})
    s.run("opencode", json.dumps({"hook_event_name": "Stop", "session_id": "oc-2", "cwd": "/w/ocproj", "last_assistant_message": "t",
                                  "background_tasks": [{"id": "sh_1", "type": "shell", "command": "node worker.js"}]}))
    s.run("opencode", json.dumps({"hook_event_name": "StopFailure", "session_id": "oc-2", "cwd": "/w/ocproj",
                                  "error": "APIError", "last_assistant_message": "boom"}))
    time.sleep(3.5)
    evs = [r["body"]["ev"] for r in ingests(s)]
    s.check("opencode sh: a failed turn ends the pause (error, no later done)", evs == ["error"], str(evs))
    s.setup([(LINK_A, {"push": "disabled"})])
    s.run("opencode", json.dumps({"hook_event_name": "StopFailure", "session_id": "oc-1", "cwd": "/w/ocproj",
                                  "error": "ProviderAuthError", "last_assistant_message": "API key invalid"}))
    rec = wait_for(lambda: ingests(s), 20)
    s.check("opencode sh: ProviderAuthError -> auth", rec and rec[0]["body"]["ev"] == "auth", str(rec)[:200])


NODE = shutil.which("node")


def node_plugin(s, kind, scenario, timeout=90):
    plugin = {"v1": ROOT / "plugins" / "opencode-v1" / "simpleterm.js", "v2": ROOT / "plugins" / "opencode" / "index.js"}[kind]
    p = subprocess.run([NODE, str(HERE / "opencode_harness.mjs"), kind, str(plugin), json.dumps(scenario)],
                       capture_output=True, text=True, env=s.env(), timeout=timeout, cwd=str(s.tmp))
    try:
        return json.loads(p.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return [{"error": p.stdout[-300:] + p.stderr[-500:]}]


def replies(calls):
    return [c["reply"] for c in calls if "reply" in c]


# --- event format v2 (TDS_AGENT_EVENTS_V2) ---------------------------------------

V2_DIR = HERE / "fixtures" / "v2"
V2_RID = "0123456789abcdef"
V2_PIN = {"SIMPLETERM_HOOK_TEST": "1", "SIMPLETERM_HOOK_TEST_RID": V2_RID, "SIMPLETERM_HOOK_TEST_NONCE": V_NONCE,
          "SIMPLETERM_HOOK_TEST_TS": V_TS, "SIMPLETERM_HOOK_TEST_TMS": V_TS + "123", "SIMPLETERM_HOOK_TEST_IV": V_IV}
V2_LINK_NAMES = {LINK_A["id"][:8]: "relay1", LINK_B["id"][:8]: "relay2", LINK_T["id"][:8]: "tunnel"}
# The agents each runtime serves (the PowerShell hook: Claude Code, Grok Build, Codex).
V2_PS1_AGENTS = {"claude", "codex", "grok"}


def v2_links(s, names, tunnel_opts=None, relay1_opts=None, relay2_opts=None):
    """Links by name: tunnel (kind=tunnel fmt=2, its own mock: the app answers suppressed at
    once), relay2 (fmt=2), relay1 (no fmt: an older app or relay). Returns (tunnel process, ctl)."""
    tun = tctl = None
    links = []
    if "tunnel" in names or "tunnel1" in names:
        tun, tctl = s.spawn_mock()
        fmt = 2 if "tunnel" in names else None
        links.append((LINK_T, dict({"kind": "tunnel", "relay_url": tctl.url, "fmt": fmt}, **(tunnel_opts or {}))))
    if "relay1" in names:
        links.append((LINK_A, dict({"push": "disabled"}, **(relay1_opts or {}))))
    if "relay2" in names:
        links.append((LINK_B, dict({"push": "disabled", "fmt": 2}, **(relay2_opts or {}))))
    return tun, tctl, links


def v2_run_case(s, case, conf=None, want_n=0):
    """Runs a fixture case; returns (sorted plaintext lines of the pinned rid, stdouts). Background
    sends are waited for: until want_n plaintexts are there, then until none came for a while (the
    PowerShell hook sends from a pwsh child that takes a second or more to start)."""
    names = case["links"]
    tun, tctl, links = v2_links(s, names, {"push": "suppressed", "unknown_error": "unknown", "max_body": 65536})
    try:
        s.setup(links, dict(case.get("conf", {}), **(conf or {})))
        if tctl:
            tctl("/_ctl/reset", {})
            tctl("/_ctl/config", {"links": {LINK_T["id"]: dict(LINK_T, push="suppressed", unknown_error="unknown", max_body=65536)}})
        for name, text in case.get("files", {}).items():
            (s.home / name).write_text(text)
        dump = s.tmp / "plain"
        shutil.rmtree(dump, ignore_errors=True)
        dump.mkdir()
        outs = []
        for st in case["steps"]:
            inp = json.dumps(st["input"], ensure_ascii=bool(case.get("ascii"))).replace("HOMEP", str(s.home))
            env = dict(V2_PIN, SIMPLETERM_HOOK_TEST_PLAIN=str(dump), **case.get("env", {}))
            env.update(st.get("env", {}))
            rc, out, err, el = s.run(st["args"][0], inp, env, args=st["args"][1:])
            outs.append(out)
        quiet = 4 if s.kind == "ps1" else 1.5
        wait_for(lambda: len([f for f in dump.iterdir() if f.name.split(".")[2:3] == [V2_RID]]) >= want_n, 30, 0.2)
        last = [-1, time.time()]

        def settled():
            n = len(list(dump.iterdir()))
            if n != last[0]:
                last[0], last[1] = n, time.time()
            return time.time() - last[1] > quiet

        wait_for(settled, 30, 0.2)
        got = []
        # One file per plaintext: <link id[:8]>.<ev>.<rid>.<pid> (the hook's test dump).
        # The plugin's version is the release's: the fixtures name it @PV@.
        pv = '"pv":"%s"' % re.search(r"^HOOK_VERSION=([0-9.]+)$", HOOK_SH.read_text(), re.M).group(1)
        for f in dump.iterdir():
            link, ev, rid = f.name.split(".")[:3]
            if rid == V2_RID:
                text = f.read_bytes().decode("utf-8", "replace").replace(pv, '"pv":"@PV@"')
                got.append("%s %s %s" % (V2_LINK_NAMES.get(link, link), ev, text))
        return sorted(got), outs
    finally:
        if tun:
            tun.terminate()
            tun.wait(5)


def v2_cases():
    return json.loads((V2_DIR / "cases.json").read_text(encoding="utf-8"))["cases"]


def v2_expected():
    p = V2_DIR / "expected.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}


def t_v2_fixtures(s):
    """Per agent and version (section 10): the plaintext each link gets, byte for byte (the PowerShell
    hook must give the same bytes: section 2.2), and what the hook prints."""
    exp = v2_expected()
    for case in v2_cases():
        if s.kind == "ps1" and case["agent"] not in V2_PS1_AGENTS:
            continue
        want = exp.get(case["name"])
        got, outs = v2_run_case(s, case, want_n=len(want["plain"]) if want else 0)
        if want is None:
            s.check("v2 fixture %s: has an expected result" % case["name"], False, "run with --regen-v2")
            continue
        miss = [x for x in want["plain"] if x not in got]
        extra = [x for x in got if x not in want["plain"]]
        s.check("v2 fixture %s: plaintexts" % case["name"], not miss and not extra,
                ("missing: %s | unexpected: %s" % (miss[:1], extra[:1]))[:1500])
        s.check("v2 fixture %s: output" % case["name"], [o.strip() for o in outs] == want["stdout"], str(outs)[:400])


# Decision extension test vector (TDS_AGENT_EVENTS_V2 section 5.3).
V2_DEXT_IV = "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
V2_DEXT_PLAIN = ('{"v":1,"fmt":2,"rid":"0123456789abcdef","nonce":"ffeeddccbbaa99887766554433221100","decision":"allow",'
                 '"req":"st-0123456789abcdef","act":"allow_scope","scope":0,"ts":1793232000}')
V2_DEXT_CT = ("/x2FBqw5ieeEiW5VTyr/64o0LnyVtzhp5XnKHdls61InCIDSFaxW9hEPP59KDFMWy0+TVLn/xKOwOGq1qivvZJJfMxiaWhE2bYCnwwo1EnkSeR3T"
              "pYmQQ8vBT9bfvb5WvKqaXyPKbsB5S8inzqEYZcxKvguy4YtBJM2la7U62pZjjDuLipCa4bjbzq8Z5Q7flhmK1R8Lm4YSkJbr4EnrJFnxvjWxO8Ue"
              "P2sWacIiuJz8P91ZWfNVT9bhBHU5Sz37")
V2_DEXT_MAC = "6d7c00d381dca94abd9351584426aa1734ef339f43e74622fda877d8a533348a"
V2_DMAC = "be8a617d1d79a5a3d616500f4926da3940466f5fe5f534b5fe13a33da4912561"
SUG_RULE = {"type": "addRules", "rules": [{"toolName": "Bash", "ruleContent": "npm test *"}], "behavior": "allow", "destination": "localSettings"}


def v2_perm(command="npm test", session="sess-v2", tool="Bash", suggestions=(SUG_RULE,), **kw):
    d = {"session_id": session, "transcript_path": "/home/u/.claude/projects/x/t.jsonl", "cwd": "/home/u/api",
         "permission_mode": "default", "hook_event_name": "PermissionRequest", "tool_name": tool,
         "tool_input": {"command": command, "description": "Run tests"}, "permission_suggestions": list(suggestions)}
    d.update(kw)
    return json.dumps(d)


def behavior(out):
    return ((decision_json(out) or {}).get("hookSpecificOutput") or {}).get("decision") or {}


def t_v2_dext_vector(s):
    """Section 5.3: the vector extension, sealed by openssl with the vector keys and IV, is what the
    mock relay sends, and the hook opens and applies it (allow_scope -> the original suggestion)."""
    ct, mac = openssl_seal(V2_DEXT_PLAIN, V_ENC, V_MAC, V2_DEXT_IV, s.openssl or "/usr/bin/openssl", "st1-dext.")
    s.check("dext vector: ct", ct == V2_DEXT_CT, ct)
    s.check("dext vector: mac", mac == V2_DEXT_MAC, mac)
    s.setup([(LINK_A, {"fmt": 2, "decision": "allow", "after": 1, "dext": {"raw": V2_DEXT_PLAIN, "iv": V2_DEXT_IV}})])
    extra = {"SIMPLETERM_HOOK_TEST": "1", "SIMPLETERM_HOOK_TEST_NONCE": V_NONCE, "SIMPLETERM_HOOK_TEST_RID": V_RID}
    rc, out, err, el = s.run("claude", v2_perm(), extra)
    b = behavior(out)
    s.check("dext vector: applied as allow_scope", b.get("behavior") == "allow" and b.get("updatedPermissions") == [SUG_RULE], out + err)
    s.check("dext vector: logged ok", "dext=ok" in s.log_text(), s.log_text()[-300:])


def t_v2_decisions(s):
    """Section 5.4: each decision the agent's way (Claude Code, Codex), and section 5.5: a decision that
    does not hold (MAC, request, decision list, values) prints nothing and the hook's safe no-decision."""
    def run(dext, decision="allow", inp=None, agent="claude", fmt=2, extra_conf=None):
        s.setup([(LINK_A, {"fmt": fmt, "decision": decision, "after": 1, "dext": dext})], conf=dict({"claude_wait": 20, "codex_wait": 20}, **(extra_conf or {})))
        rc, out, err, el = s.run(agent, inp or v2_perm())
        return out, el
    out, el = run({"act": "deny_reason", "reason": "use pnpm\nnot npm"}, "deny")
    b = behavior(out)
    s.check("decision claude deny_reason: user rejection wrapper, no interrupt", b.get("behavior") == "deny" and
            b.get("message", "").startswith("The user doesn't want to proceed") and b.get("message", "").endswith("said:\nuse pnpm\nnot npm")
            and "interrupt" not in b, out)
    plan = json.dumps({"session_id": "sp", "cwd": "/w", "hook_event_name": "PermissionRequest", "tool_name": "ExitPlanMode",
                       "tool_input": {"plan": "## Plan\n1. a", "planFilePath": "/w/p.md"}})
    out, el = run({"act": "plan_approve", "mode": "accept_edits"}, inp=plan)
    b = behavior(out)
    s.check("decision claude plan_approve: updatedInput is the tool input, setMode acceptEdits",
            b.get("updatedInput") == {"plan": "## Plan\n1. a", "planFilePath": "/w/p.md"}
            and b.get("updatedPermissions") == [{"type": "setMode", "mode": "acceptEdits", "destination": "session"}], out)
    out, el = run({"act": "plan_refine", "reason": "split step 1"}, "deny", inp=plan)
    s.check("decision claude plan_refine: deny with the reason", behavior(out).get("message", "").endswith("said:\nsplit step 1"), out)
    q = json.dumps({"session_id": "sq", "cwd": "/w", "hook_event_name": "PermissionRequest", "tool_name": "AskUserQuestion",
                    "tool_input": {"questions": [{"question": "Which DB?", "header": "DB", "multiSelect": False, "options": [{"label": "SQLite"}, {"label": "Postgres"}]},
                                                 {"question": "Which features?", "header": "F", "multiSelect": True, "options": [{"label": "Auth"}, {"label": "Search"}]}]}})
    out, el = run({"act": "answer", "answers": [{"q": 0, "pick": [1], "text": "with pgvector"}, {"q": 1, "pick": [0, 1]}]}, inp=q)
    b = behavior(out)
    s.check("decision claude answer: labels, several as a list, typed text joined",
            (b.get("updatedInput") or {}).get("answers") == {"Which DB?": "Postgres, with pgvector", "Which features?": ["Auth", "Search"]}
            and len((b.get("updatedInput") or {}).get("questions", [])) == 2, out)
    out, el = run({"act": "answer", "answers": [{"q": 0, "pick": [1]}]}, inp=q)
    s.check("decision claude answer: not every question answered -> nothing (M11)", out.strip() == "", out)
    out, el = run({"act": "answer", "answers": [{"q": 0, "pick": [7]}, {"q": 1, "pick": [0]}]}, inp=q)
    s.check("decision claude answer: a choice outside the list -> nothing", out.strip() == "", out)
    out, el = run(None, inp=q)
    s.check("decision claude: a v1 allow of a question (no dext) prints nothing", out.strip() == "", out)
    out, el = run(None, inp=plan, fmt=None)
    s.check("decision claude: a v1 allow of a plan is plan_approve (updatedInput)",
            behavior(out).get("updatedInput") == {"plan": "## Plan\n1. a", "planFilePath": "/w/p.md"}, out)
    codex = json.dumps({"session_id": "c1", "turn_id": "t1", "transcript_path": None, "cwd": "/w/repo", "hook_event_name": "PermissionRequest",
                        "tool_name": "Bash", "tool_input": {"command": "rm -rf build"}})
    out, el = run({"act": "deny_reason", "reason": "keep build"}, "deny", inp=codex, agent="codex")
    b = behavior(out)
    s.check("decision codex deny_reason: message as given, nothing else", b == {"behavior": "deny", "message": "keep build"}, out)
    # Section 5.5: dropped decisions print nothing.
    for name, dext, dec in (("bad MAC", {"act": "allow", "bad_mac": True}, "allow"),
                            ("another request (N10)", {"act": "allow", "req": "st-ffffffffffffffff"}, "allow"),
                            ("not in this link's can", {"act": "allow_scope", "scope": 0}, "allow"),
                            ("a plan's approval for a command (not offered)", {"act": "plan_approve"}, "allow"),
                            ("decision differs from the act", {"act": "deny"}, "allow"),
                            ("rid differs", {"act": "allow", "rid": "ffffffffffffffff"}, "allow"),
                            ("scope out of the list", {"act": "allow_scope", "scope": 3}, "allow"),
                            ("empty reason", {"act": "deny_reason", "reason": ""}, "deny"),
                            ("not JSON", {"act": "allow", "raw": "not json"}, "allow")):
        inp = v2_perm(suggestions=() if name == "not in this link's can" else (SUG_RULE,))
        # A cap far above the run's own time (about 3 s, more on a loaded machine).
        out, el = run(dext, dec, inp=inp, extra_conf={"claude_wait": 40})
        s.check("decision dropped (%s): nothing printed" % name, out.strip() == "", out)
        s.check("decision dropped (%s): the link's wait ends, not the cap" % name, el < 30, "%.2fs" % el)


def t_v2_n10(s):
    """Section 5.5 N10: a request the user did not see. OpenCode's reject also settles the session's other
    open requests: applied only if every one open now was seen; a v1 deny never while others are open;
    a request answered in the terminal first is not decided again."""
    oc = json.dumps({"hook_event_name": "PermissionRequest", "session_id": "ses_n", "cwd": "/w", "tool_name": "bash",
                     "tool_input": {"command": "echo a"}, "oc": "2", "request_id": "per_1", "save": ["echo *"], "others": ["per_2"]})
    pend = lambda ids: (s.home / ".simpleterm" / "run").mkdir(parents=True, exist_ok=True) or \
        (s.home / ".simpleterm" / "run" / "oc.ses_n.pending").write_text("".join(i + "\n" for i in ids))
    for name, dext, dec, open_ids, want in (
            ("seen covers every open request", {"act": "deny", "seen": ["per_1", "per_2"]}, "deny", ["per_1", "per_2"], {"decision": "deny"}),
            ("a request opened since", {"act": "deny", "seen": ["per_1", "per_2"]}, "deny", ["per_1", "per_2", "per_3"], None),
            ("seen without this request", {"act": "deny", "seen": ["per_2"]}, "deny", ["per_1", "per_2"], None),
            ("v1 deny with another open", None, "deny", ["per_1", "per_2"], None),
            ("v1 deny, nothing else open", None, "deny", ["per_1"], {"decision": "deny"}),
            ("allow_scope seen", {"act": "allow_scope", "scope": 0, "seen": ["per_1", "per_2"]}, "allow", ["per_1", "per_2"], {"decision": "allow", "scope": "always"})):
        s.setup([(LINK_A, {"fmt": 2, "decision": dec, "after": 1, "dext": dext})], conf={"opencode_wait": 20})
        pend(open_ids)
        rc, out, err, el = s.run("opencode", oc)
        s.check("N10 opencode (%s)" % name, (decision_json(out) or None) == want, out + s.log_text()[-200:])
    # A v1 link (no fmt=2) takes no extension beyond what it was offered (allow, deny).
    s.setup([(LINK_A, {"decision": "deny", "after": 1, "dext": {"act": "deny_reason", "reason": "no"}})], conf={"claude_wait": 8})
    rc, out, err, el = s.run("claude", v2_perm(session="sess-v1"))
    s.check("N10 a fmt-less link: deny_reason was not offered there -> nothing", out.strip() == "", out)
    # The decision is there and the agent moved on just before it is printed (section 5.5-6): the
    # terminal's note lands while the hook sleeps between its looks, right after the poll's result.
    s.setup([(LINK_A, {"fmt": 2, "decision": "allow", "after": 2, "dext": {"act": "allow"}})], conf={"claude_wait": 12})
    p = s.start("claude", v2_perm(session="sess-race"))
    run = s.home / ".simpleterm" / "run"
    dec = wait_for(lambda: [f for f in run.glob("rq.*.dec")], 15, 0.005)
    with open(run / "sess-race.res", "a") as f:
        f.write("%d turn -\n" % int(time.time() + 1))
    rc, out, err, el = s.finish(p, 60)
    s.check("N10 answered in the terminal after the decision came: nothing printed", dec and out.strip() == "", out)
    # Answered in the terminal first (a prompt or the tool ran): the late decision is not applied.
    s.setup([(LINK_A, {"fmt": 2, "decision": "allow", "after": 4, "dext": {"act": "allow"}})], conf={"claude_wait": 12})
    p = s.start("claude", v2_perm(session="sess-n10"))
    time.sleep(1.5)
    s.run("claude", json.dumps({"session_id": "sess-n10", "cwd": "/home/u/api", "hook_event_name": "UserPromptSubmit", "prompt": "go on"}))
    rc, out, err, el = s.finish(p, 60)
    s.check("N10 answered at the terminal first: nothing printed", out.strip() == "", out)


def t_v2_link_results(s):
    """Section 5.5 link results: a dropped decision ends only that link's wait; a v2 tunnel hears it at
    once (resolved, scope link) and gets the request again under a new rid, 3 times at most; an older
    tunnel neither. Section 5.6: the request-level result names the last rid each tunnel got."""
    if s.kind == "ps1" and False:
        return
    tun, tctl = s.spawn_mock()
    try:
        def setup(tunnel_opts, relay_opts, fmt=2, conf=None):
            s.setup([(LINK_T, {"kind": "tunnel", "relay_url": tctl.url, "fmt": fmt}), (LINK_A, dict({"fmt": 2}, **relay_opts))],
                    conf=dict({"claude_wait": 20}, **(conf or {})))
            tctl("/_ctl/reset", {})
            tctl("/_ctl/config", {"links": {LINK_T["id"]: dict(LINK_T, unknown_error="unknown", max_body=65536, **tunnel_opts)}})

        def tun_ingests(ev=None):
            return [r for r in tctl("/_ctl/records")["records"] if r["path"] == "/v1/ingest" and (ev is None or r["body"]["ev"] == ev)]

        bad = {"decision": "allow", "after": 0.5, "dext": {"act": "allow", "bad_mac": True}}
        # A bad decision, then a good one on the request sent again.
        setup({"decisions": [bad, {"decision": "allow", "after": 0.5, "dext": {"act": "allow"}}]}, {"push": "disabled"})
        rc, out, err, el = s.run("claude", v2_perm(session="lr1"))
        s.check("link result: the request sent again is decided", behavior(out).get("behavior") == "allow", out + s.log_text()[-300:])
        reqs = wait_for(lambda: len(tun_ingests("resolved")) >= 2 and tun_ingests("permission"), 10)
        perms = tun_ingests("permission")
        ids = {(r.get("plain_json") or {}).get("req", {}).get("id") for r in perms}
        rids = [r["body"]["rid"] for r in perms]
        s.check("link result: same req.id, new rid", len(perms) == 2 and len(ids) == 1 and len(set(rids)) == 2, str(rids) + str(ids))
        res = [(r.get("plain_json") or {}).get("res") for r in tun_ingests("resolved")]
        link = [r for r in res if r and r.get("scope") == "link"]
        req = [r for r in res if r and r.get("scope") == "req"]
        s.check("link result: link-level resolved (bad) for the first rid", link and link[0]["out"] == "bad" and link[0]["rrid"] == rids[0], str(res))
        s.check("link result: request-level resolved (applied) names the last rid", req and req[0]["out"] == "applied"
                and req[0]["rrid"] == rids[1] and req[0].get("act") == "allow", str(res))
        # The tunnel keeps failing: 3 resends at most, and the relay's wait goes on to its decision.
        setup({"decisions": [dict(bad) for _ in range(6)]}, {"decision": "deny", "after": 7})
        rc, out, err, el = s.run("claude", v2_perm(session="lr2"))
        s.check("link results: the relay's decision still applies", behavior(out).get("behavior") == "deny", out + s.log_text()[-300:])
        wait_for(lambda: len(tun_ingests("resolved")) >= 5, 10)
        perms = tun_ingests("permission")
        res = [(r.get("plain_json") or {}).get("res") for r in tun_ingests("resolved")]
        s.check("link results: 1 + 3 sends to the tunnel", len(perms) == 4, str(len(perms)))
        s.check("link results: 4 link-level results", len([r for r in res if r and r["scope"] == "link"]) == 4, str(res))
        last = [r for r in res if r and r["scope"] == "req"]
        s.check("link results: request-level out=other names the tunnel's last rid",
                last and last[0]["out"] == "other" and last[0]["rrid"] == perms[-1]["body"]["rid"], str(last))
        # An older app's tunnel (no fmt): no result, no resend.
        setup({"decisions": [dict(bad)]}, {"decision": "allow", "after": 3}, fmt=None)
        rc, out, err, el = s.run("claude", v2_perm(session="lr3"))
        time.sleep(1)
        s.check("link results: older tunnel: no link result, no resend, relay applies",
                behavior(out).get("behavior") == "allow" and len(tun_ingests("permission")) == 1
                and not [r for r in tun_ingests("resolved") if ((r.get("plain_json") or {}).get("res") or {}).get("scope") == "link"],
                out + str(len(tun_ingests())))
    finally:
        tun.terminate()
        tun.wait(5)


def t_v2_link_waits(s):
    """Section 4.6: waits per link and the order of sending."""
    tun, tctl = s.spawn_mock()
    try:
        def setup(tunnel_opts, relay_opts, conf=None, tunnel_fmt=2):
            s.setup([(LINK_T, {"kind": "tunnel", "relay_url": tctl.url, "fmt": tunnel_fmt}), (LINK_A, dict({"fmt": 2}, **relay_opts))],
                    conf=dict({"claude_wait": 15, "codex_wait": 15}, **(conf or {})))
            tctl("/_ctl/reset", {})
            tctl("/_ctl/config", {"links": {LINK_T["id"]: dict(LINK_T, unknown_error="unknown", max_body=65536, **tunnel_opts)}})

        def tun_ingests(ev=None):
            return [r for r in tctl("/_ctl/records")["records"] if r["path"] == "/v1/ingest" and (ev is None or r["body"]["ev"] == ev)]
        codex = json.dumps({"session_id": "cw", "turn_id": "t1", "transcript_path": None, "cwd": "/w/repo", "hook_event_name": "PermissionRequest",
                            "tool_name": "Bash", "tool_input": {"command": "make"}})
        # An older app's tunnel answers sent: the hook waits for it (even for Codex), the relay gets an alert.
        setup({"push": "sent", "decision": "allow", "after": 1}, {"push": "sent"}, tunnel_fmt=None)
        rc, out, err, el = s.run("codex", codex)
        rel = s.records("/v1/ingest")
        s.check("waits: an older tunnel's sent is waited for (codex)", behavior(out).get("behavior") == "allow", out + s.log_text()[-300:])
        s.check("waits: hidden: the relay gets a question without nonce, same rid", rel and rel[0]["body"]["ev"] == "question"
                and "nh" not in rel[0]["body"] and "nonce" not in (rel[0].get("plain_json") or {})
                and rel[0]["body"]["rid"] == tun_ingests("permission")[0]["body"]["rid"]
                and (rel[0].get("plain_json") or {}).get("req", {}).get("wait") == "none", str(rel)[:400])
        s.check("waits: not waited on the relay", not s.records("/v1/decision"), str(s.records("/v1/decision"))[:200])
        # shared: the tunnel's suppressed does not end the relay's wait.
        setup({"push": "suppressed"}, {"decision": "allow", "after": 1})
        rc, out, err, el = s.run("claude", v2_perm(session="sw"))
        s.check("waits: shared: tunnel suppressed, the relay decides", behavior(out).get("behavior") == "allow", out)
        # hidden: no tunnel answer within 5 s -> the relay is decidable, its ingest cut to the time left.
        setup({"ingest_delay": 7}, {"decision": "deny", "after": 1}, conf={"codex_wait": 40})
        rc, out, err, el = s.run("codex", codex)
        rel = s.records("/v1/ingest")
        s.check("waits: hidden: a tunnel that does not answer -> relay decidable", behavior(out).get("behavior") == "deny"
                and rel and rel[0]["body"]["ev"] == "permission" and rel[0]["body"].get("nh"), out + str(rel)[:200])
        # Typically ~7 s (the tunnel's 5 s, then the relay); the bound shows that the decision, not the
        # cap (40 s), ended it (slow under parallel load).
        s.check("waits: hidden: the tunnel's 5 seconds", 5 <= el < 30, "%.2fs" % el)
        setup({"ingest_delay": 7}, {"ingest_delay": 4, "decision": "allow"}, conf={"codex_wait": 6})
        rc, out, err, el = s.run("codex", codex)
        s.check("waits: hidden: the cap counts from the hook's start (relay ingest cut to the time left)",
                out.strip() == "" and el < 10.5 and "http=000" in s.log_text(), "%.2fs %s" % (el, s.log_text()[-300:]))
        # A relay that lost R1: the question again, same rid, without nonce, not waited.
        q = json.dumps({"session_id": "sq", "cwd": "/w", "hook_event_name": "PermissionRequest", "tool_name": "AskUserQuestion",
                        "tool_input": {"questions": [{"question": "Which DB?", "options": [{"label": "A"}]}]}})
        setup({"push": "suppressed"}, {"qdec": False}, conf={"claude_wait": 40})
        rc, out, err, el = s.run("claude", q)
        recs = s.records("/v1/ingest")
        s.check("waits: invalid-nh -> the same rid once more without nonce", len(recs) == 2 and recs[0]["status"] == 400
                and recs[1]["status"] == 200 and recs[0]["body"]["rid"] == recs[1]["body"]["rid"] and "nh" not in recs[1]["body"]
                and "can" not in ((recs[1].get("plain_json") or {}).get("req") or {}), str(recs)[:500])
        s.check("waits: invalid-nh: not waited", out.strip() == "" and el < 30 and not s.records("/v1/decision"), "%.2fs" % el)
    finally:
        tun.terminate()
        tun.wait(5)


def t_v2_not_sent(s):
    """Section 4.6: requests that may never show a prompt are not sent. Copilot permissionRequest: nothing
    and an empty output; Antigravity run_command: only with agy_wait > 0 and when no tunnel answers the
    probe (404 unknown, not shown:false)."""
    if s.kind != "sh":
        return
    s.setup([(LINK_A, {"fmt": 2})])
    rc, out, err, el = s.run("copilot", json.dumps({"hookName": "permissionRequest", "sessionId": "c1", "cwd": "/w", "toolName": "bash",
                                                    "toolInput": {"command": "ls"}, "permissionSuggestions": []}), {"COPILOT_CLI": "1"}, args=("permissionRequest",))
    s.check("not sent: copilot permissionRequest: no event, empty output, exit 0", rc == 0 and out == "" and not s.records(), out + str(s.records())[:200])
    rc, out, err, el = s.run("claude", json.dumps({"hook_event_name": "PermissionRequest", "sessionId": "c1", "toolName": "bash", "toolInput": {"command": "ls"}}),
                             {"COPILOT_CLI": "1"})
    s.check("not sent: the Claude Code plugin under Copilot (COPILOT_CLI=1) does not wait", rc == 0 and out == "" and not s.records() and el < 20, "%r %.2fs" % (out, el))
    agy = json.dumps({"conversationId": "c-1", "workspacePaths": ["/w/a"], "stepIdx": 4, "toolCall": {"name": "run_command", "args": {"CommandLine": "make"}}})
    rc, out, err, el = s.run("agy", agy, args=("PreToolUse",))
    s.check("not sent: agy run_command with agy_wait 0", out.strip() == '{"decision":"allow"}' and not s.records(), out)
    probe = __import__("socket").socket()
    probe.bind(("127.0.0.1", 0))
    closed = probe.getsockname()[1]
    probe.close()
    tun, tctl = s.spawn_mock()
    tun2, tctl2 = s.spawn_mock()
    try:
        for name, opts, sent in (("404 unknown", {}, False), ("404 unknown, shown:true", {"shown": True}, False),
                                 ("shown:false", {"shown": False}, True), ("401", {"decision_http": 401, "decision_error": "unauthorized"}, True),
                                 ("503", {"decision_http": 503, "decision_error": "x"}, True), ("other body", {"unknown_error": "not-found"}, True),
                                 ("slower than 5 s", {"decision_delay": 20}, True), ("connection refused", None, True)):
            url = tctl.url if opts is not None else "http://127.0.0.1:%d" % closed
            s.setup([(LINK_T, {"kind": "tunnel", "relay_url": url, "fmt": 2}), (LINK_A, {"fmt": 2, "push": "disabled"})], conf={"agy_wait": 5})
            if opts is not None:
                tctl("/_ctl/reset", {})
                tctl("/_ctl/config", {"links": {LINK_T["id"]: dict(LINK_T, **dict({"unknown_error": "unknown"}, **opts))}})
            rc, out, err, el = s.run("agy", agy, args=("PreToolUse",))
            got = s.records("/v1/ingest")
            s.check("probe %s: %s" % (name, "sent to the relay" if sent else "not sent"), bool(got) == sent and out.strip() == '{"decision":"allow"}',
                    "%s %.2fs" % (out, el))
            # A probe that is not cut at 5 s takes 20 s here.
            s.check("probe %s: within the 5 s" % name, el < 15, "%.2fs" % el)
        # Three tunnels answering in 4 s each: probed at once (about 4 s), not one after another (12 s).
        link_c = {"id": "17" * 16, "secret": "28" * 32, "enc": "39" * 32, "mac": "4a" * 32, "label": "box-c"}
        tun3, tctl3 = s.spawn_mock()
        s.setup([(LINK_T, {"kind": "tunnel", "relay_url": tctl.url, "fmt": 2}), (LINK_B, {"kind": "tunnel", "relay_url": tctl2.url, "fmt": 2}),
                 (link_c, {"kind": "tunnel", "relay_url": tctl3.url, "fmt": 2}), (LINK_A, {"fmt": 2})], conf={"agy_wait": 5})
        for ctl, link in ((tctl, LINK_T), (tctl2, LINK_B), (tctl3, link_c)):
            ctl("/_ctl/reset", {})
            ctl("/_ctl/config", {"links": {link["id"]: dict(link, unknown_error="unknown", decision_delay=4)}})
        rc, out, err, el = s.run("agy", agy, args=("PreToolUse",))
        tun3.terminate()
        tun3.wait(5)
        s.check("probe: tunnels probed at the same time", not s.records("/v1/ingest") and el < 10, "%.2fs" % el)
    finally:
        for t in (tun, tun2):
            t.terminate()
            t.wait(5)


def t_v2_state(s):
    """Section 6.2: state events go to tunnels only, when the state changed."""
    tun, tctl = s.spawn_mock()
    try:
        s.setup([(LINK_T, {"kind": "tunnel", "relay_url": tctl.url, "fmt": 2}), (LINK_A, {"fmt": 2})])
        tctl("/_ctl/reset", {})
        tctl("/_ctl/config", {"links": {LINK_T["id"]: dict(LINK_T, unknown_error="unknown")}})

        def states():
            return [(r.get("plain_json") or {}) for r in tctl("/_ctl/records")["records"] if r["path"] == "/v1/ingest" and r["body"]["ev"] == "state"]
        ups = json.dumps({"session_id": "st1", "cwd": "/w", "hook_event_name": "UserPromptSubmit", "prompt": "go"})
        s.run("claude", ups)
        wait_for(states, 5)
        s.run("claude", ups)
        time.sleep(2.5)
        st = states()
        s.check("state: running once (same state not sent again)", [x.get("st") for x in st] == ["running"], str(st)[:300])
        s.check("state: not to the relay", not [r for r in s.records("/v1/ingest") if r["body"]["ev"] == "state"])
        # One state a second: a change within the second waits a second, and a newer one replaces it.
        s.run("claude", json.dumps({"session_id": "st1", "cwd": "/w", "hook_event_name": "SubagentStart", "agent_id": "ag1", "agent_type": "explore"}))
        time.sleep(2.2)
        s.run("claude", json.dumps({"session_id": "st1", "cwd": "/w", "hook_event_name": "PostToolUseFailure", "tool_name": "Bash", "is_interrupt": True}))
        time.sleep(2.2)
        s.run("claude", json.dumps({"session_id": "st1", "cwd": "/w", "hook_event_name": "SessionEnd", "reason": "exit"}))
        wait_for(lambda: len(states()) >= 4, 8)
        st = states()
        s.check("state: sub_start with the subagent", [x for x in st if x.get("st") == "sub_start" and x.get("sub") == {"id": "ag1", "type": "explore"}], str(st)[:400])
        s.check("state: idle after an interrupt, turn end interrupt", [x for x in st if x.get("st") == "idle" and (x.get("turn") or {}).get("end") == "interrupt"], str(st)[:400])
        s.check("state: ended", [x for x in st if x.get("st") == "ended"], str(st)[:400])
        s.check("state: no msg in a state event", all("msg" not in x for x in st), str(st)[:300])
    finally:
        tun.terminate()
        tun.wait(5)


def t_v2_sessions(s):
    """Section 8.2: the session records of SimpleTerm sessions."""
    s.setup([(LINK_A, {"push": "disabled"})])
    sd = s.home / ".simpleterm" / "sessions" / "claude-code"
    sid = "872e63d5-f55f-46fa-93db-a0062d1259fb"
    env = {"SIMPLETERM": "1"}
    ev = lambda name, **kw: json.dumps(dict({"session_id": sid, "cwd": "/home/me/api", "hook_event_name": name, "permission_mode": "acceptEdits"}, **kw))
    s.run("claude", ev("UserPromptSubmit", prompt="Run the tests"), env)
    rec = sd / (sid + ".json")
    beat = sd / (sid + ".beat")
    j = json.loads(rec.read_text()) if rec.exists() else {}
    s.check("session: record on a prompt", j.get("sid") == sid and j.get("state") == "running" and j.get("last_prompt") == "Run the tests"
            and j.get("dir") == "/home/me/api" and j.get("pm") == "acceptEdits" and j.get("title") == "Run the tests" and j.get("title_src") == "prompt", str(j))
    s.check("session: modes 700/600", oct(sd.stat().st_mode & 0o777) == "0o700" and oct(rec.stat().st_mode & 0o777) == "0o600")
    old = time.time() - 20
    os.utime(beat, (old, old))
    s.run("claude", ev("PostToolUse", tool_name="Bash", tool_input={"command": "ls"}), env)
    s.check("session: .beat not touched again within 30 s", abs(beat.stat().st_mtime - old) < 1, str(beat.stat().st_mtime - old))
    (s.home / ".simpleterm" / "run" / "sess-v2.beatts").exists()
    bt = s.home / ".simpleterm" / "run" / (sid.replace("-", "-") + ".beatts")
    bt.write_text("%d\n" % (int(time.time()) - 40))
    s.run("claude", ev("PostToolUse", tool_name="Bash", tool_input={"command": "ls"}), env)
    s.check("session: .beat touched when 30 s old", beat.stat().st_mtime > old + 10)
    os.utime(beat, (old, old))
    s.run("claude", ev("UserPromptSubmit", prompt="again"), env)
    s.check("session: a prompt always touches .beat", beat.stat().st_mtime > old + 10)
    s.run("claude", ev("Stop", last_assistant_message="done", stop_hook_active=False), env)
    j = json.loads(rec.read_text())
    s.check("session: idle at the turn's end, first prompt kept as title", j.get("state") == "idle" and j.get("title") == "Run the tests" and j.get("last_prompt") == "again", str(j))
    s.run("claude", ev("SessionEnd", reason="exit"), env)
    s.check("session: .ended at SessionEnd", (sd / (sid + ".ended")).exists())
    s.run("claude", ev("UserPromptSubmit", prompt="resumed"), env)
    s.check("session: a resumed session drops .ended", not (sd / (sid + ".ended")).exists())
    fut = time.time() + 30
    os.utime(beat, (fut, fut))
    s.run("claude", ev("SessionEnd", reason="exit"), env)
    s.check("session: a late SessionEnd (newer .beat) does not mark it ended", not (sd / (sid + ".ended")).exists())
    s.run("claude", json.dumps({"session_id": "s:1", "cwd": "/w", "hook_event_name": "UserPromptSubmit", "prompt": "x"}), env)
    name = hashlib.sha256(b"s:1").hexdigest()[:32]
    s.check("session: an id with ':' -> sha256 name", (sd / (name + ".json")).exists() and json.loads((sd / (name + ".json")).read_text()).get("sid") == "s:1")
    s.run("claude", json.dumps({"session_id": "no-st", "cwd": "/w", "hook_event_name": "UserPromptSubmit", "prompt": "x"}))
    s.check("session: none without SIMPLETERM=1", not (sd / "no-st.json").exists())
    if s.kind == "sh":
        s.run("opencode", json.dumps({"hook_event_name": "UserPromptSubmit", "session_id": "ses_oc2", "cwd": "/w", "oc": "2"}), env)
        s.check("session: none for OpenCode 2.x (D14)", not (s.home / ".simpleterm" / "sessions" / "opencode").exists())
    # Retention (D11): 30 days by the later of .beat and the record, 200 at most.
    for f in sd.iterdir():
        f.unlink()
    now = time.time()
    for i in range(205):
        r = sd / ("r%03d.json" % i)
        r.write_text("{}")
        t = now - 3600 - i * 60
        os.utime(r, (t, t))
    olds = sd / "old.json"
    olds.write_text("{}")
    os.utime(olds, (now - 40 * 86400,) * 2)
    keep = sd / "keep.json"
    keep.write_text("{}")
    os.utime(keep, (now - 40 * 86400,) * 2)
    (sd / "keep.beat").write_text("")
    kf = s.home / ".simpleterm" / "run" / "sessions.keep"
    if kf.exists():
        kf.unlink()
    s.run("claude", ev("UserPromptSubmit", prompt="retention"), env)
    names = {f.name for f in sd.iterdir() if f.name.endswith(".json")}
    s.check("retention: 200 at most, the oldest go", len(names) == 200 and "r204.json" not in names and "r000.json" in names, str(len(names)))
    s.check("retention: an old record with a fresh .beat stays, an old one goes", "keep.json" in names and "old.json" not in names, str(sorted(names)[:5]))


def t_v2_versions(s):
    """Section 10.1: the agent's version where the agent gives none: `--version`, run in the background
    when the executable is new or newer than the cache (D13); the first dotted number is taken."""
    if s.kind != "sh":
        return
    s.setup([(LINK_A, {"push": "disabled"})])
    fake = s.bin / "opencode"
    fake.write_text("#!/bin/sh\necho 'opencode version 1.19.5 (abc)'\n")
    fake.chmod(0o755)
    try:
        stop = json.dumps({"hook_event_name": "Stop", "session_id": "ses_v", "cwd": "/w", "last_assistant_message": "t", "oc": "1"})
        s.run("opencode", stop)
        cache = s.home / ".simpleterm" / "run" / "ver.opencode"
        wait_for(cache.exists, 10)
        s.check("version cache: written in the background", cache.exists() and cache.read_text().split("\n")[1] == "1.19.5",
                cache.read_text() if cache.exists() else "-")
        s.ctl("/_ctl/reset", {})
        s.run("opencode", stop)
        p = (wait_for(lambda: ingests(s, "done"), 10) or [{}])[0].get("plain_json") or {}
        s.check("version cache: av on the next event (relay: no avs)", p.get("av") == "1.19.5" and "avs" not in p, str(p)[:300])
    finally:
        fake.unlink()


def t_v2_claude_question_once(s):
    """Claude Code reports one question twice (PreToolUse, then PermissionRequest): the decidable
    PermissionRequest goes, the PreToolUse report waits ask_delay for it and then goes only alone."""
    s.setup([(LINK_A, {"fmt": 2, "push": "disabled"})], conf={"ask_delay": 2})
    q = {"session_id": "sq1", "cwd": "/w", "tool_name": "AskUserQuestion",
         "tool_input": {"questions": [{"question": "Which DB?", "header": "DB", "options": [{"label": "A"}, {"label": "B"}]}]}}
    s.run("claude", json.dumps(dict(q, hook_event_name="PreToolUse")))
    s.run("claude", json.dumps(dict(q, hook_event_name="PermissionRequest")))
    time.sleep(3.5)
    qs = ingests(s, "question")
    s.check("claude question: one alert, the decidable one", len(qs) == 1 and qs[0]["body"].get("nh") and (qs[0].get("plain_json") or {}).get("req", {}).get("can"),
            str([(r["body"].get("nh"), (r.get("plain_json") or {}).get("req")) for r in qs])[:400])
    s.ctl("/_ctl/reset", {})
    s.run("claude", json.dumps(dict(q, session_id="sq2", hook_event_name="PreToolUse")))
    qs = wait_for(lambda: ingests(s, "question"), 8)
    s.check("claude question: PreToolUse alone still alerts (not decidable)", qs and not qs[0]["body"].get("nh"), str(qs)[:300])


def regen_v2(argv0):
    """Writes tests/fixtures/v2/expected.json from the sh hook (review the diff before committing)."""
    s = Suite("regen", [argv0, str(HOOK_SH)], "/usr/bin/openssl")
    try:
        exp = {}
        for case in v2_cases():
            got, outs = v2_run_case(s, case)
            exp[case["name"]] = {"plain": got, "stdout": [o.strip() for o in outs]}
            print(case["name"], len(got))
        (V2_DIR / "expected.json").write_text(json.dumps(exp, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    finally:
        s.close()


def t_v2_opencode_js(s):
    """Event format v2 through the OpenCode plugins: scope (always), a reason with a rejection, the
    1.19 question routes, the other open requests (section 4.5) and the bridge's pending file."""
    if not NODE or s.kind != "sh":
        return
    d = str(s.tmp)
    ask19 = {"type": "permission.asked", "properties": {"id": "per_1", "sessionID": "ses_1", "permission": "bash", "patterns": ["echo a1"],
                                                       "metadata": {"command": "echo a1"}, "always": ["echo *"], "tool": {"messageID": "msg_1", "callID": "c1"}}}
    s.setup([(LINK_A, {"fmt": 2, "decision": "allow", "after": 1, "dext": {"act": "allow_scope", "scope": 0}})])
    calls = node_plugin(s, "v1", {"directory": d, "raw": True, "steps": [{"event": ask19}], "wait": 30000, "replies": 1})
    s.check("opencode 1.19 v2: allow_scope -> reply always (raw route)",
            replies(calls) == [{"url": "/permission/{requestID}/reply", "path": {"requestID": "per_1"}, "body": {"reply": "always"}}], str(calls)[:400])
    p = (ingests(s, "permission") or [{}])[0].get("plain_json") or {}
    s.check("opencode 1.19 v2: request id, scope pattern, message id", (p.get("req") or {}).get("id") == "per_1"
            and (p.get("req") or {}).get("scopes") == [{"label": "echo *", "kind": "pattern", "dest": "process"}], str(p)[:300])
    s.setup([(LINK_A, {"fmt": 2, "decision": "deny", "after": 1, "dext": {"act": "deny_reason", "reason": "use pnpm"}})])
    calls = node_plugin(s, "v1", {"directory": d, "raw": True, "steps": [{"event": ask19}], "wait": 30000, "replies": 1})
    s.check("opencode 1.19 v2: deny_reason -> reject with the message",
            replies(calls) == [{"url": "/permission/{requestID}/reply", "path": {"requestID": "per_1"}, "body": {"reply": "reject", "message": "use pnpm"}}], str(calls)[:400])
    q = {"type": "question.asked", "properties": {"id": "que_1", "sessionID": "ses_1", "questions": [
        {"question": "Which DB?", "header": "DB", "options": [{"label": "SQLite", "description": "file"}, {"label": "Postgres"}], "multiple": False}]}}
    s.setup([(LINK_A, {"fmt": 2, "decision": "allow", "after": 1, "dext": {"act": "answer", "answers": [{"q": 0, "pick": [1], "text": "v16"}]}})])
    calls = node_plugin(s, "v1", {"directory": d, "raw": True, "steps": [{"event": q}], "wait": 30000, "replies": 1})
    s.check("opencode 1.19 v2: question answer -> /question/{id}/reply",
            replies(calls) == [{"url": "/question/{requestID}/reply", "path": {"requestID": "que_1"}, "body": {"answers": [["Postgres", "v16"]]}}], str(calls)[:400])
    s.setup([(LINK_A, {"fmt": 2, "decision": "deny", "after": 1, "dext": {"act": "deny"}})])
    calls = node_plugin(s, "v1", {"directory": d, "raw": True, "steps": [{"event": q}], "wait": 30000, "replies": 1})
    s.check("opencode 1.19 v2: question deny -> /question/{id}/reject",
            [r.get("url") for r in replies(calls)] == ["/question/{requestID}/reject"], str(calls)[:400])
    # 2.x: two open requests of a session; a decision on the first that the user saw both of.
    s.setup([(LINK_A, {"fmt": 2, "decisions": [{"decision": "deny", "after": 2, "dext": {"act": "deny_reason", "reason": "no", "seen": ["per_9", "per_10"]}}]})])
    ask = lambda rid, eid: {"id": eid, "type": "permission.asked", "location": {"directory": d},
                            "data": {"id": rid, "sessionID": "ses_9", "action": "shell", "resources": ["npm run build"], "save": ["npm *"]}}
    calls = node_plugin(s, "v2", {"directory": d, "steps": [{"event": ask("per_9", "e1")}, {"event": ask("per_10", "e2")}], "wait": 30000, "replies": 1})
    rs = replies(calls)
    s.check("opencode 2.x v2: deny_reason with every open request seen -> reject with the reason",
            rs[:1] == [{"sessionID": "ses_9", "requestID": "per_9", "decision": "reject", "message": "no"}], str(calls)[:400])
    reqs = [(r.get("plain_json") or {}).get("req") for r in ingests(s, "permission")]
    s.check("opencode 2.x v2: the second request names the first as another open one",
            any(r and r.get("id") == "per_10" and r.get("others") == ["per_9"] for r in reqs), str(reqs)[:400])


def t_opencode_js(s):
    """The OpenCode plugins themselves (node with fake OpenCode objects; skipped without node)."""
    if not NODE or s.kind != "sh":
        return
    d = str(s.tmp)
    # --- 1.x ---
    s.setup([(LINK_A, {"decision": "allow", "after": 1})])
    ask19 = {"type": "permission.asked", "properties": {"id": "per_1", "sessionID": "ses_1", "permission": "bash",
                                                       "patterns": ["npm test"], "metadata": {"command": "npm test"}, "always": []}}
    calls = node_plugin(s, "v1", {"directory": d, "steps": [{"event": ask19}], "wait": 30000, "replies": 1})
    s.check("opencode 1.x: only function exports", calls and calls[0].get("exports") == [["SimpleTermAgentHooks", "function"]], str(calls)[:300])
    s.check("opencode 1.x: device allow -> once", replies(calls) == [{"path": {"id": "ses_1", "permissionID": "per_1"},
                                                                       "body": {"response": "once"}}], str(calls)[:300])
    rec = ingests(s, "permission")
    s.check("opencode 1.x: request text", rec and rec[0]["plain_json"].get("msg") == "approve bash: npm test", str(rec)[:200])
    s.setup([(LINK_A, {"decision": "deny", "after": 1})])
    ask10 = {"type": "permission.updated", "properties": {"id": "per_2", "sessionID": "ses_1", "type": "bash", "pattern": "make",
                                                         "title": "make deploy", "metadata": {"command": "make deploy"}}}
    calls = node_plugin(s, "v1", {"directory": d, "steps": [{"event": ask10}], "wait": 30000, "replies": 1})
    s.check("opencode 1.0 permission.updated: device deny -> reject",
            [r["body"]["response"] for r in replies(calls)] == ["reject"], str(calls)[:300])
    s.setup([(LINK_A, {})], conf={"opencode_wait": 60})
    calls = node_plugin(s, "v1", {"directory": d, "steps": [
        {"event": ask19}, {"sleep": 3000},
        {"event": {"type": "permission.replied", "properties": {"sessionID": "ses_1", "requestID": "per_1", "reply": "once"}}}],
        "wait": 3000})
    s.check("opencode 1.x: answered in the terminal -> no reply, wait ends", not replies(calls)
            and wait_for(lambda: "permission signal" in s.log_text(), 5), str(calls)[:200] + s.log_text()[-200:])
    s.setup([(LINK_A, {"push": "disabled"})])
    calls = node_plugin(s, "v1", {"directory": d, "sessions": {"ses_1": {"title": "Fix the tests"}, "ses_sub": {"parentID": "ses_1"}},
                                  "steps": [{"event": {"type": "session.idle", "properties": {"sessionID": "ses_1"}}},
                                            {"event": {"type": "session.idle", "properties": {"sessionID": "ses_sub"}}}], "wait": 3000})
    rec = wait_for(lambda: ingests(s, "done"), 20)
    time.sleep(1)
    s.check("opencode 1.x: session.idle -> done with the session title, subagents skipped",
            len(ingests(s, "done")) == 1 and rec[0]["plain_json"].get("msg") == "Fix the tests", str(ingests(s))[:300])
    # 1.19.5 with OPENCODE_EXPERIMENTAL_BACKGROUND_SUBAGENTS (measured with a
    # local model stub): the parent goes idle while its background child is
    # busy; the child's report wakes the parent, which goes idle again.
    s.setup([(LINK_A, {"push": "disabled"})])

    def st(sid, kind):
        return {"event": {"type": "session.status", "properties": {"sessionID": sid, "status": {"type": kind}}}}

    def idle(sid):
        return {"event": {"type": "session.idle", "properties": {"sessionID": sid}}}

    t0 = time.time()
    node_plugin(s, "v1", {"directory": d, "sessions": {"ses_1": {"title": "Fix the tests"}, "ses_bg": {"parentID": "ses_1"}},
                          "steps": [st("ses_1", "busy"), st("ses_bg", "busy"), st("ses_1", "idle"), idle("ses_1"), {"sleep": 2500},
                                    st("ses_bg", "idle"), idle("ses_bg"), st("ses_1", "busy"), st("ses_1", "idle"), idle("ses_1")],
                          "wait": 3000})
    wait_for(lambda: ingests(s, "done"), 20)
    time.sleep(1)
    done = ingests(s, "done")
    s.check("opencode 1.x: no done while a background child is busy, then once",
            len(done) == 1 and done[0]["received"] - t0 > 2.0,
            str([(r["plain_json"].get("msg"), round(r["received"] - t0, 2)) for r in done]))
    # An errored child is not busy any more: it must not hold the parent's done back for good.
    s.setup([(LINK_A, {"push": "disabled"})])
    t0 = time.time()
    node_plugin(s, "v1", {"directory": d, "sessions": {"ses_1": {"title": "Fix the tests"}, "ses_bg": {"parentID": "ses_1"}},
                          "steps": [st("ses_1", "busy"), st("ses_bg", "busy"), st("ses_1", "idle"), idle("ses_1"), {"sleep": 800},
                                    {"event": {"type": "session.error", "properties": {"sessionID": "ses_bg",
                                                                                        "error": {"name": "APIError", "data": {"message": "x"}}}}},
                                    idle("ses_1")],
                          "wait": 2500})
    wait_for(lambda: ingests(s, "done"), 20)
    time.sleep(1)
    s.check("opencode 1.x: a child that errored does not hold the parent's done back",
            len(ingests(s, "done")) == 1, str([(r["plain_json"].get("msg")) for r in ingests(s)]))
    # --- 2.x ---
    s.setup([(LINK_A, {"decision": "allow", "after": 1})])
    ask2 = {"id": "evt_1", "type": "permission.asked", "created": 1, "location": {"directory": d},
            "data": {"id": "per_9", "sessionID": "ses_9", "action": "shell", "resources": ["npm run build"]}}
    other = dict(ask2, id="evt_2", location={"directory": "/somewhere/else"}, data=dict(ask2["data"], id="per_x"))
    calls = node_plugin(s, "v2", {"directory": d, "steps": [{"event": ask2}, {"event": ask2}, {"event": other}], "wait": 30000,
                                  "replies": 1})
    s.check("opencode 2.x: plugin shape and events", calls and calls[0] == {"id": "simpleterm", "setup": "function"}
            and "permission.asked" in (calls[1].get("subscribed") or []), str(calls)[:300])
    s.check("opencode 2.x: device allow -> once (once per event, own directory only)",
            replies(calls) == [{"sessionID": "ses_9", "requestID": "per_9", "decision": "once"}], str(calls)[:400])
    rec = ingests(s, "permission")
    s.check("opencode 2.x: one request", len(rec) == 1 and rec[0]["plain_json"].get("msg") == "approve shell: npm run build", str(rec)[:200])
    s.setup([(LINK_A, {"push": "disabled"})])
    calls = node_plugin(s, "v2", {"directory": d, "sessions": {"ses_9": {"title": "Ship it"}}, "steps": [
        {"event": {"id": "evt_3", "type": "session.execution.succeeded", "location": {"directory": d}, "data": {"sessionID": "ses_9"}}},
        {"event": {"id": "evt_4", "type": "session.execution.failed", "location": {"directory": d},
                   "data": {"sessionID": "ses_9", "error": {"type": "provider", "message": "overloaded"}}}}], "wait": 3000})
    s.check("opencode 2.x: succeeded -> done, failed -> error",
            wait_for(lambda: ingests(s, "done") and ingests(s, "error"), 20)
            and ingests(s, "done")[0]["plain_json"].get("msg") == "Ship it"
            and ingests(s, "error")[0]["plain_json"].get("msg") == "provider: overloaded", str(ingests(s))[:300])
    # An input form: data is {form: {id, sessionID, title, fields}} (OpenCode 2.x schema, form.ts).
    s.setup([(LINK_A, {"push": "disabled"})])
    form = {"id": "evt_5", "type": "form.created", "location": {"directory": d},
            "data": {"form": {"id": "frm_1", "sessionID": "ses_9", "title": "Pick a database",
                              "fields": [{"type": "string", "key": "db", "title": "Database"}]}}}
    node_plugin(s, "v2", {"directory": d, "steps": [{"event": form}], "wait": 3000})
    rec = wait_for(lambda: ingests(s, "question"), 20)
    s.check("opencode 2.x: form.created -> question with the form's title",
            rec and rec[0]["plain_json"].get("msg") == "Pick a database", str(ingests(s))[:300])

    # A running subagent's report wakes its parent again: no done until the
    # parent ends with no direct child running (as the OpenCode TUI counts).
    def ev(n, typ, sid, **data):
        return {"event": {"id": "evt_%d" % n, "type": typ, "location": {"directory": d}, "data": dict(sessionID=sid, **data)}}

    sess = {"ses_r": {"title": "Ship it"}, "ses_c": {"parentID": "ses_r"}, "ses_g": {"parentID": "ses_c"}}
    for name, steps in (
        ("execution events", [ev(10, "session.execution.started", "ses_r"), ev(11, "session.execution.started", "ses_c"),
                              ev(12, "session.execution.succeeded", "ses_r"), {"sleep": 2500},
                              ev(13, "session.execution.succeeded", "ses_c"), ev(14, "session.execution.started", "ses_r"),
                              ev(15, "session.execution.succeeded", "ses_r")]),
        ("session.status", [ev(20, "session.status", "ses_c", status={"type": "busy"}), ev(21, "session.execution.succeeded", "ses_r"),
                            {"sleep": 2500}, ev(22, "session.status", "ses_c", status={"type": "idle"}),
                            ev(23, "session.execution.started", "ses_g"), ev(24, "session.execution.succeeded", "ses_r")]),
    ):
        s.setup([(LINK_A, {"push": "disabled"})])
        t0 = time.time()
        node_plugin(s, "v2", {"directory": d, "sessions": sess, "steps": steps, "wait": 3000})
        wait_for(lambda: ingests(s, "done"), 20)
        time.sleep(1)
        done = ingests(s, "done")
        s.check("opencode 2.x: done waits for a running subagent, then comes once (%s)" % name,
                len(done) == 1 and done[0]["plain_json"].get("msg") == "Ship it" and done[0]["received"] - t0 > 2.0,
                str([(r["plain_json"].get("msg"), round(r["received"] - t0, 2)) for r in done]))

    # A background shell (`shell {background: true}`, measured on 2.2.5 with a
    # local model stub): the turn ends while it runs, its exit starts the
    # session again, and only that turn's end is done.
    def shell_ev(n, typ, **data):
        return {"event": {"id": "evt_%d" % n, "type": typ, "location": {"directory": d}, "data": data}}

    for name, owner in (("the session's own shell", "ses_r"), ("a subagent's shell", "ses_c")):
        s.setup([(LINK_A, {"push": "disabled"})])
        t0 = time.time()
        steps = [ev(40, "session.execution.started", "ses_r"),
                 shell_ev(41, "shell.created", info={"id": "sh_1", "status": "running", "command": "sleep 25",
                                                     "metadata": {"sessionID": owner}}),
                 ev(42, "session.execution.succeeded", "ses_r"), {"sleep": 2500},
                 shell_ev(43, "shell.exited", id="sh_1", exit=0, status="exited"),
                 ev(44, "session.execution.started", "ses_r"), ev(45, "session.execution.succeeded", "ses_r")]
        node_plugin(s, "v2", {"directory": d, "sessions": sess, "steps": steps, "wait": 3000})
        wait_for(lambda: ingests(s, "done"), 20)
        time.sleep(1)
        done = ingests(s, "done")
        s.check("opencode 2.x: no done while a background shell runs, then once (%s)" % name,
                len(done) == 1 and done[0]["received"] - t0 > 2.0,
                str([(r["plain_json"].get("msg"), round(r["received"] - t0, 2)) for r in done]))

    # A background shell that never exits holds nothing back: the hook decides from the open shells.
    def running_turns(name, shell_cmd, turns, conf=None):
        s.setup([(LINK_A, {"push": "disabled"})], conf=conf)
        steps = [ev(60, "session.execution.started", "ses_r"),
                 shell_ev(61, "shell.created", info={"id": "sh_9", "status": "running", "command": shell_cmd,
                                                     "metadata": {"sessionID": "ses_r"}}),
                 ev(62, "session.execution.succeeded", "ses_r")]
        if turns > 1:
            steps += [{"sleep": 500}, ev(63, "session.execution.started", "ses_r"), ev(64, "session.execution.succeeded", "ses_r")]
        t0 = time.time()
        node_plugin(s, "v2", {"directory": d, "sessions": sess, "steps": steps, "wait": 3000})
        return t0

    t0 = running_turns("dev server, two turns", "npm run dev", 2)
    wait_for(lambda: len(ingests(s, "done")) >= 2, 20)
    done = ingests(s, "done")
    s.check("opencode 2.x: a dev server left open does not block the done, of any turn",
            len(done) == 2 and all(r["plain_json"].get("msg") == "Ship it (still running in the background: shell: npm run dev)" for r in done),
            str([(r["plain_json"].get("msg"), round(r["received"] - t0, 2)) for r in done]))
    t0 = running_turns("unknown shell, never exits", "node worker.js", 1, conf={"bg_done_after": 2})
    rec = wait_for(lambda: ingests(s, "done"), 20)
    s.check("opencode 2.x: a shell that never exits -> done after bg_done_after, saying what runs",
            rec and rec[0]["received"] - t0 > 1.5
            and rec[0]["plain_json"].get("msg") == "Ship it (still running in the background: shell: node worker.js)",
            str([(r["plain_json"].get("msg"), round(r["received"] - t0, 2)) for r in ingests(s, "done")]))
    # A turn that starts after the pause and runs longer than bg_done_after is not announced done meanwhile.
    s.setup([(LINK_A, {"push": "disabled"})], conf={"bg_done_after": 2})
    t0 = time.time()
    node_plugin(s, "v2", {"directory": d, "sessions": sess, "wait": 3000, "steps": [
        ev(70, "session.execution.started", "ses_r"),
        shell_ev(71, "shell.created", info={"id": "sh_7", "status": "running", "command": "node worker.js", "metadata": {"sessionID": "ses_r"}}),
        ev(72, "session.execution.succeeded", "ses_r"), {"sleep": 500},
        ev(73, "session.execution.started", "ses_r"), {"sleep": 3500}, ev(74, "session.execution.succeeded", "ses_r")]})
    wait_for(lambda: ingests(s, "done"), 20)
    time.sleep(2.5)
    done = ingests(s, "done")
    s.check("opencode 2.x: a long turn after a pause gets no done before its own end",
            len(done) == 1 and done[0]["received"] - t0 > 3.5, str([(r["plain_json"].get("msg"), round(r["received"] - t0, 2)) for r in done]))
    # (bg_done_after 10: "at once" means well before the first pause's timer; generous for a loaded machine)
    t0 = running_turns("unknown shell, second turn", "node worker.js", 2, conf={"bg_done_after": 10})
    wait_for(lambda: ingests(s, "done"), 20)
    first = ingests(s, "done")
    time.sleep(max(0, t0 + 12.5 - time.time()))
    done = ingests(s, "done")
    s.check("opencode 2.x: the second turn with the same open shell is done at once (once, the old wait is over)",
            len(first) == 1 and first[0]["received"] - t0 < 9 and len(done) == 1,
            str([(r["plain_json"].get("msg"), round(r["received"] - t0, 2)) for r in done]))

    # Lane jobs: a hung lookup does not hold later events of the session for good, and a permission request
    # waits for the turn events that came before it (a late turn start would end its wait as answered locally).
    s.setup([(LINK_A, {"push": "disabled"})])
    node_plugin(s, "v2", {"directory": d, "sessions": {"ses_h": {"title": "Hung"}}, "wait": 4000,
                          "env": {"SIMPLETERM_LANE_TIMEOUT_MS": "800"}, "getDelay": {"ses_h": {"ms": 60000, "times": 1}},
                          "steps": [ev(80, "session.execution.started", "ses_h"), ev(81, "session.execution.succeeded", "ses_h")]})
    rec = wait_for(lambda: ingests(s, "done"), 20)
    s.check("opencode 2.x: a hung session lookup times out, the next turn event goes on", rec and rec[0]["plain_json"].get("msg") == "Hung",
            str(ingests(s))[:200])
    # The job the lane gave up on does nothing when its lookup comes back late: no late UserPromptSubmit (it
    # would undo the pause of a later Stop; only that hook writes <session>.turn), no late Stop.
    run_dir = s.home / ".simpleterm" / "run"
    s.setup([(LINK_A, {"push": "disabled"})])
    node_plugin(s, "v2", {"directory": d, "sessions": {"ses_h": {"title": "Late"}}, "wait": 5000,
                          "env": {"SIMPLETERM_LANE_TIMEOUT_MS": "600"}, "getDelay": {"ses_h": {"ms": 2500, "times": 1}},
                          "steps": [ev(82, "session.execution.started", "ses_h"), ev(83, "session.execution.succeeded", "ses_h")]})
    rec = wait_for(lambda: ingests(s, "done"), 20)
    time.sleep(1)
    s.check("opencode 2.x: the start the lane gave up on sends nothing when its lookup returns late",
            len(rec) == 1 and not (run_dir / "ses_h.turn").exists(), str(rec)[:200] + str(list(run_dir.glob("ses_h*"))))
    s.setup([(LINK_A, {"push": "disabled"})])
    node_plugin(s, "v2", {"directory": d, "sessions": {"ses_g": {"title": "Late stop"}}, "wait": 5000,
                          "env": {"SIMPLETERM_LANE_TIMEOUT_MS": "600"}, "getDelay": {"ses_g": {"ms": 2500, "times": 1}},
                          "steps": [ev(84, "session.execution.succeeded", "ses_g"), ev(85, "session.execution.started", "ses_g")]})
    s.check("opencode 2.x: the Stop the lane gave up on sends nothing when its lookup returns late",
            not ingests(s, "done") and (run_dir / "ses_g.turn").exists(), str(ingests(s))[:200] + str(list(run_dir.glob("ses_g*"))))
    # A hook the lane gave up on is stopped: a fake `sh` (first in PATH) that waits and notes its SIGTERM.
    fake = s.tmp / "fakebin"
    fake.mkdir(exist_ok=True)
    mark = s.tmp / "fake-sh-killed"
    mark.unlink(missing_ok=True)
    (fake / "sh").write_text("#!/bin/sh\ntrap 'echo killed >\"$SIMPLETERM_FAKE_MARK\"; exit 0' TERM\n"
                             "i=0; while [ $i -lt 100 ]; do /bin/sleep 0.2; i=$((i+1)); done\n")
    (fake / "sh").chmod(0o755)
    s.setup([(LINK_A, {"push": "disabled"})])
    node_plugin(s, "v2", {"directory": d, "sessions": {"ses_k": {}}, "wait": 2500,
                          "env": {"SIMPLETERM_LANE_TIMEOUT_MS": "600", "SIMPLETERM_FAKE_MARK": str(mark),
                                  "PATH": str(fake) + os.pathsep + os.environ.get("PATH", "/usr/bin:/bin")},
                          "steps": [ev(86, "session.execution.started", "ses_k")]})
    s.check("opencode 2.x: a hook the lane gave up on is stopped (SIGTERM)", mark.exists(), "no mark: the hook was left running")
    # A permission request answered while it still waits on its session lane is dropped, not sent.
    s.setup([(LINK_A, {"decision": "allow", "after": 1})])
    ask_r = {"id": "evt_95", "type": "permission.asked", "location": {"directory": d},
             "data": {"id": "per_95", "sessionID": "ses_r2", "action": "shell", "resources": ["make"]}}
    replied_r = {"id": "evt_96", "type": "permission.replied", "data": {"sessionID": "ses_r2", "requestID": "per_95", "reply": "once"}}
    calls = node_plugin(s, "v2", {"directory": d, "sessions": {"ses_r2": {}}, "wait": 3500,
                                  "getDelay": {"ses_r2": {"ms": 1500, "times": 1}},
                                  "steps": [ev(94, "session.execution.started", "ses_r2"), {"event": ask_r}, {"event": replied_r}]})
    s.check("opencode 2.x: a request answered while it waited on the lane is not sent",
            not ingests(s, "permission") and not replies(calls), str(ingests(s))[:200] + str(calls)[:200])
    s.setup([(LINK_A, {"decision": "allow", "after": 1})])
    ask_p = {"id": "evt_90", "type": "permission.asked", "location": {"directory": d},
             "data": {"id": "per_90", "sessionID": "ses_p", "action": "shell", "resources": ["make"]}}
    t0 = time.time()
    node_plugin(s, "v2", {"directory": d, "sessions": {"ses_p": {}}, "wait": 30000, "replies": 1,
                          "getDelay": {"ses_p": {"ms": 1500, "times": 1}},
                          "steps": [ev(91, "session.execution.started", "ses_p"), {"event": ask_p}]})
    rec = ingests(s, "permission")
    s.check("opencode 2.x: a permission request waits for the session's earlier turn events",
            rec and rec[0]["received"] - t0 >= 1.3, str([round(r["received"] - t0, 2) for r in rec]))

    # Two instances (two project directories): an answer without a location
    # still ends the wait in the instance that waits, whichever sees it first.
    s.setup([(LINK_A, {})], conf={"opencode_wait": 60})
    ask = {"id": "evt_30", "type": "permission.asked", "location": {"directory": d},
           "data": {"id": "per_30", "sessionID": "ses_30", "action": "shell", "resources": ["make deploy"]}}
    replied = {"id": "evt_31", "type": "permission.replied", "data": {"sessionID": "ses_30", "requestID": "per_30", "reply": "once"}}
    calls = node_plugin(s, "v2", {"directory": d, "instances": [str(s.tmp / "other-project"), d],
                                  "steps": [{"event": ask}, {"sleep": 3000}, {"event": replied}], "wait": 6000})
    stamps = {}
    for line in s.log_text().splitlines():
        for key in ("ingest ev=permission", "permission signal"):
            if key in line and key not in stamps:
                stamps[key] = time.mktime(time.strptime(line.split()[0], "%Y-%m-%dT%H:%M:%SZ"))
    took = stamps.get("permission signal", 1e12) - stamps.get("ingest ev=permission", 0)
    s.check("opencode 2.x: an answer without a location ends the wait in the waiting instance",
            not replies(calls) and took < 6, "%.0fs %s" % (took, s.log_text()[-300:]))


COPIES = [
    ("plugins/opencode/agent-hook.sh", "plugins/simpleterm/scripts/agent-hook.sh"),
    ("plugins/opencode-v1/simpleterm-agent-hook.sh", "plugins/simpleterm/scripts/agent-hook.sh"),
    ("plugins/antigravity/scripts/agent-hook.sh", "plugins/simpleterm/scripts/agent-hook.sh"),
    ("plugins/antigravity/scripts/simpleterm-notify.sh", "plugins/simpleterm/scripts/simpleterm-notify.sh"),
    ("plugins/antigravity/scripts/statusline-tap.sh", "plugins/simpleterm/scripts/statusline-tap.sh"),
    ("plugins/copilot/scripts/agent-hook.sh", "plugins/simpleterm/scripts/agent-hook.sh"),
    ("plugins/copilot/scripts/simpleterm-notify.sh", "plugins/simpleterm/scripts/simpleterm-notify.sh"),
]


MANIFESTS = ["plugins/simpleterm/.claude-plugin/plugin.json", "plugins/simpleterm/.codex-plugin/plugin.json",
             "gemini-extension.json", "plugins/antigravity/plugin.json", "plugins/opencode/package.json",
             "plugins/copilot/plugin.json"]


def versions_check():
    """Every manifest and both hook scripts name the same release (the scripts' constant decides
    when ~/.simpleterm/bin/simpleterm moves to an updated plugin)."""
    import re
    found = {m: json.loads((ROOT / m).read_text()).get("version") for m in MANIFESTS}
    for path, pat in (("plugins/simpleterm/scripts/agent-hook.sh", r"^HOOK_VERSION=([0-9.]+)$"),
                      ("plugins/simpleterm/scripts/agent-hook.ps1", r"^\$HookVersion = '([0-9.]+)'$")):
        m = re.search(pat, (ROOT / path).read_text(), re.M)
        found[path] = m.group(1) if m else None
    want = found[MANIFESTS[0]]
    return ["%s has version %s, %s has %s" % (k, v, MANIFESTS[0], want) for k, v in found.items() if v != want]


def copies_check():
    """Plugins that are installed on their own carry copies of the scripts; they must not drift."""
    bad = []
    for copy, master in COPIES:
        a, b = ROOT / copy, ROOT / master
        if not a.exists() or a.read_bytes() != b.read_bytes():
            bad.append("%s differs from %s (cp %s %s)" % (copy, master, master, copy))
    return bad


TESTS = [t_vectors, t_background, t_allow_deny, t_codex_allow, t_invalid_dmac, t_timeout, t_multi_link,
         t_tunnel, t_revoked, t_missing_deps, t_simpleterm_gating, t_local_answer, t_same_second_prompt, t_notifications, t_background_work, t_background_work_kinds, t_background_work_7501, t_question_while_background, t_service_shells, t_user_prompt_old_tasks, t_schedules, t_done_delay, t_background_events_and_badges, t_small_audit_fixes, t_codex_goal, t_agent_gone, t_events,
         t_hostile_input, t_log, t_argv, t_external_printf,
         t_usage_claude, t_usage_window, t_usage_claude_big, t_usage_claude_huge, t_usage_statusline, t_usage_relay_policy, t_usage_delivery, t_usage_codex, t_codex_hooks, t_gemini, t_notify,
         t_cli_wrapper, t_notify_no_tty, t_agy, t_agy_paths, t_grok, t_opencode_sh, t_opencode_js,
         t_v2_fixtures, t_v2_dext_vector, t_v2_decisions, t_v2_n10, t_v2_link_results, t_v2_link_waits, t_v2_not_sent,
         t_v2_state, t_v2_sessions, t_v2_opencode_js, t_copilot_hooks, t_copilot,
         t_v2_versions, t_v2_claude_question_once]

# Tests of the sh hook only (scripts and behaviour the PowerShell hook does not have).
SH_ONLY = {"t_v2_versions", "t_v2_n10", "t_v2_opencode_js", "t_copilot_hooks", "t_copilot", "t_usage_claude_big", "t_usage_claude_huge", "t_codex_hooks", "t_usage_delivery", "t_usage_statusline", "t_usage_relay_policy", "t_gemini", "t_notify", "t_notify_no_tty", "t_cli_wrapper",
           "t_agy", "t_agy_paths", "t_opencode_sh", "t_opencode_js"}


# PowerShell 7-only syntax and APIs that Windows PowerShell 5.1 (.NET Framework 4.5+) lacks.
PS7_ONLY = [
    (r"\?\?", "null-coalescing ??"), (r"\?\.", "null-conditional ?."), (r"&&|\|\|", "pipeline chain && / ||"),
    (r"\s\?\s[^:]*\s:\s", "ternary ?:"), (r"-AsHashtable", "ConvertFrom-Json -AsHashtable"),
    (r"-Parallel", "ForEach-Object -Parallel"), (r"\$Is(Windows|Linux|MacOS)\b", "$IsWindows/$IsLinux/$IsMacOS"),
    (r"utf8NoBOM|utf8BOM", "-Encoding utf8NoBOM"), (r"(To|From)HexString", "Convert.ToHexString"),
    (r"-Skip(HttpErrorCheck|CertificateCheck)", "Invoke-WebRequest -Skip*"), (r"Invoke-(RestMethod|WebRequest)", "web cmdlets (behave differently in 5.1)"),
    (r"\bclean\s*\{", "clean block"), (r"Get-Error|Test-Json", "PS 6+ cmdlet"), (r"ToUnixTime", "DateTimeOffset.ToUnixTime* (.NET 4.6)"),
    (r"System\.Net\.Http\.", "System.Net.Http namespace (needs Add-Type in 5.1)"), (r"\bAesGcm\b", "AesGcm (.NET Core 3+)"),
]


def ps51_static_check():
    """Returns a list of problems; the PowerShell hook must run on Windows PowerShell 5.1."""
    import re
    problems = []
    raw = HOOK_PS1.read_bytes()
    try:
        raw.decode("ascii")
    except UnicodeDecodeError as e:
        problems.append("non-ASCII byte at %d (5.1 reads BOM-less scripts as ANSI)" % e.start)
    for no, line in enumerate(raw.decode("utf-8", "replace").splitlines(), 1):
        code = line.split("#", 1)[0] if line.lstrip().startswith("#") else line
        code = re.sub(r"'[^']*'", "''", code)  # ignore single-quoted strings
        for pat, what in PS7_ONLY:
            if re.search(pat, code):
                problems.append("line %d: %s: %s" % (no, what, line.strip()))
    return problems


def ps_parse_check(pwsh):
    script = ("$e=$null;$t=$null;[void][System.Management.Automation.Language.Parser]::ParseFile('%s',[ref]$t,[ref]$e);"
              "$e | ForEach-Object { $_.Extent.StartLineNumber.ToString() + ': ' + $_.Message }") % HOOK_PS1
    out = subprocess.run([pwsh, "-NoProfile", "-NonInteractive", "-Command", script], capture_output=True, text=True, timeout=60)
    return [l for l in out.stdout.splitlines() if l.strip()]


def run_suite(suite, only):
    for t in TESTS:
        if only and t.__name__ not in only:
            continue
        if suite.kind == "ps1" and (t is t_missing_deps or t.__name__ in SH_ONLY):
            continue
        try:
            t(suite)
        except Exception as e:  # report and continue with the next case
            suite.check("%s raised" % t.__name__, False, repr(e))


def run_in_own_group(run):
    """Runs `run()` (the suites) in a child that leads its own process group, then stops that
    group: every hook the suites start, and the background sends they leave sleeping
    (bg_done_after waits up to 600 s), belong to it, so a finished run leaves nothing behind.
    Only the child's group is touched: this process may share its group with others (a
    `python run_tests.py | tail` under job control), and it stays in the terminal's group
    (Ctrl+C reaches it). Returns the child's exit code."""
    sys.stdout.flush()
    sys.stderr.flush()
    pid = os.fork()
    if pid == 0:
        try:
            os.setpgid(0, 0)
        except OSError:
            pass
        code = 1
        try:
            run()
        except SystemExit as e:
            code = e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
        except BaseException:
            import traceback
            traceback.print_exc()
        finally:
            sys.stdout.flush()
            sys.stderr.flush()
            os._exit(code)
    try:
        os.setpgid(pid, pid)  # whichever of parent and child gets there first
    except OSError:
        pass
    code = 1
    try:
        _, status = os.waitpid(pid, 0)
        code = os.waitstatus_to_exitcode(status) if hasattr(os, "waitstatus_to_exitcode") else (status >> 8)
    except KeyboardInterrupt:
        code = 130
    finally:
        old = signal.signal(signal.SIGTERM, signal.SIG_IGN)
        try:
            os.killpg(pid, signal.SIGTERM)
        except OSError:
            pass
        finally:
            signal.signal(signal.SIGTERM, old)
        try:
            os.waitpid(pid, os.WNOHANG)
        except OSError:
            pass
    return code


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--shell", action="append", help="shell to run agent-hook.sh with (repeatable)")
    ap.add_argument("--pwsh", help="pwsh executable to run agent-hook.ps1 with")
    ap.add_argument("--only", action="append", help="test function name (repeatable)")
    ap.add_argument("--no-sh", action="store_true")
    ap.add_argument("--hook", help="sh hook to test instead of the plugin's (e.g. an older release)")
    ap.add_argument("--regen-v2", action="store_true", help="write tests/fixtures/v2/expected.json from the sh hook and exit")
    args = ap.parse_args()
    global HOOK_SH, SCRIPTS
    if args.hook:
        HOOK_SH = Path(args.hook).resolve()
        SCRIPTS = HOOK_SH.parent
    if args.regen_v2:
        regen_v2((args.shell or ["/bin/dash"])[0])
        sys.exit(0)

    suites = []
    if not args.no_sh:
        shells = args.shell or [p for p in ("/bin/dash", "/bin/bash", "/bin/zsh", "/bin/ksh", "/bin/sh") if os.path.exists(p)]
        openssls = [("libressl", "/usr/bin/openssl")]
        for cand in ("/opt/homebrew/bin/openssl", "/usr/local/bin/openssl"):
            if os.path.exists(cand):
                openssls.append(("openssl3", cand))
                break
        for sh in shells:
            for oname, opath in openssls:
                suites.append(Suite("%s+%s" % (sh, oname), [sh, str(HOOK_SH)], opath))
    if args.pwsh:
        suites.append(Suite("pwsh", [args.pwsh, "-NoProfile", "-NonInteractive", "-File", str(HOOK_PS1)], None, "ps1"))

    failed = 0
    copies = copies_check()
    print("== script copies: %s" % ("ok" if not copies else "%d differ" % len(copies)))
    for p in copies:
        print("   FAIL " + p)
    failed += len(copies)
    versions = versions_check()
    print("== versions: %s" % ("ok" if not versions else "%d differ" % len(versions)))
    for p in versions:
        print("   FAIL " + p)
    failed += len(versions)
    static = ps51_static_check()
    print("== PowerShell 5.1 static check: %s" % ("ok" if not static else "%d problem(s)" % len(static)))
    for p in static:
        print("   FAIL " + p)
    failed += len(static)
    if args.pwsh:
        parse = ps_parse_check(args.pwsh)
        print("== PowerShell parse (%s): %s" % (args.pwsh, "ok" if not parse else "errors"))
        for p in parse:
            print("   FAIL " + p)
        failed += len(parse)

    threads = [threading.Thread(target=run_suite, args=(s, args.only)) for s in suites]
    for th in threads:
        th.start()
    for th in threads:
        th.join()

    for s in suites:
        bad = [r for r in s.results if not r[1]]
        print("== %s: %d/%d passed" % (s.name, len(s.results) - len(bad), len(s.results)))
        for name, ok, detail in bad:
            print("   FAIL %s :: %s" % (name, detail[:400]))
        failed += len(bad)
        s.close()
    print("TOTAL FAILURES:", failed)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    sys.exit(run_in_own_group(main))
