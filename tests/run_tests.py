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
import hashlib
import json
import os
import pty
import select
import shutil
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
    "mkdir", "chmod", "find", "sleep", "cat", "dd", "ls", "ps", "printf",
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
            text = "\n".join(lines + [""])
            p = st / "links" / (link["id"] + ".conf")
            p.write_text(text)
            p.chmod(0o600)
            cfg[link["id"]] = dict(link, **opts)
        conf_lines = ["poll_wait=2"] + ["%s=%s" % kv for kv in (conf or {}).items()]
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
            env["PATH"] = os.environ.get("PATH", "/usr/bin:/bin")
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

def t_vectors(s):
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
    s.check("vectors: ct", body["env"]["ct"] == V_CT, body["env"]["ct"])
    s.check("vectors: mac", body["env"]["mac"] == V_ENV_MAC, body["env"]["mac"])
    s.check("vectors: iv", body["env"]["iv"] == V_IV)
    s.check("vectors: nh", body.get("nh") == V_NH, body.get("nh"))
    s.check("vectors: rid/ev", body["rid"] == V_RID and body["ev"] == "permission")
    s.check("vectors: plaintext", recs[0]["plain"] == V_PLAIN, recs[0]["plain"])
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
        s.check("argv: event still delivered", recs and recs[0]["body"]["env"]["ct"] == V_CT, str(recs)[:200])
        s.check("argv: decision still read", "allow" in out, out + err)
        s.check("argv: no ciphertext, secret or body", argv and V_CT[:40] not in argv and LINK_A["secret"] not in argv
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


def t_notify(s):
    """`simpleterm notify`: OSC 777 on a SimpleTerm terminal, `notify` to every link."""
    tun, tctl = s.spawn_mock()
    try:
        s.setup([(LINK_A, {"push": "disabled"}), (LINK_T, {"kind": "tunnel", "relay_url": tctl.url})])
        tctl("/_ctl/config", {"links": {LINK_T["id"]: dict(LINK_T)}})
        rc, tty = notify_pty(s, ["notify", "Build done", "exit 0; 한글 \x1b]0;x\x07"], {"SIMPLETERM": "1"})
        s.check("notify: exit 0", rc == 0, str(rc))
        s.check("notify: OSC 777 on the terminal, control characters removed",
                b"\x1b]777;notify;Build done;exit 0; \xed\x95\x9c\xea\xb8\x80 ]0;x\x07" in tty, repr(tty))
        rec = wait_for(lambda: ingests(s, "notify"), 20)
        p = rec[0].get("plain_json", {}) if rec else {}
        s.check("notify: relay event", p.get("app") == "script" and p.get("title") == "Build done"
                and p.get("msg") == "exit 0; 한글 ]0;x" and p.get("host") == "dev-box", str(p))
        s.check("notify: plaintext order", rec and rec[0]["plain"].startswith(
            '{"v":1,"rid":"%s","ev":"notify","app":"script","host":"dev-box","cwd":"%s","title":"Build done","msg":"'
            % (p.get("rid"), s.tmp.name)), rec[0]["plain"] if rec else "")
        s.check("notify: tunnel event", wait_for(lambda: ingests(s, "notify", tctl), 20))
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
    w.write_text(w.read_text().replace("# rev=1", "# rev=1\n# mine"))
    s.run("claude", json.dumps({"session_id": "w", "hook_event_name": "SessionStart", "source": "startup"}))
    s.check("cli: a current one is left alone", "# mine" in w.read_text())


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


def t_agy(s):
    """Antigravity: PreToolUse always answers (`{}` would deny); device waits are opt-in."""
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
    """agy's hook commands find the script without relying on the working directory."""
    s.setup([])
    tmp = s.tmp / "agy-paths"
    shutil.rmtree(tmp, ignore_errors=True)
    root, cwd, elsewhere = tmp / "plugin-root", tmp / "workspace", tmp / "elsewhere"
    places = {
        "PLUGIN_ROOT": root,
        "installed": s.home / ".gemini" / "config" / "plugins" / "simpleterm-antigravity",
        "clone": s.home / ".simpleterm" / "src" / "plugins" / "simpleterm",
        "cwd": cwd,
    }
    for name, d in places.items():
        write(d / "scripts" / "agent-hook.sh", STUB % name)
    elsewhere.mkdir(parents=True)

    def run(event, where, env=None, substitute=False):
        cmd = agy_command(event)
        if substitute:  # agy replacing ${PLUGIN_ROOT} itself
            cmd = cmd.replace("${PLUGIN_ROOT}", str(root))
        p = subprocess.run([s.argv[0], "-c", cmd], input=b"{}", capture_output=True, cwd=str(where),
                           env=s.env(env), timeout=30)
        return p.returncode, p.stdout.decode()

    for label, env, sub, want in (
        ("${PLUGIN_ROOT} replaced", None, True, "PLUGIN_ROOT agy PreToolUse"),
        ("PLUGIN_ROOT in the environment", {"PLUGIN_ROOT": str(root)}, False, "PLUGIN_ROOT agy PreToolUse"),
        ("CLAUDE_PLUGIN_ROOT in the environment", {"CLAUDE_PLUGIN_ROOT": str(root)}, False, "PLUGIN_ROOT agy PreToolUse"),
        ("no variable: the installed copy", None, False, "installed agy PreToolUse"),
    ):
        rc, out = run("PreToolUse", cwd, env, sub)
        s.check("agy paths: %s" % label, rc == 0 and out.strip() == want, "%d %r" % (rc, out))
    shutil.rmtree(places["installed"])
    rc, out = run("Stop", cwd)
    s.check("agy paths: the app's clone next", rc == 0 and out.strip() == "clone agy Stop", "%d %r" % (rc, out))
    shutil.rmtree(places["clone"])
    rc, out = run("PreToolUse", cwd)
    s.check("agy paths: ./scripts last", rc == 0 and out.strip() == "cwd agy PreToolUse", "%d %r" % (rc, out))
    for event in ("PreToolUse", "Stop"):
        rc, out = run(event, elsewhere)
        s.check("agy paths: no script anywhere -> no output, exit 0 (%s)" % event, rc == 0 and out == "", "%d %r" % (rc, out))
    # The real plugin installed where agy puts it, run from a workspace.
    shutil.copytree(ROOT / "plugins" / "antigravity", places["installed"])
    rc, out = run("PreToolUse", elsewhere)
    s.check("agy paths: the installed plugin answers from any folder", rc == 0 and out.strip() == '{"decision":"allow"}',
            "%d %r" % (rc, out))
    shutil.rmtree(s.home / ".gemini", ignore_errors=True)
    shutil.rmtree(tmp, ignore_errors=True)


def grok_input(event, **kw):
    snake = {"Notification": "notification", "Stop": "stop", "StopFailure": "stop_failure"}[event]
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
]


def copies_check():
    """Plugins that are installed on their own carry copies of the scripts; they must not drift."""
    bad = []
    for copy, master in COPIES:
        a, b = ROOT / copy, ROOT / master
        if not a.exists() or a.read_bytes() != b.read_bytes():
            bad.append("%s differs from %s (cp %s %s)" % (copy, master, master, copy))
    return bad


TESTS = [t_vectors, t_background, t_allow_deny, t_codex_allow, t_invalid_dmac, t_timeout, t_multi_link,
         t_tunnel, t_revoked, t_missing_deps, t_simpleterm_gating, t_local_answer, t_same_second_prompt, t_notifications, t_agent_gone, t_events,
         t_hostile_input, t_log, t_argv, t_external_printf,
         t_usage_claude, t_usage_window, t_usage_claude_big, t_usage_claude_huge, t_usage_statusline, t_usage_relay_policy, t_usage_codex, t_codex_hooks, t_gemini, t_notify,
         t_cli_wrapper, t_agy, t_agy_paths, t_grok, t_opencode_sh, t_opencode_js]

# Tests of the sh hook only (scripts and behaviour the PowerShell hook does not have).
SH_ONLY = {"t_usage_claude_big", "t_usage_claude_huge", "t_codex_hooks", "t_usage_statusline", "t_usage_relay_policy", "t_gemini", "t_notify", "t_cli_wrapper",
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--shell", action="append", help="shell to run agent-hook.sh with (repeatable)")
    ap.add_argument("--pwsh", help="pwsh executable to run agent-hook.ps1 with")
    ap.add_argument("--only", action="append", help="test function name (repeatable)")
    ap.add_argument("--no-sh", action="store_true")
    ap.add_argument("--hook", help="sh hook to test instead of the plugin's (e.g. an older release)")
    args = ap.parse_args()
    global HOOK_SH, SCRIPTS
    if args.hook:
        HOOK_SH = Path(args.hook).resolve()
        SCRIPTS = HOOK_SH.parent

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
    main()
