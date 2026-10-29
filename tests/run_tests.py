#!/usr/bin/env python3
"""Tests for plugins/simpleterm/scripts (stdlib only). Run with `python3 -I`.

  python3 -I tests/run_tests.py                 # sh hook, every shell found
  python3 -I tests/run_tests.py --shell /bin/dash
  python3 -I tests/run_tests.py --pwsh /path/to/pwsh   # PowerShell hook

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
        self.relay = subprocess.Popen(
            [sys.executable, "-I", str(MOCK), "--openssl", openssl or "/usr/bin/openssl"],
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
        cfg = {}
        for link, opts in links:
            text = "\n".join([
                "v=1", "relay=" + self.url, "link=" + link["id"], "secret=" + link["secret"],
                "enc=" + link["enc"], "mac=" + link["mac"], "label=" + link["label"], "device=Test iPad", "",
            ])
            p = st / "links" / (link["id"] + ".conf")
            p.write_text(text)
            p.chmod(0o600)
            cfg[link["id"]] = dict(link, **opts)
        conf_lines = ["poll_wait=2"] + ["%s=%s" % kv for kv in (conf or {}).items()]
        (st / "agent-hook.conf").write_text("\n".join(conf_lines) + "\n")
        self.ctl("/_ctl/reset", {})
        self.ctl("/_ctl/config", {"links": cfg})

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
    rec = wait_for(lambda: [r for r in s.records("/v1/ingest") if r.get("status") == 200], 10)
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
        s.check("permission %s: within time" % verdict, el < 10, "%.2fs" % el)
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
    s.check("invalid dmac: returns promptly", el < 10, "%.2fs" % el)


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
    rec = wait_for(lambda: s.records("/v1/ingest"), 8)
    s.check("notification: idle_prompt -> question", rec and rec[0]["body"]["ev"] == "question"
            and rec[0]["plain_json"].get("msg") == "Claude is waiting for your input", str(rec)[:200])
    s.check("notification: idle_prompt keeps the done badge (no sequence)", out == "", out)
    s.ctl("/_ctl/reset", {})
    _, out, _, _ = s.run("claude", json.dumps({"session_id": "q", "hook_event_name": "Notification", "message": "MCP needs input",
                                               "notification_type": "elicitation_dialog"}), {"SIMPLETERM": "1"})
    rec = wait_for(lambda: s.records("/v1/ingest"), 8)
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
    s.check("agent gone: hook exits", wait_for(gone, 8), "pid %d" % hook_pid)
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
        rec = wait_for(lambda: s.records("/v1/ingest"), 8)
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


TESTS = [t_vectors, t_background, t_allow_deny, t_codex_allow, t_invalid_dmac, t_timeout, t_multi_link,
         t_revoked, t_missing_deps, t_simpleterm_gating, t_local_answer, t_same_second_prompt, t_notifications, t_agent_gone, t_events,
         t_hostile_input, t_log, t_argv, t_external_printf]


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
        if suite.kind == "ps1" and t is t_missing_deps:
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
    args = ap.parse_args()

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
