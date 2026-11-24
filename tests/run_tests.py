#!/usr/bin/env python3
"""Tests for plugins/simpleterm/scripts (stdlib only). Run with `python3 -I`.

  python3 -I tests/run_tests.py                 # ubuntu, macos, windows (every case) and compat
  python3 -I tests/run_tests.py --suite full    # or --suite compat
  python3 -I tests/run_tests.py --pwsh /path/to/pwsh   # the PowerShell 7 to use (default: pwsh in PATH)
  python3 -I tests/run_tests.py --openssl /path/to/openssl   # the OpenSSL 3 to use (default: Homebrew's)
  python3 -I tests/run_tests.py --shell /path/to/bash --suite compat   # another shell
  python3 -I tests/run_tests.py --hook old/agent-hook.sh # another sh hook (baseline)

Each suite gets its own temporary HOME (with ~/.simpleterm/links/*.conf) and
its own mock_relay.py process. The environments are each server OS's /bin/sh
and openssl (ENVIRONMENTS): dash with OpenSSL 3, macOS's /bin/sh with LibreSSL,
PowerShell 7, and /bin/sh with OpenSSL 3 for the cases where they meet (COMPAT).
Cases wait for what they look for (wait_for, Suite.settle), not for a set time.

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

# --- the processes a run starts ------------------------------------------------------
# Every process group a case starts (Suite.popen, notify_pty), with its suite, for reap(), settle() and
# the check that a run leaves nothing. A group id names a group only while one of its processes exists
# (the id of a live group is never handed out): a look at every process that finds none of a group's
# drops it, since its id may be anyone's later. observe() looks at least once a second (watch()), and
# ids come round only after tens of thousands of new processes, so a group is dropped long before its id
# could name another run's processes (two runs at once counted each other's: AhMunGa/simple-term#449).
GROUPS = {}  # group id -> (Suite, time.monotonic() when added)
GROUPS_LOCK = threading.Lock()
SUITES = []  # every suite of the run: a process whose command names a suite's folder is the run's
# A `sleep` this long or longer is a timer no case waits out (bg_done_after's 600 s, the 15 s watchdog of
# a version measurement), and so is a PowerShell hook's background process (`__send`) this old that a
# pause's file accounts for (busy()).
LONG_TIMER = 15


def track(pgid, suite):
    with GROUPS_LOCK:
        GROUPS[pgid] = (suite, time.monotonic())


def ps_rows(command=False):
    """(pid, ppid, pgid, stat, command) of every process (the command only when asked: it costs twice
    as much), or None when `ps` failed (a machine out of processes)."""
    cols = "pid=,ppid=,pgid=,stat=" + (",command=" if command else "")
    me = os.getpid()
    for _ in range(3):
        try:
            out = subprocess.run(["ps", "-A", "-o", cols], capture_output=True).stdout.decode("utf-8", "replace")
        except OSError:
            out = ""
        rows = []
        for line in out.splitlines():
            f = line.split(None, 4)
            if len(f) >= 4 and f[0].isdigit() and f[1].isdigit() and f[2].isdigit():
                rows.append((int(f[0]), int(f[1]), int(f[2]), f[3], f[4] if len(f) > 4 else ""))
        if any(r[0] == me for r in rows):
            return rows
        time.sleep(0.2)
    return None


def observe(command=False):
    """One look at every process (ps_rows): drops the groups none is left of (added before the look
    began) and adds those this run's processes started (an ask leads a group of its own, SimpleTerm
    if/usage-ask#run-time). Returns the rows, or None."""
    t = time.monotonic()
    rows = ps_rows(command)
    if rows is None:
        return None
    present = {r[2] for r in rows}
    with GROUPS_LOCK:
        for g, (_, added) in list(GROUPS.items()):
            if added < t and g not in present:
                del GROUPS[g]
        owner = {r[0]: GROUPS[r[2]][0] for r in rows if r[2] in GROUPS and not r[3].startswith("Z")}
        for pid, ppid, pgid, stat, _ in rows:
            if pgid not in GROUPS and ppid in owner and not stat.startswith("Z"):
                GROUPS[pgid] = (owner[ppid], t)
    return rows


def watch(stop):
    """observe() once a second until `stop` is set, so that no group outlives its id unseen."""
    while not stop.wait(1):
        observe()


def ours(rows, suites=None, but=(), groups=()):
    """This run's processes (not zombies) among `rows`, {pid: row}: those in a group of `suites` (every
    suite: None) or in `groups`, those whose command names a suite's folder (a stand-in agent), and what
    they started; but not the processes `but` (pids) and what runs under them."""
    me = os.getpid()
    with GROUPS_LOCK:
        mine_g = {g for g, (o, _) in GROUPS.items() if suites is None or o in suites} | set(groups)
    marks = [str(x.tmp) for x in (SUITES if suites is None else suites)]
    live = {r[0]: r for r in rows if not r[3].startswith("Z") and r[0] != me and not (r[1] == me and r[4].startswith("ps "))}
    kids = {}
    for r in live.values():
        kids.setdefault(r[1], []).append(r[0])

    def under(pids):
        found, todo = set(pids), list(pids)
        while todo:
            for k in kids.get(todo.pop(), ()):
                if k not in found:
                    found.add(k)
                    todo.append(k)
        return found
    skip = under([p for p in but if p in live])
    mine = {pid for pid, r in live.items() if r[2] in mine_g or (r[4] and any(m in r[4] for m in marks))}
    return {pid: live[pid] for pid in under(mine - skip) - skip}


def etime_s(text):
    """Seconds of a `ps -o etime` value ([[dd-]hh:]mm:ss)."""
    days, _, rest = text.strip().rpartition("-")
    total = 0
    for part in rest.split(":"):
        total = total * 60 + int(part)
    return total + int(days or 0) * 86400


def busy(procs, home=None):
    """`procs` ({pid: row}) without the timers no case waits out (LONG_TIMER) and the shells that only
    wait for such. The sh hook's pause is a `sleep 600`. The PowerShell hook's is a background process
    (`__send`) like every send, so one is taken for a pause only when it is LONG_TIMER old and the HOME
    `home` holds a pause's file (<sid>.bg, written before the pause starts, gone once a turn ends it):
    no more of them, the oldest first, than there are such files. A send that is merely slow is waited
    for."""
    if not procs:
        return procs
    out = subprocess.run(["ps", "-o", "pid=,etime=,command=", "-p", ",".join(map(str, procs))],
                         capture_output=True).stdout.decode("utf-8", "replace")
    parked = set()
    sends = []
    for line in out.splitlines():
        f = line.split(None, 2)
        if len(f) < 3 or not f[0].isdigit() or int(f[0]) not in procs:
            continue
        m = re.match(r"(?:\S*/)?sleep (\d+)$", f[2].strip())
        try:
            age = etime_s(f[1])
        except ValueError:
            age = 0
        if m and int(m.group(1)) >= LONG_TIMER:
            parked.add(int(f[0]))
        elif " __send " in f[2] and age >= LONG_TIMER:
            sends.append((age, int(f[0])))
    if sends and home is not None:
        pauses = len(list((Path(home) / ".simpleterm" / "run").glob("*.bg")))
        parked.update(pid for _, pid in sorted(sends, reverse=True)[:pauses])
    grew = True
    while grew:
        grew = False
        for pid in procs:
            kids = [k for k, r in procs.items() if r[1] == pid]
            if pid not in parked and kids and all(k in parked for k in kids):
                parked.add(pid)
                grew = True
    return {pid: r for pid, r in procs.items() if pid not in parked}


def commands(pids):
    """'pid command' lines of `pids` (for messages)."""
    if not pids:
        return []
    out = subprocess.run(["ps", "-o", "pid=,command=", "-p", ",".join(map(str, sorted(pids)))],
                         capture_output=True).stdout.decode("utf-8", "replace")
    return [line.strip()[:140] for line in out.splitlines() if line.strip()]

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
    "mkdir", "chmod", "find", "sleep", "cat", "dd", "ls", "ps", "printf", "touch", "readlink",
    "perl", "setsid",
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

    def __init__(self, name, argv, openssl=None, kind="sh", cases="full"):
        self.name = name
        self.argv = argv
        self.openssl = openssl
        self.kind = kind
        self.cases = cases  # full: every case; compat: COMPAT only
        self.results = []
        # Every terminalSequence a hook printed (screen_check): how many, and what Claude Code would refuse.
        self.case = None
        self.seq_n = 0
        self.seq_bad = {}
        self.seq_lock = threading.Lock()
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
        SUITES.append(self)
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
        self.reap()
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
            # The tab identity (SimpleTerm if/hook-tab-identity) reads no other process and no tmux
            # server here: on the machine running the suite they are the user's. t_v2_tab hands it stand-ins.
            "SIMPLETERM_HOOK_TEST_IDBIN": "none",
        }
        if self.kind == "ps1":
            # pwsh is run by its path; the hook needs nothing from PATH, and no agent the user has
            # installed (grok, opencode, agy: the version cache runs `--version`) may be found.
            # The suite's bin first: stand-in agents for usage asks are there (and nothing else the
            # user has installed).
            env["PATH"] = str(self.bin) + ":/usr/bin:/bin:/usr/sbin:/sbin"
            env["POWERSHELL_TELEMETRY_OPTOUT"] = "1"
            env["POWERSHELL_UPDATECHECK"] = "Off"
        env.update(extra or {})
        return env

    def popen(self, argv, **kw):
        """subprocess.Popen in a session (and process group) of its own, kept for reap(): what a
        hook leaves running in the background (a send, a done that waits up to 600 s, an ask) is
        in that group. What it prints goes through screen_check() when read with communicate()."""
        p = subprocess.Popen(argv, start_new_session=True, **kw)
        track(p.pid, self)
        talk = p.communicate

        def communicate(*a, **k):
            out, err = talk(*a, **k)
            self.screen_check(out)
            return out, err
        p.communicate = communicate
        return p

    def screen_check(self, out):
        """Every terminalSequence in a hook's output against what Claude Code passes on (allowlist_problems);
        what it would refuse becomes a failed check of the case (run_suite)."""
        if not out:
            return
        text = out.decode("utf-8", "replace") if isinstance(out, bytes) else out
        for seq in term_seqs(text):
            bad = allowlist_problems(seq) if isinstance(seq, str) else ["terminalSequence that is not a JSON string on one line"]
            with self.seq_lock:
                self.seq_n += 1
                for why in bad:
                    self.seq_bad.setdefault((self.case, why), []).append(seq)

    def screen_report(self):
        """The case's refused terminalSequences as failed checks, one per case and reason."""
        with self.seq_lock:
            bad, self.seq_bad = self.seq_bad, {}
        for (case, why), seqs_ in sorted(bad.items(), key=lambda kv: (str(kv[0][0]), kv[0][1])):
            self.check("terminalSequence allowlist (%s): %s" % (case, why), False,
                       "%d output(s); first %r" % (len(seqs_), seqs_[0]))

    def proc_run(self, argv, input=None, timeout=60, **kw):
        """subprocess.run with capture_output, by popen()."""
        kw.pop("capture_output", None)
        kw.pop("start_new_session", None)
        p = self.popen(argv, stdin=subprocess.PIPE if input is not None else kw.pop("stdin", None),
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kw)
        try:
            out, err = p.communicate(input, timeout=timeout)
        except subprocess.TimeoutExpired:
            p.kill()
            out, err = p.communicate()
            raise
        return subprocess.CompletedProcess(argv, p.returncode, out, err)

    def running(self, but=()):
        """This suite's processes that run now (ours()), {pid: row}; None when `ps` failed."""
        rows = observe()
        return None if rows is None else ours(rows, [self], but)

    def reap(self):
        """Ends what the case left running (TERM, then KILL to what is left 2 seconds later): nothing a
        case leaves in the background outlives it. Only this suite's processes are touched (ours())."""
        for sig in (signal.SIGTERM, signal.SIGKILL):
            pids = self.running() or {}
            for pid in pids:
                try:
                    os.kill(pid, sig)
                except OSError:
                    pass
            if not pids or sig == signal.SIGKILL:
                break
            wait_for(lambda: self.running() == {}, 2, 0.2)

    def settle(self, what, but=(), timeout=60):
        """Waits until what this case started has ended (the hooks and what they left in the background:
        the sends, a done's wait), but the processes `but` (Popen objects: a hook that still waits, a
        stand-in agent) and what runs under them, and the timers no case waits out (busy()). A send's
        record is in the relay once its curl ended (mock_relay.py records before it answers). After
        `timeout` seconds a failed check says what was waited for and what still ran. Returns whether
        all ended."""
        skip = [p.pid for p in but]
        end = time.time() + timeout
        while True:
            left = self.running(skip)
            if left is not None:
                left = busy(left, self.home)
                if not left:
                    return True
            if time.time() >= end:
                break
            time.sleep(0.2)
        self.check("settle: %s within %d s" % (what, timeout), False, "still running: %s" % commands(left or {}))
        return False

    def start(self, agent, stdin="", extra=None, bare=False, args=()):
        cmd = list(self.argv) + [agent] + list(args)
        p = self.popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=self.env(extra, bare), cwd=str(self.tmp),
        )
        p.t0 = time.time()
        if stdin:
            try:
                p.stdin.write(stdin if isinstance(stdin, bytes) else stdin.encode())
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


# What Claude Code passes on in a hook's terminalSequence (SimpleTerm hist/hook-events#e28, if/terminal-signals-bg#bytes):
# only OSC 0, 1, 2, 9, 99 and 777 and BEL, the whole field 4096 bytes at most, and (2.1.295+) no OSC 9 whose body starts
# with a digit but 9;4 (progress). One sequence outside drops the whole field, the hook's OSC 9 with it.
ALLOWED_OSC = {"0", "1", "2", "9", "99", "777"}


def allowlist_problems(seq):
    """Why Claude Code would drop terminalSequence `seq` ([] when it passes it on)."""
    bad = []
    if len(seq.encode("utf-8")) > 4096:
        bad.append("over 4096 bytes")
    i = 0
    while i < len(seq):
        if seq[i] == "\x07":
            i += 1
            continue
        m = re.match(r"\x1b\]([0-9]*)", seq[i:])
        if not m:
            bad.append("something other than OSC or BEL")
            break
        num, k = m.group(1), i + m.end()
        ends = [e for e in (seq.find("\x07", k), seq.find("\x1b\\", k)) if e >= 0]
        if not ends:
            bad.append("an OSC without its end")
            break
        e = min(ends)
        body = seq[k:e]
        if num not in ALLOWED_OSC:
            bad.append("OSC %s (not on the allowlist)" % (num or "without a number"))
        elif body and not body.startswith(";"):
            bad.append("OSC %s%s (not on the allowlist)" % (num, body[:4]))
        elif num == "9" and body[1:2].isdigit() and not (body == ";4" or body.startswith(";4;")):
            bad.append("OSC 9 body that starts with a digit")
        i = e + (1 if seq[e] == "\x07" else 2)
    return bad


def term_seqs(text):
    """The terminalSequence values in a hook's output (a JSON object per line; the key at any depth). A line that
    names the key but is no JSON gives None."""
    found = []
    if "terminalSequence" not in text:
        return found

    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if k == "terminalSequence":
                    found.append(v if isinstance(v, str) else None)
                else:
                    walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)
    for line in text.splitlines():
        if "terminalSequence" not in line:
            continue
        try:
            walk(json.loads(line))
        except ValueError:
            found.append(None)
    return found


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
    """Relay protocol v1 vectors (SimpleTerm if/event-envelope#vectors): the v1 fields of the plaintext are those of the vector,
    byte for byte, and the v2 fields come after them, before `ts` (SimpleTerm if/event-v2#fields);
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
    s.check("timeout: logged", "permission timeout" in s.log_text(), "rc=%s %.2fs err=%r log=%s" % (rc, el, err[-300:], s.log_text()))
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
        s.run("claude", stop)
        got = wait_for(lambda: [r for r in tctl("/_ctl/records")["records"] if r["path"] == "/v1/ingest"], 10, 0.05)
        rel = wait_for(lambda: [r for r in s.records("/v1/ingest") if "responded" in r], 20)
        # An order, not a time limit (a loaded machine does not change it): the tunnel's copy came
        # before the relay answered (it holds its answer 3 s). Sent after the relay's answer, it
        # would come later.
        s.check("tunnel first: background event reaches the tunnel before the relay answers",
                got and rel and got[0]["received"] < rel[0]["responded"],
                "tunnel %s relay %s" % ([round(r["received"] - rel[0]["received"], 2) for r in got] if got and rel else got,
                                         round(rel[0]["responded"] - rel[0]["received"], 2) if rel else rel))
        s.check("tunnel first: relay still gets it", rel, str(s.records())[:200])
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
    # (A set time on purpose: the waiting hook looks once a second (request_flow), and that it went on
    # waiting is all there is to see. 2.5 s is two looks and more.)
    time.sleep(2.5)
    s.check("local answer: other tool does not cancel", p.poll() is None)
    same = perm_input(command="make deploy", session="loc-1", event="PostToolUse")
    t = time.time()
    s.run("claude", same)
    rc, out, err, el = s.finish(p, 30)
    s.check("local answer: same tool cancels the wait", time.time() - t < 5 and out == "", "%.2fs %s" % (time.time() - t, out))
    s.check("local answer: logged", "answered-at-terminal" in s.log_text(), s.log_text())
    # A new prompt also ends the wait.
    n = len(s.records("/v1/decision"))
    p = s.start("claude", perm_input(command="make deploy", session="loc-2"))
    # Its first poll: it waits now, and what it found at its start (RES_BASE) is behind it. (The hook above
    # polled too: count from here.)
    wait_for(lambda: len(s.records("/v1/decision")) > n, 15)
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
    s.settle("the Notification hook's sends", but=[p])
    evs = [r["body"]["ev"] for r in s.records("/v1/ingest") if r.get("body")]
    s.check("notification: permission_prompt adds no relay event", evs == ["permission"], str(evs))
    s.check("notification: permission_prompt prints nothing", out == "", out)
    s.run("claude", json.dumps({"session_id": "nd-1", "hook_event_name": "UserPromptSubmit", "prompt": "x"}))
    s.finish(p, 30)
    s.ctl("/_ctl/reset", {})
    s.run("claude", note.replace("nd-1", "nd-2"))
    s.settle("the Notification hook's sends")
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
    s.settle("the hooks' background work")
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
    s.settle("the Notification hook's sends")
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
    rec = wait_for(lambda: ingests(s, "done"), 20)
    # (By the relay's clock: nothing came before bg_done_after, 2 s.)
    s.check("kinds: a shell alone -> nothing at first", all(r["received"] - t0 >= 1.8 for r in ingests(s)),
            str([(r["body"]["ev"], round(r["received"] - t0, 2)) for r in ingests(s)])[:200])
    s.check("kinds: ... then done once after bg_done_after, saying what runs",
            len(rec) == 1 and rec[0]["received"] - t0 >= 1.8
            and rec[0]["plain_json"].get("msg") == "The server is up. (still running in the background: shell: Start the dev server)",
            str([(r["plain_json"].get("msg"), round(r["received"] - t0, 2)) for r in rec]))
    s.settle("the pause's wait and send")
    s.check("kinds: ... and only once", len(ingests(s, "done")) == 1, str(ingests(s))[:200])
    # A subagent alongside: it reports back, so no time limit.
    s.ctl("/_ctl/reset", {})
    stop("k4", [task("shell", "Run tests", command="npm test"), task("subagent", "Review")])
    s.settle("the Stop hook's background work (a wait of bg_done_after, 2 s, if it started one)")
    s.check("kinds: a subagent left -> no time limit", not ingests(s), str(ingests(s))[:200])
    # A new turn before the limit ends the wait.
    s.ctl("/_ctl/reset", {})
    stop("k5", [task("monitor", "Watch the deploy")])
    s.run("claude", json.dumps({"session_id": "k5", "hook_event_name": "UserPromptSubmit", "prompt": "<task-notification>"}), st)
    s.settle("the pause's wait (bg_done_after, 2 s)")
    s.check("kinds: a new turn before the limit -> no late done", not ingests(s), str(ingests(s))[:200])


def bg_payload(body):
    """A structured payload as the app reads it (SimpleTerm if/terminal-signals#structured, if/terminal-signals-bg#fields):
    `simpleterm:state=<value>[<sep><message>]`, the prefix without regard to case and only at the start, the value
    a-z and _ in lower case, <sep> a run of white space or `;`. (value, message or None); None when not a payload."""
    m = re.match(r"(?i)simpleterm:state=([a-z_]+)(?:([\s;]+)(.*))?$", body, re.S)
    if not m:
        return None
    return m.group(1).lower(), (m.group(3) or None)


def screen_values(seq):
    """The OSC 9 payloads of a terminalSequence, in order: [(value, message)]."""
    return [bg_payload(b) for b in re.findall(r"\x1b\]9;(.*?)\x07", seq, re.S)]


def t_background_screen_values(s):
    """The background pause on the screen (SimpleTerm if/terminal-signals-bg#plugin, #vectors; issue #804). Claude
    Code 2.1.295+ reports `done` for its own turn through OSC 7501 even while a background shell runs, and drops a
    hook's OSC 7501 from terminalSequence (hist/hook-events#e28). Where it speaks 7501 itself (claude_speaks_7501)
    the hook writes the pause as one more OSC 9 value after the old one: bg_working, bg_question when the turn asks,
    bg_clear in the first output of the next turn; elsewhere the old values only."""
    s.setup([(LINK_A, {})])
    st = {"SIMPLETERM": "1"}
    shell = {"id": "bhk40d9z9", "type": "shell", "status": "running",
             "description": "Run the test suite", "command": "npm test"}

    def transcript(version):
        return write(s.tmp / ("t-%s.jsonl" % version), "\n".join(
            json.dumps({"type": t, "version": version, "message": {"role": t, "content": "x"}})
            for t in ("user", "assistant")) + "\n")

    def stop(sid, tr, extra=None, tasks=(shell,), last="x"):
        ev = {"session_id": sid, "cwd": "/w/proj", "hook_event_name": "Stop", "stop_hook_active": False,
              "last_assistant_message": last, "transcript_path": str(tr), "background_tasks": list(tasks)}
        return s.run("claude", json.dumps(ev), dict(st, **(extra or {})))[1]

    def prompt(sid, extra=None):
        return s.run("claude", json.dumps({"session_id": sid, "hook_event_name": "UserPromptSubmit", "prompt": "x"}),
                     dict(st, **(extra or {})))[1]

    tr = transcript("2.1.316")
    # The plugin output vectors of SimpleTerm if/terminal-signals-bg#vectors, byte for byte as the hook prints them.
    sleep20 = {"id": "b20", "type": "shell", "status": "running", "command": "sleep 20"}
    out = stop("bv1", tr, tasks=[sleep20])
    s.check("screen: vector Stop, pause",
            out.strip() == r'{"terminalSequence":"\u001b]9;simpleterm:state=background shell: sleep 20\u0007\u001b]9;simpleterm:state=bg_working shell: sleep 20\u0007"}',
            repr(out))
    out = prompt("bv1")
    s.check("screen: vector UserPromptSubmit",
            out.strip() == r'{"terminalSequence":"\u001b]9;simpleterm:state=running\u0007\u001b]9;simpleterm:state=bg_clear\u0007"}', repr(out))
    out = stop("bv2", tr, tasks=[SUBAGENT], last="Use option A or B?")
    s.check("screen: vector Stop, pause ask",
            out.strip() == r'{"terminalSequence":"\u001b]9;simpleterm:state=waiting Use option A or B?\u0007\u001b]9;simpleterm:state=bg_question Use option A or B?\u0007"}',
            repr(out))
    s.check("screen: the outputs parse to the rows of #vectors",
            screen_values(seqs(out)) == [("waiting", "Use option A or B?"), ("bg_question", "Use option A or B?")], str(screen_values(seqs(out))))
    out = prompt("bv2")
    s.check("screen: bg_clear parses as bg_clear, no message", screen_values(seqs(out)) == [("running", None), ("bg_clear", None)],
            str(screen_values(seqs(out))))
    wait_for(lambda: ingests(s, "question"), 20)  # the pause ask's send lands before the next case

    out = stop("b75", tr)
    s.check("screen: Claude Code 2.1.316 -> bg_working after the background state",
            seqs(out) == "\x1b]9;simpleterm:state=background shell: Run the test suite\x07"
            "\x1b]9;simpleterm:state=bg_working shell: Run the test suite\x07", repr(out))
    out2 = prompt("b75")
    s.check("screen: the next turn says bg_clear",
            seqs(out2) == "\x1b]9;simpleterm:state=running\x07\x1b]9;simpleterm:state=bg_clear\x07", repr(out2))
    out3 = prompt("b75")
    s.check("screen: bg_clear once", seqs(out3) == "\x1b]9;simpleterm:state=running\x07", repr(out3))

    # The first output of the next turn may be a Stop: done then bg_clear; or a Stop that pauses again: the new value
    # replaces the record (no bg_clear); or a StopFailure: idle, error, then bg_clear.
    stop("b76", tr)
    out = stop("b76", tr, tasks=[])
    s.check("screen: a Stop first -> done, bg_clear", seqs(out) == "\x1b]9;simpleterm:state=done\x07\x1b]9;simpleterm:state=bg_clear\x07", repr(out))
    stop("b77", tr)
    out = stop("b77", tr, tasks=[dict(shell, id="b77b", description="Build the docs")])
    s.check("screen: a Stop that pauses again -> its bg_working, no bg_clear",
            seqs(out) == "\x1b]9;simpleterm:state=background shell: Build the docs\x07\x1b]9;simpleterm:state=bg_working shell: Build the docs\x07",
            repr(out))
    stop("b78", tr)
    _, out, _, _ = s.run("claude", cc_event("b78", "StopFailure", error="server_error", last_assistant_message="API Error"), st)
    s.check("screen: a StopFailure first -> idle, error, bg_clear",
            seqs(out) == "\x1b]9;simpleterm:state=idle\x07\x1b]9;simpleterm:state=error\x07\x1b]9;simpleterm:state=bg_clear\x07", repr(out))
    # A pause written by 0.3.1-0.6.0 (`7501` on the note's second line): its record never reached the screen
    # (hist/hook-events#e28), so there is nothing to clear.
    run = s.home / ".simpleterm" / "run"
    write(run / "b79.bg", "shell: x\n7501\n%s\n\n" % ("a" * 16))
    out = prompt("b79")
    s.check("screen: a 0.6.0 pause -> no bg_clear", seqs(out) == "\x1b]9;simpleterm:state=running\x07", repr(out))

    for label, trx, extra in (("2.1.294 (no OSC 7501 of its own)", transcript("2.1.294"), None),
                              ("inside tmux", tr, {"TMUX": "/tmp/tmux-1/default,1,0"}),
                              ("inside screen", tr, {"STY": "123.pts-1.host"}),
                              ("terminal title writes off", tr, {"CLAUDE_CODE_DISABLE_TERMINAL_TITLE": "1"}),
                              ("no transcript", s.tmp / "missing.jsonl", None)):
        sid = "b75-" + label.split()[0] + label.split()[-1]
        out = stop(sid, trx, extra)
        s.check("screen: none for %s" % label, "bg_" not in seqs(out) and "state=background" in seqs(out), repr(out))
        _, out4, _, _ = s.run("claude", json.dumps({"session_id": sid, "hook_event_name": "Stop",
                                                    "last_assistant_message": "x", "background_tasks": []}),
                              dict(st, **(extra or {})))
        s.check("screen: nothing to clear for %s" % label, seqs(out4) == "\x1b]9;simpleterm:state=done\x07", repr(out4))
    # herdr: TMUX and STY are not set there, so the check holds and the value goes out (it changes nothing there:
    # SimpleTerm if/terminal-signals-bg#plugin).
    out = stop("b75-herdr", tr, {"HERDR_ENV": "1", "HERDR_PANE_ID": "w2:p1"})
    s.check("screen: inside herdr the value goes out", seqs(out).endswith("\x1b]9;simpleterm:state=bg_working shell: Run the test suite\x07"), repr(out))

    # The message is the old value's, cut the same way: JSON escapes and a long text.
    out = stop("b75-esc", tr, tasks=[dict(shell, description='Run "npm test" — all')])  # JSON: \" and —
    s.check("screen: a message with escapes is the old value's",
            seqs(out) == '\x1b]9;simpleterm:state=background shell: Run "npm test" — all\x07'
            '\x1b]9;simpleterm:state=bg_working shell: Run "npm test" — all\x07', repr(out))
    out = stop("b75-long", tr, tasks=[dict(shell, description="한" * 120)])
    v = screen_values(seqs(out))
    s.check("screen: a long message is cut as the old value (80 characters)",
            len(v) == 2 and v[1][0] == "bg_working" and v[1][1] == v[0][1] and len(v[0][1]) <= 80, str(v)[:200])


def t_background_screen_clear(s):
    """A pause whose screen value went out stays on the screen until an output writes bg_clear, however the pause
    ended meanwhile, without an output (SimpleTerm if/terminal-signals-bg#plugin; review of plugin PR #15): the next
    turn's first output writes it also after bg_done_after's late done, after the hook's path for a Stop whose last
    message is a session title (it prints nothing; no evidence that Claude Code sends one, the path is there), in the
    new session of /clear, /resume or /branch (a new session id in the same process: SessionEnd reason clear or
    resume, then SessionStart source clear, resume or fork, Claude Code hooks reference; hist/agent-sessions#e7), and
    for a pause older than the day the run files are kept."""
    s.setup([(LINK_A, {})], conf={"bg_done_after": 2})
    st = {"SIMPLETERM": "1"}
    tr = write(s.tmp / "tc.jsonl", "\n".join(json.dumps({"type": t, "version": "2.1.316", "message": {"role": t, "content": "x"}})
                                             for t in ("user", "assistant")) + "\n")
    shell = {"id": "bc1", "type": "shell", "status": "running", "description": "Start the dev server", "command": "node worker.js"}
    run = s.home / ".simpleterm" / "run"
    clear = "\x1b]9;simpleterm:state=running\x07\x1b]9;simpleterm:state=bg_clear\x07"
    running = "\x1b]9;simpleterm:state=running\x07"

    def ev(sid, name, cwd="/w/proj", **kw):
        return json.dumps(dict({"session_id": sid, "cwd": cwd, "hook_event_name": name, "transcript_path": str(tr)}, **kw))

    def stop(sid, tasks=(shell,), last="x", cwd="/w/proj"):
        return s.run("claude", ev(sid, "Stop", cwd, stop_hook_active=False, last_assistant_message=last,
                                  background_tasks=list(tasks)), st)[1]

    def prompt(sid, cwd="/w/proj"):
        return seqs(s.run("claude", ev(sid, "UserPromptSubmit", cwd, prompt="x"), st)[1])

    def paused(sid):
        out = stop(sid)
        s.check("clear paths: %s pauses with bg_working" % sid, "simpleterm:state=bg_working shell: Start the dev server" in seqs(out), repr(out))

    # bg_done_after's late done (a shell alone may run for good): the pause file goes, the screen still shows it.
    s.ctl("/_ctl/reset", {})
    paused("bc-late")
    s.check("clear paths: the late done comes", wait_for(lambda: ingests(s, "done"), 20), str(ingests(s))[:200])
    s.settle("the late done's send")
    s.check("clear paths: ... and the pause file is gone", not (run / "bc-late.bg").exists())
    out = prompt("bc-late")
    s.check("clear paths: after the late done the next turn says running, bg_clear", out == clear, repr(out))
    out = prompt("bc-late")
    s.check("clear paths: ... once", out == running, repr(out))
    # The hook's path for a Stop whose last message is a session title prints nothing (no evidence that Claude Code
    # sends such a Stop); the next output clears.
    paused("bc-title")
    _, out, _, _ = s.run("claude", ev("bc-title", "Stop", stop_hook_active=False, last_assistant_message='{"title":"Fix the build"}',
                                      background_tasks=[]), st)
    s.check("clear paths: a title Stop prints nothing", out == "", repr(out))
    out = prompt("bc-title")
    s.check("clear paths: after a title Stop the next turn says running, bg_clear", out == clear, repr(out))
    # /clear and /resume: the new session's first turn clears the old one's pause.
    for reason, source in (("clear", "clear"), ("resume", "resume"), ("resume", "fork")):
        old, new = "bc-%s-%s-a" % (reason, source), "bc-%s-%s-b" % (reason, source)
        paused(old)
        s.run("claude", ev(old, "SessionEnd", reason=reason), st)
        s.run("claude", ev(new, "SessionStart", source=source), st)
        out = prompt(new)
        s.check("clear paths: SessionEnd %s, SessionStart %s -> the new session's turn says running, bg_clear" % (reason, source),
                out == clear, repr(out))
    # Not handed over: a session that ends for good (another one starts later), another folder, an old hand-over.
    paused("bc-exit-a")
    s.run("claude", ev("bc-exit-a", "SessionEnd", reason="prompt_input_exit"), st)
    s.run("claude", ev("bc-exit-b", "SessionStart", source="startup"), st)
    out = prompt("bc-exit-b")
    s.check("clear paths: a session that ends for good hands nothing to the next one", out == running, repr(out))
    paused("bc-dir-a")
    s.run("claude", ev("bc-dir-a", "SessionEnd", reason="clear"), st)
    s.run("claude", ev("bc-dir-b", "SessionStart", cwd="/w/other", source="clear"), st)
    out = prompt("bc-dir-b", cwd="/w/other")
    s.check("clear paths: /clear in another folder takes nothing", out == running, repr(out))
    old = time.time() - 300
    for f in run.glob("bgclr.*"):
        os.utime(f, (old, old))
    s.run("claude", ev("bc-dir-c", "SessionStart", source="clear"), st)
    out = prompt("bc-dir-c")
    s.check("clear paths: a hand-over five minutes old is not taken", out == running, repr(out))
    # The run files are kept a day; a pause on the screen is cleared however late its next turn comes.
    for sid, days, want in (("bc-old2", 2, clear), ("bc-old31", 31, running)):
        paused(sid)
        t = time.time() - days * 86400
        for f in run.glob(sid + ".*"):
            os.utime(f, (t, t))
        stop("bc-other-%d" % days, tasks=[])  # another session's turn end keeps house
        s.settle("the other session's done")
        out = prompt(sid)
        s.check("clear paths: a pause %d days old -> %s" % (days, "running, bg_clear" if want == clear else "running only (gone after 30 days)"),
                out == want, repr(out))
    s.settle("the pauses' waits (bg_done_after, 2 s)")


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
    s.settle("the hooks' background work")
    s.check("question while waiting: no done and no second question", len(ingests(s)) == 1, str(ingests(s))[:300])

    # Claude Code 2.1.295+: bg_question instead of bg_working; bg_clear at the next turn.
    s.ctl("/_ctl/reset", {})
    tr = cc_transcript(s)
    out = s.run("claude", cc_event("qb2", "Stop", stop_hook_active=False, last_assistant_message=q, background_tasks=[SUBAGENT],
                                   session_crons=[], transcript_path=str(tr)), st)[1]
    s.check("question while waiting: bg_question after waiting, no bg_working",
            seqs(out) == "\x1b]9;simpleterm:state=waiting " + q + "\x07\x1b]9;simpleterm:state=bg_question " + q + "\x07", repr(out))
    wait_for(lambda: ingests(s, "question"), 20)  # its send must land before the reset below
    _, out3, _, _ = s.run("claude", cc_event("qb2", "UserPromptSubmit", prompt="yes, fix them"), st)
    s.check("question while waiting: the next turn says bg_clear",
            seqs(out3) == "\x1b]9;simpleterm:state=running\x07\x1b]9;simpleterm:state=bg_clear\x07", repr(out3))

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
    s.settle("the Stop hooks' background work")
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
    s.settle("the Stop hook's background work (a wait of bg_done_after, 2 s, if it started one)")
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
    s.settle("the Stop hooks' background work")
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
    s.check("service shell: no bg_working", seqs(out) == "\x1b]9;simpleterm:state=done\x07", repr(out))
    # Grok Build.
    s.settle("the sends of the cases above")
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
    s.settle("the hooks' background work")
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
    s.settle("the sends of the cases above")
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
    s.settle("the Grok hooks' background work")
    s.check("grok user turn: the turn that starts the task waits", not ingests(s), str(ingests(s))[:200])
    gprompt("scheduler-fired-7", "2026-11-02T10:11:00.000Z")
    gstop("scheduler-fired-7", "2026-11-02T10:11:05.000Z")
    s.settle("the Grok hooks' background work")
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
    s.settle("the hooks' background work")
    s.check("schedule: no event from the scheduled turns", not ingests(s), str(ingests(s))[:300])
    # Claude Code 2.1.295+: bg_working, with the schedule as its text.
    tr = cc_transcript(s)
    s.run("claude", cc_event("sc2", "UserPromptSubmit", prompt="x", source="loop_wakeup"), st)
    out = stop("sc2", cron[:1], "Check.", extra={"transcript_path": str(tr)})
    s.check("schedule: bg_working", seqs(out) == "\x1b]9;simpleterm:state=background scheduled: */5 * * * *\x07"
            "\x1b]9;simpleterm:state=bg_working scheduled: */5 * * * *\x07", repr(out))
    # A question in a scheduled turn is still told.
    s.ctl("/_ctl/reset", {})
    s.run("claude", cc_event("sc3", "UserPromptSubmit", prompt="x", source="schedule_wakeup"), st)
    out = stop("sc3", cron[:1], "The deploy failed. Should I roll back?")
    rec = wait_for(lambda: ingests(s, "question"), 20)
    s.check("schedule: a question in a scheduled turn -> question", len(rec) == 1 and "state=waiting" in seqs(out), str(ingests(s))[:300])
    # The Stop that finds the schedule gone is the done, once: to the tunnels only, and the screen says it was a
    # scheduled turn (SimpleTerm spec/turn-state#scheduled; the tunnel side is t_schedule_end).
    s.ctl("/_ctl/reset", {})
    s.run("claude", cc_event("sc3", "UserPromptSubmit", prompt="x", source="loop_wakeup"), st)
    out = stop("sc3", [], "The deploy finished; the loop ended.")
    s.settle("the hooks' background work")
    s.check("schedule: no schedule left -> done_scheduled on the screen, nothing to the relay",
            not ingests(s) and seqs(out) == "\x1b]9;simpleterm:state=done_scheduled\x07", repr(out) + str(ingests(s))[:300])
    # Grok Build.
    s.ctl("/_ctl/reset", {})
    gcron = [{"id": "g1", "schedule": "every 5 minutes", "recurring": True, "prompt": "check it"}]
    inp, env = grok_input("UserPromptSubmit", promptId="scheduler-fired-1", timestamp="2026-11-02T11:00:00.000Z", prompt="check it")
    s.run("claude", inp, dict(env, GROK_HOOK_EVENT="user_prompt_submit"))
    inp, env = grok_input("Stop", reason="end_turn", promptId="scheduler-fired-1", timestamp="2026-11-02T11:00:03.000Z",
                          lastAssistantMessage="Still fine.", backgroundTasks=[], sessionCrons=gcron)
    s.run("claude", inp, env)
    s.settle("the Grok hooks' background work")
    s.check("schedule: Grok Build scheduled turn -> nothing", not ingests(s), str(ingests(s))[:200])
    inp, env = grok_input("UserPromptSubmit", promptId="22222222-9300-4d94-aa8b-bed0ee67f947", timestamp="2026-11-02T11:05:00.000Z", prompt="hi")
    s.run("claude", inp, dict(env, GROK_HOOK_EVENT="user_prompt_submit"))
    inp, env = grok_input("Stop", reason="end_turn", promptId="22222222-9300-4d94-aa8b-bed0ee67f947", timestamp="2026-11-02T11:05:03.000Z",
                          lastAssistantMessage="Hello.", backgroundTasks=[], sessionCrons=gcron)
    s.run("claude", inp, env)
    s.check("schedule: Grok Build typed turn -> done", wait_for(lambda: ingests(s, "done"), 20))
    # Grok Build 1.0.77 (measured, SimpleTerm if/hook-events-turn#turn-end): each scheduled run is a background
    # subagent; the turn its result opens has promptId subagent-completed-<task>, names the schedule in its prompt
    # (scheduler_delete("<id>")) and its Stop still lists the schedule. Not a task's report: no done per run.
    sid1 = "01a1c998-e899-7942-881d-11d6b12c1b49"
    mcron = [{"id": sid1, "schedule": "every 1 minute", "recurring": True, "prompt": "say tick"}]

    def grok_run(i, crons, sched=sid1):
        pid = "subagent-completed-01a1c998-e8a0-7f71-a9cd-1cb9175eda%02d" % i
        prompt = ("<system-reminder>\nWhile you were idle, 1 background subagent completed:\n- [general-purpose] \"loop: say tick "
                  "(every 1 minute)\" — completed successfully (1.2s, 0 tool calls)\n=== Output ===\ntick\n\n")
        if sched:
            prompt += ("If this schedule is no longer relevant, run scheduler_delete(\"%s\"). If it is outdated, you can update "
                       "it with scheduler_create(new_prompt, interval, \"%s\").\n" % (sched, sched))
        prompt += "</system-reminder>"
        inp, env = grok_input("UserPromptSubmit", promptId=pid, timestamp="2026-11-11T07:5%d:25.586Z" % i, prompt=prompt)
        s.run("claude", inp, dict(env, GROK_HOOK_EVENT="user_prompt_submit"))
        inp, env = grok_input("Stop", reason="end_turn", promptId=pid, timestamp="2026-11-11T07:5%d:25.982Z" % i,
                              lastAssistantMessage="Tick result %d received." % i, backgroundTasks=[], sessionCrons=crons)
        s.run("claude", inp, env)

    s.ctl("/_ctl/reset", {})
    grok_run(1, mcron)
    grok_run(2, mcron)
    s.settle("the Grok hooks' background work (a done's wait, if one started)")
    s.check("schedule: Grok Build scheduled runs (subagent-completed-, schedule named) -> nothing",
            not ingests(s), str([(r.get("body") or {}).get("ev") for r in ingests(s)])[:200])
    # The run whose turn dropped the schedule (its Stop lists none) is the last: no relay push either.
    grok_run(3, [])
    s.settle("the Grok hooks' background work (a done's wait, if one started)")
    s.check("schedule: Grok Build last scheduled run -> nothing to the relay", not ingests(s),
            str([(r.get("body") or {}).get("ev") for r in ingests(s)])[:200])
    # A background subagent the agent started itself (no schedule named) still reports as a task: done.
    s.ctl("/_ctl/reset", {})
    grok_run(4, mcron, sched=None)
    s.check("schedule: Grok Build task report with a schedule set -> done", wait_for(lambda: ingests(s, "done"), 20))

    # The report of work that a scheduled turn started is the schedule's too (SimpleTerm spec/turn-state#background,
    # hist/turn-state#d14); the report of work a person's turn started still ends in done. Prompt shapes measured
    # (hist/hook-events#e15).
    def cc(sid, name, **kw):
        return s.run("claude", cc_event(sid, name, **kw), st)[1]

    agent = {"type": "subagent", "status": "running", "description": "run the checks"}
    s.ctl("/_ctl/reset", {})
    cc("sw1", "UserPromptSubmit", prompt="run the checks in a background agent", source="schedule_wakeup")
    cc("sw1", "Stop", stop_hook_active=False, last_assistant_message="Started the checks.",
       background_tasks=[dict(agent, id="a5c0ffee000000001")], session_crons=cron)
    cc("sw1", "UserPromptSubmit", prompt="<task-notification>\n<task-id>a5c0ffee000000001</task-id>\n<status>completed</status>")
    out = cc("sw1", "Stop", stop_hook_active=False, last_assistant_message="All checks passed.", background_tasks=[],
             session_crons=cron)
    s.settle("the hooks' background work (a done's wait, if one started)")
    s.check("schedule: the report of a loop turn's background agent rests with the loop (no done)",
            not ingests(s) and seqs(out).startswith("\x1b]9;simpleterm:state=background scheduled:"), repr(out) + str(ingests(s))[:200])
    s.ctl("/_ctl/reset", {})
    cc("sw2", "UserPromptSubmit", prompt="run the checks in a background agent", source="user")
    cc("sw2", "Stop", stop_hook_active=False, last_assistant_message="Started the checks.",
       background_tasks=[dict(agent, id="a5c0ffee000000002")], session_crons=cron)
    cc("sw2", "UserPromptSubmit", prompt="<task-notification>\n<task-id>a5c0ffee000000002</task-id>\n<status>completed</status>")
    cc("sw2", "Stop", stop_hook_active=False, last_assistant_message="All checks passed.", background_tasks=[], session_crons=cron)
    s.check("schedule: the report of a person's background agent with the loop set -> done", wait_for(lambda: ingests(s, "done"), 20))
    s.check("schedule: ... its report came after the person's turn ended: a turn of its own (task)",
            (s.home / ".simpleterm" / "run" / "sw2.turn").read_text().split("\n")[0] == "task",
            (s.home / ".simpleterm" / "run" / "sw2.turn").read_text())
    # A chain: the loop turn starts agent A, A's report turn starts agent B; B's report rests with the loop too.
    s.ctl("/_ctl/reset", {})
    cc("sw3", "UserPromptSubmit", prompt="run the checks in a background agent", source="schedule_wakeup")
    cc("sw3", "Stop", stop_hook_active=False, last_assistant_message="Started the checks.",
       background_tasks=[dict(agent, id="a5c0ffee00000000a")], session_crons=cron)
    cc("sw3", "UserPromptSubmit", prompt="<task-notification>\n<task-id>a5c0ffee00000000a</task-id>\n<status>completed</status>")
    cc("sw3", "Stop", stop_hook_active=False, last_assistant_message="Checks failed; a fixer runs.",
       background_tasks=[dict(agent, id="a5c0ffee00000000b", description="fix the checks")], session_crons=cron)
    cc("sw3", "UserPromptSubmit", prompt="<task-notification>\n<task-id>a5c0ffee00000000b</task-id>\n<status>completed</status>")
    out = cc("sw3", "Stop", stop_hook_active=False, last_assistant_message="Fixed.", background_tasks=[], session_crons=cron)
    s.settle("the hooks' background work (a done's wait, if one started)")
    s.check("schedule: a chain of reports from a loop turn (agent A starts agent B) rests with the loop (no done)",
            not ingests(s) and seqs(out).startswith("\x1b]9;simpleterm:state=background scheduled:"), repr(out) + str(ingests(s))[:200])

    # Work that ends inside the running turn: Claude Code hands its <task-notification> to that turn as a prompt,
    # between its tool calls (shapes: the orca fixture claude-task-notification-hooks.jsonl, shell-ends-mid-turn
    # and subagent-ends-mid-turn). It does not start a turn: the mark stays, the loop turn ends quiet.
    def mark(sid):
        return (s.home / ".simpleterm" / "run" / (sid + ".turn")).read_text().split("\n")

    note = "<task-notification>\n<task-id>bwaw14qyq</task-id>\n<status>completed</status>\n</task-notification>"
    s.ctl("/_ctl/reset", {})
    cc("sw4", "UserPromptSubmit", prompt="run the checks", source="schedule_wakeup")
    cc("sw4", "PostToolUse", tool_name="Bash", tool_input={"command": "sleep 2", "run_in_background": True})
    cc("sw4", "UserPromptSubmit", prompt=note)
    m = mark("sw4")
    out = cc("sw4", "Stop", stop_hook_active=False, last_assistant_message="Checks passed.", background_tasks=[], session_crons=cron)
    s.settle("the hooks' background work (a done's wait, if one started)")
    s.check("schedule: a report inside a loop turn keeps the loop's mark -> quiet (no done)",
            m[0] == "schedule" and not ingests(s) and seqs(out).startswith("\x1b]9;simpleterm:state=background scheduled:"),
            repr(m) + repr(out) + str(ingests(s))[:200])
    s.check("schedule: ... and the Stop closes the turn (no open line)", mark("sw4")[3:4] in ([], [""]), repr(mark("sw4")))
    s.ctl("/_ctl/reset", {})
    cc("sw5", "UserPromptSubmit", prompt="run the checks", source="user")
    cc("sw5", "UserPromptSubmit", prompt=note)
    s.check("schedule: a report inside a person's turn keeps the person's mark", mark("sw5")[0] == "user", repr(mark("sw5")))
    # Once the turn is over (Esc during a tool call, or a failed turn), a report starts its own turn.
    cc("sw6", "UserPromptSubmit", prompt="run the checks", source="schedule_wakeup")
    cc("sw6", "PostToolUseFailure", tool_name="Bash", tool_input={"command": "ls"}, is_interrupt=True, error="interrupted")
    cc("sw6", "UserPromptSubmit", prompt=note)
    s.check("schedule: after Esc, a report starts a turn of its own (task)", mark("sw6")[0] == "task", repr(mark("sw6")))
    cc("sw7", "UserPromptSubmit", prompt="run the checks", source="schedule_wakeup")
    cc("sw7", "StopFailure", error="server_error", last_assistant_message="API Error: 500")
    cc("sw7", "UserPromptSubmit", prompt=note)
    s.check("schedule: after a failed turn, a report starts a turn of its own (task)", mark("sw7")[0] == "task", repr(mark("sw7")))
    # Esc while Claude Code writes (or runs a tool) runs no hook at all (measured on 2.1.319 and 2.1.325,
    # SimpleTerm hist/hook-events#e23, AhMunGa/simple-term#685). Every hook of a turn carries its prompt_id, a report
    # inside the running turn included; a report after the stopped turn has a prompt_id of its own: a turn of its own
    # (hist/turn-state#d18). Here a person's turn starts an agent, a loop turn is stopped with Esc, and the agent's
    # report comes: its done is told although the loop remains.
    pa, pb, pc = ("7381fea8-eab8-4422-8076-855ff02b371a", "0f9589d0-a898-4288-a7f1-59dcea053a80",
                  "d6f4c338-0510-43e5-b216-d47ba50d4979")
    s.ctl("/_ctl/reset", {})
    cc("sw8", "UserPromptSubmit", prompt="run the checks in a background agent", source="user", prompt_id=pc)
    cc("sw8", "Stop", stop_hook_active=False, last_assistant_message="Started the checks.", prompt_id=pc,
       background_tasks=[dict(agent, id="a5c0ffee000000008")], session_crons=cron)
    cc("sw8", "UserPromptSubmit", prompt="check the deploy", source="loop_wakeup", prompt_id=pa)
    cc("sw8", "UserPromptSubmit", prompt="<task-notification>\n<task-id>a5c0ffee000000008</task-id>\n<status>completed</status>",
       prompt_id=pb)
    m = mark("sw8")
    out = cc("sw8", "Stop", stop_hook_active=False, last_assistant_message="All checks passed.", background_tasks=[],
             session_crons=cron, prompt_id=pb)
    s.check("schedule: after an Esc that ran no hook, a report with its own prompt_id starts a turn (task, id kept)",
            m[0] == "task" and m[3:5] == ["open", pb], repr(m))
    s.check("schedule: ... and its end is a done though the loop remains", wait_for(lambda: ingests(s, "done"), 20),
            repr(out) + str(ingests(s))[:200])
    s.check("schedule: ... the Stop closes the turn and keeps its id", mark("sw8")[3:5] == ["", pb], repr(mark("sw8")))
    # The same prompt_id: work that ended inside the running loop turn, whose mark stays (quiet).
    s.ctl("/_ctl/reset", {})
    cc("sw9", "UserPromptSubmit", prompt="check the deploy", source="loop_wakeup", prompt_id=pa)
    cc("sw9", "UserPromptSubmit", prompt=note, prompt_id=pa)
    m = mark("sw9")
    out = cc("sw9", "Stop", stop_hook_active=False, last_assistant_message="Checks passed.", background_tasks=[],
             session_crons=cron, prompt_id=pa)
    s.settle("the hooks' background work (a done's wait, if one started)")
    s.check("schedule: a report with the running turn's prompt_id keeps the loop's mark -> quiet",
            m[0] == "schedule" and m[3:5] == ["open", pa] and not ingests(s)
            and seqs(out).startswith("\x1b]9;simpleterm:state=background scheduled:"), repr(m) + repr(out) + str(ingests(s))[:200])
    # Grok Build: a scheduled run's turn starts a background command; its task-completed- report rests too.
    s.ctl("/_ctl/reset", {})
    grok_run(5, mcron)
    pid = "subagent-completed-01a1c998-e8a0-7f71-a9cd-1cb9175eda06"
    inp, env = grok_input("UserPromptSubmit", promptId=pid, timestamp="2026-11-11T08:00:00.000Z",
                          prompt="<system-reminder>\nscheduler_delete(\"%s\")\n</system-reminder>" % sid1)
    s.run("claude", inp, dict(env, GROK_HOOK_EVENT="user_prompt_submit"))
    inp, env = grok_input("Stop", reason="end_turn", promptId=pid, timestamp="2026-11-11T08:00:01.000Z", lastAssistantMessage="Running it.",
                          backgroundTasks=[{"id": "gbash01", "type": "bash", "status": "running", "command": "npm test"}], sessionCrons=mcron)
    s.run("claude", inp, env)
    inp, env = grok_input("UserPromptSubmit", promptId="task-completed-gbash01", timestamp="2026-11-11T08:00:30.000Z", prompt="npm test finished")
    s.run("claude", inp, dict(env, GROK_HOOK_EVENT="user_prompt_submit"))
    inp, env = grok_input("Stop", reason="end_turn", promptId="task-completed-gbash01", timestamp="2026-11-11T08:00:31.000Z",
                          lastAssistantMessage="Tests pass.", backgroundTasks=[], sessionCrons=mcron)
    s.run("claude", inp, env)
    s.settle("the Grok hooks' background work (a done's wait, if one started)")
    s.check("schedule: Grok Build report of a scheduled run's command -> nothing", not ingests(s),
            str([(r.get("body") or {}).get("ev") for r in ingests(s)])[:200])


def t_schedule_end(s):
    """The end of a turn a schedule started (SimpleTerm spec/turn-state#scheduled, AhMunGa/simple-term#469): with no
    schedule left it is a done to the tunnels only, at once, and Claude's screen says done_scheduled; one that ended
    asking is a plain done on the screen, the tunnels and the relay. A turn a task's report started ends in done
    while a schedule remains (SimpleTerm spec/turn-state#background). A StopFailure writes idle, then error, in one
    output (SimpleTerm if/terminal-signals#structured): no green done, and an app older than error is left with idle;
    a login error too, while its event says auth."""
    tun, tctl = s.spawn_mock()
    try:
        s.setup([(LINK_A, {}), (LINK_T, {"kind": "tunnel", "relay_url": tctl.url, "fmt": 2})], conf={"done_delay": None})
        st = {"SIMPLETERM": "1"}
        cron = [{"id": "c1", "schedule": "*/5 * * * *", "recurring": True, "prompt": "check the deploy"}]

        def reset():
            s.ctl("/_ctl/reset", {})
            tctl("/_ctl/reset", {})
            tctl("/_ctl/config", {"links": {LINK_T["id"]: dict(LINK_T)}})

        def stop(sid, crons, last):
            return s.run("claude", cc_event(sid, "Stop", stop_hook_active=False, last_assistant_message=last,
                                            background_tasks=[], session_crons=crons), st)[1]

        def tunnel(ev):
            return [r for r in ingests(s, ctl=tctl) if (r.get("body") or {}).get("ev") == ev]

        def turn(rec):
            return (rec[0].get("plain_json") or {}).get("turn", {}) if rec else {}

        reset()
        s.run("claude", cc_event("se1", "UserPromptSubmit", prompt="check the deploy", source="loop_wakeup"), st)
        t0 = time.time()
        out = stop("se1", [], "The deploy finished; the loop ended.")
        # No done_delay: the hook left no se1.pend, the file a done that waits keeps until it goes (both hooks).
        # (Not a time bound: on a loaded machine a PowerShell send alone takes seconds to start.)
        waited = (s.home / ".simpleterm" / "run" / "se1.pend").exists()
        s.check("schedule end: the screen says done_scheduled", seqs(out) == "\x1b]9;simpleterm:state=done_scheduled\x07", repr(out))
        d = wait_for(lambda: tunnel("done"), 10)
        s.check("schedule end: one done with by schedule to the tunnel, at once (no done_delay)",
                len(d) == 1 and turn(d).get("by") == "schedule" and not waited,
                "waited %s %s" % (waited, str([(turn([r]), round(r["received"] - t0, 2)) for r in d])[:300]))
        s.settle("the Stop hook's background work (the shipped done_delay, 3 s, if a done waits)")
        s.check("schedule end: nothing to the relay", not ingests(s), str(ingests(s))[:300])

        # Decision 9 (SimpleTerm hist/turn-state#d9): a scheduled turn that ended asking is a plain done everywhere.
        reset()
        s.run("claude", cc_event("se2", "UserPromptSubmit", prompt="check the deploy", source="loop_wakeup"), st)
        out = stop("se2", [], "The deploy failed. Should I roll back?")
        s.check("schedule end asking: done on the screen", seqs(out) == "\x1b]9;simpleterm:state=done\x07", repr(out))
        r = wait_for(lambda: ingests(s, "done"), 20)
        s.check("schedule end asking: done to the relay, by schedule, asks", len(r) == 1 and turn(r).get("by") == "schedule"
                and turn(r).get("asks") is True, str(r)[:300])
        s.check("schedule end asking: and to the tunnel", wait_for(lambda: tunnel("done"), 10), str(ingests(s, ctl=tctl))[:300])

        # A task's report woke the agent while a schedule is still set: its end is a done (it is no scheduled turn).
        reset()
        s.run("claude", cc_event("se3", "UserPromptSubmit",
                                 prompt="<task-notification>\n<task-id>b4y66jodr</task-id>\n<status>completed</status>"), st)
        out = stop("se3", cron, "The tests passed.")
        s.check("task turn with a schedule set: done on the screen", seqs(out) == "\x1b]9;simpleterm:state=done\x07", repr(out))
        r = wait_for(lambda: ingests(s, "done"), 20)
        s.check("task turn with a schedule set: done to the relay, by task", len(r) == 1 and turn(r).get("by") == "task", str(r)[:300])
        # A turn the schedule started with the schedule still set stays a pause (the loop stays quiet).
        reset()
        s.run("claude", cc_event("se3", "UserPromptSubmit", prompt="check the deploy", source="loop_wakeup"), st)
        out = stop("se3", cron, "Still deploying.")
        s.check("scheduled turn with a schedule set: still background", seqs(out).startswith("\x1b]9;simpleterm:state=background scheduled:"), repr(out))
        st_ev = wait_for(lambda: [x for x in tunnel("state") if (x.get("plain_json") or {}).get("st") == "scheduled"], 10)
        s.settle("the Stop hook's background work (the shipped done_delay, 3 s, if a done waits)")
        s.check("scheduled turn with a schedule set: state scheduled, no done anywhere",
                st_ev and not tunnel("done") and not ingests(s, "done"), str(ingests(s, ctl=tctl))[:300])

        # StopFailure: idle, then error, in one output; the event goes as before.
        failed = "\x1b]9;simpleterm:state=idle\x07\x1b]9;simpleterm:state=error\x07"
        reset()
        out = s.run("claude", cc_event("se4", "StopFailure", error="server_error", error_details="overloaded",
                                       last_assistant_message=""), st)[1]
        s.check("StopFailure: the screen says idle, then error", seqs(out) == failed, repr(out))
        s.check("StopFailure: the error goes", wait_for(lambda: ingests(s, "error"), 20), str(ingests(s))[:300])
        # A login error is no other screen value (SimpleTerm hist/turn-state#d10): error there, auth as the event.
        reset()
        out = s.run("claude", cc_event("se5", "StopFailure", error="authentication_failed",
                                       last_assistant_message=""), st)[1]
        s.check("StopFailure login: the screen says idle, then error", seqs(out) == failed, repr(out))
        s.check("StopFailure login: the event says auth", wait_for(lambda: ingests(s, "auth"), 20), str(ingests(s))[:300])
    finally:
        tun.terminate()
        tun.wait(5)


def t_done_delay(s):
    """A done waits done_delay seconds (default 3) for another Stop hook that keeps the agent going."""
    s.setup([(LINK_A, {})], conf={"done_delay": None})
    t0 = time.time()
    stop = cc_event("dd1", "Stop", stop_hook_active=False, last_assistant_message="Implemented it.", background_tasks=[], session_crons=[])
    rc, out, err, el = s.run("claude", stop, {"SIMPLETERM": "1"})
    s.check("done delay: the badge changes at once", seqs(out) == "\x1b]9;simpleterm:state=done\x07" and el < 2, "%r %.2fs" % (out, el))
    rec = wait_for(lambda: ingests(s, "done"), 20)
    # (By the relay's clock.)
    s.check("done delay: no event yet after 1.2 s", all(r["received"] - t0 >= 1.2 for r in ingests(s)),
            str([(r["body"]["ev"], round(r["received"] - t0, 2)) for r in ingests(s)])[:200])
    s.check("done delay: sent after about 3 s", len(rec) == 1 and 2.7 <= rec[0]["received"] - t0 <= 12,
            str([round(r["received"] - t0, 2) for r in rec]))
    s.check("done delay: the event is made then (its time is the send time)",
            rec and abs(rec[0]["plain_json"]["ts"] - rec[0]["received"]) < 3, str(rec[0].get("plain_json") if rec else None))
    # Another Stop hook blocked, the agent works on: any newer event of the session ends the wait.
    s.ctl("/_ctl/reset", {})
    s.run("claude", stop, {"SIMPLETERM": "1"})
    s.run("claude", cc_event("dd1", "PostToolUse", tool_name="Bash", tool_input={"command": "npm test"}), {"SIMPLETERM": "1"})
    s.settle("the done's wait (done_delay, 3 s)")
    s.check("done delay: a newer event of the session -> no done", not ingests(s), str(ingests(s))[:200])
    # ... and the Stop that follows replaces it: one done, with its message.
    s.ctl("/_ctl/reset", {})
    s.run("claude", cc_event("dd2", "Stop", stop_hook_active=False, last_assistant_message="First.", background_tasks=[], session_crons=[]))
    s.run("claude", cc_event("dd2", "Stop", stop_hook_active=True, last_assistant_message="Second.", background_tasks=[], session_crons=[]))
    rec = wait_for(lambda: ingests(s, "done"), 20)
    s.settle("both dones' waits (done_delay, 3 s)")
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
    s.settle("the hooks' background work (done_delay, 3 s)")
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
    s.settle("the hooks' background work (done_delay, 3 s)")
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
    s.settle("the Notification hook's sends")
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
    s.settle("the Notification hook's sends")
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
    s.settle("the hooks' background work (the PreToolUse report's ask_delay)")
    qs = ingests(s, "question")
    s.check("AskUserQuestion: one alert for PreToolUse + PermissionRequest", len(qs) == 1 and qs[0]["plain_json"].get("msg") == "Which database should I use?",
            str(ingests(s))[:300])
    q2 = {"questions": [{"question": "And which cache?", "header": "Cache", "options": [{"label": "Redis"}], "multiSelect": False}]}
    s.run("claude", cc_event("au1", "PermissionRequest", tool_name="AskUserQuestion", tool_input=q2), st)
    s.run("claude", cc_event("au1", "PreToolUse", tool_name="AskUserQuestion", tool_input=q2), st)
    s.run("claude", cc_event("au2", "PreToolUse", tool_name="AskUserQuestion", tool_input=q), st)
    wait_for(lambda: len(ingests(s, "question")) >= 3, 20)
    s.settle("the hooks' background work (the PreToolUse reports' ask_delay)")
    s.check("AskUserQuestion: another question or another session is another alert", len(ingests(s, "question")) == 3,
            str([r["plain_json"].get("msg") for r in ingests(s)]))
    _, out, _, _ = s.run("claude", cc_event("au1", "PreToolUse", tool_name="AskUserQuestion", tool_input=q), st)
    s.check("AskUserQuestion: the badge still says waiting for the repeat", seqs(out) == "\x1b]9;simpleterm:state=waiting\x07", repr(out))

    # Gemini CLI: AfterAgent with "[no response text]" is an API error, a cancel or a loop, not a finished answer.
    # (Gemini CLI runs the sh hook only; the PowerShell hook has no gemini agent.)
    if s.kind != "ps1":
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
    s.check("interrupt: ends the pause with bg_clear", seqs(out) == "\x1b]9;simpleterm:state=idle\x07\x1b]9;simpleterm:state=bg_clear\x07", repr(out))


AGENT_PY = (
    "import subprocess, sys\n"
    "p = subprocess.Popen(sys.argv[2:], stdin=subprocess.PIPE)\n"
    "p.stdin.write(sys.argv[1].encode()); p.stdin.close()\n"
    "print(p.pid, flush=True)\n"
    "p.wait()\n"
)
# The same, but it starts the hook only once a line comes on its stdin: the test first writes what
# the agent records before it runs a hook (Claude Code's session file, sessions/<pid>.json).
AGENT_GATED_PY = "import sys\nsys.stdin.readline()\n" + AGENT_PY


def t_agent_gone(s):
    """The agent process exits while the hook waits: stop polling, print nothing."""
    s.setup([(LINK_A, {})], conf={"claude_wait": 60})
    cmd = [sys.executable, "-I", "-c", AGENT_PY, perm_input(session="gone")] + list(s.argv) + ["claude"]
    agent = s.popen(cmd, stdout=subprocess.PIPE, env=s.env(), cwd=str(s.tmp))
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
    s.settle("the hook's polls")
    s.check("agent gone: polling stopped", len(s.records("/v1/decision")) == n, "%d -> %d" % (n, len(s.records("/v1/decision"))))


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
    s.settle("the Stop hook's background work")
    s.check("events: codex title-generation Stop filtered", not s.records("/v1/ingest"))
    for first, expect in (("Generate a concise, single-line task title for this", 0), ("Fix the tests", 1)):
        s.ctl("/_ctl/reset", {})
        j = json.dumps({"type": "agent-turn-complete", "thread-id": "x", "turn-id": "y", "cwd": "/r",
                        "client": "codex-tui", "input-messages": [first], "last-assistant-message": "done"})
        s.run("codex-notify", "", args=(j,))
        if expect:
            wait_for(lambda: s.records("/v1/ingest"), 20)
        s.settle("the notify hook's background work")
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
    if s.kind != "sh":
        return
    argv = s.argv
    shell = os.path.basename(s.argv[0])
    if shell not in ("bash", "zsh"):
        # Only these two can switch the builtin off (bash not in sh mode: as sh it reads no BASH_ENV), so
        # bash stands in for the environment's shell; the hook's check (`command -v printf`) is the same.
        if not os.path.exists("/bin/bash"):
            return
        s.argv, shell = ["/bin/bash"] + s.argv[1:], "bash"
    rc_dir = s.tmp / "rc"
    rc_dir.mkdir(exist_ok=True)
    (rc_dir / "bashenv").write_text("enable -n printf\n")
    (rc_dir / ".zshenv").write_text("disable printf\n")
    extra = {"BASH_ENV": str(rc_dir / "bashenv")} if shell == "bash" else {"ZDOTDIR": str(rc_dir)}
    try:
        s.setup([(LINK_A, {"decision": "allow", "after": 1})])
        rc, out, err, el = s.run("claude", perm_input(), dict(extra, SIMPLETERM="1"))
        s.check("external printf: nothing sent", not s.records("/v1/ingest"), str(s.records())[:200])
        s.check("external printf: no decision, exit 0", rc == 0 and out.strip() == "", out + err)
        s.check("external printf: logged", "printf is not a shell builtin; relay disabled" in s.log_text(), s.log_text())
        stop = json.dumps({"session_id": "s", "hook_event_name": "Stop", "cwd": "/x", "last_assistant_message": "ok"})
        rc, out, err, el = s.run("claude", stop, dict(extra, SIMPLETERM="1"))
        s.check("external printf: terminal sequence still works", "simpleterm:state=done" in out, out + err)
        s.settle("the Stop hook's background work")
        s.check("external printf: no background send either", not s.records("/v1/ingest"))
    finally:
        s.argv = argv


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


def codex_token_line(total=15159, window=258400, rl=True, reached=None, ts="2026-11-03T01:02:03.456Z"):
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
    return json.dumps({"timestamp": ts, "ordinal": 1, "type": "event_msg",
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
    # The done and the usage go out from separate background sends (on Windows separate processes).
    wait_for(lambda: len(ingests(s)) >= 2, 20)
    s.check("usage claude: own rid", rec and len({r["body"]["rid"] for r in ingests(s)}) == 2, str(ingests(s))[:300])
    # Unchanged: nothing more (no sequence, no event).
    s.ctl("/_ctl/reset", {})
    rc, out, err, el = s.run("claude", json.dumps(stop), {"SIMPLETERM": "1"})
    s.settle("the Stop hook's sends")
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
            seqs(out) == "\x1b]9;simpleterm:state=idle\x07\x1b]9;simpleterm:state=error\x07"
                          "\x1b]9;simpleterm:usage v=1 agent=claude-code ctx=42000 win=1000000"
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
    s.settle("the Stop hook's sends")
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
    p = s.proc_run([s.argv[0], str(tap), "cat"], input=json.dumps(STATUSLINE).encode(), capture_output=True,
                       env=s.env(), timeout=20)
    s.check("statusline: passes the input to the user's command", p.stdout.decode() == json.dumps(STATUSLINE), p.stdout[:200])
    saved = s.home / ".simpleterm" / "run" / "usage.u-claude.json"
    s.check("statusline: saved for the hooks", saved.exists() and saved.read_text().split("\n", 1)[1].strip() == json.dumps(STATUSLINE))
    # Claude Code runs a status line command with /bin/sh -c (spawn shell: true), not $SHELL or
    # the first sh on PATH: the user's command must see the same interpreter behind the tap.
    p = s.proc_run([s.argv[0], str(tap), 'echo "$0"'], input=b"{}", capture_output=True,
                       env=s.env({"SHELL": "/bin/zsh"}), timeout=20)
    s.check("statusline: the user's command runs with /bin/sh, as in Claude Code", p.stdout == b"/bin/sh\n", p.stdout)
    p = s.proc_run([s.argv[0], str(tap)], input=b"{}", capture_output=True, env=s.env(), timeout=20)
    s.check("statusline: no command and no data prints nothing", p.stdout == b"" and p.returncode == 0, p.stdout)
    p = s.proc_run([s.argv[0], str(tap)], input=json.dumps(STATUSLINE).encode(), capture_output=True, env=s.env(), timeout=20)
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
        {"id": "five_hour", "pct": 23.5, "win_min": 300, "resets_at": 4102444800, "src": "statusline"},
        {"id": "seven_day", "pct": 41.2, "win_min": 10080, "resets_at": 4102444800, "src": "statusline"}], str(rec[0].get("plain_json") if rec else None))
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
        s.settle("the PostToolUse hook's sends")
        s.check("usage policy: PostToolUse at most every 20 s", len(ingests(s, "usage", tctl)) == 1, str(len(ingests(s, "usage", tctl))))
        s.run("claude", json.dumps(dict(base, hook_event_name="Stop", last_assistant_message="ok")))
        s.check("usage policy: turn end reaches the tunnel (changed)", wait_for(lambda: len(ingests(s, "usage", tctl)) == 2, 20))
        got = (ingests(s, "usage", tctl)[-1].get("plain_json") or {}).get("ctx", {}) if ingests(s, "usage", tctl) else {}
        s.check("usage policy: the turn's last value", got.get("used") == 5320, str(got))
        s.check("usage policy: the relay gets done", wait_for(lambda: ingests(s, "done"), 20))
        s.settle("the Stop hook's sends")
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
        s.settle("the Stop hook's sends")
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
    # SimpleTerm if/usage-report#v2-fields: the rollout is a file source; at is the token_count record's time.
    s.check("usage codex: limits and plan", p.get("lims") == [
        {"id": "codex.primary", "pct": 4.0, "win_min": 300, "resets_at": 1795746291, "src": "file", "at": 1793667723},
        {"id": "codex.secondary", "pct": 12.5, "win_min": 10080, "resets_at": 1796000000, "src": "file", "at": 1793667723}]
            and p.get("plan") == "plus", str(p))
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
    s.settle("the Stop hook's sends")
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
    # SessionEnd (SimpleTerm hist/event-v2#r7): Codex 0.165 runs it for every reason ("other" only), at most 3 seconds (more
    # is cut to 3 with a warning) and ends the hook's process group then (measured).
    se = hooks["SessionEnd"][0]
    s.check("codex hooks: SessionEnd for every end, within Codex's 3-second limit",
            not se.get("matcher") and se["hooks"][0]["timeout"] <= 3, str(se))
    for ev in ("SessionStart", "PostCompact", "Stop", "SessionEnd"):
        cmd = hooks[ev][0]["hooks"][0]["command"].replace("${PLUGIN_ROOT}", str(noisy))
        p = s.proc_run([s.argv[0], "-c", cmd], input=b"{}", capture_output=True, env=s.env(), timeout=20)
        s.check("codex hooks: %s command prints nothing, whatever the script writes" % ev,
                p.returncode == 0 and p.stdout == b"", p.stdout)
    s.setup([(LINK_A, {"push": "disabled", "kind": "tunnel"})])
    ro = write(s.tmp / "codex" / "rollout-ss.jsonl", codex_token_line(total=15159) + "\n")
    cmd = hooks["SessionStart"][0]["hooks"][0]["command"].replace("${PLUGIN_ROOT}", str(SCRIPTS.parent))
    inp = json.dumps({"session_id": "cx-ss", "transcript_path": str(ro), "cwd": "/w/repo", "hook_event_name": "SessionStart",
                      "source": "resume", "model": "gpt-5.5"})
    p = s.proc_run([s.argv[0], "-c", cmd], input=inp.encode(), capture_output=True, env=s.env({"SIMPLETERM": "1"}), timeout=30)
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
    s.settle("the hooks' background work")
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
    if pid > 0:
        # (Its own session: reaped with the case.)
        track(pid, s)
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
    p = s.proc_run([s.argv[0], str(SCRIPTS / "simpleterm-notify.sh"), "notify", "no tty title", "body"], capture_output=True,
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
        s.settle("simpleterm notify's background work")
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
    p = s.proc_run([str(w), "notify", "via wrapper"], capture_output=True, env=s.env(), timeout=20)
    s.check("cli: wrapper runs notify", p.returncode == 0 and wait_for(lambda: ingests(s, "notify"), 20), p.stderr)
    w.write_text(text.replace(str(SCRIPTS), "/nonexistent/old-version"))
    p = s.proc_run([str(w), "notify", "x"], capture_output=True, env=s.env(), timeout=20)
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
    """The Copilot plugin (SimpleTerm if/plugin-locations#manifests, #381): its own hooks file in Copilot's format; every command
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
        p = s.proc_run(["/bin/bash", "-c", cmd], input=b"{}", capture_output=True, cwd=str(proj), env=s.env(dict({"COPILOT_HOME": str(cop)}, **env)), timeout=60)
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


TTY_PY = (
    # Makes the pty slave argv[1] this session's controlling terminal (the hook's /dev/tty), then runs argv[2:].
    "import fcntl, os, sys, termios\n"
    "fd = os.open(sys.argv[1], os.O_RDWR)\n"
    "try:\n"
    "    fcntl.ioctl(fd, termios.TIOCSCTTY, 0)\n"
    "except OSError:\n"
    "    pass\n"
    "os.close(fd)\n"
    "os.execv(sys.argv[2], sys.argv[2:])\n"
)


def on_tty(s, agent, stdin, extra, args=(), hold=None):
    """Runs the hook with a pty as its controlling terminal, as Copilot CLI runs its hooks (in the shell's
    session: SimpleTerm hist/hook-events#e27). Returns (stdout, bytes the hook wrote to the terminal). With `hold`,
    the input is held back until hold(read, process) returns: read() gives the terminal's bytes so far.
    The master is read the whole time the hook lives, and the slave stays open here: a session leader whose terminal
    has unread output does not finish exiting on macOS (it stays `?Es`, measured), and a pty whose slave is closed
    loses what is written to it."""
    master, slave = os.openpty()
    got = bytearray()
    lock = threading.Lock()
    stop = threading.Event()

    def drain(wait):
        while select.select([master], [], [], wait)[0]:
            try:
                b = os.read(master, 4096)
            except OSError:
                return
            if not b:
                return
            with lock:
                got.extend(b)

    def pump():
        while not stop.is_set():
            drain(0.05)
            time.sleep(0.02)

    def read():
        with lock:
            return bytes(got)
    th = threading.Thread(target=pump, daemon=True)
    th.start()
    try:
        cmd = [sys.executable, "-I", "-c", TTY_PY, os.ttyname(slave)] + list(s.argv) + [agent] + list(args)
        p = s.popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=s.env(extra), cwd=str(s.tmp))
        if hold:
            hold(read, p)
        try:
            out, _ = p.communicate(stdin.encode(), timeout=60)
        except subprocess.TimeoutExpired:
            p.kill()
            try:
                p.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                pass
            s.check("on a terminal: %s %s ends within 60 s" % (agent, " ".join(args)), False, "env %s; tty %r" % (extra, read()))
            return "", read()
        stop.set()
        th.join(2)
        drain(0.2)
        return out.decode("utf-8", "replace"), read()
    finally:
        stop.set()
        th.join(2)
        os.close(slave)
        os.close(master)


def t_copilot_session_end(s):
    """Copilot CLI writes no OSC 7501 `clear` when it ends (1.0.109); on sessionEnd the hook writes exactly
    ESC ] 7501 ; state=clear BEL to /dev/tty, once and before anything else (the record, the relay send), only with
    SIMPLETERM=1, TMUX, STY and HERDR_ENV all empty and a terminal; else nothing and no log line (SimpleTerm
    if/hook-events#session-end, #vectors, hist/hook-events#d10). No other agent's end writes it."""
    clear = bytes.fromhex("1b5d373530313b73746174653d636c65617207")
    tun, tctl = s.spawn_mock()
    try:
        session_end_cases(s, tctl, clear)
    finally:
        tun.terminate()
        tun.wait(5)


def session_end_cases(s, tctl, clear):
    s.setup([(LINK_T, {"kind": "tunnel", "relay_url": tctl.url, "fmt": 2})])
    tctl("/_ctl/reset", {})
    tctl("/_ctl/config", {"links": {LINK_T["id"]: dict(LINK_T, unknown_error="unknown")}})
    base = {"sessionId": "cse-1", "timestamp": 1793635914148, "cwd": "/w/proj", "reason": "user_exit"}
    env = {"SIMPLETERM": "1", "COPILOT_CLI_BINARY_VERSION": "1.0.109"}
    s.run("copilot", json.dumps(dict(base, source="new", initialPrompt="")), env, args=("sessionStart",))
    s.settle("the sessionStart hook's background work")
    ended = lambda: list((s.home / ".simpleterm" / "sessions").glob("*/*.ended"))
    states = lambda: [r["plain_json"].get("st") for r in ingests(s, "state", ctl=tctl)]
    sent0 = len(ingests(s, ctl=tctl))
    seen = {}

    def first(read, p):
        # The clear is on the terminal while the hook still waits for its input: nothing else came first.
        seen["tty"] = wait_for(read, 10)
        seen["running"] = p.poll() is None
        seen["ended"] = ended()
        seen["sent"] = len(ingests(s, ctl=tctl)) - sent0
    out, tty = on_tty(s, "copilot", json.dumps(base), env, ("sessionEnd",), hold=first)
    s.check("session end: the bytes, once", tty == clear, repr(tty))
    s.check("session end: before anything else (the input not read yet, no record, no send)",
            seen.get("tty") == clear and seen.get("running") and seen.get("ended") == [] and seen.get("sent") == 0, str(seen))
    st = wait_for(lambda: "ended" in states() and states(), 10)
    s.check("session end: then the record and the tunnel send", ended() != [] and "ended" in (st or []), "%s %s" % (ended(), st))
    s.check("session end: nothing on stdout", out == "", out)
    s.settle("the sessionEnd hook's background work")

    log0 = s.log_text()
    for label, extra in (("SIMPLETERM unset", {"SIMPLETERM": ""}), ("TMUX set", {"TMUX": "/tmp/tmux-1/default,1,0"}),
                         ("STY set", {"STY": "123.pts-1.host"}), ("HERDR_ENV=1", {"HERDR_ENV": "1"})):
        out, tty = on_tty(s, "copilot", json.dumps(dict(base, sessionId="cse-" + label[:4])), dict(env, **extra), ("sessionEnd",))
        s.check("session end: %s -> nothing on the terminal" % label, tty == b"", repr(tty))
    _, out, _, _ = s.run("copilot", json.dumps(dict(base, sessionId="cse-notty")), env, args=("sessionEnd",))
    s.settle("the sessionEnd hooks' background work")
    new = s.log_text()[len(log0):]
    s.check("session end: no terminal -> nothing, no log line about it (the sends log as always)",
            out == "" and not re.search(r"tty|7501|clear", new), new[-300:])
    # Other events and other agents' ends write nothing; a Claude-format hook in Copilot (COPILOT_CLI=1) writes it once.
    _, tty = on_tty(s, "copilot", json.dumps(dict(base, stopReason="end_turn")), env, ("agentStop",))
    s.check("session end: Copilot agentStop -> nothing on the terminal", tty == b"", repr(tty))
    for agent, ev in (("claude", {"session_id": "cse-cc", "hook_event_name": "SessionEnd", "reason": "other"}),
                      ("codex", {"session_id": "cse-cx", "hook_event_name": "SessionEnd"}),
                      ("grok", {"sessionId": "cse-gk", "hook_event_name": "SessionEnd", "reason": "shutdown"})):
        _, tty = on_tty(s, agent, json.dumps(ev), env)
        s.check("session end: %s SessionEnd -> nothing on the terminal" % agent, tty == b"", repr(tty))
    _, tty = on_tty(s, "claude", json.dumps({"sessionId": "cse-cf", "hook_event_name": "SessionEnd", "reason": "user_exit"}),
                    dict(env, COPILOT_CLI="1"))
    s.check("session end: Copilot through the Claude Code plugin -> the bytes, once", tty == clear, repr(tty))
    s.settle("the hooks' background work")


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
        s.settle("the errorOccurred hooks' background work")
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


def t_copilot_schedules(s):
    """Copilot CLI /every, /loop and /after (experimental; measured on 1.0.109 with a local model stub,
    SimpleTerm if/hook-events-turn#turn-end): a scheduled prompt starts with `[Scheduled prompt #<id>]`;
    events.jsonl holds session.schedule_created and session.schedule_cancelled. A scheduled turn with a
    schedule left is a pause (state scheduled); with none left its done goes to the tunnels only."""
    if s.kind != "sh":
        return
    tun, tctl = s.spawn_mock()
    try:
        s.setup([(LINK_T, {"kind": "tunnel", "relay_url": tctl.url, "fmt": 2}), (LINK_A, {"fmt": 2})])
        env = {"COPILOT_CLI": "1", "COPILOT_CLI_BINARY_VERSION": "1.0.109"}
        base = {"sessionId": "cops-1", "timestamp": 1794366354204, "cwd": "/w/proj"}
        tx = s.tmp / "cops" / "events.jsonl"
        lines = []

        def ev(t, data, agent=None):
            # A subagent's own events carry its agentId after data (measured on 1.0.105 and 1.0.109).
            rec = dict({"type": t, "data": data}, **({"agentId": agent} if agent else {}))
            rec.update({"id": "7033787d-cd09-404e-b99d-a3725d448438", "timestamp": "2026-11-11T03:12:01.230Z"})
            lines.append(json.dumps(rec, separators=(",", ":")))
            write(tx, "\n".join(lines) + "\n")

        def reset():
            s.ctl("/_ctl/reset", {})
            tctl("/_ctl/reset", {})
            tctl("/_ctl/config", {"links": {LINK_T["id"]: dict(LINK_T)}})

        def run_turn(sched_id, reply):
            prompt = "[Scheduled prompt #%d]\ncheck status" % sched_id
            s.run("copilot", json.dumps(dict(base, prompt=prompt)), env, args=("userPromptSubmitted",))
            ev("user.message", {"content": prompt, "source": "schedule-%d" % sched_id})
            ev("assistant.message", {"content": reply})
            s.run("copilot", json.dumps(dict(base, stopReason="end_turn", stop_hook_active=False, transcriptPath=str(tx))),
                  env, args=("agentStop",))

        def tunnel(kind):
            return [r for r in ingests(s, ctl=tctl) if (r.get("body") or {}).get("ev") == kind]

        reset()
        ev("session.schedule_created", {"id": 1, "intervalMs": 20000, "prompt": "check status", "recurring": True, "origin": "user"})
        run_turn(1, "Still deploying.")
        turn = (s.home / ".simpleterm" / "run" / "cops-1.turn").read_text().split("\n")[0]
        s.check("copilot schedule: a scheduled prompt's turn is the schedule's", turn == "schedule", turn)
        st = wait_for(lambda: [r for r in tunnel("state") if (r.get("plain_json") or {}).get("st") == "scheduled"], 10)
        s.settle("the agentStop hook's background work")
        s.check("copilot schedule: with the schedule left, state scheduled and no done",
                st and not tunnel("done") and not ingests(s, "done"), str(ingests(s, ctl=tctl))[:300])
        s.check("copilot schedule: the schedule is in turn.crons",
                (st[0]["plain_json"].get("turn") or {}).get("crons") == [{"sched": "every 20s", "prompt": "check status"}] if st else False,
                str(st[0]["plain_json"].get("turn") if st else None)[:300])
        # Cancelled in the schedule manager: the next scheduled turn (one more fire raced it) is the last.
        reset()
        ev("session.schedule_cancelled", {"id": 1})
        run_turn(1, "The deploy finished.")
        d = wait_for(lambda: tunnel("done"), 10)
        s.settle("the agentStop hook's background work")
        s.check("copilot schedule: none left -> done by schedule to the tunnel only",
                len(d) == 1 and (d[0]["plain_json"].get("turn") or {}).get("by") == "schedule" and not ingests(s, "done"),
                str(d)[:300] + str(ingests(s))[:200])
        # A one-shot /after is gone once its prompt came.
        reset()
        ev("session.schedule_created", {"id": 2, "at": 1794366400000, "prompt": "say hello", "recurring": False, "origin": "user"})
        run_turn(2, "Hello.")
        d = wait_for(lambda: tunnel("done"), 10)
        s.check("copilot schedule: a one-shot that fired leaves no schedule -> done to the tunnel",
                len(d) == 1 and (d[0]["plain_json"].get("turn") or {}).get("by") == "schedule", str(d)[:300])
        # A prompt you typed in the same session is yours.
        reset()
        s.run("copilot", json.dumps(dict(base, prompt="[not a schedule] hi")), env, args=("userPromptSubmitted",))
        turn = (s.home / ".simpleterm" / "run" / "cops-1.turn").read_text().split("\n")[0]
        s.check("copilot schedule: a typed prompt is the user's", turn == "user", turn)
        # A prompt you typed that starts like a scheduled one: the hook input is the same, but events.jsonl has no
        # source for it (measured on 1.0.109), so its end is yours: a plain done, to the relay too.
        reset()
        ev("session.schedule_created", {"id": 3, "intervalMs": 60000, "prompt": "check status", "recurring": True, "origin": "user"})
        typed = "[Scheduled prompt #1] hello there"
        s.run("copilot", json.dumps(dict(base, prompt=typed)), env, args=("userPromptSubmitted",))
        ev("user.message", {"content": typed})
        ev("assistant.message", {"content": "Hi."})
        s.run("copilot", json.dumps(dict(base, stopReason="end_turn", stop_hook_active=False, transcriptPath=str(tx))),
              env, args=("agentStop",))
        r = wait_for(lambda: ingests(s, "done"), 20)
        s.check("copilot schedule: a typed prompt that starts like a scheduled one ends as yours (done, by user)",
                len(r) == 1 and (r[0]["plain_json"].get("turn") or {}).get("by") == "user", str(ingests(s))[:300])

        # The report of a shell or subagent a scheduled run started rests with the schedule (SimpleTerm
        # spec/turn-state#background, hist/turn-state#d14); a typed prompt's work still ends in done. Shapes measured on
        # 1.0.105 and 1.0.109 (hist/hook-events#e15): the report turn's prompt is the notification's content, and no
        # user.message is written for that turn; events.jsonl has the turn start hook's hook.end, then the
        # system.notification.
        def opens():
            ev("hook.end", {"hookInvocationId": "6c1f74d3-8d68-4dd0-924f-901e1815a31f", "hookType": "userPromptSubmitted",
                              "success": True})

        def shell_report(prompt, src, shell):
            s.run("copilot", json.dumps(dict(base, prompt=prompt)), env, args=("userPromptSubmitted",))
            ev("user.message", dict({"content": prompt}, **({"source": src} if src else {})))
            ev("tool.execution_start", {"toolName": "bash", "mode": "async", "shellId": shell, "command": "npm test",
                                        "description": "run the checks"})
            ev("assistant.message", {"content": "Started the checks."})
            s.run("copilot", json.dumps(dict(base, stopReason="end_turn", stop_hook_active=False, transcriptPath=str(tx))),
                  env, args=("agentStop",))
            note = "<system_notification>\nShell command \"run the checks\" (shellId: %s) has completed successfully.\n</system_notification>" % shell
            opens()
            ev("system.notification", {"content": note, "kind": {"type": "shell_completed", "shellId": shell, "exitCode": 0,
                                                                "description": "run the checks"}})
            s.run("copilot", json.dumps(dict(base, prompt=note)), env, args=("userPromptSubmitted",))
            ev("assistant.message", {"content": "All checks passed."})
            s.run("copilot", json.dumps(dict(base, stopReason="end_turn", stop_hook_active=False, transcriptPath=str(tx))),
                  env, args=("agentStop",))

        def det_report(prompt, src, shell):
            # A detached shell (detach:true): no work to wait for, yet its end wakes the agent (measured on 1.0.109).
            s.run("copilot", json.dumps(dict(base, prompt=prompt)), env, args=("userPromptSubmitted",))
            ev("user.message", dict({"content": prompt}, **({"source": src} if src else {})))
            ev("tool.execution_start", {"toolCallId": "call_9_2", "toolName": "bash", "arguments": {
                "command": "sleep 4; echo DETDONE", "mode": "async", "detach": True, "shellId": shell, "description": "det sleep"}})
            ev("assistant.message", {"content": "Started it."})
            s.run("copilot", json.dumps(dict(base, stopReason="end_turn", stop_hook_active=False, transcriptPath=str(tx))),
                  env, args=("agentStop",))
            note = "<system_notification>\nDetached shell \"det sleep\" (shellId: %s) has completed.\n</system_notification>" % shell
            opens()
            ev("system.notification", {"content": note, "kind": {"type": "shell_detached_completed", "shellId": shell}})
            s.run("copilot", json.dumps(dict(base, prompt=note)), env, args=("userPromptSubmitted",))
            ev("assistant.message", {"content": "It finished."})
            s.run("copilot", json.dumps(dict(base, stopReason="end_turn", stop_hook_active=False, transcriptPath=str(tx))),
                  env, args=("agentStop",))

        def agent_report(prompt, src, call, agent):
            s.run("copilot", json.dumps(dict(base, prompt=prompt)), env, args=("userPromptSubmitted",))
            ev("user.message", dict({"content": prompt}, **({"source": src} if src else {})))
            ev("subagent.started", {"toolCallId": call, "agentName": "explore", "agentDisplayName": "sub1",
                                    "agentDescription": "review", "agentType": "explore", "executionMode": "background"}, agent)
            ev("assistant.message", {"content": "A reviewer runs."})
            # The subagent's own prompt may be written before the main agentStop (1.0.105): it is not the main prompt.
            ev("user.message", {"content": "review the diff", "source": "agent-cops-1"}, agent)
            s.run("copilot", json.dumps(dict(base, stopReason="end_turn", stop_hook_active=False, transcriptPath=str(tx))),
                  env, args=("agentStop",))
            ev("subagent.completed", {"toolCallId": call, "agentName": "explore", "agentDisplayName": "sub1"}, agent)
            note = "<system_notification>\nAgent \"sub1\" (explore) has finished processing and is now idle.\n</system_notification>"
            opens()
            ev("system.notification", {"content": note, "kind": {"type": "agent_idle", "agentId": agent, "agentType": "explore",
                                                                "displayName": "sub1", "description": "review"}})
            s.run("copilot", json.dumps(dict(base, prompt=note)), env, args=("userPromptSubmitted",))
            ev("assistant.message", {"content": "The review is in."})
            s.run("copilot", json.dumps(dict(base, stopReason="end_turn", stop_hook_active=False, transcriptPath=str(tx))),
                  env, args=("agentStop",))

        reset()
        shell_report("[Scheduled prompt #3]\ncheck status", "schedule-3", "sbg1")
        s.settle("the hooks' background work (a done's wait, if one started)")
        s.check("copilot schedule: the report of a scheduled run's shell -> no done",
                not tunnel("done") and not ingests(s, "done"), str(ingests(s, ctl=tctl))[:300] + str(ingests(s))[:200])
        reset()
        shell_report("run the checks", None, "ubg1")
        s.check("copilot schedule: the report of a typed prompt's shell with the schedule set -> done",
                wait_for(lambda: ingests(s, "done"), 20), str(ingests(s))[:300])
        reset()
        agent_report("[Scheduled prompt #3]\ncheck status", "schedule-3", "call_7_1", "5b0c2a1e-0000-4000-8000-00000000a001")
        s.settle("the hooks' background work (a done's wait, if one started)")
        s.check("copilot schedule: the report of a scheduled run's background subagent -> no done",
                not tunnel("done") and not ingests(s, "done"), str(ingests(s, ctl=tctl))[:300] + str(ingests(s))[:200])
        reset()
        agent_report("review the diff in the background", None, "call_8_1", "5b0c2a1e-0000-4000-8000-00000000a002")
        s.check("copilot schedule: the report of a typed prompt's background subagent with the schedule set -> done",
                wait_for(lambda: ingests(s, "done"), 20), str(ingests(s))[:300])
        reset()
        det_report("[Scheduled prompt #3]\ncheck status", "schedule-3", "det7")
        s.settle("the hooks' background work (a done's wait, if one started)")
        s.check("copilot schedule: the report of a scheduled run's detached shell -> no done",
                not tunnel("done") and not ingests(s, "done"), str(ingests(s, ctl=tctl))[:300] + str(ingests(s))[:200])
        reset()
        det_report("start the detached job", None, "det8")
        # The typed turn ends in done at once (a detached shell is no work left); its report is a task's done.
        r = wait_for(lambda: [x for x in ingests(s, "done") if (x["plain_json"].get("turn") or {}).get("by") == "task"], 20)
        s.check("copilot schedule: the report of a typed prompt's detached shell with the schedule set -> done", r,
                str([(x["plain_json"].get("turn") or {}).get("by") for x in ingests(s, "done")]))
        # Work that ends inside the scheduled run: its notification comes with no turn start hook (measured on 1.0.109)
        # and opens no turn, so the detached shell that run started is still the schedule's.
        reset()
        p = "[Scheduled prompt #3]\ncheck status"
        s.run("copilot", json.dumps(dict(base, prompt=p)), env, args=("userPromptSubmitted",))
        opens()
        ev("user.message", {"content": p, "source": "schedule-3"})
        ev("tool.execution_start", {"toolCallId": "call_9_3", "toolName": "bash", "arguments": {
            "command": "sleep 9; echo DET", "mode": "async", "detach": True, "shellId": "det9", "description": "det long"}})
        ev("tool.execution_start", {"toolCallId": "call_9_4", "toolName": "bash", "arguments": {
            "command": "sleep 2; echo BG", "mode": "async", "shellId": "sbg9", "description": "bg quick"}})
        ev("system.notification", {"content": "<system_notification>\nShell command \"bg quick\" (shellId: sbg9) has completed "
                                              "successfully.\n</system_notification>",
                                   "kind": {"type": "shell_completed", "shellId": "sbg9", "exitCode": 0, "description": "bg quick"}})
        ev("assistant.message", {"content": "Checked."})
        s.run("copilot", json.dumps(dict(base, stopReason="end_turn", stop_hook_active=False, transcriptPath=str(tx))),
              env, args=("agentStop",))
        note = "<system_notification>\nDetached shell \"det long\" (shellId: det9) has completed.\n</system_notification>"
        opens()
        ev("system.notification", {"content": note, "kind": {"type": "shell_detached_completed", "shellId": "det9"}})
        s.run("copilot", json.dumps(dict(base, prompt=note)), env, args=("userPromptSubmitted",))
        ev("assistant.message", {"content": "It finished."})
        s.run("copilot", json.dumps(dict(base, stopReason="end_turn", stop_hook_active=False, transcriptPath=str(tx))),
              env, args=("agentStop",))
        s.settle("the hooks' background work (a done's wait, if one started)")
        s.check("copilot schedule: a notification inside the scheduled run opens no turn; its detached shell's report -> no done",
                not tunnel("done") and not ingests(s, "done"), str(ingests(s, ctl=tctl))[:300] + str(ingests(s))[:200])
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
    s.settle("the agy Stop hook's background work")
    s.check("agy: Stop not fully idle -> nothing", out.strip() == "{}" and not ingests(s), out)
    rc, out, err, el = s.run("agy", agy_stop(), args=("Stop",))
    rec = wait_for(lambda: ingests(s, "done"), 20)
    s.check("agy: Stop fully idle -> done, {}", out.strip() == "{}" and rec and rec[0]["plain_json"].get("app") == "antigravity", out)
    # PreInvocation: {} as Stop (agy 1.5.16 and 1.5.5 went on with it, measured); nothing to the relay (state is the tunnels').
    s.ctl("/_ctl/reset", {})
    for n in (0, 1):
        rc, out, err, el = s.run("agy", json.dumps({"conversationId": "conv-1", "workspacePaths": ["/w/agyproj"], "invocationNum": n}),
                                 args=("PreInvocation",))
        s.check("agy: PreInvocation (invocationNum %d) -> {}, exit 0" % n, rc == 0 and out.strip() == "{}", out + err)
    s.settle("the agy PreInvocation hooks' background work")
    s.check("agy: PreInvocation -> nothing to the relay", not ingests(s), str(ingests(s))[:200])
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


AGY_FIX = HERE / "fixtures" / "agy-schedule"


def t_agy_schedule(s):
    """Antigravity CLI /schedule (SimpleTerm spec/turn-state#scheduled, if/hook-events-turn#turn-end,
    hist/turn-state#d19): no hook says who opened a turn, so the plugin reads it from the record at Stop. The records are
    the transcript_full.jsonl of each Stop as agy 1.5.5 wrote it (measured with a model stub, 2026-11-16): a person's turn
    is done though a schedule is set, a turn a schedule woke rests while a schedule is left and its last one is a done
    with by schedule to the tunnels only, a command's report is done (by task) unless a scheduled turn started the
    command."""
    tun, tctl = s.spawn_mock()
    try:
        s.setup([(LINK_A, {}), (LINK_T, {"kind": "tunnel", "relay_url": tctl.url, "fmt": 2})])

        def reset():
            s.ctl("/_ctl/reset", {})
            tctl("/_ctl/reset", {})
            tctl("/_ctl/config", {"links": {LINK_T["id"]: dict(LINK_T)}})

        def stop(case, k, idle):
            return s.run("agy", agy_stop(conversationId="agy-sched-%d" % case, fullyIdle=idle, executionNum=0,
                                         transcriptPath=str(AGY_FIX / ("case%d-stop%d.jsonl" % (case, k))), error=""),
                         args=("Stop",))

        def tunnel(ev):
            return [r for r in ingests(s, ctl=tctl) if (r.get("body") or {}).get("ev") == ev]

        def by(recs):
            return [((r.get("plain_json") or {}).get("turn") or {}).get("by") for r in recs]

        def state(st):
            return [r for r in tunnel("state") if (r.get("plain_json") or {}).get("st") == st]

        # cron `* * * * *`, MaxIterations 2: the person's turn, run 1 (fullyIdle false), run 2 (the last, true).
        reset()
        stop(1, 1, False)
        s.check("agy schedule: the person's turn that set a cron -> done (by user)",
                by(wait_for(lambda: ingests(s, "done"), 20)) == ["user"], str(ingests(s))[:300])
        reset()
        stop(1, 2, False)
        st = wait_for(lambda: state("scheduled"), 10)
        s.settle("the agy Stop hook's background work")
        s.check("agy schedule: a cron run with a run left -> state scheduled, no done",
                st and by(st) == ["schedule"] and not tunnel("done") and not ingests(s, "done"), str(ingests(s, ctl=tctl))[:300])
        reset()
        stop(1, 3, True)
        d = wait_for(lambda: tunnel("done"), 10)
        s.settle("the agy Stop hook's background work")
        s.check("agy schedule: the last cron run -> done by schedule to the tunnel only",
                by(d) == ["schedule"] and not ingests(s, "done"), str(d)[:300] + str(ingests(s))[:300])
        # A one-shot timer: the person's turn, the timer's turn.
        reset()
        stop(2, 1, False)
        s.check("agy schedule: the person's turn that set a timer -> done", wait_for(lambda: ingests(s, "done"), 20))
        reset()
        stop(2, 2, True)
        d = wait_for(lambda: tunnel("done"), 10)
        s.settle("the agy Stop hook's background work")
        s.check("agy schedule: the timer's turn -> done by schedule to the tunnel only",
                by(d) == ["schedule"] and not ingests(s, "done"), str(d)[:300] + str(ingests(s))[:300])
        # A background command of a person's turn: a pause, then its report turn is done (by task).
        reset()
        stop(3, 1, False)
        s.settle("the agy Stop hook's background work")
        s.check("agy schedule: a person's turn leaving a command -> no done yet", not ingests(s, "done") and not tunnel("done"),
                str(ingests(s))[:300])
        reset()
        stop(3, 2, True)
        s.check("agy schedule: the command's report turn -> done (by task)",
                by(wait_for(lambda: ingests(s, "done"), 20)) == ["task"], str(ingests(s))[:300])
        # The timer's turn starts a command: its report is the schedule's, the last turn (quiet).
        reset()
        stop(4, 1, False)
        wait_for(lambda: ingests(s, "done"), 20)
        reset()
        stop(4, 2, False)
        s.settle("the agy Stop hook's background work")
        s.check("agy schedule: the timer's turn leaving a command -> no done", not ingests(s, "done") and not tunnel("done"),
                str(ingests(s))[:300])
        reset()
        stop(4, 3, True)
        d = wait_for(lambda: tunnel("done"), 10)
        s.settle("the agy Stop hook's background work")
        s.check("agy schedule: the report of a command a scheduled turn started -> done by schedule to the tunnel only",
                by(d) == ["schedule"] and not ingests(s, "done"), str(d)[:300] + str(ingests(s))[:300])
        # A timer that fires inside the person's turn stays in that turn: done (by user).
        reset()
        stop(5, 1, True)
        s.check("agy schedule: a timer message inside a person's turn -> done (by user)",
                by(wait_for(lambda: ingests(s, "done"), 20)) == ["user"], str(ingests(s))[:300])
        # A cron killed in its first run's turn (manage_task kill): that run is the last.
        reset()
        stop(6, 1, False)
        wait_for(lambda: ingests(s, "done"), 20)
        reset()
        stop(6, 2, True)
        d = wait_for(lambda: tunnel("done"), 10)
        s.settle("the agy Stop hook's background work")
        s.check("agy schedule: the run that killed its cron -> done by schedule to the tunnel only",
                by(d) == ["schedule"] and not ingests(s, "done"), str(d)[:300] + str(ingests(s))[:300])
    finally:
        tun.terminate()
        tun.wait(5)


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
        p = s.proc_run([s.argv[0], "-c", cmd], input=stdin, capture_output=True, cwd=str(where),
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
    for event, want in (("PreToolUse", '{"decision":"allow"}\n'), ("PreInvocation", ""), ("Stop", "")):
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
    for event in ("PreToolUse", "PostToolUse", "PreInvocation", "Stop"):
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
    # agy waits for PreInvocation before every model call (measured on 1.5.16 and 1.5.5): a short timeout.
    s.check("agy hooks: PreInvocation (a turn's start), timeout 30 s at most",
            0 < hj["PreInvocation"][0]["timeout"] <= 30 and "agy PreInvocation" in hj["PreInvocation"][0]["command"], str(hj.get("PreInvocation"))[:300])
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
    snake = {"Notification": "notification", "Stop": "stop", "StopFailure": "stop_failure", "StopCancelled": "stop_cancelled",
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
    s.settle("the second copy's background work")
    s.check("grok: the same event twice (two copies of the hook) -> one alert", not ingests(s), str(ingests(s))[:200])
    s.check("grok: duplicate logged", "duplicate Stop" in s.log_text(), s.log_text()[-300:])
    inp2, _ = grok_input("Stop", reason="end_turn", promptId="p2", timestamp="2026-10-29T10:05:00.000Z", lastAssistantMessage="Grok done.")
    s.run("claude", inp2, env)
    s.check("grok: a later turn with the same text is sent", wait_for(lambda: ingests(s, "done"), 20))
    s.ctl("/_ctl/reset", {})
    for reason in ("channel_closed", "shutdown"):
        inp3, _ = grok_input("Stop", reason=reason, timestamp="2026-10-29T10:09:%02d.000Z" % len(reason), lastAssistantMessage="x")
        s.run("claude", inp3, env)
    s.settle("the session-end Stop hooks' background work")
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
    s.settle("the Notification hook's background work")
    s.check("grok: other notifications ignored", not ingests(s))
    fail, fenv = grok_input("StopFailure", error="rate_limit", errorDetails="429", lastAssistantMessage="Rate limited",
                            timestamp="2026-10-29T10:11:00.000Z")
    s.run("claude", fail, dict(fenv, GROK_HOOK_EVENT="stop_failure"))
    rec = wait_for(lambda: ingests(s), 20)
    s.check("grok: StopFailure -> error", rec and rec[0]["body"]["ev"] == "error"
            and rec[0]["plain_json"].get("msg") == "rate_limit: Rate limited", str(rec)[:200])
    # Ctrl+C or a rejected permission ends a Grok turn with StopCancelled instead of Stop (measured on 1.0.77, reason
    # user_interrupt or permission_rejected): the turn is over, as at Claude Code's Esc (SimpleTerm
    # hist/turn-state#d16), so the report that comes next starts a turn of its own.
    def gmark():
        return (s.home / ".simpleterm" / "run" / "gk-1.turn").read_text().split("\n")

    for i, (reason, extra) in enumerate((("user_interrupt", {"cancelTrigger": "ctrl_c"}), ("permission_rejected", {}))):
        ups, uenv = grok_input("UserPromptSubmit", promptId="p9%d" % i, prompt="Run the long check",
                               timestamp="2026-10-29T10:12:0%d.000Z" % i)
        s.run("claude", ups, uenv)
        m1 = gmark()
        cancel, cenv = grok_input("StopCancelled", promptId="p9%d" % i, reason=reason, cancelledBy="user",
                                  timestamp="2026-10-29T10:12:1%d.000Z" % i, **extra)
        s.run("claude", cancel, cenv)
        m2 = gmark()
        rep, renv = grok_input("UserPromptSubmit", promptId="task-completed-gbash9%d" % i, prompt="npm test finished",
                               timestamp="2026-10-29T10:12:2%d.000Z" % i)
        s.run("claude", rep, renv)
        s.check("grok: StopCancelled (%s) closes the turn; the next report is a turn of its own" % reason,
                m1[3:4] == ["open"] and m2[3:4] in ([], [""]) and gmark()[0] == "task", repr((m1, m2, gmark())))
    # A report while a Grok turn is open joins that turn (SimpleTerm hist/turn-state#d16): Grok's report ids
    # (task-completed-, subagent-completed-) are never the running turn's id, so they are not compared with it
    # (hist/turn-state#d18) ...
    ups, uenv = grok_input("UserPromptSubmit", promptId="p95", prompt="Run the long check", timestamp="2026-10-29T10:13:00.000Z")
    s.run("claude", ups, uenv)
    rep, renv = grok_input("UserPromptSubmit", promptId="task-completed-gbash95", prompt="npm test finished",
                           timestamp="2026-10-29T10:13:20.000Z")
    s.run("claude", rep, renv)
    s.check("grok: a report while a turn is open joins it (the mark keeps who started it and its promptId)",
            gmark()[0] == "user" and gmark()[3:5] == ["open", "p95"], repr(gmark()))
    # ... and a scheduled run keeps its schedule (line 3) when a command it started reports inside it.
    stop, stenv = grok_input("Stop", reason="end_turn", promptId="p95", lastAssistantMessage="Checked.",
                             backgroundTasks=[], sessionCrons=[], timestamp="2026-10-29T10:13:25.000Z")
    s.run("claude", stop, stenv)
    srun, senv = grok_input("UserPromptSubmit", promptId="subagent-completed-gsch96",
                            prompt="<system-reminder>\nscheduler_delete(\"cron96\")\n</system-reminder>",
                            timestamp="2026-10-29T10:13:30.000Z")
    s.run("claude", srun, senv)
    rep, renv = grok_input("UserPromptSubmit", promptId="task-completed-gbash96", prompt="npm test finished",
                           timestamp="2026-10-29T10:13:40.000Z")
    s.run("claude", rep, renv)
    s.check("grok: a report inside a scheduled run keeps that run's mark and schedule",
            gmark()[0] == "task" and gmark()[2:5] == ["cron96", "open", "subagent-completed-gsch96"], repr(gmark()))
    # The promptId still tells a cancelled turn's StopCancelled that comes after the next turn started (docs of
    # 1.0.77, hist/hook-events#e24): it leaves the running turn open (turn_other, AhMunGa/simple-term#685).
    ups, uenv = grok_input("UserPromptSubmit", promptId="p97", prompt="Run it again", timestamp="2026-10-29T10:14:00.000Z")
    s.run("claude", ups, uenv)
    cancel, cenv = grok_input("StopCancelled", promptId="p95", reason="user_interrupt", cancelledBy="user",
                              cancelTrigger="ctrl_c", timestamp="2026-10-29T10:14:01.000Z")
    s.run("claude", cancel, cenv)
    s.check("grok: a late StopCancelled of the turn before leaves the running turn open",
            gmark()[3:5] == ["open", "p97"], repr(gmark()))
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
    s.settle("the hooks' background work")
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
    s.settle("the Notification hook's background work")
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
    s.settle("the pause's wait (bg_done_after, 2 s) and the error's send")
    evs = [r["body"]["ev"] for r in ingests(s)]
    s.check("opencode sh: a failed turn ends the pause (error, no later done)", evs == ["error"], str(evs))
    s.setup([(LINK_A, {"push": "disabled"})])
    s.run("opencode", json.dumps({"hook_event_name": "StopFailure", "session_id": "oc-1", "cwd": "/w/ocproj",
                                  "error": "ProviderAuthError", "last_assistant_message": "API key invalid"}))
    rec = wait_for(lambda: ingests(s), 20)
    s.check("opencode sh: ProviderAuthError -> auth", rec and rec[0]["body"]["ev"] == "auth", str(rec)[:200])


def cop_line(kind, **data):
    """One line of Copilot CLI's own session record (events.jsonl), in its compact shape (1.0.114)."""
    return json.dumps({"type": kind, "data": data, "id": "ev-" + kind, "timestamp": "2026-11-24T08:17:08.940Z", "parentId": None},
                      separators=(",", ":"))


def cop_record(home, sid):
    """<COPILOT_HOME>/session-state/<sid>/events.jsonl with the turn's user.message."""
    p = Path(home) / "session-state" / sid / "events.jsonl"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(cop_line("user.message", content="go", messageId="m-" + sid, turnId="0") + "\n")
    return p


def add_lines(path, *lines):
    with open(path, "a") as f:
        f.write("".join(line + "\n" for line in lines))


def cx_line(tid, kind="task_complete", info=None, message=None):
    """A line of a Codex rollout (0.172.0): the turn's task_complete, with an error when it failed."""
    p = {"type": kind, "root_turn_id": tid, "turn_id": tid}
    if kind == "task_complete":
        p["last_agent_message"] = "Done." if info is None else None
        if info is not None:
            p["error"] = {"message": message or "failed", "codex_error_info": info}
    return json.dumps({"timestamp": "2026-11-24T07:03:37.734Z", "ordinal": 9, "type": "event_msg", "payload": p}, separators=(",", ":"))


def t_auth_end(s):
    """A turn that failed on a refused sign-in is one `auth` (turn.end error, no req) for every agent that tells it,
    a 401 that a retry fixed is nothing, and other errors stay as they were (SimpleTerm hist/hook-events#d11,
    if/hook-events-turn#turn-end). Copilot CLI and Codex tell it only in their own record as the turn ends: the hook
    watches it from the turn's first failure."""
    s.setup([(LINK_A, {"push": "disabled", "fmt": 2})])

    def evs():
        return [r["body"]["ev"] for r in ingests(s) if r["body"]["ev"] in ("auth", "error", "done")]

    def one_auth(label, msg):
        rec = wait_for(lambda: ingests(s, "auth"), 10)
        s.settle(label)
        p = rec[0]["plain_json"] if rec else {}
        s.check(label, evs() == ["auth"] and (p.get("turn") or {}).get("end") == "error" and "req" not in p
                and str(p.get("msg", "")).startswith(msg), "%s %s" % (evs(), str(p)[:300]))

    def nothing(label, want=()):
        s.settle(label)
        s.check(label, evs() == list(want), str(evs()))

    def reset():
        s.ctl("/_ctl/reset", {})

    run_dir = s.home / ".simpleterm" / "run"

    def ended(label, sid, want, msg=""):
        """one_auth or nothing for a watch whose turn's end may already be in the record when the hook starts. A watch
        that missed it (the hook before this was fixed: it read from the record's size then, on for 120 s) is stopped
        before the check."""
        if want:
            wait_for(lambda: ingests(s, "auth"), 5)
        else:
            time.sleep(1.5)
        (run_dir / (sid + ".aw")).unlink(missing_ok=True)
        if want:
            one_auth(label, msg)
        else:
            nothing(label)

    # --- Codex (both hooks): PostModelRequest, once per try; the rollout's task_complete tells the turn's end ---
    tid = "01a20c5e-02d5-7e21-8bf6-9d2ee505345a"
    ro = s.tmp / "codex-auth" / "rollout.jsonl"

    def cx_req(sid, status="failed", n=1, path=None):
        return json.dumps({"kind": "sampling", "request_id": "req-%d" % n, "attempt_number": n, "session_id": sid, "thread_id": sid,
                           "turn_id": tid, "cwd": "/w/repo", "transcript_path": str(path or ro), "model": "gpt-5.5",
                           "hook_event_name": "PostModelRequest", "status": status,
                           "error": "unexpected status 401 Unauthorized: Incorrect API key provided" if status == "failed" else None,
                           "token_usage": None, "response_id": None})

    cx401 = "unexpected status 401 Unauthorized: Incorrect API key provided: sk-stub***xxxx., url: http://127.0.0.1:52360/v1/responses"
    for i, (label, end, want) in enumerate((
            ("HTTP 401 -> one auth", cx_line(tid, info={"http_connection_failed": {"http_status_code": 401}}, message=cx401), "auth"),
            ("unauthorized (a refused token refresh) -> one auth",
             cx_line(tid, info="unauthorized", message="Your access token could not be refreshed because your refresh token has expired."), "auth"),
            ("a retry fixed it (no error) -> nothing", cx_line(tid), None),
            ("HTTP 403 -> nothing", cx_line(tid, info={"http_connection_failed": {"http_status_code": 403}}, message="unexpected status 403 Forbidden"), None),
            ("another error (500) -> nothing", cx_line(tid, info="internal_server_error", message="high demand"), None),
            ("the turn aborted -> nothing", cx_line(tid, kind="turn_aborted"), None))):
        reset()
        write(ro, cx_line(tid, kind="task_started") + "\n")
        sid = "cx-auth-%d" % i
        t0 = time.time()
        for n in (1, 2):
            rc, out, err, el = s.run("codex", cx_req(sid, n=n), args=("PostModelRequest",))
        time.sleep(1.2)
        s.check("codex auth: %s: nothing while it retries, the hook returns at once" % label,
                not evs() and rc == 0 and out == "" and time.time() - t0 < 30, "%s %r" % (evs(), out))
        add_lines(ro, end)
        if want:
            one_auth("codex auth: " + label, "Your access" if "unauthorized" in label else "unexpected status 401")
        else:
            nothing("codex auth: " + label)
    # `codex exec`: SessionEnd right after the failed turn; the watch reads on.
    reset()
    write(ro, cx_line(tid, kind="task_started") + "\n")
    s.run("codex", cx_req("cx-auth-exec"), args=("PostModelRequest",))
    s.run("codex", json.dumps({"session_id": "cx-auth-exec", "hook_event_name": "SessionEnd", "cwd": "/w/repo"}))
    add_lines(ro, cx_line(tid, info={"http_connection_failed": {"http_status_code": 401}}, message=cx401))
    one_auth("codex auth: the session ends right after the failed turn (codex exec) -> one auth", "unexpected status 401")
    # No retry (a refused token refresh, or request retries set to 0): the turn's task_complete can be in the rollout before
    # its one failed request's hook reads it. The watch reads this turn's lines from the rollout's last MiB; the turn
    # before's end is not this turn's.
    reset()
    write(ro, cx_line(tid, kind="task_started") + "\n"
          + cx_line(tid, info="unauthorized", message="Your access token could not be refreshed because your refresh token has expired.") + "\n")
    s.run("codex", cx_req("cx-auth-b1"), args=("PostModelRequest",))
    ended("codex auth: one try, the turn's end written before the hook -> one auth", "cx-auth-b1", "auth", "Your access")
    reset()
    t0 = "01a20c5e-0000-7000-8000-0000000000b0"
    write(ro, cx_line(t0, kind="task_started") + "\n" + cx_line(t0, info={"http_connection_failed": {"http_status_code": 401}}, message=cx401)
          + "\n" + cx_line(tid, kind="task_started") + "\n")
    s.run("codex", cx_req("cx-auth-b2"), args=("PostModelRequest",))
    ended("codex auth: the turn before's refused sign-in is not this turn's", "cx-auth-b2", None)
    # Any other request ends the hook at once: nothing watched, nothing written.
    reset()
    run_dir = s.home / ".simpleterm" / "run"
    rc, out, err, el = s.run("codex", cx_req("cx-auth-ok", status="completed"), args=("PostModelRequest",))
    s.check("codex auth: a completed request -> the hook ends at once, no watch", rc == 0 and out == ""
            and not list(run_dir.glob("cx-auth-ok*")), str(list(run_dir.glob("cx-auth-ok*"))))
    rc, out, err, el = s.run("codex", cx_req("cx-auth-gone", path=s.tmp / "no-such-rollout.jsonl"), args=("PostModelRequest",))
    nothing("codex auth: no rollout -> nothing, no watch left")

    # --- Claude Code (both hooks): an account or billing problem is no sign-in ---
    for e in ("account_on_hold", "verification_required", "billing_error"):
        reset()
        s.run("claude", json.dumps({"session_id": "cc-auth", "cwd": "/w/repo", "hook_event_name": "StopFailure", "error": e,
                                    "last_assistant_message": "x"}))
        wait_for(lambda: evs(), 10)
        nothing("claude: %s -> error, no auth" % e, ["error"])
    if s.kind != "sh":
        return

    # --- the Codex hooks register PostModelRequest, quiet as the others ---
    hooks = json.loads(CODEX_HOOKS.read_text())["hooks"]
    pm = (hooks.get("PostModelRequest") or [{}])[0].get("hooks") or [{}]
    s.check("codex hooks: PostModelRequest registered like Stop (sh and Windows)",
            pm[0].get("command") == hooks["Stop"][0]["hooks"][0]["command"] and pm[0].get("commandWindows") == hooks["Stop"][0]["hooks"][0]["commandWindows"],
            str(pm))

    # --- Copilot CLI: errorOccurred for every try; its events.jsonl gets session.error when the turn failed ---
    env = {"COPILOT_CLI": "1", "COPILOT_CLI_BINARY_VERSION": "1.0.114"}

    def cop_err(sid):
        return json.dumps({"sessionId": sid, "timestamp": 1795508226000, "cwd": "/w/proj", "errorContext": "model_call", "recoverable": True,
                           "error": {"message": "{\"message\":\"unauthorized: token expired\",\"code\":\"unauthorized\"}", "name": "Error"}})

    def sign_in(sid, status=401):
        return cop_line("session.error", errorType="authorization", message="Authorization error. Your credentials may be expired or invalid.",
                        statusCode=status, remediation="sign_in", originatingMessageId="m-" + sid)

    turn_end = cop_line("assistant.turn_end", turnId="0")
    rate = lambda sid: cop_line("session.error", errorType="rate_limit", message="Failed to get response from the AI model; retried 5 times",
                                statusCode=429, providerErrorCode="rate_limit_exceeded", originatingMessageId="m-" + sid)
    chome = s.tmp / "copilot-home"
    for label, sid, cenv, lines, want in (
            ("a refused sign-in (401) -> one auth", "cop-a1", {}, lambda sid: [turn_end, sign_in(sid)], "auth"),
            ("a refused sign-in (403 with sign_in) under COPILOT_HOME -> one auth", "cop-a2", {"COPILOT_HOME": str(chome)},
             lambda sid: [turn_end, sign_in(sid, 403)], "auth"),
            ("a retry fixed it (assistant.message) -> nothing", "cop-a3", {},
             lambda sid: [cop_line("assistant.message", messageId="am-1", originatingMessageId="m-" + sid, content="OK", toolRequests=[]), turn_end], None),
            ("another error (429) -> nothing", "cop-a4", {}, lambda sid: [turn_end, rate(sid)], None),
            ("a sign-in refused in the next turn is not this turn's", "cop-a5", {},
             lambda sid: [cop_line("user.message", content="again", messageId="m-2-" + sid), sign_in("2-" + sid)], None)):
        reset()
        rec_file = cop_record(cenv.get("COPILOT_HOME") or s.home / ".copilot", sid)
        for _ in range(3):
            rc, out, err, el = s.run("copilot", cop_err(sid), dict(env, **cenv), args=("errorOccurred",))
        time.sleep(1.2)
        s.check("copilot auth: %s: nothing while it retries" % label, not evs(), str(evs()))
        add_lines(rec_file, *lines(sid))
        if want:
            one_auth("copilot auth: " + label, "authorization: Authorization error")
        else:
            nothing("copilot auth: " + label)
    reset()
    s.run("copilot", cop_err("cop-none"), env, args=("errorOccurred",))
    nothing("copilot auth: no record -> nothing, no watch left")
    # One watch a turn: the next turn (userPromptSubmitted) watches again.
    reset()
    rec_file = cop_record(s.home / ".copilot", "cop-a6")
    s.run("copilot", cop_err("cop-a6"), env, args=("errorOccurred",))
    add_lines(rec_file, cop_line("assistant.message", messageId="am-1", originatingMessageId="m-cop-a6", content="OK", toolRequests=[]), turn_end)
    s.settle("copilot's first watch")
    s.run("copilot", json.dumps({"sessionId": "cop-a6", "timestamp": 1795508227000, "cwd": "/w/proj", "prompt": "again"}), env,
          args=("userPromptSubmitted",))
    add_lines(rec_file, cop_line("user.message", content="again", messageId="m-2-cop-a6"))
    s.run("copilot", cop_err("cop-a6"), env, args=("errorOccurred",))
    add_lines(rec_file, turn_end, sign_in("2-cop-a6"))
    one_auth("copilot auth: the next turn's refused sign-in -> one auth", "authorization: Authorization error")
    # A 403 is tried once: the turn's session.error comes right after its one errorOccurred (1.0.114: 1-5 ms after the
    # hook ends), and before it when Copilot does not wait for the hook. The watch reads from the turn's last user.message
    # (the record's last MiB); a session.error is the turn's when its originatingMessageId is that message's id, or by
    # position (the first after it) in a record without the ids (hist/hook-events#d11 2).
    reply = lambda sid: cop_line("assistant.message", messageId="am-0", originatingMessageId="m-" + sid, content="",
                                 toolRequests=[{"toolCallId": "c1", "name": "bash"}])
    no_ids = cop_line("session.error", errorType="authorization", message="Authorization error. Your credentials may be expired or invalid.",
                      statusCode=403, remediation="sign_in")
    for label, sid, head, before, after, want in (
            ("one try (403), its session.error written before the hook -> one auth", "cop-b1", None,
             lambda sid: [reply(sid), turn_end, sign_in(sid, 403)], (), "auth"),
            ("one try (403), its session.error written 50 ms after the hook starts -> one auth", "cop-b2", None,
             lambda sid: [reply(sid)], lambda sid: [turn_end, sign_in(sid, 403)], "auth"),
            ("a record without the ids: the first session.error after the turn's user.message -> one auth", "cop-b3",
             [cop_line("user.message", content="go", turnId="0")], lambda sid: [turn_end, no_ids], (), "auth"),
            ("the turn before's refused sign-in is not this turn's", "cop-b4",
             lambda sid: [cop_line("user.message", content="go", messageId="m-0-" + sid), turn_end, sign_in("0-" + sid),
                          cop_line("user.message", content="again", messageId="m-" + sid)], lambda sid: [], (), None),
            ("another message's refused sign-in (its originatingMessageId), written after the hook, is not this turn's", "cop-b5",
             None, lambda sid: [], (), None)):
        reset()
        rec_file = cop_record(s.home / ".copilot", sid)
        if head:
            write(rec_file, "".join(x + "\n" for x in (head(sid) if callable(head) else head)))
        add_lines(rec_file, *before(sid))
        p = s.start("copilot", cop_err(sid), env, args=("errorOccurred",))
        if after:
            time.sleep(0.05)
            add_lines(rec_file, *after(sid))
        s.finish(p, 30)
        if sid == "cop-b5":
            add_lines(rec_file, sign_in("x-" + sid))
        ended("copilot auth: " + label, sid, want, "authorization: Authorization error")
    # -p: sessionEnd reason error, the record's session.error written just after the hook starts (1.0.114: 0.07 s).
    for label, sid, line, want in (("a refused sign-in -> auth, no error", "cop-p1", sign_in, ["auth"]),
                                   ("another error -> error, no auth", "cop-p2", rate, ["error"]),
                                   ("another message's refused sign-in -> error, no auth", "cop-p3", lambda sid: sign_in("x-" + sid), ["error"])):
        reset()
        rec_file = cop_record(s.home / ".copilot", sid)
        for _ in range(3):
            s.run("copilot", cop_err(sid), env, args=("errorOccurred",))
        p = s.start("copilot", json.dumps({"sessionId": sid, "timestamp": 1795508228000, "cwd": "/w/proj", "reason": "error"}), env,
                    args=("sessionEnd",))
        time.sleep(0.15)
        add_lines(rec_file, turn_end, line(sid))
        s.finish(p, 30)
        wait_for(lambda: evs(), 10)
        nothing("copilot -p auth: sessionEnd, " + label, want)
    # -p, one try (403): the session.error already in the record when errorOccurred and sessionEnd start.
    reset()
    rec_file = cop_record(s.home / ".copilot", "cop-p4")
    add_lines(rec_file, turn_end, sign_in("cop-p4", 403))
    s.run("copilot", cop_err("cop-p4"), env, args=("errorOccurred",))
    s.run("copilot", json.dumps({"sessionId": "cop-p4", "timestamp": 1795508228000, "cwd": "/w/proj", "reason": "error"}), env,
          args=("sessionEnd",))
    wait_for(lambda: evs(), 10)
    (run_dir / "cop-p4.aw").unlink(missing_ok=True)
    nothing("copilot -p auth: one try, the session.error written before both hooks -> auth, no error", ["auth"])

    # --- Antigravity CLI: Stop with Google's API error text ---
    for label, err, want in (
            ("Error 401 (UNAUTHENTICATED)", "generating and executing: Error 401, Message: Request had invalid authentication credentials., "
                                            "Status: UNAUTHENTICATED, Details: []", "auth"),
            ("API_KEY_INVALID", "generating and executing: Error 400, Message: API key not valid. Please pass a valid API key., "
                                "Status: INVALID_ARGUMENT, Details: [reason:API_KEY_INVALID]", "auth"),
            ("Error 403 (PERMISSION_DENIED)", "generating and executing: Error 403, Message: The caller does not have permission, "
                                              "Status: PERMISSION_DENIED, Details: []", "error"),
            ("quota", "quota exceeded", "error")):
        reset()
        s.run("agy", agy_stop(error=err, terminationReason="ERROR"), args=("Stop",))
        wait_for(lambda: evs(), 10)
        nothing("agy auth: %s -> %s" % (label, want), [want])

    # --- OpenCode 1.x: APIError with its HTTP status (statusCode, handed on as status_code) ---
    for label, code, oc, want in (("401", 401, "1", "auth"), ("403", 403, "1", "auth"), ("500", 500, "1", "error"), ("no status", None, "1", "error")):
        reset()
        inp = {"hook_event_name": "StopFailure", "oc": oc, "session_id": "oc-auth", "cwd": "/w/ocproj", "error": "APIError",
               "last_assistant_message": "Incorrect API key provided: stub-key."}
        if code is not None:
            inp["status_code"] = code
        s.run("opencode", json.dumps(inp))
        wait_for(lambda: evs(), 10)
        nothing("opencode 1.x auth: APIError %s -> %s" % (label, want), [want])
    if not NODE:
        return

    def st(sid, kind):
        return {"event": {"type": "session.status", "properties": {"sessionID": sid, "status": {"type": kind}}}}

    def idle(sid):
        return {"event": {"type": "session.idle", "properties": {"sessionID": sid}}}

    def failed(sid, code):
        return {"event": {"type": "session.error", "properties": {"sessionID": sid, "error": {"name": "APIError", "data": {
            "message": "Incorrect API key provided: stub-key.", "statusCode": code, "isRetryable": code >= 500}}}}}

    d = str(s.tmp)
    # 1.19.6: session.error, then status idle and session.idle twice (measured); the next turn starts with busy.
    for code, want in ((401, ["auth"]), (500, ["error"])):
        reset()
        node_plugin(s, "v1", {"directory": d, "sessions": {"ses_1": {"title": "Fix the tests"}},
                              "steps": [st("ses_1", "busy"), failed("ses_1", code), st("ses_1", "idle"), idle("ses_1"), st("ses_1", "idle"),
                                        idle("ses_1"), {"sleep": 800}], "wait": 3000})
        wait_for(lambda: evs(), 10)
        nothing("opencode 1.x plugin: APIError %d, then session.idle twice -> %s, no done" % (code, want[0]), want)
    reset()
    node_plugin(s, "v1", {"directory": d, "sessions": {"ses_1": {"title": "Fix the tests"}},
                          "steps": [st("ses_1", "busy"), failed("ses_1", 401), st("ses_1", "idle"), idle("ses_1"), idle("ses_1"),
                                    {"sleep": 800}, st("ses_1", "busy"), st("ses_1", "idle"), idle("ses_1")], "wait": 3000})
    wait_for(lambda: len(evs()) >= 2, 10)
    nothing("opencode 1.x plugin: the next turn after the error -> its done", ["auth", "done"])


def t_auth_end_state(s):
    """A turn that ends in `auth` starts the state comparison over as every turn end does (SimpleTerm
    if/event-v2-turn#state, hist/turn-state#d26): the next turn's `running` goes. The `auth` a watch sends late, after
    the next turn has started, leaves that turn's state record alone (hist/hook-events#d11)."""
    tun, tctl = s.spawn_mock()
    try:
        s.setup([(LINK_T, {"kind": "tunnel", "relay_url": tctl.url, "fmt": 2})])
        tctl("/_ctl/config", {"links": {LINK_T["id"]: dict(LINK_T, unknown_error="unknown")}})
        run_dir = s.home / ".simpleterm" / "run"

        def states():
            return [r["plain_json"].get("st") for r in ingests(s, "state", ctl=tctl)]

        def check(label, sid):
            ok = wait_for(lambda: states() == ["running", "running"] and len(ingests(s, "auth", ctl=tctl)) == 1, 10)
            s.settle(label)
            s.check(label, ok and states() == ["running", "running"] and len(ingests(s, "auth", ctl=tctl)) == 1,
                    "%s auth=%d" % (states(), len(ingests(s, "auth", ctl=tctl))))

        # Codex (both hooks): the watch reads the turn's end in the rollout.
        ro = s.tmp / "codex-auth-state" / "rollout.jsonl"
        t1, t2 = "01a20c5e-0000-7000-8000-000000000001", "01a20c5e-0000-7000-8000-000000000002"

        def cx(sid, event, tid, **kw):
            j = {"session_id": sid, "turn_id": tid, "cwd": "/w/repo", "transcript_path": str(ro), "hook_event_name": event}
            j.update(kw)
            return s.run("codex", json.dumps(j))

        fail401 = cx_line(t1, info={"http_connection_failed": {"http_status_code": 401}}, message="unexpected status 401 Unauthorized")
        tctl("/_ctl/reset", {})
        write(ro, cx_line(t1, kind="task_started") + "\n")
        cx("cxs-1", "UserPromptSubmit", t1, prompt="go")
        cx("cxs-1", "PostModelRequest", t1, status="failed")
        add_lines(ro, fail401)
        wait_for(lambda: ingests(s, "auth", ctl=tctl), 10)
        s.settle("codex: the watch's auth")
        cx("cxs-1", "UserPromptSubmit", t2, prompt="go on")
        check("codex: auth, then the next turn's running goes", "cxs-1")
        # Late: the next turn started before the watch read the failed turn's end. Its running goes, and the auth after
        # it keeps that turn's record (the record still says running).
        tctl("/_ctl/reset", {})
        write(ro, cx_line(t1, kind="task_started") + "\n")
        cx("cxs-2", "UserPromptSubmit", t1, prompt="go")
        cx("cxs-2", "PostModelRequest", t1, status="failed")
        cx("cxs-2", "UserPromptSubmit", t2, prompt="go on")
        add_lines(ro, fail401)
        check("codex: a late auth after the next turn started -> that turn's running went", "cxs-2")
        rec = (run_dir / "cxs-2.st").read_text().split() if (run_dir / "cxs-2.st").exists() else []
        s.check("codex: the late auth keeps the next turn's state record", rec[:1] == ["running"], str(rec))
        if s.kind != "sh":
            return

        # Antigravity: Stop with a refused sign-in.
        tctl("/_ctl/reset", {})
        pre = json.dumps({"conversationId": "agys-1", "workspacePaths": ["/w/agyproj"], "invocationNum": 0})
        s.run("agy", pre, args=("PreInvocation",))
        s.run("agy", agy_stop(conversationId="agys-1", terminationReason="ERROR",
                              error="generating and executing: Error 401, Message: invalid credentials, Status: UNAUTHENTICATED"), args=("Stop",))
        s.run("agy", pre, args=("PreInvocation",))
        check("agy: auth, then the next turn's running goes", "agys-1")

        # OpenCode 1.x: APIError 401.
        tctl("/_ctl/reset", {})
        oc = lambda **kw: s.run("opencode", json.dumps(dict({"session_id": "ocs-1", "cwd": "/w/ocproj", "oc": "1"}, **kw)))
        oc(hook_event_name="UserPromptSubmit")
        oc(hook_event_name="StopFailure", error="APIError", status_code=401, last_assistant_message="Incorrect API key provided")
        oc(hook_event_name="UserPromptSubmit")
        check("opencode 1.x: auth, then the next turn's running goes", "ocs-1")

        # Copilot CLI: the watch reads session.error in its record.
        tctl("/_ctl/reset", {})
        env = {"COPILOT_CLI": "1", "COPILOT_CLI_BINARY_VERSION": "1.0.114"}
        rec_file = cop_record(s.home / ".copilot", "cops-1")
        prompt = json.dumps({"sessionId": "cops-1", "timestamp": 1795508226000, "cwd": "/w/proj", "prompt": "go"})
        s.run("copilot", prompt, env, args=("userPromptSubmitted",))
        s.run("copilot", json.dumps({"sessionId": "cops-1", "timestamp": 1795508226500, "cwd": "/w/proj", "errorContext": "model_call",
                                     "recoverable": True, "error": {"message": "unauthorized", "name": "Error"}}), env, args=("errorOccurred",))
        add_lines(rec_file, cop_line("assistant.turn_end", turnId="0"),
                  cop_line("session.error", errorType="authorization", message="Authorization error.", statusCode=401,
                           remediation="sign_in", originatingMessageId="m-cops-1"))
        wait_for(lambda: ingests(s, "auth", ctl=tctl), 10)
        s.settle("copilot: the watch's auth")
        s.run("copilot", prompt, env, args=("userPromptSubmitted",))
        check("copilot: auth, then the next turn's running goes", "cops-1")
    finally:
        tun.terminate()
        tun.wait(5)


NODE = shutil.which("node")


def node_plugin(s, kind, scenario, timeout=90):
    plugin = {"v1": ROOT / "plugins" / "opencode-v1" / "simpleterm.js", "v2": ROOT / "plugins" / "opencode" / "index.js",
              "tui": ROOT / "plugins" / "opencode" / "tui.js"}[kind]
    p = s.proc_run([NODE, str(HERE / "opencode_harness.mjs"), kind, str(plugin), json.dumps(scenario)],
                   env=s.env(), timeout=timeout, cwd=str(s.tmp))
    p.stdout = p.stdout.decode("utf-8", "replace")
    p.stderr = p.stderr.decode("utf-8", "replace")
    try:
        return json.loads(p.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return [{"error": p.stdout[-300:] + p.stderr[-500:]}]


def replies(calls):
    return [c["reply"] for c in calls if "reply" in c]


# --- event format v2 (SimpleTerm if/event-v2) ---------------------------------------

V2_DIR = HERE / "fixtures" / "v2"
V2_RID = "0123456789abcdef"
V2_URID = "a1b2c3d4e5f60718"
V2_PIN = {"SIMPLETERM_HOOK_TEST": "1", "SIMPLETERM_HOOK_TEST_RID": V2_RID, "SIMPLETERM_HOOK_TEST_URID": V2_URID, "SIMPLETERM_HOOK_TEST_NONCE": V_NONCE,
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
            # NOWEPOCH: the time of the run (a tunnel's last answer that must be recent).
            write(s.home / name, text.replace("HOMEP", str(s.home)).replace("NOWEPOCH", str(int(time.time()))))
        for name, text in case.get("bins", {}).items():
            # Stand-in agents for usage asks, in the hook's PATH.
            b = s.bin / name
            b.write_text(text)
            b.chmod(0o755)
        for name, ver in case.get("vercache", {}).items():
            # Their measured --version (run/ver.<agent>: the file and its version), not older than the file.
            write(s.home / ".simpleterm" / "run" / ("ver." + name), "%s\n%s\n" % (s.bin / name, ver))
        dump = s.tmp / "plain"
        shutil.rmtree(dump, ignore_errors=True)
        dump.mkdir()
        outs = []
        for st in case["steps"]:
            inp = json.dumps(st["input"], ensure_ascii=bool(case.get("ascii"))).replace("HOMEP", str(s.home))
            if case.get("raw"):
                # Bytes JSON cannot carry (not UTF-8): placeholders in the input, replaced here.
                inp = inp.encode()
                for mark, hexbytes in case["raw"].items():
                    inp = inp.replace(mark.encode(), bytes.fromhex(hexbytes))
            env = dict(V2_PIN, SIMPLETERM_HOOK_TEST_PLAIN=str(dump), **case.get("env", {}))
            env.update(st.get("env", {}))
            rc, out, err, el = s.run(st["args"][0], inp, env, args=st["args"][1:])
            outs.append(out)
        quiet = max(case.get("quiet", 0), 4 if s.kind == "ps1" else 1.5)
        wait_for(lambda: len([f for f in dump.iterdir() if f.name.split(".")[2] in (V2_RID, V2_URID)]) >= want_n, 30, 0.2)
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
            if rid in (V2_RID, V2_URID):
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
    """Per agent and version (SimpleTerm if/hook-events): the plaintext each link gets, byte for byte (the PowerShell
    hook must give the same bytes: SimpleTerm if/event-v2-limits#shrinking), and what the hook prints."""
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


# Decision extension test vector (SimpleTerm if/event-decision#vectors).
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
    """SimpleTerm if/event-decision#vectors: the vector extension, sealed by openssl with the vector keys and IV, is what the
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
    """SimpleTerm hist/response#e11: each decision the agent's way (Claude Code, Codex), and SimpleTerm if/event-decision#validation: a decision that
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
    # A key given twice counts with its first value: in the agent's input (the label the user saw is
    # the one answered) and in the extension (SimpleTerm if/event-decision#validation).
    pin = {"SIMPLETERM_HOOK_TEST": "1", "SIMPLETERM_HOOK_TEST_NONCE": V_NONCE, "SIMPLETERM_HOOK_TEST_RID": V_RID}
    dq = ('{"session_id":"sdq","cwd":"/w","hook_event_name":"PermissionRequest","tool_name":"AskUserQuestion","tool_input":'
          '{"questions":[{"question":"Which DB?","header":"DB","multiSelect":false,"options":[{"label":"SQLite","label":"Other"},{"label":"Postgres"}]}]}}')
    s.setup([(LINK_A, {"fmt": 2, "decision": "allow", "after": 1, "dext": {"act": "answer", "answers": [{"q": 0, "pick": [0]}]}})],
            conf={"claude_wait": 20})
    rc, out, err, el = s.run("claude", dq, pin)
    sent = (((s.records("/v1/ingest") or [{}])[0].get("plain_json") or {}).get("req") or {}).get("ask") or {}
    s.check("first value: the label sent is the label answered",
            ((sent.get("qs") or [{}])[0].get("opts") or [{}])[0].get("l") == "SQLite"
            and (behavior(out).get("updatedInput") or {}).get("answers") == {"Which DB?": "SQLite"}, str(sent)[:200] + " | " + out)
    raw = ('{"v":1,"fmt":2,"rid":"%s","nonce":"%s","decision":"allow","req":"st-%s","act":"allow","act":"deny","ts":1793232000}'
           % (V_RID, V_NONCE, V_RID))
    s.setup([(LINK_A, {"fmt": 2, "decision": "allow", "after": 1, "dext": {"raw": raw, "iv": V2_DEXT_IV}})], conf={"claude_wait": 20})
    rc, out, err, el = s.run("claude", v2_perm(session="sdx"), pin)
    s.check("first value: an extension's act given twice is its first", behavior(out).get("behavior") == "allow", out + s.log_text()[-200:])
    # SimpleTerm if/event-decision#validation: dropped decisions print nothing.
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


def t_v2_input_drain(s):
    """An input past the 256 KiB the hook reads is read to its end and dropped: an agent still writing
    to a hook that ended gets a broken pipe (Codex 0.165: "failed to write hook stdin")."""
    s.setup([(LINK_A, {"push": "disabled"})])
    big = json.dumps({"session_id": "s1", "turn_id": "t1", "cwd": "/w", "hook_event_name": "PostToolUse", "tool_name": "Bash",
                      "tool_input": {"command": "cat big"}, "tool_response": "x" * (1 << 20)}).encode()
    for agent in ("codex", "claude"):
        p = s.popen(list(s.argv) + [agent], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             env=s.env(), cwd=str(s.tmp))
        broken = False
        try:
            p.stdin.write(big)
            p.stdin.close()
        except BrokenPipeError:
            broken = True
        p.stdin = None
        out, err = p.communicate(timeout=90)
        s.check("input drain %s: 1 MiB written to the end, exit 0" % agent, not broken and p.returncode == 0, "broken=%s rc=%s" % (broken, p.returncode))


COPILOT_QUOTA_LINE = json.dumps({"type": "model.model_call_success", "id": "e9", "timestamp": "2026-11-03T01:02:03.456Z", "parentId": None, "data": {
    "model": "gpt-x", "quotaSnapshots": {
        "chat": {"isUnlimitedEntitlement": False, "entitlementRequests": 200, "usedRequests": 4, "remainingPercentage": 97.9, "resetDate": "2026-12-01T00:00:00Z"},
        "completions": {"isUnlimitedEntitlement": False, "entitlementRequests": 2000, "usedRequests": 0, "remainingPercentage": 100, "resetDate": "2026-12-01T00:00:00Z"},
        "premium_interactions": {"isUnlimitedEntitlement": False, "entitlementRequests": 0, "usedRequests": 0, "remainingPercentage": 0, "resetDate": "2026-12-01T00:00:00Z"},
        "unlimited_thing": {"isUnlimitedEntitlement": True, "entitlementRequests": 50, "remainingPercentage": 10, "resetDate": "2026-12-01T00:00:00Z"}}}},
    separators=(",", ":"))


def t_v2_usage(s):
    """SimpleTerm if/usage-report#v2-fields and if/usage-report-agents: the usage event's v2 fields from the file sources (Codex rollout src/at, Copilot
    events.jsonl quotaSnapshots, Grok usage.json and OpenCode cost), to the tunnel only."""
    tun, tctl = s.spawn_mock()
    try:
        s.setup([(LINK_T, {"kind": "tunnel", "relay_url": tctl.url, "fmt": 2}), (LINK_A, {"fmt": 2, "push": "disabled"})])
        tctl("/_ctl/config", {"links": {LINK_T["id"]: dict(LINK_T, unknown_error="unknown")}})

        def usage():
            tctl("/_ctl/reset", {})
            return lambda: [r.get("plain") for r in tctl("/_ctl/records")["records"] if r["path"] == "/v1/ingest" and r["body"]["ev"] == "usage"]
        if s.kind == "sh":
            # Copilot (sh only): the newest model call's quota; items unlimited or without requests are left out.
            ev = write(s.tmp / "cop" / "events.jsonl", COPILOT_QUOTA_LINE + "\n")
            got = usage()
            s.run("copilot", json.dumps({"hookName": "agentStop", "sessionId": "cp1", "cwd": "/w/c", "transcriptPath": str(ev)}))
            u = wait_for(got, 20)
            p = json.loads(u[0]) if u else {}
            s.check("usage copilot: chat and completions, pct 100 less remaining, a month's window, file, at",
                    p.get("lims") == [{"id": "copilot.chat", "pct": 2.1, "win_min": 43200, "resets_at": 1796083200, "src": "file", "at": 1793667723},
                                      {"id": "copilot.completions", "pct": 0, "win_min": 43200, "resets_at": 1796083200, "src": "file", "at": 1793667723}]
                    and "ctx" not in p and p.get("fmt") == 2, str(p)[:400])
            # OpenCode (sh only): the session's tokens and cost from the bridge.
            got = usage()
            s.run("opencode", json.dumps({"hook_event_name": "Stop", "session_id": "ses_c", "cwd": "/w/o", "oc": "2", "last_assistant_message": "t",
                                          "cost": 0.0123456789, "tokens_in": 12800, "tokens_out": 3400}))
            u = wait_for(got, 20)
            s.check("usage opencode: cost (micro-USD, cut), tokens, session", u and u[0].endswith(
                ',"cost":{"usd":0.012345,"tok_in":12800,"tok_out":3400,"scope":"session"},"ts":%s}' % json.loads(u[0])["ts"]), str(u)[:400])
        # Codex rollout with a null limit_id (Codex's own limit) and reached false: the ids the ask makes too.
        line = json.loads(codex_token_line())
        line["payload"]["rate_limits"]["limit_id"] = None
        line["payload"]["rate_limits"]["rate_limit_reached_type"] = False
        ro = write(s.tmp / "cx" / "ro.jsonl", json.dumps(line, separators=(",", ":")) + "\n")
        got = usage()
        s.run("codex", json.dumps({"session_id": "cxn", "turn_id": "t", "transcript_path": str(ro), "cwd": "/w/repo", "hook_event_name": "Stop",
                                   "stop_hook_active": False, "last_assistant_message": "Done."}), {"SIMPLETERM": "1"})
        u = wait_for(got, 20)
        p = json.loads(u[0]) if u else {}
        s.check("usage codex: a null limit_id is codex, reached false is not reached",
                [x["id"] for x in p.get("lims", [])] == ["codex.primary", "codex.secondary"], str(p)[:300])
        # Grok: usage.json of its session (costUsdTicks 10^-10 USD each).
        sd = s.home / ".grok" / "sessions" / "%2Fw%2Fgrokproj" / "gk-1"
        write(sd / "usage.json", json.dumps({"sessionId": "gk-1", "session": {"inputTokens": 34380, "outputTokens": 93, "costUsdTicks": 303420000}}))
        got = usage()
        inp, env = grok_input("Stop", reason="end_turn", promptId="p1", stopHookActive=False, lastAssistantMessage="Grok done.")
        s.run("claude", inp, env)
        u = wait_for(got, 20)
        p = json.loads(u[0]) if u else {}
        s.check("usage grok: cost from usage.json, no limits", p.get("cost") == {"usd": 0.030342, "tok_in": 34380, "tok_out": 93, "scope": "session"}
                and "lims" not in p and "ctx" not in p, str(p)[:300])
        s.check("usage: not to the relay", not [r for r in s.records("/v1/ingest") if r["body"]["ev"] == "usage"])
    finally:
        tun.terminate()
        tun.wait(5)


# A stand-in Claude Code (or Codex) for the usage ask: answers --version with the file version (else a measured
# version), get_usage with the file reply (or none), counts its runs and --version runs, notes its environment and
# folder, and waits for its input to end, as the real one does; with the file linger it then stays, with a child.
FAKE_ASKER = """#!/bin/sh
d=$HOME/..
if [ "$1" = --version ]; then
  echo x >>"$d/vcalls"
  if [ -f "$d/version" ]; then cat "$d/version"; elif [ "${0##*/}" = codex ]; then echo "codex-cli 0.165.0"; else echo "2.1.316 (Claude Code)"; fi
  exit 0
fi
n=$(cat "$d/asks" 2>/dev/null || echo 0)
echo $((n + 1)) >"$d/asks"
echo "exe=$0 probe=${SIMPLETERM_PROBE:-} simpleterm=${SIMPLETERM:-} pwd=$(pwd)" >"$d/ask.env"
read -r l
[ -f "$d/delay" ] && sleep "$(cat "$d/delay")"
[ -f "$d/reply" ] && cat "$d/reply"
[ -f "$d/reply2" ] && { read -r l2; read -r l3; cat "$d/reply2"; }
cat >/dev/null
if [ -f "$d/linger" ]; then sleep 600 & echo $! >"$d/child"; wait; fi
if [ -f "$d/stubborn" ]; then
  echo $$ >"$d/agentpid"
  sleep 600 & echo $! >"$d/child"
  ( sleep 601 & echo $! >"$d/grand" ) &
  trap '' TERM
  while :; do sleep 1; done
fi
"""


def t_conf_vectors(s):
    """SimpleTerm if/hook-conf-vectors#read-vectors R1-R46 (tests/fixtures/conf/read-vectors.json): what the hook does
    with each key of agent-hook.conf as the app reads it (caps 540 and 110, poll_wait 1-25, usage, the word keys,
    done_delay per agent). The PowerShell hook has no agy_wait nor opencode_wait (no Antigravity, no OpenCode)."""
    vec = json.loads((HERE / "fixtures" / "conf" / "read-vectors.json").read_text(encoding="utf-8"))["vectors"]
    s.setup([])
    conf = s.home / ".simpleterm" / "agent-hook.conf"
    for v in vec:
        if s.kind == "ps1" and v["key"] in ("agy_wait", "opencode_wait"):
            continue
        conf.write_bytes(bytes.fromhex(v["file_hex"]))
        wants = v["want"] if isinstance(v["want"], dict) else {"claude": v["want"]}
        for agent, want in sorted(wants.items()):
            rc, out, err, el = s.run(agent, "", {"SIMPLETERM_HOOK_TEST": "1"}, args=("__conf", v["key"]))
            s.check("conf %s %s (%s, %s): %s" % (v["id"], v["key"], agent, v["what"], want), out.strip() == want,
                    "got %r rc=%s %s" % (out, rc, err[-200:]))


def t_usage_ask_deadline(s):
    """An ask that gets no answer is a timeout, also when the hook's watching is slow (a loaded machine): the input
    stays open until the watcher has judged the time, so the agent does not end for want of input first and get
    read as gone (`failed`). SimpleTerm if/usage-ask#run; issue #811. The watcher is made slow by an awk that sleeps
    2 seconds in the hook's look at the ask's output (sh); the PowerShell hook has one loop (no such race)."""
    tun, tctl = s.spawn_mock()
    try:
        s.setup([(LINK_T, {"kind": "tunnel", "relay_url": tctl.url, "fmt": 2})])
        tctl("/_ctl/reset", {})
        tctl("/_ctl/config", {"links": {LINK_T["id"]: dict(LINK_T, unknown_error="unknown")}})
        for f in ("asks", "ask.env", "reply", "reply2", "delay", "linger", "stubborn"):
            (s.tmp / f).unlink() if (s.tmp / f).exists() else None
        (s.tmp / "reply").write_text("")  # no answer; the stand-in ends when its input closes
        run = s.home / ".simpleterm" / "run"
        run.mkdir(parents=True, exist_ok=True)
        (run / ("tun.%s.last" % LINK_T["id"][:8])).write_text("%d 200\n" % int(time.time()))
        fake = s.bin / "claude"
        if fake.is_symlink() or fake.exists():
            fake.unlink()
        fake.write_text(FAKE_ASKER)
        fake.chmod(0o755)
        write(run / "ver.claude", "%s\n2.1.316\n" % fake)
        tr = write(s.tmp / "trd.jsonl", json.dumps({"type": "user", "version": "2.1.316", "message": {"role": "user", "content": "x"}}) + "\n")
        env = {"SIMPLETERM": "1", "SIMPLETERM_HOOK_TEST": "1", "SIMPLETERM_HOOK_TEST_ASK_WAIT": "6"}
        if s.kind == "sh":
            slow = s.tmp / "slow-awk"
            slow.mkdir(exist_ok=True)
            write(slow / "awk", "#!/bin/sh\ncase \"$*\" in *'$0 ~ r && (x'*) sleep 2 ;; esac\nexec %s \"$@\"\n"
                  % os.path.realpath(s.bin / "awk")).chmod(0o755)
            env["PATH"] = "%s:%s" % (slow, s.bin)
        s.run("claude", cc_event("sd1", "Stop", stop_hook_active=False, last_assistant_message="Done.", background_tasks=[],
                                 session_crons=[], transcript_path=str(tr)), env)
        usage = lambda: [json.loads(r["plain"]) for r in tctl("/_ctl/records")["records"] if r["path"] == "/v1/ingest" and r["body"]["ev"] == "usage"]
        u = wait_for(usage, 120, 0.5)
        s.check("ask deadline: no answer, a slow watcher -> timeout, not failed",
                len(u) == 1 and u[0].get("uq", {}).get("err") == "timeout", str([x.get("uq") for x in u]))
        s.settle("the ask")
    finally:
        # The stand-in never answers: left on the suite's PATH, every later Claude Code Stop with a tunnel would ask
        # it and wait out the 60 seconds (the usage cases come after this one).
        for f in (s.bin / "claude", s.home / ".simpleterm" / "run" / "ver.claude"):
            if f.is_symlink() or f.exists():
                f.unlink()
        tun.terminate()
        tun.wait(5)


def t_v2_usage_ask_gate(s):
    """SimpleTerm if/usage-ask#conditions, hist/usage-ask#d21, hist/usage-ask#d22: every version is asked, by the version of the executable that the ask runs (a native
    install links it to versions/<v> and the ask runs that file; else the file's --version, cached, `unknown` if it
    gives none, measured again in the background when the file is newer or another, no ask that turn); that version
    stops for good after an answer showing spend or a hook, or 3 failed asks in a row (an answer resets the count;
    sign-in results do not count); the session's av is a transcript line's top-level "version"; an agent that stays
    ends with its children; agent-hook.conf values with comments, blanks, quotes or a CR."""
    tun, tctl = s.spawn_mock()
    try:
        trl = lambda v, extra=None: json.dumps(dict({"type": "user", "version": v, "message": {"role": "user", "content": "x"}}, **(extra or {}))) + "\n"
        tr = write(s.tmp / "trg.jsonl", trl("2.1.316"))
        stop = lambda sid="sg1": cc_event(sid, "Stop", stop_hook_active=False, last_assistant_message="Done.", background_tasks=[], session_crons=[],
                                          transcript_path=str(tr))
        run = s.home / ".simpleterm" / "run"
        fake = s.bin / "claude"
        vd = s.tmp / "share" / "claude" / "versions"
        sess = {"total_cost_usd": 0, "total_api_duration_ms": 0, "total_duration_ms": 0, "total_lines_added": 0, "total_lines_removed": 0, "model_usage": {}}
        ok = {"type": "control_response", "response": {"subtype": "success", "request_id": "1", "response": {"session": sess,
            "subscription_type": "max", "rate_limits_available": True, "rate_limits": {"seven_day": {"utilization": 12.5, "resets_at": "2026-11-10T00:00:00Z"}}}}}
        spent = json.loads(json.dumps(ok))
        spent["response"]["response"]["session"].update(total_cost_usd=0.0031, total_api_duration_ms=900, model_usage={"claude-x": {"inputTokens": 10}})
        unknown = json.loads(json.dumps(ok))
        unknown["response"]["response"]["rate_limits"] = None
        nosub = {"type": "control_response", "response": {"subtype": "success", "request_id": "1", "response": {"session": sess, "rate_limits_available": False}}}
        line = lambda o: json.dumps(o, separators=(",", ":")) + "\n"
        cache = run / "ver.claude"

        def setup(reply=ok, conf_text=None, link=None, seed="2.1.316"):
            s.setup([(LINK_T, {"kind": "tunnel", "relay_url": tctl.url, "fmt": 2})])
            tctl("/_ctl/reset", {})
            tctl("/_ctl/config", {"links": {LINK_T["id"]: dict(LINK_T, unknown_error="unknown")}})
            for f in ("asks", "ask.env", "reply", "vcalls", "version", "linger", "child", "stubborn", "agentpid", "grand"):
                (s.tmp / f).unlink() if (s.tmp / f).exists() else None
            if conf_text is not None:
                (s.home / ".simpleterm" / "agent-hook.conf").write_bytes(conf_text)
            answer(reply)
            run.mkdir(parents=True, exist_ok=True)
            fresh()
            if fake.is_symlink() or fake.exists():
                fake.unlink()
            if link:
                point(link)
            else:
                fake.write_text(FAKE_ASKER)
                fake.chmod(0o755)
                if seed:
                    write(cache, "%s\n%s\n" % (fake, seed))

        def answer(reply):
            (s.tmp / "reply").write_text(reply if isinstance(reply, str) else line(reply))

        def point(v):
            # A native install: the link on PATH names versions/<v>.
            if not (vd / v).exists():
                write(vd / v, FAKE_ASKER).chmod(0o755)
            if fake.is_symlink():
                fake.unlink()
            fake.symlink_to(vd / v)

        def fresh():
            # The app connected now, the last ask 5 minutes past.
            (run / ("tun.%s.last" % LINK_T["id"][:8])).write_text("%d 200\n" % int(time.time()))
            for f in run.glob("ask.claude.*"):
                if not f.name.endswith((".auth", ".off", ".fail")):
                    f.write_text("%d\n" % (int(time.time()) - 400))

        def asks():
            return int((s.tmp / "asks").read_text()) if (s.tmp / "asks").exists() else 0

        def vcalls():
            return len((s.tmp / "vcalls").read_text().splitlines()) if (s.tmp / "vcalls").exists() else 0

        def events():
            return [json.loads(r["plain"]) for r in tctl("/_ctl/records")["records"] if r["path"] == "/v1/ingest" and r["body"]["ev"] == "usage"]

        def off():
            f = run / "ask.claude.off"
            return f.read_text().splitlines() if f.exists() else []

        def fails():
            f = run / "ask.claude.fail"
            return f.read_text().strip() if f.exists() else None

        def turn(sid="sg1"):
            # A turn's end, and what it started in the background (an ask, a --version) ended.
            s.run("claude", stop(sid), {"SIMPLETERM": "1"})
            s.settle("the Stop hook's ask or --version, if any")

        def asked(sid="sg1", within=20):
            # One more ask, its event sent.
            n, e = asks(), len(events())
            s.run("claude", stop(sid), {"SIMPLETERM": "1"})
            return bool(wait_for(lambda: asks() > n and len(events()) > e, within))
        # Any version is asked (SimpleTerm hist/usage-ask#d22): executables and a session outside the measured ones.
        for v in ("2.2.0", "2.1.315"):
            setup(seed=v)
            tr.write_text(trl("2.3.0"))
            s.check("ask: executable %s, session 2.3.0 -> asked" % v, asked() and asks() == 1 and ("usage-ask claude " + v) in s.log_text(), s.log_text()[-300:])
        tr.write_text(trl("2.1.316"))
        # No --version measured yet: the first turn measures it (no ask then), the next one asks.
        setup(seed=None)
        turn()
        wait_for(lambda: vcalls() >= 1, 15)
        s.check("ask gate: no --version cache -> not asked this turn, measured", asks() == 0 and vcalls() == 1, "%d asks, %d --version" % (asks(), vcalls()))
        wait_for(lambda: cache.exists(), 20)
        fresh()
        s.check("ask gate: then asked by the cached version", asked() and asks() == 1 and vcalls() == 1, "%d asks, %d --version" % (asks(), vcalls()))
        # The executable replaced (newer than the cache): not asked with the old version; measured again.
        past = fake.stat().st_mtime - 10
        os.utime(cache, (past, past))
        (s.tmp / "version").write_text("2.2.1 (Claude Code)\n")
        fresh()
        turn()
        wait_for(lambda: vcalls() >= 2, 15)
        s.check("ask gate: executable newer than the cache -> not asked this turn, measured again", asks() == 1 and vcalls() == 2, "%d asks, %d --version" % (asks(), vcalls()))
        wait_for(lambda: not (run / "ver.claude.lock").exists() and "2.2.1" in cache.read_text(), 10)
        fresh()
        s.check("ask gate: then asked as 2.2.1", asked() and "usage-ask claude 2.2.1" in s.log_text(), s.log_text()[-300:])
        # An executable whose --version says nothing: asked as `unknown`, which stops as any version does.
        setup(spent, seed=None)
        (s.tmp / "version").write_text("")
        turn()
        wait_for(lambda: cache.exists(), 20)
        fresh()
        s.check("ask gate: no version from --version -> asked as unknown; spend stops unknown",
                asked() and "usage-ask claude unknown" in s.log_text() and wait_for(lambda: off() == ["unknown"], 5), "off %s; %s" % (off(), s.log_text()[-300:]))
        fresh()
        turn()
        s.check("ask gate: unknown stopped -> not asked", asks() == 1, str(asks()))
        # A native install: the link names the version (no --version), and the ask runs the file it names.
        setup(link="2.2.0")
        ran = asked()
        env = (s.tmp / "ask.env").read_text() if (s.tmp / "ask.env").exists() else ""
        s.check("ask gate: native link to versions/2.2.0 -> asked, running versions/2.2.0, no --version",
                ran and vcalls() == 0 and ("exe=%s " % (vd / "2.2.0")) in env, "%d --version, %s" % (vcalls(), env.strip()))
        # Spend stops that executable version only, and each stopped version stays stopped: a native install
        # moving between two versions, sessions of both.
        setup(spent, link="2.1.316")
        for i in range(6):
            v = ("2.1.316", "2.1.317")[i % 2]
            tr.write_text(trl(v))
            point(v)
            fresh()
            before = asks()
            s.run("claude", stop("sg-" + v), {"SIMPLETERM": "1"})
            if i < 2:
                wait_for(lambda: asks() > before and len(off()) > i, 15)
            else:
                s.settle("the Stop hook's ask, if any")
        s.check("ask gate: spend by 2.1.316 and by 2.1.317 -> each asked once, both stopped", asks() == 2 and sorted(off()) == ["2.1.316", "2.1.317"],
                "%d asks, off %s" % (asks(), off()))
        tr.write_text(trl("2.1.316"))
        # Three failed asks in a row (failed, timeout) stop the version: the fourth turn does not ask.
        # (No answer: the ask waits 60 seconds, SimpleTerm if/usage-ask#run.)
        setup(unknown)
        for reply in (unknown, unknown, ""):
            answer(reply)
            fresh()
            asked(within=85)
        fresh()
        turn()
        u = events()
        s.check("ask gate: failed, failed, timeout -> that version stopped, the 4th turn not asked",
                asks() == 3 and off() == ["2.1.316"] and fails() == "2.1.316 3" and [x.get("uq", {}).get("err") for x in u] == ["failed", "failed", "timeout"],
                "%d asks, off %s, fail %r, %s" % (asks(), off(), fails(), [x.get("uq") for x in u]))
        # An answer clears the count; sign-in results (not-subscriber, auth) leave it as it is.
        setup(unknown)
        for reply in (unknown, unknown, ok):
            answer(reply)
            fresh()
            asked()
        s.check("ask gate: an answer clears the count", fails() is None and not off(), "fail %r, off %s" % (fails(), off()))
        for reply in (unknown, unknown, nosub):
            answer(reply)
            fresh()
            asked()
        s.check("ask gate: failed, failed, not-subscriber -> still 2, not stopped", fails() == "2.1.316 2" and not off(), "fail %r, off %s" % (fails(), off()))
        for f in run.glob("ask.claude.*.auth"):
            f.unlink()
        answer({"type": "control_response", "response": {"subtype": "error", "request_id": "1", "error": "Not logged in · Please run /login"}})
        fresh()
        asked()
        s.check("ask gate: then auth -> still 2", fails() == "2.1.316 2" and not off() and events()[-1].get("uq", {}).get("err") == "auth",
                "fail %r, off %s, %s" % (fails(), off(), events()[-1].get("uq") if events() else None))
        # Another version counts from 1; a count of 3 alone (the stop not yet written) stops it too.
        setup(unknown, link="2.1.316")
        for v in ("2.1.316", "2.1.316", "2.1.317"):
            point(v)
            fresh()
            asked()
        s.check("ask gate: two failed with 2.1.316, then one with 2.1.317 -> 2.1.317 1", fails() == "2.1.317 1" and not off(), "fail %r, off %s" % (fails(), off()))
        write(run / "ask.claude.fail", "2.1.317 3\n")
        fresh()
        turn()
        s.check("ask gate: a count of 3 for the version, nothing in the stop set -> not asked", asks() == 3, str(asks()))
        # The turn-end cleanup keeps the count however old, and takes an old temporary file.
        old = time.time() - 2 * 86400
        tmpf = write(run / "ask.claude.fail.99999", "2.1.317 1\n")
        for f in (run / "ask.claude.fail", tmpf):
            os.utime(f, (old, old))
        turn()
        s.check("ask gate: the turn-end cleanup keeps ask.claude.fail, takes ask.claude.fail.<pid>",
                (run / "ask.claude.fail").exists() and not tmpf.exists(), "%s %s" % ((run / "ask.claude.fail").exists(), tmpf.exists()))
        # The session's av: a line's top-level "version", not one inside a tool result.
        setup()
        tr.write_text(trl("2.2.5", {"toolUseResult": {"structuredContent": {"name": "some-pkg", "version": "2.1.316"}}}) + json.dumps({"type": "summary", "summary": "x"}) + "\n")
        asked()
        u = events()
        s.check("ask: av is the line's top-level version (2.2.5), not a tool result's", u and u[0].get("av") == "2.2.5", str(u)[:300])
        tr.write_text(trl("2.1.316"))
        # A hook ran in the ask (--include-hook-events): as with spend.
        for sub in ("hook_started", "hook_response"):
            hook = line({"type": "system", "subtype": sub, "hook_id": "h1", "hook_name": "SessionStart:startup", "hook_event": "SessionStart"})
            setup(hook + line(ok))
            asked()
            u = events()
            s.check("ask gate: a %s event in the ask -> uq failed, no windows, version stopped" % sub,
                    u and u[0].get("uq", {}).get("err") == "failed" and "lims" not in u[0] and off() == ["2.1.316"], "%s off %s" % (str(u)[:200], off()))
        fresh()
        answer(ok)
        turn()
        s.check("ask gate: after a hook event, that version is not asked again", asks() == 1, str(asks()))
        # The agent stays after its answer, with a child of its own: both end.
        setup()
        (s.tmp / "linger").write_text("1")
        asked()
        child = wait_for(lambda: (s.tmp / "child").read_text().strip() if (s.tmp / "child").exists() else "", 10)

        def alive(pid):
            try:
                os.kill(int(pid), 0)
                return True
            except (OSError, ValueError):
                return False
        gone = wait_for(lambda: child and not alive(child), 15)
        s.check("ask gate: an agent that stays, and its child, end after the answer", bool(child) and bool(gone), "child %s alive %s" % (child, child and alive(child)))
        if child and alive(child):
            os.kill(int(child), 9)

        def pid_of(name):
            f = s.tmp / name
            return f.read_text().strip() if f.exists() else ""

        def stubborn(env_extra=None):
            # An agent that ignores TERM after its answer, with a child and a grandchild that left its tree.
            setup()
            (s.tmp / "stubborn").write_text("1")
            n = len(events())
            s.run("claude", stop(), dict({"SIMPLETERM": "1"}, **(env_extra or {})))
            wait_for(lambda: len(events()) > n, 25)
            wait_for(lambda: pid_of("agentpid") and pid_of("child") and pid_of("grand"), 10)
            agent, kid, grand = pid_of("agentpid"), pid_of("child"), pid_of("grand")
            wait_for(lambda: not alive(agent) and not alive(kid) and not alive(grand), 15)
            state = (alive(agent), alive(kid), alive(grand))
            for pid in (agent, kid, grand):
                if pid and alive(pid):
                    os.kill(int(pid), 9)
            return bool(agent and kid and grand), state
        if s.kind == "sh":
            # Its own process group (perl setpgrp, else setsid): all of it ends, TERM ignored or not.
            seen, state = stubborn()
            s.check("ask gate: in its own process group, an agent that ignores TERM, its child and a grandchild out of its tree all end",
                    seen and state == (False, False, False), "pids seen %s, alive (agent, child, grandchild) %s" % (seen, state))
            # Without perl and setsid: its tree, KILL after TERM; a grandchild out of the tree is not reached (README).
            nogrp = s.tmp / "bin-nogroup"
            if not nogrp.exists():
                nogrp.mkdir()
                for e in s.bin.iterdir():
                    if e.name not in ("perl", "setsid"):
                        os.symlink(e, nogrp / e.name)
            seen, state = stubborn({"PATH": str(nogrp)})
            s.check("ask gate: without perl and setsid, an agent that ignores TERM and its child end (its tree)",
                    seen and state[:2] == (False, False), "pids seen %s, alive (agent, child, grandchild) %s" % (seen, state))
        else:
            # The process tree (Kill(true)): an agent that ignores TERM and its child end.
            seen, state = stubborn()
            s.check("ask gate: an agent that ignores TERM and its child end (process tree)", seen and state[:2] == (False, False),
                    "pids seen %s, alive (agent, child, grandchild) %s" % (seen, state))
        # Sessions of one agent and settings folder end a turn at once: one ask (the 5-minute slot is claimed at
        # once), in every round (sh 20 sessions x 5 rounds, ps1 10 x 4: its hooks start slower).
        n, rounds = (20, 5) if s.kind == "sh" else (10, 4)
        counts = []
        for rnd in range(rounds):
            setup()
            ps = [s.start("claude", stop("race%d" % i), {"SIMPLETERM": "1"}) for i in range(n)]
            for pr in ps:
                s.finish(pr, 60)
            wait_for(lambda: asks() >= 1, 25)
            s.settle("the Stop hooks' asks, if more than one started")
            counts.append(asks())
        s.check("ask gate: %d sessions end a turn at once -> one ask, each of %d rounds" % (n, rounds), counts == [1] * rounds, str(counts))
        # agent-hook.conf as people write it: comments, blanks, CRLF, quotes; the key's first line decides.
        for name, text in (("comment", b"usage_ask=off      # off: never ask an agent for its limits\n"), ("blanks around =", b"usage_ask = off\n"),
                           ("CRLF", b"usage_ask=off\r\n"), ("trailing blank", b"usage_ask=off \n"), ("double quotes", b'usage_ask="off"\n'),
                           ("single quotes, tabs", b"  usage_ask\t=\t'OFF'  # x\r\n")):
            setup(conf_text=b"poll_wait=2\ndone_delay=0\n" + text)
            turn()
            s.check("ask conf: usage_ask=off with %s -> not asked" % name, asks() == 0, str(asks()))
        setup(conf_text=b"poll_wait=2\ndone_delay=0\nusage = 0   # no context or limits\r\n")
        turn()
        s.check("ask conf: usage = 0 with a comment and CRLF -> not asked, no usage", asks() == 0 and not events(), "%d asks, %d events" % (asks(), len(events())))
        setup(conf_text=b"poll_wait=2\ndone_delay=0\nusage_ask=yes please   # ask\nusage_ask=off\n")
        s.check("ask conf: the key's first line decides (\"yes please\", then off) -> asked", asked(), "%d asks; log %s" % (asks(), s.log_text()[-300:]))
    finally:
        if fake.is_symlink():
            fake.unlink()
        tun.terminate()
        tun.wait(5)


def t_v2_usage_ask(s):
    """SimpleTerm if/usage-ask#conditions: the usage ask — only while the app is connected (a tunnel's last event an HTTP 200 within 10
    minutes), after a turn, every 5 minutes at most, SIMPLETERM_PROBE=1 and ~/.simpleterm/probe, the answer to the
    tunnel as src ask with uq, no ask again after a failed sign-in until the credentials change, usage_ask=off, any
    session version (SimpleTerm hist/usage-ask#d22), Codex on by default and usage_ask_codex=off."""
    tun, tctl = s.spawn_mock()
    try:
        tr = write(s.tmp / "tr.jsonl", json.dumps({"type": "user", "version": "2.1.316", "message": {"role": "user", "content": "x"}}) + "\n")
        stop = cc_event("sk1", "Stop", stop_hook_active=False, last_assistant_message="Done.", background_tasks=[], session_crons=[], transcript_path=str(tr))
        run = s.home / ".simpleterm" / "run"
        fake = s.bin / "claude"
        # The session of every measured ask: no model spend (SimpleTerm if/usage-ask#conditions gate).
        sess = {"total_cost_usd": 0, "total_api_duration_ms": 0, "total_duration_ms": 0, "total_lines_added": 0, "total_lines_removed": 0, "model_usage": {}}
        ok = {"type": "control_response", "response": {"subtype": "success", "request_id": "1", "response": {"session": sess,
            "subscription_type": "max", "rate_limits_available": True, "rate_limits": {
                "five_hour": None, "seven_day": {"utilization": 12.5, "resets_at": "2026-11-10T00:00:00.000Z"},
                "model_scoped": [{"display_name": "Opus 5", "utilization": 40, "resets_at": "2026-11-10T00:00:00Z"}]}}}}

        def setup(reply=None, live=True, code=200, age=0, conf=None):
            s.setup([(LINK_T, {"kind": "tunnel", "relay_url": tctl.url, "fmt": 2}), (LINK_A, {"fmt": 2, "push": "disabled"})], conf=conf)
            tctl("/_ctl/reset", {})
            tctl("/_ctl/config", {"links": {LINK_T["id"]: dict(LINK_T, unknown_error="unknown")}})
            for f in ("asks", "ask.env", "reply", "vcalls", "version", "linger", "child"):
                (s.tmp / f).unlink() if (s.tmp / f).exists() else None
            for f in run.glob("ask.*"):
                f.unlink()
            if reply is not None:
                (s.tmp / "reply").write_text(json.dumps(reply, separators=(",", ":")) + "\n")
            run.mkdir(parents=True, exist_ok=True)
            last = run / ("tun.%s.last" % LINK_T["id"][:8])
            if live:
                last.write_text("%d %d\n" % (int(time.time()) - age, code))
            elif last.exists():
                last.unlink()
            fake.write_text(FAKE_ASKER)
            fake.chmod(0o755)
            vercache("claude", "2.1.316")

        def vercache(name, ver):
            # The executable's measured --version (run/ver.<agent>), as an earlier turn leaves it.
            write(run / ("ver." + name), "%s\n%s\n" % (s.bin / name, ver))

        def asks():
            return int((s.tmp / "asks").read_text()) if (s.tmp / "asks").exists() else 0

        def ask_events():
            return [json.loads(r["plain"]) for r in tctl("/_ctl/records")["records"] if r["path"] == "/v1/ingest" and r["body"]["ev"] == "usage"]
        setup(ok)
        s.run("claude", stop, {"SIMPLETERM": "1"})
        u = wait_for(ask_events, 25)
        p = u[0] if u else {}
        s.check("ask claude: src ask with its time, the model window, plan, uq ok",
                [(x["id"], x.get("src"), x.get("at") == p.get("ts")) for x in p.get("lims", [])] == [("seven_day", "ask", True), ("seven_day.Opus-5", "ask", True)]
                and p.get("plan") == "max" and p.get("uq") == {"src": "ask", "at": p.get("ts"), "ok": True}, str(p)[:500])
        s.check("ask: not to the relay", not [r for r in s.records("/v1/ingest") if r["body"]["ev"] == "usage"])
        env = (s.tmp / "ask.env").read_text() if (s.tmp / "ask.env").exists() else ""
        probe = s.home / ".simpleterm" / "probe"
        s.check("ask: SIMPLETERM_PROBE=1, not a SimpleTerm session, in ~/.simpleterm/probe (700)",
                "probe=1 simpleterm= " in env and env.strip().endswith("/.simpleterm/probe")
                and (s.kind != "sh" or oct(probe.stat().st_mode & 0o777) == "0o700"), env)
        # Five minutes at most per agent and settings folder.
        s.run("claude", stop, {"SIMPLETERM": "1"})
        s.settle("the Stop hook's ask, if any")
        s.check("ask: not again within 5 minutes", asks() == 1, str(asks()))
        # The hook run by an ask does nothing.
        rc, out, err, el = s.run("claude", stop, {"SIMPLETERM": "1", "SIMPLETERM_PROBE": "1"})
        s.check("ask: a hook with SIMPLETERM_PROBE=1 does nothing", rc == 0 and out == "" and "probe" not in s.log_text()[-200:], out)
        # Only while the app is connected.
        for name, kw in (("no tunnel event", {"live": False}), ("the last one 11 minutes ago", {"age": 660}), ("the last one failed", {"code": 0})):
            setup(ok, **kw)
            s.run("claude", stop, {"SIMPLETERM": "1"})
            s.settle("the Stop hook's ask, if any")
            s.check("ask: not asked, app not connected (%s)" % name, asks() == 0, str(asks()))
        # The off switch in any case.
        for v in ("off", "OFF", "No", "FALSE", "0"):
            setup(ok, conf={"usage_ask": v})
            s.run("claude", stop, {"SIMPLETERM": "1"})
            s.settle("the Stop hook's ask, if any")
            s.check("ask: usage_ask=%s" % v, asks() == 0, str(asks()))
        # Any session version is asked (SimpleTerm hist/usage-ask#d22).
        for v in ("2.2.0", "1.0.0"):
            tr.write_text(json.dumps({"type": "user", "version": v, "message": {"role": "user", "content": "x"}}) + "\n")
            setup(ok)
            s.run("claude", stop, {"SIMPLETERM": "1"})
            wait_for(lambda: asks() >= 1 and ask_events(), 25)
            s.check("ask: session version %s is asked" % v, asks() == 1 and len(ask_events()) == 1, "%d asks, %d events" % (asks(), len(ask_events())))
        tr.write_text(json.dumps({"type": "user", "version": "2.1.316", "message": {"role": "user", "content": "x"}}) + "\n")
        # No subscriber limits (API key): uq not-subscriber, no windows.
        setup({"type": "control_response", "response": {"subtype": "success", "request_id": "1", "response": {"session": sess, "rate_limits_available": False}}})
        s.run("claude", stop, {"SIMPLETERM": "1"})
        u = wait_for(ask_events, 25)
        p = u[0] if u else {}
        s.check("ask: rate_limits_available false -> uq not-subscriber, no lims",
                p.get("uq", {}).get("err") == "not-subscriber" and p["uq"].get("ok") is False and "lims" not in p, str(p)[:300])
        # Reported once: not asked again (5 minutes past) until the credentials change.
        for f in [f for f in run.glob("ask.claude.*") if not f.name.endswith((".auth", ".off"))]:
            f.write_text("%d\n" % (int(time.time()) - 400))
        s.run("claude", stop, {"SIMPLETERM": "1"})
        s.settle("the Stop hook's ask, if any")
        s.check("ask: after not-subscriber, not again until the credentials change", asks() == 1 and len(ask_events()) == 1,
                "%d asks, %d events" % (asks(), len(ask_events())))
        # An answer showing model spend: uq failed, and that version is not asked again.
        spent = json.loads(json.dumps(ok))
        spent["response"]["response"]["session"]["total_cost_usd"] = 0.0012
        setup(spent)
        s.run("claude", stop, {"SIMPLETERM": "1"})
        u = wait_for(ask_events, 25)
        s.check("ask: an answer with model spend -> uq failed, no windows", u and u[0].get("uq", {}).get("err") == "failed" and "lims" not in u[0], str(u)[:300])
        for f in [f for f in run.glob("ask.claude.*") if not f.name.endswith((".auth", ".off"))]:
            f.write_text("%d\n" % (int(time.time()) - 400))
        (s.tmp / "reply").write_text(json.dumps(ok, separators=(",", ":")) + "\n")
        s.run("claude", stop, {"SIMPLETERM": "1"})
        s.settle("the Stop hook's ask, if any")
        s.check("ask: after model spend, this version is not asked again", asks() == 1, str(asks()))
        (run / "ask.claude.off").unlink() if (run / "ask.claude.off").exists() else None
        # A failed sign-in: no ask again until the credentials file changes.
        setup({"type": "control_response", "response": {"subtype": "error", "request_id": "1", "error": "Not logged in · Please run /login"}})
        s.run("claude", stop, {"SIMPLETERM": "1"})
        u = wait_for(ask_events, 25)
        s.check("ask: a failed sign-in -> uq auth", u and u[0].get("uq", {}).get("err") == "auth", str(u)[:300])
        af = [f for f in run.glob("ask.claude.*") if not f.name.endswith(".auth")]
        for f in af:
            f.write_text("%d\n" % (int(time.time()) - 400))
        s.run("claude", stop, {"SIMPLETERM": "1"})
        s.settle("the Stop hook's ask, if any")
        s.check("ask: after a failed sign-in, not again (5 minutes past)", asks() == 1, str(asks()))
        cred = s.home / ".claude" / ".credentials.json"
        write(cred, "{}")
        future = time.time() + 5
        os.utime(cred, (future, future))
        for f in af:
            f.write_text("%d\n" % (int(time.time()) - 400))
        (s.tmp / "reply").write_text(json.dumps(ok, separators=(",", ":")) + "\n")
        s.run("claude", stop, {"SIMPLETERM": "1"})
        wait_for(lambda: asks() >= 2, 15)
        s.check("ask: asked again once the credentials changed", asks() == 2, str(asks()))
        wait_for(lambda: len(ask_events()) >= 2, 25)
        # Codex app-server: initialize, initialized, account/rateLimits/read; every limit id, as the rollout makes them.
        ro = write(s.tmp / "codex" / "ro.jsonl", json.dumps({"type": "session_meta", "payload": {"cli_version": "0.165.0"}}) + "\n")
        cfake = s.bin / "codex"
        cfake.write_text(FAKE_ASKER)
        cfake.chmod(0o755)
        cseed = lambda: vercache("codex", "0.165.0")
        snap = lambda lid, p1: {"limitId": lid, "primary": {"usedPercent": p1, "windowDurationMins": 300, "resetsAt": 1795746291},
                                "secondary": {"usedPercent": 3, "windowDurationMins": 10080, "resetsAt": 1796000000}, "planType": "plus",
                                "rateLimitReachedType": None}
        reply2 = json.dumps({"id": 2, "result": {"rateLimits": snap("codex", 4), "rateLimitsByLimitId": {
            "codex": snap("codex", 4), "codex_bengalfox": snap("codex_bengalfox", 17)}}}, separators=(",", ":")) + "\n"
        cstop = json.dumps({"session_id": "cx9", "turn_id": "t", "transcript_path": str(ro), "cwd": "/w/repo", "hook_event_name": "Stop",
                            "model": "gpt-5.5", "stop_hook_active": False, "last_assistant_message": "Done."})
        # A ChatGPT sign-in whose token the hook can see, 2 hours left (a Codex ask runs only then or for an
        # API key login: SimpleTerm if/usage-ask-refresh#fields).
        xp = base64.urlsafe_b64encode(json.dumps({"exp": int(time.time()) + 7200}).encode()).decode().rstrip("=")
        write(s.home / ".codex" / "auth.json", json.dumps({"OPENAI_API_KEY": None, "tokens": {"access_token": "eyJhbGciOiJub25lIn0.%s.c2ln" % xp}}))
        # On by default (SimpleTerm hist/usage-ask#d22); usage_ask_codex=off turns off Codex's asks only.
        for v in ("off", "No", "OFF   # not Codex", '"false"', "0"):
            setup({"id": 1, "result": {"userAgent": "x"}}, conf={"usage_ask_codex": v})
            cseed()
            (s.tmp / "reply2").write_text(reply2)
            s.run("codex", cstop, {"SIMPLETERM": "1"})
            s.settle("the Stop hook's ask, if any")
            s.check("ask codex: usage_ask_codex=%s -> not asked" % v, asks() == 0, str(asks()))
        setup({"id": 1, "result": {"userAgent": "x"}})
        cseed()
        (s.tmp / "reply2").write_text(reply2)
        s.run("codex", cstop, {"SIMPLETERM": "1"})
        u = wait_for(lambda: [x for x in ask_events() if x.get("app") == "codex"], 25)
        p = u[0] if u else {}
        s.check("ask codex: each limit id's primary and secondary, src ask, plan",
                [(x["id"], x["pct"], x.get("src")) for x in p.get("lims", [])] == [
                    ("codex.primary", 4, "ask"), ("codex.secondary", 3, "ask"), ("codex_bengalfox.primary", 17, "ask"), ("codex_bengalfox.secondary", 3, "ask")]
                and p.get("plan") == "plus" and p.get("uq", {}).get("ok") is True, str(p)[:500])
        (s.tmp / "reply2").unlink()
    finally:
        (s.home / ".codex" / "auth.json").unlink() if (s.home / ".codex" / "auth.json").exists() else None
        tun.terminate()
        tun.wait(5)


def t_v2_usage_ask_refresh(s):
    """SimpleTerm if/usage-ask-refresh#skip, #fields, #no-cut, if/usage-ask#run, hist/usage-ask#d23, #d24: no ask in a turn where the agent is
    about to refresh its sign-in token (Claude Code: claudeAiOauth.expiresAt less than 10 minutes away or past; Codex: the
    exp of the JWT tokens.access_token so, or last_refresh more than 7 days ago), and then nothing is counted and the
    5-minute slot is not taken. Claude Code: a credentials file that is not there, cannot be read or is broken, or a
    value not there or not of its form, asks. Codex asks only for an API key login (tokens null) or a read exp with no
    refresh due; anything else skips the same way (sign-in state unknown). The answer is awaited 60 seconds (0.5.1:
    20). A Codex error answer, which ends with "id":2}, is read (auth, not-subscriber), not taken for a timeout."""
    tun, tctl = s.spawn_mock()
    run = s.home / ".simpleterm" / "run"
    ccred = s.home / ".claude" / ".credentials.json"
    xcred = s.home / ".codex" / "auth.json"
    try:
        line = lambda o: json.dumps(o, separators=(",", ":")) + "\n"
        tr = write(s.tmp / "trr.jsonl", json.dumps({"type": "user", "version": "2.1.316", "message": {"role": "user", "content": "x"}}) + "\n")
        stop = cc_event("sr1", "Stop", stop_hook_active=False, last_assistant_message="Done.", background_tasks=[], session_crons=[], transcript_path=str(tr))
        ro = write(s.tmp / "codex" / "ror.jsonl", json.dumps({"type": "session_meta", "payload": {"cli_version": "0.165.0"}}) + "\n")
        cstop = json.dumps({"session_id": "cxr", "turn_id": "t", "transcript_path": str(ro), "cwd": "/w/repo", "hook_event_name": "Stop",
                            "model": "gpt-5.5", "stop_hook_active": False, "last_assistant_message": "Done."})
        sess = {"total_cost_usd": 0, "total_api_duration_ms": 0, "total_duration_ms": 0, "total_lines_added": 0, "total_lines_removed": 0, "model_usage": {}}
        ok = {"type": "control_response", "response": {"subtype": "success", "request_id": "1", "response": {"session": sess,
            "subscription_type": "max", "rate_limits_available": True, "rate_limits": {"seven_day": {"utilization": 12.5, "resets_at": "2026-11-10T00:00:00Z"}}}}}
        snap = {"limitId": "codex", "primary": {"usedPercent": 4, "windowDurationMins": 300, "resetsAt": 1795746291},
                "secondary": {"usedPercent": 3, "windowDurationMins": 10080, "resetsAt": 1796000000}, "planType": "plus", "rateLimitReachedType": None}
        cok = {"id": 2, "result": {"rateLimits": snap, "rateLimitsByLimitId": {"codex": snap}}}

        def setup(agent, reply2=None, delay=None):
            s.setup([(LINK_T, {"kind": "tunnel", "relay_url": tctl.url, "fmt": 2})])
            tctl("/_ctl/reset", {})
            tctl("/_ctl/config", {"links": {LINK_T["id"]: dict(LINK_T, unknown_error="unknown")}})
            for f in ("asks", "ask.env", "reply", "reply2", "delay", "vcalls", "version"):
                (s.tmp / f).unlink() if (s.tmp / f).exists() else None
            for c in (ccred, xcred):
                if c.exists():
                    c.chmod(0o600)
                    c.unlink()
            if agent == "claude":
                (s.tmp / "reply").write_text(line(ok))
            else:
                (s.tmp / "reply").write_text(line({"id": 1, "result": {"userAgent": "x"}}))
                (s.tmp / "reply2").write_text(line(reply2 or cok))
            if delay:
                (s.tmp / "delay").write_text(str(delay))
            run.mkdir(parents=True, exist_ok=True)
            # The app connected now; no ask before.
            (run / ("tun.%s.last" % LINK_T["id"][:8])).write_text("%d 200\n" % int(time.time()))
            fake = s.bin / agent
            fake.write_text(FAKE_ASKER)
            fake.chmod(0o755)
            write(run / ("ver." + agent), "%s\n%s\n" % (fake, "2.1.316" if agent == "claude" else "0.165.0"))

        def asks():
            return int((s.tmp / "asks").read_text()) if (s.tmp / "asks").exists() else 0

        def events(agent):
            # (The event's app: claude-code, codex.)
            app = "claude-code" if agent == "claude" else agent
            return [p for p in (json.loads(r["plain"]) for r in tctl("/_ctl/records")["records"] if r["path"] == "/v1/ingest" and r["body"]["ev"] == "usage")
                    if p.get("app") == app]

        def turn(agent):
            s.run(agent, stop if agent == "claude" else cstop, {"SIMPLETERM": "1"})

        def asked(agent, within=25):
            # The turn asked, and its usage event came.
            turn(agent)
            return bool(wait_for(lambda: asks() >= 1 and events(agent), within))

        def not_asked(agent):
            turn(agent)
            s.settle("the Stop hook's ask, if any")
            return asks() == 0

        def jwt(payload):
            b = lambda o: base64.urlsafe_b64encode(json.dumps(o, separators=(",", ":")).encode()).decode().rstrip("=")
            return b({"alg": "RS256", "typ": "JWT"}) + "." + (payload if isinstance(payload, str) else b(payload)) + ".c2ln"

        def iso(t):
            return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t)) + ".123456789Z"

        now = int(time.time())
        # A file mode 0 is read all the same by root: those cases are left out then (no geteuid on Windows).
        root = hasattr(os, "geteuid") and os.geteuid() == 0
        claude_cred = lambda ms: json.dumps({"claudeAiOauth": {"accessToken": "sk-ant-oat01-x", "refreshToken": "sk-ant-ort01-x", "expiresAt": ms,
                                                               "scopes": ["user:inference"], "subscriptionType": "max"}})
        # --- Claude Code: claudeAiOauth.expiresAt.
        for name, text in (("expires in 5 minutes", claude_cred((now + 300) * 1000)), ("expires in 9 minutes", claude_cred((now + 540) * 1000)),
                           ("expired an hour ago", claude_cred((now - 3600) * 1000))):
            setup("claude")
            write(ccred, text)
            s.check("ask refresh: claude, token %s -> not asked" % name, not_asked("claude"), "%d asks" % asks())
            left = sorted(f.name for f in run.glob("ask.claude.*"))
            s.check("ask refresh: claude, token %s -> nothing counted, no 5-minute slot, logged" % name,
                    not left and "usage-ask claude skipped: sign-in refresh due" in s.log_text(), "%s; %s" % (left, s.log_text()[-200:]))
        # The slot was not taken: once the token is fresh, the next turn asks at once.
        write(ccred, claude_cred((now + 7200) * 1000))
        s.check("ask refresh: claude, then the token refreshed (2 hours left) -> asked at once", asked("claude"), "%d asks; %s" % (asks(), s.log_text()[-200:]))
        for name, text in (("expires in 2 hours", claude_cred((now + 7200) * 1000)), ("no file", None), ("not JSON", "not json\n"),
                           ("cut short", claude_cred((now + 300) * 1000)[:40]), ("no expiresAt", "{}"),
                           ("expiresAt a string", json.dumps({"claudeAiOauth": {"expiresAt": str((now + 300) * 1000)}})),
                           ("expiresAt null", json.dumps({"claudeAiOauth": {"expiresAt": None}})), ("unreadable", claude_cred((now + 300) * 1000))):
            if name == "unreadable" and root:
                continue
            setup("claude")
            if text is not None:
                write(ccred, text)
                if name == "unreadable":
                    ccred.chmod(0)
            s.check("ask refresh: claude, credentials %s -> asked" % name, asked("claude"), "%d asks; %s" % (asks(), s.log_text()[-200:]))
        # --- Codex: the access token JWT's exp, last_refresh.
        auth = lambda tok, lr: json.dumps({"OPENAI_API_KEY": None, "tokens": {"id_token": jwt({"exp": now + 7200}), "access_token": tok,
                                                                              "refresh_token": "rt-x", "account_id": "acc"}, "last_refresh": lr}, indent=2)
        acct = {"https://api.openai.com/auth": {"chatgpt_account_id": "acc", "chatgpt_plan_type": "plus"}}
        fresh = auth(jwt(dict(acct, exp=now + 7200)), iso(now - 86400))
        skips = [("exp in 5 minutes", auth(jwt(dict(acct, exp=now + 300)), iso(now - 86400)), "refresh due"),
                 ("exp a minute past", auth(jwt(dict(acct, exp=now - 60)), iso(now - 86400)), "refresh due"),
                 ("last_refresh 8 days ago", auth(jwt(dict(acct, exp=now + 7200)), iso(now - 8 * 86400)), "refresh due"),
                 ("no JWT, last_refresh 8 days ago", auth("not-a-jwt", iso(now - 8 * 86400)), "refresh due"),
                 # The token's state not seen (#fields): skipped too, logged apart.
                 ("no JWT, last_refresh a day ago", auth("not-a-jwt", iso(now - 86400)), "state unknown"),
                 ("a JWT payload not base64url", auth(jwt("e30%%%"), iso(now - 86400)), "state unknown"),
                 ("a JWT payload not JSON", auth(jwt("AAAA"), iso(now - 86400)), "state unknown"),
                 ("tokens without access_token", json.dumps({"OPENAI_API_KEY": None, "tokens": {"refresh_token": "rt-x"}}), "state unknown"),
                 ("no file", None, "state unknown"), ("not JSON", "not json\n", "state unknown"), ("cut short", fresh[:60], "state unknown"),
                 ("larger than 64 KiB", json.dumps(dict(json.loads(fresh), pad="x" * 70000)), "state unknown"),
                 ("unreadable", fresh, "state unknown")]
        for name, text, why in skips:
            if name == "unreadable" and root:
                continue
            setup("codex")
            if text is not None:
                write(xcred, text)
                if name == "unreadable":
                    xcred.chmod(0)
            s.check("ask refresh: codex, %s -> not asked" % name, not_asked("codex"), "%d asks" % asks())
            left = sorted(f.name for f in run.glob("ask.codex.*"))
            s.check("ask refresh: codex, %s -> nothing counted, no 5-minute slot, logged (%s)" % (name, why),
                    not left and ("usage-ask codex skipped: sign-in " + why) in s.log_text(), "%s; %s" % (left, s.log_text()[-200:]))
        # The slot was not taken: once the hook sees a fresh token, the next turn asks at once.
        xcred.chmod(0o600)
        write(xcred, fresh)
        s.check("ask refresh: codex, then a token it can see (2 hours left) -> asked at once", asked("codex"), "%d asks; %s" % (asks(), s.log_text()[-200:]))
        for name, text in (("exp in 2 hours, last_refresh a day ago", fresh),
                           ("exp in 2 hours (a padded payload), last_refresh with an offset", auth(jwt(dict(acct, exp=now + 7200, x="ab")), iso(now - 86400)[:19] + "+09:00")),
                           ("exp in 2 hours, no last_refresh", json.dumps({"tokens": {"access_token": jwt(dict(acct, exp=now + 7200))}})),
                           ("an API key", json.dumps({"OPENAI_API_KEY": "sk-x", "tokens": None, "last_refresh": None})),
                           ("an API key, no tokens", json.dumps({"OPENAI_API_KEY": "sk-x"}))):
            setup("codex")
            write(xcred, text)
            s.check("ask refresh: codex, %s -> asked" % name, asked("codex"), "%d asks; %s" % (asks(), s.log_text()[-200:]))
        # --- The answer wait (60 seconds): an answer after 50 seconds is read (0.5.1 waited 20).
        setup("claude", delay=50)
        turn("claude")
        u = wait_for(lambda: events("claude"), 80)
        s.check("ask wait: claude answers after 50 seconds -> read (uq ok, its window)",
                u and u[0].get("uq", {}).get("ok") is True and [x["id"] for x in u[0].get("lims", [])] == ["seven_day"], str(u)[:300])
        # --- A Codex error answer ends with "id":2}: read as such, not a timeout.
        for msg, err in (("codex account authentication required to read rate limits", "auth"),
                         ("chatgpt authentication required to read rate limits", "not-subscriber")):
            setup("codex", reply2={"error": {"code": -32600, "message": msg}, "id": 2})
            write(xcred, fresh)
            t0 = time.time()
            turn("codex")
            u = wait_for(lambda: events("codex"), 30)
            took = time.time() - t0
            s.check("ask codex: an error answer ending with \"id\":2} (%s) -> uq %s at once" % (msg[:24], err),
                    u and u[0].get("uq", {}).get("err") == err and took < 15, "%.1f s, %s" % (took, str(u)[:300]))
        # --- The answer is a JSON-RPC response, a line without "method": notifications before it that nest an
        # object with id 2 (ending with , or }) are not the answer (SimpleTerm if/usage-ask#run).
        setup("codex")
        write(xcred, fresh)
        (s.tmp / "reply2").write_text(line({"method": "thread/started", "params": {"thread": {"id": 2, "name": "x"}}})
                                      + line({"method": "item/completed", "params": {"item": {"id": 2}}}) + line(cok))
        turn("codex")
        u = wait_for(lambda: events("codex"), 30)
        s.check("ask codex: notifications nesting {\"id\":2, ...} and {\"id\":2} before the answer -> the answer read (uq ok, its windows)",
                u and u[0].get("uq", {}).get("ok") is True and [x["id"] for x in u[0].get("lims", [])] == ["codex.primary", "codex.secondary"],
                str(u)[:300])
    finally:
        for c in (ccred, xcred):
            if c.exists():
                c.chmod(0o600)
                c.unlink()
        tun.terminate()
        tun.wait(5)


def t_usage_ask_refresh_vectors(s):
    """SimpleTerm if/usage-ask-refresh#vectors (now 1800000000) and #fields: whether the ask is skipped, as the hook's
    test mode `__refresh <file> <now>` prints it. Values not of their form (a fraction, a date-time not RFC 3339, a
    padded JWT payload) and a value past the first 64 KiB are unknown, and a file that is not one whole JSON object
    (the facts parser reads a document cut short as far as it goes) gives no values: Claude Code then asks, Codex
    skips unless it is an API key login (tokens missing or null, OPENAI_API_KEY a non-empty string)."""
    now = "1800000000"
    hdr = "eyJhbGciOiJub25lIn0"
    ok = hdr + ".eyJleHAiOjE4MDAwMDA2MDF9."
    b64 = lambda o: base64.urlsafe_b64encode(json.dumps(o, separators=(",", ":")).encode()).decode()
    codex = lambda tok, lr=None: json.dumps(dict({"tokens": {"access_token": tok}}, **({} if lr is None else {"last_refresh": lr})))
    claude = lambda ms: json.dumps({"claudeAiOauth": {"accessToken": "x", "expiresAt": ms}})
    raw_claude = lambda ms: '{"claudeAiOauth":{"expiresAt":%s}}' % ms
    pad = lambda t, n: t + " " * (n - len(t))
    v2, v9 = codex(ok, "2027-01-15T07:00:00Z"), claude(1800000601000)
    vectors = [
        ("V1", "codex", codex(hdr + ".eyJleHAiOjE4MDAwMDA1OTl9."), "skip"),
        ("V2", "codex", v2, "ask"),
        ("V3", "codex", codex(hdr + ".eyJleHAiOjE3OTk5OTk5OTl9."), "skip"),
        ("V4", "codex", codex(ok, "2027-01-08T07:59:59.999999Z"), "skip"),
        ("V5", "codex", codex(ok, "2027-01-08T16:59:59+09:00"), "skip"),
        ("V6", "codex", codex(ok, "2027-01-08T08:00:01Z"), "ask"),
        ("V7", "codex", codex("abc"), "skip"),
        ("V8", "claude", claude(1800000599000), "skip"),
        ("V9", "claude", v9, "ask"),
        ("V10", "claude", claude(0), "skip"),
        ("V11a missing", "claude", None, "ask"),
        ("V11b not JSON", "claude", "not json", "ask"),
        ("V11c cut off", "claude", v9[:-1], "ask"),
        ("V11d 65537 bytes", "claude", pad(v9, 65537), "ask"),
        ("V12a missing", "codex", None, "skip"),
        ("V12b not JSON", "codex", "not json", "skip"),
        ("V12c cut off", "codex", v2[:-1], "skip"),
        ("V12d 65537 bytes", "codex", pad(v2, 65537), "skip"),
        ("V12e 65536 bytes", "codex", pad(v2, 65536), "ask"),
        ("V13", "codex", '{"OPENAI_API_KEY":"sk-test","tokens":null}', "ask"),
        ("V14", "codex", json.dumps({"tokens": {"id_token": "x", "refresh_token": "y"}}), "skip"),
        ("V15", "codex", '{"OPENAI_API_KEY":"","tokens":null}', "skip"),
        ("V16", "codex", json.dumps({"OPENAI_API_KEY": "sk-test", "tokens": {"id_token": "x", "refresh_token": "y"}}), "skip"),
        ("V17 exp a string", "codex", codex(hdr + "." + b64({"exp": "1800000601"}).rstrip("=") + "."), "skip"),
        ("V17 exp not an integer", "codex", codex(hdr + "." + b64({"exp": 1800000601.5}).rstrip("=") + "."), "skip"),
        ("V18", "codex", codex(ok), "ask"),
        # Past the spec's vectors: the same bounds the other way, the API key cases, values not of their form.
        ("cut off, a past expiresAt", "claude", "{\"claudeAiOauth\": {\"expiresAt\": 1800000599000", "ask"),
        ("larger than 64 KiB, a past expiresAt", "claude", json.dumps({"pad": "x" * 70000, "claudeAiOauth": {"expiresAt": 1800000599000}}), "ask"),
        ("65536 bytes, a past expiresAt", "claude", pad(claude(1800000599000), 65536), "skip"),
        ("cut after an inner }", "claude", raw_claude("1800000599000")[:-1], "ask"),
        ("text after the object", "claude", raw_claude("1800000599000") + " x", "ask"),
        # Not one whole object: text after it, a second object, a bracket closing the other kind (the values would
        # skip Claude Code and ask Codex if the file were taken whole).
        ("text right after the object", "claude", raw_claude("1800000599000") + "x", "ask"),
        ("text right after the object", "codex", '{"OPENAI_API_KEY":"sk-test","tokens":null}x', "skip"),
        ("two objects", "claude", raw_claude("1800000599000") + '{"a":1}', "ask"),
        ("two objects", "codex", '{"OPENAI_API_KEY":"sk-test","tokens":null}{"a":1}', "skip"),
        ("[ closed by }", "claude", '{"claudeAiOauth":{"expiresAt":1800000599000},"a":[1}]', "ask"),
        ("[ closed by }", "codex", '{"OPENAI_API_KEY":"sk-test","tokens":null,"a":[1}]', "skip"),
        ("{ closed by ]", "claude", raw_claude("1800000599000")[:-1] + "]", "ask"),
        ("{ closed by ]", "codex", v2[:-1] + "]", "skip"),
        ("nested brackets", "codex", '{"a":[{"b":[1,2]},{"c":{}}],"OPENAI_API_KEY":"sk-test","tokens":null}', "ask"),
        ("braces in a string", "claude", '{"a":"}{\\"","claudeAiOauth":{"expiresAt":1800000599000}}\n', "skip"),
        ("within 64 KiB", "codex", json.dumps({"pad": "x" * 60000, "tokens": {"access_token": ok}}), "ask"),
        # The API key login: tokens missing or null at the top level, the key a non-empty string; last_refresh is not read.
        ("an API key, no tokens", "codex", '{"OPENAI_API_KEY":"sk-test"}', "ask"),
        ("an API key, tokens null with spaces", "codex", '{ "OPENAI_API_KEY" : "sk-test" , "tokens" :  null }', "ask"),
        ("an API key, last_refresh 8 days", "codex", '{"OPENAI_API_KEY":"sk-test","tokens":null,"last_refresh":"2027-01-07T08:00:00Z"}', "ask"),
        ("an API key, tokens in another object", "codex", '{"x":{"tokens":{"access_token":"abc"}},"OPENAI_API_KEY":"sk-test"}', "ask"),
        ("an API key, \"tokens\": in a string", "codex", '{"a":"\\"tokens\\":{","OPENAI_API_KEY":"sk-test","tokens":null}', "ask"),
        ("an API key not a string", "codex", '{"OPENAI_API_KEY":5,"tokens":null}', "skip"),
        ("no API key, tokens null", "codex", '{"OPENAI_API_KEY":null,"tokens":null}', "skip"),
        ("an API key, tokens an empty object", "codex", '{"OPENAI_API_KEY":"sk-test","tokens":{}}', "skip"),
        ("an API key, tokens nullx", "codex", '{"OPENAI_API_KEY":"sk-test","tokens":nullx}', "skip"),
        ("an API key, tokens with exp due", "codex", json.dumps({"OPENAI_API_KEY": "sk-test", "tokens": {"access_token": hdr + ".eyJleHAiOjE4MDAwMDA1OTl9."}}), "skip"),
        ("an API key, tokens with exp fine", "codex", json.dumps({"OPENAI_API_KEY": "sk-test", "tokens": {"access_token": ok}}), "ask"),
        # Not of its form (#fields): unknown. Codex: an exp in 10 minutes and 1 second not read, so skipped (V17
        # too); a last_refresh 7 days and 1 second old not read, so the ask runs on a fine exp.
        ("a padded payload", "codex", codex(hdr + "." + b64({"exp": 1800000601, "a": 12}) + "."), "skip"),
        ("last_refresh with a space", "codex", codex(ok, "2027-01-08 07:59:59Z"), "ask"),
        ("last_refresh with z", "codex", codex(ok, "2027-01-08T07:59:59z"), "ask"),
        ("last_refresh +0900", "codex", codex(ok, "2027-01-08T16:59:59+0900"), "ask"),
        ("last_refresh without a zone", "codex", codex(ok, "2027-01-08T07:59:59"), "ask"),
        ("last_refresh 8 days, no JWT", "codex", codex("abc", "2027-01-07T08:00:00Z"), "skip"),
        ("expiresAt with a fraction", "claude", raw_claude("1800000599000.5"), "ask"),
        ("expiresAt a string", "claude", claude("1800000599000"), "ask"),
        ("expiresAt within 64 KiB", "claude", json.dumps({"pad": "x" * 60000, "claudeAiOauth": {"expiresAt": 1800000599000}}), "skip"),
    ]
    for i, (name, agent, text, want) in enumerate(vectors):
        f = s.tmp / ("cred-%d.json" % i)
        if text is None:
            f.unlink() if f.exists() else None
        else:
            f.write_text(text)
        rc, out, err, _ = s.run(agent, "", {"SIMPLETERM_HOOK_TEST": "1"}, args=("__refresh", str(f), now))
        s.check("refresh vectors: %s %s -> %s" % (name, agent, want), out.strip() == want, "%r %r" % (out, err[-200:]))


def t_v2_param_keys(s):
    """The hook adds its own parameters to the input's facts as @.<name> (the request kind, the
    window, ...): a top-level input key that starts with @ must not stand in for one of them."""
    fixed = {"SIMPLETERM_HOOK_TEST": "1", "SIMPLETERM_HOOK_TEST_NONCE": V_NONCE, "SIMPLETERM_HOOK_TEST_RID": V_RID,
             "SIMPLETERM_HOOK_TEST_TS": "1793232000", "SIMPLETERM_HOOK_TEST_TMS": "1793232000123"}
    plains = []
    for extra_keys in ({}, {"@": {"rkind": "claude_notif", "win": "web", "pv": "9.9.9"}, "@x": "y"}):
        s.setup([(LINK_A, {"fmt": 2, "push": "disabled"})], conf={"claude_wait": 5})
        inp = json.loads(v2_perm(session="sess-at"))
        inp.update(extra_keys)
        s.run("claude", json.dumps(inp), fixed)
        recs = s.records("/v1/ingest")
        plains.append(recs[0].get("plain") if recs else None)
    s.check("param keys: an input key @ changes nothing in the request", plains[0] and plains[0] == plains[1],
            "%s | %s" % (str(plains[0])[:300], str(plains[1])[:300]))


def t_v2_n10(s):
    """SimpleTerm if/event-decision#validation (hist/event-decision#n10): a request the user did not see. OpenCode's reject also settles the session's other
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
    # Sent while it was the only open request (no others, so the bridge gave none), and another opened
    # before the decision: always and reject would settle that one too (OpenCode 1.19 and 2.x), so the
    # decision is judged by the requests open now, not by what the request carried (SimpleTerm if/event-decision#validation, check 5).
    for ocv in ("2", "1.19"):
        alone = json.loads(oc)
        alone.pop("others")
        alone["oc"] = ocv
        if ocv == "1.19":
            alone.pop("save")
            alone.update({"patterns": ["echo a"], "always": ["echo *"]})
        alone = json.dumps(alone)
        for name, fmt, dext, dec, open_ids, want in (
                ("dext deny, seen only this one", 2, {"act": "deny", "seen": ["per_1"]}, "deny", ["per_1", "per_3"], None),
                ("dext deny, no seen", 2, {"act": "deny"}, "deny", ["per_1", "per_3"], None),
                ("v1 deny (a quick action)", 2, None, "deny", ["per_1", "per_3"], None),
                ("older app (no fmt), v1 deny", None, None, "deny", ["per_1", "per_3"], None),
                ("dext allow_scope, seen only this one", 2, {"act": "allow_scope", "scope": 0, "seen": ["per_1"]}, "allow", ["per_1", "per_3"], None),
                ("dext deny, seen both", 2, {"act": "deny", "seen": ["per_1", "per_3"]}, "deny", ["per_1", "per_3"], {"decision": "deny"}),
                ("v1 allow (once, settles nothing else)", 2, None, "allow", ["per_1", "per_3"], {"decision": "allow"}),
                ("older app, v1 deny, nothing else open", None, None, "deny", ["per_1"], {"decision": "deny"})):
            s.setup([(LINK_A, {"fmt": fmt, "decision": dec, "after": 1, "dext": dext})], conf={"opencode_wait": 20})
            pend(open_ids)
            rc, out, err, el = s.run("opencode", alone)
            s.check("N10 opencode %s alone when sent (%s)" % (ocv, name), (decision_json(out) or None) == want, out + s.log_text()[-200:])
            if name == "dext deny, no seen":
                req = ((s.records("/v1/ingest") or [{}])[0].get("plain_json") or {}).get("req") or {}
                s.check("N10 opencode %s alone when sent: affects and others [] all the same" % ocv,
                        req.get("affects") == ["allow_scope", "deny", "deny_reason"] and req.get("others") == [], str(req)[:300])
    # A v1 link (no fmt=2) takes no extension beyond what it was offered (allow, deny).
    s.setup([(LINK_A, {"decision": "deny", "after": 1, "dext": {"act": "deny_reason", "reason": "no"}})], conf={"claude_wait": 8})
    rc, out, err, el = s.run("claude", v2_perm(session="sess-v1"))
    s.check("N10 a fmt-less link: deny_reason was not offered there -> nothing", out.strip() == "", out)
    # The decision is there and the agent moved on just before it is printed (SimpleTerm if/event-decision#validation, check 6): the
    # terminal's note lands while the hook sleeps between its looks, right after the poll's result.
    # An attempt counts only if the hook had not taken the decision yet when the note was written
    # (its result file still there); otherwise the hook was first and the attempt is repeated.
    got = None
    for attempt in range(6):
        s.setup([(LINK_A, {"fmt": 2, "decision": "allow", "after": 2, "dext": {"act": "allow"}})], conf={"claude_wait": 30})
        p = s.start("claude", v2_perm(session="sess-race%d" % attempt))
        run = s.home / ".simpleterm" / "run"
        dec = wait_for(lambda: [f for f in run.glob("rq.*.dec")], 30, 0.005)
        with open(run / ("sess-race%d.res" % attempt), "a") as f:
            f.write("%d turn -\n" % int(time.time() + 1))
        first = bool(dec) and any(f.exists() for f in dec)
        rc, out, err, el = s.finish(p, 60)
        if first:
            got = out
            break
    s.check("N10 answered in the terminal after the decision came: nothing printed", got is not None and got.strip() == "",
            "no attempt where the note came first" if got is None else got)
    # Answered in the terminal first (a prompt or the tool ran): the late decision is not applied.
    # (The decision comes 8 s after the request: the prompt is well before it, also on a loaded machine.)
    s.setup([(LINK_A, {"fmt": 2, "decision": "allow", "after": 8, "dext": {"act": "allow"}})], conf={"claude_wait": 12})
    p = s.start("claude", v2_perm(session="sess-n10"))
    # Its first poll: it waits now (what it found at its start is behind it).
    wait_for(lambda: s.records("/v1/decision"), 15)
    s.run("claude", json.dumps({"session_id": "sess-n10", "cwd": "/home/u/api", "hook_event_name": "UserPromptSubmit", "prompt": "go on"}))
    rc, out, err, el = s.finish(p, 60)
    s.check("N10 answered at the terminal first: nothing printed", out.strip() == "", out)


def t_v2_link_results(s):
    """SimpleTerm if/event-decision#link-result link results: a dropped decision ends only that link's wait; a v2 tunnel hears it at
    once (resolved, scope link) and gets the request again under a new rid, 3 times at most; an older
    tunnel neither. SimpleTerm if/ssh-tunnel-wait#resolved: the request-level result names the last rid each tunnel got."""
    tun, tctl = s.spawn_mock()
    try:
        def setup(tunnel_opts, relay_opts, fmt=2, conf=None):
            s.setup([(LINK_T, {"kind": "tunnel", "relay_url": tctl.url, "fmt": fmt}), (LINK_A, dict({"fmt": 2}, **relay_opts))],
                    conf=dict({"claude_wait": 40}, **(conf or {})))
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
        # (The relay decides late enough for all three resends, also on a loaded machine.)
        setup({"decisions": [dict(bad) for _ in range(6)]}, {"decision": "deny", "after": 25})
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
        s.settle("the hook's sends to the tunnel")
        s.check("link results: older tunnel: no link result, no resend, relay applies",
                behavior(out).get("behavior") == "allow" and len(tun_ingests("permission")) == 1
                and not [r for r in tun_ingests("resolved") if ((r.get("plain_json") or {}).get("res") or {}).get("scope") == "link"],
                out + str(len(tun_ingests())))
    finally:
        tun.terminate()
        tun.wait(5)


def t_v2_link_waits(s):
    """SimpleTerm if/ssh-tunnel-wait#link-wait: waits per link and the order of sending."""
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
        # (The relay's alert goes from the background: it may land after the hook ended.)
        rel = wait_for(lambda: s.records("/v1/ingest"), 15) or []
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
        # Counted from the relay's start instead, the relay's ingest (4 s) would fit in the 6 s and its
        # allow would be printed: the cut ingest and the empty output show it, whatever the machine's load.
        s.check("waits: hidden: the cap counts from the hook's start (relay ingest cut to the time left)",
                out.strip() == "" and el < 30 and "http=000" in s.log_text(), "%.2fs %s" % (el, s.log_text()[-300:]))
        # A Claude Code subagent's request (agent_id in the hook input): its window opens after its hook ends
        # [measured 2.1.331], so it goes as wait hidden, as Codex's (SimpleTerm spec/request-wait#hook-wait,
        # hist/request-wait#d2). The app's tunnel answers suppressed: the hook does not wait and prints
        # nothing, and the relay gets a question without buttons.
        sub = v2_perm(session="sub", agent_id="a42a3936ffcdae563", agent_type="general-purpose")

        def tun_of(sid):  # (by session: a tunnel that answers late records after the next case's reset)
            return [r for r in tun_ingests("permission") if (r.get("plain_json") or {}).get("sid") == sid]
        setup({"push": "suppressed"}, {"push": "sent"})
        rc, out, err, el = s.run("claude", sub)
        rel = wait_for(lambda: s.records("/v1/ingest"), 15) or []
        tp = tun_of("sub")
        s.check("waits: a Claude Code subagent's request goes as wait hidden",
                tp and ((tp[0].get("plain_json") or {}).get("req") or {}).get("wait") == "hidden", str(tp)[:300])
        s.check("waits: a subagent's request: the tunnel's suppressed ends it at once, nothing printed",
                out.strip() == "" and el < 15 and not s.records("/v1/decision")
                and not [r for r in tctl("/_ctl/records")["records"] if r["path"] == "/v1/decision"],
                "%r %.2fs %s" % (out, el, s.log_text()[-300:]))
        s.check("waits: a subagent's request: the relay gets a question without nonce, same rid",
                rel and rel[0]["body"]["ev"] == "question" and "nh" not in rel[0]["body"]
                and (rel[0].get("plain_json") or {}).get("req", {}).get("wait") == "none"
                and tp and rel[0]["body"]["rid"] == tp[0]["body"]["rid"], str(rel)[:400])
        # Its wait on the relay alone (no tunnel answered) is at most 60 seconds, or claude_wait when that is
        # shorter, counted from the hook's start (SimpleTerm spec/request-wait-link#send-order). As for Codex
        # above: after the tunnel's 5 s, a cap the relay's ingest (4 s) does not fit in leaves the output
        # empty. The 60 is stood in for by 6 (SIMPLETERM_HOOK_TEST_SUB_CAP): a test of 60 s otherwise.
        short = {"SIMPLETERM_HOOK_TEST": "1", "SIMPLETERM_HOOK_TEST_SUB_CAP": "6"}
        setup({"ingest_delay": 7}, {"ingest_delay": 4, "decision": "allow"})
        rc, out, err, el = s.run("claude", sub, short)
        s.check("waits: a subagent's request, relay only: its cap (60 s; 6 here) when claude_wait (15) is longer",
                out.strip() == "" and el < 30 and "http=000" in s.log_text(), "%r %.2fs %s" % (out, el, s.log_text()[-300:]))
        setup({"ingest_delay": 7}, {"ingest_delay": 4, "decision": "allow"}, conf={"claude_wait": 6})
        rc, out, err, el = s.run("claude", sub)
        s.check("waits: a subagent's request, relay only: claude_wait (6) when it is shorter than 60",
                out.strip() == "" and el < 30 and "http=000" in s.log_text(), "%r %.2fs %s" % (out, el, s.log_text()[-300:]))
        # The main thread's request (shared) keeps claude_wait: the relay's allow after its 4 s is applied.
        setup({"ingest_delay": 7}, {"ingest_delay": 4, "decision": "allow"})
        rc, out, err, el = s.run("claude", v2_perm(session="main"), short)
        tp = wait_for(lambda: tun_of("main"), 15) or []
        s.check("waits: the main thread's request stays wait shared, under claude_wait",
                behavior(out).get("behavior") == "allow"
                and tp and ((tp[0].get("plain_json") or {}).get("req") or {}).get("wait") == "shared",
                "%r %s %s" % (out, [(r.get("plain_json") or {}).get("req") for r in tp] or str(tp)[:300], s.log_text()[-300:]))
        # A relay that lost R1 (SimpleTerm hist/relay-http#r-changes): the question again, same rid, without nonce, not waited.
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


def t_v2_held(s):
    """SimpleTerm if/ssh-tunnel-wait#held "보류한 요청 다시 알리기" (#414): a v2 app's tunnel that holds a request back for
    a wait the user is looking at answers suppressed with held:true. While Claude Code's session file
    (sessions/<agent pid>.json) says this session still waits on a permission prompt, the same one
    (statusUpdatedAt unchanged), the hook sends the request to that tunnel again every 5 seconds:
    a new rid and nonce, the same req.id. A tunnel that then answers sent is waited on and decides.
    The prompt closed or replaced, another session's file, no file, plain suppressed or a tunnel
    without fmt=2: nothing again, and the hook ends as 0.5.0 did."""
    tun, tctl = s.spawn_mock()
    sessions = s.home / ".claude" / "sessions"
    try:
        def setup(push_seq, fmt=2, decision=None, after=0):
            s.setup([(LINK_T, {"kind": "tunnel", "relay_url": tctl.url, "fmt": fmt})], conf={"claude_wait": 40})
            tctl("/_ctl/reset", {})
            opts = dict(LINK_T, unknown_error="unknown", max_body=65536, push=push_seq[-1], push_seq=list(push_seq))
            if decision:
                opts.update(decision=decision, after=after)
            tctl("/_ctl/config", {"links": {LINK_T["id"]: opts}})
            shutil.rmtree(sessions, ignore_errors=True)
            sessions.mkdir(parents=True)

        def perms():
            return [r for r in tctl("/_ctl/records")["records"] if r["path"] == "/v1/ingest" and r["body"]["ev"] == "permission"]

        def results():
            # Only the results of this step's requests (their req.id): a hook posts its result in the
            # background after it ends (rq_finish), so under load the result of the step before can
            # land after this step's reset. Its window result once read as this step's last one.
            # (A wait on them ends when this step's result comes; 30 s only bounds a machine too loaded
            # for that background post to land at once.)
            recs = tctl("/_ctl/records")["records"]
            reqs = {((r.get("plain_json") or {}).get("req") or {}).get("id") for r in recs
                    if r["path"] == "/v1/ingest" and r["body"]["ev"] in ("permission", "question")}
            res = [((r.get("plain_json") or {}).get("res") or {}) for r in recs
                   if r["path"] == "/v1/ingest" and r["body"]["ev"] == "resolved"]
            return [x for x in res if x.get("req") and x.get("req") in reqs]

        def state(pid, session="held-1", status="waiting", waiting_for="permission prompt", at=1793232000123, raw=False):
            # raw: non-ASCII text as UTF-8, the way Claude Code (JSON.stringify) writes it
            f = sessions / ("%d.json" % pid)
            tmp = sessions / ("%d.json.tmp" % pid)
            tmp.write_text(json.dumps({"pid": pid, "sessionId": session, "cwd": "/home/u/api", "status": status,
                                       "waitingFor": waiting_for, "statusUpdatedAt": at, "updatedAt": at},
                                      ensure_ascii=not raw), encoding="utf-8")
            os.replace(tmp, f)

        def start(session="held-1", env=None, proc=None, file_session=None, perm=None, **st):
            """The stand-in agent (its pid names the session file) and the hook under it. Claude Code
            records the prompt in that file 5 to 45 ms before the hook starts (3 ms after it at the
            latest; SimpleTerm hist/event-v2-request#m31), and the hook gives a file it cannot read 5 seconds.
            The agent starts the hook only once the file is there, so a loaded test machine cannot
            turn those milliseconds into seconds."""
            cmd = [sys.executable, "-I", "-c", AGENT_GATED_PY, v2_perm(session=session, **(perm or {}))] + list(s.argv) + ["claude"]
            agent = s.popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=s.env(env), cwd=str(s.tmp))
            if proc:  # a /proc of the agent for a hook without ps
                (proc / str(agent.pid)).mkdir(parents=True, exist_ok=True)
                (proc / str(agent.pid) / "comm").write_text("claude\n")
            if st.get("status") != "none":
                state(agent.pid, session=file_session or session, **st)
            agent.stdin.write(b"go\n")
            agent.stdin.close()
            agent.stdin = None
            hook = int(agent.stdout.readline())
            return agent, hook

        def finished(agent, timeout=40):
            try:
                out = agent.communicate(timeout=timeout)[0]
                return True, out.decode(errors="replace")
            except subprocess.TimeoutExpired:
                return False, ""

        # Open: told again (held, held), then the app shows it (sent) and the user approves there.
        setup(["held", "held", "sent"], decision="allow")
        t0 = time.time()
        agent, hook = start()
        done, out = finished(agent)
        el = time.time() - t0
        got = perms()
        plains = [r.get("plain_json") or {} for r in got]
        s.check("held: told again every 5 s while the prompt is open, then decided there",
                done and behavior(out).get("behavior") == "allow" and len(got) == 3 and 8 <= el < 30,
                "%s %.1fs n=%d %s" % (out, el, len(got), s.log_text()[-400:]))
        s.check("held: a new rid and nonce each time, the same req.id",
                len({r["body"]["rid"] for r in got}) == 3 and len({p.get("nonce") for p in plains}) == 3
                and len({(p.get("req") or {}).get("id") for p in plains}) == 1 and all(r["body"].get("nh") for r in got),
                str(plains)[:400])
        res = results()
        s.check("held: the request's result names the last rid", wait_for(lambda: results(), 30)
                and results()[-1].get("out") == "applied" and results()[-1].get("rrid") == got[-1]["body"]["rid"], str(res)[:300])

        # Answered at the terminal (the prompt closes: busy): nothing again; the hook ends at once.
        setup(["held"])
        agent, hook = start()
        # (Waits end when the posts come; 30 s only bounds a machine too loaded to keep the hook's 5 s.)
        s.check("held: told again once", wait_for(lambda: len(perms()) >= 2, 30), "%d %s" % (len(perms()), s.log_text()[-300:]))
        n0 = len(perms())
        state(agent.pid, status="busy", waiting_for=None, at=1793232009000)
        done, out = finished(agent, 15)
        n = len(perms())
        s.settle("the hook's sends")
        s.check("held: the prompt closed: no more, the hook ends with no decision",
                done and out.strip() == "" and n == n0 and len(perms()) == n0 and "held: the window is not open" in s.log_text(),
                "%r n=%d of %d %s" % (out, n, n0, s.log_text()[-300:]))
        s.check("held: its result says window (not terminal: the prompt may be the session's next one)",
                wait_for(lambda: results(), 30) and results()[-1].get("out") == "window", str(results())[:300])

        # Another prompt in its place (statusUpdatedAt changed): stop.
        setup(["held"])
        agent, hook = start()
        s.check("held: another prompt: told again first", wait_for(lambda: len(perms()) >= 2, 30), "%d %s" % (len(perms()), s.log_text()[-300:]))
        n0 = len(perms())
        state(agent.pid, at=1793232011111)
        done, out = finished(agent, 15)
        s.check("held: another prompt (statusUpdatedAt changed): no more", done and len(perms()) == n0,
                "%d of %d %s" % (len(perms()), n0, s.log_text()[-300:]))

        # Nothing to tell by: another session's file, no file, plain suppressed, a tunnel without fmt=2,
        # or another permission hook of the session waiting (parallel tool calls: Claude shows them in
        # one window, "1 of 2", and its session file stays the same between the items [measured]).
        for name, push, fmt, st in (("another session", "held", 2, {"session": "other"}), ("no session file", "held", 2, {"status": "none"}),
                                    ("plain suppressed", "suppressed", 2, {}), ("no fmt=2", "held", None, {}),
                                    ("another permission hook waiting", "held", 2, {"sibling": True})):
            setup([push], fmt=fmt)
            run = s.home / ".simpleterm" / "run"
            run.mkdir(parents=True, exist_ok=True)
            for old in run.glob("perm.*"):
                old.unlink()
            if st.pop("sibling", False):
                # A live process (this runner) waiting on the same window (statusUpdatedAt).
                (run / ("perm.held-1.%d" % os.getpid())).write_text("1793232000123\n")
            t0 = time.time()
            agent, hook = start(file_session=st.get("session"), **{k: v for k, v in st.items() if k != "session"})
            done, out = finished(agent, 20)
            el = time.time() - t0
            s.check("held: %s: not told again, ends with no decision" % name,
                    done and out.strip() == "" and len(perms()) == 1 and el < 15, "%r %.1fs n=%d" % (out, el, len(perms())))

        # A hook of the session's earlier window that has not ended yet (it checks once a second)
        # holds another statusUpdatedAt: the window open now is still told again (E2E E4d).
        setup(["held"])
        run = s.home / ".simpleterm" / "run"
        run.mkdir(parents=True, exist_ok=True)
        for old in run.glob("perm.*"):
            old.unlink()
        (run / ("perm.held-1.%d" % os.getpid())).write_text("1793231999000\n")
        agent, hook = start()
        s.check("held: an earlier window's hook does not stop it", wait_for(lambda: len(perms()) >= 2, 30), str(len(perms())))
        state(agent.pid, status="idle", waiting_for=None, at=1793232009000)
        finished(agent, 15)
        (run / ("perm.held-1.%d" % os.getpid())).unlink()
        # A window first written well after the hook started is not taken for its own: the user may
        # have answered this request and the next prompt come (SimpleTerm if/ssh-tunnel-wait#open-window).
        setup(["held"])
        agent, hook = start(at=int(time.time() + 30) * 1000)
        done, out = finished(agent, 20)
        s.check("held: a window recorded after the hook's start + 2 s is not its own: not told again",
                done and len(perms()) == 1, "%d %s" % (len(perms()), s.log_text()[-200:]))
        # The value of the window kind (SimpleTerm if/ssh-tunnel-wait#open-window, hist/request-wait-link#d7, issue
        # AhMunGa/simple-term#446): Claude Code 2.1.322 writes `input needed` for a question window, 2.1.316 and 2.1.317
        # wrote `permission prompt`; every other permission request takes only `permission prompt`. A value that is
        # not one of the tool's is not the open window: nothing again, and one line in the hook's log.
        def asks():  # a question goes as ev=question, an approval as ev=permission
            return [r for r in tctl("/_ctl/records")["records"] if r["path"] == "/v1/ingest" and r["body"]["ev"] in ("permission", "question")]

        ask = {"tool": "AskUserQuestion", "suggestions": (), "tool_input": {"questions": [
            {"question": "Which color?", "header": "Color", "multiSelect": False,
             "options": [{"label": "Red", "description": "Warm"}, {"label": "Green", "description": "Calm"}]}]}}
        for name, perm, wf in (("question, input needed (Claude Code 2.1.322)", ask, "input needed"),
                               ("question, permission prompt (2.1.316, 2.1.317)", ask, "permission prompt")):
            setup(["held"])
            agent, hook = start(perm=perm, waiting_for=wf)
            s.check("held: %s: told again" % name, wait_for(lambda: len(asks()) >= 2, 30),
                    "%d %s" % (len(asks()), s.log_text()[-300:]))
            state(agent.pid, status="busy", waiting_for=None, at=1793232009000)
            finished(agent, 15)
        odd = "waiting on: the user's answer \u2014 \uc9c8\ubb38, please wait a while longer than forty"
        for name, perm, wf, shown in (("approval, input needed", None, "input needed", "input needed"),
                                      ("question, a value not known", ask, odd, re.sub(r"[^A-Za-z0-9 ._-]", "", odd)[:40])):
            setup(["held"])
            line = 'held: unknown waitingFor "%s" for %s (stop)' % (shown, (perm or {}).get("tool", "Bash"))
            n0 = s.log_text().count(line)
            agent, hook = start(perm=perm, waiting_for=wf, raw=True)
            done, out = finished(agent, 20)
            s.check("held: %s: not told again, one log line with the value" % name,
                    done and out.strip() == "" and len(asks()) == 1 and s.log_text().count(line) - n0 == 1,
                    "%d %r %s" % (len(asks()), line, s.log_text()[-400:]))
        # Answered at the terminal while the app shows the request (the tunnel answered sent and the hook
        # waits on it). Claude Code keeps a permission hook until the allowed tool ends [measured], which can
        # be minutes, and until 0.8.0 the hook learnt of the answer only then (PostToolUse). The session file
        # says the prompt closed at once: a hook that saw its window open and its own, and then twice in a
        # row that the session waits on nothing, ends with the result terminal (SimpleTerm
        # if/ssh-tunnel-wait#window-closed, issue AhMunGa/simple-term#895).
        def polls():
            return [r for r in tctl("/_ctl/records")["records"] if r["path"] == "/v1/decision"]

        def answered():
            return s.log_text().count("permission answered-at-terminal")

        for name, change in (("the prompt closed (busy)", {"status": "busy", "waiting_for": None, "at": 1793232009000}),
                             ("the prompt closed (idle)", {"status": "idle", "waiting_for": None, "at": 1793232009000})):
            setup(["sent"])
            n0 = answered()
            agent, hook = start()
            s.check("closed: %s: the hook waits on the tunnel" % name, wait_for(lambda: polls(), 20), s.log_text()[-300:])
            # (A set time on purpose: the hook looks once a second, and that it went on waiting is all there
            # is to see. 3.5 s is three looks with the prompt open.)
            time.sleep(3.5)
            s.check("closed: %s: the prompt open: it goes on waiting" % name, agent.poll() is None and answered() == n0)
            t = time.time()
            state(agent.pid, **change)
            done, out = finished(agent, 20)
            el = time.time() - t
            # (At least a second: one look that says closed is not enough, the second comes a second on.)
            s.check("closed: %s: the hook ends with no decision, as answered at the terminal, after two looks" % name,
                    done and out.strip() == "" and 1.0 <= el < 12 and answered() - n0 == 1,
                    "%r %.1fs %s" % (out, el, s.log_text()[-300:]))
            s.check("closed: %s: the request's result says terminal" % name,
                    wait_for(lambda: results(), 30) and results()[-1].get("out") == "terminal", str(results())[:300])
        # Another window in its place (waiting, another statusUpdatedAt): the file does not say whose it
        # is, and a request the user can still answer in the app is not ended on a guess. When the session
        # then waits on nothing, every window of it is closed, this one too.
        setup(["sent"])
        n0 = answered()
        agent, hook = start()
        s.check("closed: another window: the hook waits on the tunnel", wait_for(lambda: polls(), 20), s.log_text()[-300:])
        time.sleep(2.5)  # (two looks with its own window open, as above)
        state(agent.pid, at=1793232011111)
        time.sleep(4.5)  # (four looks at the other window)
        s.check("closed: another window in its place (waiting, another statusUpdatedAt): ends nothing",
                agent.poll() is None and answered() == n0, s.log_text()[-300:])
        state(agent.pid, status="idle", waiting_for=None, at=1793232015000)
        done, out = finished(agent, 20)
        s.check("closed: another window, then the session waits on nothing: answered at the terminal",
                done and out.strip() == "" and answered() - n0 == 1
                and wait_for(lambda: results(), 30) and results()[-1].get("out") == "terminal",
                "%r %s %s" % (out, str(results())[:200], s.log_text()[-300:]))
        # Nothing to tell by — the window never seen open and its own: no session file, another session's
        # file, a window recorded after the hook's start + 2 s. The session file then ends nothing, whatever
        # it says later; the wait goes on as in 0.8.0 (here until the agent is gone).
        run = s.home / ".simpleterm" / "run"
        for name, st in (("no session file", {"status": "none"}), ("another session's file", {"file_session": "other"}),
                         ("a window recorded late", {"late": True})):
            setup(["sent"])
            run.mkdir(parents=True, exist_ok=True)
            for old in run.glob("perm.*"):
                old.unlink()
            n0 = answered()
            if st.pop("late", False):
                st["at"] = int(time.time() + 30) * 1000
            agent, hook = start(**st)
            s.check("closed: %s: the hook waits on the tunnel" % name, wait_for(lambda: polls(), 20), s.log_text()[-300:])
            if st.get("status") != "none":
                state(agent.pid, session=st.get("file_session") or "held-1", status="busy", waiting_for=None, at=1793232009000)
            # (A set time on purpose, as above: four looks at a file that says the prompt is not open.)
            time.sleep(4.5)
            s.check("closed: %s: the session file ends nothing" % name, agent.poll() is None and answered() == n0,
                    s.log_text()[-300:])
            agent.kill()
            finished(agent, 10)
            s.settle("the hook's end")

        # A window shared with other permission hooks ("1 of 2": parallel tool calls of one answer). Claude
        # Code keeps the session file as it is from one item to the next, and the session waits on nothing
        # only once every item is answered [measured 2.1.331]: the hook then ends as answered at the
        # terminal, whether the other hooks were on the window at its first look, joined after it, or joined
        # unseen (between two looks, with the answer). Until then it goes on (SimpleTerm
        # if/ssh-tunnel-wait#window-closed, hist/ssh-tunnel-http#d8). Until 0.9.0 a shared window ended nothing.
        def mark(pid, at="1793232000123"):  # a live hook of the session that first saw the window at `at`
            (run / ("perm.held-1.%d" % pid)).write_text(at + "\n")

        for name in ("three hooks on the window, two items answered", "a hook that joins later", "a hook that joined unseen"):
            setup(["sent"])
            run.mkdir(parents=True, exist_ok=True)
            for old in run.glob("perm.*"):
                old.unlink()
            n0 = answered()
            other = None
            if name.startswith("three"):
                # Two other hooks: this runner and a process that stays alive.
                other = s.popen([sys.executable, "-I", "-c", "import time; time.sleep(60)"])
                mark(os.getpid())
                mark(other.pid)
            agent, hook = start()
            s.check("closed: %s: the hook waits on the tunnel" % name, wait_for(lambda: polls(), 20), s.log_text()[-300:])
            if name.startswith("three"):
                # (Set times on purpose: three looks at the window open with two other hooks on it, then two
                # more after one of those hooks ended, its tool done: items answered, one still open.)
                time.sleep(3.5)
                went_on = agent.poll() is None and answered() == n0
                (run / ("perm.held-1.%d" % os.getpid())).unlink()
                time.sleep(2.5)
                s.check("closed: %s: the window still open: it goes on" % name,
                        went_on and agent.poll() is None and answered() == n0, s.log_text()[-300:])
            elif name == "a hook that joins later":
                mark(os.getpid())
                time.sleep(2.5)  # (two looks at the shared window)
                s.check("closed: %s: the window still open: it goes on" % name, agent.poll() is None and answered() == n0,
                        s.log_text()[-300:])
            else:
                time.sleep(1.5)  # (a look with the window open and its own)
                mark(os.getpid())
            t = time.time()
            state(agent.pid, status="busy", waiting_for=None, at=1793232009000)
            done, out = finished(agent, 20)
            el = time.time() - t
            s.check("closed: %s: every item answered (the session waits on nothing): answered at the terminal" % name,
                    done and out.strip() == "" and 1.0 <= el < 12 and answered() - n0 == 1
                    and wait_for(lambda: results(), 30) and results()[-1].get("out") == "terminal",
                    "%r %.1fs %s %s" % (out, el, str(results())[-200:], s.log_text()[-300:]))
            if other is not None:
                other.kill()
                other.wait(5)
            for m in run.glob("perm.held-1.*"):
                m.unlink()
            s.settle("the hook's end")

        # A Claude Code subagent's request (agent_id in the hook input): its window opens after its hook ends
        # [measured 2.1.331], so the window its hook sees is another's, here the main thread's with that
        # hook's mark. It goes as wait hidden; its hook writes no mark, and the main window closing ends
        # nothing: the wait goes on (here on an older app's tunnel that answered sent) until the decision
        # (SimpleTerm if/ssh-tunnel-wait#open-window, hist/ssh-tunnel-http#d8). Until 0.9.0 it took the main
        # window for one it shared and ended with it.
        sub = {"agent_id": "a42a3936ffcdae563", "agent_type": "general-purpose"}
        setup(["sent"], decision="allow", after=12)
        run.mkdir(parents=True, exist_ok=True)
        for old in run.glob("perm.*"):
            old.unlink()
        mark(os.getpid())
        n0 = answered()
        agent, hook = start(perm=sub)
        s.check("subagent: the hook waits on the tunnel", wait_for(lambda: polls(), 20), s.log_text()[-300:])
        sent = perms()
        s.check("subagent: the request goes as wait hidden",
                sent and ((sent[0].get("plain_json") or {}).get("req") or {}).get("wait") == "hidden", str(sent)[:300])
        time.sleep(1.5)  # (a look at the main window)
        s.check("subagent: its hook writes no mark", not list(run.glob("perm.held-1.%d" % hook)),
                str(sorted(p.name for p in run.glob("perm.*"))))
        state(agent.pid, status="busy", waiting_for=None, at=1793232009000)
        time.sleep(4.5)  # (four looks at a file that says the main window closed)
        s.check("subagent: the main window closing ends nothing", agent.poll() is None and answered() == n0, s.log_text()[-300:])
        done, out = finished(agent, 30)
        s.check("subagent: the decision from the device applies", done and behavior(out).get("behavior") == "allow",
                "%r %s" % (out, s.log_text()[-300:]))
        (run / ("perm.held-1.%d" % os.getpid())).unlink()
        s.settle("the hook's end")
        # The main thread's request while a subagent's hook waits in the same session (the same window
        # value in its stand-in's file): that hook has no mark, so the main window is its own hook's alone
        # and told again (held). Until 0.9.0 the subagent's hook marked the window and the main one was
        # taken for shared: not told again.
        setup(["sent", "held", "held"])
        for old in run.glob("perm.*"):
            old.unlink()
        sub_agent, sub_hook = start(perm=sub)
        s.check("subagent and main: the subagent's hook waits on the tunnel", wait_for(lambda: polls(), 20), s.log_text()[-300:])
        agent, hook = start()
        s.check("subagent and main: the main request is told again", wait_for(lambda: len(perms()) >= 3, 30),
                "%d %s" % (len(perms()), s.log_text()[-300:]))
        state(agent.pid, status="busy", waiting_for=None, at=1793232009000)
        finished(agent, 15)
        sub_agent.kill()
        finished(sub_agent, 10)
        s.settle("the hook's end")
        # Answered while the request is on its way to a slow link (the relay answers a request it will
        # wait on about 4 seconds later): the hook looked at the window before it sent anything, so it
        # has seen it open, and the answer is told from the session file once the links have answered.
        # (No set time before the answer: the hook's mark holds the window's statusUpdatedAt once the
        # hook has looked.)
        s.setup([(LINK_A, {"ingest_delay": 4}), (LINK_T, {"kind": "tunnel", "relay_url": tctl.url, "fmt": 2})],
                conf={"claude_wait": 40})
        tctl("/_ctl/reset", {})
        tctl("/_ctl/config", {"links": {LINK_T["id"]: dict(LINK_T, unknown_error="unknown", max_body=65536, push="sent", push_seq=["sent"])}})
        shutil.rmtree(sessions, ignore_errors=True)
        sessions.mkdir(parents=True)
        run.mkdir(parents=True, exist_ok=True)
        for old in run.glob("perm.*"):
            old.unlink()
        n0 = answered()

        def looked():
            try:
                return any(p.read_text().strip() for p in run.glob("perm.held-1.*"))
            except OSError:
                return False

        agent, hook = start()
        t = time.time()
        seen = wait_for(looked, 3.5)
        state(agent.pid, status="busy", waiting_for=None, at=1793232009000)
        early = time.time() - t
        done, out = finished(agent, 25)
        s.check("closed: answered before a slow link took the request: the hook had looked first (%.2f s)" % early,
                bool(seen) and early < 3.5, "%.2f s %s" % (early, s.log_text()[-300:]))
        s.check("closed: answered before a slow link took the request: answered at the terminal",
                done and out.strip() == "" and answered() - n0 == 1
                and wait_for(lambda: results(), 30) and results()[-1].get("out") == "terminal",
                "%r %s %s" % (out, str(results())[:200], s.log_text()[-300:]))
        s.settle("the hook's end")
        # Two tunnels hold it: one round is one rid for both, sent at once (the slower tunnel's answer
        # does not hold back the other's copy; its link file sorts first).
        tun2, tctl2 = s.spawn_mock()
        try:
            link_s = {"id": "b9" * 16, "secret": "c8" * 32, "enc": "d7" * 32, "mac": "e6" * 32, "label": "dev-box"}
            s.setup([(link_s, {"kind": "tunnel", "relay_url": tctl2.url, "fmt": 2}), (LINK_T, {"kind": "tunnel", "relay_url": tctl.url, "fmt": 2})],
                    conf={"claude_wait": 40})
            for ctl, link, delay in ((tctl2, link_s, 3), (tctl, LINK_T, 0)):
                ctl("/_ctl/reset", {})
                ctl("/_ctl/config", {"links": {link["id"]: dict(link, unknown_error="unknown", max_body=65536, push="held", ingest_delay=delay)}})
            shutil.rmtree(sessions, ignore_errors=True)
            sessions.mkdir(parents=True)
            agent, hook = start()
            def both():
                a = [r for r in tctl2("/_ctl/records")["records"] if r["path"] == "/v1/ingest" and r["body"]["ev"] == "permission"]
                b = perms()
                return (a, b) if len(a) >= 2 and len(b) >= 2 else None
            got = wait_for(both, 25)
            state(agent.pid, status="idle", waiting_for=None, at=1793232009000)
            finished(agent, 20)
            if got:
                a, b = got
                s.check("held: two tunnels: one rid a round for both, a nonce each",
                        a[1]["body"]["rid"] == b[1]["body"]["rid"] and a[1]["body"]["rid"] != a[0]["body"]["rid"]
                        and (a[1].get("plain_json") or {}).get("nonce") != (b[1].get("plain_json") or {}).get("nonce"), str([a[1]["body"]["rid"], b[1]["body"]["rid"]]))
                # Sent at once: the other tunnel's copy came while the slow one still held its own
                # (it answers 3 s after it came). One after the other, it would come after that
                # answer. An order, not a time limit: a loaded machine does not change it.
                s.check("held: two tunnels: sent at once (the slow tunnel does not delay the other)",
                        b[1]["received"] < a[1]["responded"],
                        "the other copy came %.2f s after the slow one, which answered after %.2f s"
                        % (b[1]["received"] - a[1]["received"], a[1]["responded"] - a[1]["received"]))
            else:
                s.check("held: two tunnels: both told again", False, "%d %d" % (len(perms()), len(tctl2("/_ctl/records")["records"])))
        finally:
            tun2.terminate()
            tun2.wait(5)
        # Codex hides its prompt while a hook waits (hidden): even a held answer is not told again.
        setup(["held"])
        codex = json.dumps({"session_id": "held-1", "turn_id": "t1", "transcript_path": None, "cwd": "/w/repo", "hook_event_name": "PermissionRequest",
                            "tool_name": "Bash", "tool_input": {"command": "make"}})
        rc, out, err, el = s.run("codex", codex)
        s.check("held: a Codex (hidden) request is not told again", len(perms()) == 1 and el < 15, "%d %.1fs" % (len(perms()), el))
        # Nor a Claude Code subagent's (hidden): a held answer to a hidden request is not kept.
        setup(["held"])
        t0 = time.time()
        agent, hook = start(perm={"agent_id": "a42a3936ffcdae563", "agent_type": "general-purpose"})
        done, out = finished(agent, 20)
        el = time.time() - t0
        s.check("held: a Claude Code subagent's (hidden) request is not told again",
                done and out.strip() == "" and len(perms()) == 1 and el < 15, "%d %r %.1fs %s" % (len(perms()), out, el, s.log_text()[-300:]))
        if s.kind == "sh":
            # No ps (some containers): the agent's pid from /proc instead (Linux).
            nops = s.tmp / "nops"
            if not nops.exists():
                nops.mkdir()
                for e in s.bin.iterdir():
                    if e.name != "ps":
                        os.symlink(os.path.realpath(e), nops / e.name)  # a stand-in agent is a file, not a link
            for name, proc in (("from /proc", s.tmp / "fakeproc"), ("not at all", None)):
                setup(["held"])
                shutil.rmtree(s.tmp / "fakeproc", ignore_errors=True)
                env = {"PATH": str(nops)}
                if proc:
                    env.update(SIMPLETERM_HOOK_TEST="1", SIMPLETERM_HOOK_TEST_PROC=str(proc))
                agent, hook = start(env=env, proc=proc)
                if proc:
                    s.check("held: without ps, the agent found %s: told again" % name, wait_for(lambda: len(perms()) >= 2, 30), str(len(perms())))
                    state(agent.pid, status="idle", waiting_for=None, at=1793232009000)
                done, out = finished(agent, 20)
                if not proc:
                    s.check("held: without ps or /proc: not told again, ends", done and len(perms()) == 1, "%d %s" % (len(perms()), s.log_text()[-200:]))
    finally:
        tun.terminate()
        tun.wait(5)


# A stand-in agent that stays after its hook ended, until its stdin closes: a hook that sent an
# undecidable request has returned at once, and the agent's window is still open.
AGENT_STAY_PY = (
    "import subprocess, sys\n"
    "p = subprocess.Popen(sys.argv[2:], stdin=subprocess.PIPE)\n"
    "p.stdin.write(sys.argv[1].encode()); p.stdin.close()\n"
    "print(p.pid, flush=True)\n"
    "p.wait()\n"
    "sys.stdin.readline()\n"
)


def t_v2_held_bg(s):
    """SimpleTerm if/ssh-tunnel-wait#held-undecidable (#446): the hook does not wait on an undecidable request
    (wait none), so the background sender that posted it stays when a tunnel with fmt=2 answers held. Every 5
    seconds it checks the agent's own record of the window (Antigravity transcript_full.jsonl, Grok
    chat_history.jsonl / events.jsonl, Claude Code's session file) and sends the same request again (same req,
    new rid, no nonce) to the tunnels that answered held, until the window closes, the user answers at the
    terminal, the agent ends, 540 s pass or no tunnel is left. One sender per request (run/held.<session>.<key>),
    8 per user, one log line at each end. Test values (SIMPLETERM_HOOK_TEST=1 only): HELD_EVERY seconds between
    rounds, HELD_CAP the limit."""
    tun, tctl = s.spawn_mock()
    run = s.home / ".simpleterm" / "run"
    sessions = s.home / ".claude" / "sessions"
    fast = {"SIMPLETERM_HOOK_TEST": "1", "SIMPLETERM_HOOK_TEST_HELD_EVERY": "1"}
    agents = []
    try:
        def setup(push="held"):
            s.setup([(LINK_T, {"kind": "tunnel", "relay_url": tctl.url, "fmt": 2})], conf={"ask_delay": 0})
            tctl("/_ctl/reset", {})
            tctl("/_ctl/config", {"links": {LINK_T["id"]: dict(LINK_T, unknown_error="unknown", max_body=65536, push=push)}})
            shutil.rmtree(sessions, ignore_errors=True)
            sessions.mkdir(parents=True)

        def asks():
            return [r for r in tctl("/_ctl/records")["records"] if r["path"] == "/v1/ingest" and r["body"]["ev"] == "question"]

        def start(agent_args, inp, env=None, before=None):
            """The hook under a stand-in agent that stays; before(pid) writes what the agent records first."""
            cmd = [sys.executable, "-I", "-c", "import sys\nsys.stdin.readline()\n" + AGENT_STAY_PY, inp] + list(s.argv) + list(agent_args)
            agent = s.popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=s.env(dict(fast, **(env or {}))), cwd=str(s.tmp))
            if before:
                before(agent.pid)
            agent.stdin.write(b"go\n")
            agent.stdin.flush()
            int(agent.stdout.readline())
            agents.append(agent)
            return agent

        def stop(agent):
            try:
                agent.stdin.close()
            except OSError:
                pass
            try:
                agent.wait(10)
            except subprocess.TimeoutExpired:
                agent.kill()

        def marks():
            return sorted(p.name for p in run.glob("held.*")) if run.exists() else []

        def ended(line, n0, timeout=20):
            return wait_for(lambda: s.log_text().count(line) > n0 and not marks(), timeout)

        def jl(path, rows):
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "a") as f:
                for r in rows:
                    f.write(json.dumps(r, separators=(",", ":")) + "\n")

        def same_req(got):
            plains = [r.get("plain_json") or {} for r in got]
            return (len({r["body"]["rid"] for r in got}) == len(got) and len({json.dumps(p.get("req"), sort_keys=True) for p in plains}) == 1
                    and all(not p.get("nonce") for p in plains) and all(not r["body"].get("nh") for r in got))

        # Antigravity CLI runs only the sh hook (the PowerShell hook has no Antigravity CLI part).
        if s.kind != "ps1":
            # --- Antigravity ask_question: transcript_full.jsonl, the hook's stepIdx 2, the question step 1.
            tr = s.tmp / "agy" / "transcript_full.jsonl"
            shutil.rmtree(tr.parent, ignore_errors=True)
            jl(tr, [{"step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT", "status": "DONE", "content": "ask me"},
                    {"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "status": "DONE",
                     "tool_calls": [{"name": "ask_question", "args": {"questions": "[]"}}]}])
            agy_q = json.dumps({"conversationId": "conv-h", "workspacePaths": ["/w/a"], "transcriptPath": str(tr), "stepIdx": 2,
                                "toolCall": {"name": "ask_question", "args": {"questions": [{"question": "Which color?", "options": ["Red", "Green"],
                                                                                              "is_multi_select": False}]}}})
            setup()
            n0 = s.log_text().count("held: the window is not open (stop)")
            a = start(("agy", "PreToolUse"), agy_q)
            got = wait_for(lambda: len(asks()) >= 3 and asks(), 20)
            s.check("held bg: agy ask_question: told again while the transcript ends on the question",
                    got and same_req(got) and (got[0].get("plain_json") or {}).get("req", {}).get("nid") == "2",
                    "%d %s" % (len(asks()), s.log_text()[-400:]))
            s.check("held bg: agy: one sender mark while it runs", len(marks()) == 1, str(marks()))
            jl(tr, [{"step_index": 2, "source": "MODEL", "type": "GENERIC", "status": "DONE", "content": "A1: Red"}])
            ok = ended("held: the window is not open (stop)", n0)
            n1 = len(asks())
            s.settle("the sender's last sends", but=[a])
            s.check("held bg: agy: answered (step 2 written): no more, one log line, mark gone",
                    ok and len(asks()) == n1, "%d->%d %s %s" % (n1, len(asks()), marks(), s.log_text()[-300:]))
            stop(a)

            # --- Two copies of the hook for one call (the same stepIdx): one sender.
            tr2 = s.tmp / "agy2" / "transcript_full.jsonl"
            shutil.rmtree(tr2.parent, ignore_errors=True)
            jl(tr2, [{"step_index": 6, "type": "PLANNER_RESPONSE", "tool_calls": [{"name": "ask_question"}]}])
            q7 = json.loads(agy_q)
            q7.update(transcriptPath=str(tr2), stepIdx=7, conversationId="conv-h2")
            setup()
            n0 = s.log_text().count("held: another sender has it (stop)")
            a = start(("agy", "PreToolUse"), json.dumps(q7))
            wait_for(lambda: marks(), 10)
            b = start(("agy", "PreToolUse"), json.dumps(q7))
            s.check("held bg: two hooks of one call: the second sender stops",
                    wait_for(lambda: s.log_text().count("held: another sender has it (stop)") > n0, 15) and len(marks()) == 1,
                    "%s %s" % (marks(), s.log_text()[-300:]))
            stop(b)
            # The agent ends: the sender stops.
            n0 = s.log_text().count("held: agent gone (stop)")
            stop(a)
            s.check("held bg: the agent ended: stops, mark gone", ended("held: agent gone (stop)", n0), "%s %s" % (marks(), s.log_text()[-300:]))

        # --- Grok Build: question, permission window, plan review (chat_history.jsonl, events.jsonl beside updates.jsonl).
        def grok_case(name, tool, call, ntype, message, chat_last, events, close, still_open=None, ts="10:20:00"):
            gd = s.tmp / ("grok-" + call)
            shutil.rmtree(gd, ignore_errors=True)
            gd.mkdir(parents=True)
            (gd / "updates.jsonl").write_text("")
            jl(gd / "chat_history.jsonl", [{"type": "user", "content": [{"type": "text", "text": "go"}]}, chat_last])
            jl(gd / "events.jsonl", events)
            sid = "gk-" + call
            pre = {"hookEventName": "pre_tool_use", "hook_event_name": "PreToolUse", "sessionId": sid, "session_id": sid,
                   "cwd": "/w/g", "toolName": tool, "toolUseId": call, "toolInput": {}, "transcriptPath": str(gd / "updates.jsonl")}
            setup()
            s.run("claude", json.dumps(pre), {"GROK_HOOK_EVENT": "pre_tool_use", "SIMPLETERM": "1"})
            note = {"hookEventName": "notification", "hook_event_name": "Notification", "sessionId": sid, "session_id": sid,
                    "cwd": "/w/g", "notificationType": ntype, "message": message, "level": "info",
                    "timestamp": "2026-11-11T%s.000Z" % ts, "transcriptPath": str(gd / "updates.jsonl")}
            n0 = s.log_text().count("held: the window is not open (stop)")
            g = start(("claude",), json.dumps(note), {"GROK_HOOK_EVENT": "notification", "SIMPLETERM": "1"})
            got = wait_for(lambda: len(asks()) >= 3 and asks(), 20)
            s.check("held bg: grok %s: told again while open" % name,
                    got and same_req(got) and (got[0].get("plain_json") or {}).get("req", {}).get("id") == call,
                    "%d %s" % (len(asks()), s.log_text()[-400:]))
            if still_open:
                still_open(gd)
                k = len(asks())
                s.check("held bg: grok %s: still open after that line" % name, wait_for(lambda: len(asks()) > k, 10),
                        "%d %s" % (len(asks()), s.log_text()[-300:]))
            close(gd)
            ok = ended("held: the window is not open (stop)", n0)
            k = len(asks())
            s.settle("the sender's last sends", but=[g])
            s.check("held bg: grok %s: closed: no more, mark gone" % name, ok and len(asks()) == k,
                    "%d->%d %s %s" % (k, len(asks()), marks(), s.log_text()[-300:]))
            stop(g)

        grok_case("question", "ask_user_question", "call_2_0", "elicitation_dialog", "User question requested",
                  {"type": "assistant", "content": "", "tool_calls": [{"id": "call_2_0", "name": "ask_user_question", "arguments": "{}"}]},
                  [{"type": "permission_resolved", "tool_name": "ask_user_question", "decision": "allow", "wait_ms": 3},
                   {"type": "phase_changed", "phase": "tool_execution"}],
                  lambda gd: jl(gd / "chat_history.jsonl", [{"type": "tool_result", "tool_call_id": "call_2_0", "content": "answered"}]),
                  ts="10:20:01")
        grok_case("permission window", "run_terminal_command", "call_3_0", "permission_prompt", "Tool permission requested",
                  {"type": "assistant", "content": "", "tool_calls": [{"id": "call_3_0", "name": "run_terminal_command", "arguments": "{}"}]},
                  [{"type": "tool_started", "tool_name": "run_terminal_command"}, {"type": "phase_changed", "phase": "permission_prompt"},
                   {"type": "permission_requested", "tool_name": "run_terminal_command"}],
                  # an allow: the call stays without a result while the tool runs; events.jsonl says it closed
                  lambda gd: jl(gd / "events.jsonl", [{"type": "permission_resolved", "tool_name": "run_terminal_command", "decision": "allow",
                                                       "wait_ms": 9000}, {"type": "phase_changed", "phase": "tool_execution"}]),
                  ts="10:20:02")
        grok_case("plan review", "exit_plan_mode", "call_4_0", "permission_prompt", "Plan approval requested: plan.md",
                  {"type": "assistant", "content": "", "tool_calls": [{"id": "call_4_0", "name": "exit_plan_mode", "arguments": "{}"}]},
                  # the review box opens with the permission already resolved (allow, 0 ms)
                  [{"type": "permission_requested", "tool_name": "exit_plan_mode"},
                   {"type": "permission_resolved", "tool_name": "exit_plan_mode", "decision": "allow", "wait_ms": 0},
                   {"type": "phase_changed", "phase": "tool_execution"}],
                  lambda gd: jl(gd / "chat_history.jsonl", [{"type": "tool_result", "tool_call_id": "call_4_0",
                                                             "content": "The user chose to abandon the plan entirely"}]),
                  ts="10:20:03")

        # --- Claude Code: an undecidable question from PreToolUse (ask_delay 0 here), its session file says
        # waiting / input needed; the user answers at the terminal (PostToolUse of that call).
        ask_in = {"session_id": "held-q", "transcript_path": "/home/u/.claude/projects/x/t.jsonl", "cwd": "/home/u/api",
                  "hook_event_name": "PreToolUse", "tool_name": "AskUserQuestion", "tool_use_id": "toolu_q1",
                  "tool_input": {"questions": [{"question": "Which tea?", "header": "Tea", "multiSelect": False,
                                                "options": [{"label": "Green", "description": "g"}, {"label": "Black", "description": "b"}]}]}}

        def claude_file(pid, session, status="waiting", wf="input needed", at=None):
            at = at if at is not None else int(time.time() * 1000)
            tmp = sessions / ("%d.json.tmp" % pid)
            tmp.write_text(json.dumps({"pid": pid, "sessionId": session, "cwd": "/home/u/api", "status": status, "waitingFor": wf,
                                       "statusUpdatedAt": at, "updatedAt": at}))
            os.replace(tmp, sessions / ("%d.json" % pid))

        setup()
        n0 = s.log_text().count("held: answered at the terminal (stop)")
        # The window is written right after PreToolUse returns: write it once the hook ran (its first send is
        # in; start() returns when the hook was started, possibly before it read its start time).
        c = start(("claude",), json.dumps(ask_in))
        wait_for(lambda: asks(), 10)
        claude_file(c.pid, "held-q")
        got = wait_for(lambda: len(asks()) >= 3 and asks(), 20)
        s.check("held bg: claude PreToolUse question: told again while the session file waits on it",
                got and same_req(got), "%d %s" % (len(asks()), s.log_text()[-400:]))
        post = dict(ask_in, hook_event_name="PostToolUse", tool_response={"answers": {"Which tea?": "Green"}})
        s.run("claude", json.dumps(post))
        s.check("held bg: claude: answered at the terminal (PostToolUse): stops, mark gone",
                ended("held: answered at the terminal (stop)", n0), "%s %s" % (marks(), s.log_text()[-300:]))
        stop(c)

        # Claude Code MCP form (Notification elicitation_dialog): the file was written before the hook (6.4 s on 2.1.322).
        form = {"session_id": "held-f", "transcript_path": "/home/u/.claude/projects/x/t.jsonl", "cwd": "/home/u/api",
                "hook_event_name": "Notification", "notification_type": "elicitation_dialog", "message": "MCP server spike requests your input"}
        setup()
        n0 = s.log_text().count("held: the window is not open (stop)")
        at_f = int(time.time() * 1000) - 6400
        f = start(("claude",), json.dumps(form), before=lambda pid: claude_file(pid, "held-f", at=at_f))
        got = wait_for(lambda: len(asks()) >= 3 and asks(), 20)
        s.check("held bg: claude MCP form: told again", got and same_req(got), "%d %s" % (len(asks()), s.log_text()[-400:]))
        claude_file(f.pid, "held-f", status="idle", wf=None)
        s.check("held bg: claude MCP form: answered (idle): stops", ended("held: the window is not open (stop)", n0),
                "%s %s" % (marks(), s.log_text()[-300:]))
        stop(f)

        # Claude Code's URL form (Notification elicitation_url_dialog, #450 8.4): the session file says waiting /
        # input needed about 6 s before the notification [measured 2.1.322], as the MCP form: told again until it closes.
        setup()
        n0 = s.log_text().count("held: the window is not open (stop)")
        at_u = int(time.time() * 1000) - 6000
        u = start(("claude",), json.dumps(dict(form, session_id="held-u", notification_type="elicitation_url_dialog",
                                               message="Sign in to continue")),
                  before=lambda pid: claude_file(pid, "held-u", at=at_u))
        got = wait_for(lambda: len(asks()) >= 3 and asks(), 20)
        s.check("held bg: claude URL form: told again", got and same_req(got), "%d %s" % (len(asks()), s.log_text()[-400:]))
        claude_file(u.pid, "held-u", status="idle", wf=None)
        s.check("held bg: claude URL form: answered (idle): stops", ended("held: the window is not open (stop)", n0),
                "%s %s" % (marks(), s.log_text()[-300:]))
        stop(u)

        # Plain suppressed (not held): the sender ends at once, nothing again.
        tr3 = s.tmp / "agy3" / "transcript_full.jsonl"
        shutil.rmtree(tr3.parent, ignore_errors=True)
        jl(tr3, [{"step_index": 1, "type": "PLANNER_RESPONSE", "tool_calls": [{"name": "ask_question"}]}])
        # The sender's own rules, with an Antigravity question (sh) or, as the PowerShell hook has no Antigravity
        # part, a Claude Code MCP form whose session file waits on it.
        q3 = {"conversationId": "conv-h3", "workspacePaths": ["/w/a"], "transcriptPath": str(tr3), "stepIdx": 2,
              "toolCall": {"name": "ask_question", "args": {"questions": [{"question": "Which color?", "options": ["Red", "Green"],
                                                                            "is_multi_select": False}]}}}

        def gen(conv, env=None):
            if s.kind != "ps1":
                return start(("agy", "PreToolUse"), json.dumps(dict(q3, conversationId=conv)), env)
            sid = "held-" + conv
            at_g = int(time.time() * 1000) - 6000
            return start(("claude",), json.dumps(dict(form, session_id=sid)), env, before=lambda pid: claude_file(pid, sid, at=at_g))
        setup(push="suppressed")
        a = gen("conv-h3")
        wait_for(lambda: asks(), 10)
        # (A sender that stayed would tell again every second, HELD_EVERY=1, and keep this from settling.)
        s.settle("the hook's send", but=[a])
        s.check("held bg: plain suppressed: not told again, no mark", len(asks()) == 1 and not marks(), "%d %s" % (len(asks()), marks()))
        stop(a)

        # The limit (test value 3 s from the hook start).
        setup()
        n0 = s.log_text().count("held: limit (stop)")
        a = gen("conv-h4", {"SIMPLETERM_HOOK_TEST_HELD_CAP": "3"})
        s.check("held bg: the limit: stops, mark gone", ended("held: limit (stop)", n0), "%s %s" % (marks(), s.log_text()[-300:]))
        stop(a)

        # Eight live senders of the user: a ninth does not stay.
        setup()
        run.mkdir(parents=True, exist_ok=True)
        for i in range(8):
            (run / ("held.other.k%d" % i)).write_text("%d\n" % os.getpid())
        n0 = s.log_text().count("held: too many senders (stop)")
        a = gen("conv-h5")
        # (The ninth logs, then takes its mark away: wait for both.)
        s.check("held bg: eight senders alive: a ninth stops",
                wait_for(lambda: s.log_text().count("held: too many senders (stop)") > n0 and len(marks()) == 8, 15),
                "%s %s" % (marks(), s.log_text()[-300:]))
        for p in run.glob("held.other.*"):
            p.unlink()
        stop(a)

        # Test values are read only with SIMPLETERM_HOOK_TEST=1: without it a round comes every 5 s.
        setup()
        a = gen("conv-h6", {"SIMPLETERM_HOOK_TEST": ""})
        got = wait_for(lambda: len(asks()) >= 2 and asks(), 15)
        gap = (got[1]["received"] - got[0]["received"]) if got else 0
        s.check("held bg: without SIMPLETERM_HOOK_TEST the test interval is ignored (5 s)", got and gap >= 4, "%.1f s" % gap)
        stop(a)
        s.check("held bg: no mark left", wait_for(lambda: not marks(), 10), str(marks()))
    finally:
        for ag in agents:
            if ag.poll() is None:
                ag.kill()
        tun.terminate()
        tun.wait(5)


def t_v2_not_sent(s):
    """SimpleTerm spec/request-wait-link#no-send: requests that may never show a prompt are not sent. Copilot permissionRequest: nothing
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
    # agy asks before a read only outside the workspace: a read inside it does not wait, even with agy_wait.
    for name, paths, path, sent in (("inside", ["/w/a"], "/w/a/README.md", False), ("in the second folder", ["/w/a", "/w/b/"], "/w/b/src/x.ts", False),
                                    ("outside", ["/w/a"], "/etc/hosts", True), ("a name that only starts the same", ["/w/a"], "/w/ab/x", True),
                                    ("climbing out with ..", ["/w/a"], "/w/a/../../etc/passwd", True)):
        s.setup([(LINK_A, {"fmt": 2, "push": "disabled"})], conf={"agy_wait": 5})
        rd = json.dumps({"conversationId": "c-1", "workspacePaths": paths, "stepIdx": 3, "toolCall": {"name": "read_file", "args": {"Path": path}}})
        rc, out, err, el = s.run("agy", rd, args=("PreToolUse",))
        got = s.records("/v1/ingest")
        s.check("agy read_file %s: %s" % (name, "asked" if sent else "not asked, no wait"),
                out.strip() == '{"decision":"allow"}' and bool(got) == sent and (sent or el < 15), "%s %.2fs %s" % (out, el, str(got)[:150]))
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
                                 ("slower than 5 s", {"decision_delay": 40}, True), ("connection refused", None, True)):
            url = tctl.url if opts is not None else "http://127.0.0.1:%d" % closed
            s.setup([(LINK_T, {"kind": "tunnel", "relay_url": url, "fmt": 2}), (LINK_A, {"fmt": 2, "push": "disabled"})], conf={"agy_wait": 5})
            if opts is not None:
                tctl("/_ctl/reset", {})
                tctl("/_ctl/config", {"links": {LINK_T["id"]: dict(LINK_T, **dict({"unknown_error": "unknown"}, **opts))}})
            rc, out, err, el = s.run("agy", agy, args=("PreToolUse",))
            got = s.records("/v1/ingest")
            s.check("probe %s: %s" % (name, "sent to the relay" if sent else "not sent"), bool(got) == sent and out.strip() == '{"decision":"allow"}',
                    "%s %.2fs" % (out, el))
            # A probe that is not cut at 5 s takes 40 s here.
            s.check("probe %s: within the 5 s" % name, el < 30, "%.2fs" % el)
        # Three tunnels answering in 2.5 s each (well inside the probe's 5 s, also on a loaded machine):
        # probed at once, not one after another (2.5 s apart).
        link_c = {"id": "17" * 16, "secret": "28" * 32, "enc": "39" * 32, "mac": "4a" * 32, "label": "box-c"}
        tun3, tctl3 = s.spawn_mock()
        s.setup([(LINK_T, {"kind": "tunnel", "relay_url": tctl.url, "fmt": 2}), (LINK_B, {"kind": "tunnel", "relay_url": tctl2.url, "fmt": 2}),
                 (link_c, {"kind": "tunnel", "relay_url": tctl3.url, "fmt": 2}), (LINK_A, {"fmt": 2})], conf={"agy_wait": 5})
        for ctl, link in ((tctl, LINK_T), (tctl2, LINK_B), (tctl3, link_c)):
            ctl("/_ctl/reset", {})
            ctl("/_ctl/config", {"links": {link["id"]: dict(link, unknown_error="unknown", decision_delay=2.5)}})
        rc, out, err, el = s.run("agy", agy, args=("PreToolUse",))
        # When each probe reached its tunnel: at once, not 4 s apart (the mocks' clocks, not the run's time).
        got = [r["received"] for ctl in (tctl, tctl2, tctl3) for r in ctl("/_ctl/records")["records"] if r["path"] == "/v1/decision"]
        tun3.terminate()
        tun3.wait(5)
        s.check("probe: tunnels probed at the same time", not s.records("/v1/ingest") and len(got) == 3 and max(got) - min(got) < 2,
                "%.2fs %s" % (el, [round(g - min(got), 2) for g in got] if got else got))
    finally:
        for t in (tun, tun2):
            t.terminate()
            t.wait(5)


def t_v2_state(s):
    """SimpleTerm if/event-v2-turn#state: state events go to tunnels only, when the state changed."""
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
        s.settle("the prompt hook's state send (a second's wait, if one started)")
        st = states()
        s.check("state: running once (same state not sent again)", [x.get("st") for x in st] == ["running"], str(st)[:300])
        s.check("state: not to the relay", not [r for r in s.records("/v1/ingest") if r["body"]["ev"] == "state"])
        # One state a second: a change within the second waits a second, and a newer one replaces it. Each
        # change here comes once the one before was sent, so none replaces another.
        s.run("claude", json.dumps({"session_id": "st1", "cwd": "/w", "hook_event_name": "SubagentStart", "agent_id": "ag1", "agent_type": "explore"}))
        wait_for(lambda: len(states()) >= 2, 8)
        s.run("claude", json.dumps({"session_id": "st1", "cwd": "/w", "hook_event_name": "PostToolUseFailure", "tool_name": "Bash", "is_interrupt": True}))
        wait_for(lambda: len(states()) >= 3, 8)
        s.run("claude", json.dumps({"session_id": "st1", "cwd": "/w", "hook_event_name": "SessionEnd", "reason": "exit"}))
        wait_for(lambda: len(states()) >= 4, 8)
        st = states()
        s.check("state: sub_start with the subagent", [x for x in st if x.get("st") == "sub_start" and x.get("sub") == {"id": "ag1", "type": "explore"}], str(st)[:400])
        s.check("state: idle after an interrupt, turn end interrupt", [x for x in st if x.get("st") == "idle" and (x.get("turn") or {}).get("end") == "interrupt"], str(st)[:400])
        s.check("state: ended", [x for x in st if x.get("st") == "ended"], str(st)[:400])
        s.check("state: no msg in a state event", all("msg" not in x for x in st), str(st)[:300])
        # A subagent's start and stop are events of their own: in the same second as a session state
        # and as each other, none replaces another (SimpleTerm if/event-v2-turn#state).
        tctl("/_ctl/reset", {})
        tctl("/_ctl/config", {"links": {LINK_T["id"]: dict(LINK_T, unknown_error="unknown")}})
        sub = lambda name, ag: json.dumps({"session_id": "st2", "cwd": "/w", "hook_event_name": name, "agent_id": ag, "agent_type": "explore"})
        for inp in (json.dumps({"session_id": "st2", "cwd": "/w", "hook_event_name": "UserPromptSubmit", "prompt": "go"}),
                    sub("SubagentStart", "ag1"), sub("SubagentStart", "ag2"), sub("SubagentStop", "ag1")):
            s.run("claude", inp)
        wait_for(lambda: len(states()) >= 4, 15)
        s.settle("the hooks' state sends")
        got = sorted((x.get("st"), (x.get("sub") or {}).get("id")) for x in states())
        s.check("state: subagent events in the same second are all sent",
                got == sorted([("running", None), ("sub_start", "ag1"), ("sub_start", "ag2"), ("sub_stop", "ag1")]), str(got))
    finally:
        tun.terminate()
        tun.wait(5)


def t_v2_state_turns(s):
    """SimpleTerm if/event-v2-turn#state: a turn's end starts the state comparison over (issue #805). After each kind
    of turn end of the six agents the next turn's `running` reaches the tunnel, and a state that ends a turn goes even
    when it is the last one sent (Antigravity's second pause in one session, with or without its turn start).
    Antigravity's turn starts at the first `PreInvocation` of a turn (`invocationNum` 0); a later one sends nothing.
    One state a second still holds: a state that waits for its second is replaced by a newer state and dropped by a
    turn end that came meanwhile (it must not arrive after it), and `sub_start` / `sub_stop` neither reset nor wait."""
    tun, tctl = s.spawn_mock()
    try:
        s.setup([(LINK_T, {"kind": "tunnel", "relay_url": tctl.url, "fmt": 2})])
        tctl("/_ctl/reset", {})
        tctl("/_ctl/config", {"links": {LINK_T["id"]: dict(LINK_T, unknown_error="unknown")}})

        def evs(sid):
            """The session's tunnel events in the order they came: the state for a `state`, else the event (not
            the `resolved` of a request, nor a `usage` report, which is not a state)."""
            out = []
            for r in tctl("/_ctl/records")["records"]:
                p = r.get("plain_json") or {}
                if r["path"] == "/v1/ingest" and p.get("sid") == sid and r["body"]["ev"] not in ("resolved", "usage"):
                    out.append(p.get("st") if r["body"]["ev"] == "state" else r["body"]["ev"])
            return out

        task = [{"id": "sh_1", "type": "shell", "command": "sleep 30"}]
        cron = [{"id": "c1", "schedule": "*/5 * * * *", "recurring": True, "prompt": "check the deploy"}]
        ask = "Should I use A or B?"

        # --- the steps: (agent, input, env, argv, the event it sends or None)
        def cc(sid, name, want, **kw):
            return ("claude", cc_event(sid, name, **kw), {}, (), want)

        def cc_stop(sid, want, last="All tests pass.", tasks=(), crons=()):
            return cc(sid, "Stop", want, stop_hook_active=False, last_assistant_message=last, background_tasks=list(tasks),
                      session_crons=list(crons))

        def cc_start(sid, **kw):
            return cc(sid, "UserPromptSubmit", "running", **dict({"prompt": "go on"}, **kw))

        def cx(sid, name, want, **kw):
            return ("codex", json.dumps(dict({"session_id": sid, "cwd": "/w/repo", "hook_event_name": name}, **kw)), {}, (), want)

        tid = "11111111-2222-4333-8444-555555555555"

        def cx_start(sid):
            return cx(sid, "UserPromptSubmit", "running", prompt="go on", turn_id=tid)

        def gk(sid, n, event, want, **kw):
            inp, env = grok_input(event, sessionId=sid, session_id=sid, promptId="%s-p%d" % (sid, n),
                                  timestamp="2026-11-24T10:00:%02d.000Z" % (n * 2 + (event != "UserPromptSubmit")), **kw)
            return ("claude", inp, env, (), want)

        def gk_stop(sid, n, want, last="Done.", tasks=()):
            return gk(sid, n, "Stop", want, reason="end_turn", stopHookActive=False, lastAssistantMessage=last,
                      backgroundTasks=list(tasks))

        def oc(sid, name, want, **kw):
            return ("opencode", json.dumps(dict({"hook_event_name": name, "session_id": sid, "cwd": "/w/o", "oc": "2"}, **kw)), {}, (), want)

        cop_env = {"COPILOT_CLI": "1", "COPILOT_CLI_BINARY_VERSION": "1.0.109"}

        def cop(sid, hook, want, **kw):
            return ("copilot", json.dumps(dict({"sessionId": sid, "timestamp": 1793635914148, "cwd": "/w/proj"}, **kw)), cop_env, (hook,), want)

        def agy_pre(sid, n=0):
            j = {"conversationId": sid, "workspacePaths": ["/w/agyproj"], "transcriptPath": "/x/t.jsonl", "modelName": "m",
                 "artifactDirectoryPath": "/x/art", "invocationNum": n, "initialNumSteps": 1 + 2 * n, "lastUserInput": "go on"}
            return ("agy", json.dumps(j), {}, ("PreInvocation",), "running" if n == 0 else None)

        def agy_end(sid, want, **kw):
            return ("agy", agy_stop(conversationId=sid, **kw), {}, ("Stop",), want)

        rollout = write(s.tmp / "rollout-plan.jsonl", json.dumps({"type": "event_msg", "payload": {
            "type": "item_completed", "turn_id": tid, "item": {"type": "Plan", "id": "p1", "text": "1. Add the test"}}},
            separators=(",", ":")) + "\n")
        plan_write = agy_input("write_file", {"Path": "/w/agyproj/plan.md", "Content": "1. x", "ArtifactMetadata": {"RequestFeedback": True}})

        def turn(start, end, sid):
            """start, end, start: the end's event, then the next turn's running."""
            return [start(sid), end(sid), start(sid)]

        claude = [
            ("done", lambda sid: turn(cc_start, lambda x: cc_stop(x, "done"), sid)),
            ("done asking", lambda sid: turn(cc_start, lambda x: cc_stop(x, "done", last=ask), sid)),
            ("question with work left", lambda sid: turn(cc_start, lambda x: cc_stop(x, "question", last=ask, tasks=task), sid)),
            ("background", lambda sid: turn(cc_start, lambda x: cc_stop(x, "background", last="Started it.", tasks=task), sid)),
            ("error", lambda sid: turn(cc_start, lambda x: cc(x, "StopFailure", "error", error="server_error", last_assistant_message="x"), sid)),
            ("auth", lambda sid: turn(cc_start, lambda x: cc(x, "StopFailure", "auth", error="authentication_failed", last_assistant_message="x"), sid)),
            ("Esc", lambda sid: turn(cc_start, lambda x: cc(x, "PostToolUseFailure", "idle", tool_name="Bash", is_interrupt=True), sid)),
            ("scheduled", lambda sid: [cc_start(sid, prompt="check the deploy", source="schedule_wakeup"),
                                       cc_stop(sid, "scheduled", last="Still deploying.", crons=cron), cc_start(sid)]),
            ("scheduled, the last", lambda sid: [cc_start(sid, prompt="check the deploy", source="schedule_wakeup"),
                                                 cc_stop(sid, "done", last="Deployed."), cc_start(sid)]),
            # A subagent's start and stop go each time and leave the comparison alone.
            ("done with a subagent around it", lambda sid: [
                cc_start(sid), cc(sid, "SubagentStart", "sub_start", agent_id="ag1", agent_type="explore"), cc_stop(sid, "done"),
                cc(sid, "SubagentStop", "sub_stop", agent_id="ag1", agent_type="explore"), cc_start(sid)]),
        ]
        codex = [
            ("done", lambda sid: turn(cx_start, lambda x: cx(x, "Stop", "done", last_assistant_message="Done.", turn_id=tid), sid)),
            ("plan", lambda sid: turn(cx_start, lambda x: cx(x, "Stop", "question", last_assistant_message="Plan.", turn_id=tid,
                                                              transcript_path=str(rollout)), sid)),
        ]
        grok = [
            ("done", lambda sid: [gk(sid, 1, "UserPromptSubmit", "running", prompt="go"), gk_stop(sid, 1, "done"),
                                  gk(sid, 2, "UserPromptSubmit", "running", prompt="go")]),
            ("done asking", lambda sid: [gk(sid, 1, "UserPromptSubmit", "running", prompt="go"), gk_stop(sid, 1, "done", last=ask),
                                         gk(sid, 2, "UserPromptSubmit", "running", prompt="go")]),
            ("question with work left", lambda sid: [gk(sid, 1, "UserPromptSubmit", "running", prompt="go"),
                                                     gk_stop(sid, 1, "question", last=ask, tasks=task),
                                                     gk(sid, 2, "UserPromptSubmit", "running", prompt="go")]),
            ("background", lambda sid: [gk(sid, 1, "UserPromptSubmit", "running", prompt="go"), gk_stop(sid, 1, "background", tasks=task),
                                        gk(sid, 2, "UserPromptSubmit", "running", prompt="go")]),
            ("error", lambda sid: [gk(sid, 1, "UserPromptSubmit", "running", prompt="go"),
                                   gk(sid, 1, "StopFailure", "error", error="server_error", lastAssistantMessage="x"),
                                   gk(sid, 2, "UserPromptSubmit", "running", prompt="go")]),
            ("auth", lambda sid: [gk(sid, 1, "UserPromptSubmit", "running", prompt="go"),
                                  gk(sid, 1, "StopFailure", "auth", error="authentication_failed", lastAssistantMessage="x"),
                                  gk(sid, 2, "UserPromptSubmit", "running", prompt="go")]),
            ("Ctrl+C", lambda sid: [gk(sid, 1, "UserPromptSubmit", "running", prompt="go"),
                                    gk(sid, 1, "StopCancelled", "idle", reason="user_interrupt", cancelTrigger="ctrl_c"),
                                    gk(sid, 2, "UserPromptSubmit", "running", prompt="go")]),
        ]
        opencode = [
            ("done", lambda sid: turn(lambda x: oc(x, "UserPromptSubmit", "running"), lambda x: oc(x, "Stop", "done", last_assistant_message="t"), sid)),
            ("background", lambda sid: turn(lambda x: oc(x, "UserPromptSubmit", "running"),
                                            lambda x: oc(x, "Stop", "background", last_assistant_message="t", background_tasks=task), sid)),
            ("error", lambda sid: turn(lambda x: oc(x, "UserPromptSubmit", "running"), lambda x: oc(x, "StopFailure", "error", error="APIError", message="x"), sid)),
            ("auth", lambda sid: turn(lambda x: oc(x, "UserPromptSubmit", "running"), lambda x: oc(x, "StopFailure", "auth", error="ProviderAuthError", message="x"), sid)),
        ]
        copilot = [
            ("done", lambda sid: turn(lambda x: cop(x, "userPromptSubmitted", "running", prompt="go on"),
                                      lambda x: cop(x, "agentStop", "done", stopReason="end_turn"), sid)),
            ("error", lambda sid: turn(lambda x: cop(x, "userPromptSubmitted", "running", prompt="go on"),
                                       lambda x: cop(x, "errorOccurred", "error", errorContext="model_call", recoverable=False,
                                                     error={"message": "boom", "name": "Error"}), sid)),
        ]
        agy = [
            ("done", lambda sid: turn(agy_pre, lambda x: agy_end(x, "done"), sid)),
            ("background", lambda sid: turn(agy_pre, lambda x: agy_end(x, "background", fullyIdle=False), sid)),
            ("error", lambda sid: turn(agy_pre, lambda x: agy_end(x, "error", error="quota exceeded", terminationReason="ERROR"), sid)),
            ("plan", lambda sid: [agy_pre(sid), ("agy", json.dumps(dict(json.loads(plan_write), conversationId=sid)), {}, ("PostToolUse",), None),
                                  agy_end(sid, "question"), agy_pre(sid)]),
            # The second pause of a session (#805): its report's turn, done, then a new turn that pauses again. A later
            # model call of a turn (invocationNum 1) sends nothing.
            ("second pause", lambda sid: [agy_pre(sid), agy_pre(sid, 1), agy_end(sid, "background", fullyIdle=False), agy_pre(sid),
                                          agy_end(sid, "done"), agy_pre(sid), agy_pre(sid, 1), agy_end(sid, "background", fullyIdle=False)]),
            # Without the turn start (a hooks file of 0.9.0 and older) the second pause still goes.
            ("second pause, no turn start", lambda sid: [agy_end(sid, "background", fullyIdle=False), agy_end(sid, "done"),
                                                         agy_end(sid, "background", fullyIdle=False)]),
        ]
        groups = [("claude", claude), ("codex", codex), ("grok", grok)]
        if s.kind == "sh":
            groups += [("opencode", opencode), ("copilot", copilot), ("agy", agy)]

        def run_group(name, cases):
            for i, (label, make) in enumerate(cases):
                sid = "stt-%s-%d" % (name, i)
                steps = make(sid)
                want = []
                for agent, inp, env, argv, ev in steps:
                    s.run(agent, inp, env, args=argv)
                    if ev:
                        want.append(ev)
                        # One state a second: the next turn's running may wait a second.
                        wait_for(lambda: len(evs(sid)) >= len(want), 6)
                cases[i] = (label, sid, want)

        threads = [threading.Thread(target=run_group, args=g) for g in groups]
        for t in threads:
            t.start()
        for t in threads:
            t.join(300)
        s.settle("the hooks' state sends")
        for name, cases in groups:
            for label, sid, want in cases:
                got = evs(sid)
                s.check("state turns: %s %s -> %s" % (name, label, ", ".join(want)), got == want, "%s: %s" % (sid, got))

        if s.kind != "sh":  # SIMPLETERM_HOOK_TEST_NOW is the sh hook's
            return
        # One second, pinned (SIMPLETERM_HOOK_TEST_NOW): the state of the second turn start waits for its second.
        pin = {"SIMPLETERM_HOOK_TEST": "1", "SIMPLETERM_HOOK_TEST_NOW": str(int(time.time()))}
        # The turn ends before that second is over (Codex sends done at once): the waiting running is dropped, so no
        # running comes after the turn's done.
        sid = "stt-pin-codex"
        for name, extra in (("UserPromptSubmit", {"prompt": "a"}), ("Stop", {"last_assistant_message": "A."}),
                            ("UserPromptSubmit", {"prompt": "b"}), ("Stop", {"last_assistant_message": "B."})):
            s.run("codex", json.dumps(dict({"session_id": sid, "cwd": "/w/repo", "hook_event_name": name, "turn_id": tid}, **extra)), pin)
        wait_for(lambda: len(evs(sid)) >= 3, 6)
        s.settle("the hooks' state sends (a second's wait)")
        got = evs(sid)
        s.check("state turns: a running that waits for its second and a done before it -> no running after the done",
                got == ["running", "done", "done"], str(got))
        # Esc and the next prompt within the second: the next state replaces the waiting idle and goes a second later.
        sid = "stt-pin-claude"
        for step in (cc_start(sid), cc(sid, "PostToolUseFailure", None, tool_name="Bash", is_interrupt=True), cc_start(sid)):
            s.run(step[0], step[1], pin)
        t0 = time.time()
        wait_for(lambda: len(evs(sid)) >= 2, 6)
        el = time.time() - t0
        s.settle("the hooks' state sends (a second's wait)")
        got = evs(sid)
        s.check("state turns: Esc then a prompt within one second -> the running replaces the waiting idle, a second later",
                got == ["running", "running"] and el > 0.3, "%s %.2fs" % (got, el))
    finally:
        tun.terminate()
        tun.wait(5)


def t_sub_sessions(s):
    """SimpleTerm if/event-v2-turn#sub, if/hook-events-background#background (issue #805): a sub-agent's own hooks
    are not a session. Grok Build 1.0.93, Copilot CLI 1.0.115 and Antigravity CLI 1.5.16 run a sub-agent's hooks under
    the sub-agent's own id (the shapes measured, SimpleTerm hist/hook-events#e34). The plugin sends nothing under that
    id (no state, no done, no relay event, no session record), only sub_start and sub_stop under the parent's sid with
    the sub-agent's id (Grok's subagentId too), and sub.parent only for a sub-agent's sub-agent. Antigravity's main Stop
    names the sub-agents its record created that have not gone idle (turn.bg, kind subagent) and sets no
    bg_done_after done for them. Copilot's main agentStop waits for its own hook.start line in events.jsonl before it
    counts the work (the sub-agent's line may come after the hook started)."""
    tun, tctl = s.spawn_mock()
    try:
        s.setup([(LINK_T, {"kind": "tunnel", "relay_url": tctl.url, "fmt": 2}), (LINK_A, {"fmt": 2})], conf={"bg_done_after": 2})
        tctl("/_ctl/reset", {})
        tctl("/_ctl/config", {"links": {LINK_T["id"]: dict(LINK_T, unknown_error="unknown")}})

        def evs(sid):
            """The session's tunnel events in order: (the state for a state, else the event, the sub id)."""
            out = []
            for r in tctl("/_ctl/records")["records"]:
                p = r.get("plain_json") or {}
                if r["path"] == "/v1/ingest" and p.get("sid") == sid and r["body"]["ev"] not in ("resolved", "usage"):
                    out.append((p.get("st") if r["body"]["ev"] == "state" else r["body"]["ev"], (p.get("sub") or {}).get("id")))
            return out

        def tunnel_all(sid):
            return [r for r in tctl("/_ctl/records")["records"] if (r.get("plain_json") or {}).get("sid") == sid]

        def relay(sid):
            return [r for r in s.records("/v1/ingest") if (r.get("plain_json") or {}).get("sid") == sid]

        def state(sid, st):
            got = [r.get("plain_json") or {} for r in tctl("/_ctl/records")["records"] if r["path"] == "/v1/ingest"]
            return [p for p in got if p.get("sid") == sid and p.get("st") == st]

        def records(sid):
            d = s.home / ".simpleterm" / "sessions"
            return sorted(str(p.relative_to(d)) for p in d.rglob("*") if p.is_file() and p.name.startswith(sid)) if d.exists() else []

        def play(steps, sid, label):
            """steps: (agent, input, env, argv, the parent's event it sends or None); waits for each."""
            want, n0 = [], len(evs(sid))
            for agent, inp, env, argv, ev in steps:
                s.run(agent, inp, env, args=argv)
                if ev:
                    want.append(ev)
                    wait_for(lambda: len(evs(sid)) >= n0 + len(want), 6)
            s.settle("%s: the hooks' sends" % label)
            return want

        # --- Grok Build 1.0.93: spawn_subagent with background (both hooks, sh and Windows).
        P, S = "gsub-main", "gsub-agent-1"
        n = [0]

        def gk(sid, event, snake, **kw):
            n[0] += 1
            j = {"hookEventName": snake, "sessionId": sid, "cwd": "/w/grokproj", "workspaceRoot": "/w/grokproj",
                 "timestamp": "2026-11-24T14:36:%02d.000000+00:00" % n[0], "permissionMode": "bypassPermissions",
                 "hook_event_name": event, "session_id": sid}
            j.update(kw)
            return json.dumps(j), {"GROK_HOOK_EVENT": snake, "SIMPLETERM": "1"}

        def g(sid, event, snake, ev, **kw):
            inp, env = gk(sid, event, snake, **kw)
            return ("claude", inp, env, (), ev)

        task = [{"id": S, "type": "subagent", "status": "running", "description": "bg measure", "agentType": "general-purpose"}]
        grok = [
            g(P, "UserPromptSubmit", "user_prompt_submit", ("running", None), promptId="gp-1", prompt="MAINTASK start one"),
            g(P, "SubagentStart", "subagent_start", ("sub_start", S), subagentId=S, subagentType="general-purpose",
              description="bg measure"),
            g(S, "UserPromptSubmit", "user_prompt_submit", None, promptId="gp-sub", prompt="SUBTASK count",
              subagentType="general-purpose"),
            g(P, "Stop", "stop", ("background", None), promptId="gp-1", reason="end_turn", stopHookActive=False,
              lastAssistantMessage="Started the sub-agent.", backgroundTasks=task, sessionCrons=[]),
            g(S, "SubagentStop", "subagent_stop", ("sub_stop", S), promptId="gp-sub", phase="gate", subagentId=S,
              subagentType="general-purpose", stopHookActive=False, lastAssistantMessage="SUB-DONE"),
            g(S, "SessionEnd", "session_end", None, reason="shutdown", subagentType="general-purpose"),
            g(P, "UserPromptSubmit", "user_prompt_submit", ("running", None), promptId="subagent-completed-" + S,
              prompt="<system-reminder>\nWhile you were idle, 1 background subagent completed"),
            g(P, "Stop", "stop", ("done", None), promptId="subagent-completed-" + S, reason="end_turn",
              stopHookActive=False, lastAssistantMessage="Report: the sub-agent finished.", backgroundTasks=[], sessionCrons=[]),
        ]
        want = play(grok, P, "grok")
        s.check("sub sessions: grok, the parent's events", evs(P) == want, str(evs(P)))
        st = state(P, "sub_start")
        s.check("sub sessions: grok sub_start names the sub-agent (subagentId), no parent",
                st and st[0].get("sub") == {"id": S, "type": "general-purpose"}, str(st)[:300])
        s.check("sub sessions: grok, nothing under the sub-agent's id", not tunnel_all(S) and not relay(S),
                str(tunnel_all(S) + relay(S))[:300])
        s.check("sub sessions: grok, one relay done of the parent", [r["body"]["ev"] for r in relay(P)] == ["done"],
                str([r["body"]["ev"] for r in relay(P)]))
        s.check("sub sessions: grok, no session record of the sub-agent", not records(S), str(records(S)))
        if s.kind != "sh":
            return

        # --- Copilot CLI 1.0.115: task with mode background.
        P, S = "csub-main", "csub-agent-1"
        tx = s.tmp / "csub" / "events.jsonl"
        lines = []
        env = {"COPILOT_CLI": "1", "COPILOT_CLI_BINARY_VERSION": "1.0.115"}
        ts = [1795531161898]

        def ev(t, data, agent=None):
            rec = dict({"type": t, "data": data}, **({"agentId": agent} if agent else {}))
            rec.update({"id": "e7895550-3728-4d1e-9d27-15d2f75c72e8", "timestamp": "2026-11-24T14:39:22.423Z"})
            lines.append(json.dumps(rec, separators=(",", ":")))
            write(tx, "\n".join(lines) + "\n")

        def hook_start(hook, inp):
            ev("hook.start", {"hookInvocationId": "402928cf-3e4d-4b50-800c-503d06c66f54", "hookType": hook, "input": inp})

        def cop(hook, want, sid=None, write_start=True, **kw):
            sid = sid or P
            ts[0] += 37
            inp = dict({"sessionId": sid, "timestamp": ts[0], "cwd": "/w/proj"}, **kw)
            if write_start:
                hook_start(hook, inp)
            return ("copilot", json.dumps(inp), env, (hook,), want)

        sub = {"agentId": S, "agentType": "general-purpose", "parentAgentId": P}
        steps = [cop("userPromptSubmitted", ("running", None), prompt="MAINTASK start one")]
        want = play(steps, P, "copilot prompt")
        ev("user.message", {"content": "MAINTASK start one"})
        ev("subagent.started", {"toolCallId": "call_1_0", "agentName": "general-purpose", "agentDisplayName": "bgmeasure",
                                "agentDescription": "bg measure", "agentType": "general-purpose", "executionMode": "background"}, S)
        ev("assistant.message", {"content": "Started the sub-agent."})
        ev("assistant.turn_end", {"turnId": "0"})
        steps = [
            cop("agentStop", ("background", None), transcriptPath=str(tx), stopReason="end_turn", stop_hook_active=False),
            cop("subagentStart", ("sub_start", S), transcriptPath=str(tx), agentName="general-purpose", **sub),
            cop("userPromptSubmitted", None, sid=S, prompt="SUBTASK count", **sub),
            cop("agentStop", ("sub_stop", S), sid=S, transcriptPath=str(tx), stopReason="end_turn", stop_hook_active=False, **sub),
            cop("subagentStop", ("sub_stop", S), transcriptPath=str(tx), agentName="general-purpose", response="SUB-DONE",
                stopReason="end_turn", stop_hook_active=False, **sub),
        ]
        want += play(steps, P, "copilot sub-agent")
        ev("subagent.completed", {"toolCallId": "call_1_0", "agentName": "general-purpose", "agentDisplayName": "bgmeasure"}, S)
        note = "<system_notification>\nAgent \"bgmeasure\" (general-purpose) has finished processing and is now idle.\n</system_notification>"
        ev("hook.end", {"hookInvocationId": "6c1f74d3-8d68-4dd0-924f-901e1815a31f", "hookType": "userPromptSubmitted", "success": True})
        ev("system.notification", {"content": note, "kind": {"type": "agent_idle", "agentId": S, "agentType": "general-purpose",
                                                            "displayName": "bgmeasure", "description": "bg measure"}})
        steps = [cop("userPromptSubmitted", ("running", None), prompt=note)]
        want += play(steps, P, "copilot report prompt")
        ev("assistant.message", {"content": "Report: the sub-agent finished."})
        steps = [cop("agentStop", ("done", None), transcriptPath=str(tx), stopReason="end_turn", stop_hook_active=False)]
        want += play(steps, P, "copilot report")
        s.check("sub sessions: copilot, the parent's events", evs(P) == want, str(evs(P)))
        st = state(P, "sub_start")
        s.check("sub sessions: copilot sub_start has no parent (the main session's sub-agent)",
                st and st[0].get("sub") == {"id": S, "type": "general-purpose"}, str(st)[:300])
        s.check("sub sessions: copilot, nothing under the sub-agent's id", not tunnel_all(S) and not relay(S),
                str(tunnel_all(S) + relay(S))[:300])
        s.check("sub sessions: copilot, one relay done of the parent", [r["body"]["ev"] for r in relay(P)] == ["done"],
                str([r["body"]["ev"] for r in relay(P)]))
        s.check("sub sessions: copilot, no session record of the sub-agent", not records(S), str(records(S)))

        # Copilot writes events.jsonl in batches: the sub-agent's line may come after the agentStop hook started
        # (1.0.115, 3 runs of 3), then the hook's own hook.start line. The hook waits for its line.
        P = "crace-main"
        tx = s.tmp / "crace" / "events.jsonl"
        lines = []
        play([cop("userPromptSubmitted", ("running", None), prompt="MAINTASK start one")], P, "copilot race prompt")
        ev("user.message", {"content": "MAINTASK start one"})
        ts[0] += 37
        stop = {"sessionId": P, "timestamp": ts[0], "cwd": "/w/proj", "transcriptPath": str(tx), "stopReason": "end_turn",
                "stop_hook_active": False}
        p = s.start("copilot", json.dumps(stop), env, args=("agentStop",))
        time.sleep(0.6)
        ev("subagent.started", {"toolCallId": "call_2_0", "agentName": "general-purpose", "agentDisplayName": "late",
                                "agentDescription": "late line", "agentType": "general-purpose", "executionMode": "background"}, "csub-agent-2")
        ev("assistant.message", {"content": "Started it."})
        ev("assistant.turn_end", {"turnId": "0"})
        hook_start("agentStop", stop)
        s.finish(p)
        wait_for(lambda: len(evs(P)) >= 2, 6)
        s.settle("copilot race: the hook's sends")
        s.check("sub sessions: copilot, a sub-agent line written after the hook started still counts (background, no done)",
                evs(P) == [("running", None), ("background", None)] and not relay(P), str(evs(P)) + str(relay(P))[:200])

        # --- Antigravity CLI 1.5.16: invoke_subagent (always in the background, a conversation of its own).
        P, S = "f41d4660-7c54-484e-8d2b-51aa2eac1f33", "3013f634-dd4f-45cc-9e16-998a5b47e2b4"
        tp = s.tmp / "asub" / P / "transcript_full.jsonl"
        tsub = s.tmp / "asub" / S / "transcript_full.jsonl"

        def step(f, i, t, **kw):
            rec = dict({"step_index": i, "source": "MODEL", "type": t, "status": "DONE", "created_at": "2026-11-24T14:54:13Z"}, **kw)
            with open(f, "a") as fh:
                fh.write(json.dumps(rec, separators=(",", ":")) + "\n")

        def sysmsg(sender, content):
            return ("The following is a <SYSTEM_MESSAGE> not actually sent by the user. It is provided by the system as important "
                    "information to pay attention to.\n\n<SYSTEM_MESSAGE>\n[Message] timestamp=2026-11-24T14:54:13Z sender=%s "
                    "priority=MESSAGE_PRIORITY_HIGH content=%s\n</SYSTEM_MESSAGE>" % (sender, content))

        tp.parent.mkdir(parents=True, exist_ok=True)
        tsub.parent.mkdir(parents=True, exist_ok=True)
        step(tp, 0, "USER_INPUT", source="USER_EXPLICIT", content="<USER_REQUEST>\nMAINTASK start one\n</USER_REQUEST>")
        step(tp, 1, "PLANNER_RESPONSE", tool_calls=[{"name": "invoke_subagent", "args": {
            "Prompt": "SUBTASK count {to} \"three\"", "Role": "Measure Helper", "TypeName": "self"}}])
        step(tp, 2, "GENERIC", content="Created At: 2026-11-24T23:54:13+09:00\nCreated the following subagent:\n{\n  \"conversationId\":  "
             "\"%s\",\n  \"logAbsoluteUri\":  \"file:///x/%s/.system_generated/logs/transcript.jsonl\"\n}\nThe subagent will send "
             "you a message when it has completed its task or requires guidance." % (S, S))
        step(tp, 3, "PLANNER_RESPONSE", content="Started the sub-agent; I will report when it is done.")
        step(tsub, 0, "SYSTEM_MESSAGE", source="SYSTEM", content=sysmsg(P, "SUBTASK count {to} \"three\""))
        step(tsub, 1, "PLANNER_RESPONSE", content="SUB-DONE counted one two three.")

        def pre(sid, n, steps0, last, path):
            j = {"conversationId": sid, "workspacePaths": ["/w/agyproj"], "transcriptPath": str(path), "modelName": "m",
                 "artifactDirectoryPath": "/x/art", "hookEventName": "PreInvocation", "invocationNum": n,
                 "initialNumSteps": steps0, "lastUserInput": last}
            return json.dumps(j)

        def stop_(sid, idle, last, path):
            return agy_stop(conversationId=sid, transcriptPath=str(path), executionNum=0, fullyIdle=idle, lastUserInput=last,
                            continuationActive=False, error="", hookEventName="Stop")

        t0 = time.time()
        steps = [
            ("agy", pre(P, 0, 1, "MAINTASK start one", tp), {}, ("PreInvocation",), ("running", None)),
            ("agy", pre(S, 0, 0, "", tsub), {}, ("PreInvocation",), None),
            ("agy", stop_(P, False, "MAINTASK start one", tp), {}, ("Stop",), ("background", None)),
            ("agy", stop_(S, True, "", tsub), {}, ("Stop",), ("sub_stop", S)),
        ]
        want = play(steps, P, "agy sub-agent")
        bg = state(P, "background")
        s.check("sub sessions: agy, the main pause names the sub-agent (turn.bg)",
                bg and [(b.get("kind"), b.get("id"), b.get("name"), b.get("desc")) for b in (bg[0].get("turn") or {}).get("bg", [])]
                == [("subagent", S, "self", "Measure Helper")], str(bg[0].get("turn") if bg else bg)[:400])
        # bg_done_after is 2 s here: a pause for a sub-agent sets no done for it.
        time.sleep(max(0, t0 + 3.5 - time.time()))
        s.settle("agy: a pause's wait, if one was set")
        s.check("sub sessions: agy, no bg_done_after done for a sub-agent", ("done", None) not in evs(P), str(evs(P)))
        step(tp, 4, "SYSTEM_MESSAGE", source="SYSTEM",
             content=sysmsg("system", "Subagent %s has gone idle. This was the subagent's most recent response: SUB-DONE" % S))
        steps = [
            ("agy", pre(P, 0, 4, "MAINTASK start one", tp), {}, ("PreInvocation",), ("running", None)),
            ("agy", stop_(P, True, "MAINTASK start one", tp), {}, ("Stop",), ("done", None)),
        ]
        step(tp, 5, "PLANNER_RESPONSE", content="Report: the sub-agent finished.")
        want += play(steps, P, "agy report")
        s.check("sub sessions: agy, the parent's events", evs(P) == want, str(evs(P)))
        d = [r.get("plain_json") or {} for r in relay(P) if r["body"]["ev"] == "done"]
        s.check("sub sessions: agy, the report turn of a sub-agent is a task's (by task)",
                d and (d[0].get("turn") or {}).get("by") == "task", str(d[0].get("turn") if d else d)[:300])
        s.check("sub sessions: agy, nothing under the sub-agent's id", not tunnel_all(S) and not relay(S),
                str(tunnel_all(S) + relay(S))[:300])
        s.check("sub sessions: agy, one relay done of the parent", [r["body"]["ev"] for r in relay(P)] == ["done"],
                str([r["body"]["ev"] for r in relay(P)]))
        s.check("sub sessions: agy, no session record of the sub-agent", not records(S), str(records(S)))
        # A sub-agent's first model call before its record has a line (no transcript yet) is still not a session.
        S2 = "5a0c1d2e-0000-4000-8000-000000000002"
        s.run("agy", pre(S2, 0, 0, "", s.tmp / "asub" / S2 / "none.jsonl"), {}, args=("PreInvocation",))
        s.settle("agy: a sub-agent's first model call")
        s.check("sub sessions: agy, a first call with no steps and no input sends nothing", not tunnel_all(S2) and not relay(S2),
                str(tunnel_all(S2))[:300])
    finally:
        tun.terminate()
        tun.wait(5)


def t_v2_sessions(s):
    """SimpleTerm if/session-record#files: the session records of SimpleTerm sessions."""
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
    if s.kind != "ps1":  # Unix modes; the PowerShell hook runs on Windows (as in t_log)
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
    # Codex 0.165's SessionEnd (SimpleTerm hist/event-v2#r7): session_id, transcript_path, cwd, hook_event_name and reason
    # ("other", the only value) [measured]; nothing printed.
    cd = s.home / ".simpleterm" / "sessions" / "codex"
    cx = "019a5c3e-0000-7000-8000-00000000c0de"
    cev = lambda name, **kw: json.dumps(dict({"session_id": cx, "transcript_path": None, "cwd": "/w/repo", "hook_event_name": name}, **kw))
    s.run("codex", cev("UserPromptSubmit", turn_id="t1", prompt="Fix it", model="gpt-5.5", permission_mode="default"), env)
    rc, out, err, el = s.run("codex", cev("SessionEnd", reason="other"), env)
    s.check("session: codex .ended at SessionEnd, nothing printed",
            (cd / (cx + ".json")).exists() and (cd / (cx + ".ended")).exists() and out.strip() == "" and el < 3, "%r %.2fs" % (out, el))
    # Quit before any prompt: SessionEnd only, no record, no lone mark (the keep counts records).
    nr = "019a5c3e-0000-7000-8000-00000000beef"
    s.run("codex", json.dumps({"session_id": nr, "transcript_path": None, "cwd": "/w/repo", "hook_event_name": "SessionEnd", "reason": "other"}), env)
    s.check("session: no .ended for a session without a record", not (cd / (nr + ".ended")).exists())
    shutil.rmtree(cd, ignore_errors=True)  # the retention case below counts every agent's records
    s.run("claude", json.dumps({"session_id": "s:1", "cwd": "/w", "hook_event_name": "UserPromptSubmit", "prompt": "x"}), env)
    name = hashlib.sha256(b"s:1").hexdigest()[:32]
    s.check("session: an id with ':' -> sha256 name", (sd / (name + ".json")).exists() and json.loads((sd / (name + ".json")).read_text()).get("sid") == "s:1")
    s.run("claude", json.dumps({"session_id": "no-st", "cwd": "/w", "hook_event_name": "UserPromptSubmit", "prompt": "x"}))
    s.check("session: none without SIMPLETERM=1", not (sd / "no-st.json").exists())
    if s.kind == "sh":
        s.run("opencode", json.dumps({"hook_event_name": "UserPromptSubmit", "session_id": "ses_oc2", "cwd": "/w", "oc": "2"}), env)
        s.check("session: none for OpenCode 2.x (D14)", not (s.home / ".simpleterm" / "sessions" / "opencode").exists())
    # Retention (SimpleTerm hist/session-record#d11): 30 days by the later of .beat and the record, 200 at most.
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


def t_v2_mux(s):
    """SimpleTerm if/event-v2#common-fields, if/hook-events-identification#identification: `mux` and `pane` from the hook
    environment (herdr: HERDR_ENV=1 with HERDR_PANE_ID; tmux and screen first, as the nearer multiplexer),
    `pane` right after `mux`, the same on the relay and the tunnel and in the tunnel's states; the session
    record names the multiplexer but never the pane (SimpleTerm if/session-record#fields, hist/session-record#d25)."""
    tun, tctl = s.spawn_mock()
    try:
        s.setup([(LINK_T, {"kind": "tunnel", "relay_url": tctl.url, "fmt": 2}), (LINK_A, {"fmt": 2, "push": "disabled"})],
                conf={"claude_wait": 5})
        tctl("/_ctl/reset", {})
        tctl("/_ctl/config", {"links": {LINK_T["id"]: dict(LINK_T, push="suppressed", unknown_error="unknown")}})
        herdr = {"HERDR_ENV": "1", "HERDR_PANE_ID": "w1:p3"}
        tmux = {"TMUX": "/tmp/tmux-1000/default,4242,0", "TMUX_PANE": "%13"}
        cases = [  # (session, hook environment, mux, pane)
            ("mx-none", {}, None, None),
            ("mx-herdr", herdr, "herdr", "w1:p3"),
            ("mx-herdr-no-env", {"HERDR_PANE_ID": "w1:p3"}, None, None),
            ("mx-herdr-env-0", {"HERDR_ENV": "0", "HERDR_PANE_ID": "w1:p3"}, None, None),
            ("mx-herdr-no-pane", {"HERDR_ENV": "1"}, None, None),
            ("mx-herdr-empty-pane", {"HERDR_ENV": "1", "HERDR_PANE_ID": ""}, None, None),
            ("mx-pane-64", dict(herdr, HERDR_PANE_ID="p" * 64), "herdr", "p" * 64),
            ("mx-pane-65", dict(herdr, HERDR_PANE_ID="p" * 65), "herdr", None),
            ("mx-pane-space", dict(herdr, HERDR_PANE_ID="w1 p3"), "herdr", None),
            ("mx-pane-quote", dict(herdr, HERDR_PANE_ID='w1"p3'), "herdr", None),
            ("mx-pane-non-ascii", dict(herdr, HERDR_PANE_ID="w1:pé"), "herdr", None),
            ("mx-tmux", tmux, "tmux", "%13"),
            ("mx-tmux-no-pane", {"TMUX": tmux["TMUX"]}, "tmux", None),
            ("mx-tmux-in-herdr", dict(herdr, **tmux), "tmux", "%13"),
            ("mx-screen-in-herdr", dict(herdr, STY="4242.pts-0.box"), "screen", None),
        ]
        for sid, env, _, _ in cases:
            s.run("claude", v2_perm(session=sid), env)

        def plains(recs, ev):
            got = {}
            for r in recs:
                if r["path"] == "/v1/ingest" and r.get("body", {}).get("ev") == ev and r.get("plain"):
                    got[(r.get("plain_json") or {}).get("sid")] = r["plain"]
            return got
        wait_for(lambda: len(plains(tctl("/_ctl/records")["records"], "permission")) >= len(cases), 15)
        links = (("relay", plains(s.records(), "permission")), ("tunnel", plains(tctl("/_ctl/records")["records"], "permission")))
        for sid, env, mux, pane in cases:
            for where, got in links:
                raw = got.get(sid)
                j = json.loads(raw) if raw else {}
                ok = raw is not None and j.get("mux") == mux and j.get("pane") == pane
                if pane:
                    ok = ok and ('"mux":"%s","pane":"%s",' % (mux, pane)) in raw
                s.check("mux %s: %s has mux %s, pane %s" % (sid, where, mux, pane), ok, str(raw)[:300])
        # A SimpleTerm session's prompt: the tunnel's state event and the session record.
        sd = s.home / ".simpleterm" / "sessions" / "claude-code"
        tctl("/_ctl/reset", {})
        tctl("/_ctl/config", {"links": {LINK_T["id"]: dict(LINK_T, push="suppressed", unknown_error="unknown")}})
        recs = (("mx-rec-herdr", herdr, "herdr", "w1:p3"), ("mx-rec-tmux", tmux, "tmux", "%13"), ("mx-rec-none", {}, None, None))
        for sid, env, _, _ in recs:
            s.run("claude", json.dumps({"session_id": sid, "cwd": "/w", "hook_event_name": "UserPromptSubmit", "prompt": "go"}), dict(env, SIMPLETERM="1"))
        wait_for(lambda: len(plains(tctl("/_ctl/records")["records"], "state")) >= len(recs), 10)
        states = plains(tctl("/_ctl/records")["records"], "state")
        for sid, env, mux, pane in recs:
            j = json.loads(states[sid]) if sid in states else {}
            s.check("mux %s: state has mux %s, pane %s" % (sid, mux, pane), sid in states and j.get("mux") == mux and j.get("pane") == pane, str(states.get(sid))[:300])
            rec = sd / (sid + ".json")
            r = json.loads(rec.read_text()) if rec.exists() else None
            s.check("mux %s: session record has mux %s and no pane" % (sid, mux), r is not None and r.get("mux") == mux and "pane" not in r, str(r)[:300])
        # The events a hook run sends after its first: the result of a decision (`resolved`) …
        tctl("/_ctl/reset", {})
        tctl("/_ctl/config", {"links": {LINK_T["id"]: dict(LINK_T, unknown_error="unknown",
                                                           decisions=[{"decision": "allow", "after": 0.5, "dext": {"act": "allow"}}])}})
        rc, out, err, el = s.run("claude", v2_perm(session="mx-res-herdr"), herdr)
        wait_for(lambda: plains(tctl("/_ctl/records")["records"], "resolved"), 10)
        raw = plains(tctl("/_ctl/records")["records"], "resolved").get("mx-res-herdr")
        s.check("mux mx-res-herdr: resolved has mux herdr, pane w1:p3",
                behavior(out).get("behavior") == "allow" and raw is not None and '"mux":"herdr","pane":"w1:p3",' in raw, out + str(raw)[:300])
        # … a turn's end (`done`), inside tmux …
        tctl("/_ctl/reset", {})
        s.run("claude", json.dumps({"session_id": "mx-done-tmux", "cwd": "/w", "hook_event_name": "Stop", "stop_hook_active": False,
                                    "last_assistant_message": "Done."}), tmux)
        wait_for(lambda: plains(tctl("/_ctl/records")["records"], "done"), 20)
        raw = plains(tctl("/_ctl/records")["records"], "done").get("mx-done-tmux")
        s.check("mux mx-done-tmux: done has mux tmux, pane %13", raw is not None and '"mux":"tmux","pane":"%13",' in raw, str(raw)[:300])
        if s.kind == "sh":
            # … and a usage report (Copilot's quota file, sh only).
            ev = write(s.tmp / "mxcop" / "events.jsonl", COPILOT_QUOTA_LINE + "\n")
            tctl("/_ctl/reset", {})
            s.run("copilot", json.dumps({"hookName": "agentStop", "sessionId": "mx-use-herdr", "cwd": "/w/c", "transcriptPath": str(ev)}), herdr)
            wait_for(lambda: plains(tctl("/_ctl/records")["records"], "usage"), 20)
            raw = plains(tctl("/_ctl/records")["records"], "usage").get("mx-use-herdr")
            s.check("mux mx-use-herdr: usage has mux herdr, pane w1:p3", raw is not None and '"mux":"herdr","pane":"w1:p3",' in raw, str(raw)[:300])
    finally:
        tun.terminate()
        tun.wait(5)
    if not NODE or s.kind != "sh":
        return
    # Through the OpenCode plugins, which hand the hook their own environment: 1.x is the TUI's
    # (mux herdr and the pane), a 2.x service keeps its first TUI's (mux unknown, no pane).
    d = str(s.tmp)
    ask19 = {"type": "permission.asked", "properties": {"id": "per_m1", "sessionID": "ses_m1", "permission": "bash", "patterns": ["echo a1"],
                                                       "metadata": {"command": "echo a1"}, "always": ["echo *"], "tool": {"messageID": "msg_1", "callID": "c1"}}}
    ask2 = {"id": "e1", "type": "permission.asked", "location": {"directory": d},
            "data": {"id": "per_m2", "sessionID": "ses_m2", "action": "shell", "resources": ["npm run build"], "save": ["npm *"]}}
    for kind, ev, mux, pane in (("v1", ask19, "herdr", "w1:p3"), ("v2", ask2, "unknown", None)):
        s.setup([(LINK_A, {"fmt": 2, "push": "disabled"})])
        node_plugin(s, kind, {"directory": d, "env": herdr, "steps": [{"event": ev}], "wait": 3000})
        p = (wait_for(lambda: ingests(s, "permission"), 10) or [{}])[0].get("plain_json") or {}
        s.check("mux opencode %s plugin inside herdr: mux %s, pane %s" % (kind, mux, pane), p.get("mux") == mux and p.get("pane") == pane, str(p)[:300])


TAB_PS = r'''#!/bin/sh
# Stand-in ps for the tab identity cases: ps.d/<pid>/{ppid,comm,args,env,tty} beside it.
d=${0%/*}/ps.d
E='' fields='' pid='' all=''
while [ $# -gt 0 ]; do
  case $1 in
    -E) E=1 ;;
    -o) shift; fields="$fields $1" ;;
    -p) shift; pid=$1 ;;
    -U) shift; all=1 ;;
  esac
  shift
done
show() {
  out=''
  for f in $fields; do
    case $f in
      pid=) v=$1 ;;
      ppid=) v=$(cat "$d/$1/ppid") ;;
      comm=) v=$(cat "$d/$1/comm") ;;
      tty=) v=$(cat "$d/$1/tty" 2>/dev/null || echo '??') ;;
      args= | command=) v=$(cat "$d/$1/args"); [ -n "$E" ] && [ -f "$d/$1/env" ] && v="$v $(tr '\n' ' ' <"$d/$1/env")" ;;
    esac
    out="$out${out:+ }$v"
  done
  printf '%s\n' "$out"
}
if [ -n "$all" ]; then
  for x in "$d"/*; do show "${x##*/}"; done
  exit 0
fi
[ -d "$d/$pid" ] || exit 1
show "$pid"
'''
TAB_TMUX = r'''#!/bin/sh
# Stand-in tmux: tmux.d/pane.<pane> (the session id) and tmux.d/clients beside it.
d=${0%/*}/tmux.d
case " $* " in
  *" display-message "*)
    t=''
    while [ $# -gt 0 ]; do [ "$1" = -t ] && t=$2; shift; done
    cat "$d/pane.$t" 2>/dev/null || exit 1 ;;
  *" list-clients "*) cat "$d/clients" ;;
  *) exit 1 ;;
esac
'''
MK_A = "st1-0123456789abcdef"
MK_B = "st1-fedcba9876543210"
MK_C = "st1-00000000000000c0"


def merged(*ds):
    r = {}
    for d in ds:
        r.update(d)
    return r


def tab_bin(root, procs=None, tmux=None, linux=None, container=False):
    """Stand-ins of the reads the tab identity makes (SimpleTerm if/hook-tab-identity#other-process), in folder
    root: procs {pid: dict(ppid, comm, args, env {name: value}, tty)} for ps; tmux (pane, its session id,
    [(client pid, session id)]); linux {pid: dict(ppid, comm, args, env, fd {n: target})} as proc/ (proc/1
    exists, so the hook reads /proc as on Linux); container: root/.dockerenv."""
    shutil.rmtree(root, ignore_errors=True)
    root.mkdir(parents=True)
    write(root / "ps", TAB_PS).chmod(0o755)
    write(root / "tmux", TAB_TMUX).chmod(0o755)
    for pid, p in (procs or {}).items():
        d = root / "ps.d" / str(pid)
        write(d / "ppid", str(p.get("ppid", 1)) + "\n")
        write(d / "comm", p["comm"] + "\n")
        write(d / "args", p.get("args", p["comm"]) + "\n")
        if "env" in p:
            write(d / "env", "".join("%s=%s\n" % kv for kv in p["env"].items()))
        if "tty" in p:
            write(d / "tty", p["tty"] + "\n")
    if tmux:
        write(root / "tmux.d" / ("pane." + tmux[0]), tmux[1] + "\n")
        write(root / "tmux.d" / "clients", "".join("%s:%s\n" % c for c in tmux[2]))
    if linux is not None:
        for pid, p in merged({1: {"ppid": 0, "comm": "init"}}, linux).items():
            d = root / "proc" / str(pid)
            write(d / "stat", "%d (%s) S %d 0 0\n" % (pid, p["comm"], p.get("ppid", 1)))
            write(d / "status", "Name:\t%s\nUid:\t%d\t%d\t%d\t%d\n" % ((p["comm"],) + (os.getuid(),) * 4))
            (d / "cmdline").write_bytes(("\0".join(p.get("args", p["comm"]).split(" ")) + "\0").encode())
            (d / "environ").write_bytes("".join("%s=%s\0" % kv for kv in p.get("env", {}).items()).encode())
            (d / "fd").mkdir()
            for n, target in p.get("fd", {}).items():
                os.symlink(target, d / "fd" / str(n))
    if container:
        write(root / "root" / ".dockerenv", "")
    return root


def t_v2_tab(s):
    """SimpleTerm if/hook-tab-identity (#450), phase 1: the tab field (a: the tab's marker, b: not a SimpleTerm
    tab, c: unknown, with why, n and cl), rules 1 to 4 in order, the clients of tmux and herdr with the ancestor
    check of each client (inside another multiplexer, unreadable or gone: n only), Codex's daemon bound to one
    TUI by its arguments, the scope fields msess (herdr named session, tunnel and relay) and msock (tmux socket,
    tunnel only), the session record of a daemon hook (if/session-record#scope), and the relay summary that
    drops msess first when it is over budget (if/event-v2-limits#shrinking). Every process read goes to
    stand-ins (SIMPLETERM_HOOK_TEST_IDBIN)."""
    tun, tctl = s.spawn_mock()
    try:
        s.setup([(LINK_T, {"kind": "tunnel", "relay_url": tctl.url, "fmt": 2}), (LINK_A, {"fmt": 2, "push": "disabled"})],
                conf={"claude_wait": 5, "codex_wait": 0})
        tctl("/_ctl/reset", {})
        tctl("/_ctl/config", {"links": {LINK_T["id"]: dict(LINK_T, push="suppressed", unknown_error="unknown", max_body=65536)}})
        base = s.tmp / "idb"
        sock = "/tmp/tmux-1000/default"
        # The hook's ancestors: 100 the hook's sh, 90 the agent, 80 the login shell (the walk stops there).
        chain = {100: {"ppid": 90, "comm": "sh"}, 90: {"ppid": 80, "comm": "claude", "args": "claude"}, 80: {"ppid": 1, "comm": "-zsh"}}
        cases = []  # (sid, agent, input, env, tab, mux, pane, msess, msock)

        def cx_in(sid, event="PermissionRequest"):
            d = {"session_id": sid, "turn_id": "t1", "transcript_path": "/nonexistent/rollout.jsonl", "cwd": "/w/api",
                 "hook_event_name": event, "model": "gpt-5.5", "permission_mode": "default"}
            if event == "PermissionRequest":
                d.update(tool_name="Bash", tool_input={"command": "echo hi > x"})
            else:
                d.update(prompt="go")
            return json.dumps(d)

        def case(sid, env, tab, mux=None, pane=None, msess=None, msock=None, agent="claude", **bin_kw):
            root = base / sid
            start = bin_kw.pop("start", "100")
            if bin_kw.pop("off", False):
                e = dict(env)
            else:
                tab_bin(root, **bin_kw)
                e = dict(env, SIMPLETERM_HOOK_TEST="1", SIMPLETERM_HOOK_TEST_IDBIN=str(root), SIMPLETERM_HOOK_TEST_IDPPID=start)
            cases.append((sid, agent, cx_in(sid) if agent == "codex" else v2_perm(session=sid), e, tab, mux, pane, msess, msock))

        # Rules 3 and 4 (no multiplexer, no shared host).
        case("tb-a", {"LC_SIMPLETERM_TAB": MK_A, "SIMPLETERM": "1"}, {"st": "a", "tm": MK_A}, procs=chain)
        case("tb-b", {}, {"st": "b"}, procs=chain)
        case("tb-refused", {"SIMPLETERM": "1"}, {"st": "c", "why": "refused"}, procs=chain)
        case("tb-form", {"LC_SIMPLETERM_TAB": "st1-ABC"}, {"st": "c", "why": "form"}, procs=chain)
        case("tb-form-long", {"LC_SIMPLETERM_TAB": MK_A + "0"}, {"st": "c", "why": "form"}, procs=chain)
        case("tb-container", {"SIMPLETERM": "1"}, {"st": "c", "why": "container"}, procs=chain, container=True)
        case("tb-container-mark", {"LC_SIMPLETERM_TAB": MK_A}, {"st": "a", "tm": MK_A}, procs=chain, container=True)
        # Podman: container= in the environment of process 1 (Linux).
        case("tb-container-pid1", {"SIMPLETERM": "1"}, {"st": "c", "why": "container"},
             linux=merged(chain, {1: {"ppid": 0, "comm": "init", "env": {"container": "podman"}}}))
        # No process can be read at all (the suite's default): the hook's own environment still decides.
        case("tb-off", {"LC_SIMPLETERM_TAB": MK_A}, {"st": "a", "tm": MK_A}, off=True)
        # Rule 2, tmux: the clients of the pane's session; a client is a tab unless a server is among its ancestors.
        tm_env = {"TMUX": sock + ",4242,0", "TMUX_PANE": "%3", "LC_SIMPLETERM_TAB": MK_C}
        clients = merged(chain, {201: {"comm": "tmux", "tty": "ttys001", "env": {"LC_SIMPLETERM_TAB": MK_A}},
                                 202: {"comm": "tmux", "tty": "ttys002", "env": {"LC_SIMPLETERM_TAB": MK_B}},
                                 203: {"comm": "tmux", "tty": "ttys003", "env": {"LC_SIMPLETERM_TAB": MK_C}},
                                 # 204 runs in a pane of another tmux: its marker is that server's first tab's
                                 204: {"ppid": 85, "comm": "tmux", "tty": "ttys004", "env": {"LC_SIMPLETERM_TAB": MK_C}},
                                 85: {"ppid": 84, "comm": "-zsh"}, 84: {"ppid": 1, "comm": "/opt/homebrew/bin/tmux", "args": "tmux new -s w"},
                                 205: {"comm": "tmux", "tty": "ttys005", "env": {"PATH": "/usr/bin"}},
                                 206: {"comm": "tmux", "tty": "ttys006", "env": {"LC_SIMPLETERM_TAB": MK_A}},
                                 207: {"ppid": 999, "comm": "tmux", "tty": "ttys007", "env": {"LC_SIMPLETERM_TAB": MK_B}}})
        mux = {"st": "c", "why": "mux"}
        case("tb-tmux", tm_env, dict(mux, n=2, cl=[MK_A, MK_B]), "tmux", "%3", None, sock,
             procs=clients, tmux=("%3", "$1", [(201, "$1"), (202, "$1"), (203, "$2")]))
        case("tb-tmux-nested", tm_env, dict(mux, n=2, cl=[MK_A]), "tmux", "%3", None, sock,
             procs=clients, tmux=("%3", "$1", [(201, "$1"), (204, "$1")]))
        case("tb-tmux-nomark", tm_env, dict(mux, n=2, cl=[MK_A]), "tmux", "%3", None, sock,
             procs=clients, tmux=("%3", "$1", [(201, "$1"), (205, "$1")]))
        case("tb-tmux-same", tm_env, dict(mux, n=2, cl=[MK_A]), "tmux", "%3", None, sock,
             procs=clients, tmux=("%3", "$1", [(201, "$1"), (206, "$1")]))
        # A client whose parent is gone, and a client that is gone itself, count in n only.
        case("tb-tmux-noread", tm_env, dict(mux, n=3, cl=[MK_A]), "tmux", "%3", None, sock,
             procs=clients, tmux=("%3", "$1", [(201, "$1"), (207, "$1"), (299, "$1")]))
        nine = merged(chain, {210 + k: {"comm": "tmux", "tty": "ttys01%d" % k, "env": {"LC_SIMPLETERM_TAB": "st1-00000000000000d%d" % k}} for k in range(9)})
        case("tb-tmux-nine", tm_env, dict(mux, n=9, cl=["st1-00000000000000d%d" % k for k in range(8)]), "tmux", "%3", None, sock,
             procs=nine, tmux=("%3", "$1", [(210 + k, "$1") for k in range(9)]))
        case("tb-tmux-none", tm_env, dict(mux, n=0, cl=[]), "tmux", "%3", None, sock, procs=chain, tmux=("%3", "$1", [(203, "$2")]))
        # The clients cannot be listed (no pane id, tmux fails): no n and no cl.
        case("tb-tmux-nopane", {"TMUX": sock + ",1,0"}, mux, "tmux", None, None, sock, procs=clients, tmux=("%3", "$1", [(201, "$1")]))
        case("tb-tmux-fail", tm_env, mux, "tmux", "%3", None, sock, procs=clients)
        case("tb-tmux-quote", {"TMUX": '/tmp/a"b,1,0', "TMUX_PANE": "%3"}, mux, "tmux", "%3", procs=chain)
        case("tb-tmux-long", {"TMUX": "/" + "s" * 256 + ",1,0", "TMUX_PANE": "%3"}, mux, "tmux", "%3", procs=chain)
        # A tmux server among the ancestors without TMUX is no multiplexer (rule 2): the marker decides.
        case("tb-tmux-novar", {"LC_SIMPLETERM_TAB": MK_A}, {"st": "a", "tm": MK_A},
             procs=merged(chain, {80: {"ppid": 84, "comm": "-zsh"}, 84: {"ppid": 1, "comm": "/opt/homebrew/bin/tmux", "args": "tmux new -s w"}}))
        # The same on Linux (/proc): the server is "tmux: server".
        lx = {100: {"ppid": 90, "comm": "sh"}, 90: {"ppid": 80, "comm": "claude"}, 80: {"ppid": 84, "comm": "bash"},
              84: {"ppid": 1, "comm": "tmux: server", "args": "tmux new -s w"},
              201: {"ppid": 1, "comm": "tmux: client", "args": "tmux attach", "env": {"LC_SIMPLETERM_TAB": MK_A, "HOME": "/home/u"}, "fd": {0: "/dev/pts/3"}},
              204: {"ppid": 85, "comm": "tmux: client", "args": "tmux attach", "env": {"LC_SIMPLETERM_TAB": MK_B}, "fd": {0: "/dev/pts/4"}},
              85: {"ppid": 84, "comm": "bash"}}
        case("tb-tmux-linux", tm_env, dict(mux, n=2, cl=[MK_A]), "tmux", "%3", None, sock, linux=lx, tmux=("%3", "$1", [(201, "$1"), (204, "$1")]))
        # herdr: the user's herdr processes run without a subcommand, of the pane's session.
        hd = merged(chain, {301: {"comm": "herdr", "args": "herdr --session s2", "tty": "ttys021", "env": {"LC_SIMPLETERM_TAB": MK_A}},
                            302: {"comm": "herdr", "args": "/opt/homebrew/bin/herdr server", "env": {"LC_SIMPLETERM_TAB": MK_C}},
                            303: {"comm": "herdr", "args": "herdr --session s3", "tty": "ttys023", "env": {"LC_SIMPLETERM_TAB": MK_C}},
                            304: {"comm": "herdr", "args": "herdr pane run w1:p1 x", "env": {"LC_SIMPLETERM_TAB": MK_C}},
                            305: {"comm": "/opt/homebrew/bin/herdr", "args": "/opt/homebrew/bin/herdr --session=s2", "tty": "ttys025", "env": {"LC_SIMPLETERM_TAB": MK_B}},
                            306: {"comm": "herdr", "args": "herdr", "tty": "ttys026", "env": {"LC_SIMPLETERM_TAB": MK_C}}})
        hd_env = {"HERDR_ENV": "1", "HERDR_PANE_ID": "w1:p1", "HERDR_SESSION": "s2", "LC_SIMPLETERM_TAB": MK_C}
        case("tb-herdr", hd_env, dict(mux, n=2, cl=[MK_A, MK_B]), "herdr", "w1:p1", "s2", procs=hd)
        case("tb-herdr-default", dict(hd_env, HERDR_SESSION=""), dict(mux, n=1, cl=[MK_C]), "herdr", "w1:p1", procs=hd)
        case("tb-herdr-badsess", dict(hd_env, HERDR_SESSION="a b"), dict(mux, n=0, cl=[]), "herdr", "w1:p1", procs=hd)
        case("tb-herdr-noprocs", hd_env, mux, "herdr", "w1:p1", "s2", procs=chain)
        # screen: detected by STY; its clients are not listed in phase 1.
        case("tb-screen", {"STY": "400.w", "LC_SIMPLETERM_TAB": MK_C}, mux, "screen", procs=chain)
        # abduco and dtach set no variable: the master among the ancestors tells. No mux field for them.
        case("tb-dtach", {"LC_SIMPLETERM_TAB": MK_C}, mux,
             procs={100: {"ppid": 90, "comm": "sh"}, 90: {"ppid": 110, "comm": "claude"}, 110: {"ppid": 111, "comm": "bash"},
                    111: {"ppid": 1, "comm": "dtach", "args": "dtach -c /tmp/d.sock bash"}})
        case("tb-abduco", {"LC_SIMPLETERM_TAB": MK_C, "SIMPLETERM": "1"}, mux,
             procs={100: {"ppid": 90, "comm": "sh"}, 90: {"ppid": 120, "comm": "claude"}, 120: {"ppid": 121, "comm": "-zsh"},
                    121: {"ppid": 1, "comm": "/usr/bin/abduco", "args": "abduco -e ^q -c work zsh -l"}})
        # The same from /proc, with herdr's clients listed there too.
        case("tb-herdr-linux", hd_env, dict(mux, n=1, cl=[MK_A]), "herdr", "w1:p1", "s2",
             linux={100: {"ppid": 90, "comm": "sh"}, 90: {"ppid": 80, "comm": "claude"}, 80: {"ppid": 302, "comm": "bash"},
                    301: {"ppid": 1, "comm": "herdr", "args": "herdr --session s2", "env": {"LC_SIMPLETERM_TAB": MK_A, "PATH": "/usr/bin"}, "fd": {0: "/dev/pts/2"}},
                    302: {"ppid": 1, "comm": "herdr", "args": "herdr server", "env": {"LC_SIMPLETERM_TAB": MK_C}},
                    303: {"ppid": 1, "comm": "herdr", "args": "herdr --session s3", "env": {"LC_SIMPLETERM_TAB": MK_B}, "fd": {0: "/dev/pts/3"}}})

        # Rule 1, Codex: the daemon is the hook's host (the nearest ancestor named codex, whatever shell
        # stands between). The session's TUI is the one started as "resume <session>": judged by its
        # ancestors and its marker, whatever the daemon's own environment says.
        def daemon(sid, more=None):
            return merged({80: {"ppid": 1, "comm": "-zsh"}, 500: {"ppid": 501, "comm": "sh"},
                           501: {"ppid": 1, "comm": "codex", "args": "codex app-server --listen unix:///tmp/x --managed-daemon"},
                           # not candidates: a TUI that does not use the daemon, and the daemon's own child
                           520: {"ppid": 80, "comm": "codex", "args": "codex -C /w resume %s --no-daemon" % sid, "env": {"LC_SIMPLETERM_TAB": MK_C}},
                           530: {"ppid": 501, "comm": "codex", "args": "codex exec x"}}, more or {})

        def tui(env, args="codex -C /w", ppid=80, comm="codex"):
            return {"ppid": ppid, "comm": comm, "args": args, "tty": "ttys030", "env": dict(env, PATH="/usr/bin")}
        cx = dict(agent="codex", start="500")
        stale = {"LC_SIMPLETERM_TAB": MK_C, "SIMPLETERM": "1", "TMUX": sock + ",1,0", "TMUX_PANE": "%9"}  # the daemon's own
        other = tui({"LC_SIMPLETERM_TAB": MK_A})

        def resumed(sid, env, **kw):
            return tui(env, "codex resume " + sid, **kw)
        in_tmux = {86: {"ppid": 87, "comm": "-zsh"}, 87: {"ppid": 1, "comm": "tmux", "args": "tmux"}}
        case("tb-cx-exact", stale, {"st": "a", "tm": MK_B}, "tmux", procs=daemon("tb-cx-exact", {510: other, 511: resumed("tb-cx-exact", {"LC_SIMPLETERM_TAB": MK_B})}), **cx)
        case("tb-cx-exact-b", stale, {"st": "b"}, "tmux", procs=daemon("tb-cx-exact-b", {510: other, 511: resumed("tb-cx-exact-b", {})}), **cx)
        case("tb-cx-exact-form", {}, {"st": "c", "why": "form"},
             procs=daemon("tb-cx-exact-form", {510: other, 511: resumed("tb-cx-exact-form", {"LC_SIMPLETERM_TAB": "st1-XYZ"})}), **cx)
        case("tb-cx-exact-mux", stale, mux, "tmux",
             procs=daemon("tb-cx-exact-mux", merged(in_tmux, {510: other, 511: resumed("tb-cx-exact-mux", {"LC_SIMPLETERM_TAB": MK_B}, ppid=86)})), **cx)
        # Its environment cannot be read (ps shows none), or holds two values: unknown, never b or a.
        case("tb-cx-exact-noenv", stale, {"st": "c", "why": "daemon"}, "tmux",
             procs=daemon("tb-cx-exact-noenv", {510: other, 511: {"ppid": 80, "comm": "codex", "args": "codex resume tb-cx-exact-noenv"}}), **cx)
        case("tb-cx-exact-two", {}, {"st": "c", "why": "daemon"},
             procs=daemon("tb-cx-exact-two", {511: resumed("tb-cx-exact-two", {"LC_SIMPLETERM_TAB": MK_B, "NOTE": "x LC_SIMPLETERM_TAB=" + MK_C})}), **cx)
        # No word of an argument is read as a variable: a marker there is not the tab's, and a k=v there
        # does not make a hidden environment "read, no marker".
        case("tb-cx-exact-argmark", {}, {"st": "a", "tm": MK_B},
             procs=daemon("tb-cx-exact-argmark", {511: tui({"LC_SIMPLETERM_TAB": MK_B}, "codex resume tb-cx-exact-argmark LC_SIMPLETERM_TAB=" + MK_C)}), **cx)
        case("tb-cx-exact-argonly", {}, {"st": "b"},
             procs=daemon("tb-cx-exact-argonly", {511: tui({}, "codex resume tb-cx-exact-argonly LC_SIMPLETERM_TAB=" + MK_C)}), **cx)
        case("tb-cx-exact-hidden", stale, {"st": "c", "why": "daemon"}, "tmux",
             procs=daemon("tb-cx-exact-hidden", {510: other, 511: {"ppid": 80, "comm": "codex", "args": "codex -c model_reasoning_effort=high resume tb-cx-exact-hidden"}}), **cx)
        # Its parent is gone: whether it runs inside a multiplexer cannot be told.
        case("tb-cx-exact-orphan", {}, {"st": "c", "why": "daemon"},
             procs=daemon("tb-cx-exact-orphan", {511: resumed("tb-cx-exact-orphan", {"LC_SIMPLETERM_TAB": MK_B}, ppid=999)}), **cx)
        # No TUI names the session: c daemon, n the candidate TUIs, cl the markers of those outside a
        # multiplexer. The only TUI is a candidate too, not the session's: a late event of a session whose
        # TUI has gone must not name another tab.
        case("tb-cx-sole", stale, {"st": "c", "why": "daemon", "n": 1, "cl": [MK_A]}, "tmux", procs=daemon("tb-cx-sole", {510: other}), **cx)
        case("tb-cx-sole-b", {}, {"st": "c", "why": "daemon", "n": 1, "cl": []}, procs=daemon("tb-cx-sole-b", {510: tui({})}), **cx)
        case("tb-cx-unbound", stale, {"st": "c", "why": "daemon", "n": 3, "cl": [MK_A]}, "tmux",
             procs=daemon("tb-cx-unbound", {510: other, 511: tui({}),
                                            512: tui({"LC_SIMPLETERM_TAB": MK_B}, ppid=85), 85: {"ppid": 1, "comm": "abduco", "args": "abduco -c x codex"}}), **cx)
        case("tb-cx-two-exact", {}, {"st": "c", "why": "daemon", "n": 2, "cl": [MK_A, MK_B]},
             procs=daemon("tb-cx-two-exact", {510: resumed("tb-cx-two-exact", {"LC_SIMPLETERM_TAB": MK_A}),
                                              511: resumed("tb-cx-two-exact", {"LC_SIMPLETERM_TAB": MK_B})}), **cx)
        case("tb-cx-nocand", stale, {"st": "c", "why": "daemon", "n": 0, "cl": []}, "tmux", procs=daemon("tb-cx-nocand"), **cx)
        # A codex whose path has a blank is a candidate too (two TUIs, so the first is not the only one).
        case("tb-cx-space", {}, {"st": "c", "why": "daemon", "n": 2, "cl": [MK_A, MK_B]},
             procs=daemon("tb-cx-space", {510: other, 511: tui({"LC_SIMPLETERM_TAB": MK_B}, comm="/Users/u/Application Support/codex/bin/codex")}), **cx)
        # Codex starts the hook through another shell: the daemon is still found.
        case("tb-cx-wrapper", stale, {"st": "c", "why": "daemon", "n": 1, "cl": [MK_A]}, "tmux",
             procs=daemon("tb-cx-wrapper", {500: {"ppid": 505, "comm": "sh"}, 505: {"ppid": 501, "comm": "tcsh"}, 510: other}), **cx)
        # Codex runs the hook itself (--no-daemon): the hook's own environment, as any agent, scope fields too.
        case("tb-cx-builtin", {"LC_SIMPLETERM_TAB": MK_A}, {"st": "a", "tm": MK_A},
             procs={80: {"ppid": 1, "comm": "-zsh"}, 500: {"ppid": 510, "comm": "sh"}, 510: tui({"LC_SIMPLETERM_TAB": MK_A}, "codex -C /w resume tb-cx-builtin --no-daemon")}, **cx)
        case("tb-cx-builtin-tmux", {"TMUX": sock + ",1,0", "TMUX_PANE": "%9", "LC_SIMPLETERM_TAB": MK_C}, dict(mux, n=1, cl=[MK_A]), "tmux", "%9", None, sock,
             procs=merged({80: {"ppid": 84, "comm": "-zsh"}, 84: {"ppid": 1, "comm": "tmux", "args": "tmux"}, 500: {"ppid": 510, "comm": "sh"},
                           510: tui({}, "codex --no-daemon"), 201: {"comm": "tmux", "tty": "ttys001", "env": {"LC_SIMPLETERM_TAB": MK_A}}}),
             tmux=("%9", "$1", [(201, "$1")]), **cx)
        # A Codex screen runs the hook itself (if/hook-events-identification#identification, hist/hook-events#d12):
        # the first argument of the nearest codex that is not an option is absent, resume, fork or a prompt with
        # a blank, options skipped with their values as codex --help 0.172.0 lists them. Then the hook's own
        # pane and scope fields go, as for any agent. Any other host (a command, one word, an option not in the
        # list or one without its value, -i followed by an argument: it takes several) sends none. The tab
        # field and mux do not change.
        cx_tm = {"TMUX": sock + ",1,0", "TMUX_PANE": "%9", "LC_SIMPLETERM_TAB": MK_C}
        cx_tab = dict(mux, n=1, cl=[MK_A])
        cx_cl = ("%9", "$1", [(201, "$1")])

        def on_screen(args, comm="codex"):
            return merged({80: {"ppid": 84, "comm": "-zsh"}, 84: {"ppid": 1, "comm": "tmux", "args": "tmux"}, 500: {"ppid": 510, "comm": "sh"},
                           510: tui({}, args, comm=comm), 201: {"comm": "tmux", "tty": "ttys001", "env": {"LC_SIMPLETERM_TAB": MK_A}}})
        screens = [
            ("codex", True),
            ("/opt/homebrew/lib/node_modules/@openai/codex/vendor/aarch64-apple-darwin/codex/codex -C /w resume 019a-x --no-daemon", True),
            ("codex fork --last", True),
            ("codex -m gpt-5.5 -c model_reasoning_effort=high --search -s workspace-write fix the failing test", True),
            ("codex --model=gpt-5.5 -cfoo=1 -a never -- fix the plan", True),
            # ps joins the arguments with blanks: a value with a blank comes split, and a command
            # anywhere among the words left after the options keeps it no screen (also after --).
            ("codex -c k=a b fix the bug", True),
            ("codex -c k=a b resume x", True),
            ("codex -c k=a b exec foo", False),
            ("codex --cd /tmp/a b exec foo", False),
            ("codex -c k=a resume exec foo", False),
            ("codex -c k=a -- b exec foo", False),
            ("codex -a never -- exec the plan", False),
            ("codex please review this change", False),
            ("codex --enable x --disable y --add-dir /tmp -p work --no-alt-screen", True),
            ("codex -i shot.png", True),
            ("codex exec fix the failing test", False),
            ("codex e fix it now", False),
            ("codex -C /w exec --json fix it", False),
            ("codex review", False),
            ("codex mcp-server", False),
            ("codex agents", False),
            ("codex exec-server --listen ws://127.0.0.1:9", False),
            ("codex newcmd", False),
            ("codex hello", False),
            ("codex --frobnicate fix the bug", False),
            ("codex --frobnicate=1 fix the bug", False),
            ("codex -i shot.png fix the bug", False),
            ("codex -C", False),
        ]
        for k, (args, sends) in enumerate(screens):
            case("tb-cx-screen-%d" % k, cx_tm, cx_tab, "tmux", "%9" if sends else None, None, sock if sends else None,
                 procs=on_screen(args), tmux=cx_cl, **cx)
        # A path with a blank: the program ends at the word whose last part is codex.
        case("tb-cx-screen-space", cx_tm, cx_tab, "tmux", "%9", None, sock,
             procs=on_screen("/Users/u/Application Support/codex/bin/codex resume x", comm="/Users/u/Application Support/codex/bin/codex"), tmux=cx_cl, **cx)
        case("tb-cx-exec-space", cx_tm, cx_tab, "tmux", None, None, None,
             procs=on_screen("/Users/u/Application Support/codex/bin/codex exec fix the bug", comm="/Users/u/Application Support/codex/bin/codex"), tmux=cx_cl, **cx)
        case("tb-cx-exec-space-dir", cx_tm, cx_tab, "tmux", None, None, None,
             procs=on_screen("/Users/u/codex dir/codex exec fix the bug", comm="/Users/u/codex dir/codex"), tmux=cx_cl, **cx)
        # herdr: the screen's pane and session; codex exec there sends neither.
        hscr = merged(hd, {500: {"ppid": 510, "comm": "sh"}, 510: tui({}, "codex --no-daemon")})
        case("tb-cx-screen-herdr", hd_env, dict(mux, n=2, cl=[MK_A, MK_B]), "herdr", "w1:p1", "s2", procs=hscr, **cx)
        case("tb-cx-exec-herdr", hd_env, dict(mux, n=2, cl=[MK_A, MK_B]), "herdr",
             procs=merged(hscr, {510: tui({}, "codex exec go on")}), **cx)
        # The same from /proc (its arguments split at NUL, read back joined by blanks).
        lxs = merged(lx, {90: {"ppid": 80, "comm": "codex", "args": "codex --no-daemon"}})
        case("tb-cx-screen-linux", tm_env, dict(mux, n=2, cl=[MK_A]), "tmux", "%3", None, sock, linux=lxs,
             tmux=("%3", "$1", [(201, "$1"), (204, "$1")]), agent="codex")
        case("tb-cx-exec-linux", tm_env, dict(mux, n=2, cl=[MK_A]), "tmux", linux=merged(lxs, {90: {"ppid": 80, "comm": "codex", "args": "codex exec x y"}}),
             tmux=("%3", "$1", [(201, "$1"), (204, "$1")]), agent="codex")
        # No codex among the ancestors, or nothing can be read: whether it is the daemon is not known,
        # so unknown, and no scope field of an environment that may be another tab's.
        case("tb-cx-nohost", stale, {"st": "c", "why": "daemon"}, "tmux",
             procs={80: {"ppid": 1, "comm": "-zsh"}, 500: {"ppid": 510, "comm": "sh"}, 510: {"ppid": 80, "comm": "node", "args": "node x.js"}}, **cx)
        case("tb-cx-noread", {"LC_SIMPLETERM_TAB": MK_A, "TMUX": "/x,1,0", "TMUX_PANE": "%2"}, {"st": "c", "why": "daemon"}, "tmux", agent="codex", off=True)
        # Another app-server (an IDE's, not the managed daemon): its environment is not a tab's either.
        case("tb-cx-appserver", stale, {"st": "c", "why": "daemon"}, "tmux",
             procs={80: {"ppid": 1, "comm": "-zsh"}, 500: {"ppid": 501, "comm": "sh"},
                    501: {"ppid": 80, "comm": "codex", "args": "codex app-server --listen stdio://"}, 510: other}, **cx)
        # The same from /proc: the candidates listed there, and a line feed inside another variable's
        # value does not make a marker.
        lcx = {80: {"ppid": 1, "comm": "bash"}, 500: {"ppid": 501, "comm": "sh"},
               501: {"ppid": 1, "comm": "codex", "args": "codex app-server --listen unix:///tmp/x --managed-daemon"},
               510: {"ppid": 80, "comm": "codex", "args": "codex", "env": {"LC_SIMPLETERM_TAB": MK_A, "PATH": "/usr/bin"}, "fd": {0: "/dev/pts/1"}},
               511: {"ppid": 80, "comm": "codex", "args": "codex resume tb-cx-linux",
                     "env": {"NOTE": "x\nLC_SIMPLETERM_TAB=" + MK_C, "LC_SIMPLETERM_TAB": MK_B, "PATH": "/usr/bin"}, "fd": {0: "/dev/pts/2"}}}
        case("tb-cx-linux", {}, {"st": "a", "tm": MK_B}, linux=lcx, **cx)
        case("tb-cx-linux-unbound", {}, {"st": "c", "why": "daemon", "n": 2, "cl": [MK_A, MK_B]}, linux=lcx, **cx)
        for sid, agent, inp, env, *_ in cases:
            s.run(agent, inp, env)

        def plains(recs):
            got = {}
            for r in recs:
                if r["path"] == "/v1/ingest" and r.get("plain"):
                    got[(r.get("plain_json") or {}).get("sid")] = r["plain"]
            return got
        wait_for(lambda: len(plains(tctl("/_ctl/records")["records"])) >= len(cases) and len(plains(s.records())) >= len(cases), 30)
        tun_p, rel_p = plains(tctl("/_ctl/records")["records"]), plains(s.records())
        order = ("mux", "pane", "msess", "msock", "tab", "tms")
        for sid, agent, inp, env, tab, mux_v, pane, msess, msock in cases:
            for where, got in (("tunnel", tun_p), ("relay", rel_p)):
                raw = got.get(sid)
                j = json.loads(raw) if raw else {}
                want_tab = tab if where == "tunnel" else None
                ok = (raw is not None and j.get("tab") == want_tab and j.get("mux") == mux_v and j.get("pane") == pane
                      and j.get("msess") == msess and j.get("msock") == (msock if where == "tunnel" else None))
                # key order: mux, pane, msess, msock, tab, then tms (if/event-v2#common-fields)
                ok = ok and [k for k in j if k in order] == [k for k in order if k in j]
                if ok and want_tab:
                    ok = list(j["tab"]) == [k for k in ("st", "tm", "why", "n", "cl") if k in want_tab]
                s.check("tab %s: %s tab %s mux %s pane %s msess %s msock %s" % (sid, where, want_tab, mux_v, pane, msess, msock and "set"),
                        ok, str(raw)[:400])
        # Codex's notify program runs in the daemon too: its own environment (the stale marker) is not its tab.
        root = tab_bin(base / "cx-notify", procs=daemon("cx-notify", {510: other}))
        s.run("codex-notify", "", dict(stale, SIMPLETERM_HOOK_TEST="1", SIMPLETERM_HOOK_TEST_IDBIN=str(root), SIMPLETERM_HOOK_TEST_IDPPID="500"),
              args=(json.dumps({"type": "agent-turn-complete", "cwd": "/w/cxnotify", "last-assistant-message": "notify-probe done"}),))
        probe = wait_for(lambda: [r for r in tctl("/_ctl/records")["records"] if r["path"] == "/v1/ingest" and "notify-probe" in (r.get("plain") or "")], 15)
        jn = (probe[0].get("plain_json") or {}) if probe else {}
        s.check("tab cx-notify: the notify program in the daemon is c daemon with the candidate, not the daemon's marker, "
                "and sends none of the daemon's pane and scope fields",
                jn.get("tab") == {"st": "c", "why": "daemon", "n": 1, "cl": [MK_A]} and "msock" not in jn and "pane" not in jn
                and jn.get("mux") == "tmux", str(probe)[:400])
        # In a screen that runs it itself it is the screen's: its pane and socket (hist/hook-events#d12).
        root = tab_bin(base / "cx-notify-screen", procs=on_screen("codex --no-daemon"), tmux=cx_cl)
        s.run("codex-notify", "", dict(cx_tm, SIMPLETERM_HOOK_TEST="1", SIMPLETERM_HOOK_TEST_IDBIN=str(root), SIMPLETERM_HOOK_TEST_IDPPID="500"),
              args=(json.dumps({"type": "agent-turn-complete", "cwd": "/w/cxscreen", "last-assistant-message": "screen-notify done"}),))
        probe = wait_for(lambda: [r for r in tctl("/_ctl/records")["records"] if r["path"] == "/v1/ingest" and "screen-notify" in (r.get("plain") or "")], 15)
        jn = (probe[0].get("plain_json") or {}) if probe else {}
        s.check("tab cx-notify-screen: the notify program of a screen sends the screen's pane and socket",
                jn.get("tab") == cx_tab and jn.get("mux") == "tmux" and jn.get("pane") == "%9" and jn.get("msock") == sock, str(probe)[:400])
        # The session record of a Codex hook (if/session-record#scope): in the daemon only for a TUI whose
        # own environment has the marker (the one tied by its arguments, else the only TUI); SIMPLETERM of
        # the daemon says nothing. Made at a prompt or a session's start only; one that is there is kept up.
        sd = s.home / ".simpleterm" / "sessions" / "codex"
        builtin = {80: {"ppid": 1, "comm": "-zsh"}, 500: {"ppid": 510, "comm": "sh"}, 510: tui({}, "codex --no-daemon")}
        marked = {"LC_SIMPLETERM_TAB": MK_A}

        def rec_run(sid, env, procs, event="UserPromptSubmit"):
            root = tab_bin(base / (sid + "-" + event), procs=procs)
            s.run("codex", cx_in(sid, event), dict(env, SIMPLETERM_HOOK_TEST="1", SIMPLETERM_HOOK_TEST_IDBIN=str(root), SIMPLETERM_HOOK_TEST_IDPPID="500"))
            rec = sd / (sid + ".json")
            return json.loads(rec.read_text()) if rec.exists() else None
        recs = [  # (sid, hook environment, processes, record written, its mux)
            ("cx-rec-sole", {}, daemon("cx-rec-sole", {510: tui(marked)}), True, None),
            ("cx-rec-sole-tmux", {}, daemon("cx-rec-sole-tmux", merged(in_tmux, {510: tui(marked, ppid=86)})), True, "tmux"),
            ("cx-rec-exact", {}, daemon("cx-rec-exact", {510: tui({}), 511: resumed("cx-rec-exact", marked)}), True, None),
            ("cx-rec-nomark", stale, daemon("cx-rec-nomark", {510: tui({})}), False, None),
            ("cx-rec-unbound", stale, daemon("cx-rec-unbound", {510: tui(marked), 511: tui({"LC_SIMPLETERM_TAB": MK_B})}), False, None),
            ("cx-rec-noenv", stale, daemon("cx-rec-noenv", {510: {"ppid": 80, "comm": "codex", "args": "codex"}}), False, None),
            ("cx-rec-builtin", {"SIMPLETERM": "1"}, builtin, True, None),
            ("cx-rec-builtin-other", {}, builtin, False, None),
            ("cx-rec-screen-tmux", dict(cx_tm, SIMPLETERM="1"), on_screen("codex --no-daemon"), True, "tmux"),
            ("cx-rec-exec-tmux", dict(cx_tm, SIMPLETERM="1"), on_screen("codex exec x y"), True, "tmux"),
        ]
        for sid, env, procs, want, rmux in recs:
            r = rec_run(sid, env, procs)
            s.check("tab %s: session record %s, mux %s" % (sid, "written" if want else "not written", rmux),
                    (r is not None and r.get("mux") == rmux and "pane" not in r) if want else r is None, str(r)[:300])
        # Not at an event that is neither a prompt nor a session's start.
        r = rec_run("cx-rec-late", {}, daemon("cx-rec-late", {510: tui(marked)}), "PermissionRequest")
        s.check("tab cx-rec-late: no record is made at a permission request", r is None and not (sd / "cx-rec-late.beat").exists(), str(r)[:300])
        # A record that is there is kept up whatever the processes are now, and keeps its multiplexer
        # when no TUI of the session can be looked at.
        two = daemon("cx-rec-sole-tmux", {510: tui({}), 511: tui({})})
        root = tab_bin(base / "cx-rec-again", procs=two)
        s.run("codex", json.dumps(dict(json.loads(cx_in("cx-rec-sole-tmux", "UserPromptSubmit")), prompt="again")),
              dict(stale, SIMPLETERM_HOOK_TEST="1", SIMPLETERM_HOOK_TEST_IDBIN=str(root), SIMPLETERM_HOOK_TEST_IDPPID="500"))
        r = json.loads((sd / "cx-rec-sole-tmux.json").read_text())
        s.check("tab cx-rec-again: a record that is there is kept up without a TUI to tie it to, with the multiplexer it had",
                r.get("last_prompt") == "again" and r.get("mux") == "tmux", str(r)[:300])
        # A late prompt-less event of a recorded session whose TUI has gone, the only TUI left being another
        # tab's inside tmux: the record does not take that TUI's multiplexer. A TUI tied by its arguments does.
        root = tab_bin(base / "cx-rec-late-other", procs=daemon("cx-rec-sole", merged(in_tmux, {510: tui(marked, ppid=86)})))
        s.run("codex", json.dumps(dict(json.loads(cx_in("cx-rec-sole", "UserPromptSubmit")), prompt="late")),
              dict(SIMPLETERM_HOOK_TEST="1", SIMPLETERM_HOOK_TEST_IDBIN=str(root), SIMPLETERM_HOOK_TEST_IDPPID="500"))
        r = json.loads((sd / "cx-rec-sole.json").read_text())
        s.check("tab cx-rec-late-other: the record of a session does not take the multiplexer of another tab's only TUI",
                r.get("last_prompt") == "late" and "mux" not in r, str(r)[:300])
        root = tab_bin(base / "cx-rec-late-tied", procs=daemon("cx-rec-sole", merged(in_tmux, {510: tui({}), 511: resumed("cx-rec-sole", marked, ppid=86)})))
        s.run("codex", json.dumps(dict(json.loads(cx_in("cx-rec-sole", "UserPromptSubmit")), prompt="tied")),
              dict(SIMPLETERM_HOOK_TEST="1", SIMPLETERM_HOOK_TEST_IDBIN=str(root), SIMPLETERM_HOOK_TEST_IDPPID="500"))
        r = json.loads((sd / "cx-rec-sole.json").read_text())
        s.check("tab cx-rec-late-tied: the record takes the multiplexer of the TUI tied to the session by its arguments",
                r.get("last_prompt") == "tied" and r.get("mux") == "tmux", str(r)[:300])
        # The relay summary over budget: msess goes first (and is recorded in cut); mux and pane stay.
        tctl("/_ctl/reset", {})
        tctl("/_ctl/config", {"links": {LINK_T["id"]: dict(LINK_T, push="suppressed", unknown_error="unknown", max_body=65536)}})
        big = "".join(chr(0x4E00 + i) for i in range(400))
        env = {"HERDR_ENV": "1", "HERDR_PANE_ID": "p" * 64, "HERDR_SESSION": "s" * 64}
        sid_big = "tb-big-" + "x" * 121
        big_in = json.loads(v2_perm(command=big, session=sid_big, cwd="/w/" + "d" * 64))
        big_in["tool_input"]["description"] = big[:120]
        s.run("claude", json.dumps(big_in), env)
        wait_for(lambda: plains(s.records()).get(sid_big) and plains(tctl("/_ctl/records")["records"]).get(sid_big), 15)
        rel = plains(s.records()).get(sid_big) or ""
        tun_raw = plains(tctl("/_ctl/records")["records"]).get(sid_big) or ""
        jr = json.loads(rel) if rel else {}
        s.check("tab: relay over budget drops msess first (cut msess 64), keeps mux and pane, within 2048 bytes",
                bool(rel) and "msess" not in jr and (jr.get("cut") or {}).get("msess") == 64 and jr.get("mux") == "herdr"
                and jr.get("pane") == "p" * 64 and len(rel.encode()) <= 2048,
                "%d %s" % (len(rel.encode()), json.dumps({k: v for k, v in jr.items() if k not in ("msg", "req", "sid", "cwd", "nonce", "pane")})[:500]))
        s.check("tab: the tunnel keeps msess", json.loads(tun_raw).get("msess") == "s" * 64 if tun_raw else False, tun_raw[:200])
        # Within budget the relay keeps msess.
        s.run("claude", v2_perm(session="tb-small"), dict(env, HERDR_PANE_ID="w1:p1", HERDR_SESSION="s2"))
        wait_for(lambda: plains(s.records()).get("tb-small"), 15)
        js = json.loads(plains(s.records()).get("tb-small") or "{}")
        s.check("tab: relay within budget keeps msess", js.get("msess") == "s2" and "cut" not in js, str(js)[:300])
    finally:
        tun.terminate()
        tun.wait(5)


def t_v2_versions(s):
    """SimpleTerm if/hook-events-identification#version-cache: the agent's version where the agent gives none: `--version`, run in the background
    when the executable is new or newer than the cache (SimpleTerm hist/event-v2#d13); the first dotted number is taken."""
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
        # The first event's own send (no version yet) is in before the next one is looked at.
        wait_for(lambda: ingests(s, "done"), 20)
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
    s.settle("the PreToolUse report's wait (ask_delay, 2 s) and the sends")
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
    1.19 question routes, the other open requests (SimpleTerm if/event-v2-request#affects) and the bridge's pending file."""
    if not NODE or s.kind != "sh":
        return
    d = str(s.tmp)
    ask19 = {"type": "permission.asked", "properties": {"id": "per_1", "sessionID": "ses_1", "permission": "bash", "patterns": ["echo a1"],
                                                       "metadata": {"command": "echo a1"}, "always": ["echo *"], "tool": {"messageID": "msg_1", "callID": "c1"}}}
    # (A 1.19 always or reject settles the session's other requests: the app names the ones the user
    # saw, this one at least, SimpleTerm if/event-decision#validation, check 5.)
    s.setup([(LINK_A, {"fmt": 2, "decision": "allow", "after": 1, "dext": {"act": "allow_scope", "scope": 0, "seen": ["per_1"]}})])
    calls = node_plugin(s, "v1", {"directory": d, "raw": True, "steps": [{"event": ask19}], "wait": 30000, "replies": 1})
    s.check("opencode 1.19 v2: allow_scope -> reply always (raw route)",
            replies(calls) == [{"url": "/permission/{requestID}/reply", "path": {"requestID": "per_1"}, "body": {"reply": "always"}}], str(calls)[:400])
    p = (ingests(s, "permission") or [{}])[0].get("plain_json") or {}
    s.check("opencode 1.19 v2: request id, scope pattern, message id", (p.get("req") or {}).get("id") == "per_1"
            and (p.get("req") or {}).get("scopes") == [{"label": "echo *", "kind": "pattern", "dest": "process"}], str(p)[:300])
    s.setup([(LINK_A, {"fmt": 2, "decision": "deny", "after": 1, "dext": {"act": "deny_reason", "reason": "use pnpm", "seen": ["per_1"]}})])
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


def t_opencode_schedule(s):
    """OpenCode 2.2.3+ schedules (flag `schedules`; SimpleTerm spec/turn-state#scheduled, if/hook-events-turn#turn-end,
    hist/turn-state#d20). The events are those 2.2.7 sent with a model stub (2026-11-16): a schedule's prompt is a user
    inbox item with payload.metadata.schedule, a person's one without it, a background shell's report a synthetic item
    naming the shell. A scheduled turn rests while schedule_list has an active schedule, its last one is a done with by
    schedule to the tunnels only; a schedule's prompt inside a person's turn leaves it the person's; the report of a shell
    a scheduled turn started is the schedule's."""
    if not NODE or s.kind != "sh":
        return
    d = str(s.tmp)
    tun, tctl = s.spawn_mock()
    try:
        s.setup([(LINK_A, {}), (LINK_T, {"kind": "tunnel", "relay_url": tctl.url, "fmt": 2})])
        n = [100]

        def ev(typ, **data):
            n[0] += 1
            return {"event": {"id": "evt_%d" % n[0], "type": typ, "location": {"directory": d}, "data": data}}

        sid = "ses_s"
        sch = "sch_1e29c1c1c001LYyOwyXTrzGqiq"

        def human(inbox):
            return [ev("session.inbox.enqueued", sessionID=sid, inboxID=inbox,
                       item={"type": "user", "payload": {"text": "every 15s say tick, twice"}, "delivery": "steer"})]

        def scheduled(run):
            inbox = "msg_%s_%d" % (sch, run)
            return [ev("session.inbox.enqueued", sessionID=sid, inboxID=inbox,
                       item={"type": "user", "payload": {"text": "say tick", "metadata": {"schedule": {
                           "id": sch, "name": "twice", "run": run, "dueAt": 1794803274060, "late": False, "check": {}}}},
                           "delivery": "steer"}),
                    ev("session.execution.started", sessionID=sid),
                    ev("session.inbox.delivered", sessionID=sid, inboxID=inbox)]

        def turn(start):
            return start[:1] + [ev("session.execution.started", sessionID=sid),
                                ev("session.inbox.delivered", sessionID=sid, inboxID=start[0]["event"]["data"]["inboxID"])]

        def info(status, left):
            return [{"id": sch, "sessionID": sid, "name": "twice", "when": {"type": "every", "every": "15 seconds"},
                     "action": {"type": "prompt", "prompt": "say tick"}, "status": status, "remainingRuns": left}]

        def run(steps, sched, instances=None):
            s.ctl("/_ctl/reset", {})
            tctl("/_ctl/reset", {})
            tctl("/_ctl/config", {"links": {LINK_T["id"]: dict(LINK_T)}})
            sc = {"directory": d, "sessions": {sid: {"title": "Ticks"}}, "schedules": {sid: sched}, "steps": steps, "wait": 3000}
            if instances:
                sc["instances"] = instances
            return node_plugin(s, "v2", sc)

        def tunnel(ev_):
            return [r for r in ingests(s, ctl=tctl) if (r.get("body") or {}).get("ev") == ev_]

        def by(recs):
            return [((r.get("plain_json") or {}).get("turn") or {}).get("by") for r in recs]

        def scheduled_state():
            return [r for r in tunnel("state") if (r.get("plain_json") or {}).get("st") == "scheduled"]

        succeeded = ev("session.execution.succeeded", sessionID=sid)
        # The person's turn that sets the schedule: done (by user), though the schedule is active.
        calls = run(turn(human("msg_1e29c1412001eEc8auhRq89EUd")) + [succeeded], info("active", 2))
        s.check("opencode schedule: the person's turn -> done (by user)",
                by(wait_for(lambda: ingests(s, "done"), 20)) == ["user"], str(ingests(s))[:300])
        s.check("opencode schedule: a person's turn does not ask schedule_list", not [c for c in calls if "schedule_list" in c],
                str(calls)[:300])
        # Run 1 of 2: a schedule is left -> state scheduled, no done.
        run(scheduled(1) + [ev("session.execution.succeeded", sessionID=sid)], info("active", 1))
        st = wait_for(scheduled_state, 10)
        s.settle("the plugin's hooks' background work")
        s.check("opencode schedule: a run with a run left -> state scheduled (by schedule), no done",
                st and by(st) == ["schedule"] and (st[0].get("plain_json") or {}).get("turn", {}).get("crons")
                and not tunnel("done") and not ingests(s, "done"), str(ingests(s, ctl=tctl))[:400] + str(ingests(s))[:200])
        # Run 2, the last (the schedule is done when its prompt is sent): a done by schedule to the tunnel only.
        run(scheduled(2) + [ev("session.execution.succeeded", sessionID=sid)], info("done", 0))
        dn = wait_for(lambda: tunnel("done"), 10)
        s.settle("the plugin's hooks' background work")
        s.check("opencode schedule: the last run -> done by schedule to the tunnel only",
                by(dn) == ["schedule"] and not ingests(s, "done"), str(dn)[:300] + str(ingests(s))[:300])
        # Without the enqueued item (a plugin that came up late), the inbox id of a schedule's prompt still tells it.
        run([ev("session.execution.started", sessionID=sid),
             ev("session.inbox.delivered", sessionID=sid, inboxID="msg_%s_3" % sch),
             ev("session.execution.succeeded", sessionID=sid)], [])
        dn = wait_for(lambda: tunnel("done"), 10)
        s.settle("the plugin's hooks' background work")
        s.check("opencode schedule: a delivered msg_sch_ id alone -> the schedule's turn",
                by(dn) == ["schedule"] and not ingests(s, "done"), str(dn)[:300] + str(ingests(s))[:300])
        # No session.inbox.delivered (every 2.2.7 run had one, nothing promises it): an item enqueued while the session
        # was idle is the execution's that starts next, so the last run stays quiet (AhMunGa/simple-term#469) ...
        run(scheduled(2)[:2] + [ev("session.execution.succeeded", sessionID=sid)], info("done", 0))
        dn = wait_for(lambda: tunnel("done"), 10)
        s.settle("the plugin's hooks' background work")
        s.check("opencode schedule: the last run without its delivered event -> done by schedule to the tunnel only",
                by(dn) == ["schedule"] and not ingests(s, "done"), str(dn)[:300] + str(ingests(s))[:300])
        # ... and a person's prompt the same way is the person's turn.
        run(human("msg_1e29c1412001bbbbbbbbbbbbbbbb") + [ev("session.execution.started", sessionID=sid), succeeded],
            info("active", 1))
        s.check("opencode schedule: a person's turn without its delivered event -> done (by user)",
                by(wait_for(lambda: ingests(s, "done"), 20)) == ["user"], str(ingests(s))[:300])
        # Two project directories, two plugin instances, each sees every event (the other one first): the execution
        # and inbox bookkeeping runs once per event, so the judgement is the same as with one instance.
        two = [str(s.tmp / "other-project"), d]
        run(scheduled(2)[:2] + [ev("session.execution.succeeded", sessionID=sid)], info("done", 0), two)
        dn = wait_for(lambda: tunnel("done"), 10)
        s.settle("the plugin's hooks' background work")
        s.check("opencode schedule, two instances: the last run without its delivered event -> done by schedule, tunnel only",
                by(dn) == ["schedule"] and not ingests(s, "done"), str(dn)[:300] + str(ingests(s))[:300])
        steps = turn(human("msg_1e29c1412001cccccccccccccccc"))
        steps += [ev("session.inbox.enqueued", sessionID=sid, inboxID="msg_%s_1" % sch,
                     item={"type": "user", "payload": {"text": "say tick", "metadata": {"schedule": {"id": sch, "run": 1}}},
                           "delivery": "steer"}),
                  ev("session.inbox.delivered", sessionID=sid, inboxID="msg_%s_1" % sch), succeeded]
        run(steps, info("active", 1), two)
        s.check("opencode schedule, two instances: a schedule's prompt inside a person's turn -> the person's done",
                by(wait_for(lambda: ingests(s, "done"), 20)) == ["user"], str(ingests(s))[:300] + str(tunnel("state"))[:200])
        # A schedule's prompt that comes during a person's turn joins it: the person's done.
        steps = turn(human("msg_1e29c1412001aaaaaaaaaaaaaaaa"))
        steps += [ev("session.inbox.enqueued", sessionID=sid, inboxID="msg_%s_1" % sch,
                     item={"type": "user", "payload": {"text": "say tick", "metadata": {"schedule": {"id": sch, "run": 1}}},
                           "delivery": "steer"}),
                  ev("session.inbox.delivered", sessionID=sid, inboxID="msg_%s_1" % sch), succeeded]
        run(steps, info("done", 0))
        s.check("opencode schedule: a schedule's prompt inside a person's turn -> the person's done",
                by(wait_for(lambda: ingests(s, "done"), 20)) == ["user"], str(ingests(s))[:300])
        # A scheduled turn starts a background shell; the shell's report turn is the schedule's.
        shell = "sh_1e2ae2c770019UON02jWlTl6VR"
        steps = scheduled(1) + [
            ev("shell.created", info={"id": shell, "status": "running", "command": "sleep 4; echo BG_K",
                                      "metadata": {"sessionID": sid}}),
            ev("session.execution.succeeded", sessionID=sid), {"sleep": 1500},
            ev("shell.exited", id=shell, exit=0, status="exited"),
            ev("session.inbox.enqueued", sessionID=sid, inboxID="msg_1e2ae2cb4001FT4ZLXHf2PQjVB",
               item={"type": "synthetic", "payload": {
                   "text": "<shell id=\"%s\" state=\"completed\" command=\"sleep 4; echo BG_K\">\nBG_K\n\n</shell>" % shell,
                   "description": "sleep 4; echo BG_K",
                   "metadata": {"source": "shell", "shellID": shell, "jobID": shell, "state": "completed", "exit": 0}},
                   "delivery": "steer"}),
            ev("session.execution.started", sessionID=sid),
            ev("session.inbox.delivered", sessionID=sid, inboxID="msg_1e2ae2cb4001FT4ZLXHf2PQjVB"),
            ev("session.execution.succeeded", sessionID=sid)]
        run(steps, [])
        dn = wait_for(lambda: tunnel("done"), 10)
        s.settle("the plugin's hooks' background work")
        s.check("opencode schedule: the report of a shell a scheduled turn started -> one done by schedule, tunnel only",
                by(dn) == ["schedule"] and not ingests(s, "done"), str(dn)[:300] + str(ingests(s))[:300])
    finally:
        tun.terminate()
        tun.wait(5)


def t_opencode_tui(s):
    """OpenCode 2.x TUI part (tui.js, SimpleTerm if/hook-tab-opencode#claims): what it claims (cur: the root session
    of the route; seen: the roots this TUI had as cur that are still tabs, newest first, none while tabs are off;
    the tab's marker, SIMPLETERM and multiplexer variables, a value over 1,024 bytes left out), when (at start, a change
    seen by the 250 ms look, server.connected, a failed call again at the next look) and how (the RPC simpleterm-tab at
    this TUI's location, none without one, the client read at each call); a call with no answer in 5 s counts as failed;
    after 8 failures in a row the calls space out (2 s, 4 s, 5 s at most) until one succeeds or server.connected."""
    if not NODE or s.kind != "sh":
        return
    env = {"LC_SIMPLETERM_TAB": MK_A, "SIMPLETERM": "1", "TMUX": "/tmp/tmux-501/default,77,0", "TMUX_PANE": "%3",
           "HERDR_TAB_ID": "w1:t1", "OPENCODE_OTHER": "x", "HERDR_SOCKET_PATH": "/x" * 600}

    def run(steps, **kw):
        sc = dict({"env": env, "route": {"type": "session", "sessionID": "ses_A"}, "tabs": ["ses_A", "ses_B"],
                   "location": "/w/proj", "steps": steps}, **kw)
        return node_plugin(s, "tui", sc, timeout=60)

    def at(calls, mark):
        return next((c["at"] for c in calls if c.get("mark") == mark), None)

    def claims(calls, after=-1, before=10 ** 9):
        return [c for c in calls if "claim" in c and after <= c["at"] < before]

    def route(sid):
        return {"route": {"type": "session", "sessionID": sid}}

    calls = run([{"sleep": 450}, route("ses_B"), {"sleep": 500}, {"route": {"type": "home"}}, {"sleep": 500},
                 {"tabs": ["ses_B"]}, {"sleep": 500}, {"roots": {"ses_sub": "ses_B"}}, route("ses_sub"), {"sleep": 500},
                 {"mark": "quiet"}, {"sleep": 900}, {"mark": "connected"}, {"emit": "server.connected"}, {"sleep": 300}])
    cl = claims(calls)
    seq = [(c["claim"].get("cur"), c["claim"].get("seen")) for c in cl]
    s.check("opencode tui: its own id, the claim of the route's root and of the tabs it showed, newest first",
            calls[0].get("id") == "simpleterm.tui" and seq[:5] == [("ses_A", []), ("ses_B", ["ses_A"]), ("", ["ses_B", "ses_A"]),
                                                                  ("", ["ses_B"]), ("ses_B", [])], str(seq) + str(calls)[:300])
    first = cl[0]["claim"] if cl else {}
    s.check("opencode tui: the claim's fields (the tab's values only, a long one left out) at this TUI's location",
            first.get("v") == 1 and isinstance(first.get("pid"), int) and first["pid"] > 1 and isinstance(first.get("t"), int)
            and first.get("tab") == MK_A and first.get("st") is True
            and first.get("env") == {"TMUX": env["TMUX"], "TMUX_PANE": "%3"}
            and cl[0].get("rpc") == "simpleterm-tab" and cl[0].get("opts") == {"location": {"directory": "/w/proj"}}, str(cl[:1]))
    q, c2 = at(calls, "quiet"), at(calls, "connected")
    s.check("opencode tui: no claim while nothing changes; server.connected sends it again",
            q is not None and claims(calls, q, c2) == [] and [c["claim"]["cur"] for c in claims(calls, c2)] == ["ses_B"], str(seq))
    s.check("opencode tui: its cleanup stops listening", calls[-1].get("listeners") == 0, str(calls[-1:]))
    # Tabs off (herdr's default): no seen. Two failed calls (rpc.unavailable): sent at the next looks. No location: no
    # location option. A new client (the service restarted) is the one called.
    calls = run([{"sleep": 900}, route("ses_B"), {"sleep": 500}, {"client": 2}, route("ses_A"), {"sleep": 500}],
                enabled=False, location="", fail=2)
    cl = claims(calls)
    s.check("opencode tui: failed calls go again, tabs off claim no seen, no location, the client read at each call",
            len([c for c in calls if "failed" in c]) == 2
            and [(c["claim"]["cur"], c["claim"]["seen"], c["opts"], c["client"]) for c in cl] ==
            [("ses_A", [], None, 1), ("ses_B", [], None, 1), ("ses_A", [], None, 2)], str(calls)[:600])
    # A call that never answers (the service gone without closing): failed after 5 s, then the screen's claim goes.
    calls = run([{"sleep": 1000}, route("ses_B"), {"sleep": 5600}], hang=1)
    cl, hung = claims(calls), [c for c in calls if "hung" in c]
    s.check("opencode tui: a call with no answer for 5 s counts as failed and the next look sends",
            len(hung) == 1 and cl and cl[0]["claim"]["cur"] == "ses_B" and 4900 <= cl[0]["at"] - hung[0]["at"] <= 5600,
            str(calls)[:600])
    # Failing calls: 8 at the 250 ms looks, then 2 s and 4 s apart; server.connected and the first success end that.
    calls = run([{"sleep": 6500}, {"fail": 0}, {"mark": "up"}, {"emit": "server.connected"}, {"sleep": 300}, route("ses_B"),
                 {"sleep": 500}], fail=1000)
    fl = [c["at"] for c in calls if "failed" in c]
    up = at(calls, "up")
    gaps = [b - a for a, b in zip(fl, fl[1:])]
    s.check("opencode tui: failures in a row space out after 8, server.connected sends at once, a success ends it",
            9 <= len(fl) <= 11 and max(gaps[:7] or [0]) < 600 and len(gaps) > 8 and 1800 <= gaps[8] <= 2600
            and [c["claim"]["cur"] for c in claims(calls, up)] == ["ses_A", "ses_B"]
            and claims(calls, up)[0]["at"] - up < 200 and claims(calls, up)[1]["at"] - claims(calls, up)[0]["at"] < 900,
            str(fl) + str(claims(calls, up))[:300])
    calls = run([{"sleep": 400}], noClient=True)
    s.check("opencode tui: no client (no RPC): nothing sent, nothing broken", not claims(calls) and calls[-1].get("end") is not None,
            str(calls)[:300])


def oc_capture_hook(s):
    """A stand-in for agent-hook.sh that writes, one line per run, the tab variables it got and its input."""
    cap = s.tmp / "oc-cap.txt"
    hook = s.tmp / "oc-cap.sh"
    hook.write_text(
        "#!/bin/sh\n"
        "in=$(cat)\n"
        "e=$(awk 'BEGIN { for (k in ENVIRON) if (k ~ /^(LC_SIMPLETERM_TAB|SIMPLETERM|TMUX|TMUX_PANE|STY|HERDR_[A-Z_]+)$/)"
        " printf \"%s=%s\\001\", k, ENVIRON[k] }')\n"
        "printf '%s\\t%s\\n' \"$e\" \"$in\" >>\"$SIMPLETERM_OC_CAPTURE\"\n")
    cap.write_text("")

    def got():
        out = []
        for line in cap.read_text().splitlines():
            e, _, i = line.partition("\t")
            env_ = dict(kv.split("=", 1) for kv in e.split("\x01") if "=" in kv)
            try:
                inp = json.loads(i)
            except ValueError:
                inp = {"raw": i}
            out.append((env_, inp))
        return out
    return hook, cap, got


def t_opencode_tabs(s):
    """OpenCode 2.x server part (index.js) with its TUIs' tab claims (SimpleTerm if/hook-tab-opencode#binding,
    #hook-input, #view-state, if/session-record#opencode2): a session bound to the one TUI whose screen shows it
    (cur), else to the one that has it as a tab (seen, bg 1), else many or none; the hook gets the bound TUI's tab
    values and oc_tab, never the service's; a dead, old or malformed claim is dropped; a hook waits for a claim that
    comes late; the screen's session gets one View once it stayed 1 s; a deleted session's record goes; without the
    plugin RPC the hook gets what 0.9.0 gave. The hook is a stand-in that writes what it got."""
    if not NODE or s.kind != "sh":
        return
    d = str(s.tmp)
    hook, cap, got = oc_capture_hook(s)
    svc = {"LC_SIMPLETERM_TAB": MK_C, "SIMPLETERM": "1", "TMUX": "/tmp/tmux-501/first,1,0", "TMUX_PANE": "%0",
           "HERDR_TAB_ID": "w9:t9", "HERDR_WORKSPACE_ID": "w9", "HERDR_STARTUP_CWD": "/x"}
    env = dict(svc, SIMPLETERM_HOOK_TEST="1", SIMPLETERM_OC_HOOK=str(hook), SIMPLETERM_OC_CAPTURE=str(cap))
    n = [0]

    def ev(typ, **data):
        n[0] += 1
        return {"event": {"id": "evt_t%d" % n[0], "type": typ, "location": {"directory": d}, "data": data}}

    def ask(sid):
        return ev("permission.asked", id="per_" + sid, sessionID=sid, action="shell", resources=["make"])

    def claim(pid, cur, seen=(), tab=MK_A, st=True, env_=None, **kw):
        return {"claim": dict({"v": 1, "pid": pid, "t": "$now", "tab": tab, "st": st, "env": env_ or {}, "cur": cur,
                               "seen": list(seen)}, **kw)}

    sess = {sid: {"title": sid, "location": {"directory": d}} for sid in
            ("ses_1", "ses_2", "ses_3", "ses_4", "ses_5", "ses_6", "ses_7", "ses_9", "ses_v1", "ses_v2", "ses_v3", "ses_v4")}
    sess["ses_1c"] = {"parentID": "ses_1", "location": {"directory": d}}

    def run(steps, wait=4000, **kw):
        cap.write_text("")
        sc = dict({"directory": d, "env": env, "rpc": True, "sleepers": 3, "sessions": sess, "steps": steps, "wait": wait}, **kw)
        return node_plugin(s, "v2", sc), got()

    def of(rows, sid, event="PermissionRequest"):
        return [r for r in rows if r[1].get("session_id") == sid and r[1].get("hook_event_name") == event]

    def one(rows, sid, bg, st=True):
        r = of(rows, sid)
        t = r[0][1].get("oc_tab", {}) if r else {}
        return len(r) == 1 and t.get("bind") == "one" and isinstance(t.get("pid"), int) and t.get("bg") == bg and t.get("st") is st

    tm = {"TMUX": "/tmp/tmux-501/default,77,0", "TMUX_PANE": "%3"}
    A = claim("$p0", "ses_1", ["ses_2", "ses_4"], env_=tm)
    B = claim("$p1", "ses_3", ["ses_2"], tab=MK_B, st=False)
    calls, rows = run([A, B] + [ask(x) for x in ("ses_1", "ses_4", "ses_2", "ses_3", "ses_1c", "ses_9")], wait=6000)
    r1 = of(rows, "ses_1")
    s.check("opencode tabs: the one TUI showing the session: its tab, SIMPLETERM and tmux variables, never the service's",
            one(rows, "ses_1", 0) and r1[0][0] == dict(tm, LC_SIMPLETERM_TAB=MK_A, SIMPLETERM="1"), str(rows)[:600])
    s.check("opencode tabs: a session only one TUI has as a tab: bound to it with bg 1", one(rows, "ses_4", 1), str(of(rows, "ses_4")))
    r2 = of(rows, "ses_2")
    s.check("opencode tabs: a tab of two TUIs: many with n, their markers and st; the service's values taken out",
            len(r2) == 1 and r2[0][1].get("oc_tab") == {"bind": "many", "n": 2, "cl": [MK_A, MK_B], "st": True} and r2[0][0] == {},
            str(r2))
    r3 = of(rows, "ses_3")
    s.check("opencode tabs: a TUI outside SimpleTerm's tab: its marker, no SIMPLETERM, st false",
            one(rows, "ses_3", 0, st=False) and r3[0][0] == {"LC_SIMPLETERM_TAB": MK_B}, str(r3))
    s.check("opencode tabs: a subagent's request is its root session's", one(rows, "ses_1c", 0), str(of(rows, "ses_1c")))
    r9 = of(rows, "ses_9")
    s.check("opencode tabs: a session no TUI names: none, nothing of the service's",
            len(r9) == 1 and r9[0][1].get("oc_tab") == {"bind": "none"} and r9[0][0] == {}, str(r9))
    # Two TUIs whose screens show the same session: many. A claim that comes 100 ms after the request: one.
    calls, rows = run([claim("$p0", "ses_5"), claim("$p1", "ses_5", tab=MK_B, st=False), ask("ses_5"), ask("ses_7"),
                       {"sleep": 100}, claim("$p2", "ses_7", tab=MK_C)])
    r5, r7 = of(rows, "ses_5"), of(rows, "ses_7")
    s.check("opencode tabs: two screens show it: many", len(r5) == 1 and r5[0][1].get("oc_tab", {}).get("bind") == "many"
            and r5[0][1]["oc_tab"].get("n") == 2, str(r5))
    s.check("opencode tabs: a request waits for a claim that comes late",
            one(rows, "ses_7", 0) and r7[0][0].get("LC_SIMPLETERM_TAB") == MK_C, str(r7))
    # Dropped claims: a gone process, 91 s old, another version, no pid, over 8 KiB, not an object.
    calls, rows = run([claim("$dead", "ses_1"), claim("$p0", "ses_2", t="$old"), claim("$p1", "ses_3", v=2),
                       claim(0, "ses_4"), claim("$p2", "ses_5", env_={"TMUX": "x" * 9000}), {"claim": "ses_6"},
                       ask("ses_1"), ask("ses_2"), ask("ses_3"), ask("ses_4"), ask("ses_5")], wait=6000)
    s.check("opencode tabs: a dead, old, other-version, pid-less or oversized claim is dropped",
            [of(rows, x)[0][1].get("oc_tab") if of(rows, x) else None for x in ("ses_1", "ses_2", "ses_3", "ses_4", "ses_5")]
            == [{"bind": "none"}] * 5, str(rows)[:600])
    # A claim older than the one held for that TUI (a timed-out call that arrives late) does not replace it.
    calls, rows = run([claim("$p0", "ses_1"), claim("$p0", "ses_2", t="$ago:3000"), ask("ses_1"), ask("ses_2")])
    s.check("opencode tabs: an older claim of the same TUI is dropped",
            one(rows, "ses_1", 0) and [r[1].get("oc_tab") for r in of(rows, "ses_2")] == [{"bind": "none"}], str(rows)[:600])
    # The screen's session: one View after 1 s on screen; a route that changes within 1 s and "" give none; a
    # claim sent again with the same cur gives no second one; running when the session runs a turn.
    calls, rows = run([claim("$p0", "ses_v1"), {"sleep": 1300}, claim("$p0", "ses_v1"), {"sleep": 1300},
                       claim("$p0", "ses_v2"), {"sleep": 400}, claim("$p0", "ses_v3"), {"sleep": 1300},
                       claim("$p0", ""), {"sleep": 1300},
                       ev("session.execution.started", sessionID="ses_v4"), claim("$p0", "ses_v4"), {"sleep": 1500}])
    views = [(r[1].get("session_id"), r[1].get("view_state"), (r[1].get("oc_tab") or {}).get("bg"), r[1].get("cwd"))
             for r in rows if r[1].get("hook_event_name") == "View"]
    s.check("opencode tabs: View once per session that stayed 1 s on screen (idle, or running in a turn), bound without bg",
            views == [("ses_v1", "idle", 0, d), ("ses_v3", "idle", 0, d), ("ses_v4", "running", 0, d)], str(views))
    # A deleted session's record goes; another's stays.
    rec = s.home / ".simpleterm" / "sessions" / "opencode"
    rec.mkdir(parents=True, exist_ok=True)
    for name in ("ses_del.json", "ses_del.beat", "ses_keep.json"):
        (rec / name).write_text("{}\n")
    run([ev("session.deleted", sessionID="ses_del")], wait=2000)
    s.check("opencode tabs: session.deleted removes the session's record", sorted(p.name for p in rec.iterdir()) == ["ses_keep.json"],
            str(sorted(p.name for p in rec.iterdir())))
    # No plugin RPC (a build without it): the hook gets no oc_tab and the service's environment, as with 0.9.0.
    calls, rows = run([ask("ses_1")], rpc=False)
    r1 = of(rows, "ses_1")
    s.check("opencode tabs: without the plugin RPC, no oc_tab and the service's environment",
            len(r1) == 1 and "oc_tab" not in r1[0][1] and r1[0][0].get("LC_SIMPLETERM_TAB") == MK_C, str(r1))


def t_opencode_tab_events(s):
    """OpenCode 2.x events and records with the tab claims, end to end through the real hook (SimpleTerm
    if/hook-tab-opencode#events, #view-state, if/event-v2#common-fields bg, if/session-record#opencode2): the bound
    TUI's tab, multiplexer, pane and msock; bg 1 to the tunnel only; many and none as c daemon with mux unknown; View
    as one state though the same state went last, with no record; a new record only for a session a SimpleTerm TUI
    names, at its prompt, with the bound TUI's multiplexer, kept up at every event, its mux changed only by an event
    bound to one TUI without bg."""
    if not NODE or s.kind != "sh":
        return
    d = str(s.tmp)
    tun, tctl = s.spawn_mock()
    try:
        s.setup([(LINK_T, {"kind": "tunnel", "relay_url": tctl.url, "fmt": 2}), (LINK_A, {"fmt": 2})])
        rec = s.home / ".simpleterm" / "sessions" / "opencode"
        n = [0]

        def ev(typ, **data):
            n[0] += 1
            return {"event": {"id": "evt_e%d" % n[0], "type": typ, "location": {"directory": d}, "data": data}}

        def turn(sid):
            return [ev("session.execution.started", sessionID=sid), ev("session.execution.succeeded", sessionID=sid)]

        def claim(pid, cur, seen=(), tab=MK_A, st=True, env_=None):
            return {"claim": {"v": 1, "pid": pid, "t": "$now", "tab": tab, "st": st, "env": env_ or {}, "cur": cur, "seen": list(seen)}}

        sess = {sid: {"title": "T " + sid, "location": {"directory": d}} for sid in ("ses_1", "ses_2", "ses_3", "ses_4", "ses_9", "ses_v")}
        tm = {"TMUX": "/tmp/tmux-501/default,77,0", "TMUX_PANE": "%3"}

        def run(steps, wait=5000):
            s.ctl("/_ctl/reset", {})
            tctl("/_ctl/reset", {})
            tctl("/_ctl/config", {"links": {LINK_T["id"]: dict(LINK_T)}})
            return node_plugin(s, "v2", {"directory": d, "rpc": True, "sleepers": 3, "sessions": sess, "steps": steps, "wait": wait})

        def tunnel(ev_, sid):
            return [(r.get("plain_json") or {}) for r in ingests(s, ctl=tctl)
                    if (r.get("body") or {}).get("ev") == ev_ and (r.get("plain_json") or {}).get("sid") == sid]

        def relay(ev_, sid):
            return [(r.get("plain_json") or {}) for r in ingests(s, ev_) if (r.get("plain_json") or {}).get("sid") == sid]

        def record(sid):
            p = rec / (sid + ".json")
            return json.loads(p.read_text()) if p.exists() else None

        # ses_9 has a record from before: it is kept up whatever the claims say.
        rec.mkdir(parents=True, exist_ok=True)
        (rec / "ses_9.json").write_text(json.dumps({"v": 1, "app": "opencode", "sid": "ses_9", "dir": d, "last_at": 1,
                                                    "started_at": 1, "state": "running", "mux": "tmux"}) + "\n")
        A = claim("$p0", "ses_1", ["ses_2", "ses_4"], env_=tm)
        B = claim("$p1", "ses_3", ["ses_2"], tab=MK_B, st=False)
        run([A, B] + turn("ses_1") + turn("ses_4") + turn("ses_2") + turn("ses_3") + turn("ses_9"), wait=8000)
        wait_for(lambda: len(tunnel("done", "ses_9")) and len(relay("done", "ses_4")), 20)
        s.settle("the plugin's hooks' background work")
        st1 = tunnel("state", "ses_1")
        s.check("opencode events: a tmux TUI's session: its multiplexer, pane, msock and tab, no bg",
                st1 and st1[0].get("mux") == "tmux" and st1[0].get("pane") == "%3" and st1[0].get("msock") == "/tmp/tmux-501/default"
                and (st1[0].get("tab") or {}).get("st") == "c" and (st1[0].get("tab") or {}).get("why") == "mux" and "bg" not in st1[0],
                str(st1)[:400])
        t4, r4 = tunnel("done", "ses_4"), relay("done", "ses_4")
        s.check("opencode events: a session in another tab of the TUI: bg 1 on the tunnel only",
                t4 and t4[0].get("bg") == 1 and t4[0].get("pane") == "%3" and r4 and "bg" not in r4[0], str(t4)[:300] + str(r4)[:300])
        t2 = tunnel("done", "ses_2")
        s.check("opencode events: many: c daemon with n and the markers, mux unknown, no pane",
                t2 and t2[0].get("tab") == {"st": "c", "why": "daemon", "n": 2, "cl": [MK_A, MK_B]} and t2[0].get("mux") == "unknown"
                and "pane" not in t2[0], str(t2)[:300])
        t3 = tunnel("done", "ses_3")
        s.check("opencode events: a TUI in a tab with a marker: a", t3 and t3[0].get("tab") == {"st": "a", "tm": MK_B}
                and "mux" not in t3[0], str(t3)[:300])
        t9 = tunnel("done", "ses_9")
        s.check("opencode events: none: c daemon without n, mux unknown", t9 and t9[0].get("tab") == {"st": "c", "why": "daemon"}
                and t9[0].get("mux") == "unknown", str(t9)[:300])
        r1, r2, r3, r9 = record("ses_1"), record("ses_2"), record("ses_3"), record("ses_9")
        s.check("opencode records: made for the sessions a SimpleTerm TUI names, with the bound TUI's multiplexer",
                r1 and r1.get("mux") == "tmux" and r1.get("dir") == d and r1.get("state") == "idle"
                and r2 and r2.get("mux") == "unknown" and record("ses_4") and r3 is None, str((r1, r2, r3)))
        s.check("opencode records: a record from before is kept up though no TUI names its session",
                r9 and r9.get("state") == "idle" and r9.get("last_at", 0) > 1 and r9.get("mux") == "tmux", str(r9))
        # The mux of a record: not changed by an event bound to many or with bg, changed by one bound to one TUI.
        run([claim("$p0", "ses_x", ["ses_1"]), claim("$p1", "ses_y", ["ses_1"], tab=MK_B)] + turn("ses_1"))
        wait_for(lambda: len(tunnel("done", "ses_1")), 20)
        s.settle("the plugin's hooks' background work")
        m_many = (record("ses_1") or {}).get("mux")
        run([claim("$p0", "ses_x", ["ses_1"])] + turn("ses_1"))
        wait_for(lambda: len(tunnel("done", "ses_1")), 20)
        s.settle("the plugin's hooks' background work")
        m_bg = (record("ses_1") or {}).get("mux")
        run([claim("$p2", "ses_1", tab=MK_C)] + turn("ses_1"))
        wait_for(lambda: len(tunnel("done", "ses_1")), 20)
        s.settle("the plugin's hooks' background work")
        s.check("opencode records: mux kept at many and bg, the plain tab's (none) at one without bg",
                m_many == "tmux" and m_bg == "tmux" and "mux" not in (record("ses_1") or {"mux": 1}), str((m_many, m_bg, record("ses_1"))))
        # View: one state though the same state went last; no done, no record of its own.
        run([claim("$p0", "ses_v"), ev("session.execution.started", sessionID="ses_v"), {"sleep": 2500}])
        wait_for(lambda: len(tunnel("state", "ses_v")) >= 2, 10)
        s.settle("the plugin's hooks' background work")
        sv = [x.get("st") for x in tunnel("state", "ses_v")]
        s.check("opencode events: View sends its state though the same one went last, and no done",
                sv == ["running", "running"] and not tunnel("done", "ses_v"), str(sv))
        s.check("opencode records: View leaves the record as the prompt made it", (record("ses_v") or {}).get("state") == "running",
                str(record("ses_v")))
        # No link and no SimpleTerm (the plugin only): the hook leaves before ~/.simpleterm/run as 0.9.0 did; a session
        # that a SimpleTerm TUI names (oc_tab st) is recorded all the same.
        s.setup([])
        run_dir = s.home / ".simpleterm" / "run"
        shutil.rmtree(run_dir, ignore_errors=True)
        base = {"hook_event_name": "UserPromptSubmit", "cwd": d, "oc": "2", "prompt": "hi"}
        s.run("opencode", json.dumps(dict(base, session_id="ses_n1", oc_tab={"bind": "none"}), separators=(",", ":")))
        s.check("opencode: no link, no SimpleTerm, no SimpleTerm TUI: the hook leaves before its run folder",
                not run_dir.exists() and record("ses_n1") is None, str(list(run_dir.glob("*")) if run_dir.exists() else ""))
        s.run("opencode", json.dumps(dict(base, session_id="ses_n2", oc_tab={"bind": "many", "n": 2, "cl": [], "st": True}),
                                     separators=(",", ":")))
        s.check("opencode records: no link, a session a SimpleTerm TUI names: recorded", record("ses_n2") is not None,
                str(list(rec.glob("*")) if rec.exists() else ""))
    finally:
        tun.terminate()
        tun.wait(5)


def t_opencode_automation(s):
    """OpenCode 2.4 automations (SimpleTerm if/hook-events-scheduled#by-schedule, hist/turn-state#d27; the events and
    automation_list output of 2.4.1, 2026-11-24): an automation's prompt (payload.metadata.automation, or the inbox id
    msg_aut_<id>_<run> with or without _send) opens a scheduled turn; what is left is read with the automation tool of
    the namespace automation (not the browser's list), counting only active prompt automations to this session; a
    build that still has schedule_list reads that one."""
    if not NODE or s.kind != "sh":
        return
    d = str(s.tmp)
    tun, tctl = s.spawn_mock()
    try:
        s.setup([(LINK_A, {}), (LINK_T, {"kind": "tunnel", "relay_url": tctl.url, "fmt": 2})])
        n = [500]
        sid = "ses_df351777cffe2nLK4hfaSmumDU"
        aut = "aut_20cae892a001jolEx5V6vpKYaw"

        def ev(typ, **data):
            n[0] += 1
            return {"event": {"id": "evt_%d" % n[0], "type": typ, "location": {"directory": d}, "data": data}}

        def run_of(run, inbox=None, meta=True):
            inbox = inbox or "msg_%s_%d" % (aut, run)
            steps = []
            if meta:
                steps.append(ev("session.inbox.enqueued", sessionID=sid, inboxID=inbox, item={"type": "user", "payload": {
                    "text": "AUTO-A run", "metadata": {"automation": {"id": aut, "name": "A", "run": run, "dueAt": 1795509154698,
                                                                      "late": False}}}, "delivery": "steer"}))
            return steps + [ev("session.execution.started", sessionID=sid), ev("session.inbox.delivered", sessionID=sid, inboxID=inbox),
                            ev("session.execution.succeeded", sessionID=sid)]

        def auto(id_, status="active", typ="prompt", to=sid, trig=None):
            a = {"id": id_, "name": id_, "trigger": trig or {"type": "every", "every": "60 seconds"}, "tz": "Asia/Seoul",
                 "action": {"type": "prompt", "prompt": "P " + id_, "to": {"session": to}}, "status": status, "runCount": 1}
            if typ != "prompt":
                a["action"] = {"type": typ, "code": "x"}
            return a

        left = [auto(aut), auto("aut_other", to="ses_other"), auto("aut_code", typ="code"), auto("aut_paused", status="paused"),
                auto("aut_at", trig={"type": "at", "at": "2026-11-24T08:32:49.701Z"})]

        def run(steps, automations, **kw):
            s.ctl("/_ctl/reset", {})
            tctl("/_ctl/reset", {})
            tctl("/_ctl/config", {"links": {LINK_T["id"]: dict(LINK_T)}})
            return node_plugin(s, "v2", dict({"directory": d, "sessions": {sid: {"title": "Auto"}}, "automations": automations,
                                              "steps": steps, "wait": 3000}, **kw))

        def tunnel(ev_):
            return [(r.get("plain_json") or {}) for r in ingests(s, ctl=tctl) if (r.get("body") or {}).get("ev") == ev_]

        def scheduled():
            return [x for x in tunnel("state") if x.get("st") == "scheduled"]

        calls = run(run_of(1), left)
        st = wait_for(scheduled, 10)
        s.settle("the plugin's hooks' background work")
        crons = ((st[0].get("turn") or {}).get("crons") if st else None) or []
        s.check("opencode automation: a run with prompt automations to this session left -> scheduled, no done",
                st and (st[0].get("turn") or {}).get("by") == "schedule"
                and [c.get("sched") for c in crons] == ["every 60 seconds", "at 2026-11-24T08:32:49.701Z"]
                and [c.get("prompt") for c in crons] == ["P " + aut, "P aut_at"]
                and not tunnel("done") and not ingests(s, "done"), str(st)[:400] + str(ingests(s))[:200])
        s.check("opencode automation: automation_list of the automation namespace, not the browser's list",
                [c.get("tool") for c in calls if "tool" in c] == ["automation_list"], str(calls)[:400])
        # The screen turns to the session at its scheduled pause: no View state (idle would end the pause in the app,
        # if/hook-tab-opencode#view-state).
        view = [{"claim": {"v": 1, "pid": "$p0", "t": "$now", "tab": MK_A, "st": True, "env": {}, "cur": sid, "seen": []}},
                {"sleep": 2500}]
        run(view, left, rpc=True, sleepers=1)
        s.settle("the plugin's hooks' background work")
        s.check("opencode automation: a View at the scheduled pause sends no state", not tunnel("state"), str(tunnel("state"))[:300])
        # The last run: only a code automation, another session's and a paused one are left -> done by schedule, tunnel only.
        run(run_of(2), [auto(aut, status="done"), auto("aut_other", to="ses_other"), auto("aut_code", typ="code"),
                        auto("aut_paused", status="paused")])
        dn = wait_for(lambda: tunnel("done"), 10)
        s.settle("the plugin's hooks' background work")
        s.check("opencode automation: nothing of this session's left -> done by schedule to the tunnel only",
                dn and (dn[0].get("turn") or {}).get("by") == "schedule" and not ingests(s, "done"), str(dn)[:300] + str(ingests(s))[:300])
        # No pause after that done: a View sends idle.
        run(view, [], rpc=True, sleepers=1)
        vi = wait_for(lambda: tunnel("state"), 10)
        s.settle("the plugin's hooks' background work")
        s.check("opencode automation: a View after the last run's done sends idle", [x.get("st") for x in vi or []] == ["idle"],
                str(vi)[:300])
        # No enqueued item (a plugin that came up late): the inbox id alone tells it, with or without _send.
        for label, inbox in (("msg_aut_", "msg_%s_3" % aut), ("msg_aut_ _send", "msg_%s_4_send" % aut)):
            run(run_of(3, inbox=inbox, meta=False), [])
            dn = wait_for(lambda: tunnel("done"), 10)
            s.settle("the plugin's hooks' background work")
            s.check("opencode automation: a delivered %s id alone -> the automation's turn" % label,
                    dn and (dn[0].get("turn") or {}).get("by") == "schedule" and not ingests(s, "done"), str(dn)[:300])
        # A build with schedule_list (2.2.3 to 2.3.x) reads it, not the automations.
        calls = run(run_of(5), left, schedules={sid: [{"id": "sch_1", "sessionID": sid, "name": "s", "when": {"type": "every",
                                                                                                         "every": "15 seconds"},
                                                       "action": {"type": "prompt", "prompt": "tick"}, "status": "active"}]})
        st = wait_for(scheduled, 10)
        s.settle("the plugin's hooks' background work")
        s.check("opencode automation: schedule_list first when the build has it",
                [c for c in calls if "schedule_list" in c] and not [c for c in calls if "tool" in c]
                and [c.get("sched") for c in (((st[0].get("turn") or {}).get("crons") or []) if st else [])] == ["every 15 seconds"],
                str(calls)[:400] + str(st)[:300])
    finally:
        tun.terminate()
        tun.wait(5)


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
    s.settle("the plugin's hooks' background work")
    s.check("opencode 1.x: session.idle -> done with the session title, subagents skipped",
            len(ingests(s, "done")) == 1 and rec[0]["plain_json"].get("msg") == "Fix the tests", str(ingests(s))[:300])
    # The session's tokens and cost (session info) reach the usage event (SimpleTerm if/usage-report#agents).
    info = {"title": "Fix the tests", "cost": 0.25, "tokens": {"input": 100, "output": 20, "reasoning": 5, "cache": {"read": 50, "write": 10}}}
    want = {"usd": 0.25, "tok_in": 160, "tok_out": 25, "scope": "session"}
    for kind, steps in (("v1", [{"event": {"type": "session.idle", "properties": {"sessionID": "ses_1"}}}]),
                        ("v2", [{"event": {"id": "evt_c", "type": "session.execution.succeeded", "location": {"directory": d}, "data": {"sessionID": "ses_1"}}}])):
        s.setup([(LINK_A, {"push": "disabled", "kind": "tunnel"})])
        node_plugin(s, kind, {"directory": d, "sessions": {"ses_1": info}, "steps": steps, "wait": 3000})
        u = wait_for(lambda: ingests(s, "usage"), 20)
        s.check("opencode %s: the session's tokens and cost in the usage event" % kind,
                u and u[0]["plain_json"].get("cost") == want, str(u[0].get("plain_json") if u else None)[:300])
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
    s.settle("the plugin's hooks' background work")
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
    s.settle("the plugin's hooks' background work")
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
        s.settle("the plugin's hooks' background work")
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
        s.settle("the plugin's hooks' background work")
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
    s.settle("the pauses' waits (bg_done_after, 2 s)")
    done = ingests(s, "done")
    s.check("opencode 2.x: a long turn after a pause gets no done before its own end",
            len(done) == 1 and done[0]["received"] - t0 > 3.5, str([(r["plain_json"].get("msg"), round(r["received"] - t0, 2)) for r in done]))
    # (bg_done_after 10: "at once" means well before the first pause's timer; generous for a loaded machine)
    t0 = running_turns("unknown shell, second turn", "node worker.js", 2, conf={"bg_done_after": 10})
    wait_for(lambda: ingests(s, "done"), 20)
    first = ingests(s, "done")
    s.settle("the first pause's wait (bg_done_after, 10 s)")
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
    s.settle("the plugin's hooks' background work")
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


def t_hooks_removed_plugin(s):
    """A session still running after its plugin is removed still runs the hook commands it registered at start
    (SimpleTerm if/plugin-locations#manifests, hist/plugin-locations#d3, #e5; issue AhMunGa/simple-term#686). With the
    script gone the command ends with exit 0 and prints nothing on stdout, in the shell the agent runs it with: Gemini
    CLI reads another exit code with text as `deny`, and a denied AfterAgent runs the agent again (one prompt made 36
    model calls, measured on 0.66.0 with a stub). Gemini CLI runs a hook with `bash -c` on Unix and with PowerShell
    `-Command` (the command + `; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }`) on Windows (0.66.0 bundle,
    getShellConfiguration). The Copilot and Antigravity commands find their script themselves (same rule)."""
    gone = s.tmp / "removed-plugin"
    there = s.tmp / "kept-plugin"
    home = s.tmp / "removed-home"
    for d in (gone, there / "plugins" / "simpleterm" / "scripts", home):
        d.mkdir(parents=True, exist_ok=True)
    rec = home / "ran.log"
    if rec.exists():
        rec.unlink()
    (there / "plugins" / "simpleterm" / "scripts" / "agent-hook.sh").write_text(
        '#!/bin/sh\ncat > /dev/null\necho "ran $*" >> "%s"\n' % rec)
    env = {"HOME": str(home), "PATH": "/usr/bin:/bin", "LANG": "en_US.UTF-8"}

    def run(argv, cwd):
        p = subprocess.run(argv, input=b"{}", capture_output=True, env=env, cwd=str(cwd), timeout=60)
        return p.returncode, p.stdout.decode("utf-8", "replace")

    if s.kind == "ps1":
        def shell(c):
            return [s.argv[0], "-NoProfile", "-NonInteractive", "-Command", c + "; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }"]
    else:
        def shell(c):
            return ["bash", "-c", c]
    gem = json.loads((ROOT / "hooks" / "hooks.json").read_text())
    cmds = [(ev, h["command"]) for ev, groups in gem["hooks"].items() for g in groups for h in g["hooks"]]
    got = [(ev,) + run(shell(c.replace("${extensionPath}", str(gone))), home) for ev, c in cmds]
    s.check("removed plugin: Gemini hook commands (%s) end with 0 and print nothing" % ("PowerShell" if s.kind == "ps1" else "bash -c"),
            len(cmds) == 2 and all(rc == 0 and out == "" for _, rc, out in got), str(got))
    got = [(ev,) + run(shell(c.replace("${extensionPath}", str(there))), home) for ev, c in cmds]
    ran = rec.read_text().splitlines() if rec.exists() else []
    s.check("kept plugin: the Gemini hook commands run the script with `gemini`",
            all(rc == 0 and out == "" for _, rc, out in got) and ran == ["ran gemini"] * len(cmds), "%s ran=%s" % (got, ran))
    if s.kind != "sh":
        return
    cp = json.loads(COPILOT_HOOKS.read_text())
    got = [(ev,) + run(["bash", "-c", h["bash"]], gone) for ev, groups in cp["hooks"].items() for h in groups]
    s.check("removed plugin: Copilot hook commands end with 0 and print nothing",
            got and all(rc == 0 and out == "" for _, rc, out in got), str(got))
    def commands(x, ev=""):
        if isinstance(x, dict):
            if isinstance(x.get("command"), str):
                yield ev, x["command"]
            for k, v in x.items():
                yield from commands(v, k if isinstance(v, list) else ev)
        elif isinstance(x, list):
            for v in x:
                yield from commands(v, ev)
    ag = json.loads((ROOT / "plugins" / "antigravity" / "hooks.json").read_text())
    got = [(ev,) + run(["bash", "-c", c], gone) for ev, c in commands(ag)]
    # (Antigravity's PreToolUse answers its neutral `allow` when it finds no script.)
    s.check("removed plugin: Antigravity hook commands end with 0 (nothing, or PreToolUse's allow)",
            got and all(rc == 0 and out in ("", '{"decision":"allow"}\n') for _, rc, out in got), str(got))


def copies_check():
    """Plugins that are installed on their own carry copies of the scripts; they must not drift."""
    bad = []
    for copy, master in COPIES:
        a, b = ROOT / copy, ROOT / master
        if not a.exists() or a.read_bytes() != b.read_bytes():
            bad.append("%s differs from %s (cp %s %s)" % (copy, master, master, copy))
    return bad


TESTS = [t_vectors, t_background, t_allow_deny, t_codex_allow, t_invalid_dmac, t_timeout, t_multi_link,
         t_tunnel, t_revoked, t_missing_deps, t_simpleterm_gating, t_local_answer, t_same_second_prompt, t_notifications, t_background_work, t_background_work_kinds, t_background_screen_values, t_background_screen_clear, t_question_while_background, t_copilot_session_end, t_usage_ask_deadline, t_service_shells, t_user_prompt_old_tasks, t_schedules, t_schedule_end, t_done_delay, t_background_events_and_badges, t_small_audit_fixes, t_codex_goal, t_agent_gone, t_events,
         t_hostile_input, t_log, t_argv, t_external_printf,
         t_usage_claude, t_usage_window, t_usage_claude_big, t_usage_claude_huge, t_usage_statusline, t_usage_relay_policy, t_usage_delivery, t_usage_codex, t_codex_hooks, t_gemini, t_notify,
         t_cli_wrapper, t_notify_no_tty, t_agy, t_agy_schedule, t_agy_paths, t_grok, t_opencode_sh, t_auth_end, t_auth_end_state, t_opencode_js, t_opencode_schedule,
         t_opencode_automation, t_opencode_tui, t_opencode_tabs, t_opencode_tab_events,
         t_v2_fixtures, t_v2_dext_vector, t_v2_decisions, t_v2_param_keys, t_v2_input_drain, t_v2_usage, t_v2_usage_ask, t_v2_usage_ask_gate, t_v2_usage_ask_refresh, t_usage_ask_refresh_vectors, t_conf_vectors, t_v2_n10, t_v2_link_results, t_v2_link_waits, t_v2_held, t_v2_held_bg, t_v2_not_sent,
         t_v2_state, t_v2_state_turns, t_sub_sessions, t_v2_sessions, t_v2_mux, t_v2_tab, t_v2_opencode_js, t_copilot_hooks, t_copilot, t_copilot_schedules,
         t_v2_versions, t_v2_claude_question_once, t_hooks_removed_plugin]

# The cases where the shell and openssl meet (the compat set): the openssl calls (random hex, SHA-256 read
# by awk, the HMAC whose key blocks printf writes, the AES-256-CBC envelope and dext, base64 both ways),
# the byte-exact events and terminal sequences, and the shell's own reading of input, settings and argv.
COMPAT = {"t_vectors", "t_allow_deny", "t_invalid_dmac", "t_missing_deps", "t_hostile_input", "t_argv", "t_external_printf",
          "t_background_screen_values", "t_v2_fixtures", "t_v2_dext_vector", "t_v2_decisions", "t_usage_ask_refresh_vectors",
          "t_conf_vectors"}

# Tests of the sh hook only (scripts and behaviour the PowerShell hook does not have).
SH_ONLY = {"t_copilot_session_end", "t_v2_versions", "t_v2_n10", "t_v2_opencode_js", "t_copilot_hooks", "t_copilot", "t_copilot_schedules", "t_usage_claude_big", "t_usage_claude_huge", "t_codex_hooks", "t_usage_delivery", "t_usage_statusline", "t_usage_relay_policy", "t_gemini", "t_notify", "t_notify_no_tty", "t_cli_wrapper",
           "t_agy", "t_agy_schedule", "t_agy_paths", "t_opencode_sh", "t_opencode_js", "t_opencode_schedule",
           "t_opencode_automation", "t_opencode_tui", "t_opencode_tabs", "t_opencode_tab_events"}


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


PWSH_TIMEOUT = 60


def pwsh_out(pwsh, script):
    """What `pwsh -Command script` prints, run in a HOME of its own (pwsh writes caches there); None when
    it does not run to the end: it cannot start, takes over PWSH_TIMEOUT s, or exits with an error."""
    home = tempfile.mkdtemp(prefix="st-pwsh-")
    env = {"HOME": home, "PATH": "/usr/bin:/bin", "POWERSHELL_TELEMETRY_OPTOUT": "1", "POWERSHELL_UPDATECHECK": "Off"}
    try:
        p = subprocess.run([pwsh, "-NoProfile", "-NonInteractive", "-Command", script], capture_output=True, text=True,
                           timeout=PWSH_TIMEOUT, env=env)
        return p.stdout if p.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        return None
    finally:
        shutil.rmtree(home, ignore_errors=True)


def ps_parse_check(pwsh):
    """The parse errors in agent-hook.ps1, one line each. A parse that does not run to the end is one too:
    no output is not a pass."""
    script = ("$e=$null;$t=$null;[void][System.Management.Automation.Language.Parser]::ParseFile('%s',[ref]$t,[ref]$e);"
              "$e | ForEach-Object { $_.Extent.StartLineNumber.ToString() + ': ' + $_.Message }") % HOOK_PS1
    out = pwsh_out(pwsh, script)
    if out is None:
        return ["the parse did not run to the end (could not start, over %d s, or exited with an error)" % PWSH_TIMEOUT]
    return [l for l in out.splitlines() if l.strip()]


def pwsh_major(pwsh):
    """PowerShell's major version, 0 when `pwsh` is not PowerShell or does not answer (a parse check alone
    passes anything that prints nothing)."""
    out = (pwsh_out(pwsh, "'PS ' + $PSVersionTable.PSVersion.Major") or "").strip()
    return int(out[3:]) if re.fullmatch(r"PS \d+", out) else 0


def shell_works(sh):
    try:
        return subprocess.run([sh, "-c", "echo ok"], capture_output=True, text=True, timeout=10).stdout == "ok\n"
    except (OSError, subprocess.SubprocessError):
        return False


# Tests that keep the CPU busy (t_service_shells: some 200 Stop hooks, about 40 s of CPU a suite):
# at most two suites run one at a time, so the others' timed checks do not run on a machine loaded
# far past its cores (the full matrix runs ten suites at once).
HEAVY = {"t_service_shells": threading.Semaphore(2), "t_v2_held": threading.Semaphore(3), "t_v2_held_bg": threading.Semaphore(3)}


def leftovers():
    """What the run left running: this run's processes (ours(): the suites' groups and folders, and
    this run's own group, if it has one, but for this process and its `ps`)."""
    rows = observe(command=True)
    if rows is None:
        return ["(ps failed: cannot tell)"]
    return ["%d %s" % (pid, r[4][:140]) for pid, r in sorted(ours(rows, groups=own_group()).items())]


def run_suite(suite, only):
    for t in TESTS:
        if only and t.__name__ not in only:
            continue
        if suite.kind == "ps1" and (t is t_missing_deps or t.__name__ in SH_ONLY):
            continue
        if suite.cases == "compat" and t.__name__ not in COMPAT:
            continue
        sem = HEAVY.get(t.__name__)
        if sem:
            sem.acquire()
        suite.case = t.__name__
        try:
            t(suite)
        except Exception as e:  # report and continue with the next case
            suite.check("%s raised" % t.__name__, False, repr(e))
        finally:
            suite.reap()
            suite.screen_report()
            if sem:
                sem.release()
    # Every hook output of every case, not one case's: Claude Code drops a whole terminalSequence for one sequence
    # outside its allowlist, and an output check alone never sees that (SimpleTerm hist/hook-events#e28).
    if suite.seq_n:
        suite.check("terminalSequence allowlist: %d hook outputs checked" % suite.seq_n, True)


def own_group():
    """This run's process group, {pgid}, when this process leads it (run_in_own_group); else empty: a
    child whose setpgid failed is still in its parent's group, which may be the user's shell's or a
    pipeline's, and that group is not this run's."""
    g = os.getpgrp()
    return {g} if g == os.getpid() else set()


def end_ours():
    """Ends every process of this run but this one (ours(): the suites' groups and folders, and this run's group
    if it has one, own_group): TERM, then KILL to what is left a second later. The hooks a case starts lead
    sessions of their own (Suite.popen), so a TERM to the run's group does not reach them."""
    groups = own_group()
    for sig in (signal.SIGTERM, signal.SIGKILL):
        rows = observe()
        pids = ours(rows, groups=groups) if rows is not None else {}
        for p in pids:
            try:
                os.kill(p, sig)
            except OSError:
                pass
        if not pids or sig == signal.SIGKILL:
            break
        wait_for(lambda: not ours(observe() or [], groups=groups), 1, 0.1)


def run_in_own_group(run):
    """Runs `run()` (the suites) in a child that leads its own process group, then stops that
    group. The child's processes, and the hooks the suites start in sessions of their own with
    the background sends they leave sleeping (bg_done_after waits up to 600 s), end with the run:
    each case reaps its own, and a TERM to the child (from here, when this process is ended or
    interrupted) ends them all (end_ours) before the child exits. Only the child's group is
    signalled from here: this process may share its group with others (a `python run_tests.py |
    tail` under job control), and it stays in the terminal's group (Ctrl+C reaches it). Returns
    the child's exit code."""
    sys.stdout.flush()
    sys.stderr.flush()
    pid = os.fork()
    if pid == 0:
        try:
            os.setpgid(0, 0)
        except OSError:
            pass
        code = 1

        def child_term(signum, frame):
            raise KeyboardInterrupt
        signal.signal(signal.SIGTERM, child_term)
        try:
            run()
        except SystemExit as e:
            code = e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
        except KeyboardInterrupt:
            code = 143
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            end_ours()
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

    def term(signum, frame):
        raise KeyboardInterrupt
    # `timeout` (or any TERM) ends this process: the child's group goes with it (finally below), or it would run on
    # with nothing reading its output.
    signal.signal(signal.SIGTERM, term)
    try:
        _, status = os.waitpid(pid, 0)
        code = os.waitstatus_to_exitcode(status) if hasattr(os, "waitstatus_to_exitcode") else (status >> 8)
    except KeyboardInterrupt:
        code = 130
    finally:
        old = signal.signal(signal.SIGTERM, signal.SIG_IGN)
        try:
            os.killpg(pid, signal.SIGTERM)
            # (What does not take TERM within 5 seconds gets KILL: the child ends the hooks first, end_ours.)

            def gone():
                try:
                    os.killpg(pid, 0)
                    return False
                except OSError:
                    return True
            if not wait_for(gone, 5, 0.1):
                os.killpg(pid, signal.SIGKILL)
        except OSError:
            pass
        finally:
            signal.signal(signal.SIGTERM, old)
        try:
            os.waitpid(pid, os.WNOHANG)
        except OSError:
            pass
    return code


def openssl_kind(path):
    """'openssl3', 'libressl' or None (not there / neither) from `openssl version`."""
    try:
        v = subprocess.run([path, "version"], capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    return "libressl" if v.startswith("LibreSSL") else "openssl3" if re.match(r"OpenSSL 3\.", v) else None


# The environments (AhMunGa/simple-term#449). Every plugin runs the hook by `sh` (the hook commands,
# OpenCode's spawn("sh")), whatever the user's shell: what counts is each server OS's /bin/sh and openssl.
#   ubuntu   Debian, Ubuntu: dash, OpenSSL 3                 /bin/dash + OpenSSL 3      every case
#   macos    macOS: bash 3.2 in sh mode, LibreSSL            /bin/sh + /usr/bin/openssl every case
#   windows  Windows PowerShell 5.1 and PowerShell 7          pwsh 7 (its own HOME)      every case, and
#            the static check that the script runs on 5.1 (ps51_static_check)
#   compat   bash in sh mode with OpenSSL 3 (macOS with Homebrew's openssl first in PATH; RHEL, Fedora
#            and Arch run bash 5 so)                         /bin/sh + OpenSSL 3        COMPAT only
# Not run: zsh (no OS has it as /bin/sh), ksh93 (no target's /bin/sh; OpenBSD's ksh is pdksh), bash out of
# sh mode (macOS runs the hook by /bin/sh). busybox ash (Alpine) is dash's kin. Another shell (a bash 5):
# `--shell PATH --suite compat`.
ENVIRONMENTS = [("ubuntu", "/bin/dash", "openssl3", "full"), ("macos", "/bin/sh", "libressl", "full"),
                ("compat", "/bin/sh", "openssl3", "compat")]
LIBRESSL = "/usr/bin/openssl"  # macOS's
OPENSSL3 = ("/opt/homebrew/bin/openssl", "/usr/local/bin/openssl", "/usr/bin/openssl")  # Homebrew's, or a Linux's own


def select_environments(args):
    """(suites, missing, pwsh) for the arguments. Only what the asked suites need is looked for, and an
    environment that cannot run is one failure (`missing`), not a quiet gap. windows (pwsh) is part of
    the full suite and runs the plugin's PowerShell hook: --suite compat, --no-pwsh, --shell and --hook
    (both about the sh hook) leave it out, whatever --pwsh says or PATH holds."""
    sets = args.suite or ["full", "compat"]
    missing = []
    found = {}

    def openssl(kind):
        if kind not in found:
            cands = [LIBRESSL] if kind == "libressl" else [args.openssl] if args.openssl else list(OPENSSL3)
            found[kind] = next((p for p in cands if openssl_kind(p) == kind), None)
        return found[kind]

    def wanted(kind):
        if kind == "libressl":
            return "LibreSSL at " + LIBRESSL
        return "OpenSSL 3 at " + (args.openssl or " or ".join(OPENSSL3)) + " (--openssl PATH)"

    suites = []
    hook_ok = not args.hook or os.path.isfile(args.hook)
    if not hook_ok:
        missing.append("--hook %s: no such file" % args.hook)
    if not args.no_sh and hook_ok:
        if args.shell:
            # Another shell: every case, or the compat set when only that was asked; OpenSSL 3 (LibreSSL when
            # there is none and none was named).
            cases = "compat" if set(sets) == {"compat"} else "full"
            kind = "openssl3" if args.openssl or openssl("openssl3") else "libressl"
            envs = [(cases, sh, kind, cases) for sh in args.shell]
        else:
            envs = [e for e in ENVIRONMENTS if e[3] in sets]
        for name, sh, kind, cases in envs:
            why = ([] if shell_works(sh) else ["%s does not run `sh -c`" % sh]) + ([] if openssl(kind) else ["no " + wanted(kind)])
            if why:
                missing.append("%s: cannot run (%s)" % (name, "; ".join(why)))
            else:
                suites.append(Suite("%s %s+%s" % (name, sh, kind), [sh, str(HOOK_SH)], openssl(kind), cases=cases))
    pwsh = None
    if "full" in sets and not (args.no_pwsh or args.shell or args.hook):
        cand = args.pwsh or shutil.which("pwsh")
        if not cand:
            missing.append("windows: no pwsh in PATH (--pwsh PATH, or --no-pwsh to leave it out)")
        elif pwsh_major(cand) < 7:
            missing.append("windows: %s is not PowerShell 7 (--pwsh PATH, or --no-pwsh to leave it out)" % cand)
        else:
            pwsh = cand
            suites.append(Suite("windows pwsh", [pwsh, "-NoProfile", "-NonInteractive", "-File", str(HOOK_PS1)], None, "ps1"))
    if not suites and not missing:
        missing.append("nothing to run (--no-sh leaves windows only, and --suite compat, --no-pwsh, --shell or --hook leave it out)")
    return suites, missing, pwsh


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--suite", action="append", choices=("full", "compat"),
                    help="full: ubuntu, macos and windows, every case; compat: the compat set (default: both)")
    ap.add_argument("--shell", action="append", help="run the sh hook with this shell instead of the environments' (repeatable; no windows)")
    ap.add_argument("--openssl", help="the OpenSSL 3 to use (default: Homebrew's, else /usr/bin/openssl if it is OpenSSL 3)")
    ap.add_argument("--pwsh", help="the PowerShell 7 for the windows environment (default: pwsh in PATH)")
    ap.add_argument("--no-pwsh", action="store_true", help="leave the windows environment out")
    ap.add_argument("--only", action="append", help="test function name (repeatable)")
    ap.add_argument("--no-sh", action="store_true", help="leave the sh environments out")
    ap.add_argument("--hook", help="sh hook to test instead of the plugin's (e.g. an older release; no windows)")
    ap.add_argument("--regen-v2", action="store_true", help="write tests/fixtures/v2/expected.json from the sh hook and exit")
    args = ap.parse_args()
    global HOOK_SH, SCRIPTS
    if args.hook:
        HOOK_SH = Path(args.hook).resolve()
        SCRIPTS = HOOK_SH.parent
    if args.regen_v2:
        regen_v2((args.shell or ["/bin/dash"])[0])
        sys.exit(0)

    suites, missing, pwsh = select_environments(args)

    failed = 0
    print("== environments: %s" % (", ".join(s.name for s in suites) or "none"))
    for m in missing:
        print("   FAIL " + m)
    failed += len(missing)
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
    if pwsh:
        parse = ps_parse_check(pwsh)
        print("== PowerShell parse (%s): %s" % (pwsh, "ok" if not parse else "errors"))
        for p in parse:
            print("   FAIL " + p)
        failed += len(parse)

    stop = threading.Event()
    watcher = threading.Thread(target=watch, args=(stop,), daemon=True)
    watcher.start()
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
    # Nothing the cases started may outlive the run (each case's groups are reaped after it).
    stop.set()
    watcher.join(10)
    left = leftovers()
    print("== leftover processes: %d" % len(left))
    for p in left[:20]:
        print("   FAIL left running: " + p)
    failed += len(left)
    print("TOTAL FAILURES:", failed)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    sys.exit(run_in_own_group(main))
