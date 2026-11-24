// SimpleTerm agent hooks for OpenCode 2.x: permission approvals from a
// SimpleTerm device, and done / error alerts. This is the server part; the
// TUI part (tui.js) tells it which tab shows a session. Install with
//   opencode plugin add 'github:AhMunGa/simpleterm-agent-hooks#release::path:plugins/opencode'
// or copy this directory to ~/.config/opencode/plugins/simpleterm/.
//
// The work is done by agent-hook.sh next to this file (the same script as the
// Claude Code and Codex plugin), run as `sh agent-hook.sh opencode` with a
// Claude-shaped event on stdin. For a permission request it waits for a
// device's answer and prints {"decision":"allow"|"deny"}; whichever answers
// first, the device or the terminal prompt, wins. No imports from OpenCode.

import { spawn } from "node:child_process";
import { existsSync, mkdirSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

// The suite's stand-in hook (tests only).
const HOOK =
  process.env.SIMPLETERM_HOOK_TEST === "1" && process.env.SIMPLETERM_OC_HOOK
    ? process.env.SIMPLETERM_OC_HOOK
    : join(dirname(fileURLToPath(import.meta.url)), "agent-hook.sh");
const TYPES = [
  "permission.asked",
  "permission.replied",
  "session.created",
  "session.deleted",
  "session.status",
  "session.execution.started",
  "session.execution.succeeded",
  "session.execution.failed",
  "session.execution.interrupted",
  "session.inbox.enqueued",
  "session.inbox.delivered",
  "form.created",
  "shell.created",
  "shell.exited",
];

// Each project directory gets its own plugin instance and every instance sees
// every event: handle an event once, in the instance of its directory.
const seen = (globalThis.__simpletermSeen ??= new Set());
// Which sessions are running and whose child each one is, as every instance
// sees it (an event may be handled by any of them).
const sessions = (globalThis.__simpletermSessions ??= { running: new Set(), parent: new Map() });
// Background shells still running (shell id -> {owner session id, command}).
// A shell started with `background: true` outlives the turn, and its exit
// starts the session again (measured on 2.2.5: execution.succeeded 0.1 s
// after shell.created, shell.exited 25 s later, then execution.started and
// .succeeded again). A shell that never exits (a dev server) must not hold
// the done back for good: the hook gets the open shells with the Stop and
// decides as it does for Claude Code's background_tasks (a service is not
// waited for, other shells are, for a while).
const shells = (globalThis.__simpletermShells ??= new Map());

// Who started a turn (SimpleTerm if/hook-events-scheduled#by-schedule,
// hist/turn-state#d20; measured on 2.2.7). What starts or joins a turn comes
// through the session's inbox: `session.inbox.enqueued` names an item, and
// `session.inbox.delivered` hands it to the execution that runs then. A
// schedule's prompt is a user item with payload.metadata.schedule (inbox id
// msg_sch_<schedule>_<run>), from 2.4 an automation's one with
// payload.metadata.automation (msg_aut_<automation>_<run>, with _send for
// the prompt a code automation sends [static 2.4.1]; measured 2.4.1), a
// person's prompt a user item with neither, the
// report of a background shell a synthetic item naming the shell
// (payload.metadata.shellID). inbox: inbox id -> {kind, shell}.
const inbox = (globalThis.__simpletermInbox ??= new Map());
// The execution of each session that runs or ran last (session id ->
// {sched, human, shells, ids}): what was delivered to it.
const execs = (globalThis.__simpletermExecs ??= new Map());
// The execution that started each background shell (shell id -> execution):
// the turn its report wakes belongs to whoever started that one.
const shellExec = (globalThis.__simpletermShellExec ??= new Map());
// Items enqueued while their session was idle (session id -> inbox ids). An
// idle session starts an execution for them (enqueued, then
// execution.started 0-10 ms later [measured 2.2.7]), so they are that
// execution's even when their session.inbox.delivered does not come.
const idleQueue = (globalThis.__simpletermIdleQueue ??= new Map());
const SCHED_ID = /^msg_(?:sch|aut)_[A-Za-z0-9]+_\d+(?:_send)?$/;

function newExec(sessionID) {
  const e = { sched: 0, human: 0, shells: [], ids: new Set() };
  execs.delete(sessionID);
  execs.set(sessionID, e);
  if (execs.size > 500) execs.delete(execs.keys().next().value);
  return e;
}

// Counts one inbox item in an execution, once (an item taken at
// execution.started is not counted again by its delivered event).
function take(e, inboxID) {
  const iid = String(inboxID || "");
  if (!iid || e.ids.has(iid)) return;
  const it = inbox.get(iid) || (SCHED_ID.test(iid) ? { kind: "schedule", shell: "" } : null);
  inbox.delete(iid);
  if (!it) return;
  if (e.ids.size < 100) e.ids.add(iid);
  if (it.kind === "schedule") e.sched++;
  else if (it.kind === "human") e.human++;
  else if (it.shell && e.shells.length < 20) e.shells.push(it.shell);
}

// "schedule" when only schedules' prompts started the execution, or the
// report of a shell that such an execution started; "user" when a person's
// prompt is in it (a schedule's prompt that came during a person's turn
// joins that turn); "" when it is not known.
function turnBy(e, depth = 0) {
  if (!e || depth > 8) return "";
  if (e.human) return "user";
  if (e.sched) return "schedule";
  for (const id of e.shells) if (turnBy(shellExec.get(id), depth + 1) === "schedule") return "schedule";
  return "";
}

// An automation's trigger as the hook's schedule text: every 60 seconds,
// at <time>, cron <expression>, event <server> <event> [static 2.4.1].
function triggerText(tr, name) {
  if (tr && typeof tr === "object" && typeof tr.type === "string") {
    if (tr.type === "event") return ["event", tr.server, tr.event].filter((x) => typeof x === "string" && x).join(" ");
    const v = tr[tr.type];
    if (typeof v === "string" || typeof v === "number") return `${tr.type} ${v}`;
  }
  return String(name || "automation");
}

// The session's schedules that will still run, as the hook's session_crons
// (SimpleTerm if/hook-events-scheduled#by-schedule). OpenCode updates a
// schedule or an automation when it sends the prompt, so at the end of that
// turn the list is final [measured 2.2.7, 2.4.1]. 2.2.3 to 2.3.x: the
// schedule_list tool, status `active` (a paused one does not wake the
// session). 2.4: the tool `list` of the namespace automation (a browser tool
// is named `list` too), the active prompt automations to this session (a
// shell, code or sub-agent automation prompts no session of its own). No
// tool, an error or over 3 s: none left.
async function activeSchedules(ctx, sessionID) {
  try {
    const tools = await ctx.tool.list();
    if (!Array.isArray(tools)) return [];
    const sched = tools.find((t) => t && t.name === "schedule_list");
    const tool = sched || tools.find((t) => t && t.name === "list" && t.options && t.options.namespace === "automation");
    if (!tool) return [];
    const ac = new AbortController();
    let timer;
    const r = await Promise.race([
      tool.execute({}, { sessionID, signal: ac.signal, progress: () => {} }),
      new Promise((resolve) => {
        timer = setTimeout(() => {
          ac.abort();
          resolve(null);
        }, 3000);
      }),
    ]).finally(() => clearTimeout(timer));
    if (!sched) {
      const autos = r && r.output && Array.isArray(r.output.automations) ? r.output.automations : [];
      return autos
        .filter((a) => a && a.status === "active" && a.action && a.action.type === "prompt" && a.action.to && a.action.to.session === sessionID)
        .slice(0, 5)
        .map((a) => ({ id: String(a.id || ""), schedule: triggerText(a.trigger, a.name).slice(0, 80), prompt: String(a.action.prompt || "").slice(0, 200) }));
    }
    const list = r && r.output && Array.isArray(r.output.schedules) ? r.output.schedules : [];
    return list
      .filter((s) => s && s.status === "active")
      .slice(0, 5)
      .map((s) => {
        const w = s.when && typeof s.when === "object" ? s.when : {};
        const at = w.type && w[w.type] !== undefined ? `${w.type} ${w[w.type]}` : String(s.name || "schedule");
        return { id: String(s.id || ""), schedule: at.slice(0, 80), prompt: String((s.action && s.action.prompt) || "").slice(0, 200) };
      });
  } catch {
    return [];
  }
}

// Permission requests that were answered (bounded), for one still waiting on its session lane.
const replied = (globalThis.__simpletermReplied ??= new Set());
// Permission requests open per session (session id -> Set of request ids):
// in OpenCode 2.x a `reject` or `always` also settles the session's other
// open requests, so a request carries them (`others`) and the hook checks,
// when a decision comes, that the user saw every one still open
// (SimpleTerm if/event-v2-request#affects, if/event-decision#validation). The hook reads them from
// ~/.simpleterm/run/oc.<session>.pending.
const pending = (globalThis.__simpletermPending ??= new Map());

// The session's tokens and cost as OpenCode keeps them (session info `cost`
// and `tokens`), for the usage event's `cost` (SimpleTerm if/usage-report#agents).
function usage(info) {
  const out = {};
  if (typeof info?.cost === "number" && Number.isFinite(info.cost) && info.cost >= 0) out.cost = info.cost;
  const t = info?.tokens;
  if (t && typeof t === "object") {
    const n = (v) => (Number.isInteger(v) && v >= 0 ? v : 0);
    out.tokens_in = n(t.input) + n(t.cache?.read) + n(t.cache?.write);
    out.tokens_out = n(t.output) + n(t.reasoning);
  }
  return out;
}

function pendingFile(sessionID) {
  const st = join(process.env.HOME || homedir(), ".simpleterm");
  if (!existsSync(st)) return null;
  const run = join(st, "run");
  try {
    mkdirSync(run, { recursive: true, mode: 0o700 });
  } catch {
    return null;
  }
  const name = String(sessionID).replace(/[^A-Za-z0-9_-]/g, "_").slice(0, 80) || "nosession";
  return join(run, "oc." + name + ".pending");
}

function writePending(sessionID) {
  const f = pendingFile(sessionID);
  if (!f) return;
  const ids = [...(pending.get(sessionID) || [])];
  try {
    writeFileSync(f + ".tmp", ids.join("\n") + (ids.length ? "\n" : ""), { mode: 0o600 });
    renameSync(f + ".tmp", f);
  } catch {
    // no record: the hook then sees no other open request
  }
}

function openRequest(sessionID, id) {
  if (!sessionID || !id) return;
  let set = pending.get(sessionID);
  if (!set) pending.set(sessionID, (set = new Set()));
  set.add(id);
  if (set.size > 64) set.delete(set.values().next().value);
  if (pending.size > 200) pending.delete(pending.keys().next().value);
  writePending(sessionID);
}

function closeRequest(id) {
  for (const [sid, set] of pending) {
    if (set.delete(id)) {
      writePending(sid);
      if (!set.size) pending.delete(sid);
    }
  }
}

function firstSeen(id) {
  if (!id) return true;
  if (seen.has(id)) return false;
  seen.add(id);
  if (seen.size > 500) seen.delete(seen.values().next().value);
  return true;
}

function remember(set, value, max) {
  set.add(value);
  if (set.size > max) set.delete(set.values().next().value);
}

// Every instance calls track() with every event, before the directory check
// and firstSeen, but the state it keeps is shared by all of them and some of
// it is not idempotent (an execution starts afresh, an inbox item is taken
// once): it runs once per event id, in whichever instance sees it first.
const tracked = (globalThis.__simpletermTracked ??= new Set());

// Session state from execution and status events (the OpenCode TUI counts a
// session as running from session.execution.started until it ends).
function track(event) {
  if (event.id) {
    if (tracked.has(event.id)) return;
    remember(tracked, event.id, 500);
  }
  const d = event.data || {};
  if (event.type === "shell.created") {
    const info = d.info || {};
    const owner = info.metadata && info.metadata.sessionID;
    if (info.id && owner && info.status !== "exited") {
      shells.set(info.id, { owner, command: String(info.command || "") });
      if (shells.size > 500) shells.delete(shells.keys().next().value);
    }
    if (info.id && owner && execs.has(owner)) {
      shellExec.set(info.id, execs.get(owner));
      if (shellExec.size > 500) shellExec.delete(shellExec.keys().next().value);
    }
    return;
  }
  if (event.type === "shell.exited") {
    shells.delete(d.id);
    return;
  }
  const id = d.sessionID;
  if (!id) return;
  switch (event.type) {
    case "session.inbox.enqueued": {
      const item = d.item || {};
      const p = item.payload || {};
      const meta = p.metadata && typeof p.metadata === "object" ? p.metadata : {};
      let kind = "";
      let shell = "";
      if (item.type === "user") kind = meta.schedule || meta.automation ? "schedule" : "human";
      else if (item.type === "synthetic" && meta.source === "shell") {
        kind = "shell";
        shell = String(meta.shellID || (/^<shell id="([^"]+)"/.exec(String(p.text || "")) || [])[1] || "");
      }
      if (d.inboxID && kind) {
        inbox.set(d.inboxID, { kind, shell });
        if (inbox.size > 500) inbox.delete(inbox.keys().next().value);
        if (!sessions.running.has(id)) {
          const q = idleQueue.get(id) || [];
          if (q.length < 20) q.push(String(d.inboxID));
          idleQueue.delete(id);
          idleQueue.set(id, q);
          if (idleQueue.size > 500) idleQueue.delete(idleQueue.keys().next().value);
        }
      }
      return;
    }
    case "session.inbox.delivered": {
      const q = idleQueue.get(id);
      const i = q ? q.indexOf(String(d.inboxID || "")) : -1;
      if (i >= 0) q.splice(i, 1);
      if (q && !q.length) idleQueue.delete(id);
      take(execs.get(id) || newExec(id), d.inboxID);
      return;
    }
    case "session.created":
      sessions.parent.set(id, d.parentID || "");
      if (sessions.parent.size > 2000) sessions.parent.delete(sessions.parent.keys().next().value);
      return;
    case "session.execution.started": {
      remember(sessions.running, id, 500);
      const e = newExec(id);
      for (const iid of idleQueue.get(id) || []) take(e, iid);
      idleQueue.delete(id);
      return;
    }
    case "session.execution.succeeded":
    case "session.execution.failed":
    case "session.execution.interrupted":
      sessions.running.delete(id);
      return;
    case "session.status": {
      const type = d.status && d.status.type;
      if (type === "idle") sessions.running.delete(id);
      else if (type === "busy" || type === "retry") remember(sessions.running, id, 500);
      return;
    }
  }
}

// Runs the hook (env: the bound tab's, `tabbed`); resolves with the first
// JSON object it printed, or null.
function runHook(event, cwd, waits, key, job, env) {
  return new Promise((resolve) => {
    let out = "";
    let child;
    if (job && job.abandoned) {
      resolve(null);
      return;
    }
    try {
      child = spawn("sh", [HOOK, "opencode"], {
        cwd: cwd || process.cwd(),
        env: env || process.env,
        stdio: ["pipe", "pipe", "ignore"],
      });
    } catch {
      resolve(null);
      return;
    }
    if (key) waits.set(key, child);
    if (job) job.child = child;
    child.on("error", () => resolve(null));
    child.stdout.on("data", (chunk) => {
      if (out.length < 65536) out += chunk;
    });
    child.on("close", () => {
      if (key && waits.get(key) === child) waits.delete(key);
      const line = out.split("\n").find((l) => l.trim().startsWith("{"));
      try {
        resolve(line ? JSON.parse(line) : null);
      } catch {
        resolve(null);
      }
    });
    child.stdin.on("error", () => {});
    child.stdin.end(JSON.stringify(event));
  });
}

async function sessionInfo(ctx, sessionID) {
  try {
    return (await ctx.session.get({ sessionID })) || {};
  } catch {
    return {};
  }
}

async function parentOf(ctx, sessionID) {
  let parent = sessions.parent.get(sessionID);
  if (parent === undefined) {
    parent = (await sessionInfo(ctx, sessionID)).parentID || "";
    sessions.parent.set(sessionID, parent);
  }
  return parent;
}

// The background shells of the session or of a direct child that were still
// running (`open`, taken when the event arrived), as the hook's
// background_tasks: the exit of one wakes that session again.
async function openShellsOf(ctx, sessionID, open) {
  const mine = [];
  for (const sh of open) {
    if (sh.owner === sessionID || (await parentOf(ctx, sh.owner)) === sessionID) {
      mine.push({ id: sh.id, type: "shell", command: sh.command });
    }
  }
  return mine.slice(0, 10);
}

// True if a direct child of the session was running (`running`, taken when
// the event arrived). Its report wakes the session again, so the session is
// not done yet; a grandchild reports to its own parent. The same check as the
// OpenCode TUI's own notifications.
async function hasRunningChild(ctx, sessionID, running) {
  for (const id of running) {
    if (id !== sessionID && (await parentOf(ctx, id)) === sessionID) return true;
  }
  return false;
}

// The turn events of one session run one after the other: a start must reach
// the hook before the end of the turn it belongs to, or it would undo the
// pause that end made.
const lanes = (globalThis.__simpletermLanes ??= new Map());
// A job that hangs (a session lookup, the hook) must not hold the session's
// later events for good: after this long the lane goes on without it.
const LANE_TIMEOUT_MS = Number(process.env.SIMPLETERM_LANE_TIMEOUT_MS) > 0 ? Number(process.env.SIMPLETERM_LANE_TIMEOUT_MS) : 15000;
// A lane job gets `job`: when the lane gives up on it (`abandoned`) it must not
// start a hook any more (a late start would undo the pause of a later Stop, a
// late Stop would write one during the next turn), and a hook it has running
// is stopped.
function inLane(sessionID, work) {
  const job = { abandoned: false, child: null };
  const run = (lanes.get(sessionID) || Promise.resolve()).then(() => {
    let timer;
    const limit = new Promise((resolve) => {
      timer = setTimeout(() => {
        job.abandoned = true;
        if (job.child) job.child.kill("SIGTERM");
        resolve();
      }, LANE_TIMEOUT_MS);
    });
    return Promise.race([work(job), limit]).finally(() => clearTimeout(timer));
  });
  const tail = run.catch(() => {});
  lanes.set(sessionID, tail);
  tail.then(() => {
    if (lanes.get(sessionID) === tail) lanes.delete(sessionID);
  });
  return run;
}


// --- Tab claims (SimpleTerm if/hook-tab-opencode) ----------------------------
// The service's environment is that of the process that started it, so a
// hook run with it cannot tell the tab. The TUI part (tui.js) in each TUI
// claims the root session on its screen (cur) and the ones it showed that are
// still tabs (seen), with its tab's values; a session's hooks run with the
// values of the one TUI it is bound to (#binding, #hook-input).
const TAB_NAMES = ["TMUX", "TMUX_PANE", "STY", "HERDR_ENV", "HERDR_PANE_ID", "HERDR_SESSION", "HERDR_SOCKET_PATH"];
// Taken out of the service's environment for every hook while claims come.
const TAB_STRIP = ["LC_SIMPLETERM_TAB", "SIMPLETERM", ...TAB_NAMES, "HERDR_TAB_ID", "HERDR_WORKSPACE_ID", "HERDR_STARTUP_CWD"];
const MARKER = /^st1-[0-9a-f]{16}$/;
const CLAIM_MAX = 8192; // bytes (#bytes)
const CLAIM_TTL_MS = 90000;
// No live claim names the session while some claim exists: wait this long
// for one (a new session's claim comes about when its first hook does),
// longer in the service's first minute (TUIs claiming again after a restart).
const CLAIM_WAIT_MS = 300;
const FIRST_CLAIM_WAIT_MS = 1000;
const FIRST_MS = 60000;
// A screen's session gets a View once it stayed this long (#view-state).
const VIEW_MS = 1000;
const TAB_RPC = {
  id: "simpleterm-tab",
  methods: {
    claim: {
      input: { type: "object", additionalProperties: true },
      output: { type: "object", additionalProperties: true },
    },
  },
  events: {},
};
// One table per service process, shared by every instance. active: an
// instance registered the RPC (without it every hook works as in 0.9.0).
const tab = (globalThis.__simpletermTab ??= { active: false, claims: new Map(), waiters: new Set(), views: new Map(), startedAt: Date.now() });

async function tabRpc() {
  try {
    const mod = await import("@opencode/plugin/rpc");
    if (mod && mod.Rpc && typeof mod.Rpc.define === "function") return mod.Rpc.define(TAB_RPC);
  } catch {
    // no SDK next to the plugin: the plain JSON Schema definition
  }
  return TAB_RPC;
}

function alive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return !!e && e.code === "EPERM";
  }
}

// Keeps the last claim of a TUI process; drops one that is not an object,
// another version, without a positive pid or a time, or over 8 KiB (#errors).
function takeClaim(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) return null;
  let size;
  try {
    size = Buffer.byteLength(JSON.stringify(input));
  } catch {
    return null;
  }
  if (size > CLAIM_MAX || input.v !== 1 || !Number.isInteger(input.pid) || input.pid <= 0 || !Number.isFinite(input.t)) return null;
  const env = {};
  if (input.env && typeof input.env === "object") for (const n of TAB_NAMES) if (typeof input.env[n] === "string") env[n] = input.env[n];
  const c = {
    pid: input.pid,
    t: input.t,
    tab: typeof input.tab === "string" ? input.tab : "",
    st: input.st === true,
    env,
    cur: typeof input.cur === "string" ? input.cur : "",
    seen: Array.isArray(input.seen) ? input.seen.filter((s) => typeof s === "string" && s).slice(0, 32) : [],
  };
  tab.claims.delete(c.pid);
  tab.claims.set(c.pid, c);
  if (tab.claims.size > 256) tab.claims.delete(tab.claims.keys().next().value);
  for (const w of [...tab.waiters]) w();
  return c;
}

// Claims whose process exists and whose time is at most 90 s old.
function liveClaims() {
  const now = Date.now();
  const out = [];
  for (const [pid, c] of tab.claims) {
    if (now - c.t > CLAIM_TTL_MS || !alive(pid)) tab.claims.delete(pid);
    else out.push(c);
  }
  return out;
}

// #binding for root session R: the one TUI showing it (bg 0), else the one
// that has it as a tab (bg 1), else many or none. naming: every live claim
// that names R.
function bindOf(root) {
  const live = liveClaims();
  const cur = live.filter((c) => c.cur === root);
  const tabs = live.filter((c) => c.cur !== root && c.seen.includes(root));
  const naming = [...cur, ...tabs];
  if (cur.length === 1) return { bind: "one", claim: cur[0], bg: 0, naming };
  if (cur.length > 1) return { bind: "many", naming };
  if (tabs.length === 1) return { bind: "one", claim: tabs[0], bg: 1, naming };
  if (tabs.length > 1) return { bind: "many", naming };
  return { bind: "none", naming, any: live.length > 0 };
}

async function bindTab(root) {
  let b = bindOf(root);
  if (b.bind !== "none" || !b.any) return b;
  const ms = Date.now() - tab.startedAt < FIRST_MS ? FIRST_CLAIM_WAIT_MS : CLAIM_WAIT_MS;
  await new Promise((resolve) => {
    let timer;
    const done = () => {
      clearTimeout(timer);
      tab.waiters.delete(check);
      resolve();
    };
    const check = () => {
      if (bindOf(root).bind !== "none") done();
    };
    timer = setTimeout(done, ms);
    tab.waiters.add(check);
  });
  return bindOf(root);
}

// The hook input field oc_tab (#hook-input).
function ocTab(b) {
  const st = b.naming.some((c) => c.st);
  if (b.bind === "one") return { bind: "one", pid: b.claim.pid, bg: b.bg, st };
  if (b.bind === "many") {
    const cl = [];
    for (const c of b.naming) if (MARKER.test(c.tab) && !cl.includes(c.tab) && cl.length < 8) cl.push(c.tab);
    return { bind: "many", n: b.naming.length, cl, st };
  }
  return { bind: "none" };
}

// The hook's environment: the service's without its tab values, and with
// binding one the bound TUI's.
function hookEnv(b) {
  const env = { ...process.env };
  for (const n of TAB_STRIP) delete env[n];
  if (b.bind === "one") {
    const c = b.claim;
    if (c.tab) env.LC_SIMPLETERM_TAB = c.tab;
    if (c.st) env.SIMPLETERM = "1";
    Object.assign(env, c.env);
  }
  return env;
}

// The root of a session along the parent chain: a subagent's session belongs
// to the root session the TUI shows.
async function rootOf(ctx, sessionID) {
  let id = sessionID;
  for (let i = 0; i < 8; i++) {
    const parent = await parentOf(ctx, id);
    if (!parent || parent === id) break;
    id = parent;
  }
  return id;
}

// A hook input and environment for an event of the session: with oc_tab and
// the bound TUI's values once the RPC is registered; as 0.9.0 before.
async function tabbed(ctx, sessionID, input) {
  if (!tab.active || !sessionID) return { input, env: process.env };
  const b = await bindTab(await rootOf(ctx, sessionID));
  return { input: { ...input, oc_tab: ocTab(b) }, env: hookEnv(b) };
}

// The folder of each session as its events gave it (the hook's cwd for a View).
const sessionDirs = (globalThis.__simpletermSessionDirs ??= new Map());

function rememberDir(sessionID, dir) {
  if (!sessionID || typeof dir !== "string" || !dir) return;
  sessionDirs.delete(sessionID);
  sessionDirs.set(sessionID, dir);
  if (sessionDirs.size > 2000) sessionDirs.delete(sessionDirs.keys().next().value);
}

// A deleted session cannot be resumed: its record goes (SimpleTerm
// if/session-record#opencode2). Removing twice is harmless.
function removeRecord(sessionID) {
  const sid = String(sessionID || "");
  if (!/^[A-Za-z0-9_-][A-Za-z0-9._-]{0,127}$/.test(sid)) return;
  const dir = join(process.env.HOME || homedir(), ".simpleterm", "sessions", "opencode");
  for (const ext of [".json", ".beat", ".ended"]) {
    try {
      rmSync(join(dir, sid + ext), { force: true });
    } catch {
      // not there
    }
  }
}

export default {
  id: "simpleterm",
  setup(ctx) {
    const controller = new AbortController();
    const waits = new Map();
    const home = ctx.location?.directory;
    let closed = false;
    let registration = null;

    // The screen's session: once a TUI's cur stayed on R for 1 s, one View
    // hook for R (SimpleTerm if/hook-tab-opencode#view-state). A claim sent
    // again with the same cur starts none.
    function viewOf(c) {
      const v = tab.views.get(c.pid);
      if (v && v.root === c.cur) return;
      if (v) clearTimeout(v.timer);
      tab.views.delete(c.pid);
      if (!c.cur) return;
      const root = c.cur;
      const timer = setTimeout(() => {
        const now = tab.claims.get(c.pid);
        if (closed || !now || now.cur !== root || !liveClaims().includes(now)) return;
        inLane(root, async (job) => {
          const info = await sessionInfo(ctx, root);
          if (job.abandoned || info.parentID) return;
          const cwd = (info.location && typeof info.location.directory === "string" && info.location.directory) || sessionDirs.get(root) || home;
          const state = sessions.running.has(root) ? "running" : "idle";
          const t = await tabbed(ctx, root, { hook_event_name: "View", session_id: root, cwd, oc: "2", view_state: state });
          if (job.abandoned) return;
          await runHook(t.input, cwd, undefined, undefined, job, t.env);
        }).catch(() => {});
      }, VIEW_MS);
      tab.views.set(c.pid, { root, timer });
      if (tab.views.size > 256) {
        const [pid, old] = tab.views.entries().next().value;
        clearTimeout(old.timer);
        tab.views.delete(pid);
      }
    }

    // The RPC the TUI parts call (if/hook-tab-opencode#claims). A build
    // without the plugin RPC: no claims, every hook as in 0.9.0.
    if (ctx.rpc && typeof ctx.rpc.register === "function") {
      (async () => {
        const reg = await ctx.rpc.register(await tabRpc(), {
          claim: async (input) => {
            const c = takeClaim(input);
            if (c) viewOf(c);
            return {};
          },
        });
        if (closed) {
          if (reg && typeof reg.dispose === "function") reg.dispose();
          return;
        }
        registration = reg;
        tab.active = true;
      })().catch(() => {});
    }

    async function handle(event) {
      track(event);
      const done = event.type === "session.execution.succeeded";
      const running = done ? [...sessions.running] : [];
      const open = done ? [...shells].map(([id, v]) => ({ id, owner: v.owner, command: v.command })) : [];
      const d = event.data || {};
      const by = done ? turnBy(execs.get(d.sessionID)) : "";
      if (event.type === "permission.replied") {
        // Answered (in the terminal, or by us): stop waiting for a device.
        // Every instance looks; the waiting one may not see this event first.
        const child = waits.get(d.requestID);
        if (child) child.kill("SIGTERM");
        remember(replied, d.requestID, 500); // a request still waiting on the session lane is dropped
        closeRequest(d.requestID);
        return;
      }
      if (event.type === "session.deleted") {
        removeRecord(d.sessionID || (d.info && d.info.id));
        return;
      }
      if (event.type === "permission.asked") openRequest(d.sessionID, d.id);
      const where = event.location?.directory;
      rememberDir(d.sessionID, where);
      if (where && home && where !== home) return;
      if (!firstSeen(event.id)) return;
      const cwd = where || home;
      switch (event.type) {
        case "permission.asked": {
          // After the turn events of the session that came before it: a late
          // turn start would otherwise end this wait as "answered locally".
          await (lanes.get(d.sessionID) || Promise.resolve());
          if (replied.has(d.id)) return;
          const detail = Array.isArray(d.resources) ? d.resources.join(" ") : String(d.message || "");
          const parent = await parentOf(ctx, d.sessionID);
          const others = [...(pending.get(d.sessionID) || [])].filter((id) => id !== d.id);
          const t = await tabbed(ctx, d.sessionID, {
            hook_event_name: "PermissionRequest",
            session_id: d.sessionID,
            cwd,
            tool_name: d.action || "permission",
            tool_input: { command: detail },
            // event format v2 (SimpleTerm if/event-v2-request#fields, if/hook-events#request-source)
            oc: "2",
            request_id: d.id,
            ...(Array.isArray(d.save) ? { save: d.save.map(String) } : {}),
            ...(Array.isArray(d.resources) ? { resources: d.resources.map(String) } : {}),
            ...(d.metadata && typeof d.metadata === "object" ? { metadata: d.metadata } : {}),
            ...(others.length ? { others } : {}),
            ...(parent ? { parent_session_id: parent } : {}),
          });
          if (replied.has(d.id)) return;
          const out = await runHook(t.input, cwd, waits, d.id, undefined, t.env);
          const decision = out && out.decision;
          if (decision !== "allow" && decision !== "deny") return;
          // allow: once, or always (a scope); deny: reject, with the user's
          // reason when there is one.
          await ctx.permission
            .reply({
              sessionID: d.sessionID,
              requestID: d.id,
              decision: decision === "allow" ? (out.scope === "always" ? "always" : "once") : "reject",
              ...(decision === "deny" ? { message: typeof out.message === "string" && out.message ? out.message : "Denied from SimpleTerm" } : {}),
            })
            .catch(() => {}); // answered in the terminal first
          return;
        }
        case "session.execution.started":
          // A turn of the session's own starts (a person's prompt, or the
          // session taken up again): the hook ends the pause of the last
          // Stop, so a long turn is not announced done by that pause's timer.
          return inLane(d.sessionID, async (job) => {
            const info = await sessionInfo(ctx, d.sessionID);
            if (job.abandoned || info.parentID) return; // given up on, or a subagent's session
            const t = await tabbed(ctx, d.sessionID, { hook_event_name: "UserPromptSubmit", session_id: d.sessionID, cwd, oc: "2" });
            if (job.abandoned) return;
            await runHook(t.input, cwd, undefined, undefined, job, t.env);
          });
        case "session.execution.succeeded":
        case "session.execution.failed":
          return inLane(d.sessionID, (job) => turnEnd(event, d, cwd, running, open, by, job));
        case "form.created": {
          // data: { form: { id, sessionID, title, metadata: {kind}, fields, ... } }:
          // a question (kind question) is answered in the terminal until the
          // plugin can reply to a form (SimpleTerm hist/event-decision#m8); the alert carries its fields.
          const form = d.form || d;
          const fields = Array.isArray(form.fields) ? form.fields : [];
          const t = await tabbed(ctx, form.sessionID, {
            hook_event_name: "Form",
            session_id: form.sessionID,
            cwd,
            oc: "2",
            request_id: String(form.id || ""),
            message: String((fields[0] && fields[0].description) || form.title || form.message || ""),
            form: { fields },
          });
          await runHook(t.input, cwd, undefined, undefined, undefined, t.env);
          return;
        }
      }
    }

    async function turnEnd(event, d, cwd, running, open, by, job) {
      const info = await sessionInfo(ctx, d.sessionID);
      sessions.parent.set(d.sessionID, info.parentID || "");
      if (info.parentID) return; // a subagent's session
      const failed = event.type === "session.execution.failed";
      if (!failed && (await hasRunningChild(ctx, d.sessionID, running))) return;
      const background = failed ? [] : await openShellsOf(ctx, d.sessionID, open);
      // A scheduled turn (turn_by) rests while a schedule is left
      // (session_crons) and its last one is a quiet done (SimpleTerm
      // spec/turn-state#scheduled).
      const crons = !failed && by === "schedule" ? await activeSchedules(ctx, d.sessionID) : [];
      const err = d.error || {};
      if (job.abandoned) return;
      const t = await tabbed(
        ctx,
        d.sessionID,
        failed
          ? {
              hook_event_name: "StopFailure",
              session_id: d.sessionID,
              cwd,
              oc: "2",
              error: String(err.type || "error"),
              last_assistant_message: String(err.message || ""),
            }
          : {
              hook_event_name: "Stop",
              session_id: d.sessionID,
              cwd,
              oc: "2",
              last_assistant_message: String(info.title || ""),
              ...(background.length ? { background_tasks: background } : {}),
              ...(by ? { turn_by: by } : {}),
              ...(crons.length ? { session_crons: crons } : {}),
              ...usage(info),
            },
      );
      if (job.abandoned) return;
      await runHook(t.input, cwd, undefined, undefined, job, t.env);
    }

    (async () => {
      for await (const event of ctx.event.subscribe({ types: TYPES, signal: controller.signal })) {
        handle(event).catch(() => {});
      }
    })().catch(() => {});

    return () => {
      closed = true;
      controller.abort();
      for (const child of waits.values()) child.kill("SIGTERM");
      try {
        if (registration && typeof registration.dispose === "function") registration.dispose();
      } catch {
        // already gone
      }
    };
  },
};
