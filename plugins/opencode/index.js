// SimpleTerm agent hooks for OpenCode 2.x: permission approvals from a
// SimpleTerm device, and done / error alerts. Install with
//   opencode plugin add 'github:AhMunGa/simpleterm-agent-hooks#main::path:plugins/opencode'
// or copy this directory to ~/.config/opencode/plugins/simpleterm/.
//
// The work is done by agent-hook.sh next to this file (the same script as the
// Claude Code and Codex plugin), run as `sh agent-hook.sh opencode` with a
// Claude-shaped event on stdin. For a permission request it waits for a
// device's answer and prints {"decision":"allow"|"deny"}; whichever answers
// first, the device or the terminal prompt, wins. No imports from OpenCode.

import { spawn } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HOOK = join(dirname(fileURLToPath(import.meta.url)), "agent-hook.sh");
const TYPES = [
  "permission.asked",
  "permission.replied",
  "session.created",
  "session.status",
  "session.execution.started",
  "session.execution.succeeded",
  "session.execution.failed",
  "session.execution.interrupted",
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

// Permission requests that were answered (bounded), for one still waiting on its session lane.
const replied = (globalThis.__simpletermReplied ??= new Set());

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

// Session state from execution and status events (the OpenCode TUI counts a
// session as running from session.execution.started until it ends).
function track(event) {
  const d = event.data || {};
  if (event.type === "shell.created") {
    const info = d.info || {};
    const owner = info.metadata && info.metadata.sessionID;
    if (info.id && owner && info.status !== "exited") {
      shells.set(info.id, { owner, command: String(info.command || "") });
      if (shells.size > 500) shells.delete(shells.keys().next().value);
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
    case "session.created":
      sessions.parent.set(id, d.parentID || "");
      if (sessions.parent.size > 2000) sessions.parent.delete(sessions.parent.keys().next().value);
      return;
    case "session.execution.started":
      remember(sessions.running, id, 500);
      return;
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

// Runs the hook; resolves with the first JSON object it printed, or null.
function runHook(event, cwd, waits, key, job) {
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
        env: process.env,
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

export default {
  id: "simpleterm",
  setup(ctx) {
    const controller = new AbortController();
    const waits = new Map();
    const home = ctx.location?.directory;

    async function handle(event) {
      track(event);
      const done = event.type === "session.execution.succeeded";
      const running = done ? [...sessions.running] : [];
      const open = done ? [...shells].map(([id, v]) => ({ id, owner: v.owner, command: v.command })) : [];
      const d = event.data || {};
      if (event.type === "permission.replied") {
        // Answered (in the terminal, or by us): stop waiting for a device.
        // Every instance looks; the waiting one may not see this event first.
        const child = waits.get(d.requestID);
        if (child) child.kill("SIGTERM");
        remember(replied, d.requestID, 500); // a request still waiting on the session lane is dropped
        return;
      }
      const where = event.location?.directory;
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
          const out = await runHook(
            {
              hook_event_name: "PermissionRequest",
              session_id: d.sessionID,
              cwd,
              tool_name: d.action || "permission",
              tool_input: { command: detail },
            },
            cwd,
            waits,
            d.id,
          );
          const decision = out && out.decision;
          if (decision !== "allow" && decision !== "deny") return;
          await ctx.permission
            .reply({
              sessionID: d.sessionID,
              requestID: d.id,
              decision: decision === "allow" ? "once" : "reject",
              ...(decision === "deny" ? { message: "Denied from SimpleTerm" } : {}),
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
            await runHook({ hook_event_name: "UserPromptSubmit", session_id: d.sessionID, cwd }, cwd, undefined, undefined, job);
          });
        case "session.execution.succeeded":
        case "session.execution.failed":
          return inLane(d.sessionID, (job) => turnEnd(event, d, cwd, running, open, job));
        case "form.created": {
          // data: { form: { id, sessionID, title, fields, ... } }
          const form = d.form || d;
          await runHook(
            {
              hook_event_name: "Notification",
              session_id: form.sessionID,
              cwd,
              message: String(form.title || form.message || ""),
            },
            cwd,
          );
          return;
        }
      }
    }

    async function turnEnd(event, d, cwd, running, open, job) {
      const info = await sessionInfo(ctx, d.sessionID);
      sessions.parent.set(d.sessionID, info.parentID || "");
      if (info.parentID) return; // a subagent's session
      const failed = event.type === "session.execution.failed";
      if (!failed && (await hasRunningChild(ctx, d.sessionID, running))) return;
      const background = failed ? [] : await openShellsOf(ctx, d.sessionID, open);
      const err = d.error || {};
      if (job.abandoned) return;
      await runHook(
        failed
          ? {
              hook_event_name: "StopFailure",
              session_id: d.sessionID,
              cwd,
              error: String(err.type || "error"),
              last_assistant_message: String(err.message || ""),
            }
          : {
              hook_event_name: "Stop",
              session_id: d.sessionID,
              cwd,
              last_assistant_message: String(info.title || ""),
              ...(background.length ? { background_tasks: background } : {}),
            },
        cwd,
        undefined,
        undefined,
        job,
      );
    }

    (async () => {
      for await (const event of ctx.event.subscribe({ types: TYPES, signal: controller.signal })) {
        handle(event).catch(() => {});
      }
    })().catch(() => {});

    return () => {
      controller.abort();
      for (const child of waits.values()) child.kill("SIGTERM");
    };
  },
};
