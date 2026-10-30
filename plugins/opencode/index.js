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
];

// Each project directory gets its own plugin instance and every instance sees
// every event: handle an event once, in the instance of its directory.
const seen = (globalThis.__simpletermSeen ??= new Set());
// Which sessions are running and whose child each one is, as every instance
// sees it (an event may be handled by any of them).
const sessions = (globalThis.__simpletermSessions ??= { running: new Set(), parent: new Map() });

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
function runHook(event, cwd, waits, key) {
  return new Promise((resolve) => {
    let out = "";
    let child;
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

export default {
  id: "simpleterm",
  setup(ctx) {
    const controller = new AbortController();
    const waits = new Map();
    const home = ctx.location?.directory;

    async function handle(event) {
      track(event);
      const running = event.type === "session.execution.succeeded" ? [...sessions.running] : [];
      const d = event.data || {};
      if (event.type === "permission.replied") {
        // Answered (in the terminal, or by us): stop waiting for a device.
        // Every instance looks; the waiting one may not see this event first.
        const child = waits.get(d.requestID);
        if (child) child.kill("SIGTERM");
        return;
      }
      const where = event.location?.directory;
      if (where && home && where !== home) return;
      if (!firstSeen(event.id)) return;
      const cwd = where || home;
      switch (event.type) {
        case "permission.asked": {
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
        case "session.execution.succeeded":
        case "session.execution.failed": {
          const info = await sessionInfo(ctx, d.sessionID);
          sessions.parent.set(d.sessionID, info.parentID || "");
          if (info.parentID) return; // a subagent's session
          const failed = event.type === "session.execution.failed";
          if (!failed && (await hasRunningChild(ctx, d.sessionID, running))) return;
          const err = d.error || {};
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
                },
            cwd,
          );
          return;
        }
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
