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
  "session.execution.succeeded",
  "session.execution.failed",
  "form.created",
];

// Each project directory gets its own plugin instance and every instance sees
// every event: handle an event once, in the instance of its directory.
const seen = (globalThis.__simpletermSeen ??= new Set());

function firstSeen(id) {
  if (!id) return true;
  if (seen.has(id)) return false;
  seen.add(id);
  if (seen.size > 500) seen.delete(seen.values().next().value);
  return true;
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

export default {
  id: "simpleterm",
  setup(ctx) {
    const controller = new AbortController();
    const waits = new Map();
    const home = ctx.location?.directory;

    async function handle(event) {
      const where = event.location?.directory;
      if (where && home && where !== home) return;
      if (!firstSeen(event.id)) return;
      const d = event.data || {};
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
        case "permission.replied": {
          // Answered (in the terminal, or by us): stop waiting for a device.
          const child = waits.get(d.requestID);
          if (child) child.kill("SIGTERM");
          return;
        }
        case "session.execution.succeeded":
        case "session.execution.failed": {
          const info = await sessionInfo(ctx, d.sessionID);
          if (info.parentID) return; // a subagent's session
          const failed = event.type === "session.execution.failed";
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
          await runHook(
            {
              hook_event_name: "Notification",
              session_id: d.sessionID,
              cwd,
              message: String(d.title || d.message || ""),
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
