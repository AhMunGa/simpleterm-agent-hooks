// SimpleTerm agent hooks for OpenCode 1.x: permission approvals from a
// SimpleTerm device, and done / error alerts. Install: put this file and
// simpleterm-agent-hook.sh in ~/.config/opencode/plugins/ (see the README).
//
// The work is done by simpleterm-agent-hook.sh next to this file (the same
// script as the Claude Code and Codex plugin), run as
// `sh simpleterm-agent-hook.sh opencode` with a Claude-shaped event on stdin.
// For a permission request it waits for a device's answer and prints
// {"decision":"allow"|"deny"}; whichever answers first, the device or the
// terminal prompt, wins.
//
// OpenCode 1.x loads every export of this file as a plugin function (1.19
// rejects anything else): export nothing but the plugin.

import { spawn } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HOOK = join(dirname(fileURLToPath(import.meta.url)), "simpleterm-agent-hook.sh");

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

export const SimpleTermAgentHooks = async ({ client, directory }) => {
  const waits = new Map();

  async function session(id) {
    try {
      const r = await client.session.get({ path: { id } });
      return (r && r.data) || {};
    } catch {
      return {};
    }
  }

  async function handle(event) {
    const p = event.properties || {};
    switch (event.type) {
      // 1.19: permission.asked {id, sessionID, permission, patterns, metadata}
      // 1.0:  permission.updated {id, sessionID, type, pattern, title, metadata}
      case "permission.asked":
      case "permission.updated": {
        const m = p.metadata || {};
        const patterns = Array.isArray(p.patterns) ? p.patterns : Array.isArray(p.pattern) ? p.pattern : [p.pattern];
        const detail = m.command || m.filepath || m.url || m.query || p.title || patterns.filter(Boolean).join(" ");
        const out = await runHook(
          {
            hook_event_name: "PermissionRequest",
            session_id: p.sessionID,
            cwd: directory,
            tool_name: p.permission || p.type || "permission",
            tool_input: { command: String(detail || "") },
          },
          directory,
          waits,
          p.id,
        );
        const decision = out && out.decision;
        if (decision !== "allow" && decision !== "deny") return;
        await client
          .postSessionIdPermissionsPermissionId({
            path: { id: p.sessionID, permissionID: p.id },
            body: { response: decision === "allow" ? "once" : "reject" },
          })
          .catch(() => {}); // answered in the terminal first
        return;
      }
      case "permission.replied": {
        // Answered (in the terminal, or by us): stop waiting for a device.
        const child = waits.get(p.requestID || p.permissionID);
        if (child) child.kill("SIGTERM");
        return;
      }
      case "session.idle": {
        const info = await session(p.sessionID);
        if (info.parentID) return; // a subagent's session
        await runHook(
          { hook_event_name: "Stop", session_id: p.sessionID, cwd: directory, last_assistant_message: String(info.title || "") },
          directory,
        );
        return;
      }
      case "session.error": {
        const e = p.error || {};
        if (e.name === "MessageAbortedError") return; // stopped by the user
        await runHook(
          {
            hook_event_name: "StopFailure",
            session_id: p.sessionID || "",
            cwd: directory,
            error: String(e.name || "error"),
            last_assistant_message: String((e.data && e.data.message) || ""),
          },
          directory,
        );
        return;
      }
    }
  }

  return {
    event: async ({ event }) => {
      handle(event).catch(() => {});
    },
  };
};
