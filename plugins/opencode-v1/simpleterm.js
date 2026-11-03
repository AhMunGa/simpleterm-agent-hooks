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
import { existsSync, mkdirSync, renameSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HOOK = join(dirname(fileURLToPath(import.meta.url)), "simpleterm-agent-hook.sh");

// The session's tokens and cost as OpenCode keeps them (session info `cost`
// and `tokens`), for the usage event's `cost` (TDS_AGENT_EVENTS_V2 section 9.3).
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

// Open permission requests per session, for the hook (TDS_AGENT_EVENTS_V2
// sections 4.5, 5.5): in 1.19 a `reject` or `always` also settles the
// session's other open requests. Kept in ~/.simpleterm/run/oc.<session>.pending.
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

export const SimpleTermAgentHooks = async ({ client, directory }) => {
  const waits = new Map();
  const pending = new Map();
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
  // 1.19 replies through the client's raw HTTP (with a reason); 1.0 has only
  // the session route (no reason).
  const raw = client && client._client;
  async function post(url, path, body) {
    return raw.post({ url, path, body, headers: { "Content-Type": "application/json" } });
  }
  // Sessions OpenCode reports busy. With background subagents (1.19,
  // OPENCODE_EXPERIMENTAL_BACKGROUND_SUBAGENTS) the parent goes idle while a
  // child still works, and the child's report wakes the parent again.
  const busy = new Set();

  async function session(id) {
    try {
      const r = await client.session.get({ path: { id } });
      return (r && r.data) || {};
    } catch {
      return {};
    }
  }

  async function busyChild(id) {
    for (const other of [...busy]) {
      if (other !== id && (await session(other)).parentID === id) return true;
    }
    return false;
  }

  async function handle(event) {
    const p = event.properties || {};
    if (event.type === "session.status" && p.sessionID) {
      const type = p.status && p.status.type;
      if (type === "busy" || type === "retry") {
        busy.add(p.sessionID);
        if (busy.size > 500) busy.delete(busy.values().next().value);
      } else if (type === "idle") busy.delete(p.sessionID);
    }
    switch (event.type) {
      // 1.19: permission.asked {id, sessionID, permission, patterns, metadata}
      // 1.0:  permission.updated {id, sessionID, type, pattern, title, metadata}
      case "permission.asked":
      case "permission.updated": {
        const v19 = event.type === "permission.asked";
        const m = p.metadata || {};
        const patterns = Array.isArray(p.patterns) ? p.patterns : Array.isArray(p.pattern) ? p.pattern : [p.pattern];
        const detail = m.command || m.filepath || m.url || m.query || p.title || patterns.filter(Boolean).join(" ");
        const others = [...(pending.get(p.sessionID) || [])].filter((id) => id !== p.id);
        openRequest(p.sessionID, p.id);
        const parent = (await session(p.sessionID)).parentID;
        const scope = v19 ? (Array.isArray(p.always) ? p.always : []) : patterns.filter(Boolean);
        const out = await runHook(
          {
            hook_event_name: "PermissionRequest",
            session_id: p.sessionID,
            cwd: directory,
            tool_name: p.permission || p.type || "permission",
            tool_input: { command: String(detail || "") },
            // event format v2 (TDS_AGENT_EVENTS_V2 sections 4, 10.2)
            oc: v19 ? "1.19" : "1.0",
            request_id: String(p.id || ""),
            patterns: patterns.filter(Boolean).map(String),
            always: scope.map(String),
            metadata: m,
            ...(others.length && v19 ? { others } : {}),
            ...(parent ? { parent_session_id: parent } : {}),
            ...(p.tool && p.tool.messageID ? { message_id: String(p.tool.messageID) } : {}),
          },
          directory,
          waits,
          p.id,
        );
        const decision = out && out.decision;
        if (decision !== "allow" && decision !== "deny") return;
        const reply = decision === "allow" ? (out.scope === "always" ? "always" : "once") : "reject";
        if (v19 && raw) {
          // A reason goes to the model with a rejection (1.19).
          await post("/permission/{requestID}/reply", { requestID: p.id }, {
            reply,
            ...(reply === "reject" && typeof out.message === "string" && out.message ? { message: out.message } : {}),
          }).catch(() => {}); // answered in the terminal first
          return;
        }
        await client
          .postSessionIdPermissionsPermissionId({
            path: { id: p.sessionID, permissionID: p.id },
            body: { response: reply },
          })
          .catch(() => {}); // answered in the terminal first
        return;
      }
      case "permission.replied": {
        // Answered (in the terminal, or by us): stop waiting for a device.
        const id = p.requestID || p.permissionID;
        const child = waits.get(id);
        if (child) child.kill("SIGTERM");
        closeRequest(id);
        return;
      }
      case "question.asked": {
        // 1.19: {id, sessionID, questions: [{question, header, options: [{label, description}], multiple}]}.
        // A device's answer goes to /question/{id}/reply ({answers: [[...]]}),
        // a refusal to /reject (no reason there; the session stops).
        if (!raw) return;
        const qs = Array.isArray(p.questions) ? p.questions : [];
        const out = await runHook(
          {
            hook_event_name: "Question",
            session_id: p.sessionID,
            cwd: directory,
            oc: "1.19",
            request_id: String(p.id || ""),
            tool_input: { questions: [{ question: String((qs[0] && qs[0].question) || "") }] },
            questions: qs,
          },
          directory,
          waits,
          p.id,
        );
        const decision = out && out.decision;
        if (decision === "answer" && Array.isArray(out.answers)) {
          await post("/question/{requestID}/reply", { requestID: p.id }, { answers: out.answers }).catch(() => {});
        } else if (decision === "deny") {
          await post("/question/{requestID}/reject", { requestID: p.id }, undefined).catch(() => {});
        }
        return;
      }
      case "question.replied":
      case "question.rejected": {
        // Answered in the terminal first: stop waiting for a device.
        const child = waits.get(p.requestID || p.id);
        if (child) child.kill("SIGTERM");
        return;
      }
      case "session.idle": {
        busy.delete(p.sessionID);
        const info = await session(p.sessionID);
        if (info.parentID) return; // a subagent's session
        if (await busyChild(p.sessionID)) return; // its report wakes this one
        await runHook(
          { hook_event_name: "Stop", session_id: p.sessionID, cwd: directory, last_assistant_message: String(info.title || ""), title: String(info.title || ""), oc: "1", ...usage(info) },
          directory,
        );
        return;
      }
      case "session.error": {
        // An errored session is no longer busy: a stuck entry would hold
        // its parent's done back for good.
        busy.delete(p.sessionID);
        const e = p.error || {};
        if (e.name === "MessageAbortedError") return; // stopped by the user
        await runHook(
          {
            hook_event_name: "StopFailure",
            oc: "1",
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
