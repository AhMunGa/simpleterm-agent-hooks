// SimpleTerm agent hooks for OpenCode 2.x: the TUI part (package export
// "./tui"). OpenCode loads it in every TUI process, so its environment is that
// of the terminal tab the TUI runs in, while the server part (index.js) runs
// in the shared background service, whose environment is that of the process
// that started the service. This part tells the server part, over the plugin
// RPC simpleterm-tab, which root session this TUI shows (cur), which ones it
// showed that are still tabs (seen), and this tab's marker, SIMPLETERM and
// multiplexer variables (SimpleTerm if/hook-tab-opencode#claims).
//
// Nothing here may break OpenCode: without a client or the plugin RPC, or
// when a call fails, nothing changes. It writes nothing to disk. No imports
// from OpenCode.

// The RPC contract; the server part registers the same shape.
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
// The tab's variables the hook reads besides the marker (if/hook-tab-identity#rules).
const NAMES = ["TMUX", "TMUX_PANE", "STY", "HERDR_ENV", "HERDR_PANE_ID", "HERDR_SESSION", "HERDR_SOCKET_PATH"];
const VALUE_MAX = 1024; // bytes; a longer value is left out (if/hook-tab-opencode#bytes)
const SEEN_MAX = 32;
// A route change raises no TUI event: look every LOOK_MS, and at once on
// the events below.
const LOOK_MS = 250;
const WAKE = new Set(["session.created", "session.execution.started", "permission.asked", "form.created"]);
// Sent again this often though nothing changed: the server part drops a
// claim 90 s after its time.
const BEAT_MS = 30000;
// A call with no answer in CALL_MS failed (a service gone without closing).
// After FAST_TRIES failures in a row (2 s of looks, longer than a new service
// takes to register the server part) the next call waits BACKOFF_MS, doubled
// each time up to BACKOFF_MAX, until one succeeds or server.connected comes.
const CALL_MS = 5000;
const FAST_TRIES = 8;
const BACKOFF_MS = 2000;
const BACKOFF_MAX = 5000;

function identity(env) {
  const vars = {};
  for (const name of NAMES) {
    const v = env[name];
    if (typeof v === "string" && Buffer.byteLength(v) <= VALUE_MAX) vars[name] = v;
  }
  const tab = typeof env.LC_SIMPLETERM_TAB === "string" && Buffer.byteLength(env.LC_SIMPLETERM_TAB) <= VALUE_MAX ? env.LC_SIMPLETERM_TAB : "";
  return { tab, st: env.SIMPLETERM === "1", env: vars };
}

// p, or a rejection after ms.
function within(p, ms) {
  let timer;
  const late = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error("timeout")), ms);
    if (timer && typeof timer.unref === "function") timer.unref();
  });
  return Promise.race([p, late]).finally(() => clearTimeout(timer));
}

function setup(ctx) {
  const me = identity(process.env);
  // Root sessions this TUI has had as cur, most recent first.
  const shown = [];
  let lastKey = null; // what was last sent; null: send at the next look
  let lastAt = 0;
  let sending = false;
  let stopped = false;
  let fails = 0; // failed calls in a row
  let nextAt = 0; // no call before this, but a forced one

  const root = (id) => {
    try {
      const r = ctx.data.session.root(id);
      return typeof r === "string" && r ? r : id;
    } catch {
      return id; // not in the TUI's data yet
    }
  };

  function current() {
    let cur = "";
    try {
      const route = ctx.ui.router.current();
      if (route && route.type === "session" && typeof route.sessionID === "string" && route.sessionID) cur = root(route.sessionID);
    } catch {
      // no route API
    }
    if (cur) {
      const i = shown.indexOf(cur);
      if (i !== 0) {
        if (i > 0) shown.splice(i, 1);
        shown.unshift(cur);
        if (shown.length > 256) shown.length = 256;
      }
    }
    let seen = [];
    try {
      // Tabs off (herdr's default): no seen.
      if (ctx.ui.tabs.enabled()) {
        const open = new Set();
        for (const t of ctx.ui.tabs.list() || []) if (t && typeof t.sessionID === "string" && t.sessionID) open.add(root(t.sessionID));
        seen = shown.filter((id) => id !== cur && open.has(id)).slice(0, SEEN_MAX);
      }
    } catch {
      seen = [];
    }
    return { cur, seen };
  }

  async function look(force) {
    if (stopped || sending) return;
    if (!force && Date.now() < nextAt) return;
    const { cur, seen } = current();
    const key = cur + "\n" + seen.join(",");
    if (!force && key === lastKey && Date.now() - lastAt < BEAT_MS) return;
    // ctx.client changes when the service restarts: read it at every call.
    const client = ctx.client;
    if (!client || typeof client.rpc !== "function") return;
    sending = true;
    try {
      const rpc = client.rpc(TAB_RPC);
      const input = { v: 1, pid: process.pid, t: Date.now(), tab: me.tab, st: me.st, env: me.env, cur, seen };
      // At this TUI's location, read now (none at setup on a new service).
      const loc = ctx.location;
      const dir = loc && typeof loc.directory === "string" ? loc.directory : "";
      await within(dir ? rpc.claim(input, { location: { directory: dir } }) : rpc.claim(input), CALL_MS);
      lastKey = key;
      lastAt = Date.now();
      fails = 0;
      nextAt = 0;
    } catch {
      // rpc.unavailable (the server part not registered yet, the service
      // restarting), no answer, or any failure: sent again at the next look,
      // spaced out after FAST_TRIES in a row.
      lastKey = null;
      fails += 1;
      nextAt = fails > FAST_TRIES ? Date.now() + Math.min(BACKOFF_MS * 2 ** (fails - FAST_TRIES - 1), BACKOFF_MAX) : 0;
    } finally {
      sending = false;
    }
  }

  let stopListen = null;
  try {
    stopListen = ctx.data.listen((arg) => {
      const type = arg && (arg.details ? arg.details.type : arg.type);
      if (type === "server.connected") look(true);
      else if (WAKE.has(type)) look(false);
    });
  } catch {
    // no event API: the looks alone
  }
  const timer = setInterval(() => look(false), LOOK_MS);
  if (timer && typeof timer.unref === "function") timer.unref();
  look(true);

  // The claim lapses by itself: the server part drops it when this process is
  // gone or 90 s after its time.
  return () => {
    stopped = true;
    clearInterval(timer);
    try {
      if (typeof stopListen === "function") stopListen();
    } catch {
      // already gone
    }
  };
}

export default {
  id: "simpleterm.tui",
  setup(ctx) {
    try {
      return setup(ctx);
    } catch {
      return undefined; // never break the TUI
    }
  },
};
