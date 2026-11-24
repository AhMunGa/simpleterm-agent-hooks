// Drives the OpenCode plugins with fake OpenCode objects (tests only).
//   node tests/opencode_harness.mjs v1|v2|tui <plugin file> '<scenario JSON>'
// scenario: {directory, env?, getDelay?, instances?: [dir], sessions: {id: info}, schedules?: {id: [Schedule.Info]},
//            steps: [{event, gap?} | {sleep: ms} | {schedules: {id: [Schedule.Info]}}], wait: ms}
// wait: the most to wait at the end for the plugin to finish (settle()).
// schedules: OpenCode's schedule_list tool (ctx.tool.list) answers with that session's list; a step replaces it.
// automations: [Automation.Info] of the project (2.4's automation tools, after a browser tool also named `list`);
//   a step {automations: [...]} replaces it.
// rpc: true gives the plugin ctx.rpc (2.4's plugin RPC); a step {claim: {...}, via?: directory} calls the `claim`
//   handler registered at that directory (default: the first instance's). In a claim "$self" is this process's pid,
//   "$p0".."$pN" the pids of scenario.sleepers child processes, "$dead" one that has exited, "$now" and "$old"
//   (91 s ago) times.
// tui: the TUI part with a fake TUI context: scenario {env, route, tabs, enabled, roots, location, noClient, steps:
//   [{route} | {tabs: [session ids]} | {enabled} | {roots} | {location} | {fail: n} | {client: label} | {emit: type}
//   | {mark} | {sleep}]}; every claim call is recorded with its time.
// Prints the plugin's calls (permission replies) as JSON on the last line.
import { spawn, spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";

const [kind, file, scenarioJson] = process.argv.slice(2);
const scenario = JSON.parse(scenarioJson);
const calls = [];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
// What the plugin has under way, as Node counts it: a hook it runs (ProcessWrap), a timer (its lane
// limit, schedule_list's limit, a slow session lookup here), a file request. Between two of this
// harness's own sleeps nothing else can be pending: work that waits on none of these never resumes.
const BUSY = new Set(["ProcessWrap", "Timeout", "Immediate", "FSReqCallback", "FSReqPromise", "FileHandle"]);
const idle = () => !process.getActiveResourcesInfo().some((r) => BUSY.has(r));
// Waits until the plugin is idle (twice in a row, 100 ms apart) or `scenario.replies` permission
// replies arrived; `ms` at most (then the test's own checks say what is missing).
async function settle(ms) {
  const want = scenario.replies || 0;
  const end = Date.now() + ms;
  let quiet = 0;
  while (Date.now() < end) {
    if (want && calls.filter((c) => c.reply).length >= want) return;
    quiet = idle() ? quiet + 1 : 0;
    if (quiet >= 2) return;
    await sleep(100);
  }
}
// scenario.env: environment of the plugin (read when it loads).
Object.assign(process.env, scenario.env || {});
// scenario.getDelay: {sessionID: {ms, times}}: the first `times` session lookups of a session take `ms` (2.x only).
const delays = JSON.parse(JSON.stringify(scenario.getDelay || {}));
const schedules = { ...(scenario.schedules || {}) };
let automations = scenario.automations || null;
// Live processes for the claims' pids (killed at the end), and one that has exited.
const pids = { $self: process.pid };
const sleepers = [];
for (let i = 0; i < (scenario.sleepers || 0); i++) {
  const c = spawn("sleep", ["300"], { stdio: "ignore" });
  c.unref(); // not counted by settle()
  sleepers.push(c);
  pids["$p" + i] = c.pid;
}
const gone = spawnSync("sh", ["-c", "echo $$"]);
pids.$dead = Number(String(gone.stdout).trim()) || 999999;
function fill(v) {
  if (typeof v === "string" && v in pids) return pids[v];
  if (v === "$now") return Date.now();
  if (v === "$old") return Date.now() - 91000;
  if (Array.isArray(v)) return v.map(fill);
  if (v && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, fill(x)]));
  return v;
}
const mod = await import(pathToFileURL(file).href);

if (kind === "v1") {
  const client = {
    postSessionIdPermissionsPermissionId: async (args) => {
      calls.push({ reply: args });
      return { data: true };
    },
    session: { get: async ({ path }) => ({ data: (scenario.sessions || {})[path.id] || {} }) },
  };
  // scenario.raw: the client's raw HTTP (1.19), which carries a reason and the question routes.
  if (scenario.raw) {
    client._client = {
      post: async (args) => {
        calls.push({ reply: { url: args.url, path: args.path, body: args.body } });
        return { response: { status: 200 }, data: true };
      },
    };
  }
  const entries = Object.entries(mod);
  calls.push({ exports: entries.map(([k, v]) => [k, typeof v]) });
  const hooks = [];
  for (const [, fn] of entries) hooks.push(await fn({ client, directory: scenario.directory, worktree: scenario.directory, project: {}, $: null }));
  for (const step of scenario.steps) {
    if (step.sleep) await sleep(step.sleep);
    else for (const h of hooks) h.event && h.event({ event: step.event });
  }
  await settle(scenario.wait || 1000);
} else if (kind === "tui") {
  const def = mod.default;
  calls.push({ id: def.id, setup: typeof def.setup });
  const st = { route: scenario.route || { type: "home" }, tabs: scenario.tabs || [], enabled: scenario.enabled !== false,
               roots: scenario.roots || {}, location: scenario.location || "", fail: scenario.fail || 0 };
  const listeners = new Set();
  const t0 = Date.now();
  const mkClient = (label) => ({
    rpc: (d) => ({
      claim: async (input, opts) => {
        if (st.fail > 0) {
          st.fail -= 1;
          calls.push({ failed: label, at: Date.now() - t0 });
          const e = new Error("rpc.unavailable");
          e.type = "rpc.unavailable";
          throw e;
        }
        calls.push({ claim: input, opts: opts === undefined ? null : opts, rpc: d && d.id, client: label, at: Date.now() - t0 });
        return {};
      },
    }),
  });
  let client = mkClient(1);
  const ctx = {
    get location() { return st.location ? { directory: st.location } : undefined; },
    get client() { return scenario.noClient ? undefined : client; },
    ui: {
      router: { current: () => st.route },
      tabs: {
        enabled: () => st.enabled,
        list: () => st.tabs.map((id) => ({ sessionID: id, active: !!st.route && st.route.sessionID === id, busy: false, attention: false })),
      },
    },
    data: {
      session: { root: (id) => st.roots[id] || id },
      listen: (h) => { listeners.add(h); return () => listeners.delete(h); },
    },
  };
  const cleanup = await def.setup(ctx);
  for (const step of scenario.steps || []) {
    if (step.sleep) await sleep(step.sleep);
    else if ("route" in step) st.route = step.route;
    else if ("tabs" in step) st.tabs = step.tabs;
    else if ("enabled" in step) st.enabled = step.enabled;
    else if ("roots" in step) st.roots = step.roots;
    else if ("location" in step) st.location = step.location;
    else if ("fail" in step) st.fail = step.fail;
    else if ("client" in step) client = mkClient(step.client);
    else if ("emit" in step) for (const h of [...listeners]) h({ details: { type: step.emit, data: {} } });
    else if ("mark" in step) calls.push({ mark: step.mark, at: Date.now() - t0 });
  }
  if (typeof cleanup === "function") cleanup();
  calls.push({ end: Date.now() - t0, listeners: listeners.size });
} else {
  // One instance per directory (scenario.instances, default [directory]); like
  // OpenCode, every instance gets every event, in the listed order.
  const def = mod.default;
  calls.push({ id: def.id, setup: typeof def.setup });
  const instances = [];
  const regs = [];
  const tools = () => {
    const list = [];
    if (automations) {
      list.push({ id: "browser_list", name: "list", options: { namespace: "browser" },
                  execute: async () => { calls.push({ tool: "browser_list" }); return { output: { tabs: [] } }; } });
      list.push({ id: "automation_list", name: "list", options: { namespace: "automation", codemode: true },
                  execute: async (_args, c) => {
                    calls.push({ tool: "automation_list", sid: c && c.sessionID });
                    return { output: { now: new Date().toISOString(), automations: automations || [] }, content: [] };
                  } });
    }
    if (scenario.schedules) {
      list.push({
        name: "schedule_list",
        execute: async (_args, c) => {
          calls.push({ schedule_list: c && c.sessionID });
          return { output: { now: Date.now(), schedules: schedules[c && c.sessionID] || [] } };
        },
      });
    }
    return list;
  };
  for (const directory of scenario.instances || [scenario.directory]) {
    const inst = { queue: [], wake: null };
    const ctx = {
      location: { directory },
      event: {
        subscribe: (opts) => {
          if (!instances.length) calls.push({ subscribed: opts.types });
          return {
            [Symbol.asyncIterator]() {
              return {
                next: async () => {
                  while (!inst.queue.length) {
                    if (opts.signal && opts.signal.aborted) return { done: true, value: undefined };
                    await new Promise((r) => (inst.wake = r));
                  }
                  return { done: false, value: inst.queue.shift() };
                },
              };
            },
          };
        },
      },
      permission: { reply: async (args) => { calls.push({ reply: args, directory }); } },
      ...(scenario.schedules || automations ? { tool: { list: async () => tools() } } : {}),
      ...(scenario.rpc
        ? {
            rpc: {
              register: async (def, handlers) => {
                regs.push({ directory, def, handlers });
                if (regs.length === 1) calls.push({ registered: def && def.id });
                return { dispose() {} };
              },
            },
          }
        : {}),
      session: {
        get: async ({ sessionID }) => {
          const dl = delays[sessionID];
          if (dl && dl.times > 0) {
            dl.times -= 1;
            await sleep(dl.ms);
          }
          return (scenario.sessions || {})[sessionID] || {};
        },
      },
    };
    inst.cleanup = await def.setup(ctx);
    instances.push(inst);
  }
  const wakeAll = () => {
    for (const inst of instances) {
      const w = inst.wake;
      inst.wake = null;
      if (w) w();
    }
  };
  if (scenario.rpc) {
    const until = Date.now() + 2000;
    while (regs.length < instances.length && Date.now() < until) await sleep(10);
  }
  const first = (scenario.instances || [scenario.directory])[0];
  for (const step of scenario.steps) {
    if (step.sleep) await sleep(step.sleep);
    else if (step.schedules) Object.assign(schedules, step.schedules);
    else if (step.automations) automations = step.automations;
    else if (step.claim) {
      const reg = regs.find((r) => r.directory === (step.via || first)) || regs[0];
      let out;
      try {
        out = reg ? await reg.handlers.claim(fill(step.claim), {}) : "no registration";
      } catch (e) {
        out = "threw " + String((e && e.message) || e);
      }
      calls.push({ claimed: out === undefined ? null : out });
      await sleep(step.gap ?? 20);
    } else {
      for (const inst of instances) inst.queue.push(step.event);
      wakeAll();
      await sleep(step.gap ?? 50);
    }
  }
  await settle(scenario.wait || 1000);
  for (const inst of instances) if (typeof inst.cleanup === "function") inst.cleanup();
  wakeAll();
}
for (const c of sleepers) c.kill("SIGTERM");
console.log(JSON.stringify(calls));
process.exit(0);
