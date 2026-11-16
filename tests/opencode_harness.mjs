// Drives the OpenCode plugins with fake OpenCode objects (tests only).
//   node tests/opencode_harness.mjs v1|v2 <plugin file> '<scenario JSON>'
// scenario: {directory, env?, getDelay?, instances?: [dir], sessions: {id: info}, schedules?: {id: [Schedule.Info]},
//            steps: [{event, gap?} | {sleep: ms} | {schedules: {id: [Schedule.Info]}}], wait: ms}
// wait: the most to wait at the end for the plugin to finish (settle()).
// schedules: OpenCode's schedule_list tool (ctx.tool.list) answers with that session's list; a step replaces it.
// Prints the plugin's calls (permission replies) as JSON on the last line.
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
} else {
  // One instance per directory (scenario.instances, default [directory]); like
  // OpenCode, every instance gets every event, in the listed order.
  const def = mod.default;
  calls.push({ id: def.id, setup: typeof def.setup });
  const instances = [];
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
      ...(scenario.schedules
        ? {
            tool: {
              list: async () => [
                {
                  name: "schedule_list",
                  execute: async (_args, c) => {
                    calls.push({ schedule_list: c && c.sessionID });
                    return { output: { now: Date.now(), schedules: schedules[c && c.sessionID] || [] } };
                  },
                },
              ],
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
  for (const step of scenario.steps) {
    if (step.sleep) await sleep(step.sleep);
    else if (step.schedules) Object.assign(schedules, step.schedules);
    else {
      for (const inst of instances) inst.queue.push(step.event);
      wakeAll();
      await sleep(step.gap ?? 50);
    }
  }
  await settle(scenario.wait || 1000);
  for (const inst of instances) if (typeof inst.cleanup === "function") inst.cleanup();
  wakeAll();
}
console.log(JSON.stringify(calls));
process.exit(0);
