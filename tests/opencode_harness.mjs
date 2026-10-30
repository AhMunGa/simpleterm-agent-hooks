// Drives the OpenCode plugins with fake OpenCode objects (tests only).
//   node tests/opencode_harness.mjs v1|v2 <plugin file> '<scenario JSON>'
// scenario: {directory, instances?: [dir], sessions: {id: info}, steps: [{event, gap?} | {sleep: ms}], wait: ms}
// Prints the plugin's calls (permission replies) as JSON on the last line.
import { pathToFileURL } from "node:url";

const [kind, file, scenarioJson] = process.argv.slice(2);
const scenario = JSON.parse(scenarioJson);
const calls = [];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
// Waits up to `ms`, or less once `scenario.replies` permission replies arrived.
async function settle(ms) {
  const want = scenario.replies || 0;
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (want && calls.filter((c) => c.reply).length >= want) return;
    await sleep(100);
  }
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
      session: { get: async ({ sessionID }) => (scenario.sessions || {})[sessionID] || {} },
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
