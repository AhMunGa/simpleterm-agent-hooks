# SimpleTerm agent hooks

Hooks that connect a coding agent on your server to the SimpleTerm iPad/phone SSH app:

- **Alerts**: end-to-end encrypted notifications when the agent finishes, asks a question,
  hits an error, or needs a permission.
- **Approvals and answers**: approve or deny a permission request from the app, with a reason or
  for a scope the agent suggested, answer an agent's question, approve a plan. The hook waits for
  your answer and hands it to the agent. If no answer comes, the agent's own prompt in the
  terminal stays in charge.
- **What is asked**: the command, the diff, the URL, the questions and their choices, the plan, and
  which answers the agent takes from a hook (event format v2, see below).
- **Status badges** (Claude Code): the terminal tab shows running, waiting for approval, or done.
- **Context and rate limits**: how full the agent's context window is and, where the agent
  reports it, how much of its rate limits is used.
- **`simpleterm notify`**: the same alerts from your own scripts.

One repository serves eight agents: Claude Code, Codex, GitHub Copilot CLI, Antigravity CLI,
Grok Build, OpenCode 2.x and 1.x, and Gemini CLI.

## What each agent supports

| Agent | Alerts | Answer from the device | Badge | Context / limits |
|---|---|---|---|---|
| Claude Code | permission, question, plan, done, error, sign-in | allow, allow for a suggested scope, deny, deny with a reason, answer a question, approve a plan (default or accept edits) or ask for changes; the terminal prompt stays open, first answer wins (waits up to 540 s) | yes | context; 5-hour, 7-day and per-model limits by [asking Claude Code](#asking-the-agent-for-its-limits) or the [status line tap](#context-and-rate-limits) |
| Codex | permission, plan, done | allow, deny, deny with a reason: in the connected app, or from another device when no app is connected (Codex hides its prompt while a hook waits, up to 60 s) | Codex sends OSC 7501 itself | context, limits (the rollout and [asking Codex](#asking-the-agent-for-its-limits)), plan |
| GitHub Copilot CLI | permission and question (alerts), plan, done, error | not yet: its permission hook also runs for calls that never prompt, so it is not used until those can be told apart | no | premium requests, chat and completions quota (from its session events) |
| Antigravity CLI (`agy`) | question, plan, done, error; commands, file writes and edits, reads outside the workspace, MCP calls with `agy_wait` | opt-in (`agy_wait`, only while the app is not connected): allow, deny, deny with a reason, approve a plan | agy sends OSC 7501 itself | no |
| Grok Build | permission, question and plan (alerts), idle question, done, error | no: a Grok hook can block but not approve | no | session tokens and cost |
| OpenCode 2.x | permission, question (input form, alert), done, error | allow, always (the pattern), deny, deny with a reason; device or terminal, first answer wins | the TUI sends OSC 7501 itself | session tokens and cost |
| OpenCode 1.x | permission, question, done, error | allow, always, deny (1.19: with a reason), answer a question (1.19); device or terminal, first answer wins | no | session tokens and cost |
| Gemini CLI | permission (alert only), done | no: Gemini takes no answer from a hook | no | context |

"Alert only" means the device shows that the agent is waiting; you answer in the terminal.
Which answers a request takes is in the request itself (`req.can`, see [Event format v2](#event-format-v2)):
the app never shows a button the agent would not take.
Windows: Claude Code (through Git Bash) and Codex (PowerShell) only; see [Windows](#windows).

## Requirements

- macOS, Linux or BSD with `sh`, `curl` and `openssl` (OpenSSL 1.1/3.x or LibreSSL 3.3+).
  Without `curl` or `openssl` the hook only writes the status badges. It also sends nothing when
  `printf` is not a shell builtin (OpenBSD `sh`/`ksh`, mksh), so that secrets never appear in the
  process list.
- One of the agents below. Tested with the real CLI: Claude Code 2.1.312 (alerts, approvals,
  context reports), Codex 0.165.0 (alerts and approvals), Gemini CLI 0.63.0 and 0.66.0, GitHub
  Copilot CLI 1.0.105 (the plugin given with `--plugin-dir` and installed with `copilot plugin
  install`, with a local model stub: prompt, done, session end, errors). The event format v2 inputs
  are recorded hook inputs of Claude Code 2.1.316, Codex 0.165.0, OpenCode 1.0.223, 1.19.5 and
  2.2.5, Copilot CLI 1.0.105, Antigravity CLI 1.4.12 and Grok Build 1.0.70 (measured with local
  model stubs), replayed in `tests/`.
- The SimpleTerm app, paired with this server (see [Pair with the SimpleTerm app](#pair-with-the-simpleterm-app)).

## Install

Run the commands for each agent you use on the server. The SimpleTerm app can run them for you
after asking; it does not edit your agents' settings files. It runs the same commands as below,
except where an agent's section says otherwise. Running an install command again changes nothing:
Gemini CLI and Grok Build then report that the plugin is already installed (exit 1), and where a
block clones `~/.simpleterm/src` and you already have it, run
`git -C ~/.simpleterm/src pull --ff-only` instead of the clone.

### Claude Code

```sh
claude plugin marketplace add AhMunGa/simpleterm-agent-hooks
claude plugin install simpleterm@simpleterm-agent-hooks
```

The hooks load in new sessions. In a running session, run `/reload-plugins`.

### Codex

```sh
codex plugin marketplace add AhMunGa/simpleterm-agent-hooks
codex plugin add simpleterm@simpleterm-agent-hooks
```

**Trust the hooks once.** Codex does not run plugin hooks until you review them. Start `codex`;
at **Hooks need review** choose **Trust all and continue** (or open `/hooks`). `codex exec` skips
untrusted hooks without a message, so do this in the interactive `codex` first. Codex asks again
after every update, because trust is tied to the plugin's contents.

### Gemini CLI

```sh
mkdir -p -m 700 ~/.simpleterm
cd ~/.simpleterm && gemini extensions install https://github.com/AhMunGa/simpleterm-agent-hooks --consent --skip-settings
```

With `--consent`, Gemini CLI also trusts the folder the command runs in if it is not trusted yet
(folder trust is on by default), so run it from `~/.simpleterm` rather than from your home or a
project. Gemini installs the whole repository as the extension `simpleterm` (it reads
`gemini-extension.json` and `hooks/hooks.json` at the top). It needs `git`, and it cannot be run
from inside a Gemini session. `~/.simpleterm` is the plugin's own folder, readable only by you.
`--skip-settings` changes nothing for this extension, which has no settings to ask for. The
SimpleTerm app makes the folder itself and runs the second line.

### GitHub Copilot CLI

```sh
copilot plugin marketplace add AhMunGa/simpleterm-agent-hooks
copilot plugin install simpleterm-copilot@simpleterm-agent-hooks
```

Copilot reads its own catalog in this repository (`.github/plugin/marketplace.json`), which lists
only `simpleterm-copilot`; Claude Code and Codex read `.claude-plugin/marketplace.json` and do not
see it. The direct install `copilot plugin install AhMunGa/simpleterm-agent-hooks:plugins/copilot`
still works, but Copilot says direct installs are deprecated. If you installed that way, run
`copilot plugin uninstall simpleterm-copilot` once before installing from the marketplace; with
both, Copilot keeps two copies (the first uninstall removes the direct one).

The plugin is `simpleterm-copilot`, a folder of its own (`plugins/copilot`) with hooks in Copilot's
own format: a session's prompts, the plan review (`exit_plan_mode`), its prompts and questions
(`notification`), the end of a turn (`agentStop`), subagents, errors and the session's end.
Copilot does not read `~/.claude`; do not give it the Claude Code plugin (if you do, the hook sees
`COPILOT_CLI=1` and acts as this plugin, without waiting). Copilot's permission hook runs for every
tool call, also for those that never prompt (read-only commands, already allowed ones), so the
plugin does not register it yet and Copilot's permission prompts are alerts: answer them in the
terminal. Errors that Copilot retries are no alerts; a session that ends on an error is one
(`copilot -p`). Unix only.

### Antigravity CLI (`agy`)

```sh
agy plugin install https://github.com/AhMunGa/simpleterm-agent-hooks/tree/main/plugins/antigravity
```

If your `agy` does not take a GitHub folder, install from a copy:

```sh
mkdir -p -m 700 ~/.simpleterm
git clone --depth 1 https://github.com/AhMunGa/simpleterm-agent-hooks ~/.simpleterm/src
agy plugin install ~/.simpleterm/src/plugins/antigravity
```

Both ways install the same files into `~/.gemini/config/plugins/simpleterm-antigravity` (agy 1.5.4),
and the plugin does not use the copy afterwards. The SimpleTerm app installs from the copy, which
every agy takes.

The plugin is `simpleterm-antigravity`, a folder of its own (`plugins/antigravity`): agy reads
`plugin.json` and `hooks.json` at a plugin's top, and treats a folder with `.claude-plugin/` as a
Claude Code plugin. Check that the hooks loaded with `agy -p "/hooks" --output-format json`.

Each hook command finds the script itself, in this order: `${PLUGIN_ROOT}` and
`${CLAUDE_PLUGIN_ROOT}` (if agy fills them in), the install folder
`~/.gemini/config/plugins/simpleterm-antigravity`, the older install folder from agy's
documentation `~/.gemini/antigravity-cli/plugins/simpleterm-antigravity`, the app's copy
`~/.simpleterm/src/plugins/simpleterm`, and last the folder the hook runs in: agy 1.4.12 runs a
plugin's hooks in the plugin's own folder and gives them no `PLUGIN_ROOT` (measured with a
workspace plugin), so that folder counts, but only when its `plugin.json` names
`simpleterm-antigravity`: a workspace's own `scripts/agent-hook.sh` never runs. If none is there,
`PreToolUse` answers `{"decision":"allow"}`, as the script does when the device did not decide, and
`Stop` prints nothing; all exit 0 (agy reads `{}` from `PreToolUse` as a denial and a failed or
timed-out hook as a failed tool call, measured).

agy has no "waiting for permission" event: its `PreToolUse` hook runs before every tool call,
before agy decides whether to ask. So by default the plugin only alerts for agy's own questions
(`ask_question`), a plan waiting for review, and when the agent stops. To answer from the device
(`run_command`, `write_file`, `edit_file`, `call_mcp_tool`, and `read_file` of a path outside the
workspace folders: agy asks before those reads only), set `agy_wait` (seconds, at most 110) in
`~/.simpleterm/agent-hook.conf`: such a call then first asks the SSH tunnel whether
the app is connected, and only when it is not, waits that long for an answer from another device
before agy's permission policy runs; the terminal shows no prompt meanwhile. With no answer the
policy decides as usual. While the app is connected, agy shows its own prompt and the app answers
it there. A plan for review (agy writes `plan.md` with `RequestFeedback`) is an alert, not a
`done`; with `agy_wait` and no app connected, the `Stop` hook waits for an approval from a device
(a v2 relay) and agy goes on with the plan in the same turn.

**Signing in over SSH.** With SSH variables set, agy keeps its sign-in in a file instead of the
keychain (measured), so on a server you reach by SSH you sign in to agy there once.

### Grok Build

Grok Build runs the hooks of Claude Code plugins that are enabled in `~/.claude/settings.json`.
If the Claude Code plugin above is installed, **Grok already uses it**: install nothing more. The
hook sees Grok's `GROK_HOOK_EVENT` and reports `grok-build` events. Otherwise:

```sh
grok plugin install "AhMunGa/simpleterm-agent-hooks#plugins/simpleterm" --trust
```

Keep the quotes: zsh with `extendedglob` and csh read a bare `#`. Grok loads a plugin name once,
so having both does not send alerts twice (and the hook drops a second copy of the same event
anyway). Grok has no hook that can approve a permission, so its permission waits are alerts only.

### OpenCode 2.x

```sh
opencode plugin add "github:AhMunGa/simpleterm-agent-hooks#main::path:plugins/opencode"
```

`opencode plugin add` records the plugin in `~/.config/opencode/opencode.json`. To leave that
file alone, copy the folder instead: `plugins/opencode` to `~/.config/opencode/plugins/simpleterm/`.
Use one way, not both (OpenCode refuses the same plugin id twice). OpenCode 2.x runs plugins in
a shared background service, so the plugin sends alerts to linked devices but writes nothing to
the terminal.

### OpenCode 1.x

OpenCode 1.x loads every `.js` file in `~/.config/opencode/plugins/`:

```sh
rm -f ~/.config/opencode/plugins/simpleterm.js ~/.config/opencode/plugins/simpleterm-agent-hook.sh
mkdir -p ~/.config/opencode/plugins
curl -fsSL -o ~/.config/opencode/plugins/simpleterm.js https://raw.githubusercontent.com/AhMunGa/simpleterm-agent-hooks/main/plugins/opencode-v1/simpleterm.js
curl -fsSL -o ~/.config/opencode/plugins/simpleterm-agent-hook.sh https://raw.githubusercontent.com/AhMunGa/simpleterm-agent-hooks/main/plugins/opencode-v1/simpleterm-agent-hook.sh
```

The first line removes links that an earlier SimpleTerm app made into `~/.simpleterm/src`
(`curl -o` would write through them). The SimpleTerm app copies the same two files from its copy of
this repository (`~/.simpleterm/src`, as for Antigravity) instead of downloading them, so it needs
only `github.com`; the files have the same content. It works with OpenCode 1.0
(`permission.updated`) and 1.19 (`permission.asked`). OpenCode 2.x lists a 1.x plugin file as
failed and goes on.

## Pair with the SimpleTerm app

The plugin sends no alerts until the app links this server. In SimpleTerm, connect a tab to the
server, open the **Agents** panel and choose **Set up agent alerts**, then **Link this device**
(relay push must be on in Settings > Notifications). Over SFTP the app writes one link file per device to
`~/.simpleterm/links/<linkId>.conf`, holding the relay address and the keys for that device.
Revoking the link in the app stops delivery at the relay. Deleting the file stops the hook from
sending.

Status badges need no link: in a SimpleTerm session (`SIMPLETERM=1`) Claude Code shows them as
soon as the plugin is installed.

### Through the SSH connection (inside tmux too)

While SimpleTerm is connected to a server set up for alerts, it also opens an SSH tunnel: the
server forwards a loopback port (`127.0.0.1`) to the app over that SSH connection, and the app
writes a link file with `kind=tunnel` and that port. The hook talks to it exactly as to the relay
(same encryption and signed answers), so:

- alerts and approvals reach the app inside tmux, screen or zellij, where terminal notifications
  are dropped, and without the relay, an account or a push service;
- a permission answered in the app goes to that exact agent; no keys are typed into the terminal.

The tunnel lives as long as the connection. The app removes its file when the connection ends;
a file left by a dropped connection is removed the next time that device connects. When the
tunnel is gone the hook stops waiting there at once. The server must allow TCP forwarding
(OpenSSH's default `AllowTcpForwarding yes`); otherwise only the relay works.

## What it sends

| Agent event | Alert (`ev`) | Badge (Claude Code, SimpleTerm sessions only) |
|---|---|---|
| Claude `PermissionRequest` | `permission` (waits for your answer, up to 540 s); for `AskUserQuestion` a `question` you can answer where the receiver takes answers (`fmt=2`) | waiting, then running |
| Claude `PreToolUse` `AskUserQuestion`, `Notification` (idle, elicitation, input needed) | `question` (one per question: the `PermissionRequest` of the same question goes first, the `PreToolUse` one only when none came within `ask_delay`; `idle_prompt` only when no `done` was sent or is pending for the turn) | waiting (idle keeps done; `agent_needs_input`, another session's, leaves the badge) |
| Claude `UserPromptSubmit`, `PostToolUse`, `PostToolUseFailure` | none (context, see below) | running |
| Claude `Stop` / `StopFailure` | `done` (sent 3 s later on Claude Code, see below) / `error` or `auth` | done / idle, then error (a login error too) |
| Claude `Stop` with `background_tasks` in flight | none (and no idle question until the next turn), unless the last message asks you something (`question`), only services or tasks that ran before your prompt are left (`done`) | background (+ an OSC 7501 `working` record, see below); waiting (+ a `blocked` record) for a question |
| Claude `Stop` with `session_crons` set, turn started by a schedule | none (a question: `question`) | background, `scheduled: <schedule>` |
| Claude `Stop` with no schedule left, turn started by a schedule | `done` to the SSH tunnel only, at once (the app lists it without an alert); one that ends asking you something is a plain `done` | `done_scheduled` (`done` when it asks) |
| Claude `PostToolUseFailure` with `is_interrupt` (Esc; not for a subagent's tool, `agent_id` set) | none | idle |
| Claude `SessionStart`, `PostCompact`, `PostModelSwitch` | none (context) | none |
| Claude `SessionEnd`, `SubagentStart`, `SubagentStop` | `state` `ended`, `sub_start`, `sub_stop` (SSH tunnel only) | none |
| Codex `PermissionRequest` | `permission`, to the SSH tunnel first; to the relay (waits up to 60 s) only when no tunnel answered, else an alert there | none |
| Codex `Stop` | `done`, none while a `/goal` is active; a `question` (plan) when the turn ended on "Implement this plan?" | none |
| Codex `UserPromptSubmit`, `PreToolUse`, `PostToolUse` | none (session records; `state` `running`) | none |
| Codex `SessionStart` (resumed or forked session), `PostCompact` | none (context) | none |
| Codex `SessionEnd` (0.5.1) | `state` `ended` (SSH tunnel only) and the session record's `.ended`. Codex runs it when it exits normally (`/quit`, Ctrl+D, Ctrl+C, the end of `codex exec`), not when killed by a signal (an SSH drop); by default (its shared daemon) only when the conversation is closed there, about 30 minutes later, or the daemon stops. It gives the hook 3 seconds at most | none |
| Gemini `Notification` (`ToolPermission`) | `question` (`approve <tool>: <command or file>`) | none |
| Gemini `AfterAgent` | `done` (at once); `error` when the turn had no response text (API error, cancel, loop) | none |
| agy `PreToolUse` `run_command`, `write_file`, `edit_file`, `call_mcp_tool`, `read_file` outside the workspace (only with `agy_wait` and no app connected) | `permission` | none |
| agy `PreToolUse` `ask_question` | `question` | none |
| agy `PreToolUse`/`PostToolUse` `write_file` of a plan for review | none (the next `Stop` is the review) | none |
| agy `Stop` (fully idle) | `done` or `error`; after a plan for review a `question` (plan) | none |
| Grok `Notification` `permission_prompt` (also "Plan approval requested"), `elicitation_dialog`, `idle_prompt` | `question`, with what is asked from the `PreToolUse` before it (`idle_prompt` only when no `done` was sent or is pending for the turn) | none |
| Grok `SessionEnd`, `SubagentStart`, `SubagentStop` | `state` (SSH tunnel only) | none |
| Grok `Stop` (`end_turn`) / `StopFailure` | `done` (none with `backgroundTasks` or `sessionCrons`, same rules as Claude) / `error` or `auth` | none |
| OpenCode permission request | `permission` (waits up to 540 s) | none |
| OpenCode turn finished / failed | `done` (none while a subagent of it runs; a background shell is judged as Claude Code's `background_tasks`) / `error` or `auth` | none |
| OpenCode 2.x input form | `question` | none |
| OpenCode 1.19 question | `question` you can answer (`fmt=2`) | none |
| Copilot `notification` (permission prompt, question) | `question` (an alert) | none |
| Copilot `preToolUse` `exit_plan_mode` | `question` (plan) | none |
| Copilot `agentStop` | `done` (none while background shells or subagents run, as for Claude Code; after a turn a `/every` or `/after` schedule started, none while a schedule is left, and the last one to the SSH tunnel only); a subagent's own stop: `state` `sub_stop` | none |
| Copilot `userPromptSubmitted`, `sessionEnd`, `subagentStart`/`Stop` | `state` (SSH tunnel only); `error` when a session ends on one | none |
| `simpleterm notify` | `notify` | OSC 777 notification instead |

**Background work is not done.** Claude Code (2.1.145+), Grok Build and OpenCode end a turn while a
shell, subagent or monitor started in the background still runs, and take the turn up again when
it reports back (OpenCode 2.x: `shell.created`/`shell.exited`, sent as `background_tasks`, and
running child sessions; 1.x background subagents: busy child sessions). Such a `Stop` lists that work (`background_tasks`, Grok `backgroundTasks`), so the
hook sends no `done` and no idle question then; the turn the agent takes up later sends `done` as
usual. The badge says `background`. Claude Code 2.1.295+ also reports its own turns through OSC
7501 and counts only background subagents as working, so the hook adds a `working` record of its
own (`id=simpleterm-bg`) and takes it back when the next turn starts; it writes that record only
when the transcript names 2.1.295 or later, outside tmux and screen, and without
`CLAUDE_CODE_DISABLE_TERMINAL_TITLE`. Codex's background terminals and subagents do not wake it,
so its `Stop` is done then; a `/goal` does (Codex starts each next turn itself), so no `done` while
the rollout's last `thread_goal_updated` is `active` and no `update_goal` call followed it, unless
no next turn starts within `codex_goal_check` seconds (default 5: a goal can also end blocked, on
a limit or by `/goal clear` without a trace in the rollout). Only work that reports back holds
`done` back for good (subagent, workflow, cloud session, MCP task). With only work that may run
for good left (shell, monitor, idle teammate, or agy's `fullyIdle: false`), `done` comes once after
`bg_done_after` seconds (default 600) of the same pause, saying what still runs. Claude Code's own
housekeeping (dream, auto-mode scan, memory import or save) is not counted.

Four more rules decide, at a `Stop` that still lists background work or schedules, whether you are
told (Claude Code and Grok Build; Codex's background work does not wake it, so none of this applies
there):

- **A question while waiting.** If the last message of the turn (`last_assistant_message`, Grok
  `lastAssistantMessage`) asks you something, you get a `question` alert with that text and the
  badge says `waiting`, because the agent will not go on before you answer. The last two sentences
  count (fenced code left out): one ending in `?` or a full-width `?`, a Korean request or
  question ending (`...까요`, `...하시겠습니까`, `...주세요`, `...주시겠어요`, `...나요`, and the
  like), or an English ask (`Should I`, `Shall I`, `Would you like`, `Do you want`, `Let me know which` or `whether`,
  `Want me to`, `Please confirm`). It is a reading of text, not a protocol, so a wrong guess costs
  one extra alert. The word lists are one table (`ASK_AWK` in `agent-hook.sh`). Claude Code
  2.1.295+ gets a `blocked` (kind `question`) OSC 7501 record `simpleterm-bg` instead of the
  `working` one; the next turn takes it back. The idle question 60 s later stays suppressed.
- **Services are not waited for.** A background shell is a service when its command is a known
  one, at the command position. When in doubt it is not: a wrong "service" ends the turn early and
  sends a second `done` later, while a missed one only delays the `done` to `bg_done_after`. The
  rules (`SVC_AWK`, one table):
  - The command is cut at `;`, `&&`, `||`, `&` and line breaks; only the **last** element counts
    (`cd web && npm run dev` and `npm run dev &` are services, `npm run dev & npx wait-on ... && npx
    playwright test` is not), and any command of its `|` pipeline may be the service, unless the
    last command of the pipeline can end it (`head`, `grep -q|-l|-m N`: `tail -f x | grep -m1 ready`
    ends once `tail` writes again and dies of SIGPIPE, not at the match; measured, so this is a guess
    towards "not a service").
    One pass over the text drops comments (a `#` that starts a word, outside quotes, to the end of the
    line: `npm run build  # then: preview & serve`), heredoc bodies and the inside of `"..."`, `'...'`
    and `$'...'`, and joins backslash line continuations (`git commit -m "npm run dev"`, `sh -c
    "..."` are not services). `\u00XX` escapes in the JSON are decoded for 0x20-0x7F (Go writes `&` as `\u0026`). A
    command over 64 KiB is not looked at (not a service). Heredoc operators count only with a
    delimiter that starts with a letter or `_` (or a quoted one), so `$((1<<3))` and `(( n <<= 1 ))`
    are not heredocs; `"$(cat <<'EOF' ... EOF)"` bodies are dropped too.
  - Leading `VAR=val` words and the launchers `npx`, `bunx`, `pnpm exec|dlx`, `yarn dlx`, `uv|poetry
    run`, `bundle exec`, `env`, `nohup`, `exec`, `sudo` are skipped (an option we cannot read gives up).
    Between the tool and its subcommand only options are allowed: ones that take a value
    (`--filter -F -C --cwd --prefix --dir -p --project --workspace -w --app --namespace -n
    --context --kubeconfig -f --file --env-file --project-name --profile --port --host --config -c
    --mode -m --base --logLevel -l --outDir`), a few flags without one (`-r --recursive -s --silent
    -q --quiet --if-present --workspaces -ws --include-workspace-root --stream --parallel --no-bail
    --open --force --strictPort --debug --verbose -v --no-color --offline --prefer-offline
    --ignore-scripts -A`), `--name=value`, and `run`; any other option gives up. Words after a lone
    `--` belong to another command; tools that run a script (`node`, `python`, `tsx`) stop at it.
  - Package managers `npm|pnpm|yarn|bun [run]` `dev|start|serve|preview|watch`, also `dev:web`
    style names, `pnpm --filter web dev`, `yarn workspace web dev`, `bun --watch|--hot`; a name whose
    suffix is a finite task (`setup migrate migration db seed build init prepare install reset
    clean test lint check generate gen codegen deploy publish release typecheck format once`: `dev:setup`,
    `start:db`) is a job, not a server.
    Likewise `turbo [run] dev`, `nx serve|dev|start` and `nx run proj:serve`, `next dev|start`, `ng
    serve`, `astro|nuxt dev|preview`, `expo start`, `storybook dev|start`, `browser-sync start`,
    `vite` (also `vite --host`; not `vite build|optimize`), `parcel <entry>|serve|watch` (not `parcel
    build`; the Parcel CLI docs: `parcel <entry>` is `serve`, `watch` keeps running), `vitest -w|--watch|dev|watch` (a plain `vitest` runs once under
    an agent), `webpack serve|server|s|watch|w`, `webpack-dev-server`, `live-server`.
  - `nodemon`, `uvicorn`, `gunicorn`, `python -m http.server|uvicorn|gunicorn|flask run`, `manage.py
    runserver`, `rails s` (not with `-d`), `flask run`, `php artisan serve`, `hugo server|serve`, `jekyll
    serve`, `serve`, `http-server`, `node --watch`, `deno run --watch`.
  - `docker compose up` / `docker-compose up` unless it ends by itself (`-d`, `--detach`, `--wait`,
    `--abort-on-container-exit|failure`, `--exit-code-from`, `--no-start`, `--dry-run`), `docker|
    kubectl logs -f` (not for a `job/`), `kubectl port-forward`, `kubectl get ... -w`, `tail -f|-F|
    --follow` (not with `--pid`), `journalctl -f`, `watch` (not with `-g`/`-e`).
  - Watchers by their own flag: `tsc|webpack|rollup|swc|mocha|sass -w|--watch` (`-w` is the short form of
    `--watch` in Dart Sass), `tailwindcss -w`, `esbuild --watch`, `jest --watch|--watchAll`, `cargo watch`, `tsx watch`, `watchexec`.

  `-w` counts only for those tools (`make -w`, `curl -w`, `docker exec -w`, `jest -w` (that is
  `--maxWorkers`), `kubectl rollout status -w` are not services), and so are not `--watch=false`,
  `pnpm prisma migrate dev`, `pnpm sst deploy --stage dev`, `nx build web -c dev`, `npm install
  vite`, `npm i -g http-server`. When only such shells (and the agent's housekeeping) are left, `done`
  goes at once, ending with `(still running in the background: <task>)`, instead of after
  `bg_done_after`; other shells keep the `bg_done_after` wait.
- **Your own prompt is answered.** At every `Stop` the hook records the ids of the tasks running.
  When you typed the prompt that started the turn and every task still running was already running
  before it, the turn is a report: `done`, with the same `(still running in the background: ...)`
  ending. A task started by that turn keeps it waiting. Turns the agent starts itself (a task's
  report, a schedule) always wait. Who started the turn: Claude Code puts it in
  `UserPromptSubmit` `source` (`user` and `sdk` are people; `system`, `loop_wakeup`,
  `schedule_wakeup`, `poll_event` are not; found in the 2.1.316 binary). Version 2.1.316 itself
  sends no `source`, so there a `<task-notification>` or `<agent-message>` prompt, the `/loop`
  sentinel, or a prompt equal to one listed in the last `Stop`'s `session_crons` marks a turn the
  agent started; every other prompt is yours. Grok Build has no such field: a prompt id that
  starts with `task-completed-`, `bash-completed-`, `monitor-completed-`, `subagent-completed-`,
  `workflow-completed-`, `parent-agent-message-`, `parent-message-`, `notifications-`,
  `goal-summary-`, `goal-classifier-nudge-`, `plan-resume-` or `scheduler-fired-` marks one (read
  from the 1.0.70 binary; your prompts carry a UUID).
- **Loops and schedules are quiet.** While `session_crons` (Grok `sessionCrons`: `/loop`,
  CronCreate, ScheduleWakeup) is set, a turn the schedule started sends no `done` and the badge
  says `background`, `scheduled: <schedule>` (`+N more`); Claude Code 2.1.295+ gets a `working`
  record with that text. A turn you typed still ends with `done`, so does a turn a task's report
  started once none of its work is left, a question still alerts, and an error always does. The
  first `Stop` that finds no schedule left after a turn the schedule started is the `done`: to the
  SSH tunnels only and at once (no relay push), with `done_scheduled` on Claude Code's screen, so the
  app shows it in its list without an alert. When that turn ends asking you something it is a plain
  `done` everywhere. Copilot CLI's `/every` (`/loop`) and `/after` follow the same rules: its
  scheduled prompt starts with `[Scheduled prompt #<id>]` (one you type that starts so is yours:
  its `user.message` in the session's `events.jsonl` has no `schedule-<id>` source), and the
  schedules left come from that `events.jsonl`. Grok Build 1.0.77 runs each scheduled run as a
  background subagent: the `subagent-completed-` turn its result opens is the schedule's when its
  prompt names (`scheduler_delete("<id>")`) a schedule of that `Stop`'s or the previous `Stop`'s
  `sessionCrons`. The report of work that a scheduled turn started (a background agent or shell) is
  the schedule's turn too, and so is the report of work that report started: Claude Code's
  `<task-notification>` by its `<task-id>`, Grok's `task-completed-` or `subagent-completed-` by
  the id after it, Copilot's `<system_notification>` by the shell (detached ones too) or background
  subagent the last notification in `events.jsonl` names. The
  hook keeps the ids of up to 32 such pieces of work until no schedule is left or the session ends.
  The report of work a turn you typed started still ends with `done`.

**A `done` waits 3 seconds on Claude Code and Grok Build** (`done_delay`). Another Stop hook (yours
or a plugin's) may block the stop so that the agent works on; the agent then fires `Stop` again
with `stop_hook_active: true`. Any newer event of the same session within the delay (a tool call,
a prompt, a permission request) cancels the `done`, and a newer `Stop` replaces it, so such a turn
sends one `done`, for its real end. The badge changes at once; only the alert is late. Codex,
Gemini CLI and OpenCode register no event that would arrive within the delay (Codex: `SessionStart`,
`PermissionRequest`, `PostCompact`, `Stop`; Gemini: `Notification`, `AfterAgent`), so for them the
wait could only delay the alert: their default is 0 (at once; set `done_delay` to wait anyway,
a newer `Stop` then still replaces the first). Only events of the main thread cancel the wait: a
subagent's own tool calls (their hook input carries `agent_id`, foreground or background; from the
binary's schema, not yet captured from a background subagent's `PostToolUse`) carry the
session id too, but are no sign of the main thread going on, so a `done` that leaves background
work running is not lost to them. A `done` whose `Stop` carried `stop_hook_active: true` also carries
`"stop_hook_active":true` in its plaintext.

Codex runs a `PermissionRequest` hook before it shows its own approval prompt, so while the hook
waits the terminal shows only `Waiting for approval in SimpleTerm`. The wait is 60 seconds by
default and is skipped when no device was notified.

Codex runs hooks with your shell: `$SHELL -c` (Codex 0.165; `$SHELL -lc`, which also reads your
login profile, only when it has no single local environment). Whatever your shell's startup files
print to standard output (zsh always reads `~/.zshenv`) becomes the hook's output: it breaks the
approval answer, and on `SessionStart` Codex adds it to the session as developer context. The
plugin's `SessionStart` hook runs only for resumed and forked sessions (a new one has no usage
yet), and the commands that need no answer send the script's own output to `/dev/null`. That
cannot catch what the shell prints before the command runs: **if a startup file writes to
standard output (`~/.zshenv`, `BASH_ENV`, or a login profile when Codex uses `-lc`), that text
can end up in the developer context of a resumed or forked session.** Print from those files
only in an interactive shell (zsh: `[[ -o interactive ]] && …`).

## Event format v2

From 0.4.0 the plugin adds fields to every event (the numeric `v` stays 1: older apps read the v1
fields and skip the rest). The contract is in the SimpleTerm app's specs (`index/if-agent-events`:
`if/event-v2`, `if/event-v2-request`, `if/event-v2-limits`, `if/event-decision`); in short:

> **Spec IDs.** Names like `if/event-v2#fields` or `hist/event-v2-request#r16` here, in the scripts
> and in the tests are IDs of the SimpleTerm app's specs, in the SimpleTerm repository
> (`AhMunGa/simple-term`): the `id:` at the head of a file under `docs/spec/`, `docs/interfaces/`,
> `docs/data/` or `docs/ops/` (`spec/` feature specs, `if/` interfaces, `data/` data, `hist/` the
> decisions and measurements next to them in `_history/`, `ops/` runbooks, `index/` the chapter and
> group READMEs); `#name` is an anchor `{#name}` in that file. To find one, start at
> `docs/spec/README.md` (top level), go to the group README, then the file.

- **Who sent it**: the format (`fmt`: 2), the plugin's version, the agent's version (from its
  transcript or rollout, `COPILOT_CLI_BINARY_VERSION`, or for OpenCode, Antigravity and Grok Build a
  cached `--version`, run in the background when the executable changes), the session and turn
  ids, the subagent, the working folder, the permission mode, a multiplexer (`tmux`, `screen`,
  `herdr`; `unknown` for OpenCode 2.x, whose service keeps the first TUI's environment) and the id of
  the agent's pane there (`pane`: `TMUX_PANE`, `HERDR_PANE_ID`; never for Codex or OpenCode 2.x),
  with which the app ties an event to a herdr or tmux session row. These are for diagnosis and
  records; nothing is switched on or off by a version.
- **What is asked** (`req`): the window's kind (shell, edit, read, web, mcp, question, plan, form,
  login, other), the tool, the request itself (the command and its description, the file and the
  change as a replacement, a whole new file or a patch, the URL, the MCP server, tool and
  arguments, the questions with their choices, the plan), the answers the agent takes from a hook
  (`can`), the scopes Claude Code or OpenCode suggest, the other requests an OpenCode answer also
  settles, and whether the agent's own prompt shows while the hook waits (`wait`: shared, hidden,
  none).
- **Per link**: the SSH tunnel gets the whole request (32 KiB), the relay a summary (2048 bytes):
  each field is cut at its limit, then whole items and objects are left out in a fixed order and
  the event says what was cut (`cut`), the same bytes from the sh and the PowerShell hook. A link
  whose receiver has not said it takes v2 decisions (`fmt=2` in its link file, written by the app)
  gets only the answers a v1 allow/deny can give, and questions there are alerts.
- **Answers** (`dext`): the app seals what you chose (a scope, a reason, your answers, a plan mode)
  with the link's keys next to the v1 allow/deny. The hook checks it: its MAC, that it answers this
  request (`req`), that the choice was offered to that link, that you saw every other request an
  OpenCode answer also settles, and that the request was not answered in the terminal meanwhile.
  A decision that fails ends only that link's wait; a v2 tunnel hears it (`resolved`, scope link)
  and gets the request again (3 times at most). A v1 allow/deny (an older app, an alert's quick
  action) still works, with its plain meaning.
- **Who waits where**: Claude Code and OpenCode show their prompt while the hook waits, so every
  link gets the request at once. Codex and Antigravity hide it: the SSH tunnel gets it first, and
  when the app answers there the relay only gets an alert (other devices show it without buttons),
  so nothing you press on another device goes unheard; only when no tunnel answers is the relay
  asked, and the hook waits there. A link answering `sent` (also an older app's tunnel) is waited
  for, other answers end that link only.
- **A request held back for a wait** (0.5.1, SimpleTerm issue #414): while you look at an agent's
  own prompt in SimpleTerm, the app shows no second card for a request that asks the same; its
  tunnel answers `suppressed` with `"held":true`. If that request was in fact another session's
  (another SSH client in the same folder), it would stay off the device after you answer the tab's
  prompt. So for a Claude Code permission request (the hook and Claude's prompt wait together) the
  hook stays while Claude's own session record (`sessions/<pid>.json` under `CLAUDE_CONFIG_DIR` or
  `~/.claude`) says that very prompt is still open (this session, `waiting` on a `permission
  prompt`, its `statusUpdatedAt` unchanged) and no other permission hook of the session waits on
  that same prompt (parallel tool calls share one prompt, "1 of 2", and the record does not change
  between them), and sends the request to every tunnel that held it, at once and under one new rid,
  about every 5 seconds: a new rid and nonce, the same request id. The app holds it again while the
  wait it was held for is open and shows it, with its buttons, only when it comes more than 1.5 s
  after that wait ended; once the prompt closes (answered in the terminal, or another one comes)
  nothing more is sent and the hook ends as before. Older apps never say `held` and older hooks
  ignore it. Other agents' requests are not sent again: their hooks do not wait, and no record of
  theirs tells an open prompt (SimpleTerm `if/ssh-tunnel-wait#held`, `hist/event-v2-request#r16`, issue #446).
- **Ends and states**: a turn's end carries how it ended, who started it, whether its last message
  asks you something, its last message (tunnel), the background work still running (new this turn
  or older, services), the schedules and an active Codex goal. To the SSH tunnel only: `state`
  (running, background, scheduled, idle, ended, a subagent starting or stopping) and `resolved`
  (how a request ended: applied, answered in the terminal, left to the agent's window, ...).
- **Session records** (SimpleTerm sessions only, `SIMPLETERM=1`): `~/.simpleterm/sessions/<agent>/`
  keeps one record per session (id, folder, title, last prompt, times, transcript path, permission
  mode, settings folder, state), a `.beat` file whose time is the session's last hook event (touched
  at most every 30 seconds) and an `.ended` file after the session ended, for the app's "resume"
  list. 30 days, 200 records at most. Not for OpenCode 2.x (its service cannot tell a SimpleTerm
  session from another).

## `simpleterm notify`

```sh
make test; simpleterm notify "Tests finished" "exit $?"
```

In a SimpleTerm session it shows an OSC 777 notification on the terminal (inside tmux only with
`set -g allow-passthrough on`), and it sends a `notify` event to every linked device (the SSH
tunnel and the relay), so it also reaches you when the app is in the background. It returns at
once and exits 0.

The terminal and the event get the same text, so the app can tell the two copies of one
notification from two notifications: runs of whitespace, line breaks included (tab, LF, VT, FF,
CR, NEL, U+2028, U+2029), become one space; other control characters (C0, DEL, C1) and invalid
UTF-8 are removed; `;`, which separates the fields of OSC 777, becomes `,`; leading and trailing
spaces go; the title is cut at 64 characters (256 bytes) and the body at 200 characters
(800 bytes), between characters and not after a space. Text that is only whitespace sends
nothing.

The hooks keep the command at `~/.simpleterm/bin/simpleterm`, a small script that runs the
installed plugin's `scripts/simpleterm-notify.sh`. At a session start and at the end of a turn
they point it at the newest release they run from, so an update takes effect even while the agent
keeps the old version's folder for a while; another agent's copy of the same or a newer release is
left alone. Add the folder to your `PATH`, for example in `~/.profile` or `~/.zshrc`:

```sh
export PATH="$HOME/.simpleterm/bin:$PATH"
```

On Windows the Codex hook keeps `~/.simpleterm/bin/simpleterm.cmd` for `simpleterm notify` in
cmd and PowerShell.

## Context and rate limits

The hooks report how much of the context window is used and, where the agent gives it, the
rate limits. Only changes are sent, and only while SimpleTerm is connected: on Claude Code's
terminal and through the SSH tunnel. The relay gets none, because it would show every update as a
notification.

| Agent | Context | Window | Limits | From |
|---|---|---|---|---|
| Claude Code | last response's input + cache tokens, or the compaction's result | `CLAUDE_CODE_MAX_CONTEXT_TOKENS`, `CLAUDE_CODE_DISABLE_1M_CONTEXT`, the status line tap, the `[1m]` model at session start (kept for the session until a model switch), else guessed from the model (marked `est`; a guess below the context in use becomes 1M) | 5-hour and 7-day, only with the status line tap below; `reached` when a turn fails on a rate limit | the session transcript (only its last 2 MiB, only the `usage` keys) |
| Codex | the last request's tokens (`baseline` 12000, as the Codex TUI counts) | from Codex | primary/secondary windows of each limit id, plan | the session rollout file (with its record's time) and [asking Codex](#asking-the-agent-for-its-limits) |
| GitHub Copilot CLI | none | none | premium requests, chat and completions (items with a quota; 100 less the remaining percentage, monthly) | the session's `events.jsonl` (the newest model call) |
| Grok Build | none | none | none; the session's tokens and cost | the session's `usage.json` |
| OpenCode | none | none | none; the session's tokens and cost | the session info, passed on by the plugin |
| Gemini CLI | the last request's prompt tokens | 1,048,576 (Gemma 4: 256,000) | none | the chat record |
| Antigravity CLI | none | none | none (not asked until it is known where agy keeps a signed-in token on a server) | |

Every window carries where it came from (`src`: `ask`, `file`, `statusline`) and, except the
status line's, when it was checked (`at`), so the app shows "checked 3 minutes ago" and a late,
older value does not replace a newer one.

Claude Code gives its rate limits only to the status line, not to hooks, and a plugin cannot set
the status line. If you want them in SimpleTerm, put the tap in front of your own status line
command in `~/.claude/settings.json`:

```json
{
  "statusLine": {
    "type": "command",
    "command": "~/.simpleterm/bin/simpleterm statusline '<your status line command>'"
  }
}
```

The tap saves the status line input to `~/.simpleterm/run/usage.<session>.json`, then runs your
command with the same input and prints what it prints. It runs the command with `/bin/sh -c`, as
Claude Code does with a status line command of its own, so the command behaves as before. If you have no status line of your own,
leave the command out (`~/.simpleterm/bin/simpleterm statusline`): the tap then prints a short
line itself, such as `Opus · context 8% · 5h 23% · 7d 41%`. The hooks use the saved file while it
is fresh (10 minutes) for the exact window size and the limits.

To send no context or limits at all, set `usage=0` in `~/.simpleterm/agent-hook.conf`.

### Asking the agent for its limits

Claude Code gives its limits to no hook, so at the end of a turn the hook asks Claude Code
itself. Codex writes its limits to its rollout file, which the hook reads after every turn, and
the hook asks Codex as well (all its limit ids, also between requests). Asks happen only:

- while the SimpleTerm app is connected (an SSH tunnel took the last event within 10 minutes);
- once per 5 minutes per agent and settings folder (`CLAUDE_CONFIG_DIR`, `CODEX_HOME`);
- while asks of that agent version are not stopped (below). Every version and OS is asked.

The ask runs in the background (the turn's hook does not wait), with its input and output
closed, at most 20 seconds, in the empty folder `~/.simpleterm/probe`, with
`SIMPLETERM_PROBE=1` (a hook that the ask runs does nothing). It runs the agent's executable on
`PATH`, links followed to the end (a native Claude Code install links `~/.local/bin/claude` to
`~/.local/share/claude/versions/<version>`, which gives the version); otherwise the version is the
executable's `--version`, kept in `~/.simpleterm/run/ver.<agent>` and measured again (no ask that
turn) when the executable changes, `unknown` if it gives none. The answer goes to the SSH tunnel
only. Only one ask starts per 5 minutes even when several sessions end a turn at once.

The sh hook starts the ask in a process group of its own (with `perl`, else `setsid`): when the
agent has not ended 3 seconds after its answer (or the 20 seconds), every process of that group
gets TERM, and what is left 2 seconds later KILL, those that left the agent's tree too. On a
server with neither `perl` nor `setsid` (a minimal container) the hook ends the agent's process
tree instead, the same way, and a process that left the tree (its parent gone) is not reached. The
PowerShell hook ends the agent's process tree (KILL), which does not reach such a process either.

| Agent | What it runs | What comes back |
|---|---|---|
| Claude Code | `claude -p --input-format stream-json --output-format stream-json --verbose --safe-mode --strict-mcp-config --no-session-persistence --include-hook-events` with one `get_usage` control request | 5-hour, 7-day and per-model 7-day windows, plan |
| Codex | `codex app-server`: `initialize`, `account/rateLimits/read` | each limit id's primary and secondary window, plan |

**Tokens.** Against a local mock API (2026-11-03), the versions measured made no model request
at all (`/v1/messages`, `count_tokens`, `/responses`, `/chat/completions`: 0): 22 asks of Claude
Code 2.1.316 and 2.1.317 and 11 asks of Codex 0.165.0 on macOS, with no sign-in, an API key, or a
subscriber sign-in; the same harness counted 6 and 31 model requests in real turns. Other
versions and other systems (Linux, Windows) are asked as well, taken to work the same way but not
measured. What stops a version (an `unknown` one too):

- Claude Code says in its answer what the ask's own session spent. If an answer shows any spend
  (cost, API time, a model's tokens), or the ask ran a hook (`--include-hook-events` shows it),
  that version of the executable is not asked again (it is added to
  `~/.simpleterm/run/ask.<agent>.off`, one version a line). Codex's answer has no such numbers.
- For Claude Code and Codex alike: after 3 failed asks in a row of the same version (no answer,
  an unknown one, or none in 20 seconds) that version stops the same way. An answer clears the
  count (`~/.simpleterm/run/ask.<agent>.fail`); a sign-in result (below) does not change it.

What the asks do request: Claude Code its usage (`GET /api/oauth/usage`, about 10 small account
requests with a subscriber sign-in); Codex its usage (`/wham/usage`) and its plugin list.

**What the agents themselves write.** Claude Code keeps the usage it fetched in its own state
file `~/.claude.json` (`cachedUsageUtilization`) and may make a backup of that file next to it;
SimpleTerm and the plugin do not write that file nor change your settings (status line and the
rest).

Asking Codex starts `codex app-server`, which on its own does more (measured 2026-11-03 with
Codex 0.165.0 in an empty `CODEX_HOME`):

- it creates or updates its own files in `~/.codex` (`CODEX_HOME`): `state_5`, `logs_2`,
  `goals_1`, `memories_1` and `queue_1` databases, `installation_id`, its built-in skills
  (`skills/.system`) and a temporary file; `config.toml` and `auth.json` were left as they were;
- it syncs its plugin list over the network (`git` to `github.com/openai/plugins`, and the ChatGPT
  plugin endpoints when signed in);
- with an expired ChatGPT sign-in it refreshes the token (8 token requests were seen).

Not checked: whether a successful refresh rewrites `auth.json`, and what happens when another
Codex on the server refreshes at the same moment; whether the ChatGPT backend accepts the client
name `simpleterm` it sees. To keep Codex out of it, set `usage_ask_codex=off`; its limits still
come from its rollout.

The ask stops not only after a failed sign-in (`auth`) but also when the account has no plan
limits to give (`not-subscriber`: no sign-in, an API key, `CLAUDE_CODE_OAUTH_TOKEN`, a gateway):
the app gets that answer once, and the agent is not asked again until its credentials file is
newer than that answer (`$CLAUDE_CONFIG_DIR/.credentials.json`, else `~/.claude/.credentials.json`;
`$CODEX_HOME/auth.json`, else `~/.codex/auth.json`), as after `/login` or `codex login`. Its file
values still go meanwhile. A Claude Code that keeps its sign-in in the macOS keychain has no such
file: delete `~/.simpleterm/run/ask.claude.*.auth` to have it asked again. These answers do not
count as failed asks.

To turn asking off, set `usage_ask=off` (or `0`, `no`, `false`) in `~/.simpleterm/agent-hook.conf`;
to turn off only Codex's, set `usage_ask_codex=off` there. The values may be in any case (`OFF`,
`No` ...); any other value leaves the default (both asked). To have a stopped version asked again,
delete its line from `~/.simpleterm/run/ask.<agent>.off` (and `ask.<agent>.fail` if it names that
version).

## Configuration

`~/.simpleterm/agent-hook.conf`, all optional:

```
claude_wait=540   # seconds a Claude Code permission waits for a device, at most 540
codex_wait=60     # the same for Codex
opencode_wait=540 # the same for OpenCode
agy_wait=0        # the same for Antigravity (commands, file writes and edits, reads outside the workspace, MCP calls); 0 (off) by default, at most 110
poll_wait=25      # one long-poll, 1-25
usage=1           # 0: send no context or rate limits
usage_ask=on      # off: never ask an agent for its limits
usage_ask_codex=on # off: do not ask Codex (its app-server; see "Asking the agent for its limits")
bg_done_after=600 # a pause with only shells/monitors left: done after this many seconds; 0: never
codex_goal_check=5 # seconds to wait for a Codex /goal's next turn before sending done
done_delay=3      # seconds a done waits for a newer event of the session (another Stop hook); 0: at once (default 3 on Claude Code and Grok Build, 0 on the others)
ask_delay=2       # seconds a Claude Code question from PreToolUse waits for its PermissionRequest (the answerable one)
```

The first line of a key decides. Blanks around the line and the `=`, Windows line ends, a comment
from `#`, quotes around a value (`usage_ask = "off"  # never`) and a UTF-8 BOM at the start of the
file are allowed; numbers are read as decimal (`0090` is 90). The same keys can also be changed in the SimpleTerm app, in a server's
agent alert settings: the app reads this file and writes the line of the key you change (removing
it to go back to the default).

## Privacy

- Without a SimpleTerm link file nothing is sent over the network.
- Each alert is encrypted on the server (AES-256-CBC + HMAC-SHA256) with keys that only this
  server's link file and your device hold. The relay sees the event type and ciphertext, not the text.
- The encrypted alert holds the agent name, the host label you gave in the app, the last folder
  name of the working directory, and a message of at most 200 characters: the start of the command
  or file path for a permission request, the question, or the start of the agent's last reply
  (OpenCode: the session title). The full tool input and the conversation are never sent.
- A context report holds only numbers: tokens used, window size, limit percentages, window lengths,
  reset times and the Codex plan name. To compute it the hook reads the end of the agent's
  transcript and takes the `usage` keys; it reads no message text.
- `simpleterm notify` sends the title and body you give it.
- Event format v2 (see above) also sends what an agent asks: the command, the file and its change,
  the URL, the MCP call's arguments, the questions, the plan, and the end of a turn's last message
  and background work. The SSH tunnel gets them whole (at most 32 KiB an event); the relay gets
  a short summary, still encrypted end to end, and no file contents, diffs, MCP arguments or last
  message. The working folder's full path, the permission mode and the settings folder go only to
  the tunnel.
- Usage asks send nothing anywhere but their answer to the SSH tunnel: limits, plan and when
  they were checked (never an account id, an error text or a token).
- Session records stay on the server, in `~/.simpleterm/sessions` (folder 700, files 600); the app
  reads them over SFTP when you open its resume list.
- A permission answer is signed by the device; the hook ignores an answer whose signature does not match.
- The hook keeps a 200-line log in `~/.simpleterm/agent-hook.log` with event types, the first
  8 characters of link IDs and HTTP results, never message text or host names.

## Security notes

- The link token (`secret`) goes to curl on standard input (`-K -`), and the HMAC key (`mac`) is
  used inside the shell and passed to `openssl dgst` on standard input. Neither appears on a
  command line. Both pass through `printf`, which is why the hook sends nothing when `printf` is
  not a shell builtin.
- The request body (the envelope's `iv` and `ct`) is passed to curl as a file in
  `~/.simpleterm/run/` (mode 600, directory 700) with `--data-binary @file`, and deleted right after.
- **The AES key (`enc`) is on the command line of `openssl enc -K` for a few milliseconds.**
  `openssl enc` takes a raw key no other way. Another user on the same host who reads the process
  list at that moment can see it (Linux `hidepid=2` prevents this). The key alone cannot forge an
  answer (answers are signed with `mac`), and the ciphertext never appears on a command line.
- The PowerShell hook encrypts and sends from .NET, so nothing appears on a command line. Its
  background sender receives the event (message text, no keys) in environment variables, which
  only the same user and administrators can read.
- Answer signatures: the sh hook compares them as plain strings, the PowerShell hook in constant
  time. The hook accepts one answer per request and gives up on a mismatch, so a signature cannot
  be guessed byte by byte.

## Update

| Agent | Command |
|---|---|
| Claude Code | `claude plugin update simpleterm@simpleterm-agent-hooks` |
| Codex | `codex plugin marketplace upgrade simpleterm-agent-hooks`, then trust the changed hooks again in `codex` |
| Gemini CLI | `gemini extensions update simpleterm` |
| GitHub Copilot CLI | `copilot plugin update simpleterm-copilot` |
| Antigravity | run the install commands again (from a copy: `git -C ~/.simpleterm/src pull --ff-only` instead of the clone) |
| Grok Build | `grok plugin update simpleterm` (nothing to do when it uses the Claude Code plugin) |
| OpenCode 2.x | `opencode plugin update "github:AhMunGa/simpleterm-agent-hooks#main::path:plugins/opencode"` |
| OpenCode 1.x | run the install commands again |

## Uninstall

```sh
claude plugin uninstall simpleterm@simpleterm-agent-hooks
claude plugin marketplace remove simpleterm-agent-hooks
codex plugin remove simpleterm@simpleterm-agent-hooks
codex plugin marketplace remove simpleterm-agent-hooks
gemini extensions uninstall simpleterm
agy plugin uninstall simpleterm-antigravity
copilot plugin uninstall simpleterm-copilot
copilot plugin marketplace remove simpleterm-agent-hooks
grok plugin uninstall simpleterm --confirm
opencode plugin remove "github:AhMunGa/simpleterm-agent-hooks#main::path:plugins/opencode"
rm -f ~/.config/opencode/plugins/simpleterm.js ~/.config/opencode/plugins/simpleterm-agent-hook.sh
```

Run the lines for the agents you installed. To remove the link files, the `simpleterm` command
and state too: `rm -rf ~/.simpleterm`, and revoke the link in the app.

**Hooks installed by an earlier SimpleTerm app.** Earlier test builds of the app added the same
hooks to `~/.claude/settings.json` and `~/.codex/hooks.json` (handlers whose command contains
`.simpleterm/agent-hook`). Remove those entries when you install the plugin; otherwise every alert
arrives twice (Grok Build also runs those Claude Code entries).

## Windows

Not tested on Windows yet.

- **Codex**: the hooks declare `commandWindows`, which runs `scripts/agent-hook.ps1` with Windows
  PowerShell 5.1+ (no extra tools needed): approvals, done alerts, context and limits, and
  `simpleterm notify` (`~/.simpleterm/bin/simpleterm.cmd`).
- **Claude Code**: plugin hooks have no per-OS command, so the hooks run `scripts/agent-hook.sh`
  through Git Bash ([Git for Windows](https://git-scm.com/downloads/win)). Without Git Bash the
  hooks fail and alerts are not sent. The permission and question hooks are marked
  `"onFailure": "continue"`, so such a failure never blocks or denies a tool call.
- Gemini CLI, Antigravity, Grok Build and OpenCode: Unix only (the hooks need `sh`).

## Known limitations

- **Copilot CLI answers come from the terminal.** Until its permission hook can tell a call that
  will prompt from one that will not, the plugin does not register it; Copilot's prompts are alerts.
  An interactive session whose model calls keep failing gets no error alert (Copilot reports each
  try as recoverable and the session goes on); `copilot -p` gets one when the session ends on it.
- **OpenCode 2.x questions are alerts** (its input forms are answered over its HTTP server, which a
  plugin cannot reach yet), and OpenCode's last message is not in a turn's end.
- **Claude Code MCP forms** are alerts without the server's name (the `Notification` has none).
- **Codex's daemon mode** (its default): hooks run in Codex's shared daemon with the environment of
  the terminal that started it, so `SIMPLETERM` (session records) and `TMUX`/`STY`/`HERDR_*` (`mux`)
  may be another session's (the hook sends no `pane` for Codex for that reason); a Codex session's
  end comes when the daemon closes the conversation (about 30 minutes after you quit or the SSH
  connection drops). `codex --no-daemon` runs hooks in the session itself. SimpleTerm
  `hist/event-v2-turn#r17`, issue #447.
- **A held request is told again for Claude Code only.** Other agents' requests held back for a wait
  you are looking at stay off the device once you answer that wait (their hooks do not wait, and no
  record of theirs tells an open prompt; other devices get the relay's push; SimpleTerm issue #446).
- **Background work that never ends.** A dev server the table of services does not know, or
  another endless job left in the background, never wakes the agent: `done` comes only after
  `bg_done_after` (default 10 minutes), and the badge stays `background` until the next turn
  (a turn you type while it still runs is `done` at once). This holds on OpenCode 2.x too: an
  open shell no longer blocks the dones of later turns. Known services (`npm run dev`,
  `tail -f`, ...) get their `done` at once.
- **Watch modes that read stdin.** `esbuild --watch` ends when stdin is closed (esbuild's docs);
  `--watch=forever` keeps it running. Both count as services here. A background shell started
  without `=forever` and with stdin closed ends by itself, which wakes the agent as any finished
  task does. `tailwindcss --watch` may behave the same (not measured).
- **Comments.** A `#` right after `$(...)` or after an escaped space is read as an ordinary
  character (not a comment), and a `#` that starts a word inside `$(...)` as a comment start; at
  worst the rest of the line is dropped or kept wrongly, which misses a service (a later `done`)
  rather than invents one.
- **A turn that ends with a question is a `done`.** Its `done` carries the question (the last
  message) and no `question` follows when Claude Code's `idle_prompt` comes 60 s later, so the
  alert does not change into "response needed". The lock-screen reply action that the old 60 s
  `question` push offered is gone for these turns: type the follow-up in the app or the terminal.
  The same holds at a `Stop` that lists only services or tasks that ran before your prompt (the
  `done` carries the question). Only where the agent still waits for work it started (not a
  service, not older than your prompt) the question is sent as a `question` (see above).
- **Questions are read from text.** Whether the last message asks something is a guess from its
  last two sentences (see above); a question phrased in another way is read wrongly now and then. A report that
  ends with a sign-off such as `Let me know if you need anything else` or `If you want me to ...`, a
  wait or FYI request (`기다려 주세요`, `참고해 주시기 바랍니다`, `양해 부탁드립니다`: the word before the
  ending starts with 기다, 참고, 참조, 양해, 이해, 감안 or 유의; `참고해서 결정해 주세요` still asks), or a
  `?` inside inline code or a table row is not read as a question. Trade-off: any sentence with
  `if you want me to` is read as an offer, not a question, so `If you want me to continue, say
  so` stays quiet while `Do you want me to continue?` asks.
- **Scheduled turns before Claude Code sends `UserPromptSubmit` `source`.** 2.1.316 sends none;
  a turn started by a schedule is recognised by its prompt (equal to one of the last `Stop`'s
  `session_crons`) and a typed prompt equal to a scheduled one counts as scheduled.
- **Grok's own OSC 7501.** Grok Build reports `done` through OSC 7501 while background work runs,
  and a Grok hook cannot write to the terminal, so the SimpleTerm tab still alerts then (the
  pushed alert does not).
- **Codex `notify` program.** The plugin uses Codex's `Stop` hook. A `notify` program you set
  yourself (`agent-hook.sh codex-notify`) also runs for every subagent turn and every `/goal`
  turn and sends `done` for each.

- **Large hook input on macOS.** The sh hook reads the agent's event JSON (at most 256 KiB) one
  character at a time, which the macOS `awk` (BWK) does in time that grows faster than the input:
  a `PostToolUse` after a large Read or command output takes up to about 0.9 s there (measured:
  64 KiB 0.10 s, 128 KiB 0.28 s, 256 KiB 0.91 s). Transcripts are not affected: their long lines
  are cut down first.

## Layout

```
.claude-plugin/marketplace.json        marketplace (read by both Claude Code and Codex)
.github/plugin/marketplace.json        Copilot CLI catalog (simpleterm-copilot only)
gemini-extension.json, hooks/hooks.json  Gemini CLI extension (the repository is the extension)
plugins/simpleterm/                    Claude Code, Codex and Grok Build
  .claude-plugin/plugin.json           Claude Code (and Grok) manifest; hooks in hooks/hooks.json
  .codex-plugin/plugin.json            Codex manifest; hooks in hooks/codex-hooks.json
  hooks/hooks.json                     Claude Code hooks (Grok Build runs them too)
  hooks/codex-hooks.json               Codex hooks
  scripts/agent-hook.sh                POSIX sh hook (all agents; macOS, Linux, BSD, Git Bash)
  scripts/agent-hook.ps1               PowerShell hook (Windows: Claude Code, Codex)
  scripts/simpleterm-notify.sh         the `simpleterm` command
  scripts/statusline-tap.sh            optional Claude Code status line tap
plugins/antigravity/                   Antigravity CLI plugin (plugin.json, hooks.json, script copies)
plugins/copilot/                       GitHub Copilot CLI plugin (plugin.json, hooks.json, script copies)
plugins/opencode/                      OpenCode 2.x plugin (package.json, index.js, script copy)
plugins/opencode-v1/                   OpenCode 1.x plugin file and script copy
tests/                                 hook tests, mock relay, OpenCode harness, v2 fixtures (not part of a plugin)
```

## Development

`tests/` runs the hooks against a mock relay (`tests/mock_relay.py`), which also plays the device:
it decrypts the envelope, checks the MAC and signs answers. Python 3 standard library only; the
OpenCode plugin tests also need `node`.

```sh
python3 -I tests/run_tests.py                          # sh hook, every shell found × LibreSSL and OpenSSL 3
python3 -I tests/run_tests.py --shell /bin/dash
python3 -I tests/run_tests.py --no-sh --pwsh <path>    # PowerShell hook, plus a Windows PowerShell 5.1 static check
python3 -I tests/run_tests.py --hook old/agent-hook.sh # another sh hook, e.g. to see new tests fail on a release
```

`plugins/simpleterm/scripts/` is the source. The Antigravity and OpenCode plugins are installed on
their own and carry copies of the scripts; after changing a script, copy it (the tests fail while
a copy differs):

```sh
cp plugins/simpleterm/scripts/agent-hook.sh plugins/opencode/agent-hook.sh
cp plugins/simpleterm/scripts/agent-hook.sh plugins/opencode-v1/simpleterm-agent-hook.sh
cp plugins/simpleterm/scripts/agent-hook.sh plugins/simpleterm/scripts/simpleterm-notify.sh \
   plugins/simpleterm/scripts/statusline-tap.sh plugins/antigravity/scripts/
cp plugins/simpleterm/scripts/agent-hook.sh plugins/simpleterm/scripts/simpleterm-notify.sh plugins/copilot/scripts/
```

Test-only variables: with `SIMPLETERM_HOOK_TEST=1`, `SIMPLETERM_HOOK_TEST_IV`, `_NONCE`, `_RID`,
`_TS` and `_TMS` replace the random values so the envelope can be compared with the protocol test
vectors, `SIMPLETERM_HOOK_TEST_PLAIN=<folder>` keeps each plaintext before it is sealed (one
file per event and link), and `SIMPLETERM_HOOK_TEST_PROC=<folder>` stands in for Linux's `/proc`
(the agent's pid where `ps` is missing). They are ignored otherwise.

`tests/fixtures/v2/cases.json` holds hook inputs per agent and version, `expected.json` the
plaintext every link gets, byte for byte; the sh hook and, for the agents it serves (Claude Code,
Codex, Grok Build), the PowerShell hook are both held to it.
After a deliberate change, `python3 -I tests/run_tests.py --regen-v2` rewrites `expected.json`
from the sh hook: read the diff before committing it.

When releasing, bump `version` in every manifest (`plugins/simpleterm/.claude-plugin/plugin.json`,
`.codex-plugin/plugin.json`, `gemini-extension.json`, `plugins/antigravity/plugin.json`,
`plugins/opencode/package.json`, `plugins/copilot/plugin.json`) and the release in the scripts (`HOOK_VERSION` in
`scripts/agent-hook.sh`, `$HookVersion` in `scripts/agent-hook.ps1`); installed copies update only
when it changes, and the tests fail while they differ.

## License

[MIT](LICENSE)
