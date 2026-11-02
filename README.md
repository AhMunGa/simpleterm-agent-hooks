# SimpleTerm agent hooks

Hooks that connect a coding agent on your server to the SimpleTerm iPad/phone SSH app:

- **Alerts**: end-to-end encrypted notifications when the agent finishes, asks a question,
  hits an error, or needs a permission.
- **Approvals**: approve or deny a permission request from the notification. The hook waits
  for your answer and hands it to the agent. If no answer comes, the agent's own prompt in the
  terminal stays in charge.
- **Status badges** (Claude Code): the terminal tab shows running, waiting for approval, or done.
- **Context and rate limits**: how full the agent's context window is and, where the agent
  reports it, how much of its rate limits is used.
- **`simpleterm notify`**: the same alerts from your own scripts.

One repository serves seven agents: Claude Code, Codex, Gemini CLI, Antigravity CLI, Grok Build,
and OpenCode 2.x and 1.x.

## What each agent supports

| Agent | Alerts | Approve from the device | Badge | Context / limits |
|---|---|---|---|---|
| Claude Code | permission, question, done, error, sign-in | yes; the terminal prompt stays open, first answer wins (waits up to 540 s) | yes | context; 5-hour/7-day limits with the [status line tap](#context-and-rate-limits) |
| Codex | permission, done | yes; Codex shows its own prompt after the hook (waits up to 60 s) | Codex sends OSC 7501 itself | context, limits, plan |
| Gemini CLI | permission (alert only), done | no: Gemini takes no answer from a hook | no | context |
| Antigravity CLI (`agy`) | done, error, `ask_question`/`ask_permission`; commands with `agy_wait` | opt-in (`agy_wait`): `run_command` waits before agy's permission policy | agy sends OSC 7501 itself | no |
| Grok Build | permission (alert only), idle question, done, error | no: a Grok hook can block but not approve | no | no |
| OpenCode 2.x | permission, done, error, input forms | yes; device or terminal, first answer wins | the TUI sends OSC 7501 itself | no |
| OpenCode 1.x | permission, done, error | yes; device or terminal, first answer wins | no | no |

"Alert only" means the device shows that the agent is waiting; you answer in the terminal.
Windows: Claude Code (through Git Bash) and Codex (PowerShell) only; see [Windows](#windows).

## Requirements

- macOS, Linux or BSD with `sh`, `curl` and `openssl` (OpenSSL 1.1/3.x or LibreSSL 3.3+).
  Without `curl` or `openssl` the hook only writes the status badges. It also sends nothing when
  `printf` is not a shell builtin (OpenBSD `sh`/`ksh`, mksh), so that secrets never appear in the
  process list.
- One of the agents below. Tested with the real CLI: Claude Code 2.1.312 (alerts, approvals,
  context reports), Codex 0.165.0 (alerts and approvals), Gemini CLI 0.63.0 and 0.66.0. Codex
  context reports, Antigravity CLI, Grok Build and OpenCode are built from their documentation and
  source and tested with recorded events, not yet with the real CLI.
- The SimpleTerm app, paired with this server (see [Pair with the SimpleTerm app](#pair-with-the-simpleterm-app)).

## Install

Run the commands for each agent you use on the server. The SimpleTerm app can run them for you
after asking; it does not edit your agents' settings files. Running an install command again is
harmless.

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
mkdir -p ~/.simpleterm
cd ~/.simpleterm && gemini extensions install https://github.com/AhMunGa/simpleterm-agent-hooks --consent
```

With `--consent`, Gemini CLI also trusts the folder the command runs in if it is not trusted yet
(folder trust is on by default), so run it from `~/.simpleterm` rather than from your home or a
project. Gemini installs the whole repository as the extension `simpleterm` (it reads
`gemini-extension.json` and `hooks/hooks.json` at the top). It needs `git`, and it cannot be run
from inside a Gemini session.

### Antigravity CLI (`agy`)

```sh
agy plugin install https://github.com/AhMunGa/simpleterm-agent-hooks/tree/main/plugins/antigravity
```

If your `agy` does not take a GitHub folder, install from a copy:

```sh
git clone --depth 1 https://github.com/AhMunGa/simpleterm-agent-hooks ~/.simpleterm/src
agy plugin install ~/.simpleterm/src/plugins/antigravity
```

The plugin is `simpleterm-antigravity`, a folder of its own (`plugins/antigravity`): agy reads
`plugin.json` and `hooks.json` at a plugin's top, and treats a folder with `.claude-plugin/` as a
Claude Code plugin. Check that the hooks loaded with `agy -p "/hooks" --output-format json`.

**Not tested with a real `agy` yet**: this plugin is built from agy's documentation and change
log. They do not say in which folder a hook command runs, so each command finds the script
itself, in this order: `${PLUGIN_ROOT}` and `${CLAUDE_PLUGIN_ROOT}` (if agy fills them in), the
install folder `~/.gemini/config/plugins/simpleterm-antigravity`, the older install folder from
agy's documentation `~/.gemini/antigravity-cli/plugins/simpleterm-antigravity`, then the app's
copy `~/.simpleterm/src/plugins/simpleterm`. It never looks in the folder the hook runs in: that
can be a workspace, and a repository's own `scripts/agent-hook.sh` must not run. If none is
there, `PreToolUse` answers `{"decision":"allow"}`, as the script does when the device did not
decide, and `Stop` prints nothing; both exit 0.

agy has no "waiting for permission" event: its `PreToolUse` hook runs before every tool call,
before agy decides whether to ask. So by default the plugin only alerts for agy's own questions
(`ask_question`, `ask_permission`) and when the agent stops. To approve commands from the device,
set `agy_wait` (seconds, at most 110) in `~/.simpleterm/agent-hook.conf`: every `run_command`
then waits that long for your answer before agy's permission policy runs, and the terminal shows
no prompt meanwhile. With no answer the policy decides as usual.

### Grok Build

Grok Build runs the hooks of Claude Code plugins that are enabled in `~/.claude/settings.json`.
If the Claude Code plugin above is installed, **Grok already uses it**: install nothing more. The
hook sees Grok's `GROK_HOOK_EVENT` and reports `grok-build` events. Otherwise:

```sh
grok plugin install AhMunGa/simpleterm-agent-hooks#plugins/simpleterm --trust
```

Grok loads a plugin name once, so having both does not send alerts twice (and the hook drops a
second copy of the same event anyway). Grok has no hook that can approve a permission, so its
permission waits are alerts only.

### OpenCode 2.x

```sh
opencode plugin add 'github:AhMunGa/simpleterm-agent-hooks#main::path:plugins/opencode'
```

`opencode plugin add` records the plugin in `~/.config/opencode/opencode.json`. To leave that
file alone, copy the folder instead: `plugins/opencode` to `~/.config/opencode/plugins/simpleterm/`.
Use one way, not both (OpenCode refuses the same plugin id twice). OpenCode 2.x runs plugins in
a shared background service, so the plugin sends alerts to linked devices but writes nothing to
the terminal.

### OpenCode 1.x

OpenCode 1.x loads every `.js` file in `~/.config/opencode/plugins/`:

```sh
mkdir -p ~/.config/opencode/plugins
curl -fsSL -o ~/.config/opencode/plugins/simpleterm.js https://raw.githubusercontent.com/AhMunGa/simpleterm-agent-hooks/main/plugins/opencode-v1/simpleterm.js
curl -fsSL -o ~/.config/opencode/plugins/simpleterm-agent-hook.sh https://raw.githubusercontent.com/AhMunGa/simpleterm-agent-hooks/main/plugins/opencode-v1/simpleterm-agent-hook.sh
```

It works with OpenCode 1.0 (`permission.updated`) and 1.19 (`permission.asked`). OpenCode 2.x
lists a 1.x plugin file as failed and goes on.

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
| Claude `PermissionRequest` | `permission` (waits for your answer, up to 540 s) | waiting, then running |
| Claude `PreToolUse` `AskUserQuestion`, `Notification` (idle, elicitation, input needed) | `question` (one per question: `PermissionRequest` repeats it; `idle_prompt` only when no `done` was sent or is pending for the turn) | waiting (idle keeps done; `agent_needs_input`, another session's, leaves the badge) |
| Claude `UserPromptSubmit`, `PostToolUse`, `PostToolUseFailure` | none (context, see below) | running |
| Claude `Stop` / `StopFailure` | `done` (sent 3 s later on Claude Code, see below) / `error` or `auth` | done |
| Claude `Stop` with `background_tasks` in flight | none (and no idle question until the next turn), unless the last message asks you something (`question`), only services or tasks that ran before your prompt are left (`done`) | background (+ an OSC 7501 `working` record, see below); waiting (+ a `blocked` record) for a question |
| Claude `Stop` with `session_crons` set, turn started by a schedule | none (a question: `question`) | background, `scheduled: <schedule>` |
| Claude `PostToolUseFailure` with `is_interrupt` (Esc; not for a subagent's tool, `agent_id` set) | none | idle |
| Claude `SessionStart`, `PostCompact`, `PostModelSwitch` | none (context) | none |
| Codex `PermissionRequest` | `permission` (waits up to 60 s) | none |
| Codex `Stop` | `done`, none while a `/goal` is active | none |
| Codex `SessionStart` (resumed or forked session), `PostCompact` | none (context) | none |
| Gemini `Notification` (`ToolPermission`) | `question` (`approve <tool>: <command or file>`) | none |
| Gemini `AfterAgent` | `done` (at once); `error` when the turn had no response text (API error, cancel, loop) | none |
| agy `PreToolUse` `run_command` (only with `agy_wait`) | `permission` | none |
| agy `PreToolUse` `ask_question`, `ask_permission` | `question` | none |
| agy `Stop` (fully idle) | `done`, or `error` | none |
| Grok `Notification` `permission_prompt`, `idle_prompt` | `question` (`idle_prompt` only when no `done` was sent or is pending for the turn) | none |
| Grok `Stop` (`end_turn`) / `StopFailure` | `done` (none with `backgroundTasks` or `sessionCrons`, same rules as Claude) / `error` or `auth` | none |
| OpenCode permission request | `permission` (waits up to 540 s) | none |
| OpenCode turn finished / failed | `done` (none while a subagent of it runs; a background shell is judged as Claude Code's `background_tasks`) / `error` or `auth` | none |
| OpenCode 2.x input form | `question` | none |
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
- **Services are not waited for.** A background shell whose command looks like a service (`npm
  run dev`/`start`/`serve`/`preview`/`watch`, `next dev`, `vite`, `nodemon`, `python -m
  http.server`, `manage.py runserver`, `rails s`, `flask run`, `uvicorn`, `docker compose up`
  without `-d`, `tail -f`, `--watch`, `-w`, `watch`, `vite` (not `vite build`), `npx tsc|webpack|sass
  -w`, `vitest -w`, `docker|kubectl logs -f`, `journalctl -f`, `kubectl port-forward`, `pnpm
  --filter web dev`, `turbo dev`, `nx serve`, `ng serve`, `astro|nuxt|storybook dev`, `expo
  start`, `php artisan serve`, `hugo server`, `jekyll serve`, `npx serve`, `http-server`,
  `gunicorn`) never ends and never wakes the agent. A plain `vitest` is not one: it watches only on
  a terminal and not under an agent. Each command of a pipeline or `&&` chain is read on its own;
  `--watch=false`, `python -W`, `make -w`, `kubectl rollout status -w` and `curl -w` are not
  services. When only
  such shells (and the agent's housekeeping) are left, `done` goes at once, ending with `(still
  running in the background: <task>)`, instead of after `bg_done_after`. The patterns are one
  table (`SVC_AWK`); other shells keep the `bg_done_after` wait.
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
  record with that text. A turn you typed still ends with `done`, a question still alerts, and an
  error always does. The first `Stop` that finds no schedule left is the `done`.

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
| Codex | the last request's tokens (`baseline` 12000, as the Codex TUI counts) | from Codex | primary/secondary windows, plan | the session rollout file |
| Gemini CLI | the last request's prompt tokens | 1,048,576 (Gemma 4: 256,000) | none | the chat record |

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

## Configuration

`~/.simpleterm/agent-hook.conf`, all optional:

```
claude_wait=540   # seconds a Claude Code permission waits for a device, at most 540
codex_wait=60     # the same for Codex
opencode_wait=540 # the same for OpenCode
agy_wait=0        # Antigravity run_command waits; 0 (off) by default, at most 110
poll_wait=25      # one long-poll, 1-25
usage=1           # 0: send no context or rate limits
bg_done_after=600 # a pause with only shells/monitors left: done after this many seconds; 0: never
codex_goal_check=5 # seconds to wait for a Codex /goal's next turn before sending done
done_delay=3      # seconds a done waits for a newer event of the session (another Stop hook); 0: at once (default 3 on Claude Code and Grok Build, 0 on Codex, Gemini CLI and OpenCode)
```

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
| Antigravity | run the install command again (from a copy: `git -C ~/.simpleterm/src pull` first) |
| Grok Build | `grok plugin update simpleterm` (nothing to do when it uses the Claude Code plugin) |
| OpenCode 2.x | `opencode plugin update 'github:AhMunGa/simpleterm-agent-hooks#main::path:plugins/opencode'` |
| OpenCode 1.x | run the two `curl` commands again |

## Uninstall

```sh
claude plugin uninstall simpleterm@simpleterm-agent-hooks
claude plugin marketplace remove simpleterm-agent-hooks
codex plugin remove simpleterm@simpleterm-agent-hooks
codex plugin marketplace remove simpleterm-agent-hooks
gemini extensions uninstall simpleterm
agy plugin uninstall simpleterm-antigravity
grok plugin uninstall simpleterm --confirm
opencode plugin remove 'github:AhMunGa/simpleterm-agent-hooks#main::path:plugins/opencode'
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

- **Background work that never ends.** A dev server the table of services does not know, or
  another endless job left in the background, never wakes the agent: `done` comes only after
  `bg_done_after` (default 10 minutes), and the badge stays `background` until the next turn
  (a turn you type while it still runs is `done` at once).
- **A turn that ends with a question is a `done`.** Its `done` carries the question (the last
  message) and no `question` follows when Claude Code's `idle_prompt` comes 60 s later, so the
  alert does not change into "response needed". The lock-screen reply action that the old 60 s
  `question` push offered is gone for these turns: type the follow-up in the app or the terminal.
  (A question that leaves background work running is still a `question`, see above.) This holds on OpenCode 2.x too: an
  open shell no longer blocks the dones of later turns. Commands that look like services
  (`npm run dev`, `tail -f`, ...) get their `done` at once.
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
plugins/opencode/                      OpenCode 2.x plugin (package.json, index.js, script copy)
plugins/opencode-v1/                   OpenCode 1.x plugin file and script copy
tests/                                 hook tests, mock relay, OpenCode harness (not part of a plugin)
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
```

Test-only variables: with `SIMPLETERM_HOOK_TEST=1`, `SIMPLETERM_HOOK_TEST_IV`, `_NONCE`, `_RID` and
`_TS` replace the random values so the envelope can be compared with the protocol test vectors.
They are ignored otherwise.

When releasing, bump `version` in every manifest (`plugins/simpleterm/.claude-plugin/plugin.json`,
`.codex-plugin/plugin.json`, `gemini-extension.json`, `plugins/antigravity/plugin.json`,
`plugins/opencode/package.json`) and the release in the scripts (`HOOK_VERSION` in
`scripts/agent-hook.sh`, `$HookVersion` in `scripts/agent-hook.ps1`); installed copies update only
when it changes, and the tests fail while they differ.

## License

[MIT](LICENSE)
