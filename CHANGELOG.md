# Changelog

## 0.3.1 - 2026-11-02

- **A turn that ends with background work in flight is not done**:
  - **Claude Code**: a `Stop` whose `background_tasks` (2.1.145+) is not empty sends no `done` and
    no idle question until the next turn (`UserPromptSubmit`, which also comes when the
    background work reports back, `Stop`, `StopFailure`); the badge is
    `simpleterm:state=background <first task>`. Measured on 2.1.316: the turn the background work
    wakes ends with `background_tasks: []` and sends `done`. Claude Code 2.1.295+ reports `done`
    for its own turn through OSC 7501 even then (it counts only background subagents as working),
    so the hook adds an OSC 7501 `working` record `id=simpleterm-bg` (taken back at the next
    turn) when the transcript names 2.1.295 or later, outside tmux and screen, and without
    `CLAUDE_CODE_DISABLE_TERMINAL_TITLE`. A background subagent's tool calls keep the
    `background` badge. Only work that reports back holds `done` back for good (subagent,
    workflow, cloud session, MCP task); Claude Code's own housekeeping (dream, auto-mode scan,
    memory import or save) is not counted; with only work that may run for good left (shell,
    monitor, idle teammate) `done` comes once after `bg_done_after` seconds (default 600) of the
    same pause, saying what still runs (made then: fresh rid and time).
  - **Grok Build** (1.0.70, measured with a local model stub): the same for `backgroundTasks`;
    `UserPromptSubmit` ends the pause.
  - **Codex**: no `done` while a `/goal` is active (the rollout's last `thread_goal_updated` is
    `active` and no `update_goal` call followed it); Codex starts each next turn itself. If no
    next turn starts within `codex_goal_check` seconds (default 5), `done` goes then: a goal can
    end blocked, on a limit or by `/goal clear` without a trace in the rollout.
    Background terminals and subagents do not wake Codex, so their `Stop` stays done.
  - **OpenCode 2.x** (2.2.5, measured with a local model stub): the background shells
    (`shell {background: true}`, `shell.created` / `shell.exited`) of the session or of a direct
    subagent are sent with the `Stop` as `background_tasks`, and the hook decides as for Claude
    Code: a service (`npm run dev`) is `done` at once, other shells wait (their exit starts the
    session again, and that turn's end is done) for at most `bg_done_after` seconds, and a turn
    after the one that started the shell is `done` at once (OpenCode does not say who started a
    turn, so it counts as yours). A shell that never exits no longer blocks the dones of every
    later turn. Running child sessions are still waited for (they end). The plugin sends a turn
    start (`UserPromptSubmit`) for every `session.execution.started` of a root session and the
    hook ends the pause at it (also at `StopFailure`), so a long turn after a pause is not
    announced `done` by the pause's `bg_done_after` timer; the events of one session run in order.
  - **OpenCode 1.x** (1.19.5 with `OPENCODE_EXPERIMENTAL_BACKGROUND_SUBAGENTS`): no `done` while a
    child session is busy (`session.status`); the child's report wakes the parent again. A child
    that errors is not busy any more.
  - **Antigravity**: `done` only when fully idle, as before; `fullyIdle: false` now pauses the
    same way (agy does not say what still runs, so the wait is bounded by `bg_done_after`).
  - **Questions while waiting** (Claude Code, Grok Build): when the last message of a turn that
    leaves background work or schedules asks the user something (last two sentences, fenced code
    left out: `?`, a full-width `?`, a Korean request or question ending, an English ask; a `?`
    in inline code or a table row, `a?.b`, a wait or FYI request such as `기다려 주세요`,
    `참고해 주세요`, `양해 바랍니다` and `if you want me to ...` are not asks), the user gets a `question` alert with the message and the badge says `waiting`; Claude Code
    2.1.295+ gets a `blocked` (kind `question`) OSC 7501 record `simpleterm-bg` instead of the
    `working` one. The word lists are one table in the script.
  - **Services are not waited for**: a background shell whose command looks like a service (`npm
    run dev`, `next dev`, `vite`, `nodemon`, `python -m http.server`, `manage.py runserver`,
    `rails s`, `flask run`, `uvicorn`, `docker compose up` without `-d`, `tail -f`, `--watch`,
    `-w`, `watch`, `vite`, `npx tsc|webpack -w`, `docker|kubectl logs -f`, `journalctl -f`,
    `kubectl port-forward`, `pnpm --filter web dev`, `turbo dev`, `nx serve`, `ng serve`, `astro dev`,
    `expo start`, `php artisan serve`, `hugo server`, `jekyll serve`, `npx serve`, `gunicorn`; a
    plain `vitest` is not one, it watches only on a terminal and not under an agent) sends `done` at once with `(still running in the background: ...)` instead of
    after `bg_done_after`; the note is kept whole when the message is long. A command is split at
    `;`, `&&`, `||`, `|` and each part is read on its own, so `pip install flask && npm run build`
    and `tail -n 50 x.log | cut -f 2` are not services; `--watch=false`, `--watchAll=false`,
    `--no-watch`, `python -W`, `make -w`, `docker exec -w`, `kubectl rollout status -w` and
    `curl -w` are not either.
  - **A prompt you typed is answered**: every `Stop` records the ids of the running tasks; when a
    person typed the prompt of the turn and only tasks that ran before it are left, the turn is a
    report (`done` with the note). Turns started by a task's report or a schedule still wait. The
    origin comes from `UserPromptSubmit` `source` (Claude Code, where sent), a
    `<task-notification>`/`<agent-message>` prompt, the `/loop` sentinel or the prompt of a
    listed schedule; Grok Build: the prompt id (`task-completed-`, `scheduler-fired-`, ...).
  - **Loops and schedules are quiet**: with `session_crons` / `sessionCrons` set, the turns a
    schedule starts send no `done` (badge `background`, `scheduled: ...`); typed turns, questions
    and errors still alert, and the `Stop` that finds the schedule gone is the `done`.
- **A `done` waits 3 seconds** (`done_delay`, 0 sends at once) and is cancelled by any newer event
  of the session, so a Stop that another Stop hook blocks (the agent works on,
  `stop_hook_active: true`) no longer sends a `done` before and another after (Claude Code and
  Grok Build, whose later events come within the delay; Codex, Gemini CLI and OpenCode register
  no such event, so their default is 0: at once; `done_delay` sets either). Only events of the
  main thread cancel the wait: a subagent's tool calls (hook input with `agent_id`) carry the
  session id too and no longer cancel a `done` that leaves background work running. A `done` of a `Stop` with `stop_hook_active: true` carries
  `"stop_hook_active":true`.
- A turn that ends with a question is a `done` carrying the question; Claude Code's `idle_prompt`
  60 s later adds no `question` (the lock-screen reply of that push is gone for these turns).
- The hook no longer redirects with the special builtin `:` (a failed redirection ended the shell:
  exit 2 from a Stop hook means "block and continue"); the OpenCode plugin's per-session event
  lane has a 15 s timeout, and a permission request waits for the turn events before it.
- Claude Code and Grok Build: `idle_prompt` (60 s after a turn) is a repeat of a `done` that was
  sent or is pending for that turn, so it sends no `question` and does not touch the badge; the
  mark is taken back by the next prompt, an interrupt or `StopFailure`, so a turn that ended
  without a `done` (interrupt, failure, no Stop hook) still gets the `question` as the safety net.
- Claude Code: one `AskUserQuestion` sends one `question` (`PreToolUse` and `PermissionRequest`
  both reported it); `agent_needs_input` (another background session's) still alerts but no
  longer changes this tab's badge; `PostToolUseFailure` with `is_interrupt` (Esc) sets the badge
  idle, not running, and ends a background pause (not when the interrupted tool is a subagent's,
  foreground or background: its hook input carries `agent_id`, found in the 2.1.316 binary's
  schema; not yet captured from a background subagent's `PostToolUse`). A turn paused on a
  question keeps the `waiting` badge when a background subagent runs a tool.
- Gemini CLI: an `AfterAgent` with `[no response text]` (API error, cancelled stream, loop) sends
  `error`, not `done`.

## 0.3.0 - 2026-10-29

- More agents (#347):
  - **Gemini CLI**: the repository is a Gemini extension (`gemini-extension.json`,
    `hooks/hooks.json`). `AfterAgent` sends done; a tool permission (`Notification`
    `ToolPermission`) sends an alert (Gemini takes no answer from a hook).
  - **Antigravity CLI** (`agy`): its own plugin folder `plugins/antigravity` (agy reads root
    `plugin.json`/`hooks.json` and treats a `.claude-plugin/` folder as a Claude Code plugin).
    `Stop` (fully idle) sends done or error, `ask_question`/`ask_permission` an alert; approving
    `run_command` from the device is opt-in (`agy_wait`, it runs before agy's policy). Every
    `PreToolUse` run answers `{"decision":"allow"}` unless the device decided (what agy does with
    no answer is not documented). The hook commands find the script from any working folder
    (`${PLUGIN_ROOT}`, `${CLAUDE_PLUGIN_ROOT}`, the install folder, the older install folder
    `~/.gemini/antigravity-cli/plugins/simpleterm-antigravity`, the app's clone) and never run
    one from the working folder itself (a workspace's own `scripts/agent-hook.sh`); with no
    script, `PreToolUse` still answers `{"decision":"allow"}` and `Stop` prints nothing. Not
    tested with a real `agy` yet.
  - **Grok Build**: Grok runs Claude Code plugins' hooks; with `GROK_HOOK_EVENT` set the hook
    reports `grok-build` instead of `claude-code`. Permission prompts and idle prompts are alerts,
    `Stop` (`end_turn` only) done, `StopFailure` error. A second copy of the same event within
    30 seconds is dropped. `hooks/hooks.json` now passes `permission_prompt` notifications
    (Claude Code ignores them as before).
  - **OpenCode**: a 2.x plugin (`plugins/opencode`, `opencode plugin add`) and a 1.x plugin file
    (`plugins/opencode-v1`). Permission requests wait for the device; whichever answers first, the
    device or the terminal prompt, wins. In 2.x an input form alerts with its title
    (`form.created` carries `{form}`), a turn is done only when no subagent of it still runs (as
    the OpenCode TUI counts), and an answer given in the terminal ends the wait in whichever
    plugin instance holds it.
- `simpleterm notify "title" ["body"]` (`scripts/simpleterm-notify.sh`; the hooks keep
  `~/.simpleterm/bin/simpleterm` pointing at the newest installed release of it, so an update
  takes effect while the agent still keeps the old folder): OSC 777 on a SimpleTerm terminal and a
  `notify` event to every link, with the same text in both (whitespace runs, line breaks
  included, become one space; other control characters and invalid UTF-8 are removed; `;`
  becomes `,`; trimmed; title 64 and body 200 characters), so the app can match the two. The background sender now
  ignores SIGHUP before it starts, so it outlives a terminal that closes right after the command.
- Context and rate limits (#342): Claude Code (transcript; window from the environment, the status
  line tap or a `[1m]` model at session start, kept for the session until a model switch, else
  guessed from the model, `est`, and raised to 1M when the context in use is larger; 5-hour/7-day
  limits through the optional `scripts/statusline-tap.sh`, which runs your own status line command
  with `/bin/sh -c` as Claude Code does and prints a short line of its own when you have none;
  `reached` on a rate-limit failure), Codex (rollout: context, window, limits, plan) and Gemini CLI
  (chat record). An OSC 9 `simpleterm:usage` on Claude Code's terminal and a `usage` event to the
  SSH tunnel links (not the relay: it would not push them); only changes are sent, and a value
  counts as sent once the terminal or a tunnel got it. Long transcript lines (a large Edit) are
  read in linear time (1 MiB: 0.15 s, was 14 s with macOS awk). New Claude Code hooks
  `SessionStart`, `PostCompact`, `PostModelSwitch`; new Codex hooks `SessionStart` (resumed and
  forked sessions only: Codex adds what a SessionStart hook prints, and what the shell's startup
  files print, to the session) and `PostCompact`; the Codex commands that need no answer send
  the script's output to `/dev/null`. `usage=0` in `agent-hook.conf` turns it off.
- PowerShell hook: `notify` (`simpleterm.cmd`), Grok's `GROK_HOOK_EVENT` (with the same rules as
  the sh hook), and context/limits for Claude Code and Codex.

## 0.2.0 - 2026-10-29

- SSH tunnel links (`kind=tunnel`): while the SimpleTerm app is connected to the server, it
  forwards a loopback port to itself over the SSH connection and writes a link file for it.
  The hooks treat it like a relay link, so alerts and approvals reach the app inside tmux and
  without the relay. Tunnels get background events first (the app then tells the relay it has
  shown them), answer an ingest within 5 seconds, and a permission wait stops as soon as the
  tunnel is gone instead of waiting out `claude_wait`/`codex_wait`.

## 0.1.1 - 2026-10-29

- Fix: when a prompt and the permission request of the same session arrived within the same
  second, the hook treated the prompt as an answer typed in the terminal and stopped waiting,
  so approving from the device did nothing. Notes written before the wait began no longer count
  (`agent-hook.sh` and `agent-hook.ps1`).

## 0.1.0 - 2026-10-29

First release.

- One marketplace (`simpleterm-agent-hooks`) and one plugin (`simpleterm`) for Claude Code and Codex.
- Claude Code: status badges, question/done/error alerts and permission approvals
  (`UserPromptSubmit`, `PreToolUse` `AskUserQuestion`, `PermissionRequest`, `PostToolUse`,
  `PostToolUseFailure`, `Notification`, `Stop`, `StopFailure`).
- Codex: permission approvals and done alerts (`PermissionRequest`, `Stop`); Windows uses
  `commandWindows` with the PowerShell hook.
- Hook scripts: SimpleTerm agent hook v1 (`agent-hook.sh`, `agent-hook.ps1`).
