# Changelog

## 0.4.0 - 2026-11-03

Event format v2 (SimpleTerm `docs/tech_specs/TDS_AGENT_EVENTS_V2.md`, issue AhMunGa/simple-term#381):
the app sees what an agent asks and which answers that agent takes from a hook, and answers with
more than allow and deny. The numeric `v` stays 1 and every v1 field keeps its meaning and place:
older apps and relays read these events as before, and a v1 allow or deny still works.

- **What is asked, per link.** Every event names the plugin and agent version, the session, turn
  and subagent, the folder, the permission mode and a multiplexer; a request names its window
  (shell, edit, read, web, mcp, question, plan, form, login, other), the tool, the command, the
  file and its change, the URL, the MCP call, the questions with their choices or the plan, the
  answers the agent takes (`can`), the suggested scopes, and the other OpenCode requests an answer
  also settles. The SSH tunnel gets it whole (32 KiB), the relay a summary (2048 bytes): fields are
  cut at fixed limits, then items and objects are left out in a fixed order, recorded in `cut`; the
  sh and the PowerShell hook make the same bytes. A link without `fmt=2` gets only the answers a v1
  decision can give, and a question there stays an alert.
- **Answers.** Claude Code: allow for a suggested scope (`updatedPermissions`), deny with your
  reason (worded as a user's rejection, so the model reads it), answer `AskUserQuestion` (by
  `PermissionRequest`: `updatedInput` with your answers), approve a plan (`updatedInput`, optionally
  accept edits) or ask for changes; a v1 allow of a plan now works too. Codex and Antigravity: deny
  with a reason; Antigravity: approve a plan from its `Stop` hook. OpenCode: always (the pattern),
  reject with a reason (1.19 and 2.x), answer a 1.19 question. The extension (`dext`) is checked:
  its MAC (`st1-dext.`), the request it answers, the answers offered to that link, the other
  requests an OpenCode answer settles, a request answered in the terminal meanwhile; a key given
  twice counts with its first value, as in the agent's input. OpenCode 1.19 and 2.x always and
  reject settle every request of the session open at that moment: such an answer (also a v1 deny,
  also from an older app) applies only if the user saw every one of them, those that opened after
  the request was sent included; the request always names them (`affects`, `others`, `[]` when
  none).
- **Waiting per link.** A decision that does not hold ends only that link's wait; a v2 tunnel hears
  it (`resolved`) and gets the request again under a new rid, 3 times at most. Codex and
  Antigravity, whose prompt hides while a hook waits: the tunnel first; when the app answers there,
  the relay gets an alert without buttons and nothing waits on it; only when no tunnel answers is the
  relay asked. A relay that rejects a question's `nh` gets it once more without one. The cap counts
  from the hook's start.
- **Results and states** to the SSH tunnel: `resolved` (applied, answered in the terminal, left to
  the agent, another device's answer, gone) and `state` (running, background, scheduled, idle, ended,
  a subagent starting or stopping). A turn's end carries how it ended, who started it, its last
  message, the background work and schedules left, a Codex goal.
- **Session records** for the app's resume list: `~/.simpleterm/sessions/<agent>/<session>.json`,
  `.beat` (the last hook event) and `.ended`, SimpleTerm sessions only, 30 days and 200 records at
  most; not for OpenCode 2.x.
- **Plans.** Codex: a turn that ended on "Implement this plan?" (the rollout's Plan item) is a
  `question` (plan), not a `done`. Antigravity: a plan written for review (`RequestFeedback`) makes
  the next `Stop` a `question` (plan), and with `agy_wait` and no app connected that `Stop` waits for
  an approval. Copilot: `exit_plan_mode` is a `question` (plan).
- **GitHub Copilot CLI** (`plugins/copilot`, `copilot plugin install
  AhMunGa/simpleterm-agent-hooks:plugins/copilot`): alerts for its prompts and questions, plan, done
  (not while background shells or subagents run, read from its `events.jsonl`; a subagent's own stop
  is not the session's), an error when a session ends on one (retried errors are not), session
  records and states. Its permission hook also runs for calls that never prompt, so it is not
  registered yet: answers stay in the terminal. The Claude Code plugin given to Copilot acts the
  same way (`COPILOT_CLI=1`) instead of waiting. Measured with Copilot 1.0.105 and a local model.
- **Antigravity fixes** (#381): file writes and edits, reads outside the workspace and MCP calls
  can be answered too (with `agy_wait`); `ask_permission` (no such tool) is gone; a call is only
  sent when no app is connected (the tunnel is asked first: 404 `unknown`, unless `shown:false`);
  the hook folder counts when it is this plugin's own (agy gives no `PLUGIN_ROOT`); `Stop` waits up
  to 130 s; `toolCall.args.Cwd` (not there) is no longer read; signing in over SSH is documented.
- **Grok Build**: a permission prompt's alert names the tool, command, file or URL from the
  `PreToolUse` before it; questions and the plan review are alerts; session end and subagents are
  states.
- **Claude Code**: `SessionEnd`, `SubagentStart`, `SubagentStop` hooks; the `PreToolUse` report of
  a question waits `ask_delay` (2 s) for the answerable `PermissionRequest` one.
- **Codex**: `UserPromptSubmit`, `PreToolUse` and `PostToolUse` hooks for the session records (no
  output; their tool input and output are not read).
- **PowerShell hook** (Windows): event format v2 as above for Claude Code, Codex and Grok Build, the
  same bytes as the sh hook; a `[1m]` model's context window is 1M (exact); the OSC 7501 version
  check takes spaces around `:`; a run folder that cannot be made no longer stops the hook; Windows
  PowerShell 5.1 no longer queues a third request to the relay behind a long poll (2 connections
  per host); a waiting background `done` ends as soon as a newer event replaces it.
- **State events**: a subagent's start and stop are sent each time, at once; within the second
  only session states replace one another.
- **Fixes**: an input past 256 KiB is read to its end, so the agent no longer gets a broken pipe
  (Codex: `failed to write hook stdin`); bytes that are not well-formed UTF-8 (overlong forms,
  encoded surrogates, past U+10FFFF) become spaces in every event, as the app drops an event it
  cannot decode; an Antigravity read inside the workspace never waits with `agy_wait` (agy asks
  only for reads outside it); a background send that trimmed `~/.simpleterm/agent-hook.log` at the
  moment the hook did could leave it empty.

## 0.3.2 - 2026-11-02

Fixes and refinements to the background-work handling of 0.3.1.

- **A hook that could not write its run folder no longer ends early.** A failed `:` redirection
  ended the shell (dash: exit 2, which Claude Code and Grok Build read as "block and continue", so a
  `Stop` could repeat); `simpleterm notify` without a terminal sent nothing on dash. Both write with
  `printf` now.
- **A background shell is a service only when it is a known one; when in doubt it is not.** A wrong
  "service" ended the turn early and sent a second `done` later, a missed one only delays the
  `done` to `bg_done_after`. The command is read at its command position (after `VAR=val`, `npx`,
  `pnpm exec|dlx`, `yarn dlx`, `bunx`, `uv|poetry run`, `bundle exec`, `env`, `nohup`, `exec`,
  `sudo`) and looked up as (tool, subcommand) in one table: `npm|pnpm|yarn|bun [run]
  dev|start|serve|preview|watch` (also `dev:web`, `--filter web`; `dev:setup`, `start:db` and other
  finite suffixes are jobs), `turbo`, `nx`, `next`, `ng`, `astro|nuxt`, `expo`, `storybook`, `vite`
  (not `vite build`), `parcel`, `vitest -w|dev|watch` (a plain `vitest` runs once under an agent),
  `webpack serve`, `live-server`, `nodemon`, `uvicorn`, `gunicorn`, `python -m http.server`,
  `manage.py runserver`, `rails s`, `flask run`, `php artisan serve`, `hugo serve`, `jekyll serve`,
  `node|deno --watch`, `bun --watch`, `docker compose up` (not with `-d`, `--wait`,
  `--abort-on-container-exit`, `--exit-code-from`, ...), `docker|kubectl logs -f` (not `job/`),
  `kubectl port-forward|get -w`, `tail -f` (not `--pid`), `journalctl -f`, `watch`, and watchers by
  their own flag (`tsc|webpack|rollup|swc|mocha|sass -w|--watch`, `jest --watch|--watchAll`,
  `esbuild --watch`, `tailwindcss -w`, `cargo watch`, `tsx watch`, `watchexec`). `-w` is never global
  (`make -w`, `curl -w`, `docker exec -w`, `jest -w` are not services). Only the last element of a
  `;`/`&&`/`||`/`&` list counts (`cd web && npm run dev` is a service, `npm run dev & npx wait-on ...
  && npx playwright test` is not); a pipeline whose last command can end it (`head`, `grep -q|-m`) is
  none. Comments, heredoc bodies (also in `"$(cat <<'EOF' ...)"`), quoted text and line
  continuations are not read as commands; `$((1<<3))` is no heredoc; `\u00XX` JSON escapes (Go
  writes `&` as `\u0026`) are decoded; a command over 64 KiB is not looked at.
- **Questions read from text** (Claude Code, Grok Build): a `?` in inline code or a table row,
  `a?.b`, and wait or FYI requests (`기다려 주세요`, `참고해 주시기 바랍니다`, `양해 부탁드립니다`,
  `if you want me to ...`) are not asks; `부탁드립니다` is a request ending.
- **`idle_prompt` does not repeat a `done`** (Claude Code, Grok Build): it comes 60 s after a turn;
  when a `done` was sent or is pending for that turn it sends no `question` and leaves the badge. An
  interrupt, `StopFailure` or a new prompt takes the mark back, so a turn that ended without a
  `done` still gets the `question`. A turn that ends with a question is a `done` carrying the
  question (the lock-screen reply of the old 60 s push is gone for these turns).
- **A pending `done` is cancelled by the main thread only.** A subagent's tool calls (hook input
  with `agent_id`; from the binary's schema, not yet captured from a background subagent) carry the
  session id too and no longer cancel it. An interrupted subagent tool (`is_interrupt` with
  `agent_id`) does not end the main session's wait, and a turn paused on a question keeps the
  `waiting` badge when a background subagent runs a tool.
- **`done_delay` defaults to 0 for Codex, Gemini CLI and OpenCode**: they register no event that
  could cancel the wait, so it only delayed the alert (Claude Code and Grok Build keep 3 s).
- **OpenCode 2.x**: the open background shells go with the `Stop` as `background_tasks` and are
  judged as Claude Code's (a service is `done` at once; other shells wait at most `bg_done_after`; a
  turn after the one that started the shell is `done` at once), so a shell that never exits no longer
  blocks the dones of later turns. The plugin sends a turn start for every `session.execution.started`
  of a root session (and `StopFailure` ends a pause), so a long turn after a pause is not announced
  `done` by the pause's timer. The events of a session run in order with a 15 s timeout per job (a job
  it gave up on starts no hook when its lookup returns late; a running hook is stopped), a permission
  request waits for the turn events before it, and one answered meanwhile is dropped. **OpenCode
  1.x**: a child session that errored is not busy any more.

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
  - **OpenCode 2.x** (2.2.5, measured with a local model stub): a background shell
    (`shell {background: true}`) of the session or of a direct subagent holds back `done`
    (`shell.created` / `shell.exited`); its exit starts the session again, and that turn's end is
    done. Background subagents were already counted.
  - **OpenCode 1.x** (1.19.5 with `OPENCODE_EXPERIMENTAL_BACKGROUND_SUBAGENTS`): no `done` while a
    child session is busy (`session.status`); the child's report wakes the parent again.
  - **Antigravity**: `done` only when fully idle, as before; `fullyIdle: false` now pauses the
    same way (agy does not say what still runs, so the wait is bounded by `bg_done_after`).
  - **Questions while waiting** (Claude Code, Grok Build): when the last message of a turn that
    leaves background work or schedules asks the user something (last two sentences, fenced code
    left out: `?`, a full-width `?`, a Korean request or question ending, an English ask), the
    user gets a `question` alert with the message and the badge says `waiting`; Claude Code
    2.1.295+ gets a `blocked` (kind `question`) OSC 7501 record `simpleterm-bg` instead of the
    `working` one. The word lists are one table in the script.
  - **Services are not waited for**: a background shell whose command looks like a service (`npm
    run dev`, `next dev`, `vite`, `nodemon`, `python -m http.server`, `manage.py runserver`,
    `rails s`, `flask run`, `uvicorn`, `docker compose up` without `-d`, `tail -f`, `--watch`,
    `-w`, `watch`) sends `done` at once with `(still running in the background: ...)` instead of
    after `bg_done_after`; the note is kept whole when the message is long.
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
  `stop_hook_active: true`) no longer sends a `done` before and another after (Claude Code, Codex,
  Grok Build, Gemini CLI). A `done` of a `Stop` with `stop_hook_active: true` carries
  `"stop_hook_active":true`.
- Claude Code: one `AskUserQuestion` sends one `question` (`PreToolUse` and `PermissionRequest`
  both reported it); `agent_needs_input` (another background session's) still alerts but no
  longer changes this tab's badge; `PostToolUseFailure` with `is_interrupt` (Esc) sets the badge
  idle, not running, and ends a background pause.
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
