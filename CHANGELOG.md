# Changelog

## Unreleased

- **The next turn's `running` reaches the app after every kind of turn end** (SimpleTerm
  `if/event-v2-turn#state`, issue AhMunGa/simple-term#805). A `state` went only when it was not the
  one sent before, and a turn that ended in `done`, a question, `error` or `auth` did not count as a
  change, so the next turn's `running` was dropped: a tmux or herdr row stayed "done" or "waiting"
  while the agent worked. A turn's end now starts the comparison over: the next state goes even when it is the one sent
  before, and a state still waiting for its second is dropped rather than arriving after the turn's
  end. Both hooks (sh, PowerShell).
- **Antigravity CLI sends `running` at each turn's start, and every pause.** agy has no prompt hook.
  The plugin now registers `PreInvocation`, which agy runs before every model call, and takes the
  first of a turn (`invocationNum` 0) as the turn's start: a person's prompt, a background command's
  report and a scheduled run alike (measured on 1.5.16, the latest, and on 1.5.5; a `UserPromptSubmit`
  in `hooks.json` did not run on 1.5.16). The second pause of a session now sends
  `state: background` as the first does (it was dropped as a repeat). agy waits for the hook before
  it calls the model: 0.28 to 0.39 s at a turn's start and 0.06 to 0.08 s at each later call (1.5.16
  on a Mac).
  Tested against stand-ins of the six agents, and with agy 1.5.16 and 1.5.5 in an isolated home with
  a model stub and a stand-in tunnel; the PowerShell hook was not run (no `pwsh` on the test machine).
- **A turn that failed on a refused sign-in is one `auth` for Antigravity CLI, Copilot CLI, Codex and
  OpenCode 1.x too** (SimpleTerm `hist/hook-events#d11`, issue AhMunGa/simple-term#667). agy: a `Stop` error with
  `Error 401`, `UNAUTHENTICATED` or `API_KEY_INVALID`. Copilot and Codex run their failure hook for every try,
  a 401 a retry fixes too, so from a turn's first failure the hook reads the turn in the agent's own record (Copilot's
  `events.jsonl` from the turn's `user.message`, its `session.error` by `originatingMessageId`; Codex's
  rollout, the turn's lines) for 120 s at most and sends `auth` only when the turn ended there on a refused
  sign-in, also when the turn's end was written before the hook read it; Codex now registers `PostModelRequest` (both hooks). OpenCode 1.x: an `APIError` with HTTP
  status 401 or 403, and the two `done` after any error are gone. Claude Code's account and billing errors stay
  `error`. Such a turn end restarts the `state` comparison as every other does (the next turn's `running`
  goes), and a late `auth` leaves alone a next turn that already started. Tested against stand-ins built from records of Copilot 1.0.114, Codex 0.172.0, agy 1.5.16 and
  OpenCode 1.19.6; Codex 0.165.0, the oldest the README names, loads the hooks file with `PostModelRequest` and
  runs its other hooks as before (isolated install, model stub); the PowerShell hook was not run (no `pwsh` on
  the test machine).
- **A Claude Code subagent's approval request no longer keeps its window off the terminal**
  (SimpleTerm `spec/request-wait#hook-wait`, `if/ssh-tunnel-wait#window-closed`, issue AhMunGa/simple-term#895).
  Claude Code 2.1.331 (the latest) runs every subagent in the background and opens a subagent's
  approval window only after its `PermissionRequest` hook ends, so a hook that waited for the app
  left the terminal without the window for up to `claude_wait` (540 s). A request whose hook input
  has `agent_id` now goes as `wait: hidden`, as Codex's: with the app connected the hook does not
  wait and the window opens at once; on relay links alone it waits at most 60 seconds, or
  `claude_wait` when that is shorter. Such a request is never judged from the session file (no mark,
  no resend, no end when the main thread's window closes). A window shared by parallel tool calls
  ("1 of 2") now also ends as answered at the terminal once the session waits on nothing, which it
  does only after every item is answered (measured on 2.1.331). Both hooks (sh, PowerShell); the
  PowerShell hook was not run (no `pwsh` on the test machine).

## 0.9.0 - 2026-11-24

- **A Claude Code request answered in the terminal ends at once** (SimpleTerm `if/ssh-tunnel-wait#window-closed`,
  issue AhMunGa/simple-term#895). Claude Code keeps a `PermissionRequest` hook alive until the tool it allowed
  has ended, and the waiting hook learnt of the answer only from that tool's `PostToolUse`: the app went on
  showing the request (its card, "waiting", its alerts) for as long as the tool ran, up to `claude_wait`. The
  waiting hook now reads Claude's session record (`sessions/<pid>.json`) once a second for every request it
  waits on, not only for a held one, and once before it sends the request. Once it has seen its own prompt
  open, alone on it, and two reads in a row then say the session waits on nothing, it ends every wait and sends
  `resolved` with `out: terminal` (log: `permission answered-at-terminal (window closed)`): about 2 seconds
  after the answer, or after every link has taken the request when that is later (the relay takes about 4
  seconds).
  Nothing to tell by ends nothing: a prompt shared with another permission hook ("1 of 2"), no record, another
  session's record, a prompt recorded later than the hook's start plus 2 s. The wait then ends as before, at
  the tool's end. Another prompt in its place (the session still `waiting`, another `statusUpdatedAt`) ends
  nothing while it is there; once the session then waits on nothing, the wait ends as above. Ending a request
  the user can still answer in the app would be the worse mistake.
  While a prompt is open the record says `waiting` whatever else the session does, a subagent at work
  included: Claude Code 2.1.331 puts a waiting dialog ahead of `busy` when it writes the status (read from its
  code, not measured).
  Both hooks (sh, PowerShell). Tested against a stand-in agent and session record; the PowerShell hook was not
  run (no `pwsh` on the test machine), and neither hook was run under a real Claude Code.

## 0.8.0 - 2026-11-24

Which terminal tab a hook runs for (SimpleTerm `if/hook-tab-identity` phase 1, `if/event-v2#common-fields`,
`if/event-v2-limits#shrinking`, `if/session-record#scope`; issues AhMunGa/simple-term#450, #447, #635).

- **`tab`** on every v2 event to a tunnel (never to the relay), after the multiplexer fields:
  `{"st":"a","tm":"st1-…"}` (the tab's marker `LC_SIMPLETERM_TAB`, which the app sends by the SSH environment
  request and by the shell integration line), `{"st":"b"}` (no marker, no `SIMPLETERM`, no container: not a
  SimpleTerm tab) or `{"st":"c","why":…}` (unknown: `mux`, `daemon`, `container`, `refused`, `form`), with `n`
  (candidate tabs found) and `cl` (their well-formed markers, at most 8, each once) where the clients can be read.
  An app that predates the field ignores it.
- **Rules, the first that applies**: (1) a host shared by several tabs: Codex's daemon (the nearest ancestor
  named `codex` is `codex app-server … --managed-daemon`; the notify program too) is tied by arguments only to
  the one TUI started as `resume <session>` (TUIs started with `--no-daemon`, the daemon's own children and
  other app-servers are not candidates), and that TUI is judged: inside a multiplexer `c` `mux`, a marker `a`,
  none `b`, unreadable `c` `daemon`; no such TUI: `c` `daemon` with `n` and `cl` (the only TUI is a
  candidate, not the session's: an event can come after the session's TUI has gone); another
  `codex app-server` (an IDE's) or a host that cannot be read: `c` `daemon`. OpenCode 2.x is always `c` `daemon`;
  (2) a multiplexer: `TMUX`, `STY`, herdr, or an `abduco` or `dtach` master among the hook's ancestors up to
  the SSH or login process (they set no variable; `mux` is not sent for those two); (3) the marker (`a`, or `c`
  `form`); (4) a container signal,
  `SIMPLETERM=1` without a marker (`refused`), or `b`.
- **Clients**: tmux (`list-clients` of the pane's session) and herdr (the user's `herdr` processes run without a
  subcommand, of the pane's session). A client with a multiplexer server among its ancestors (told by command
  names), one whose ancestors cannot be read and one that has gone count in `n` only. From a client's or a
  TUI's environment only the value of `LC_SIMPLETERM_TAB` is taken (Linux `/proc/<pid>/environ` one entry at a
  time, macOS `ps -E -p` with the command line taken off the front and cut out in the same pipeline; two
  different values: none is taken); nothing else is
  kept, written or sent. Windows reads none. The README's Privacy section states the rules.
- **Scope fields**: `msess` (herdr's named session, tunnel and relay; the relay summary drops it first when it is
  over budget, recorded in `cut`) and `msock` (the tmux socket path, tunnel only; sent as it is or not at all:
  printable ASCII without `"` or `\`, 256 bytes at most). A Codex hook in the daemon, or one that cannot
  tell, sends neither: its variables may be another tab's.
- **Session record of a Codex hook**: a record that is there is kept up without a look at any process; a new one
  is made at a prompt or a session's start only. In the daemon it is made only for a TUI whose own environment
  has the tab marker (the one tied by its arguments, else the only TUI), with the multiplexer that TUI runs in
  (by its ancestors; a record that is there changes its multiplexer only for a tied TUI); before, the
  daemon's `SIMPLETERM` decided, which belonged to the TUI that started the
  daemon. A Codex that runs its hooks itself (`--no-daemon`) goes by `SIMPLETERM` as before, and so does
  Windows.
- Codex sends no `pane`, as before, and the multiplexer fields of every agent are as before.
- The same in `agent-hook.ps1` (Claude Code, Codex, Grok Build) and in every plugin's copy of `agent-hook.sh`.
  The test suite gives the hook stand-ins for every process read (`SIMPLETERM_HOOK_TEST_IDBIN`); outside a case
  that sets them it reads nothing (`none`). `t_v2_tab` holds the cases of the rules for both hooks. Outside herdr
  the relay events are byte for byte those before; the tunnel events gain `tab` (the shared fixtures).
- Not in this release (phase 2 of `if/hook-tab-identity`): the outer tabs of nested multiplexers, the clients of
  screen, abduco and dtach, and the TUI part that tells an OpenCode 2.x service which tab shows a session.

## 0.7.0 - 2026-11-17

- **Claude Code background pause on the screen** (SimpleTerm `if/terminal-signals-bg`, `hist/hook-events#e28`,
  issue AhMunGa/simple-term#804): Claude Code passes a hook's `terminalSequence` on only when every sequence in it is
  OSC 0, 1, 2, 9, 99, 777 or BEL, and drops the whole field for one OSC 7501 (2.1.141 to 2.1.325). The OSC 7501
  record `simpleterm-bg` that 0.3.1 to 0.6.0 put there therefore never reached the terminal, and the badge's own
  `background`, `waiting` or `running` went with it. The hook now writes no OSC 7501 there: where Claude Code
  speaks OSC 7501 itself (the same check as before) it writes, after the old value, the OSC 9 value `bg_working`
  (a pause, with the pause's summary), `bg_question` (a pause that asks, with the question) or `bg_clear` (in the
  first output of the next turn while the screen shows a pause: `UserPromptSubmit`, or a `Stop`, `StopFailure` or
  Esc interrupt that comes first; a `Stop` that pauses again writes its own value instead). A pause stays on the
  screen until an output says `bg_clear`: the late `done` after `bg_done_after`, a turn whose hook writes nothing
  and the run files' one-day clean-up leave it for the next turn (a mark, `<session>.bgclr`, kept 30 days), and
  `/clear`, `/resume` or `/branch` hand it to the new session of the same folder. The message is the old value's,
  cut the same way. An app that does not know the values drops them and keeps the old one. The sh and the
  PowerShell hook.
- **Copilot CLI session end** (SimpleTerm `if/hook-events#session-end`, `hist/hook-events#d10`, `#e27`): on
  `sessionEnd` the hook writes `ESC ] 7501 ; state=clear BEL` to `/dev/tty`, before anything else and once, in a
  SimpleTerm session outside tmux, screen and herdr, when the terminal opens; else nothing. Copilot CLI writes no
  `clear` itself (1.0.109), so the app kept it as the tab's agent until a shell prompt. The sh hook (Copilot runs
  no PowerShell hook).
- **Usage ask timeout** (issue AhMunGa/simple-term#811): the sh hook's ask counted its 60 seconds in rounds in two
  loops, and on a loaded machine the input side closed first; the agent then ended for want of input and the ask
  was read as gone (`failed`, which counts toward stopping that version) instead of `timeout`. One deadline on the
  clock now decides, the watcher alone judges it, and the input stays open until it has. The PowerShell hook had
  one loop already.
- **Tests**: the runner checks every `terminalSequence` any hook prints against what Claude Code passes on (the
  allowlist above, 4096 bytes, no OSC 9 starting with a digit but `9;4`); the 0.6.0 hooks fail it. The runner has
  environments per server OS (ubuntu: dash and OpenSSL 3; macos: `/bin/sh` and LibreSSL; windows: PowerShell 7;
  compat: the cases another `sh` must pass), waits for conditions instead of fixed sleeps, and an environment that
  cannot run counts as a failure (README "Development"). A test-only `SIMPLETERM_HOOK_TEST_ASK_WAIT` shortens the
  ask's wait.

## 0.6.0 - 2026-11-16

The install, update and move commands of the README take the branch `release` (SimpleTerm
`spec/plugin-update#release`, `if/cmd-plugin-installer#commands`, `if/cmd-plugin-update#commands`,
`if/ext-plugin-repo#readme-differences`). Moving to `release` changes no hook; the hook changes since 0.5.1
are the items below, and they are what 0.6.0 brings.

- **`release` branch**: `release` moves only to a commit that raises the plugin version (Claude Code does not
  receive a new commit that keeps the version). `main` is where work lands and may carry a commit that is not
  a release. The README installs from `release`, and has a section for moving an install made from `main` to
  `release`. The SimpleTerm app moves such an install itself, with the same commands.

The last run of an Antigravity CLI or OpenCode schedule is quiet, and a task report after a Claude Code Esc is told
(SimpleTerm `spec/turn-state#scheduled`, `if/hook-events-scheduled`, `hist/turn-state#d18`, `#d19`, `#d20`, issues
AhMunGa/simple-term#469, AhMunGa/simple-term#685).

- **Antigravity CLI** (`/schedule`, measured on 1.5.5): no hook says who opened a turn, so at `Stop` the sh hook
  reads `transcript_full.jsonl` (its last 4 MiB): the step that opened the turn (a person's input, or the message of
  a cron, timer or background command) and the schedules and commands still left. A turn a schedule woke rests
  (`state: scheduled`) while a schedule is left, and its last one is a `done` with `by: schedule` to the tunnels
  only; before, that last run was a plain `done`. The report of a command a scheduled turn started is the
  schedule's too. A person's turn that only leaves a schedule now ends in `done` (before, it waited as for a shell).
- **OpenCode 2.x** (2.2.3+ with the `schedules` flag, measured on 2.2.7): the plugin follows the session's inbox
  (`session.inbox.enqueued`, `session.inbox.delivered`): an execution that only a schedule's prompt started, or the
  report of a shell such an execution started, is a scheduled turn, and its `Stop` carries `turn_by` and the active
  schedules from OpenCode's `schedule_list` tool (`session_crons`). An item enqueued while the session was idle counts
  for the execution that starts next even if its `delivered` event does not come. Before, every scheduled run ended
  in `done`.
- **Claude Code Esc** (2.1.319, 2.1.325 run no hook when Esc stops a turn): the turn mark keeps the `prompt_id` of
  the prompt that opened the turn, and a task report with another id starts a turn of its own. Before, a report
  after an Esc took over the stopped turn, and when that was a `/loop` turn with a schedule left, the report's
  `done` was lost. A Grok Build `StopCancelled` whose `promptId` is not the open turn's leaves that turn alone
  (Grok can send it after the next turn started). The sh and the PowerShell hook.

The usage ask no longer signs Claude Code or Codex out by cutting a sign-in refresh (SimpleTerm
`if/usage-ask-refresh`, `hist/usage-ask#d23`, `#d24`, `hist/usage-ask#e5`, `#e6`, issue AhMunGa/simple-term#693).

- **What happened**: an ask started while the agent's access token was about to expire made the asking process
  refresh it. When the ask was ended at its 20-second limit after the server had rotated the refresh token, the saved
  refresh token was dead: every Codex failed with `refresh_token_reused` once its access token expired (`codex login`
  again), and Claude Code cleared its credentials and failed at once (`/login` again). Measured with a mock sign-in
  server on Codex 0.167.0 and Claude Code 2.1.325; their own refresh timeouts are 45 and 30 seconds.
- **Now**, in the sh and the PowerShell hook: no ask in a turn where the credentials file says a refresh is due (the
  access token expires in less than 10 minutes or has expired; for Codex also a `last_refresh` more than 7 days old),
  and nothing is counted then. The answer is awaited 60 seconds instead of 20.
  - Claude Code: a file that is not there, cannot be read or is not whole JSON still asks; the 60 seconds outlast its
    refresh (measured).
  - Codex: asked only with an API key sign-in or when the hook read the access token's `exp` and no refresh is due.
    A missing, unreadable, broken or over-64-KiB `auth.json`, or a token whose `exp` is not seen, skips the ask
    (logged `sign-in state unknown`): an ask of Codex refreshes at start-up and answers before saving the refresh,
    whatever the wait (measured).
- **Codex error answers**: an error answer ends with `"id":2}`, which the ask did not take for an answer, so a failed
  sign-in or an API key was read as `timeout` after 20 seconds, and three of them stopped asks of that Codex version.
  It is now read as `auth` or `not-subscriber`. The answer is the first line with `"id":2` then `,` or `}` and no
  `"method":` (a JSON-RPC response), so a notification before it that nests an object with id 2 is not taken for it.

The PowerShell hook's held sender runs, and a Claude Code URL form is told again (SimpleTerm
`if/ssh-tunnel-wait#open-window`, issue AhMunGa/simple-term#446).

- **PowerShell**: run on pwsh 7.7.0 for the first time, the held sender of `agent-hook.ps1` stopped before its
  first round: `@($links)` on its list of held links threw `Argument types do not match`, and the error was
  swallowed, so the PowerShell hook never told a held request again. The links are now copied one by one. The
  sender's tests run on pwsh too (with a Claude Code MCP form; the Antigravity CLI cases on the sh hook only).
- **Claude Code URL form** (`Notification` `elicitation_url_dialog`): Claude Code 2.1.322 writes `waiting` and
  `input needed` in its session file for it as for the MCP form, so it is told again while that window is open,
  in the sh and the PowerShell hook. Before, it logged `held: no record of claude's window to tell it by (stop)`.
- README: the known limitation on held requests names the requests that still cannot be told again.

A running Gemini CLI session no longer runs the agent again when the extension is removed or updated under it
(SimpleTerm `if/plugin-locations#manifests`, `hist/plugin-locations#d3`, `hist/plugin-locations#e5`, issue
AhMunGa/simple-term#686).

- **What happened**: a Gemini CLI session keeps the hook commands it registered at start. Once the extension's
  folder was gone, `sh "<script>" gemini` ended with 127 and `No such file or directory`. The folder goes away on
  the app's remove, a user's `gemini extensions uninstall`, and the reinstall that turns on auto-update;
  `gemini extensions update` also removes the folder and copies it again. Gemini CLI reads any exit code other
  than 0 or 1 with text as `deny`, and a denied `AfterAgent` runs the agent again, so one prompt made up to 36
  model calls (measured with a local model stub on 0.66.0).
- **Now**: the two commands in `hooks/hooks.json` end with `; exit 0`. The hook always ends with 0 and prints
  nothing on stdout, also when its script is gone: one model call per prompt (measured). `; exit 0` reads the same
  in `bash -c` (Gemini CLI on Linux and macOS) and in PowerShell (Gemini CLI on Windows). The hook's Gemini path
  gives its exit code no meaning, so nothing else changes. With the script gone, Gemini CLI shows the shell's
  `No such file or directory` line as a message under the turn.
- **Already installed**: a session that started before the update keeps the old commands. Update the extension
  and start Gemini CLI again.
- Claude Code, Grok Build and Codex keep their hook files: in the same measurement they did not run the agent again
  (Claude Code and Grok Build do not run a hook whose plugin folder is gone). The Copilot CLI and Antigravity CLI
  commands already end with 0 when they find no script; a new test holds all three to the rule.

A held Claude Code question is told again on Claude Code 2.1.322 too (SimpleTerm
`if/ssh-tunnel-wait#open-window`, `hist/request-wait-link#d7`, issue AhMunGa/simple-term#446).

- **The window value per kind**: Claude Code 2.1.322 writes `waitingFor: "input needed"` in its session
  file for a question window (`AskUserQuestion`); 2.1.316 and 2.1.317 wrote `permission prompt`
  (`hist/event-v2-request#e32`). The open-window check before telling a held request again took only
  `permission prompt`, so on 2.1.322 a held question was not told again (the hook ended with
  `held: the window is not open`). Now a question takes `permission prompt` or `input needed`, and every
  other permission request (approval, plan, `Workflow`) still only `permission prompt`. The version is not
  read; the other conditions stay (same `sessionId`, `waiting`, the first value at most 2 s after the hook
  started, `statusUpdatedAt` unchanged, the parallel-call marks).
- **An unknown value is logged once**: when the session waits with a `waitingFor` that is no value of the
  request's tool, the hook tells nothing again and writes one line to its log on the server:
  `held: unknown waitingFor "<value>" for <tool> (stop)` (the value keeps only ASCII letters, digits,
  spaces and `.`, `_`, `-`, cut at 40 characters). A new Claude Code version that writes another value
  shows up there.
- The same in `agent-hook.ps1` and in every plugin's copy of `agent-hook.sh`. Nothing on the wire changes.

A held request the hook does not wait on is told again while its window is open (SimpleTerm
`if/ssh-tunnel-wait#held-undecidable`, `if/ssh-tunnel-wait#open-window`, `spec/request-wait-link#held`,
`hist/request-wait-link` D and E, issue AhMunGa/simple-term#446).

- **Who stays**: an undecidable request (`req.wait` `none`: an Antigravity CLI or Grok Build question, a
  Grok Build permission window or plan review, a Claude Code MCP form, or a Claude Code question from
  `PreToolUse` that the hook does not wait on) is sent from the detached sender. Before, that sender
  dropped the answer, so a request a v2 app held back (`"held":true`, the user was looking at another
  wait) was never shown. Now the sender reads the answer: when a tunnel of a `fmt=2` link answered held,
  it stays, and every 5 seconds it checks the agent's own record of the window and, while it is open,
  sends the same request again (the same `req`, a new rid and time, no nonce) to the tunnels that
  answered held. A tunnel that answers anything but held is dropped.
- **The window's record**: Antigravity CLI `transcript_full.jsonl` (the last step is the planner's
  `ask_question` call one step before the request's), Grok Build `chat_history.jsonl` (the last line is
  the assistant's call with the request's id, no result for it) and for a permission window also
  `events.jsonl` (the last line is `permission_requested`), Claude Code its session file (`input needed`
  for the MCP form; `input needed` or `permission prompt` for a question, first seen after the first
  send). A request with no record (Claude Code's `agent_needs_input`, Antigravity CLI's plan
  confirmation, Codex, OpenCode, Copilot CLI) is not told again: one log line `held: no record of <agent>'s window to tell it by (stop)`.
- **Limits**: one sender per request (the mark `run/held.<session>.<request key>` holds its pid; a
  second hook of the same call logs `held: another sender has it (stop)`), at most 8 per user
  (`held: too many senders (stop)`), 540 seconds from the hook's start (`held: limit (stop)`). It also
  stops when the agent is gone, the request was answered at the terminal, or the window is no longer
  open, each with one log line; the mark goes with it, also on TERM or INT.
- The same in `agent-hook.ps1` (Claude Code and Grok Build; it runs no Antigravity CLI hook) and in
  every plugin's copy of `agent-hook.sh`. The first send is unchanged.

Agents inside herdr, and the pane an agent runs in (SimpleTerm `if/event-v2#common-fields`,
`if/hook-events-identification#identification`, issue AhMunGa/simple-term#612): the app's agent session list can
tie an alert or a request to a herdr or tmux session row whose session id it does not know yet
(before an agent's first prompt, or Copilot CLI after `/clear`).

- **`mux` `herdr`**: a hook whose environment has `HERDR_ENV=1` and `HERDR_PANE_ID` sends
  `"mux":"herdr"`. `TMUX` and `STY` are still read first: herdr (0.9.5, measured) removes `TMUX`,
  `TMUX_PANE` and `STY` from its panes, so when both are there a tmux or screen was started inside a
  herdr pane and is the nearer multiplexer. OpenCode 2.x stays `unknown`.
- **`pane`** (new, optional, right after `mux`): the multiplexer's own id of the agent's pane,
  `HERDR_PANE_ID` (such as `w1:p3`) inside herdr and `TMUX_PANE` (such as `%13`) inside tmux; none
  inside screen. Sent only when it fits `[A-Za-z0-9%._:-]{1,64}`, and never for Codex (its default
  daemon runs every hook with the environment of the TUI that started it, so the id would name
  another pane) or OpenCode 2.x (`mux` `unknown`). The tunnel and the relay get the same value (an
  opaque id, not a secret), and no relay cut drops it, as with `mux` (`if/event-v2-limits#shrinking`).
  Every v2 event carries it (requests, results, states, turn ends, usage). The session record
  (`if/session-record`) does not (a resumed session runs in another pane); its `mux` can now be
  `herdr`.
- The same in `agent-hook.ps1` (Claude Code, Codex, Grok Build) and in every plugin's copy of
  `agent-hook.sh`. The OpenCode plugins hand the hook their own environment as before.
- **Which app reads it**: the SimpleTerm app reads `pane` and `herdr` from #612 (the agent session
  list). An older app ignores `pane` and reads `herdr` as a multiplexer name it does not know, which
  already means "inside a multiplexer" (no key is sent, no OSC 7501 wait is matched), as inside tmux.
  With an older plugin a newer app ties rows by session id only.
- Outside herdr, tmux and screen the events and records are byte for byte those of 0.5.1 (the shared
  fixtures); inside tmux the events gain `pane`.

The install commands here and in the SimpleTerm app are the same, or the README says why not
(SimpleTerm `if/cmd-plugin-installer#commands`, `hist/cmd-plugin-installer#d6`, issue
AhMunGa/simple-term#470). No hook changed.

- **Copilot CLI from a marketplace**: a catalog of its own, `.github/plugin/marketplace.json`
  (marketplace `simpleterm-agent-hooks`, only `simpleterm-copilot`), so
  `copilot plugin install simpleterm-copilot@simpleterm-agent-hooks` works after
  `copilot plugin marketplace add AhMunGa/simpleterm-agent-hooks`. Copilot reads that file before
  `.claude-plugin/marketplace.json`; Claude Code and Codex do not read it and list no Copilot plugin
  (measured: Copilot CLI 1.0.108, Claude Code 2.1.322, Codex 0.167.0; SimpleTerm
  `if/plugin-locations#distribution`, `hist/plugin-locations#d2`). The direct install still works,
  but Copilot 1.0.108 says direct installs are deprecated.
- **README**: Grok Build's and OpenCode 2.x's arguments are in double quotes (unquoted, zsh with
  `extendedglob` stops at the `#` and csh drops everything after it, `--trust` too); Gemini CLI
  makes `~/.simpleterm` owner-only (`mkdir -p -m 700`) and passes `--skip-settings`, as the app
  does; the Antigravity copy install makes the same folder first; OpenCode 1.x first removes the
  links an earlier SimpleTerm app made into `~/.simpleterm/src` (`curl -o` would write through
  them). Running an install again changes nothing, but Gemini CLI and Grok Build exit 1 then.

The end of a turn a schedule started (SimpleTerm `spec/turn-state#scheduled`,
`if/hook-events-turn#background`, issue AhMunGa/simple-term#469):

- **The last scheduled turn is quiet**: the `Stop` that finds no schedule left after a turn a
  schedule started (`/loop`, `ScheduleWakeup`, CronCreate; Grok Build `scheduler-fired-`) sends its
  `done` (`turn.by: schedule`) to the tunnels only and at once (no `done_delay`: no alert waits on
  it), nothing to the relay, and Claude Code's screen gets the new state value
  `simpleterm:state=done_scheduled` (`if/terminal-signals#structured`), so the app lists the result
  without an alert and keeps Claude's own OSC 7501 `done` quiet too. A turn that ended asking
  (`turn.asks`) is still a plain `done` on the screen, the tunnels and the relay. An older app drops
  the new value and alerts on the agent's own `done` as before.
- **A task's turn ends while a schedule is set**: only a turn a schedule started waits for the
  schedule; a turn a task's report (or the agent) started ends in `done` when none of its work is
  left (`spec/turn-state#background`). Before, a set schedule kept it quiet.
- **Grok Build's scheduled runs** (`if/hook-events-turn#turn-end`, measured on 1.0.77): each run is
  a background subagent, and the turn its result opens starts with `subagent-completed-` like any
  subagent's report. That turn is the schedule's when its prompt names (`scheduler_delete("<id>")`)
  a schedule of the `Stop`'s `sessionCrons` or of the previous `Stop`'s (a run whose turn drops the
  schedule ends with none): no `done` per run, and the last one goes to the tunnels only. With the
  rule above alone each run sent a `done`. Grok has no one-shot schedule.
- **Copilot CLI's scheduled turns** (`/every`, alias `/loop`, and `/after`, an experimental
  feature; `if/hook-events-turn#turn-end`): a prompt that starts with `[Scheduled prompt #<id>]` is
  a turn a schedule started (the hook input has no `source`, measured on 1.0.109), and the schedules
  left at `agentStop` are counted from `events.jsonl` (`session.schedule_created` less
  `session.schedule_cancelled` and a one-shot whose prompt came). The rules above apply: no `done`
  while a schedule is set after a scheduled turn, and the last one goes to the tunnels only. A
  prompt you type that starts with that mark is yours again at `agentStop`: the session's last
  `user.message` in `events.jsonl` has a `schedule-<id>` source for a run and none when you typed
  it, written before `agentStop` (`hist/turn-state#d11`). A subagent's own prompt in that file
  (source `agent-<session id>`, which can come before the main `agentStop`) is not the session's
  prompt: before, a scheduled run that started a background subagent could read as yours. A
  one-shot `/after` run (measured on 1.0.109) leaves no schedule at its `agentStop`
  (`hist/hook-events#e12`). `agent-hook.sh` only: Copilot runs no `agent-hook.ps1`.
- **The report of work a scheduled turn started is the schedule's** (`spec/turn-state#background`,
  `if/hook-events-turn#background`, `hist/turn-state#d14`): a `/loop` turn that ran a background
  agent sent a `done` with each report (the rule above; before #469 it sent nothing), and a Copilot
  scheduled run's background shell did the same before. A scheduled turn's `Stop` now keeps the ids
  of the work it started (the newest 32, until no schedule is left or the session ends), and a
  report turn on one of them ends like a scheduled turn, a report on a report too: Claude Code's
  `<task-notification>` by its `<task-id>`, Grok Build's `task-completed-` and
  `subagent-completed-` by the id after it, Copilot's `<system_notification>` by the work the
  notification that opened the turn names (in `events.jsonl` it follows the main agent's
  `userPromptSubmitted` hook; a notification of work that ended inside a running turn comes with no
  such hook and opens none, measured on 1.0.109): a shell (`shell_completed`, its `shellId`), a
  detached shell (`shell_detached_completed`; the scheduled turn keeps the ids of the detached shells it
  started, which are no work to wait for), or a background subagent (`agent_idle`, its `agentId`,
  tied to the `toolCallId` of its `subagent.started`); no `user.message` is written for that turn
  (measured on 1.0.105 and 1.0.109). A report that comes while a turn runs does not start a turn:
  Claude Code hands work that ended inside the turn to it as a `<task-notification>` prompt between
  its tool calls, and the turn keeps who started it (the turn mark `<sid>.turn` has a 4th line
  `open` until the turn's `Stop`, `StopFailure` or Esc; Claude Code and Grok Build). Before, a
  `/loop` turn whose background work ended inside it sent a `done`. The report of work
  your own turn started still ends in `done` (`hist/hook-events#e15`). Codex has no schedules;
  OpenCode 2.x and Antigravity follow.
- **Grok Build's cancelled turn ends the turn** (`hist/turn-state#d16`): Grok 1.0.77 runs
  `StopCancelled` instead of `Stop` when a turn ends without completing (Ctrl+C: `reason`
  `user_interrupt`, `cancelTrigger` `ctrl_c`; a rejected permission: `permission_rejected`;
  measured). The hooks file now names it, and the hook ends the turn as at Claude Code's Esc: `state`
  `idle` with `turn.end: interrupt`, and the turn mark closes, so a report that comes next starts a
  turn of its own. Before, the plugin did not hear it and the turn stayed open. Claude Code ignores
  the entry (2.1.322 runs the other hooks of the file; `claude plugin validate` warns "unknown hook
  event; entry ignored at runtime").
- **A failed turn shows an error**: Claude Code's `StopFailure` writes `simpleterm:state=idle` and
  then the new state value `simpleterm:state=error` in the same output, instead of `done` (a failed
  turn showed a green done badge where Claude does not speak OSC 7501). The app shows the error badge
  and one error alert, which the `error` event pairs with; a login error is `error` on the screen
  too while its event stays `auth`. An older app drops `error` and is left with `idle`: the badge is
  cleared. The `error` or `auth` event is unchanged.
- The same in `agent-hook.ps1` and in every plugin's copy of `agent-hook.sh`.

## 0.5.1 - 2026-11-04

A request held back for a wait is told again while it is still open (SimpleTerm
`docs/tech_specs/TDS_AGENT_EVENTS_V2.md` section 4.6 "보류한 요청 다시 알리기", D23, issue
AhMunGa/simple-term#414), and Codex session ends are recorded (section 8, R7).
- **Held requests told again**: a SimpleTerm tunnel answers `suppressed` with `"held":true` for a
  request it held back because the user is looking at an agent's own prompt that asks the same. For
  a Claude Code permission request (tool approvals, plans, questions; the hook waits beside Claude's
  prompt), the hook then stays while Claude's own session record (`sessions/<pid>.json` under
  `CLAUDE_CONFIG_DIR` or `~/.claude`) says this session still waits on that very permission prompt
  (`status` `waiting`, `waitingFor` `permission prompt`, `statusUpdatedAt` as first seen, taken only
  if written no later than 2 s after the hook's start) and no other permission hook of the session
  waits on that same prompt (a `run/perm.<session>.<pid>` mark of a live hook holding the
  `statusUpdatedAt` it first saw: parallel tool calls share one prompt, "1 of 2", and Claude's
  record does not change from one item to the next, measured on 2.1.316; the hook of an earlier
  prompt that has not ended yet holds another value and does not count), and sends the request to
  that tunnel again about every 5 seconds (4 to 6: whole seconds): one new rid for every held tunnel
  in a round, sent to all of them at once, a nonce each, the same request id, a fresh `ts` and
  `tms`. Each round's events are sealed first; then the hook checks the terminal answer
  (`PostToolUse`, turn notes) and that the agent lives, and last the window, and posts at once (tens
  of ms from the check). A tunnel that then answers `sent` is waited on as usual; one that no longer
  answers `held` gets nothing more. Once the prompt closes or another one takes its place, or the
  record cannot be read (5 seconds after the hook's start before it is first seen, then 3 reads in a
  row), nothing more is sent and the hook ends as before (`resolved` `window`, or `terminal` from
  `PostToolUse` and turn notes as before). The cap stays `claude_wait`. Older apps never say `held`,
  so the hook behaves as 0.5.0 there; other agents' requests are not sent again.
- **The agent's pid without `ps`**: where `ps` is missing or may not run (some containers), the hook
  reads the command name and parent from Linux's `/proc` (agent-gone checks and the held resend need
  it). Without either, the held resend stays off.
- **Codex `SessionEnd`** (Codex 0.165.0, measured): registered (no matcher: its only `reason` is
  `other`; timeout 3, Codex's most). The hook writes the session record's `.ended` first (only for a
  session with a record: one quit before any prompt left a lone mark the keep never counted), then
  sends `state` `ended` to the tunnels, and does not wait for the send (the PowerShell hook hands it
  to a child there too): Codex ends the hook's process group after the timeout and keeps the
  children of a hook that ended in time. Codex runs it on a normal exit and at the end of `codex
  exec`, not on a signal (an SSH drop); in its default daemon mode only when the conversation is
  closed there (about 30 minutes later) or the daemon stops. In daemon mode every Codex hook gets
  the environment of the terminal that started the daemon (SimpleTerm `TDS_AGENT_EVENTS_V2.md` R17,
  issue AhMunGa/simple-term#447); this release does not change that. The PowerShell hook also writes
  the end mark before sending (Claude Code, Grok Build, Codex).
- **PowerShell: a request that runs out its wait is logged as a timeout**: the PowerShell hook ran its
  once-a-second checks on a timer, so a poll that ended at the deadline sometimes ended the request
  as `permission no-decision` instead of `permission timeout` (the answer to the agent was the same,
  none). The checks also run as soon as the deadline has come, as in `agent-hook.sh`.

## 0.5.0 - 2026-11-03

Usage v2 (SimpleTerm `docs/tech_specs/TDS_AGENT_EVENTS_V2.md` section 9, issue
AhMunGa/simple-term#418): limits asked from the agent, where each value came from and when it
was checked, tokens and cost where there are no limits. The plaintext `v` stays 1; the screen's
OSC 9 is as before.

- **The usage event is a v2 event**: the common fields (`fmt`, `pv`, `av`, `sid`, ...) after the
  v1 fields, `uq` and `cost` before `ts`. Every window has `src` (`ask`, `file`, `statusline`) and,
  but for the status line, `at` (Codex: the rollout record's time).
- **Asking the agent** at a turn's end, only while the app is connected (a tunnel's last event an
  HTTP 200 within 10 minutes), every 5 minutes per agent and settings folder, in the background
  with `SIMPLETERM_PROBE=1` in `~/.simpleterm/probe`, 20 s at most, the answer to the tunnel only
  with `uq`: Claude Code `get_usage` (5-hour, 7-day, per-model 7-day, plan) and Codex `app-server`
  `account/rateLimits/read` (every limit id, as the rollout names it). Every version and OS is
  asked; measured (macOS, a local mock API): 0 model requests in 22 asks of Claude Code 2.1.316 and
  2.1.317 and 11 of Codex 0.165.0. The ask runs the executable on `PATH` with its links followed (a
  native Claude Code install names its version there), else by its `--version`, kept until the
  executable changes (no ask that turn). That version stops for good after a Claude Code answer
  that shows any spend or a hook run in the ask, or after 3 failed or timed-out asks in a row of
  that version, Claude Code or Codex (`run/ask.<agent>.off`, one version a line, `unknown` if
  `--version` gives none; the count in `run/ask.<agent>.fail`, cleared by an answer). After a
  failed sign-in or an answer of no plan limits (`not-subscriber`, sent once) no ask until the
  credentials file changes; these do not count. One ask per 5 minutes even when several sessions
  end a turn at once (the slot is claimed at once). An agent still there 3 seconds after its
  answer is ended with its process group, TERM then KILL (the sh hook starts it in one with `perl`
  or `setsid`; without either, and in the PowerShell hook, its process tree, which misses a
  process that left it). `usage_ask=off` turns asking off, `usage_ask_codex=off` only
  Codex's (its app-server writes its own files in `~/.codex`, syncs its plugins and may refresh an
  expired sign-in). Claude Code writes its usage cache to its own `~/.claude.json` (README).
- **agent-hook.conf** values may have blanks around the `=`, a `#` comment, quotes, Windows line
  ends and a UTF-8 BOM at the start of the file, in any case (`usage_ask = "OFF"  # never`); the
  first line of a key decides. This holds for every key (`claude_wait` and the rest); before, such
  a line was ignored. Numbers are read as decimal in the sh hook too (`claude_wait=0090` is 90, not
  an error; `usage=00` is off), as the PowerShell hook and the app read them (SimpleTerm
  `TDS_AGENT_ALERTS.md` section 6.7).
- **The session's version** (`av`) from a Claude Code transcript is a line's own `version`, not one
  inside a tool result.
- **GitHub Copilot CLI**: premium requests, chat and completions quota from its session events.
- **Grok Build** and **OpenCode**: the session's tokens and cost (`cost`); the OpenCode plugins
  pass the session's cost and tokens on `Stop`.
- A hook run with `SIMPLETERM_PROBE=1` does nothing.

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
