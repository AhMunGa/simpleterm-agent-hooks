# Changelog

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
    (`${PLUGIN_ROOT}`, `${CLAUDE_PLUGIN_ROOT}`, the install folder, the app's clone, then
    `./scripts`) and print nothing when it is missing. Not tested with a real `agy` yet.
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
