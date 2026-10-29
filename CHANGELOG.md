# Changelog

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
