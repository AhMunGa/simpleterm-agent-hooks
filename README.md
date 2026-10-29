# SimpleTerm agent hooks

Hooks for [Claude Code](https://code.claude.com/docs/en/plugins) and
[Codex CLI](https://developers.openai.com/codex/plugins) that connect a coding agent on your server
to the SimpleTerm iPad/phone SSH app:

- **Status badges** (Claude Code): the terminal tab shows running, waiting for approval, or done.
- **Alerts**: end-to-end encrypted push notifications when the agent finishes, asks a question,
  hits an error, or needs a permission.
- **Approvals**: approve or deny a permission request from the notification. The hook waits for
  your answer and hands it to the agent. If no answer comes, the agent's own prompt in the
  terminal stays in charge.

One repository serves both agents. It is a plugin marketplace with one plugin, `simpleterm`.

## Requirements

- macOS, Linux or BSD with `sh`, `curl` and `openssl` (OpenSSL 1.1/3.x or LibreSSL 3.3+).
  Without `curl` or `openssl` the hook only writes the status badges. It also sends nothing when
  `printf` is not a shell builtin (OpenBSD `sh`/`ksh`, mksh), so that secrets never appear in the
  process list.
- Claude Code with `claude plugin` (2.1.312 tested), or Codex CLI with `codex plugin` (0.165.0 tested).
- The SimpleTerm app, paired with this server (see below).
- Windows: see [Windows](#windows).

## Install

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

## Pair with the SimpleTerm app

The plugin sends nothing until the app links this server. Turn on agent alerts for the host in
SimpleTerm. Over SFTP the app writes one link file per device to
`~/.simpleterm/links/<linkId>.conf`, holding the relay address and the keys for that device.
The app only writes its own files under `~/.simpleterm`; it does not run commands on the server
or edit your Claude Code and Codex settings. Revoking the link in the app stops delivery at the
relay. Deleting the file stops the hook from sending.

Status badges need no link: in a SimpleTerm session (`SIMPLETERM=1`) Claude Code shows them as
soon as the plugin is installed.

## What it sends

| Agent event | Alert | Badge (Claude Code, SimpleTerm sessions only) |
|---|---|---|
| Claude `PermissionRequest` | permission (waits for your answer, up to 540 s) | waiting, then running |
| Claude `PreToolUse` `AskUserQuestion`, `Notification` (idle, elicitation, input needed) | question | waiting (idle keeps done) |
| Claude `UserPromptSubmit`, `PostToolUse`, `PostToolUseFailure` | none | running |
| Claude `Stop` / `StopFailure` | done / error or sign-in problem | done |
| Codex `PermissionRequest` | permission (waits up to 60 s) | none |
| Codex `Stop` | done | none |

Codex runs a `PermissionRequest` hook before it shows its own approval prompt, so while the hook
waits the terminal shows only `Waiting for approval in SimpleTerm`. The wait is 60 seconds by
default and is skipped when no device was notified. Codex runs hooks through your login shell
(`$SHELL -lc`); a login profile that prints to standard output breaks the approval answer.

Wait times can be changed in `~/.simpleterm/agent-hook.conf`:

```
claude_wait=540   # seconds, at most 540
codex_wait=60
poll_wait=25      # one long-poll, 1-25
```

## Privacy

- Without a SimpleTerm link file nothing is sent over the network.
- Each alert is encrypted on the server (AES-256-CBC + HMAC-SHA256) with keys that only this
  server's link file and your device hold. The relay sees the event type and ciphertext, not the text.
- The encrypted alert holds the agent name, the host label you gave in the app, the last folder
  name of the working directory, and a message of at most 200 characters: the start of the command
  or file path for a permission request, the question, or the start of the agent's last reply.
  The full tool input and the conversation are never sent.
- A permission answer is signed by the device; the hook ignores an answer whose signature does not match.
- The hook keeps a 200-line log in `~/.simpleterm/agent-hook.log` with event types, the first
  8 characters of link IDs and HTTP results, never message text or host names.

## Update

Claude Code:

```sh
claude plugin update simpleterm@simpleterm-agent-hooks
```

Codex (then trust the changed hooks again in `codex`):

```sh
codex plugin marketplace upgrade simpleterm-agent-hooks
```

## Uninstall

Claude Code:

```sh
claude plugin uninstall simpleterm@simpleterm-agent-hooks
claude plugin marketplace remove simpleterm-agent-hooks
```

Codex:

```sh
codex plugin remove simpleterm@simpleterm-agent-hooks
codex plugin marketplace remove simpleterm-agent-hooks
```

To remove the link files and state too: `rm -rf ~/.simpleterm`, and revoke the link in the app.

**Hooks installed by an earlier SimpleTerm app.** Earlier test builds of the app added the same
hooks to `~/.claude/settings.json` and `~/.codex/hooks.json` (handlers whose command contains
`.simpleterm/agent-hook`). Remove those entries when you install the plugin; otherwise every alert
arrives twice.

## Windows

Not tested on Windows yet.

- **Codex**: the hooks declare `commandWindows`, which runs `scripts/agent-hook.ps1` with Windows
  PowerShell 5.1+ (no extra tools needed).
- **Claude Code**: plugin hooks have no per-OS command, so the hooks run `scripts/agent-hook.sh`
  through Git Bash ([Git for Windows](https://git-scm.com/downloads/win)). Without Git Bash the
  hooks fail and alerts are not sent. The permission and question hooks are marked
  `"onFailure": "continue"`, so such a failure never blocks or denies a tool call.

## Layout

```
.claude-plugin/marketplace.json        marketplace (read by both Claude Code and Codex)
plugins/simpleterm/
  .claude-plugin/plugin.json           Claude Code manifest; hooks in hooks/hooks.json
  .codex-plugin/plugin.json            Codex manifest; hooks in hooks/codex-hooks.json
  hooks/hooks.json                     Claude Code hooks
  hooks/codex-hooks.json               Codex hooks
  scripts/agent-hook.sh                POSIX sh hook (macOS, Linux, BSD, Git Bash)
  scripts/agent-hook.ps1               PowerShell hook (Windows)
```

When releasing, bump `version` in both `plugin.json` files; installed copies update only when it changes.

## License

[MIT](LICENSE)
