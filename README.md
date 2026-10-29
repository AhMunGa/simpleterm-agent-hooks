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
| Claude `PreToolUse` `AskUserQuestion`, `Notification` (idle, elicitation, input needed) | `question` | waiting (idle keeps done) |
| Claude `UserPromptSubmit`, `PostToolUse`, `PostToolUseFailure` | none (context, see below) | running |
| Claude `Stop` / `StopFailure` | `done` / `error` or `auth` | done |
| Claude `SessionStart`, `PostCompact`, `PostModelSwitch` | none (context) | none |
| Codex `PermissionRequest` | `permission` (waits up to 60 s) | none |
| Codex `Stop` | `done` | none |
| Codex `SessionStart`, `PostCompact` | none (context) | none |
| Gemini `Notification` (`ToolPermission`) | `question` (`approve <tool>: <command or file>`) | none |
| Gemini `AfterAgent` | `done` | none |
| agy `PreToolUse` `run_command` (only with `agy_wait`) | `permission` | none |
| agy `PreToolUse` `ask_question`, `ask_permission` | `question` | none |
| agy `Stop` (fully idle) | `done`, or `error` | none |
| Grok `Notification` `permission_prompt`, `idle_prompt` | `question` | none |
| Grok `Stop` (`end_turn`) / `StopFailure` | `done` / `error` or `auth` | none |
| OpenCode permission request | `permission` (waits up to 540 s) | none |
| OpenCode turn finished / failed | `done` / `error` or `auth` | none |
| OpenCode 2.x input form | `question` | none |
| `simpleterm notify` | `notify` | OSC 777 notification instead |

Codex runs a `PermissionRequest` hook before it shows its own approval prompt, so while the hook
waits the terminal shows only `Waiting for approval in SimpleTerm`. The wait is 60 seconds by
default and is skipped when no device was notified. Codex runs hooks through your login shell
(`$SHELL -lc`); a login profile that prints to standard output breaks the approval answer.

## `simpleterm notify`

```sh
make test; simpleterm notify "Tests finished" "exit $?"
```

In a SimpleTerm session it shows an OSC 777 notification on the terminal (inside tmux only with
`set -g allow-passthrough on`), and it sends a `notify` event to every linked device (the SSH
tunnel and the relay), so it also reaches you when the app is in the background. The title is cut
at 256 bytes and the body at 800. It returns at once and exits 0.

The hooks keep the command at `~/.simpleterm/bin/simpleterm` (a small script that runs the
installed plugin's `scripts/simpleterm-notify.sh`, rewritten when the plugin moves). Add the folder
to your `PATH`, for example in `~/.profile` or `~/.zshrc`:

```sh
export PATH="$HOME/.simpleterm/bin:$PATH"
```

On Windows the Codex hook keeps `~/.simpleterm/bin/simpleterm.cmd` for `simpleterm notify` in
cmd and PowerShell.

## Context and rate limits

The hooks report how much of the context window is used and, where the agent gives it, the
rate limits. Only changes are sent. The SSH tunnel gets every change; the relay only the last one
of a turn.

| Agent | Context | Window | Limits | From |
|---|---|---|---|---|
| Claude Code | last response's input + cache tokens, or the compaction's result | `CLAUDE_CODE_MAX_CONTEXT_TOKENS`, `CLAUDE_CODE_DISABLE_1M_CONTEXT`, else guessed from the model (marked `est`) | 5-hour and 7-day, only with the status line tap below; `reached` when a turn fails on a rate limit | the session transcript (only its last 2 MiB, only the `usage` keys) |
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
command with the same input and prints what it prints (with no command it prints nothing). The
hooks use that file while it is fresh (10 minutes) for the exact window size and the limits.

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
`plugins/opencode/package.json`); installed copies update only when it changes.

## License

[MIT](LICENSE)
