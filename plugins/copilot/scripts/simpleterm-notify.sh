#!/bin/sh
# simpleterm: the SimpleTerm helper command (simpleterm-agent-hooks plugin).
#
#   simpleterm notify "title" ["body"]   alert this terminal (in a SimpleTerm
#                                         session) and every linked device
#   simpleterm statusline [command]      Claude Code status line tap (README)
#
# ~/.simpleterm/bin/simpleterm runs this script; the plugin's hooks write that
# file and keep it pointing at the installed plugin. Always exits 0 once the
# arguments are valid: a script's last line should not fail because of it.

[ -n "${ZSH_VERSION:-}" ] && emulate sh
here=${0%/*}
[ "$here" = "$0" ] && here=.

usage() {
  cat <<'EOF'
usage: simpleterm notify "title" ["body"]
       simpleterm statusline ['your status line command']

notify      Shows a notification in SimpleTerm: on this terminal when it is a
            SimpleTerm session, and through each linked device (the SSH tunnel
            or the push relay set up by the app). Example:
              make test; simpleterm notify "Tests finished" "exit $?"
statusline  For Claude Code's statusLine setting: saves its input for the
            SimpleTerm hooks (rate limits), then runs your own command with
            the same input. See the plugin README.
EOF
}

case ${1:-} in
  notify)
    shift
    if [ $# -lt 1 ] || [ $# -gt 2 ] || [ -z "${1:-}${2:-}" ]; then
      usage >&2
      exit 2
    fi
    exec sh "$here/agent-hook.sh" notify "$1" "${2:-}"
    ;;
  statusline)
    shift
    exec sh "$here/statusline-tap.sh" "$@"
    ;;
  -h | --help | help)
    usage
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
