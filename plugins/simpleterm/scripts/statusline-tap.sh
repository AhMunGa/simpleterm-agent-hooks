#!/bin/sh
# Claude Code status line tap for the SimpleTerm agent hooks (optional; only
# you can register it, the plugin and the app never change your settings):
#
#   "statusLine": {"type": "command",
#     "command": "~/.simpleterm/bin/simpleterm statusline '<your command>'"}
#
# Claude Code gives the 5-hour and 7-day rate limits only to the status line,
# not to hooks. This saves the status line input (session id, model, context
# window, rate limits, cost; no conversation text) to
# ~/.simpleterm/run/usage.<session>.json for the hooks, then runs your own
# status line command with the same input and prints what it prints. Without
# a command it prints a short line of its own (model, context, limits), so
# the status line is not left blank. Nothing is saved when ~/.simpleterm is
# absent.

[ -n "${ZSH_VERSION:-}" ] && emulate sh
umask 077

in=$(head -c 262144 2>/dev/null)
d=${HOME:-}/.simpleterm
if [ -n "${HOME:-}" ] && [ -d "$d" ]; then
  sid=$(printf '%s' "$in" | tr -d '\r\n' |
    sed -n 's/.*"session_id" *: *"\([A-Za-z0-9_-]\{1,80\}\)".*/\1/p' | head -n 1)
  if [ -n "$sid" ] && mkdir -p "$d/run" 2>/dev/null; then
    f=$d/run/usage.$sid.json
    { date +%s; printf '%s\n' "$in"; } >"$f.$$" 2>/dev/null && mv -f "$f.$$" "$f" 2>/dev/null
    rm -f "$f.$$" 2>/dev/null
  fi
fi

if [ $# -eq 0 ]; then
  flat=$(printf '%s' "$in" | tr -d '\r\n')
  pick() { # sed expression
    printf '%s' "$flat" | sed -n "$1" | head -n 1
  }
  model=$(pick 's/.*"model" *: *{[^}]*"display_name" *: *"\([^"]*\)".*/\1/p')
  ctx=$(pick 's/.*"context_window" *: *{[^}]*"used_percentage" *: *\([0-9][0-9.]*\).*/\1/p')
  h5=$(pick 's/.*"five_hour" *: *{ *"used_percentage" *: *\([0-9][0-9.]*\).*/\1/p')
  d7=$(pick 's/.*"seven_day" *: *{ *"used_percentage" *: *\([0-9][0-9.]*\).*/\1/p')
  line=$model
  [ -n "$ctx" ] && line="${line:+$line · }context ${ctx%%.*}%"
  [ -n "$h5" ] && line="${line:+$line · }5h ${h5%%.*}%"
  [ -n "$d7" ] && line="${line:+$line · }7d ${d7%%.*}%"
  [ -n "$line" ] && printf '%s\n' "$line"
  exit 0
fi
if [ $# -eq 1 ]; then
  printf '%s' "$in" | sh -c "$1"
else
  printf '%s' "$in" | "$@"
fi
