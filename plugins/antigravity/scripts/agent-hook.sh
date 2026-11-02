#!/bin/sh
# SimpleTerm agent hook v1 (POSIX sh), part of the simpleterm-agent-hooks
# plugin; see README.md and docs/tech_specs/TDS_AGENT_ALERTS.md (sections 5
# and 6) of the SimpleTerm app for the contract.
#
#   sh agent-hook.sh claude          Claude Code hook (event JSON on stdin). Run
#                                    by Grok Build (GROK_HOOK_EVENT set) it acts
#                                    as `grok`.
#   sh agent-hook.sh claude signal   Claude Code PermissionRequest status only
#   sh agent-hook.sh codex           Codex hook (event JSON on stdin)
#   sh agent-hook.sh codex-notify J  Codex `notify` program (JSON is last arg)
#   sh agent-hook.sh gemini          Gemini CLI hook (event JSON on stdin)
#   sh agent-hook.sh agy EVENT       Antigravity CLI hook (event JSON on stdin;
#                                    the event is not in it)
#   sh agent-hook.sh grok            Grok Build hook (event JSON on stdin)
#   sh agent-hook.sh opencode        OpenCode, from the plugin's bridge
#                                    (Claude-shaped event JSON on stdin)
#   sh agent-hook.sh notify T [B]    `simpleterm notify` (simpleterm-notify.sh)
#
# Turns agent events into end-to-end encrypted relay events and, for
# permission requests, waits for a decision made on a SimpleTerm device.
# Needs curl and openssl; without them it does nothing. It never evaluates
# its input, prints only agent-defined JSON on stdout, and always exits 0.
# Anything that goes wrong leaves the agent's own terminal prompt in charge.

[ -n "${ZSH_VERSION:-}" ] && emulate sh
umask 077
LC_ALL=C
export LC_ALL

AGENT=${1:-}
MODE=${2:-}
[ -n "${HOME:-}" ] || exit 0
ST_DIR=$HOME/.simpleterm
LINKS_DIR=$ST_DIR/links
RUN_DIR=$ST_DIR/run
LOG=$ST_DIR/agent-hook.log
LOGGED=0

MAX_INPUT=262144
MAX_LINKS=16
# The plugin release of this script (the manifests carry the same).
HOOK_VERSION=0.3.1
# Bumped when the ~/.simpleterm/bin/simpleterm wrapper must be rewritten.
CLI_REV=2
CR=$(printf '\r')

log() {
  [ -d "$ST_DIR" ] || return 0
  printf '%s %s %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null)" \
    "${AGENT:-?}" "$*" >>"$LOG" 2>/dev/null
  LOGGED=1
}

trim_log() {
  [ "$LOGGED" = 1 ] || return 0
  n=$(awk 'END { print NR }' "$LOG" 2>/dev/null) || return 0
  [ "${n:-0}" -gt 200 ] 2>/dev/null || return 0
  tail -n 200 "$LOG" >"$LOG.$$" 2>/dev/null && mv -f "$LOG.$$" "$LOG" 2>/dev/null
  rm -f "$LOG.$$" 2>/dev/null
}

finish() {
  agy_default
  trim_log
  exit 0
}

# What Antigravity does with `{}`, no output or a crash from PreToolUse is
# not documented and not measured yet (1.0.16 only says an empty decision is
# handled safely). So every PreToolUse run ends with an explicit decision,
# `allow` (the permission policy decides) unless the device answered. Stop
# gets `{}` (the stop proceeds).
ANSWERED=0
agy_default() {
  [ "$AGENT" = agy ] && [ "$ANSWERED" = 0 ] || return 0
  ANSWERED=1
  if [ "$MODE" = PreToolUse ]; then printf '{"decision":"allow"}\n'; else printf '{}\n'; fi
}

# --- JSON helpers (awk, byte semantics) ------------------------------------

# jwalk(s) records `GOT[path] = value` for each wanted path (jwant("a,b.c"))
# found in the JSON text s, in document order in GOTK[1..GOTN]. String values
# stay JSON-escaped (they are re-embedded as-is, never decoded or
# evaluated). Paths: `a`, `a.b`, `a.0.b`. Tolerates truncation.
JSON_FN='
function jpath(   d, p) {
  p = ""
  for (d = 1; d <= JD; d++) p = p (d > 1 ? "." : "") JK[d]
  return p
}
function jemit(v,   p) {
  if (JD == 0) return
  p = jpath()
  if ((p in WANT) && !(p in GOT)) { GOT[p] = v; GOTN++; GOTK[GOTN] = p; jneed-- }
}
function jwant(list,   W, k) {
  split("", WANT)
  WANTN = split(list, W, ",")
  for (k = 1; k <= WANTN; k++) WANT[W[k]] = 1
}
function jwalk(s,   len, i, c, j, seg, m, str) {
  split("", GOT); GOTN = 0; jneed = WANTN
  len = length(s); i = 1; JD = 0
  while (i <= len && jneed > 0) {
    c = substr(s, i, 1)
    if (c == " " || c == "\t" || c == "\n" || c == "\r") { i++; continue }
    if (c == ",") {
      if (JD > 0) { if (JT[JD] == "a") JK[JD]++; else JE[JD] = 1 }
      i++; continue
    }
    if (c == ":") { if (JD > 0) JE[JD] = 0; i++; continue }
    if (c == "{" || c == "[") {
      JD++
      if (c == "{") { JT[JD] = "o"; JK[JD] = ""; JE[JD] = 1 }
      else { JT[JD] = "a"; JK[JD] = 0; JE[JD] = 0 }
      i++; continue
    }
    if (c == "}" || c == "]") { if (JD > 0) JD--; i++; continue }
    if (c == "\"") {
      j = i + 1
      while (j <= len) {
        seg = substr(s, j, 512)
        m = match(seg, /["\\]/)
        if (m == 0) { j += length(seg); continue }
        j += m - 1
        if (substr(s, j, 1) == "\\") { j += 2; continue }
        break
      }
      if (j > len) break
      str = substr(s, i + 1, j - i - 1)
      i = j + 1
      if (JD > 0 && JT[JD] == "o" && JE[JD]) { JK[JD] = str; continue }
      jemit(str); continue
    }
    j = i
    while (j <= len && index(" \t\r\n,:}]", substr(s, j, 1)) == 0) j++
    jemit(substr(s, i, j - i))
    i = j
  }
}
function isnum(v) { return v ~ /^[0-9]+$/ }
function isdec(v) { return v ~ /^[0-9]+([.][0-9]+)?$/ }'

# Prints `path=value` for each wanted path (comma list) found in the JSON on
# stdin, in document order.
JSON_GET=$JSON_FN'
BEGIN { jwant(want) }
{ s = s $0 "\n" }
END { jwalk(s); for (k = 1; k <= GOTN; k++) print GOTK[k] "=" GOT[GOTK[k]] }'

# Truncates JSON-escaped string content (one value per line on stdin) to at
# most `maxu` characters and `maxb` bytes without splitting an escape or a
# UTF-8 sequence; control characters become spaces. mode=base keeps only the
# last path component (for cwd).
JSON_TRIM='
function hexv(h,   k, v, c) {
  v = 0; h = tolower(h)
  if (length(h) != 4) return -1
  for (k = 1; k <= 4; k++) {
    c = index("0123456789abcdef", substr(h, k, 1))
    if (c == 0) return -1
    v = v * 16 + c - 1
  }
  return v
}
{
  s = $0
  if (mode == "base") {
    while (length(s) > 0 && (substr(s, length(s), 1) == "/" || substr(s, length(s) - 1) == "\\\\")) {
      if (substr(s, length(s), 1) == "/") s = substr(s, 1, length(s) - 1)
      else s = substr(s, 1, length(s) - 2)
    }
    p = 0
    for (k = 1; k <= length(s); k++) {
      if (substr(s, k, 1) == "/") p = k
      else if (substr(s, k, 2) == "\\\\") { p = k + 1; k++ }
      else if (substr(s, k, 1) == "\\") k++
    }
    s = substr(s, p + 1)
  }
  n = length(s); i = 1; out = ""; u = 0; b = 0
  while (i <= n && u < maxu) {
    c = substr(s, i, 1); step = 1; unit = c
    if (c == "\\") {
      e = substr(s, i + 1, 1); step = 2
      if (e == "u") {
        v = hexv(substr(s, i + 2, 4))
        if (v < 0) break
        unit = substr(s, i, 6); step = 6
        if (v >= 55296 && v <= 56319) {
          v2 = -1
          if (substr(s, i + 6, 2) == "\\u") v2 = hexv(substr(s, i + 8, 4))
          if (v2 >= 56320 && v2 <= 57343) { unit = substr(s, i, 12); step = 12 }
          else unit = " "
        } else if (v >= 56320 && v <= 57343) unit = " "
        else if (v < 32 || (v >= 127 && v <= 159) || v == 8232 || v == 8233) unit = " "
      } else if (e == "\"" || e == "\\" || e == "/") unit = c e
      else if (e == "") break
      else unit = " "
    } else if (c >= "\300") {
      w = 0
      if (c < "\340") w = 2; else if (c < "\360") w = 3; else if (c < "\370") w = 4
      ok = (w > 0)
      for (j = 1; ok && j < w; j++) {
        x = substr(s, i + j, 1)
        if (x < "\200" || x >= "\300") ok = 0
      }
      if (ok) {
        unit = substr(s, i, w); step = w
        if (c == "\302" && substr(unit, 2, 1) < "\240") unit = " "
      } else unit = " "
    } else if (c < " " || c >= "\177") unit = " "
    if (b + length(unit) > maxb) break
    out = out unit; b += length(unit); u++; i += step
  }
  print out
}'

json_trim() { # value maxu maxb [mode]
  printf '%s\n' "$1" | awk -v maxu="$2" -v maxb="$3" -v mode="${4:-}" "$JSON_TRIM" 2>/dev/null
}

# Escapes plain text (our own config files, command-line arguments) as JSON
# string content.
json_text() { # text maxu maxb [mode]
  t=$(printf '%s' "$1" | tr -d '\000-\037\177' | sed 's/\\/\\\\/g; s/"/\\"/g')
  json_trim "$t" "$2" "$3" "${4:-}"
}

# Text of a `simpleterm notify` notification. The terminal (OSC 777) and the
# `notify` event get the same text, so the app can tell two copies of one
# notification from two notifications: whitespace runs, line breaks included
# (TAB LF VT FF CR, NEL, U+2028, U+2029), become one space; other control
# characters (C0, DEL, C1) and invalid UTF-8 are removed; `;`, the OSC 777
# field separator, becomes `,`; leading and trailing spaces go; then it is
# cut to $2 characters and $3 bytes, between characters and not after a
# space.
NOTIFY_TEXT='
function feed(s,   n, i, c, w, j, x, lo, hi, ok, unit) {
  n = length(s); i = 1
  while (i <= n) {
    c = substr(s, i, 1); w = 1
    if (c >= "\302" && c <= "\364") {
      w = c < "\340" ? 2 : (c < "\360" ? 3 : 4)
      lo = "\200"; hi = "\277"
      if (c == "\340") lo = "\240"; else if (c == "\355") hi = "\237"
      else if (c == "\360") lo = "\220"; else if (c == "\364") hi = "\217"
      x = substr(s, i + 1, 1); ok = (x >= lo && x <= hi)
      for (j = 2; ok && j < w; j++) { x = substr(s, i + j, 1); if (x < "\200" || x > "\277") ok = 0 }
      if (!ok) { i++; continue }
      unit = substr(s, i, w)
      if (unit == "\302\205" || unit == "\342\200\250" || unit == "\342\200\251") unit = " "
      else if (c == "\302" && substr(unit, 2, 1) < "\240") unit = ""
    } else if (c >= "\200") { i++; continue }
    else if (c == " " || (c >= "\011" && c <= "\015")) unit = " "
    else if (c < " " || c == "\177") unit = ""
    else if (c == ";") unit = ","
    else unit = c
    i += w
    if (unit == "") continue
    if (unit == " ") { if (u > 0) sp = 1; continue }
    if (u + sp + 1 > maxu || b + sp + length(unit) > maxb) return 1
    if (sp) { out = out " "; u++; b++; sp = 0 }
    out = out unit; u++; b += length(unit)
  }
  return 0
}
NR > 1 && u > 0 { sp = 1 }
{ if (feed($0)) exit }
END { printf "%s", out }'

notify_text() { # text maxu maxb
  printf '%s' "$1" | head -c 65536 | awk -v maxu="$2" -v maxb="$3" "$NOTIFY_TEXT" 2>/dev/null
}

is_hex() { # value length
  [ "${#1}" -eq "$2" ] || return 1
  case $1 in *[!0-9a-f]*) return 1 ;; esac
  return 0
}

is_uint() {
  case $1 in '' | *[!0-9]*) return 1 ;; esac
  [ "${#1}" -le 12 ]
}

# --- crypto (openssl) --------------------------------------------------------

rand_hex() { # bytes
  openssl rand -hex "$1" 2>/dev/null
}

sha256_hex() {
  printf '%s' "$1" | openssl dgst -sha256 2>/dev/null | awk '{ print $NF }'
}

# printf format string with the 64-byte HMAC block (key ^ pad) as octal
# escapes, so the key never appears on a command line.
pad_fmt() { # key-hex(32 bytes) pad
  k="${1}0000000000000000000000000000000000000000000000000000000000000000"
  out='' i=0
  while [ "$i" -lt 64 ]; do
    hh=${k%"${k#??}"}
    k=${k#??}
    x=$((0x$hh ^ $2))
    out="$out\\$((x >> 6 & 7))$((x >> 3 & 7))$((x & 7))"
    i=$((i + 1))
  done
  printf '%s' "$out"
}

hmac_hex() { # key-hex message
  ip=$(pad_fmt "$1" 54)
  op=$(pad_fmt "$1" 92)
  # shellcheck disable=SC2059 # the format strings are our own octal escapes
  { printf "$op"; { printf "$ip"; printf '%s' "$2"; } | openssl dgst -sha256 -binary; } |
    openssl dgst -sha256 2>/dev/null | awk '{ print $NF }'
}

# Sets ENV_JSON to the section 5.2 envelope of $1 (plaintext) for the loaded link.
seal() {
  ENV_JSON=''
  iv=$(rand_hex 16)
  [ "${SIMPLETERM_HOOK_TEST:-}" = 1 ] && [ -n "${SIMPLETERM_HOOK_TEST_IV:-}" ] && iv=$SIMPLETERM_HOOK_TEST_IV
  is_hex "$iv" 32 || return 1
  # The AES key is on openssl's command line for a few milliseconds; openssl
  # enc has no other way to take a raw key (README "Security notes").
  ct=$(printf '%s' "$1" | openssl enc -aes-256-cbc -K "$L_ENC" -iv "$iv" -a -A 2>/dev/null) || return 1
  [ -n "$ct" ] || return 1
  mac=$(hmac_hex "$L_MAC" "st1.$iv.$ct")
  is_hex "$mac" 64 || return 1
  ENV_JSON='{"v":1,"iv":"'$iv'","ct":"'$ct'","mac":"'$mac'"}'
}

# --- links ---------------------------------------------------------------

# Loads one link file into L_*; returns 1 if it is unusable.
load_link() { # file
  L_FILE=$1 L_RELAY='' L_LINK='' L_SECRET='' L_ENC='' L_MAC='' L_LABEL='' L_V='' L_KIND=''
  [ -f "$1" ] || return 1
  size=$(wc -c <"$1" 2>/dev/null) || return 1
  [ "${size:-99999}" -le 4096 ] 2>/dev/null || { log "link-skip too-large"; return 1; }
  while IFS= read -r line || [ -n "$line" ]; do
    [ "${#line}" -le 512 ] || continue
    line=${line%"$CR"}
    case $line in
      v=*) L_V=${line#v=} ;;
      relay=*) L_RELAY=${line#relay=} ;;
      link=*) L_LINK=${line#link=} ;;
      secret=*) L_SECRET=${line#secret=} ;;
      enc=*) L_ENC=${line#enc=} ;;
      mac=*) L_MAC=${line#mac=} ;;
      label=*) L_LABEL=${line#label=} ;;
      kind=*) L_KIND=${line#kind=} ;;
    esac
  done <"$1"
  [ "$L_V" = 1 ] || { log "link-skip version"; return 1; }
  # kind=tunnel: the app's end of its SSH connection, forwarded to a loopback
  # port for as long as that connection lives (TDS section 6.5).
  [ "$L_KIND" = tunnel ] || L_KIND=''
  is_hex "$L_LINK" 32 && is_hex "$L_SECRET" 64 && is_hex "$L_ENC" 64 && is_hex "$L_MAC" 64 ||
    { log "link-skip fields"; return 1; }
  L_RELAY=${L_RELAY%/}
  case $L_RELAY in
    *[!A-Za-z0-9.:/_~%-]* | '') log "link-skip relay"; return 1 ;;
    https://?*) L_PROTO='=https' ;;
    http://127.0.0.1:* | http://127.0.0.1/* | http://127.0.0.1 | \
      http://localhost:* | http://localhost/* | http://localhost) L_PROTO='=http' ;;
    *) log "link-skip relay"; return 1 ;;
  esac
  [ -e "$RUN_DIR/$L_LINK.revoked" ] && return 1
  return 0
}

# Prints usable link files, one per line (file names are hex link IDs).
list_links() {
  [ -d "$LINKS_DIR" ] || return 0
  count=0
  for f in "$LINKS_DIR"/*.conf; do
    [ -f "$f" ] || continue
    base=${f##*/}
    is_hex "${base%.conf}" 32 || continue
    count=$((count + 1))
    [ "$count" -le "$MAX_LINKS" ] || break
    printf '%s\n' "$f"
  done
}

# --- HTTP (curl) -----------------------------------------------------------

# Prints the HTTP status (000 on failure); the response goes to $5. Nothing
# secret reaches curl's argv: the bearer token comes through stdin and the
# request body (the envelope; with the `openssl enc -K` exposure below it
# would be readable) through $5.req, a 600 file in the 700 run directory.
http() { # method path body max-time outfile
  rm -f "$5"
  if [ "$1" = POST ]; then
    rm -f "$5.req"
    printf '%s' "$3" >"$5.req" 2>/dev/null || { rm -f "$5.req"; printf 000; return 0; }
    code=$(printf 'header = "Authorization: Bearer %s.%s"\n' "$L_LINK" "$L_SECRET" |
      curl -s -K - --proto "$L_PROTO" --max-redirs 0 --connect-timeout 5 \
        --max-time "$4" -A simpleterm-hook/1 -H 'Content-Type: application/json' \
        --data-binary "@$5.req" -o "$5" -w '%{http_code}' "$L_RELAY$2" 2>/dev/null)
    rm -f "$5.req"
  else
    code=$(printf 'header = "Authorization: Bearer %s.%s"\n' "$L_LINK" "$L_SECRET" |
      curl -s -K - --proto "$L_PROTO" --max-redirs 0 --connect-timeout 5 \
        --max-time "$4" -A simpleterm-hook/1 -o "$5" -w '%{http_code}' "$L_RELAY$2" 2>/dev/null)
  fi
  case $code in [0-9][0-9][0-9]) ;; *) code=000 ;; esac
  printf '%s' "$code"
}

resp_get() { # file wanted-paths
  [ -f "$1" ] || return 0
  head -c 4096 "$1" 2>/dev/null | awk -v want="$2" "$JSON_GET" 2>/dev/null
}

# --- event payload ---------------------------------------------------------

# Builds the section 5.2 plaintext for the loaded link. `usage` carries
# USAGE_JSON instead of a message; `notify` adds a title.
plaintext() { # rid ev nonce
  host=$(json_text "$L_LABEL" 64 256)
  p='{"v":1,"rid":"'$1'","ev":"'$2'","app":"'$APP'","host":"'$host'","cwd":"'$CWD_BASE'"'
  case $2 in
    usage) p=$p$USAGE_JSON ;;
    notify) p=$p',"title":"'$TITLE'","msg":"'$MSG'"' ;;
    *) p=$p',"msg":"'$MSG'"' ;;
  esac
  # A `done` of a Stop that another Stop hook had already kept going.
  [ "$2" = done ] && [ -n "${XFLAGS:-}" ] && p=$p$XFLAGS
  [ -n "$3" ] && p=$p',"nonce":"'$3'"'
  printf '%s,"ts":%s}' "$p" "$TS"
}

# Sends one event to one link; prints the push result or an error code.
ingest_one() { # rid ev nonce outfile
  nh=''
  [ -n "$3" ] && nh=$(sha256_hex "$3")
  seal "$(plaintext "$1" "$2" "$3")" || { log "seal-failed link=$(printf %.8s "$L_LINK")"; return 1; }
  body='{"v":1,"rid":"'$1'","ev":"'$2'"'
  [ -n "$nh" ] && body=$body',"nh":"'$nh'"'
  body=$body',"env":'$ENV_JSON'}'
  # A tunnel answers at once or not at all (a dead port may belong to
  # something else by now); the relay may hold the request a few seconds.
  mt=20
  [ "$L_KIND" = tunnel ] && mt=5
  code=$(http POST /v1/ingest "$body" "$mt" "$4")
  push=''
  case $code in
    200)
      push=$(resp_get "$4" push | sed -n 's/^push=//p')
      ;;
    410) printf '' 2>/dev/null >"$RUN_DIR/$L_LINK.revoked" ;;
  esac
  rm -f "$4"
  log "ingest ev=$2 link=$(printf %.8s "$L_LINK") http=$code push=${push:--}"
  printf '%s' "${push:-http$code}"
  [ "$code" = 200 ]
}

# Sends event $1 to every link in the background and returns at once.
# Tunnels go first: the app reports a shown event to the relay ("seen"),
# which holds a push for a few seconds to hear that, so a device that is
# connected gets no second alert. $3 limits it to `tunnel` or `relay` links;
# once a link took the event, text $5 is written to file $4.
send_bg() { # ev [rid] [all|tunnel|relay] [file text]
  [ -n "$LINKS" ] || return 0
  sb_rid=${2:-$RID}
  sb_scope=${3:-all}
  sb_file=${4:-} sb_text=${5:-}
  [ -n "$sb_rid" ] || return 0
  # Ignored before the fork, so the sender also outlives a terminal that
  # closes right after `simpleterm notify` (its children get SIGHUP).
  trap '' HUP
  (
    for pass in tunnel relay; do
      [ "$sb_scope" = all ] || [ "$sb_scope" = "$pass" ] || continue
      printf '%s\n' "$LINKS" | while IFS= read -r f; do
        load_link "$f" || continue
        if [ "$L_KIND" = tunnel ]; then [ "$pass" = tunnel ] || continue; else [ "$pass" = relay ] || continue; fi
        ingest_one "$sb_rid" "$1" '' "$RUN_DIR/ing.$$.$sb_rid.$(printf %.8s "$L_LINK")" >/dev/null &&
          [ -n "$sb_file" ] && printf '%s\n' "$sb_text" >"$sb_file" 2>/dev/null
      done
    done
    trim_log
  ) </dev/null >/dev/null 2>&1 &
}

# --- terminal sequence (Claude Code only, SimpleTerm sessions only) ---------

# USAGE_SEQ is the JSON-escaped usage OSC to append, if any (usage_report);
# BG_SEQ the hook's OSC 7501 record for background work (bg_pause, note).
print_state() { # running|waiting|done|background [message]
  [ "$AGENT" = claude ] || return 0
  [ "${SIMPLETERM:-}" = 1 ] || return 0
  m=''
  [ -n "${2:-}" ] && m=' '$(json_trim "$2" 80 320)
  printf '{"terminalSequence":"\\u001b]9;simpleterm:state=%s%s\\u0007%s%s"}\n' "$1" "$m" "$BG_SEQ" "$USAGE_SEQ"
}

print_usage() {
  [ "$AGENT" = claude ] && [ "${SIMPLETERM:-}" = 1 ] && [ -n "$USAGE_SEQ" ] || return 0
  printf '{"terminalSequence":"%s"}\n' "$USAGE_SEQ"
}

state_json() { # running|waiting|done -> ,"terminalSequence":... or nothing
  [ "$AGENT" = claude ] && [ "${SIMPLETERM:-}" = 1 ] || return 0
  printf ',"terminalSequence":"\\u001b]9;simpleterm:state=%s\\u0007"' "$1"
}

# --- permission flow -------------------------------------------------------

conf_int() { # key default
  v=''
  if [ -f "$ST_DIR/agent-hook.conf" ]; then
    v=$(head -c 4096 "$ST_DIR/agent-hook.conf" 2>/dev/null | sed -n "s/^$1=\\([0-9]*\\)\$/\\1/p" | head -n 1)
  fi
  is_uint "$v" || v=$2
  printf '%s' "$v"
}

# Long-polls one link for the decision on $1 and writes allow/deny/invalid.
poll_link() { # rid nonce outfile deadline
  cpid='' r=none
  trap 'kill "$cpid" 2>/dev/null; exit 0' TERM
  resp="$RUN_DIR/dec.$$.$1.$(printf %.8s "$L_LINK")"
  while :; do
    now=$(date +%s)
    [ "$now" -lt "$4" ] || break
    w=$((POLL_WAIT))
    [ "$w" -gt $(($4 - now)) ] && w=$(($4 - now))
    [ "$w" -ge 1 ] || w=1
    printf 'header = "Authorization: Bearer %s.%s"\n' "$L_LINK" "$L_SECRET" |
      curl -s -K - --proto "$L_PROTO" --max-redirs 0 --connect-timeout 5 \
        --max-time $((w + 10)) -A simpleterm-hook/1 -o "$resp" -w '%{http_code}' \
        "$L_RELAY/v1/decision?rid=$1&wait=$w" >"$resp.code" 2>/dev/null &
    cpid=$!
    wait "$cpid"
    cpid=''
    code=$(cat "$resp.code" 2>/dev/null)
    case $code in
      200)
        st='' dec='' dmac=''
        while IFS= read -r kv; do
          case $kv in
            status=*) st=${kv#status=} ;;
            decision=*) dec=${kv#decision=} ;;
            dmac=*) dmac=${kv#dmac=} ;;
          esac
        done <<EOF
$(resp_get "$resp" status,decision,dmac)
EOF
        if [ "$st" = decided ]; then
          r=invalid
          case $dec in
            allow | deny)
              is_hex "$dmac" 64 &&
                [ "$(hmac_hex "$L_MAC" "st1-dec.$1.$dec.$2")" = "$dmac" ] && r=$dec
              ;;
          esac
          log "decision link=$(printf %.8s "$L_LINK") result=$r"
          break
        fi
        [ $(($(date +%s) - now)) -ge 1 ] || sleep 1
        ;;
      404 | 410 | 401 | 403)
        log "decision link=$(printf %.8s "$L_LINK") http=$code"
        [ "$code" = 410 ] && [ "$(resp_get "$resp" error)" = 'error=revoked' ] &&
          printf '' 2>/dev/null >"$RUN_DIR/$L_LINK.revoked"
        break
        ;;
      000)
        # The app's connection ended (or the port is gone): nothing will
        # answer there, so stop instead of waiting out the deadline.
        if [ "$L_KIND" = tunnel ]; then
          log "decision link=$(printf %.8s "$L_LINK") tunnel-gone"
          break
        fi
        sleep 2
        ;;
      *) sleep 2 ;;
    esac
  done
  rm -f "$resp" "$resp.code"
  printf '%s\n' "$r" >"$3.tmp" && mv -f "$3.tmp" "$3"
}

# Prints the agent's PID: the nearest ancestor that is not a shell (hooks
# run under `sh -c`, Codex under `$SHELL -c` or `-lc`). Empty if ps is
# unavailable.
agent_pid() {
  ap=$PPID n=0
  while [ "$n" -lt 4 ] && is_uint "$ap" && [ "$ap" -gt 1 ]; do
    comm=$(ps -o comm= -p "$ap" 2>/dev/null) || { ap=''; break; }
    case ${comm##*/} in
      sh | -sh | bash | -bash | dash | zsh | -zsh | ksh | mksh | ash | fish | -fish | busybox) ;;
      *) break ;;
    esac
    ap=$(ps -o ppid= -p "$ap" 2>/dev/null | tr -d ' ')
    n=$((n + 1))
  done
  is_uint "$ap" && [ "$ap" -gt 1 ] && printf '%s' "$ap"
}

# True if the agent moved on from request $1 (answered at the terminal).
# Notes already in the file when the wait began (RES_BASE) do not count: the
# prompt that started this turn, or an earlier identical tool call, can carry
# the same second as the request.
answered_locally() { # since fingerprint
  [ -f "$RUN_DIR/$SID.res" ] || return 1
  res=$(cat "$RUN_DIR/$SID.res" 2>/dev/null)
  case $res in "$RES_BASE"*) res=${res#"$RES_BASE"} ;; esac
  while IFS=' ' read -r t kind fp; do
    is_uint "$t" || continue
    [ "$t" -ge "$1" ] || continue
    [ "$kind" = turn ] && return 0
    [ "$kind" = tool ] && [ "$fp" = "$2" ] && return 0
  done <<EOF
$res
EOF
  return 1
}

# Prints a device decision (allow|deny) or the no-decision answer (none) in
# the agent's own format.
emit_decision() {
  case $AGENT:$1 in
    claude:allow | codex:allow)
      printf '{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"allow"}}%s}\n' \
        "$(state_json running)"
      ;;
    claude:deny | codex:deny)
      printf '{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"deny","message":"Denied from SimpleTerm"}}%s}\n' \
        "$(state_json running)"
      ;;
    # Antigravity: auto_approve approves a call that would ask; allow leaves
    # it to the permission policy (the terminal prompt).
    agy:allow) ANSWERED=1; printf '{"decision":"auto_approve"}\n' ;;
    agy:deny) ANSWERED=1; printf '{"decision":"deny","reason":"Denied from SimpleTerm"}\n' ;;
    agy:none) agy_default ;;
    # OpenCode: the plugin's bridge replies once/reject.
    opencode:allow) printf '{"decision":"allow"}\n' ;;
    opencode:deny) printf '{"decision":"deny"}\n' ;;
  esac
}

permission_flow() {
  case $AGENT in
    codex) cap=$(conf_int codex_wait 60) ;;
    agy) cap=$(conf_int agy_wait 0) ;;
    opencode) cap=$(conf_int opencode_wait 540) ;;
    *) cap=$(conf_int claude_wait 540) ;;
  esac
  [ "$cap" -le 540 ] || cap=540
  # The Antigravity hook's timeout is 120 seconds (hooks.json).
  [ "$AGENT" = agy ] && [ "$cap" -gt 110 ] && cap=110
  POLL_WAIT=$(conf_int poll_wait 25)
  [ "$POLL_WAIT" -ge 1 ] && [ "$POLL_WAIT" -le 25 ] || POLL_WAIT=25
  start=$(date +%s)
  RES_BASE=$(cat "$RUN_DIR/$SID.res" 2>/dev/null)
  deadline=$((start + cap))
  PIDS='' JOBS='' POLLERS=0
  AGENT_PID=$(agent_pid)

  cleanup_perm() {
    for p in $PIDS; do kill "$p" 2>/dev/null; done
    rm -f "$RUN_DIR"/ing."$$".* "$RUN_DIR"/out."$$".* "$RUN_DIR"/dec."$$".* 2>/dev/null
  }
  # The agent may end the wait (Claude Code signals hooks when a turn is
  # interrupted, the OpenCode bridge when its prompt was answered): print
  # nothing and leave the decision to the agent.
  trap 'cleanup_perm; log "permission signal"; trim_log; exit 0' TERM INT HUP

  # Ingest to every link in parallel; each job leaves its nonce and result.
  n=0
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    n=$((n + 1))
    (
      load_link "$f" || exit 0
      nonce=$(rand_hex 16)
      [ "${SIMPLETERM_HOOK_TEST:-}" = 1 ] && [ -n "${SIMPLETERM_HOOK_TEST_NONCE:-}" ] &&
        nonce=$SIMPLETERM_HOOK_TEST_NONCE
      is_hex "$nonce" 32 || exit 0
      push=$(ingest_one "$RID" permission "$nonce" "$RUN_DIR/ing.$$.$n")
      printf '%s %s %s\n' "$push" "$nonce" "$f" >"$RUN_DIR/out.$$.$n"
    ) </dev/null >/dev/null 2>&1 &
    JOBS="$JOBS $!"
  done <<EOF
$LINKS
EOF
  for p in $JOBS; do wait "$p" 2>/dev/null; done

  # Wait only where a device was actually notified.
  i=0
  while [ "$i" -lt "$n" ]; do
    i=$((i + 1))
    [ -f "$RUN_DIR/out.$$.$i" ] || continue
    read -r push nonce f <"$RUN_DIR/out.$$.$i" || continue
    [ "$push" = sent ] || continue
    load_link "$f" || continue
    (poll_link "$RID" "$nonce" "$RUN_DIR/out.$$.$i.dec" "$deadline") </dev/null >/dev/null 2>&1 &
    PIDS="$PIDS $!"
    POLLERS=$((POLLERS + 1))
  done

  # Pollers always leave a result file; zombies make kill -0 unreliable.
  decision=''
  if [ -n "$PIDS" ]; then
    while :; do
      done_n=0
      i=0
      while [ "$i" -lt "$n" ]; do
        i=$((i + 1))
        [ -f "$RUN_DIR/out.$$.$i.dec" ] || continue
        done_n=$((done_n + 1))
        read -r d <"$RUN_DIR/out.$$.$i.dec"
        case $d in allow | deny) decision=$d ;; esac
        [ -n "$decision" ] && break
      done
      [ -n "$decision" ] && break
      [ "$done_n" -lt "$POLLERS" ] || break
      if answered_locally "$start" "$FP"; then
        log "permission answered-at-terminal"
        break
      fi
      if [ -n "$AGENT_PID" ] && ! kill -0 "$AGENT_PID" 2>/dev/null; then
        log "permission agent-gone"
        break
      fi
      [ "$(date +%s)" -lt "$deadline" ] || break
      sleep 1
    done
    if [ -z "$decision" ] && ! answered_locally "$start" "$FP" &&
      { [ -z "$AGENT_PID" ] || kill -0 "$AGENT_PID" 2>/dev/null; }; then
      if [ "$(date +%s)" -ge "$deadline" ]; then log "permission timeout"; else log "permission no-decision"; fi
    fi
  fi
  cleanup_perm
  LOGGED=1

  case $decision in
    allow | deny)
      emit_decision "$decision"
      log "permission $decision"
      ;;
    *) emit_decision none ;;
  esac
}

# --- usage (#342) ------------------------------------------------------------

# How much of a transcript to read: its end only, where the newest record
# is. The last 256 KiB nearly always hold it; 2 MiB is the most we read.
USAGE_TAIL=2097152

# Claude Code transcript (JSONL) -> "<context tokens> <model>": the newest
# main-thread assistant usage (input + cache creation + cache read, the
# status line's formula) or, if a compaction came after it, its postTokens.
# Only these keys are read; message text is never looked at.
#
# jwalk reads a line character by character, and BWK awk (macOS) measures
# the whole string again on every substr(), so a 1 MiB line (a large Edit or
# Write) took over 10 seconds. A line longer than 32 KiB is first cut down,
# with index() only, to the keys used here: the first isSidechain, model and
# role (the line's own, ahead of message.content), and the usage object, the
# first `"usage":{` after `"stop_reason":` that holds input and output token
# counts (message.content and wireToolInputs can hold a tool input with a
# "usage" key of its own, before and after it).
USAGE_CLAUDE=$JSON_FN'
function after(s, key, n,   p) {
  p = index(s, key)
  return p ? substr(s, p + length(key), n) : ""
}
function skeleton(L,   v, side, model, s, p, k, u, piece) {
  if (length(L) <= 32768) return L
  if (after(L, "\"role\":\"", 10) != "assistant\"") {
    if (!index(L, "\"subtype\":\"compact_boundary\"")) return ""
    v = after(L, "\"compactMetadata\":{", 4096)
    v = after(v, "\"postTokens\":", 24)
    sub(/[^0-9].*/, "", v)
    return "{\"type\":\"system\",\"subtype\":\"compact_boundary\",\"compactMetadata\":{\"postTokens\":" (v == "" ? "null" : v) "}}"
  }
  side = (after(L, "\"isSidechain\":", 4) == "true")
  model = after(L, "\"model\":\"", 128)
  sub(/".*/, "", model)
  s = L
  p = index(s, "\"stop_reason\":")
  if (p) s = substr(s, p)
  for (k = 0; k < 8; k++) {
    u = index(s, "\"usage\":{")
    if (!u) return ""
    piece = substr(s, u + 8, 2048)
    if (match(piece, /"input_tokens":[0-9]/) && match(piece, /"output_tokens":[0-9]/)) break
    s = substr(s, u + 9)
  }
  if (k == 8) return ""
  return "{\"type\":\"assistant\",\"isSidechain\":" (side ? "true" : "false") ",\"message\":{\"model\":\"" model "\",\"usage\":" piece "}}"
}
BEGIN {
  jwant("type,isSidechain,subtype,message.model,message.usage.input_tokens,message.usage.cache_creation_input_tokens,message.usage.cache_read_input_tokens,message.usage.cache_creation.ephemeral_5m_input_tokens,message.usage.cache_creation.ephemeral_1h_input_tokens,compactMetadata.postTokens")
  n = 0
}
NR == 1 && skip { next }
index($0, "\"compact_boundary\"") || (index($0, "\"usage\":{") && index($0, "\"type\":\"assistant\"")) { n++; L[n % 8] = $0 }
END {
  ctx = ""; model = ""
  for (k = n; k >= 1 && k > n - 8; k--) {
    jwalk(skeleton(L[k % 8]))
    if (GOT["type"] == "system") {
      if (GOT["subtype"] == "compact_boundary" && ctx == "" && isnum(GOT["compactMetadata.postTokens"]))
        ctx = GOT["compactMetadata.postTokens"] + 0
      continue
    }
    if (GOT["type"] != "assistant" || GOT["isSidechain"] == "true" || GOT["message.model"] == "<synthetic>") continue
    if (ctx == "") {
      if (!isnum(GOT["message.usage.input_tokens"])) continue
      cc = GOT["message.usage.cache_creation_input_tokens"]
      cc = isnum(cc) ? cc + 0 : 0
      if (cc == 0) {
        if (isnum(GOT["message.usage.cache_creation.ephemeral_5m_input_tokens"])) cc += GOT["message.usage.cache_creation.ephemeral_5m_input_tokens"]
        if (isnum(GOT["message.usage.cache_creation.ephemeral_1h_input_tokens"])) cc += GOT["message.usage.cache_creation.ephemeral_1h_input_tokens"]
      }
      cr = GOT["message.usage.cache_read_input_tokens"]
      cr = isnum(cr) ? cr + 0 : 0
      ctx = GOT["message.usage.input_tokens"] + cc + cr
    }
    if (GOT["message.model"] != "") { model = GOT["message.model"]; break }
  }
  if (ctx != "") printf "%.0f %s\n", ctx, (model == "" ? "-" : model)
}'

# Codex rollout (JSONL) -> a usage line (see usage_report): the newest
# token_count event with info (context) and the newest with rate limits.
USAGE_CODEX=$JSON_FN'
function lim(id, p, w, r) {
  if (!isdec(p) || !isnum(w) || !isnum(r)) return
  lims = lims " " id ":" p ":" w ":" r
}
BEGIN {
  jwant("payload.type,payload.info.last_token_usage.total_tokens,payload.info.model_context_window,payload.rate_limits.limit_id,payload.rate_limits.primary.used_percent,payload.rate_limits.primary.window_minutes,payload.rate_limits.primary.resets_at,payload.rate_limits.secondary.used_percent,payload.rate_limits.secondary.window_minutes,payload.rate_limits.secondary.resets_at,payload.rate_limits.plan_type,payload.rate_limits.rate_limit_reached_type")
  n = 0
}
NR == 1 && skip { next }
index($0, "\"token_count\"") { n++; L[n % 8] = $0 }
END {
  ctx = ""; win = "-"; rl = 0; lims = ""; plan = "-"; reached = 0
  for (k = n; k >= 1 && k > n - 8; k--) {
    jwalk(L[k % 8])
    if (GOT["payload.type"] != "token_count") continue
    if (ctx == "" && isnum(GOT["payload.info.last_token_usage.total_tokens"])) {
      ctx = GOT["payload.info.last_token_usage.total_tokens"]
      if (isnum(GOT["payload.info.model_context_window"])) win = GOT["payload.info.model_context_window"]
    }
    if (!rl && (("payload.rate_limits.primary.used_percent" in GOT) || ("payload.rate_limits.plan_type" in GOT))) {
      rl = 1
      id = GOT["payload.rate_limits.limit_id"]
      gsub(/[^A-Za-z0-9_.-]/, "", id)
      if (id == "") id = "codex"
      lim(id ".primary", GOT["payload.rate_limits.primary.used_percent"], GOT["payload.rate_limits.primary.window_minutes"], GOT["payload.rate_limits.primary.resets_at"])
      lim(id ".secondary", GOT["payload.rate_limits.secondary.used_percent"], GOT["payload.rate_limits.secondary.window_minutes"], GOT["payload.rate_limits.secondary.resets_at"])
      p = GOT["payload.rate_limits.plan_type"]
      if (p ~ /^[A-Za-z0-9_-]+$/ && p != "null") plan = p
      r = GOT["payload.rate_limits.rate_limit_reached_type"]
      if (r != "" && r != "null") reached = 1
    }
    if (ctx != "" && rl) break
  }
  if (ctx != "") print ctx, win, "rollout", 0, 12000, plan, reached lims
}'

# Gemini CLI chat record (JSONL, or the pretty JSON of older versions) ->
# "<prompt tokens> <model>" of the newest model response.
USAGE_GEMINI='
NR == 1 && skip { next }
{
  line = $0
  if (index(line, "\"tokens\":{")) {
    if (match(line, /"tokens":[{]"input":[0-9]+/)) {
      v = substr(line, RSTART, RLENGTH); sub(/.*:/, "", v); inp = v; mdl = ""
      if (match(line, /[}],"model":"[^"]*"/)) mdl = substr(line, RSTART + 11, RLENGTH - 12)
    }
  } else if (line ~ /^[ \t]*"tokens": [{][ \t]*$/) { intok = 1; pinp = "" }
  else if (intok && line ~ /^[ \t]*"input": [0-9]+/) { v = line; gsub(/[^0-9]/, "", v); pinp = v }
  else if (intok && line ~ /^[ \t]*[}]/) {
    intok = 0
    if (pinp != "") { inp = pinp; mdl = ""; wantm = 1 }
  } else if (wantm && line ~ /^[ \t]*"model": "/) {
    m = line; sub(/^[ \t]*"model": "/, "", m); sub(/".*$/, "", m); mdl = m; wantm = 0
  }
}
END { if (inp != "") print inp, (mdl == "" ? "-" : mdl) }'

# Status line data saved by scripts/statusline-tap.sh (optional, the user
# registers it): "<id>:<used %>:<window minutes>:<reset epoch>" entries.
STATUSLINE_LIMS=$JSON_FN'
function lim(id, p, w, r) {
  if (!isdec(p) || !isnum(w) || !isnum(r) || r + 0 <= now + 0) return
  printf " %s:%s:%s:%s", id, p, w, r
}
BEGIN {
  jwant("context_window.context_window_size,rate_limits.five_hour.used_percentage,rate_limits.five_hour.resets_at,rate_limits.seven_day.used_percentage,rate_limits.seven_day.resets_at,rate_limits.spend_limit.used_percentage,rate_limits.spend_limit.resets_at,rate_limits.spend_limit.period")
}
NR > 1 { s = s $0 "\n" }
END {
  jwalk(s)
  w = GOT["context_window.context_window_size"]
  printf "%s", (isnum(w) ? w : "-")
  lim("five_hour", GOT["rate_limits.five_hour.used_percentage"], 300, GOT["rate_limits.five_hour.resets_at"])
  lim("seven_day", GOT["rate_limits.seven_day.used_percentage"], 10080, GOT["rate_limits.seven_day.resets_at"])
  p = GOT["rate_limits.spend_limit.period"]
  pw = (p == "daily" ? 1440 : (p == "weekly" ? 10080 : (p == "monthly" ? 43200 : 0)))
  lim("spend_limit", GOT["rate_limits.spend_limit.used_percentage"], pw, GOT["rate_limits.spend_limit.resets_at"])
  printf "\n"
}'

# A usage line "<ctx> <win|-> <src> <est 0|1> <baseline|-> <plan|-> <reached
# 0|1> [<id>:<pct>:<win min>:<reset epoch>]..." -> two lines: the OSC 9
# body and the plaintext fields of the `usage` event.
USAGE_FMT='
function num(v) { return v ~ /^[0-9]+$/ }
function dec(v) { return v ~ /^[0-9]+([.][0-9]+)?$/ }
NR == 1 {
  if (!num($1) || !($3 ~ /^[a-z]+$/)) exit
  osc = "simpleterm:usage v=1 agent=" app " ctx=" $1
  js = ",\"ctx\":{\"used\":" $1
  if (num($2)) { osc = osc " win=" $2; js = js ",\"win\":" $2 }
  if (num($5)) js = js ",\"baseline\":" $5
  osc = osc " src=" $3; js = js ",\"src\":\"" $3 "\""
  if ($4 == 1) { osc = osc " est=1"; js = js ",\"est\":true" }
  js = js "}"
  la = ""
  for (i = 8; i <= NF; i++) {
    if (split($i, P, ":") != 4) continue
    if (!(P[1] ~ /^[A-Za-z0-9_.-]+$/) || !dec(P[2]) || !num(P[3]) || !num(P[4])) continue
    osc = osc " lim=" $i
    la = la (la == "" ? "" : ",") "{\"id\":\"" P[1] "\",\"pct\":" P[2] ",\"win_min\":" P[3] ",\"resets_at\":" P[4] "}"
  }
  if ($7 == 1) { osc = osc " lim=reached"; la = la (la == "" ? "" : ",") "{\"id\":\"reached\"}" }
  js = js ",\"lims\":[" la "]"
  if ($6 ~ /^[A-Za-z0-9_-]+$/ && $6 != "-") js = js ",\"plan\":\"" $6 "\""
  print osc
  print js
}'

# A file path from the hook input (JSON-escaped) that can be read, or empty.
input_file() {
  case $1 in '' | null) return 0 ;; esac
  p=$(printf '%s\n' "$1" | awk '{
    s = $0; out = ""
    for (i = 1; i <= length(s); i++) {
      c = substr(s, i, 1)
      if (c == "\\") {
        e = substr(s, i + 1, 1)
        if (e != "\\" && e != "/" && e != "\"") exit 1
        c = e; i++
      }
      out = out c
    }
    print out
  }' 2>/dev/null) || return 0
  [ -f "$p" ] && [ -r "$p" ] && printf '%s' "$p"
}

# The end of file $1 through awk program $2 (a cut first line is skipped):
# the last 256 KiB, or the last USAGE_TAIL bytes when that found nothing or
# no model name (a result ending in " -").
tail_awk() { # file program
  size=$(wc -c <"$1" 2>/dev/null | tr -d ' ')
  is_uint "$size" || return 0
  for lim in 262144 "$USAGE_TAIL"; do
    skip=0
    [ "$size" -gt "$lim" ] && skip=1
    r=$(tail -c "$lim" "$1" 2>/dev/null | awk -v skip="$skip" -v now="$NOW" "$2" 2>/dev/null)
    case $r in '' | *' -') ;; *) printf '%s\n' "$r"; return 0 ;; esac
    [ "$skip" = 1 ] || break
  done
  [ -n "$r" ] && printf '%s\n' "$r"
}

# Context window of a Claude model: what Claude Code would use, from the
# environment it passed on, or a guess from the model name (est=1).
claude_window() { # model
  U_EST=0
  v=${CLAUDE_CODE_MAX_CONTEXT_TOKENS:-}
  # A JSON number has no leading zeros (and $((v)) would read them as octal).
  while :; do case $v in 0?*) v=${v#0} ;; *) break ;; esac; done
  if is_uint "$v" && [ "$v" -ge 1000 ]; then U_WIN=$v; return; fi
  case ${CLAUDE_CODE_DISABLE_1M_CONTEXT:-} in 1 | true | TRUE | True) U_WIN=200000; return ;; esac
  U_EST=1 U_WIN=200000
  case $(printf '%s' "$1" | tr 'A-Z' 'a-z') in
    *'[1m]'*) U_WIN=1000000 U_EST=0 ;;
    *claude-fable-*) U_WIN=1000000 ;;
    *claude-sonnet-[5-9]* | *claude-sonnet-[1-9][0-9]*) U_WIN=1000000 ;;
    *claude-opus-4-[7-9]* | *claude-opus-[5-9]* | *claude-opus-[1-9][0-9]*) U_WIN=1000000 ;;
    *claude-haiku-5-[5-9]* | *claude-haiku-[6-9]* | *claude-haiku-[1-9][0-9]*) U_WIN=1000000 ;;
  esac
}

# Sets U_LINE (see USAGE_FMT) for the current event, or leaves it empty.
usage_compute() {
  U_LINE=''
  case $AGENT in
    claude)
      reached=0
      [ "$EVENT" = StopFailure ] && [ "$ERR" = rate_limit ] && reached=1
      src=transcript ctx='' model=$MODEL
      if is_uint "$CTXTOK" && [ "$CTXTOK" -gt 0 ]; then
        # SessionStart (resume, fork) and PostModelSwitch say it themselves.
        ctx=$CTXTOK src=hook
      else
        f=$(input_file "$TPATH")
        if [ -n "$f" ]; then
          # Split the awk result into words; no pathname expansion of them.
          set -f
          set -- $(tail_awk "$f" "$USAGE_CLAUDE")
          set +f
          ctx=${1:-}
          [ "${2:--}" = - ] || [ -n "$model" ] || model=$2
        fi
      fi
      is_uint "$ctx" || return 0
      model=$(printf '%s' "$model" | tr -cd 'A-Za-z0-9._:@/[]-')
      claude_window "$model"
      # The session's window as last known, "<window|-> <est 0|1> <since>":
      # transcripts drop the [1m] of a 1M session (only SessionStart names
      # it), so a guess from them alone would flip between 1M and 200K.
      # SessionStart and PostModelSwitch name the model in use: what was
      # known before no longer holds, nor does a status line saved earlier.
      wf=$RUN_DIR/$SID.win
      mw='' me=1 ms=0
      [ -f "$wf" ] && read -r mw me ms 2>/dev/null <"$wf"
      is_uint "$mw" || mw=''
      [ "$me" = 0 ] || me=1
      is_uint "$ms" || ms=0
      case $EVENT in SessionStart | PostModelSwitch) mw='' me=1 ms=$NOW ;; esac
      lims=''
      sl=$RUN_DIR/usage.$SID.json
      if [ -f "$sl" ]; then
        t=$(head -n 1 "$sl" 2>/dev/null)
        if is_uint "$t" && [ $((NOW - t)) -le 600 ] && [ $((t - NOW)) -le 60 ]; then
          set -f
          set -- $(head -c 65536 "$sl" | awk -v now="$NOW" "$STATUSLINE_LIMS" 2>/dev/null)
          set +f
          is_uint "${1:-}" && [ "$t" -gt "$ms" ] && U_WIN=$1 U_EST=0
          [ $# -gt 0 ] && shift
          lims=$*
        fi
      fi
      if [ "$U_EST" = 1 ] && [ -n "$mw" ]; then U_WIN=$mw U_EST=$me; fi
      # A guess below the context in use is wrong: the window is 1M.
      [ "$U_EST" = 1 ] && [ "$ctx" -gt "$U_WIN" ] && U_WIN=1000000 mw=1000000
      if [ "$U_EST" = 0 ]; then new="$U_WIN 0 $ms"; elif [ -n "$mw" ]; then new="$U_WIN 1 $ms"; else new="- 1 $ms"; fi
      [ "$(cat "$wf" 2>/dev/null)" = "$new" ] || printf '%s\n' "$new" >"$wf" 2>/dev/null
      U_LINE="$ctx $U_WIN $src $U_EST - - $reached $lims"
      ;;
    codex)
      f=$(input_file "$TPATH")
      [ -n "$f" ] || return 0
      U_LINE=$(tail_awk "$f" "$USAGE_CODEX")
      ;;
    gemini)
      f=$(input_file "$TPATH")
      [ -n "$f" ] || return 0
      set -f
      set -- $(tail_awk "$f" "$USAGE_GEMINI")
      set +f
      is_uint "${1:-}" || return 0
      win=1048576 est=1
      case ${2:-} in gemini-*) est=0 ;; gemma-4*) win=256000 est=0 ;; esac
      U_LINE="$1 $win transcript $est - - 0"
      ;;
  esac
}

# Reports context and rate limits when they changed: an OSC 9 for the
# terminal (Claude Code in SimpleTerm, USAGE_SEQ) and a `usage` event for the
# SSH tunnel links. The relay gets none: it does not push them (an iOS push
# is always an alert) and every request costs a function call.
usage_report() {
  USAGE_SEQ=''
  [ "$(conf_int usage 1)" = 0 ] && return 0
  usage_compute
  [ -n "$U_LINE" ] || return 0
  out=$(printf '%s\n' "$U_LINE" | awk -v app="$APP" "$USAGE_FMT" 2>/dev/null)
  osc=$(printf '%s\n' "$out" | sed -n 1p)
  USAGE_JSON=$(printf '%s\n' "$out" | sed -n 2p)
  [ -n "$osc" ] && [ -n "$USAGE_JSON" ] || return 0
  [ "$(cat "$RUN_DIR/$SID.usage" 2>/dev/null)" != "$osc" ] || return 0
  # Recorded as sent only once SimpleTerm has it: on Claude Code's terminal
  # (printed below), or when a tunnel link took the event. Otherwise it goes
  # again next time, though unchanged, in case the app connects meanwhile.
  USAGE_SEQ='\u001b]9;'$osc'\u0007'
  [ "$AGENT" = claude ] && [ "${SIMPLETERM:-}" = 1 ] && printf '%s\n' "$osc" >"$RUN_DIR/$SID.usage" 2>/dev/null
  urid=$(rand_hex 8)
  is_hex "$urid" 16 && send_bg usage "$urid" tunnel "$RUN_DIR/$SID.usage" "$osc"
}

# --- the `simpleterm` command --------------------------------------------------

# True if dotted version $1 is older than $2.
ver_lt() { # a b
  awk -v a="$1" -v b="$2" 'BEGIN {
    split(a, A, "."); split(b, B, ".")
    for (i = 1; i <= 3; i++) { if (A[i] + 0 < B[i] + 0) exit 0; if (A[i] + 0 > B[i] + 0) exit 1 }
    exit 1
  }' 2>/dev/null
}

# Keeps ~/.simpleterm/bin/simpleterm pointing at the newest installed copy of
# simpleterm-notify.sh. It is rewritten when missing, when the script it
# names is gone (the plugin moved: updated or removed), when in an older
# format, or when it names an older release than this one: an updated plugin
# re-points it at once, though the agent may keep the old folder for a
# while. Another copy of the same or a newer release (Codex, Gemini and
# Grok install their own) is left alone, so copies do not take turns.
ensure_cli() {
  [ -d "$ST_DIR" ] || return 0
  here=${0%/*}
  case $here in /*) ;; *) here=$(cd "$here" 2>/dev/null && pwd) || return 0 ;; esac
  src=$here/simpleterm-notify.sh
  [ -f "$src" ] || return 0
  case $src in *"'"* | *"$CR"* | *'
'*) return 0 ;; esac
  w=$ST_DIR/bin/simpleterm
  if [ -f "$w" ]; then
    cur=$(sed -n "s/^s='\\(.*\\)'\$/\\1/p" "$w" 2>/dev/null | head -n 1)
    rev=$(sed -n 's/^# rev=\([0-9]*\)$/\1/p' "$w" 2>/dev/null | head -n 1)
    ver=$(sed -n 's/^# version=\([0-9][0-9.]*\)$/\1/p' "$w" 2>/dev/null | head -n 1)
    if [ -n "$cur" ] && [ -f "$cur" ] && is_uint "$rev" && [ "$rev" -ge "$CLI_REV" ]; then
      [ "$cur" = "$src" ] && return 0
      [ -n "$ver" ] && ! ver_lt "$ver" "$HOOK_VERSION" && return 0
    fi
  fi
  mkdir -p "$ST_DIR/bin" 2>/dev/null || return 0
  {
    printf '#!/bin/sh\n'
    printf '# simpleterm: written by the SimpleTerm agent hooks plugin, which keeps it\n'
    printf '# pointing at the plugin (see its README). Edits are overwritten.\n'
    printf '# rev=%s\n' "$CLI_REV"
    printf '# version=%s\n' "$HOOK_VERSION"
    printf "s='%s'\n" "$src"
    printf '[ -f "$s" ] || { echo "simpleterm: $s is gone; start your agent once to update this command" >&2; exit 1; }\n'
    printf 'exec sh "$s" "$@"\n'
  } >"$w.$$" 2>/dev/null && chmod 755 "$w.$$" 2>/dev/null && mv -f "$w.$$" "$w" 2>/dev/null &&
    log "cli installed"
  rm -f "$w.$$" 2>/dev/null
}

# --- de-duplication ------------------------------------------------------------

# True for the first delivery of an event (key $1) within 30 seconds. Grok
# Build loads a plugin name once (the Claude Code plugin and the one installed
# in Grok are the same `simpleterm`), but a copy configured another way
# (another plugin name, a settings file) runs the same hook again; the copies
# of one event carry the same timestamp.
once() { # key
  f=$RUN_DIR/dd.$1
  ( set -C; printf '%s\n' "$NOW" >"$f" ) 2>/dev/null && return 0
  t=$(cat "$f" 2>/dev/null)
  if is_uint "$t" && [ $((NOW - t)) -gt 30 ]; then
    rm -f "$f"
    ( set -C; printf '%s\n' "$NOW" >"$f" ) 2>/dev/null && return 0
  fi
  log "duplicate $EVENT"
  return 1
}

# True for the first alert for this question of this session within 30
# seconds: Claude Code reports one AskUserQuestion twice (PreToolUse and
# PermissionRequest).
ask_once() {
  once "q.$(printf '%s|%s' "$SID" "${QTEXT:-$DESC}" | cksum | awk '{ print $1 }')"
}

# --- main ----------------------------------------------------------------

case $AGENT in
  claude)
    APP=claude-code
    # Grok Build runs Claude Code plugins' hooks (and this plugin installed
    # in Grok uses the same hooks file): it sets GROK_HOOK_EVENT.
    if [ -n "${GROK_HOOK_EVENT:-}" ]; then AGENT=grok APP=grok-build; fi
    ;;
  codex | codex-notify) APP=codex ;;
  gemini) APP=gemini-cli ;;
  agy) APP=antigravity ;;
  grok) APP=grok-build ;;
  opencode) APP=opencode ;;
  notify) APP=script ;;
  *) exit 0 ;;
esac

if [ "$AGENT" = codex-notify ]; then
  INPUT=''
  for a in "$@"; do INPUT=$a; done
  [ "${#INPUT}" -le "$MAX_INPUT" ] || INPUT=''
elif [ "$AGENT" = notify ]; then
  INPUT=''
else
  INPUT=$(head -c "$MAX_INPUT" 2>/dev/null) || INPUT=$(dd bs=4096 count=64 2>/dev/null)
fi

# Nothing to do without a link or a SimpleTerm session.
LINKS=$(list_links)
if [ -z "$LINKS" ] && [ "${SIMPLETERM:-}" != 1 ]; then
  [ "$AGENT" = notify ] && [ -t 2 ] &&
    echo 'simpleterm: not a SimpleTerm session and no linked device (~/.simpleterm/links); nothing sent' >&2
  agy_default
  exit 0
fi

mkdir -p "$RUN_DIR" 2>/dev/null
chmod 700 "$ST_DIR" "$RUN_DIR" 2>/dev/null

if [ -n "$LINKS" ]; then
  # Link secrets, the HMAC key blocks and plaintext pass through printf. Only
  # a shell builtin keeps them out of the process list that other local
  # users can read; OpenBSD sh/ksh and mksh run printf from /usr/bin.
  case $(command -v printf 2>/dev/null) in
    printf) ;;
    *)
      log "printf is not a shell builtin; relay disabled"
      LINKS=''
      ;;
  esac
fi
if [ -n "$LINKS" ]; then
  for dep in curl openssl; do
    command -v "$dep" >/dev/null 2>&1 && continue
    log "missing $dep; relay disabled"
    LINKS=''
  done
fi

RID=$(rand_hex 8)
TS=$(date +%s)
NOW=$TS
if [ "${SIMPLETERM_HOOK_TEST:-}" = 1 ]; then
  [ -n "${SIMPLETERM_HOOK_TEST_RID:-}" ] && RID=$SIMPLETERM_HOOK_TEST_RID
  [ -n "${SIMPLETERM_HOOK_TEST_TS:-}" ] && TS=$SIMPLETERM_HOOK_TEST_TS
fi
is_hex "$RID" 16 || RID=''
is_uint "$TS" || TS=0
is_uint "$NOW" || NOW=0
[ -n "$RID" ] || LINKS=''
USAGE_SEQ='' USAGE_JSON='' TITLE='' MSG=''

# `simpleterm notify "title" ["body"]`: an OSC 777 notification on this
# terminal (in a SimpleTerm session) and a `notify` event to every link.
if [ "$AGENT" = notify ]; then
  t=$(notify_text "${2:-}" 64 256)
  b=$(notify_text "${3:-}" 200 800)
  [ -n "$t$b" ] || finish
  if [ "${SIMPLETERM:-}" = 1 ] && { printf '' >/dev/tty; } 2>/dev/null; then
    if [ -n "${TMUX:-}" ]; then
      # tmux forwards it only with `set -g allow-passthrough on`.
      printf '\033Ptmux;\033\033]777;notify;%s;%s\007\033\\' "$t" "$b" >/dev/tty 2>/dev/null
    else
      printf '\033]777;notify;%s;%s\007' "$t" "$b" >/dev/tty 2>/dev/null
    fi
  fi
  # Already within the limits; escaping can double the bytes, not the count.
  TITLE=$(json_text "$t" 64 512)
  MSG=$(json_text "$b" 200 1600)
  CWD_BASE=$(json_text "$PWD" 64 256 base)
  send_bg notify
  finish
fi

# Fields of the agent's event JSON. Agents name the same things differently
# (Grok sends camelCase and snake_case, Antigravity camelCase).
case $AGENT in
  claude | opencode)
    # background_tasks (Claude Code Stop): the first ten tasks.
    # session_crons (the first five): scheduled wake-ups. prompt/source tell
    # who started a turn; stop_hook_active and is_interrupt are flags. agent_id is
    # there only when a subagent's own tool call fires the hook (foreground or
    # background; absent for the main thread).
    WANT='hook_event_name,notification_type,tool_name,tool_input.command,tool_input.file_path,tool_input.url,tool_input.description,tool_input.questions.0.question,session_id,cwd,message,last_assistant_message,error,transcript_path,context_tokens,model,to_model,prompt,source,stop_hook_active,is_interrupt,agent_id'
    for i in 0 1 2 3 4 5 6 7 8 9; do WANT=$WANT,background_tasks.$i.id,background_tasks.$i.type,background_tasks.$i.description,background_tasks.$i.command; done
    for i in 0 1 2 3 4; do WANT=$WANT,session_crons.$i.id,session_crons.$i.schedule,session_crons.$i.prompt; done
    ;;
  codex)
    WANT='hook_event_name,tool_name,tool_input.command,tool_input.file_path,tool_input.description,session_id,cwd,last_assistant_message,transcript_path,stop_hook_active'
    ;;
  codex-notify) WANT='type,cwd,last-assistant-message,input-messages.0' ;;
  gemini)
    WANT='hook_event_name,notification_type,message,details.type,details.command,details.rootCommand,details.filePath,details.fileName,details.toolName,details.serverName,details.urls.0,details.prompt,prompt_response,session_id,cwd,transcript_path,stop_hook_active'
    ;;
  agy)
    WANT='conversationId,workspacePaths.0,toolCall.name,toolCall.args.CommandLine,toolCall.args.Cwd,toolCall.args.questions.0.question,toolCall.args.Action,toolCall.args.Target,terminationReason,error,fullyIdle'
    ;;
  grok)
    # backgroundTasks (Grok's Stop, camelCase): the first ten tasks.
    # sessionCrons (the first five): scheduled wake-ups; a prompt id that is
    # not a person's marks a turn Grok started itself.
    WANT='hook_event_name,hookEventName,notificationType,sessionId,cwd,message,lastAssistantMessage,error,reason,promptId,timestamp,prompt,stop_hook_active'
    for i in 0 1 2 3 4 5 6 7 8 9; do WANT=$WANT,backgroundTasks.$i.id,backgroundTasks.$i.type,backgroundTasks.$i.description,backgroundTasks.$i.command; done
    for i in 0 1 2 3 4; do WANT=$WANT,sessionCrons.$i.id,sessionCrons.$i.schedule,sessionCrons.$i.prompt; done
    ;;
esac

EVENT='' NTYPE='' TOOL='' DETAIL='' DESC='' SID='' CWD='' LAST='' ERR='' QTEXT='' FIRSTIN='' NTYPE2=''
TPATH='' CTXTOK='' MODEL='' GTYPE='' FULLYIDLE='' TERMREASON='' EXTRA='' GKEY='' REASON=''
PROMPT='' SRC='' STOPACT='' ISINT='' AGENTID='' PROMPTID='' XFLAGS=''
BG_N=0 BG_FINITE=0 BG_PICK='' BG_TYPE='' BG_DESC='' BG_CMD='' BG_SEQ=''
BG_SVC=0 BG_IDMAP='' BG_KEEP='' BG_SHELLS='' BG_IDS='' BG_NOID=0 BG_M=''
CRON_N=0 CRON_SCHED='' CRON_SUMS=''

# --- what the hook reads from the text of a turn ------------------------------

# A shell task whose command is a service (a dev server, a watcher, a
# follower) is not something the agent waits for: it never ends and never
# wakes the agent. exit 0 when the command (one JSON-escaped line on stdin) is
# one. A wrong "service" ends the turn early and sends a second done later; a
# missed one only delays the done to bg_done_after: so only what is known is
# matched, and only at the command position. The command is split at ; & | (and
# line breaks); in each part leading VAR=val words, shell keywords and a few
# launchers (npx, bunx, pnpm exec|dlx, yarn dlx, uv|poetry run, bundle exec,
# env, nohup, exec, sudo; an option we cannot read gives up) are skipped, and
# the command word with its subcommand is looked up in the table below
# (svcseg). Between the two only options are allowed, and the values of the
# options in VF. Words after a lone -- belong to another command.
SVC_AWK='
BEGIN {
  VF = " --filter -F -C --cwd --prefix --dir -p --project --workspace -w --app -A --namespace -n --context --kubeconfig -f --file --env-file --project-name --profile --port --host --config -c --mode -m --base --logLevel -l --outDir "
}
function base(w) { sub(/^.*\//, "", w); return tolower(w) }
function isopt(w) { return substr(w, 1, 1) == "-" }
# The first word from j on that is not an option (or an option value).
function nxt(j) {
  while (j <= n && isopt(W[j])) {
    if (W[j] == "--") return n + 1
    if (index(W[j], "=") == 0 && index(VF, " " W[j] " ") > 0) j += 2; else j++
  }
  return j
}
# Does an option word matching the regex string re come from j on (before a lone --)?
function anyopt(j, re,   k) {
  for (k = j; k <= n; k++) { if (W[k] == "--") return 0; if (W[k] ~ re) return 1 }
  return 0
}
function svcseg(seg,   i, w, lw, c, j, k, t) {
  gsub(/[()\t]/, " ", seg)
  n = split(seg, W, " ")
  i = 1
  while (i <= n) {
    w = W[i]
    if (w ~ /^[A-Za-z_][A-Za-z0-9_]*=/) { i++; continue }
    lw = base(w)
    if (lw ~ /^(do|then|else|elif|if|while|until|time|nohup|exec|bunx|!)$/) { i++; continue }
    if (lw == "npx") {
      i++
      while (i <= n && isopt(W[i])) { if (W[i] ~ /^(-y|--yes|--no-install|--no|-q|--quiet)$/) i++; else return 0 }
      continue
    }
    if (lw == "env" || lw == "sudo") { i++; if (isopt(W[i])) return 0; continue }
    if ((lw == "pnpm" && (W[i + 1] == "exec" || W[i + 1] == "dlx")) || (lw == "yarn" && W[i + 1] == "dlx") || ((lw == "uv" || lw == "poetry") && W[i + 1] == "run") || (lw == "bundle" && W[i + 1] == "exec")) {
      i += 2
      if (isopt(W[i])) return 0
      continue
    }
    break
  }
  if (i > n) return 0
  c = base(W[i]); j = i + 1
  if (c ~ /^(npm|pnpm|yarn|bun)$/) {
    j = nxt(j)
    if (c == "yarn" && W[j] == "workspace") j = nxt(j + 2)
    if (W[j] == "run" || W[j] == "run-script") j = nxt(j + 1)
    t = tolower(W[j])
    return (j <= n && t ~ /^(dev|start|serve|preview|watch)(:[a-z0-9_-]+)?$/)
  }
  if (c == "next") { j = nxt(j); return (W[j] ~ /^(dev|start)$/) }
  if (c == "vite") {
    j = nxt(j)
    if (anyopt(i + 1, "^(-v|-h|--version|--help)$")) return 0
    return (j > n || W[j] ~ /^(dev|serve|preview)$/ || W[j] ~ /^[0-9]*[<>]/ || W[j] ~ /[\/.]/)
  }
  if (c == "vitest") return (anyopt(j, "^(-w|--watch|--watch=true|--watch=1)$") || W[nxt(j)] ~ /^(dev|watch)$/)
  if (c ~ /^(nodemon|uvicorn|gunicorn|watchexec|watch|serve|http-server)$/) return 1
  if (c ~ /^python[0-9.]*$/) {
    for (k = j; k <= n; k++) {
      if (W[k] == "-m" && W[k + 1] ~ /^(http[.]server|uvicorn|gunicorn|hypercorn)$/) return 1
      if (W[k] == "-m" && W[k + 1] == "flask") return (W[nxt(k + 2)] == "run")
      if (W[k] ~ /manage[.]py$/ && W[k + 1] == "runserver") return 1
    }
    return 0
  }
  if (c ~ /manage[.]py$/) return (W[nxt(j)] == "runserver")
  if (c == "rails") return (W[nxt(j)] ~ /^(s|server)$/)
  if (c == "flask") return (W[nxt(j)] == "run")
  if (c == "docker" || c == "docker-compose") {
    j = nxt(j)
    if (c == "docker" && W[j] == "compose") j = nxt(j + 1)
    else if (c == "docker") { if (W[j] != "logs") return 0 }
    if (W[j] == "up") return !anyopt(j + 1, "^(-d|--detach)$")
    if (W[j] == "logs") return anyopt(j + 1, "^(-[a-zA-Z]*f[a-zA-Z]*|--follow)$")
    return 0
  }
  if (c == "kubectl") {
    j = nxt(j)
    if (W[j] == "port-forward") return 1
    if (W[j] == "logs") return anyopt(j + 1, "^(-[a-zA-Z]*f[a-zA-Z]*|--follow)$")
    if (W[j] == "get") return anyopt(j + 1, "^(-w|--watch|--watch-only)$")
    return 0
  }
  if (c == "tail") return anyopt(j, "^(-[a-zA-Z]*[fF][a-zA-Z]*|--follow(=.*)?)$")
  if (c == "journalctl") return anyopt(j, "^(-[a-zA-Z]*f[a-zA-Z]*|--follow)$")
  if (c == "turbo") { j = nxt(j); if (W[j] == "run") j = nxt(j + 1); return (W[j] ~ /^(dev|watch|serve|start)(:[a-z0-9_-]+)?$/) }
  if (c == "nx") {
    j = nxt(j)
    if (W[j] ~ /^(serve|dev|start)$/) return 1
    if (W[j] == "run") { j = nxt(j + 1); return (W[j] ~ /:(serve|dev|start)(:|$)/) }
    return 0
  }
  if (c == "ng") return (W[nxt(j)] ~ /^(serve|s)$/)
  if (c == "astro" || c == "nuxt" || c == "nuxi") return (W[nxt(j)] == "dev")
  if (c == "expo") return (W[nxt(j)] == "start")
  if (c == "storybook" || c == "sb") return (W[nxt(j)] == "dev")
  if (c == "php") { for (k = j; k < n; k++) if (W[k] == "artisan") return (W[k + 1] == "serve"); return 0 }
  if (c == "hugo") return (W[nxt(j)] == "server")
  if (c == "jekyll") return (W[nxt(j)] ~ /^(serve|s)$/)
  if (c == "cargo") return (W[nxt(j)] == "watch")
  if (c == "tsx" && W[nxt(j)] == "watch") return 1
  if (c ~ /^(tsc|webpack|sass|esbuild|rollup|swc|tailwindcss|jest|mocha|tsx|parcel)$/) return anyopt(j, "^(-w|--watch|--watchAll|--watch=true|--watch=1)$")
  return 0
}
{
  s = $0
  gsub(/\\n/, ";", s)
  gsub(/\\[rt"]/, " ", s)
  np = split(s, part, /[;&|]+/)
  for (q = 1; q <= np; q++) if (svcseg(part[q])) found = 1
}
END { exit !found }'

is_service_cmd() { printf '%s\n' "$1" | awk "$SVC_AWK" 2>/dev/null; }

# Does the last message of a turn ask the user something? exit 0 if so (one
# JSON-escaped line on stdin). Only the end of the message counts: its last
# two sentences, fenced code blocks left out. A sentence asks when it ends
# with ? or a full-width question mark, ends with a Korean request or question ending
# (table KO), or contains an English ask (table EN). This is a reading of text,
# not a protocol: a wrong guess costs one extra alert, or the answer to come
# with the final report. Korean is written as octal escapes to keep this file
# ASCII; the endings, in order: kkayo (halkkayo, deurilkkayo), nikka
# (hasigetseumnikka), hasigesseoyo, juseyo (allyeo juseyo, golla juseyo,
# hwaginhae juseyo), jusigesseoyo, jusilraeyo, nayo (itnayo), ingayo,
# baramnida, hallaeyo.
ASK_AWK='
BEGIN {
  nk = split("\352\271\214\354\232\224|\353\213\210\352\271\214|\355\225\230\354\213\234\352\262\240\354\226\264\354\232\224|\354\243\274\354\204\270\354\232\224|\354\243\274\354\213\234\352\262\240\354\226\264\354\232\224|\354\243\274\354\213\244\353\236\230\354\232\224|\353\202\230\354\232\224|\354\235\270\352\260\200\354\232\224|\353\260\224\353\236\215\353\213\210\353\213\244|\355\225\240\353\236\230\354\232\224|\353\266\200\355\203\201\353\223\234\353\246\275\353\213\210\353\213\244", KO, "|")
  ne = split("should i|shall i|would you like|do you want|let me know which|let me know whether|want me to|please confirm|please choose|please select|please tell me", EN, "|")
  FWQ = "\357\274\237"; FWE = "\357\274\201"; IDEO = "\343\200\202"
  nf = split("\352\270\260\353\213\244|\354\260\270\352\263\240|\354\260\270\354\241\260|\354\226\221\355\225\264|\354\235\264\355\225\264|\352\260\220\354\225\210|\354\234\240\354\235\230", FYI, "|")
  REQ["\354\243\274\354\204\270\354\232\224"] = 1; REQ["\353\260\224\353\236\215\353\213\210\353\213\244"] = 1; REQ["\353\266\200\355\203\201\353\223\234\353\246\275\353\213\210\353\213\244"] = 1
  nh = split("\354\243\274\354\213\234\352\270\260|\355\225\230\354\213\234\352\270\260|\354\213\234\352\270\260", HON, "|")
  nc = split("\343\200\215|\343\200\217|\342\200\235|\342\200\231|\357\274\211|" FWQ "|" FWE "|" IDEO, CL, "|")
}
function hexv(h,   k, v, c) {
  v = 0; h = tolower(h)
  if (length(h) != 4) return -1
  for (k = 1; k <= 4; k++) {
    c = index("0123456789abcdef", substr(h, k, 1))
    if (c == 0) return -1
    v = v * 16 + c - 1
  }
  return v
}
function u8(cp) {
  if (cp < 32) return " "
  if (cp < 128) return sprintf("%c", cp)
  if (cp < 2048) return sprintf("%c%c", 192 + int(cp / 64), 128 + cp % 64)
  if (cp >= 55296 && cp <= 57343) return " "
  return sprintf("%c%c%c", 224 + int(cp / 4096), 128 + int(cp / 64) % 64, 128 + cp % 64)
}
function unesc(s,   out, p, c, cp) {
  out = ""
  while ((p = index(s, "\\")) > 0) {
    out = out substr(s, 1, p - 1)
    c = substr(s, p + 1, 1)
    if (c == "n" || c == "r") { out = out "\n"; s = substr(s, p + 2) }
    else if (c == "t") { out = out " "; s = substr(s, p + 2) }
    else if (c == "u") {
      cp = hexv(substr(s, p + 2, 4))
      if (cp < 0) { out = out " "; s = substr(s, p + 2) }
      else { out = out u8(cp); s = substr(s, p + 6) }
    } else { out = out c; s = substr(s, p + 2) }
  }
  return out s
}
function ends(s, suf) { return length(s) >= length(suf) && substr(s, length(s) - length(suf) + 1) == suf }
# The sentence without trailing space, markup, quotes and punctuation.
function core(s,   k, again, t) {
  again = 1
  while (again && length(s) > 0) {
    again = 0
    t = substr(s, length(s))
    if (index(" \t\n*_`\"\047)]}>.,;:!?", t)) { s = substr(s, 1, length(s) - 1); again = 1; continue }
    for (k = 1; k <= nc; k++) if (ends(s, CL[k])) { s = substr(s, 1, length(s) - length(CL[k])); again = 1; break }
  }
  return s
}
function add(x, term,   y) {
  y = x; sub(/^[ \t\n]+/, "", y); sub(/[ \t\n]+$/, "", y)
  if (!(y ~ /[A-Za-z0-9\200-\377]/)) return
  if (y ~ /^[0-9]+[.)]?$/) return
  m++; S[m] = y; T[m] = term
}
# "Wait a moment", "for your reference", "bear with us" end like a request
# but ask for nothing: the word before the ending (past a polite "juusigi" /
# "hasigi") starts with one of those words. "Check it, then decide for me"
# keeps asking: its last word is the thing asked.
function fyi(cr, sl,   t, k, n, W, w) {
  t = substr(cr, 1, length(cr) - sl)
  sub(/ +$/, "", t)
  for (k = 1; k <= nh; k++) if (ends(t, HON[k])) { t = substr(t, 1, length(t) - length(HON[k])); break }
  sub(/ +$/, "", t)
  n = split(t, W, " ")
  w = (n > 0) ? W[n] : ""
  for (k = 1; k <= nf; k++) if (index(w, FYI[k]) == 1) return 1
  return 0
}
function asks(k,   x, cr, low, j, p) {
  x = S[k]
  if (T[k] == "?" || T[k] == FWQ) return 1
  cr = core(x)
  for (j = 1; j <= nk; j++) if (ends(cr, KO[j])) { if ((KO[j] in REQ) && fyi(cr, length(KO[j]))) continue; return 1 }
  low = " " tolower(cr) " "
  for (j = 1; j <= ne; j++) { p = index(low, " " EN[j] " "); if (p > 6 && substr(low, p - 6, 6) == "if you") continue; if (p > 0) return 1 }
  return 0
}
NR == 1 {
  s = $0; len = length(s); fence = 0; W = 2000
  if (len > W) {
    head = substr(s, 1, len - W); s = substr(s, len - W + 1)
    p = index(s, "\\n")
    if (p > 0) { head = head substr(s, 1, p + 1); s = substr(s, p + 2) }
    fence = gsub(/```/, "&", head) % 2
  }
  n = split(unesc(s), L, "\n"); txt = ""
  for (i = 1; i <= n; i++) {
    tr = L[i]; sub(/^[ \t]+/, "", tr)
    if (substr(tr, 1, 3) == "```") { fence = !fence; continue }
    if (!fence) txt = txt L[i] "\n"
  }
  m = 0; cur = ""; tl = length(txt); code = 0; line = ""
  for (i = 1; i <= tl; i++) {
    c = substr(txt, i, 1); cur = cur c; line = line c; term = ""
    if (c == "\n") { add(cur, ""); cur = ""; line = ""; code = 0 }
    else if (c == "`") code = !code
    # No sentence ends inside inline code or in a table row; `a?.b` is not one either.
    else if ((c == "?" || c == "!") && !code && line !~ /^[ \t]*\|/) {
      nx = substr(txt, i + 1, 1)
      if (!(nx ~ /[A-Za-z0-9]/) && !(c == "?" && nx == "." && substr(txt, i + 2, 1) ~ /[A-Za-z0-9_$]/)) term = c
    }
    else if (c == "." && !code) { nx = substr(txt, i + 1, 1); if (nx == "" || nx == " " || nx == "\n") term = c }
    else if (c >= "\200") {
      t3 = substr(txt, i, 3)
      if (t3 == FWQ || t3 == FWE || t3 == IDEO) { term = t3; cur = cur substr(txt, i + 1, 2); i += 2 }
    }
    if (term != "") { add(cur, term); cur = "" }
  }
  add(cur, "")
  for (k = m; k >= 1 && k > m - 2; k--) if (asks(k)) exit 0
  exit 1
}'

ask_detect() { [ -n "$1" ] && printf '%s\n' "$1" | awk "$ASK_AWK" 2>/dev/null; }

# Checksum of the start of a prompt, to compare a scheduled prompt (Stop's
# session_crons) with the prompt a later UserPromptSubmit carries.
prompt_sum() { printf '%s' "$(json_trim "$1" 200 800)" | cksum | awk '{ print $1 }'; }

# One field of a background task (Stop `background_tasks`, Grok
# `backgroundTasks`), in document order: a task's id and type come before its
# description and command. Claude Code 2.1.316 type labels: work that
# reports back and wakes the agent (subagent, workflow, cloud session,
# MCP task: they end), work that may run for good (shell, monitor, an idle
# teammate; and labels we do not know), and its own housekeeping that never
# wakes it (dream, auto-mode scan, memory import, memory save: not counted).
# A shell whose command is_service_cmd counts in BG_SVC; BG_KEEP lists the
# counted tasks and BG_IDMAP the ids by index (bg_ids_finish).
bg_field() { # path=value
  bk=${1#*.}
  bk=${bk%%.*}
  bf=${1#*.*.}
  bf=${bf%%=*}
  bv=${1#*=}
  case $bf in
    id) case $bv in '' | *[!A-Za-z0-9_-]*) ;; *) BG_IDMAP="$BG_IDMAP $bk=$bv" ;; esac ;;
    type)
      case $bv in
        dream | 'auto-mode scan' | 'memory import' | 'memory save') return 0 ;;
        subagent | workflow | 'cloud session' | 'MCP task') BG_FINITE=$((BG_FINITE + 1)) ;;
        shell) BG_SHELLS="$BG_SHELLS $bk" ;;
      esac
      BG_N=$((BG_N + 1))
      BG_KEEP="$BG_KEEP $bk"
      [ -n "$BG_PICK" ] || BG_PICK=$bk BG_TYPE=$bv
      ;;
    description) [ "$bk" = "$BG_PICK" ] && [ -z "$BG_DESC" ] && BG_DESC=$bv ;;
    command)
      [ "$bk" = "$BG_PICK" ] && [ -z "$BG_CMD" ] && BG_CMD=$bv
      case "$BG_SHELLS " in *" $bk "*) is_service_cmd "$bv" && BG_SVC=$((BG_SVC + 1)) ;; esac
      ;;
  esac
  return 0
}

# The ids of the counted tasks in BG_IDS; BG_NOID counts those with none.
bg_ids_finish() {
  BG_IDS='' BG_NOID=0
  for bk in $BG_KEEP; do
    bi=''
    for bp in $BG_IDMAP; do
      [ "${bp%%=*}" = "$bk" ] && bi=${bp#*=}
    done
    if [ -n "$bi" ]; then BG_IDS="$BG_IDS $bi"; else BG_NOID=$((BG_NOID + 1)); fi
  done
}

# One field of a scheduled wake-up (Stop `session_crons`, Grok
# `sessionCrons`): how many, the first one's schedule, and a checksum of each
# prompt (the prompt of the turn it starts is that text).
cron_field() { # path=value
  ck=${1#*.}
  ck=${ck%%.*}
  cf=${1#*.*.}
  cf=${cf%%=*}
  cv=${1#*=}
  [ $((ck + 1)) -gt "$CRON_N" ] && CRON_N=$((ck + 1))
  case $cf in
    schedule) [ "$ck" = 0 ] && CRON_SCHED=$cv ;;
    prompt) [ -n "$cv" ] && CRON_SUMS="$CRON_SUMS $(prompt_sum "$cv")" ;;
  esac
  return 0
}
while IFS= read -r kv; do
  case $kv in
    background_tasks.[0-9].* | backgroundTasks.[0-9].*) bg_field "$kv" ;;
    session_crons.[0-9].* | sessionCrons.[0-9].*) cron_field "$kv" ;;
    prompt=*) PROMPT=${kv#*=} ;;
    source=*) SRC=${kv#*=} ;;
    stop_hook_active=*) STOPACT=${kv#*=} ;;
    is_interrupt=*) ISINT=${kv#*=} ;;
    agent_id=*) AGENTID=${kv#*=} ;;
    # Grok sends both: hook_event_name has Claude's PascalCase names.
    hook_event_name=*) EVENT=${kv#*=} ;;
    hookEventName=*) [ -n "$EVENT" ] || EVENT=${kv#*=} ;;
    notification_type=* | notificationType=*) [ -n "$NTYPE" ] || NTYPE=${kv#*=} ;;
    type=*) NTYPE2=${kv#*=} ;;
    tool_name=* | toolCall.name=*) TOOL=${kv#*=} ;;
    tool_input.command=* | tool_input.file_path=* | tool_input.url=* | toolCall.args.CommandLine=* | toolCall.args.Target=*) [ -n "$DETAIL" ] || DETAIL=${kv#*=} ;;
    toolCall.args.Action=*) DESC=${kv#*=} ;;
    details.filePath=*) DETAIL=${kv#*=} ;;
    details.command=* | details.fileName=* | details.serverName=* | details.urls.0=* | details.prompt=*) [ -n "$DETAIL" ] || DETAIL=${kv#*=} ;;
    details.type=*) GTYPE=${kv#*=} ;;
    details.rootCommand=* | details.toolName=*) [ -n "$TOOL" ] || TOOL=${kv#*=} ;;
    tool_input.description=*) DESC=${kv#*=} ;;
    tool_input.questions.0.question=* | toolCall.args.questions.0.question=*) QTEXT=${kv#*=} ;;
    session_id=* | sessionId=* | conversationId=*) [ -n "$SID" ] || SID=${kv#*=} ;;
    cwd=* | workspacePaths.0=*) [ -n "$CWD" ] || CWD=${kv#*=} ;;
    toolCall.args.Cwd=*) EXTRA=${kv#*=} ;;
    message=*) LAST=${kv#*=} ;;
    last_assistant_message=* | lastAssistantMessage=* | prompt_response=*) LAST=${kv#*=} ;;
    last-assistant-message=*) LAST=${kv#*=} ;;
    input-messages.0=*) FIRSTIN=${kv#*=} ;;
    error=*) ERR=${kv#*=} ;;
    transcript_path=*) TPATH=${kv#*=} ;;
    context_tokens=*) CTXTOK=${kv#*=} ;;
    model=* | to_model=*) MODEL=${kv#*=} ;;
    fullyIdle=*) FULLYIDLE=${kv#*=} ;;
    terminationReason=*) TERMREASON=${kv#*=} ;;
    reason=*) REASON=${kv#*=} ;;
    promptId=*) PROMPTID=${kv#*=}; GKEY=$GKEY.$PROMPTID ;;
    timestamp=*) GKEY=$GKEY.${kv#*=} ;;
  esac
done <<EOF
$(printf '%s' "$INPUT" | awk -v want="$WANT" "$JSON_GET" 2>/dev/null)
EOF

[ "$AGENT" = codex-notify ] && EVENT=notify
# Antigravity hooks name their event on the command line.
[ "$AGENT" = agy ] && EVENT=$MODE
if [ "$AGENT" = grok ]; then
  case $EVENT in
    notification) EVENT=Notification ;;
    stop) EVENT=Stop ;;
    stop_failure) EVENT=StopFailure ;;
    user_prompt_submit) EVENT=UserPromptSubmit ;;
  esac
fi
SID=$(printf '%s' "$SID" | tr -c 'A-Za-z0-9_-' '_' | cut -c1-80)
[ -n "$SID" ] || SID=nosession

CWD_BASE=$(json_trim "${CWD:-$EXTRA}" 64 256 base)
FP=$(printf '%s\t%s' "$TOOL" "$(json_trim "$DETAIL" 200 800)" | cksum | awk '{ print $1 }')

# A `done` waits done_delay seconds (done_later) in case another Stop hook
# keeps the agent going; any later event of the main thread ends that wait.
# Only the turn-end events that send a `done` themselves leave it be (a newer
# one replaces it), and so do the events of a subagent (agent_id is set,
# whether it runs in the foreground or the background): a background
# subagent's tool calls carry the session id and are no sign of the main
# thread going on.
case $AGENT:$EVENT in
  claude:Stop | codex:Stop | grok:Stop | gemini:AfterAgent) ;;
  *)
    if [ -z "$AGENTID" ] && [ -f "$RUN_DIR/$SID.pend" ]; then rm -f "$RUN_DIR/$SID.pend" 2>/dev/null; fi
    ;;
esac

# Lets a waiting permission hook see that the agent moved on. A new turn
# starts the file over, so it holds at most one turn of tool calls, and ends
# a background pause (bg_pause), taking back its OSC 7501 record.
note() { # turn | tool fingerprint
  if [ "$1" = turn ]; then
    printf '%s turn -\n' "$(date +%s)" >"$RUN_DIR/$SID.res" 2>/dev/null
    rm -f "$RUN_DIR/$SID.goal" "$RUN_DIR/$SID.done" 2>/dev/null
    if [ -f "$RUN_DIR/$SID.bg" ]; then
      [ "$(sed -n 2p "$RUN_DIR/$SID.bg" 2>/dev/null)" = 7501 ] &&
        BG_SEQ="\\u001b]7501;state=clear:id=$BG_ID\\u0007"
      rm -f "$RUN_DIR/$SID.bg" 2>/dev/null
    fi
  else
    printf '%s tool %s\n' "$(date +%s)" "$2" >>"$RUN_DIR/$SID.res" 2>/dev/null
  fi
}

# Claude Code ended a turn while work it started still runs (Stop
# `background_tasks`, Claude Code 2.1.145+: shells, subagents, monitors,
# workflows). It takes the turn up again when that work reports back, so the
# session is not done: no `done` event, a `background` state instead, and no
# idle question until the next turn note. $RUN_DIR/$SID.bg holds the state's
# message meanwhile, and `7501` on its second line when the hook wrote the
# OSC 7501 record below.
#
# Claude Code 2.1.295+ reports itself through OSC 7501 and SimpleTerm then
# follows that, not `simpleterm:state`. For its own turn it reports `done`
# (it counts background subagents as working, shells and monitors not), so
# the hook adds a `working` record of its own, id $BG_ID: SimpleTerm shows the
# most urgent record of a terminal. Claude Code runs Stop hooks before it
# reports the turn's end, so the record is there first. Only where Claude
# Code speaks OSC 7501 itself: elsewhere a record of the hook's would make
# SimpleTerm stop reading `simpleterm:state`.
BG_ID=simpleterm-bg
bg_paused() { [ -f "$RUN_DIR/$SID.bg" ]; }

claude_speaks_7501() {
  [ -z "${TMUX:-}" ] && [ -z "${STY:-}" ] || return 1
  case ${CLAUDE_CODE_DISABLE_TERMINAL_TITLE:-} in '' | 0 | false | FALSE | False) ;; *) return 1 ;; esac
  f=$(input_file "$TPATH")
  [ -n "$f" ] || return 1
  # Each transcript entry carries the version that wrote it.
  tail -c 65536 "$f" 2>/dev/null | awk '
    { s = $0; while (match(s, /"version"[ ]*:[ ]*"[0-9][0-9.]*"/)) { v = substr(s, RSTART, RLENGTH - 1); s = substr(s, RSTART + RLENGTH); sub(/.*"/, "", v) } }
    END { n = split(v, x, "."); exit !(n >= 3 && (x[1] > 2 || (x[1] == 2 && (x[2] > 1 || (x[2] == 1 && x[3] >= 295))))) }'
}

# Text (JSON-escaped) as standard base64 for an OSC 7501 field; nothing for
# escapes other than \" \\ \/ or without openssl.
b64_text() {
  t=$(printf '%s\n' "$1" | awk '{
    s = $0; out = ""
    for (i = 1; i <= length(s); i++) {
      c = substr(s, i, 1)
      if (c == "\\") {
        e = substr(s, i + 1, 1)
        if (e != "\\" && e != "/" && e != "\"") exit 1
        c = e; i++
      }
      out = out c
    }
    print out
  }' 2>/dev/null) || return 0
  command -v openssl >/dev/null 2>&1 || return 0
  printf '%s' "$t" | openssl base64 -A 2>/dev/null
}

# The first counted task (or, with only scheduled wake-ups, the first
# schedule) as a short line for the badge and the pause note: BG_M.
bg_summary() {
  if [ "$BG_N" -gt 0 ]; then
    BG_M=${BG_DESC:-$BG_CMD}
    [ -n "$BG_M" ] || BG_M=task
    [ -n "$BG_TYPE" ] && BG_M="$BG_TYPE: $BG_M"
    if [ "$BG_N" -ge 10 ]; then
      BG_M="$BG_M (+9 or more)"
    elif [ "$BG_N" -gt 1 ]; then
      BG_M="$BG_M (+$((BG_N - 1)) more)"
    fi
  else
    BG_M="scheduled: ${CRON_SCHED:-wake-up}"
    [ "$CRON_N" -gt 1 ] && BG_M="$BG_M (+$((CRON_N - 1)) more)"
  fi
  BG_M=$(json_trim "$BG_M" 80 320)
}

# The turn ended and the agent waits for background work or a schedule. Not
# done: the badge says `background` (note in $SID.bg), unless the last
# message asks the user something (pause ask): then the user is told, as
# `question`, the badge says `waiting`, and Claude Code 2.1.295+ gets a
# `blocked` OSC 7501 record (kind question) instead of the `working` one.
bg_pause() {
  bg_summary
  flag=''
  if [ "$AGENT" = claude ] && [ "${SIMPLETERM:-}" = 1 ] && claude_speaks_7501; then
    flag=7501
    if [ "${1:-}" = ask ]; then
      e=$(b64_text "$(json_trim "$LAST" 200 800)")
      case $e in *[!A-Za-z0-9+/=]*) e='' ;; esac
      BG_SEQ="\\u001b]7501;state=blocked:id=$BG_ID:kind=question${e:+:msg=$e}\\u0007"
    else
      e=$(b64_text "$BG_M")
      case $e in *[!A-Za-z0-9+/=]*) e='' ;; esac
      BG_SEQ="\\u001b]7501;state=working:id=$BG_ID${e:+:msg=$e}\\u0007"
    fi
  fi
  # Line 1: the badge's message (the question when asking), 2: the OSC 7501
  # flag, 3: the pause's token, 4: `ask` while the badge says `waiting`.
  if [ "${1:-}" = ask ]; then bm=$(json_trim "$LAST" 80 320); else bm=$BG_M; fi
  printf '%s\n%s\n%s\n%s\n' "$bm" "$flag" "$RID" "${1:-}" >"$RUN_DIR/$SID.bg" 2>/dev/null
  if [ "${1:-}" = ask ]; then
    MSG=$(json_trim "$LAST" 200 800)
    send_bg question
    print_state waiting "$LAST"
    return 0
  fi
  bgm=$BG_M # print_state reuses m
  print_state background "$bgm"
  [ "$BG_N" -gt 0 ] && [ "$BG_FINITE" -eq 0 ] && bg_later "$RID" "$bgm"
  return 0
}

# Only work that may run for good is left (a dev server, a monitor, an idle
# teammate, or agy's own `fullyIdle: false`): it may never wake the agent,
# and then nothing else would come. After bg_done_after seconds (default
# 600) of the same pause, `done` goes once, saying what still runs. A new
# turn or another pause ends the wait. The event is made then (fresh rid and
# time: a link refuses events more than 5 minutes old).
bg_later() { # token what
  [ -n "$LINKS" ] || return 0
  w=$(conf_int bg_done_after 600)
  [ "$w" -gt 0 ] || return 0
  MSG=$(done_msg "$2")
  trap '' HUP
  (
    sleep "$w"
    [ "$(sed -n 3p "$RUN_DIR/$SID.bg" 2>/dev/null)" = "$1" ] || exit 0
    rm -f "$RUN_DIR/$SID.bg" 2>/dev/null
    later_send done
  ) </dev/null >/dev/null 2>&1 &
}

# The last message and what still runs, as the text of a `done`: the suffix
# is kept whole and the message gives way (200 characters, 800 bytes in all).
done_msg() { # what
  dm=$(json_trim "(still running in the background: $1)" 120 480)
  dr=$((200 - ${#dm} - 1))
  if [ -n "$LAST" ] && [ "$dr" -gt 20 ]; then
    printf '%s %s' "$(json_trim "$LAST" "$dr" $((800 - ${#dm} - 1)))" "$dm"
  else
    printf '%s' "$dm"
  fi
}

# Sends `done` (text MSG) done_delay seconds from now (default 3; 0: at once)
# unless something of the session happens first: another Stop hook may have
# kept the agent going, and then its next event (or Stop) comes within
# moments. The event is made then (fresh rid and time). Only where the agent
# has such an event to send (Claude Code, Grok Build): Codex, Gemini CLI and
# OpenCode register none that would come within moments, so their default is
# 0 (a second Stop still replaces the first within the wait if one is set).
done_later() {
  [ -n "$LINKS" ] || return 0
  case $AGENT in codex | gemini | opencode) dw=0 ;; *) dw=3 ;; esac
  dw=$(conf_int done_delay $dw)
  if [ "$dw" -le 0 ] || ! printf '%s\n' "$RID" >"$RUN_DIR/$SID.pend" 2>/dev/null; then
    send_bg done
    return 0
  fi
  trap '' HUP
  (
    sleep "$dw"
    [ "$(cat "$RUN_DIR/$SID.pend" 2>/dev/null)" = "$RID" ] || exit 0
    rm -f "$RUN_DIR/$SID.pend" 2>/dev/null
    later_send done
  ) </dev/null >/dev/null 2>&1 &
}

later_send() { # ev
  TS=$(date +%s)
  NOW=$TS
  is_uint "$TS" || TS=0
  RID=$(rand_hex 8)
  is_hex "$RID" 16 || return 0
  send_bg "$1"
}

# Codex `/goal` (on by default since 0.16x): while a goal is active Codex
# starts the next turn itself, and each turn ends with a Stop. The rollout
# (transcript) records `thread_goal_updated` with the goal's status, and the
# model ends a goal with an `update_goal` call; the turns between are not
# done. Measured with Codex 0.165.0.
codex_goal_active() { # rollout file
  [ -n "$1" ] || return 1
  awk '
    /"type":"thread_goal_updated"/ { active = ($0 ~ /"status":"active"/); called = 0; next }
    /"name":"update_goal"/ { called = 1 }
    END { exit !(active && !called) }' "$1" 2>/dev/null
}

# A goal can also end without a trace in the rollout (blocked after an
# error, a usage or token budget limit, `/goal clear`), and then no next
# turn starts. Measured: Codex starts a goal's next turn within milliseconds
# (task_started). If none started codex_goal_check seconds (default 5) after
# this Stop, the turn was the last: `done` goes then.
codex_goal_later() { # rollout file
  [ -n "$LINKS" ] || return 0
  gf=$1
  off=$(wc -c <"$gf" 2>/dev/null | tr -d ' ')
  is_uint "$off" || return 0
  w=$(conf_int codex_goal_check 5)
  MSG=$(json_trim "$LAST" 200 800)
  printf '%s\n' "$RID" >"$RUN_DIR/$SID.goal" 2>/dev/null
  trap '' HUP
  (
    sleep "$w"
    [ "$(cat "$RUN_DIR/$SID.goal" 2>/dev/null)" = "$RID" ] || exit 0
    tail -c +$((off + 1)) "$gf" 2>/dev/null | awk '/"type":"task_started"/ { found = 1 } END { exit !found }' && exit 0
    rm -f "$RUN_DIR/$SID.goal" 2>/dev/null
    later_send done
  ) </dev/null >/dev/null 2>&1 &
}

# The status of a running turn: while a paused session's background
# subagents run tools, the pause's own badge (`waiting` when the turn paused
# on a question, `background` otherwise); `running` otherwise.
print_running() {
  if bg_paused; then
    bm=$(head -c 400 "$RUN_DIR/$SID.bg" 2>/dev/null | head -n 1)
    if [ "$(sed -n 4p "$RUN_DIR/$SID.bg" 2>/dev/null)" = ask ]; then print_state waiting "$bm"; else print_state background "$bm"; fi
  else
    print_state running
  fi
}

# A turn ended: housekeeping.
turn_end() {
  ensure_cli
  find "$RUN_DIR" -type f -mtime +0 -exec rm -f {} + 2>/dev/null
}

# --- who started a turn, and what ran before it ------------------------------

# Sets PROMPT_USER: 1 if a person typed the prompt (or we cannot tell), 0 if
# the agent started the turn itself: background work reporting back, a
# scheduled wake-up. Claude Code 2.1.3xx names it in UserPromptSubmit
# `source` (user and sdk are people; system, loop_wakeup, schedule_wakeup and
# poll_event are not); where `source` is missing (2.1.316 sends none) a
# <task-notification> or <agent-message> prompt, the /loop sentinel, or the
# prompt of a wake-up listed at the last Stop (session_crons) says so. Grok
# Build has no such field: the prompt id of a turn it starts itself begins
# with a fixed word (task-completed-, scheduler-fired-, ...; static, from the
# 1.0.70 binary), a person's is a UUID.
PROMPT_USER=1
prompt_origin() {
  PROMPT_USER=1
  if [ "$AGENT" = grok ]; then
    case $PROMPTID in
      task-completed-* | bash-completed-* | monitor-completed-* | subagent-completed-* | workflow-completed-* | \
        parent-agent-message-* | parent-message-* | notifications-* | goal-summary-* | goal-classifier-nudge-* | \
        plan-resume-* | scheduler-fired-*) PROMPT_USER=0 ;;
    esac
    return 0
  fi
  case $SRC in
    user | sdk) ;;
    '')
      case $PROMPT in
        '<task-notification>'* | '<agent-message '* | '<<autonomous-loop'*) PROMPT_USER=0 ;;
        '') ;;
        *)
          if [ -f "$RUN_DIR/$SID.crons" ]; then
            case " $(cat "$RUN_DIR/$SID.crons" 2>/dev/null) " in *" $(prompt_sum "$PROMPT") "*) PROMPT_USER=0 ;; esac
          fi
          ;;
      esac
      ;;
    *) PROMPT_USER=0 ;;
  esac
}

# $SID.turn: line 1 `user` or `auto` (who started this turn), line 2 the ids
# of the background tasks that already ran when it started ($SID.stopids, the
# last Stop's list), for the Stop that ends it.
turn_mark() {
  tm_ids=''
  [ -f "$RUN_DIR/$SID.stopids" ] && IFS= read -r tm_ids <"$RUN_DIR/$SID.stopids"
  if [ "$PROMPT_USER" = 1 ]; then tm_who=user; else tm_who=auto; fi
  printf '%s\n%s\n' "$tm_who" "$tm_ids" >"$RUN_DIR/$SID.turn" 2>/dev/null
}

# True if every counted task was already running before the turn began.
bg_all_old() {
  [ "$BG_N" -gt 0 ] && [ "$BG_NOID" -eq 0 ] || return 1
  for bi in $BG_IDS; do
    case " $PREV_IDS " in *" $bi "*) ;; *) return 1 ;; esac
  done
  return 0
}

# A `done` for the turn that just ended ($1: what still runs, if anything).
stop_done() {
  if [ -n "${1:-}" ]; then MSG=$(done_msg "$1"); else MSG=$(json_trim "$LAST" 200 800); fi
  [ "$STOPACT" = true ] && XFLAGS=',"stop_hook_active":true'
  done_later
  # The turn's done is sent (or pending): Claude Code's idle_prompt, 60 s
  # later, repeats it (the next turn note takes the mark back).
  # (printf, not `:`: a failed redirection of a special builtin ends the shell.)
  printf '' 2>/dev/null >"$RUN_DIR/$SID.done"
  usage_report
  print_state done
  turn_end
}

# A Stop (Claude Code, Codex, Grok): done, or not yet. Not done while the
# agent waits for work it started or for a schedule, unless
#  - a person typed this turn and only work that ran before it is left (the
#    answer to the person is not held back by an older task; scheduled
#    turns and turns started by a task's report are not this),
#  - only services are left (a dev server, a watcher: nothing the agent
#    waits for), or
#  - the last message asks the user something: then they are told (pause ask).
# A turn the agent started itself while a schedule (/loop, cron) is set stays
# quiet: `background` with "scheduled: ..."; the Stop that finds the
# schedule gone is the done. TURN_USER defaults to 1 (a person) when the
# turn's start was not seen.
stop_flow() {
  TURN_USER=1 PREV_IDS='' t1='' t2=''
  if [ -f "$RUN_DIR/$SID.turn" ]; then
    { IFS= read -r t1; IFS= read -r t2; } <"$RUN_DIR/$SID.turn"
    [ "$t1" = auto ] && TURN_USER=0
    PREV_IDS=$t2
  fi
  bg_ids_finish
  printf '%s\n' "$BG_IDS" >"$RUN_DIR/$SID.stopids" 2>/dev/null
  if [ "$CRON_N" -gt 0 ]; then
    printf '%s\n' "$CRON_SUMS" >"$RUN_DIR/$SID.crons" 2>/dev/null
  elif [ -f "$RUN_DIR/$SID.crons" ]; then
    rm -f "$RUN_DIR/$SID.crons" 2>/dev/null
  fi
  if [ "$BG_N" -eq 0 ] && [ "$CRON_N" -eq 0 ]; then
    stop_done
    return 0
  fi
  if [ "$TURN_USER" = 1 ] && { [ "$BG_N" -eq 0 ] || bg_all_old; }; then
    bg_summary
    if [ "$BG_N" -gt 0 ]; then stop_done "$BG_M"; else stop_done; fi
    return 0
  fi
  if [ "$BG_N" -gt 0 ] && [ "$BG_SVC" -eq "$BG_N" ] && { [ "$CRON_N" -eq 0 ] || [ "$TURN_USER" = 1 ]; }; then
    bg_summary
    stop_done "$BG_M"
    return 0
  fi
  usage_report
  # OpenCode's LAST is the session's title, not a message to the person.
  if [ "$AGENT" != opencode ] && ask_detect "$LAST"; then bg_pause ask; else bg_pause; fi
  turn_end
}

case $AGENT:$EVENT in
  claude:PermissionRequest | codex:PermissionRequest | opencode:PermissionRequest)
    if [ "$MODE" = signal ]; then
      print_state waiting "approve $TOOL: $DETAIL"
    elif [ "$TOOL" = AskUserQuestion ]; then
      MSG=$(json_trim "${QTEXT:-$DESC}" 200 800)
      ask_once && send_bg question
    else
      d=$DETAIL
      [ "$TOOL" = apply_patch ] && d=${DESC:-patch}
      [ -n "$d" ] || d=$DESC
      MSG=$(json_trim "approve $TOOL: $d" 200 800)
      [ -n "$LINKS" ] && permission_flow
    fi
    ;;
  claude:PreToolUse)
    if [ "$TOOL" = AskUserQuestion ]; then
      MSG=$(json_trim "$QTEXT" 200 800)
      ask_once && send_bg question
      print_state waiting
    fi
    ;;
  claude:Notification)
    # permission_prompt is ignored: PermissionRequest already reported that
    # wait (one relay event per agent wait). idle_prompt keeps the done badge.
    case $NTYPE in
      idle_prompt)
        # Claude Code sends it 60 s after a turn while only background shells
        # or monitors run: the work is not waiting for the user.
        bg_paused && finish
        # Already told by this turn's done: the prompt repeats it. Without a
        # done (interrupt, StopFailure, no Stop hook) it stays the safety net.
        [ -f "$RUN_DIR/$SID.done" ] && finish
        MSG=$(json_trim "$LAST" 200 800)
        send_bg question
        ;;
      elicitation_dialog | elicitation_url_dialog)
        print_state waiting
        MSG=$(json_trim "$LAST" 200 800)
        send_bg question
        ;;
      agent_needs_input)
        # Another background session of the user's needs input, not this
        # one: the alert stays, this tab's badge does not change.
        MSG=$(json_trim "$LAST" 200 800)
        send_bg question
        ;;
    esac
    ;;
  claude:UserPromptSubmit)
    note turn
    prompt_origin
    turn_mark
    usage_report
    print_state running
    ;;
  claude:PostToolUse | claude:PostToolUseFailure)
    if [ "$EVENT" = PostToolUseFailure ] && [ "$ISINT" = true ] && [ -z "$AGENTID" ]; then
      # Esc during a tool call: the turn is over (no Stop follows). Not when
      # a subagent's tool was interrupted (agent_id is set): the main
      # session's wait goes on.
      note turn
      print_state idle
      finish
    fi
    note tool "$FP"
    # Context grows with each tool call; look again every 20 seconds at most.
    t=$(cat "$RUN_DIR/$SID.ut" 2>/dev/null)
    if ! is_uint "$t" || [ $((NOW - t)) -ge 20 ] || [ "$t" -gt "$NOW" ]; then
      printf '%s\n' "$NOW" >"$RUN_DIR/$SID.ut" 2>/dev/null
      usage_report
    fi
    print_running
    ;;
  claude:SessionStart | claude:PostCompact | claude:PostModelSwitch)
    usage_report
    print_usage
    [ "$EVENT" = SessionStart ] && ensure_cli
    ;;
  claude:Stop | codex:Stop)
    note turn
    case $LAST in '{\"title\":'*) finish ;; esac
    gf=''
    [ "$AGENT" = codex ] && gf=$(input_file "$TPATH")
    if [ "$AGENT" = codex ] && codex_goal_active "$gf"; then
      usage_report
      codex_goal_later "$gf"
      turn_end
      finish
    fi
    stop_flow
    ;;
  claude:StopFailure)
    note turn
    ev=error
    case $ERR in authentication_failed | oauth_org_not_allowed | cloud_credential_error) ev=auth ;; esac
    MSG=$(json_trim "$ERR: $LAST" 200 800)
    send_bg "$ev"
    usage_report
    print_state done
    ;;
  codex:SessionStart | codex:PostCompact)
    usage_report
    ;;
  codex-notify:notify)
    [ "$NTYPE2" = agent-turn-complete ] || finish
    case $FIRSTIN in 'Generate a concise, single-line task title'*) finish ;; esac
    MSG=$(json_trim "$LAST" 200 800)
    send_bg done
    ;;
  gemini:Notification)
    # Gemini CLI asks after this hook returns and takes no answer from it:
    # an alert only (`question`, the event for "needs input").
    [ "$NTYPE" = ToolPermission ] || finish
    case $GTYPE in edit) TOOL=edit ;; info) TOOL=${TOOL:-fetch} ;; esac
    MSG=$(json_trim "approve ${TOOL:-$GTYPE}: ${DETAIL:-$LAST}" 200 800)
    send_bg question
    ;;
  gemini:AfterAgent)
    case $LAST in
      '[no response text]'*)
        # What Gemini CLI passes when the turn produced no answer: an API
        # error, a cancelled stream or a detected loop.
        MSG=$(json_trim "no_response: the turn ended without an answer" 200 800)
        send_bg error
        ;;
      *)
        MSG=$(json_trim "$LAST" 200 800)
        [ "$STOPACT" = true ] && XFLAGS=',"stop_hook_active":true'
        done_later
        ;;
    esac
    usage_report
    turn_end
    ;;
  agy:PreToolUse)
    case $TOOL in
      run_command)
        # Opt-in (agy_wait): this hook runs before every command, before the
        # permission policy, so waiting here delays commands the policy
        # would allow, and the terminal shows no prompt meanwhile.
        [ -n "$LINKS" ] && [ "$(conf_int agy_wait 0)" -gt 0 ] || finish
        MSG=$(json_trim "approve $TOOL: $DETAIL" 200 800)
        permission_flow
        ;;
      ask_question)
        MSG=$(json_trim "$QTEXT" 200 800)
        send_bg question
        ;;
      ask_permission)
        MSG=$(json_trim "approve ${DESC:-$TOOL}: $DETAIL" 200 800)
        send_bg question
        ;;
    esac
    ;;
  agy:Stop)
    # Only a fully idle agent is done (background tasks may still run).
    # Cancelling (Esc) sends no Stop at all.
    note turn
    if [ -n "$ERR" ] && [ "$ERR" != null ]; then
      MSG=$(json_trim "${TERMREASON:-error}: $ERR" 200 800)
      send_bg error
    elif [ "$FULLYIDLE" = true ]; then
      MSG=''
      send_bg done
    elif [ "$FULLYIDLE" = false ]; then
      # Background commands, schedules or subagents still run; agy does not
      # say which, so the wait is bounded as for a dev server.
      BG_N=1
      bg_pause
    fi
    turn_end
    ;;
  grok:UserPromptSubmit)
    # Also the turn Grok starts itself when background work reports back
    # (promptId task-completed-<id> or subagent-completed-<id>).
    note turn
    prompt_origin
    turn_mark
    ;;
  grok:Notification)
    # Grok asks in its own prompt and takes no answer from a hook:
    # permission_prompt (only while its permission UI waits) and idle_prompt
    # are alerts. The key includes the event's timestamp, the same in every
    # copy of one event.
    case $NTYPE in
      permission_prompt) ;;
      idle_prompt) bg_paused && finish; [ -f "$RUN_DIR/$SID.done" ] && finish ;;
      *) finish ;;
    esac
    once "$(printf '%s|%s|%s|%s|%s' "$EVENT" "$SID" "$NTYPE" "$GKEY" "$LAST" | cksum | awk '{ print $1 }')" || finish
    MSG=$(json_trim "$LAST" 200 800)
    send_bg question
    ;;
  grok:Stop | grok:StopFailure)
    # A Stop also comes when the session closes (reason channel_closed or
    # shutdown); only end_turn ends a turn.
    [ "$EVENT" = Stop ] && [ -n "$REASON" ] && [ "$REASON" != end_turn ] && finish
    once "$(printf '%s|%s|%s|%s|%s' "$EVENT" "$SID" "$GKEY" "$ERR" "$LAST" | cksum | awk '{ print $1 }')" || finish
    note turn
    # Grok 1.0.70 lists work still in flight in backgroundTasks, as Claude
    # Code does, and takes the turn up again when it reports back.
    if [ "$EVENT" = Stop ]; then
      stop_flow
    else
      ev=error
      case $ERR in authentication_failed | oauth_org_not_allowed | cloud_credential_error) ev=auth ;; esac
      MSG=$(json_trim "$ERR: $LAST" 200 800)
      send_bg "$ev"
      turn_end
    fi
    ;;
  opencode:Notification)
    MSG=$(json_trim "$LAST" 200 800)
    send_bg question
    ;;
  opencode:Stop)
    # The plugin lists the background shells still open (background_tasks):
    # a dev server does not hold the done back, other work waits as for
    # Claude Code. OpenCode does not say who started a turn (the plugin's
    # UserPromptSubmit stands for every turn start): shells that were open at
    # the last Stop do not hold this one back.
    note turn
    stop_flow
    ;;
  opencode:UserPromptSubmit)
    # Sent by the plugin when a session's own turn starts (a person's, or the
    # session taken up again by a background shell): ends a pause, and the
    # shells open at the last Stop do not hold this turn's Stop back.
    note turn
    PROMPT_USER=1
    turn_mark
    ;;
  opencode:StopFailure)
    note turn
    ev=error
    case $ERR in ProviderAuthError | *[Aa]uth*) ev=auth ;; esac
    MSG=$(json_trim "$ERR: $LAST" 200 800)
    send_bg "$ev"
    ;;
esac
finish
