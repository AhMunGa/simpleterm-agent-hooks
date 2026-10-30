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
# Bumped when the ~/.simpleterm/bin/simpleterm wrapper must be rewritten.
CLI_REV=1
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

# Plain text (no control characters) cut to at most $2 bytes without
# splitting a UTF-8 sequence; for terminal sequences.
UTF8_CUT='
{
  s = (NR > 1 ? s " " : "") $0
}
END {
  n = length(s); i = 1; out = ""
  while (i <= n) {
    c = substr(s, i, 1); w = 1
    if (c >= "\300") { if (c < "\340") w = 2; else if (c < "\360") w = 3; else w = 4 }
    else if (c >= "\200") { i++; continue }
    if (length(out) + w > maxb) break
    out = out substr(s, i, w); i += w
  }
  printf "%s", out
}'

plain_cut() { # text maxb
  printf '%s' "$1" | tr -d '\000-\010\013-\037\177' | tr '\t\n' '  ' |
    awk -v maxb="$2" "$UTF8_CUT" 2>/dev/null
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
    410) : >"$RUN_DIR/$L_LINK.revoked" ;;
  esac
  rm -f "$4"
  log "ingest ev=$2 link=$(printf %.8s "$L_LINK") http=$code push=${push:--}"
  printf '%s' "${push:-http$code}"
}

# Sends event $1 to every link in the background and returns at once.
# Tunnels go first: the app reports a shown event to the relay ("seen"),
# which holds a push for a few seconds to hear that, so a device that is
# connected gets no second alert. $3 limits it to `tunnel` or `relay` links.
send_bg() { # ev [rid] [all|tunnel|relay]
  [ -n "$LINKS" ] || return 0
  sb_rid=${2:-$RID}
  sb_scope=${3:-all}
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
        ingest_one "$sb_rid" "$1" '' "$RUN_DIR/ing.$$.$sb_rid.$(printf %.8s "$L_LINK")" >/dev/null
      done
    done
    trim_log
  ) </dev/null >/dev/null 2>&1 &
}

# --- terminal sequence (Claude Code only, SimpleTerm sessions only) ---------

# USAGE_SEQ is the JSON-escaped usage OSC to append, if any (usage_report).
print_state() { # running|waiting|done [message]
  [ "$AGENT" = claude ] || return 0
  [ "${SIMPLETERM:-}" = 1 ] || return 0
  m=''
  [ -n "${2:-}" ] && m=' '$(json_trim "$2" 80 320)
  printf '{"terminalSequence":"\\u001b]9;simpleterm:state=%s%s\\u0007%s"}\n' "$1" "$m" "$USAGE_SEQ"
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
          : >"$RUN_DIR/$L_LINK.revoked"
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
  printf '%s\n' "$osc" >"$RUN_DIR/$SID.usage" 2>/dev/null
  USAGE_SEQ='\u001b]9;'$osc'\u0007'
  urid=$(rand_hex 8)
  is_hex "$urid" 16 && send_bg usage "$urid" tunnel
}

# --- the `simpleterm` command --------------------------------------------------

# Keeps ~/.simpleterm/bin/simpleterm pointing at this plugin's
# simpleterm-notify.sh. Rewritten only when missing, when the script it
# names is gone (the plugin moved: updated or removed) or when older.
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
    [ -n "$cur" ] && [ -f "$cur" ] && is_uint "$rev" && [ "$rev" -ge "$CLI_REV" ] && return 0
  fi
  mkdir -p "$ST_DIR/bin" 2>/dev/null || return 0
  {
    printf '#!/bin/sh\n'
    printf '# simpleterm: written by the SimpleTerm agent hooks plugin, which keeps it\n'
    printf '# pointing at the plugin (see its README). Edits are overwritten.\n'
    printf '# rev=%s\n' "$CLI_REV"
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
  t=$(plain_cut "${2:-}" 256)
  b=$(plain_cut "${3:-}" 800)
  [ -n "$t$b" ] || finish
  if [ "${SIMPLETERM:-}" = 1 ] && { : >/dev/tty; } 2>/dev/null; then
    if [ -n "${TMUX:-}" ]; then
      # tmux forwards it only with `set -g allow-passthrough on`.
      printf '\033Ptmux;\033\033]777;notify;%s;%s\007\033\\' "$t" "$b" >/dev/tty 2>/dev/null
    else
      printf '\033]777;notify;%s;%s\007' "$t" "$b" >/dev/tty 2>/dev/null
    fi
  fi
  TITLE=$(json_text "$t" 64 256)
  MSG=$(json_text "$b" 200 800)
  CWD_BASE=$(json_text "$PWD" 64 256 base)
  send_bg notify
  finish
fi

# Fields of the agent's event JSON. Agents name the same things differently
# (Grok sends camelCase and snake_case, Antigravity camelCase).
case $AGENT in
  claude | opencode)
    WANT='hook_event_name,notification_type,tool_name,tool_input.command,tool_input.file_path,tool_input.url,tool_input.description,tool_input.questions.0.question,session_id,cwd,message,last_assistant_message,error,transcript_path,context_tokens,model,to_model'
    ;;
  codex)
    WANT='hook_event_name,tool_name,tool_input.command,tool_input.file_path,tool_input.description,session_id,cwd,last_assistant_message,transcript_path'
    ;;
  codex-notify) WANT='type,cwd,last-assistant-message,input-messages.0' ;;
  gemini)
    WANT='hook_event_name,notification_type,message,details.type,details.command,details.rootCommand,details.filePath,details.fileName,details.toolName,details.serverName,details.urls.0,details.prompt,prompt_response,session_id,cwd,transcript_path'
    ;;
  agy)
    WANT='conversationId,workspacePaths.0,toolCall.name,toolCall.args.CommandLine,toolCall.args.Cwd,toolCall.args.questions.0.question,toolCall.args.Action,toolCall.args.Target,terminationReason,error,fullyIdle'
    ;;
  grok)
    WANT='hook_event_name,hookEventName,notificationType,sessionId,cwd,message,lastAssistantMessage,error,reason,promptId,timestamp'
    ;;
esac

EVENT='' NTYPE='' TOOL='' DETAIL='' DESC='' SID='' CWD='' LAST='' ERR='' QTEXT='' FIRSTIN='' NTYPE2=''
TPATH='' CTXTOK='' MODEL='' GTYPE='' FULLYIDLE='' TERMREASON='' EXTRA='' GKEY='' REASON=''
while IFS= read -r kv; do
  case $kv in
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
    promptId=* | timestamp=*) GKEY=$GKEY.${kv#*=} ;;
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
  esac
fi
SID=$(printf '%s' "$SID" | tr -c 'A-Za-z0-9_-' '_' | cut -c1-80)
[ -n "$SID" ] || SID=nosession

CWD_BASE=$(json_trim "${CWD:-$EXTRA}" 64 256 base)
FP=$(printf '%s\t%s' "$TOOL" "$(json_trim "$DETAIL" 200 800)" | cksum | awk '{ print $1 }')

# Lets a waiting permission hook see that the agent moved on. A new turn
# starts the file over, so it holds at most one turn of tool calls.
note() { # turn | tool fingerprint
  if [ "$1" = turn ]; then
    printf '%s turn -\n' "$(date +%s)" >"$RUN_DIR/$SID.res" 2>/dev/null
  else
    printf '%s tool %s\n' "$(date +%s)" "$2" >>"$RUN_DIR/$SID.res" 2>/dev/null
  fi
}

# A turn ended: housekeeping.
turn_end() {
  ensure_cli
  find "$RUN_DIR" -type f -mtime +0 -exec rm -f {} + 2>/dev/null
}

case $AGENT:$EVENT in
  claude:PermissionRequest | codex:PermissionRequest | opencode:PermissionRequest)
    if [ "$MODE" = signal ]; then
      print_state waiting "approve $TOOL: $DETAIL"
    elif [ "$TOOL" = AskUserQuestion ]; then
      MSG=$(json_trim "${QTEXT:-$DESC}" 200 800)
      send_bg question
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
      send_bg question
      print_state waiting
    fi
    ;;
  claude:Notification)
    # permission_prompt is ignored: PermissionRequest already reported that
    # wait (one relay event per agent wait). idle_prompt keeps the done badge.
    case $NTYPE in
      idle_prompt)
        MSG=$(json_trim "$LAST" 200 800)
        send_bg question
        ;;
      elicitation_dialog | elicitation_url_dialog | agent_needs_input)
        print_state waiting
        MSG=$(json_trim "$LAST" 200 800)
        send_bg question
        ;;
    esac
    ;;
  claude:UserPromptSubmit)
    note turn
    usage_report
    print_state running
    ;;
  claude:PostToolUse | claude:PostToolUseFailure)
    note tool "$FP"
    # Context grows with each tool call; look again every 20 seconds at most.
    t=$(cat "$RUN_DIR/$SID.ut" 2>/dev/null)
    if ! is_uint "$t" || [ $((NOW - t)) -ge 20 ] || [ "$t" -gt "$NOW" ]; then
      printf '%s\n' "$NOW" >"$RUN_DIR/$SID.ut" 2>/dev/null
      usage_report
    fi
    print_state running
    ;;
  claude:SessionStart | claude:PostCompact | claude:PostModelSwitch)
    usage_report
    print_usage
    [ "$EVENT" = SessionStart ] && ensure_cli
    ;;
  claude:Stop | codex:Stop)
    note turn
    case $LAST in '{\"title\":'*) finish ;; esac
    MSG=$(json_trim "$LAST" 200 800)
    send_bg done
    usage_report
    print_state done
    turn_end
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
  codex:UserPromptSubmit | codex:SessionStart | codex:PostCompact)
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
    MSG=$(json_trim "$LAST" 200 800)
    send_bg done
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
    if [ -n "$ERR" ] && [ "$ERR" != null ]; then
      MSG=$(json_trim "${TERMREASON:-error}: $ERR" 200 800)
      send_bg error
    elif [ "$FULLYIDLE" = true ]; then
      MSG=''
      send_bg done
    fi
    turn_end
    ;;
  grok:Notification)
    # Grok asks in its own prompt and takes no answer from a hook:
    # permission_prompt (only while its permission UI waits) and idle_prompt
    # are alerts. The key includes the event's timestamp, the same in every
    # copy of one event.
    case $NTYPE in
      permission_prompt | idle_prompt) ;;
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
    if [ "$EVENT" = Stop ]; then
      MSG=$(json_trim "$LAST" 200 800)
      send_bg done
    else
      ev=error
      case $ERR in authentication_failed | oauth_org_not_allowed | cloud_credential_error) ev=auth ;; esac
      MSG=$(json_trim "$ERR: $LAST" 200 800)
      send_bg "$ev"
    fi
    turn_end
    ;;
  opencode:Notification)
    MSG=$(json_trim "$LAST" 200 800)
    send_bg question
    ;;
  opencode:Stop)
    MSG=$(json_trim "$LAST" 200 800)
    send_bg done
    turn_end
    ;;
  opencode:StopFailure)
    ev=error
    case $ERR in ProviderAuthError | *[Aa]uth*) ev=auth ;; esac
    MSG=$(json_trim "$ERR: $LAST" 200 800)
    send_bg "$ev"
    ;;
esac
finish
