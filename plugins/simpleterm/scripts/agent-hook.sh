#!/bin/sh
# SimpleTerm agent hook (POSIX sh), part of the simpleterm-agent-hooks
# plugin; see README.md and, in the SimpleTerm app repository,
# docs/tech_specs/TDS_AGENT_ALERTS.md (sections 5 and 6: relay protocol v1,
# hooks, SSH tunnel) and docs/tech_specs/TDS_AGENT_EVENTS_V2.md (event and
# decision format v2: request contents, decision lists, decision extensions,
# results, states, session records) for the contract.
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
#   sh agent-hook.sh copilot EVENT   GitHub Copilot CLI hook (event JSON on
#                                    stdin; the event is not in it)
#   sh agent-hook.sh notify T [B]    `simpleterm notify` (simpleterm-notify.sh)
#
# Turns agent events into end-to-end encrypted relay events and, for
# permission requests, questions and plans, waits for a decision made on a
# SimpleTerm device.
# Needs curl and openssl; without them it does nothing. It never evaluates
# its input, prints only agent-defined JSON on stdout, and always exits 0.
# Anything that goes wrong leaves the agent's own terminal prompt in charge.

[ -n "${ZSH_VERSION:-}" ] && emulate sh
umask 077
LC_ALL=C
export LC_ALL

# A usage ask runs the agent with SIMPLETERM_PROBE=1 (TDS_AGENT_EVENTS_V2
# section 9.2): hooks it runs do nothing, or the ask would make sessions and
# alerts of its own.
[ "${SIMPLETERM_PROBE:-}" = 1 ] && exit 0

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
HOOK_VERSION=0.5.0
# Bumped when the ~/.simpleterm/bin/simpleterm wrapper must be rewritten.
CLI_REV=2
CR=$(printf '\r')

log() {
  [ -d "$ST_DIR" ] || return 0
  printf '%s %s %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null)" \
    "${AGENT:-?}" "$*" >>"$LOG" 2>/dev/null
  LOGGED=1
}

# $1 tells a background subshell's copy from the hook's own: they share $$,
# and two trims writing one copy can leave an empty log.
trim_log() {
  [ "$LOGGED" = 1 ] || return 0
  n=$(awk 'END { print NR }' "$LOG" 2>/dev/null) || return 0
  [ "${n:-0}" -gt 200 ] 2>/dev/null || return 0
  tl="$LOG.$$${1:+.$1}"
  tail -n 200 "$LOG" >"$tl" 2>/dev/null && mv -f "$tl" "$LOG" 2>/dev/null
  rm -f "$tl" 2>/dev/null
}

# True if path $1 is inside one of agy's workspace folders (AWS, from
# workspacePaths). A path with a .. segment, or none given, counts as outside.
agy_in_workspace() { # path
  case $1 in '' | ../* | */../* | */.. | ..) return 1 ;; /*) ;; *) return 0 ;; esac
  while IFS= read -r aw; do
    aw=${aw%/}
    [ -n "$aw" ] || continue
    case $1 in "$aw" | "$aw"/*) return 0 ;; esac
  done <<EOF
$AWS
EOF
  return 1
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
    } else if (c >= "\302" && c <= "\364") {
      # Well-formed UTF-8 only (as NOTIFY_TEXT and jnorm).
      w = c < "\340" ? 2 : (c < "\360" ? 3 : 4)
      lo = "\200"; hi = "\277"
      if (c == "\340") lo = "\240"; else if (c == "\355") hi = "\237"
      else if (c == "\360") lo = "\220"; else if (c == "\364") hi = "\217"
      x = substr(s, i + 1, 1); ok = (x >= lo && x <= hi)
      for (j = 2; ok && j < w; j++) { x = substr(s, i + j, 1); if (x < "\200" || x > "\277") ok = 0 }
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

# MSG (v1, cut) and MSGF (whole: the v2 builder cuts it and records the
# cut, TDS_AGENT_EVENTS_V2 section 2.2) from JSON-escaped text.
setmsg() {
  MSGF=$1
  MSG=$(json_trim "$1" 200 800)
}

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
  L_FILE=$1 L_RELAY='' L_LINK='' L_SECRET='' L_ENC='' L_MAC='' L_LABEL='' L_V='' L_KIND='' L_FMT=''
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
      fmt=*) L_FMT=${line#fmt=} ;;
    esac
  done <"$1"
  [ "$L_V" = 1 ] || { log "link-skip version"; return 1; }
  # kind=tunnel: the app's end of its SSH connection, forwarded to a loopback
  # port for as long as that connection lives (TDS section 6.5).
  [ "$L_KIND" = tunnel ] || L_KIND=''
  # fmt=2: the receiver takes decision extensions and decidable questions
  # (TDS_AGENT_EVENTS_V2 section 1.2). Anything else is an older receiver.
  [ "$L_FMT" = 2 ] || L_FMT=''
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

# Builds the plaintext for the loaded link: the section 5.2 (v1) fields
# only for notify, usage and test; the v2 fields (TDS_AGENT_EVENTS_V2) too
# for every other event once V2=1 (SPEC). `usage` carries USAGE_JSON instead
# of a message; `notify` adds a title.
plaintext() { # rid ev nonce
  case $2 in
    notify | test) ;;
    *) if [ "$V2" = 1 ]; then v2_plain "$@"; return; fi ;;
  esac
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

# Sends one event to one link; prints "<push result or http<code>> <http
# code> <error code or ->". ING_MT caps the relay's time (the tunnel's is 5).
ingest_raw() { # rid ev nonce outfile
  nh=''
  [ -n "$3" ] && nh=$(sha256_hex "$3")
  pt=$(plaintext "$1" "$2" "$3")
  # Test only: the plaintext before it is sealed, to compare the sh and the
  # PowerShell hook byte for byte (TDS_AGENT_EVENTS_V2 section 2.2): one
  # file per event and link in directory SIMPLETERM_HOOK_TEST_PLAIN.
  [ "${SIMPLETERM_HOOK_TEST:-}" = 1 ] && [ -n "${SIMPLETERM_HOOK_TEST_PLAIN:-}" ] && [ -d "$SIMPLETERM_HOOK_TEST_PLAIN" ] &&
    printf '%s' "$pt" >"$SIMPLETERM_HOOK_TEST_PLAIN/$(printf %.8s "$L_LINK").$2.$1.$$"
  if [ -z "$pt" ] || ! seal "$pt"; then
    log "seal-failed link=$(printf %.8s "$L_LINK")"
    printf 'seal 000 -'
    return 1
  fi
  body='{"v":1,"rid":"'$1'","ev":"'$2'"'
  [ -n "$nh" ] && body=$body',"nh":"'$nh'"'
  body=$body',"env":'$ENV_JSON'}'
  # A tunnel answers at once or not at all (a dead port may belong to
  # something else by now); the relay may hold the request a few seconds.
  mt=${ING_MT:-20}
  is_uint "$mt" && [ "$mt" -ge 1 ] || mt=1
  [ "$mt" -le 20 ] || mt=20
  [ "$L_KIND" = tunnel ] && [ "$mt" -gt 5 ] && mt=5
  code=$(http POST /v1/ingest "$body" "$mt" "$4")
  push='' err=''
  case $code in
    200) push=$(resp_get "$4" push | sed -n 's/^push=//p' | tr -cd 'a-z-') ;;
    410) printf '' 2>/dev/null >"$RUN_DIR/$L_LINK.revoked" ;;
    400) err=$(resp_get "$4" error | sed -n 's/^error=//p' | tr -cd 'a-zA-Z-') ;;
  esac
  rm -f "$4"
  # The last event to a tunnel and its answer: a usage ask needs the app
  # connected (an HTTP 200 within 10 minutes, section 9.2).
  [ "$L_KIND" = tunnel ] && printf '%s %s\n' "$(date +%s)" "$code" >"$RUN_DIR/tun.$(printf %.8s "$L_LINK").last" 2>/dev/null
  log "ingest ev=$2 link=$(printf %.8s "$L_LINK") http=$code push=${push:--}"
  printf '%s %s %s' "${push:-http$code}" "$code" "${err:--}"
  [ "$code" = 200 ]
}

# Sends one event to one link; prints the push result or an error code.
ingest_one() { # rid ev nonce outfile
  io=$(ingest_raw "$@")
  ior=$?
  printf '%s' "${io%% *}"
  return $ior
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
  # One rid per event: a receiver shows a rid once (send_state takes a new
  # one when this run's rid went out already).
  [ "$sb_rid" = "$RID" ] && RID_USED=1
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
        ingest_one "$sb_rid" "$1" '' "$RUN_DIR/ing.$$.$sb_rid.$1.$(printf %.8s "$L_LINK")" >/dev/null &&
          [ -n "$sb_file" ] && printf '%s\n' "$sb_text" >"$sb_file" 2>/dev/null
      done
    done
    trim_log "s$sb_rid"
  ) </dev/null >/dev/null 2>&1 &
}

# --- event format v2 (TDS_AGENT_EVENTS_V2) ---------------------------------------

TAB=$(printf '\t')
NL='
'
# Normalizing and cutting JSON-escaped text (section 2.2), shared by the
# programs below; CTRLRE is set in their BEGIN.
NORM_FN='
function nhex(h,   k, v, c) {
  v = 0; h = tolower(h)
  if (length(h) != 4) return -1
  for (k = 1; k <= 4; k++) {
    c = index("0123456789abcdef", substr(h, k, 1))
    if (c == 0) return -1
    v = v * 16 + c - 1
  }
  return v
}
# JSON-escaped string content s, normalized (TDS_AGENT_EVENTS_V2 section
# 2.2): escapes stay as received; control characters and the escapes that
# stand for them become a space (keepnl keeps \n, \t, \u000a and \u0009);
# lone surrogates and bytes that are not well-formed UTF-8 (overlong forms,
# encoded surrogates included) become a space, one per byte; a broken
# escape ends the text. In 512-byte pieces, so that long values stay linear
# in awks that measure a string on every substr().
function jnorm(s, keepnl,   n, pos, buf, out, co, i, bl, lim, c, e, v, v2, unit, step, w, ok, j, x, stop, lo, hi) {
  n = length(s)
  if (n == 0) return ""
  pos = 1; buf = ""; out = ""; stop = 0
  while (!stop && (pos <= n || buf != "")) {
    if (pos <= n) { buf = buf substr(s, pos, 512); pos += 512 }
    bl = length(buf); i = 1; co = ""
    lim = (pos > n) ? bl : bl - 12
    while (i <= lim) {
      c = substr(buf, i, 1); step = 1; unit = c
      if (c == "\\") {
        e = substr(buf, i + 1, 1); step = 2
        if (e == "u") {
          v = nhex(substr(buf, i + 2, 4))
          if (v < 0) { stop = 1; break }
          unit = substr(buf, i, 6); step = 6
          if (v >= 55296 && v <= 56319) {
            v2 = -1
            if (substr(buf, i + 6, 2) == "\\u") v2 = nhex(substr(buf, i + 8, 4))
            if (v2 >= 56320 && v2 <= 57343) { unit = substr(buf, i, 12); step = 12 }
            else unit = " "
          } else if (v >= 56320 && v <= 57343) unit = " "
          else if (keepnl && (v == 10 || v == 9)) unit = unit
          else if (v < 32 || (v >= 127 && v <= 159) || v == 8232 || v == 8233) unit = " "
        } else if (e == "\"" || e == "\\" || e == "/") unit = c e
        else if (keepnl && (e == "n" || e == "t")) unit = c e
        else if (e == "") { stop = 1; break }
        else unit = " "
      } else if (c >= "\302" && c <= "\364") {
        # Well-formed UTF-8 only (as NOTIFY_TEXT): no overlong forms, no
        # encoded surrogates, nothing past U+10FFFF.
        w = c < "\340" ? 2 : (c < "\360" ? 3 : 4)
        lo = "\200"; hi = "\277"
        if (c == "\340") lo = "\240"; else if (c == "\355") hi = "\237"
        else if (c == "\360") lo = "\220"; else if (c == "\364") hi = "\217"
        x = substr(buf, i + 1, 1); ok = (x >= lo && x <= hi)
        for (j = 2; ok && j < w; j++) { x = substr(buf, i + j, 1); if (x < "\200" || x > "\277") ok = 0 }
        if (ok) {
          unit = substr(buf, i, w); step = w
          if (c == "\302" && substr(unit, 2, 1) < "\240") unit = " "
        } else unit = " "
      } else if (c < " " || c >= "\177") unit = " "
      co = co unit; i += step
    }
    out = out co
    buf = substr(buf, i)
  }
  return out
}
# The longest start of normalized content s with at most maxu units (an
# escape, a surrogate pair escape or a UTF-8 character is one) and maxb
# bytes, never splitting a unit.
function ucut(s, maxu, maxb,   n, pos, buf, out, co, i, bl, lim, c, step, u, b, done) {
  n = length(s)
  if (n <= maxb && n <= maxu) return s
  pos = 1; buf = ""; out = ""; u = 0; b = 0; done = 0
  while (!done && (pos <= n || buf != "")) {
    if (pos <= n) { buf = buf substr(s, pos, 512); pos += 512 }
    bl = length(buf); i = 1; co = ""
    lim = (pos > n) ? bl : bl - 12
    while (i <= lim) {
      c = substr(buf, i, 1)
      if (c == "\\") {
        step = 2
        if (substr(buf, i + 1, 1) == "u") {
          step = 6
          c = nhex(substr(buf, i + 2, 4))
          if (c >= 55296 && c <= 56319) step = 12
        }
      } else if (c >= "\360") step = 4
      else if (c >= "\340") step = 3
      else if (c >= "\300") step = 2
      else step = 1
      if (u + 1 > maxu || b + step > maxb) { done = 1; break }
      co = co substr(buf, i, step); u++; b += step; i += step
    }
    out = out co
    if (done) break
    buf = substr(buf, i)
  }
  return out
}
# Raw text as the content of a JSON string: \ and " escaped, control
# characters (tab and line breaks too) as spaces. In pieces, as jnorm.
function jesc(t,   n, pos, out, co, piece, k, c) {
  n = length(t); pos = 1; out = ""
  while (pos <= n) {
    piece = substr(t, pos, 512); pos += 512
    gsub(CTRLRE, " ", piece)
    co = ""
    while ((k = match(piece, /[\\"]/)) > 0) {
      c = substr(piece, k, 1)
      co = co substr(piece, 1, k - 1) "\\" c
      piece = substr(piece, k + 1)
    }
    out = out co piece
  }
  return out
}
'

# Facts of the agent's event JSON (stdin), one line per scalar:
# `path TAB s|r TAB value` (strings JSON-escaped as received, never decoded),
# and for a few containers (tool_input and the like) `path TAB j TAB text`:
# the container's own text as the content of a JSON string (\ and " escaped,
# control characters as spaces). With rawp set, only that container's text,
# raw (control characters as spaces), for an answer that hands it back.
JSON_FACTS='
function fpath(   d, p) {
  p = ""
  for (d = 1; d <= JD; d++) p = p (d > 1 ? "." : "") JK[d]
  return p
}
function femit(p, t, v) {
  # A top-level key of the input that starts with @ would read as one of the
  # parameters the hook adds (@.rkind and the like): left out.
  if (substr(p, 1, 1) == "@") return
  if (FN_OUT >= 20000) return
  FN_OUT++
  if (t == "s") gsub(CTRLRE, " ", v)
  printf "%s\t%s\t%s\n", p, t, v
}
function fspan(p) { return (p in SPANW) || p ~ /^permission_suggestions\.[0-9]+$/ }
BEGIN {
  CTRLRE = "[" sprintf("%c", 1) "-" sprintf("%c", 31) sprintf("%c", 127) "]"
  n = split("tool_input,tool_input.questions,requested_schema,toolCall.args.Arguments,toolInput,toolArgs", W, ",")
  for (k = 1; k <= n; k++) SPANW[W[k]] = 1
  if (rawp != "") { split("", SPANW); SPANW[rawp] = 1 }
}
{ s = s $0 "\n" }
END {
  len = length(s); i = 1; JD = 0
  while (i <= len) {
    c = substr(s, i, 1)
    if (c == " " || c == "\t" || c == "\n" || c == "\r") { i++; continue }
    if (c == ",") {
      if (JD > 0) { if (JT[JD] == "a") JK[JD]++; else JE[JD] = 1 }
      i++; continue
    }
    if (c == ":") { if (JD > 0) JE[JD] = 0; i++; continue }
    if (c == "{" || c == "[") {
      p = (JD > 0) ? fpath() : ""
      JD++
      if (c == "{") { JT[JD] = "o"; JK[JD] = ""; JE[JD] = 1 }
      else { JT[JD] = "a"; JK[JD] = 0; JE[JD] = 0 }
      SPS[JD] = 0
      if (p != "" && fspan(p)) { SPS[JD] = i; SPP[JD] = p }
      i++; continue
    }
    if (c == "}" || c == "]") {
      if (JD > 0) {
        if (SPS[JD] > 0 && rawp != "" && SPP[JD] == rawp) {
          t = substr(s, SPS[JD], i - SPS[JD] + 1)
          gsub(CTRLRE, " ", t)
          print t
          exit
        }
        if (SPS[JD] > 0 && rawp == "") femit(SPP[JD], "j", jesc(substr(s, SPS[JD], i - SPS[JD] + 1)))
        SPS[JD] = 0
        JD--
      }
      i++; continue
    }
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
      if (JD > 0 && rawp == "") femit(fpath(), "s", str)
      continue
    }
    j = i
    while (j <= len && index(" \t\r\n,:}]", substr(s, j, 1)) == 0) j++
    if (JD > 0 && rawp == "") femit(fpath(), "r", substr(s, i, j - i))
    i = j
  }
}
'

# The v2 fields of an event (section 3) as spec lines `path TAB o|a|s|r TAB
# value`, from the facts and `@.<key>` parameters (strings, JSON-escaped):
# common fields, the request (section 4; rkind names how this agent asked),
# the end of a turn (section 6.1), a state (6.2) or a result (5.6). Lines
# starting with # are notes for the waiting hook (#smap: the original index
# of each Claude scope).
V2_SPEC='
function fs(p) { return (p in FT && FT[p] != "r") ? FV[p] : "" }
function fr(p) { return (p in FT && FT[p] == "r" && FV[p] != "null") ? FV[p] : "" }
function P(k) { return fs("@." k) }
function out(p, t, v) { printf "%s\t%s\t%s\n", p, t, v }
function S(p, v, keep) { if (v != "") out(p, "s", jnorm(v, keep)) }
function R(p, v) { if (v != "") out(p, "r", v) }
function B(p, v) { if (v == "true" || v == "false") out(p, "r", v) }
function O(p) { out(p, "o", "") }
function A(p) { out(p, "a", "") }
function isid(v) { return v ~ /^[A-Za-z0-9._:-]+$/ && length(v) <= 128 }
# The first non-empty string fact among the comma list of paths.
function first(list,   L, n, k) {
  n = split(list, L, ",")
  for (k = 1; k <= n; k++) if (fs(L[k]) != "") return fs(L[k])
  return ""
}
# A list of decision ids as a JSON array: CAN (space list) at path p.
function ids(p, list,   L, n, k, m) {
  n = split(list, L, " ")
  if (n == 0) return
  A(p); m = 0
  for (k = 1; k <= n; k++) out(p "." m++, "s", L[k])
}
function inlist(list, v) { return index(" " list " ", " " v " ") > 0 }

# --- asks -----------------------------------------------------------------
function ask_shell(cmd, desc) { O("req.ask"); S("req.ask.cmd", cmd, 1); S("req.ask.desc", desc, 1) }
function ask_path(p) { O("req.ask"); S("req.ask.path", p, 1) }
function ask_web(url, prompt) { O("req.ask"); S("req.ask.url", url, 1); S("req.ask.prompt", prompt, 1) }
function ask_mcp(server, tool, args) { O("req.ask"); S("req.ask.server", server, 1); S("req.ask.tool", tool, 1); S("req.ask.args", args, 0) }
function ask_text(t) { if (t == "") return; O("req.ask"); S("req.ask.text", t, 1) }
# mcp__<server>__<tool> (Claude, Codex) or <server>__<tool> (Grok): MS, MT.
function mcp_split(name, pre,   r) {
  MS = ""; MT = ""
  r = substr(name, length(pre) + 1)
  if (index(r, "__") == 0) return 0
  MS = substr(r, 1, index(r, "__") - 1); MT = substr(r, index(r, "__") + 2)
  return MS != "" && MT != ""
}
# Questions under prefix qp (qp.N...), with the field names of the agent.
function ask_qs(qp, fq, fh, fm, fopt, fl, fd, free, multitrue,   n, k, m, l, base, ob) {
  O("req.ask"); A("req.ask.qs"); n = 0
  for (k = 0; k < 64; k++) {
    base = qp "." k
    if (!((base "." fq) in FT) && !((base "." fh) in FT) && !((base "." fopt ".0." fl) in FT) && !((base "." fopt ".0") in FT)) break
    O("req.ask.qs." n)
    S("req.ask.qs." n ".q", fs(base "." fq), 1)
    S("req.ask.qs." n ".h", fs(base "." fh), 1)
    m = fr(base "." fm)
    if (m == "" && multitrue != "" && fs(base "." fm) == multitrue) m = "true"
    out("req.ask.qs." n ".multi", "r", m == "true" ? "true" : "false")
    out("req.ask.qs." n ".free", "r", free ? "true" : (fr(base ".custom") == "true" ? "true" : "false"))
    A("req.ask.qs." n ".opts")
    for (m = 0; m < 64; m++) {
      ob = base "." fopt "." m
      if (fl != "" && (ob "." fl) in FT) l = fs(ob "." fl)
      else if (ob in FT) l = fs(ob)
      else break
      O("req.ask.qs." n ".opts." m)
      S("req.ask.qs." n ".opts." m ".l", l, 1)
      if (fl != "") S("req.ask.qs." n ".opts." m ".d", fs(ob "." fd), 1)
    }
    n++
  }
  NQ = n
}
# Codex apply_patch: the files it touches, lines added and removed.
function ask_codex_patch(t,   L, n, k, x, files, nf, add, del, path) {
  O("req.ask"); n = split(t, L, /\\n/); nf = 0; add = 0; del = 0; path = ""
  for (k = 1; k <= n; k++) {
    x = L[k]
    if (x ~ /^\*\*\* (Add|Update|Delete) File: /) {
      sub(/^\*\*\* (Add|Update|Delete) File: /, "", x)
      if (path == "") path = x
      files[++nf] = x
    } else if (x ~ /^\+/ && x !~ /^\+\+\+/) add++
    else if (x ~ /^-/ && x !~ /^---/) del++
  }
  S("req.ask.path", path, 1)
  if (nf > 1) { A("req.ask.files"); for (k = 1; k <= nf; k++) S("req.ask.files." (k - 1), files[k], 1) }
  O("req.ask.change"); out("req.ask.change.form", "s", "patch"); out("req.ask.change.fmt", "s", "codex")
  S("req.ask.change.text", t, 1)
  out("req.ask.add", "r", add); out("req.ask.del", "r", del)
}
function change_replace(old, new, all) {
  O("req.ask.change"); out("req.ask.change.form", "s", "replace")
  S("req.ask.change.old", old, 1); S("req.ask.change.new", new, 1); B("req.ask.change.all", all)
}
function change_write(content) { O("req.ask.change"); out("req.ask.change.form", "s", "write"); S("req.ask.change.content", content, 1) }
function change_patch(text) { if (text == "") return; O("req.ask.change"); out("req.ask.change.form", "s", "patch"); out("req.ask.change.fmt", "s", "unified"); S("req.ask.change.text", text, 1) }

# Claude permission_suggestions -> scopes (addDirectories left out: undoing
# it does not stop the next redirect from asking). SMAP: original indexes.
function claude_scopes(   k, j, t, lab, beh, n, x) {
  n = 0; SMAP = ""
  for (k = 0; k < 16; k++) {
    if (!(("permission_suggestions." k ".type") in FT)) break
    t = fs("permission_suggestions." k ".type"); beh = fs("permission_suggestions." k ".behavior")
    if (t == "addDirectories" || t == "removeDirectories") continue
    if ((t == "addRules" || t == "replaceRules") && beh != "" && beh != "allow") continue
    lab = ""
    if (t == "addRules" || t == "replaceRules") {
      for (j = 0; j < 16; j++) {
        x = fs("permission_suggestions." k ".rules." j ".toolName")
        if (x == "") break
        if (fs("permission_suggestions." k ".rules." j ".ruleContent") != "") x = x "(" fs("permission_suggestions." k ".rules." j ".ruleContent") ")"
        lab = lab (lab == "" ? "" : ", ") x
      }
      SK[n] = "rule"
    } else if (t == "setMode") { lab = fs("permission_suggestions." k ".mode"); SK[n] = "mode" }
    else { lab = t; SK[n] = "other" }
    if (lab == "") continue
    SL[n] = lab; SD[n] = fs("permission_suggestions." k ".destination"); SMAP = SMAP " " k
    n++
  }
  NS = n
}
function scopes(   k) {
  if (NS == 0) return
  A("req.scopes")
  for (k = 0; k < NS; k++) {
    O("req.scopes." k); S("req.scopes." k ".label", SL[k], 1); out("req.scopes." k ".kind", "s", SK[k]); S("req.scopes." k ".dest", SD[k], 1)
  }
}

# --- requests ---------------------------------------------------------------
function req(rk,   id, win, tool, wait, can, t, v, others, no, k, oc, aff) {
  id = ""; win = "other"; tool = ""; wait = "shared"; can = ""; NS = 0; NQ = 0; SMAP = ""
  rid = P("rid")
  if (rk == "claude_perm" || rk == "claude_askpre") {
    tool = fs("tool_name")
    if (tool == "Bash") win = "shell"
    else if (tool == "Edit" || tool == "Write" || tool == "MultiEdit") win = "edit"
    else if (tool == "WebFetch") win = "web"
    else if (tool ~ /^mcp__/ && mcp_split(tool, "mcp__")) win = "mcp"
    else if (tool == "AskUserQuestion") win = "question"
    else if (tool == "ExitPlanMode") win = "plan"
    if (win == "question") can = "answer deny deny_reason"
    else if (win == "plan") can = "plan_approve plan_refine deny"
    else { claude_scopes(); can = "allow" (NS > 0 ? " allow_scope" : "") " deny deny_reason" }
  } else if (rk == "claude_notif") {
    t = P("ntype"); wait = "none"
    win = (t == "elicitation_dialog") ? "form" : (t == "elicitation_url_dialog") ? "login" : "other"
  } else if (rk == "codex_perm") {
    tool = fs("tool_name"); wait = "hidden"
    if (tool == "Bash") win = "shell"
    else if (tool == "apply_patch") win = "edit"
    else if (tool ~ /^mcp__/ && mcp_split(tool, "mcp__")) win = "mcp"
    can = "allow deny deny_reason"
  } else if (rk == "codex_plan") {
    win = "plan"; wait = "none"
  } else if (rk == "oc_perm") {
    oc = P("oc"); tool = fs("tool_name")
    if (isid(fs("request_id"))) id = fs("request_id")
    if (tool == "bash" || tool == "shell") win = "shell"
    else if (tool == "edit" || tool == "write") win = "edit"
    no = 0; while (no < 64 && (("others." no) in FT)) no++
    v = ""
    for (k = 0; k < 64; k++) {
      t = fs((oc == "2" ? "save." : "always.") k)
      if (t == "") break
      v = v (v == "" ? "" : " ") t
    }
    if (v != "") { NS = 1; SL[0] = v; SK[0] = "pattern"; SD[0] = (oc == "2") ? "project" : (oc == "1.0" ? "session" : "process") }
    can = "allow" (NS ? " allow_scope" : "") " deny"
    if (oc != "1.0" && !(oc == "1.19" && no > 0)) can = can " deny_reason"
  } else if (rk == "oc_question") {
    win = "question"; tool = "question"
    if (isid(fs("request_id"))) id = fs("request_id")
    can = "answer deny"
  } else if (rk == "oc_form") {
    win = "question"; tool = "question"; wait = "none"
    if (isid(fs("request_id"))) id = fs("request_id")
  } else if (rk == "agy_tool" || rk == "agy_ask") {
    tool = fs("toolCall.name"); wait = (rk == "agy_ask") ? "none" : "hidden"
    if (tool == "run_command") win = "shell"
    else if (tool == "write_file" || tool == "edit_file") win = "edit"
    else if (tool == "read_file") win = "read"
    else if (tool == "call_mcp_tool") win = "mcp"
    else if (tool == "ask_question") win = "question"
    if (rk == "agy_tool") can = "allow deny deny_reason"
  } else if (rk == "agy_plan") {
    win = "plan"; tool = fs("plan.toolCall.name"); wait = P("wait")
    can = "plan_approve"
  } else if (rk == "cop_notif") {
    wait = "none"; t = fs("message")
    if (fs("notification_type") == "elicitation_dialog") win = "question"
    else if (t ~ /^Run command: /) win = "shell"
    else if (t ~ /^Edit file: /) win = "edit"
    else if (t ~ /^Fetch URL: /) win = "web"
    else if (t ~ /^Use MCP tool: /) win = "mcp"
  } else if (rk == "cop_plan") {
    win = "plan"; tool = fs("toolName"); wait = "none"
  } else if (rk == "grok_notif") {
    wait = "none"; tool = fs("pre.toolName")
    if (isid(fs("pre.toolUseId"))) id = fs("pre.toolUseId")
    t = P("ntype")
    if (t == "plan" || tool == "exit_plan_mode") win = "plan"
    else if (t == "elicitation_dialog" || tool == "ask_user_question") win = "question"
    else if (tool == "run_terminal_command" || tool == "run_terminal_cmd" || tool == "Bash") win = "shell"
    else if (tool == "write" || tool == "search_replace" || tool == "edit_file") win = "edit"
    else if (tool == "web_fetch") win = "web"
    else if (tool == "read_file") win = "read"
    else if (tool != "" && mcp_split(tool, "")) win = "mcp"
  }
  if (id == "") id = "st-" rid
  O("req")
  out("req.id", "s", id)
  t = (rk == "agy_tool" || rk == "agy_ask") ? fr("stepIdx") : (rk == "agy_plan") ? fr("plan.stepIdx") : ""
  if (isid(t)) out("req.nid", "s", t)
  out("req.win", "s", win)
  S("req.tool", tool, 1)
  out("req.wait", "s", wait)
  # what is asked
  if (rk == "claude_perm" || rk == "claude_askpre") {
    if (win == "shell") ask_shell(fs("tool_input.command"), fs("tool_input.description"))
    else if (win == "edit") {
      ask_path(fs("tool_input.file_path"))
      if (tool == "Edit") change_replace(fs("tool_input.old_string"), fs("tool_input.new_string"), fr("tool_input.replace_all"))
      else if (tool == "Write") change_write(fs("tool_input.content"))
    }
    else if (win == "web") ask_web(fs("tool_input.url"), fs("tool_input.prompt"))
    else if (win == "mcp") ask_mcp(MS, MT, fs("tool_input"))
    else if (win == "question") ask_qs("tool_input.questions", "question", "header", "multiSelect", "options", "label", "description", 1, "")
    else if (win == "plan") { O("req.ask"); S("req.ask.text", fs("tool_input.plan"), 1); S("req.ask.file", fs("tool_input.planFilePath"), 1) }
    else ask_text(first("tool_input.description,tool_input.command,tool_input.file_path,tool_input.url,tool_input.prompt"))
  } else if (rk == "claude_notif") {
    t = fs("message")
    if (win == "other") ask_text(t)
    else if (t != "") { O("req.ask"); S("req.ask.msg", t, 1) }
  } else if (rk == "codex_perm") {
    if (win == "shell") ask_shell(fs("tool_input.command"), fs("tool_input.description"))
    else if (win == "edit") ask_codex_patch(fs("tool_input.command"))
    else if (win == "mcp") ask_mcp(MS, MT, fs("tool_input"))
    else ask_text(first("tool_input.description,tool_input.command"))
  } else if (rk == "codex_plan") ask_text(fs("@.plan"))
  else if (rk == "oc_perm") {
    if (win == "shell") ask_shell(first("metadata.command,tool_input.command"), "")
    else if (win == "edit") {
      O("req.ask"); S("req.ask.path", first("metadata.filepath,metadata.files.0.file,patterns.0,resources.0"), 1)
      if (("metadata.files.1.file") in FT) { A("req.ask.files"); for (k = 0; k < 64 && (("metadata.files." k ".file") in FT); k++) S("req.ask.files." k, fs("metadata.files." k ".file"), 1) }
      change_patch(first("metadata.diff,metadata.files.0.patch"))
    } else ask_text(fs("tool_input.command"))
  } else if (rk == "oc_question") ask_qs("questions", "question", "header", "multiple", "options", "label", "description", 1, "")
  else if (rk == "oc_form") ask_qs("form.fields", "description", "title", "type", "options", "label", "description", 0, "multiselect")
  else if (rk == "agy_tool" || rk == "agy_ask") {
    if (win == "shell") ask_shell(fs("toolCall.args.CommandLine"), "")
    else if (win == "edit") {
      ask_path(fs("toolCall.args.Path"))
      if (tool == "edit_file") change_replace(fs("toolCall.args.Target"), fs("toolCall.args.Replacement"), "")
      else change_write(fs("toolCall.args.Content"))
    }
    else if (win == "read") ask_path(fs("toolCall.args.Path"))
    else if (win == "mcp") ask_mcp(fs("toolCall.args.ServerName"), fs("toolCall.args.ToolName"), fs("toolCall.args.Arguments"))
    else if (win == "question") ask_qs("toolCall.args.questions", "question", "header", "is_multi_select", "options", "label", "description", 0, "")
  } else if (rk == "agy_plan") { O("req.ask"); S("req.ask.text", first("plan.toolCall.args.Content,plan.toolCall.args.ArtifactMetadata.Summary"), 1); S("req.ask.file", fs("plan.toolCall.args.Path"), 1) }
  else if (rk == "cop_notif") {
    t = fs("message")
    if (win == "shell") ask_shell(substr(t, 14), "")
    else if (win == "edit") ask_path(substr(t, 12))
    else if (win == "web") ask_web(substr(t, 12), "")
    else if (win == "mcp") {
      v = substr(t, 15)
      if (index(v, "/") > 0) ask_mcp(substr(v, 1, index(v, "/") - 1), substr(v, index(v, "/") + 1), "")
      else ask_text(t)
    }
    else if (win == "question") {
      v = fs("pre.toolArgs.message")
      O("req.ask"); A("req.ask.qs"); O("req.ask.qs.0"); S("req.ask.qs.0.q", v != "" ? v : t, 1)
      out("req.ask.qs.0.multi", "r", "false"); out("req.ask.qs.0.free", "r", "false"); A("req.ask.qs.0.opts"); NQ = 1
    }
    else ask_text(t)
  } else if (rk == "cop_plan") ask_text(fs("toolArgs.summary"))
  else if (rk == "grok_notif") {
    if (win == "shell") ask_shell(fs("pre.toolInput.command"), fs("pre.toolInput.description"))
    else if (win == "edit" || win == "read") ask_path(first("pre.toolInput.file_path,pre.toolInput.path,pre.toolInput.target_file"))
    else if (win == "web") ask_web(fs("pre.toolInput.url"), fs("pre.toolInput.prompt"))
    else if (win == "mcp") ask_mcp(MS, MT, fs("pre.toolInput"))
    else if (win == "question" && (("pre.toolInput.questions.0.question") in FT)) ask_qs("pre.toolInput.questions", "question", "header", "multiSelect", "options", "label", "description", 0, "")
    else ask_text(fs("message"))
  }
  # what may be decided (the full list; the builder narrows it per link)
  ids("req.can", can)
  scopes()
  if (win == "plan" && rk == "claude_perm") { A("req.modes"); out("req.modes.0", "s", "default"); out("req.modes.1", "s", "accept_edits") }
  # OpenCode 1.19 and 2.x: always, also with no other request open now, as
  # one may open before the decision comes (section 4.5).
  if (rk == "oc_perm" && P("oc") != "1.0") {
    aff = ""
    if (inlist(can, "allow_scope")) aff = "allow_scope"
    aff = aff (aff == "" ? "" : " ") "deny"
    if (inlist(can, "deny_reason")) aff = aff " deny_reason"
    ids("req.affects", aff)
    A("req.others")
    for (k = 0; k < no; k++) if (isid(fs("others." k))) out("req.others." k, "s", fs("others." k))
  }
  if (SMAP != "") out("#smap", "s", SMAP)
}

# --- the end of a turn -------------------------------------------------------
function bgkind(t) {
  if (t == "subagent" || t == "shell" || t == "monitor" || t == "workflow" || t == "teammate") return t
  if (t == "cloud session") return "cloud"
  if (t == "MCP task") return "mcp_task"
  return "other"
}
function turn(   bp, cp, k, n, t, id, base) {
  O("turn")
  S("turn.end", P("end")); S("turn.by", P("by"))
  B("turn.asks", P("asks"))
  S("turn.last", P("last"), 1)
  B("turn.late", P("late")); B("turn.hook", P("hook"))
  bp = P("bgp")
  if (bp != "" && ((bp ".0.type") in FT || (bp ".0.id") in FT)) {
    A("turn.bg"); n = 0
    for (k = 0; k < 64; k++) {
      base = bp "." k
      if (!((base ".type") in FT) && !((base ".id") in FT)) break
      t = fs(base ".type")
      if (t == "dream" || t == "auto-mode scan" || t == "memory import" || t == "memory save") continue
      O("turn.bg." n)
      id = fs(base ".id")
      if (id ~ /^[A-Za-z0-9_-]+$/ && length(id) <= 64) out("turn.bg." n ".id", "s", id)
      else id = ""
      out("turn.bg." n ".kind", "s", bgkind(t))
      S("turn.bg." n ".name", first(base ".agent_type," base ".agentType"), 1)
      S("turn.bg." n ".desc", fs(base ".description"), 1)
      S("turn.bg." n ".cmd", fs(base ".command"), 1)
      if (id != "") out("turn.bg." n ".new", "r", inlist(P("prev"), id) ? "false" : "true")
      if (t == "shell") out("turn.bg." n ".svc", "r", inlist(P("svc"), k) ? "true" : "false")
      S("turn.bg." n ".st", fs(base ".status"), 1)
      n++
    }
  }
  cp = P("cronp")
  if (cp != "" && (cp ".0.schedule") in FT) {
    A("turn.crons")
    for (k = 0; k < 64 && ((cp "." k ".schedule") in FT); k++) {
      O("turn.crons." k); S("turn.crons." k ".sched", fs(cp "." k ".schedule"), 1); S("turn.crons." k ".prompt", fs(cp "." k ".prompt"), 1)
    }
  }
  S("turn.goal", P("goal"))
}

BEGIN { FS = "\t"; CTRLRE = "[" sprintf("%c", 1) "-" sprintf("%c", 31) sprintf("%c", 127) "]" }
{
  t = $2; v = substr($0, length($1) + length(t) + 3)
  if (!($1 in FT)) { FT[$1] = t; FV[$1] = v }
}
END {
  out("fmt", "r", "2")
  S("pv", P("pv")); S("av", P("av")); S("avs", P("avs")); S("sid", P("sid")); S("tid", P("tid"))
  if (P("sub.id") != "") { O("sub"); S("sub.id", P("sub.id")); S("sub.type", P("sub.type"), 1); S("sub.name", P("sub.name"), 1); S("sub.parent", P("sub.parent")); B("sub.bg", P("sub.bg")) }
  S("dir", P("dir"))
  if (P("cfg.var") != "" && P("cfg.path") != "") { O("cfg"); S("cfg.var", P("cfg.var")); S("cfg.path", P("cfg.path")) }
  S("pm", P("pm")); S("mux", P("mux")); R("tms", P("tms"))
  if (P("rkind") != "") req(P("rkind"))
  if (P("turn") == "1") turn()
  S("st", P("st"))
  if (P("res.scope") != "") {
    O("res"); S("res.scope", P("res.scope")); S("res.req", P("res.req")); S("res.rrid", P("res.rrid")); S("res.out", P("res.out")); S("res.act", P("res.act")); S("res.win", P("res.win"))
  }
}
'

# Builds the plaintext for one link from the v1 fields (`=key TAB value`) and
# the spec: the link's variant of the request (section 4.3), then the field
# limits and the deterministic cuts of section 2.2 (the PowerShell hook does
# the same, byte for byte). Prints the plaintext, then META lines.
V2_BUILD='
# V2 plaintext builder (TDS_AGENT_EVENTS_V2 sections 2.1, 2.2, 3): the v1
# fields (lines "=key TAB value") and the v2 spec (lines "path TAB type TAB
# value", types o a s r) for one link (kind tunnel|relay, fmt2, dec: whether
# it carries a nonce, waitov) in; the plaintext out, and META lines.
function gpath(p,   n, Q, k, g) {
  n = split(p, Q, ".")
  g = ""
  for (k = 1; k <= n; k++) g = g (k > 1 ? "." : "") (Q[k] ~ /^[0-9]+$/ ? "#" : Q[k])
  return g
}
function kill(i,   k) {
  if (ND[i]) return
  ND[i] = 1
  for (k = 1; k <= NC[i]; k++) kill(CH[i, k])
}
function live(i,   k, n) { n = 0; for (k = 1; k <= NC[i]; k++) if (!ND[CH[i, k]]) n++; return n }
function lastlive(i,   k) { for (k = NC[i]; k >= 1; k--) if (!ND[CH[i, k]]) return CH[i, k]; return 0 }
function node(p) { return (p in IDX && !ND[IDX[p]]) ? IDX[p] : 0 }
function ser(i,   s, k, c, f) {
  if (NT[i] == "s") return "\"" NV[i] "\""
  if (NT[i] == "r") return NV[i]
  s = (NT[i] == "o") ? "{" : "["
  f = 1
  for (k = 1; k <= NC[i]; k++) {
    c = CH[i, k]
    if (ND[c]) continue
    s = s (f ? "" : ",") (NT[i] == "o" ? "\"" NK[c] "\":" : "") ser(c)
    f = 0
  }
  return s ((NT[i] == "o") ? "}" : "]")
}
# The cut record (section 2.2 step 6).
function rec(path, val) {
  if (path in REC) return
  REC[path] = 1
  if (PLUS > 0 || CLIVE >= 16) { PLUS++; return }
  CN++; CK[CN] = path; CV[CN] = val; CLIVE++
}
function unrec(path,   k, pre) {
  pre = path "."
  for (k = 1; k <= CN; k++) {
    if (CDEAD[k]) continue
    if (substr(CK[k], 1, length(pre)) == pre) { CDEAD[k] = 1; CLIVE-- }
  }
}
function cutjson(   s, k, f) {
  if (CLIVE == 0 && PLUS == 0) return ""
  s = ",\"cut\":{"; f = 1
  for (k = 1; k <= CN; k++) {
    if (CDEAD[k]) continue
    s = s (f ? "" : ",") "\"" CK[k] "\":" CV[k]; f = 0
  }
  if (PLUS > 0) s = s (f ? "" : ",") "\"+\":" PLUS
  return s "}"
}
function plain(   s, k, c) {
  s = "{\"v\":1,\"rid\":\"" V1["rid"] "\",\"ev\":\"" V1["ev"] "\",\"app\":\"" V1["app"] "\",\"host\":\"" HOST "\",\"cwd\":\"" CWD "\""
  if ("title" in V1) s = s ",\"title\":\"" TITLE "\""
  if ("msg" in V1) s = s ",\"msg\":\"" MSG "\""
  s = s V1["uv1"] V1["xflags"]
  if (dec && V1["nonce"] != "") s = s ",\"nonce\":\"" V1["nonce"] "\""
  for (k = 1; k <= NC[0]; k++) {
    c = CH[0, k]
    if (!ND[c]) s = s ",\"" NK[c] "\":" ser(c)
  }
  return s cutjson() V1["uv2"] ",\"ts\":" V1["ts"] "}"
}
function size() { return length(plain()) }
# Removes decision id d from req.can.
function nocan(d,   i, k) {
  i = node("req.can")
  if (!i) return
  for (k = 1; k <= NC[i]; k++) if (!ND[CH[i, k]] && NV[CH[i, k]] == d) kill(CH[i, k])
}
function cankeep(list,   i, k) {
  i = node("req.can")
  if (!i) return
  for (k = 1; k <= NC[i]; k++) if (!ND[CH[i, k]] && index(" " list " ", " " NV[CH[i, k]] " ") == 0) kill(CH[i, k])
}
function hascan(d,   i, k) {
  i = node("req.can")
  if (!i) return 0
  for (k = 1; k <= NC[i]; k++) if (!ND[CH[i, k]] && NV[CH[i, k]] == d) return 1
  return 0
}
function drop(p) { if (node(p)) kill(IDX[p]) }
# Section 2.2 field limits: STR[generic path] "tunnel relay" bytes (- not
# sent to the relay), CNT the same for arrays.
function limits() {
  split("", STR); split("", CNT)
  STR["dir"] = "1024 -"; STR["cfg"] = "0 -"; STR["cfg.path"] = "1024 -"
  STR["avs"] = "0 -"; STR["tid"] = "0 -"; STR["pm"] = "0 -"; STR["tms"] = "0 -"; STR["req.nid"] = "0 -"
  STR["req.tool"] = "128 128"; STR["req.ask.cmd"] = "8192 400"; STR["req.ask.desc"] = "1024 200"
  STR["req.ask.path"] = "1024 256"; STR["req.ask.file"] = "1024 256"; STR["req.ask.files.#"] = "1024 256"
  STR["req.ask.change"] = "0 -"; STR["req.ask.change.old"] = "12288 -"; STR["req.ask.change.new"] = "12288 -"
  STR["req.ask.change.content"] = "24576 -"; STR["req.ask.change.text"] = "24576 -"
  STR["req.ask.url"] = "2048 400"; STR["req.ask.prompt"] = "1024 -"
  STR["req.ask.server"] = "128 128"; STR["req.ask.tool"] = "128 128"; STR["req.ask.args"] = "4096 -"
  STR["req.ask.msg"] = "1024 200"; STR["req.ask.schema"] = "8192 -"
  # A plan is long; any other text short.
  STR["req.ask.text"] = (node("req.win") && NV[IDX["req.win"]] == "plan") ? "24576 600" : "1024 200"
  STR["req.ask.qs.#.q"] = "400 160"; STR["req.ask.qs.#.h"] = "64 32"
  STR["req.ask.qs.#.opts.#.l"] = "200 64"; STR["req.ask.qs.#.opts.#.d"] = "600 -"
  STR["req.scopes.#.label"] = "200 80"; STR["sub.type"] = "64 64"; STR["sub.name"] = "64 64"
  STR["turn.last"] = "4000 -"; STR["turn.bg.#.name"] = "64 32"; STR["turn.bg.#.desc"] = "200 80"
  STR["turn.bg.#.cmd"] = "200 80"; STR["turn.crons"] = "0 -"; STR["turn.crons.#.sched"] = "64 -"
  STR["turn.crons.#.prompt"] = "200 -"
  CNT["req.ask.files"] = "32 4"; CNT["req.ask.qs"] = "8 4"; CNT["req.ask.qs.#.opts"] = "16 8"
  CNT["req.scopes"] = "8 4"; CNT["req.others"] = "32 8"; CNT["turn.bg"] = "16 3"; CNT["turn.crons"] = "8 -"
}
function lim(tab, g,   L) {
  if (!(g in tab)) return 0
  split(tab[g], L, " ")
  return (kind == "tunnel") ? L[1] : L[2]
}
function v1cut(key, v, mu, mb,   c) {
  c = ucut(v, mu, mb)
  if (length(c) < length(v)) rec(key, length(v))
  return c
}
BEGIN { FS = "\t"; N = 0; NT[0] = "o"; NC[0] = 0 }
/^=/ { V1[substr($1, 2)] = substr($0, length($1) + 2); next }
/^#/ { META[++NM] = $0; next }
{
  p = $1; t = $2; v = substr($0, length(p) + length(t) + 3)
  if (p in IDX) next
  k = 0
  while (match(substr(p, k + 1), /\./)) k += RSTART
  par = (k > 0) ? substr(p, 1, k - 1) : ""
  if (par != "" && !(par in IDX)) next
  pi = (par == "") ? 0 : IDX[par]
  if (NT[pi] != "o" && NT[pi] != "a") next
  N++; IDX[p] = N; NP[N] = p; NT[N] = t; NV[N] = v; NK[N] = substr(p, k + 1); NC[N] = 0
  NC[pi]++; CH[pi, NC[pi]] = N
}
END {
  limits()
  budget = (kind == "tunnel") ? 32768 : 2048
  # variant of this link (section 4.3)
  if (waitov != "" && node("req.wait")) NV[IDX["req.wait"]] = waitov
  if (!dec) { drop("req.can"); drop("req.scopes"); drop("req.modes"); drop("req.affects"); drop("req.others") }
  else if (!fmt2) {
    win = node("req.win") ? NV[IDX["req.win"]] : ""
    if (win == "plan") { cankeep("plan_approve deny"); drop("req.modes") }
    else cankeep("allow deny")
    drop("req.scopes")
    if (node("req.others") && live(IDX["req.others"]) > 0) cankeep("allow")
    drop("req.affects"); drop("req.others")
  }
  # step 0: field limits, in serialization order (v1 fields first)
  HOST = v1cut("host", jnorm(V1["host"], 0), 64, 256)
  CWD = v1cut("cwd", jnorm(V1["cwd"], 0), 64, 256)
  if ("title" in V1) TITLE = v1cut("title", jnorm(V1["title"], 0), 64, 256)
  if ("msg" in V1) MSG = v1cut("msg", jnorm(V1["msg"], 0), 200, 800)
  for (i = 1; i <= N; i++) {
    if (ND[i]) continue
    g = gpath(NP[i])
    if (NT[i] == "a" || NT[i] == "o") {
      if (kind == "relay" && (g in STR) && lim(STR, g) == "-") { kill(i); continue }
      if (NT[i] == "a" && (g in CNT)) {
        c = lim(CNT, g)
        if (c == "-") { kill(i); continue }
        n = 0
        for (k = 1; k <= NC[i]; k++) {
          if (ND[CH[i, k]]) continue
          n++
          if (n > c + 0) kill(CH[i, k])
        }
        if (n > c + 0) {
          rec(NP[i], n)
          if (g == "req.ask.qs") nocan("answer")
        }
      }
      continue
    }
    if (!(g in STR)) continue
    c = lim(STR, g)
    if (c == "-") { kill(i); continue }
    if (c + 0 > 0 && length(NV[i]) > c + 0) {
      rec(NP[i], length(NV[i]))
      NV[i] = ucut(NV[i], 1000000000, c + 0)
    }
  }
  for (i = 1; i <= N; i++) ORIG[i] = live(i)
  # step 1: the last item of the first non-empty array
  split("req.others turn.bg req.scopes req.ask.qs", ARR, " ")
  while (size() > budget) {
    done = 0
    for (a = 1; a <= 4 && !done; a++) {
      i = node(ARR[a])
      if (!i || live(i) == 0) continue
      c = lastlive(i)
      unrec(NP[c]); kill(c)
      rec(ARR[a], ORIG[i])
      if (ARR[a] == "req.ask.qs") nocan("answer")
      if (live(i) == 0) {
        if (ARR[a] == "req.scopes") { kill(i); nocan("allow_scope") }
        if (ARR[a] == "req.others") { kill(i); drop("req.affects") }
      }
      done = 1
    }
    if (!done) break
  }
  # step 2: whole objects
  split("req.ask req.scopes req.modes turn sub req", OBJ, " ")
  for (a = 1; a <= 6 && size() > budget; a++) {
    i = node(OBJ[a])
    if (!i) continue
    b = length(ser(i))
    unrec(OBJ[a]); kill(i)
    rec(OBJ[a], b)
    if (OBJ[a] == "req.ask") { nocan("answer"); nocan("allow_scope") }
    if (OBJ[a] == "req.scopes") nocan("allow_scope")
  }
  print plain()
  m = "META"
  i = node("req")
  if (i) {
    m = m " rq=" (node("req.id") ? NV[IDX["req.id"]] : "") " win=" (node("req.win") ? NV[IDX["req.win"]] : "")
    s = ""; i = node("req.can")
    if (i) for (k = 1; k <= NC[i]; k++) if (!ND[CH[i, k]]) s = s (s == "" ? "" : ",") NV[CH[i, k]]
    m = m " can=" s
    s = ""; i = node("req.affects")
    if (i) for (k = 1; k <= NC[i]; k++) if (!ND[CH[i, k]]) s = s (s == "" ? "" : ",") NV[CH[i, k]]
    m = m " aff=" s
    i = node("req.scopes"); m = m " ns=" (i ? live(i) : 0)
    s = ""; i = node("req.modes")
    if (i) for (k = 1; k <= NC[i]; k++) if (!ND[CH[i, k]]) s = s (s == "" ? "" : ",") NV[CH[i, k]]
    m = m " modes=" s
    s = ""; i = node("req.ask.qs")
    m = m " nq=" (i ? live(i) : 0)
  }
  print m
  for (k = 1; k <= NM; k++) print META[k]
}
'

V2=0 V2C=0 FACTS='' AT='' SPEC='' MSGF='' NOMSG='' WAITOV='' METAF='' ING_MT=''
RAWSID='' TID='' PMODE='' DIRV='' SUBID='' SUBTYPE='' SUBPAR='' OCV='' CWD_BASEF='' T0=0 V2X=''

# Adds the @-parameter $1 (JSON-escaped value $2, nothing if empty).
at() { [ -n "${2:-}" ] || return 0; AT="$AT@.$1${TAB}s$TAB$2$NL"; }

# FACTS of the event, once.
v2_facts() {
  [ -n "$FACTS" ] && return 0
  FACTS=$(printf '%s' "$INPUT" | awk "$NORM_FN$JSON_FACTS" 2>/dev/null)
}

# The raw text of container $1 of the event (an answer hands it back).
raw_span() { printf '%s' "$INPUT" | awk -v rawp="$1" "$NORM_FN$JSON_FACTS" 2>/dev/null; }

# SPEC from FACTS, AT and the extra parameter lines $1; V2=1.
v2_spec() {
  v2_facts
  SPEC=$( { printf '%s\n' "$FACTS"; printf '%s' "$AT"; printf '%s' "${1:-}"; } | awk "$NORM_FN$V2_SPEC" 2>/dev/null)
  V2=1
}

# The plaintext of SPEC for the loaded link (plaintext()); META to METAF.
v2_plain() { # rid ev nonce
  vf=0
  [ "$L_FMT" = 2 ] && vf=1
  vd=0
  [ -n "$3" ] && vd=1
  vx=''
  [ "$2" = done ] && vx=${XFLAGS:-}
  vo=$( {
    printf '=rid\t%s\n=ev\t%s\n=app\t%s\n=host\t%s\n=cwd\t%s\n' "$1" "$2" "$APP" "$(json_text "$L_LABEL" 100000 100000)" "$CWD_BASEF"
    [ -n "$NOMSG" ] || printf '=msg\t%s\n' "$MSGF"
    # A usage event's own fields: v1 ones (ctx, lims, plan) after cwd, uq and
    # cost before ts (section 9.1).
    [ "$2" = usage ] && printf '=uv1\t%s\n=uv2\t%s\n' "$USAGE_JSON" "$USAGE_V2"
    printf '=xflags\t%s\n=nonce\t%s\n=ts\t%s\n' "$vx" "$3" "$TS"
    printf '%s\n' "$SPEC"
  } | awk -v kind="${L_KIND:-relay}" -v fmt2="$vf" -v dec="$vd" -v waitov="$WAITOV" "$NORM_FN$V2_BUILD" 2>/dev/null)
  [ -n "$METAF" ] && printf '%s\n' "$vo" | sed 1d >"$METAF" 2>/dev/null
  printf '%s\n' "$vo" | sed -n 1p
}

# The agent's version for a cached `--version` (D13): its executable's path
# and the version, in run/ver.<name>; run again in the background when the
# executable is newer than the cache or moved. The output format is not
# measured (M16): the first dotted number is taken.
ver_cache() { # executable-name
  vb=$(command -v "$1" 2>/dev/null) || return 0
  case $vb in /*) ;; *) return 0 ;; esac
  vc=$RUN_DIR/ver.$1
  vp=$(sed -n 1p "$vc" 2>/dev/null)
  [ "$vp" = "$vb" ] && AV=$(sed -n 2p "$vc" 2>/dev/null)
  [ "$vp" = "$vb" ] && ! [ "$vb" -nt "$vc" ] && return 0
  ( set -C; printf '' >"$vc.lock" ) 2>/dev/null || return 0
  trap '' HUP
  (
    "$vb" --version </dev/null >"$vc.out" 2>/dev/null &
    vk=$!
    ( sleep 15; kill "$vk" 2>/dev/null ) &
    wait "$vk" 2>/dev/null
    v=$(head -c 4096 "$vc.out" 2>/dev/null | awk 'match($0, /[0-9]+[.][0-9]+[0-9A-Za-z.+_-]*/) { print substr($0, RSTART, RLENGTH); exit }')
    case $v in '' | *[!0-9A-Za-z.+_-]*) ;; *) printf '%s\n%s\n' "$vb" "$v" >"$vc.tmp" && mv -f "$vc.tmp" "$vc" ;; esac
    rm -f "$vc.out" "$vc.tmp" "$vc.lock"
  ) </dev/null >/dev/null 2>&1 &
}

# JSON lines -> the string value of the top-level key "version" of the last
# line that has one (cut=1: the first line is a partial one, skipped).
TOP_VERSION='
function topver(s,   n, i, c, d, ins, esc, st, key, ks) {
  # Scanned up to just past the last "version" (no key there after it).
  n = length(s); i = 0
  while ((c = index(substr(s, i + 1), "\"version\"")) > 0) i += c
  if (!i) return ""
  if (n > i + 79) n = i + 79
  d = 0; ins = 0; esc = 0; st = ""; key = ""
  for (i = 1; i <= n; i++) {
    c = substr(s, i, 1)
    if (ins) {
      if (esc) esc = 0
      else if (c == "\\") esc = 1
      else if (c == "\"") {
        ins = 0
        if (d == 1 && st == "k") key = substr(s, ks, i - ks)
        else if (d == 1 && st == "v" && key == "version") return substr(s, ks, i - ks)
      }
      continue
    }
    if (c == "\"") { ins = 1; ks = i + 1 }
    else if (c == "{" || c == "[") { d++; if (d == 1) st = (c == "{") ? "k" : "" }
    else if (c == "}" || c == "]") { d--; if (d < 1) return "" }
    else if (d == 1 && c == ":") st = "v"
    else if (d == 1 && c == ",") { st = "k"; key = "" }
  }
  return ""
}
{ L[NR] = $0 }
END {
  for (j = NR; j > cut; j--) {
    if (!index(L[j], "\"version\"")) continue
    v = topver(L[j])
    if (v != "") { print v; exit }
  }
}'

# AV and AVS: the agent's version and where it came from (section 10.1).
v2_version() {
  AV='' AVS=''
  case $AGENT in
    claude)
      # The top-level "version" of the last transcript line that has one, in
      # the last 256 KiB (the first line there cut unless the file is
      # shorter): not a "version" inside a tool result or message.
      vf=$(input_file "$TPATH")
      if [ -n "$vf" ]; then
        vz=$(wc -c 2>/dev/null <"$vf" | tr -d ' ')
        is_uint "$vz" || vz=0
        AV=$(tail -c 262144 "$vf" 2>/dev/null | awk -v cut=$((vz > 262144)) "$TOP_VERSION" 2>/dev/null)
      fi
      AVS=transcript
      ;;
    codex)
      vf=$(input_file "$TPATH")
      [ -n "$vf" ] && AV=$(head -c 65536 "$vf" 2>/dev/null | awk 'match($0, /"cli_version"[ ]*:[ ]*"[^"]*"/) { v = substr($0, RSTART, RLENGTH - 1); sub(/.*"/, "", v); print v; exit }')
      AVS=rollout
      ;;
    copilot) AV=${COPILOT_CLI_BINARY_VERSION:-} AVS=env ;;
    opencode | agy | grok) ver_cache "$AGENT"; AVS=cache ;;
  esac
  case $AV in '' | *[!0-9A-Za-z.+_-]*) AV='' ;; esac
  [ "${#AV}" -le 32 ] || AV=''
}

is_id() { # value: section 3 id format
  case $1 in '' | *[!A-Za-z0-9._:-]*) return 1 ;; esac
  [ "${#1}" -le 128 ]
}

# Codex: the last turn's approval and sandbox policy from the rollout, as
# its permission mode (`on-request/read-only`).
codex_pm() {
  vf=$(input_file "$TPATH")
  [ -n "$vf" ] || return 0
  tail -c 262144 "$vf" 2>/dev/null | awk '
    /"type":"turn_context"/ {
      a = ""; b = ""
      if (match($0, /"approval_policy":"[A-Za-z0-9._-]*"/)) { a = substr($0, RSTART + 19, RLENGTH - 20) }
      if (match($0, /"sandbox_policy":[{]"type":"[A-Za-z0-9._-]*"/)) { b = substr($0, RSTART + 26, RLENGTH - 27) }
      if (a != "") pm = a (b != "" ? "/" b : "")
    }
    END { print pm }'
}

# The common fields (section 3) as @-parameters, once per run.
v2_common() {
  [ "$V2C" = 1 ] && return 0
  V2C=1
  at pv "$HOOK_VERSION"
  v2_version
  at av "$AV"
  [ -n "$AV" ] && at avs "$AVS"
  vs=$RAWSID
  # An OpenCode subagent's request comes from its own (child) session.
  if [ -n "$SUBPAR_SESSION" ] && is_id "$SUBPAR_SESSION" && is_id "$RAWSID"; then
    vs=$SUBPAR_SESSION SUBID=$RAWSID SUBTYPE=${SUBTYPE:-subagent}
  fi
  is_id "$vs" && at sid "$vs"
  is_id "$TID" && at tid "$TID"
  if is_id "$SUBID"; then
    at sub.id "$SUBID"
    at sub.type "$SUBTYPE"
    is_id "$SUBPAR" && at sub.parent "$SUBPAR"
  fi
  case $DIRV in /* | [A-Za-z]:'\\'*) at dir "$DIRV" ;; esac
  cv='' cp=''
  case $AGENT in
    claude) [ -n "${CLAUDE_CONFIG_DIR:-}" ] && cv=CLAUDE_CONFIG_DIR cp=$CLAUDE_CONFIG_DIR ;;
    codex) [ -n "${CODEX_HOME:-}" ] && [ "${CODEX_HOME%/}" != "$HOME/.codex" ] && cv=CODEX_HOME cp=$CODEX_HOME ;;
    grok) [ -n "${GROK_HOME:-}" ] && [ "${GROK_HOME%/}" != "$HOME/.grok" ] && cv=GROK_HOME cp=$GROK_HOME ;;
    copilot) [ -n "${COPILOT_HOME:-}" ] && cv=COPILOT_HOME cp=$COPILOT_HOME ;;
    opencode)
      if [ "$OCV" != 2 ]; then
        if [ -n "${OPENCODE_CONFIG_DIR:-}" ]; then cv=OPENCODE_CONFIG_DIR cp=$OPENCODE_CONFIG_DIR
        elif [ -n "${OPENCODE_CONFIG:-}" ]; then cv=OPENCODE_CONFIG cp=$OPENCODE_CONFIG
        elif [ -n "${XDG_CONFIG_HOME:-}" ] && [ "${XDG_CONFIG_HOME%/}" != "$HOME/.config" ]; then cv=XDG_CONFIG_HOME cp=$XDG_CONFIG_HOME
        fi
      fi
      ;;
  esac
  if [ -n "$cv" ] && [ -n "$cp" ]; then
    at cfg.var "$cv"
    at cfg.path "$(json_text "$cp" 100000 100000)"
  fi
  [ "$AGENT" = codex ] && PMODE=$(codex_pm)
  case $PMODE in '' | *[!A-Za-z0-9._:/-]*) ;; *) [ "${#PMODE}" -le 48 ] && at pm "$PMODE" ;; esac
  if [ "$AGENT" = opencode ] && [ "$OCV" = 2 ]; then at mux unknown
  elif [ -n "${TMUX:-}" ]; then at mux tmux
  elif [ -n "${STY:-}" ]; then at mux screen
  fi
}

# Event time in milliseconds where `date` has them (GNU), for `tms`.
v2_tms() {
  if [ "${SIMPLETERM_HOOK_TEST:-}" = 1 ] && [ -n "${SIMPLETERM_HOOK_TEST_TMS:-}" ]; then
    printf '%s' "$SIMPLETERM_HOOK_TEST_TMS"
    return 0
  fi
  vt=$(date +%s%3N 2>/dev/null)
  case $vt in *[!0-9]*) ;; ?????????????) printf '%s' "$vt" ;; esac
}

# Prepares SPEC for an event: the common fields, `tms`, and the extra
# parameter lines $1 (request kind, end of a turn, state, result).
v2_prep() { # [extra lines]
  v2_common
  V2X=${1:-}
  v2_spec "$V2X@.tms${TAB}s$TAB$(v2_tms)$NL"
}

# --- states and results to the tunnel (sections 6.2, 5.6) -----------------------

has_tunnel() {
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    case $(head -c 4096 "$f" 2>/dev/null) in *kind=tunnel*) return 0 ;; esac
  done <<EOF
$LINKS
EOF
  return 1
}

# A state event (section 6.2) to the tunnels, when the session's state
# changed, one a second at most (a change within the second goes a second
# later unless another replaced it). A subagent's start or stop is an event
# of its own: sent each time, at once, and it neither replaces a session
# state nor is replaced by one. $2: extra parameter lines (the turn).
send_state() { # st [extra]
  [ -n "$LINKS" ] && has_tunnel || return 0
  sf=$RUN_DIR/$SID.st sl=''
  case $1 in
    sub_start | sub_stop) ;;
    *)
      sl=$(cat "$sf" 2>/dev/null)
      [ "${sl%% *}" = "$1" ] && return 0
      ;;
  esac
  srid=$RID
  if [ "${RID_USED:-0}" = 1 ]; then
    srid=$(rand_hex 8)
    is_hex "$srid" 16 || return 0
  fi
  ss=$SPEC sx=$V2X sm=$NOMSG
  v2_prep "${2:-}@.st${TAB}s$TAB$1$NL"
  NOMSG=1
  case $1 in
    sub_start | sub_stop)
      send_bg state "$srid" tunnel
      SPEC=$ss V2X=$sx NOMSG=$sm
      return 0
      ;;
  esac
  printf '%s %s %s\n' "$1" "$NOW" "$srid" >"$sf" 2>/dev/null
  if [ "${sl#* }" != "$sl" ] && [ "$(printf '%s' "$sl" | cut -d' ' -f2)" = "$NOW" ]; then
    trap '' HUP
    (
      sleep 1
      [ "$(cut -d' ' -f3 "$sf" 2>/dev/null)" = "$srid" ] || exit 0
      later_send state tunnel
    ) </dev/null >/dev/null 2>&1 &
  else
    send_bg state "$srid" tunnel
  fi
  SPEC=$ss V2X=$sx NOMSG=$sm
}

# --- session records (section 8.2) --------------------------------------------

# Only sessions started in SimpleTerm (SIMPLETERM=1), with an id that can
# be resumed; OpenCode 2.x not at all (D14: its service's environment is the
# first TUI's).
sess_ok() {
  [ "${SIMPLETERM:-}" = 1 ] || return 1
  [ "$AGENT" = opencode ] && [ "$OCV" = 2 ] && return 1
  case $AGENT in claude | codex | grok | agy | copilot | opencode) ;; *) return 1 ;; esac
  is_id "$RAWSID" || return 1
  SESS_DIR=$ST_DIR/sessions/$APP
  case $RAWSID in
    *:*) SESS_NAME=$(sha256_hex "$RAWSID" | cut -c1-32) ;;
    *) SESS_NAME=$RAWSID ;;
  esac
  [ -n "$SESS_NAME" ] || return 1
  SESS=$SESS_DIR/$SESS_NAME
}

# The session's last hook event: <name>.beat's modification time (touched
# when 30 seconds old, or always with $1 = force).
sess_beat() { # [force]
  sess_ok || return 0
  bt=$RUN_DIR/$SID.beatts
  if [ "${1:-}" != force ]; then
    t=$(cat "$bt" 2>/dev/null)
    is_uint "$t" && [ $((NOW - t)) -le 30 ] && [ "$t" -le "$NOW" ] && [ -f "$SESS.beat" ] && return 0
  fi
  mkdir -p "$SESS_DIR" 2>/dev/null && chmod 700 "$ST_DIR/sessions" "$SESS_DIR" 2>/dev/null
  touch "$SESS.beat" 2>/dev/null && printf '%s\n' "$NOW" >"$bt" 2>/dev/null
}

# The session's title and where it came from (section 10.7): SESS_TITLE
# (JSON-escaped), SESS_TSRC.
sess_title() {
  SESS_TITLE='' SESS_TSRC=''
  tf=$(input_file "$TPATH")
  case $AGENT in
    claude)
      [ -n "$tf" ] && SESS_TITLE=$(tail -c 262144 "$tf" 2>/dev/null | awk '
        /"type":"ai-title"/ && match($0, /"aiTitle":"([^"\\]|\\.)*"/) { t = substr($0, RSTART + 11, RLENGTH - 12) }
        END { print t }')
      SESS_TSRC=ai
      ;;
    codex)
      ci=${CODEX_HOME:-$HOME/.codex}/session_index.jsonl
      [ -f "$ci" ] && SESS_TITLE=$(tail -c 262144 "$ci" 2>/dev/null | awk -v id="\"$RAWSID\"" '
        index($0, "\"id\":" id) && match($0, /"thread_name":"([^"\\]|\\.)*"/) { t = substr($0, RSTART + 15, RLENGTH - 16) }
        END { print t }')
      SESS_TSRC=ai
      ;;
    grok)
      [ -n "$tf" ] && [ -f "${tf%/*}/summary.json" ] && SESS_TITLE=$(head -c 65536 "${tf%/*}/summary.json" | awk -v want=generated_title "$JSON_GET" 2>/dev/null | sed -n 's/^generated_title=//p')
      SESS_TSRC=ai
      ;;
    copilot)
      [ -n "$tf" ] && [ -f "${tf%/*}/workspace.yaml" ] &&
        SESS_TITLE=$(json_text "$(sed -n 's/^name: *//p' "${tf%/*}/workspace.yaml" 2>/dev/null | head -n 1 | sed "s/^[\"']//; s/[\"']\$//")" 120 400)
      # The session's name: a model-made title (interactive), else the first prompt.
      SESS_TSRC=ai
      ;;
    opencode) SESS_TITLE=$OCTITLE SESS_TSRC=ai ;;
  esac
  [ -n "$SESS_TITLE" ] || SESS_TSRC=''
}

# Writes the session's record (state running|idle; $2 the prompt): a temp
# file renamed into place, 4096 bytes at most. Keeps started_at, the last
# prompt and a title it cannot find again from the record before.
sess_write() { # state [prompt]
  sess_ok || return 0
  mkdir -p "$SESS_DIR" 2>/dev/null && chmod 700 "$ST_DIR/sessions" "$SESS_DIR" 2>/dev/null
  old=$(head -c 4096 "$SESS.json" 2>/dev/null)
  ow=''
  [ -n "$old" ] && ow=$(printf '%s' "$old" | awk -v want=started_at,last_prompt,title,title_src "$JSON_GET" 2>/dev/null)
  so=$(printf '%s\n' "$ow" | sed -n 's/^started_at=//p')
  is_uint "$so" || so=$NOW
  lp=$(json_trim "${2:-}" 200 800)
  [ -n "$lp" ] || lp=$(printf '%s\n' "$ow" | sed -n 's/^last_prompt=//p')
  sess_title
  ti=$(json_trim "$SESS_TITLE" 120 400) ts=$SESS_TSRC
  if [ -z "$ti" ]; then
    ti=$(printf '%s\n' "$ow" | sed -n 's/^title=//p') ts=$(printf '%s\n' "$ow" | sed -n 's/^title_src=//p')
  fi
  if [ -z "$ti" ] && [ -n "$lp" ]; then ti=$(json_trim "$lp" 120 400) ts=prompt; fi
  case $ts in ai | user | prompt) ;; *) ts='' ;; esac
  [ -n "$ts" ] || ti=''
  j='{"v":1,"app":"'$APP'"'
  [ -n "$AV" ] && j=$j',"av":"'$AV'"'
  j=$j',"sid":"'$RAWSID'"'
  case $DIRV in /* | [A-Za-z]:'\\'*) j=$j',"dir":"'$(json_trim "$DIRV" 100000 1024)'"' ;; esac
  [ -n "$ti" ] && j=$j',"title":"'$ti'","title_src":"'$ts'"'
  [ -n "$lp" ] && j=$j',"last_prompt":"'$lp'"'
  j=$j',"last_at":'$NOW',"started_at":'$so
  tp=$(input_file "$TPATH")
  case $tp in /*) j=$j',"tpath":"'$(json_text "$tp" 100000 1024)'"' ;; esac
  case $PMODE in '' | *[!A-Za-z0-9._:/-]*) ;; *) [ "${#PMODE}" -le 48 ] && j=$j',"pm":"'$PMODE'"' ;; esac
  for kv in $(printf '%s' "$AT" | sed -n "s/^@\\.cfg\\.var${TAB}s${TAB}/var=/p"); do cvv=${kv#var=}; done
  cpp=$(printf '%s' "$AT" | sed -n "s/^@\\.cfg\\.path${TAB}s${TAB}//p")
  [ -n "${cvv:-}" ] && [ -n "$cpp" ] && j=$j',"cfg":{"var":"'$cvv'","path":"'$(json_trim "$cpp" 100000 1024)'"}'
  j=$j',"state":"'$1'"'
  if [ "$AGENT" = opencode ] && [ "$OCV" = 2 ]; then j=$j',"mux":"unknown"'
  elif [ -n "${TMUX:-}" ]; then j=$j',"mux":"tmux"'
  elif [ -n "${STY:-}" ]; then j=$j',"mux":"screen"'
  fi
  j=$j'}'
  [ "${#j}" -le 4096 ] || return 0
  printf '%s\n' "$j" >"$SESS.json.$$" 2>/dev/null && chmod 600 "$SESS.json.$$" 2>/dev/null && mv -f "$SESS.json.$$" "$SESS.json" 2>/dev/null
  rm -f "$SESS.json.$$" 2>/dev/null
  sess_keep
}

# A session starts or is resumed: no `.ended` any more.
sess_start() { # [prompt]
  sess_ok || return 0
  sess_beat force
  rm -f "$SESS.ended" 2>/dev/null
}

# The session ended: `.ended`, unless the record's .beat is newer than this
# event (it was resumed meanwhile: a late end must not mark it ended).
sess_end() {
  sess_ok || return 0
  [ -f "$SESS.beat" ] && [ -f "$RUN_DIR/t0.$$" ] && [ "$SESS.beat" -nt "$RUN_DIR/t0.$$" ] && return 0
  mkdir -p "$SESS_DIR" 2>/dev/null && chmod 700 "$ST_DIR/sessions" "$SESS_DIR" 2>/dev/null
  printf '' 2>/dev/null >"$SESS.ended"
}

# Keeps records whose last activity (.beat or the record, the later) is
# within 30 days, 200 at most (D11); at most once in ten minutes.
sess_keep() {
  kf=$RUN_DIR/sessions.keep
  t=$(cat "$kf" 2>/dev/null)
  is_uint "$t" && [ $((NOW - t)) -lt 600 ] && [ "$t" -le "$NOW" ] && return 0
  printf '%s\n' "$NOW" >"$kf" 2>/dev/null
  # Newest first by the later of .beat and .json: the first time a name
  # appears in `ls -t` is its last activity.
  ls -t "$ST_DIR"/sessions/*/*.beat "$ST_DIR"/sessions/*/*.json 2>/dev/null | awk '
    { b = $0; sub(/\.(beat|json)$/, "", b) }
    !(b in seen) { seen[b] = 1; n++; if (n > 200) print b }' | while IFS= read -r b; do
    rm -f "$b.json" "$b.beat" "$b.ended" 2>/dev/null
  done
  find "$ST_DIR/sessions" -type f \( -name '*.json' -o -name '*.beat' \) -mtime +30 2>/dev/null | while IFS= read -r f; do
    b=${f%.*}
    # Both old (or gone) before the record goes.
    [ -n "$(find "$b.json" "$b.beat" -mtime -31 2>/dev/null)" ] && continue
    rm -f "$b.json" "$b.beat" "$b.ended" 2>/dev/null
  done
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

# The value of key $1 in agent-hook.conf (section 9.2 D21, its first 4 KiB;
# a UTF-8 BOM at the start of the file is dropped, TDS_AGENT_ALERTS section
# 6.7): the first line `key=value` of that key decides, blanks allowed
# around the line and the `=`. From the value a CR, a comment (from the first `#`), the
# blanks around it and one pair of quotes around all of it are taken away
# (`usage_ask = "off"  # never`). Empty: the default.
conf_val() { # key
  [ -f "$ST_DIR/agent-hook.conf" ] || return 0
  head -c 4096 "$ST_DIR/agent-hook.conf" 2>/dev/null | awk -v k="$1" -v q="'" '
  NR == 1 && substr($0, 1, 3) == "\357\273\277" { $0 = substr($0, 4) }
  {
    i = index($0, "="); if (!i) next
    kk = substr($0, 1, i - 1); gsub(/^[ \t]+|[ \t]+$/, "", kk)
    if (kk != k) next
    vv = substr($0, i + 1); gsub(/\r/, "", vv); sub(/#.*/, "", vv); gsub(/^[ \t]+|[ \t]+$/, "", vv)
    f = substr(vv, 1, 1)
    if (length(vv) >= 2 && (f == "\"" || f == q) && substr(vv, length(vv)) == f) vv = substr(vv, 2, length(vv) - 2)
    print vv; exit
  }' 2>/dev/null
}

conf_int() { # key default
  v=$(conf_val "$1")
  is_uint "$v" || v=$2
  # Decimal, as the app and the PowerShell hook read it: no leading zeros
  # ($(( )) reads 060 as octal 48 and fails on 0090; TDS_AGENT_ALERTS
  # section 6.7 R13).
  while :; do
    case $v in 0[0-9]*) v=${v#0} ;; *) break ;; esac
  done
  printf '%s' "$v"
}

# What the hook does with each key (TDS_AGENT_ALERTS section 6.7):
# the device-wait cap of agent $1 (<agent>_wait, at most 540; agy at most
# 110: its hook's timeout is 120 seconds).
conf_wait_cap() { # agent
  case $1 in
    codex) c=$(conf_int codex_wait 60) ;;
    agy) c=$(conf_int agy_wait 0) ;;
    opencode) c=$(conf_int opencode_wait 540) ;;
    *) c=$(conf_int claude_wait 540) ;;
  esac
  [ "$c" -le 540 ] || c=540
  [ "$1" = agy ] && [ "$c" -gt 110 ] && c=110
  printf '%s' "$c"
}

# One long-poll's seconds: poll_wait 1 to 25, else 25.
conf_poll_wait() {
  c=$(conf_int poll_wait 25)
  [ "$c" -ge 1 ] && [ "$c" -le 25 ] || c=25
  printf '%s' "$c"
}

# The seconds a done of agent $1 waits (done_delay; 3 where a newer event of
# the session may come within moments, else 0).
conf_done_delay() { # agent
  case $1 in codex | gemini | opencode | copilot | agy) c=0 ;; *) c=3 ;; esac
  conf_int done_delay $c
}

# True unless usage (the v1 key) is 0 as a number (00 too, R27): context
# and limits are reported.
conf_usage_on() {
  [ "$(conf_int usage 1)" -ne 0 ]
}

# True unless word key $1 (usage_ask, usage_ask_codex) is off, 0, no or
# false, in any case.
conf_on() { # key
  case $(conf_word "$1" on | tr 'A-Z' 'a-z') in off | 0 | no | false) return 1 ;; esac
  return 0
}

# The decision response $1: DST DDEC DMAC and the decision extension's
# envelope DXV DXIV DXCT DXMAC (section 5.1; at the end of the response, so
# the first 8 KiB are read; an older hook reads only 4 KiB).
resp_decision() {
  DST='' DDEC='' DMAC='' DXV='' DXIV='' DXCT='' DXMAC=''
  [ -f "$1" ] || return 0
  while IFS= read -r kv; do
    case $kv in
      status=*) DST=${kv#status=} ;;
      decision=*) DDEC=${kv#decision=} ;;
      dmac=*) DMAC=${kv#dmac=} ;;
      dext.v=*) DXV=${kv#dext.v=} ;;
      dext.iv=*) DXIV=${kv#dext.iv=} ;;
      dext.ct=*) DXCT=${kv#dext.ct=} ;;
      dext.mac=*) DXMAC=${kv#dext.mac=} ;;
    esac
  done <<EOF
$(head -c 8192 "$1" 2>/dev/null | awk -v want=status,decision,dmac,dext.v,dext.iv,dext.ct,dext.mac "$JSON_GET" 2>/dev/null)
EOF
}

# Long-polls one link for the decision on rid $1 and writes $3: line 1
# allow, deny, invalid (the dmac does not match) or none; line 2 the decision
# extension: none, bad (its MAC does not match or it does not open) or ok;
# line 3 its plaintext when ok.
poll_link() { # rid nonce outfile deadline
  cpid='' r=none x=none xp=''
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
        resp_decision "$resp"
        if [ "$DST" = decided ]; then
          r=invalid
          case $DDEC in
            allow | deny)
              is_hex "$DMAC" 64 &&
                [ "$(hmac_hex "$L_MAC" "st1-dec.$1.$DDEC.$2")" = "$DMAC" ] && r=$DDEC
              ;;
          esac
          if [ "$r" != invalid ] && [ -n "$DXV$DXIV$DXCT$DXMAC" ]; then
            # The extension is MACed with st1-dext. (not the event's st1.),
            # so an event envelope cannot be passed back as one.
            x=bad
            DXCT=$(printf '%s' "$DXCT" | sed 's#\\/#/#g')
            case $DXCT in '' | *[!A-Za-z0-9+/=]*) DXCT='' ;; esac
            if [ "$DXV" = 1 ] && is_hex "$DXIV" 32 && is_hex "$DXMAC" 64 && [ -n "$DXCT" ] && [ "${#DXCT}" -le 2944 ] &&
              [ "$(hmac_hex "$L_MAC" "st1-dext.$DXIV.$DXCT")" = "$DXMAC" ]; then
              xp=$(printf '%s' "$DXCT" | openssl enc -d -aes-256-cbc -K "$L_ENC" -iv "$DXIV" -a -A 2>/dev/null | head -c 4096 | tr -d '\n\r')
              [ -n "$xp" ] && x=ok
            fi
          fi
          log "decision link=$(printf %.8s "$L_LINK") result=$r dext=$x"
          break
        fi
        [ $(($(date +%s) - now)) -ge 1 ] || sleep 1
        ;;
      404 | 410 | 401 | 403 | 409)
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
  printf '%s\n%s\n%s\n' "$r" "$x" "$xp" >"$3.tmp" && mv -f "$3.tmp" "$3"
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

# --- decisions (TDS_AGENT_EVENTS_V2 section 5) -----------------------------------

# A reason the user typed, wrapped as Claude Code reads a user's rejection:
# a bare reason is read as script output and ignored [measured].
CLAUDE_DENY='The user doesn'"'"'t want to proceed with this tool use. The tool use was rejected (eg. if it was a file edit, the new_string was NOT written to the file). To tell you how to proceed, the user said:\n'
# What an Antigravity Stop hook says to go on with an approved plan.
AGY_PLAN_OK='The user approved the plan in SimpleTerm. Implement it now.'

# Prints a device decision (allow|deny) or the no-decision answer (none) in
# the agent's own format (the v1 decisions; v2_emit has the others).
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

# The answers of an `answer` decision (lines E: the event's facts, X: the
# extension's) in the agent's form, or BAD: Claude Code takes an object
# {question: answer} (a choice by its label, several as an array, typed text
# as it is, both joined with ", "), the OpenCode bridge a list per question.
# Every question must be answered (M11), choices index the original list,
# typed text only where the question takes it.
ANSWER_AWK='
BEGIN { FS = "\t" }
# (a key given twice counts with its first value, section 5.5)
$1 == "E" { if (!($2 in E)) E[$2] = substr($0, length($1) + length($2) + length($3) + 4); next }
$1 == "X" { if (!($2 in X)) { X[$2] = substr($0, length($1) + length($2) + length($3) + 4); XT[$2] = $3 }; next }
function lab(q, v,   b) { b = qp "." q ".options." v; return ((b "." fl) in E) ? E[b "." fl] : E[b] }
END {
  n = 0; bad = 0
  for (k = 0; k < 64 && (("answers." k ".q") in X); k++) {
    q = X["answers." k ".q"]
    if (XT["answers." k ".q"] != "r" || q !~ /^[0-9]+$/ || q + 0 >= nq || (q in SEEN)) { bad = 1; break }
    SEEN[q] = 1; n++
    no = 0
    while (no < 64 && (((qp "." q ".options." no "." fl) in E) || ((qp "." q ".options." no) in E))) no++
    np = 0
    for (m = 0; m < 64 && (("answers." k ".pick." m) in X); m++) {
      v = X["answers." k ".pick." m]
      if (v !~ /^[0-9]+$/ || v + 0 >= no) { bad = 1; break }
      PL[k, np++] = lab(q, v)
    }
    if (bad) break
    t = (XT["answers." k ".text"] == "s") ? X["answers." k ".text"] : ""
    if ((t != "" && !free) || length(t) > 2400 || (np == 0 && t == "")) { bad = 1; break }
    NP[k] = np; TX[k] = t; QI[k] = q
  }
  if (bad || n != nq || n == 0) { print "BAD"; exit }
  if (mode == "claude") {
    o = "{"
    for (k = 0; k < n; k++) {
      if (TX[k] != "" || NP[k] == 1) {
        v = ""
        for (m = 0; m < NP[k]; m++) v = v (m ? ", " : "") PL[k, m]
        if (TX[k] != "") v = v (v == "" ? "" : ", ") TX[k]
        v = "\"" v "\""
      } else {
        v = "["
        for (m = 0; m < NP[k]; m++) v = v (m ? "," : "") "\"" PL[k, m] "\""
        v = v "]"
      }
      o = o (k ? "," : "") "\"" E[qp "." QI[k] "." fq] "\":" v
    }
    print o "}"
  } else {
    for (q = 0; q < nq; q++) for (k = 0; k < n; k++) if (QI[k] == q) {
      v = "["
      for (m = 0; m < NP[k]; m++) v = v (m ? "," : "") "\"" PL[k, m] "\""
      if (TX[k] != "") v = v (NP[k] ? "," : "") "\"" TX[k] "\""
      O[q] = v "]"
    }
    o = "["
    for (q = 0; q < nq; q++) o = o (q ? "," : "") O[q]
    print o "]"
  }
}'

# Prints decision $1 (a decision id, section 4.3) in the agent's format,
# with X_* from its extension (section 5.4). Returns 1 if there is nothing
# to print for it here.
v2_emit() { # act
  case $AGENT:$1 in
    *:allow | *:deny) emit_decision "$1" ;;
    claude:allow_scope)
      sg=$(raw_span "permission_suggestions.$X_ORIG")
      [ -n "$sg" ] || return 1
      printf '{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"allow","updatedPermissions":[%s]}}%s}\n' \
        "$sg" "$(state_json running)"
      ;;
    claude:deny_reason | claude:plan_refine)
      printf '{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"deny","message":"%s%s"}}%s}\n' \
        "$CLAUDE_DENY" "$X_REASON" "$(state_json running)"
      ;;
    claude:answer)
      qs=$(raw_span tool_input.questions)
      [ -n "$qs" ] && [ -n "$X_ANSWERS" ] || return 1
      printf '{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"allow","updatedInput":{"questions":%s,"answers":%s}}}%s}\n' \
        "$qs" "$X_ANSWERS" "$(state_json running)"
      ;;
    claude:plan_approve)
      ti=$(raw_span tool_input)
      [ -n "$ti" ] || return 1
      up=''
      [ "$X_MODE" = accept_edits ] && up=',"updatedPermissions":[{"type":"setMode","mode":"acceptEdits","destination":"session"}]'
      printf '{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"allow","updatedInput":%s%s}}%s}\n' \
        "$ti" "$up" "$(state_json running)"
      ;;
    codex:deny_reason)
      printf '{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"deny","message":"%s"}}}\n' "$X_REASON"
      ;;
    agy:deny_reason) ANSWERED=1; printf '{"decision":"deny","reason":"%s"}\n' "$X_REASON" ;;
    agy:plan_approve) ANSWERED=1; printf '{"decision":"continue","reason":"%s"}\n' "$AGY_PLAN_OK" ;;
    opencode:allow_scope) printf '{"decision":"allow","scope":"always"}\n' ;;
    opencode:deny_reason) printf '{"decision":"deny","message":"%s"}\n' "$X_REASON" ;;
    opencode:answer)
      [ -n "$X_ANSWERS" ] || return 1
      printf '{"decision":"answer","answers":%s}\n' "$X_ANSWERS"
      ;;
    *) return 1 ;;
  esac
}

# Other requests of the session that are open now (OpenCode: the bridge
# keeps run/oc.<session>.pending), but not request $1.
open_others() { # request id
  [ -f "$RUN_DIR/oc.$SID.pending" ] || return 0
  head -c 16384 "$RUN_DIR/oc.$SID.pending" 2>/dev/null | while IFS= read -r oo; do
    is_id "$oo" && [ "$oo" != "$1" ] && printf '%s\n' "$oo"
  done
}

# Judges the decision that link $1 (rq.$$.$1.*) brought (section 5.5): JV
# apply (JA the decision id), window (nothing to print: a v1 allow of a
# question), bad (1, 2, 4), changed (3, 5) or none (the wait ended without
# one).
rq_judge() { # i
  JV=none JA='' X_REASON='' X_MODE='' X_ANSWERS='' X_ORIG=''
  { IFS= read -r jd; IFS= read -r jx; IFS= read -r jp; } <"$RUN_DIR/rq.$$.$1.got"
  read -r js_push js_nonce js_rid js_dec js_kind js_code js_fmt <"$RUN_DIR/rq.$$.$1.st"
  jm=$(cat "$RUN_DIR/rq.$$.$1.meta" 2>/dev/null)
  jrq='' jwin='' jcan='' jaff='' jns=0 jmodes='' jnq=0 jsmap=''
  for kv in $(printf '%s\n' "$jm" | sed -n '1s/^META //p'); do
    case $kv in
      rq=*) jrq=${kv#rq=} ;; win=*) jwin=${kv#win=} ;; can=*) jcan=${kv#can=} ;; aff=*) jaff=${kv#aff=} ;;
      ns=*) jns=${kv#ns=} ;; modes=*) jmodes=${kv#modes=} ;; nq=*) jnq=${kv#nq=} ;;
    esac
  done
  jsmap=$(printf '%s\n' "$jm" | sed -n "s/^#smap${TAB}s${TAB}//p")
  [ -n "$jrq" ] || jrq=$REQ_ID
  # OpenCode 1.19 and 2.x settle the session's other open permission
  # requests with always and reject: these decisions are judged by the
  # requests open now, whatever the request carried when it was sent
  # (section 5.5-5). A question's reject settles only the question.
  [ "$AGENT" = opencode ] && [ "$OCV" != 1.0 ] && [ "$EVENT" = PermissionRequest ] && jaff=allow_scope,deny,deny_reason
  case $jd in allow | deny) ;; invalid) JV=bad; return 0 ;; *) return 0 ;; esac
  [ "$jx" = bad ] && { JV=bad; return 0; }
  if [ "$jx" != ok ]; then
    # No extension (an older app, a relay before R2, an alert's quick
    # action): the decision's default meaning for the request.
    if [ "$jd" = deny ]; then JA=deny
    else
      case $jwin in question) JV=window; return 0 ;; plan) JA=plan_approve ;; *) JA=allow ;; esac
    fi
    if [ -n "$jaff" ] && [ "$JA" = deny ] && [ -n "$(open_others "$jrq")" ]; then JV=changed; return 0; fi
    if [ "$JA" = plan_approve ] && [ "$AGENT" = claude ]; then X_MODE=default; fi
    case ",$jcan," in *",$JA,"*) ;; *) [ -z "$jcan" ] || { JV=bad; return 0; } ;; esac
    JV=apply
    return 0
  fi
  # The extension (section 5.2).
  xv='' xf='' xr='' xn='' xd='' xq='' xa='' xs='' xm='' xseen='' xks=' '
  xfacts=$(printf '%s' "$jp" | awk "$NORM_FN$JSON_FACTS" 2>/dev/null)
  while IFS="$TAB" read -r xk xt xval; do
    # A key given twice counts with its first value (section 5.5).
    case $xks in *" $xk "*) continue ;; esac
    xks="$xks$xk "
    case $xk in
      v) xv=$xval ;; fmt) xf=$xval ;; rid) xr=$xval ;; nonce) xn=$xval ;; decision) xd=$xval ;;
      req) xq=$xval ;; act) xa=$xval ;; scope) [ "$xt" = r ] && xs=$xval ;; mode) xm=$xval ;;
      reason) [ "$xt" = s ] && X_REASON=$xval ;;
      seen.*) xseen="$xseen $xval" ;;
    esac
  done <<EOF
$xfacts
EOF
  if [ "$xv" != 1 ] || [ "$xr" != "$js_rid" ] || [ "$xn" != "$js_nonce" ] || [ "$xd" != "$jd" ]; then JV=bad; return 0; fi
  # N10: the request the user saw.
  [ -n "$jrq" ] && [ "$xq" = "$jrq" ] || { JV=changed; return 0; }
  case ",$jcan," in *",$xa,"*) ;; *) JV=bad; return 0 ;; esac
  case $xa in
    allow | allow_scope | allow_edit | answer | plan_approve | form_accept) [ "$jd" = allow ] || { JV=bad; return 0; } ;;
    *) [ "$jd" = deny ] || { JV=bad; return 0; } ;;
  esac
  case $xa in
    allow_scope)
      is_uint "$xs" && [ "$xs" -lt "$jns" ] || { JV=bad; return 0; }
      set -f
      set -- $jsmap
      set +f
      # The agent's own index of the scope, where the hook keeps a map
      # (Claude Code's suggestions; OpenCode's scope is its one pattern
      # list). Checked first: a shift past the end ends dash and ksh.
      if [ "$#" -gt 0 ]; then
        [ "$xs" -lt "$#" ] || { JV=bad; return 0; }
        shift "$xs"
        X_ORIG=$1
      fi
      ;;
    plan_approve)
      [ -z "$xm" ] || case ",$jmodes," in *",$xm,"*) X_MODE=$xm ;; *) JV=bad; return 0 ;; esac
      ;;
    deny_reason | plan_refine)
      [ -n "$X_REASON" ] && [ "${#X_REASON}" -le 6000 ] || { JV=bad; return 0; }
      ;;
    answer)
      case $AGENT in claude) aq=tool_input.questions am=claude ;; *) aq=questions am=opencode ;; esac
      X_ANSWERS=$( { printf '%s\n' "$FACTS" | sed 's/^/E	/'; printf '%s\n' "$xfacts" | sed 's/^/X	/'; } |
        awk -v qp="$aq" -v fq=question -v fl=label -v free=1 -v nq="$jnq" -v mode="$am" "$ANSWER_AWK" 2>/dev/null)
      [ -n "$X_ANSWERS" ] && [ "$X_ANSWERS" != BAD ] || { JV=bad; return 0; }
      ;;
  esac
  # N10: the other requests that this decision also settles were all seen.
  case ",$jaff," in
    *",$xa,"*)
      case " $xseen " in *" $jrq "*) ;; *) JV=changed; return 0 ;; esac
      for oo in $(open_others "$jrq"); do
        case " $xseen " in *" $oo "*) ;; *) JV=changed; return 0 ;; esac
      done
      ;;
  esac
  JA=$xa JV=apply
}

# --- waiting for a decision (section 4.6) --------------------------------------

# Sends request SPEC as link index $1 to link file $2 when its kind is $8
# (tunnel, relay or all): rid $3, ev $4, decidable $5 (1: with a nonce),
# waitov $6, relay time $7. Leaves rq.$$.$1.st
# "<push> <nonce|-> <rid> <dec> <kind> <http code> <fmt>" and rq.$$.$1.meta.
rq_send() { # i file rid ev dec waitov maxtime pass
  load_link "$2" || return 0
  case $8 in tunnel) [ "$L_KIND" = tunnel ] || return 0 ;; relay) [ "$L_KIND" != tunnel ] || return 0 ;; esac
  rd=$5 rw=$6
  # A question is decidable only where the receiver takes decisions on
  # questions (fmt=2; for the relay that is R1). Elsewhere it is an alert,
  # and one whose window would hide while the hook waits does not wait.
  if [ "$4" = question ] && [ "$L_FMT" != 2 ] && [ "$rd" = 1 ]; then
    rd=0
    [ "$rw" = hidden ] && rw=none
  fi
  rn=''
  if [ "$rd" = 1 ]; then
    rn=$(rand_hex 16)
    [ "${SIMPLETERM_HOOK_TEST:-}" = 1 ] && [ -n "${SIMPLETERM_HOOK_TEST_NONCE:-}" ] && rn=$SIMPLETERM_HOOK_TEST_NONCE
    is_hex "$rn" 32 || { rd=0; rn=''; }
  fi
  METAF=$RUN_DIR/rq.$$.$1.meta WAITOV=$rw ING_MT=$7
  ri=$(ingest_raw "$3" "$4" "$rn" "$RUN_DIR/ing.$$.$1")
  rp=${ri%% *} rc=${ri#* }
  re=${rc#* } rc=${rc%% *}
  if [ "$rc" = 400 ] && [ "$re" = invalid-nh ] && [ -n "$rn" ] && [ "$L_KIND" != tunnel ]; then
    # The relay lost R1 (rolled back): the same rid once more, not
    # decidable, and no wait there (section 2.4).
    log "ingest invalid-nh link=$(printf %.8s "$L_LINK"): again without a nonce"
    rd=0 rn=''
    ri=$(ingest_raw "$3" "$4" '' "$RUN_DIR/ing.$$.$1")
    rp=${ri%% *} rc=${ri#* }
    rc=${rc%% *}
  fi
  printf '%s %s %s %s %s %s %s\n' "$rp" "${rn:--}" "$3" "$rd" "${L_KIND:-relay}" "$rc" "${L_FMT:-1}" >"$RUN_DIR/rq.$$.$1.st"
}

# Starts the poller of link index $1 if it took the request to wait on.
rq_poll() { # i
  [ -f "$RUN_DIR/rq.$$.$1.st" ] || return 0
  read -r pp pn pr pd pk pc pf <"$RUN_DIR/rq.$$.$1.st"
  [ "$pp" = sent ] && [ "$pd" = 1 ] || return 0
  load_link "$(cat "$RUN_DIR/rq.$$.$1.f")" || return 0
  rm -f "$RUN_DIR/rq.$$.$1.dec"
  printf '' >"$RUN_DIR/rq.$$.$1.w"
  (poll_link "$pr" "$pn" "$RUN_DIR/rq.$$.$1.dec" "$deadline") </dev/null >/dev/null 2>&1 &
  PIDS="$PIDS $!"
}

# A result event (section 5.6) to the tunnel of link index $1: scope $2,
# out $3, the request event's rid $4, decision id or window kind $5.
rq_result() { # i scope out rrid [act|win]
  load_link "$(cat "$RUN_DIR/rq.$$.$1.f" 2>/dev/null)" || return 0
  [ "$L_KIND" = tunnel ] || return 0
  rx="@.res.scope${TAB}s$TAB$2$NL@.res.req${TAB}s$TAB$REQ_ID$NL@.res.rrid${TAB}s$TAB$4$NL@.res.out${TAB}s$TAB$3$NL"
  [ "$3" = applied ] && [ -n "${5:-}" ] && rx="$rx@.res.act${TAB}s$TAB$5$NL"
  [ "$3" = window ] && [ -n "${5:-}" ] && rx="$rx@.res.win${TAB}s$TAB$5$NL"
  rs=$( { printf '%s\n' "$FACTS"; printf '%s' "$AT"; printf '%s' "$rx"; } | awk "$NORM_FN$V2_SPEC" 2>/dev/null)
  (
    SPEC=$rs NOMSG=1 METAF='' WAITOV='' ING_MT=''
    TS=$(date +%s)
    is_uint "$TS" || TS=0
    rr=$(rand_hex 8)
    is_hex "$rr" 16 && ingest_one "$rr" resolved '' "$RUN_DIR/ing.$$.res.$1" >/dev/null
  )
}

# Ends the request: the request-level result to every tunnel that took it,
# in the background ($1 out, $2 the link index whose decision applied).
rq_finish() { # out [i] [act]
  for p in $PIDS; do kill "$p" 2>/dev/null; done
  PIDS=''
  [ -n "${REQ_ID:-}" ] || return 0
  trap '' HUP
  (
    i=0
    while [ "$i" -lt "$RQ_N" ]; do
      i=$((i + 1))
      [ -f "$RUN_DIR/rq.$$.$i.st" ] || continue
      read -r fp fn fr fd fk fc ff <"$RUN_DIR/rq.$$.$i.st"
      [ "$fk" = tunnel ] && [ "$fc" = 200 ] || continue
      fo=$1 fa=${3:-}
      if [ "$1" = applied ] && [ "${2:-}" != "$i" ]; then fo=other fa=''; fi
      [ "$fo" = window ] && fa=$RQ_WIN
      rq_result "$i" req "$fo" "$fr" "$fa"
    done
    rm -f "$RUN_DIR"/rq."$$".* "$RUN_DIR"/ing."$$".* "$RUN_DIR"/dec."$$".* 2>/dev/null
    trim_log f
  ) </dev/null >/dev/null 2>&1 &
}

# A decision from link index $1 was dropped ($2 bad or changed, section
# 5.5): that link's wait ends; a tunnel of a v2 app hears it at once and gets
# the request again under a new rid (3 times at most).
rq_reject() { # i bad|changed
  read -r xp xn xr xd xk xc xf <"$RUN_DIR/rq.$$.$1.st"
  log "decision link-$1 dropped: $2"
  [ "$xk" = tunnel ] && [ "$xf" = 2 ] || return 0
  rq_result "$1" link "$2" "$xr"
  xcount=$(cat "$RUN_DIR/rq.$$.$1.n" 2>/dev/null)
  is_uint "$xcount" || xcount=0
  [ "$xcount" -lt 3 ] || return 0
  answered_locally "$start" "$FP" && return 0
  printf '%s\n' $((xcount + 1)) >"$RUN_DIR/rq.$$.$1.n"
  if [ "$AGENT" = opencode ]; then
    # The other open requests as they are now.
    FACTS=$(printf '%s\n' "$FACTS" | sed '/^others\./d')
    xo=0
    for oo in $(open_others "$REQ_ID"); do
      FACTS="$FACTS$NL""others.$xo${TAB}s$TAB$oo"
      xo=$((xo + 1))
    done
    v2_spec "$V2X@.tms${TAB}s$TAB$(v2_tms)$NL"
  fi
  xnr=$(rand_hex 8)
  is_hex "$xnr" 16 || return 0
  rq_send "$1" "$(cat "$RUN_DIR/rq.$$.$1.f")" "$xnr" "$RQ_EV" 1 '' 5 tunnel
  rq_poll "$1"
}

# True if a tunnel answered the probe (section 4.6): HTTP 404 with error
# `unknown` (and not shown:false) to a decision poll of an unknown rid.
tunnel_probe() {
  tp=0 tjobs=''
  rm -f "$RUN_DIR/probe.$$.ok"
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    tp=$((tp + 1))
    (
      load_link "$f" || exit 0
      [ "$L_KIND" = tunnel ] || exit 0
      pr=$(rand_hex 8)
      is_hex "$pr" 16 || exit 0
      o=$RUN_DIR/probe.$$.$tp
      code=$(http GET "/v1/decision?rid=$pr&wait=0" '' 5 "$o")
      e=$(resp_get "$o" error,shown)
      rm -f "$o"
      log "probe link=$(printf %.8s "$L_LINK") http=$code"
      [ "$code" = 404 ] || exit 0
      case $e in *error=unknown*) ;; *) exit 0 ;; esac
      case $e in *shown=false*) exit 0 ;; esac
      printf '' >"$RUN_DIR/probe.$$.ok"
    ) </dev/null >/dev/null 2>&1 &
    tjobs="$tjobs $!"
  done <<EOF
$LINKS
EOF
  for p in $tjobs; do wait "$p" 2>/dev/null; done
  [ -f "$RUN_DIR/probe.$$.ok" ] && { rm -f "$RUN_DIR/probe.$$.ok"; return 0; }
  return 1
}

# Sends the request in SPEC (ev $1) the way $2 says (section 4.6) and waits
# per link; then prints the agent's answer, or nothing (its safe
# no-decision), and tells the tunnels how the request ended.
#   shared   every link at once, decidable (Claude Code, OpenCode)
#   hidden   tunnels first; if one answered, the relay only gets an alert
#            without a nonce; otherwise the relay is decidable (Codex, agy)
#   relay    the relay only, decidable (agy after an unanswered probe)
#   agyplan  tunnels an alert (wait none); the fmt=2 relay decidable, the
#            others an alert, only when no tunnel answered and agy_wait > 0
request_flow() { # ev mode
  RQ_EV=$1 RQ_MODE=$2
  # (The Antigravity hook's timeout is 120 seconds, hooks.json.)
  cap=$(conf_wait_cap "$AGENT")
  POLL_WAIT=$(conf_poll_wait)
  # The cap counts from the hook's start (the tunnel's 5 seconds and the
  # relay's ingest included, section 4.6).
  start=$T0
  RES_BASE=$(cat "$RUN_DIR/$SID.res" 2>/dev/null)
  deadline=$((start + cap))
  PIDS='' RQ_N=0
  REQ_ID=$(printf '%s\n' "$SPEC" | sed -n "s/^req\\.id${TAB}s${TAB}//p")
  RID_USED=1
  RQ_WIN=$(printf '%s\n' "$SPEC" | sed -n "s/^req\\.win${TAB}s${TAB}//p")
  AGENT_PID=$(agent_pid)
  # The agent may end the wait (Claude Code signals hooks when a turn is
  # interrupted, the OpenCode bridge when its prompt was answered): print
  # nothing and leave the decision to the agent.
  rq_sig=gone
  [ "$AGENT" = opencode ] && rq_sig=terminal
  trap 'rq_finish $rq_sig; log "permission signal"; finish' TERM INT HUP

  while IFS= read -r f; do
    [ -n "$f" ] || continue
    RQ_N=$((RQ_N + 1))
    printf '%s\n' "$f" >"$RUN_DIR/rq.$$.$RQ_N.f"
  done <<EOF
$LINKS
EOF
  rq_pass() { # pass dec waitov ev maxtime
    i=0 JOBS=''
    while [ "$i" -lt "$RQ_N" ]; do
      i=$((i + 1))
      (rq_send "$i" "$(cat "$RUN_DIR/rq.$$.$i.f")" "$RID" "$4" "$2" "$3" "$5" "$1") </dev/null >/dev/null 2>&1 &
      JOBS="$JOBS $!"
    done
    for p in $JOBS; do wait "$p" 2>/dev/null; done
  }
  tunnel_took() { # a tunnel answered HTTP 200
    i=0
    while [ "$i" -lt "$RQ_N" ]; do
      i=$((i + 1))
      [ -f "$RUN_DIR/rq.$$.$i.st" ] || continue
      read -r tp tn tr td tk tc tf <"$RUN_DIR/rq.$$.$i.st"
      [ "$tk" = tunnel ] && [ "$tc" = 200 ] && return 0
    done
    return 1
  }
  remain() { r=$((deadline - $(date +%s))); [ "$r" -ge 1 ] || r=1; [ "$r" -le 20 ] || r=20; printf '%s' "$r"; }
  case $RQ_MODE in
    shared) rq_pass all 1 '' "$RQ_EV" 20 ;;
    relay) rq_pass relay 1 '' "$RQ_EV" "$(remain)" ;;
    hidden)
      rq_pass tunnel 1 '' "$RQ_EV" 5
      if tunnel_took; then
        # The app is connected: other devices get an alert without buttons,
        # so a decision there is never left unheard.
        trap '' HUP
        (rq_pass relay 0 none question 20) </dev/null >/dev/null 2>&1 &
      else
        rq_pass relay 1 '' "$RQ_EV" "$(remain)"
      fi
      ;;
    agyplan)
      rq_pass tunnel 0 none "$RQ_EV" 5
      if ! tunnel_took && [ "$cap" -gt 0 ]; then
        rq_pass relay 1 hidden "$RQ_EV" "$(remain)"
      else
        rq_pass relay 0 none "$RQ_EV" 20
      fi
      ;;
  esac

  i=0
  while [ "$i" -lt "$RQ_N" ]; do i=$((i + 1)); rq_poll "$i"; done

  decision='' dlink='' rq_out=window
  while :; do
    waiting=0
    i=0
    while [ "$i" -lt "$RQ_N" ]; do
      i=$((i + 1))
      [ -f "$RUN_DIR/rq.$$.$i.w" ] || continue
      waiting=1
      [ -f "$RUN_DIR/rq.$$.$i.dec" ] || continue
      mv -f "$RUN_DIR/rq.$$.$i.dec" "$RUN_DIR/rq.$$.$i.got"
      rm -f "$RUN_DIR/rq.$$.$i.w"
      rq_judge "$i"
      if [ "$JV" = apply ] || [ "$JV" = window ]; then
        if answered_locally "$start" "$FP"; then rq_out=terminal; break 2; fi
        decision=$JA dlink=$i
        [ "$JV" = window ] && decision=''
        break 2
      fi
      case $JV in bad | changed) rq_reject "$i" "$JV" ;; esac
    done
    [ "$waiting" = 1 ] || break
    if answered_locally "$start" "$FP"; then
      log "permission answered-at-terminal"
      rq_out=terminal
      break
    fi
    if [ -n "$AGENT_PID" ] && ! kill -0 "$AGENT_PID" 2>/dev/null; then
      log "permission agent-gone"
      rq_out=gone
      break
    fi
    if [ "$(date +%s)" -ge "$deadline" ]; then log "permission timeout"; break; fi
    sleep 1
  done
  trap - TERM INT HUP
  LOGGED=1
  if [ -n "$decision" ] && v2_emit "$decision"; then
    log "permission $decision"
    rq_finish applied "$dlink" "$decision"
  else
    [ "$rq_out" = window ] && [ -z "$dlink" ] && log "permission no-decision"
    [ "$AGENT" = agy ] && agy_default
    rq_finish "$rq_out"
  fi
}

# --- usage (#342) ------------------------------------------------------------

# ISO 8601 date-time (YYYY-MM-DDTHH:MM:SS, a fraction, Z or +-HH:MM) to
# epoch seconds; -1 if it is not one (section 9.1 `at`, the windows' resets).
ISO_FN='
function isoepoch(t,   y, mo, d, h, mi, se, r, off, yy, era, yoe, doy, doe) {
  if (t !~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9][Tt ][0-9][0-9]:[0-9][0-9]:[0-9][0-9]/) return -1
  y = substr(t, 1, 4) + 0; mo = substr(t, 6, 2) + 0; d = substr(t, 9, 2) + 0
  h = substr(t, 12, 2) + 0; mi = substr(t, 15, 2) + 0; se = substr(t, 18, 2) + 0
  r = substr(t, 20)
  sub(/^[.][0-9]+/, "", r)
  if (r == "Z" || r == "z") off = 0
  else if (r ~ /^[+-][0-9][0-9]:?[0-9][0-9]$/) {
    off = (substr(r, 2, 2) * 60 + substr(r, length(r) - 1, 2)) * 60
    if (substr(r, 1, 1) == "+") off = -off
  } else return -1
  if (mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || se > 59) return -1
  yy = y - (mo <= 2 ? 1 : 0); era = int(yy / 400); yoe = yy - era * 400
  doy = int((153 * (mo > 2 ? mo - 3 : mo + 9) + 2) / 5) + d - 1
  doe = yoe * 365 + int(yoe / 4) - int(yoe / 100) + doy
  return (era * 146097 + doe - 719468) * 86400 + h * 3600 + mi * 60 + se + off
}
# Minutes from a month before date-time t to t (a monthly window: Copilot).
function monthmin(t,   e, y, mo, d, md) {
  e = isoepoch(t)
  if (e < 0) return -1
  y = substr(t, 1, 4) + 0; mo = substr(t, 6, 2) + 0 - 1; d = substr(t, 9, 2) + 0
  if (mo < 1) { mo = 12; y-- }
  md = (mo == 2) ? ((y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)) ? 29 : 28) : ((mo == 4 || mo == 6 || mo == 9 || mo == 11) ? 30 : 31)
  if (d > md) d = md
  return int((e - isoepoch(sprintf("%04d-%02d-%02d", y, mo, d) substr(t, 11))) / 60)
}
# A non-negative decimal (digits, a fraction) as micro-units, exactly
# (strings, no floats); -1 if it is not one. And back, without trailing
# zeros. 100 - pct of Copilot, USD of Grok and OpenCode.
function micro(v,   i, f) {
  if (v !~ /^[0-9]+([.][0-9]+)?$/) return -1
  i = v; f = ""
  if (index(v, ".")) { i = substr(v, 1, index(v, ".") - 1); f = substr(v, index(v, ".") + 1) }
  f = substr(f "000000", 1, 6)
  return (i f) + 0
}
function unmicro(m,   i, f) {
  sub(/^0+/, "", m)
  m = substr("0000000", 1, 7 - length(m) > 0 ? 7 - length(m) : 0) m
  i = substr(m, 1, length(m) - 6); f = substr(m, length(m) - 5)
  sub(/^0+/, "", i); if (i == "") i = "0"
  sub(/0+$/, "", f)
  return i (f == "" ? "" : "." f)
}'


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
USAGE_CODEX=$JSON_FN$ISO_FN'
function lim(id, p, w, r) {
  if (!isdec(p) || !isnum(w) || !isnum(r)) return
  lims = lims " " id ":" p ":" w ":" r ":file" (at >= 0 ? ":" at : "")
}
BEGIN {
  jwant("timestamp,payload.type,payload.info.last_token_usage.total_tokens,payload.info.model_context_window,payload.rate_limits.limit_id,payload.rate_limits.primary.used_percent,payload.rate_limits.primary.window_minutes,payload.rate_limits.primary.resets_at,payload.rate_limits.secondary.used_percent,payload.rate_limits.secondary.window_minutes,payload.rate_limits.secondary.resets_at,payload.rate_limits.plan_type,payload.rate_limits.rate_limit_reached_type")
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
      # The record time is when Codex learned these values (section 9.1).
      at = isoepoch(GOT["timestamp"])
      id = GOT["payload.rate_limits.limit_id"]
      gsub(/[^A-Za-z0-9_.-]/, "", id)
      # (A null limit_id: the ask names that limit codex too.)
      if (id == "" || id == "null") id = "codex"
      lim(id ".primary", GOT["payload.rate_limits.primary.used_percent"], GOT["payload.rate_limits.primary.window_minutes"], GOT["payload.rate_limits.primary.resets_at"])
      lim(id ".secondary", GOT["payload.rate_limits.secondary.used_percent"], GOT["payload.rate_limits.secondary.window_minutes"], GOT["payload.rate_limits.secondary.resets_at"])
      p = GOT["payload.rate_limits.plan_type"]
      if (p ~ /^[A-Za-z0-9_-]+$/ && p != "null") plan = p
      r = GOT["payload.rate_limits.rate_limit_reached_type"]
      if (r != "" && r != "null" && r != "false") reached = 1
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
  printf " %s:%s:%s:%s:statusline", id, p, w, r
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

# A usage line "<ctx|-> <win|-> <src|-> <est 0|1> <baseline|-> <plan|->
# <reached 0|1> [<id>:<pct>:<win min>:<reset epoch>[:<src>[:<at epoch>]]]..."
# -> two lines: the OSC 9 body (v1; none without a context) and the v1
# fields of the `usage` event, with each window's `src` and `at` (section
# 9.1).
USAGE_FMT='
function num(v) { return v ~ /^[0-9]+$/ }
function dec(v) { return v ~ /^[0-9]+([.][0-9]+)?$/ }
NR == 1 {
  hc = num($1)
  if (!hc && $1 != "-") exit
  if (hc && !($3 ~ /^[a-z]+$/)) exit
  osc = ""; js = ""
  if (hc) {
    osc = "simpleterm:usage v=1 agent=" app " ctx=" $1
    js = ",\"ctx\":{\"used\":" $1
    if (num($2)) { osc = osc " win=" $2; js = js ",\"win\":" $2 }
    if (num($5)) js = js ",\"baseline\":" $5
    osc = osc " src=" $3; js = js ",\"src\":\"" $3 "\""
    if ($4 == 1) { osc = osc " est=1"; js = js ",\"est\":true" }
    js = js "}"
  }
  la = ""; nl = 0
  for (i = 8; i <= NF; i++) {
    n = split($i, P, ":")
    if (n < 4 || n > 6) continue
    if (!(P[1] ~ /^[A-Za-z0-9_.-]+$/) || !dec(P[2]) || !num(P[3]) || !num(P[4])) continue
    if (n >= 5 && P[5] !~ /^(ask|file|statusline|hook)$/) continue
    if (n == 6 && !num(P[6])) continue
    if (hc) osc = osc " lim=" P[1] ":" P[2] ":" P[3] ":" P[4]
    e = "{\"id\":\"" P[1] "\",\"pct\":" P[2] ",\"win_min\":" P[3] ",\"resets_at\":" P[4]
    if (n >= 5) e = e ",\"src\":\"" P[5] "\""
    if (n == 6) e = e ",\"at\":" P[6]
    la = la (la == "" ? "" : ",") e "}"; nl++
  }
  if ($7 == 1) { if (hc) osc = osc " lim=reached"; la = la (la == "" ? "" : ",") "{\"id\":\"reached\"}"; nl++ }
  # (As in v1, a report with a context always names its windows, [] too.)
  if (hc || nl) js = js ",\"lims\":[" la "]"
  if ($6 ~ /^[A-Za-z0-9_-]+$/ && $6 != "-") js = js ",\"plan\":\"" $6 "\""
  print osc
  print js
}'

# Copilot session events (events.jsonl), the facts of its newest
# model.model_call_success line that has quotaSnapshots -> usage line windows
# "copilot.<item>:<pct>:<win>:<reset>:file:<at>" (section 9.3): an item
# counts when it is not unlimited and has requests; pct is 100 less the
# remaining percentage, the window the month before its reset.
COPILOT_QUOTA=$ISO_FN'
BEGIN { FS = "\t" }
$1 == "timestamp" && $2 == "s" { ts = $3; next }
index($1, "data.quotaSnapshots.") == 1 {
  k = substr($1, 21); f = k; sub(/\..*/, "", k); sub(/^[^.]*\./, "", f)
  if (!(k in SEEN)) { SEEN[k] = 1; K[++nk] = k }
  if (!((k SUBSEP f) in Q)) Q[k, f] = $3
}
END {
  at = isoepoch(ts); out = ""
  for (i = 1; i <= nk; i++) {
    k = K[i]; id = k; gsub(/[^A-Za-z0-9_.-]/, "", id)
    if (id == "" || Q[k, "isUnlimitedEntitlement"] != "false") continue
    if (Q[k, "entitlementRequests"] !~ /^[0-9]+$/ || Q[k, "entitlementRequests"] + 0 <= 0) continue
    m = micro(Q[k, "remainingPercentage"])
    if (m < 0 || m + 0 > 100000000) continue
    r = isoepoch(Q[k, "resetDate"]); w = monthmin(Q[k, "resetDate"])
    if (r < 0 || w <= 0) continue
    out = out " copilot." id ":" unmicro(100000000 - m) ":" w ":" r ":file" (at >= 0 ? ":" at : "")
  }
  print substr(out, 2)
}'

# Grok usage.json (facts) or the OpenCode bridge (cost, tokens_in,
# tokens_out) -> the `cost` object, or nothing (section 9.3).
COST_FN=$ISO_FN'
function costjson(usd, tin, tout,   s) {
  s = ""
  if (usd != "") s = s ",\"usd\":" usd
  if (tin ~ /^[0-9]+$/) s = s ",\"tok_in\":" tin
  if (tout ~ /^[0-9]+$/) s = s ",\"tok_out\":" tout
  if (s == "") return ""
  return ",\"cost\":{" substr(s, 2) ",\"scope\":\"session\"}"
}'
GROK_COST=$COST_FN'
BEGIN { FS = "\t" }
$2 == "r" && !($1 in G) { G[$1] = $3 }
END {
  # costUsdTicks: 10^-10 USD each (xAI cost_in_usd_ticks); micro-USD exact.
  t = G["session.costUsdTicks"]; usd = ""
  if (t ~ /^[0-9]+$/) { sub(/^0+/, "", t); usd = unmicro(length(t) > 4 ? substr(t, 1, length(t) - 4) : "0") }
  printf "%s", costjson(usd, G["session.inputTokens"], G["session.outputTokens"])
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

# Sets U_LINE (see USAGE_FMT) and U_COST (the `cost` object) for the
# current event, or leaves them empty.
usage_compute() {
  U_LINE='' U_COST=''
  case $AGENT in
    copilot)
      # The quota of the newest model call in the session's events (file).
      f=$(input_file "$TPATH")
      [ -n "$f" ] || return 0
      ql=$(tail -c 262144 "$f" 2>/dev/null | awk 'index($0, "\"quotaSnapshots\"") && index($0, "\"model.model_call_success\"") { l = $0 } END { print l }')
      [ -n "$ql" ] || return 0
      w=$(printf '%s\n' "$ql" | awk "$NORM_FN$JSON_FACTS" 2>/dev/null | awk "$COPILOT_QUOTA" 2>/dev/null)
      [ -n "$w" ] && U_LINE="- - - 0 - - 0 $w"
      ;;
    grok)
      # Tokens and cost of the session (usage.json; no limits).
      is_id "$RAWSID" || return 0
      uf=''
      for d in "$HOME"/.grok/sessions/*/"$RAWSID"; do [ -f "$d/usage.json" ] && uf=$d/usage.json; done
      [ -n "$uf" ] || return 0
      U_COST=$(head -c 262144 "$uf" 2>/dev/null | awk "$NORM_FN$JSON_FACTS" 2>/dev/null | awk "$GROK_COST" 2>/dev/null)
      ;;
    opencode)
      # Tokens and cost of the session, from the bridge (no limits).
      U_COST=$(awk -v c="$OCCOST" -v i="$OCTIN" -v o="$OCTOUT" "$COST_FN"' BEGIN { m = micro(c); printf "%s", costjson(m >= 0 ? unmicro(m) : "", i, o) }' 2>/dev/null)
      ;;
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

# Reports context, rate limits and cost when they changed: an OSC 9 for the
# terminal (Claude Code in SimpleTerm, USAGE_SEQ; v1, context and windows
# only) and a `usage` event for the SSH tunnel links (section 9.1). The relay
# gets none: it does not push them (an iOS push is always an alert) and every
# request costs a function call. At a turn's end it may also ask the agent
# (usage_ask).
usage_report() {
  USAGE_SEQ=''
  conf_usage_on || return 0
  usage_compute
  osc='' USAGE_JSON=''
  if [ -n "$U_LINE" ]; then
    out=$(printf '%s\n' "$U_LINE" | awk -v app="$APP" "$USAGE_FMT" 2>/dev/null)
    osc=$(printf '%s\n' "$out" | sed -n 1p)
    USAGE_JSON=$(printf '%s\n' "$out" | sed -n 2p)
  fi
  usage_ask
  [ -n "$USAGE_JSON$U_COST" ] || return 0
  key=$osc$USAGE_JSON$U_COST
  [ "$(cat "$RUN_DIR/$SID.usage" 2>/dev/null)" != "$key" ] || return 0
  # Recorded as sent only once SimpleTerm has it: on Claude Code's terminal
  # (printed below), or when a tunnel link took the event. Otherwise it goes
  # again next time, though unchanged, in case the app connects meanwhile.
  if [ -n "$osc" ]; then
    USAGE_SEQ='\u001b]9;'$osc'\u0007'
    [ "$AGENT" = claude ] && [ "${SIMPLETERM:-}" = 1 ] && printf '%s\n' "$key" >"$RUN_DIR/$SID.usage" 2>/dev/null
  fi
  usage_send "$(usage_rid)" "$U_COST" "$RUN_DIR/$SID.usage" "$key"
}

# A usage event's own rid (SIMPLETERM_HOOK_TEST_URID in tests).
usage_rid() {
  if [ "${SIMPLETERM_HOOK_TEST:-}" = 1 ] && [ -n "${SIMPLETERM_HOOK_TEST_URID:-}" ]; then
    printf '%s' "$SIMPLETERM_HOOK_TEST_URID"
  else
    rand_hex 8
  fi
}

# The `usage` event (USAGE_JSON, then $2: uq, cost) to the tunnels, with the
# common fields (section 9.1); $3 gets text $4 once a tunnel took it.
usage_send() { # rid tail [file text]
  is_hex "$1" 16 || return 0
  us=$SPEC ux=$V2X um=$NOMSG
  USAGE_V2=$2 NOMSG=1
  v2_prep
  send_bg usage "$1" tunnel "${3:-}" "${4:-}"
  SPEC=$us V2X=$ux NOMSG=$um USAGE_V2=''
}

# --- usage asks (TDS_AGENT_EVENTS_V2 section 9.2) ----------------------------------

# Every version and OS is asked (D22, 2026-11-03 user decision). Measured
# against a local mock API (2026-11-03, .hjc/research/2026-11-03-usage-ask
# of the app): 0 model requests in 22 asks of Claude Code 2.1.316 and
# 2.1.317 and 11 of Codex 0.165.0 on macOS (the same harness caught 6 and 31
# in real turns). What guards the others: the version of the executable
# that ran stops for good after an answer showing spend or a hook, or after
# 3 failed asks in a row (run/ask.<agent>.off).

# A value of agent-hook.conf (conf_val), or $2 if empty. The caller compares
# it in any case.
conf_word() { # key default
  v=$(conf_val "$1")
  printf '%s' "${v:-$2}"
}

# True if the app is connected: a tunnel link whose last event got an HTTP
# 200 within 10 minutes (ingest_raw records it). A tunnel file left behind
# by a closed connection does not count.
tunnel_live() {
  tn=$(date +%s)
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    load_link "$f" || continue
    [ "$L_KIND" = tunnel ] || continue
    lt='' lc=''
    read -r lt lc 2>/dev/null <"$RUN_DIR/tun.$(printf %.8s "$L_LINK").last" || continue
    is_uint "$lt" && [ "$lc" = 200 ] && [ $((tn - lt)) -le 600 ] && [ $((lt - tn)) -le 60 ] && return 0
  done <<EOF
$LINKS
EOF
  return 1
}

# True if the last ask of file $1 (ask.<agent>.<h>) started less than 5
# minutes ago (a time more than 60 seconds ahead does not count).
ask_recent() { # ask-file
  la=$(cat "$1" 2>/dev/null)
  is_uint "$la" && [ $((NOW - la)) -lt 300 ] && [ $((la - NOW)) -le 60 ]
}

# True if asks of the agent's executable version $1 were stopped (an answer
# of that version showed model spend or a hook, or 3 asks in a row failed):
# run/ask.<agent>.off, one version a line (`unknown` among them).
ask_stopped() { # version
  [ -f "$RUN_DIR/ask.$AGENT.off" ] || return 1
  head -c 4096 "$RUN_DIR/ask.$AGENT.off" 2>/dev/null | awk -v v="$1" '$0 == v { f = 1; exit } END { exit !f }'
}

# How an ask starts its own process group (section 9.2 time): perl's
# setpgrp, else setsid (Linux, BusyBox); without either it cannot (a POSIX
# shell without job control does not start one: dash needs a terminal for
# set -m, macOS has no setsid), and its process tree is ended instead.
ask_group_how() {
  if command -v perl >/dev/null 2>&1; then
    ASK_GRP=perl
  elif command -v setsid >/dev/null 2>&1; then
    ASK_GRP=setsid
  else
    ASK_GRP=''
  fi
}

# Runs command "$@" in place (exec), as the leader of a process group of
# its own when ASK_GRP says how: its process id is that of the group.
ask_exec() { # command...
  case $ASK_GRP in
    perl) exec perl -e 'setpgrp(0, 0); exec { $ARGV[0] } @ARGV or exit 127' -- "$@" ;;
    setsid) exec setsid "$@" ;;
    *) exec "$@" ;;
  esac
}

# Ends process $1 and what it started: its process group when ask_exec
# started one (every process of it, those that left its tree too), else its
# tree (kill_tree). TERM, then KILL to what is left 2 seconds later.
ask_kill() { # pid
  is_uint "$1" && [ "$1" -gt 1 ] || return 0
  if [ -n "$ASK_GRP" ]; then
    # (`kill -SIG -<group>`: dash takes no `--`, bash no `-s SIG -<group>`.)
    kill -TERM -"$1" 2>/dev/null || return 0
    sleep 2
    kill -0 -"$1" 2>/dev/null && kill -KILL -"$1" 2>/dev/null
  else
    kill_tree "$1"
  fi
  return 0
}

# Ends process $1 and every process under it, where it has no process group
# of its own: the process and then those under it are stopped first, so
# that none starts another unseen while ps runs; then all get TERM and go on
# to take it, and what is left 2 seconds later KILL. A process that left
# the tree before (its parent gone) is not reached.
kill_tree() { # pid
  is_uint "$1" && [ "$1" -gt 1 ] || return 0
  kill -STOP "$1" 2>/dev/null || return 0
  kt=$1
  for kr in 1 2; do
    kt=$( { ps -A -o pid= -o ppid= 2>/dev/null || ps -o pid= -o ppid= 2>/dev/null; } | awk -v r="$1" '
      $1 ~ /^[0-9]+$/ && $2 ~ /^[0-9]+$/ { n[$2]++; k[$2, n[$2]] = $1 }
      END { q[1] = r; m = 1; for (i = 1; i <= m && m < 512; i++) { p = q[i]; for (j = 1; j <= n[p]; j++) q[++m] = k[p, j] } for (i = 1; i <= m; i++) printf "%s ", q[i] }' 2>/dev/null)
    # (Each a number: the words are the process ids.)
    # shellcheck disable=SC2086
    kill -STOP ${kt:-$1} 2>/dev/null
  done
  # shellcheck disable=SC2086
  kill ${kt:-$1} 2>/dev/null
  # shellcheck disable=SC2086
  kill -CONT ${kt:-$1} 2>/dev/null
  sleep 2
  for kp in ${kt:-$1}; do
    kill -0 "$kp" 2>/dev/null && kill -KILL "$kp" 2>/dev/null
  done
  return 0
}

# The folder an ask runs in: ~/.simpleterm/probe (700), with no project
# settings.
ask_probe_dir() {
  mkdir -p "$ST_DIR/probe" 2>/dev/null && chmod 700 "$ST_DIR/probe" 2>/dev/null
}

# The probe's environment, in a subshell: ~/.simpleterm/probe, SIMPLETERM_PROBE=1
# and none of the agent session's own variables (measured, Claude Code
# 2.1.316): an ask is not a child of that session.
ask_env() {
  cd "$ST_DIR/probe" || exit 0
  unset CLAUDECODE CLAUDE_CODE_ENTRYPOINT CLAUDE_CODE_SESSION_ID CLAUDE_CODE_CHILD_SESSION CLAUDE_CODE_EXECPATH \
    CLAUDE_CODE_SESSION_ATTENDED CLAUDE_CODE_MESSAGING_SOCKET CLAUDE_CODE_MESSAGING_TOKEN \
    CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS CLAUDE_EFFORT CLAUDE_PID AI_AGENT SIMPLETERM 2>/dev/null
  SIMPLETERM_PROBE=1
  export SIMPLETERM_PROBE
}

# True if $1 is a version as av is written (section 3): [0-9A-Za-z.+_-]{1,32}.
ask_ver_ok() { # version
  case $1 in '' | *[!0-9A-Za-z.+_-]*) return 1 ;; esac
  [ "${#1}" -le 32 ]
}

# The version of agent executable $1, which the ask would run (section 9.2
# condition 6, D21, D22): ASK_BV, and ASK_EXE the file that the ask then
# runs. Its links are followed to the end: .../versions/<version> (a native
# Claude Code install) gives the version. Otherwise run/ver.<agent> (D13,
# section 10.1: that file's path, and its --version's first dotted number or
# an empty line if it gave none) is used for the same file while the file is
# not newer: `unknown` if it holds no version. Else it is measured again in
# the background (15 seconds at most) and ASK_BV stays empty: no ask this
# turn.
ask_bin_version() { # executable
  ASK_BV='' ASK_EXE=''
  r=$1 n=0
  while [ -h "$r" ] && [ "$n" -lt 16 ]; do
    t=$(readlink "$r" 2>/dev/null) || return 0
    case $t in '') return 0 ;; /*) r=$t ;; *) r=${r%/*}/$t ;; esac
    n=$((n + 1))
  done
  [ -f "$r" ] && ! [ -h "$r" ] || return 0
  case $r in *"$CR"* | *'
'*) return 0 ;; esac
  v=''
  case ${r%/*} in */versions) v=${r##*/} ;; esac
  ask_ver_ok "$v" || v=''
  if [ -z "$v" ]; then
    vc=$RUN_DIR/ver.$AGENT
    if [ -f "$vc" ] && [ "$(sed -n 1p "$vc" 2>/dev/null)" = "$r" ] && ! [ "$r" -nt "$vc" ]; then
      v=$(sed -n 2p "$vc" 2>/dev/null)
      ask_ver_ok "$v" || v=unknown
    else
      ask_probe_dir || return 0
      # (A lock left by a measurement that never ended holds a minute.)
      [ -n "$(find "$vc.lock" -mmin +1 2>/dev/null)" ] && rm -f "$vc.lock"
      ( set -C; printf '' >"$vc.lock" ) 2>/dev/null || return 0
      trap '' HUP
      (
        ask_group_how
        v=$(
          ask_env
          ask_exec "$r" --version </dev/null >"$vc.out" 2>/dev/null &
          vk=$!
          ( sleep 15; ask_kill "$vk" ) </dev/null >/dev/null 2>&1 &
          wd=$!
          wait "$vk" 2>/dev/null
          # (Its sleep ends by itself: ending it as a tree needs ps, which can
          # be slow on a loaded machine.)
          kill "$wd" 2>/dev/null
          head -c 4096 "$vc.out" 2>/dev/null | awk 'match($0, /[0-9]+[.][0-9]+[0-9A-Za-z.+_-]*/) { print substr($0, RSTART, RLENGTH); exit }'
        )
        # (None: an empty line, so the same file is not measured again.)
        ask_ver_ok "$v" || v=''
        printf '%s\n%s\n' "$r" "$v" >"$vc.tmp" && mv -f "$vc.tmp" "$vc"
        rm -f "$vc.out" "$vc.tmp" "$vc.lock"
      ) </dev/null >/dev/null 2>&1 &
      return 0
    fi
  fi
  ASK_BV=$v ASK_EXE=$r
}

# The failed asks in a row of executable version ASK_BV (D22): the first line
# of run/ask.<agent>.fail (its first 4 KiB), `<version> <count>`; 0 if it is
# another version or not of that form.
ask_fails() {
  [ -f "$RUN_DIR/ask.$AGENT.fail" ] || { printf 0; return 0; }
  head -c 4096 "$RUN_DIR/ask.$AGENT.fail" 2>/dev/null | awk -v v="$ASK_BV" '
    NR == 1 { if ($0 ~ /^[0-9A-Za-z.+_-]+ [1-9][0-9]*$/ && substr($0, 1, length(v) + 1) == v " " && length($0) - length(v) <= 10) c = substr($0, length(v) + 2); exit }
    END { print c + 0 }' 2>/dev/null
}

# After an ask: an answer ($1 0) clears the count; a failed one (failed,
# timeout; $1 1) adds one, from 1 for another version, written whole to
# run/ask.<agent>.fail.<pid> and renamed over the file (not counted if that
# fails); the third stops that version (D22). Sign-in results (auth,
# not-subscriber) do not come here.
ask_fail_count() { # 1|0
  ff=$RUN_DIR/ask.$AGENT.fail
  if [ "$1" = 0 ]; then
    rm -f "$ff" 2>/dev/null
    return 0
  fi
  fc=$(($(ask_fails) + 1))
  if printf '%s %s\n' "$ASK_BV" "$fc" >"$ff.$$" 2>/dev/null && mv -f "$ff.$$" "$ff" 2>/dev/null; then
    [ "$fc" -ge 3 ] && ask_stop
  fi
  rm -f "$ff.$$" 2>/dev/null
  return 0
}

# Stops asks of executable version ASK_BV for good (run/ask.<agent>.off).
ask_stop() {
  ask_stopped "$ASK_BV" || printf '%s\n' "$ASK_BV" >>"$RUN_DIR/ask.$AGENT.off" 2>/dev/null
}

# At the end of a turn, while the app is connected, at most every 5 minutes
# per agent and settings folder: asks Claude Code or Codex for its limits in
# the background (stdio closed, 20 seconds at most), unless asks of the
# version of the executable that the ask runs were stopped (section 9.2,
# D21, D22). After a failed sign-in or an answer of no plan limits
# (not-subscriber) it asks again only once the agent's credentials file
# changed. usage_ask=off in agent-hook.conf turns it off; usage_ask_codex=off
# turns off Codex's only (its app-server writes its own state, syncs its
# plugins over the network and may refresh an expired sign-in).
usage_ask() {
  # (Values in any case: OFF and No turn it off too.)
  conf_on usage_ask || return 0
  case $EVENT in Stop | StopFailure) ;; *) return 0 ;; esac
  case $AGENT in
    claude)
      ab=claude cfg=${CLAUDE_CONFIG_DIR:-$HOME/.claude}
      ind=$cfg/.credentials.json
      ;;
    codex)
      conf_on usage_ask_codex || return 0
      ab=codex cfg=${CODEX_HOME:-$HOME/.codex}
      ind=$cfg/auth.json
      ;;
    *) return 0 ;;
  esac
  [ -n "$LINKS" ] && tunnel_live || return 0
  ap=$(command -v "$ab" 2>/dev/null)
  case $ap in /*) ;; *) return 0 ;; esac
  # The version of the executable the ask runs (a native install moves the
  # link on PATH to a newer version while sessions of the older one still
  # run): asks of it not stopped.
  ask_bin_version "$ap"
  [ -n "$ASK_BV" ] || return 0
  ask_stopped "$ASK_BV" && return 0
  [ "$(ask_fails)" -ge 3 ] && return 0
  v2_common
  af=$RUN_DIR/ask.$AGENT.$(printf '%s' "$cfg" | cksum | awk '{ print $1 }')
  if [ -f "$af.auth" ]; then
    [ -f "$ind" ] && [ "$ind" -nt "$af.auth" ] || return 0
    rm -f "$af.auth"
  fi
  ask_recent "$af" && return 0
  # The slot is claimed at once: Stop hooks of several sessions of this
  # agent and settings folder may end together. $af.lk is held while the
  # time is checked again and written; one left by a hook that died is
  # taken after 5 minutes.
  if ! ( set -C; : >"$af.lk" ) 2>/dev/null; then
    [ -n "$(find "$af.lk" -mmin +5 2>/dev/null)" ] || return 0
    rm -f "$af.lk"
    ( set -C; : >"$af.lk" ) 2>/dev/null || return 0
  fi
  if ask_recent "$af" || ! printf '%s\n' "$NOW" >"$af" 2>/dev/null; then
    rm -f "$af.lk"
    return 0
  fi
  rm -f "$af.lk"
  ask_probe_dir || return 0
  log "usage-ask $AGENT $ASK_BV"
  trap '' HUP
  (ask_run "$ASK_EXE" "$af") </dev/null >/dev/null 2>&1 &
}

# Runs command "$@" in ~/.simpleterm/probe with SIMPLETERM_PROBE=1, its
# standard input the lines of file $AQ.in followed by the lines that
# ask_more prints once file $AQ.out holds $AQ_WAIT1, then open until
# $AQ.out holds $AQ_WAIT2 (or 20 seconds); its output in $AQ.out. Sets
# AQ_RES: ok (got $AQ_WAIT2), gone (ended without it) or timeout.
ask_pipe() { # command...
  : >"$AQ.out"
  rm -f "$AQ.done"
  ask_group_how
  (
    ask_env
    {
      cat "$AQ.in"
      if [ -n "$AQ_WAIT1" ]; then
        aw=0
        while [ "$aw" -lt 20 ] && [ ! -f "$AQ.done" ]; do
          case $(head -c 1048576 "$AQ.out" 2>/dev/null) in *"$AQ_WAIT1"*) break ;; esac
          sleep 1
          aw=$((aw + 1))
        done
        cat "$AQ.more" 2>/dev/null
      fi
      aw=0
      while [ "$aw" -lt 20 ] && [ ! -f "$AQ.done" ]; do sleep 1; aw=$((aw + 1)); done
    } | ask_exec "$@" >"$AQ.out" 2>/dev/null &
    apid=$!
    aw=0 res=timeout
    while [ "$aw" -lt 20 ]; do
      case $(head -c 1048576 "$AQ.out" 2>/dev/null) in *"$AQ_WAIT2"*) res=ok; break ;; esac
      kill -0 "$apid" 2>/dev/null || { res=gone; break; }
      sleep 1
      aw=$((aw + 1))
    done
    case $(head -c 1048576 "$AQ.out" 2>/dev/null) in *"$AQ_WAIT2"*) res=ok ;; esac
    printf '%s\n' "$res" >"$AQ.res"
    : >"$AQ.done"
    aw=0
    while [ "$aw" -lt 3 ] && kill -0 "$apid" 2>/dev/null; do sleep 1; aw=$((aw + 1)); done
    # Still there, or something it started left in its group: all of it.
    if kill -0 "$apid" 2>/dev/null || { [ -n "$ASK_GRP" ] && kill -0 -"$apid" 2>/dev/null; }; then
      ask_kill "$apid"
    fi
  ) </dev/null >/dev/null 2>&1
  AQ_RES=$(cat "$AQ.res" 2>/dev/null)
}

# The first line of $AQ.out holding $1, cut to 256 KiB, as facts.
ask_facts() { # text
  awk -v t="$1" 'index($0, t) { print; exit }' "$AQ.out" 2>/dev/null | head -c 262144 | awk "$NORM_FN$JSON_FACTS" 2>/dev/null
}

# Claude Code get_usage control response (facts) -> "OK <usage line>" or
# "ERR <uq.err>" (section 9.3). at: the epoch the answer came. An answer
# whose session shows any model spend (cost, API time or a model's usage;
# measured 0 in every ask, 2.1.316 and 2.1.317) is "ERR spent": asks of that
# version stop.
CLAUDE_USAGE=$ISO_FN'
BEGIN { FS = "\t" }
!($1 in F) { F[$1] = $3; T[$1] = $2 }
function win(id, p, w,   u, r) {
  u = F[p ".utilization"]; r = isoepoch(F[p ".resets_at"])
  if (T[p ".utilization"] != "r" || u !~ /^[0-9]+([.][0-9]+)?$/ || r < 0) return
  out = out " " id ":" u ":" w ":" r ":ask:" at
}
END {
  if (F["response.subtype"] != "success") {
    e = tolower(F["response.error"])
    print (e ~ /auth|log ?in|credential|oauth|unauthori|401|403/) ? "ERR auth" : "ERR failed"
    exit
  }
  R = "response.response."
  if (F[R "session.total_cost_usd"] !~ /^0([.]0+)?$/ || F[R "session.total_api_duration_ms"] !~ /^0([.]0+)?$/) { print "ERR spent"; exit }
  for (p in F) if (index(p, R "session.model_usage.") == 1) { print "ERR spent"; exit }
  if (F[R "rate_limits_available"] == "false") { print "ERR not-subscriber"; exit }
  # Limits there but not known now (traffic turned off, a failed refresh):
  # nothing to show, not 0 percent.
  if (!((R "rate_limits.five_hour.utilization") in F) && !((R "rate_limits.seven_day.utilization") in F) && !((R "rate_limits.model_scoped.0.utilization") in F)) { print "ERR failed"; exit }
  plan = F[R "subscription_type"]
  if (T[R "subscription_type"] != "s" || plan !~ /^[A-Za-z0-9_-]+$/) plan = "-"
  out = ""
  win("five_hour", R "rate_limits.five_hour", 300)
  win("seven_day", R "rate_limits.seven_day", 10080)
  for (k = 0; k < 16 && ((R "rate_limits.model_scoped." k ".display_name") in F); k++) {
    n = F[R "rate_limits.model_scoped." k ".display_name"]
    gsub(/[^A-Za-z0-9._-]/, "-", n)
    if (n != "") win(substr("seven_day." n, 1, 64), R "rate_limits.model_scoped." k, 10080)
  }
  print "OK - - - 0 - " plan " 0" out
}'

# Codex app-server account/rateLimits/read reply (facts) -> as CLAUDE_USAGE:
# each RateLimitSnapshot of rateLimitsByLimitId (else rateLimits) as
# <limitId>.primary and .secondary, the id as the rollout path makes it.
CODEX_USAGE='
BEGIN { FS = "\t" }
!($1 in F) { F[$1] = $3; T[$1] = $2; O[++no] = $1 }
function snap(b, key,   id) {
  id = (T[b ".limitId"] == "s") ? F[b ".limitId"] : key
  gsub(/[^A-Za-z0-9_.-]/, "", id)
  if (id == "") id = "codex"
  w(id ".primary", b ".primary"); w(id ".secondary", b ".secondary")
  if (plan == "-" && T[b ".planType"] == "s" && F[b ".planType"] ~ /^[A-Za-z0-9_-]+$/) plan = F[b ".planType"]
  if (T[b ".rateLimitReachedType"] == "s") reached = 1
}
function w(id, b,   p, m, r) {
  p = F[b ".usedPercent"]; m = F[b ".windowDurationMins"]; r = F[b ".resetsAt"]
  if (p !~ /^[0-9]+([.][0-9]+)?$/ || m !~ /^[0-9]+$/ || r !~ /^[0-9]+$/) return
  out = out " " id ":" p ":" m ":" r ":ask:" at
}
END {
  # Measured (0.165.0): -32600 "codex account authentication required to
  # read rate limits" (signed out), -32600 "chatgpt authentication required
  # to read rate limits" (an API key: no plan limits), -32603 "failed to
  # fetch codex rate limits: GET .../wham/usage failed: 401 ..." (the
  # backend refused). The message itself goes nowhere.
  if ("error.message" in F || "error.code" in F) {
    e = tolower(F["error.message"])
    if (e ~ /chatgpt authentication required/) print "ERR not-subscriber"
    else if (e ~ /authentication required|401|403/) print "ERR auth"
    else print "ERR failed"
    exit
  }
  plan = "-"; reached = 0; out = ""; nk = 0
  B = "result.rateLimitsByLimitId."
  for (i = 1; i <= no; i++) {
    p = O[i]
    if (index(p, B) != 1) continue
    k = substr(p, length(B) + 1); sub(/\..*/, "", k)
    if (k in SEEN) continue
    SEEN[k] = 1; snap(B k, k); nk++
  }
  if (!nk) snap("result.rateLimits", "codex")
  if (out == "" && plan == "-" && !reached && !("result.rateLimits.limitId" in F) && !nk) { print "ERR failed"; exit }
  print "OK - - - 0 - " plan " " reached out
}'

# The time an answer came (SIMPLETERM_HOOK_TEST_TS in tests).
ask_now() {
  if [ "${SIMPLETERM_HOOK_TEST:-}" = 1 ] && [ -n "${SIMPLETERM_HOOK_TEST_TS:-}" ]; then
    printf '%s' "$SIMPLETERM_HOOK_TEST_TS"
  else
    date +%s
  fi
}

# The ask itself (in the background): runs it, makes the `usage` event from
# its answer (windows src ask, uq) and sends it to the tunnels.
ask_run() { # agent-executable ask-file
  AQ=$RUN_DIR/ask.$$.$(rand_hex 4) A='' hk=''
  case $AGENT in
    claude)
      printf '%s\n' '{"type":"control_request","request_id":"1","request":{"subtype":"get_usage","skip_behaviors":true}}' >"$AQ.in"
      AQ_WAIT1='' AQ_WAIT2='"type":"control_response"'
      ask_pipe "$1" -p --input-format stream-json --output-format stream-json --verbose --safe-mode \
        --strict-mcp-config --no-session-persistence --include-hook-events
      at=$(ask_now)
      [ "$AQ_RES" = ok ] && A=$(ask_facts '"type":"control_response"' | awk -v at="$at" "$CLAUDE_USAGE" 2>/dev/null)
      # A hook ran in the ask (--include-hook-events shows it; measured 0):
      # the probe guard did not hold or the ask ran as a turn, so as with
      # spend (D21).
      case $(head -c 1048576 "$AQ.out" 2>/dev/null) in
        *'{"type":"system","subtype":"hook_started"'* | *'{"type":"system","subtype":"hook_progress"'* | *'{"type":"system","subtype":"hook_response"'*) hk=1 ;;
      esac
      ;;
    codex)
      printf '%s\n' '{"id":1,"method":"initialize","params":{"clientInfo":{"name":"simpleterm","version":"'"$HOOK_VERSION"'"}}}' >"$AQ.in"
      printf '%s\n' '{"method":"initialized"}' '{"id":2,"method":"account/rateLimits/read"}' >"$AQ.more"
      AQ_WAIT1='"id":1,' AQ_WAIT2='"id":2,'
      ask_pipe "$1" app-server
      at=$(ask_now)
      [ "$AQ_RES" = ok ] && A=$(ask_facts '"id":2,' | awk -v at="$at" "$CODEX_USAGE" 2>/dev/null)
      ;;
  esac
  rm -f "$AQ".* 2>/dev/null
  case $A in
    'OK '*) err='' ;;
    'ERR '*) err=${A#ERR } ;;
    *) if [ "$AQ_RES" = timeout ]; then err=timeout; else err=failed; fi ;;
  esac
  [ -n "$hk" ] && err=spent
  case $err in
    # The ask cost a model call: no more asks of this executable version
    # (added to the set, D21); a failed ask too.
    spent) ask_stop; err=failed; ask_fail_count 1 ;;
    failed | timeout | unsupported) ask_fail_count 1 ;;
    '') ask_fail_count 0 ;;
  esac
  log "usage-ask $AGENT ${err:-ok}"
  # A failed sign-in, or an account without plan limits (an API key, a
  # gateway): not asked again until the credentials change (one report of
  # it goes; the files still give what they have).
  case $err in auth | not-subscriber) : >"$2.auth" ;; esac
  TS=$at NOW=$at USAGE_JSON=''
  [ -z "$err" ] && USAGE_JSON=$(printf '%s\n' "${A#OK }" | awk -v app="$APP" "$USAGE_FMT" 2>/dev/null | sed -n 2p)
  uq=',"uq":{"src":"ask","at":'$at',"ok":'
  if [ -z "$err" ]; then uq=$uq'true}'; else uq=$uq'false,"err":"'$err'"}'; fi
  RID_USED=1
  usage_send "$(usage_rid)" "$uq"
  wait
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
    # in Grok uses the same hooks file): it sets GROK_HOOK_EVENT. GitHub
    # Copilot CLI loads a Claude Code plugin given to it (--plugin-dir); it
    # sets COPILOT_CLI=1 (and CLAUDE_PROJECT_DIR too), and then this is
    # Copilot, never a Claude Code wait.
    if [ "${COPILOT_CLI:-}" = 1 ]; then AGENT=copilot APP=copilot-cli MODE=''
    elif [ -n "${GROK_HOOK_EVENT:-}" ]; then AGENT=grok APP=grok-build; fi
    ;;
  codex | codex-notify) APP=codex ;;
  gemini) APP=gemini-cli ;;
  agy) APP=antigravity ;;
  grok) APP=grok-build ;;
  opencode) APP=opencode ;;
  copilot) APP=copilot-cli ;;
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
  # The rest of a larger input is read and dropped: an agent still writing
  # to a hook that ended gets a broken pipe (Codex 0.165: "failed to write
  # hook stdin").
  [ "${#INPUT}" -lt $((MAX_INPUT - 4096)) ] || cat >/dev/null 2>&1
fi

# Codex runs PreToolUse and PostToolUse hooks for the session record's
# heartbeat only (TDS_AGENT_EVENTS_V2 section 8.3): their large tool input or
# output is not read, only its start (session_id and the event come first).
if [ "$AGENT" = codex ]; then
  ih=$(printf '%.4096s' "$INPUT")
  case $ih in *'"hook_event_name":"PreToolUse"'* | *'"hook_event_name":"PostToolUse"'*) INPUT=$ih ;; esac
fi

# Tests only (SIMPLETERM_HOOK_TEST=1): `agent-hook.sh <agent> __conf <key>`
# prints what the hook does with key <key> of agent-hook.conf (the read
# vectors of TDS_AGENT_ALERTS section 6.7).
if [ "${SIMPLETERM_HOOK_TEST:-}" = 1 ] && [ "${2:-}" = __conf ]; then
  case ${3:-} in
    usage) if conf_usage_on; then echo on; else echo off; fi ;;
    usage_ask | usage_ask_codex) if conf_on "$3"; then echo on; else echo off; fi ;;
    claude_wait | codex_wait | agy_wait | opencode_wait) conf_wait_cap "${3%_wait}"; echo ;;
    poll_wait) conf_poll_wait; echo ;;
    done_delay) conf_done_delay "$AGENT"; echo ;;
    bg_done_after) conf_int bg_done_after 600; echo ;;
    codex_goal_check) conf_int codex_goal_check 5; echo ;;
    ask_delay) conf_int ask_delay 2; echo ;;
  esac
  exit 0
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
T0=$NOW
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
    # v2 (TDS_AGENT_EVENTS_V2 section 10.1): turn, permission mode, the
    # subagent's type, a session's end; from the OpenCode bridge its request
    # id, version family, parent session, message id and session title.
    WANT=$WANT',prompt_id,permission_mode,agent_type,reason,request_id,oc,parent_session_id,message_id,title,cost,tokens_in,tokens_out'
    for i in 0 1 2 3 4 5 6 7 8 9; do WANT=$WANT,background_tasks.$i.id,background_tasks.$i.type,background_tasks.$i.description,background_tasks.$i.command; done
    for i in 0 1 2 3 4; do WANT=$WANT,session_crons.$i.id,session_crons.$i.schedule,session_crons.$i.prompt; done
    ;;
  codex)
    WANT='hook_event_name,tool_name,tool_input.command,tool_input.file_path,tool_input.description,session_id,cwd,last_assistant_message,transcript_path,stop_hook_active,turn_id,permission_mode,prompt,source'
    ;;
  codex-notify) WANT='type,cwd,last-assistant-message,input-messages.0' ;;
  gemini)
    WANT='hook_event_name,notification_type,message,details.type,details.command,details.rootCommand,details.filePath,details.fileName,details.toolName,details.serverName,details.urls.0,details.prompt,prompt_response,session_id,cwd,transcript_path,stop_hook_active'
    ;;
  agy)
    # toolCall.args has no Cwd in 1.4.12 (the workspace is workspacePaths).
    WANT='conversationId,workspacePaths.0,workspacePaths.1,workspacePaths.2,workspacePaths.3,workspacePaths.4,workspacePaths.5,workspacePaths.6,workspacePaths.7,toolCall.name,toolCall.args.CommandLine,toolCall.args.questions.0.question,toolCall.args.Path,toolCall.args.ServerName,toolCall.args.ToolName,toolCall.args.ArtifactMetadata.RequestFeedback,terminationReason,error,fullyIdle,executionNum,stepIdx,transcriptPath,lastUserInput'
    ;;
  grok)
    # backgroundTasks (Grok's Stop, camelCase): the first ten tasks.
    # sessionCrons (the first five): scheduled wake-ups; a prompt id that is
    # not a person's marks a turn Grok started itself.
    WANT='hook_event_name,hookEventName,notificationType,sessionId,cwd,message,lastAssistantMessage,error,reason,promptId,timestamp,prompt,stop_hook_active'
    WANT=$WANT',permissionMode,agentId,agent_id,agentType,subagentType,toolName,toolUseId,transcriptPath,transcript_path'
    for i in 0 1 2 3 4 5 6 7 8 9; do WANT=$WANT,backgroundTasks.$i.id,backgroundTasks.$i.type,backgroundTasks.$i.description,backgroundTasks.$i.command; done
    for i in 0 1 2 3 4; do WANT=$WANT,sessionCrons.$i.id,sessionCrons.$i.schedule,sessionCrons.$i.prompt; done
    ;;
  copilot)
    # GitHub Copilot CLI (camelCase; notification and Claude-format events
    # in snake_case): section 10 of TDS_AGENT_EVENTS_V2.
    WANT='hookName,hook_event_name,hookEventName,sessionId,session_id,cwd,transcriptPath,transcript_path,message,notification_type,toolName,tool_name,agentId,agent_id,agentType,agent_type,parentAgentId,parent_agent_id,stopReason,prompt,reason,error.message,error.name,error,stop_hook_active,timestamp,recoverable,errorContext,error_context'
    ;;
esac

EVENT='' NTYPE='' TOOL='' DETAIL='' DESC='' SID='' CWD='' LAST='' ERR='' QTEXT='' FIRSTIN='' NTYPE2=''
TPATH='' CTXTOK='' MODEL='' GTYPE='' FULLYIDLE='' TERMREASON='' EXTRA='' GKEY='' REASON=''
PROMPT='' SRC='' STOPACT='' ISINT='' AGENTID='' PROMPTID='' XFLAGS='' REQIDIN='' TOOLUSEID=''
OCTITLE='' OCCOST='' OCTIN='' OCTOUT='' RFB='' APATH='' AWS='' LASTIN='' SUBPAR_SESSION='' BG_SVCIDX='' AMS='' AMT='' RECOV='' ECTX=''
BG_N=0 BG_FINITE=0 BG_PICK='' BG_TYPE='' BG_DESC='' BG_CMD='' BG_SEQ=''
BG_SVC=0 BG_IDMAP='' BG_KEEP='' BG_SHELLS='' BG_IDS='' BG_NOID=0 BG_M=''
CRON_N=0 CRON_SCHED='' CRON_SUMS=''

# --- what the hook reads from the text of a turn ------------------------------

# A shell task whose command is a service (a dev server, a watcher, a
# follower) is not something the agent waits for: it never ends and never
# wakes the agent. exit 0 when the command (one JSON-escaped line on stdin) is
# one. A wrong "service" ends the turn early and sends a second done later; a
# missed one only delays the done to bg_done_after: so when in doubt it is not
# one, and only what is known is matched, at the command position:
#  - the command is unescaped, backslash-newline joined, heredoc bodies
#    dropped and the text of "..." and '...' emptied (a word is left), then
#    cut at ; && || & and line breaks into list elements; only the LAST
#    element counts (`cd web && npm run dev`, `npm run dev &`), and of its
#    pipeline (|) any command may be the service;
#  - in each command leading VAR=val words, shell keywords and a few
#    launchers (npx, bunx, pnpm exec|dlx, yarn dlx, uv|poetry run, bundle
#    exec, env, nohup, exec, sudo; an option we cannot read gives up) are
#    skipped, and the command word with its subcommand is looked up in
#    svcseg. Between the two only options are allowed: VF takes a value, BOOL
#    does not, any other one gives up. Words after a lone -- belong to
#    another command, and tools that run a script (node, python, tsx) stop
#    at the script.
SVC_AWK='
BEGIN {
  VF = " --filter -F -C --cwd --prefix --dir -p --project --workspace -w --app --namespace -n --context --kubeconfig -f --file --env-file --project-name --profile --port --host --config -c --mode -m --base --logLevel -l --outDir "
  BOOL = " -r --recursive -s --silent -q --quiet --if-present --workspaces -ws --include-workspace-root --stream --parallel --no-bail --open --force --strictPort --debug --verbose -v --no-color --offline --prefer-offline --ignore-scripts -A "
  UNK = 1000000
  DONE = " setup migrate migration db seed build init prepare install reset clean test lint check generate gen codegen deploy publish release typecheck format once "
}
function base(w) { sub(/^.*\//, "", w); return tolower(w) }
function isopt(w) { return substr(w, 1, 1) == "-" }
# The first word from j on that is not an option (or an option value); n + 1 at the end or a lone --,
# UNK when an option is not known. A value flag takes the next word only when that is no option.
function nxt(j) {
  while (j <= n && isopt(W[j])) {
    if (W[j] == "--") return n + 1
    if (index(W[j], "=") > 0 || index(BOOL, " " W[j] " ") > 0) j++
    else if (index(VF, " " W[j] " ") > 0) { if (j < n && !isopt(W[j + 1])) j += 2; else j++ }
    else return UNK
  }
  return j
}
# Does an option word matching the regex string re come from j on (before a lone --)?
function anyopt(j, re,   k) {
  for (k = j; k <= n; k++) { if (W[k] == "--") return 0; if (W[k] ~ re) return 1 }
  return 0
}
# Leading options only (tools that run a script: the script ends them); `run` may come between when allowed.
function leadopt(j, re, allowrun) {
  while (j <= n) {
    if (W[j] == "--") return 0
    if (allowrun && W[j] == "run") { j++; continue }
    if (!isopt(W[j])) return 0
    if (W[j] ~ re) return 1
    if (index(W[j], "=") == 0 && index(VF, " " W[j] " ") > 0 && j < n && !isopt(W[j + 1])) j += 2; else j++
  }
  return 0
}
# A script name `dev:setup` is a job, not a server, when a part of its suffix is a finite task.
function jobname(t,   p, m, SP, k) {
  p = index(t, ":")
  if (p == 0) return 0
  m = split(substr(t, p + 1), SP, /[:_-]/)
  for (k = 1; k <= m; k++) if (index(DONE, " " SP[k] " ") > 0) return 1
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
    if (lw ~ /^(do|then|else|elif|if|while|until|time|nohup|exec|bunx|!|[{}])$/) { i++; continue }
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
    if (c == "bun" && leadopt(j, "^--(watch|hot)$", 1)) return 1
    j = nxt(j)
    if (c == "yarn" && W[j] == "workspace") j = nxt(j + 2)
    if (W[j] == "run" || W[j] == "run-script") j = nxt(j + 1)
    t = tolower(W[j])
    return (j <= n && t ~ /^(dev|start|serve|preview|watch)(:[a-z0-9_-]+)?$/ && !jobname(t))
  }
  if (c == "next") { j = nxt(j); return (W[j] ~ /^(dev|start)$/) }
  if (c == "vite") {
    if (anyopt(j, "^(-v|-h|--version|--help)$")) return 0
    j = nxt(j)
    if (j >= UNK) return 0
    return (j > n || W[j] ~ /^(dev|serve|preview)$/ || W[j] ~ /^[0-9]*[<>]/ || index(W[j], "/") > 0 || index(W[j], ".") > 0)
  }
  if (c == "vitest") return (anyopt(j, "^(-w|--watch|--watch=true|--watch=1)$") || W[nxt(j)] ~ /^(dev|watch)$/)
  if (c == "watch") return !anyopt(j, "^(-[a-zA-Z]*[ge][a-zA-Z]*|--chgexit|--errexit)$")
  if (c == "gunicorn") return !anyopt(j, "^--check-config$")
  if (c ~ /^(nodemon|uvicorn|watchexec|serve|http-server|live-server|webpack-dev-server)$/) return 1
  if (c == "parcel") { j = nxt(j); return (j <= n && W[j] != "build") }
  if (c == "node") return leadopt(j, "^--watch(-path(=.*)?)?$", 0)
  if (c == "deno") return leadopt(j, "^--watch(=.*)?$", 1)
  if (c ~ /^python[0-9.]*$/) {
    for (k = j; k <= n; k++) {
      if (W[k] == "-m") {
        if (W[k + 1] ~ /^(http[.]server|uvicorn|gunicorn|hypercorn)$/) return 1
        if (W[k + 1] == "flask") return (W[nxt(k + 2)] == "run")
        return 0
      }
      if (!isopt(W[k])) return (W[k] ~ /manage[.]py$/ && W[k + 1] == "runserver")
    }
    return 0
  }
  if (c ~ /manage[.]py$/) return (W[nxt(j)] == "runserver")
  if (c == "rails") return (W[nxt(j)] ~ /^(s|server)$/ && !anyopt(j, "^(-d|--daemon)$"))
  if (c == "flask") return (W[nxt(j)] == "run")
  if (c == "docker" || c == "docker-compose") {
    j = nxt(j)
    if (c == "docker" && W[j] == "compose") j = nxt(j + 1)
    else if (c == "docker") { if (W[j] != "logs") return 0 }
    if (W[j] == "up") return !anyopt(j + 1, "^(-[a-zA-Z]*d[a-zA-Z]*|--detach(=.*)?|--wait|--abort-on-container-exit|--abort-on-container-failure|--exit-code-from(=.*)?|--no-start|--dry-run)$")
    if (W[j] == "logs") return anyopt(j + 1, "^(-[a-zA-Z]*f[a-zA-Z]*|--follow)$")
    return 0
  }
  if (c == "kubectl") {
    j = nxt(j)
    if (W[j] == "port-forward") return 1
    if (W[j] == "logs") {
      for (k = j + 1; k <= n; k++) if (W[k] ~ /^jobs?(\.[a-z]+)*(\/|$)/ || index(W[k], "job-name=") > 0) return 0
      return anyopt(j + 1, "^(-[a-zA-Z]*f[a-zA-Z]*|--follow)$")
    }
    if (W[j] == "get") return anyopt(j + 1, "^(-w|--watch|--watch-only)$")
    return 0
  }
  if (c == "tail") return (anyopt(j, "^(-[a-zA-Z]*[fF][a-zA-Z]*|--follow(=.*)?)$") && !anyopt(j, "^--pid(=.*)?$"))
  if (c == "journalctl") return anyopt(j, "^(-[a-zA-Z]*f[a-zA-Z]*|--follow)$")
  if (c == "turbo") {
    j = nxt(j)
    if (W[j] == "run") j = nxt(j + 1)
    t = tolower(W[j])
    return (t ~ /^(dev|watch|serve|start)(:[a-z0-9_-]+)?$/ && !jobname(t))
  }
  if (c == "nx") {
    j = nxt(j)
    if (W[j] ~ /^(serve|dev|start)$/) return 1
    if (W[j] == "run") { j = nxt(j + 1); return (W[j] ~ /:(serve|dev|start)(:|$)/) }
    return 0
  }
  if (c == "ng") return (W[nxt(j)] ~ /^(serve|s)$/)
  if (c == "astro" || c == "nuxt" || c == "nuxi") return (W[nxt(j)] ~ /^(dev|preview)$/)
  if (c == "expo") return (W[nxt(j)] == "start")
  if (c == "storybook" || c == "sb") return (W[nxt(j)] ~ /^(dev|start)$/)
  if (c == "browser-sync") return (W[nxt(j)] == "start")
  if (c == "php") { for (k = j; k < n; k++) if (W[k] == "artisan") return (W[k + 1] == "serve"); return 0 }
  if (c == "hugo") return (W[nxt(j)] ~ /^(server|serve)$/)
  if (c == "jekyll") return (W[nxt(j)] ~ /^(serve|s)$/)
  if (c == "cargo") return (W[nxt(j)] == "watch")
  if (c == "tsx") return (W[nxt(j)] == "watch")
  if (c == "tsc" || c == "rollup" || c == "swc" || c == "mocha") return anyopt(j, "^(-w|--watch)$")
  if (c == "webpack") return (W[nxt(j)] ~ /^(serve|server|s|watch|w)$/ || anyopt(j, "^(-w|--watch)$"))
  if (c == "tailwindcss") return anyopt(j, "^(-w|--watch(=always)?)$")
  if (c == "sass") return anyopt(j, "^(-w|--watch)$")
  if (c == "esbuild") return anyopt(j, "^--watch(=forever)?$")
  if (c == "jest") return anyopt(j, "^--(watch|watchAll)$")
  return 0
}
# One hex digit, -1 if it is none.
function hexd(c) { return index("0123456789abcdef", tolower(c)) - 1 }
# JSON string body to the text of the command: real characters, line breaks kept. A \u00XX
# in the ASCII range (0x20-0x7F) is that character (Go writes `&` as `\u0026`), any other \u
# escape a space.
function unesc(s,   out, p, c, d1, d2, d3, d4, v) {
  out = ""
  while ((p = index(s, "\\")) > 0) {
    out = out substr(s, 1, p - 1)
    c = substr(s, p + 1, 1)
    if (c == "n") { out = out "\n"; s = substr(s, p + 2) }
    else if (c == "r" || c == "t") { out = out " "; s = substr(s, p + 2) }
    else if (c == "u") {
      d1 = hexd(substr(s, p + 2, 1)); d2 = hexd(substr(s, p + 3, 1)); d3 = hexd(substr(s, p + 4, 1)); d4 = hexd(substr(s, p + 5, 1))
      v = d1 * 4096 + d2 * 256 + d3 * 16 + d4
      if (d1 == 0 && d2 == 0 && d3 >= 2 && d3 <= 7) out = out sprintf("%c", v); else out = out " "
      s = substr(s, p + 6)
    }
    else { out = out c; s = substr(s, p + 2) }
  }
  return out s
}
# The text of the command in one pass: comments (a # that starts a word, outside quotes, up to
# the line break) and heredoc bodies dropped, line continuations joined, the inside of quotes
# emptied (one word `_` is left), redirections with & removed, then every list separator is a ;
# and a pipe stays a |.
# A heredoc operator at i (<<, not <<<): its delimiter, or "" when there is none. HDE is the index
# of the last character of the operator. The delimiter starts with a letter or _ (so $((1<<3)) and
# (( n <<= 1 )) are not heredocs) unless it is quoted.
function hdparse(s, i, len,   e, bq, de, sq, dq) {
  sq = "\047"; dq = "\""
  e = i + 2
  if (substr(s, e, 1) == "-") e++
  while (substr(s, e, 1) == " " || substr(s, e, 1) == "\t") e++
  bq = substr(s, e, 1)
  if (bq == sq || bq == dq || bq == "\\") e++; else bq = ""
  if (!(bq == sq || bq == dq || substr(s, e, 1) ~ /[A-Za-z_]/)) return ""
  de = e
  while (de <= len && index(" \t\n;&|()<>" sq dq, substr(s, de, 1)) == 0) de++
  if (de <= e) return ""
  if (bq == sq || bq == dq) HDE = de; else HDE = de - 1
  return substr(s, e, de - e)
}
# From the line break at j: the index of the line break that ends the body (the line of hd).
function hdskip(s, j, len, hd,   nl, ln, t) {
  while (j < len) {
    nl = index(substr(s, j + 1), "\n")
    if (nl == 0) { ln = substr(s, j + 1); j = len } else { ln = substr(s, j + 1, nl - 1); j += nl }
    t = ln; sub(/^[ \t]+/, "", t)
    if (t == hd) break
  }
  return j
}
function clean(s,   out, i, len, ch, pv, q, hd, d, j, sq, dq) {
  sq = "\047"; dq = "\""
  out = ""; q = ""; hd = ""; len = length(s)
  for (i = 1; i <= len; i++) {
    ch = substr(s, i, 1)
    if (q == "") {
      pv = (i > 1) ? substr(s, i - 1, 1) : ""
      if (ch == "#" && (pv == "" || index(" \t\n;&|()", pv) > 0)) {
        while (i < len && substr(s, i + 1, 1) != "\n") i++
        continue
      }
      if (ch == "\n") {
        out = out "\n"
        if (hd != "") { i = hdskip(s, i, len, hd); hd = "" }
        continue
      }
      if (ch == "\\") {
        if (substr(s, i + 1, 1) == "\n") out = out " "; else out = out "_"
        i++
        continue
      }
      if (ch == sq || ch == dq) { q = ch; out = out "_"; continue }
      if (ch == "$" && substr(s, i + 1, 1) == sq) { q = "a"; out = out "_"; i++; continue }
      if (ch == "<" && substr(s, i + 1, 1) == "<") {
        if (substr(s, i + 2, 1) == "<") { out = out "<<<"; i += 2; continue }
        d = hdparse(s, i, len)
        if (d != "") { hd = d; i = HDE; out = out " "; continue }
      }
      out = out ch
    } else if (q == sq) { if (ch == sq) q = "" }
    else if (q == "a") { if (ch == "\\") i++; else if (ch == sq) q = "" }
    else {
      if (ch == "\\") i++
      else if (ch == dq) q = ""
      else if (ch == "<" && substr(s, i + 1, 1) == "<" && substr(s, i + 2, 1) != "<") {
        # a heredoc inside a $(...) in double quotes (the line break follows the delimiter): its body
        # is not part of the command either
        d = hdparse(s, i, len)
        j = HDE + 1
        while (substr(s, j, 1) == " " || substr(s, j, 1) == "\t") j++
        if (d != "" && substr(s, j, 1) == "\n") i = hdskip(s, j, len, d)
      }
    }
  }
  gsub(/\|&/, "|", out)
  gsub(/[0-9]*[<>]&[0-9-]*/, " ", out)
  gsub(/&>>?/, " > ", out)
  gsub(/\|\|/, ";", out)
  gsub(/&&/, ";", out)
  gsub(/&/, ";", out)
  gsub(/\n/, ";", out)
  return out
}
# A last pipeline command that ends early (head, grep -q|-l|-m N) can end the pipeline too: when the
# earlier command writes again it dies of SIGPIPE (not before; measured), so this is a guess.
function consumer(seg,   m, X, k, c) {
  gsub(/[()\t]/, " ", seg)
  m = split(seg, X, " ")
  k = 1
  while (k <= m && X[k] ~ /^[A-Za-z_][A-Za-z0-9_]*=/) k++
  c = base(X[k])
  if (c == "head") return 1
  if (c ~ /^(grep|egrep|fgrep)$/) {
    for (k++; k <= m; k++) if (X[k] ~ /^(-[a-zA-Z]*[qlm][a-zA-Z0-9]*|--quiet|--silent|--max-count(=.*)?|--files-with-matches)$/) return 1
  }
  return 0
}
{
  s = clean(unesc($0))
  ne = split(s, E, ";")
  last = ""
  for (q = ne; q >= 1; q--) { t = E[q]; gsub(/[ \t]/, "", t); if (t != "" && t != "}") { last = E[q]; break } }
  np = split(last, part, "|")
  if (!(np > 1 && consumer(part[np]))) for (q = 1; q <= np; q++) if (svcseg(part[q])) found = 1
}
END { exit !found }'

# A command over 64 KiB is not looked at (the hook has seconds, not a minute): not a service.
is_service_cmd() {
  [ "${#1}" -le 65536 ] || return 1
  printf '%s\n' "$1" | awk "$SVC_AWK" 2>/dev/null
}

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
      case "$BG_SHELLS " in *" $bk "*) is_service_cmd "$bv" && BG_SVC=$((BG_SVC + 1)) BG_SVCIDX="$BG_SVCIDX $bk" ;; esac
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
    agent_id=* | agentId=*) AGENTID=${kv#*=} ;;
    agent_type=* | agentType=* | subagentType=*) [ -n "$SUBTYPE" ] || SUBTYPE=${kv#*=} ;;
    parentAgentId=* | parent_agent_id=*) SUBPAR=${kv#*=} ;;
    prompt_id=* | turn_id=* | message_id=* | executionNum=*) TID=${kv#*=} ;;
    permission_mode=* | permissionMode=*) PMODE=${kv#*=} ;;
    request_id=*) REQIDIN=${kv#*=} ;;
    oc=*) OCV=${kv#*=} ;;
    parent_session_id=*) SUBPAR_SESSION=${kv#*=} ;;
    cost=*) OCCOST=${kv#*=} ;;
    tokens_in=*) OCTIN=${kv#*=} ;;
    tokens_out=*) OCTOUT=${kv#*=} ;;
    title=*) OCTITLE=${kv#*=} ;;
    toolName=*) [ -n "$TOOL" ] || TOOL=${kv#*=} ;;
    toolUseId=*) TOOLUSEID=${kv#*=} ;;
    transcriptPath=*) [ -n "$TPATH" ] || TPATH=${kv#*=} ;;
    toolCall.args.ArtifactMetadata.RequestFeedback=*) RFB=${kv#*=} ;;
    toolCall.args.Path=*) APATH=${kv#*=} ;;
    toolCall.args.ServerName=*) AMS=${kv#*=} ;;
    toolCall.args.ToolName=*) AMT=${kv#*=} ;;
    lastUserInput=*) LASTIN=${kv#*=} ;;
    hookName=*) [ -n "$EVENT" ] || EVENT=${kv#*=} ;;
    error.name=*) ERR=${kv#*=} ;;
    error.message=*) LAST=${kv#*=} ;;
    stopReason=*) REASON=${kv#*=} ;;
    recoverable=*) RECOV=${kv#*=} ;;
    errorContext=* | error_context=*) ECTX=${kv#*=} ;;
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
    cwd=*) [ -n "$CWD" ] || CWD=${kv#*=} ;;
    workspacePaths.0=*)
      [ -n "$CWD" ] || CWD=${kv#*=}
      AWS="$AWS${kv#*=}$NL"
      ;;
    workspacePaths.[1-7]=*) AWS="$AWS${kv#*=}$NL" ;;
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
    promptId=*) PROMPTID=${kv#*=}; GKEY=$GKEY.$PROMPTID TID=$PROMPTID ;;
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
if [ "$AGENT" = copilot ]; then
  # Our Copilot hooks name the event on the command line; a Claude-format
  # hook (the Claude Code plugin given to Copilot) has it in the input.
  [ -n "$MODE" ] && EVENT=$MODE
  case $EVENT in
    PermissionRequest) EVENT=permissionRequest ;;
    PreToolUse) EVENT=preToolUse ;;
    PostToolUse) EVENT=postToolUse ;;
    Notification) EVENT=notification ;;
    Stop) EVENT=agentStop ;;
    UserPromptSubmit) EVENT=userPromptSubmitted ;;
    SessionStart) EVENT=sessionStart ;;
    SessionEnd) EVENT=sessionEnd ;;
    SubagentStart) EVENT=subagentStart ;;
    SubagentStop) EVENT=subagentStop ;;
  esac
fi
RAWSID=$SID
SID=$(printf '%s' "$SID" | tr -c 'A-Za-z0-9_-' '_' | cut -c1-80)
[ -n "$SID" ] || SID=nosession
DIRV=$CWD
# A subagent (its own hook events carry its id; section 7).
SUBID=''
is_id "$AGENTID" && SUBID=$AGENTID

CWD_BASE=$(json_trim "$CWD" 64 256 base)
CWD_BASEF=$(json_trim "$CWD" 100000 400000 base)
FP=$(printf '%s\t%s' "$TOOL" "$(json_trim "$DETAIL" 200 800)" | cksum | awk '{ print $1 }')

# A `done` waits done_delay seconds (done_later) in case another Stop hook
# keeps the agent going; any later event of the main thread ends that wait.
# Only the turn-end events that send a `done` themselves leave it be (a newer
# one replaces it), and so do the events of a subagent (agent_id is set,
# whether it runs in the foreground or the background): a background
# subagent's tool calls carry the session id and are no sign of the main
# thread going on.
case $AGENT:$EVENT in
  claude:Stop | codex:Stop | grok:Stop | gemini:AfterAgent | copilot:agentStop | opencode:Stop | *:SessionEnd | *:sessionEnd) ;;
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
  pend=background
  [ "$BG_N" -eq 0 ] && [ "$CRON_N" -gt 0 ] && pend=scheduled
  if [ "${1:-}" = ask ]; then
    setmsg "$LAST"
    turn_at background true
    v2_prep "$TURN_AT"
    send_bg question
    print_state waiting "$LAST"
    return 0
  fi
  bgm=$BG_M # print_state reuses m
  print_state background "$bgm"
  turn_at "$pend" "$TASKS"
  send_state "$pend" "$TURN_AT"
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
  MSG=$(done_msg "$2") MSGF=''
  MSGF=$MSG
  turn_at done "$TASKS" true
  v2_prep "$TURN_AT"
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
  dw=$(conf_done_delay "$AGENT")
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

later_send() { # ev [scope]
  TS=$(date +%s)
  NOW=$TS
  is_uint "$TS" || TS=0
  RID=$(rand_hex 8)
  is_hex "$RID" 16 || return 0
  # v2: the event's time again (tms).
  [ "$V2" = 1 ] && v2_spec "$V2X@.tms${TAB}s$TAB$(v2_tms)$NL"
  send_bg "$1" "$RID" "${2:-all}"
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
  setmsg "$LAST"
  turn_at done
  v2_prep "$TURN_AT"
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
  # (Kept: the hold after an ask got auth or not-subscriber, until the
  # credentials change, the stopped versions and the count of failed asks.)
  find "$RUN_DIR" -type f -mtime +0 ! -name 'ask.*.auth' ! -name 'ask.*.off' ! -name 'ask.*.fail' -exec rm -f {} + 2>/dev/null
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
PROMPT_USER=1 PROMPT_BY=user
prompt_origin() {
  PROMPT_USER=1 PROMPT_BY=user
  if [ "$AGENT" = grok ]; then
    case $PROMPTID in
      task-completed-* | bash-completed-* | monitor-completed-* | subagent-completed-* | workflow-completed-*) PROMPT_BY=task ;;
      scheduler-fired-*) PROMPT_BY=schedule ;;
      parent-agent-message-* | parent-message-* | notifications-* | goal-summary-* | goal-classifier-nudge-* | plan-resume-*) PROMPT_BY=agent ;;
    esac
  elif [ "$AGENT" = copilot ]; then
    case $PROMPT in '<system_notification>'*) PROMPT_BY=task ;; esac
  else
    case $SRC in
      user | sdk) ;;
      loop_wakeup | schedule_wakeup) PROMPT_BY=schedule ;;
      poll_event) PROMPT_BY=task ;;
      '')
        case $PROMPT in
          '<task-notification>'*) PROMPT_BY=task ;;
          '<agent-message '*) PROMPT_BY=agent ;;
          '<<autonomous-loop'*) PROMPT_BY=schedule ;;
          '') ;;
          *)
            if [ -f "$RUN_DIR/$SID.crons" ]; then
              case " $(cat "$RUN_DIR/$SID.crons" 2>/dev/null) " in *" $(prompt_sum "$PROMPT") "*) PROMPT_BY=schedule ;; esac
            fi
            ;;
        esac
        ;;
      *) PROMPT_BY=agent ;;
    esac
  fi
  [ "$PROMPT_BY" = user ] || PROMPT_USER=0
}

# $SID.turn: line 1 `user` or `auto` (who started this turn), line 2 the ids
# of the background tasks that already ran when it started ($SID.stopids, the
# last Stop's list), for the Stop that ends it.
turn_mark() {
  tm_ids=''
  [ -f "$RUN_DIR/$SID.stopids" ] && IFS= read -r tm_ids <"$RUN_DIR/$SID.stopids"
  tm_who=$PROMPT_BY
  [ "$PROMPT_USER" = 1 ] && tm_who=user
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

# TURN_AT: @-parameters of the end of a turn (TDS_AGENT_EVENTS_V2 section
# 6.1): end $1, asks $2 (true|false), late $3. Who started the turn is the
# turn's mark (turn_mark); the background tasks and schedules come from the
# event's facts.
TASKS='' TLAST='' TGOAL=''
turn_at() { # end [asks] [late]
  TURN_AT="@.turn${TAB}s${TAB}1$NL@.end${TAB}s$TAB$1$NL"
  tb=${TURN_BY:-}
  [ -z "$tb" ] && [ -f "$RUN_DIR/$SID.turn" ] && tb=$(sed -n 1p "$RUN_DIR/$SID.turn" 2>/dev/null)
  case $tb in user | task | schedule | agent) ;; auto) tb=agent ;; *) tb=unknown ;; esac
  TURN_AT="$TURN_AT@.by${TAB}s$TAB$tb$NL"
  [ -n "${2:-}" ] && TURN_AT="$TURN_AT@.asks${TAB}s$TAB$2$NL"
  # OpenCode's LAST is the session's title, not the last message.
  [ "$AGENT" != opencode ] && [ -n "${TLAST:-$LAST}" ] && TURN_AT="$TURN_AT@.last${TAB}s$TAB${TLAST:-$LAST}$NL"
  [ -n "${3:-}" ] && TURN_AT="$TURN_AT@.late${TAB}s$TAB$3$NL"
  [ "$STOPACT" = true ] && TURN_AT="$TURN_AT@.hook${TAB}s${TAB}true$NL"
  case $AGENT in
    grok) TURN_AT="$TURN_AT@.bgp${TAB}s${TAB}backgroundTasks$NL@.cronp${TAB}s${TAB}sessionCrons$NL" ;;
    *) TURN_AT="$TURN_AT@.bgp${TAB}s${TAB}background_tasks$NL@.cronp${TAB}s${TAB}session_crons$NL" ;;
  esac
  TURN_AT="$TURN_AT@.prev${TAB}s$TAB$PREV_IDS$NL@.svc${TAB}s$TAB$BG_SVCIDX$NL"
  [ -n "$TGOAL" ] && TURN_AT="$TURN_AT@.goal${TAB}s$TAB$TGOAL$NL"
  return 0
}

# A `done` for the turn that just ended ($1: what still runs, if anything).
stop_done() {
  if [ -n "${1:-}" ]; then MSG=$(done_msg "$1") MSGF=''; MSGF=$MSG; else setmsg "$LAST"; fi
  [ "$STOPACT" = true ] && XFLAGS=',"stop_hook_active":true'
  turn_at done "$TASKS"
  v2_prep "$TURN_AT"
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
  TURN_USER=1 PREV_IDS='' t1='' t2='' TURN_BY=''
  if [ -f "$RUN_DIR/$SID.turn" ]; then
    { IFS= read -r t1; IFS= read -r t2; } <"$RUN_DIR/$SID.turn"
    [ -n "$t1" ] && [ "$t1" != user ] && TURN_USER=0
    TURN_BY=$t1
    PREV_IDS=$t2
  fi
  bg_ids_finish
  printf '%s\n' "$BG_IDS" >"$RUN_DIR/$SID.stopids" 2>/dev/null
  if [ "$CRON_N" -gt 0 ]; then
    printf '%s\n' "$CRON_SUMS" >"$RUN_DIR/$SID.crons" 2>/dev/null
  elif [ -f "$RUN_DIR/$SID.crons" ]; then
    rm -f "$RUN_DIR/$SID.crons" 2>/dev/null
  fi
  TASKS=''
  if [ "$AGENT" != opencode ]; then
    TASKS=false
    ask_detect "$LAST" && TASKS=true
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
  if [ "$TASKS" = true ]; then bg_pause ask; else bg_pause; fi
  turn_end
}

# --- v2 helpers of the event handlers ---------------------------------------------

# The request kind parameter lines for v2_prep (TDS_AGENT_EVENTS_V2 section 4).
rk_at() { # kind [extra lines]
  RK_AT="@.rkind${TAB}s$TAB$1$NL@.rid${TAB}s$TAB$RID$NL${2:-}"
}

# Saves this event's facts that a later event of the session needs, with
# prefix $1, in run/$SID.$2 (at most 64 KiB; the line of a long value goes).
facts_keep() { # prefix file [path regex]
  v2_facts
  printf '%s\n' "$FACTS" | awk -v pre="$1" -v re="${3:-.}" 'length($0) <= 65536 && $1 ~ re { print pre $0 }' FS="$TAB" |
    head -c 65536 >"$RUN_DIR/$SID.$2.$$" 2>/dev/null && mv -f "$RUN_DIR/$SID.$2.$$" "$RUN_DIR/$SID.$2"
}

# Facts saved by facts_keep within $2 seconds, added to FACTS.
facts_add() { # file max-age
  ff=$RUN_DIR/$SID.$1
  [ -f "$ff" ] || return 1
  [ -n "$(find "$ff" -mmin -"$(( ($2 + 59) / 60 ))" 2>/dev/null)" ] || return 1
  v2_facts
  FACTS="$FACTS$NL$(cat "$ff" 2>/dev/null)"
}

# Codex: the plan of turn TID from the rollout (`item_completed` with
# item.type Plan, measured on 0.165.0, M2): its text, JSON-escaped.
codex_plan() { # rollout file
  [ -n "$1" ] && is_id "$TID" || return 1
  tail -c 1048576 "$1" 2>/dev/null | awk -v tid="\"turn_id\":\"$TID\"" '
    index($0, "\"type\":\"item_completed\"") && index($0, tid) && (p = index($0, "\"item\":{\"type\":\"Plan\"")) {
      r = substr($0, p)
      q = index(r, "\"text\":\"")
      if (!q) next
      r = substr(r, q + 8)
      if (match(r, /^([^"\\]|\\.)*/)) t = substr(r, 1, RLENGTH)
    }
    END { if (t == "") exit 1; print t }'
}

# Copilot's session events (transcriptPath, events.jsonl): the last answer
# (TLAST) and the background shells and subagents that have not ended, as
# background_tasks facts and kv lines for bg_field (section 10.4).
COPILOT_TX='
function str(s, key,   p, r) {
  p = index(s, "\"" key "\":\"")
  if (!p) return ""
  r = substr(s, p + length(key) + 4)
  if (match(r, /^([^"\\]|\\.)*/)) return substr(r, 1, RLENGTH)
  return ""
}
/"type":"assistant\.message"/ { c = str($0, "content"); if (c != "") last = c }
/"type":"tool\.execution_start"/ && /"toolName":"bash"/ && /"mode":"async"/ && !/"detach":true/ {
  id = str($0, "shellId"); if (id == "") next
  if (!(id in SH)) { NS++; SO[NS] = id }
  SH[id] = 1; SC[id] = str($0, "command"); SD[id] = str($0, "description")
}
/"type":"system\.notification"/ && (/"type":"shell_completed"/ || /"type":"shell_detached_completed"/) { delete SH[str($0, "shellId")] }
/"type":"tool\.execution_start"/ && /"toolName":"stop_bash"/ { delete SH[str($0, "shellId")] }
/"type":"subagent\.started"/ && /"executionMode":"background"/ {
  id = str($0, "toolCallId"); if (id == "") next
  if (!(id in SA)) { NA++; AO[NA] = id }
  SA[id] = 1; AT[id] = str($0, "agentType"); AN[id] = str($0, "agentDisplayName")
}
/"type":"subagent\.(completed|failed)"/ { delete SA[str($0, "toolCallId")] }
END {
  n = 0
  for (k = 1; k <= NS; k++) if (SO[k] in SH) {
    i = SO[k]
    printf "F\tbackground_tasks.%d.id\ts\t%s\n", n, i
    printf "F\tbackground_tasks.%d.type\ts\tshell\n", n
    if (SD[i] != "") printf "F\tbackground_tasks.%d.description\ts\t%s\n", n, SD[i]
    if (SC[i] != "") printf "F\tbackground_tasks.%d.command\ts\t%s\n", n, SC[i]
    n++
  }
  for (k = 1; k <= NA; k++) if (AO[k] in SA) {
    i = AO[k]
    printf "F\tbackground_tasks.%d.id\ts\t%s\n", n, i
    printf "F\tbackground_tasks.%d.type\ts\tsubagent\n", n
    if (AT[i] != "") printf "F\tbackground_tasks.%d.agentType\ts\t%s\n", n, AT[i]
    if (AN[i] != "") printf "F\tbackground_tasks.%d.description\ts\t%s\n", n, AN[i]
    n++
  }
  if (last != "") print "L\t" last
}'

copilot_tx() {
  tf=$(input_file "$TPATH")
  [ -n "$tf" ] || return 0
  tx=$(tail -c 2097152 "$tf" 2>/dev/null | awk "$COPILOT_TX" 2>/dev/null)
  [ -n "$tx" ] || return 0
  TLAST=$(printf '%s\n' "$tx" | sed -n "s/^L$TAB//p")
  [ -n "$TLAST" ] && LAST=$TLAST
  v2_facts
  ft=$(printf '%s\n' "$tx" | sed -n "s/^F$TAB//p")
  [ -n "$ft" ] && FACTS="$FACTS$NL$ft"
  while IFS="$TAB" read -r k t v; do
    [ -n "$k" ] && bg_field "$k=$v"
  done <<EOF
$ft
EOF
}

# The session's record at a turn's start (state running, its prompt) or end.
sess_turn() { # running|idle [prompt]
  sess_ok || return 0
  v2_common
  if [ "$1" = running ]; then sess_start; else sess_beat force; fi
  sess_write "$@"
}

# The heartbeat of the session's record (section 8.2): every hook event.
case $AGENT:$EVENT in
  agy:PreToolUse | grok:PreToolUse) sess_beat ;;
  *:UserPromptSubmit | *:userPromptSubmitted | *:SessionStart | *:sessionStart | *:SessionEnd | *:sessionEnd) ;;
  *) sess_beat ;;
esac

case $AGENT:$EVENT in
  claude:PermissionRequest | codex:PermissionRequest | opencode:PermissionRequest)
    if [ "$MODE" = signal ]; then
      print_state waiting "approve $TOOL: $DETAIL"
      finish
    fi
    case $AGENT in claude) rk=claude_perm ;; codex) rk=codex_perm ;; *) rk=oc_perm ;; esac
    rk_at "$rk" "@.oc${TAB}s$TAB$OCV$NL"
    if [ "$TOOL" = AskUserQuestion ]; then
      # The question's decidable report (section 10.3): this one, not the
      # PreToolUse before it, which waits ask_delay seconds for it.
      setmsg "${QTEXT:-$DESC}"
      ask_once || finish
      v2_prep "$RK_AT"
      [ -n "$LINKS" ] && request_flow question shared
    else
      d=$DETAIL
      [ "$TOOL" = apply_patch ] && d=${DESC:-patch}
      [ -n "$d" ] || d=$DESC
      setmsg "approve $TOOL: $d"
      v2_prep "$RK_AT"
      # Codex hides its prompt while the hook waits (section 4.6).
      w=shared
      [ "$AGENT" = codex ] && w=hidden
      [ -n "$LINKS" ] && request_flow permission "$w"
    fi
    ;;
  opencode:Question)
    # OpenCode 1.19 question.asked, from the bridge: an answer goes back to
    # the bridge (section 5.4).
    setmsg "$QTEXT"
    rk_at oc_question "@.oc${TAB}s$TAB$OCV$NL"
    v2_prep "$RK_AT"
    [ -n "$LINKS" ] && request_flow question shared
    ;;
  opencode:Form)
    # OpenCode 2.x form.created (a question): an alert, answered in the
    # terminal until the plugin can reply to a form (M8).
    setmsg "${QTEXT:-$LAST}"
    rk_at oc_form "@.oc${TAB}s$TAB$OCV$NL"
    v2_prep "$RK_AT"
    send_bg question
    ;;
  claude:PreToolUse)
    if [ "$TOOL" = AskUserQuestion ]; then
      setmsg "$QTEXT"
      print_state waiting
      # PermissionRequest reports the same question, decidable: it goes
      # first. This one is the safety net for a question without one.
      rk_at claude_askpre
      v2_prep "$RK_AT"
      w=$(conf_int ask_delay 2)
      trap '' HUP
      (
        sleep "$w"
        ask_once && send_bg question
      ) </dev/null >/dev/null 2>&1 &
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
        setmsg "$LAST"
        v2_prep
        send_bg question
        ;;
      elicitation_dialog | elicitation_url_dialog | agent_needs_input)
        # agent_needs_input: another background session of the user's needs
        # input, not this one: the alert stays, this tab's badge does not.
        [ "$NTYPE" = agent_needs_input ] || print_state waiting
        setmsg "$LAST"
        rk_at claude_notif "@.ntype${TAB}s$TAB$NTYPE$NL"
        v2_prep "$RK_AT"
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
    send_state running
    sess_turn running "$PROMPT"
    ;;
  claude:PostToolUse | claude:PostToolUseFailure)
    if [ "$EVENT" = PostToolUseFailure ] && [ "$ISINT" = true ] && [ -z "$AGENTID" ]; then
      # Esc during a tool call: the turn is over (no Stop follows). Not when
      # a subagent's tool was interrupted (agent_id is set): the main
      # session's wait goes on.
      note turn
      print_state idle
      turn_at interrupt
      send_state idle "$TURN_AT"
      sess_turn idle
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
    if [ "$EVENT" = SessionStart ]; then
      ensure_cli
      sess_start
      sess_ok && [ ! -f "$SESS.json" ] && sess_turn idle
    fi
    ;;
  claude:SessionEnd | grok:SessionEnd | copilot:sessionEnd | codex:SessionEnd)
    if [ "$AGENT" = copilot ] && [ "$REASON" = error ]; then
      # The session ended on an error (its last try, kept above).
      e=$(cat "$RUN_DIR/$SID.cerr" 2>/dev/null)
      setmsg "${e:-error: the session ended on an error}"
      LAST='' TLAST=''
      turn_at error
      v2_prep "$TURN_AT"
      send_bg error
    fi
    rm -f "$RUN_DIR/$SID.cerr" 2>/dev/null
    printf '' 2>/dev/null >"$RUN_DIR/t0.$$"
    # The record first: Codex gives this hook 3 seconds at most and then
    # ends its process group (0.165.0, measured).
    sess_end
    send_state ended
    rm -f "$RUN_DIR/t0.$$" 2>/dev/null
    # The agent is exiting and may take its hooks' children with it
    # (measured with Copilot -p): the sends finish first. Codex keeps the
    # children of a hook that ended in time, and ends the whole group of
    # one that did not (measured), so its hook does not wait.
    [ "$AGENT" = codex ] || wait
    ;;
  claude:SubagentStart | claude:SubagentStop | grok:SubagentStart | grok:SubagentStop | copilot:subagentStart | copilot:subagentStop)
    case $EVENT in *Start | *start) send_state sub_start ;; *) send_state sub_stop ;; esac
    ;;
  claude:Stop | codex:Stop)
    note turn
    case $LAST in '{\"title\":'*) finish ;; esac
    gf=''
    [ "$AGENT" = codex ] && gf=$(input_file "$TPATH")
    if [ "$AGENT" = codex ] && plan=$(codex_plan "$gf"); then
      # The turn ended on Codex's "Implement this plan?" (M2): a question,
      # not a done; answered in Codex's window (keys).
      setmsg "$plan"
      rk_at codex_plan "@.plan${TAB}s$TAB$plan$NL"
      v2_prep "$RK_AT"
      send_bg question
      usage_report
      turn_end
      sess_turn idle
      finish
    fi
    if [ "$AGENT" = codex ] && codex_goal_active "$gf"; then
      usage_report
      TGOAL=active
      turn_at background
      send_state background "$TURN_AT"
      TGOAL=''
      codex_goal_later "$gf"
      turn_end
      sess_turn idle
      finish
    fi
    stop_flow
    sess_turn idle
    ;;
  claude:StopFailure)
    note turn
    ev=error te=error
    case $ERR in authentication_failed | oauth_org_not_allowed | cloud_credential_error) ev=auth ;; rate_limit) te=limit ;; esac
    setmsg "$ERR: $LAST"
    turn_at "$te"
    v2_prep "$TURN_AT"
    send_bg "$ev"
    usage_report
    print_state done
    sess_turn idle
    ;;
  codex:SessionStart | codex:PostCompact)
    usage_report
    [ "$EVENT" = SessionStart ] && sess_start
    ;;
  codex:UserPromptSubmit)
    note turn
    prompt_origin
    turn_mark
    send_state running
    sess_turn running "$PROMPT"
    ;;
  codex:PreToolUse | codex:PostToolUse)
    # Registered for the session record's heartbeat only (section 8.3).
    ;;
  codex-notify:notify)
    [ "$NTYPE2" = agent-turn-complete ] || finish
    case $FIRSTIN in 'Generate a concise, single-line task title'*) finish ;; esac
    setmsg "$LAST"
    v2_prep
    send_bg done
    ;;
  gemini:Notification)
    # Gemini CLI asks after this hook returns and takes no answer from it:
    # an alert only (`question`, the event for "needs input").
    [ "$NTYPE" = ToolPermission ] || finish
    case $GTYPE in edit) TOOL=edit ;; info) TOOL=${TOOL:-fetch} ;; esac
    setmsg "approve ${TOOL:-$GTYPE}: ${DETAIL:-$LAST}"
    v2_prep
    send_bg question
    ;;
  gemini:AfterAgent)
    case $LAST in
      '[no response text]'*)
        # What Gemini CLI passes when the turn produced no answer: an API
        # error, a cancelled stream or a detected loop.
        setmsg "no_response: the turn ended without an answer"
        v2_prep
        send_bg error
        ;;
      *)
        setmsg "$LAST"
        [ "$STOPACT" = true ] && XFLAGS=',"stop_hook_active":true'
        v2_prep
        done_later
        ;;
    esac
    usage_report
    turn_end
    ;;
  agy:PreToolUse | agy:PostToolUse)
    if [ "$TOOL" = write_file ] && [ "$RFB" = true ]; then
      # A plan for review (ArtifactMetadata.RequestFeedback, M3): the Stop
      # that ends this turn is its review, not a done.
      facts_keep plan. agyplan '^(toolCall\.|stepIdx)'
      finish
    fi
    [ "$EVENT" = PreToolUse ] || finish
    case $TOOL in
      ask_question)
        setmsg "$QTEXT"
        rk_at agy_ask
        v2_prep "$RK_AT"
        send_bg question
        ;;
      run_command | write_file | edit_file | read_file | call_mcp_tool)
        # This hook runs before every call, before agy's permission policy:
        # only with agy_wait > 0 (opt-in), and then only when no tunnel
        # answers (an app that is connected sees agy's own prompt, section
        # 4.6), does a request go out and wait.
        [ -n "$LINKS" ] && [ "$(conf_wait_cap agy)" -gt 0 ] || finish
        # agy asks before a read only outside the workspace (its policy):
        # a read inside it does not wait.
        [ "$TOOL" = read_file ] && agy_in_workspace "$APATH" && finish
        d=$DETAIL
        [ -n "$d" ] || d=$APATH
        [ "$TOOL" = call_mcp_tool ] && d="$AMS/$AMT"
        setmsg "approve $TOOL: $d"
        if tunnel_probe; then
          log "permission tunnel-answered: no request"
          finish
        fi
        rk_at agy_tool
        v2_prep "$RK_AT"
        request_flow permission relay
        ;;
    esac
    ;;
  agy:Stop)
    # Only a fully idle agent is done (background tasks may still run).
    # Cancelling (Esc) sends no Stop at all.
    note turn
    if [ -f "$RUN_DIR/$SID.agyplan" ] && [ "$FULLYIDLE" != false ] && { [ -z "$ERR" ] || [ "$ERR" = null ]; }; then
      # The turn ended on a plan for review: a question (section 4.6
      # "agy plan"), decidable only on a v2 relay while no tunnel answers.
      facts_add agyplan 3600
      rm -f "$RUN_DIR/$SID.agyplan" 2>/dev/null
      setmsg "approve plan"
      rk_at agy_plan
      v2_prep "$RK_AT"
      [ -n "$LINKS" ] && request_flow question agyplan
      turn_end
      sess_turn idle
      finish
    fi
    LAST=''
    if [ -n "$ERR" ] && [ "$ERR" != null ]; then
      setmsg "${TERMREASON:-error}: $ERR"
      turn_at error
      v2_prep "$TURN_AT"
      send_bg error
    elif [ "$FULLYIDLE" = true ]; then
      setmsg ''
      turn_at done
      v2_prep "$TURN_AT"
      send_bg done
    elif [ "$FULLYIDLE" = false ]; then
      # Background commands, schedules or subagents still run; agy does not
      # say which, so the wait is bounded as for a dev server.
      BG_N=1
      bg_pause
    fi
    turn_end
    sess_turn idle "$LASTIN"
    ;;
  grok:UserPromptSubmit)
    # Also the turn Grok starts itself when background work reports back
    # (promptId task-completed-<id> or subagent-completed-<id>).
    note turn
    prompt_origin
    turn_mark
    send_state running
    sess_turn running "$PROMPT"
    ;;
  grok:PreToolUse)
    # Which tool asks next: the Notification of a permission prompt names
    # none (section 10.2).
    facts_keep pre. grokpre '^(toolName|toolUseId|toolInput)'
    ;;
  grok:PostToolUse)
    [ -n "$TOOLUSEID" ] && [ -f "$RUN_DIR/$SID.grokpre" ] &&
      awk -v id="$TOOLUSEID" -F "$TAB" '$1 == "pre.toolUseId" && $3 == id { f = 1 } END { exit !f }' "$RUN_DIR/$SID.grokpre" 2>/dev/null &&
      rm -f "$RUN_DIR/$SID.grokpre"
    ;;
  grok:Notification)
    # Grok asks in its own prompt and takes no answer from a hook:
    # permission_prompt (only while its permission UI waits; also its plan
    # review, "Plan approval requested"), elicitation_dialog (a question)
    # and idle_prompt are alerts. The key includes the event's timestamp, the
    # same in every copy of one event.
    nt=$NTYPE
    case $NTYPE in
      permission_prompt) case $LAST in 'Plan approval requested'*) nt=plan ;; esac ;;
      elicitation_dialog) ;;
      idle_prompt) bg_paused && finish; [ -f "$RUN_DIR/$SID.done" ] && finish ;;
      *) finish ;;
    esac
    once "$(printf '%s|%s|%s|%s|%s' "$EVENT" "$SID" "$NTYPE" "$GKEY" "$LAST" | cksum | awk '{ print $1 }')" || finish
    setmsg "$LAST"
    if [ "$NTYPE" = idle_prompt ]; then
      v2_prep
    else
      facts_add grokpre 600
      rk_at grok_notif "@.ntype${TAB}s$TAB$nt$NL"
      v2_prep "$RK_AT"
    fi
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
      ev=error te=error
      case $ERR in authentication_failed | oauth_org_not_allowed | cloud_credential_error) ev=auth ;; rate_limit) te=limit ;; esac
      setmsg "$ERR: $LAST"
      turn_at "$te"
      v2_prep "$TURN_AT"
      send_bg "$ev"
      turn_end
    fi
    sess_turn idle
    ;;
  opencode:Notification)
    setmsg "$LAST"
    v2_prep
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
    sess_turn idle
    ;;
  opencode:UserPromptSubmit)
    # Sent by the plugin when a session's own turn starts (a person's, or the
    # session taken up again by a background shell): ends a pause, and the
    # shells open at the last Stop do not hold this turn's Stop back.
    note turn
    PROMPT_USER=1 PROMPT_BY=user
    turn_mark
    send_state running
    sess_turn running
    ;;
  opencode:StopFailure)
    note turn
    ev=error
    case $ERR in ProviderAuthError | *[Aa]uth*) ev=auth ;; esac
    setmsg "$ERR: $LAST"
    turn_at error
    v2_prep "$TURN_AT"
    send_bg "$ev"
    sess_turn idle
    ;;
  copilot:permissionRequest)
    # It comes for calls whose prompt never shows too (read-only, already
    # allowed, plan.md): until that can be told from the hook (M9) it sends
    # nothing and prints nothing (an empty output is Copilot's "no decision";
    # exit 1 or other output would be a denial).
    ;;
  copilot:preToolUse)
    case $TOOL in
      exit_plan_mode)
        # The plan's review (section 10.4): an alert; answered in Copilot.
        v2_facts
        sm=$(printf '%s\n' "$FACTS" | sed -n "s/^toolArgs\\.summary${TAB}s$TAB//p" | head -n 1)
        setmsg "${sm:-plan ready}"
        rk_at cop_plan
        v2_prep "$RK_AT"
        send_bg question
        ;;
      ask_user)
        # Its notification (elicitation_dialog) carries no question.
        facts_keep pre. coppre '^toolArgs'
        ;;
    esac
    ;;
  copilot:notification)
    case $NTYPE in
      permission_prompt) ;;
      elicitation_dialog) facts_add coppre 600 ;;
      *) finish ;;
    esac
    setmsg "$LAST"
    rk_at cop_notif
    v2_prep "$RK_AT"
    send_bg question
    ;;
  copilot:userPromptSubmitted)
    note turn
    prompt_origin
    turn_mark
    send_state running
    sess_turn running "$PROMPT"
    ;;
  copilot:sessionStart)
    sess_start
    sess_ok && [ ! -f "$SESS.json" ] && sess_turn idle
    ;;
  copilot:agentStop)
    # A subagent's own stop (agentId set) is not the session's (section 7).
    if [ -n "$AGENTID" ]; then
      send_state sub_stop
      finish
    fi
    note turn
    copilot_tx
    stop_flow
    sess_turn idle
    ;;
  copilot:errorOccurred)
    # A failed tool is the model's to handle. Copilot retries a failed model
    # call and reports each try as recoverable (measured on 1.0.105: six
    # tries, all recoverable, then sessionEnd with reason error in -p mode):
    # kept for that end, not an alert of its own.
    [ "$ECTX" = tool_execution ] && finish
    if [ "$RECOV" = true ]; then
      printf '%s\n' "$(json_trim "${ERR:-error}: $LAST" 200 800)" >"$RUN_DIR/$SID.cerr" 2>/dev/null
      finish
    fi
    note turn
    setmsg "${ERR:-error}: $LAST"
    turn_at error
    v2_prep "$TURN_AT"
    send_bg error
    sess_turn idle
    ;;
esac
finish
