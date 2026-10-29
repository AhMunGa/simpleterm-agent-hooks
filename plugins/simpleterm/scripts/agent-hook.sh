#!/bin/sh
# SimpleTerm agent hook v1 (POSIX sh). Installed by the SimpleTerm app as
# ~/.simpleterm/agent-hook.sh; see README.md and
# docs/tech_specs/TDS_AGENT_ALERTS.md (sections 5 and 6) for the contract.
#
#   sh agent-hook.sh claude          Claude Code hook (event JSON on stdin)
#   sh agent-hook.sh claude signal   Claude Code PermissionRequest status only
#   sh agent-hook.sh codex           Codex hook (event JSON on stdin)
#   sh agent-hook.sh codex-notify J  Codex `notify` program (JSON is last arg)
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
  trim_log
  exit 0
}

# --- JSON helpers (awk, byte semantics) ------------------------------------

# Prints `path=value` for each wanted path (comma list) found in the JSON on
# stdin. String values stay JSON-escaped (they are re-embedded as-is, never
# decoded or evaluated). Paths: `a`, `a.b`, `a.0.b`. Tolerates truncation.
JSON_GET='
function path(   d, p) {
  p = ""
  for (d = 1; d <= depth; d++) p = p (d > 1 ? "." : "") K[d]
  return p
}
function emit(v,   p) {
  if (depth == 0) return
  p = path()
  if ((p in WANT) && !(p in GOT)) { GOT[p] = 1; need--; print p "=" v }
}
BEGIN { need = split(want, W, ","); for (k = 1; k <= need; k++) WANT[W[k]] = 1 }
{ s = s $0 "\n" }
END {
  len = length(s); i = 1; depth = 0
  while (i <= len && need > 0) {
    c = substr(s, i, 1)
    if (c == " " || c == "\t" || c == "\n" || c == "\r") { i++; continue }
    if (c == ",") {
      if (depth > 0) { if (T[depth] == "a") K[depth]++; else EXPK[depth] = 1 }
      i++; continue
    }
    if (c == ":") { if (depth > 0) EXPK[depth] = 0; i++; continue }
    if (c == "{" || c == "[") {
      depth++
      if (c == "{") { T[depth] = "o"; K[depth] = ""; EXPK[depth] = 1 }
      else { T[depth] = "a"; K[depth] = 0; EXPK[depth] = 0 }
      i++; continue
    }
    if (c == "}" || c == "]") { if (depth > 0) depth--; i++; continue }
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
      if (depth > 0 && T[depth] == "o" && EXPK[depth]) { K[depth] = str; continue }
      emit(str); continue
    }
    j = i
    while (j <= len && index(" \t\r\n,:}]", substr(s, j, 1)) == 0) j++
    emit(substr(s, i, j - i))
    i = j
  }
}'

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

# Escapes plain text (from our own config files) as JSON string content.
json_text() { # text maxu maxb
  t=$(printf '%s' "$1" | tr -d '\000-\037\177' | sed 's/\\/\\\\/g; s/"/\\"/g')
  json_trim "$t" "$2" "$3"
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
  L_FILE=$1 L_RELAY='' L_LINK='' L_SECRET='' L_ENC='' L_MAC='' L_LABEL='' L_V=''
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
    esac
  done <"$1"
  [ "$L_V" = 1 ] || { log "link-skip version"; return 1; }
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

# Builds the section 5.2 plaintext for the loaded link.
plaintext() { # rid ev nonce
  host=$(json_text "$L_LABEL" 64 256)
  p='{"v":1,"rid":"'$1'","ev":"'$2'","app":"'$APP'","host":"'$host'","cwd":"'$CWD_BASE'","msg":"'$MSG'"'
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
  code=$(http POST /v1/ingest "$body" 20 "$4")
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

# Sends $1 to every link in the background and returns at once.
send_bg() { # ev
  [ -n "$LINKS" ] || return 0
  (
    trap '' HUP
    printf '%s\n' "$LINKS" | while IFS= read -r f; do
      load_link "$f" || continue
      ingest_one "$RID" "$1" '' "$RUN_DIR/ing.$$.$RID.$(printf %.8s "$L_LINK")" >/dev/null
    done
    trim_log
  ) </dev/null >/dev/null 2>&1 &
}

# --- terminal sequence (Claude Code only, SimpleTerm sessions only) ---------

print_state() { # running|waiting|done [message]
  [ "$AGENT" = claude ] || return 0
  [ "${SIMPLETERM:-}" = 1 ] || return 0
  m=''
  [ -n "${2:-}" ] && m=' '$(json_trim "$2" 80 320)
  printf '{"terminalSequence":"\\u001b]9;simpleterm:state=%s%s\\u0007"}\n' "$1" "$m"
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
      *) sleep 2 ;;
    esac
  done
  rm -f "$resp" "$resp.code"
  printf '%s\n' "$r" >"$3.tmp" && mv -f "$3.tmp" "$3"
}

# Prints the agent's PID: the nearest ancestor that is not a shell (hooks
# run under `sh -c`, Codex under `$SHELL -lc`). Empty if ps is unavailable.
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
answered_locally() { # since fingerprint
  [ -f "$RUN_DIR/$SID.res" ] || return 1
  while IFS=' ' read -r t kind fp; do
    is_uint "$t" || continue
    [ "$t" -ge "$1" ] || continue
    [ "$kind" = turn ] && return 0
    [ "$kind" = tool ] && [ "$fp" = "$2" ] && return 0
  done <"$RUN_DIR/$SID.res"
  return 1
}

permission_flow() {
  if [ "$AGENT" = codex ]; then
    cap=$(conf_int codex_wait 60)
  else
    cap=$(conf_int claude_wait 540)
  fi
  [ "$cap" -le 540 ] || cap=540
  POLL_WAIT=$(conf_int poll_wait 25)
  [ "$POLL_WAIT" -ge 1 ] && [ "$POLL_WAIT" -le 25 ] || POLL_WAIT=25
  start=$(date +%s)
  deadline=$((start + cap))
  PIDS='' JOBS='' POLLERS=0
  AGENT_PID=$(agent_pid)

  cleanup_perm() {
    for p in $PIDS; do kill "$p" 2>/dev/null; done
    rm -f "$RUN_DIR"/ing."$$".* "$RUN_DIR"/out."$$".* "$RUN_DIR"/dec."$$".* 2>/dev/null
  }
  # The agent may end the wait (Claude Code signals hooks when a turn is
  # interrupted): print nothing and leave the decision to the agent.
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
    allow)
      printf '{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"allow"}}%s}\n' \
        "$(state_json running)"
      log "permission allow"
      ;;
    deny)
      printf '{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"deny","message":"Denied from SimpleTerm"}}%s}\n' \
        "$(state_json running)"
      log "permission deny"
      ;;
  esac
}

# --- main ----------------------------------------------------------------

case $AGENT in
  claude) APP=claude-code ;;
  codex | codex-notify) APP=codex ;;
  *) exit 0 ;;
esac

if [ "$AGENT" = codex-notify ]; then
  INPUT=''
  for a in "$@"; do INPUT=$a; done
  [ "${#INPUT}" -le "$MAX_INPUT" ] || INPUT=''
else
  INPUT=$(head -c "$MAX_INPUT" 2>/dev/null) || INPUT=$(dd bs=4096 count=64 2>/dev/null)
fi

# Nothing to do without a link or a SimpleTerm session.
LINKS=$(list_links)
[ -n "$LINKS" ] || [ "${SIMPLETERM:-}" = 1 ] || exit 0

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

EVENT='' NTYPE='' TOOL='' DETAIL='' DESC='' SID='' CWD='' LAST='' ERR='' QTEXT='' FIRSTIN='' NTYPE2=''
while IFS= read -r kv; do
  case $kv in
    hook_event_name=*) EVENT=${kv#*=} ;;
    notification_type=*) NTYPE=${kv#*=} ;;
    type=*) NTYPE2=${kv#*=} ;;
    tool_name=*) TOOL=${kv#*=} ;;
    tool_input.command=* | tool_input.file_path=* | tool_input.url=*) [ -n "$DETAIL" ] || DETAIL=${kv#*=} ;;
    tool_input.description=*) DESC=${kv#*=} ;;
    tool_input.questions.0.question=*) QTEXT=${kv#*=} ;;
    session_id=*) SID=${kv#*=} ;;
    cwd=*) CWD=${kv#*=} ;;
    message=*) LAST=${kv#*=} ;;
    last_assistant_message=*) LAST=${kv#*=} ;;
    last-assistant-message=*) LAST=${kv#*=} ;;
    input-messages.0=*) FIRSTIN=${kv#*=} ;;
    error=*) ERR=${kv#*=} ;;
  esac
done <<EOF
$(printf '%s' "$INPUT" | awk -v want='hook_event_name,notification_type,type,tool_name,tool_input.command,tool_input.file_path,tool_input.url,tool_input.description,tool_input.questions.0.question,session_id,cwd,message,last_assistant_message,last-assistant-message,input-messages.0,error' "$JSON_GET" 2>/dev/null)
EOF

[ "$AGENT" = codex-notify ] && EVENT=notify
SID=$(printf '%s' "$SID" | tr -c 'A-Za-z0-9_-' '_' | cut -c1-80)
[ -n "$SID" ] || SID=nosession

RID=$(rand_hex 8)
TS=$(date +%s)
if [ "${SIMPLETERM_HOOK_TEST:-}" = 1 ]; then
  [ -n "${SIMPLETERM_HOOK_TEST_RID:-}" ] && RID=$SIMPLETERM_HOOK_TEST_RID
  [ -n "${SIMPLETERM_HOOK_TEST_TS:-}" ] && TS=$SIMPLETERM_HOOK_TEST_TS
fi
is_hex "$RID" 16 || RID=''
is_uint "$TS" || TS=0
[ -n "$RID" ] || LINKS=''

CWD_BASE=$(json_trim "$CWD" 64 256 base)
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

case $AGENT:$EVENT in
  claude:PermissionRequest | codex:PermissionRequest)
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
    print_state running
    ;;
  claude:PostToolUse | claude:PostToolUseFailure)
    note tool "$FP"
    print_state running
    ;;
  claude:Stop | codex:Stop)
    note turn
    case $LAST in '{\"title\":'*) finish ;; esac
    MSG=$(json_trim "$LAST" 200 800)
    send_bg done
    print_state done
    find "$RUN_DIR" -type f -mtime +0 -exec rm -f {} + 2>/dev/null
    ;;
  claude:StopFailure)
    note turn
    ev=error
    case $ERR in authentication_failed | oauth_org_not_allowed | cloud_credential_error) ev=auth ;; esac
    MSG=$(json_trim "$ERR: $LAST" 200 800)
    send_bg "$ev"
    print_state done
    ;;
  codex-notify:notify)
    [ "$NTYPE2" = agent-turn-complete ] || finish
    case $FIRSTIN in 'Generate a concise, single-line task title'*) finish ;; esac
    MSG=$(json_trim "$LAST" 200 800)
    send_bg done
    ;;
esac
finish
