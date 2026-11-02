# SimpleTerm agent hook v1 (Windows PowerShell 5.1+ and PowerShell 7).
# Installed by the SimpleTerm app as ~/.simpleterm/agent-hook.ps1; see
# README.md and docs/tech_specs/TDS_AGENT_ALERTS.md (sections 5 and 6).
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File agent-hook.ps1 claude
#   ... agent-hook.ps1 claude signal     Claude Code PermissionRequest status only
#   ... agent-hook.ps1 codex             Codex hook (event JSON on stdin)
#   ... agent-hook.ps1 codex-notify J    Codex `notify` program (JSON is last arg)
#   ... agent-hook.ps1 notify T [B]      `simpleterm notify` (simpleterm.cmd)
#
# Same behavior as agent-hook.sh for Claude Code, Codex and Grok Build (run
# with `claude` and GROK_HOOK_EVENT set), using only .NET (Aes CBC/PKCS7,
# HMACSHA256, HttpWebRequest). Gemini CLI, Antigravity and OpenCode are
# sh-only. It never evaluates its input, prints only agent-defined JSON on
# stdout, and always exits 0. Keep this file ASCII: Windows PowerShell 5.1
# reads BOM-less scripts in the ANSI code page.

$ErrorActionPreference = 'Stop'
$ScriptArgs = @($args)
$Agent = ''
$Mode = ''
if ($ScriptArgs.Count -gt 0) { $Agent = [string]$ScriptArgs[0] }
if ($ScriptArgs.Count -gt 1) { $Mode = [string]$ScriptArgs[1] }

$MaxInput = 262144
$MaxLinks = 16
# The plugin release of this script (the manifests carry the same).
$HookVersion = '0.3.1'
# Bumped when the ~/.simpleterm/bin/simpleterm.cmd wrapper must be rewritten.
$CliRev = 2
$Inv = [Globalization.CultureInfo]::InvariantCulture
$Utf8 = New-Object System.Text.UTF8Encoding($false)
$IsWin = ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT)

$StDir = Join-Path $HOME '.simpleterm'
$LinksDir = Join-Path $StDir 'links'
$RunDir = Join-Path $StDir 'run'
$LogPath = Join-Path $StDir 'agent-hook.log'
$Script:Logged = $false

function Now-Epoch {
    $epoch = New-Object DateTime(1970, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)
    return [int64][Math]::Floor(([DateTime]::UtcNow - $epoch).TotalSeconds)
}

function Write-Log([string]$text) {
    try {
        if (-not [IO.Directory]::Exists($StDir)) { return }
        $line = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture) +
            ' ' + $Agent + ' ' + $text + "`n"
        [IO.File]::AppendAllText($LogPath, $line, $Utf8)
        $Script:Logged = $true
    } catch { }
}

function Trim-Log {
    if (-not $Script:Logged) { return }
    try {
        $lines = [IO.File]::ReadAllLines($LogPath, $Utf8)
        if ($lines.Length -le 200) { return }
        $keep = $lines[($lines.Length - 200)..($lines.Length - 1)]
        $tmp = $LogPath + '.' + $PID
        [IO.File]::WriteAllText($tmp, (($keep -join "`n") + "`n"), $Utf8)
        if ([IO.File]::Exists($LogPath)) { [IO.File]::Delete($LogPath) }
        [IO.File]::Move($tmp, $LogPath)
    } catch { }
}

function Write-Out([string]$text) {
    $bytes = $Utf8.GetBytes($text + "`n")
    $out = [Console]::OpenStandardOutput()
    $out.Write($bytes, 0, $bytes.Length)
    $out.Flush()
}

# --- JSON helpers --------------------------------------------------------

$TokenRe = New-Object System.Text.RegularExpressions.Regex('"(?:[^"\\]|\\.)*"|[{}\[\],:]|[^\s{}\[\],:"]+|"')

# Returns a hashtable path -> value for the wanted paths (`a`, `a.b`,
# `a.0.b`). String values stay JSON-escaped. Tolerates truncated input.
function Get-JsonFields([string]$text, [string[]]$want) {
    $result = @{}
    $wantSet = @{}
    foreach ($w in $want) { $wantSet[$w] = $true }
    $need = $want.Count
    $types = New-Object System.Collections.ArrayList
    $keys = New-Object System.Collections.ArrayList
    $expectKey = New-Object System.Collections.ArrayList
    $m = $TokenRe.Match($text)
    while ($m.Success -and $need -gt 0) {
        $t = $m.Value
        $depth = $types.Count
        if ($t -eq '{' -or $t -eq '[') {
            if ($t -eq '{') { [void]$types.Add('o'); [void]$keys.Add(''); [void]$expectKey.Add($true) }
            else { [void]$types.Add('a'); [void]$keys.Add(0); [void]$expectKey.Add($false) }
        } elseif ($t -eq '}' -or $t -eq ']') {
            if ($depth -gt 0) {
                $types.RemoveAt($depth - 1); $keys.RemoveAt($depth - 1); $expectKey.RemoveAt($depth - 1)
            }
        } elseif ($t -eq ',') {
            if ($depth -gt 0) {
                if ($types[$depth - 1] -eq 'a') { $keys[$depth - 1] = [int]$keys[$depth - 1] + 1 }
                else { $expectKey[$depth - 1] = $true }
            }
        } elseif ($t -eq ':') {
            if ($depth -gt 0) { $expectKey[$depth - 1] = $false }
        } elseif ($t -eq '"') {
            break
        } else {
            $isString = $t.StartsWith('"')
            $value = $t
            if ($isString) { $value = $t.Substring(1, $t.Length - 2) }
            if ($depth -gt 0 -and $types[$depth - 1] -eq 'o' -and $expectKey[$depth - 1]) {
                $keys[$depth - 1] = $value
            } elseif ($depth -gt 0) {
                $path = ($keys | ForEach-Object { [string]$_ }) -join '.'
                if ($wantSet.ContainsKey($path) -and -not $result.ContainsKey($path)) {
                    $result[$path] = $value
                    $need--
                }
            }
        }
        $m = $m.NextMatch()
    }
    return $result
}

function Get-Field($fields, [string]$name) {
    if ($fields.ContainsKey($name)) { return [string]$fields[$name] }
    return ''
}

function Test-Hex4([string]$s) {
    return ($s.Length -eq 4 -and $s -match '^[0-9a-fA-F]{4}$')
}

# Truncates JSON-escaped string content to $maxU characters and $maxB UTF-8
# bytes without splitting an escape or a surrogate pair; control characters
# become spaces. -Base keeps only the last path component (for cwd).
function Limit-JsonText([string]$s, [int]$maxU, [int]$maxB, [switch]$Base) {
    if ($Base) {
        while ($s.Length -gt 0) {
            if ($s.EndsWith('/')) { $s = $s.Substring(0, $s.Length - 1) }
            elseif ($s.EndsWith('\\')) { $s = $s.Substring(0, $s.Length - 2) }
            else { break }
        }
        $p = 0
        $k = 0
        while ($k -lt $s.Length) {
            $c = $s[$k]
            if ($c -eq '/') { $p = $k + 1 }
            elseif ($c -eq '\' -and $k + 1 -lt $s.Length -and $s[$k + 1] -eq '\') { $p = $k + 2; $k++ }
            elseif ($c -eq '\') { $k++ }
            $k++
        }
        $s = $s.Substring([Math]::Min($p, $s.Length))
    }
    $sb = New-Object System.Text.StringBuilder
    $i = 0; $u = 0; $b = 0; $n = $s.Length
    while ($i -lt $n -and $u -lt $maxU) {
        $c = $s[$i]
        $unit = [string]$c
        $step = 1
        $code = [int]$c
        if ($c -eq '\') {
            if ($i + 1 -ge $n) { break }
            $e = $s[$i + 1]
            $step = 2
            if ($e -eq 'u') {
                if ($i + 6 -gt $n -or -not (Test-Hex4 $s.Substring($i + 2, 4))) { break }
                $v = [Convert]::ToInt32($s.Substring($i + 2, 4), 16)
                $unit = $s.Substring($i, 6); $step = 6
                if ($v -ge 0xD800 -and $v -le 0xDBFF) {
                    $v2 = -1
                    if ($i + 12 -le $n -and $s.Substring($i + 6, 2) -eq '\u' -and (Test-Hex4 $s.Substring($i + 8, 4))) {
                        $v2 = [Convert]::ToInt32($s.Substring($i + 8, 4), 16)
                    }
                    if ($v2 -ge 0xDC00 -and $v2 -le 0xDFFF) { $unit = $s.Substring($i, 12); $step = 12 }
                    else { $unit = ' ' }
                } elseif ($v -ge 0xDC00 -and $v -le 0xDFFF) { $unit = ' ' }
                elseif ($v -lt 32 -or ($v -ge 127 -and $v -le 159) -or $v -eq 0x2028 -or $v -eq 0x2029) { $unit = ' ' }
            } elseif ($e -eq '"' -or $e -eq '\' -or $e -eq '/') {
                $unit = $s.Substring($i, 2)
            } else {
                $unit = ' '
            }
        } elseif ([char]::IsHighSurrogate($c)) {
            if ($i + 1 -lt $n -and [char]::IsLowSurrogate($s[$i + 1])) { $unit = $s.Substring($i, 2); $step = 2 }
            else { $unit = ' ' }
        } elseif ([char]::IsLowSurrogate($c)) {
            $unit = ' '
        } elseif ($code -lt 32 -or ($code -ge 127 -and $code -le 159) -or $code -eq 0x2028 -or $code -eq 0x2029) {
            $unit = ' '
        }
        $ub = $Utf8.GetByteCount($unit)
        if ($b + $ub -gt $maxB) { break }
        [void]$sb.Append($unit)
        $b += $ub; $u++; $i += $step
    }
    return $sb.ToString()
}

# Escapes plain text (from our own config files) as JSON string content.
function ConvertTo-JsonText([string]$text, [int]$maxU, [int]$maxB) {
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $text.ToCharArray()) {
        $code = [int]$ch
        if ($code -lt 32 -or $code -eq 127) { continue }
        if ($ch -eq '\') { [void]$sb.Append('\\') }
        elseif ($ch -eq '"') { [void]$sb.Append('\"') }
        else { [void]$sb.Append($ch) }
    }
    return (Limit-JsonText $sb.ToString() $maxU $maxB)
}

# Text of a `simpleterm notify` notification, as notify_text in agent-hook.sh:
# the terminal (OSC 777) and the `notify` event get the same text. Whitespace
# runs, line breaks included (TAB LF VT FF CR, NEL, U+2028, U+2029), become
# one space; other control characters (C0, DEL, C1) and lone surrogates (the
# UTF-16 form of invalid UTF-8) are removed; `;`, the OSC 777 field
# separator, becomes `,`; leading and trailing spaces go; then it is cut to
# $maxU characters and $maxB UTF-8 bytes, between characters and not after a
# space.
function Format-NotifyText([string]$text, [int]$maxU, [int]$maxB) {
    $t = [regex]::Replace([string]$text, '[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]', '')
    $t = [regex]::Replace($t, '[\t\n\x0b\x0c\r\u0085\u2028\u2029]', ' ')
    $t = [regex]::Replace($t, '[\x00-\x1f\x7f-\x9f]', '').Replace(';', ',')
    $t = [regex]::Replace($t, ' {2,}', ' ').Trim(' ')
    $sb = New-Object System.Text.StringBuilder
    $u = 0; $b = 0
    for ($i = 0; $i -lt $t.Length; $i++) {
        $unit = [string]$t[$i]
        if ([char]::IsHighSurrogate($t[$i])) { $unit = $t.Substring($i, 2); $i++ }
        $n = $Utf8.GetByteCount($unit)
        if ($u + 1 -gt $maxU -or $b + $n -gt $maxB) { break }
        [void]$sb.Append($unit); $u++; $b += $n
    }
    return $sb.ToString().TrimEnd(' ')
}

function Test-Hex([string]$s, [int]$len) {
    return ($null -ne $s -and $s.Length -eq $len -and $s -cmatch '^[0-9a-f]+$')
}

function Test-UInt([string]$s) {
    return ($null -ne $s -and $s -match '^[0-9]{1,12}$')
}

# --- crypto ----------------------------------------------------------------

function ConvertFrom-Hex([string]$h) {
    $bytes = New-Object byte[] ($h.Length / 2)
    for ($i = 0; $i -lt $bytes.Length; $i++) { $bytes[$i] = [Convert]::ToByte($h.Substring($i * 2, 2), 16) }
    return , $bytes
}

function ConvertTo-Hex([byte[]]$bytes) {
    $sb = New-Object System.Text.StringBuilder ($bytes.Length * 2)
    foreach ($x in $bytes) { [void]$sb.Append($x.ToString('x2')) }
    return $sb.ToString()
}

function New-RandomHex([int]$n) {
    $bytes = New-Object byte[] $n
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
    $rng.Dispose()
    return (ConvertTo-Hex $bytes)
}

function Get-Sha256Hex([string]$text) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $hash = $sha.ComputeHash([Text.Encoding]::ASCII.GetBytes($text))
    $sha.Dispose()
    return (ConvertTo-Hex $hash)
}

function Get-HmacHex([string]$keyHex, [string]$message) {
    $h = New-Object System.Security.Cryptography.HMACSHA256 (, (ConvertFrom-Hex $keyHex))
    $mac = $h.ComputeHash([Text.Encoding]::ASCII.GetBytes($message))
    $h.Dispose()
    return (ConvertTo-Hex $mac)
}

function Test-SameHex([string]$a, [string]$b) {
    if ($a.Length -ne $b.Length) { return $false }
    $diff = 0
    for ($i = 0; $i -lt $a.Length; $i++) { $diff = $diff -bor ([int]$a[$i] -bxor [int]$b[$i]) }
    return ($diff -eq 0)
}

# Returns the section 5.2 envelope JSON of $plain for $link, or $null.
function New-Envelope([string]$plain, $link) {
    $iv = New-RandomHex 16
    if ($env:SIMPLETERM_HOOK_TEST -eq '1' -and $env:SIMPLETERM_HOOK_TEST_IV) { $iv = $env:SIMPLETERM_HOOK_TEST_IV }
    if (-not (Test-Hex $iv 32)) { return $null }
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.Key = ConvertFrom-Hex $link.enc
    $aes.IV = ConvertFrom-Hex $iv
    $enc = $aes.CreateEncryptor()
    $pb = $Utf8.GetBytes($plain)
    $ct = [Convert]::ToBase64String($enc.TransformFinalBlock($pb, 0, $pb.Length))
    $enc.Dispose()
    $aes.Dispose()
    $mac = Get-HmacHex $link.mac ('st1.' + $iv + '.' + $ct)
    return '{"v":1,"iv":"' + $iv + '","ct":"' + $ct + '","mac":"' + $mac + '"}'
}

# --- links -----------------------------------------------------------------

function Read-Link([string]$file) {
    try {
        $info = New-Object IO.FileInfo($file)
        if (-not $info.Exists -or $info.Length -gt 4096) { Write-Log 'link-skip too-large'; return $null }
        $link = @{ v = ''; relay = ''; link = ''; secret = ''; enc = ''; mac = ''; label = ''; kind = '' }
        foreach ($line in [IO.File]::ReadAllLines($file, $Utf8)) {
            if ($line.Length -gt 512) { continue }
            $idx = $line.IndexOf('=')
            if ($idx -lt 1) { continue }
            $k = $line.Substring(0, $idx)
            if ($link.ContainsKey($k)) { $link[$k] = $line.Substring($idx + 1).TrimEnd("`r") }
        }
        if ($link.v -ne '1') { Write-Log 'link-skip version'; return $null }
        # kind=tunnel: the app's end of its SSH connection on a loopback port.
        if ($link.kind -cne 'tunnel') { $link.kind = '' }
        if (-not ((Test-Hex $link.link 32) -and (Test-Hex $link.secret 64) -and (Test-Hex $link.enc 64) -and (Test-Hex $link.mac 64))) {
            Write-Log 'link-skip fields'; return $null
        }
        $relay = $link.relay.TrimEnd('/')
        $ok = ($relay -cmatch '^https://[A-Za-z0-9.:/_~%-]+$') -or
            ($relay -cmatch '^http://(127\.0\.0\.1|localhost)(:[0-9]+)?(/[A-Za-z0-9._~%/-]*)?$')
        if (-not $ok) { Write-Log 'link-skip relay'; return $null }
        $link.relay = $relay
        if ([IO.File]::Exists((Join-Path $RunDir ($link.link + '.revoked')))) { return $null }
        return $link
    } catch {
        Write-Log 'link-skip unreadable'
        return $null
    }
}

function Get-LinkFiles {
    $files = @()
    if (-not [IO.Directory]::Exists($LinksDir)) { return $files }
    foreach ($f in ([IO.Directory]::GetFiles($LinksDir, '*.conf') | Sort-Object)) {
        $name = [IO.Path]::GetFileNameWithoutExtension($f)
        if (-not (Test-Hex $name 32)) { continue }
        $files += $f
        if ($files.Count -ge $MaxLinks) { break }
    }
    return $files
}

function Get-ConfInt([string]$key, [int]$default) {
    $path = Join-Path $StDir 'agent-hook.conf'
    try {
        if ([IO.File]::Exists($path) -and (New-Object IO.FileInfo($path)).Length -le 4096) {
            foreach ($line in [IO.File]::ReadAllLines($path, $Utf8)) {
                if ($line -cmatch ('^' + $key + '=([0-9]{1,6})\s*$')) { return [int]$Matches[1] }
            }
        }
    } catch { }
    return $default
}

# --- HTTP ------------------------------------------------------------------

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch { }

# Starts an asynchronous request; Complete-Relay finishes it.
function Start-Relay($link, [string]$method, [string]$path, [string]$body, [int]$timeoutSec) {
    $req = [System.Net.HttpWebRequest]::Create($link.relay + $path)
    $req.Method = $method
    $req.AllowAutoRedirect = $false
    $req.UserAgent = 'simpleterm-hook/1'
    $req.Timeout = $timeoutSec * 1000
    $req.ReadWriteTimeout = $timeoutSec * 1000
    $req.Headers['Authorization'] = 'Bearer ' + $link.link + '.' + $link.secret
    if ($method -eq 'POST') {
        $bytes = $Utf8.GetBytes($body)
        $req.ContentType = 'application/json'
        $req.ContentLength = $bytes.Length
        $stream = $req.GetRequestStream()
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Close()
    }
    return @{ req = $req; ar = $req.BeginGetResponse($null, $null); until = [DateTime]::UtcNow.AddSeconds($timeoutSec); link = $link }
}

function Test-RelayDone($op) {
    if ($op.ar.IsCompleted) { return $true }
    if ([DateTime]::UtcNow -gt $op.until) { try { $op.req.Abort() } catch { } ; return $true }
    return $false
}

# Waits for the request and returns @{ code; body } (code 0 on failure).
function Complete-Relay($op) {
    while (-not (Test-RelayDone $op)) { Start-Sleep -Milliseconds 100 }
    $resp = $null
    try {
        $resp = $op.req.EndGetResponse($op.ar)
    } catch {
        $ex = $_.Exception
        while ($null -ne $ex -and -not ($ex -is [System.Net.WebException])) { $ex = $ex.InnerException }
        if ($null -ne $ex -and $null -ne $ex.Response) { $resp = $ex.Response }
    }
    if ($null -eq $resp) { return @{ code = 0; body = '' } }
    $code = [int]$resp.StatusCode
    $body = ''
    try {
        $stream = $resp.GetResponseStream()
        $buf = New-Object byte[] 4096
        $total = 0
        while ($total -lt $buf.Length) {
            $n = $stream.Read($buf, $total, $buf.Length - $total)
            if ($n -le 0) { break }
            $total += $n
        }
        $body = $Utf8.GetString($buf, 0, $total)
    } catch { }
    $resp.Close()
    return @{ code = $code; body = $body }
}

function Short([string]$id) { return $id.Substring(0, 8) }

# --- event payload ---------------------------------------------------------

# `usage` carries $Script:UsageJson instead of a message; `notify` a title.
function New-Plaintext($link, [string]$rid, [string]$ev, [string]$nonce) {
    $hostText = ConvertTo-JsonText $link.label 64 256
    $p = '{"v":1,"rid":"' + $rid + '","ev":"' + $ev + '","app":"' + $App + '","host":"' + $hostText +
        '","cwd":"' + $CwdBase + '"'
    if ($ev -eq 'usage') { $p += $Script:UsageJson }
    elseif ($ev -eq 'notify') { $p += ',"title":"' + $Script:Title + '","msg":"' + $Script:Msg + '"' }
    else { $p += ',"msg":"' + $Script:Msg + '"' }
    # A done of a Stop that another Stop hook had already kept going.
    if ($ev -eq 'done' -and $Script:XFlag -eq '1') { $p += ',"stop_hook_active":true' }
    if ($nonce) { $p += ',"nonce":"' + $nonce + '"' }
    return $p + ',"ts":' + $Ts + '}'
}

function Start-Ingest($link, [string]$rid, [string]$ev, [string]$nonce) {
    $envJson = New-Envelope (New-Plaintext $link $rid $ev $nonce) $link
    if ($null -eq $envJson) { Write-Log ('seal-failed link=' + (Short $link.link)); return $null }
    $body = '{"v":1,"rid":"' + $rid + '","ev":"' + $ev + '"'
    if ($nonce) { $body += ',"nh":"' + (Get-Sha256Hex $nonce) + '"' }
    $body += ',"env":' + $envJson + '}'
    # A tunnel answers at once or not at all; the relay may hold the request.
    $timeout = 20
    if ($link.kind -eq 'tunnel') { $timeout = 5 }
    return (Start-Relay $link 'POST' '/v1/ingest' $body $timeout)
}

# Finishes an ingest; returns the push result or httpNNN.
function Complete-Ingest($op, [string]$ev) {
    $r = Complete-Relay $op
    $push = ''
    if ($r.code -eq 200) { $push = Get-Field (Get-JsonFields $r.body @('push')) 'push' }
    if ($r.code -eq 410) {
        try { [IO.File]::WriteAllText((Join-Path $RunDir ($op.link.link + '.revoked')), '', $Utf8) } catch { }
    }
    $Script:IngestCode = $r.code
    $shown = $push
    if (-not $shown) { $shown = '-' }
    Write-Log ('ingest ev=' + $ev + ' link=' + (Short $op.link.link) + ' http=' + ('{0:000}' -f $r.code) + ' push=' + $shown)
    if ($push) { return $push }
    return ('http' + $r.code)
}

# Sends the event to every link from a detached child process and returns.
# $scope limits it to `tunnel` or `relay` links; once a link took the event,
# $markText is written to the run file $markName.
# (PowerShell names are case-insensitive: a parameter `$rid` would hide `$Rid`.)
function Send-Background([string]$ev, [string]$eventRid, [string]$scope, [string]$markName, [string]$markText) {
    if ($LinkFiles.Count -eq 0) { return }
    if (-not $eventRid) { $eventRid = $Rid }
    if (-not $scope) { $scope = 'all' }
    # The child gets the event through its environment, not its command line.
    $usage = [Convert]::ToBase64String($Utf8.GetBytes([string]$Script:UsageJson))
    $mark = [Convert]::ToBase64String($Utf8.GetBytes([string]$markText))
    $payload = '{"ev":"' + $ev + '","rid":"' + $eventRid + '","ts":"' + $Ts + '","cwd":"' + $CwdBase +
        '","msg":"' + $Script:Msg + '","title":"' + $Script:Title + '","xflag":"' + $Script:XFlag + '","usage":"' + $usage + '","scope":"' + $scope +
        '","mark":"' + $markName + '","marktext":"' + $mark + '"' + $Script:LaterJson + '}'
    $env:SIMPLETERM_HOOK_PAYLOAD = [Convert]::ToBase64String($Utf8.GetBytes($payload))
    $exe = (Get-Process -Id $PID).Path
    $argList = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $PSCommandPath + '"'), $Agent, '__send')
    try {
        if ($IsWin) {
            Start-Process -FilePath $exe -ArgumentList $argList -WindowStyle Hidden | Out-Null
        } else {
            # Keep the agent's stdout pipe out of the child, or the agent waits for it.
            Start-Process -FilePath $exe -ArgumentList $argList -RedirectStandardOutput '/dev/null' `
                -RedirectStandardError ([IO.Path]::Combine($RunDir, 'bg.err')) | Out-Null
        }
    } catch {
        Write-Log ('background-start-failed ' + $_.Exception.GetType().Name)
    }
    Remove-Item Env:\SIMPLETERM_HOOK_PAYLOAD -ErrorAction SilentlyContinue
}

# Sends `done` later from the background child: after $wait seconds, if the
# file $file still holds $token on line $line (a pause or a goal turn not
# ended meanwhile) and, for a goal, the rollout $path got no task_started
# after $offset. The event is made then (fresh rid and time).
function Start-LaterSend([string]$kind, [int]$wait, [string]$file, [int]$line, [string]$token, [string]$path, [int64]$offset) {
    $Script:LaterJson = ',"lkind":"' + $kind + '","lwait":"' + $wait + '","lline":"' + $line + '","ltoken":"' + $token +
        '","lfile":"' + [Convert]::ToBase64String($Utf8.GetBytes($file)) + '","lpath":"' + [Convert]::ToBase64String($Utf8.GetBytes($path)) +
        '","loff":"' + $offset + '"'
    Send-Background 'done'
    $Script:LaterJson = ''
}

function Test-LaterStillDue($f) {
    $wait = Get-Field $f 'lwait'
    $line = Get-Field $f 'lline'
    $off = Get-Field $f 'loff'
    if (-not (Test-UInt $wait) -or -not (Test-UInt $line) -or -not (Test-UInt $off)) { return $false }
    Start-Sleep -Seconds ([int]$wait)
    try {
        $file = $Utf8.GetString([Convert]::FromBase64String((Get-Field $f 'lfile')))
        $lines = [IO.File]::ReadAllLines($file, $Utf8)
        if ($lines.Count -le [int]$line -or $lines[[int]$line] -ne (Get-Field $f 'ltoken')) { return $false }
        if ((Get-Field $f 'lkind') -eq 'goal') {
            $path = $Utf8.GetString([Convert]::FromBase64String((Get-Field $f 'lpath')))
            $fs = [IO.File]::Open($path, 'Open', 'Read', 'ReadWrite')
            try {
                [void]$fs.Seek([int64]$off, 'Begin')
                $rest = (New-Object IO.StreamReader($fs, $Utf8)).ReadToEnd()
            } finally { $fs.Dispose() }
            if ($rest.Contains('"type":"task_started"')) { return $false }
        }
        [IO.File]::Delete($file)
    } catch { return $false }
    return $true
}

function Invoke-SendChild {
    $raw = $env:SIMPLETERM_HOOK_PAYLOAD
    if (-not $raw) { return }
    $json = $Utf8.GetString([Convert]::FromBase64String($raw))
    $f = Get-JsonFields $json @('ev', 'rid', 'ts', 'msg', 'cwd', 'title', 'xflag', 'usage', 'scope', 'mark', 'marktext',
        'lkind', 'lwait', 'lline', 'ltoken', 'lfile', 'lpath', 'loff')
    $ev = Get-Field $f 'ev'
    $Script:Rid = Get-Field $f 'rid'
    $Script:Ts = Get-Field $f 'ts'
    $Script:Msg = Get-Field $f 'msg'
    $Script:Title = Get-Field $f 'title'
    $Script:XFlag = Get-Field $f 'xflag'
    $Script:CwdBase = Get-Field $f 'cwd'
    $scope = Get-Field $f 'scope'
    $mark = Get-Field $f 'mark'
    if (-not ($mark -cmatch '^[A-Za-z0-9_-]{1,80}\.usage$')) { $mark = '' }
    $markText = ''
    try { $markText = $Utf8.GetString([Convert]::FromBase64String((Get-Field $f 'marktext'))) } catch { $mark = '' }
    try { $Script:UsageJson = $Utf8.GetString([Convert]::FromBase64String((Get-Field $f 'usage'))) } catch { $Script:UsageJson = '' }
    if (-not ($ev -cmatch '^[a-z]{1,16}$') -or -not (Test-Hex $Script:Rid 16) -or -not (Test-UInt $Script:Ts)) { return }
    if ($ev -eq 'usage' -and -not $Script:UsageJson) { return }
    if (Get-Field $f 'lkind') {
        if (-not (Test-LaterStillDue $f)) { return }
        $Script:Rid = New-RandomHex 8
        $Script:Ts = [string](Now-Epoch)
        if (-not (Test-Hex $Script:Rid 16)) { return }
    }
    $ops = @()
    foreach ($file in (Get-LinkFiles)) {
        $link = Read-Link $file
        if ($null -eq $link) { continue }
        if ($scope -eq 'tunnel' -and $link.kind -ne 'tunnel') { continue }
        if ($scope -eq 'relay' -and $link.kind -eq 'tunnel') { continue }
        try { $op = Start-Ingest $link $Script:Rid $ev ''; if ($op) { $ops += $op } } catch { Write-Log 'ingest-failed' }
    }
    foreach ($op in $ops) {
        try {
            $Script:IngestCode = 0
            [void](Complete-Ingest $op $ev)
            if ($Script:IngestCode -eq 200 -and $mark) { [IO.File]::WriteAllText((Join-Path $RunDir $mark), $markText + "`n", $Utf8) }
        } catch { Write-Log 'ingest-failed' }
    }
}

# --- terminal sequence (Claude Code only, SimpleTerm sessions only) -------

# $Script:UsageSeq is the JSON-escaped usage OSC to append, if any;
# $Script:BgSeq the hook's OSC 7501 record for background work.
function Write-State([string]$state, [string]$message) {
    if ($Agent -ne 'claude' -or $env:SIMPLETERM -ne '1') { return }
    $m = ''
    if ($message) { $m = ' ' + (Limit-JsonText $message 80 320) }
    Write-Out ('{"terminalSequence":"\u001b]9;simpleterm:state=' + $state + $m + '\u0007' + $Script:BgSeq + $Script:UsageSeq + '"}')
}

function Write-UsageOnly {
    if ($Agent -ne 'claude' -or $env:SIMPLETERM -ne '1' -or -not $Script:UsageSeq) { return }
    Write-Out ('{"terminalSequence":"' + $Script:UsageSeq + '"}')
}

function Get-StateJson([string]$state) {
    if ($Agent -ne 'claude' -or $env:SIMPLETERM -ne '1') { return '' }
    return (',"terminalSequence":"\u001b]9;simpleterm:state=' + $state + '\u0007"')
}

# --- permission flow -------------------------------------------------------

# The agent's PID: the nearest ancestor that is not a shell (Codex runs hooks
# under cmd.exe). 0 if it cannot be found.
function Get-ParentPid([int]$id) {
    $p = Get-Process -Id $id -ErrorAction Stop
    if ($p.PSObject.Properties['Parent'] -and $null -ne $p.Parent) { return [int]$p.Parent.Id }
    $w = Get-CimInstance Win32_Process -Filter ('ProcessId=' + $id) -ErrorAction Stop
    return [int]$w.ParentProcessId
}

function Get-AgentPid {
    try {
        $cur = $PID
        for ($n = 0; $n -lt 4; $n++) {
            $parent = Get-ParentPid $cur
            if ($parent -le 1) { return 0 }
            $name = (Get-Process -Id $parent -ErrorAction Stop).ProcessName
            if ($name -notmatch '^(cmd|powershell|pwsh|sh|bash|dash|zsh|conhost)$') { return $parent }
            $cur = $parent
        }
    } catch { }
    return 0
}

# Notes already in the file when the wait began ($script:ResBase lines) do not
# count: the prompt that started this turn, or an earlier identical tool call,
# can carry the same second as the request.
function Get-ResLineCount {
    $path = Join-Path $RunDir ($Sid + '.res')
    if (-not [IO.File]::Exists($path)) { return 0 }
    return [IO.File]::ReadAllLines($path, $Utf8).Count
}

function Test-AnsweredLocally([int64]$since, [string]$fp) {
    $path = Join-Path $RunDir ($Sid + '.res')
    if (-not [IO.File]::Exists($path)) { return $false }
    $lines = [IO.File]::ReadAllLines($path, $Utf8)
    $first = 0
    if ($lines.Count -ge $script:ResBase) { $first = $script:ResBase }
    for ($i = $first; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        $parts = $line.Split(' ')
        if ($parts.Count -lt 3 -or -not (Test-UInt $parts[0])) { continue }
        if ([int64]$parts[0] -lt $since) { continue }
        if ($parts[1] -eq 'turn') { return $true }
        if ($parts[1] -eq 'tool' -and $parts[2] -eq $fp) { return $true }
    }
    return $false
}

function Invoke-PermissionFlow {
    if ($Agent -eq 'codex') { $cap = Get-ConfInt 'codex_wait' 60 } else { $cap = Get-ConfInt 'claude_wait' 540 }
    if ($cap -gt 540) { $cap = 540 }
    $pollWait = Get-ConfInt 'poll_wait' 25
    if ($pollWait -lt 1 -or $pollWait -gt 25) { $pollWait = 25 }
    $start = Now-Epoch
    $script:ResBase = Get-ResLineCount
    $deadline = $start + $cap
    $agentPid = Get-AgentPid
    $decision = ''
    try {
        $ingests = @()
        foreach ($file in $LinkFiles) {
            $link = Read-Link $file
            if ($null -eq $link) { continue }
            $nonce = New-RandomHex 16
            if ($env:SIMPLETERM_HOOK_TEST -eq '1' -and $env:SIMPLETERM_HOOK_TEST_NONCE) { $nonce = $env:SIMPLETERM_HOOK_TEST_NONCE }
            if (-not (Test-Hex $nonce 32)) { continue }
            try {
                $op = Start-Ingest $link $Rid 'permission' $nonce
                if ($op) { $ingests += @{ op = $op; nonce = $nonce; link = $link } }
            } catch { Write-Log ('ingest-failed link=' + (Short $link.link)) }
        }
        # Wait only where a device was actually notified.
        $polls = @()
        foreach ($it in $ingests) {
            $push = Complete-Ingest $it.op 'permission'
            if ($push -eq 'sent') { $polls += @{ link = $it.link; nonce = $it.nonce; op = $null; done = $false } }
        }
        if ($polls.Count -eq 0) { return }
        $answered = $false
        while ($true) {
            $now = Now-Epoch
            $active = 0
            foreach ($p in $polls) {
                if ($p.done) { continue }
                if ($null -eq $p.op) {
                    if ($now -ge $deadline) { $p.done = $true; continue }
                    $w = [Math]::Min($pollWait, $deadline - $now)
                    if ($w -lt 1) { $w = 1 }
                    $p.op = Start-Relay $p.link 'GET' ('/v1/decision?rid=' + $Rid + '&wait=' + $w) '' ($w + 10)
                    $p.started = $now
                }
                $active++
                if (-not (Test-RelayDone $p.op)) { continue }
                $r = Complete-Relay $p.op
                $p.op = $null
                if ($r.code -eq 200) {
                    $f = Get-JsonFields $r.body @('status', 'decision', 'dmac')
                    if ((Get-Field $f 'status') -eq 'decided') {
                        $d = Get-Field $f 'decision'
                        $dmac = Get-Field $f 'dmac'
                        $result = 'invalid'
                        if (($d -ceq 'allow' -or $d -ceq 'deny') -and (Test-Hex $dmac 64)) {
                            $expect = Get-HmacHex $p.link.mac ('st1-dec.' + $Rid + '.' + $d + '.' + $p.nonce)
                            if (Test-SameHex $expect $dmac) { $result = $d }
                        }
                        Write-Log ('decision link=' + (Short $p.link.link) + ' result=' + $result)
                        $p.done = $true
                        if ($result -ne 'invalid') { $decision = $result; break }
                    } elseif ((Now-Epoch) -eq $p.started) {
                        Start-Sleep -Seconds 1
                    }
                } elseif ($r.code -eq 404 -or $r.code -eq 410 -or $r.code -eq 401 -or $r.code -eq 403) {
                    Write-Log ('decision link=' + (Short $p.link.link) + ' http=' + $r.code)
                    if ($r.code -eq 410 -and (Get-Field (Get-JsonFields $r.body @('error')) 'error') -eq 'revoked') {
                        try { [IO.File]::WriteAllText((Join-Path $RunDir ($p.link.link + '.revoked')), '', $Utf8) } catch { }
                    }
                    $p.done = $true
                } elseif ($r.code -eq 0 -and $p.link.kind -eq 'tunnel') {
                    # The app's connection ended: nothing will answer there.
                    Write-Log ('decision link=' + (Short $p.link.link) + ' tunnel-gone')
                    $p.done = $true
                } else {
                    Start-Sleep -Seconds 2
                }
            }
            if ($decision) { break }
            if ($active -eq 0) { break }
            if (Test-AnsweredLocally $start $Fp) { $answered = $true; Write-Log 'permission answered-at-terminal'; break }
            if ($agentPid -gt 0 -and $null -eq (Get-Process -Id $agentPid -ErrorAction SilentlyContinue)) {
                $answered = $true; Write-Log 'permission agent-gone'; break
            }
            if ((Now-Epoch) -ge $deadline) { break }
            Start-Sleep -Milliseconds 500
        }
        foreach ($p in $polls) { if ($null -ne $p.op) { try { $p.op.req.Abort() } catch { } } }
        if (-not $decision -and -not $answered) {
            if ((Now-Epoch) -ge $deadline) { Write-Log 'permission timeout' } else { Write-Log 'permission no-decision' }
        }
    } finally {
    }
    if ($decision -eq 'allow') {
        Write-Out ('{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"allow"}}' + (Get-StateJson 'running') + '}')
        Write-Log 'permission allow'
    } elseif ($decision -eq 'deny') {
        Write-Out ('{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"deny","message":"Denied from SimpleTerm"}}' + (Get-StateJson 'running') + '}')
        Write-Log 'permission deny'
    }
}

# --- usage (#342) ------------------------------------------------------------

function Format-Num($v) {
    if ($v -is [double] -or $v -is [decimal] -or $v -is [single]) { return $v.ToString('0.##########', $Inv) }
    return [string]$v
}

function Test-Num($v) { return ($null -ne $v -and (Format-Num $v) -match '^[0-9]{1,15}$') }
function Test-Dec($v) { return ($null -ne $v -and (Format-Num $v) -match '^[0-9]{1,15}(\.[0-9]+)?$') }

# The lines in the last $bytes of $path; a cut first line is blanked.
function Read-TailLines([string]$path, [int]$bytes) {
    $fs = New-Object IO.FileStream($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
    try {
        $len = $fs.Length
        $n = [int][Math]::Min([int64]$bytes, $len)
        [void]$fs.Seek($len - $n, [IO.SeekOrigin]::Begin)
        $buf = New-Object byte[] $n
        $read = 0
        while ($read -lt $n) {
            $r = $fs.Read($buf, $read, $n - $read)
            if ($r -le 0) { break }
            $read += $r
        }
    } finally { $fs.Dispose() }
    $lines = $Utf8.GetString($buf, 0, $read).Split([char]10)
    if ($len -gt $n -and $lines.Length -gt 0) { $lines[0] = '' }
    return , $lines
}

function ConvertFrom-JsonLine([string]$line) {
    try { return ($line | ConvertFrom-Json) } catch { return $null }
}

# JSON-escaped text with only \" \\ \/ escapes decoded, or '' for others.
function ConvertFrom-SimpleEscapes([string]$raw) {
    $sb = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt $raw.Length; $i++) {
        $c = $raw[$i]
        if ($c -eq '\') {
            if ($i + 1 -ge $raw.Length) { return '' }
            $e = $raw[$i + 1]
            if ($e -ne '\' -and $e -ne '/' -and $e -ne '"') { return '' }
            $c = $e
            $i++
        }
        [void]$sb.Append($c)
    }
    return $sb.ToString()
}

# A readable file named by a JSON-escaped path from the hook input, or ''.
function Get-InputFile([string]$raw) {
    if (-not $raw -or $raw -eq 'null') { return '' }
    $sb = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt $raw.Length; $i++) {
        $c = $raw[$i]
        if ($c -eq '\') {
            if ($i + 1 -ge $raw.Length) { return '' }
            $e = $raw[$i + 1]
            if ($e -ne '\' -and $e -ne '/' -and $e -ne '"') { return '' }
            $c = $e
            $i++
        }
        [void]$sb.Append($c)
    }
    $path = $sb.ToString()
    try { if ([IO.File]::Exists($path)) { return $path } } catch { }
    return ''
}

# Claude Code transcript: the newest main-thread assistant usage (input +
# cache creation + cache read) or a later compaction's postTokens. Only these
# keys are read. @{ ctx; model } or $null.
function Get-ClaudeUsage([string]$path) {
    $ctx = $null
    $model = ''
    $len = (New-Object IO.FileInfo($path)).Length
    foreach ($limit in @(262144, 2097152)) {
        $lines = Read-TailLines $path $limit
        $ctx = $null
        $model = ''
        $seen = 0
        for ($i = $lines.Length - 1; $i -ge 0 -and $seen -lt 8; $i--) {
            $line = $lines[$i]
            if (-not ($line.Contains('"compact_boundary"') -or ($line.Contains('"usage":{') -and $line.Contains('"type":"assistant"')))) { continue }
            $seen++
            $o = ConvertFrom-JsonLine $line
            if ($null -eq $o) { continue }
            if ($o.type -eq 'system') {
                if ($o.subtype -eq 'compact_boundary' -and $null -eq $ctx -and $null -ne $o.compactMetadata -and (Test-Num $o.compactMetadata.postTokens)) {
                    $ctx = [int64]$o.compactMetadata.postTokens
                }
                continue
            }
            if ($o.type -ne 'assistant' -or $o.isSidechain -eq $true -or $null -eq $o.message -or $o.message.model -eq '<synthetic>') { continue }
            if ($null -eq $ctx) {
                $u = $o.message.usage
                if ($null -eq $u -or -not (Test-Num $u.input_tokens)) { continue }
                $cc = [int64]0
                if (Test-Num $u.cache_creation_input_tokens) { $cc = [int64]$u.cache_creation_input_tokens }
                if ($cc -eq 0 -and $null -ne $u.cache_creation) {
                    if (Test-Num $u.cache_creation.ephemeral_5m_input_tokens) { $cc += [int64]$u.cache_creation.ephemeral_5m_input_tokens }
                    if (Test-Num $u.cache_creation.ephemeral_1h_input_tokens) { $cc += [int64]$u.cache_creation.ephemeral_1h_input_tokens }
                }
                $cr = [int64]0
                if (Test-Num $u.cache_read_input_tokens) { $cr = [int64]$u.cache_read_input_tokens }
                $ctx = [int64]$u.input_tokens + $cc + $cr
            }
            if ($o.message.model) { $model = [string]$o.message.model; break }
        }
        if ($null -ne $ctx -and $model) { break }
        if ($len -le $limit) { break }
    }
    if ($null -eq $ctx) { return $null }
    return @{ ctx = $ctx; model = $model }
}

# Codex rollout: the newest token_count with info and the newest with rate
# limits. A usage table (see Format-Usage) or $null.
function Get-CodexUsage([string]$path) {
    $len = (New-Object IO.FileInfo($path)).Length
    $ctx = $null; $win = $null; $rl = $null
    foreach ($limit in @(262144, 2097152)) {
        $lines = Read-TailLines $path $limit
        $ctx = $null; $win = $null; $rl = $null
        $seen = 0
        for ($i = $lines.Length - 1; $i -ge 0 -and $seen -lt 8; $i--) {
            if (-not $lines[$i].Contains('"token_count"')) { continue }
            $seen++
            $o = ConvertFrom-JsonLine $lines[$i]
            if ($null -eq $o -or $null -eq $o.payload -or $o.payload.type -ne 'token_count') { continue }
            $info = $o.payload.info
            if ($null -eq $ctx -and $null -ne $info -and $null -ne $info.last_token_usage -and (Test-Num $info.last_token_usage.total_tokens)) {
                $ctx = [int64]$info.last_token_usage.total_tokens
                if (Test-Num $info.model_context_window) { $win = [int64]$info.model_context_window }
            }
            if ($null -eq $rl -and $null -ne $o.payload.rate_limits) { $rl = $o.payload.rate_limits }
            if ($null -ne $ctx -and $null -ne $rl) { break }
        }
        if ($null -ne $ctx) { break }
        if ($len -le $limit) { break }
    }
    if ($null -eq $ctx) { return $null }
    $u = @{ ctx = $ctx; win = $win; src = 'rollout'; est = $false; base = 12000; plan = ''; reached = $false; lims = @() }
    if ($null -ne $rl) {
        $id = ([string]$rl.limit_id) -replace '[^A-Za-z0-9_.-]', ''
        if (-not $id) { $id = 'codex' }
        foreach ($k in @('primary', 'secondary')) {
            $w = $rl.$k
            if ($null -ne $w -and (Test-Dec $w.used_percent) -and (Test-Num $w.window_minutes) -and (Test-Num $w.resets_at)) {
                $u.lims += , @(($id + '.' + $k), (Format-Num $w.used_percent), (Format-Num $w.window_minutes), (Format-Num $w.resets_at))
            }
        }
        if (([string]$rl.plan_type) -match '^[A-Za-z0-9_-]+$') { $u.plan = [string]$rl.plan_type }
        if ($rl.rate_limit_reached_type) { $u.reached = $true }
    }
    return $u
}

# Context window Claude Code would use: from its environment, or a guess
# from the model name (est).
function Get-ClaudeWindow([string]$model) {
    $v = [string]$env:CLAUDE_CODE_MAX_CONTEXT_TOKENS
    if ($v -match '^[0-9]{1,18}$' -and [int64]$v -ge 1000 -and [int64]$v -le 999999999999) { return @{ win = [int64]$v; est = $false } }
    if (@('1', 'true', 'TRUE', 'True') -contains [string]$env:CLAUDE_CODE_DISABLE_1M_CONTEXT) { return @{ win = 200000; est = $false } }
    $m = $model.ToLowerInvariant()
    $big = ($m -match 'claude-fable-') -or ($m -match 'claude-sonnet-([5-9]|[1-9][0-9])') -or
        ($m -match 'claude-opus-(4-[7-9]|[5-9]|[1-9][0-9])') -or ($m -match 'claude-haiku-(5-[5-9]|[6-9]|[1-9][0-9])')
    if ($big) { return @{ win = 1000000; est = $true } }
    return @{ win = 200000; est = $true }
}

function Get-UsageNow {
    $tpath = Get-InputFile (Get-Field $f 'transcript_path')
    if ($Agent -eq 'codex') {
        if (-not $tpath) { return $null }
        return (Get-CodexUsage $tpath)
    }
    if ($Agent -ne 'claude') { return $null }
    $ctx = $null; $src = 'transcript'
    $model = (Get-Field $f 'to_model')
    if (-not $model) { $model = Get-Field $f 'model' }
    $tok = Get-Field $f 'context_tokens'
    if ((Test-UInt $tok) -and [int64]$tok -gt 0) {
        $ctx = [int64]$tok; $src = 'hook'
    } elseif ($tpath) {
        $c = Get-ClaudeUsage $tpath
        if ($null -ne $c) { $ctx = $c.ctx; if (-not $model) { $model = $c.model } }
    }
    if ($null -eq $ctx) { return $null }
    $model = $model -replace '[^A-Za-z0-9._:@/\[\]-]', ''
    $w = Get-ClaudeWindow $model
    $u = @{ ctx = $ctx; win = $w.win; src = $src; est = $w.est; base = $null; plan = ''; reached = $false; lims = @() }
    if ($HookEvent -eq 'StopFailure' -and (Get-Field $f 'error') -eq 'rate_limit') { $u.reached = $true }
    # The session's window as last known, "<window|-> <est 0|1> <since>" (as in
    # agent-hook.sh): transcripts drop the [1m] of a 1M session. SessionStart
    # and PostModelSwitch name the model in use and start it over.
    $winPath = Join-Path $RunDir ($Sid + '.win')
    $mw = ''; $me = $true; $ms = [int64]0
    try {
        if ([IO.File]::Exists($winPath)) {
            $parts = @(([IO.File]::ReadAllText($winPath, $Utf8).Trim()) -split ' ')
            if ($parts.Count -ge 3) {
                if (Test-UInt $parts[0]) { $mw = $parts[0] }
                $me = ($parts[1] -ne '0')
                if (Test-UInt $parts[2]) { $ms = [int64]$parts[2] }
            }
        }
    } catch { }
    if ($HookEvent -eq 'SessionStart' -or $HookEvent -eq 'PostModelSwitch') { $mw = ''; $me = $true; $ms = Now-Epoch }
    # Optional status line tap (scripts/statusline-tap.sh): exact window, limits.
    $sl = Join-Path $RunDir ('usage.' + $Sid + '.json')
    try {
        if ([IO.File]::Exists($sl) -and (New-Object IO.FileInfo($sl)).Length -le 65536) {
            $text = [IO.File]::ReadAllText($sl, $Utf8)
            $nl = $text.IndexOf([char]10)
            $t = ''
            if ($nl -gt 0) { $t = $text.Substring(0, $nl).Trim() }
            $now = Now-Epoch
            if ((Test-UInt $t) -and ($now - [int64]$t) -le 600 -and ([int64]$t - $now) -le 60) {
                $o = ConvertFrom-JsonLine $text.Substring($nl + 1)
                if ($null -ne $o) {
                    if ($null -ne $o.context_window -and (Test-Num $o.context_window.context_window_size) -and [int64]$t -gt $ms) {
                        $u.win = [int64]$o.context_window.context_window_size; $u.est = $false
                    }
                    if ($null -ne $o.rate_limits) {
                        $period = [string]$o.rate_limits.spend_limit.period
                        $pw = 0
                        if ($period -eq 'daily') { $pw = 1440 } elseif ($period -eq 'weekly') { $pw = 10080 } elseif ($period -eq 'monthly') { $pw = 43200 }
                        foreach ($row in @(@('five_hour', 300), @('seven_day', 10080), @('spend_limit', $pw))) {
                            $lw = $o.rate_limits.($row[0])
                            if ($null -ne $lw -and (Test-Dec $lw.used_percentage) -and (Test-Num $lw.resets_at) -and [int64]$lw.resets_at -gt $now) {
                                $u.lims += , @($row[0], (Format-Num $lw.used_percentage), [string]$row[1], (Format-Num $lw.resets_at))
                            }
                        }
                    }
                }
            }
        }
    } catch { }
    if ($u.est -and $mw) { $u.win = [int64]$mw; $u.est = $me }
    # A guess below the context in use is wrong: the window is 1M.
    if ($u.est -and $u.ctx -gt $u.win) { $u.win = 1000000; $mw = '1000000' }
    $new = '- 1 ' + $ms
    if (-not $u.est) { $new = [string]$u.win + ' 0 ' + $ms } elseif ($mw) { $new = [string]$u.win + ' 1 ' + $ms }
    try {
        $old = ''
        if ([IO.File]::Exists($winPath)) { $old = [IO.File]::ReadAllText($winPath, $Utf8).Trim() }
        if ($old -ne $new) { [IO.File]::WriteAllText($winPath, $new + "`n", $Utf8) }
    } catch { }
    return $u
}

# A usage table -> @{ osc (OSC 9 body); json (plaintext fields) }.
function Format-Usage($u) {
    $osc = 'simpleterm:usage v=1 agent=' + $App + ' ctx=' + $u.ctx
    $js = ',"ctx":{"used":' + $u.ctx
    if ($null -ne $u.win) { $osc += ' win=' + $u.win; $js += ',"win":' + $u.win }
    if ($null -ne $u.base) { $js += ',"baseline":' + $u.base }
    $osc += ' src=' + $u.src
    $js += ',"src":"' + $u.src + '"'
    if ($u.est) { $osc += ' est=1'; $js += ',"est":true' }
    $js += '}'
    $la = @()
    foreach ($l in $u.lims) {
        $osc += ' lim=' + $l[0] + ':' + $l[1] + ':' + $l[2] + ':' + $l[3]
        $la += ('{"id":"' + $l[0] + '","pct":' + $l[1] + ',"win_min":' + $l[2] + ',"resets_at":' + $l[3] + '}')
    }
    if ($u.reached) { $osc += ' lim=reached'; $la += '{"id":"reached"}' }
    $js += ',"lims":[' + ($la -join ',') + ']'
    if ($u.plan) { $js += ',"plan":"' + $u.plan + '"' }
    return @{ osc = $osc; json = $js }
}

# Reports changed context/limits: the OSC for the terminal (Claude Code in
# SimpleTerm) and a `usage` event for the SSH tunnel links (the relay does
# not push them, so it gets none).
function Invoke-UsageReport {
    $Script:UsageSeq = ''
    if ((Get-ConfInt 'usage' 1) -eq 0) { return }
    $u = $null
    try { $u = Get-UsageNow } catch { Write-Log ('usage-failed ' + $_.Exception.GetType().Name) }
    if ($null -eq $u) { return }
    $fmt = Format-Usage $u
    $Script:UsageJson = $fmt.json
    $last = Join-Path $RunDir ($Sid + '.usage')
    $prev = ''
    try { if ([IO.File]::Exists($last)) { $prev = [IO.File]::ReadAllText($last, $Utf8).Trim() } } catch { }
    if ($prev -eq $fmt.osc) { return }
    # Recorded as sent only once SimpleTerm has it: on Claude Code's terminal,
    # or when a tunnel link took the event (as in agent-hook.sh).
    $Script:UsageSeq = '\u001b]9;' + $fmt.osc + '\u0007'
    if ($Agent -eq 'claude' -and $env:SIMPLETERM -eq '1') {
        try { [IO.File]::WriteAllText($last, $fmt.osc + "`n", $Utf8) } catch { }
    }
    Send-Background 'usage' (New-RandomHex 8) 'tunnel' ($Sid + '.usage') $fmt.osc
}

# --- the `simpleterm` command (Windows) ---------------------------------------

# Keeps ~/.simpleterm/bin/simpleterm.cmd pointing at the newest installed copy
# of this script, so that `simpleterm notify "title" "body"` works in cmd and
# PowerShell. Rewritten when missing, when its script is gone, when in an
# older format or when it names an older release (as in agent-hook.sh).
function Update-Cli {
    try {
        if (-not $IsWin -or -not [IO.Directory]::Exists($StDir)) { return }
        $self = $PSCommandPath
        if (-not $self -or $self.Contains('"') -or $self.Contains('%')) { return }
        $bin = Join-Path $StDir 'bin'
        $w = Join-Path $bin 'simpleterm.cmd'
        if ([IO.File]::Exists($w)) {
            $text = [IO.File]::ReadAllText($w)
            $m = [regex]::Match($text, '-File "([^"]+)"')
            $r = [regex]::Match($text, 'rev=([0-9]+)')
            $v = [regex]::Match($text, 'version=([0-9]+(\.[0-9]+){1,3})')
            if ($m.Success -and [IO.File]::Exists($m.Groups[1].Value) -and $r.Success -and [int]$r.Groups[1].Value -ge $CliRev) {
                if ($m.Groups[1].Value -eq $self) { return }
                if ($v.Success -and -not ([version]$v.Groups[1].Value -lt [version]$HookVersion)) { return }
            }
        }
        if (-not [IO.Directory]::Exists($bin)) { [void][IO.Directory]::CreateDirectory($bin) }
        $body = "@echo off`r`nrem simpleterm: written by the SimpleTerm agent hooks plugin (rev=" + $CliRev + " version=" + $HookVersion + "); edits are overwritten.`r`n" +
            'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $self + '" %*' + "`r`n"
        [IO.File]::WriteAllText($w, $body, (New-Object System.Text.ASCIIEncoding))
        Write-Log 'cli installed'
    } catch { }
}

# True for the first delivery of an event (key) within 30 seconds: Grok Build
# runs this plugin's hooks twice when Claude Code and Grok both have it.
function Test-Once([string]$key) {
    $path = Join-Path $RunDir ('dd.' + $key)
    $now = Now-Epoch
    for ($try = 0; $try -lt 2; $try++) {
        try {
            $fs = New-Object IO.FileStream($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
            $b = $Utf8.GetBytes([string]$now)
            $fs.Write($b, 0, $b.Length)
            $fs.Dispose()
            return $true
        } catch {
            $t = ''
            try { $t = [IO.File]::ReadAllText($path).Trim() } catch { }
            if (-not ((Test-UInt $t) -and ($now - [int64]$t) -gt 30)) { break }
            try { [IO.File]::Delete($path) } catch { }
        }
    }
    Write-Log ('duplicate ' + $HookEvent)
    return $false
}

# True for the first alert for this question of this session within 30
# seconds: Claude Code reports one AskUserQuestion twice (PreToolUse and
# PermissionRequest).
function Test-AskOnce([string]$question) {
    $key = 'q.' + (Get-Sha256Hex ($Sid + '|' + $question)).Substring(0, 16)
    return (Test-Once $key)
}

# --- main ------------------------------------------------------------------

function Read-Input {
    if ($Agent -eq 'codex-notify') {
        if ($ScriptArgs.Count -lt 2) { return '' }
        $last = [string]$ScriptArgs[$ScriptArgs.Count - 1]
        if ($last.Length -gt $MaxInput) { return '' }
        return $last
    }
    $stream = [Console]::OpenStandardInput()
    $buf = New-Object byte[] $MaxInput
    $total = 0
    while ($total -lt $buf.Length) {
        $n = $stream.Read($buf, $total, $buf.Length - $total)
        if ($n -le 0) { break }
        $total += $n
    }
    return $Utf8.GetString($buf, 0, $total)
}

function Add-Note([string]$kind, [string]$fp) {
    $path = Join-Path $RunDir ($Sid + '.res')
    try {
        if ($kind -eq 'turn') {
            [IO.File]::WriteAllText($path, ([string](Now-Epoch) + " turn -`n"), $Utf8)
            [IO.File]::Delete((Join-Path $RunDir ($Sid + '.goal')))
            [IO.File]::Delete((Join-Path $RunDir ($Sid + '.done')))
            $bg = Join-Path $RunDir ($Sid + '.bg')
            if ([IO.File]::Exists($bg)) {
                $lines = [IO.File]::ReadAllLines($bg, $Utf8)
                if ($lines.Count -gt 1 -and $lines[1] -eq '7501') {
                    $Script:BgSeq = '\u001b]7501;state=clear:id=' + $BgId + '\u0007'
                }
                [IO.File]::Delete($bg)
            }
        }
        else { [IO.File]::AppendAllText($path, ([string](Now-Epoch) + ' tool ' + $fp + "`n"), $Utf8) }
    } catch { }
}

# Claude Code ended a turn while work it started still runs (Stop
# `background_tasks`, Claude Code 2.1.145+: shells, subagents, monitors,
# workflows). It takes the turn up again when that work reports back, so the
# session is not done: no `done` event, a `background` state instead, and no
# idle question until the next turn note. $RunDir\$Sid.bg holds the state's
# message meanwhile, and `7501` on its second line when the hook wrote an
# OSC 7501 `working` record (as agent-hook.sh explains: Claude Code 2.1.295+
# reports `done` for its own turn through OSC 7501).
$BgId = 'simpleterm-bg'
function Test-TurnDone { return [IO.File]::Exists((Join-Path $RunDir ($Sid + '.done'))) }
function Test-BgPaused { return [IO.File]::Exists((Join-Path $RunDir ($Sid + '.bg'))) }

function Test-Claude7501 {
    if ($env:TMUX -or $env:STY) { return $false }
    if (@('', '0', 'false', 'FALSE', 'False') -notcontains [string]$env:CLAUDE_CODE_DISABLE_TERMINAL_TITLE) { return $false }
    $p = Get-InputFile (Get-Field $f 'transcript_path')
    if (-not $p) { return $false }
    $v = ''
    try {
        $fs = [IO.File]::Open($p, 'Open', 'Read', 'ReadWrite')
        try {
            $n = [Math]::Min([int64]65536, $fs.Length)
            [void]$fs.Seek(-$n, 'End')
            $buf = New-Object byte[] $n
            $read = $fs.Read($buf, 0, $n)
            $ms = [regex]::Matches($Utf8.GetString($buf, 0, $read), '"version":"([0-9][0-9.]*)"')
            if ($ms.Count -gt 0) { $v = $ms[$ms.Count - 1].Groups[1].Value }
        } finally { $fs.Dispose() }
    } catch { return $false }
    $x = $v.Split('.')
    if ($x.Count -lt 3) { return $false }
    try { $a = [int]$x[0]; $b = [int]$x[1]; $c = [int]$x[2] } catch { return $false }
    return ($a -gt 2 -or ($a -eq 2 -and ($b -gt 1 -or ($b -eq 1 -and $c -ge 295))))
}

# Codex `/goal`: while a goal is active Codex starts the next turn itself and
# each turn ends with a Stop. The rollout records `thread_goal_updated` with
# the goal's status; the model ends a goal with an `update_goal` call.
function Test-CodexGoalActive {
    $p = Get-InputFile (Get-Field $f 'transcript_path')
    if (-not $p) { return $false }
    $active = $false
    $called = $false
    try {
        foreach ($line in [IO.File]::ReadLines($p)) {
            if ($line.Contains('"type":"thread_goal_updated"')) { $active = $line.Contains('"status":"active"'); $called = $false }
            elseif ($line.Contains('"name":"update_goal"')) { $called = $true }
        }
    } catch { return $false }
    return ($active -and -not $called)
}

# The first counted task (or, with only scheduled wake-ups, the first
# schedule) as a short line for the badge and the pause note.
function Get-BgSummary {
    if ($BgN -gt 0) {
        $m = $BgDesc
        if (-not $m) { $m = 'task' }
        if ($BgType) { $m = $BgType + ': ' + $m }
        if ($BgN -ge 10) { $m += ' (+9 or more)' }
        elseif ($BgN -gt 1) { $m += ' (+' + ($BgN - 1) + ' more)' }
    } else {
        $sch = $CronSched
        if (-not $sch) { $sch = 'wake-up' }
        $m = 'scheduled: ' + $sch
        if ($CronN -gt 1) { $m += ' (+' + ($CronN - 1) + ' more)' }
    }
    return (Limit-JsonText $m 80 320)
}

# The last message and what still runs, as the text of a done: the suffix is
# kept whole and the message gives way (200 characters, 800 bytes in all).
function Get-DoneMsg([string]$what) {
    $sfx = Limit-JsonText ('(still running in the background: ' + $what + ')') 120 480
    $room = 200 - $sfx.Length - 1
    if ($Last -and $room -gt 20) {
        return ((Limit-JsonText $Last $room (800 - $sfx.Length - 1)) + ' ' + $sfx)
    }
    return $sfx
}

# The turn ended and the agent waits for background work or a schedule. Not
# done: the badge says background (note in $Sid.bg), unless the last message
# asks the user something ($ask): then the user is told, as question, the
# badge says waiting, and Claude Code 2.1.295+ gets a blocked OSC 7501 record
# (kind question) instead of the working one.
function Invoke-BgPause([bool]$ask) {
    $m = Get-BgSummary
    $flag = ''
    if ($Agent -eq 'claude' -and $env:SIMPLETERM -eq '1' -and (Test-Claude7501)) {
        $flag = '7501'
        $e = ''
        if ($ask) { $t = ConvertFrom-SimpleEscapes (Limit-JsonText $Last 200 800) }
        else { $t = ConvertFrom-SimpleEscapes $m }
        if ($t) { $e = [Convert]::ToBase64String($Utf8.GetBytes($t)) }
        if ($ask) { $Script:BgSeq = '\u001b]7501;state=blocked:id=' + $BgId + ':kind=question' }
        else { $Script:BgSeq = '\u001b]7501;state=working:id=' + $BgId }
        if ($e) { $Script:BgSeq += ':msg=' + $e }
        $Script:BgSeq += '\u0007'
    }
    $bgFile = Join-Path $RunDir ($Sid + '.bg')
    # Line 1: the badge's message (the question when asking), 2: the OSC 7501
    # flag, 3: the pause's token, 4: `ask` while the badge says waiting.
    $bm = $m
    $askMark = ''
    if ($ask) { $bm = Limit-JsonText $Last 80 320; $askMark = 'ask' }
    try { [IO.File]::WriteAllText($bgFile, $bm + "`n" + $flag + "`n" + $Rid + "`n" + $askMark + "`n", $Utf8) } catch { }
    if ($ask) {
        $Script:Msg = Limit-JsonText $Last 200 800
        Send-Background 'question'
        Write-State 'waiting' $Last
        return
    }
    Write-State 'background' $m
    # Only work that may run for good is left (a dev server): after
    # bg_done_after seconds (default 600) of the same pause, done once.
    $wait = Get-ConfInt 'bg_done_after' 600
    if ($BgN -gt 0 -and $BgFinite -eq 0 -and $wait -gt 0 -and $LinkFiles.Count -gt 0) {
        $Script:Msg = Get-DoneMsg $m
        Start-LaterSend 'bg' $wait $bgFile 2 $Rid '' 0
    }
}

# Sends done (text Msg) done_delay seconds from now (default 3; 0: at once)
# unless something of the session happens first: another Stop hook may have
# kept the agent going, and then its next event (or Stop) comes within
# moments. The event is made then (fresh rid and time). Only where the agent
# has such an event to send (Claude Code, Grok Build): Codex registers none
# that would come within moments, so its default is 0.
function Send-DoneLater {
    if ($LinkFiles.Count -eq 0) { return }
    $dw = 3
    if ($Agent -eq 'codex') { $dw = 0 }
    $dw = Get-ConfInt 'done_delay' $dw
    if ($dw -le 0) { Send-Background 'done'; return }
    $pendFile = Join-Path $RunDir ($Sid + '.pend')
    try { [IO.File]::WriteAllText($pendFile, $Rid + "`n", $Utf8) } catch { Send-Background 'done'; return }
    Start-LaterSend 'pend' $dw $pendFile 0 $Rid '' 0
}

# --- who started a turn, and what ran before it -----------------------------

# Prompt ids of the turns Grok Build starts itself (static, from the 1.0.70
# binary); a person's prompt id is a UUID.
$GrokAutoPrefixes = @('task-completed-', 'bash-completed-', 'monitor-completed-', 'subagent-completed-',
    'workflow-completed-', 'parent-agent-message-', 'parent-message-', 'notifications-', 'goal-summary-',
    'goal-classifier-nudge-', 'plan-resume-', 'scheduler-fired-')

# Checksum of the start of a prompt, to compare a scheduled prompt (Stop
# session_crons) with the prompt a later UserPromptSubmit carries.
function Get-PromptSum([string]$text) {
    return (Get-Sha256Hex (Limit-JsonText $text 200 800)).Substring(0, 16)
}

# True if a person typed the prompt (or we cannot tell), false if the agent
# started the turn itself: background work reporting back, a scheduled
# wake-up. Claude Code names it in UserPromptSubmit source where it sends one
# (2.1.316 sends none): then a task-notification or agent-message prompt, the
# /loop sentinel, or the prompt of a wake-up listed at the last Stop says so.
function Get-PromptUser {
    if ($Agent -eq 'grok') {
        $promptIdText = Get-Field $f 'promptId'
        foreach ($pre in $GrokAutoPrefixes) {
            if ($promptIdText.StartsWith($pre, [StringComparison]::Ordinal)) { return $false }
        }
        return $true
    }
    $src = Get-Field $f 'source'
    if ($src -eq 'user' -or $src -eq 'sdk') { return $true }
    if ($src) { return $false }
    $pr = Get-Field $f 'prompt'
    if (-not $pr) { return $true }
    foreach ($pre in @('<task-notification>', '<agent-message ', '<<autonomous-loop')) {
        if ($pr.StartsWith($pre, [StringComparison]::Ordinal)) { return $false }
    }
    $cronFile = Join-Path $RunDir ($Sid + '.crons')
    try {
        if ([IO.File]::Exists($cronFile)) {
            $sums = ([IO.File]::ReadAllText($cronFile, $Utf8)).Trim() -split ' +'
            if ($sums -contains (Get-PromptSum $pr)) { return $false }
        }
    } catch { }
    return $true
}

# Sid.turn: line 1 user or auto (who started this turn), line 2 the ids of the
# background tasks that already ran when it started (Sid.stopids, the last
# Stop list), for the Stop that ends it.
function Write-TurnMark([bool]$user) {
    $ids = ''
    try {
        $idsFile = Join-Path $RunDir ($Sid + '.stopids')
        if ([IO.File]::Exists($idsFile)) { $ids = ([IO.File]::ReadAllText($idsFile, $Utf8) -split "`n")[0] }
        $who = 'auto'
        if ($user) { $who = 'user' }
        [IO.File]::WriteAllText((Join-Path $RunDir ($Sid + '.turn')), ($who + "`n" + $ids + "`n"), $Utf8)
    } catch { }
}

# --- reading the last message of a turn -------------------------------------

# Does the last message ask the user something? Only the end counts: its last
# two sentences, fenced code blocks left out. A sentence asks when it ends
# with ? or a full-width question mark, ends with a Korean request or question
# ending, or contains an English ask. A reading of text, not a protocol: a
# wrong guess costs one extra alert. The tables are the same as ASK_AWK in
# agent-hook.sh (Korean as \u escapes: this file stays ASCII).
$AskKo = @([regex]::Unescape('\uAE4C\uC694'), [regex]::Unescape('\uB2C8\uAE4C'), [regex]::Unescape('\uD558\uC2DC\uACA0\uC5B4\uC694'),
    [regex]::Unescape('\uC8FC\uC138\uC694'), [regex]::Unescape('\uC8FC\uC2DC\uACA0\uC5B4\uC694'), [regex]::Unescape('\uC8FC\uC2E4\uB798\uC694'),
    [regex]::Unescape('\uB098\uC694'), [regex]::Unescape('\uC778\uAC00\uC694'), [regex]::Unescape('\uBC14\uB78D\uB2C8\uB2E4'),
    [regex]::Unescape('\uD560\uB798\uC694'), [regex]::Unescape('\uBD80\uD0C1\uB4DC\uB9BD\uB2C8\uB2E4'))
# Endings that can be a plain request or a wait / FYI note (juseyo, baramnida,
# butakdeurimnida), and the polite forms before them (juusigi, hasigi, sigi).
$AskReq = @([regex]::Unescape('\uC8FC\uC138\uC694'), [regex]::Unescape('\uBC14\uB78D\uB2C8\uB2E4'),
    [regex]::Unescape('\uBD80\uD0C1\uB4DC\uB9BD\uB2C8\uB2E4'))
$AskHon = @([regex]::Unescape('\uC8FC\uC2DC\uAE30'), [regex]::Unescape('\uD558\uC2DC\uAE30'), [regex]::Unescape('\uC2DC\uAE30'))
# Words just before a request ending that make it no ask ("wait a moment",
# "for your reference", "bear with us"): kidari, chamgo, chamjo, yanghae,
# ihae, gamangan, yuui: the last word before the ending starts with one.
$AskFyi = @([regex]::Unescape('\uAE30\uB2E4'), [regex]::Unescape('\uCC38\uACE0'), [regex]::Unescape('\uCC38\uC870'),
    [regex]::Unescape('\uC591\uD574'), [regex]::Unescape('\uC774\uD574'), [regex]::Unescape('\uAC10\uC548'),
    [regex]::Unescape('\uC720\uC758'))
$AskEn = @('should i', 'shall i', 'would you like', 'do you want', 'let me know which', 'let me know whether', 'want me to', 'please confirm',
    'please choose', 'please select', 'please tell me')
$AskFwQ = [string][char]0xFF1F
$AskTermChars = @($AskFwQ, [string][char]0xFF01, [string][char]0x3002)
$AskCloseChars = @([string][char]0x300D, [string][char]0x300F, [string][char]0x201D, [string][char]0x2019, [string][char]0xFF09)

function ConvertFrom-JsonEscapes([string]$raw) {
    $sb = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt $raw.Length; $i++) {
        $c = $raw[$i]
        if ($c -ne '\') { [void]$sb.Append($c); continue }
        if ($i + 1 -ge $raw.Length) { break }
        $e = $raw[$i + 1]
        $i++
        if ($e -eq 'n' -or $e -eq 'r') { [void]$sb.Append("`n") }
        elseif ($e -eq 't') { [void]$sb.Append(' ') }
        elseif ($e -eq 'u') {
            $hex = ''
            if ($i + 4 -lt $raw.Length) { $hex = $raw.Substring($i + 1, 4) }
            if (Test-Hex4 $hex) { [void]$sb.Append([char][Convert]::ToInt32($hex, 16)); $i += 4 }
            else { [void]$sb.Append(' ') }
        }
        else { [void]$sb.Append($e) }
    }
    return $sb.ToString()
}

$AskCoreChars = " `t`n*_``" + '"' + "'" + ')]}>.,;:!?'

function Get-AskCore([string]$text) {
    $again = $true
    while ($again -and $text.Length -gt 0) {
        $again = $false
        $endCh = $text.Substring($text.Length - 1)
        if ($AskCoreChars.IndexOf($endCh, [StringComparison]::Ordinal) -ge 0) {
            $text = $text.Substring(0, $text.Length - 1)
            $again = $true
            continue
        }
        foreach ($cl in ($AskCloseChars + $AskTermChars)) {
            if ($text.EndsWith($cl, [StringComparison]::Ordinal)) {
                $text = $text.Substring(0, $text.Length - $cl.Length)
                $again = $true
                break
            }
        }
    }
    return $text
}

function Test-AskText([string]$raw) {
    if (-not $raw) { return $false }
    $s = $raw
    $fence = $false
    if ($s.Length -gt 2000) {
        $head = $s.Substring(0, $s.Length - 2000)
        $s = $s.Substring($s.Length - 2000)
        $p = $s.IndexOf('\n', [StringComparison]::Ordinal)
        if ($p -ge 0) { $head += $s.Substring(0, $p + 2); $s = $s.Substring($p + 2) }
        $fence = (([regex]::Matches($head, '```')).Count % 2) -eq 1
    }
    $lines = (ConvertFrom-JsonEscapes $s) -split "`n"
    $kept = New-Object System.Text.StringBuilder
    foreach ($ln in $lines) {
        if ($ln.TrimStart().StartsWith('```', [StringComparison]::Ordinal)) { $fence = -not $fence; continue }
        if (-not $fence) { [void]$kept.Append($ln + "`n") }
    }
    $txt = $kept.ToString()
    $sent = New-Object System.Collections.ArrayList
    $cur = New-Object System.Text.StringBuilder
    $code = $false
    $line = ''
    for ($i = 0; $i -lt $txt.Length; $i++) {
        $c = [string]$txt[$i]
        [void]$cur.Append($c)
        $line += $c
        $term = ''
        $nx = ''
        if ($i + 1 -lt $txt.Length) { $nx = [string]$txt[$i + 1] }
        $nx2 = ''
        if ($i + 2 -lt $txt.Length) { $nx2 = [string]$txt[$i + 2] }
        if ($c -eq "`n") { $term = 'nl'; $line = ''; $code = $false }
        elseif ($c -eq '`') { $code = -not $code }
        # No sentence ends inside inline code or in a table row; a?.b is not one either.
        elseif (($c -eq '?' -or $c -eq '!') -and -not $code -and $line -notmatch '^[ \t]*\|') {
            if ($nx -notmatch '[A-Za-z0-9]' -and -not ($c -eq '?' -and $nx -eq '.' -and $nx2 -match '[A-Za-z0-9_$]')) { $term = $c }
        }
        elseif ($c -eq '.' -and -not $code) { if ($nx -eq '' -or $nx -eq ' ' -or $nx -eq "`n") { $term = $c } }
        elseif ($AskTermChars -contains $c) { $term = $c }
        if ($term) {
            $x = $cur.ToString().Trim()
            $cur.Length = 0
            if ($x -match '[A-Za-z0-9]' -or $x -match '[^\u0000-\u007F]') {
                if ($x -notmatch '^[0-9]+[.)]?$') {
                    $tt = $term
                    if ($term -eq 'nl') { $tt = '' }
                    [void]$sent.Add(@($x, $tt))
                }
            }
        }
    }
    $x = $cur.ToString().Trim()
    if (($x -match '[A-Za-z0-9]' -or $x -match '[^\u0000-\u007F]') -and $x -notmatch '^[0-9]+[.)]?$') { [void]$sent.Add(@($x, '')) }
    for ($k = $sent.Count - 1; $k -ge 0 -and $k -ge $sent.Count - 2; $k--) {
        if ($sent[$k][1] -eq '?' -or $sent[$k][1] -eq $AskFwQ) { return $true }
        $core = Get-AskCore $sent[$k][0]
        for ($j = 0; $j -lt $AskKo.Count; $j++) {
            $ko = $AskKo[$j]
            if (-not $core.EndsWith($ko, [StringComparison]::Ordinal)) { continue }
            # A request ending after a wait / FYI word is no ask; "check it, then
            # decide for me" keeps asking (its last word is the thing asked).
            if ($AskReq -contains $ko) {
                $tail = $core.Substring(0, $core.Length - $ko.Length).TrimEnd(' ')
                foreach ($h in $AskHon) {
                    if ($tail.EndsWith($h, [StringComparison]::Ordinal)) { $tail = $tail.Substring(0, $tail.Length - $h.Length).TrimEnd(' '); break }
                }
                $lastWord = $tail
                $sp = $tail.LastIndexOf(' ')
                if ($sp -ge 0) { $lastWord = $tail.Substring($sp + 1) }
                $fyi = $false
                foreach ($w in $AskFyi) { if ($lastWord.StartsWith($w, [StringComparison]::Ordinal)) { $fyi = $true } }
                if ($fyi) { continue }
            }
            return $true
        }
        $low = ' ' + $core.ToLowerInvariant() + ' '
        foreach ($en in $AskEn) {
            $p = $low.IndexOf(' ' + $en + ' ', [StringComparison]::Ordinal)
            if ($p -lt 0) { continue }
            if ($p -ge 6 -and $low.Substring($p - 6, 6) -eq 'if you') { continue }
            return $true
        }
    }
    return $false
}

# --- services ------------------------------------------------------------------

# A shell task whose command is a service (a dev server, a watcher, a
# follower) is not something the agent waits for: it never ends and never
# wakes the agent. A wrong "service" ends the turn early and sends a second
# done later; a missed one only delays the done to bg_done_after: so when in
# doubt it is not one, and only what is known is matched, at the command
# position (the same table as SVC_AWK in agent-hook.sh; read its comment). The
# command is unescaped, backslash-newline joined, heredoc bodies dropped and
# the inside of quotes emptied, then cut at ; && || & and line breaks into list
# elements: only the last one counts, and any command of its pipeline may be
# the service.
$SvcValueFlags = ' --filter -F -C --cwd --prefix --dir -p --project --workspace -w --app --namespace -n --context --kubeconfig -f --file --env-file --project-name --profile --port --host --config -c --mode -m --base --logLevel -l --outDir '
$SvcBoolFlags = ' -r --recursive -s --silent -q --quiet --if-present --workspaces -ws --include-workspace-root --stream --parallel --no-bail --open --force --strictPort --debug --verbose -v --no-color --offline --prefer-offline --ignore-scripts -A '
$SvcDoneWords = ' setup migrate migration db seed build init prepare install reset clean test lint check generate gen codegen deploy publish release typecheck format once '
$SvcUnk = 1000000
$SvcWords = @()
$SvcN = 0

function Get-SvcBase([string]$w) { return ([regex]::Replace($w, '^.*/', '')).ToLowerInvariant() }

function Get-SvcWord([int]$j) {
    if ($j -ge 0 -and $j -lt $Script:SvcN) { return [string]$Script:SvcWords[$j] }
    return ''
}

# The index of the first word from j on that is not an option (or an option value); N at
# the end or a lone --, $SvcUnk when an option is not known. A value flag takes the next
# word only when that is no option.
function Skip-SvcOpts([int]$j) {
    while ($j -lt $Script:SvcN -and (Get-SvcWord $j).StartsWith('-')) {
        $x = Get-SvcWord $j
        if ($x -ceq '--') { return $Script:SvcN }
        if ($x.IndexOf('=') -ge 0 -or $SvcBoolFlags.Contains(' ' + $x + ' ')) { $j++ }
        elseif ($SvcValueFlags.Contains(' ' + $x + ' ')) {
            if (($j + 1) -lt $Script:SvcN -and -not (Get-SvcWord ($j + 1)).StartsWith('-')) { $j += 2 } else { $j++ }
        }
        else { return $SvcUnk }
    }
    return $j
}

# Does an option word matching the (case-sensitive) regex come from j on, before a lone --?
function Test-SvcAnyOpt([int]$j, [string]$re) {
    for ($k = $j; $k -lt $Script:SvcN; $k++) {
        $x = Get-SvcWord $k
        if ($x -ceq '--') { return $false }
        if ($x -cmatch $re) { return $true }
    }
    return $false
}

# Leading options only (tools that run a script: the script ends them); `run` may come between when allowed.
function Test-SvcLeadOpt([int]$j, [string]$re, [bool]$allowRun) {
    while ($j -lt $Script:SvcN) {
        $x = Get-SvcWord $j
        if ($x -ceq '--') { return $false }
        if ($allowRun -and $x -ceq 'run') { $j++; continue }
        if (-not $x.StartsWith('-')) { return $false }
        if ($x -cmatch $re) { return $true }
        if ($x.IndexOf('=') -lt 0 -and $SvcValueFlags.Contains(' ' + $x + ' ') -and ($j + 1) -lt $Script:SvcN -and -not (Get-SvcWord ($j + 1)).StartsWith('-')) { $j += 2 } else { $j++ }
    }
    return $false
}

# A script name `dev:setup` is a job, not a server, when a part of its suffix is a finite task.
function Test-SvcJobName([string]$t) {
    $p = $t.IndexOf(':')
    if ($p -lt 0) { return $false }
    foreach ($part in [regex]::Split($t.Substring($p + 1), '[:_-]')) {
        if ($SvcDoneWords.Contains(' ' + $part + ' ')) { return $true }
    }
    return $false
}

function Test-ServiceSegment([string]$seg) {
    $seg = [regex]::Replace($seg, '[()\t]', ' ')
    $Script:SvcWords = @($seg -split ' +' | Where-Object { $_ -ne '' })
    $Script:SvcN = $Script:SvcWords.Count
    $n = $Script:SvcN
    $i = 0
    while ($i -lt $n) {
        $w = Get-SvcWord $i
        if ($w -cmatch '^[A-Za-z_][A-Za-z0-9_]*=') { $i++; continue }
        $lw = Get-SvcBase $w
        if ($lw -cmatch '^(do|then|else|elif|if|while|until|time|nohup|exec|bunx|!|[{}])$') { $i++; continue }
        if ($lw -ceq 'npx') {
            $i++
            while ($i -lt $n -and (Get-SvcWord $i).StartsWith('-')) {
                if ((Get-SvcWord $i) -cmatch '^(-y|--yes|--no-install|--no|-q|--quiet)$') { $i++ } else { return $false }
            }
            continue
        }
        if ($lw -ceq 'env' -or $lw -ceq 'sudo') { $i++; if ((Get-SvcWord $i).StartsWith('-')) { return $false }; continue }
        $nx = Get-SvcWord ($i + 1)
        if (($lw -ceq 'pnpm' -and ($nx -ceq 'exec' -or $nx -ceq 'dlx')) -or ($lw -ceq 'yarn' -and $nx -ceq 'dlx') -or
            (($lw -ceq 'uv' -or $lw -ceq 'poetry') -and $nx -ceq 'run') -or ($lw -ceq 'bundle' -and $nx -ceq 'exec')) {
            $i += 2
            if ((Get-SvcWord $i).StartsWith('-')) { return $false }
            continue
        }
        break
    }
    if ($i -ge $n) { return $false }
    $c = Get-SvcBase (Get-SvcWord $i)
    $j = $i + 1
    if ($c -cmatch '^(npm|pnpm|yarn|bun)$') {
        if ($c -ceq 'bun' -and (Test-SvcLeadOpt $j '^--(watch|hot)$' $true)) { return $true }
        $j = Skip-SvcOpts $j
        if ($c -ceq 'yarn' -and (Get-SvcWord $j) -ceq 'workspace') { $j = Skip-SvcOpts ($j + 2) }
        if ((Get-SvcWord $j) -ceq 'run' -or (Get-SvcWord $j) -ceq 'run-script') { $j = Skip-SvcOpts ($j + 1) }
        $t = (Get-SvcWord $j).ToLowerInvariant()
        return ($j -lt $n -and $t -cmatch '^(dev|start|serve|preview|watch)(:[a-z0-9_-]+)?$' -and -not (Test-SvcJobName $t))
    }
    if ($c -ceq 'next') { return ((Get-SvcWord (Skip-SvcOpts $j)) -cmatch '^(dev|start)$') }
    if ($c -ceq 'vite') {
        if (Test-SvcAnyOpt $j '^(-v|-h|--version|--help)$') { return $false }
        $j = Skip-SvcOpts $j
        if ($j -ge $SvcUnk) { return $false }
        $x = Get-SvcWord $j
        return ($j -ge $n -or $x -cmatch '^(dev|serve|preview)$' -or $x -cmatch '^[0-9]*[<>]' -or $x.Contains('/') -or $x.Contains('.'))
    }
    if ($c -ceq 'vitest') {
        return ((Test-SvcAnyOpt $j '^(-w|--watch|--watch=true|--watch=1)$') -or (Get-SvcWord (Skip-SvcOpts $j)) -cmatch '^(dev|watch)$')
    }
    if ($c -ceq 'watch') { return (-not (Test-SvcAnyOpt $j '^(-[a-zA-Z]*[ge][a-zA-Z]*|--chgexit|--errexit)$')) }
    if ($c -ceq 'gunicorn') { return (-not (Test-SvcAnyOpt $j '^--check-config$')) }
    if ($c -cmatch '^(nodemon|uvicorn|watchexec|serve|http-server|live-server|webpack-dev-server)$') { return $true }
    if ($c -ceq 'parcel') { $j = Skip-SvcOpts $j; return ($j -lt $n -and (Get-SvcWord $j) -cne 'build') }
    if ($c -ceq 'node') { return (Test-SvcLeadOpt $j '^--watch(-path(=.*)?)?$' $false) }
    if ($c -ceq 'deno') { return (Test-SvcLeadOpt $j '^--watch(=.*)?$' $true) }
    if ($c -cmatch '^python[0-9.]*$') {
        for ($k = $j; $k -lt $n; $k++) {
            $x = Get-SvcWord $k
            $y = Get-SvcWord ($k + 1)
            if ($x -ceq '-m') {
                if ($y -cmatch '^(http[.]server|uvicorn|gunicorn|hypercorn)$') { return $true }
                if ($y -ceq 'flask') { return ((Get-SvcWord (Skip-SvcOpts ($k + 2))) -ceq 'run') }
                return $false
            }
            if (-not $x.StartsWith('-')) { return ($x -cmatch 'manage[.]py$' -and $y -ceq 'runserver') }
        }
        return $false
    }
    if ($c -cmatch 'manage[.]py$') { return ((Get-SvcWord (Skip-SvcOpts $j)) -ceq 'runserver') }
    if ($c -ceq 'rails') { return ((Get-SvcWord (Skip-SvcOpts $j)) -cmatch '^(s|server)$' -and -not (Test-SvcAnyOpt $j '^(-d|--daemon)$')) }
    if ($c -ceq 'flask') { return ((Get-SvcWord (Skip-SvcOpts $j)) -ceq 'run') }
    if ($c -ceq 'docker' -or $c -ceq 'docker-compose') {
        $j = Skip-SvcOpts $j
        if ($c -ceq 'docker' -and (Get-SvcWord $j) -ceq 'compose') { $j = Skip-SvcOpts ($j + 1) }
        elseif ($c -ceq 'docker') { if ((Get-SvcWord $j) -cne 'logs') { return $false } }
        if ((Get-SvcWord $j) -ceq 'up') {
            return (-not (Test-SvcAnyOpt ($j + 1) '^(-[a-zA-Z]*d[a-zA-Z]*|--detach(=.*)?|--wait|--abort-on-container-exit|--abort-on-container-failure|--exit-code-from(=.*)?|--no-start|--dry-run)$'))
        }
        if ((Get-SvcWord $j) -ceq 'logs') { return (Test-SvcAnyOpt ($j + 1) '^(-[a-zA-Z]*f[a-zA-Z]*|--follow)$') }
        return $false
    }
    if ($c -ceq 'kubectl') {
        $j = Skip-SvcOpts $j
        $sub = Get-SvcWord $j
        if ($sub -ceq 'port-forward') { return $true }
        if ($sub -ceq 'logs') {
            for ($k = $j + 1; $k -lt $n; $k++) { $w2 = Get-SvcWord $k; if ($w2 -cmatch '^jobs?(\.[a-z]+)*(/|$)' -or $w2.Contains('job-name=')) { return $false } }
            return (Test-SvcAnyOpt ($j + 1) '^(-[a-zA-Z]*f[a-zA-Z]*|--follow)$')
        }
        if ($sub -ceq 'get') { return (Test-SvcAnyOpt ($j + 1) '^(-w|--watch|--watch-only)$') }
        return $false
    }
    if ($c -ceq 'tail') { return ((Test-SvcAnyOpt $j '^(-[a-zA-Z]*[fF][a-zA-Z]*|--follow(=.*)?)$') -and -not (Test-SvcAnyOpt $j '^--pid(=.*)?$')) }
    if ($c -ceq 'journalctl') { return (Test-SvcAnyOpt $j '^(-[a-zA-Z]*f[a-zA-Z]*|--follow)$') }
    if ($c -ceq 'turbo') {
        $j = Skip-SvcOpts $j
        if ((Get-SvcWord $j) -ceq 'run') { $j = Skip-SvcOpts ($j + 1) }
        $t = (Get-SvcWord $j).ToLowerInvariant()
        return ($t -cmatch '^(dev|watch|serve|start)(:[a-z0-9_-]+)?$' -and -not (Test-SvcJobName $t))
    }
    if ($c -ceq 'nx') {
        $j = Skip-SvcOpts $j
        if ((Get-SvcWord $j) -cmatch '^(serve|dev|start)$') { return $true }
        if ((Get-SvcWord $j) -ceq 'run') { return ((Get-SvcWord (Skip-SvcOpts ($j + 1))) -cmatch ':(serve|dev|start)(:|$)') }
        return $false
    }
    if ($c -ceq 'ng') { return ((Get-SvcWord (Skip-SvcOpts $j)) -cmatch '^(serve|s)$') }
    if ($c -ceq 'astro' -or $c -ceq 'nuxt' -or $c -ceq 'nuxi') { return ((Get-SvcWord (Skip-SvcOpts $j)) -cmatch '^(dev|preview)$') }
    if ($c -ceq 'expo') { return ((Get-SvcWord (Skip-SvcOpts $j)) -ceq 'start') }
    if ($c -ceq 'storybook' -or $c -ceq 'sb') { return ((Get-SvcWord (Skip-SvcOpts $j)) -cmatch '^(dev|start)$') }
    if ($c -ceq 'browser-sync') { return ((Get-SvcWord (Skip-SvcOpts $j)) -ceq 'start') }
    if ($c -ceq 'php') {
        for ($k = $j; $k -lt ($n - 1); $k++) { if ((Get-SvcWord $k) -ceq 'artisan') { return ((Get-SvcWord ($k + 1)) -ceq 'serve') } }
        return $false
    }
    if ($c -ceq 'hugo') { return ((Get-SvcWord (Skip-SvcOpts $j)) -cmatch '^(server|serve)$') }
    if ($c -ceq 'jekyll') { return ((Get-SvcWord (Skip-SvcOpts $j)) -cmatch '^(serve|s)$') }
    if ($c -ceq 'cargo') { return ((Get-SvcWord (Skip-SvcOpts $j)) -ceq 'watch') }
    if ($c -ceq 'tsx') { return ((Get-SvcWord (Skip-SvcOpts $j)) -ceq 'watch') }
    if ($c -ceq 'tsc' -or $c -ceq 'rollup' -or $c -ceq 'swc' -or $c -ceq 'mocha') { return (Test-SvcAnyOpt $j '^(-w|--watch)$') }
    if ($c -ceq 'webpack') { return ((Get-SvcWord (Skip-SvcOpts $j)) -cmatch '^(serve|server|s|watch|w)$' -or (Test-SvcAnyOpt $j '^(-w|--watch)$')) }
    if ($c -ceq 'tailwindcss') { return (Test-SvcAnyOpt $j '^(-w|--watch(=always)?)$') }
    if ($c -ceq 'sass') { return (Test-SvcAnyOpt $j '^(-w|--watch)$') }
    if ($c -ceq 'esbuild') { return (Test-SvcAnyOpt $j '^--watch(=forever)?$') }
    if ($c -ceq 'jest') { return (Test-SvcAnyOpt $j '^--(watch|watchAll)$') }
    return $false
}

# The JSON string body as the text of the command: real characters, line breaks kept. A
# \u00XX in the ASCII range is that character (Go writes & as &), any other \u escape
# a space.
function Get-SvcUnescape([string]$raw) {
    $sb = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt $raw.Length; $i++) {
        $c = $raw[$i]
        if ($c -ne '\') { [void]$sb.Append($c); continue }
        if ($i + 1 -ge $raw.Length) { break }
        $e = $raw[$i + 1]
        $i++
        if ($e -eq 'n') { [void]$sb.Append("`n") }
        elseif ($e -eq 'r' -or $e -eq 't') { [void]$sb.Append(' ') }
        elseif ($e -eq 'u') {
            $hex = ''
            if ($i + 4 -lt $raw.Length) { $hex = $raw.Substring($i + 1, 4) }
            $ch = ' '
            if ($hex -match '^[0-9A-Fa-f]{4}$') {
                $v = [Convert]::ToInt32($hex, 16)
                if ($v -ge 32 -and $v -le 127) { $ch = [string][char]$v }
            }
            [void]$sb.Append($ch)
            $i += 4
        }
        else { [void]$sb.Append($e) }
    }
    return $sb.ToString()
}

# The text of the command in one pass: comments (a # that starts a word, outside quotes, up
# to the line break) and heredoc bodies dropped, line continuations joined, the inside of
# quotes emptied (one word _ is left), redirections with & removed, then every list
# separator is a ; and a pipe stays a |.
function Get-SvcClean([string]$s) {
    $out = New-Object System.Text.StringBuilder
    $q = ''
    $hd = ''
    $len = $s.Length
    for ($i = 0; $i -lt $len; $i++) {
        $ch = [string]$s[$i]
        if ($q -eq '') {
            $pv = ''
            if ($i -gt 0) { $pv = [string]$s[$i - 1] }
            if ($ch -eq '#' -and ($pv -eq '' -or " `t`n;&|()".IndexOf([char]$pv) -ge 0)) {
                while (($i + 1) -lt $len -and $s[$i + 1] -ne "`n") { $i++ }
                continue
            }
            if ($ch -eq "`n") {
                [void]$out.Append("`n")
                if ($hd -ne '') {
                    while (($i + 1) -lt $len) {
                        $nl = $s.IndexOf("`n", $i + 1)
                        if ($nl -lt 0) { $ln = $s.Substring($i + 1); $i = $len } else { $ln = $s.Substring($i + 1, $nl - $i - 1); $i = $nl }
                        if ($ln.TrimStart(' ', "`t") -ceq $hd) { break }
                    }
                    $hd = ''
                }
                continue
            }
            if ($ch -eq '\') {
                if (($i + 1) -lt $len -and $s[$i + 1] -eq "`n") { [void]$out.Append(' ') } else { [void]$out.Append('_') }
                $i++
                continue
            }
            if ($ch -eq "'" -or $ch -eq '"') { $q = $ch; [void]$out.Append('_'); continue }
            if ($ch -eq '$' -and ($i + 1) -lt $len -and $s[$i + 1] -eq "'") { $q = 'a'; [void]$out.Append('_'); $i++; continue }
            if ($ch -eq '<' -and ($i + 1) -lt $len -and $s[$i + 1] -eq '<') {
                if (($i + 2) -lt $len -and $s[$i + 2] -eq '<') { [void]$out.Append('<<<'); $i += 2; continue }
                $e = $i + 2
                if ($e -lt $len -and $s[$e] -eq '-') { $e++ }
                while ($e -lt $len -and ($s[$e] -eq ' ' -or $s[$e] -eq "`t")) { $e++ }
                $bq = ''
                if ($e -lt $len -and ($s[$e] -eq "'" -or $s[$e] -eq '"' -or $s[$e] -eq '\')) { $bq = [string]$s[$e]; $e++ }
                $de = $e
                while ($de -lt $len -and " `t`n;&|()<>'`"".IndexOf($s[$de]) -lt 0) { $de++ }
                if ($de -gt $e) {
                    $hd = $s.Substring($e, $de - $e)
                    if ($bq -eq "'" -or $bq -eq '"') { $de++ }
                    $i = $de - 1
                    [void]$out.Append(' ')
                    continue
                }
            }
            [void]$out.Append($ch)
        }
        elseif ($q -eq "'") { if ($ch -eq "'") { $q = '' } }
        elseif ($q -eq 'a') {
            if ($ch -eq '\') { $i++ }
            elseif ($ch -eq "'") { $q = '' }
        }
        else {
            if ($ch -eq '\') { $i++ }
            elseif ($ch -eq '"') { $q = '' }
        }
    }
    $t = $out.ToString()
    $t = $t.Replace('|&', '|')
    $t = [regex]::Replace($t, '[0-9]*[<>]&[0-9-]*', ' ')
    $t = [regex]::Replace($t, '&>>?', ' > ')
    return $t.Replace('||', ';').Replace('&&', ';').Replace('&', ';').Replace("`n", ';')
}

# A last pipeline command that ends early (head, grep -q|-l|-m N) ends the pipeline too.
function Test-SvcConsumer([string]$seg) {
    $x = @([regex]::Replace($seg, '[()\t]', ' ') -split ' +' | Where-Object { $_ -ne '' })
    $k = 0
    while ($k -lt $x.Count -and $x[$k] -cmatch '^[A-Za-z_][A-Za-z0-9_]*=') { $k++ }
    if ($k -ge $x.Count) { return $false }
    $c = Get-SvcBase ([string]$x[$k])
    if ($c -ceq 'head') { return $true }
    if ($c -cmatch '^(grep|egrep|fgrep)$') {
        for ($k = $k + 1; $k -lt $x.Count; $k++) {
            if ([string]$x[$k] -cmatch '^(-[a-zA-Z]*[qlm][a-zA-Z0-9]*|--quiet|--silent|--max-count(=.*)?|--files-with-matches)$') { return $true }
        }
    }
    return $false
}

function Test-ServiceCmd([string]$cmd) {
    $last = ''
    foreach ($el in ((Get-SvcClean (Get-SvcUnescape $cmd)) -split ';')) {
        $t = $el -replace '[ \t]', ''
        if ($t -ne '' -and $t -ne '}') { $last = $el }
    }
    $parts = @($last -split '\|')
    if ($parts.Count -gt 1 -and (Test-SvcConsumer $parts[$parts.Count - 1])) { return $false }
    foreach ($part in $parts) {
        if (Test-ServiceSegment $part) { return $true }
    }
    return $false
}

# --- the end of a turn ----------------------------------------------------------

# True if every counted task was already running before the turn began.
function Test-BgAllOld([string]$prevIds) {
    if ($BgN -le 0 -or $BgNoId -gt 0) { return $false }
    $prev = @($prevIds -split ' +')
    foreach ($bi in $BgIds) { if ($prev -notcontains $bi) { return $false } }
    return $true
}

# A done for the turn that just ended (what: what still runs, if anything).
function Invoke-StopDone([string]$what) {
    if ($what) { $Script:Msg = Get-DoneMsg $what } else { $Script:Msg = Limit-JsonText $Last 200 800 }
    if ((Get-Field $f 'stop_hook_active') -eq 'true') { $Script:XFlag = '1' }
    Send-DoneLater
    # The turn's done is sent (or pending): Claude Code's idle_prompt, 60 s
    # later, repeats it (the next turn note takes the mark back).
    try { [IO.File]::WriteAllText((Join-Path $RunDir ($Sid + '.done')), "`n", $Utf8) } catch { }
    Invoke-UsageReport
    Write-State 'done' ''
    Update-Cli
}

# A Stop (Claude Code, Codex, Grok): done, or not yet. Not done while the agent
# waits for work it started or for a schedule, unless a person typed this turn
# and only work that ran before it is left, only services are left, or the
# last message asks the user something (then they are told). A turn the agent
# started itself while a schedule (/loop, cron) is set stays quiet:
# background with "scheduled: ...". The same as stop_flow in agent-hook.sh.
function Invoke-StopFlow {
    $turnUser = $true
    $prevIds = ''
    $turnFile = Join-Path $RunDir ($Sid + '.turn')
    try {
        if ([IO.File]::Exists($turnFile)) {
            $tl = [IO.File]::ReadAllText($turnFile, $Utf8) -split "`n"
            if ($tl.Count -gt 0 -and $tl[0] -eq 'auto') { $turnUser = $false }
            if ($tl.Count -gt 1) { $prevIds = $tl[1] }
        }
        [IO.File]::WriteAllText((Join-Path $RunDir ($Sid + '.stopids')), (($BgIds -join ' ') + "`n"), $Utf8)
        $cronFile = Join-Path $RunDir ($Sid + '.crons')
        if ($CronN -gt 0) { [IO.File]::WriteAllText($cronFile, (($CronSums -join ' ') + "`n"), $Utf8) }
        else { [IO.File]::Delete($cronFile) }
    } catch { }
    if ($BgN -eq 0 -and $CronN -eq 0) { Invoke-StopDone ''; return }
    if ($turnUser -and ($BgN -eq 0 -or (Test-BgAllOld $prevIds))) {
        if ($BgN -gt 0) { Invoke-StopDone (Get-BgSummary) } else { Invoke-StopDone '' }
        return
    }
    if ($BgN -gt 0 -and $BgSvc -eq $BgN -and ($CronN -eq 0 -or $turnUser)) {
        Invoke-StopDone (Get-BgSummary)
        return
    }
    Invoke-UsageReport
    Invoke-BgPause (Test-AskText $Last)
    Update-Cli
}

# The status of a running turn: while a paused session's background subagents
# run tools, the pause's own badge (`waiting` when the turn paused on a
# question, `background` otherwise); `running` otherwise.
function Write-Running {
    $path = Join-Path $RunDir ($Sid + '.bg')
    if ([IO.File]::Exists($path)) {
        $m = ''
        $state = 'background'
        try {
            $bl = [IO.File]::ReadAllText($path, $Utf8) -split "`n"
            $m = $bl[0]
            if ($bl.Count -gt 3 -and $bl[3] -eq 'ask') { $state = 'waiting' }
        } catch { }
        Write-State $state $m
    } else {
        Write-State 'running' ''
    }
}

try {
    switch ($Agent) {
        'claude' {
            $App = 'claude-code'
            # Grok Build runs Claude Code plugins' hooks; it sets GROK_HOOK_EVENT.
            if ($env:GROK_HOOK_EVENT -and $Mode -ne '__send') { $Agent = 'grok'; $App = 'grok-build' }
        }
        'grok' { $App = 'grok-build' }
        'codex' { $App = 'codex' }
        'codex-notify' { $App = 'codex' }
        'notify' { $App = 'script' }
        default { exit 0 }
    }
    $Script:UsageSeq = ''
    $Script:BgSeq = ''
    $Script:LaterJson = ''
    $Script:UsageJson = ''
    $Script:Title = ''
    $Script:XFlag = ''

    if ($Mode -eq '__send') {
        Invoke-SendChild
        Trim-Log
        exit 0
    }

    $InputText = ''
    if ($Agent -ne 'notify') { $InputText = Read-Input }
    $LinkFiles = @(Get-LinkFiles)
    if ($LinkFiles.Count -eq 0 -and $env:SIMPLETERM -ne '1') { exit 0 }
    if (-not [IO.Directory]::Exists($RunDir)) { [void][IO.Directory]::CreateDirectory($RunDir) }

    # Stop `background_tasks` (Claude Code) or `backgroundTasks` (Grok): the first ten tasks.
    $bgWant = @(foreach ($i in 0..9) { foreach ($k in 'background_tasks', 'backgroundTasks') { "$k.$i.id"; "$k.$i.type"; "$k.$i.description"; "$k.$i.command" } })
    # session_crons (Claude Code) or sessionCrons (Grok): the first five wake-ups.
    $cronWant = @(foreach ($i in 0..4) { foreach ($k in 'session_crons', 'sessionCrons') { "$k.$i.id"; "$k.$i.schedule"; "$k.$i.prompt" } })
    $f = Get-JsonFields $InputText (@('hook_event_name', 'hookEventName', 'notification_type', 'notificationType', 'type',
        'tool_name', 'tool_input.command', 'tool_input.file_path', 'tool_input.url', 'tool_input.description',
        'tool_input.questions.0.question', 'session_id', 'sessionId', 'cwd', 'message', 'last_assistant_message',
        'lastAssistantMessage', 'last-assistant-message', 'input-messages.0', 'error', 'transcript_path', 'context_tokens',
        'model', 'to_model', 'promptId', 'toolUseId', 'reason', 'timestamp', 'prompt', 'source', 'stop_hook_active',
        'is_interrupt', 'agent_id') + $bgWant + $cronWant)
    $HookEvent = Get-Field $f 'hook_event_name'
    if (-not $HookEvent) { $HookEvent = Get-Field $f 'hookEventName' }
    if ($Agent -eq 'codex-notify') { $HookEvent = 'notify' }
    # Grok's camelCase event names (hookEventName), as in agent-hook.sh.
    if ($Agent -eq 'grok') {
        if ($HookEvent -eq 'notification') { $HookEvent = 'Notification' }
        elseif ($HookEvent -eq 'stop') { $HookEvent = 'Stop' }
        elseif ($HookEvent -eq 'stop_failure') { $HookEvent = 'StopFailure' }
        elseif ($HookEvent -eq 'user_prompt_submit') { $HookEvent = 'UserPromptSubmit' }
    }
    $Tool = Get-Field $f 'tool_name'
    $Detail = ''
    foreach ($k in @('tool_input.command', 'tool_input.file_path', 'tool_input.url')) {
        if (-not $Detail) { $Detail = Get-Field $f $k }
    }
    $Desc = Get-Field $f 'tool_input.description'
    $Last = Get-Field $f 'last_assistant_message'
    if (-not $Last) { $Last = Get-Field $f 'lastAssistantMessage' }
    if (-not $Last) { $Last = Get-Field $f 'last-assistant-message' }
    if (-not $Last) { $Last = Get-Field $f 'message' }
    $sidRaw = Get-Field $f 'session_id'
    if (-not $sidRaw) { $sidRaw = Get-Field $f 'sessionId' }
    $Sid = $sidRaw -replace '[^A-Za-z0-9_-]', '_'
    if ($Sid.Length -gt 80) { $Sid = $Sid.Substring(0, 80) }
    if (-not $Sid) { $Sid = 'nosession' }

    $Rid = New-RandomHex 8
    $Ts = [string](Now-Epoch)
    if ($env:SIMPLETERM_HOOK_TEST -eq '1') {
        if ($env:SIMPLETERM_HOOK_TEST_RID) { $Rid = $env:SIMPLETERM_HOOK_TEST_RID }
        if ($env:SIMPLETERM_HOOK_TEST_TS) { $Ts = $env:SIMPLETERM_HOOK_TEST_TS }
    }
    if (-not (Test-Hex $Rid 16)) { $LinkFiles = @() }
    if (-not (Test-UInt $Ts)) { $Ts = '0' }
    $CwdBase = Limit-JsonText (Get-Field $f 'cwd') 64 256 -Base
    $Fp = (Get-Sha256Hex ($Tool + "`t" + (Limit-JsonText $Detail 200 800))).Substring(0, 16)
    $Script:Msg = ''
    # Stop `background_tasks` (Claude Code) or `backgroundTasks` (Grok): the
    # first task and up to ten ids.
    $bgKey = 'background_tasks'
    if ($Agent -eq 'grok') { $bgKey = 'backgroundTasks' }
    # Claude Code 2.1.316 type labels: subagent, workflow, cloud session and
    # MCP task report back (they end); shell, monitor, an idle teammate (and
    # labels we do not know) may run for good; dream, auto-mode scan, memory
    # import and memory save are its own housekeeping and never wake it.
    $BgN = 0
    $BgFinite = 0
    $BgType = ''
    $BgDesc = ''
    $BgSvc = 0
    $BgNoId = 0
    $BgIds = @()
    for ($i = 0; $i -lt 10; $i++) {
        $t = Get-Field $f ($bgKey + '.' + $i + '.type')
        if (-not $t -or @('dream', 'auto-mode scan', 'memory import', 'memory save') -contains $t) { continue }
        $BgN++
        if (@('subagent', 'workflow', 'cloud session', 'MCP task') -contains $t) { $BgFinite++ }
        $bgId = Get-Field $f ($bgKey + '.' + $i + '.id')
        if ($bgId -cmatch '^[A-Za-z0-9_-]+$') { $BgIds += $bgId } else { $BgNoId++ }
        $bgCmd = Get-Field $f ($bgKey + '.' + $i + '.command')
        if ($t -eq 'shell' -and $bgCmd -and (Test-ServiceCmd $bgCmd)) { $BgSvc++ }
        if (-not $BgType) {
            $BgType = $t
            $BgDesc = Get-Field $f ($bgKey + '.' + $i + '.description')
            if (-not $BgDesc) { $BgDesc = $bgCmd }
        }
    }
    # Scheduled wake-ups: how many, the first one's schedule, a checksum of each prompt.
    $cronKey = 'session_crons'
    if ($Agent -eq 'grok') { $cronKey = 'sessionCrons' }
    $CronN = 0
    $CronSched = ''
    $CronSums = @()
    for ($i = 0; $i -lt 5; $i++) {
        $cId = Get-Field $f ($cronKey + '.' + $i + '.id')
        $cSch = Get-Field $f ($cronKey + '.' + $i + '.schedule')
        $cPr = Get-Field $f ($cronKey + '.' + $i + '.prompt')
        if (-not ($cId -or $cSch -or $cPr)) { continue }
        if ($i + 1 -gt $CronN) { $CronN = $i + 1 }
        if ($i -eq 0) { $CronSched = $cSch }
        if ($cPr) { $CronSums += (Get-PromptSum $cPr) }
    }

    # `simpleterm notify "title" ["body"]`: an OSC 777 notification on this
    # console (in a SimpleTerm session) and a `notify` event to every link.
    if ($Agent -eq 'notify') {
        $t = ''
        $b = ''
        if ($ScriptArgs.Count -gt 1) { $t = [string]$ScriptArgs[1] }
        if ($ScriptArgs.Count -gt 2) { $b = [string]$ScriptArgs[2] }
        $t = Format-NotifyText $t 64 256
        $b = Format-NotifyText $b 200 800
        if (-not ($t + $b)) { exit 0 }
        if ($env:SIMPLETERM -eq '1' -and -not [Console]::IsOutputRedirected) {
            try { [Console]::Out.Write([string][char]27 + ']777;notify;' + $t + ';' + $b + [string][char]7); [Console]::Out.Flush() } catch { }
        }
        # Already within the limits; escaping can double the bytes, not the count.
        $Script:Title = ConvertTo-JsonText $t 64 512
        $Script:Msg = ConvertTo-JsonText $b 200 1600
        $cwd = (Get-Location).Path
        $CwdBase = Limit-JsonText (ConvertTo-JsonText $cwd 4096 16384) 64 256 -Base
        Send-Background 'notify'
        Trim-Log
        exit 0
    }

    # A done waits done_delay seconds (Send-DoneLater) in case another Stop
    # hook keeps the agent going; any later event of the main thread ends that
    # wait. Only the Stop events that send a done themselves leave it be, and
    # so do the events of a subagent (agent_id is set, foreground or
    # background): its tool calls carry the session id and are no sign of the
    # main thread going on.
    if (@('claude:Stop', 'codex:Stop', 'grok:Stop') -notcontains ($Agent + ':' + $HookEvent) -and -not (Get-Field $f 'agent_id')) {
        try { [IO.File]::Delete((Join-Path $RunDir ($Sid + '.pend'))) } catch { }
    }

    switch ($Agent + ':' + $HookEvent) {
        { $_ -eq 'claude:PermissionRequest' -or $_ -eq 'codex:PermissionRequest' } {
            if ($Mode -eq 'signal') {
                Write-State 'waiting' ('approve ' + $Tool + ': ' + $Detail)
            } elseif ($Tool -eq 'AskUserQuestion') {
                $q = Get-Field $f 'tool_input.questions.0.question'
                if (-not $q) { $q = $Desc }
                $Script:Msg = Limit-JsonText $q 200 800
                if (Test-AskOnce $q) { Send-Background 'question' }
            } else {
                $d = $Detail
                if ($Tool -eq 'apply_patch') { $d = $Desc; if (-not $d) { $d = 'patch' } }
                if (-not $d) { $d = $Desc }
                $Script:Msg = Limit-JsonText ('approve ' + $Tool + ': ' + $d) 200 800
                if ($LinkFiles.Count -gt 0) { Invoke-PermissionFlow }
            }
            break
        }
        'claude:PreToolUse' {
            if ($Tool -eq 'AskUserQuestion') {
                $q = Get-Field $f 'tool_input.questions.0.question'
                $Script:Msg = Limit-JsonText $q 200 800
                if (Test-AskOnce $q) { Send-Background 'question' }
                Write-State 'waiting' ''
            }
            break
        }
        'claude:Notification' {
            # permission_prompt is ignored: PermissionRequest already reported that
            # wait (one relay event per agent wait). idle_prompt keeps the done badge.
            $nt = Get-Field $f 'notification_type'
            if ($nt -eq 'idle_prompt') {
                # Claude Code sends it 60 s after a turn while only background
                # shells or monitors run: the work is not waiting for the user.
                if (Test-BgPaused) { break }
                # Already told by this turn's done: the prompt repeats it. Without
                # a done (interrupt, StopFailure, no Stop hook) it stays the safety net.
                if (Test-TurnDone) { break }
                $Script:Msg = Limit-JsonText (Get-Field $f 'message') 200 800
                Send-Background 'question'
            } elseif ($nt -eq 'elicitation_dialog' -or $nt -eq 'elicitation_url_dialog') {
                Write-State 'waiting' ''
                $Script:Msg = Limit-JsonText (Get-Field $f 'message') 200 800
                Send-Background 'question'
            } elseif ($nt -eq 'agent_needs_input') {
                # Another background session of the user's needs input, not
                # this one: the alert stays, this tab's badge does not change.
                $Script:Msg = Limit-JsonText (Get-Field $f 'message') 200 800
                Send-Background 'question'
            }
            break
        }
        'claude:UserPromptSubmit' {
            Add-Note 'turn' ''
            Write-TurnMark (Get-PromptUser)
            Invoke-UsageReport
            Write-State 'running' ''
            break
        }
        { $_ -eq 'claude:PostToolUse' -or $_ -eq 'claude:PostToolUseFailure' } {
            if ($HookEvent -eq 'PostToolUseFailure' -and (Get-Field $f 'is_interrupt') -eq 'true' -and -not (Get-Field $f 'agent_id')) {
                # Esc during a tool call: the turn is over (no Stop follows).
                # Not when a subagent's tool was interrupted (agent_id is
                # set): the main session's wait goes on.
                Add-Note 'turn' ''
                Write-State 'idle' ''
                break
            }
            Add-Note 'tool' $Fp
            # Context grows with each tool call; look again every 20 seconds at most.
            $utPath = Join-Path $RunDir ($Sid + '.ut')
            $ut = ''
            try { if ([IO.File]::Exists($utPath)) { $ut = [IO.File]::ReadAllText($utPath).Trim() } } catch { }
            $now = Now-Epoch
            if (-not (Test-UInt $ut) -or ($now - [int64]$ut) -ge 20 -or [int64]$ut -gt $now) {
                try { [IO.File]::WriteAllText($utPath, [string]$now, $Utf8) } catch { }
                Invoke-UsageReport
            }
            Write-Running
            break
        }
        { $_ -eq 'claude:SessionStart' -or $_ -eq 'claude:PostCompact' -or $_ -eq 'claude:PostModelSwitch' -or
          $_ -eq 'codex:SessionStart' -or $_ -eq 'codex:PostCompact' } {
            Invoke-UsageReport
            Write-UsageOnly
            if ($HookEvent -eq 'SessionStart') { Update-Cli }
            break
        }
        { $_ -eq 'claude:Stop' -or $_ -eq 'codex:Stop' } {
            Add-Note 'turn' ''
            if ($Last.StartsWith('{\"title\":')) { break }
            if ($Agent -eq 'codex' -and (Test-CodexGoalActive)) {
                Invoke-UsageReport
                # A goal can end without a trace in the rollout (blocked, a
                # budget or usage limit, /goal clear): if no next turn started
                # codex_goal_check seconds (default 5) later, this was the last.
                $roll = Get-InputFile (Get-Field $f 'transcript_path')
                if ($roll -and $LinkFiles.Count -gt 0) {
                    $goalFile = Join-Path $RunDir ($Sid + '.goal')
                    try {
                        [IO.File]::WriteAllText($goalFile, $Rid + "`n", $Utf8)
                        $Script:Msg = Limit-JsonText $Last 200 800
                        Start-LaterSend 'goal' (Get-ConfInt 'codex_goal_check' 5) $goalFile 0 $Rid $roll ((Get-Item -LiteralPath $roll).Length)
                    } catch { }
                }
                Update-Cli
                break
            }
            Invoke-StopFlow
            break
        }
        'claude:StopFailure' {
            Add-Note 'turn' ''
            $err = Get-Field $f 'error'
            $ev = 'error'
            if ($err -eq 'authentication_failed' -or $err -eq 'oauth_org_not_allowed' -or $err -eq 'cloud_credential_error') { $ev = 'auth' }
            $Script:Msg = Limit-JsonText ($err + ': ' + (Get-Field $f 'last_assistant_message')) 200 800
            Send-Background $ev
            Invoke-UsageReport
            Write-State 'done' ''
            break
        }
        'grok:UserPromptSubmit' {
            # Also the turn Grok starts itself when background work reports back.
            Add-Note 'turn' ''
            Write-TurnMark (Get-PromptUser)
            break
        }
        'grok:Notification' {
            # Grok asks in its own prompt and takes no answer from a hook:
            # permission_prompt and idle_prompt are alerts. The key includes
            # the event's timestamp, the same in every copy of one event.
            $nt = Get-Field $f 'notificationType'
            if (-not $nt) { $nt = Get-Field $f 'notification_type' }
            if (@('permission_prompt', 'idle_prompt') -notcontains $nt) { break }
            if ($nt -eq 'idle_prompt' -and ((Test-BgPaused) -or (Test-TurnDone))) { break }
            $key = (Get-Sha256Hex ($HookEvent + '|' + $Sid + '|' + $nt + '|' + (Get-Field $f 'promptId') + '|' + (Get-Field $f 'timestamp') + '|' + $Last)).Substring(0, 16)
            if (-not (Test-Once $key)) { break }
            $Script:Msg = Limit-JsonText $Last 200 800
            Send-Background 'question'
            break
        }
        { $_ -eq 'grok:Stop' -or $_ -eq 'grok:StopFailure' } {
            # A Stop also comes when the session closes (reason channel_closed
            # or shutdown); only end_turn ends a turn.
            $reason = Get-Field $f 'reason'
            if ($HookEvent -eq 'Stop' -and $reason -and $reason -ne 'end_turn') { break }
            $err = Get-Field $f 'error'
            $key = (Get-Sha256Hex ($HookEvent + '|' + $Sid + '|' + (Get-Field $f 'promptId') + '|' + (Get-Field $f 'timestamp') + '|' + $err + '|' + $Last)).Substring(0, 16)
            if (-not (Test-Once $key)) { break }
            Add-Note 'turn' ''
            # Grok 1.0.70 lists work still in flight in backgroundTasks, as
            # Claude Code does, and takes the turn up again when it reports back.
            if ($HookEvent -eq 'Stop') {
                Invoke-StopFlow
            } else {
                $ev = 'error'
                if ($err -eq 'authentication_failed' -or $err -eq 'oauth_org_not_allowed' -or $err -eq 'cloud_credential_error') { $ev = 'auth' }
                $Script:Msg = Limit-JsonText ($err + ': ' + $Last) 200 800
                Send-Background $ev
            }
            break
        }
        'codex-notify:notify' {
            if ((Get-Field $f 'type') -ne 'agent-turn-complete') { break }
            if ((Get-Field $f 'input-messages.0').StartsWith('Generate a concise, single-line task title')) { break }
            $Script:Msg = Limit-JsonText (Get-Field $f 'last-assistant-message') 200 800
            Send-Background 'done'
            break
        }
    }
} catch {
    Write-Log ('error ' + $_.Exception.GetType().Name)
}
Trim-Log
exit 0
