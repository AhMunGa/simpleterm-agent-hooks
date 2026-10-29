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
# Bumped when the ~/.simpleterm/bin/simpleterm.cmd wrapper must be rewritten.
$CliRev = 1
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
    $shown = $push
    if (-not $shown) { $shown = '-' }
    Write-Log ('ingest ev=' + $ev + ' link=' + (Short $op.link.link) + ' http=' + ('{0:000}' -f $r.code) + ' push=' + $shown)
    if ($push) { return $push }
    return ('http' + $r.code)
}

# Sends the event to every link from a detached child process and returns.
# $scope limits it to `tunnel` or `relay` links.
# (PowerShell names are case-insensitive: a parameter `$rid` would hide `$Rid`.)
function Send-Background([string]$ev, [string]$eventRid, [string]$scope) {
    if ($LinkFiles.Count -eq 0) { return }
    if (-not $eventRid) { $eventRid = $Rid }
    if (-not $scope) { $scope = 'all' }
    # The child gets the event through its environment, not its command line.
    $usage = [Convert]::ToBase64String($Utf8.GetBytes([string]$Script:UsageJson))
    $payload = '{"ev":"' + $ev + '","rid":"' + $eventRid + '","ts":"' + $Ts + '","cwd":"' + $CwdBase +
        '","msg":"' + $Script:Msg + '","title":"' + $Script:Title + '","usage":"' + $usage + '","scope":"' + $scope + '"}'
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

function Invoke-SendChild {
    $raw = $env:SIMPLETERM_HOOK_PAYLOAD
    if (-not $raw) { return }
    $json = $Utf8.GetString([Convert]::FromBase64String($raw))
    $f = Get-JsonFields $json @('ev', 'rid', 'ts', 'msg', 'cwd', 'title', 'usage', 'scope')
    $ev = Get-Field $f 'ev'
    $Script:Rid = Get-Field $f 'rid'
    $Script:Ts = Get-Field $f 'ts'
    $Script:Msg = Get-Field $f 'msg'
    $Script:Title = Get-Field $f 'title'
    $Script:CwdBase = Get-Field $f 'cwd'
    $scope = Get-Field $f 'scope'
    try { $Script:UsageJson = $Utf8.GetString([Convert]::FromBase64String((Get-Field $f 'usage'))) } catch { $Script:UsageJson = '' }
    if (-not ($ev -cmatch '^[a-z]{1,16}$') -or -not (Test-Hex $Script:Rid 16) -or -not (Test-UInt $Script:Ts)) { return }
    if ($ev -eq 'usage' -and -not $Script:UsageJson) { return }
    $ops = @()
    foreach ($file in (Get-LinkFiles)) {
        $link = Read-Link $file
        if ($null -eq $link) { continue }
        if ($scope -eq 'tunnel' -and $link.kind -ne 'tunnel') { continue }
        if ($scope -eq 'relay' -and $link.kind -eq 'tunnel') { continue }
        try { $op = Start-Ingest $link $Script:Rid $ev ''; if ($op) { $ops += $op } } catch { Write-Log 'ingest-failed' }
    }
    foreach ($op in $ops) { try { [void](Complete-Ingest $op $ev) } catch { Write-Log 'ingest-failed' } }
}

# --- terminal sequence (Claude Code only, SimpleTerm sessions only) -------

# $Script:UsageSeq is the JSON-escaped usage OSC to append, if any.
function Write-State([string]$state, [string]$message) {
    if ($Agent -ne 'claude' -or $env:SIMPLETERM -ne '1') { return }
    $m = ''
    if ($message) { $m = ' ' + (Limit-JsonText $message 80 320) }
    Write-Out ('{"terminalSequence":"\u001b]9;simpleterm:state=' + $state + $m + '\u0007' + $Script:UsageSeq + '"}')
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
    if ($v -match '^[0-9]{4,12}$') { return @{ win = [int64]$v; est = $false } }
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
                    if ($null -ne $o.context_window -and (Test-Num $o.context_window.context_window_size)) {
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
    try { [IO.File]::WriteAllText($last, $fmt.osc + "`n", $Utf8) } catch { }
    $Script:UsageSeq = '\u001b]9;' + $fmt.osc + '\u0007'
    Send-Background 'usage' (New-RandomHex 8) 'tunnel'
}

# --- the `simpleterm` command (Windows) ---------------------------------------

# Keeps ~/.simpleterm/bin/simpleterm.cmd pointing at this script, so that
# `simpleterm notify "title" "body"` works in cmd and PowerShell.
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
            if ($m.Success -and [IO.File]::Exists($m.Groups[1].Value) -and $r.Success -and [int]$r.Groups[1].Value -ge $CliRev) { return }
        }
        if (-not [IO.Directory]::Exists($bin)) { [void][IO.Directory]::CreateDirectory($bin) }
        $body = "@echo off`r`nrem simpleterm: written by the SimpleTerm agent hooks plugin (rev=" + $CliRev + "); edits are overwritten.`r`n" +
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
        if ($kind -eq 'turn') { [IO.File]::WriteAllText($path, ([string](Now-Epoch) + " turn -`n"), $Utf8) }
        else { [IO.File]::AppendAllText($path, ([string](Now-Epoch) + ' tool ' + $fp + "`n"), $Utf8) }
    } catch { }
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
    $Script:UsageJson = ''
    $Script:Title = ''

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

    $f = Get-JsonFields $InputText @('hook_event_name', 'hookEventName', 'notification_type', 'notificationType', 'type',
        'tool_name', 'tool_input.command', 'tool_input.file_path', 'tool_input.url', 'tool_input.description',
        'tool_input.questions.0.question', 'session_id', 'sessionId', 'cwd', 'message', 'last_assistant_message',
        'lastAssistantMessage', 'last-assistant-message', 'input-messages.0', 'error', 'transcript_path', 'context_tokens',
        'model', 'to_model', 'promptId', 'toolUseId')
    $HookEvent = Get-Field $f 'hook_event_name'
    if (-not $HookEvent) { $HookEvent = Get-Field $f 'hookEventName' }
    if ($Agent -eq 'codex-notify') { $HookEvent = 'notify' }
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

    # `simpleterm notify "title" ["body"]`: an OSC 777 notification on this
    # console (in a SimpleTerm session) and a `notify` event to every link.
    if ($Agent -eq 'notify') {
        $t = ''
        $b = ''
        if ($ScriptArgs.Count -gt 1) { $t = [string]$ScriptArgs[1] }
        if ($ScriptArgs.Count -gt 2) { $b = [string]$ScriptArgs[2] }
        $t = ($t -replace '[\x00-\x1f\x7f]', ' ')
        $b = ($b -replace '[\x00-\x1f\x7f]', ' ')
        if ($t.Length -gt 120) { $t = $t.Substring(0, 120) }
        if ($b.Length -gt 400) { $b = $b.Substring(0, 400) }
        if (-not ($t + $b)) { exit 0 }
        if ($env:SIMPLETERM -eq '1' -and -not [Console]::IsOutputRedirected) {
            try { [Console]::Out.Write([string][char]27 + ']777;notify;' + $t + ';' + $b + [string][char]7); [Console]::Out.Flush() } catch { }
        }
        $Script:Title = ConvertTo-JsonText $t 64 256
        $Script:Msg = ConvertTo-JsonText $b 200 800
        $cwd = (Get-Location).Path
        $CwdBase = Limit-JsonText (ConvertTo-JsonText $cwd 4096 16384) 64 256 -Base
        Send-Background 'notify'
        Trim-Log
        exit 0
    }

    switch ($Agent + ':' + $HookEvent) {
        { $_ -eq 'claude:PermissionRequest' -or $_ -eq 'codex:PermissionRequest' } {
            if ($Mode -eq 'signal') {
                Write-State 'waiting' ('approve ' + $Tool + ': ' + $Detail)
            } elseif ($Tool -eq 'AskUserQuestion') {
                $q = Get-Field $f 'tool_input.questions.0.question'
                if (-not $q) { $q = $Desc }
                $Script:Msg = Limit-JsonText $q 200 800
                Send-Background 'question'
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
                $Script:Msg = Limit-JsonText (Get-Field $f 'tool_input.questions.0.question') 200 800
                Send-Background 'question'
                Write-State 'waiting' ''
            }
            break
        }
        'claude:Notification' {
            # permission_prompt is ignored: PermissionRequest already reported that
            # wait (one relay event per agent wait). idle_prompt keeps the done badge.
            $nt = Get-Field $f 'notification_type'
            if ($nt -eq 'idle_prompt') {
                $Script:Msg = Limit-JsonText (Get-Field $f 'message') 200 800
                Send-Background 'question'
            } elseif ($nt -eq 'elicitation_dialog' -or $nt -eq 'elicitation_url_dialog' -or $nt -eq 'agent_needs_input') {
                Write-State 'waiting' ''
                $Script:Msg = Limit-JsonText (Get-Field $f 'message') 200 800
                Send-Background 'question'
            }
            break
        }
        'claude:UserPromptSubmit' {
            Add-Note 'turn' ''
            Invoke-UsageReport
            Write-State 'running' ''
            break
        }
        { $_ -eq 'claude:PostToolUse' -or $_ -eq 'claude:PostToolUseFailure' } {
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
            Write-State 'running' ''
            break
        }
        { $_ -eq 'claude:SessionStart' -or $_ -eq 'claude:PostCompact' -or $_ -eq 'claude:PostModelSwitch' -or
          $_ -eq 'codex:SessionStart' -or $_ -eq 'codex:PostCompact' -or $_ -eq 'codex:UserPromptSubmit' } {
            Invoke-UsageReport
            Write-UsageOnly
            if ($HookEvent -eq 'SessionStart') { Update-Cli }
            break
        }
        { $_ -eq 'claude:Stop' -or $_ -eq 'codex:Stop' } {
            Add-Note 'turn' ''
            if ($Last.StartsWith('{\"title\":')) { break }
            $Script:Msg = Limit-JsonText $Last 200 800
            Send-Background 'done'
            Invoke-UsageReport
            Write-State 'done' ''
            Update-Cli
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
        'grok:Notification' {
            # Grok asks in its own prompt and takes no answer from a hook.
            $nt = Get-Field $f 'notificationType'
            if (-not $nt) { $nt = Get-Field $f 'notification_type' }
            if (@('permission_prompt', 'idle_prompt', 'elicitation_dialog') -notcontains $nt) { break }
            $key = (Get-Sha256Hex ($HookEvent + '|' + $Sid + '|' + $nt + '|' + (Get-Field $f 'promptId') + '|' + $Last)).Substring(0, 16)
            if (-not (Test-Once $key)) { break }
            $Script:Msg = Limit-JsonText $Last 200 800
            Send-Background 'question'
            break
        }
        { $_ -eq 'grok:Stop' -or $_ -eq 'grok:StopFailure' } {
            $err = Get-Field $f 'error'
            $key = (Get-Sha256Hex ($HookEvent + '|' + $Sid + '|' + (Get-Field $f 'promptId') + '|' + $err + '|' + $Last)).Substring(0, 16)
            if (-not (Test-Once $key)) { break }
            if ($HookEvent -eq 'Stop') {
                $Script:Msg = Limit-JsonText $Last 200 800
                Send-Background 'done'
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
