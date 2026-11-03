# SimpleTerm agent hook (Windows PowerShell 5.1+ and PowerShell 7), part of the
# simpleterm-agent-hooks plugin; see README.md and, in the SimpleTerm app
# repository, docs/tech_specs/TDS_AGENT_ALERTS.md (sections 5 and 6: relay
# protocol v1, hooks, SSH tunnel) and docs/tech_specs/TDS_AGENT_EVENTS_V2.md
# (event and decision format v2: request contents, decision lists, decision
# extensions, results, states, session records) for the contract.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File agent-hook.ps1 claude
#   ... agent-hook.ps1 claude signal     Claude Code PermissionRequest status only
#   ... agent-hook.ps1 codex             Codex hook (event JSON on stdin)
#   ... agent-hook.ps1 codex-notify J    Codex `notify` program (JSON is last arg)
#   ... agent-hook.ps1 notify T [B]      `simpleterm notify` (simpleterm.cmd)
#
# The same behavior as agent-hook.sh for Claude Code, Codex and Grok Build (run
# with `claude` and GROK_HOOK_EVENT set), using only .NET (Aes CBC/PKCS7,
# HMACSHA256, HttpWebRequest): for the same input it makes the same event
# plaintext, byte for byte (TDS_AGENT_EVENTS_V2 section 2.2). Gemini CLI,
# Antigravity, OpenCode and GitHub Copilot CLI are sh-only (run by Copilot,
# COPILOT_CLI=1, it does nothing). It never evaluates its input, prints only
# agent-defined JSON on stdout, and always exits 0. Keep this file ASCII:
# Windows PowerShell 5.1 reads BOM-less scripts in the ANSI code page.
#
# Text is handled as bytes: a "byte string" holds one char (U+0000 to U+00FF)
# per byte, as ISO-8859-1 decodes it. Lengths, cuts and comparisons are then
# those of agent-hook.sh (LC_ALL=C awk), and what goes out is the same bytes.
# PowerShell compares strings without case by default: here every comparison
# that agent-hook.sh makes is -ceq / -cne / -cmatch or ordinal.

$ErrorActionPreference = 'Stop'

# A usage ask runs the agent with SIMPLETERM_PROBE=1 (TDS_AGENT_EVENTS_V2
# section 9.2): hooks it runs do nothing, or the ask would make sessions and
# alerts of its own.
if ($env:SIMPLETERM_PROBE -ceq '1') { exit 0 }

$ScriptArgs = @($args)
$Agent = ''
$Mode = ''
if ($ScriptArgs.Count -gt 0) { $Agent = [string]$ScriptArgs[0] }
if ($ScriptArgs.Count -gt 1) { $Mode = [string]$ScriptArgs[1] }

$MaxInput = 262144
$MaxLinks = 16
# The plugin release of this script (the manifests carry the same).
$HookVersion = '0.5.0'
# Bumped when the ~/.simpleterm/bin/simpleterm.cmd wrapper must be rewritten.
$CliRev = 2
$Inv = [Globalization.CultureInfo]::InvariantCulture
$Utf8 = New-Object System.Text.UTF8Encoding($false)
$Latin1 = [Text.Encoding]::GetEncoding(28591)
$IsWin = ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT)
$Ord = [StringComparison]::Ordinal
$Tab = [string][char]9
$Nl = [string][char]10

$StDir = Join-Path $HOME '.simpleterm'
$LinksDir = Join-Path $StDir 'links'
$RunDir = Join-Path $StDir 'run'
$LogPath = Join-Path $StDir 'agent-hook.log'
$Script:Logged = $false

function Now-Epoch {
    $epoch = New-Object DateTime(1970, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)
    return [int64][Math]::Floor(([DateTime]::UtcNow - $epoch).TotalSeconds)
}

function Now-Ms {
    $epoch = New-Object DateTime(1970, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)
    return [int64][Math]::Floor(([DateTime]::UtcNow - $epoch).TotalMilliseconds)
}

# Byte string <-> .NET text.
function BS([string]$text) {
    if (-not $text) { return '' }
    return $Latin1.GetString($Utf8.GetBytes($text))
}

function US([string]$bytes) {
    if (-not $bytes) { return '' }
    return $Utf8.GetString($Latin1.GetBytes($bytes))
}

function Write-Log([string]$text) {
    try {
        if (-not [IO.Directory]::Exists($StDir)) { return }
        $line = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', $Inv) + ' ' + $Agent + ' ' + $text + "`n"
        [IO.File]::AppendAllText($LogPath, $line, $Latin1)
        $Script:Logged = $true
    } catch { }
}

function Trim-Log {
    if (-not $Script:Logged) { return }
    try {
        $lines = $Latin1.GetString([IO.File]::ReadAllBytes($LogPath)).Split([char]10)
        $n = $lines.Length
        if ($n -gt 0 -and $lines[$n - 1] -ceq '') { $n-- }
        if ($n -le 200) { return }
        $keep = $lines[($n - 200)..($n - 1)]
        $tmp = $LogPath + '.' + $PID
        [IO.File]::WriteAllText($tmp, (($keep -join "`n") + "`n"), $Latin1)
        if ([IO.File]::Exists($LogPath)) { [IO.File]::Delete($LogPath) }
        [IO.File]::Move($tmp, $LogPath)
    } catch { }
}

# Writes a byte string (and a line break) to stdout.
function Write-Out([string]$text) {
    $bytes = $Latin1.GetBytes($text + "`n")
    $out = [Console]::OpenStandardOutput()
    $out.Write($bytes, 0, $bytes.Length)
    $out.Flush()
}

# --- files (byte strings) -------------------------------------------------------

function Read-HeadB([string]$path, [int64]$max) {
    try {
        $fs = New-Object IO.FileStream($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
        try {
            $n = [int][Math]::Min($max, $fs.Length)
            $buf = New-Object byte[] $n
            $read = 0
            while ($read -lt $n) {
                $r = $fs.Read($buf, $read, $n - $read)
                if ($r -le 0) { break }
                $read += $r
            }
            return $Latin1.GetString($buf, 0, $read)
        } finally { $fs.Dispose() }
    } catch { return '' }
}

function Read-TailB([string]$path, [int64]$max) {
    try {
        $fs = New-Object IO.FileStream($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
        try {
            $len = $fs.Length
            $n = [int][Math]::Min($max, $len)
            [void]$fs.Seek($len - $n, [IO.SeekOrigin]::Begin)
            $buf = New-Object byte[] $n
            $read = 0
            while ($read -lt $n) {
                $r = $fs.Read($buf, $read, $n - $read)
                if ($r -le 0) { break }
                $read += $r
            }
            return $Latin1.GetString($buf, 0, $read)
        } finally { $fs.Dispose() }
    } catch { return '' }
}

# The whole file, or $null when it cannot be read.
function Read-FileB([string]$path) {
    try {
        if ([IO.File]::Exists($path)) { return $Latin1.GetString([IO.File]::ReadAllBytes($path)) }
    } catch { }
    return $null
}

# Line $n (0-based) of a file, '' if it has none (sed -n Np).
function Read-LineB([string]$path, [int]$n) {
    $t = Read-FileB $path
    if ($null -eq $t) { return '' }
    $l = $t.Split([char]10)
    if ($n -lt $l.Length) {
        if ($n -eq $l.Length - 1 -and $l[$n] -ceq '') { return '' }
        return $l[$n]
    }
    return ''
}

function Write-FileB([string]$path, [string]$text) {
    try { [IO.File]::WriteAllText($path, $text, $Latin1); return $true } catch { return $false }
}

function Remove-FileQ([string]$path) {
    try { if ([IO.File]::Exists($path)) { [IO.File]::Delete($path) } } catch { }
}

# --- JSON helpers (byte strings) -------------------------------------------------

# One JSON token at a time, as the awk scanners of agent-hook.sh read them:
# white space, a structural character (1), a string (2), a string that does not
# end (3), or a bare word up to white space or , : } ] (4).
$TokRe = New-Object System.Text.RegularExpressions.Regex ('\G(?:[ \t\r\n]+|([,:{}\[\]])|("[^"\\]*(?:\\[\s\S][^"\\]*)*")|(")|([^ \t\r\n,:}\]]+))')
$CtrlRe = New-Object System.Text.RegularExpressions.Regex ('[\x01-\x1F\x7F]')
$NormRe = New-Object System.Text.RegularExpressions.Regex ('[^\x20-\x5B\x5D-\x7E]')
$UnitRe = New-Object System.Text.RegularExpressions.Regex ('[\\\xC0-\xFF]')

# Port of jwalk (JSON_GET): the wanted paths (`a`, `a.b`, `a.0.b`) found in
# the JSON text, the first of each, in document order: @{ order; got }.
# String values stay JSON-escaped. Tolerates truncation.
function Get-JsonKV([string]$text, [string[]]$want) {
    $wantSet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($w in $want) { [void]$wantSet.Add($w) }
    $got = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::Ordinal)
    $order = New-Object 'System.Collections.Generic.List[string]'
    $need = $wantSet.Count
    $jt = New-Object 'System.Collections.Generic.List[int]'
    $jk = New-Object 'System.Collections.Generic.List[string]'
    $je = New-Object 'System.Collections.Generic.List[bool]'
    $m = $TokRe.Match([string]$text, 0)
    while ($m.Success -and $need -gt 0) {
        $d = $jt.Count
        $v = $null
        if ($m.Groups[1].Success) {
            $c = $m.Groups[1].Value
            if ($c -ceq ',') {
                if ($d -gt 0) { if ($jt[$d - 1] -eq 2) { $jk[$d - 1] = [string]([int]$jk[$d - 1] + 1) } else { $je[$d - 1] = $true } }
            } elseif ($c -ceq ':') {
                if ($d -gt 0) { $je[$d - 1] = $false }
            } elseif ($c -ceq '{') { $jt.Add(1); $jk.Add(''); $je.Add($true) }
            elseif ($c -ceq '[') { $jt.Add(2); $jk.Add('0'); $je.Add($false) }
            elseif ($d -gt 0) { $jt.RemoveAt($d - 1); $jk.RemoveAt($d - 1); $je.RemoveAt($d - 1) }
        } elseif ($m.Groups[2].Success) {
            $s = $m.Groups[2].Value
            $s = $s.Substring(1, $s.Length - 2)
            if ($d -gt 0 -and $jt[$d - 1] -eq 1 -and $je[$d - 1]) { $jk[$d - 1] = $s } else { $v = $s }
        } elseif ($m.Groups[3].Success) {
            break
        } elseif ($m.Groups[4].Success) {
            $v = $m.Groups[4].Value
        }
        if ($null -ne $v -and $d -gt 0) {
            $p = $jk -join '.'
            if ($wantSet.Contains($p) -and -not $got.ContainsKey($p)) {
                $got[$p] = $v
                $order.Add($p)
                $need--
            }
        }
        $m = $m.NextMatch()
    }
    return @{ order = $order; got = $got }
}

function Get-Field($kv, [string]$name) {
    $v = $null
    if ($kv.got.TryGetValue($name, [ref]$v)) { return [string]$v }
    return ''
}

$SpanDefault = @('tool_input', 'tool_input.questions', 'requested_schema', 'toolCall.args.Arguments', 'toolInput', 'toolArgs')

# Port of JSON_FACTS: one line `path TAB s|r|j TAB value` per scalar (strings
# JSON-escaped as received, control characters as spaces) and for a few
# containers (tool_input and the like) their own text as the content of a JSON
# string (j). With $rawp: only that container's text, raw (control characters
# as spaces), for an answer that hands it back.
function Get-Facts([string]$s, [string]$rawp) {
    $spanW = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    if ($rawp) { [void]$spanW.Add($rawp) } else { foreach ($w in $SpanDefault) { [void]$spanW.Add($w) } }
    $out = New-Object 'System.Collections.Generic.List[string]'
    $jt = New-Object 'System.Collections.Generic.List[int]'
    $jk = New-Object 'System.Collections.Generic.List[string]'
    $je = New-Object 'System.Collections.Generic.List[bool]'
    $sps = New-Object 'System.Collections.Generic.List[int]'
    $spp = New-Object 'System.Collections.Generic.List[string]'
    $count = 0
    $m = $TokRe.Match([string]$s, 0)
    while ($m.Success) {
        $d = $jt.Count
        if ($m.Groups[1].Success) {
            $c = $m.Groups[1].Value
            if ($c -ceq ',') {
                if ($d -gt 0) { if ($jt[$d - 1] -eq 2) { $jk[$d - 1] = [string]([int]$jk[$d - 1] + 1) } else { $je[$d - 1] = $true } }
            } elseif ($c -ceq ':') {
                if ($d -gt 0) { $je[$d - 1] = $false }
            } elseif ($c -ceq '{' -or $c -ceq '[') {
                $p = ''
                if ($d -gt 0) { $p = $jk -join '.' }
                if ($c -ceq '{') { $jt.Add(1); $jk.Add(''); $je.Add($true) } else { $jt.Add(2); $jk.Add('0'); $je.Add($false) }
                $st = -1
                if ($p.Length -gt 0 -and ($spanW.Contains($p) -or $p -cmatch '\Apermission_suggestions\.[0-9]+\z')) { $st = $m.Index }
                $sps.Add($st)
                $spp.Add($p)
            } elseif ($d -gt 0) {
                $st = $sps[$d - 1]
                if ($st -ge 0) {
                    $t = $s.Substring($st, $m.Index - $st + 1)
                    if ($rawp) {
                        if ($spp[$d - 1] -ceq $rawp) { return $CtrlRe.Replace($t, ' ') }
                    } elseif ($count -lt 20000) {
                        $count++
                        $out.Add($spp[$d - 1] + $Tab + 'j' + $Tab + (ConvertTo-JsonEsc $t))
                    }
                }
                $jt.RemoveAt($d - 1); $jk.RemoveAt($d - 1); $je.RemoveAt($d - 1); $sps.RemoveAt($d - 1); $spp.RemoveAt($d - 1)
            }
        } elseif ($m.Groups[2].Success) {
            $v = $m.Groups[2].Value
            $v = $v.Substring(1, $v.Length - 2)
            if ($d -gt 0 -and $jt[$d - 1] -eq 1 -and $je[$d - 1]) { $jk[$d - 1] = $v }
            elseif ($d -gt 0 -and -not $rawp -and $count -lt 20000 -and -not $jk[0].StartsWith('@', [StringComparison]::Ordinal)) {
                $count++
                $out.Add(($jk -join '.') + $Tab + 's' + $Tab + $CtrlRe.Replace($v, ' '))
            }
        } elseif ($m.Groups[3].Success) {
            break
        } elseif ($m.Groups[4].Success) {
            # A top-level key that starts with @ would read as one of the hook's own parameters: left out (sh: femit).
            if ($d -gt 0 -and -not $rawp -and $count -lt 20000 -and -not $jk[0].StartsWith('@', [StringComparison]::Ordinal)) {
                $count++
                $out.Add(($jk -join '.') + $Tab + 'r' + $Tab + $m.Groups[4].Value)
            }
        }
        $m = $m.NextMatch()
    }
    if ($rawp) { return '' }
    return (, $out)
}

# Raw text as the content of a JSON string: \ and " escaped, control
# characters (tab and line breaks too) as spaces (jesc).
function ConvertTo-JsonEsc([string]$t) {
    return $CtrlRe.Replace($t, ' ').Replace('\', '\\').Replace('"', '\"')
}

function Test-Hex4([string]$s) {
    return ($s.Length -eq 4 -and $s -cmatch '\A[0-9a-fA-F]{4}\z')
}

# nhex(substr(s, i + 1, 4)): the value of 4 hex digits at 0-based index i, -1 if none.
function Get-Hex4([string]$s, [int]$i) {
    if ($i -lt 0 -or $i + 4 -gt $s.Length) { return -1 }
    $h = $s.Substring($i, 4)
    if ($h -cnotmatch '\A[0-9a-fA-F]{4}\z') { return -1 }
    return [Convert]::ToInt32($h, 16)
}

# jnorm: JSON-escaped string content, normalized (TDS_AGENT_EVENTS_V2 section
# 2.2): escapes stay as received; control characters and the escapes that
# stand for them become a space ($keepnl keeps \n, \t, \u000a and \u0009);
# lone surrogates and bytes that are not UTF-8 become a space; a broken escape
# ends the text.
function ConvertTo-Norm([string]$s, [bool]$keepnl) {
    $n = $s.Length
    if ($n -eq 0) { return '' }
    $sb = New-Object System.Text.StringBuilder ($n + 16)
    $i = 0
    while ($i -lt $n) {
        $m = $NormRe.Match($s, $i)
        if (-not $m.Success) { [void]$sb.Append($s, $i, $n - $i); break }
        $k = $m.Index
        if ($k -gt $i) { [void]$sb.Append($s, $i, $k - $i) }
        $i = $k
        $c = [int]$s[$i]
        $step = 1
        $unit = ' '
        if ($c -eq 92) {
            if ($i + 1 -ge $n) { break }
            $e = [int]$s[$i + 1]
            $step = 2
            if ($e -eq 117) {
                $v = Get-Hex4 $s ($i + 2)
                if ($v -lt 0) { break }
                $unit = $s.Substring($i, 6)
                $step = 6
                if ($v -ge 55296 -and $v -le 56319) {
                    $v2 = -1
                    if ($i + 8 -le $n -and $s.Substring($i + 6, 2) -ceq '\u') { $v2 = Get-Hex4 $s ($i + 8) }
                    if ($v2 -ge 56320 -and $v2 -le 57343) { $unit = $s.Substring($i, 12); $step = 12 } else { $unit = ' ' }
                } elseif ($v -ge 56320 -and $v -le 57343) { $unit = ' ' }
                elseif ($keepnl -and ($v -eq 10 -or $v -eq 9)) { }
                elseif ($v -lt 32 -or ($v -ge 127 -and $v -le 159) -or $v -eq 8232 -or $v -eq 8233) { $unit = ' ' }
            } elseif ($e -eq 34 -or $e -eq 92 -or $e -eq 47) { $unit = $s.Substring($i, 2) }
            elseif ($keepnl -and ($e -eq 110 -or $e -eq 116)) { $unit = $s.Substring($i, 2) }
        } elseif ($c -ge 194 -and $c -le 244) {
            # Well-formed UTF-8 only (sh: as NOTIFY_TEXT): no overlong forms, no
            # encoded surrogates, nothing past U+10FFFF.
            if ($c -lt 224) { $w = 2 } elseif ($c -lt 240) { $w = 3 } else { $w = 4 }
            $lo = 128; $hi = 191
            if ($c -eq 224) { $lo = 160 } elseif ($c -eq 237) { $hi = 159 } elseif ($c -eq 240) { $lo = 144 } elseif ($c -eq 244) { $hi = 143 }
            $ok = $true
            for ($j = 1; $ok -and $j -lt $w; $j++) {
                if ($i + $j -ge $n) { $ok = $false } else {
                    $x = [int]$s[$i + $j]
                    if ($j -eq 1) { if ($x -lt $lo -or $x -gt $hi) { $ok = $false } }
                    elseif ($x -lt 128 -or $x -gt 191) { $ok = $false }
                }
            }
            if ($ok) {
                $unit = $s.Substring($i, $w)
                $step = $w
                if ($c -eq 194 -and [int]$s[$i + 1] -lt 160) { $unit = ' ' }
            }
        }
        [void]$sb.Append($unit)
        $i += $step
    }
    return $sb.ToString()
}

# ucut: the longest start of normalized content with at most $maxu units (an
# escape, a surrogate pair escape or a UTF-8 character is one) and $maxb bytes,
# never splitting a unit.
function Get-UCut([string]$s, [int64]$maxu, [int64]$maxb) {
    $n = $s.Length
    if ($n -le $maxb -and $n -le $maxu) { return $s }
    $u = [int64]0
    $b = [int64]0
    $i = 0
    while ($i -lt $n) {
        $m = $UnitRe.Match($s, $i)
        $k = $n
        if ($m.Success) { $k = $m.Index }
        if ($k -gt $i) {
            # A run of one-byte units.
            $run = [int64]($k - $i)
            $room = [Math]::Min($maxu - $u, $maxb - $b)
            if ($room -lt $run) { $i += [int]$room; break }
            $u += $run; $b += $run; $i = $k
            if ($i -ge $n) { break }
        }
        $c = [int]$s[$i]
        if ($c -eq 92) {
            $step = 2
            if ($i + 1 -lt $n -and [int]$s[$i + 1] -eq 117) {
                $step = 6
                $v = Get-Hex4 $s ($i + 2)
                if ($v -ge 55296 -and $v -le 56319) { $step = 12 }
            }
        } elseif ($c -ge 240) { $step = 4 } elseif ($c -ge 224) { $step = 3 } else { $step = 2 }
        if ($u + 1 -gt $maxu -or $b + $step -gt $maxb) { break }
        $u++; $b += $step; $i += $step
    }
    if ($i -gt $n) { $i = $n }
    return $s.Substring(0, $i)
}

# json_trim (JSON_TRIM): JSON-escaped string content cut to $maxU characters
# and $maxB bytes without splitting an escape or a UTF-8 sequence; control
# characters become spaces. -Base keeps only the last path component (cwd).
function Limit-Json([string]$s, [int64]$maxU, [int64]$maxB, [switch]$Base) {
    if ($Base) {
        while ($s.Length -gt 0) {
            if ($s.EndsWith('/', $Ord)) { $s = $s.Substring(0, $s.Length - 1) }
            elseif ($s.Length -ge 2 -and $s.EndsWith('\\', $Ord)) { $s = $s.Substring(0, $s.Length - 2) }
            else { break }
        }
        $p = 0
        $k = 0
        while ($k -lt $s.Length) {
            $c = [int]$s[$k]
            if ($c -eq 47) { $p = $k + 1 }
            elseif ($c -eq 92 -and $k + 1 -lt $s.Length -and [int]$s[$k + 1] -eq 92) { $p = $k + 2; $k++ }
            elseif ($c -eq 92) { $k++ }
            $k++
        }
        $s = $s.Substring([Math]::Min($p, $s.Length))
    }
    $sb = New-Object System.Text.StringBuilder
    $n = $s.Length
    $i = 0
    $u = 0
    $b = 0
    while ($i -lt $n -and $u -lt $maxU) {
        $c = [int]$s[$i]
        $step = 1
        $unit = [string]$s[$i]
        if ($c -eq 92) {
            if ($i + 1 -ge $n) { break }
            $e = [int]$s[$i + 1]
            $step = 2
            if ($e -eq 117) {
                $v = Get-Hex4 $s ($i + 2)
                if ($v -lt 0) { break }
                $unit = $s.Substring($i, 6)
                $step = 6
                if ($v -ge 55296 -and $v -le 56319) {
                    $v2 = -1
                    if ($i + 8 -le $n -and $s.Substring($i + 6, 2) -ceq '\u') { $v2 = Get-Hex4 $s ($i + 8) }
                    if ($v2 -ge 56320 -and $v2 -le 57343) { $unit = $s.Substring($i, 12); $step = 12 } else { $unit = ' ' }
                } elseif ($v -ge 56320 -and $v -le 57343) { $unit = ' ' }
                elseif ($v -lt 32 -or ($v -ge 127 -and $v -le 159) -or $v -eq 8232 -or $v -eq 8233) { $unit = ' ' }
            } elseif ($e -eq 34 -or $e -eq 92 -or $e -eq 47) { $unit = $s.Substring($i, 2) }
            else { $unit = ' ' }
        } elseif ($c -ge 194 -and $c -le 244) {
            # Well-formed UTF-8 only (sh: as NOTIFY_TEXT): no overlong forms, no
            # encoded surrogates, nothing past U+10FFFF.
            if ($c -lt 224) { $w = 2 } elseif ($c -lt 240) { $w = 3 } else { $w = 4 }
            $lo = 128; $hi = 191
            if ($c -eq 224) { $lo = 160 } elseif ($c -eq 237) { $hi = 159 } elseif ($c -eq 240) { $lo = 144 } elseif ($c -eq 244) { $hi = 143 }
            $ok = $true
            for ($j = 1; $ok -and $j -lt $w; $j++) {
                if ($i + $j -ge $n) { $ok = $false } else {
                    $x = [int]$s[$i + $j]
                    if ($j -eq 1) { if ($x -lt $lo -or $x -gt $hi) { $ok = $false } }
                    elseif ($x -lt 128 -or $x -gt 191) { $ok = $false }
                }
            }
            if ($ok) {
                $unit = $s.Substring($i, $w)
                $step = $w
                if ($c -eq 194 -and [int]$s[$i + 1] -lt 160) { $unit = ' ' }
            } else { $unit = ' ' }
        } elseif ($c -lt 32 -or $c -ge 127) { $unit = ' ' }
        if ($b + $unit.Length -gt $maxB) { break }
        [void]$sb.Append($unit)
        $b += $unit.Length
        $u++
        $i += $step
    }
    return $sb.ToString()
}

# json_text: plain text (a byte string: our own config files, command-line
# arguments) as JSON string content: control characters dropped, \ and "
# escaped, then cut as Limit-Json.
function ConvertTo-JsonB([string]$text, [int64]$maxU, [int64]$maxB, [switch]$Base) {
    $t = [regex]::Replace([string]$text, '[\x00-\x1F\x7F]', '').Replace('\', '\\').Replace('"', '\"')
    return (Limit-Json $t $maxU $maxB -Base:$Base)
}

# Text of a `simpleterm notify` notification, as notify_text in agent-hook.sh:
# the terminal (OSC 777) and the `notify` event get the same text. Whitespace
# runs, line breaks included (TAB LF VT FF CR, NEL, U+2028, U+2029), become
# one space; other control characters (C0, DEL, C1) and lone surrogates (the
# UTF-16 form of invalid UTF-8) are removed; `;`, the OSC 777 field
# separator, becomes `,`; leading and trailing spaces go; then it is cut to
# $maxU characters and $maxB UTF-8 bytes, between characters and not after a
# space. (.NET text in, .NET text out.)
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
    return ($null -ne $s -and $s.Length -eq $len -and $s -cmatch '\A[0-9a-f]+\z')
}

function Test-UInt([string]$s) {
    return ($null -ne $s -and $s -cmatch '\A[0-9]{1,12}\z')
}

# is_id: the section 3 id format.
function Test-Id([string]$s) {
    return ($null -ne $s -and $s -cmatch '\A[A-Za-z0-9._:-]+\z' -and $s.Length -le 128)
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
    $hash = $sha.ComputeHash($Latin1.GetBytes($text))
    $sha.Dispose()
    return (ConvertTo-Hex $hash)
}

function Get-HmacHex([string]$keyHex, [string]$message) {
    $h = New-Object System.Security.Cryptography.HMACSHA256 (, (ConvertFrom-Hex $keyHex))
    $mac = $h.ComputeHash($Latin1.GetBytes($message))
    $h.Dispose()
    return (ConvertTo-Hex $mac)
}

# Compares two MACs in constant time.
function Test-SameHex([string]$a, [string]$b) {
    if ($a.Length -ne $b.Length) { return $false }
    $diff = 0
    for ($i = 0; $i -lt $a.Length; $i++) { $diff = $diff -bor ([int]$a[$i] -bxor [int]$b[$i]) }
    return ($diff -eq 0)
}

# Returns the section 5.2 envelope JSON of plaintext $plain (a byte string)
# for $link, or $null.
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
    $pb = $Latin1.GetBytes($plain)
    $ct = [Convert]::ToBase64String($enc.TransformFinalBlock($pb, 0, $pb.Length))
    $enc.Dispose()
    $aes.Dispose()
    $mac = Get-HmacHex $link.mac ('st1.' + $iv + '.' + $ct)
    return '{"v":1,"iv":"' + $iv + '","ct":"' + $ct + '","mac":"' + $mac + '"}'
}

# Opens a decision extension (section 5.1): its plaintext (the first 4096
# bytes, line breaks dropped) or '' if it does not decrypt.
function Open-Dext($link, [string]$iv, [string]$ct) {
    try {
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key = ConvertFrom-Hex $link.enc
        $aes.IV = ConvertFrom-Hex $iv
        $dec = $aes.CreateDecryptor()
        $cb = [Convert]::FromBase64String($ct)
        $pb = $dec.TransformFinalBlock($cb, 0, $cb.Length)
        $dec.Dispose()
        $aes.Dispose()
        $n = [Math]::Min(4096, $pb.Length)
        return $Latin1.GetString($pb, 0, $n).Replace("`n", '').Replace("`r", '')
    } catch { return '' }
}

# --- links -----------------------------------------------------------------

# Loads one link file; $null if it is unusable (load_link).
function Read-Link([string]$file) {
    try {
        $info = New-Object IO.FileInfo($file)
        if (-not $info.Exists) { return $null }
        if ($info.Length -gt 4096) { Write-Log 'link-skip too-large'; return $null }
        $link = @{ v = ''; relay = ''; link = ''; secret = ''; enc = ''; mac = ''; label = ''; kind = ''; fmt = ''; file = $file }
        $text = $Latin1.GetString([IO.File]::ReadAllBytes($file))
        foreach ($line in $text.Split([char]10)) {
            if ($line.Length -gt 512) { continue }
            if ($line.EndsWith("`r", $Ord)) { $line = $line.Substring(0, $line.Length - 1) }
            foreach ($k in @('v', 'relay', 'link', 'secret', 'enc', 'mac', 'label', 'kind', 'fmt')) {
                if ($line.StartsWith($k + '=', $Ord)) { $link[$k] = $line.Substring($k.Length + 1); break }
            }
        }
        if ($link.v -cne '1') { Write-Log 'link-skip version'; return $null }
        # kind=tunnel: the app's end of its SSH connection on a loopback port.
        if ($link.kind -cne 'tunnel') { $link.kind = '' }
        # fmt=2: the receiver takes decision extensions and decidable questions
        # (TDS_AGENT_EVENTS_V2 section 1.2). Anything else is an older receiver.
        if ($link.fmt -cne '2') { $link.fmt = '' }
        if (-not ((Test-Hex $link.link 32) -and (Test-Hex $link.secret 64) -and (Test-Hex $link.enc 64) -and (Test-Hex $link.mac 64))) {
            Write-Log 'link-skip fields'; return $null
        }
        $relay = $link.relay
        if ($relay.EndsWith('/', $Ord)) { $relay = $relay.Substring(0, $relay.Length - 1) }
        $ok = ($relay -cmatch '\A[A-Za-z0-9.:/_~%-]+\z') -and
            (($relay -cmatch '\Ahttps://.') -or ($relay -cmatch '\Ahttp://(127\.0\.0\.1|localhost)([:/]|\z)'))
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
    $all = [IO.Directory]::GetFiles($LinksDir, '*.conf')
    [Array]::Sort($all, [StringComparer]::Ordinal)
    foreach ($f in $all) {
        $name = [IO.Path]::GetFileName($f)
        if (-not $name.EndsWith('.conf', $Ord)) { continue }
        if (-not (Test-Hex $name.Substring(0, $name.Length - 5) 32)) { continue }
        $files += $f
        if ($files.Count -ge $MaxLinks) { break }
    }
    return $files
}

# conf_val: the value of $key in ~/.simpleterm/agent-hook.conf (section 9.2
# D21, its first 4 KiB; a UTF-8 BOM at the start of the file is dropped):
# the first line `key=value` of that key decides,
# blanks allowed around the line and the `=`. From the value a CR, a comment
# (from the first `#`), the blanks around it and one pair of quotes around all
# of it are taken away. Empty: the default.
function Get-ConfVal([string]$key) {
    $path = Join-Path $StDir 'agent-hook.conf'
    $blank = [char[]]@([char]32, [char]9)
    try {
        if ([IO.File]::Exists($path)) {
            $text = Read-HeadB $path 4096
            # A UTF-8 BOM at the start of the file is dropped (TDS_AGENT_ALERTS
            # section 6.7; conf_val).
            if ($text.StartsWith([string][char]0xEF + [char]0xBB + [char]0xBF, $Ord)) { $text = $text.Substring(3) }
            foreach ($line in $text.Split([char]10)) {
                $e = $line.IndexOf('=')
                if ($e -lt 0 -or $line.Substring(0, $e).Trim($blank) -cne $key) { continue }
                $v = $line.Substring($e + 1).Replace([string][char]13, '')
                $h = $v.IndexOf('#')
                if ($h -ge 0) { $v = $v.Substring(0, $h) }
                $v = $v.Trim($blank)
                if ($v.Length -ge 2 -and ($v[0] -eq [char]34 -or $v[0] -eq [char]39) -and $v[$v.Length - 1] -eq $v[0]) { $v = $v.Substring(1, $v.Length - 2) }
                return $v
            }
        }
    } catch { }
    return ''
}

# conf_int: key=digits from ~/.simpleterm/agent-hook.conf, or the default.
function Get-ConfInt([string]$key, [int64]$default) {
    $v = Get-ConfVal $key
    if (Test-UInt $v) { return [int64]$v }
    return $default
}

# What the hook does with each key (TDS_AGENT_ALERTS section 6.7; as in
# agent-hook.sh): the device-wait cap of agent $agent (<agent>_wait, at most
# 540; conf_wait_cap).
function Get-ConfWaitCap([string]$agent) {
    if ($agent -ceq 'codex') { $c = Get-ConfInt 'codex_wait' 60 } else { $c = Get-ConfInt 'claude_wait' 540 }
    if ($c -gt 540) { $c = 540 }
    return $c
}

# One long-poll's seconds: poll_wait 1 to 25, else 25 (conf_poll_wait).
function Get-ConfPollWait {
    $c = Get-ConfInt 'poll_wait' 25
    if ($c -lt 1 -or $c -gt 25) { $c = 25 }
    return $c
}

# The seconds a done of agent $agent waits (done_delay; 3, Codex 0;
# conf_done_delay).
function Get-ConfDoneDelay([string]$agent) {
    $c = 3
    if ($agent -ceq 'codex') { $c = 0 }
    return (Get-ConfInt 'done_delay' $c)
}

# True unless usage (the v1 key) is 0 (conf_usage_on).
function Test-ConfUsageOn {
    return -not ((Get-ConfInt 'usage' 1) -eq 0)
}

# --- HTTP ------------------------------------------------------------------

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch { }
# Every link long-polls at once (several may share the relay's host): .NET
# Framework allows 2 connections per host by default, and a third request
# would queue behind a 25-second poll. No 100-continue round trip either.
try {
    [Net.ServicePointManager]::DefaultConnectionLimit = 64
    [Net.ServicePointManager]::Expect100Continue = $false
} catch { }

# Starts an asynchronous request ($body: a byte string); Complete-Relay
# finishes it. Nothing secret goes on a command line: the bearer token is a
# request header.
function Start-Relay($link, [string]$method, [string]$path, [string]$body, [int]$timeoutSec) {
    $op = @{ req = $null; ar = $null; until = [DateTime]::UtcNow.AddSeconds($timeoutSec); link = $link; failed = $false }
    try {
        $req = [System.Net.HttpWebRequest]::Create($link.relay + $path)
        $op.req = $req
        $req.Method = $method
        $req.AllowAutoRedirect = $false
        $req.UserAgent = 'simpleterm-hook/1'
        $req.Timeout = $timeoutSec * 1000
        $req.ReadWriteTimeout = $timeoutSec * 1000
        $req.Headers['Authorization'] = 'Bearer ' + $link.link + '.' + $link.secret
        if ($method -eq 'POST') {
            $bytes = $Latin1.GetBytes($body)
            $req.ContentType = 'application/json'
            $req.ContentLength = $bytes.Length
            $stream = $req.GetRequestStream()
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Close()
        }
        $op.ar = $req.BeginGetResponse($null, $null)
    } catch {
        $op.failed = $true
    }
    return $op
}

function Test-RelayDone($op) {
    if ($op.failed) { return $true }
    if ($op.ar.IsCompleted) { return $true }
    if ([DateTime]::UtcNow -gt $op.until) { try { $op.req.Abort() } catch { } ; return $true }
    return $false
}

# Waits for the request and returns @{ code; body } (code 0 on failure; the
# first $max bytes of the body as a byte string).
function Complete-Relay($op, [int]$max) {
    if ($max -le 0) { $max = 4096 }
    while (-not (Test-RelayDone $op)) { Start-Sleep -Milliseconds 50 }
    if ($op.failed) { return @{ code = 0; body = '' } }
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
        $buf = New-Object byte[] $max
        $total = 0
        while ($total -lt $buf.Length) {
            $n = $stream.Read($buf, $total, $buf.Length - $total)
            if ($n -le 0) { break }
            $total += $n
        }
        $body = $Latin1.GetString($buf, 0, $total)
    } catch { }
    try { $resp.Close() } catch { }
    return @{ code = $code; body = $body }
}

function Short([string]$id) { return $id.Substring(0, 8) }

function Format-Code([int]$code) { return $code.ToString('000', $Inv) }

# --- event format v2: the spec (V2_SPEC) -------------------------------------------

# The v2 fields of an event (TDS_AGENT_EVENTS_V2 section 3) as spec lines
# `path TAB o|a|s|r TAB value`, from the facts and `@.<key>` parameters
# (strings, JSON-escaped): common fields, the request (section 4; rkind names
# how this agent asked), the end of a turn (section 6.1), a state (6.2) or a
# result (5.6). Lines starting with # are notes for the waiting hook (#smap:
# the original index of each Claude scope). The port of V2_SPEC in
# agent-hook.sh, for the request kinds of the agents this hook serves.
function SpFs([string]$p) {
    $t = $null
    if ($Script:SFT.TryGetValue($p, [ref]$t) -and $t -cne 'r') { return $Script:SFV[$p] }
    return ''
}

function SpFr([string]$p) {
    $t = $null
    if ($Script:SFT.TryGetValue($p, [ref]$t) -and $t -ceq 'r' -and $Script:SFV[$p] -cne 'null') { return $Script:SFV[$p] }
    return ''
}

function SpIn([string]$p) { return $Script:SFT.ContainsKey($p) }
function SpP([string]$k) { return (SpFs ('@.' + $k)) }
function SpOut([string]$p, [string]$t, [string]$v) { $Script:SOut.Add($p + $Tab + $t + $Tab + $v) }
function SpS([string]$p, [string]$v, [bool]$keep) { if ($v.Length -gt 0) { SpOut $p 's' (ConvertTo-Norm $v $keep) } }
function SpR([string]$p, [string]$v) { if ($v.Length -gt 0) { SpOut $p 'r' $v } }
function SpB([string]$p, [string]$v) { if ($v -ceq 'true' -or $v -ceq 'false') { SpOut $p 'r' $v } }
function SpO([string]$p) { SpOut $p 'o' '' }
function SpA([string]$p) { SpOut $p 'a' '' }

# The first non-empty string fact among the comma list of paths.
function SpFirst([string]$list) {
    foreach ($p in $list.Split(',')) {
        $x = SpFs $p
        if ($x.Length -gt 0) { return $x }
    }
    return ''
}

function Split-Words([string]$list) {
    return @(([string]$list).Split([char[]]@([char]32, [char]9, [char]10), [StringSplitOptions]::RemoveEmptyEntries))
}

# A list of decision ids as a JSON array at path p.
function SpIds([string]$p, [string]$list) {
    $l = Split-Words $list
    if ($l.Count -eq 0) { return }
    SpA $p
    $m = 0
    foreach ($x in $l) { SpOut ($p + '.' + $m) 's' $x; $m++ }
}

function Test-InList([string]$list, [string]$v) { return (' ' + $list + ' ').Contains(' ' + $v + ' ') }

function SpAskShell([string]$cmd, [string]$desc) { SpO 'req.ask'; SpS 'req.ask.cmd' $cmd $true; SpS 'req.ask.desc' $desc $true }
function SpAskPath([string]$p) { SpO 'req.ask'; SpS 'req.ask.path' $p $true }
function SpAskWeb([string]$url, [string]$prompt) { SpO 'req.ask'; SpS 'req.ask.url' $url $true; SpS 'req.ask.prompt' $prompt $true }
function SpAskMcp([string]$server, [string]$tool, [string]$a) { SpO 'req.ask'; SpS 'req.ask.server' $server $true; SpS 'req.ask.tool' $tool $true; SpS 'req.ask.args' $a $false }
function SpAskText([string]$t) { if ($t.Length -eq 0) { return }; SpO 'req.ask'; SpS 'req.ask.text' $t $true }

# mcp__<server>__<tool> (Claude, Codex) or <server>__<tool> (Grok): MS, MT.
function SpMcpSplit([string]$name, [string]$pre) {
    $Script:MS = ''
    $Script:MT = ''
    $r = ''
    if ($name.Length -gt $pre.Length) { $r = $name.Substring($pre.Length) }
    $k = $r.IndexOf('__', $Ord)
    if ($k -lt 0) { return $false }
    $Script:MS = $r.Substring(0, $k)
    $Script:MT = $r.Substring($k + 2)
    return ($Script:MS.Length -gt 0 -and $Script:MT.Length -gt 0)
}

# Questions under prefix qp (qp.N...), with the field names of the agent.
function SpAskQs([string]$qp, [string]$fq, [string]$fh, [string]$fm, [string]$fopt, [string]$fl, [string]$fd, [bool]$free, [string]$multitrue) {
    SpO 'req.ask'
    SpA 'req.ask.qs'
    $n = 0
    for ($k = 0; $k -lt 64; $k++) {
        $base = $qp + '.' + $k
        if (-not (SpIn ($base + '.' + $fq)) -and -not (SpIn ($base + '.' + $fh)) -and -not (SpIn ($base + '.' + $fopt + '.0.' + $fl)) -and -not (SpIn ($base + '.' + $fopt + '.0'))) { break }
        $q = 'req.ask.qs.' + $n
        SpO $q
        SpS ($q + '.q') (SpFs ($base + '.' + $fq)) $true
        SpS ($q + '.h') (SpFs ($base + '.' + $fh)) $true
        $m = SpFr ($base + '.' + $fm)
        if ($m.Length -eq 0 -and $multitrue.Length -gt 0 -and (SpFs ($base + '.' + $fm)) -ceq $multitrue) { $m = 'true' }
        if ($m -ceq 'true') { SpOut ($q + '.multi') 'r' 'true' } else { SpOut ($q + '.multi') 'r' 'false' }
        if ($free -or (SpFr ($base + '.custom')) -ceq 'true') { SpOut ($q + '.free') 'r' 'true' } else { SpOut ($q + '.free') 'r' 'false' }
        SpA ($q + '.opts')
        for ($j = 0; $j -lt 64; $j++) {
            $ob = $base + '.' + $fopt + '.' + $j
            if ($fl.Length -gt 0 -and (SpIn ($ob + '.' + $fl))) { $l = SpFs ($ob + '.' + $fl) }
            elseif (SpIn $ob) { $l = SpFs $ob }
            else { break }
            SpO ($q + '.opts.' + $j)
            SpS ($q + '.opts.' + $j + '.l') $l $true
            if ($fl.Length -gt 0) { SpS ($q + '.opts.' + $j + '.d') (SpFs ($ob + '.' + $fd)) $true }
        }
        $n++
    }
    $Script:NQ = $n
}

# Codex apply_patch: the files it touches, lines added and removed.
function SpAskCodexPatch([string]$t) {
    SpO 'req.ask'
    $files = New-Object 'System.Collections.Generic.List[string]'
    $add = 0
    $del = 0
    $path = ''
    foreach ($x in $t.Split([string[]]@('\n'), [StringSplitOptions]::None)) {
        if ($x -cmatch '\A\*\*\* (Add|Update|Delete) File: ') {
            $x = $x -creplace '\A\*\*\* (Add|Update|Delete) File: ', ''
            if ($path.Length -eq 0) { $path = $x }
            $files.Add($x)
        } elseif ($x.StartsWith('+', $Ord) -and -not $x.StartsWith('+++', $Ord)) { $add++ }
        elseif ($x.StartsWith('-', $Ord) -and -not $x.StartsWith('---', $Ord)) { $del++ }
    }
    SpS 'req.ask.path' $path $true
    if ($files.Count -gt 1) {
        SpA 'req.ask.files'
        for ($k = 0; $k -lt $files.Count; $k++) { SpS ('req.ask.files.' + $k) $files[$k] $true }
    }
    SpO 'req.ask.change'
    SpOut 'req.ask.change.form' 's' 'patch'
    SpOut 'req.ask.change.fmt' 's' 'codex'
    SpS 'req.ask.change.text' $t $true
    SpOut 'req.ask.add' 'r' ([string]$add)
    SpOut 'req.ask.del' 'r' ([string]$del)
}

function SpChangeReplace([string]$old, [string]$new, [string]$all) {
    SpO 'req.ask.change'
    SpOut 'req.ask.change.form' 's' 'replace'
    SpS 'req.ask.change.old' $old $true
    SpS 'req.ask.change.new' $new $true
    SpB 'req.ask.change.all' $all
}

function SpChangeWrite([string]$content) {
    SpO 'req.ask.change'
    SpOut 'req.ask.change.form' 's' 'write'
    SpS 'req.ask.change.content' $content $true
}

# Claude permission_suggestions -> scopes (addDirectories left out: undoing
# it does not stop the next redirect from asking). SMAP: original indexes.
function SpClaudeScopes {
    $n = 0
    $Script:SMAP = ''
    $Script:SL = @{}
    $Script:SK = @{}
    $Script:SD = @{}
    for ($k = 0; $k -lt 16; $k++) {
        $pre = 'permission_suggestions.' + $k
        if (-not (SpIn ($pre + '.type'))) { break }
        $t = SpFs ($pre + '.type')
        $beh = SpFs ($pre + '.behavior')
        if ($t -ceq 'addDirectories' -or $t -ceq 'removeDirectories') { continue }
        if (($t -ceq 'addRules' -or $t -ceq 'replaceRules') -and $beh.Length -gt 0 -and $beh -cne 'allow') { continue }
        $lab = ''
        if ($t -ceq 'addRules' -or $t -ceq 'replaceRules') {
            for ($j = 0; $j -lt 16; $j++) {
                $x = SpFs ($pre + '.rules.' + $j + '.toolName')
                if ($x.Length -eq 0) { break }
                $rc = SpFs ($pre + '.rules.' + $j + '.ruleContent')
                if ($rc.Length -gt 0) { $x = $x + '(' + $rc + ')' }
                if ($lab.Length -gt 0) { $lab += ', ' }
                $lab += $x
            }
            $Script:SK[$n] = 'rule'
        } elseif ($t -ceq 'setMode') { $lab = SpFs ($pre + '.mode'); $Script:SK[$n] = 'mode' }
        else { $lab = $t; $Script:SK[$n] = 'other' }
        if ($lab.Length -eq 0) { continue }
        $Script:SL[$n] = $lab
        $Script:SD[$n] = SpFs ($pre + '.destination')
        $Script:SMAP += ' ' + $k
        $n++
    }
    $Script:NS = $n
}

function SpScopes {
    if ($Script:NS -eq 0) { return }
    SpA 'req.scopes'
    for ($k = 0; $k -lt $Script:NS; $k++) {
        SpO ('req.scopes.' + $k)
        SpS ('req.scopes.' + $k + '.label') $Script:SL[$k] $true
        SpOut ('req.scopes.' + $k + '.kind') 's' $Script:SK[$k]
        SpS ('req.scopes.' + $k + '.dest') $Script:SD[$k] $true
    }
}

function SpReq([string]$rk) {
    $id = ''
    $win = 'other'
    $tool = ''
    $wait = 'shared'
    $can = ''
    $Script:NS = 0
    $Script:NQ = 0
    $Script:SMAP = ''
    $rid = SpP 'rid'
    if ($rk -ceq 'claude_perm' -or $rk -ceq 'claude_askpre') {
        $tool = SpFs 'tool_name'
        if ($tool -ceq 'Bash') { $win = 'shell' }
        elseif ($tool -ceq 'Edit' -or $tool -ceq 'Write' -or $tool -ceq 'MultiEdit') { $win = 'edit' }
        elseif ($tool -ceq 'WebFetch') { $win = 'web' }
        elseif ($tool.StartsWith('mcp__', $Ord) -and (SpMcpSplit $tool 'mcp__')) { $win = 'mcp' }
        elseif ($tool -ceq 'AskUserQuestion') { $win = 'question' }
        elseif ($tool -ceq 'ExitPlanMode') { $win = 'plan' }
        if ($win -ceq 'question') { $can = 'answer deny deny_reason' }
        elseif ($win -ceq 'plan') { $can = 'plan_approve plan_refine deny' }
        else {
            SpClaudeScopes
            $can = 'allow'
            if ($Script:NS -gt 0) { $can += ' allow_scope' }
            $can += ' deny deny_reason'
        }
    } elseif ($rk -ceq 'claude_notif') {
        $t = SpP 'ntype'
        $wait = 'none'
        if ($t -ceq 'elicitation_dialog') { $win = 'form' } elseif ($t -ceq 'elicitation_url_dialog') { $win = 'login' } else { $win = 'other' }
    } elseif ($rk -ceq 'codex_perm') {
        $tool = SpFs 'tool_name'
        $wait = 'hidden'
        if ($tool -ceq 'Bash') { $win = 'shell' }
        elseif ($tool -ceq 'apply_patch') { $win = 'edit' }
        elseif ($tool.StartsWith('mcp__', $Ord) -and (SpMcpSplit $tool 'mcp__')) { $win = 'mcp' }
        $can = 'allow deny deny_reason'
    } elseif ($rk -ceq 'codex_plan') {
        $win = 'plan'
        $wait = 'none'
    } elseif ($rk -ceq 'grok_notif') {
        $wait = 'none'
        $tool = SpFs 'pre.toolName'
        if (Test-Id (SpFs 'pre.toolUseId')) { $id = SpFs 'pre.toolUseId' }
        $t = SpP 'ntype'
        if ($t -ceq 'plan' -or $tool -ceq 'exit_plan_mode') { $win = 'plan' }
        elseif ($t -ceq 'elicitation_dialog' -or $tool -ceq 'ask_user_question') { $win = 'question' }
        elseif ($tool -ceq 'run_terminal_command' -or $tool -ceq 'run_terminal_cmd' -or $tool -ceq 'Bash') { $win = 'shell' }
        elseif ($tool -ceq 'write' -or $tool -ceq 'search_replace' -or $tool -ceq 'edit_file') { $win = 'edit' }
        elseif ($tool -ceq 'web_fetch') { $win = 'web' }
        elseif ($tool -ceq 'read_file') { $win = 'read' }
        elseif ($tool.Length -gt 0 -and (SpMcpSplit $tool '')) { $win = 'mcp' }
    }
    if ($id.Length -eq 0) { $id = 'st-' + $rid }
    SpO 'req'
    SpOut 'req.id' 's' $id
    SpOut 'req.win' 's' $win
    SpS 'req.tool' $tool $true
    SpOut 'req.wait' 's' $wait
    # what is asked
    if ($rk -ceq 'claude_perm' -or $rk -ceq 'claude_askpre') {
        if ($win -ceq 'shell') { SpAskShell (SpFs 'tool_input.command') (SpFs 'tool_input.description') }
        elseif ($win -ceq 'edit') {
            SpAskPath (SpFs 'tool_input.file_path')
            if ($tool -ceq 'Edit') { SpChangeReplace (SpFs 'tool_input.old_string') (SpFs 'tool_input.new_string') (SpFr 'tool_input.replace_all') }
            elseif ($tool -ceq 'Write') { SpChangeWrite (SpFs 'tool_input.content') }
        }
        elseif ($win -ceq 'web') { SpAskWeb (SpFs 'tool_input.url') (SpFs 'tool_input.prompt') }
        elseif ($win -ceq 'mcp') { SpAskMcp $Script:MS $Script:MT (SpFs 'tool_input') }
        elseif ($win -ceq 'question') { SpAskQs 'tool_input.questions' 'question' 'header' 'multiSelect' 'options' 'label' 'description' $true '' }
        elseif ($win -ceq 'plan') { SpO 'req.ask'; SpS 'req.ask.text' (SpFs 'tool_input.plan') $true; SpS 'req.ask.file' (SpFs 'tool_input.planFilePath') $true }
        else { SpAskText (SpFirst 'tool_input.description,tool_input.command,tool_input.file_path,tool_input.url,tool_input.prompt') }
    } elseif ($rk -ceq 'claude_notif') {
        $t = SpFs 'message'
        if ($win -ceq 'other') { SpAskText $t }
        elseif ($t.Length -gt 0) { SpO 'req.ask'; SpS 'req.ask.msg' $t $true }
    } elseif ($rk -ceq 'codex_perm') {
        if ($win -ceq 'shell') { SpAskShell (SpFs 'tool_input.command') (SpFs 'tool_input.description') }
        elseif ($win -ceq 'edit') { SpAskCodexPatch (SpFs 'tool_input.command') }
        elseif ($win -ceq 'mcp') { SpAskMcp $Script:MS $Script:MT (SpFs 'tool_input') }
        else { SpAskText (SpFirst 'tool_input.description,tool_input.command') }
    } elseif ($rk -ceq 'codex_plan') { SpAskText (SpP 'plan') }
    elseif ($rk -ceq 'grok_notif') {
        if ($win -ceq 'shell') { SpAskShell (SpFs 'pre.toolInput.command') (SpFs 'pre.toolInput.description') }
        elseif ($win -ceq 'edit' -or $win -ceq 'read') { SpAskPath (SpFirst 'pre.toolInput.file_path,pre.toolInput.path,pre.toolInput.target_file') }
        elseif ($win -ceq 'web') { SpAskWeb (SpFs 'pre.toolInput.url') (SpFs 'pre.toolInput.prompt') }
        elseif ($win -ceq 'mcp') { SpAskMcp $Script:MS $Script:MT (SpFs 'pre.toolInput') }
        elseif ($win -ceq 'question' -and (SpIn 'pre.toolInput.questions.0.question')) { SpAskQs 'pre.toolInput.questions' 'question' 'header' 'multiSelect' 'options' 'label' 'description' $false '' }
        else { SpAskText (SpFs 'message') }
    }
    # what may be decided (the full list; the builder narrows it per link)
    SpIds 'req.can' $can
    SpScopes
    if ($win -ceq 'plan' -and $rk -ceq 'claude_perm') { SpA 'req.modes'; SpOut 'req.modes.0' 's' 'default'; SpOut 'req.modes.1' 's' 'accept_edits' }
    if ($Script:SMAP.Length -gt 0) { SpOut '#smap' 's' $Script:SMAP }
}

function SpBgKind([string]$t) {
    if ($t -ceq 'subagent' -or $t -ceq 'shell' -or $t -ceq 'monitor' -or $t -ceq 'workflow' -or $t -ceq 'teammate') { return $t }
    if ($t -ceq 'cloud session') { return 'cloud' }
    if ($t -ceq 'MCP task') { return 'mcp_task' }
    return 'other'
}

function SpTurn {
    SpO 'turn'
    SpS 'turn.end' (SpP 'end') $false
    SpS 'turn.by' (SpP 'by') $false
    SpB 'turn.asks' (SpP 'asks')
    SpS 'turn.last' (SpP 'last') $true
    SpB 'turn.late' (SpP 'late')
    SpB 'turn.hook' (SpP 'hook')
    $bp = SpP 'bgp'
    if ($bp.Length -gt 0 -and ((SpIn ($bp + '.0.type')) -or (SpIn ($bp + '.0.id')))) {
        SpA 'turn.bg'
        $n = 0
        for ($k = 0; $k -lt 64; $k++) {
            $base = $bp + '.' + $k
            if (-not (SpIn ($base + '.type')) -and -not (SpIn ($base + '.id'))) { break }
            $t = SpFs ($base + '.type')
            if ($t -ceq 'dream' -or $t -ceq 'auto-mode scan' -or $t -ceq 'memory import' -or $t -ceq 'memory save') { continue }
            $q = 'turn.bg.' + $n
            SpO $q
            $id = SpFs ($base + '.id')
            if ($id -cmatch '\A[A-Za-z0-9_-]+\z' -and $id.Length -le 64) { SpOut ($q + '.id') 's' $id } else { $id = '' }
            SpOut ($q + '.kind') 's' (SpBgKind $t)
            SpS ($q + '.name') (SpFirst ($base + '.agent_type,' + $base + '.agentType')) $true
            SpS ($q + '.desc') (SpFs ($base + '.description')) $true
            SpS ($q + '.cmd') (SpFs ($base + '.command')) $true
            if ($id.Length -gt 0) { if (Test-InList (SpP 'prev') $id) { SpOut ($q + '.new') 'r' 'false' } else { SpOut ($q + '.new') 'r' 'true' } }
            if ($t -ceq 'shell') { if (Test-InList (SpP 'svc') ([string]$k)) { SpOut ($q + '.svc') 'r' 'true' } else { SpOut ($q + '.svc') 'r' 'false' } }
            SpS ($q + '.st') (SpFs ($base + '.status')) $true
            $n++
        }
    }
    $cp = SpP 'cronp'
    if ($cp.Length -gt 0 -and (SpIn ($cp + '.0.schedule'))) {
        SpA 'turn.crons'
        for ($k = 0; $k -lt 64 -and (SpIn ($cp + '.' + $k + '.schedule')); $k++) {
            SpO ('turn.crons.' + $k)
            SpS ('turn.crons.' + $k + '.sched') (SpFs ($cp + '.' + $k + '.schedule')) $true
            SpS ('turn.crons.' + $k + '.prompt') (SpFs ($cp + '.' + $k + '.prompt')) $true
        }
    }
    SpS 'turn.goal' (SpP 'goal') $false
}

# The spec of the input text (facts, then @-parameter lines): the first line
# of each path counts. Returns the spec lines joined with line breaks.
function Get-Spec([string]$text) {
    $Script:SFT = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::Ordinal)
    $Script:SFV = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::Ordinal)
    $Script:SOut = New-Object 'System.Collections.Generic.List[string]'
    $Script:MS = ''
    $Script:MT = ''
    $recs = $text.Split([char]10)
    $nr = $recs.Length
    if ($nr -gt 0 -and $recs[$nr - 1].Length -eq 0) { $nr-- }
    for ($r = 0; $r -lt $nr; $r++) {
        $line = $recs[$r]
        $t1 = $line.IndexOf([char]9)
        if ($t1 -lt 0) { $p = $line; $t = ''; $v = '' }
        else {
            $p = $line.Substring(0, $t1)
            $t2 = $line.IndexOf([char]9, $t1 + 1)
            if ($t2 -lt 0) { $t = $line.Substring($t1 + 1); $v = '' } else { $t = $line.Substring($t1 + 1, $t2 - $t1 - 1); $v = $line.Substring($t2 + 1) }
        }
        if (-not $Script:SFT.ContainsKey($p)) { $Script:SFT[$p] = $t; $Script:SFV[$p] = $v }
    }
    SpOut 'fmt' 'r' '2'
    SpS 'pv' (SpP 'pv') $false
    SpS 'av' (SpP 'av') $false
    SpS 'avs' (SpP 'avs') $false
    SpS 'sid' (SpP 'sid') $false
    SpS 'tid' (SpP 'tid') $false
    if ((SpP 'sub.id').Length -gt 0) {
        SpO 'sub'
        SpS 'sub.id' (SpP 'sub.id') $false
        SpS 'sub.type' (SpP 'sub.type') $true
        SpS 'sub.name' (SpP 'sub.name') $true
        SpS 'sub.parent' (SpP 'sub.parent') $false
        SpB 'sub.bg' (SpP 'sub.bg')
    }
    SpS 'dir' (SpP 'dir') $false
    if ((SpP 'cfg.var').Length -gt 0 -and (SpP 'cfg.path').Length -gt 0) { SpO 'cfg'; SpS 'cfg.var' (SpP 'cfg.var') $false; SpS 'cfg.path' (SpP 'cfg.path') $false }
    SpS 'pm' (SpP 'pm') $false
    SpS 'mux' (SpP 'mux') $false
    SpR 'tms' (SpP 'tms')
    if ((SpP 'rkind').Length -gt 0) { SpReq (SpP 'rkind') }
    if ((SpP 'turn') -ceq '1') { SpTurn }
    SpS 'st' (SpP 'st') $false
    if ((SpP 'res.scope').Length -gt 0) {
        SpO 'res'
        foreach ($k in @('scope', 'req', 'rrid', 'out', 'act', 'win')) { SpS ('res.' + $k) (SpP ('res.' + $k)) $false }
    }
    return ($Script:SOut -join "`n")
}

# --- event format v2: the plaintext of one link (V2_BUILD) ---------------------------

# Builds the plaintext for one link from the v1 fields and the spec
# (TDS_AGENT_EVENTS_V2 sections 2.1, 2.2, 3): the link's variant of the
# request (section 4.3), then the field limits and the deterministic cuts of
# section 2.2, the same bytes as agent-hook.sh. Returns @{ plain; meta } (meta:
# the META line, then the spec's notes).
function New-PlainV2($link, [string]$rid, [string]$ev, [string]$nonce) {
    $kind = 'relay'
    if ($link.kind -ceq 'tunnel') { $kind = 'tunnel' }
    $fmt2 = ($link.fmt -ceq '2')
    $dec = ($nonce.Length -gt 0)
    $vx = ''
    if ($ev -ceq 'done') { $vx = [string]$Script:XFlags }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('=rid' + $Tab + $rid + $Nl + '=ev' + $Tab + $ev + $Nl + '=app' + $Tab + $Script:App + $Nl)
    [void]$sb.Append('=host' + $Tab + (ConvertTo-JsonB $link.label 100000 100000) + $Nl + '=cwd' + $Tab + $Script:CwdBaseF + $Nl)
    if (-not $Script:NoMsg) { [void]$sb.Append('=msg' + $Tab + $Script:MsgF + $Nl) }
    # A usage event's own fields: v1 ones (ctx, lims, plan) after cwd, uq and
    # cost before ts (section 9.1).
    if ($ev -ceq 'usage') { [void]$sb.Append('=uv1' + $Tab + [string]$Script:UsageJson + $Nl + '=uv2' + $Tab + [string]$Script:UsageV2 + $Nl) }
    [void]$sb.Append('=xflags' + $Tab + $vx + $Nl + '=nonce' + $Tab + $nonce + $Nl + '=ts' + $Tab + $Script:Ts + $Nl)
    [void]$sb.Append([string]$Script:Spec + $Nl)
    $recs = $sb.ToString().Split([char]10)
    $nr = $recs.Length
    if ($nr -gt 0 -and $recs[$nr - 1].Length -eq 0) { $nr-- }

    $V1 = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::Ordinal)
    $notes = New-Object 'System.Collections.Generic.List[string]'
    $NP = New-Object 'System.Collections.Generic.List[string]'
    $NT = New-Object 'System.Collections.Generic.List[string]'
    $NV = New-Object 'System.Collections.Generic.List[string]'
    $NK = New-Object 'System.Collections.Generic.List[string]'
    $CH = New-Object 'System.Collections.Generic.List[object]'
    $ND = New-Object 'System.Collections.Generic.List[bool]'
    $IDX = New-Object 'System.Collections.Generic.Dictionary[string,int]' ([StringComparer]::Ordinal)
    $NP.Add(''); $NT.Add('o'); $NV.Add(''); $NK.Add(''); $CH.Add((New-Object 'System.Collections.Generic.List[int]')); $ND.Add($false)
    for ($r = 0; $r -lt $nr; $r++) {
        $line = $recs[$r]
        $t1 = $line.IndexOf([char]9)
        if ($line.StartsWith('=', $Ord)) {
            if ($t1 -lt 0) { $V1[$line.Substring(1)] = '' } else { $V1[$line.Substring(1, $t1 - 1)] = $line.Substring($t1 + 1) }
            continue
        }
        if ($line.StartsWith('#', $Ord)) { $notes.Add($line); continue }
        if ($t1 -lt 0) { $p = $line; $t = ''; $v = '' }
        else {
            $p = $line.Substring(0, $t1)
            $t2 = $line.IndexOf([char]9, $t1 + 1)
            if ($t2 -lt 0) { $t = $line.Substring($t1 + 1); $v = '' } else { $t = $line.Substring($t1 + 1, $t2 - $t1 - 1); $v = $line.Substring($t2 + 1) }
        }
        if ($IDX.ContainsKey($p)) { continue }
        $k = $p.LastIndexOf('.')
        $par = ''
        if ($k -ge 0) { $par = $p.Substring(0, $k) }
        if ($par.Length -gt 0 -and -not $IDX.ContainsKey($par)) { continue }
        $pi = 0
        if ($par.Length -gt 0) { $pi = $IDX[$par] }
        if ($NT[$pi] -cne 'o' -and $NT[$pi] -cne 'a') { continue }
        $id = $NP.Count
        $IDX[$p] = $id
        $NP.Add($p); $NT.Add($t); $NV.Add($v); $NK.Add($p.Substring($k + 1)); $CH.Add((New-Object 'System.Collections.Generic.List[int]')); $ND.Add($false)
        $CH[$pi].Add($id)
    }

    function GetV1([string]$k) { $x = $null; if ($V1.TryGetValue($k, [ref]$x)) { return $x }; return '' }
    function BKill([int]$i) {
        $stack = New-Object 'System.Collections.Generic.Stack[int]'
        $stack.Push($i)
        while ($stack.Count -gt 0) {
            $x = $stack.Pop()
            if ($ND[$x]) { continue }
            $ND[$x] = $true
            foreach ($c in $CH[$x]) { $stack.Push($c) }
        }
    }
    function BLive([int]$i) { $n = 0; foreach ($c in $CH[$i]) { if (-not $ND[$c]) { $n++ } }; return $n }
    function BLastLive([int]$i) { for ($k = $CH[$i].Count - 1; $k -ge 0; $k--) { if (-not $ND[$CH[$i][$k]]) { return $CH[$i][$k] } }; return 0 }
    function BNode([string]$p) { $x = 0; if ($IDX.TryGetValue($p, [ref]$x) -and -not $ND[$x]) { return $x }; return 0 }
    function BSer([int]$i) {
        $t = $NT[$i]
        if ($t -ceq 's') { return '"' + $NV[$i] + '"' }
        if ($t -ceq 'r') { return $NV[$i] }
        $o = ($t -ceq 'o')
        $x = New-Object System.Text.StringBuilder
        if ($o) { [void]$x.Append('{') } else { [void]$x.Append('[') }
        $f = $true
        foreach ($c in $CH[$i]) {
            if ($ND[$c]) { continue }
            if (-not $f) { [void]$x.Append(',') }
            if ($o) { [void]$x.Append('"' + $NK[$c] + '":') }
            [void]$x.Append((BSer $c))
            $f = $false
        }
        if ($o) { [void]$x.Append('}') } else { [void]$x.Append(']') }
        return $x.ToString()
    }
    # The cut record (section 2.2 step 6).
    $CK = New-Object 'System.Collections.Generic.List[string]'
    $CV = New-Object 'System.Collections.Generic.List[string]'
    $CDEAD = New-Object 'System.Collections.Generic.List[bool]'
    $REC = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    $cs = @{ clive = 0; plus = 0 }
    function BRec([string]$path, $val) {
        if (-not $REC.Add($path)) { return }
        if ($cs.plus -gt 0 -or $cs.clive -ge 16) { $cs.plus++; return }
        $CK.Add($path); $CV.Add([string]$val); $CDEAD.Add($false); $cs.clive++
    }
    function BUnrec([string]$path) {
        $pre = $path + '.'
        for ($k = 0; $k -lt $CK.Count; $k++) {
            if ($CDEAD[$k]) { continue }
            if ($CK[$k].StartsWith($pre, $Ord)) { $CDEAD[$k] = $true; $cs.clive-- }
        }
    }
    function BCut {
        if ($cs.clive -eq 0 -and $cs.plus -eq 0) { return '' }
        $x = ',"cut":{'
        $f = $true
        for ($k = 0; $k -lt $CK.Count; $k++) {
            if ($CDEAD[$k]) { continue }
            if (-not $f) { $x += ',' }
            $x += '"' + $CK[$k] + '":' + $CV[$k]
            $f = $false
        }
        if ($cs.plus -gt 0) { if (-not $f) { $x += ',' }; $x += '"+":' + $cs.plus }
        return $x + '}'
    }
    function BPlain {
        $x = New-Object System.Text.StringBuilder
        [void]$x.Append('{"v":1,"rid":"' + (GetV1 'rid') + '","ev":"' + (GetV1 'ev') + '","app":"' + (GetV1 'app') + '","host":"' + $vs.host + '","cwd":"' + $vs.cwd + '"')
        if ($V1.ContainsKey('title')) { [void]$x.Append(',"title":"' + $vs.title + '"') }
        if ($V1.ContainsKey('msg')) { [void]$x.Append(',"msg":"' + $vs.msg + '"') }
        [void]$x.Append((GetV1 'uv1'))
        [void]$x.Append((GetV1 'xflags'))
        if ($dec -and (GetV1 'nonce').Length -gt 0) { [void]$x.Append(',"nonce":"' + (GetV1 'nonce') + '"') }
        foreach ($c in $CH[0]) {
            if (-not $ND[$c]) { [void]$x.Append(',"' + $NK[$c] + '":' + (BSer $c)) }
        }
        [void]$x.Append((BCut))
        [void]$x.Append((GetV1 'uv2'))
        [void]$x.Append(',"ts":' + (GetV1 'ts') + '}')
        return $x.ToString()
    }
    function BSize { return (BPlain).Length }
    # Removes decision id d from req.can, or keeps only those in list.
    function BNoCan([string]$d) {
        $i = BNode 'req.can'
        if (-not $i) { return }
        foreach ($c in $CH[$i]) { if (-not $ND[$c] -and $NV[$c] -ceq $d) { BKill $c } }
    }
    function BCanKeep([string]$list) {
        $i = BNode 'req.can'
        if (-not $i) { return }
        foreach ($c in $CH[$i]) { if (-not $ND[$c] -and -not (Test-InList $list $NV[$c])) { BKill $c } }
    }
    function BDrop([string]$p) { $i = BNode $p; if ($i) { BKill $i } }
    function BGPath([string]$p) {
        $q = $p.Split('.')
        for ($k = 0; $k -lt $q.Length; $k++) { if ($q[$k] -cmatch '\A[0-9]+\z') { $q[$k] = '#' } }
        return ($q -join '.')
    }
    function BV1Cut([string]$key, [string]$v, [int64]$mu, [int64]$mb) {
        $c = Get-UCut $v $mu $mb
        if ($c.Length -lt $v.Length) { BRec $key $v.Length }
        return $c
    }

    # Section 2.2 field limits: "tunnel relay" bytes (- not sent to the relay),
    # CNT the same for arrays.
    $STR = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::Ordinal)
    $CNT = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::Ordinal)
    $STR['dir'] = '1024 -'; $STR['cfg'] = '0 -'; $STR['cfg.path'] = '1024 -'
    $STR['avs'] = '0 -'; $STR['tid'] = '0 -'; $STR['pm'] = '0 -'; $STR['tms'] = '0 -'; $STR['req.nid'] = '0 -'
    $STR['req.tool'] = '128 128'; $STR['req.ask.cmd'] = '8192 400'; $STR['req.ask.desc'] = '1024 200'
    $STR['req.ask.path'] = '1024 256'; $STR['req.ask.file'] = '1024 256'; $STR['req.ask.files.#'] = '1024 256'
    $STR['req.ask.change'] = '0 -'; $STR['req.ask.change.old'] = '12288 -'; $STR['req.ask.change.new'] = '12288 -'
    $STR['req.ask.change.content'] = '24576 -'; $STR['req.ask.change.text'] = '24576 -'
    $STR['req.ask.url'] = '2048 400'; $STR['req.ask.prompt'] = '1024 -'
    $STR['req.ask.server'] = '128 128'; $STR['req.ask.tool'] = '128 128'; $STR['req.ask.args'] = '4096 -'
    $STR['req.ask.msg'] = '1024 200'; $STR['req.ask.schema'] = '8192 -'
    $STR['req.ask.qs.#.q'] = '400 160'; $STR['req.ask.qs.#.h'] = '64 32'
    $STR['req.ask.qs.#.opts.#.l'] = '200 64'; $STR['req.ask.qs.#.opts.#.d'] = '600 -'
    $STR['req.scopes.#.label'] = '200 80'; $STR['sub.type'] = '64 64'; $STR['sub.name'] = '64 64'
    $STR['turn.last'] = '4000 -'; $STR['turn.bg.#.name'] = '64 32'; $STR['turn.bg.#.desc'] = '200 80'
    $STR['turn.bg.#.cmd'] = '200 80'; $STR['turn.crons'] = '0 -'; $STR['turn.crons.#.sched'] = '64 -'
    $STR['turn.crons.#.prompt'] = '200 -'
    # A plan is long; any other text short.
    $wn = BNode 'req.win'
    if ($wn -and $NV[$wn] -ceq 'plan') { $STR['req.ask.text'] = '24576 600' } else { $STR['req.ask.text'] = '1024 200' }
    $CNT['req.ask.files'] = '32 4'; $CNT['req.ask.qs'] = '8 4'; $CNT['req.ask.qs.#.opts'] = '16 8'
    $CNT['req.scopes'] = '8 4'; $CNT['req.others'] = '32 8'; $CNT['turn.bg'] = '16 3'; $CNT['turn.crons'] = '8 -'
    $li = 1
    if ($kind -ceq 'tunnel') { $li = 0 }

    $budget = 2048
    if ($kind -ceq 'tunnel') { $budget = 32768 }
    # variant of this link (section 4.3)
    if ($Script:WaitOv.Length -gt 0) { $i = BNode 'req.wait'; if ($i) { $NV[$i] = $Script:WaitOv } }
    if (-not $dec) { BDrop 'req.can'; BDrop 'req.scopes'; BDrop 'req.modes'; BDrop 'req.affects'; BDrop 'req.others' }
    elseif (-not $fmt2) {
        $win = ''
        $i = BNode 'req.win'
        if ($i) { $win = $NV[$i] }
        if ($win -ceq 'plan') { BCanKeep 'plan_approve deny'; BDrop 'req.modes' } else { BCanKeep 'allow deny' }
        BDrop 'req.scopes'
        $i = BNode 'req.others'
        if ($i -and (BLive $i) -gt 0) { BCanKeep 'allow' }
        BDrop 'req.affects'
        BDrop 'req.others'
    }
    # step 0: field limits, in serialization order (v1 fields first)
    $vs = @{ host = ''; cwd = ''; title = ''; msg = '' }
    $vs.host = BV1Cut 'host' (ConvertTo-Norm (GetV1 'host') $false) 64 256
    $vs.cwd = BV1Cut 'cwd' (ConvertTo-Norm (GetV1 'cwd') $false) 64 256
    if ($V1.ContainsKey('title')) { $vs.title = BV1Cut 'title' (ConvertTo-Norm (GetV1 'title') $false) 64 256 }
    if ($V1.ContainsKey('msg')) { $vs.msg = BV1Cut 'msg' (ConvertTo-Norm (GetV1 'msg') $false) 200 800 }
    for ($i = 1; $i -lt $NP.Count; $i++) {
        if ($ND[$i]) { continue }
        $g = BGPath $NP[$i]
        $t = $NT[$i]
        if ($t -ceq 'a' -or $t -ceq 'o') {
            if ($kind -ceq 'relay' -and $STR.ContainsKey($g) -and $STR[$g].Split(' ')[$li] -ceq '-') { BKill $i; continue }
            if ($t -ceq 'a' -and $CNT.ContainsKey($g)) {
                $c = $CNT[$g].Split(' ')[$li]
                if ($c -ceq '-') { BKill $i; continue }
                $cn = [int]$c
                $n = 0
                foreach ($cc in $CH[$i]) {
                    if ($ND[$cc]) { continue }
                    $n++
                    if ($n -gt $cn) { BKill $cc }
                }
                if ($n -gt $cn) {
                    BRec $NP[$i] $n
                    if ($g -ceq 'req.ask.qs') { BNoCan 'answer' }
                }
            }
            continue
        }
        if (-not $STR.ContainsKey($g)) { continue }
        $c = $STR[$g].Split(' ')[$li]
        if ($c -ceq '-') { BKill $i; continue }
        $cn = [int]$c
        if ($cn -gt 0 -and $NV[$i].Length -gt $cn) {
            BRec $NP[$i] $NV[$i].Length
            $NV[$i] = Get-UCut $NV[$i] 1000000000 $cn
        }
    }
    $ORIG = @{}
    $ARR = @('req.others', 'turn.bg', 'req.scopes', 'req.ask.qs')
    foreach ($a in $ARR) { $x = 0; if ($IDX.TryGetValue($a, [ref]$x)) { $ORIG[$a] = BLive $x } }
    # step 1: the last item of the first non-empty array
    while ((BSize) -gt $budget) {
        $done = $false
        foreach ($a in $ARR) {
            $i = BNode $a
            if (-not $i -or (BLive $i) -eq 0) { continue }
            $c = BLastLive $i
            BUnrec $NP[$c]
            BKill $c
            BRec $a $ORIG[$a]
            if ($a -ceq 'req.ask.qs') { BNoCan 'answer' }
            if ((BLive $i) -eq 0) {
                if ($a -ceq 'req.scopes') { BKill $i; BNoCan 'allow_scope' }
                if ($a -ceq 'req.others') { BKill $i; BDrop 'req.affects' }
            }
            $done = $true
            break
        }
        if (-not $done) { break }
    }
    # step 2: whole objects
    foreach ($a in @('req.ask', 'req.scopes', 'req.modes', 'turn', 'sub', 'req')) {
        if ((BSize) -le $budget) { break }
        $i = BNode $a
        if (-not $i) { continue }
        $b = (BSer $i).Length
        BUnrec $a
        BKill $i
        BRec $a $b
        if ($a -ceq 'req.ask') { BNoCan 'answer'; BNoCan 'allow_scope' }
        if ($a -ceq 'req.scopes') { BNoCan 'allow_scope' }
    }
    $plain = BPlain
    $m = 'META'
    if (BNode 'req') {
        $x = ''; $i = BNode 'req.id'; if ($i) { $x = $NV[$i] }
        $m += ' rq=' + $x
        $x = ''; $i = BNode 'req.win'; if ($i) { $x = $NV[$i] }
        $m += ' win=' + $x
        foreach ($pair in @(@('can', 'req.can'), @('aff', 'req.affects'))) {
            $l = @()
            $i = BNode $pair[1]
            if ($i) { foreach ($c in $CH[$i]) { if (-not $ND[$c]) { $l += $NV[$c] } } }
            $m += ' ' + $pair[0] + '=' + ($l -join ',')
        }
        $i = BNode 'req.scopes'
        $x = 0; if ($i) { $x = BLive $i }
        $m += ' ns=' + $x
        $l = @()
        $i = BNode 'req.modes'
        if ($i) { foreach ($c in $CH[$i]) { if (-not $ND[$c]) { $l += $NV[$c] } } }
        $m += ' modes=' + ($l -join ',')
        $i = BNode 'req.ask.qs'
        $x = 0; if ($i) { $x = BLive $i }
        $m += ' nq=' + $x
    }
    $meta = New-Object 'System.Collections.Generic.List[string]'
    $meta.Add($m)
    foreach ($x in $notes) { $meta.Add($x) }
    return @{ plain = $plain; meta = $meta }
}

# --- event payload ---------------------------------------------------------

# A file path from the hook input (JSON-escaped byte string) that can be read
# (.NET text), or ''.
function Get-InputFile([string]$raw) {
    if (-not $raw -or $raw -ceq 'null') { return '' }
    $sb = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt $raw.Length; $i++) {
        $c = $raw[$i]
        if ([int]$c -eq 92) {
            if ($i + 1 -ge $raw.Length) { return '' }
            $e = [int]$raw[$i + 1]
            if ($e -ne 92 -and $e -ne 47 -and $e -ne 34) { return '' }
            $c = $raw[$i + 1]
            $i++
        }
        [void]$sb.Append($c)
    }
    $path = US $sb.ToString()
    try { if ([IO.File]::Exists($path)) { return $path } } catch { }
    return ''
}

# MSG (v1, cut) and MSGF (whole: the v2 builder cuts it and records the cut,
# TDS_AGENT_EVENTS_V2 section 2.2) from JSON-escaped text (setmsg).
function Set-Msg([string]$text) {
    $Script:MsgF = $text
    $Script:Msg = Limit-Json $text 200 800
}

# The section 5.2 (v1) plaintext for $link: notify and test, and every event
# before the v2 fields are prepared (a usage event has them: Send-Usage).
# `usage` carries UsageJson instead of a message; `notify` adds a title.
function New-PlainV1($link, [string]$rid, [string]$ev, [string]$nonce) {
    $hostText = ConvertTo-JsonB $link.label 64 256
    $p = '{"v":1,"rid":"' + $rid + '","ev":"' + $ev + '","app":"' + $Script:App + '","host":"' + $hostText + '","cwd":"' + $Script:CwdBase + '"'
    if ($ev -ceq 'usage') { $p += $Script:UsageJson }
    elseif ($ev -ceq 'notify') { $p += ',"title":"' + $Script:Title + '","msg":"' + $Script:Msg + '"' }
    else { $p += ',"msg":"' + $Script:Msg + '"' }
    # A done of a Stop that another Stop hook had already kept going.
    if ($ev -ceq 'done' -and $Script:XFlags) { $p += $Script:XFlags }
    if ($nonce) { $p += ',"nonce":"' + $nonce + '"' }
    return $p + ',"ts":' + $Script:Ts + '}'
}

function Get-Plaintext($link, [string]$rid, [string]$ev, [string]$nonce) {
    $Script:LastMeta = $null
    if ($ev -cne 'notify' -and $ev -cne 'test' -and $Script:V2) {
        $r = New-PlainV2 $link $rid $ev $nonce
        $Script:LastMeta = $r.meta
        return $r.plain
    }
    return (New-PlainV1 $link $rid $ev $nonce)
}

# Builds and seals one event for one link (ingest_raw, up to the send):
# @{ link; ev; meta; body; mt } or, if it cannot be sealed, @{ seal }.
# IngMt caps the relay's time (the tunnel's is 5).
function New-Ingest($link, [string]$rid, [string]$ev, [string]$nonce) {
    $nh = ''
    if ($nonce) { $nh = Get-Sha256Hex $nonce }
    $pt = Get-Plaintext $link $rid $ev $nonce
    $meta = $Script:LastMeta
    # Test only: the plaintext before it is sealed, to compare the sh and the
    # PowerShell hook byte for byte (TDS_AGENT_EVENTS_V2 section 2.2): one
    # file per event and link in directory SIMPLETERM_HOOK_TEST_PLAIN.
    if ($env:SIMPLETERM_HOOK_TEST -eq '1' -and $env:SIMPLETERM_HOOK_TEST_PLAIN -and [IO.Directory]::Exists($env:SIMPLETERM_HOOK_TEST_PLAIN)) {
        [void](Write-FileB (Join-Path $env:SIMPLETERM_HOOK_TEST_PLAIN ((Short $link.link) + '.' + $ev + '.' + $rid + '.' + $PID)) $pt)
    }
    $envJson = $null
    if ($pt) { $envJson = New-Envelope $pt $link }
    if ($null -eq $envJson) {
        Write-Log ('seal-failed link=' + (Short $link.link))
        return @{ seal = $true; link = $link; ev = $ev; meta = $meta }
    }
    $body = '{"v":1,"rid":"' + $rid + '","ev":"' + $ev + '"'
    if ($nh) { $body += ',"nh":"' + $nh + '"' }
    $body += ',"env":' + $envJson + '}'
    # A tunnel answers at once or not at all (a dead port may belong to
    # something else by now); the relay may hold the request a few seconds.
    $mt = [string]$Script:IngMt
    if (-not $mt) { $mt = '20' }
    if (-not (Test-UInt $mt) -or [int64]$mt -lt 1) { $mt = '1' }
    $t = [int64]$mt
    if ($t -gt 20) { $t = 20 }
    if ($link.kind -ceq 'tunnel' -and $t -gt 5) { $t = 5 }
    return @{ seal = $false; link = $link; ev = $ev; meta = $meta; body = $body; mt = [int]$t }
}

# Sends a built event; Complete-Ingest finishes it.
function Start-IngestOp($prep) {
    if ($prep.seal) { return $prep }
    $op = Start-Relay $prep.link 'POST' '/v1/ingest' $prep.body $prep.mt
    $op.ev = $prep.ev
    $op.meta = $prep.meta
    $op.seal = $false
    return $op
}

function Start-Ingest($link, [string]$rid, [string]$ev, [string]$nonce) {
    return (Start-IngestOp (New-Ingest $link $rid $ev $nonce))
}

# Finishes an ingest: @{ push (the push result or http<code>); code (3 digits); err }.
function Complete-Ingest($op) {
    if ($op.seal) { return @{ push = 'seal'; code = '000'; err = '-' } }
    $r = Complete-Relay $op 4096
    $push = ''
    $err = ''
    if ($r.code -eq 200) { $push = [regex]::Replace((Get-Field (Get-JsonKV $r.body @('push')) 'push'), '[^a-z-]', '') }
    elseif ($r.code -eq 410) { [void](Write-FileB (Join-Path $RunDir ($op.link.link + '.revoked')) '') }
    elseif ($r.code -eq 400) { $err = [regex]::Replace((Get-Field (Get-JsonKV $r.body @('error')) 'error'), '[^a-zA-Z-]', '') }
    $code = Format-Code $r.code
    # The last event to a tunnel and its answer: a usage ask needs the app
    # connected (an HTTP 200 within 10 minutes, section 9.2).
    if ($op.link.kind -ceq 'tunnel') { [void](Write-FileB (Join-Path $RunDir ('tun.' + (Short $op.link.link) + '.last')) ([string](Now-Epoch) + ' ' + $code + "`n")) }
    $shown = $push
    if (-not $shown) { $shown = '-' }
    Write-Log ('ingest ev=' + $op.ev + ' link=' + (Short $op.link.link) + ' http=' + $code + ' push=' + $shown)
    if (-not $push) { $push = 'http' + $code }
    if (-not $err) { $err = '-' }
    return @{ push = $push; code = $code; err = $err }
}

# Sends event $ev to every link (tunnels first: the app reports a shown event
# to the relay, which holds a push for a few seconds to hear that), $scope
# `all`, `tunnel` or `relay`; once a link took the event, $markText goes to the
# run file $markName. The body of send_bg (here in the detached child).
function Send-Now([string]$ev, [string]$rid, [string]$scope, [string]$markName, [string]$markText) {
    # Every link's event is made first, then sent: tunnels, then the relay.
    $preps = @{ tunnel = (New-Object 'System.Collections.Generic.List[object]'); relay = (New-Object 'System.Collections.Generic.List[object]') }
    foreach ($file in (Get-LinkFiles)) {
        $link = Read-Link $file
        if ($null -eq $link) { continue }
        $pass = 'relay'
        if ($link.kind -ceq 'tunnel') { $pass = 'tunnel' }
        if ($scope -cne 'all' -and $scope -cne $pass) { continue }
        try { $preps[$pass].Add((New-Ingest $link $rid $ev '')) } catch { Write-Log 'ingest-failed' }
    }
    foreach ($pass in @('tunnel', 'relay')) {
        $ops = New-Object 'System.Collections.Generic.List[object]'
        foreach ($prep in $preps[$pass]) {
            try { $ops.Add((Start-IngestOp $prep)) } catch { Write-Log 'ingest-failed' }
        }
        foreach ($op in $ops) {
            try {
                $r = Complete-Ingest $op
                if ($r.code -ceq '200' -and $markName) { [void](Write-FileB (Join-Path $RunDir $markName) ($markText + "`n")) }
            } catch { Write-Log 'ingest-failed' }
        }
    }
}

# --- detached sends ------------------------------------------------------------

# A send that outlives the hook (sh: a background subshell) runs in a detached
# child process (agent-hook.ps1 <agent> __send <job>). The job file in the run
# directory holds what it needs (each value base64 of its bytes): the event's
# fields, facts and spec, so that a later send can make the event again.
function New-Job([string]$kind) {
    return @{
        kind = $kind; agent = $Script:Agent; app = $Script:App; sid = $Script:Sid; now = [string]$Script:Now
        ts = [string]$Script:Ts; rid = [string]$Script:Rid; v2 = $(if ($Script:V2) { '1' } else { '' })
        spec = [string]$Script:Spec; facts = [string]$Script:FactsText; at = [string]$Script:AT; v2x = [string]$Script:V2X
        msgf = [string]$Script:MsgF; nomsg = $(if ($Script:NoMsg) { '1' } else { '' }); xflags = [string]$Script:XFlags
        waitov = [string]$Script:WaitOv; cwdbasef = [string]$Script:CwdBaseF; cwdbase = [string]$Script:CwdBase
        msg = [string]$Script:Msg; title = [string]$Script:Title; usage = [string]$Script:UsageJson; reqid = [string]$Script:ReqId
        usagev2 = [string]$Script:UsageV2
    }
}

function Save-Job([hashtable]$job) {
    $name = 'job.' + $PID + '.' + (New-RandomHex 4)
    $sb = New-Object System.Text.StringBuilder
    foreach ($k in $job.Keys) { [void]$sb.Append([string]$k + '=' + [Convert]::ToBase64String($Latin1.GetBytes([string]$job[$k])) + "`n") }
    if (-not (Write-FileB (Join-Path $RunDir $name) $sb.ToString())) { return '' }
    return $name
}

function Read-Job([string]$name) {
    if ($name -cnotmatch '\Ajob\.[0-9]+\.[0-9a-f]{8}\z') { return $null }
    $path = Join-Path $RunDir $name
    $t = Read-FileB $path
    Remove-FileQ $path
    if ($null -eq $t) { return $null }
    $job = @{}
    foreach ($line in $t.Split([char]10)) {
        $k = $line.IndexOf('=')
        if ($k -lt 1) { continue }
        try { $job[$line.Substring(0, $k)] = $Latin1.GetString([Convert]::FromBase64String($line.Substring($k + 1))) } catch { }
    }
    return $job
}

function Start-Child([hashtable]$job) {
    $name = Save-Job $job
    if (-not $name) { return }
    $exe = (Get-Process -Id $PID).Path
    $argList = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $PSCommandPath + '"'), $Script:Agent0, '__send', $name)
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
        Remove-FileQ (Join-Path $RunDir $name)
    }
}

# send_bg: event $ev to every link (scope all|tunnel|relay) from a detached
# child; returns at once.
function Send-Background([string]$ev, [string]$eventRid, [string]$scope, [string]$markName, [string]$markText) {
    if ($Script:LinkFiles.Count -eq 0) { return }
    if (-not $eventRid) { $eventRid = $Script:Rid }
    # One rid per event: a receiver shows a rid once (Send-State takes a new
    # one when this run's rid went out already).
    if ($eventRid -ceq $Script:Rid) { $Script:RidUsed = $true }
    if (-not $eventRid) { return }
    if (-not $scope) { $scope = 'all' }
    $job = New-Job 'send'
    $job.ev = $ev
    $job.rid = $eventRid
    $job.scope = $scope
    $job.mark = $markName
    $job.marktext = $markText
    Start-Child $job
}

# Sends `done` (or $ev) later from the child: after $wait seconds, if line $line
# of file $file still holds $token (a pending done, a pause or a goal turn not
# ended meanwhile) and, for a goal, the rollout $path got no task_started after
# $offset. The event is made then (fresh rid and time).
function Start-LaterSend([string]$kind, [int64]$wait, [string]$file, [int]$line, [string]$token, [string]$path, [int64]$offset) {
    if ($Script:LinkFiles.Count -eq 0) { return }
    $job = New-Job 'later'
    $job.ev = 'done'
    $job.scope = 'all'
    $job.lkind = $kind
    $job.lwait = [string]$wait
    $job.lfile = BS $file
    $job.lline = [string]$line
    $job.ltoken = $token
    $job.lpath = BS $path
    $job.loff = [string]$offset
    Start-Child $job
}

function Restore-Job($job) {
    $Script:Agent = $job.agent
    $Script:App = $job.app
    $Script:Sid = $job.sid
    $Script:Now = 0
    if (Test-UInt $job.now) { $Script:Now = [int64]$job.now }
    $Script:Ts = $job.ts
    $Script:Rid = $job.rid
    $Script:V2 = ($job.v2 -ceq '1')
    $Script:Spec = $job.spec
    $Script:FactsText = $job.facts
    $Script:AT = $job.at
    $Script:V2X = $job.v2x
    $Script:MsgF = $job.msgf
    $Script:NoMsg = ($job.nomsg -ceq '1')
    $Script:XFlags = $job.xflags
    $Script:WaitOv = $job.waitov
    $Script:CwdBaseF = $job.cwdbasef
    $Script:CwdBase = $job.cwdbase
    $Script:Msg = $job.msg
    $Script:Title = $job.title
    $Script:UsageJson = $job.usage
    $Script:UsageV2 = [string]$job.usagev2
    $Script:ReqId = $job.reqid
    $Script:IngMt = ''
    $Script:InputB = ''
    $Script:LinkFiles = @(Get-LinkFiles)
}

function Test-LaterStillDue($job) {
    if (-not (Test-UInt $job.lwait) -or -not (Test-UInt $job.lline) -or -not (Test-UInt $job.loff)) { return $false }
    $file = US $job.lfile
    # The token is this run's rid, never written again once replaced: a wait
    # that another event ended stops at once instead of sleeping out (a
    # PowerShell process is not a cheap sleeper).
    $until = [DateTime]::UtcNow.AddSeconds([int]$job.lwait)
    while ($true) {
        $left = ($until - [DateTime]::UtcNow).TotalMilliseconds
        if ($left -le 0) { break }
        Start-Sleep -Milliseconds ([int][Math]::Min($left, 2000))
        if ((Read-LineB $file ([int]$job.lline)) -cne $job.ltoken) { return $false }
    }
    try {
        if ((Read-LineB $file ([int]$job.lline)) -cne $job.ltoken) { return $false }
        if ($job.lkind -ceq 'goal') {
            $path = US $job.lpath
            $fs = [IO.File]::Open($path, 'Open', 'Read', 'ReadWrite')
            try {
                [void]$fs.Seek([int64]$job.loff, 'Begin')
                $rest = (New-Object IO.StreamReader($fs, $Latin1)).ReadToEnd()
            } finally { $fs.Dispose() }
            if ($rest.Contains('"type":"task_started"')) { return $false }
        }
        [IO.File]::Delete($file)
    } catch { return $false }
    return $true
}

# later_send: the event made now (fresh rid, time and, v2, tms) and sent.
function Send-Later([string]$ev, [string]$scope) {
    $Script:Now = Now-Epoch
    $Script:Ts = [string]$Script:Now
    $Script:Rid = New-RandomHex 8
    if (-not (Test-Hex $Script:Rid 16)) { return }
    # v2: the event's time again (tms).
    if ($Script:V2) { Update-Spec ($Script:V2X + '@.tms' + $Tab + 's' + $Tab + (Get-Tms) + $Nl) }
    if (-not $scope) { $scope = 'all' }
    Send-Now $ev $Script:Rid $scope '' ''
}

function Invoke-Child([string]$name) {
    $job = Read-Job $name
    if ($null -eq $job) { return }
    Restore-Job $job
    switch -CaseSensitive ([string]$job.kind) {
        'send' {
            $mark = [string]$job.mark
            if ($mark -cnotmatch '\A[A-Za-z0-9_-]{1,80}\.usage\z') { $mark = '' }
            if ($job.ev -cnotmatch '\A[a-z]{1,16}\z' -or -not (Test-Hex $job.rid 16) -or -not (Test-UInt $job.ts)) { return }
            Send-Now $job.ev $job.rid $job.scope $mark ([string]$job.marktext)
        }
        'later' { if (Test-LaterStillDue $job) { Send-Later $job.ev $job.scope } }
        'state' {
            Start-Sleep -Seconds 1
            $f = (Read-LineB (Join-Path $RunDir ($Script:Sid + '.st')) 0).Split(' ')
            if ($f.Length -ge 3 -and $f[2] -ceq $job.rid) { Send-Later 'state' 'tunnel' }
        }
        'ask' {
            if (Test-UInt $job.wait) { Start-Sleep -Seconds ([int]$job.wait) }
            if (Test-Once ([string]$job.key)) { Send-Now 'question' $Script:Rid 'all' '' '' }
        }
        'resolved' {
            foreach ($item in ([string]$job.items).Split([char]10)) {
                $x = $item.Split([char]9)
                if ($x.Length -lt 5) { continue }
                Send-Result (Read-Link (US $x[0])) $x[1] $x[2] $x[3] $x[4]
            }
        }
        'ver' { Invoke-VerChild $job }
        'askver' { Invoke-AskVerChild $job }
        'uask' { Invoke-AskChild $job }
    }
}

# --- event format v2: the common fields --------------------------------------------

# Adds the @-parameter $k (JSON-escaped value $v, nothing if empty).
function Add-At([string]$k, [string]$v) {
    if ($v.Length -gt 0) { $Script:AT += '@.' + $k + $Tab + 's' + $Tab + $v + $Nl }
}

# The facts of the event, once.
function Initialize-Facts {
    if ($Script:FactsText) { return }
    $Script:FactsText = (Get-Facts $Script:InputB '') -join "`n"
}

# The raw text of container $p of the event (an answer hands it back).
function Get-RawSpan([string]$p) { return [string](Get-Facts $Script:InputB $p) }

# SPEC from the facts, AT and the extra parameter lines; V2 on.
function Update-Spec([string]$extra) {
    Initialize-Facts
    $Script:Spec = Get-Spec ([string]$Script:FactsText + "`n" + $Script:AT + $extra)
    $Script:V2 = $true
}

# The agent's version for a cached `--version` (D13): its executable's path and
# the version, in run/ver.<name>; run again by a child when the executable is
# newer than the cache or moved. The first dotted number of the output is taken.
function Update-VerCache([string]$name) {
    try {
        $cmd = @(Get-Command -Name $name -CommandType Application -ErrorAction SilentlyContinue)
        if ($cmd.Count -eq 0) { return }
        $vb = [string]$cmd[0].Path
        if (-not $vb -or -not [IO.Path]::IsPathRooted($vb)) { return }
        $vc = Join-Path $RunDir ('ver.' + $name)
        $vp = Read-LineB $vc 0
        if ($vp -ceq (BS $vb)) { $Script:AV = Read-LineB $vc 1 }
        if ($vp -ceq (BS $vb) -and -not ([IO.File]::GetLastWriteTimeUtc($vb) -gt [IO.File]::GetLastWriteTimeUtc($vc))) { return }
        try {
            $fs = New-Object IO.FileStream(($vc + '.lock'), [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
            $fs.Dispose()
        } catch { return }
        $job = New-Job 'ver'
        $job.vname = $name
        $job.vb = BS $vb
        Start-Child $job
    } catch { }
}

function Invoke-VerChild($job) {
    $name = [string]$job.vname
    if ($name -cnotmatch '\A[a-z]{1,16}\z') { return }
    $vc = Join-Path $RunDir ('ver.' + $name)
    try {
        $vb = US $job.vb
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $vb
        $psi.Arguments = '--version'
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $psi.RedirectStandardInput = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $p = [System.Diagnostics.Process]::Start($psi)
        $p.StandardInput.Close()
        $out = $p.StandardOutput.ReadToEndAsync()
        $err = $p.StandardError.ReadToEndAsync()
        if (-not $p.WaitForExit(15000)) { try { $p.Kill() } catch { } }
        $text = ''
        if ($out.Wait(2000)) { $text = BS ([string]$out.Result) }
        if ($text.Length -gt 4096) { $text = $text.Substring(0, 4096) }
        $v = ''
        foreach ($line in $text.Split([char]10)) {
            $m = [regex]::Match($line, '[0-9]+[.][0-9]+[0-9A-Za-z.+_-]*')
            if ($m.Success) { $v = $m.Value; break }
        }
        if ($v -cmatch '\A[0-9A-Za-z.+_-]+\z') {
            if (Write-FileB ($vc + '.tmp') ($job.vb + "`n" + $v + "`n")) {
                Remove-FileQ $vc
                [IO.File]::Move(($vc + '.tmp'), $vc)
            }
        }
    } catch { }
    Remove-FileQ ($vc + '.tmp')
    Remove-FileQ ($vc + '.lock')
}

# A JSON line -> the string value of its top-level key "version", or ''
# (TOP_VERSION in agent-hook.sh).
function Get-TopVersion([string]$s) {
    $last = $s.LastIndexOf('"version"', [StringComparison]::Ordinal)
    if ($last -lt 0) { return '' }
    # Scanned up to just past the last "version" (no key there after it).
    $n = [Math]::Min($s.Length, $last + 80)
    $marks = [char[]]@([char]34, [char]123, [char]125, [char]91, [char]93, [char]58, [char]44)
    $d = 0
    $st = ''
    $key = ''
    $i = 0
    while ($i -lt $n) {
        $i = $s.IndexOfAny($marks, $i, $n - $i)
        if ($i -lt 0) { break }
        $c = $s[$i]
        if ($c -eq [char]34) {
            # A string: to its closing quote (one not escaped).
            $j = $i + 1
            while ($true) {
                if ($j -ge $n) { return '' }
                $j = $s.IndexOfAny([char[]]@([char]34, [char]92), $j, $n - $j)
                if ($j -lt 0) { return '' }
                if ($s[$j] -eq [char]92) { $j += 2; continue }
                break
            }
            if ($d -eq 1 -and $st -ceq 'k') { $key = $s.Substring($i + 1, $j - $i - 1) }
            elseif ($d -eq 1 -and $st -ceq 'v' -and $key -ceq 'version') { return $s.Substring($i + 1, $j - $i - 1) }
            $i = $j + 1
            continue
        }
        if ($c -eq [char]123 -or $c -eq [char]91) {
            $d++
            if ($d -eq 1) { if ($c -eq [char]123) { $st = 'k' } else { $st = '' } }
        } elseif ($c -eq [char]125 -or $c -eq [char]93) {
            $d--
            if ($d -lt 1) { return '' }
        } elseif ($d -eq 1 -and $c -eq [char]58) {
            $st = 'v'
        } elseif ($d -eq 1 -and $c -eq [char]44) {
            $st = 'k'
            $key = ''
        }
        $i++
    }
    return ''
}

# AV and AVS: the agent's version and where it came from (section 10.1).
function Get-AgentVersion {
    $Script:AV = ''
    $Script:AVS = ''
    if ($Script:Agent -ceq 'claude') {
        # The top-level "version" of the last transcript line that has one,
        # in the last 256 KiB (the first line there cut unless the file is
        # shorter): not a "version" inside a tool result or message.
        $vf = Get-InputFile $Script:TPath
        if ($vf) {
            $cut = $false
            try { $cut = ((New-Object IO.FileInfo $vf).Length -gt 262144) } catch { }
            $lines = (Read-TailB $vf 262144).Split([char]10)
            $first = 0
            if ($cut) { $first = 1 }
            for ($j = $lines.Length - 1; $j -ge $first; $j--) {
                if (-not $lines[$j].Contains('"version"')) { continue }
                $v = Get-TopVersion $lines[$j]
                if ($v) { $Script:AV = $v; break }
            }
        }
        $Script:AVS = 'transcript'
    } elseif ($Script:Agent -ceq 'codex') {
        $vf = Get-InputFile $Script:TPath
        if ($vf) {
            $m = [regex]::Match((Read-HeadB $vf 65536), '"cli_version" *: *"([^"\n]*)"')
            if ($m.Success) { $Script:AV = $m.Groups[1].Value }
        }
        $Script:AVS = 'rollout'
    } elseif ($Script:Agent -ceq 'grok') {
        Update-VerCache 'grok'
        $Script:AVS = 'cache'
    }
    if ($Script:AV -cnotmatch '\A[0-9A-Za-z.+_-]+\z' -or $Script:AV.Length -gt 32) { $Script:AV = '' }
}

# Codex: the last turn's approval and sandbox policy from the rollout, as its
# permission mode (`on-request/read-only`).
function Get-CodexPm {
    $vf = Get-InputFile $Script:TPath
    if (-not $vf) { return '' }
    $pm = ''
    foreach ($line in (Read-TailB $vf 262144).Split([char]10)) {
        if (-not $line.Contains('"type":"turn_context"')) { continue }
        $a = ''
        $b = ''
        $m = [regex]::Match($line, '"approval_policy":"([A-Za-z0-9._-]*)"')
        if ($m.Success) { $a = $m.Groups[1].Value }
        $m = [regex]::Match($line, '"sandbox_policy":\{"type":"([A-Za-z0-9._-]*)"')
        if ($m.Success) { $b = $m.Groups[1].Value }
        if ($a) { $pm = $a; if ($b) { $pm += '/' + $b } }
    }
    return $pm
}

# The common fields (section 3) as @-parameters, once per run.
function Initialize-Common {
    if ($Script:V2C) { return }
    $Script:V2C = $true
    Add-At 'pv' $HookVersion
    Get-AgentVersion
    Add-At 'av' $Script:AV
    if ($Script:AV) { Add-At 'avs' $Script:AVS }
    if (Test-Id $Script:RawSid) { Add-At 'sid' $Script:RawSid }
    if (Test-Id $Script:Tid) { Add-At 'tid' $Script:Tid }
    if (Test-Id $Script:SubId) {
        Add-At 'sub.id' $Script:SubId
        Add-At 'sub.type' $Script:SubType
        if (Test-Id $Script:SubPar) { Add-At 'sub.parent' $Script:SubPar }
    }
    if ($Script:DirV -cmatch '\A(/|[A-Za-z]:\\\\)') { Add-At 'dir' $Script:DirV }
    $cv = ''
    $cp = ''
    if ($Script:Agent -ceq 'claude') {
        if ($env:CLAUDE_CONFIG_DIR) { $cv = 'CLAUDE_CONFIG_DIR'; $cp = $env:CLAUDE_CONFIG_DIR }
    } elseif ($Script:Agent -ceq 'codex') {
        if ($env:CODEX_HOME -and -not (Test-DefaultHome $env:CODEX_HOME '.codex')) { $cv = 'CODEX_HOME'; $cp = $env:CODEX_HOME }
    } elseif ($Script:Agent -ceq 'grok') {
        if ($env:GROK_HOME -and -not (Test-DefaultHome $env:GROK_HOME '.grok')) { $cv = 'GROK_HOME'; $cp = $env:GROK_HOME }
    }
    if ($cv -and $cp) {
        Add-At 'cfg.var' $cv
        Add-At 'cfg.path' (ConvertTo-JsonB (BS $cp) 100000 100000)
    }
    if ($Script:Agent -ceq 'codex') { $Script:PMode = Get-CodexPm }
    if ($Script:PMode -cmatch '\A[A-Za-z0-9._:/-]+\z' -and $Script:PMode.Length -le 48) { Add-At 'pm' $Script:PMode }
    if ($env:TMUX) { Add-At 'mux' 'tmux' }
    elseif ($env:STY) { Add-At 'mux' 'screen' }
}

# True if $dir (one trailing / or \ dropped) is ~/<name>.
function Test-DefaultHome([string]$dir, [string]$name) {
    if ($dir.EndsWith('/', $Ord) -or $dir.EndsWith('\', $Ord)) { $dir = $dir.Substring(0, $dir.Length - 1) }
    return ($dir -ceq ($HOME + '/' + $name) -or $dir -ceq (Join-Path $HOME $name))
}

# The event time in milliseconds, for `tms`.
function Get-Tms {
    if ($env:SIMPLETERM_HOOK_TEST -eq '1' -and $env:SIMPLETERM_HOOK_TEST_TMS) { return (BS $env:SIMPLETERM_HOOK_TEST_TMS) }
    $t = [string](Now-Ms)
    if ($t -cmatch '\A[0-9]{13}\z') { return $t }
    return ''
}

# Prepares SPEC for an event: the common fields, `tms`, and the extra
# parameter lines (request kind, end of a turn, state, result).
function Initialize-V2([string]$extra) {
    Initialize-Common
    $Script:V2X = $extra
    Update-Spec ($extra + '@.tms' + $Tab + 's' + $Tab + (Get-Tms) + $Nl)
}

# --- states and results to the tunnel (sections 6.2, 5.6) -----------------------

function Test-HasTunnel {
    foreach ($f in $Script:LinkFiles) {
        if ((Read-HeadB $f 4096).Contains('kind=tunnel')) { return $true }
    }
    return $false
}

# A state event (section 6.2) to the tunnels, when the session's state
# changed, one a second at most (a change within the second goes a second later
# unless another replaced it). A subagent's start or stop is an event of its
# own: sent each time, at once, and it neither replaces a session state nor is
# replaced by one. $extra: extra parameter lines (the turn).
# -Sync sends from this process (the agent is exiting: the send finishes
# before the hook does).
function Send-State([string]$st, [string]$extra, [switch]$Sync) {
    if ($Script:LinkFiles.Count -eq 0 -or -not (Test-HasTunnel)) { return }
    $sub = ($st -ceq 'sub_start' -or $st -ceq 'sub_stop')
    $sf = Join-Path $RunDir ($Script:Sid + '.st')
    $sl = ''
    $sp = -1
    if (-not $sub) {
        $sl = Read-FileB $sf
        if ($null -eq $sl) { $sl = '' }
        $sl = $sl.TrimEnd([char]10)
        $first = $sl
        $sp = $sl.IndexOf(' ')
        if ($sp -ge 0) { $first = $sl.Substring(0, $sp) }
        if ($first -ceq $st) { return }
    }
    $srid = $Script:Rid
    if ($Script:RidUsed) {
        $srid = New-RandomHex 8
        if (-not (Test-Hex $srid 16)) { return }
    }
    if (-not $sub) { [void](Write-FileB $sf ($st + ' ' + $Script:Now + ' ' + $srid + "`n")) }
    $ss = $Script:Spec
    $sx = $Script:V2X
    $sm = $Script:NoMsg
    Initialize-V2 ($extra + '@.st' + $Tab + 's' + $Tab + $st + $Nl)
    $Script:NoMsg = $true
    $f2 = ''
    if ($sp -ge 0) { $f2 = $sl.Split(' ')[1] }
    if ($sp -ge 0 -and $f2 -ceq [string]$Script:Now) {
        if ($Sync) {
            $sr = @($Script:Rid, $Script:Ts, $Script:Now, $Script:Spec)
            Start-Sleep -Seconds 1
            $f = (Read-LineB $sf 0).Split(' ')
            if ($f.Length -ge 3 -and $f[2] -ceq $srid) { Send-Later 'state' 'tunnel' }
            $Script:Rid = $sr[0]; $Script:Ts = $sr[1]; $Script:Now = $sr[2]; $Script:Spec = $sr[3]
        } else {
            $job = New-Job 'state'
            $job.rid = $srid
            Start-Child $job
        }
    } elseif ($Sync) {
        if ($srid -ceq $Script:Rid) { $Script:RidUsed = $true }
        Send-Now 'state' $srid 'tunnel' '' ''
    } else {
        Send-Background 'state' $srid 'tunnel'
    }
    $Script:Spec = $ss
    $Script:V2X = $sx
    $Script:NoMsg = $sm
}

# A result event (section 5.6) to the tunnel $link: scope, out, the request
# event's rid, decision id or window kind. Sent and finished here.
function Send-Result($link, [string]$scope, [string]$out, [string]$rrid, [string]$aw) {
    if ($null -eq $link -or $link.kind -cne 'tunnel') { return }
    $rx = '@.res.scope' + $Tab + 's' + $Tab + $scope + $Nl + '@.res.req' + $Tab + 's' + $Tab + $Script:ReqId + $Nl +
        '@.res.rrid' + $Tab + 's' + $Tab + $rrid + $Nl + '@.res.out' + $Tab + 's' + $Tab + $out + $Nl
    if ($out -ceq 'applied' -and $aw) { $rx += '@.res.act' + $Tab + 's' + $Tab + $aw + $Nl }
    if ($out -ceq 'window' -and $aw) { $rx += '@.res.win' + $Tab + 's' + $Tab + $aw + $Nl }
    $rs = Get-Spec ([string]$Script:FactsText + "`n" + $Script:AT + $rx)
    $save = @($Script:Spec, $Script:NoMsg, $Script:WaitOv, $Script:IngMt, $Script:Ts)
    $Script:Spec = $rs
    $Script:NoMsg = $true
    $Script:WaitOv = ''
    $Script:IngMt = ''
    $Script:Ts = [string](Now-Epoch)
    try {
        $rr = New-RandomHex 8
        if (Test-Hex $rr 16) { [void](Complete-Ingest (Start-Ingest $link $rr 'resolved' '')) }
    } catch { Write-Log 'ingest-failed' }
    $Script:Spec = $save[0]
    $Script:NoMsg = $save[1]
    $Script:WaitOv = $save[2]
    $Script:IngMt = $save[3]
    $Script:Ts = $save[4]
}

# --- session records (section 8.2) --------------------------------------------

# Only sessions started in SimpleTerm (SIMPLETERM=1), with an id that can be
# resumed. The file name is the id, or the start of its SHA-256 when it has
# a `:` (a Windows file name cannot).
function Test-SessOk {
    if ($env:SIMPLETERM -ne '1') { return $false }
    if ($Script:Agent -cne 'claude' -and $Script:Agent -cne 'codex' -and $Script:Agent -cne 'grok') { return $false }
    if (-not (Test-Id $Script:RawSid)) { return $false }
    $Script:SessDir = Join-Path (Join-Path $StDir 'sessions') $Script:App
    if ($Script:RawSid.Contains(':')) { $Script:SessName = (Get-Sha256Hex $Script:RawSid).Substring(0, 32) } else { $Script:SessName = $Script:RawSid }
    $Script:Sess = Join-Path $Script:SessDir $Script:SessName
    return $true
}

function New-SessDir {
    try { if (-not [IO.Directory]::Exists($Script:SessDir)) { [void][IO.Directory]::CreateDirectory($Script:SessDir) } } catch { }
}

function Set-Touch([string]$path) {
    try {
        if ([IO.File]::Exists($path)) { [IO.File]::SetLastWriteTimeUtc($path, [DateTime]::UtcNow) }
        else { [IO.File]::WriteAllBytes($path, (New-Object byte[] 0)) }
        return $true
    } catch { return $false }
}

# The session's last hook event: <name>.beat's modification time (touched when
# 30 seconds old, or always with -Force).
function Update-SessBeat([switch]$Force) {
    if (-not (Test-SessOk)) { return }
    $bt = Join-Path $RunDir ($Script:Sid + '.beatts')
    if (-not $Force) {
        $t = (Read-LineB $bt 0)
        if ((Test-UInt $t) -and ($Script:Now - [int64]$t) -le 30 -and [int64]$t -le $Script:Now -and [IO.File]::Exists($Script:Sess + '.beat')) { return }
    }
    New-SessDir
    if (Set-Touch ($Script:Sess + '.beat')) { [void](Write-FileB $bt ([string]$Script:Now + "`n")) }
}

# The session's title and where it came from (section 10.7): SessTitle
# (JSON-escaped), SessTsrc.
function Get-SessTitle {
    $Script:SessTitle = ''
    $Script:SessTsrc = ''
    $tf = Get-InputFile $Script:TPath
    if ($Script:Agent -ceq 'claude') {
        if ($tf) {
            foreach ($line in (Read-TailB $tf 262144).Split([char]10)) {
                if (-not $line.Contains('"type":"ai-title"')) { continue }
                $m = [regex]::Match($line, '"aiTitle":"((?:[^"\\]|\\.)*)"')
                if ($m.Success) { $Script:SessTitle = $m.Groups[1].Value }
            }
        }
        $Script:SessTsrc = 'ai'
    } elseif ($Script:Agent -ceq 'codex') {
        $ch = $env:CODEX_HOME
        if (-not $ch) { $ch = Join-Path $HOME '.codex' }
        $ci = Join-Path $ch 'session_index.jsonl'
        if ([IO.File]::Exists($ci)) {
            foreach ($line in (Read-TailB $ci 262144).Split([char]10)) {
                if (-not $line.Contains('"id":"' + $Script:RawSid + '"')) { continue }
                $m = [regex]::Match($line, '"thread_name":"((?:[^"\\]|\\.)*)"')
                if ($m.Success) { $Script:SessTitle = $m.Groups[1].Value }
            }
        }
        $Script:SessTsrc = 'ai'
    } elseif ($Script:Agent -ceq 'grok') {
        if ($tf) {
            $sj = Join-Path ([IO.Path]::GetDirectoryName($tf)) 'summary.json'
            if ([IO.File]::Exists($sj)) { $Script:SessTitle = Get-Field (Get-JsonKV (Read-HeadB $sj 65536) @('generated_title')) 'generated_title' }
        }
        $Script:SessTsrc = 'ai'
    }
    if (-not $Script:SessTitle) { $Script:SessTsrc = '' }
}

# Writes the session's record (state running|idle; $prompt): a temp file
# renamed into place, 4096 bytes at most. Keeps started_at, the last prompt and
# a title it cannot find again from the record before.
function Write-SessRecord([string]$state, [string]$prompt) {
    if (-not (Test-SessOk)) { return }
    New-SessDir
    $old = Read-HeadB ($Script:Sess + '.json') 4096
    $ow = $null
    if ($old) { $ow = Get-JsonKV $old @('started_at', 'last_prompt', 'title', 'title_src') }
    $so = ''
    if ($ow) { $so = Get-Field $ow 'started_at' }
    if (-not (Test-UInt $so)) { $so = [string]$Script:Now }
    $lp = Limit-Json $prompt 200 800
    if (-not $lp -and $ow) { $lp = Get-Field $ow 'last_prompt' }
    Get-SessTitle
    $ti = Limit-Json $Script:SessTitle 120 400
    $ts = $Script:SessTsrc
    if (-not $ti) {
        $ti = ''
        $ts = ''
        if ($ow) { $ti = Get-Field $ow 'title'; $ts = Get-Field $ow 'title_src' }
    }
    if (-not $ti -and $lp) { $ti = Limit-Json $lp 120 400; $ts = 'prompt' }
    if ($ts -cne 'ai' -and $ts -cne 'user' -and $ts -cne 'prompt') { $ts = '' }
    if (-not $ts) { $ti = '' }
    $j = '{"v":1,"app":"' + $Script:App + '"'
    if ($Script:AV) { $j += ',"av":"' + $Script:AV + '"' }
    $j += ',"sid":"' + $Script:RawSid + '"'
    if ($Script:DirV -cmatch '\A(/|[A-Za-z]:\\\\)') { $j += ',"dir":"' + (Limit-Json $Script:DirV 100000 1024) + '"' }
    if ($ti) { $j += ',"title":"' + $ti + '","title_src":"' + $ts + '"' }
    if ($lp) { $j += ',"last_prompt":"' + $lp + '"' }
    $j += ',"last_at":' + $Script:Now + ',"started_at":' + $so
    # An absolute path: / or, on Windows, a drive (agent-hook.sh takes / only).
    $tp = Get-InputFile $Script:TPath
    if ($tp -cmatch '\A(/|[A-Za-z]:\\)') { $j += ',"tpath":"' + (ConvertTo-JsonB (BS $tp) 100000 1024) + '"' }
    if ($Script:PMode -cmatch '\A[A-Za-z0-9._:/-]+\z' -and $Script:PMode.Length -le 48) { $j += ',"pm":"' + $Script:PMode + '"' }
    $cvv = ''
    $cpp = ''
    foreach ($line in $Script:AT.Split([char]10)) {
        if ($line.StartsWith('@.cfg.var' + $Tab + 's' + $Tab, $Ord)) { $cvv = $line.Substring(12) }
        elseif ($line.StartsWith('@.cfg.path' + $Tab + 's' + $Tab, $Ord)) { $cpp = $line.Substring(13) }
    }
    if ($cvv -and $cpp) { $j += ',"cfg":{"var":"' + $cvv + '","path":"' + (Limit-Json $cpp 100000 1024) + '"}' }
    $j += ',"state":"' + $state + '"'
    if ($env:TMUX) { $j += ',"mux":"tmux"' } elseif ($env:STY) { $j += ',"mux":"screen"' }
    $j += '}'
    if ($j.Length -gt 4096) { return }
    $tmp = $Script:Sess + '.json.' + $PID
    if (Write-FileB $tmp ($j + "`n")) {
        try {
            if ([IO.File]::Exists($Script:Sess + '.json')) { [IO.File]::Delete($Script:Sess + '.json') }
            [IO.File]::Move($tmp, $Script:Sess + '.json')
        } catch { }
    }
    Remove-FileQ $tmp
    Invoke-SessKeep
}

# A session starts or is resumed: no `.ended` any more.
function Start-Sess {
    if (-not (Test-SessOk)) { return }
    Update-SessBeat -Force
    Remove-FileQ ($Script:Sess + '.ended')
}

# The session ended: `.ended`, unless the record's .beat is newer than this
# event (it was resumed meanwhile: a late end must not mark it ended).
function Stop-Sess([DateTime]$since) {
    if (-not (Test-SessOk)) { return }
    try {
        if ([IO.File]::Exists($Script:Sess + '.beat') -and [IO.File]::GetLastWriteTimeUtc($Script:Sess + '.beat') -gt $since) { return }
    } catch { }
    New-SessDir
    [void](Write-FileB ($Script:Sess + '.ended') '')
}

# Keeps records whose last activity (.beat or the record, the later) is within
# 30 days, 200 at most (D11); at most once in ten minutes.
function Invoke-SessKeep {
    $kf = Join-Path $RunDir 'sessions.keep'
    $t = Read-LineB $kf 0
    if ((Test-UInt $t) -and ($Script:Now - [int64]$t) -lt 600 -and [int64]$t -le $Script:Now) { return }
    [void](Write-FileB $kf ([string]$Script:Now + "`n"))
    try {
        $root = Join-Path $StDir 'sessions'
        if (-not [IO.Directory]::Exists($root)) { return }
        $last = @{}
        foreach ($d in [IO.Directory]::GetDirectories($root)) {
            foreach ($f in [IO.Directory]::GetFiles($d)) {
                if (-not ($f.EndsWith('.json', $Ord) -or $f.EndsWith('.beat', $Ord))) { continue }
                $b = $f.Substring(0, $f.Length - 5)
                $w = [IO.File]::GetLastWriteTimeUtc($f)
                if (-not $last.ContainsKey($b) -or $w -gt $last[$b]) { $last[$b] = $w }
            }
        }
        $now = [DateTime]::UtcNow
        $n = 0
        foreach ($e in ($last.GetEnumerator() | Sort-Object -Property Value -Descending)) {
            $n++
            if ($n -gt 200 -or ($now - $e.Value).TotalDays -ge 31) {
                foreach ($x in @('.json', '.beat', '.ended')) { Remove-FileQ ($e.Key + $x) }
            }
        }
    } catch { }
}

# The session's record at a turn's start (state running, its prompt) or end.
function Write-SessTurn([string]$state, [string]$prompt) {
    if (-not (Test-SessOk)) { return }
    Initialize-Common
    if ($state -ceq 'running') { Start-Sess } else { Update-SessBeat -Force }
    Write-SessRecord $state $prompt
}

# --- terminal sequence (Claude Code only, SimpleTerm sessions only) -------

# $Script:UsageSeq is the JSON-escaped usage OSC to append, if any;
# $Script:BgSeq the hook's OSC 7501 record for background work.
function Write-State([string]$state, [string]$message) {
    if ($Script:Agent -cne 'claude' -or $env:SIMPLETERM -ne '1') { return }
    $m = ''
    if ($message) { $m = ' ' + (Limit-Json $message 80 320) }
    Write-Out ('{"terminalSequence":"\u001b]9;simpleterm:state=' + $state + $m + '\u0007' + $Script:BgSeq + $Script:UsageSeq + '"}')
}

function Write-UsageOnly {
    if ($Script:Agent -cne 'claude' -or $env:SIMPLETERM -ne '1' -or -not $Script:UsageSeq) { return }
    Write-Out ('{"terminalSequence":"' + $Script:UsageSeq + '"}')
}

function Get-StateJson([string]$state) {
    if ($Script:Agent -cne 'claude' -or $env:SIMPLETERM -ne '1') { return '' }
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

# ISO 8601 date-time (YYYY-MM-DDTHH:MM:SS, a fraction, Z or +-HH:MM) to epoch
# seconds; -1 if it is not one (section 9.1 `at`, the windows' resets). The
# port of isoepoch (ISO_FN) in agent-hook.sh, its int() truncations included.
function Get-IsoEpoch([string]$t) {
    if ($t -cnotmatch '\A[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt ][0-9]{2}:[0-9]{2}:[0-9]{2}') { return [int64]-1 }
    $y = [int64]$t.Substring(0, 4); $mo = [int64]$t.Substring(5, 2); $d = [int64]$t.Substring(8, 2)
    $h = [int64]$t.Substring(11, 2); $mi = [int64]$t.Substring(14, 2); $se = [int64]$t.Substring(17, 2)
    $r = [regex]::Replace($t.Substring(19), '\A[.][0-9]+', '')
    $off = [int64]0
    if ($r -ceq 'Z' -or $r -ceq 'z') { $off = [int64]0 }
    elseif ($r -cmatch '\A[+-][0-9][0-9]:?[0-9][0-9]\z') {
        $off = ([int64]$r.Substring(1, 2) * 60 + [int64]$r.Substring($r.Length - 2, 2)) * 60
        if ($r.StartsWith('+', $Ord)) { $off = -$off }
    } else { return [int64]-1 }
    if ($mo -lt 1 -or $mo -gt 12 -or $d -lt 1 -or $d -gt 31 -or $h -gt 23 -or $mi -gt 59 -or $se -gt 59) { return [int64]-1 }
    $yy = $y
    if ($mo -le 2) { $yy = $y - 1 }
    $era = [int64][Math]::Truncate([double]$yy / 400)
    $yoe = $yy - $era * 400
    $mp = $mo + 9
    if ($mo -gt 2) { $mp = $mo - 3 }
    $doy = [int64][Math]::Truncate([double](153 * $mp + 2) / 5) + $d - 1
    $doe = $yoe * 365 + [int64][Math]::Truncate([double]$yoe / 4) - [int64][Math]::Truncate([double]$yoe / 100) + $doy
    return [int64](($era * 146097 + $doe - 719468) * 86400 + $h * 3600 + $mi * 60 + $se + $off)
}

# Minutes from a month before date-time t to t (monthmin: a monthly window,
# Copilot's in agent-hook.sh; no agent of this hook has one).
function Get-MonthMin([string]$t) {
    $e = Get-IsoEpoch $t
    if ($e -lt 0) { return [int64]-1 }
    $y = [int64]$t.Substring(0, 4); $mo = [int64]$t.Substring(5, 2) - 1; $d = [int64]$t.Substring(8, 2)
    if ($mo -lt 1) { $mo = 12; $y-- }
    $md = 31
    if ($mo -eq 2) {
        $md = 28
        if ($y % 4 -eq 0 -and ($y % 100 -ne 0 -or $y % 400 -eq 0)) { $md = 29 }
    } elseif ($mo -eq 4 -or $mo -eq 6 -or $mo -eq 9 -or $mo -eq 11) { $md = 30 }
    if ($d -gt $md) { $d = $md }
    # sprintf("%04d-%02d-%02d", y, mo, d)
    $ys = ([string][Math]::Abs($y))
    if ($y -lt 0) { $ys = '-' + $ys.PadLeft(3, '0') } else { $ys = $ys.PadLeft(4, '0') }
    $b = Get-IsoEpoch ($ys + '-' + ([string]$mo).PadLeft(2, '0') + '-' + ([string]$d).PadLeft(2, '0') + $t.Substring(10))
    return [int64][Math]::Truncate([double]($e - $b) / 60)
}

# A non-negative decimal (digits, a fraction) as micro-units, exactly, by
# string math (micro: Copilot's 100 - pct and OpenCode's USD in
# agent-hook.sh): the digits without leading zeros, or -1 if it is not one.
# And back, without trailing zeros (unmicro: Grok's USD).
function Get-Micro([string]$v) {
    if ($v -cnotmatch '\A[0-9]+([.][0-9]+)?\z') { return '-1' }
    $i = $v
    $f = ''
    $k = $v.IndexOf('.')
    if ($k -ge 0) { $i = $v.Substring(0, $k); $f = $v.Substring($k + 1) }
    $f = ($f + '000000').Substring(0, 6)
    $m = ($i + $f).TrimStart('0')
    if (-not $m) { $m = '0' }
    return $m
}

function Get-Unmicro([string]$m) {
    $m = $m.TrimStart('0')
    if ($m.Length -lt 7) { $m = '0000000'.Substring(0, 7 - $m.Length) + $m }
    $i = $m.Substring(0, $m.Length - 6).TrimStart('0')
    if (-not $i) { $i = '0' }
    $f = $m.Substring($m.Length - 6).TrimEnd('0')
    if ($f) { return $i + '.' + $f }
    return $i
}

$CodexWant = @('timestamp', 'payload.type', 'payload.info.last_token_usage.total_tokens', 'payload.info.model_context_window',
    'payload.rate_limits.limit_id', 'payload.rate_limits.primary.used_percent', 'payload.rate_limits.primary.window_minutes',
    'payload.rate_limits.primary.resets_at', 'payload.rate_limits.secondary.used_percent', 'payload.rate_limits.secondary.window_minutes',
    'payload.rate_limits.secondary.resets_at', 'payload.rate_limits.plan_type', 'payload.rate_limits.rate_limit_reached_type')

# Codex rollout (JSONL) -> a usage line (see Format-UsageLine): the newest
# token_count event with info (context) and the newest with rate limits, its
# windows from the file with the record's time (USAGE_CODEX through tail_awk:
# the last 256 KiB, then the last 2 MiB if that found nothing). Raw JSON
# tokens, as agent-hook.sh passes them on.
function Get-CodexUsageLine([string]$path) {
    $size = (New-Object IO.FileInfo($path)).Length
    $r = ''
    foreach ($lim in @(262144, 2097152)) {
        $skip = ($size -gt $lim)
        $r = Get-CodexUsageTail (Read-TailB $path $lim) $skip
        if ($r -and -not $r.EndsWith(' -', $Ord)) { return $r }
        if (-not $skip) { break }
    }
    return $r
}

function Get-CodexUsageTail([string]$text, [bool]$skip) {
    $recs = $text.Split([char]10)
    $L = New-Object 'System.Collections.Generic.List[string]'
    for ($i = 0; $i -lt $recs.Length; $i++) {
        # A cut first line is skipped.
        if ($i -eq 0 -and $skip) { continue }
        if ($recs[$i].Contains('"token_count"')) { $L.Add($recs[$i]) }
    }
    $ctx = ''; $win = '-'; $rl = $false; $lims = ''; $plan = '-'; $reached = '0'
    for ($k = $L.Count - 1; $k -ge 0 -and $k -ge $L.Count - 8; $k--) {
        $kv = Get-JsonKV $L[$k] $CodexWant
        if ((Get-Field $kv 'payload.type') -cne 'token_count') { continue }
        $tt = Get-Field $kv 'payload.info.last_token_usage.total_tokens'
        if (-not $ctx -and $tt -cmatch '\A[0-9]+\z') {
            $ctx = $tt
            $mw = Get-Field $kv 'payload.info.model_context_window'
            if ($mw -cmatch '\A[0-9]+\z') { $win = $mw }
        }
        if (-not $rl -and ($kv.got.ContainsKey('payload.rate_limits.primary.used_percent') -or $kv.got.ContainsKey('payload.rate_limits.plan_type'))) {
            $rl = $true
            # The record time is when Codex learned these values (section 9.1).
            $at = Get-IsoEpoch (Get-Field $kv 'timestamp')
            $id = [regex]::Replace((Get-Field $kv 'payload.rate_limits.limit_id'), '[^A-Za-z0-9_.-]', '')
            # (A null limit_id is Codex's own: the ask names it codex too.)
            if (-not $id -or $id -ceq 'null') { $id = 'codex' }
            foreach ($w in @('primary', 'secondary')) {
                $b = 'payload.rate_limits.' + $w + '.'
                $p = Get-Field $kv ($b + 'used_percent')
                $m = Get-Field $kv ($b + 'window_minutes')
                $rs = Get-Field $kv ($b + 'resets_at')
                if ($p -cmatch '\A[0-9]+([.][0-9]+)?\z' -and $m -cmatch '\A[0-9]+\z' -and $rs -cmatch '\A[0-9]+\z') {
                    $lims += ' ' + $id + '.' + $w + ':' + $p + ':' + $m + ':' + $rs + ':file'
                    if ($at -ge 0) { $lims += ':' + $at }
                }
            }
            $p = Get-Field $kv 'payload.rate_limits.plan_type'
            if ($p -cmatch '\A[A-Za-z0-9_-]+\z' -and $p -cne 'null') { $plan = $p }
            $p = Get-Field $kv 'payload.rate_limits.rate_limit_reached_type'
            if ($p -and $p -cne 'null' -and $p -cne 'false') { $reached = '1' }
        }
        if ($ctx -and $rl) { break }
    }
    if (-not $ctx) { return '' }
    return $ctx + ' ' + $win + ' rollout 0 12000 ' + $plan + ' ' + $reached + $lims
}

# Context window Claude Code would use: from its environment, or a guess
# from the model name (est).
function Get-ClaudeWindow([string]$model) {
    $v = [string]$env:CLAUDE_CODE_MAX_CONTEXT_TOKENS
    if ($v -match '^[0-9]{1,18}$' -and [int64]$v -ge 1000 -and [int64]$v -le 999999999999) { return @{ win = [int64]$v; est = $false } }
    if (@('1', 'true', 'TRUE', 'True') -contains [string]$env:CLAUDE_CODE_DISABLE_1M_CONTEXT) { return @{ win = 200000; est = $false } }
    $m = $model.ToLowerInvariant()
    # A [1m] model names its window itself (exact).
    if ($m.Contains('[1m]')) { return @{ win = 1000000; est = $false } }
    $big = ($m -match 'claude-fable-') -or ($m -match 'claude-sonnet-([5-9]|[1-9][0-9])') -or
        ($m -match 'claude-opus-(4-[7-9]|[5-9]|[1-9][0-9])') -or ($m -match 'claude-haiku-(5-[5-9]|[6-9]|[1-9][0-9])')
    if ($big) { return @{ win = 1000000; est = $true } }
    return @{ win = 200000; est = $true }
}

$StatusWant = @('context_window.context_window_size', 'rate_limits.five_hour.used_percentage', 'rate_limits.five_hour.resets_at',
    'rate_limits.seven_day.used_percentage', 'rate_limits.seven_day.resets_at', 'rate_limits.spend_limit.used_percentage',
    'rate_limits.spend_limit.resets_at', 'rate_limits.spend_limit.period')

# Status line data saved by scripts/statusline-tap.sh (optional, the user
# registers it): its lines after the first (STATUSLINE_LIMS) -> @{ win (digits
# or -); lims (" <id>:<used %>:<window minutes>:<reset epoch>:statusline"...,
# windows that reset after $now) }. Raw JSON tokens.
function Get-StatusLineLims([string]$text, [int64]$now) {
    $s = ''
    $nl = $text.IndexOf([char]10)
    if ($nl -ge 0) { $s = $text.Substring($nl + 1) }
    $kv = Get-JsonKV $s $StatusWant
    $r = @{ win = '-'; lims = '' }
    $w = Get-Field $kv 'context_window.context_window_size'
    if ($w -cmatch '\A[0-9]+\z') { $r.win = $w }
    $p = Get-Field $kv 'rate_limits.spend_limit.period'
    $pw = '0'
    if ($p -ceq 'daily') { $pw = '1440' } elseif ($p -ceq 'weekly') { $pw = '10080' } elseif ($p -ceq 'monthly') { $pw = '43200' }
    foreach ($row in @(@('five_hour', '300'), @('seven_day', '10080'), @('spend_limit', $pw))) {
        $u = Get-Field $kv ('rate_limits.' + $row[0] + '.used_percentage')
        $rs = Get-Field $kv ('rate_limits.' + $row[0] + '.resets_at')
        if ($u -cnotmatch '\A[0-9]+([.][0-9]+)?\z' -or $rs -cnotmatch '\A[0-9]+\z' -or [double]$rs -le $now) { continue }
        $r.lims += ' ' + $row[0] + ':' + $u + ':' + $row[1] + ':' + $rs + ':statusline'
    }
    return $r
}

# The `cost` object of a session (costjson in COST_FN), or ''.
function Get-CostJson([string]$usd, [string]$tin, [string]$tout) {
    $s = ''
    if ($usd) { $s += ',"usd":' + $usd }
    if ($tin -cmatch '\A[0-9]+\z') { $s += ',"tok_in":' + $tin }
    if ($tout -cmatch '\A[0-9]+\z') { $s += ',"tok_out":' + $tout }
    if (-not $s) { return '' }
    return ',"cost":{' + $s.Substring(1) + ',"scope":"session"}'
}

# Grok Build: tokens and cost of the session from its usage.json (no limits;
# GROK_COST, section 9.3), the last of ~/.grok/sessions/*/<session>/usage.json.
# costUsdTicks: 10^-10 USD each (xAI cost_in_usd_ticks); micro-USD exact.
function Get-GrokCost {
    if (-not (Test-Id $Script:RawSid)) { return '' }
    $root = Join-Path (Join-Path $HOME '.grok') 'sessions'
    $uf = ''
    try {
        if (-not [IO.Directory]::Exists($root)) { return '' }
        $names = New-Object 'System.Collections.Generic.List[string]'
        foreach ($d in [IO.Directory]::GetDirectories($root)) { $names.Add([IO.Path]::GetFileName($d)) }
        $names.Sort([StringComparer]::Ordinal)
        foreach ($n in $names) {
            # (A shell glob * leaves dot names out.)
            if ($n.StartsWith('.', $Ord)) { continue }
            $f = [IO.Path]::Combine($root, $n, (US $Script:RawSid), 'usage.json')
            if ([IO.File]::Exists($f)) { $uf = $f }
        }
    } catch { return '' }
    if (-not $uf) { return '' }
    return (Get-GrokCostOf (Read-HeadB $uf 262144))
}

# The `cost` object of a Grok usage.json text (GROK_COST), or ''.
function Get-GrokCostOf([string]$text) {
    $G = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::Ordinal)
    foreach ($l in (Get-Facts $text '')) {
        $x = ([string]$l).Split([char]9)
        if ($x.Length -ge 3 -and $x[1] -ceq 'r' -and -not $G.ContainsKey($x[0])) { $G[$x[0]] = $x[2] }
    }
    $t = ''; $tin = ''; $tout = ''
    [void]$G.TryGetValue('session.costUsdTicks', [ref]$t)
    [void]$G.TryGetValue('session.inputTokens', [ref]$tin)
    [void]$G.TryGetValue('session.outputTokens', [ref]$tout)
    $usd = ''
    if ([string]$t -cmatch '\A[0-9]+\z') {
        $t = ([string]$t).TrimStart('0')
        if ($t.Length -gt 4) { $usd = Get-Unmicro $t.Substring(0, $t.Length - 4) } else { $usd = Get-Unmicro '0' }
    }
    return (Get-CostJson $usd ([string]$tin) ([string]$tout))
}

# The usage line of the current event and its `cost` object (usage_compute):
# @{ line; cost }, each '' if there is none. The line is "<ctx|-> <win|->
# <src|-> <est 0|1> <baseline|-> <plan|-> <reached 0|1>
# [<id>:<pct>:<win min>:<reset epoch>[:<src>[:<at epoch>]]]...".
function Get-UsageLine {
    $u = @{ line = ''; cost = '' }
    if ($Script:Agent -ceq 'grok') {
        $u.cost = Get-GrokCost
        return $u
    }
    $tpath = Get-InputFile $Script:TPath
    if ($Script:Agent -ceq 'codex') {
        if ($tpath) { $u.line = Get-CodexUsageLine $tpath }
        return $u
    }
    if ($Script:Agent -cne 'claude') { return $u }
    $reached = '0'
    if ($Script:HookEvent -ceq 'StopFailure' -and $Script:Err -ceq 'rate_limit') { $reached = '1' }
    $ctx = $null; $src = 'transcript'
    $model = $Script:Model
    $tok = $Script:CtxTok
    if ((Test-UInt $tok) -and [int64]$tok -gt 0) {
        $ctx = [int64]$tok; $src = 'hook'
    } elseif ($tpath) {
        $c = Get-ClaudeUsage $tpath
        if ($null -ne $c) { $ctx = $c.ctx; if (-not $model) { $model = $c.model } }
    }
    if ($null -eq $ctx) { return $u }
    $model = $model -replace '[^A-Za-z0-9._:@/\[\]-]', ''
    $w = Get-ClaudeWindow $model
    $win = $w.win
    $est = $w.est
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
    if ($Script:HookEvent -ceq 'SessionStart' -or $Script:HookEvent -ceq 'PostModelSwitch') { $mw = ''; $me = $true; $ms = $Script:Now }
    # Optional status line tap (scripts/statusline-tap.sh): exact window, limits.
    $lims = ''
    $sl = Join-Path $RunDir ('usage.' + $Sid + '.json')
    try {
        if ([IO.File]::Exists($sl)) {
            $head = Read-HeadB $sl 65536
            $t = $head
            $nl = $head.IndexOf([char]10)
            if ($nl -ge 0) { $t = $head.Substring(0, $nl) }
            $now = $Script:Now
            if ((Test-UInt $t) -and ($now - [int64]$t) -le 600 -and ([int64]$t - $now) -le 60) {
                $s = Get-StatusLineLims $head $now
                if ((Test-UInt $s.win) -and [int64]$t -gt $ms) { $win = [int64]$s.win; $est = $false }
                $lims = $s.lims
            }
        }
    } catch { }
    if ($est -and $mw) { $win = [int64]$mw; $est = $me }
    # A guess below the context in use is wrong: the window is 1M.
    if ($est -and $ctx -gt $win) { $win = 1000000; $mw = '1000000' }
    $new = '- 1 ' + $ms
    if (-not $est) { $new = [string]$win + ' 0 ' + $ms } elseif ($mw) { $new = [string]$win + ' 1 ' + $ms }
    try {
        $old = ''
        if ([IO.File]::Exists($winPath)) { $old = [IO.File]::ReadAllText($winPath, $Utf8).Trim() }
        if ($old -ne $new) { [IO.File]::WriteAllText($winPath, $new + "`n", $Utf8) }
    } catch { }
    $e = '0'
    if ($est) { $e = '1' }
    $u.line = [string]$ctx + ' ' + [string]$win + ' ' + $src + ' ' + $e + ' - - ' + $reached + $lims
    return $u
}

# awk's `$n == 1` of a field: a number when it looks like one.
function Test-AwkOne([string]$v) {
    if ($v -cmatch '\A[+-]?([0-9]+[.]?[0-9]*|[.][0-9]+)([eE][+-]?[0-9]+)?\z') { return ([double]::Parse($v, $Inv) -eq 1) }
    return ($v -ceq '1')
}

# A usage line (see Get-UsageLine) -> @{ osc (the OSC 9 body: v1, none
# without a context); json (the v1 fields of the `usage` event, with each
# window's `src` and `at`, section 9.1) } (USAGE_FMT).
function Format-UsageLine([string]$line) {
    $r = @{ osc = ''; json = '' }
    $k = $line.IndexOf([char]10)
    if ($k -ge 0) { $line = $line.Substring(0, $k) }
    $fs = New-Object 'System.Collections.Generic.List[string]'
    foreach ($m in [regex]::Matches($line, '[^ \t]+')) { $fs.Add($m.Value) }
    while ($fs.Count -lt 7) { $fs.Add('') }
    $num = '\A[0-9]+\z'
    $dec = '\A[0-9]+([.][0-9]+)?\z'
    $hc = ($fs[0] -cmatch $num)
    if (-not $hc -and $fs[0] -cne '-') { return $r }
    if ($hc -and $fs[2] -cnotmatch '\A[a-z]+\z') { return $r }
    $osc = ''
    $js = ''
    if ($hc) {
        $osc = 'simpleterm:usage v=1 agent=' + $Script:App + ' ctx=' + $fs[0]
        $js = ',"ctx":{"used":' + $fs[0]
        if ($fs[1] -cmatch $num) { $osc += ' win=' + $fs[1]; $js += ',"win":' + $fs[1] }
        if ($fs[4] -cmatch $num) { $js += ',"baseline":' + $fs[4] }
        $osc += ' src=' + $fs[2]
        $js += ',"src":"' + $fs[2] + '"'
        if (Test-AwkOne $fs[3]) { $osc += ' est=1'; $js += ',"est":true' }
        $js += '}'
    }
    $la = ''
    $nl = 0
    for ($i = 7; $i -lt $fs.Count; $i++) {
        $P = $fs[$i].Split(':')
        $n = $P.Length
        if ($n -lt 4 -or $n -gt 6) { continue }
        if ($P[0] -cnotmatch '\A[A-Za-z0-9_.-]+\z' -or $P[1] -cnotmatch $dec -or $P[2] -cnotmatch $num -or $P[3] -cnotmatch $num) { continue }
        if ($n -ge 5 -and $P[4] -cnotmatch '\A(ask|file|statusline|hook)\z') { continue }
        if ($n -eq 6 -and $P[5] -cnotmatch $num) { continue }
        if ($hc) { $osc += ' lim=' + $P[0] + ':' + $P[1] + ':' + $P[2] + ':' + $P[3] }
        $e = '{"id":"' + $P[0] + '","pct":' + $P[1] + ',"win_min":' + $P[2] + ',"resets_at":' + $P[3]
        if ($n -ge 5) { $e += ',"src":"' + $P[4] + '"' }
        if ($n -eq 6) { $e += ',"at":' + $P[5] }
        if ($la) { $la += ',' }
        $la += $e + '}'
        $nl++
    }
    if (Test-AwkOne $fs[6]) {
        if ($hc) { $osc += ' lim=reached' }
        if ($la) { $la += ',' }
        $la += '{"id":"reached"}'
        $nl++
    }
    # (As in v1, a report with a context always names its windows, [] too.)
    if ($hc -or $nl -gt 0) { $js += ',"lims":[' + $la + ']' }
    if ($fs[5] -cmatch '\A[A-Za-z0-9_-]+\z' -and $fs[5] -cne '-') { $js += ',"plan":"' + $fs[5] + '"' }
    $r.osc = $osc
    $r.json = $js
    return $r
}

# Reports context, rate limits and cost when they changed: an OSC 9 for the
# terminal (Claude Code in SimpleTerm, UsageSeq; v1, context and windows only)
# and a `usage` event for the SSH tunnel links (section 9.1). The relay gets
# none: it does not push them (an iOS push is always an alert) and every
# request costs a function call. At a turn's end it may also ask the agent
# (Invoke-UsageAsk). As usage_report in agent-hook.sh.
function Invoke-UsageReport {
    $Script:UsageSeq = ''
    if (-not (Test-ConfUsageOn)) { return }
    $u = @{ line = ''; cost = '' }
    try { $u = Get-UsageLine } catch { Write-Log ('usage-failed ' + $_.Exception.GetType().Name) }
    $osc = ''
    $Script:UsageJson = ''
    if ($u.line) {
        $fmt = Format-UsageLine $u.line
        $osc = $fmt.osc
        $Script:UsageJson = $fmt.json
    }
    try { Invoke-UsageAsk } catch { Write-Log ('usage-ask-failed ' + $_.Exception.GetType().Name) }
    $cost = [string]$u.cost
    if (-not ($Script:UsageJson + $cost)) { return }
    $key = $osc + $Script:UsageJson + $cost
    $last = Join-Path $RunDir ($Sid + '.usage')
    $prev = Read-FileB $last
    if ($null -eq $prev) { $prev = '' }
    if ($prev.TrimEnd([char]10) -ceq $key) { return }
    # Recorded as sent only once SimpleTerm has it: on Claude Code's terminal
    # (printed by Write-State), or when a tunnel link took the event.
    # Otherwise it goes again next time, though unchanged, in case the app
    # connects meanwhile.
    if ($osc) {
        $Script:UsageSeq = '\u001b]9;' + $osc + '\u0007'
        if ($Script:Agent -ceq 'claude' -and $env:SIMPLETERM -eq '1') { [void](Write-FileB $last ($key + "`n")) }
    }
    Send-Usage (Get-UsageRid) $cost ($Sid + '.usage') $key
}

# A usage event's own rid (SIMPLETERM_HOOK_TEST_URID in tests).
function Get-UsageRid {
    if ($env:SIMPLETERM_HOOK_TEST -eq '1' -and $env:SIMPLETERM_HOOK_TEST_URID) { return (BS $env:SIMPLETERM_HOOK_TEST_URID) }
    return (New-RandomHex 8)
}

# The `usage` event (UsageJson, then $tail: uq, cost) to the tunnels, with the
# common fields (section 9.1); once a tunnel took it, $markText goes to the
# run file $markName (usage_send). -Sync sends from this process (a usage
# ask's child, already in the background).
function Send-Usage([string]$rid, [string]$tail, [string]$markName, [string]$markText, [switch]$Sync) {
    if (-not (Test-Hex $rid 16)) { return }
    $us = $Script:Spec
    $ux = $Script:V2X
    $um = $Script:NoMsg
    $Script:UsageV2 = $tail
    $Script:NoMsg = $true
    Initialize-V2 ''
    if ($Sync) { Send-Now 'usage' $rid 'tunnel' $markName $markText }
    else { Send-Background 'usage' $rid 'tunnel' $markName $markText }
    $Script:Spec = $us
    $Script:V2X = $ux
    $Script:NoMsg = $um
    $Script:UsageV2 = ''
}

# --- usage asks (TDS_AGENT_EVENTS_V2 section 9.2) ----------------------------------

# Every version and OS is asked (D22, 2026-11-03 user decision). Measured
# against a local mock API (2026-11-03, .hjc/research/2026-11-03-usage-ask of
# the app): 0 model requests in 22 asks of Claude Code 2.1.316 and 2.1.317 and
# 11 of Codex 0.165.0 on macOS (the same harness caught 6 and 31 in real
# turns). What guards the others: the version of the executable that ran stops
# for good after an answer showing spend or a hook, or after 3 failed asks in
# a row (run/ask.<agent>.off).

# A value of agent-hook.conf (Get-ConfVal), or $default if empty (conf_word).
# The caller compares it in any case.
function Get-ConfWord([string]$key, [string]$default) {
    $v = Get-ConfVal $key
    if (-not $v) { return $default }
    return $v
}

# True unless word key $key (usage_ask, usage_ask_codex) is off, 0, no or
# false, in any case (conf_on).
function Test-ConfOn([string]$key) {
    return -not (@('off', '0', 'no', 'false') -ccontains (Get-ConfWord $key 'on').ToLowerInvariant())
}

# A number as awk reads a string (its leading number, else 0).
function Get-AwkNum([string]$s) {
    $m = [regex]::Match($s, '\A[ \t]*[+-]?([0-9]+[.]?[0-9]*|[.][0-9]+)([eE][+-]?[0-9]+)?')
    if (-not $m.Success) { return [double]0 }
    try { return [double]::Parse($m.Value.Trim(), $Inv) } catch { return [double]0 }
}

# True if dotted version $a is older than $b (ver_lt: the first three parts).
function Test-VerLt([string]$a, [string]$b) {
    $pa = $a.Split('.')
    $pb = $b.Split('.')
    for ($i = 0; $i -lt 3; $i++) {
        $x = [double]0
        $y = [double]0
        if ($i -lt $pa.Length) { $x = Get-AwkNum $pa[$i] }
        if ($i -lt $pb.Length) { $y = Get-AwkNum $pb[$i] }
        if ($x -lt $y) { return $true }
        if ($x -gt $y) { return $false }
    }
    return $false
}

# True if the app is connected: a tunnel link whose last event got an HTTP 200
# within 10 minutes (Complete-Ingest records it). A tunnel file left behind by
# a closed connection does not count (tunnel_live).
function Test-TunnelLive {
    $tn = Now-Epoch
    foreach ($f in $Script:LinkFiles) {
        $link = Read-Link $f
        if ($null -eq $link -or $link.kind -cne 'tunnel') { continue }
        $t = Read-FileB (Join-Path $RunDir ('tun.' + (Short $link.link) + '.last'))
        if ($null -eq $t) { continue }
        # read -r lt lc: a whole line, its first word and the rest.
        $k = $t.IndexOf([char]10)
        if ($k -lt 0) { continue }
        $m = [regex]::Match($t.Substring(0, $k), '\A[ \t]*([^ \t]*)[ \t]*(.*?)[ \t]*\z')
        $lt = $m.Groups[1].Value
        $lc = $m.Groups[2].Value
        if ((Test-UInt $lt) -and $lc -ceq '200' -and ($tn - [int64]$lt) -le 600 -and ([int64]$lt - $tn) -le 60) { return $true }
    }
    return $false
}

# The agent's executable on PATH: claude or codex (claude.exe, codex.exe on
# Windows), a full path, or ''.
function Find-AskAgent([string]$name) {
    if ($IsWin) { $name += '.exe' }
    try {
        $cmd = @(Get-Command -Name $name -CommandType Application -ErrorAction SilentlyContinue)
        if ($cmd.Count -eq 0) { return '' }
        $p = [string]$cmd[0].Path
        if ($p -and [IO.Path]::IsPathRooted($p) -and [IO.File]::Exists($p)) { return $p }
    } catch { }
    return ''
}

# True if the last ask of file $af (ask.<agent>.<h>) started less than 5
# minutes ago (a time more than 60 seconds ahead does not count; ask_recent).
function Test-AskRecent([string]$af) {
    $la = Read-FileB $af
    if ($null -eq $la) { $la = '' }
    $la = $la.TrimEnd([char]10)
    return ((Test-UInt $la) -and ($Script:Now - [int64]$la) -lt 300 -and ([int64]$la - $Script:Now) -le 60)
}

# Creates empty file $path only if it is not there (a claim): $true if this
# call made it.
function New-ClaimFile([string]$path) {
    try {
        $fs = New-Object IO.FileStream($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
        $fs.Dispose()
        return $true
    } catch { return $false }
}

# True if asks of the agent's executable version $v were stopped (an answer of
# that version showed model spend or a hook, or 3 asks in a row failed):
# run/ask.<agent>.off, one version a line, `unknown` among them (ask_stopped).
function Test-AskStopped([string]$v) {
    $t = Read-HeadB (Join-Path $RunDir ('ask.' + $Script:Agent + '.off')) 4096
    foreach ($l in $t.Split([char]10)) { if ($l -ceq $v) { return $true } }
    return $false
}

# Stops asks of executable version $v for good (ask_stop).
function Add-AskStopped([string]$v) {
    if (Test-AskStopped $v) { return }
    $off = Join-Path $RunDir ('ask.' + $Script:Agent + '.off')
    $old = Read-FileB $off
    if ($null -eq $old) { $old = '' }
    if ($old -and -not $old.EndsWith([string][char]10, $Ord)) { $old += "`n" }
    [void](Write-FileB $off ($old + $v + "`n"))
}

# The failed asks in a row of executable version $v (D22; ask_fails): the first
# line of run/ask.<agent>.fail (its first 4 KiB), `<version> <count>`; 0 if it
# is another version or not of that form.
function Get-AskFails([string]$v) {
    $l = (Read-HeadB (Join-Path $RunDir ('ask.' + $Script:Agent + '.fail')) 4096).Split([char]10)[0]
    $m = [regex]::Match($l, '\A([0-9A-Za-z.+_-]+) ([1-9][0-9]{0,8})\z')
    if ($m.Success -and $m.Groups[1].Value -ceq $v) { return [int64]$m.Groups[2].Value }
    return [int64]0
}

# After an ask: an answer clears the count; a failed one (failed, timeout;
# $failed) adds one, from 1 for another version, written whole to
# run/ask.<agent>.fail.<pid> and renamed over the file (not counted if that
# fails); the third stops that version (D22; ask_fail_count). Sign-in results
# (auth, not-subscriber) do not come here.
function Update-AskFails([string]$v, [bool]$failed) {
    $ff = Join-Path $RunDir ('ask.' + $Script:Agent + '.fail')
    if (-not $failed) { Remove-FileQ $ff; return }
    $c = (Get-AskFails $v) + 1
    $tmp = $ff + '.' + $PID
    $done = $false
    if (Write-FileB $tmp ($v + ' ' + $c + "`n")) {
        try { Move-Item -LiteralPath $tmp -Destination $ff -Force -ErrorAction Stop; $done = $true } catch { }
    }
    Remove-FileQ $tmp
    if ($done -and $c -ge 3) { Add-AskStopped $v }
}

# Ends process $p and every process under it (the agent's own children;
# kill_tree). .NET Framework has no Kill(true): taskkill /T there.
function Stop-AskTree($p) {
    try { if ($p.HasExited) { return } } catch { return }
    try { $p.Kill($true); return } catch { }
    if ($IsWin) {
        try {
            $tk = Join-Path ([Environment]::GetFolderPath('System')) 'taskkill.exe'
            $k = [System.Diagnostics.Process]::Start((New-Object System.Diagnostics.ProcessStartInfo -Property @{
                FileName = $tk; Arguments = ('/T /F /PID ' + $p.Id); UseShellExecute = $false; CreateNoWindow = $true }))
            [void]$k.WaitForExit(5000)
        } catch { }
    }
    try { if (-not $p.HasExited) { $p.Kill() } } catch { }
}

# The folder an ask runs in: ~/.simpleterm/probe (700 where there are modes;
# Windows: the profile's own ACL), with no project settings (ask_probe_dir).
function Initialize-AskProbe {
    $probe = Join-Path $StDir 'probe'
    try { if (-not [IO.Directory]::Exists($probe)) { [void][IO.Directory]::CreateDirectory($probe) } } catch { return $false }
    if (-not $IsWin) { try { [IO.File]::SetUnixFileMode($probe, 448) } catch { } }
    return $true
}

# A ProcessStartInfo for agent $exe as the ask runs it: in ~/.simpleterm/probe
# with SIMPLETERM_PROBE=1, without the session's variables.
function New-AskPsi([string]$exe, [string]$argLine) {
    $probe = Join-Path $StDir 'probe'
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $exe
    $psi.Arguments = $argLine
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.WorkingDirectory = $probe
    foreach ($v in $AskUnset) { if ($psi.EnvironmentVariables.ContainsKey($v)) { $psi.EnvironmentVariables.Remove($v) } }
    $psi.EnvironmentVariables['SIMPLETERM_PROBE'] = '1'
    if (-not $IsWin) { $psi.EnvironmentVariables['PWD'] = $probe }
    return $psi
}

# The version of agent executable $exe, which the ask would run (section 9.2
# condition 6, D21, D22; ask_bin_version): @{ bv; exe }, exe the file that the
# ask then runs. Its links are followed to the end: .../versions/<version> (a
# native Claude Code install) gives the version. Otherwise run/ver.<agent>
# (D13, section 10.1: that file's path, and its --version's first dotted
# number or an empty line if it gave none) is used for the same file while the
# file is not newer: `unknown` if it holds no version. Else a child measures it
# again (15 seconds at most) and bv stays '': no ask this turn.
function Get-AskBinVersion([string]$exe) {
    $res = @{ bv = ''; exe = '' }
    $r = $exe
    for ($n = 0; $n -le 16; $n++) {
        $t = $null
        try {
            $fi = New-Object IO.FileInfo $r
            if (-not ($fi.Attributes -band [IO.FileAttributes]::ReparsePoint)) { break }
            $t = $fi.LinkTarget
        } catch { return $res }
        if ($n -eq 16 -or -not $t) { return $res }
        if ([IO.Path]::IsPathRooted($t)) { $r = $t } else { $r = Join-Path ([IO.Path]::GetDirectoryName($r)) $t }
    }
    if (-not [IO.File]::Exists($r) -or $r.Contains([string][char]10) -or $r.Contains([string][char]13)) { return $res }
    $v = ''
    $dir = [IO.Path]::GetDirectoryName($r)
    if ($dir -and [IO.Path]::GetFileName($dir) -ceq 'versions') { $v = [IO.Path]::GetFileName($r) }
    if (-not (Test-AskVer $v)) { $v = '' }
    if (-not $v) {
        $vc = Join-Path $RunDir ('ver.' + $Script:Agent)
        $fresh = $false
        try { $fresh = [IO.File]::Exists($vc) -and ((Read-LineB $vc 0) -ceq (BS $r)) -and -not ([IO.File]::GetLastWriteTimeUtc($r) -gt [IO.File]::GetLastWriteTimeUtc($vc)) } catch { }
        if ($fresh) {
            $v = Read-LineB $vc 1
            if (-not (Test-AskVer $v)) { $v = 'unknown' }
        } else {
            if (-not (Initialize-AskProbe)) { return $res }
            # (A lock left by a measurement that never ended holds a minute.)
            try { if ([IO.File]::Exists($vc + '.lock') -and ([DateTime]::UtcNow - [IO.File]::GetLastWriteTimeUtc($vc + '.lock')).TotalSeconds -gt 60) { Remove-FileQ ($vc + '.lock') } } catch { }
            try {
                $fs = New-Object IO.FileStream(($vc + '.lock'), [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
                $fs.Dispose()
            } catch { return $res }
            $job = New-Job 'askver'
            $job.vb = BS $r
            Start-Child $job
            return $res
        }
    }
    $res.bv = $v
    $res.exe = $r
    return $res
}

# True if $v is a version as av is written (section 3): [0-9A-Za-z.+_-]{1,32}
# (ask_ver_ok).
function Test-AskVer([string]$v) {
    return ($v -cmatch '\A[0-9A-Za-z.+_-]{1,32}\z')
}

# Measures run/ver.<agent> again (the child of Get-AskBinVersion): the file's
# --version, run as the ask runs, 15 seconds at most; none: an empty line, so
# the same file is not measured again.
function Invoke-AskVerChild($job) {
    if ($Script:Agent -cne 'claude' -and $Script:Agent -cne 'codex') { return }
    $vc = Join-Path $RunDir ('ver.' + $Script:Agent)
    try {
        $p = [System.Diagnostics.Process]::Start((New-AskPsi (US ([string]$job.vb)) '--version'))
        try {
            $p.StandardInput.Close()
            $out = $p.StandardOutput.ReadToEndAsync()
            [void]$p.StandardError.ReadToEndAsync()
            if (-not $p.WaitForExit(15000)) { Stop-AskTree $p }
            $text = ''
            if ($out.Wait(2000)) { $text = BS ([string]$out.Result) }
            if ($text.Length -gt 4096) { $text = $text.Substring(0, 4096) }
            $v = ''
            foreach ($line in $text.Split([char]10)) {
                $m = [regex]::Match($line, '[0-9]+[.][0-9]+[0-9A-Za-z.+_-]*')
                if ($m.Success) { $v = $m.Value; break }
            }
            if (-not (Test-AskVer $v)) { $v = '' }
            if (Write-FileB ($vc + '.tmp') ([string]$job.vb + "`n" + $v + "`n")) {
                Remove-FileQ $vc
                [IO.File]::Move(($vc + '.tmp'), $vc)
            }
        } finally { try { $p.Dispose() } catch { } }
    } catch { }
    Remove-FileQ ($vc + '.tmp')
    Remove-FileQ ($vc + '.lock')
}

# At the end of a turn, while the app is connected, at most every 5 minutes
# per agent and settings folder: asks Claude Code or Codex for its limits in a
# detached child (stdio closed, 20 seconds at most), unless asks of the version
# of the executable that the ask runs were stopped (section 9.2, D21, D22).
# After a failed sign-in or an answer of no plan limits (not-subscriber) it
# asks again only once the agent's credentials file changed. usage_ask=off in
# agent-hook.conf turns it off; usage_ask_codex=off turns off Codex's only
# (its app-server writes its own state, syncs its plugins and may refresh an
# expired sign-in). As usage_ask in agent-hook.sh.
function Invoke-UsageAsk {
    # (Values in any case: OFF and No turn it off too.)
    if (-not (Test-ConfOn 'usage_ask')) { return }
    if ($Script:HookEvent -cne 'Stop' -and $Script:HookEvent -cne 'StopFailure') { return }
    if ($Script:Agent -ceq 'claude') {
        $ab = 'claude'
        $cfg = [string]$env:CLAUDE_CONFIG_DIR
        if (-not $cfg) { $cfg = Join-Path $HOME '.claude' }
        $ind = Join-Path $cfg '.credentials.json'
    } elseif ($Script:Agent -ceq 'codex') {
        if (-not (Test-ConfOn 'usage_ask_codex')) { return }
        $ab = 'codex'
        $cfg = [string]$env:CODEX_HOME
        if (-not $cfg) { $cfg = Join-Path $HOME '.codex' }
        $ind = Join-Path $cfg 'auth.json'
    } else { return }
    if ($Script:LinkFiles.Count -eq 0 -or -not (Test-TunnelLive)) { return }
    $ap = Find-AskAgent $ab
    if (-not $ap) { return }
    # The version of the executable the ask runs (a native install moves the
    # link on PATH to a newer version while sessions of the older one still
    # run): asks of it not stopped.
    $bin = Get-AskBinVersion $ap
    if (-not $bin.bv -or (Test-AskStopped $bin.bv) -or (Get-AskFails $bin.bv) -ge 3) { return }
    Initialize-Common
    $af = Join-Path $RunDir ('ask.' + $Script:Agent + '.' + (Get-Sha256Hex (BS $cfg)).Substring(0, 16))
    $auth = $af + '.auth'
    if ([IO.File]::Exists($auth)) {
        if (-not ([IO.File]::Exists($ind) -and [IO.File]::GetLastWriteTimeUtc($ind) -gt [IO.File]::GetLastWriteTimeUtc($auth))) { return }
        Remove-FileQ $auth
    }
    if (Test-AskRecent $af) { return }
    # The slot is claimed at once: Stop hooks of several sessions of this
    # agent and settings folder may end together. $af.lk is held while the
    # time is checked again and written; one left by a hook that died is taken
    # after 5 minutes (as usage_ask in agent-hook.sh).
    $lk = $af + '.lk'
    if (-not (New-ClaimFile $lk)) {
        $old = $false
        try { $old = [IO.File]::Exists($lk) -and ([DateTime]::UtcNow - [IO.File]::GetLastWriteTimeUtc($lk)).TotalSeconds -gt 300 } catch { }
        if (-not $old) { return }
        Remove-FileQ $lk
        if (-not (New-ClaimFile $lk)) { return }
    }
    if ((Test-AskRecent $af) -or -not (Write-FileB $af ([string]$Script:Now + "`n"))) { Remove-FileQ $lk; return }
    Remove-FileQ $lk
    if (-not (Initialize-AskProbe)) { return }
    Write-Log ('usage-ask ' + $Script:Agent + ' ' + $bin.bv)
    Initialize-Facts
    $job = New-Job 'uask'
    $job.ap = BS $bin.exe
    $job.af = BS $af
    $job.av = $Script:AV
    $job.bv = $bin.bv
    Start-Child $job
}

# The agent session's own variables (measured, Claude Code 2.1.316): the ask
# is not a child of that session.
$AskUnset = @('CLAUDECODE', 'CLAUDE_CODE_ENTRYPOINT', 'CLAUDE_CODE_SESSION_ID', 'CLAUDE_CODE_CHILD_SESSION', 'CLAUDE_CODE_EXECPATH',
    'CLAUDE_CODE_SESSION_ATTENDED', 'CLAUDE_CODE_MESSAGING_SOCKET', 'CLAUDE_CODE_MESSAGING_TOKEN',
    'CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS', 'CLAUDE_EFFORT', 'CLAUDE_PID', 'AI_AGENT', 'SIMPLETERM')

function Write-AskLines($stream, [string[]]$lines) {
    try {
        foreach ($l in $lines) {
            $b = $Latin1.GetBytes($l + "`n")
            $stream.Write($b, 0, $b.Length)
        }
        $stream.Flush()
    } catch { }
}

# Takes what the agent wrote so far ($st.text, 2 MiB at most kept).
function Step-AskOut($st) {
    while ($null -ne $st.task -and $st.task.IsCompleted) {
        $n = 0
        try { $n = [int]$st.task.Result } catch { $n = 0 }
        if ($n -le 0) { $st.eof = $true; $st.task = $null; break }
        if ($st.text.Length -lt 2097152) { $st.text += $Latin1.GetString($st.buf, 0, $n) }
        try { $st.task = $st.so.ReadAsync($st.buf, 0, $st.buf.Length) } catch { $st.eof = $true; $st.task = $null }
    }
}

# The first MiB of the output, where the answers are looked for.
function Get-AskHead($st) {
    if ($st.text.Length -gt 1048576) { return $st.text.Substring(0, 1048576) }
    return $st.text
}

# Runs agent $exe ($argLine) in ~/.simpleterm/probe with SIMPLETERM_PROBE=1,
# its standard input the lines $inLines, then the lines $moreLines once its
# output holds $w1 (or at once without $w1), then open until the output holds
# $w2 or 20 seconds passed; then closed, and the agent stopped 3 seconds
# later (ask_pipe). Returns @{ res: ok (got $w2), gone (ended without it) or
# timeout; text: its output }.
function Invoke-AskPipe([string]$exe, [string]$argLine, [string[]]$inLines, [string[]]$moreLines, [string]$w1, [string]$w2) {
    $st = @{ res = 'gone'; text = ''; eof = $false; task = $null; so = $null; buf = (New-Object byte[] 65536) }
    $p = $null
    try {
        $psi = New-AskPsi $exe $argLine
        # (.NET Framework would start the agent's input with the console
        # encoding's preamble: a UTF-8 code page's BOM.)
        if ($IsWin) { try { [Console]::InputEncoding = $Utf8 } catch { } }
        $p = [System.Diagnostics.Process]::Start($psi)
    } catch { return $st }
    try {
        $st.so = $p.StandardOutput.BaseStream
        # Its errors go nowhere (2>/dev/null), read so that it never blocks.
        [void]$p.StandardError.ReadToEndAsync()
        $st.task = $st.so.ReadAsync($st.buf, 0, $st.buf.Length)
        $si = $p.StandardInput.BaseStream
        Write-AskLines $si $inLines
        $sent = ($w1.Length -eq 0)
        $until = [DateTime]::UtcNow.AddSeconds(20)
        $st.res = 'timeout'
        while ($true) {
            Step-AskOut $st
            if (-not $sent -and (Get-AskHead $st).Contains($w1)) { Write-AskLines $si $moreLines; $sent = $true }
            if ((Get-AskHead $st).Contains($w2)) { $st.res = 'ok'; break }
            if ($p.HasExited) {
                # Ended: what it wrote is read to the end first.
                $end = [DateTime]::UtcNow.AddSeconds(2)
                while (-not $st.eof -and [DateTime]::UtcNow -lt $end) { Step-AskOut $st; if (-not $st.eof) { Start-Sleep -Milliseconds 50 } }
                $st.res = 'gone'
                break
            }
            if ([DateTime]::UtcNow -ge $until) { break }
            Start-Sleep -Milliseconds 100
        }
        if ((Get-AskHead $st).Contains($w2)) { $st.res = 'ok' }
        if (-not $sent) { Write-AskLines $si $moreLines }
        try { $p.StandardInput.Close() } catch { }
        $kill = [DateTime]::UtcNow.AddSeconds(3)
        while (-not $p.HasExited -and [DateTime]::UtcNow -lt $kill) { Step-AskOut $st; Start-Sleep -Milliseconds 100 }
        # Still there: it and what it started.
        Stop-AskTree $p
        $end = [DateTime]::UtcNow.AddSeconds(1)
        while (-not $st.eof -and [DateTime]::UtcNow -lt $end) { Step-AskOut $st; if (-not $st.eof) { Start-Sleep -Milliseconds 50 } }
    } catch {
        Stop-AskTree $p
    }
    try { $p.Dispose() } catch { }
    return $st
}

# The facts of the first line of output $text holding $w, cut to 256 KiB
# (ask_facts).
function Get-AskFacts([string]$text, [string]$w) {
    foreach ($line in $text.Split([char]10)) {
        if (-not $line.Contains($w)) { continue }
        $l = $line + "`n"
        if ($l.Length -gt 262144) { $l = $l.Substring(0, 262144) }
        return (Get-Facts $l '')
    }
    return @()
}

# Facts lines `path TAB type TAB value` -> @{ F (value); T (type); O (paths in
# order) }, the first line of each path.
function Read-FactMap($facts) {
    $m = @{
        F = (New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::Ordinal))
        T = (New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::Ordinal))
        O = (New-Object 'System.Collections.Generic.List[string]')
    }
    foreach ($x in $facts) {
        $l = [string]$x
        $p = $l; $t = ''; $v = ''
        $t1 = $l.IndexOf([char]9)
        if ($t1 -ge 0) {
            $p = $l.Substring(0, $t1)
            $t2 = $l.IndexOf([char]9, $t1 + 1)
            if ($t2 -lt 0) { $t = $l.Substring($t1 + 1) }
            else {
                $t = $l.Substring($t1 + 1, $t2 - $t1 - 1)
                $v = $l.Substring($t2 + 1)
                $t3 = $v.IndexOf([char]9)
                if ($t3 -ge 0) { $v = $v.Substring(0, $t3) }
            }
        }
        if (-not $m.F.ContainsKey($p)) { $m.F[$p] = $v; $m.T[$p] = $t; $m.O.Add($p) }
    }
    return $m
}

function Get-FactV($m, [string]$p) { $x = $null; if ($m.F.TryGetValue($p, [ref]$x)) { return [string]$x }; return '' }
function Get-FactT($m, [string]$p) { $x = $null; if ($m.T.TryGetValue($p, [ref]$x)) { return [string]$x }; return '' }

# A window of a Claude Code answer: " <id>:<pct>:<win>:<reset>:ask:<at>" or ''.
function Get-ClaudeAskWin($m, [string]$id, [string]$p, [string]$w, [string]$at) {
    $u = Get-FactV $m ($p + '.utilization')
    $r = Get-IsoEpoch (Get-FactV $m ($p + '.resets_at'))
    if ((Get-FactT $m ($p + '.utilization')) -cne 'r' -or $u -cnotmatch '\A[0-9]+([.][0-9]+)?\z' -or $r -lt 0) { return '' }
    return ' ' + $id + ':' + $u + ':' + $w + ':' + $r + ':ask:' + $at
}

# Claude Code get_usage control response (facts) -> "OK <usage line>" or "ERR
# <uq.err>" (section 9.3; CLAUDE_USAGE). $at: the epoch the answer came. An
# answer whose session shows any model spend (cost, API time or a model's
# usage; measured 0 in every ask, 2.1.316 and 2.1.317) is "ERR spent": asks
# of that version stop.
function Get-ClaudeAskLine($facts, [string]$at) {
    $m = Read-FactMap $facts
    if ((Get-FactV $m 'response.subtype') -cne 'success') {
        $e = (Get-FactV $m 'response.error').ToLowerInvariant()
        if ($e -cmatch 'auth|log ?in|credential|oauth|unauthori|401|403') { return 'ERR auth' }
        return 'ERR failed'
    }
    $R = 'response.response.'
    if ((Get-FactV $m ($R + 'session.total_cost_usd')) -cnotmatch '\A0([.]0+)?\z' -or (Get-FactV $m ($R + 'session.total_api_duration_ms')) -cnotmatch '\A0([.]0+)?\z') { return 'ERR spent' }
    foreach ($p in $m.O) { if ($p.StartsWith($R + 'session.model_usage.', $Ord)) { return 'ERR spent' } }
    if ((Get-FactV $m ($R + 'rate_limits_available')) -ceq 'false') { return 'ERR not-subscriber' }
    # Limits there but not known now (traffic turned off, a failed refresh):
    # nothing to show, not 0 percent.
    if (-not $m.F.ContainsKey($R + 'rate_limits.five_hour.utilization') -and -not $m.F.ContainsKey($R + 'rate_limits.seven_day.utilization') -and
        -not $m.F.ContainsKey($R + 'rate_limits.model_scoped.0.utilization')) { return 'ERR failed' }
    $plan = Get-FactV $m ($R + 'subscription_type')
    if ((Get-FactT $m ($R + 'subscription_type')) -cne 's' -or $plan -cnotmatch '\A[A-Za-z0-9_-]+\z') { $plan = '-' }
    $out = ''
    $out += Get-ClaudeAskWin $m 'five_hour' ($R + 'rate_limits.five_hour') '300' $at
    $out += Get-ClaudeAskWin $m 'seven_day' ($R + 'rate_limits.seven_day') '10080' $at
    for ($k = 0; $k -lt 16 -and $m.F.ContainsKey($R + 'rate_limits.model_scoped.' + $k + '.display_name'); $k++) {
        $n = [regex]::Replace((Get-FactV $m ($R + 'rate_limits.model_scoped.' + $k + '.display_name')), '[^A-Za-z0-9._-]', '-')
        if (-not $n) { continue }
        $id = 'seven_day.' + $n
        if ($id.Length -gt 64) { $id = $id.Substring(0, 64) }
        $out += Get-ClaudeAskWin $m $id ($R + 'rate_limits.model_scoped.' + $k) '10080' $at
    }
    return 'OK - - - 0 - ' + $plan + ' 0' + $out
}

# A window of a Codex RateLimitSnapshot: " <id>:<pct>:<win>:<reset>:ask:<at>" or ''.
function Get-CodexAskWin($m, [string]$id, [string]$b, [string]$at) {
    $p = Get-FactV $m ($b + '.usedPercent')
    $w = Get-FactV $m ($b + '.windowDurationMins')
    $r = Get-FactV $m ($b + '.resetsAt')
    if ($p -cnotmatch '\A[0-9]+([.][0-9]+)?\z' -or $w -cnotmatch '\A[0-9]+\z' -or $r -cnotmatch '\A[0-9]+\z') { return '' }
    return ' ' + $id + ':' + $p + ':' + $w + ':' + $r + ':ask:' + $at
}

# One RateLimitSnapshot at fact path $b (its id, else $key) into $cs: its
# primary and secondary windows, the plan, reached.
function Add-CodexAskSnap($m, $cs, [string]$b, [string]$key, [string]$at) {
    $id = $key
    if ((Get-FactT $m ($b + '.limitId')) -ceq 's') { $id = Get-FactV $m ($b + '.limitId') }
    $id = [regex]::Replace($id, '[^A-Za-z0-9_.-]', '')
    if (-not $id) { $id = 'codex' }
    $cs.out += Get-CodexAskWin $m ($id + '.primary') ($b + '.primary') $at
    $cs.out += Get-CodexAskWin $m ($id + '.secondary') ($b + '.secondary') $at
    if ($cs.plan -ceq '-' -and (Get-FactT $m ($b + '.planType')) -ceq 's' -and (Get-FactV $m ($b + '.planType')) -cmatch '\A[A-Za-z0-9_-]+\z') { $cs.plan = Get-FactV $m ($b + '.planType') }
    if ((Get-FactT $m ($b + '.rateLimitReachedType')) -ceq 's') { $cs.reached = 1 }
}

# Codex app-server account/rateLimits/read reply (facts) -> as
# Get-ClaudeAskLine: each RateLimitSnapshot of rateLimitsByLimitId (else
# rateLimits) as <limitId>.primary and .secondary, the id as the rollout path
# makes it (CODEX_USAGE).
function Get-CodexAskLine($facts, [string]$at) {
    $m = Read-FactMap $facts
    # Measured (0.165.0): -32600 "codex account authentication required to
    # read rate limits" (signed out), -32600 "chatgpt authentication required
    # to read rate limits" (an API key: no plan limits), -32603 "failed to
    # fetch codex rate limits: GET .../wham/usage failed: 401 ..." (the
    # backend refused). The message itself goes nowhere.
    if ($m.F.ContainsKey('error.message') -or $m.F.ContainsKey('error.code')) {
        $e = (Get-FactV $m 'error.message').ToLowerInvariant()
        if ($e -cmatch 'chatgpt authentication required') { return 'ERR not-subscriber' }
        if ($e -cmatch 'authentication required|401|403') { return 'ERR auth' }
        return 'ERR failed'
    }
    $cs = @{ plan = '-'; reached = 0; out = '' }
    $nk = 0
    $B = 'result.rateLimitsByLimitId.'
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($p in $m.O) {
        if (-not $p.StartsWith($B, $Ord)) { continue }
        $k = $p.Substring($B.Length)
        $d = $k.IndexOf('.')
        if ($d -ge 0) { $k = $k.Substring(0, $d) }
        if (-not $seen.Add($k)) { continue }
        Add-CodexAskSnap $m $cs ($B + $k) $k $at
        $nk++
    }
    if ($nk -eq 0) { Add-CodexAskSnap $m $cs 'result.rateLimits' 'codex' $at }
    if (-not $cs.out -and $cs.plan -ceq '-' -and $cs.reached -eq 0 -and -not $m.F.ContainsKey('result.rateLimits.limitId') -and $nk -eq 0) { return 'ERR failed' }
    return 'OK - - - 0 - ' + $cs.plan + ' ' + $cs.reached + $cs.out
}

# The time an answer came (SIMPLETERM_HOOK_TEST_TS in tests).
function Get-AskNow {
    if ($env:SIMPLETERM_HOOK_TEST -eq '1' -and $env:SIMPLETERM_HOOK_TEST_TS) { return (BS $env:SIMPLETERM_HOOK_TEST_TS) }
    return [string](Now-Epoch)
}

# The ask itself (the detached child): runs it, makes the `usage` event from
# its answer (windows src ask, uq) and sends it to the tunnels (ask_run).
function Invoke-AskChild($job) {
    $ap = US ([string]$job.ap)
    $af = US ([string]$job.af)
    $Script:AV = [string]$job.av
    # The common fields came with the job.
    $Script:V2C = $true
    # The executable's version, checked by Invoke-UsageAsk.
    $bv = [string]$job.bv
    $hk = $false
    if ($Script:Agent -ceq 'claude') {
        $w2 = '"type":"control_response"'
        $q = Invoke-AskPipe $ap '-p --input-format stream-json --output-format stream-json --verbose --safe-mode --strict-mcp-config --no-session-persistence --include-hook-events' `
            @('{"type":"control_request","request_id":"1","request":{"subtype":"get_usage","skip_behaviors":true}}') @() '' $w2
        # A hook ran in the ask (--include-hook-events shows it; measured 0):
        # the probe guard did not hold or the ask ran as a turn, so as with
        # spend (D21).
        $head = Get-AskHead $q
        foreach ($k in @('hook_started', 'hook_progress', 'hook_response')) {
            if ($head.Contains('{"type":"system","subtype":"' + $k + '"')) { $hk = $true }
        }
    } elseif ($Script:Agent -ceq 'codex') {
        $w2 = '"id":2,'
        $q = Invoke-AskPipe $ap 'app-server' @('{"id":1,"method":"initialize","params":{"clientInfo":{"name":"simpleterm","version":"' + $HookVersion + '"}}}') `
            @('{"method":"initialized"}', '{"id":2,"method":"account/rateLimits/read"}') '"id":1,' $w2
    } else { return }
    $at = Get-AskNow
    $a = ''
    if ($q.res -ceq 'ok') {
        $facts = Get-AskFacts $q.text $w2
        if ($Script:Agent -ceq 'claude') { $a = [string](Get-ClaudeAskLine $facts $at) } else { $a = [string](Get-CodexAskLine $facts $at) }
    }
    $err = ''
    if ($a.StartsWith('OK ', $Ord)) { $err = '' }
    elseif ($a.StartsWith('ERR ', $Ord)) { $err = $a.Substring(4) }
    elseif ($q.res -ceq 'timeout') { $err = 'timeout' }
    else { $err = 'failed' }
    if ($hk) { $err = 'spent' }
    if ($err -ceq 'spent') {
        # The ask cost a model call: no more asks of this executable version
        # (added to the set, D21); a failed ask too.
        Add-AskStopped $bv
        $err = 'failed'
        Update-AskFails $bv $true
    } elseif ($err -ceq 'failed' -or $err -ceq 'timeout' -or $err -ceq 'unsupported') {
        Update-AskFails $bv $true
    } elseif (-not $err) {
        Update-AskFails $bv $false
    }
    $shown = $err
    if (-not $shown) { $shown = 'ok' }
    Write-Log ('usage-ask ' + $Script:Agent + ' ' + $shown)
    # A failed sign-in, or an account without plan limits (an API key, a
    # gateway): not asked again until the credentials change (sh: ask_run).
    if ($err -ceq 'auth' -or $err -ceq 'not-subscriber') { [void](Write-FileB ($af + '.auth') '') }
    $Script:Ts = $at
    if (Test-UInt $at) { $Script:Now = [int64]$at }
    $Script:UsageJson = ''
    if (-not $err) { $Script:UsageJson = (Format-UsageLine $a.Substring(3)).json }
    $uq = ',"uq":{"src":"ask","at":' + $at + ',"ok":'
    if (-not $err) { $uq += 'true}' } else { $uq += 'false,"err":"' + $err + '"}' }
    $Script:RidUsed = $true
    Send-Usage (Get-UsageRid) $uq '' '' -Sync
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
    $now = $Script:Now
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
    Write-Log ('duplicate ' + $Script:HookEvent)
    return $false
}

# --- decisions (TDS_AGENT_EVENTS_V2 section 5) -----------------------------------

# A reason the user typed, wrapped as Claude Code reads a user's rejection: a
# bare reason is read as script output and ignored [measured].
$ClaudeDeny = 'The user doesn''t want to proceed with this tool use. The tool use was rejected (eg. if it was a file edit, the new_string was NOT written to the file). To tell you how to proceed, the user said:\n'

# Prints a device decision (allow|deny) in the agent's own format (the v1
# decisions; Write-V2Decision has the others).
function Write-Decision([string]$d) {
    if ($Script:Agent -cne 'claude' -and $Script:Agent -cne 'codex') { return }
    if ($d -ceq 'allow') {
        Write-Out ('{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"allow"}}' + (Get-StateJson 'running') + '}')
    } elseif ($d -ceq 'deny') {
        Write-Out ('{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"deny","message":"Denied from SimpleTerm"}}' + (Get-StateJson 'running') + '}')
    }
}

# Prints decision $act (a decision id, section 4.3) in the agent's format, with
# X* from its extension (section 5.4). False if there is nothing to print for
# it here.
function Write-V2Decision([string]$act) {
    $a = $Script:Agent
    if ($act -ceq 'allow' -or $act -ceq 'deny') { Write-Decision $act; return $true }
    if ($a -ceq 'claude' -and $act -ceq 'allow_scope') {
        $sg = Get-RawSpan ('permission_suggestions.' + $Script:XOrig)
        if (-not $sg) { return $false }
        Write-Out ('{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"allow","updatedPermissions":[' + $sg + ']}}' + (Get-StateJson 'running') + '}')
        return $true
    }
    if ($a -ceq 'claude' -and ($act -ceq 'deny_reason' -or $act -ceq 'plan_refine')) {
        Write-Out ('{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"deny","message":"' + $ClaudeDeny + $Script:XReason + '"}}' + (Get-StateJson 'running') + '}')
        return $true
    }
    if ($a -ceq 'claude' -and $act -ceq 'answer') {
        $qs = Get-RawSpan 'tool_input.questions'
        if (-not $qs -or -not $Script:XAnswers) { return $false }
        Write-Out ('{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"allow","updatedInput":{"questions":' + $qs + ',"answers":' + $Script:XAnswers + '}}}' + (Get-StateJson 'running') + '}')
        return $true
    }
    if ($a -ceq 'claude' -and $act -ceq 'plan_approve') {
        $ti = Get-RawSpan 'tool_input'
        if (-not $ti) { return $false }
        $up = ''
        if ($Script:XMode -ceq 'accept_edits') { $up = ',"updatedPermissions":[{"type":"setMode","mode":"acceptEdits","destination":"session"}]' }
        Write-Out ('{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"allow","updatedInput":' + $ti + $up + '}}' + (Get-StateJson 'running') + '}')
        return $true
    }
    if ($a -ceq 'codex' -and $act -ceq 'deny_reason') {
        Write-Out ('{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"deny","message":"' + $Script:XReason + '"}}}')
        return $true
    }
    return $false
}

# Splits a facts line into path, type, value.
function Split-Fact([string]$line) {
    $t1 = $line.IndexOf([char]9)
    if ($t1 -lt 0) { return @($line, '', '') }
    $t2 = $line.IndexOf([char]9, $t1 + 1)
    if ($t2 -lt 0) { return @($line.Substring(0, $t1), $line.Substring($t1 + 1), '') }
    return @($line.Substring(0, $t1), $line.Substring($t1 + 1, $t2 - $t1 - 1), $line.Substring($t2 + 1))
}

# The answers of an `answer` decision (E: the event's facts, X: the
# extension's) in Claude Code's form, or BAD (ANSWER_AWK): an object
# {question: answer} (a choice by its label, several as an array, typed text as
# it is, both joined with ", "). Every question must be answered (M11), choices
# index the original list, typed text only where the question takes it.
function Get-Answers([string]$factsE, [string]$factsX, [string]$qp, [string]$fq, [string]$fl, [bool]$free, [double]$nq) {
    $E = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::Ordinal)
    $X = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::Ordinal)
    $XT = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::Ordinal)
    # (a key given twice counts with its first value, section 5.5; sh: ANSWER_AWK)
    foreach ($line in $factsE.Split([char]10)) { $f = Split-Fact $line; if (-not $E.ContainsKey($f[0])) { $E[$f[0]] = $f[2] } }
    foreach ($line in $factsX.Split([char]10)) { $f = Split-Fact $line; if (-not $X.ContainsKey($f[0])) { $X[$f[0]] = $f[2]; $XT[$f[0]] = $f[1] } }
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    $PL = @{}
    $NP = @{}
    $TX = @{}
    $QI = @{}
    $n = 0
    $bad = $false
    for ($k = 0; $k -lt 64 -and $X.ContainsKey('answers.' + $k + '.q'); $k++) {
        $q = $X['answers.' + $k + '.q']
        if ($XT['answers.' + $k + '.q'] -cne 'r' -or $q -cnotmatch '\A[0-9]+\z' -or [double]$q -ge $nq -or $seen.Contains($q)) { $bad = $true; break }
        [void]$seen.Add($q)
        $n++
        $no = 0
        while ($no -lt 64 -and ($E.ContainsKey($qp + '.' + $q + '.options.' + $no + '.' + $fl) -or $E.ContainsKey($qp + '.' + $q + '.options.' + $no))) { $no++ }
        $picks = @()
        for ($m = 0; $m -lt 64 -and $X.ContainsKey('answers.' + $k + '.pick.' + $m); $m++) {
            $v = $X['answers.' + $k + '.pick.' + $m]
            if ($v -cnotmatch '\A[0-9]+\z' -or [double]$v -ge $no) { $bad = $true; break }
            $b = $qp + '.' + $q + '.options.' + $v
            $l = ''
            if ($E.ContainsKey($b + '.' + $fl)) { $l = $E[$b + '.' + $fl] } elseif ($E.ContainsKey($b)) { $l = $E[$b] }
            $picks += $l
        }
        if ($bad) { break }
        $t = ''
        if ($XT.ContainsKey('answers.' + $k + '.text') -and $XT['answers.' + $k + '.text'] -ceq 's') { $t = $X['answers.' + $k + '.text'] }
        if (($t -and -not $free) -or $t.Length -gt 2400 -or ($picks.Count -eq 0 -and -not $t)) { $bad = $true; break }
        $PL[$k] = $picks
        $NP[$k] = $picks.Count
        $TX[$k] = $t
        $QI[$k] = $q
    }
    if ($bad -or $n -ne $nq -or $n -eq 0) { return 'BAD' }
    $o = '{'
    for ($k = 0; $k -lt $n; $k++) {
        if ($TX[$k] -or $NP[$k] -eq 1) {
            $v = ($PL[$k] -join ', ')
            if ($TX[$k]) { if ($v) { $v += ', ' }; $v += $TX[$k] }
            $v = '"' + $v + '"'
        } else {
            $v = '[' + (($PL[$k] | ForEach-Object { '"' + $_ + '"' }) -join ',') + ']'
        }
        if ($k -gt 0) { $o += ',' }
        $qt = ''
        $key = $qp + '.' + $QI[$k] + '.' + $fq
        if ($E.ContainsKey($key)) { $qt = $E[$key] }
        $o += '"' + $qt + '":' + $v
    }
    return ($o + '}')
}

# Judges the decision that link $L brought (section 5.5, rq_judge): JV apply
# (JA the decision id), window (nothing to print: a v1 allow of a question),
# bad (1, 2, 4), changed (3, 5) or none (the wait ended without one).
function Invoke-Judge($L) {
    $Script:JV = 'none'
    $Script:JA = ''
    $Script:XReason = ''
    $Script:XMode = ''
    $Script:XAnswers = ''
    $Script:XOrig = ''
    $jd = $L.poll.r
    $jx = $L.poll.x
    $jp = $L.poll.xp
    $jrq = ''; $jwin = ''; $jcan = ''; $jaff = ''; $jns = 0; $jmodes = ''; $jnq = 0; $jsmap = ''
    if ($null -ne $L.meta -and $L.meta.Count -gt 0) {
        if ($L.meta[0].StartsWith('META ', $Ord)) {
            foreach ($kv in (Split-Words $L.meta[0].Substring(5))) {
                if ($kv.StartsWith('rq=', $Ord)) { $jrq = $kv.Substring(3) }
                elseif ($kv.StartsWith('win=', $Ord)) { $jwin = $kv.Substring(4) }
                elseif ($kv.StartsWith('can=', $Ord)) { $jcan = $kv.Substring(4) }
                elseif ($kv.StartsWith('aff=', $Ord)) { $jaff = $kv.Substring(4) }
                elseif ($kv.StartsWith('ns=', $Ord)) { $jns = $kv.Substring(3) }
                elseif ($kv.StartsWith('modes=', $Ord)) { $jmodes = $kv.Substring(6) }
                elseif ($kv.StartsWith('nq=', $Ord)) { $jnq = $kv.Substring(3) }
            }
        }
        foreach ($x in $L.meta) { if ($x.StartsWith('#smap' + $Tab + 's' + $Tab, $Ord)) { $jsmap = $x.Substring(8) } }
    }
    if ($jd -ceq 'invalid') { $Script:JV = 'bad'; return }
    if ($jd -cne 'allow' -and $jd -cne 'deny') { return }
    if ($jx -ceq 'bad') { $Script:JV = 'bad'; return }
    if ($jx -cne 'ok') {
        # No extension (an older app, a relay before R2, an alert's quick
        # action): the decision's default meaning for the request.
        if ($jd -ceq 'deny') { $Script:JA = 'deny' }
        elseif ($jwin -ceq 'question') { $Script:JV = 'window'; return }
        elseif ($jwin -ceq 'plan') { $Script:JA = 'plan_approve' }
        else { $Script:JA = 'allow' }
        if ($Script:JA -ceq 'plan_approve' -and $Script:Agent -ceq 'claude') { $Script:XMode = 'default' }
        if (-not (',' + $jcan + ',').Contains(',' + $Script:JA + ',') -and $jcan) { $Script:JV = 'bad'; return }
        $Script:JV = 'apply'
        return
    }
    # The extension (section 5.2).
    $xv = ''; $xr = ''; $xn = ''; $xd = ''; $xq = ''; $xa = ''; $xs = ''; $xm = ''; $xseen = ''
    $xfacts = (Get-Facts $jp '') -join "`n"
    $xks = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($line in $xfacts.Split([char]10)) {
        if (-not $line) { continue }
        $f = Split-Fact $line
        $xk = $f[0]
        # A key given twice counts with its first value (section 5.5).
        if (-not $xks.Add($xk)) { continue }
        if ($xk -ceq 'v') { $xv = $f[2] }
        elseif ($xk -ceq 'rid') { $xr = $f[2] }
        elseif ($xk -ceq 'nonce') { $xn = $f[2] }
        elseif ($xk -ceq 'decision') { $xd = $f[2] }
        elseif ($xk -ceq 'req') { $xq = $f[2] }
        elseif ($xk -ceq 'act') { $xa = $f[2] }
        elseif ($xk -ceq 'scope') { if ($f[1] -ceq 'r') { $xs = $f[2] } }
        elseif ($xk -ceq 'mode') { $xm = $f[2] }
        elseif ($xk -ceq 'reason') { if ($f[1] -ceq 's') { $Script:XReason = $f[2] } }
        elseif ($xk.StartsWith('seen.', $Ord)) { $xseen += ' ' + $f[2] }
    }
    $nonce = $L.poll.nonce
    if (-not $nonce) { $nonce = '-' }
    if ($xv -cne '1' -or $xr -cne $L.poll.rid -or $xn -cne $nonce -or $xd -cne $jd) { $Script:JV = 'bad'; return }
    # N10: the request the user saw.
    if (-not $jrq -or $xq -cne $jrq) { $Script:JV = 'changed'; return }
    if (-not (',' + $jcan + ',').Contains(',' + $xa + ',')) { $Script:JV = 'bad'; return }
    if (@('allow', 'allow_scope', 'allow_edit', 'answer', 'plan_approve', 'form_accept') -ccontains $xa) {
        if ($jd -cne 'allow') { $Script:JV = 'bad'; return }
    } elseif ($jd -cne 'deny') { $Script:JV = 'bad'; return }
    if ($xa -ceq 'allow_scope') {
        if (-not (Test-UInt $xs) -or [int64]$xs -ge [int64]$jns) { $Script:JV = 'bad'; return }
        $w = Split-Words $jsmap
        if ($w.Count -gt 0) {
            if ([int64]$xs -ge $w.Count) { $Script:JV = 'bad'; return }
            $Script:XOrig = $w[[int]$xs]
        }
    } elseif ($xa -ceq 'plan_approve') {
        if ($xm) {
            if ((',' + $jmodes + ',').Contains(',' + $xm + ',')) { $Script:XMode = $xm } else { $Script:JV = 'bad'; return }
        }
    } elseif ($xa -ceq 'deny_reason' -or $xa -ceq 'plan_refine') {
        if (-not $Script:XReason -or $Script:XReason.Length -gt 6000) { $Script:JV = 'bad'; return }
    } elseif ($xa -ceq 'answer') {
        $Script:XAnswers = Get-Answers ([string]$Script:FactsText) $xfacts 'tool_input.questions' 'question' 'label' $true ([double]$jnq)
        if (-not $Script:XAnswers -or $Script:XAnswers -ceq 'BAD') { $Script:XAnswers = ''; $Script:JV = 'bad'; return }
    }
    # N10: the other requests that this decision also settles were all seen
    # (OpenCode only: no other requests here).
    if ((',' + $jaff + ',').Contains(',' + $xa + ',')) {
        if (-not (' ' + $xseen + ' ').Contains(' ' + $jrq + ' ')) { $Script:JV = 'changed'; return }
    }
    $Script:JA = $xa
    $Script:JV = 'apply'
}

# --- waiting for a decision (section 4.6) --------------------------------------

# Sends the request in SPEC as event $ev to the links of $links whose kind is
# $pass (tunnel, relay or all), all at once: rid $rid, decidable $dec (with a
# nonce), waitov $waitov, relay time $maxtime (rq_send). Each link's state goes
# to $L.st: push, nonce, rid, dec, kind, code, fmt; its META to $L.meta.
function Send-RqPass($links, [string]$pass, [bool]$dec, [string]$waitov, [string]$ev, [int64]$maxtime, [string]$rid) {
    $pending = New-Object 'System.Collections.Generic.List[object]'
    foreach ($L in $links) {
        $link = Read-Link $L.f
        if ($null -eq $link) { continue }
        if ($pass -ceq 'tunnel' -and $link.kind -cne 'tunnel') { continue }
        if ($pass -ceq 'relay' -and $link.kind -ceq 'tunnel') { continue }
        $rd = $dec
        $rw = $waitov
        # A question is decidable only where the receiver takes decisions on
        # questions (fmt=2; for the relay that is R1). Elsewhere it is an alert,
        # and one whose window would hide while the hook waits does not wait.
        if ($ev -ceq 'question' -and $link.fmt -cne '2' -and $rd) {
            $rd = $false
            if ($rw -ceq 'hidden') { $rw = 'none' }
        }
        $rn = ''
        if ($rd) {
            $rn = New-RandomHex 16
            if ($env:SIMPLETERM_HOOK_TEST -eq '1' -and $env:SIMPLETERM_HOOK_TEST_NONCE) { $rn = $env:SIMPLETERM_HOOK_TEST_NONCE }
            if (-not (Test-Hex $rn 32)) { $rd = $false; $rn = '' }
        }
        $Script:WaitOv = $rw
        $Script:IngMt = [string]$maxtime
        try { $op = Start-Ingest $link $rid $ev $rn } catch { $op = @{ seal = $true; link = $link; ev = $ev; meta = $null } }
        $pending.Add(@{ L = $L; link = $link; op = $op; rn = $rn; rd = $rd; rw = $rw })
    }
    $Script:WaitOv = ''
    $Script:IngMt = ''
    foreach ($p in $pending) {
        $r = Complete-Ingest $p.op
        $meta = $p.op.meta
        if ($r.code -ceq '400' -and $r.err -ceq 'invalid-nh' -and $p.rn -and $p.link.kind -cne 'tunnel') {
            # The relay lost R1 (rolled back): the same rid once more, not
            # decidable, and no wait there (section 2.4).
            Write-Log ('ingest invalid-nh link=' + (Short $p.link.link) + ': again without a nonce')
            $p.rd = $false
            $p.rn = ''
            $Script:WaitOv = $p.rw
            $Script:IngMt = [string]$maxtime
            $op2 = Start-Ingest $p.link $rid $ev ''
            $Script:WaitOv = ''
            $Script:IngMt = ''
            $r2 = Complete-Ingest $op2
            $r = @{ push = $r2.push; code = $r2.code; err = $r.err }
            $meta = $op2.meta
        }
        $kind = 'relay'
        if ($p.link.kind -ceq 'tunnel') { $kind = 'tunnel' }
        $fmt = '1'
        if ($p.link.fmt -ceq '2') { $fmt = '2' }
        $p.L.st = @{ push = $r.push; nonce = $p.rn; rid = $rid; dec = $p.rd; kind = $kind; code = $r.code; fmt = $fmt }
        $p.L.meta = $meta
        $p.L.link = $p.link
    }
}

# Starts waiting on link $L if it took the request to wait on (rq_poll).
function Start-RqPoll($L) {
    if ($null -eq $L.st -or $L.st.push -cne 'sent' -or -not $L.st.dec) { return }
    $L.waiting = $true
    $L.poll = @{ rid = $L.st.rid; nonce = $L.st.nonce; op = $null; nextAt = [DateTime]::MinValue; started = 0; done = $false; r = 'none'; x = 'none'; xp = '' }
}

# One step of a link's long poll for the decision (poll_link): on its end,
# poll.done with r allow, deny, invalid (the dmac does not match) or none; x
# the decision extension none, bad (its MAC does not match or it does not
# open) or ok; xp its plaintext when ok.
function Step-RqPoll($L, [int64]$deadline, [int64]$pollWait) {
    $P = $L.poll
    if ($P.done) { return }
    $link = $L.link
    if ($null -eq $P.op) {
        $now = Now-Epoch
        if ($now -ge $deadline) { $P.done = $true; return }
        if ([DateTime]::UtcNow -lt $P.nextAt) { return }
        $w = [Math]::Min($pollWait, $deadline - $now)
        if ($w -lt 1) { $w = 1 }
        $P.op = Start-Relay $link 'GET' ('/v1/decision?rid=' + $P.rid + '&wait=' + $w) '' ([int]($w + 10))
        $P.started = $now
        return
    }
    if (-not (Test-RelayDone $P.op)) { return }
    $r = Complete-Relay $P.op 8192
    $P.op = $null
    $code = $r.code
    if ($code -eq 200) {
        $kv = Get-JsonKV $r.body @('status', 'decision', 'dmac', 'dext.v', 'dext.iv', 'dext.ct', 'dext.mac')
        if ((Get-Field $kv 'status') -ceq 'decided') {
            $ddec = Get-Field $kv 'decision'
            $dmac = Get-Field $kv 'dmac'
            $res = 'invalid'
            if (($ddec -ceq 'allow' -or $ddec -ceq 'deny') -and (Test-Hex $dmac 64)) {
                if (Test-SameHex (Get-HmacHex $link.mac ('st1-dec.' + $P.rid + '.' + $ddec + '.' + $P.nonce)) $dmac) { $res = $ddec }
            }
            $x = 'none'
            $xp = ''
            $dxv = Get-Field $kv 'dext.v'
            $dxiv = Get-Field $kv 'dext.iv'
            $dxct = Get-Field $kv 'dext.ct'
            $dxmac = Get-Field $kv 'dext.mac'
            if ($res -cne 'invalid' -and ($dxv + $dxiv + $dxct + $dxmac)) {
                # The extension is MACed with st1-dext. (not the event's st1.),
                # so an event envelope cannot be passed back as one.
                $x = 'bad'
                $ct = $dxct.Replace('\/', '/')
                if ($ct -cnotmatch '\A[A-Za-z0-9+/=]+\z') { $ct = '' }
                if ($dxv -ceq '1' -and (Test-Hex $dxiv 32) -and (Test-Hex $dxmac 64) -and $ct -and $ct.Length -le 2944 -and
                    (Test-SameHex (Get-HmacHex $link.mac ('st1-dext.' + $dxiv + '.' + $ct)) $dxmac)) {
                    $xp = Open-Dext $link $dxiv $ct
                    if ($xp) { $x = 'ok' }
                }
            }
            Write-Log ('decision link=' + (Short $link.link) + ' result=' + $res + ' dext=' + $x)
            $P.r = $res
            $P.x = $x
            $P.xp = $xp
            $P.done = $true
            return
        }
        if ((Now-Epoch) - $P.started -lt 1) { $P.nextAt = [DateTime]::UtcNow.AddSeconds(1) }
        return
    }
    if ($code -eq 404 -or $code -eq 410 -or $code -eq 401 -or $code -eq 403 -or $code -eq 409) {
        Write-Log ('decision link=' + (Short $link.link) + ' http=' + $code)
        if ($code -eq 410 -and (Get-Field (Get-JsonKV $r.body @('error')) 'error') -ceq 'revoked') {
            [void](Write-FileB (Join-Path $RunDir ($link.link + '.revoked')) '')
        }
        $P.done = $true
        return
    }
    if ($code -eq 0 -and $link.kind -ceq 'tunnel') {
        # The app's connection ended (or the port is gone): nothing will
        # answer there, so stop instead of waiting out the deadline.
        Write-Log ('decision link=' + (Short $link.link) + ' tunnel-gone')
        $P.done = $true
        return
    }
    $P.nextAt = [DateTime]::UtcNow.AddSeconds(2)
}

# A decision from link $L was dropped (bad or changed, section 5.5): that
# link's wait ends; a tunnel of a v2 app hears it at once and gets the request
# again under a new rid (3 times at most) (rq_reject).
function Invoke-RqReject($L, [string]$why, [int64]$start) {
    Write-Log ('decision link-' + $L.i + ' dropped: ' + $why)
    if ($L.st.kind -cne 'tunnel' -or $L.st.fmt -cne '2') { return }
    Send-Result $L.link 'link' $why $L.st.rid ''
    if ($L.n -ge 3) { return }
    if (Test-AnsweredLocally $start $Script:Fp) { return }
    $L.n++
    $nr = New-RandomHex 8
    if (-not (Test-Hex $nr 16)) { return }
    Send-RqPass @($L) 'tunnel' $true '' $Script:RqEv 5 $nr
    Start-RqPoll $L
}

# Ends the request: the request-level result to every tunnel that took it, from
# a detached child ($out; $dl the link whose decision applied, $act) (rq_finish).
function Complete-Request($links, [string]$out, $dl, [string]$act) {
    foreach ($L in $links) {
        if ($null -ne $L.poll -and $null -ne $L.poll.op) { try { $L.poll.op.req.Abort() } catch { } }
    }
    if (-not $Script:ReqId) { return }
    $items = @()
    foreach ($L in $links) {
        if ($null -eq $L.st -or $L.st.kind -cne 'tunnel' -or $L.st.code -cne '200') { continue }
        $fo = $out
        $fa = $act
        if ($out -ceq 'applied' -and -not [object]::ReferenceEquals($L, $dl)) { $fo = 'other'; $fa = '' }
        if ($fo -ceq 'window') { $fa = $Script:RqWin }
        $items += ((BS $L.f) + $Tab + 'req' + $Tab + $fo + $Tab + $L.st.rid + $Tab + $fa)
    }
    if ($items.Count -eq 0) { return }
    $job = New-Job 'resolved'
    $job.items = ($items -join "`n")
    Start-Child $job
}

# Sends the request in SPEC (ev $ev) the way $mode says (section 4.6) and
# waits per link; then prints the agent's answer, or nothing (its safe
# no-decision), and tells the tunnels how the request ended (request_flow).
#   shared   every link at once, decidable (Claude Code)
#   hidden   tunnels first; if one answered, the relay only gets an alert
#            without a nonce; otherwise the relay is decidable (Codex)
function Invoke-RequestFlow([string]$ev, [string]$mode) {
    $Script:RqEv = $ev
    $cap = Get-ConfWaitCap $Script:Agent
    $pollWait = Get-ConfPollWait
    # The cap counts from the hook's start (the tunnel's 5 seconds and the
    # relay's ingest included, section 4.6).
    $start = $Script:T0
    $Script:ResBase = Get-ResLineCount
    $deadline = $start + $cap
    $Script:ReqId = ''
    $Script:RqWin = ''
    foreach ($line in ([string]$Script:Spec).Split([char]10)) {
        if ($line.StartsWith('req.id' + $Tab + 's' + $Tab, $Ord)) { $Script:ReqId = $line.Substring(9) }
        elseif ($line.StartsWith('req.win' + $Tab + 's' + $Tab, $Ord)) { $Script:RqWin = $line.Substring(10) }
    }
    $Script:RidUsed = $true
    $agentPid = Get-AgentPid
    $links = @()
    $n = 0
    foreach ($f in $Script:LinkFiles) {
        $n++
        $links += @{ i = $n; f = $f; st = $null; meta = $null; link = $null; n = 0; waiting = $false; poll = $null }
    }
    function Get-Remain { $r = $deadline - (Now-Epoch); if ($r -lt 1) { $r = 1 }; if ($r -gt 20) { $r = 20 }; return $r }
    if ($mode -ceq 'shared') {
        Send-RqPass $links 'all' $true '' $ev 20 $Script:Rid
    } elseif ($mode -ceq 'hidden') {
        Send-RqPass $links 'tunnel' $true '' $ev 5 $Script:Rid
        $took = $false
        foreach ($L in $links) { if ($null -ne $L.st -and $L.st.kind -ceq 'tunnel' -and $L.st.code -ceq '200') { $took = $true } }
        if ($took) {
            # The app is connected: other devices get an alert without buttons,
            # so a decision there is never left unheard.
            $sw = $Script:WaitOv
            $Script:WaitOv = 'none'
            Send-Background 'question' $Script:Rid 'relay'
            $Script:WaitOv = $sw
        } else {
            Send-RqPass $links 'relay' $true '' $ev (Get-Remain) $Script:Rid
        }
    }
    foreach ($L in $links) { Start-RqPoll $L }

    $decision = ''
    $dl = $null
    $out = 'window'
    $nextCheck = [DateTime]::MinValue
    while ($true) {
        $waiting = $false
        $ended = $false
        foreach ($L in $links) {
            if (-not $L.waiting) { continue }
            $waiting = $true
            Step-RqPoll $L $deadline $pollWait
            if (-not $L.poll.done) { continue }
            $L.waiting = $false
            Invoke-Judge $L
            if ($Script:JV -ceq 'apply' -or $Script:JV -ceq 'window') {
                if (Test-AnsweredLocally $start $Script:Fp) { $out = 'terminal'; $ended = $true; break }
                $decision = $Script:JA
                $dl = $L
                if ($Script:JV -ceq 'window') { $decision = '' }
                $ended = $true
                break
            }
            if ($Script:JV -ceq 'bad' -or $Script:JV -ceq 'changed') { Invoke-RqReject $L $Script:JV $start }
        }
        if ($ended) { break }
        if (-not $waiting) { break }
        if ([DateTime]::UtcNow -ge $nextCheck) {
            $nextCheck = [DateTime]::UtcNow.AddSeconds(1)
            if (Test-AnsweredLocally $start $Script:Fp) {
                Write-Log 'permission answered-at-terminal'
                $out = 'terminal'
                break
            }
            if ($agentPid -gt 0 -and $null -eq (Get-Process -Id $agentPid -ErrorAction SilentlyContinue)) {
                Write-Log 'permission agent-gone'
                $out = 'gone'
                break
            }
            if ((Now-Epoch) -ge $deadline) { Write-Log 'permission timeout'; break }
        }
        Start-Sleep -Milliseconds 100
    }
    $Script:Logged = $true
    if ($decision -and (Write-V2Decision $decision)) {
        Write-Log ('permission ' + $decision)
        Complete-Request $links 'applied' $dl $decision
    } else {
        if ($out -ceq 'window' -and $null -eq $dl) { Write-Log 'permission no-decision' }
        Complete-Request $links $out $null ''
    }
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
                $lines = [IO.File]::ReadAllLines($bg, $Latin1)
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
    $p = Get-InputFile $Script:TPath
    if (-not $p) { return $false }
    $v = ''
    try {
        $fs = [IO.File]::Open($p, 'Open', 'Read', 'ReadWrite')
        try {
            $n = [Math]::Min([int64]65536, $fs.Length)
            [void]$fs.Seek(-$n, 'End')
            $buf = New-Object byte[] $n
            $read = $fs.Read($buf, 0, $n)
            $ms = [regex]::Matches($Utf8.GetString($buf, 0, $read), '"version" *: *"([0-9][0-9.]*)"')
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
function Test-CodexGoalActive([string]$p) {
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
    $lines = (ConvertFrom-JsonEscapes (US $s)) -split "`n"
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
# \u00XX in the ASCII range (0x20-0x7F) is that character (Go writes `&` as `\u0026`), any
# other \u escape
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

# A heredoc operator at i (<<, not <<<): its delimiter, or '' when there is none. $SvcHde is the
# index of the last character of the operator. The delimiter starts with a letter or _ (so
# $((1<<3)) and (( n <<= 1 )) are not heredocs) unless it is quoted.
$SvcHde = 0
function Get-SvcHdParse([string]$s, [int]$i) {
    $len = $s.Length
    $e = $i + 2
    if ($e -lt $len -and $s[$e] -eq '-') { $e++ }
    while ($e -lt $len -and ($s[$e] -eq ' ' -or $s[$e] -eq "`t")) { $e++ }
    $bq = ''
    if ($e -lt $len -and ($s[$e] -eq "'" -or $s[$e] -eq '"' -or $s[$e] -eq '\')) { $bq = [string]$s[$e]; $e++ }
    if (-not ($bq -eq "'" -or $bq -eq '"' -or ($e -lt $len -and ([string]$s[$e]) -cmatch '^[A-Za-z_]$'))) { return '' }
    $de = $e
    while ($de -lt $len -and " `t`n;&|()<>'`"".IndexOf($s[$de]) -lt 0) { $de++ }
    if ($de -le $e) { return '' }
    if ($bq -eq "'" -or $bq -eq '"') { $Script:SvcHde = $de } else { $Script:SvcHde = $de - 1 }
    return $s.Substring($e, $de - $e)
}

# From the line break at j: the index of the line break that ends the body (the line of hd).
function Get-SvcHdSkip([string]$s, [int]$j, [string]$hd) {
    $len = $s.Length
    while (($j + 1) -lt $len) {
        $nl = $s.IndexOf([char]10, $j + 1)
        if ($nl -lt 0) { $ln = $s.Substring($j + 1); $j = $len } else { $ln = $s.Substring($j + 1, $nl - $j - 1); $j = $nl }
        if ($ln.TrimStart(' ', "`t") -ceq $hd) { break }
    }
    return $j
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
                if ($hd -ne '') { $i = Get-SvcHdSkip $s $i $hd; $hd = '' }
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
                $d = Get-SvcHdParse $s $i
                if ($d -ne '') { $hd = $d; $i = $Script:SvcHde; [void]$out.Append(' '); continue }
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
            elseif ($ch -eq '<' -and ($i + 1) -lt $len -and $s[$i + 1] -eq '<' -and -not (($i + 2) -lt $len -and $s[$i + 2] -eq '<')) {
                # a heredoc inside a $(...) in double quotes (the line break follows the delimiter): its body
                # is not part of the command either
                $d = Get-SvcHdParse $s $i
                $j = $Script:SvcHde + 1
                while ($j -lt $len -and ($s[$j] -eq ' ' -or $s[$j] -eq "`t")) { $j++ }
                if ($d -ne '' -and $j -lt $len -and $s[$j] -eq "`n") { $i = Get-SvcHdSkip $s $j $d }
            }
        }
    }
    $t = $out.ToString()
    $t = $t.Replace('|&', '|')
    $t = [regex]::Replace($t, '[0-9]*[<>]&[0-9-]*', ' ')
    $t = [regex]::Replace($t, '&>>?', ' > ')
    return $t.Replace('||', ';').Replace('&&', ';').Replace('&', ';').Replace("`n", ';')
}

# A last pipeline command that ends early (head, grep -q|-l|-m N) can end the pipeline too: when the
# earlier command writes again it dies of SIGPIPE (not before; measured), so this is a guess.
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
    # A command over 64 KiB is not looked at (the hook has seconds, not a minute): not a service.
    if ($cmd.Length -gt 65536) { return $false }
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

# --- who started a turn, and what ran before it -----------------------------

# Checksum of the start of a prompt, to compare a scheduled prompt (Stop
# session_crons) with the prompt a later UserPromptSubmit carries.
function Get-PromptSum([string]$text) {
    return (Get-Sha256Hex (Limit-Json $text 200 800)).Substring(0, 16)
}

# PromptBy: who started the turn (user, task, schedule, agent); PromptUser
# true if a person typed the prompt (or we cannot tell). Claude Code names it
# in UserPromptSubmit `source` (user and sdk are people; system, loop_wakeup,
# schedule_wakeup and poll_event are not); where `source` is missing (2.1.316
# sends none) a <task-notification> or <agent-message> prompt, the /loop
# sentinel, or the prompt of a wake-up listed at the last Stop (session_crons)
# says so. Grok Build has no such field: the prompt id of a turn it starts
# itself begins with a fixed word (static, from the 1.0.70 binary), a
# person's is a UUID.
function Set-PromptOrigin {
    $by = 'user'
    if ($Script:Agent -ceq 'grok') {
        $p = $Script:PromptId
        foreach ($x in @('task-completed-', 'bash-completed-', 'monitor-completed-', 'subagent-completed-', 'workflow-completed-')) {
            if ($p.StartsWith($x, $Ord)) { $by = 'task' }
        }
        if ($p.StartsWith('scheduler-fired-', $Ord)) { $by = 'schedule' }
        foreach ($x in @('parent-agent-message-', 'parent-message-', 'notifications-', 'goal-summary-', 'goal-classifier-nudge-', 'plan-resume-')) {
            if ($p.StartsWith($x, $Ord)) { $by = 'agent' }
        }
    } else {
        $src = $Script:Src
        $pr = $Script:Prompt
        if ($src -ceq 'user' -or $src -ceq 'sdk') { }
        elseif ($src -ceq 'loop_wakeup' -or $src -ceq 'schedule_wakeup') { $by = 'schedule' }
        elseif ($src -ceq 'poll_event') { $by = 'task' }
        elseif ($src.Length -eq 0) {
            if ($pr.StartsWith('<task-notification>', $Ord)) { $by = 'task' }
            elseif ($pr.StartsWith('<agent-message ', $Ord)) { $by = 'agent' }
            elseif ($pr.StartsWith('<<autonomous-loop', $Ord)) { $by = 'schedule' }
            elseif ($pr.Length -gt 0) {
                $cronFile = Join-Path $RunDir ($Script:Sid + '.crons')
                $t = Read-FileB $cronFile
                if ($null -ne $t -and (Split-Words $t) -ccontains (Get-PromptSum $pr)) { $by = 'schedule' }
            }
        } else { $by = 'agent' }
    }
    $Script:PromptBy = $by
    $Script:PromptUser = ($by -ceq 'user')
}

# $Sid.turn: line 1 who started this turn, line 2 the ids of the background
# tasks that already ran when it started ($Sid.stopids, the last Stop's list),
# for the Stop that ends it.
function Write-TurnMark {
    $ids = Read-LineB (Join-Path $RunDir ($Script:Sid + '.stopids')) 0
    $who = $Script:PromptBy
    if ($Script:PromptUser) { $who = 'user' }
    [void](Write-FileB (Join-Path $RunDir ($Script:Sid + '.turn')) ($who + "`n" + $ids + "`n"))
}

# TurnAt: @-parameters of the end of a turn (TDS_AGENT_EVENTS_V2 section 6.1):
# end, asks (true|false), late. Who started the turn is the turn's mark; the
# background tasks and schedules come from the event's facts.
function Set-TurnAt([string]$end, [string]$asks, [string]$late) {
    $t = '@.turn' + $Tab + 's' + $Tab + '1' + $Nl + '@.end' + $Tab + 's' + $Tab + $end + $Nl
    $tb = $Script:TurnBy
    if (-not $tb) { $tb = Read-LineB (Join-Path $RunDir ($Script:Sid + '.turn')) 0 }
    if ($tb -ceq 'auto') { $tb = 'agent' }
    elseif (@('user', 'task', 'schedule', 'agent') -cnotcontains $tb) { $tb = 'unknown' }
    $t += '@.by' + $Tab + 's' + $Tab + $tb + $Nl
    if ($asks) { $t += '@.asks' + $Tab + 's' + $Tab + $asks + $Nl }
    if ($Script:Last) { $t += '@.last' + $Tab + 's' + $Tab + $Script:Last + $Nl }
    if ($late) { $t += '@.late' + $Tab + 's' + $Tab + $late + $Nl }
    if ($Script:StopAct -ceq 'true') { $t += '@.hook' + $Tab + 's' + $Tab + 'true' + $Nl }
    if ($Script:Agent -ceq 'grok') { $t += '@.bgp' + $Tab + 's' + $Tab + 'backgroundTasks' + $Nl + '@.cronp' + $Tab + 's' + $Tab + 'sessionCrons' + $Nl }
    else { $t += '@.bgp' + $Tab + 's' + $Tab + 'background_tasks' + $Nl + '@.cronp' + $Tab + 's' + $Tab + 'session_crons' + $Nl }
    $t += '@.prev' + $Tab + 's' + $Tab + $Script:PrevIds + $Nl + '@.svc' + $Tab + 's' + $Tab + $Script:BgSvcIdx + $Nl
    if ($Script:TGoal) { $t += '@.goal' + $Tab + 's' + $Tab + $Script:TGoal + $Nl }
    $Script:TurnAt = $t
}

# The request kind parameter lines (TDS_AGENT_EVENTS_V2 section 4).
function Set-RkAt([string]$kind, [string]$extra) {
    $Script:RkAt = '@.rkind' + $Tab + 's' + $Tab + $kind + $Nl + '@.rid' + $Tab + 's' + $Tab + $Script:Rid + $Nl + $extra
}

# One field of a background task (Stop `background_tasks`, Grok
# `backgroundTasks`), in document order: a task's id and type come before its
# description and command. Claude Code 2.1.316 type labels: work that reports
# back and wakes the agent (subagent, workflow, cloud session, MCP task: they
# end), work that may run for good (shell, monitor, an idle teammate; and
# labels we do not know), and its own housekeeping that never wakes it (dream,
# auto-mode scan, memory import, memory save: not counted). A shell whose
# command is a service counts in BgSvc.
function Add-BgField([string]$p, [string]$v) {
    $d1 = $p.IndexOf('.')
    $d2 = $p.IndexOf('.', $d1 + 1)
    $bk = $p.Substring($d1 + 1, $d2 - $d1 - 1)
    $bf = $p.Substring($d2 + 1)
    if ($bf -ceq 'id') {
        if ($v -cmatch '\A[A-Za-z0-9_-]+\z') { $Script:BgIdMap.Add(@($bk, $v)) }
    } elseif ($bf -ceq 'type') {
        if (@('dream', 'auto-mode scan', 'memory import', 'memory save') -ccontains $v) { return }
        if (@('subagent', 'workflow', 'cloud session', 'MCP task') -ccontains $v) { $Script:BgFinite++ }
        elseif ($v -ceq 'shell') { $Script:BgShells += ' ' + $bk }
        $Script:BgN++
        $Script:BgKeep += $bk
        if (-not $Script:BgPick) { $Script:BgPick = $bk; $Script:BgType = $v }
    } elseif ($bf -ceq 'description') {
        if ($bk -ceq $Script:BgPick -and -not $Script:BgDesc) { $Script:BgDesc = $v }
    } elseif ($bf -ceq 'command') {
        if ($bk -ceq $Script:BgPick -and -not $Script:BgCmd) { $Script:BgCmd = $v }
        if ((Test-InList $Script:BgShells $bk) -and (Test-ServiceCmd $v)) { $Script:BgSvc++; $Script:BgSvcIdx += ' ' + $bk }
    }
}

# The ids of the counted tasks in BgIds; BgNoId counts those with none.
function Complete-BgIds {
    $Script:BgIds = ''
    $Script:BgNoId = 0
    foreach ($bk in $Script:BgKeep) {
        $bi = ''
        foreach ($pair in $Script:BgIdMap) { if ($pair[0] -ceq $bk) { $bi = $pair[1] } }
        if ($bi) { $Script:BgIds += ' ' + $bi } else { $Script:BgNoId++ }
    }
}

# One field of a scheduled wake-up (Stop `session_crons`, Grok `sessionCrons`):
# how many, the first one's schedule, and a checksum of each prompt.
function Add-CronField([string]$p, [string]$v) {
    $d1 = $p.IndexOf('.')
    $d2 = $p.IndexOf('.', $d1 + 1)
    $ck = [int]$p.Substring($d1 + 1, $d2 - $d1 - 1)
    $cf = $p.Substring($d2 + 1)
    if ($ck + 1 -gt $Script:CronN) { $Script:CronN = $ck + 1 }
    if ($cf -ceq 'schedule' -and $ck -eq 0) { $Script:CronSched = $v }
    if ($cf -ceq 'prompt' -and $v) { $Script:CronSums += ' ' + (Get-PromptSum $v) }
}

# True if every counted task was already running before the turn began.
function Test-BgAllOld {
    if ($Script:BgN -le 0 -or $Script:BgNoId -gt 0) { return $false }
    foreach ($bi in (Split-Words $Script:BgIds)) {
        if (-not (Test-InList $Script:PrevIds $bi)) { return $false }
    }
    return $true
}

# The first counted task (or, with only scheduled wake-ups, the first schedule)
# as a short line for the badge and the pause note: BgM.
function Get-BgSummary {
    if ($Script:BgN -gt 0) {
        $m = $Script:BgDesc
        if (-not $m) { $m = $Script:BgCmd }
        if (-not $m) { $m = 'task' }
        if ($Script:BgType) { $m = $Script:BgType + ': ' + $m }
        if ($Script:BgN -ge 10) { $m += ' (+9 or more)' }
        elseif ($Script:BgN -gt 1) { $m += ' (+' + ($Script:BgN - 1) + ' more)' }
    } else {
        $sch = $Script:CronSched
        if (-not $sch) { $sch = 'wake-up' }
        $m = 'scheduled: ' + $sch
        if ($Script:CronN -gt 1) { $m += ' (+' + ($Script:CronN - 1) + ' more)' }
    }
    $Script:BgM = Limit-Json $m 80 320
}

# The last message and what still runs, as the text of a done: the suffix is
# kept whole and the message gives way (200 characters, 800 bytes in all).
function Get-DoneMsg([string]$what) {
    $dm = Limit-Json ('(still running in the background: ' + $what + ')') 120 480
    $dr = 200 - $dm.Length - 1
    if ($Script:Last -and $dr -gt 20) {
        return ((Limit-Json $Script:Last $dr (800 - $dm.Length - 1)) + ' ' + $dm)
    }
    return $dm
}

# Text (JSON-escaped) as standard base64 for an OSC 7501 field; nothing for
# escapes other than \" \\ \/.
function ConvertTo-B64Text([string]$text) {
    $sb = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt $text.Length; $i++) {
        $c = $text[$i]
        if ([int]$c -eq 92) {
            if ($i + 1 -ge $text.Length) { return '' }
            $e = [int]$text[$i + 1]
            if ($e -ne 92 -and $e -ne 47 -and $e -ne 34) { return '' }
            $c = $text[$i + 1]
            $i++
        }
        [void]$sb.Append($c)
    }
    return [Convert]::ToBase64String($Latin1.GetBytes($sb.ToString()))
}

# The turn ended and the agent waits for background work or a schedule. Not
# done: the badge says background (note in $Sid.bg), unless the last message
# asks the user something ($ask): then the user is told, as question, the badge
# says waiting, and Claude Code 2.1.295+ gets a blocked OSC 7501 record (kind
# question) instead of the working one.
function Invoke-BgPause([bool]$ask) {
    Get-BgSummary
    $flag = ''
    if ($Script:Agent -ceq 'claude' -and $env:SIMPLETERM -eq '1' -and (Test-Claude7501)) {
        $flag = '7501'
        if ($ask) {
            $e = ConvertTo-B64Text (Limit-Json $Script:Last 200 800)
            $Script:BgSeq = '\u001b]7501;state=blocked:id=' + $BgId + ':kind=question'
        } else {
            $e = ConvertTo-B64Text $Script:BgM
            $Script:BgSeq = '\u001b]7501;state=working:id=' + $BgId
        }
        if ($e) { $Script:BgSeq += ':msg=' + $e }
        $Script:BgSeq += '\u0007'
    }
    $bgFile = Join-Path $RunDir ($Script:Sid + '.bg')
    # Line 1: the badge's message (the question when asking), 2: the OSC 7501
    # flag, 3: the pause's token, 4: `ask` while the badge says waiting.
    $bm = $Script:BgM
    $askMark = ''
    if ($ask) { $bm = Limit-Json $Script:Last 80 320; $askMark = 'ask' }
    [void](Write-FileB $bgFile ($bm + "`n" + $flag + "`n" + $Script:Rid + "`n" + $askMark + "`n"))
    $pend = 'background'
    if ($Script:BgN -eq 0 -and $Script:CronN -gt 0) { $pend = 'scheduled' }
    if ($ask) {
        Set-Msg $Script:Last
        Set-TurnAt 'background' 'true' ''
        Initialize-V2 $Script:TurnAt
        Send-Background 'question'
        Write-State 'waiting' $Script:Last
        return
    }
    $bgm = $Script:BgM
    Write-State 'background' $bgm
    Set-TurnAt $pend $Script:Tasks ''
    Send-State $pend $Script:TurnAt
    if ($Script:BgN -gt 0 -and $Script:BgFinite -eq 0) { Invoke-BgLater $Script:Rid $bgm }
}

# Only work that may run for good is left (a dev server, a monitor, an idle
# teammate): it may never wake the agent, and then nothing else would come.
# After bg_done_after seconds (default 600) of the same pause, `done` goes once,
# saying what still runs. A new turn or another pause ends the wait.
function Invoke-BgLater([string]$token, [string]$what) {
    if ($Script:LinkFiles.Count -eq 0) { return }
    $w = Get-ConfInt 'bg_done_after' 600
    if ($w -le 0) { return }
    $Script:Msg = Get-DoneMsg $what
    $Script:MsgF = $Script:Msg
    Set-TurnAt 'done' $Script:Tasks 'true'
    Initialize-V2 $Script:TurnAt
    Start-LaterSend 'bg' $w (Join-Path $RunDir ($Script:Sid + '.bg')) 2 $token '' 0
}

# Sends done done_delay seconds from now (default 3; 0: at once) unless
# something of the session happens first: another Stop hook may have kept the
# agent going, and then its next event (or Stop) comes within moments. Only
# where the agent has such an event to send (Claude Code, Grok Build): Codex
# registers none that would come within moments, so its default is 0.
function Send-DoneLater {
    if ($Script:LinkFiles.Count -eq 0) { return }
    $dw = Get-ConfDoneDelay $Script:Agent
    $pendFile = Join-Path $RunDir ($Script:Sid + '.pend')
    if ($dw -le 0 -or -not (Write-FileB $pendFile ($Script:Rid + "`n"))) { Send-Background 'done'; return }
    Start-LaterSend 'pend' $dw $pendFile 0 $Script:Rid '' 0
}

# A turn ended: housekeeping (the command wrapper, run files a day old).
function Invoke-TurnEnd {
    Update-Cli
    try {
        $now = [DateTime]::UtcNow
        foreach ($f in [IO.Directory]::GetFiles($RunDir)) {
            # (Kept: the hold after an ask got auth or not-subscriber, until the
            # credentials change, the stopped versions and the count of failed asks.)
            if ([IO.Path]::GetFileName($f) -cmatch '\Aask\..*\.(auth|off|fail)\z') { continue }
            if (($now - [IO.File]::GetLastWriteTimeUtc($f)).TotalDays -ge 1) { Remove-FileQ $f }
        }
    } catch { }
}

# A done for the turn that just ended ($what: what still runs, if anything).
function Invoke-StopDone([string]$what) {
    if ($what) { $Script:Msg = Get-DoneMsg $what; $Script:MsgF = $Script:Msg } else { Set-Msg $Script:Last }
    if ($Script:StopAct -ceq 'true') { $Script:XFlags = ',"stop_hook_active":true' }
    Set-TurnAt 'done' $Script:Tasks ''
    Initialize-V2 $Script:TurnAt
    Send-DoneLater
    # The turn's done is sent (or pending): Claude Code's idle_prompt, 60 s
    # later, repeats it (the next turn note takes the mark back).
    [void](Write-FileB (Join-Path $RunDir ($Script:Sid + '.done')) '')
    Invoke-UsageReport
    Write-State 'done' ''
    Invoke-TurnEnd
}

# A Stop (Claude Code, Codex, Grok): done, or not yet. Not done while the agent
# waits for work it started or for a schedule, unless a person typed this turn
# and only work that ran before it is left, only services are left, or the
# last message asks the user something (then they are told). A turn the agent
# started itself while a schedule (/loop, cron) is set stays quiet:
# background with "scheduled: ...". The same as stop_flow in agent-hook.sh.
function Invoke-StopFlow {
    $Script:TurnUser = $true
    $Script:PrevIds = ''
    $Script:TurnBy = ''
    $turnFile = Join-Path $RunDir ($Script:Sid + '.turn')
    if ([IO.File]::Exists($turnFile)) {
        $t1 = Read-LineB $turnFile 0
        $t2 = Read-LineB $turnFile 1
        if ($t1 -and $t1 -cne 'user') { $Script:TurnUser = $false }
        $Script:TurnBy = $t1
        $Script:PrevIds = $t2
    }
    Complete-BgIds
    [void](Write-FileB (Join-Path $RunDir ($Script:Sid + '.stopids')) ($Script:BgIds + "`n"))
    $cronFile = Join-Path $RunDir ($Script:Sid + '.crons')
    if ($Script:CronN -gt 0) { [void](Write-FileB $cronFile ($Script:CronSums + "`n")) }
    else { Remove-FileQ $cronFile }
    $Script:Tasks = 'false'
    if (Test-AskText $Script:Last) { $Script:Tasks = 'true' }
    if ($Script:BgN -eq 0 -and $Script:CronN -eq 0) { Invoke-StopDone ''; return }
    if ($Script:TurnUser -and ($Script:BgN -eq 0 -or (Test-BgAllOld))) {
        Get-BgSummary
        if ($Script:BgN -gt 0) { Invoke-StopDone $Script:BgM } else { Invoke-StopDone '' }
        return
    }
    if ($Script:BgN -gt 0 -and $Script:BgSvc -eq $Script:BgN -and ($Script:CronN -eq 0 -or $Script:TurnUser)) {
        Get-BgSummary
        Invoke-StopDone $Script:BgM
        return
    }
    Invoke-UsageReport
    Invoke-BgPause ($Script:Tasks -ceq 'true')
    Invoke-TurnEnd
}

# Codex: the plan of turn Tid from the rollout (`item_completed` with item.type
# Plan, measured on 0.165.0, M2): its text, JSON-escaped, or $null.
function Get-CodexPlan([string]$path) {
    if (-not $path -or -not (Test-Id $Script:Tid)) { return $null }
    $tid = '"turn_id":"' + $Script:Tid + '"'
    $t = ''
    foreach ($line in (Read-TailB $path 1048576).Split([char]10)) {
        if (-not ($line.Contains('"type":"item_completed"') -and $line.Contains($tid))) { continue }
        $p = $line.IndexOf('"item":{"type":"Plan"', $Ord)
        if ($p -lt 0) { continue }
        $r = $line.Substring($p)
        $q = $r.IndexOf('"text":"', $Ord)
        if ($q -lt 0) { continue }
        $t = [regex]::Match($r.Substring($q + 8), '\A(?:[^"\\]|\\[\s\S])*').Value
    }
    if (-not $t) { return $null }
    return $t
}

# A goal can also end without a trace in the rollout (blocked after an error, a
# usage or token budget limit, /goal clear), and then no next turn starts. If
# none started codex_goal_check seconds (default 5) after this Stop, the turn
# was the last: done goes then.
function Invoke-CodexGoalLater([string]$gf) {
    if ($Script:LinkFiles.Count -eq 0) { return }
    $off = [int64]-1
    try { $off = (New-Object IO.FileInfo($gf)).Length } catch { return }
    $w = Get-ConfInt 'codex_goal_check' 5
    Set-Msg $Script:Last
    Set-TurnAt 'done' '' ''
    Initialize-V2 $Script:TurnAt
    $goalFile = Join-Path $RunDir ($Script:Sid + '.goal')
    [void](Write-FileB $goalFile ($Script:Rid + "`n"))
    Start-LaterSend 'goal' $w $goalFile 0 $Script:Rid $gf $off
}

# Saves this event's facts that a later event of the session needs, with
# prefix $prefix, in run/$Sid.$name (at most 64 KiB; the line of a long value
# goes).
function Save-FactsKeep([string]$prefix, [string]$name, [string]$re) {
    Initialize-Facts
    $sb = New-Object System.Text.StringBuilder
    foreach ($line in ([string]$Script:FactsText).Split([char]10)) {
        if ($line.Length -gt 65536) { continue }
        $p = $line
        $t1 = $line.IndexOf([char]9)
        if ($t1 -ge 0) { $p = $line.Substring(0, $t1) }
        if ($p -cmatch $re) { [void]$sb.Append($prefix + $line + "`n") }
    }
    $t = $sb.ToString()
    if ($t.Length -gt 65536) { $t = $t.Substring(0, 65536) }
    $path = Join-Path $RunDir ($Script:Sid + '.' + $name)
    if (Write-FileB ($path + '.' + $PID) $t) {
        try { Remove-FileQ $path; [IO.File]::Move(($path + '.' + $PID), $path) } catch { Remove-FileQ ($path + '.' + $PID) }
    }
}

# Facts saved by Save-FactsKeep within $maxAge seconds, added to the facts.
function Add-FactsFile([string]$name, [int]$maxAge) {
    $path = Join-Path $RunDir ($Script:Sid + '.' + $name)
    if (-not [IO.File]::Exists($path)) { return }
    $mins = [Math]::Floor(($maxAge + 59) / 60)
    if (([DateTime]::UtcNow - [IO.File]::GetLastWriteTimeUtc($path)).TotalMinutes -ge $mins) { return }
    Initialize-Facts
    $t = Read-FileB $path
    if ($null -eq $t) { $t = '' }
    $Script:FactsText = [string]$Script:FactsText + "`n" + $t.TrimEnd([char]10)
}

# True for the first alert for this question of this session within 30
# seconds: Claude Code reports one AskUserQuestion twice (PreToolUse and
# PermissionRequest).
function Get-AskKey {
    $q = $Script:QText
    if (-not $q) { $q = $Script:Desc }
    return ('q.' + (Get-Sha256Hex ($Script:Sid + '|' + $q)).Substring(0, 16))
}

# The fields of the hook input that the hook reads (the case list of
# agent-hook.sh), in document order.
function Read-HookFields($kv) {
    foreach ($p in $kv.order) {
        $v = $kv.got[$p]
        if ($p -cmatch '\A(background_tasks|backgroundTasks)\.[0-9]\.') { Add-BgField $p $v; continue }
        if ($p -cmatch '\A(session_crons|sessionCrons)\.[0-9]\.') { Add-CronField $p $v; continue }
        if ($p -ceq 'prompt') { $Script:Prompt = $v }
        elseif ($p -ceq 'source') { $Script:Src = $v }
        elseif ($p -ceq 'stop_hook_active') { $Script:StopAct = $v }
        elseif ($p -ceq 'is_interrupt') { $Script:IsInt = $v }
        elseif ($p -ceq 'agent_id' -or $p -ceq 'agentId') { $Script:AgentId = $v }
        elseif ($p -ceq 'agent_type' -or $p -ceq 'agentType' -or $p -ceq 'subagentType') { if (-not $Script:SubType) { $Script:SubType = $v } }
        elseif ($p -ceq 'parentAgentId' -or $p -ceq 'parent_agent_id') { $Script:SubPar = $v }
        elseif ($p -ceq 'prompt_id' -or $p -ceq 'turn_id' -or $p -ceq 'message_id' -or $p -ceq 'executionNum') { $Script:Tid = $v }
        elseif ($p -ceq 'permission_mode' -or $p -ceq 'permissionMode') { $Script:PMode = $v }
        elseif ($p -ceq 'toolName') { if (-not $Script:Tool) { $Script:Tool = $v } }
        elseif ($p -ceq 'toolUseId') { $Script:ToolUseId = $v }
        elseif ($p -ceq 'transcriptPath') { if (-not $Script:TPath) { $Script:TPath = $v } }
        elseif ($p -ceq 'hook_event_name') { $Script:HookEvent = $v }
        elseif ($p -ceq 'hookEventName') { if (-not $Script:HookEvent) { $Script:HookEvent = $v } }
        elseif ($p -ceq 'notification_type' -or $p -ceq 'notificationType') { if (-not $Script:NType) { $Script:NType = $v } }
        elseif ($p -ceq 'type') { $Script:NType2 = $v }
        elseif ($p -ceq 'tool_name') { $Script:Tool = $v }
        elseif ($p -ceq 'tool_input.command' -or $p -ceq 'tool_input.file_path' -or $p -ceq 'tool_input.url') { if (-not $Script:Detail) { $Script:Detail = $v } }
        elseif ($p -ceq 'tool_input.description') { $Script:Desc = $v }
        elseif ($p -ceq 'tool_input.questions.0.question') { $Script:QText = $v }
        elseif ($p -ceq 'session_id' -or $p -ceq 'sessionId') { if (-not $Script:Sid) { $Script:Sid = $v } }
        elseif ($p -ceq 'cwd') { if (-not $Script:Cwd) { $Script:Cwd = $v } }
        elseif ($p -ceq 'message' -or $p -ceq 'last_assistant_message' -or $p -ceq 'lastAssistantMessage' -or $p -ceq 'last-assistant-message') { $Script:Last = $v }
        elseif ($p -ceq 'input-messages.0') { $Script:FirstIn = $v }
        elseif ($p -ceq 'error') { $Script:Err = $v }
        elseif ($p -ceq 'transcript_path') { $Script:TPath = $v }
        elseif ($p -ceq 'context_tokens') { $Script:CtxTok = $v }
        elseif ($p -ceq 'model' -or $p -ceq 'to_model') { $Script:Model = $v }
        elseif ($p -ceq 'reason') { $Script:Reason = $v }
        elseif ($p -ceq 'promptId') { $Script:PromptId = $v; $Script:GKey += '.' + $v; $Script:Tid = $v }
        elseif ($p -ceq 'timestamp') { $Script:GKey += '.' + $v }
    }
}

function Write-Running {
    $path = Join-Path $RunDir ($Script:Sid + '.bg')
    if ([IO.File]::Exists($path)) {
        $m = Read-LineB $path 0
        if ($m.Length -gt 400) { $m = $m.Substring(0, 400) }
        if ((Read-LineB $path 3) -ceq 'ask') { Write-State 'waiting' $m } else { Write-State 'background' $m }
    } else {
        Write-State 'running' ''
    }
}

# --- main ----------------------------------------------------------------

# The event, as the case list at the end of agent-hook.sh; return = finish.
function Invoke-Event {
    $ev = $Script:Agent + ':' + $Script:HookEvent
    if ($ev -ceq 'claude:PermissionRequest' -or $ev -ceq 'codex:PermissionRequest') {
        if ($Mode -ceq 'signal') {
            Write-State 'waiting' ('approve ' + $Script:Tool + ': ' + $Script:Detail)
            return
        }
        $rk = 'claude_perm'
        if ($Script:Agent -ceq 'codex') { $rk = 'codex_perm' }
        Set-RkAt $rk ('@.oc' + $Tab + 's' + $Tab + $Nl)
        if ($Script:Tool -ceq 'AskUserQuestion') {
            # The question's decidable report (section 10.3): this one, not the
            # PreToolUse before it, which waits ask_delay seconds for it.
            $q = $Script:QText
            if (-not $q) { $q = $Script:Desc }
            Set-Msg $q
            if (-not (Test-Once (Get-AskKey))) { return }
            Initialize-V2 $Script:RkAt
            if ($Script:LinkFiles.Count -gt 0) { Invoke-RequestFlow 'question' 'shared' }
        } else {
            $d = $Script:Detail
            if ($Script:Tool -ceq 'apply_patch') { $d = $Script:Desc; if (-not $d) { $d = 'patch' } }
            if (-not $d) { $d = $Script:Desc }
            Set-Msg ('approve ' + $Script:Tool + ': ' + $d)
            Initialize-V2 $Script:RkAt
            # Codex hides its prompt while the hook waits (section 4.6).
            $w = 'shared'
            if ($Script:Agent -ceq 'codex') { $w = 'hidden' }
            if ($Script:LinkFiles.Count -gt 0) { Invoke-RequestFlow 'permission' $w }
        }
        return
    }
    if ($ev -ceq 'claude:PreToolUse') {
        if ($Script:Tool -ceq 'AskUserQuestion') {
            Set-Msg $Script:QText
            Write-State 'waiting' ''
            # PermissionRequest reports the same question, decidable: it goes
            # first. This one is the safety net for a question without one.
            Set-RkAt 'claude_askpre' ''
            Initialize-V2 $Script:RkAt
            if ($Script:LinkFiles.Count -gt 0) {
                $job = New-Job 'ask'
                $job.wait = [string](Get-ConfInt 'ask_delay' 2)
                $job.key = Get-AskKey
                Start-Child $job
            }
        }
        return
    }
    if ($ev -ceq 'claude:Notification') {
        # permission_prompt is ignored: PermissionRequest already reported that
        # wait (one relay event per agent wait). idle_prompt keeps the done badge.
        $nt = $Script:NType
        if ($nt -ceq 'idle_prompt') {
            # Claude Code sends it 60 s after a turn while only background shells
            # or monitors run: the work is not waiting for the user.
            if (Test-BgPaused) { return }
            # Already told by this turn's done: the prompt repeats it. Without a
            # done (interrupt, StopFailure, no Stop hook) it stays the safety net.
            if (Test-TurnDone) { return }
            Set-Msg $Script:Last
            Initialize-V2 ''
            Send-Background 'question'
        } elseif ($nt -ceq 'elicitation_dialog' -or $nt -ceq 'elicitation_url_dialog' -or $nt -ceq 'agent_needs_input') {
            # agent_needs_input: another background session of the user's needs
            # input, not this one: the alert stays, this tab's badge does not.
            if ($nt -cne 'agent_needs_input') { Write-State 'waiting' '' }
            Set-Msg $Script:Last
            Set-RkAt 'claude_notif' ('@.ntype' + $Tab + 's' + $Tab + $nt + $Nl)
            Initialize-V2 $Script:RkAt
            Send-Background 'question'
        }
        return
    }
    if ($ev -ceq 'claude:UserPromptSubmit') {
        Add-Note 'turn' ''
        Set-PromptOrigin
        Write-TurnMark
        Invoke-UsageReport
        Write-State 'running' ''
        Send-State 'running' ''
        Write-SessTurn 'running' $Script:Prompt
        return
    }
    if ($ev -ceq 'claude:PostToolUse' -or $ev -ceq 'claude:PostToolUseFailure') {
        if ($Script:HookEvent -ceq 'PostToolUseFailure' -and $Script:IsInt -ceq 'true' -and -not $Script:AgentId) {
            # Esc during a tool call: the turn is over (no Stop follows). Not when
            # a subagent's tool was interrupted (agent_id is set): the main
            # session's wait goes on.
            Add-Note 'turn' ''
            Write-State 'idle' ''
            Set-TurnAt 'interrupt' '' ''
            Send-State 'idle' $Script:TurnAt
            Write-SessTurn 'idle' ''
            return
        }
        Add-Note 'tool' $Script:Fp
        # Context grows with each tool call; look again every 20 seconds at most.
        $utPath = Join-Path $RunDir ($Script:Sid + '.ut')
        $ut = Read-LineB $utPath 0
        $now = $Script:Now
        if (-not (Test-UInt $ut) -or ($now - [int64]$ut) -ge 20 -or [int64]$ut -gt $now) {
            [void](Write-FileB $utPath ([string]$now + "`n"))
            Invoke-UsageReport
        }
        Write-Running
        return
    }
    if ($ev -ceq 'claude:SessionStart' -or $ev -ceq 'claude:PostCompact' -or $ev -ceq 'claude:PostModelSwitch') {
        Invoke-UsageReport
        Write-UsageOnly
        if ($Script:HookEvent -ceq 'SessionStart') {
            Update-Cli
            Start-Sess
            if ((Test-SessOk) -and -not [IO.File]::Exists($Script:Sess + '.json')) { Write-SessTurn 'idle' '' }
        }
        return
    }
    if ($ev -ceq 'claude:SessionEnd' -or $ev -ceq 'grok:SessionEnd' -or $ev -ceq 'codex:SessionEnd') {
        $since = [DateTime]::UtcNow
        # The record first: Codex gives this hook 3 seconds at most and then
        # ends it (0.165.0, measured).
        Stop-Sess $since
        # The agent is exiting and may take its hooks' children with it: the
        # send finishes first (here, not in a child).
        Send-State 'ended' '' -Sync
        return
    }
    if (@('claude:SubagentStart', 'claude:SubagentStop', 'grok:SubagentStart', 'grok:SubagentStop') -ccontains $ev) {
        if ($Script:HookEvent.EndsWith('Start', $Ord)) { Send-State 'sub_start' '' } else { Send-State 'sub_stop' '' }
        return
    }
    if ($ev -ceq 'claude:Stop' -or $ev -ceq 'codex:Stop') {
        Add-Note 'turn' ''
        if ($Script:Last.StartsWith('{\"title\":', $Ord)) { return }
        $gf = ''
        if ($Script:Agent -ceq 'codex') { $gf = Get-InputFile $Script:TPath }
        if ($Script:Agent -ceq 'codex') {
            $plan = Get-CodexPlan $gf
            if ($null -ne $plan) {
                # The turn ended on Codex's "Implement this plan?" (M2): a question,
                # not a done; answered in Codex's window (keys).
                Set-Msg $plan
                Set-RkAt 'codex_plan' ('@.plan' + $Tab + 's' + $Tab + $plan + $Nl)
                Initialize-V2 $Script:RkAt
                Send-Background 'question'
                Invoke-UsageReport
                Invoke-TurnEnd
                Write-SessTurn 'idle' ''
                return
            }
            if (Test-CodexGoalActive $gf) {
                Invoke-UsageReport
                $Script:TGoal = 'active'
                Set-TurnAt 'background' '' ''
                Send-State 'background' $Script:TurnAt
                $Script:TGoal = ''
                if ($gf) { Invoke-CodexGoalLater $gf }
                Invoke-TurnEnd
                Write-SessTurn 'idle' ''
                return
            }
        }
        Invoke-StopFlow
        Write-SessTurn 'idle' ''
        return
    }
    if ($ev -ceq 'claude:StopFailure') {
        Add-Note 'turn' ''
        $e = 'error'
        $te = 'error'
        if (@('authentication_failed', 'oauth_org_not_allowed', 'cloud_credential_error') -ccontains $Script:Err) { $e = 'auth' }
        elseif ($Script:Err -ceq 'rate_limit') { $te = 'limit' }
        Set-Msg ($Script:Err + ': ' + $Script:Last)
        Set-TurnAt $te '' ''
        Initialize-V2 $Script:TurnAt
        Send-Background $e
        Invoke-UsageReport
        Write-State 'done' ''
        Write-SessTurn 'idle' ''
        return
    }
    if ($ev -ceq 'codex:SessionStart' -or $ev -ceq 'codex:PostCompact') {
        Invoke-UsageReport
        if ($Script:HookEvent -ceq 'SessionStart') { Start-Sess }
        return
    }
    if ($ev -ceq 'codex:UserPromptSubmit' -or $ev -ceq 'grok:UserPromptSubmit') {
        # Grok: also the turn it starts itself when background work reports back
        # (promptId task-completed-<id> or subagent-completed-<id>).
        Add-Note 'turn' ''
        Set-PromptOrigin
        Write-TurnMark
        Send-State 'running' ''
        Write-SessTurn 'running' $Script:Prompt
        return
    }
    if ($ev -ceq 'codex:PreToolUse' -or $ev -ceq 'codex:PostToolUse') {
        # Registered for the session record's heartbeat only (section 8.3).
        return
    }
    if ($ev -ceq 'codex-notify:notify') {
        if ($Script:NType2 -cne 'agent-turn-complete') { return }
        if ($Script:FirstIn.StartsWith('Generate a concise, single-line task title', $Ord)) { return }
        Set-Msg $Script:Last
        Initialize-V2 ''
        Send-Background 'done'
        return
    }
    if ($ev -ceq 'grok:PreToolUse') {
        # Which tool asks next: the Notification of a permission prompt names
        # none (section 10.2).
        Save-FactsKeep 'pre.' 'grokpre' '^(toolName|toolUseId|toolInput)'
        return
    }
    if ($ev -ceq 'grok:PostToolUse') {
        $gp = Join-Path $RunDir ($Script:Sid + '.grokpre')
        if ($Script:ToolUseId -and [IO.File]::Exists($gp)) {
            foreach ($line in (Read-FileB $gp).Split([char]10)) {
                $f = $line.Split([char]9)
                if ($f.Length -ge 3 -and $f[0] -ceq 'pre.toolUseId' -and $f[2] -ceq $Script:ToolUseId) { Remove-FileQ $gp; break }
            }
        }
        return
    }
    if ($ev -ceq 'grok:Notification') {
        # Grok asks in its own prompt and takes no answer from a hook:
        # permission_prompt (only while its permission UI waits; also its plan
        # review, "Plan approval requested"), elicitation_dialog (a question)
        # and idle_prompt are alerts. The key includes the event's timestamp, the
        # same in every copy of one event.
        $nt = $Script:NType
        if ($nt -ceq 'permission_prompt') { if ($Script:Last.StartsWith('Plan approval requested', $Ord)) { $nt = 'plan' } }
        elseif ($nt -ceq 'elicitation_dialog') { }
        elseif ($nt -ceq 'idle_prompt') { if ((Test-BgPaused) -or (Test-TurnDone)) { return } }
        else { return }
        $key = (Get-Sha256Hex ($Script:HookEvent + '|' + $Script:Sid + '|' + $Script:NType + '|' + $Script:GKey + '|' + $Script:Last)).Substring(0, 16)
        if (-not (Test-Once $key)) { return }
        Set-Msg $Script:Last
        if ($Script:NType -ceq 'idle_prompt') {
            Initialize-V2 ''
        } else {
            Add-FactsFile 'grokpre' 600
            Set-RkAt 'grok_notif' ('@.ntype' + $Tab + 's' + $Tab + $nt + $Nl)
            Initialize-V2 $Script:RkAt
        }
        Send-Background 'question'
        return
    }
    if ($ev -ceq 'grok:Stop' -or $ev -ceq 'grok:StopFailure') {
        # A Stop also comes when the session closes (reason channel_closed or
        # shutdown); only end_turn ends a turn.
        if ($Script:HookEvent -ceq 'Stop' -and $Script:Reason -and $Script:Reason -cne 'end_turn') { return }
        $key = (Get-Sha256Hex ($Script:HookEvent + '|' + $Script:Sid + '|' + $Script:GKey + '|' + $Script:Err + '|' + $Script:Last)).Substring(0, 16)
        if (-not (Test-Once $key)) { return }
        Add-Note 'turn' ''
        # Grok 1.0.70 lists work still in flight in backgroundTasks, as Claude
        # Code does, and takes the turn up again when it reports back.
        if ($Script:HookEvent -ceq 'Stop') {
            Invoke-StopFlow
        } else {
            $e = 'error'
            $te = 'error'
            if (@('authentication_failed', 'oauth_org_not_allowed', 'cloud_credential_error') -ccontains $Script:Err) { $e = 'auth' }
            elseif ($Script:Err -ceq 'rate_limit') { $te = 'limit' }
            Set-Msg ($Script:Err + ': ' + $Script:Last)
            Set-TurnAt $te '' ''
            Initialize-V2 $Script:TurnAt
            Send-Background $e
            Invoke-TurnEnd
        }
        Write-SessTurn 'idle' ''
        return
    }
}

try {
    $Script:Agent0 = $Agent
    # Tests only (SIMPLETERM_HOOK_TEST=1): `agent-hook.ps1 <agent> __conf <key>`
    # prints what the hook does with key <key> of agent-hook.conf (the read
    # vectors of TDS_AGENT_ALERTS section 6.7; as in agent-hook.sh).
    if ($env:SIMPLETERM_HOOK_TEST -eq '1' -and $Mode -ceq '__conf' -and $ScriptArgs.Count -gt 2) {
        $k = [string]$ScriptArgs[2]
        $o = ''
        if ($k -ceq 'usage') { if (Test-ConfUsageOn) { $o = 'on' } else { $o = 'off' } }
        elseif ($k -ceq 'usage_ask' -or $k -ceq 'usage_ask_codex') { if (Test-ConfOn $k) { $o = 'on' } else { $o = 'off' } }
        elseif ($k -ceq 'claude_wait' -or $k -ceq 'codex_wait') { $o = [string](Get-ConfWaitCap $k.Substring(0, $k.Length - 5)) }
        elseif ($k -ceq 'poll_wait') { $o = [string](Get-ConfPollWait) }
        elseif ($k -ceq 'done_delay') { $o = [string](Get-ConfDoneDelay $Agent) }
        elseif ($k -ceq 'bg_done_after') { $o = [string](Get-ConfInt 'bg_done_after' 600) }
        elseif ($k -ceq 'codex_goal_check') { $o = [string](Get-ConfInt 'codex_goal_check' 5) }
        elseif ($k -ceq 'ask_delay') { $o = [string](Get-ConfInt 'ask_delay' 2) }
        Write-Out ($o + "`n")
        exit 0
    }
    if ($Mode -eq '__send') {
        $Script:Rid = ''
        $Script:Ts = '0'
        $Script:BgSeq = ''
        $Script:UsageSeq = ''
        if ($ScriptArgs.Count -gt 2) { Invoke-Child ([string]$ScriptArgs[2]) }
        Trim-Log
        exit 0
    }
    switch -CaseSensitive ($Agent) {
        'claude' {
            $App = 'claude-code'
            # GitHub Copilot CLI loads a Claude Code plugin given to it and sets
            # COPILOT_CLI=1: its hooks are sh-only. Grok Build runs Claude Code
            # plugins' hooks; it sets GROK_HOOK_EVENT.
            if ($env:COPILOT_CLI -eq '1') { exit 0 }
            if ($env:GROK_HOOK_EVENT) { $Agent = 'grok'; $App = 'grok-build' }
        }
        'grok' { $App = 'grok-build' }
        'codex' { $App = 'codex' }
        'codex-notify' { $App = 'codex' }
        'notify' { $App = 'script' }
        default { exit 0 }
    }
    $Script:UsageSeq = ''
    $Script:BgSeq = ''
    $Script:UsageJson = ''
    $Script:UsageV2 = ''
    $Script:Title = ''
    $Script:Msg = ''
    $Script:MsgF = ''
    $Script:XFlags = ''
    $Script:V2 = $false
    $Script:V2C = $false
    $Script:FactsText = ''
    $Script:AT = ''
    $Script:Spec = ''
    $Script:V2X = ''
    $Script:NoMsg = $false
    $Script:WaitOv = ''
    $Script:IngMt = ''
    $Script:ReqId = ''
    $Script:TurnAt = ''
    $Script:RkAt = ''
    $Script:TurnBy = ''
    $Script:Tasks = ''
    $Script:TGoal = ''
    $Script:PrevIds = ''
    $Script:PromptBy = 'user'
    $Script:PromptUser = $true
    $Script:RidUsed = $false

    # The input as bytes (trailing line breaks and NUL bytes dropped, as the
    # sh hook's command substitution does).
    $Script:InputB = ''
    if ($Agent -ceq 'codex-notify') {
        if ($ScriptArgs.Count -ge 2) {
            $Script:InputB = BS ([string]$ScriptArgs[$ScriptArgs.Count - 1])
            if ($Script:InputB.Length -gt $MaxInput) { $Script:InputB = '' }
        }
    } elseif ($Agent -cne 'notify') {
        $stream = [Console]::OpenStandardInput()
        $buf = New-Object byte[] $MaxInput
        $total = 0
        while ($total -lt $buf.Length) {
            $n = $stream.Read($buf, $total, $buf.Length - $total)
            if ($n -le 0) { break }
            $total += $n
        }
        # The rest of a larger input is read and dropped: an agent still
        # writing to a hook that ended gets a broken pipe (sh: cat >/dev/null).
        if ($total -ge $buf.Length) {
            $rest = New-Object byte[] 65536
            try { while ($stream.Read($rest, 0, $rest.Length) -gt 0) { } } catch { }
        }
        $Script:InputB = $Latin1.GetString($buf, 0, $total).Replace([string][char]0, '').TrimEnd([char]10)
    }
    # Codex runs PreToolUse and PostToolUse hooks for the session record's
    # heartbeat only (TDS_AGENT_EVENTS_V2 section 8.3): their large tool input
    # or output is not read, only its start (session_id and the event come
    # first).
    if ($Agent -ceq 'codex' -and $Script:InputB.Length -gt 4096) {
        $ih = $Script:InputB.Substring(0, 4096)
        if ($ih.Contains('"hook_event_name":"PreToolUse"') -or $ih.Contains('"hook_event_name":"PostToolUse"')) { $Script:InputB = $ih }
    }

    # Nothing to do without a link or a SimpleTerm session.
    $Script:LinkFiles = @(Get-LinkFiles)
    if ($Script:LinkFiles.Count -eq 0 -and $env:SIMPLETERM -ne '1') { exit 0 }
    # A run directory that cannot be made (a file in its place) leaves the
    # hook working without its run files, as agent-hook.sh does.
    try { if (-not [IO.Directory]::Exists($RunDir)) { [void][IO.Directory]::CreateDirectory($RunDir) } } catch { }

    $Script:Rid = New-RandomHex 8
    $Script:Now = Now-Epoch
    $Script:Ts = [string]$Script:Now
    if ($env:SIMPLETERM_HOOK_TEST -eq '1') {
        if ($env:SIMPLETERM_HOOK_TEST_RID) { $Script:Rid = BS $env:SIMPLETERM_HOOK_TEST_RID }
        if ($env:SIMPLETERM_HOOK_TEST_TS) { $Script:Ts = BS $env:SIMPLETERM_HOOK_TEST_TS }
    }
    if (-not (Test-Hex $Script:Rid 16)) { $Script:Rid = '' }
    if (-not (Test-UInt $Script:Ts)) { $Script:Ts = '0' }
    $Script:T0 = $Script:Now
    if (-not $Script:Rid) { $Script:LinkFiles = @() }

    # `simpleterm notify "title" ["body"]`: an OSC 777 notification on this
    # console (in a SimpleTerm session) and a `notify` event to every link.
    if ($Agent -ceq 'notify') {
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
        $Script:Title = ConvertTo-JsonB (BS $t) 64 512
        $Script:Msg = ConvertTo-JsonB (BS $b) 200 1600
        $Script:CwdBase = ConvertTo-JsonB (BS (Get-Location).Path) 64 256 -Base
        Send-Background 'notify'
        Trim-Log
        exit 0
    }

    # Fields of the agent's event JSON. Agents name the same things differently
    # (Grok sends camelCase and snake_case).
    $want = @()
    if ($Agent -ceq 'claude') {
        # background_tasks (Claude Code Stop): the first ten tasks. session_crons
        # (the first five): scheduled wake-ups. prompt/source tell who started a
        # turn; stop_hook_active and is_interrupt are flags. agent_id is there
        # only when a subagent's own tool call fires the hook.
        $want = @('hook_event_name', 'notification_type', 'tool_name', 'tool_input.command', 'tool_input.file_path', 'tool_input.url',
            'tool_input.description', 'tool_input.questions.0.question', 'session_id', 'cwd', 'message', 'last_assistant_message', 'error',
            'transcript_path', 'context_tokens', 'model', 'to_model', 'prompt', 'source', 'stop_hook_active', 'is_interrupt', 'agent_id',
            'prompt_id', 'permission_mode', 'agent_type', 'reason', 'request_id', 'oc', 'parent_session_id', 'message_id', 'title')
        foreach ($i in 0..9) { foreach ($k in @('id', 'type', 'description', 'command')) { $want += 'background_tasks.' + $i + '.' + $k } }
        foreach ($i in 0..4) { foreach ($k in @('id', 'schedule', 'prompt')) { $want += 'session_crons.' + $i + '.' + $k } }
    } elseif ($Agent -ceq 'codex') {
        $want = @('hook_event_name', 'tool_name', 'tool_input.command', 'tool_input.file_path', 'tool_input.description', 'session_id', 'cwd',
            'last_assistant_message', 'transcript_path', 'stop_hook_active', 'turn_id', 'permission_mode', 'prompt', 'source')
    } elseif ($Agent -ceq 'codex-notify') {
        $want = @('type', 'cwd', 'last-assistant-message', 'input-messages.0')
    } elseif ($Agent -ceq 'grok') {
        # backgroundTasks (Grok's Stop, camelCase): the first ten tasks.
        # sessionCrons (the first five): scheduled wake-ups; a prompt id that is
        # not a person's marks a turn Grok started itself.
        $want = @('hook_event_name', 'hookEventName', 'notificationType', 'sessionId', 'cwd', 'message', 'lastAssistantMessage', 'error', 'reason',
            'promptId', 'timestamp', 'prompt', 'stop_hook_active', 'permissionMode', 'agentId', 'agent_id', 'agentType', 'subagentType', 'toolName',
            'toolUseId', 'transcriptPath', 'transcript_path')
        foreach ($i in 0..9) { foreach ($k in @('id', 'type', 'description', 'command')) { $want += 'backgroundTasks.' + $i + '.' + $k } }
        foreach ($i in 0..4) { foreach ($k in @('id', 'schedule', 'prompt')) { $want += 'sessionCrons.' + $i + '.' + $k } }
    }
    foreach ($v in @('HookEvent', 'NType', 'Tool', 'Detail', 'Desc', 'Sid', 'Cwd', 'Last', 'Err', 'QText', 'FirstIn', 'NType2', 'TPath',
            'CtxTok', 'Model', 'GKey', 'Reason', 'Prompt', 'Src', 'StopAct', 'IsInt', 'AgentId', 'PromptId', 'ToolUseId', 'SubType', 'SubPar',
            'Tid', 'PMode', 'BgPick', 'BgType', 'BgDesc', 'BgCmd', 'BgShells', 'BgSvcIdx', 'BgIds', 'CronSched', 'CronSums', 'BgM')) {
        Set-Variable -Name $v -Value '' -Scope Script
    }
    $Script:BgN = 0
    $Script:BgFinite = 0
    $Script:BgSvc = 0
    $Script:BgNoId = 0
    $Script:CronN = 0
    $Script:BgKeep = New-Object 'System.Collections.Generic.List[string]'
    $Script:BgIdMap = New-Object 'System.Collections.Generic.List[object]'
    $kv = Get-JsonKV $Script:InputB $want
    $f = $kv
    Read-HookFields $kv

    if ($Agent -ceq 'codex-notify') { $Script:HookEvent = 'notify' }
    # Grok's camelCase event names (hookEventName), as in agent-hook.sh.
    if ($Agent -ceq 'grok') {
        if ($Script:HookEvent -ceq 'notification') { $Script:HookEvent = 'Notification' }
        elseif ($Script:HookEvent -ceq 'stop') { $Script:HookEvent = 'Stop' }
        elseif ($Script:HookEvent -ceq 'stop_failure') { $Script:HookEvent = 'StopFailure' }
        elseif ($Script:HookEvent -ceq 'user_prompt_submit') { $Script:HookEvent = 'UserPromptSubmit' }
    }
    $Script:RawSid = $Script:Sid
    $Script:Sid = [regex]::Replace($Script:Sid, '[^A-Za-z0-9_-]', '_')
    if ($Script:Sid.Length -gt 80) { $Script:Sid = $Script:Sid.Substring(0, 80) }
    if (-not $Script:Sid) { $Script:Sid = 'nosession' }
    $Script:DirV = $Script:Cwd
    # A subagent (its own hook events carry its id; section 7).
    $Script:SubId = ''
    if (Test-Id $Script:AgentId) { $Script:SubId = $Script:AgentId }
    $Script:CwdBase = Limit-Json $Script:Cwd 64 256 -Base
    $Script:CwdBaseF = Limit-Json $Script:Cwd 100000 400000 -Base
    $Script:Fp = (Get-Sha256Hex ($Script:Tool + "`t" + (Limit-Json $Script:Detail 200 800))).Substring(0, 16)
    $Sid = $Script:Sid

    # A done waits done_delay seconds (Send-DoneLater) in case another Stop
    # hook keeps the agent going; any later event of the main thread ends that
    # wait. Only the turn-end events that send a done themselves leave it be
    # (a newer one replaces it), and so do the events of a subagent (agent_id
    # is set, foreground or background): its tool calls carry the session id
    # and are no sign of the main thread going on.
    $ev0 = $Agent + ':' + $Script:HookEvent
    if (@('claude:Stop', 'codex:Stop', 'grok:Stop') -cnotcontains $ev0 -and $Script:HookEvent -cne 'SessionEnd' -and -not $Script:AgentId) {
        Remove-FileQ (Join-Path $RunDir ($Script:Sid + '.pend'))
    }
    # The heartbeat of the session's record (section 8.2): every hook event.
    if (@('UserPromptSubmit', 'SessionStart', 'SessionEnd') -cnotcontains $Script:HookEvent) { Update-SessBeat }
    Invoke-Event
} catch {
    Write-Log ('error ' + $_.Exception.GetType().Name + ' ' + $_.InvocationInfo.ScriptLineNumber)
}
Trim-Log
exit 0
