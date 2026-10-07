#Requires -Version 5.1
<#
.SYNOPSIS
Manual CA-08 check: Windows' inbox OpenSSH_for_Windows_9.5p2 sshd accepts a
keyroster user certificate for a listed principal and rejects a certificate
for an unlisted principal.

.DESCRIPTION
There is no upstream OpenSSH 9.5p2 tarball, so CI cannot build this version;
see test/manual/README.md. The script starts a temporary sshd.exe in debug mode
(one connection per run) on 127.0.0.1 only, with its own sshd_config in an
ACL-restricted temp directory. It never stops, restarts or reconfigures the
installed sshd service and never reads or writes its configuration.

Cases:
  accept  test-cert.pub carries -Principal; the login must succeed and
          whoami must name -Principal.
  reject  reject-cert.pub carries keyroster-reject-test, which is not listed;
          the login (as the same user) must fail with "Permission denied"
          and sshd must log that the certificate holds no authorized principal.

The result goes to {CertDir}\result.json (sshd_version, accept, reject,
finished_at). Exit codes: 0 both PASS, 1 a case failed, 2 a precondition
failed, 3 not elevated.

.PARAMETER CertDir
Directory holding test (the throwaway private key), test-cert.pub,
reject-cert.pub and user_ca.pub.

.PARAMETER Principal
Your own Windows account name in lowercase. A temporary sshd that runs as you
can only log you in.

.PARAMETER Port
Loopback port for the temporary sshd (default 2222; 22 is refused).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$CertDir,
    [Parameter(Mandatory = $true)][string]$Principal,
    [int]$Port = 2222
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$OpenSSHDir = Join-Path $env:SystemRoot 'System32\OpenSSH'
$Sshd = Join-Path $OpenSSHDir 'sshd.exe'
$Ssh = Join-Path $OpenSSHDir 'ssh.exe'
$Keygen = Join-Path $OpenSSHDir 'ssh-keygen.exe'
$RejectPrincipal = 'keyroster-reject-test'
$Utf8 = New-Object System.Text.UTF8Encoding $false

function Stop-Check([int]$Code, [string]$Message) {
    Write-Host "ERROR: $Message"
    exit $Code
}

# Windows command-line quoting for Start-Process, which joins arguments
# without quoting them in PowerShell 5.1.
function ConvertTo-ArgString([string[]]$ArgList) {
    $quoted = foreach ($a in $ArgList) {
        if ($a -eq '') { '""' }
        elseif ($a -match '[\s"]') { '"' + (($a -replace '(\\*)"', '$1$1\"') -replace '(\\+)$', '$1$1') + '"' }
        else { $a }
    }
    return ($quoted -join ' ')
}

# Runs a native program with stdout and stderr captured in files, so that
# PowerShell 5.1 never turns native stderr into an error record.
function Invoke-Native([string]$Exe, [string[]]$ArgList, [string]$Base, [int]$TimeoutMs = 30000) {
    $out = "$Base.out"
    $err = "$Base.err"
    $p = Start-Process -FilePath $Exe -ArgumentList (ConvertTo-ArgString $ArgList) -NoNewWindow -PassThru `
        -RedirectStandardOutput $out -RedirectStandardError $err
    $null = $p.Handle  # keeps ExitCode readable after exit
    if (-not $p.WaitForExit($TimeoutMs)) {
        Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
        $p.WaitForExit()
    }
    return [pscustomobject]@{
        Code   = $p.ExitCode
        Stdout = [IO.File]::ReadAllText($out)
        Stderr = [IO.File]::ReadAllText($err)
    }
}

function ConvertTo-ConfigPath([string]$Path) {
    $p = $Path -replace '\\', '/'
    if ($p -match '\s') { return '"' + $p + '"' }
    return $p
}

# Stops the temporary sshd and any child it spawned. Only processes started by
# this script are touched; the installed service's process is never a target.
function Stop-TempSshd($Proc) {
    if ($null -eq $Proc) { return }
    if (-not $Proc.WaitForExit(10000)) {
        Get-CimInstance Win32_Process -Filter "ParentProcessId=$($Proc.Id)" -ErrorAction SilentlyContinue |
            ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
        Stop-Process -Id $Proc.Id -Force -ErrorAction SilentlyContinue
        $Proc.WaitForExit()
    }
}

# --- Preconditions ---------------------------------------------------------

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = (New-Object Security.Principal.WindowsPrincipal $identity).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Stop-Check 3 'run from an elevated PowerShell ("Run as administrator")'
}

$Principal = $Principal.ToLowerInvariant()
if ($Principal -ne $env:USERNAME.ToLowerInvariant()) {
    Stop-Check 2 "-Principal must be your own account name in lowercase ('$($env:USERNAME.ToLowerInvariant())'): the temporary sshd runs as you and can only log you in"
}
if ($Port -eq 22 -or $Port -lt 1 -or $Port -gt 65535) {
    Stop-Check 2 "-Port $Port is not allowed (22 belongs to the installed sshd service)"
}
if (Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue) {
    Stop-Check 2 "port $Port is already in use; pass another -Port"
}

$CertDir = (Resolve-Path -LiteralPath $CertDir).Path
foreach ($f in 'test', 'test-cert.pub', 'reject-cert.pub', 'user_ca.pub') {
    if (-not (Test-Path -LiteralPath (Join-Path $CertDir $f) -PathType Leaf)) {
        Stop-Check 2 "missing $f in $CertDir"
    }
}
foreach ($exe in $Sshd, $Ssh, $Keygen) {
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { Stop-Check 2 "missing $exe" }
}

$tmp = Join-Path $env:TEMP ('keyroster-9.5p2-' + [guid]::NewGuid().ToString('N').Substring(0, 12))
New-Item -ItemType Directory -Path $tmp | Out-Null
$sshdProc = $null
$results = [ordered]@{ accept = 'FAIL'; reject = 'FAIL' }
$sshdVersion = ''

try {
    $v = Invoke-Native $Sshd @('-V') (Join-Path $tmp 'version')
    $sshdVersion = (($v.Stderr + $v.Stdout) -split "`r?`n" | Where-Object { $_ -match 'OpenSSH' } | Select-Object -First 1)
    if ($null -eq $sshdVersion) { $sshdVersion = '' }
    $sshdVersion = $sshdVersion.Trim()
    Write-Host "sshd version: $sshdVersion"
    if ($sshdVersion -notmatch '^OpenSSH_for_Windows_9\.5p2\b') {
        Stop-Check 2 "this check needs OpenSSH_for_Windows_9.5p2, found '$sshdVersion'"
    }

    # ACL: SYSTEM, Administrators and the current user only, no inheritance.
    $sid = $identity.User.Value
    $acl = Invoke-Native 'icacls.exe' @($tmp, '/inheritance:r', '/grant:r',
        '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F', "*${sid}:(OI)(CI)F") (Join-Path $env:TEMP "kr-icacls-$PID")
    Remove-Item -LiteralPath (Join-Path $env:TEMP "kr-icacls-$PID.out"), (Join-Path $env:TEMP "kr-icacls-$PID.err") -ErrorAction SilentlyContinue
    if ($acl.Code -ne 0) { Stop-Check 2 "icacls failed: $($acl.Stdout)$($acl.Stderr)" }

    # Inputs are copied into the restricted directory, so the private key and
    # the files sshd reads carry only the restricted ACL.
    $key = Join-Path $tmp 'id_test'
    Copy-Item -LiteralPath (Join-Path $CertDir 'test') -Destination $key
    Copy-Item -LiteralPath (Join-Path $CertDir 'test-cert.pub') -Destination (Join-Path $tmp 'accept-cert.pub')
    Copy-Item -LiteralPath (Join-Path $CertDir 'reject-cert.pub') -Destination (Join-Path $tmp 'reject-cert.pub')
    Copy-Item -LiteralPath (Join-Path $CertDir 'user_ca.pub') -Destination (Join-Path $tmp 'user_ca.pub')

    $hostKey = Join-Path $tmp 'ssh_host_ed25519_key'
    $kg = Invoke-Native $Keygen @('-q', '-t', 'ed25519', '-N', '', '-C', 'keyroster-9.5p2-check', '-f', $hostKey) (Join-Path $tmp 'keygen')
    if ($kg.Code -ne 0) { Stop-Check 2 "ssh-keygen failed: $($kg.Stderr)" }

    [IO.File]::WriteAllText((Join-Path $tmp 'principals'), "$Principal`n", $Utf8)
    $hostPub = [IO.File]::ReadAllText("$hostKey.pub").Trim()
    [IO.File]::WriteAllText((Join-Path $tmp 'known_hosts'), "[127.0.0.1]:$Port $hostPub`n", $Utf8)
    [IO.File]::WriteAllText((Join-Path $tmp 'ssh_config'), "# empty: no user or system ssh_config applies`n", $Utf8)

    $cfg = Join-Path $tmp 'sshd_config'
    $config = @(
        'ListenAddress 127.0.0.1'
        "Port $Port"
        "HostKey $(ConvertTo-ConfigPath $hostKey)"
        "PidFile $(ConvertTo-ConfigPath (Join-Path $tmp 'sshd.pid'))"
        'AuthorizedKeysFile none'
        "TrustedUserCAKeys $(ConvertTo-ConfigPath (Join-Path $tmp 'user_ca.pub'))"
        "AuthorizedPrincipalsFile $(ConvertTo-ConfigPath (Join-Path $tmp 'principals'))"
        'PubkeyAuthentication yes'
        'PasswordAuthentication no'
        'KbdInteractiveAuthentication no'
        'GSSAPIAuthentication no'
        'LogLevel VERBOSE'
    ) -join "`n"
    [IO.File]::WriteAllText($cfg, "$config`n", $Utf8)

    $t = Invoke-Native $Sshd @('-t', '-f', $cfg) (Join-Path $tmp 'configtest')
    if ($t.Code -ne 0) { Stop-Check 2 "sshd -t rejected the temporary config: $($t.Stderr)" }

    foreach ($case in 'accept', 'reject') {
        $log = Join-Path $tmp "sshd-$case.log"
        $sshdProc = Start-Process -FilePath $Sshd -ArgumentList (ConvertTo-ArgString @('-d', '-f', $cfg, '-E', $log)) `
            -NoNewWindow -PassThru -RedirectStandardOutput (Join-Path $tmp "sshd-$case.out") `
            -RedirectStandardError (Join-Path $tmp "sshd-$case.err")
        $null = $sshdProc.Handle

        $listening = $false
        for ($i = 0; $i -lt 50 -and -not $sshdProc.HasExited; $i++) {
            if (Get-NetTCPConnection -LocalAddress 127.0.0.1 -LocalPort $Port -State Listen -ErrorAction SilentlyContinue) {
                $listening = $true
                break
            }
            Start-Sleep -Milliseconds 200
        }

        $client = $null
        if ($listening) {
            $client = Invoke-Native $Ssh @('-n', '-F', (Join-Path $tmp 'ssh_config'),
                '-i', $key, '-o', "CertificateFile=$(Join-Path $tmp "$case-cert.pub")",
                '-o', 'IdentitiesOnly=yes', '-o', 'IdentityAgent=none', '-o', 'BatchMode=yes',
                '-o', 'PreferredAuthentications=publickey', '-o', 'ConnectTimeout=10',
                '-o', 'StrictHostKeyChecking=yes', '-o', "UserKnownHostsFile=$(Join-Path $tmp 'known_hosts')",
                '-p', "$Port", "$Principal@127.0.0.1", 'whoami') (Join-Path $tmp "client-$case")
        }
        Stop-TempSshd $sshdProc
        $sshdProc = $null

        $sshdLog = ''
        if (Test-Path -LiteralPath $log) { $sshdLog = [IO.File]::ReadAllText($log) }

        if ($null -eq $client) {
            Write-Host "FAIL $case (the temporary sshd did not start listening on 127.0.0.1:$Port)"
        }
        elseif ($case -eq 'accept') {
            $who = ($client.Stdout -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -Last 1)
            $user = ''
            if ($who) { $user = ($who.Trim() -split '\\')[-1].ToLowerInvariant() }
            if ($client.Code -eq 0 -and $user -eq $Principal) { $results.accept = 'PASS' }
            Write-Host "$($results.accept) accept (ssh exit $($client.Code), whoami user '$user')"
        }
        else {
            $denied = $client.Stderr -match 'Permission denied'
            $refused = $sshdLog -match 'does not contain an authorized principal'
            if ($client.Code -ne 0 -and $denied -and $refused) { $results.reject = 'PASS' }
            Write-Host "$($results.reject) reject (ssh exit $($client.Code), client denied: $denied, sshd principal refusal logged: $refused)"
        }

        if ($results[$case] -ne 'PASS') {
            # Keep the evidence before the temp directory is removed.
            foreach ($f in "sshd-$case.log", "sshd-$case.err", "client-$case.out", "client-$case.err") {
                $src = Join-Path $tmp $f
                if (Test-Path -LiteralPath $src) { Copy-Item -LiteralPath $src -Destination (Join-Path $CertDir $f) -Force }
            }
            Write-Host "  logs copied to $CertDir"
        }
    }

    $finished = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
    $result = [ordered]@{
        sshd_version = $sshdVersion
        accept       = $results.accept
        reject       = $results.reject
        finished_at  = $finished
    }
    [IO.File]::WriteAllText((Join-Path $CertDir 'result.json'), (ConvertTo-Json $result) + "`n", $Utf8)
    Write-Host "result: $(Join-Path $CertDir 'result.json')"
}
finally {
    Stop-TempSshd $sshdProc
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

if ($results.accept -eq 'PASS' -and $results.reject -eq 'PASS') { exit 0 }
exit 1
