#!/usr/bin/env pwsh
#
# Windows regression test: wolfsshd refuses a config with Match Group.
#
# Windows wolfsshd does not look up a user's groups, so a Match Group block
# could never apply and its restrictions would be skipped. The config load
# refuses it instead. This starts wolfsshd -D with a Match Group block and
# checks the daemon exits without listening and logs the selector refusal, so
# an exit for any other reason does not pass. A Match User control with the
# same settings must come up, both before and after the refused cases, so a
# daemon that cannot start at all, or a port left busy, does not pass.
#
# Usage:
#   pwsh sshd_match_group_win_test.ps1 -SshdExe <path-to-wolfsshd.exe> [-Port N]
#   (SshdExe also accepts the SSHD_PATH environment variable.)

param(
    [string]$SshdExe = $env:SSHD_PATH,
    [int]$Port = 22337
)

$ErrorActionPreference = "Stop"
$exitCode = 1

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot  = (Resolve-Path (Join-Path $scriptDir "..\..\..")).Path
$keyPath   = (Resolve-Path (Join-Path $repoRoot "keys\server-key.pem")).Path
$confFile  = Join-Path $scriptDir "sshd_config_test_match_group_win"
$authFile  = Join-Path $scriptDir "authorized_keys_test_match_group_win"
$logFile   = Join-Path $scriptDir "log_match_group_win.txt"

# Logged by HandleMatch() in configuration.c under WOLFSSHD_NO_MATCH_GROUP.
# Errors reach the -E log without -d.
$refusal = "Unsupported Match selector, only User is handled on this platform"

if (-not $SshdExe -or -not (Test-Path $SshdExe)) {
    Write-Host "ERROR: wolfsshd.exe not found (pass -SshdExe or set SSHD_PATH)"
    exit 1
}

"" | Out-File -FilePath $authFile -Encoding ASCII

# Writes the config with $selector as the Match criteria.
function Write-Config([string]$selector) {
    @"
Port $Port
Protocol 2
PasswordAuthentication yes
UseDNS no
HostKey $keyPath
AuthorizedKeysFile $authFile

Match $selector
	ForceCommand internal-sftp
"@ | Out-File -FilePath $confFile -Encoding ASCII
}

# Starts wolfsshd -D on the current config, logging to $logFile. Returns
# $true once it listens on $Port, $false when it exits first or never listens
# within 10 seconds. The exit code is not used: the Windows main() does not
# return StartSSHD's result.
function Test-Listens {
    # -E appends, so start each run with an empty log
    Remove-Item -Path $logFile -Force -ErrorAction SilentlyContinue
    $sshd = Start-Process -FilePath $SshdExe `
        -ArgumentList "-D", "-f", "`"$confFile`"", "-p", "$Port", `
            "-E", "`"$logFile`"" `
        -NoNewWindow -PassThru
    try {
        for ($i = 0; $i -lt 20; $i++) {
            if ($sshd.HasExited) {
                return $false
            }
            try {
                $probe = New-Object System.Net.Sockets.TcpClient
                $probe.Connect("127.0.0.1", $Port)
                $probe.Close()
                return $true
            }
            catch {
                Start-Sleep -Milliseconds 500
            }
        }
        return $false
    }
    finally {
        if (-not $sshd.HasExited) {
            Stop-Process -Id $sshd.Id -Force -ErrorAction SilentlyContinue
            $sshd.WaitForExit(5000) | Out-Null
        }
    }
}

# True when the daemon did not listen and its log names the selector refusal.
function Test-Refused {
    if (Test-Listens) {
        return $false
    }
    if (-not (Test-Path $logFile)) {
        Write-Host "no log written to $logFile"
        return $false
    }
    if (-not (Select-String -Path $logFile -SimpleMatch -Quiet `
            -Pattern $refusal)) {
        Write-Host "log does not show the selector refusal:"
        Get-Content -Path $logFile | Write-Host
        return $false
    }
    return $true
}

try {
    Write-Config "User nosuchuser"
    if (-not (Test-Listens)) {
        throw "control: wolfsshd did not start with a Match User block"
    }

    Write-Config "Group Administrators"
    if (-not (Test-Refused)) {
        throw "wolfsshd did not refuse a Match Group block it cannot apply"
    }

    Write-Config "User nosuchuser Group Administrators"
    if (-not (Test-Refused)) {
        throw "wolfsshd did not refuse a Match User/Group block it cannot apply"
    }

    Write-Config "User nosuchuser"
    if (-not (Test-Listens)) {
        throw "control: wolfsshd did not start again with a Match User block"
    }

    Write-Host "PASS: Match Group refused, Match User accepted"
    $exitCode = 0
}
catch {
    Write-Host "FAIL: $_"
    $exitCode = 1
}
finally {
    Remove-Item -Path $confFile, $authFile, $logFile -Force `
        -ErrorAction SilentlyContinue
}

exit $exitCode
