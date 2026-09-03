#!/usr/bin/env pwsh
#
# Windows regression test for wolfsshd -D (foreground) option parsing.
#
# On Windows, StartSSHD() rebuilds argv from GetCommandLineW(); a bug in that
# path left -D (foreground) mode parsing the raw wide command line, so -f and
# -p were silently ignored and the daemon fell back to its compiled-in
# defaults. This test starts wolfsshd with -D and a config file at a
# non-default path whose Port line differs from the -p value, then checks that
# the listener comes up on the -p port. That only happens if -D mode parsed
# both -f (to find the config) and -p (to override the config's Port).
#
# No Windows user account or authorized key is required: the check is that the
# daemon binds the requested port, not that a session authenticates.
#
# Usage:
#   pwsh sshd_dash_d_test.ps1 -SshdExe <path-to-wolfsshd.exe> [-Port N] [-ConfPort N]
#   (SshdExe also accepts the SSHD_PATH environment variable.)

param(
    [string]$SshdExe = $env:SSHD_PATH,
    [int]$Port = 22335,
    [int]$ConfPort = 22336
)

$ErrorActionPreference = "Stop"
$exitCode = 1

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot  = (Resolve-Path (Join-Path $scriptDir "..\..\..")).Path
$keyPath   = (Resolve-Path (Join-Path $repoRoot "keys\server-key.pem")).Path
$confFile  = Join-Path $scriptDir "sshd_config_test_dash_d"
$authFile  = Join-Path $scriptDir "authorized_keys_test_dash_d"

if (-not $SshdExe -or -not (Test-Path $SshdExe)) {
    Write-Host "ERROR: wolfsshd.exe not found (pass -SshdExe or set SSHD_PATH)"
    exit 1
}

if ($Port -eq $ConfPort) {
    Write-Host "ERROR: -Port and -ConfPort must differ so the test can tell them apart"
    exit 1
}

# The config's Port is deliberately not the port we probe. If -p is parsed it
# wins (wolfsshd only reads the config Port when none was given on the command
# line), so a listener on $Port proves the -p override took effect.
@"
Port $ConfPort
Protocol 2
PermitRootLogin yes
PasswordAuthentication yes
UseDNS no
HostKey $keyPath
AuthorizedKeysFile $authFile
"@ | Out-File -FilePath $confFile -Encoding ASCII

"" | Out-File -FilePath $authFile -Encoding ASCII

# -D selects the non-service (foreground) path on Windows.
$sshd = Start-Process -FilePath $SshdExe `
    -ArgumentList "-D", "-f", "`"$confFile`"", "-p", "$Port" `
    -NoNewWindow -PassThru

try {
    $up = $false
    for ($i = 0; $i -lt 20; $i++) {
        if ($sshd.HasExited) {
            throw "wolfsshd exited early (code $($sshd.ExitCode)); -D option parsing likely failed"
        }
        try {
            $probe = New-Object System.Net.Sockets.TcpClient
            $probe.Connect("127.0.0.1", $Port)
            $probe.Close()
            $up = $true
            break
        }
        catch {
            Start-Sleep -Milliseconds 500
        }
    }
    if (-not $up) {
        throw "wolfsshd did not listen on the -p port $Port; -D did not honor -f/-p"
    }

    # The config Port must not have been used: nothing should answer there.
    $confBound = $false
    try {
        $probe = New-Object System.Net.Sockets.TcpClient
        $probe.Connect("127.0.0.1", $ConfPort)
        $probe.Close()
        $confBound = $true
    }
    catch {
        # expected: no listener on the config Port
    }
    if ($confBound) {
        throw "wolfsshd listened on the config Port $ConfPort; -p override was not applied"
    }

    Write-Host "PASS: -D mode parsed -f and -p (listening on $Port, not $ConfPort)"
    $exitCode = 0
}
catch {
    Write-Host "FAIL: $_"
    $exitCode = 1
}
finally {
    if ($sshd -and -not $sshd.HasExited) {
        Stop-Process -Id $sshd.Id -Force -ErrorAction SilentlyContinue
    }
    Remove-Item -Path $confFile, $authFile -Force -ErrorAction SilentlyContinue
}

exit $exitCode
