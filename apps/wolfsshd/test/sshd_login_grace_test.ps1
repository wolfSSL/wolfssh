#!/usr/bin/env pwsh
#
# Windows regression test for wolfsshd LoginGraceTime enforcement.
#
# Opens a raw TCP connection that never authenticates and verifies that
# wolfsshd drops it at the login grace deadline. No Windows user account or
# authorized key is required, because the connection is closed before
# authentication ever completes - this exercises the pre-auth grace timer only.
#
# The positive path - a successful authentication calling CancelLoginTimer so
# the session survives past the grace deadline - is deliberately not covered
# here, as it would require provisioning a real Windows user account and key.
# That cancel-on-success path is exercised on POSIX by sshd_login_grace_test.sh.
#
# Enforcement is checked behaviorally (the server closes the connection at the
# grace deadline), not by reading the daemon log, so the test does not depend on
# debug logging being compiled into the wolfSSH Windows build.
#
# Usage:
#   pwsh sshd_login_grace_test.ps1 -SshdExe <path-to-wolfsshd.exe> [-Port N] [-Grace N]
#   (SshdExe also accepts the SSHD_PATH environment variable.)

param(
    [string]$SshdExe = $env:SSHD_PATH,
    [int]$Port = 22224,
    [int]$Grace = 5
)

$ErrorActionPreference = "Stop"
$exitCode = 1

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot  = (Resolve-Path (Join-Path $scriptDir "..\..\..")).Path
$keyPath   = (Resolve-Path (Join-Path $repoRoot "keys\server-key.pem")).Path
$confFile  = Join-Path $scriptDir "sshd_config_test_login_grace"
$authFile  = Join-Path $scriptDir "authorized_keys_test"

if (-not $SshdExe -or -not (Test-Path $SshdExe)) {
    Write-Host "ERROR: wolfsshd.exe not found (pass -SshdExe or set SSHD_PATH)"
    exit 1
}

@"
Port $Port
Protocol 2
LoginGraceTime $Grace
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords no
UseDNS no
HostKey $keyPath
AuthorizedKeysFile $authFile
"@ | Out-File -FilePath $confFile -Encoding ASCII

"" | Out-File -FilePath $authFile -Encoding ASCII

# Run wolfsshd in the foreground (-D selects the non-service path on Windows).
$sshd = Start-Process -FilePath $SshdExe `
    -ArgumentList "-D", "-f", "`"$confFile`"", "-p", "$Port" `
    -NoNewWindow -PassThru

try {
    # Wait for the listener to accept connections.
    $up = $false
    for ($i = 0; $i -lt 20; $i++) {
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
        # throw rather than exit so the finally block still stops the daemon
        throw "wolfsshd did not start listening on port $Port"
    }

    # Open a raw TCP connection and never authenticate. The server sends its
    # banner, waits for ours, and must close the connection once the login grace
    # time expires. Block on Read (with a timeout well past the grace time) and
    # measure when the server closes the connection.
    $stall = New-Object System.Net.Sockets.TcpClient
    $stall.Connect("127.0.0.1", $Port)
    $stream = $stall.GetStream()
    $stream.ReadTimeout = ($Grace + 5) * 1000

    $buf = New-Object byte[] 4096
    $dropped = $false
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        while ($true) {
            $n = $stream.Read($buf, 0, $buf.Length)
            if ($n -le 0) {
                $dropped = $true   # server closed the connection
                break
            }
            # otherwise the server sent its banner; keep waiting for the drop
        }
    }
    catch [System.IO.IOException] {
        # A server close can surface as a reset (IOException), not a graceful
        # EOF. Decide by elapsed time like the .sh test: a throw before the read
        # timeout means the server closed the connection.
        $dropped = $sw.Elapsed.TotalSeconds -lt ($Grace + 4)
    }
    $elapsed = [math]::Round($sw.Elapsed.TotalSeconds, 1)
    $stall.Close()

    Write-Host "connection closed=$dropped after ${elapsed}s (grace=$Grace)"

    if ($dropped -and ($elapsed -ge ($Grace - 1)) -and ($elapsed -le ($Grace + 4))) {
        Write-Host "PASS: unauthenticated connection dropped at login grace deadline"
        $exitCode = 0
    }
    elseif ($dropped) {
        Write-Host "FAIL: connection closed at ${elapsed}s, not near the grace deadline ($Grace s)"
    }
    else {
        Write-Host "FAIL: connection still open past the grace time (not enforced)"
    }
}
catch {
    Write-Host "ERROR: $_"
    $exitCode = 1
}
finally {
    if ($sshd -and -not $sshd.HasExited) {
        Stop-Process -Id $sshd.Id -Force -ErrorAction SilentlyContinue
    }
}

exit $exitCode
