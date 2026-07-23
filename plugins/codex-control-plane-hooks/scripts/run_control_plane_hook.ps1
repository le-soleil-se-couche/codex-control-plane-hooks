$ErrorActionPreference = "Stop"
$env:PYTHON_MANAGER_AUTOMATIC_INSTALL = "0"

$hookScript = Join-Path $PSScriptRoot "control_plane_hook.py"
$probeCode = "import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)"
$probeDeadlineMs = 5000
$probeTimeoutMs = 1500
$terminationTimeoutMs = 500
$taskkillTimeoutMs = 1000
$probeStopwatch = [System.Diagnostics.Stopwatch]::StartNew()

function Get-RemainingProbeMilliseconds {
    param(
        [Parameter(Mandatory = $true)]
        [int] $Maximum
    )

    $remaining = $probeDeadlineMs - [int] $probeStopwatch.ElapsedMilliseconds
    if ($remaining -le 0) {
        return 0
    }
    return [Math]::Min($remaining, $Maximum)
}

function Stop-ProbeProcessTree {
    param(
        [Parameter(Mandatory = $true)]
        [System.Diagnostics.Process] $Process
    )

    $killer = $null
    $fallbackRequired = $false
    try {
        $startInfo = New-Object System.Diagnostics.ProcessStartInfo
        $startInfo.FileName = Join-Path $env:SystemRoot "System32\taskkill.exe"
        $startInfo.Arguments = "/PID $($Process.Id) /T /F"
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        $killer = New-Object System.Diagnostics.Process
        $killer.StartInfo = $startInfo
        $killWaitMs = Get-RemainingProbeMilliseconds -Maximum $taskkillTimeoutMs
        if ($killWaitMs -le 0 -or -not $killer.Start()) {
            throw "Probe cleanup deadline expired"
        }
        if (-not $killer.WaitForExit($killWaitMs)) {
            try {
                $killer.Kill()
            }
            catch {
            }
            $fallbackRequired = $true
        }
        elseif ($killer.ExitCode -ne 0) {
            $fallbackRequired = $true
        }
    }
    catch {
        $fallbackRequired = $true
    }
    finally {
        if ($null -ne $killer) {
            $killer.Dispose()
        }
    }
    if ($fallbackRequired) {
        try {
            $Process.Kill($true)
        }
        catch {
            try {
                $Process.Kill()
            }
            catch {
            }
        }
    }
    $terminationWaitMs = Get-RemainingProbeMilliseconds -Maximum $terminationTimeoutMs
    if ($terminationWaitMs -gt 0) {
        try {
            [void] $Process.WaitForExit($terminationWaitMs)
        }
        catch {
        }
    }
}

function Resolve-ApplicationPath {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Name
    )

    $process = $null
    try {
        $waitMs = Get-RemainingProbeMilliseconds -Maximum $probeTimeoutMs
        if ($waitMs -le 0) {
            return $null
        }
        $startInfo = New-Object System.Diagnostics.ProcessStartInfo
        $startInfo.FileName = Join-Path $env:SystemRoot "System32\where.exe"
        $startInfo.Arguments = $Name
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardInput = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true

        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $startInfo
        if (-not $process.Start()) {
            return $null
        }
        $process.StandardInput.Close()
        if (-not $process.WaitForExit($waitMs)) {
            Stop-ProbeProcessTree -Process $process
            return $null
        }
        if ($process.ExitCode -ne 0) {
            return $null
        }
        $candidate = $process.StandardOutput.ReadLine()
        if (
            [String]::IsNullOrWhiteSpace($candidate) -or
            -not [System.IO.Path]::IsPathRooted($candidate) -or
            -not [System.IO.File]::Exists($candidate)
        ) {
            return $null
        }
        return $candidate.Trim()
    }
    catch {
        return $null
    }
    finally {
        if ($null -ne $process) {
            $process.Dispose()
        }
    }
}

function Find-CompatiblePython {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Name,
        [Parameter(Mandatory = $true)]
        [string] $ProbeArguments
    )

    $applicationPath = Resolve-ApplicationPath -Name $Name
    if ($null -eq $applicationPath) {
        return $null
    }

    $process = $null
    try {
        $startInfo = New-Object System.Diagnostics.ProcessStartInfo
        $startInfo.FileName = $applicationPath
        $startInfo.Arguments = $ProbeArguments
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardInput = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true

        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $startInfo
        if (-not $process.Start()) {
            return $null
        }
        $process.StandardInput.Close()
        $waitMs = Get-RemainingProbeMilliseconds -Maximum $probeTimeoutMs
        if ($waitMs -le 0 -or -not $process.WaitForExit($waitMs)) {
            Stop-ProbeProcessTree -Process $process
            return $null
        }
        if ($process.ExitCode -eq 0) {
            return $applicationPath
        }
        return $null
    }
    catch {
        return $null
    }
    finally {
        if ($null -ne $process) {
            $process.Dispose()
        }
    }
}

$pyPath = Find-CompatiblePython `
    -Name "py.exe" `
    -ProbeArguments ('-3 -I -S -c "{0}"' -f $probeCode)
if ($null -ne $pyPath) {
    & $pyPath -3 -I -S $hookScript
    if ($null -eq $LASTEXITCODE) {
        exit 126
    }
    exit [int] $LASTEXITCODE
}

$pythonPath = Find-CompatiblePython `
    -Name "python.exe" `
    -ProbeArguments ('-I -S -c "{0}"' -f $probeCode)
if ($null -ne $pythonPath) {
    & $pythonPath -I -S $hookScript
    if ($null -eq $LASTEXITCODE) {
        exit 126
    }
    exit [int] $LASTEXITCODE
}

[Console]::Error.WriteLine(
    "codex-control-plane-hooks requires Python 3.9+ via py.exe -3 or python.exe"
)
exit 127
