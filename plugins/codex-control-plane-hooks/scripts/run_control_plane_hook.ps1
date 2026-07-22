$ErrorActionPreference = "Stop"
$env:PYTHON_MANAGER_AUTOMATIC_INSTALL = "0"

$hookScript = Join-Path $PSScriptRoot "control_plane_hook.py"
$probeCode = "import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)"
$probeTimeoutMs = 2000
$terminationTimeoutMs = 500
$taskkillTimeoutMs = 1000

function Stop-ProbeProcessTree {
    param(
        [Parameter(Mandatory = $true)]
        [System.Diagnostics.Process] $Process
    )

    try {
        $Process.Kill($true)
    }
    catch {
        $killer = $null
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
            if ($killer.Start() -and -not $killer.WaitForExit($taskkillTimeoutMs)) {
                try {
                    $killer.Kill()
                }
                catch {
                }
            }
        }
        catch {
            try {
                $Process.Kill()
            }
            catch {
            }
        }
        finally {
            if ($null -ne $killer) {
                $killer.Dispose()
            }
        }
    }
    try {
        [void] $Process.WaitForExit($terminationTimeoutMs)
    }
    catch {
    }
}

function Find-CompatiblePython {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Name,
        [Parameter(Mandatory = $true)]
        [string] $ProbeArguments
    )

    try {
        $command = Get-Command $Name -CommandType Application -ErrorAction Stop |
            Select-Object -First 1
    }
    catch {
        return $null
    }

    $process = $null
    try {
        $startInfo = New-Object System.Diagnostics.ProcessStartInfo
        $startInfo.FileName = $command.Source
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
        if (-not $process.WaitForExit($probeTimeoutMs)) {
            Stop-ProbeProcessTree -Process $process
            return $null
        }
        if ($process.ExitCode -eq 0) {
            return $command.Source
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
