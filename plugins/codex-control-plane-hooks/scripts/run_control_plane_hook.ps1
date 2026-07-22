$ErrorActionPreference = "Stop"
$env:PYTHON_MANAGER_AUTOMATIC_INSTALL = "0"

$hookScript = Join-Path $PSScriptRoot "control_plane_hook.py"
$probeCode = "import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)"

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
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(2000)) {
            try {
                $process.Kill()
            }
            catch {
            }
            $process.WaitForExit()
            [void] $stdoutTask.GetAwaiter().GetResult()
            [void] $stderrTask.GetAwaiter().GetResult()
            return $null
        }
        [void] $stdoutTask.GetAwaiter().GetResult()
        [void] $stderrTask.GetAwaiter().GetResult()
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
