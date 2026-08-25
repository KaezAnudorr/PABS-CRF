param(
    [ValidateSet('pabs-128', 'pabs-192', 'pabs-256', 'mldsa-44', 'mldsa-65', 'mldsa-87')]
    [string]$Scheme = 'pabs-128',
    [int]$Iterations = 100,
    [string]$OutputDirectory = 'test-results/resource'
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$binary = Join-Path $projectRoot 'target\release\examples\matched_mldsa_baseline.exe'
$outputRoot = Join-Path $projectRoot $OutputDirectory
New-Item -ItemType Directory -Force -Path $outputRoot | Out-Null

Push-Location $projectRoot
try {
    cargo build --quiet --release --example matched_mldsa_baseline
    if ($LASTEXITCODE -ne 0) {
        throw 'Release build failed.'
    }

    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $benchmarkJson = Join-Path $outputRoot "$($Scheme)_$($stamp)_timing.json"
    $stdoutPath = Join-Path $outputRoot "$($Scheme)_$($stamp)_stdout.log"
    $stderrPath = Join-Path $outputRoot "$($Scheme)_$($stamp)_stderr.log"
    $env:PABS_BENCH_ITERS = [string]$Iterations
    $env:PABS_BENCH_OUTPUT = $benchmarkJson

    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $binary
    $startInfo.Arguments = $Scheme
    $startInfo.WorkingDirectory = $projectRoot
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    if (-not $process.Start()) {
        throw 'Could not start the benchmark process.'
    }
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    $peakWorkingSet = 0L
    $peakPagedMemory = 0L
    while (-not $process.HasExited) {
        $process.Refresh()
        $peakWorkingSet = [Math]::Max($peakWorkingSet, [int64]$process.WorkingSet64)
        $peakPagedMemory = [Math]::Max($peakPagedMemory, [int64]$process.PagedMemorySize64)
        Start-Sleep -Milliseconds 5
    }
    $process.WaitForExit()
    [System.IO.File]::WriteAllText($stdoutPath, $stdoutTask.Result)
    [System.IO.File]::WriteAllText($stderrPath, $stderrTask.Result)
    if ($process.ExitCode -ne 0) {
        throw "Benchmark failed with exit code $($process.ExitCode)."
    }

    $record = [ordered]@{
        scheme = $Scheme
        iterations = $Iterations
        timestamp_utc = (Get-Date).ToUniversalTime().ToString('o')
        operating_system = [System.Environment]::OSVersion.VersionString
        architecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
        processor = (Get-CimInstance Win32_Processor | Select-Object -First 1 -ExpandProperty Name).Trim()
        logical_processors = [System.Environment]::ProcessorCount
        rustc = (& rustc --version)
        peak_working_set_bytes = $peakWorkingSet
        peak_paged_memory_bytes = $peakPagedMemory
        timing_file = Split-Path -Leaf $benchmarkJson
    }
    $resourcePath = Join-Path $outputRoot "$($Scheme)_$($stamp)_resources.json"
    $record | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $resourcePath -Encoding utf8
    Get-Content -LiteralPath $resourcePath
}
finally {
    Remove-Item Env:PABS_BENCH_ITERS -ErrorAction SilentlyContinue
    Remove-Item Env:PABS_BENCH_OUTPUT -ErrorAction SilentlyContinue
    Pop-Location
}
