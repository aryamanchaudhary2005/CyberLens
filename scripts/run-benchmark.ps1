[CmdletBinding()]
param(
    [string] $BaseUrl = 'http://127.0.0.1:8000',
    [ValidateRange(1, 10000)] [int] $Requests = 100,
    [ValidateRange(1, 128)] [int] $Concurrency = 5,
    [ValidateRange(1, 3600)] [int] $TimeoutSeconds = 180,
    [string] $OutputPath
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$pythonVenv = Join-Path $repoRoot 'backend/.venv/Scripts/python.exe'
$python = if (Test-Path -LiteralPath $pythonVenv) { $pythonVenv } else { (Get-Command python -ErrorAction Stop).Source }
$docker = Get-Command docker -ErrorAction Stop

if (-not $env:CYBERLENS_BENCHMARK_USERNAME -or -not $env:CYBERLENS_BENCHMARK_PASSWORD) {
    throw 'Set CYBERLENS_BENCHMARK_USERNAME and CYBERLENS_BENCHMARK_PASSWORD in the current PowerShell session. Credentials are never accepted as command-line arguments.'
}

Push-Location $repoRoot
try {
    $modeOutput = & $docker.Source compose exec -T api python -c "from app.config import get_settings; print(get_settings().app_mode)"
    if ($LASTEXITCODE -ne 0) { throw 'Could not verify the API mode before preparing benchmark fixtures.' }
    $mode = ($modeOutput -join '').Trim()
    if ($mode -ne 'demo') { throw "Refusing to seed benchmark fixtures because APP_MODE is '$mode'; the benchmark is Demo-only." }

    Write-Host 'Ensuring the five synthetic benchmark assets exist (seed-demo is additive and does not reset records).'
    & $docker.Source compose exec -T api python -m app.cli seed-demo
    if ($LASTEXITCODE -ne 0) { throw "Demo fixture seed failed with exit code $LASTEXITCODE." }

    $arguments = @(
        (Join-Path $repoRoot 'benchmarks/run_benchmark.py'),
        '--base-url', $BaseUrl,
        '--requests', $Requests.ToString(),
        '--concurrency', $Concurrency.ToString(),
        '--timeout-seconds', $TimeoutSeconds.ToString()
    )
    if ($OutputPath) { $arguments += @('--output', $OutputPath) }
    & $python @arguments
    if ($LASTEXITCODE -ne 0) { throw "Benchmark failed with exit code $LASTEXITCODE." }
} finally {
    Pop-Location
}
