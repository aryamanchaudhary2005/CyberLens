[CmdletBinding()]
param(
    [switch] $SkipDependencyInstall
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$backendRoot = Join-Path $repoRoot 'backend'
$frontendRoot = Join-Path $repoRoot 'frontend'

$venvPython = Join-Path $backendRoot '.venv/Scripts/python.exe'
if (Test-Path -LiteralPath $venvPython) {
    $python = $venvPython
} else {
    $python = (Get-Command python -ErrorAction Stop).Source
}
$npm = (Get-Command npm -ErrorAction Stop).Source
$docker = Get-Command docker -ErrorAction SilentlyContinue

function Invoke-Check {
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [string] $Executable,
        [Parameter(Mandatory)] [string[]] $Arguments,
        [Parameter(Mandatory)] [string] $WorkingDirectory
    )

    Write-Host "`n== $Name =="
    Push-Location $WorkingDirectory
    try {
        & $Executable @Arguments
        if ($LASTEXITCODE -ne 0) {
            throw "$Name failed with exit code $LASTEXITCODE."
        }
    } finally {
        Pop-Location
    }
}

Invoke-Check -Name 'Backend tests' -Executable $python -Arguments @('-m', 'pytest', '-q') -WorkingDirectory $backendRoot

if (-not $SkipDependencyInstall) {
    Invoke-Check -Name 'Install frontend dependencies from lockfile' -Executable $npm -Arguments @('ci') -WorkingDirectory $frontendRoot
}

Invoke-Check -Name 'Frontend TypeScript checks' -Executable $npm -Arguments @('run', 'typecheck') -WorkingDirectory $frontendRoot
Invoke-Check -Name 'Frontend production build' -Executable $npm -Arguments @('run', 'build') -WorkingDirectory $frontendRoot
if ($null -ne $docker) {
    Invoke-Check -Name 'Live Docker Compose configuration' -Executable $docker.Source -Arguments @('compose', 'config', '--quiet') -WorkingDirectory $repoRoot
    Invoke-Check -Name 'Isolated Demo Docker Compose configuration' -Executable $docker.Source -Arguments @(
        'compose', '--project-name', 'cyberlens-demo', '-f', 'docker-compose.yml', '-f', 'docker-compose.demo.yml', 'config', '--quiet'
    ) -WorkingDirectory $repoRoot
    & (Join-Path $PSScriptRoot 'test-compose-isolation.ps1')
} else {
    Write-Host "`n== Docker Compose configuration ==`nSkipped: Docker CLI is not installed."
}

Write-Host "`nAll local verification checks passed. PostgreSQL migrations and browser smoke tests run in CI against isolated services."
