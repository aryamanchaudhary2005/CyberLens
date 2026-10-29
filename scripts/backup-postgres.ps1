[CmdletBinding()]
param(
    [string] $OutputPath = (Join-Path (Get-Location) ("cyberlens-{0:yyyyMMdd-HHmmss}.dump" -f (Get-Date)))
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$docker = Get-Command docker -ErrorAction Stop
$resolvedOutputPath = [IO.Path]::GetFullPath($OutputPath)
$parent = Split-Path -Parent $resolvedOutputPath
if ($parent -and -not (Test-Path -LiteralPath $parent)) {
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
}
if (Test-Path -LiteralPath $resolvedOutputPath) {
    throw "Refusing to overwrite existing backup '$resolvedOutputPath'. Choose a new path."
}
$containerPath = "/tmp/cyberlens-backup-$([guid]::NewGuid().ToString('N')).dump"

Push-Location $repoRoot
try {
    Write-Host "Writing PostgreSQL custom-format backup to $resolvedOutputPath"
    & $docker.Source compose exec -T postgres sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc --file="$1"' sh $containerPath
    if ($LASTEXITCODE -ne 0) {
        throw "PostgreSQL backup failed with exit code $LASTEXITCODE."
    }
    & $docker.Source compose cp "postgres:$containerPath" $resolvedOutputPath
    if ($LASTEXITCODE -ne 0) {
        throw "Could not copy the PostgreSQL backup from the container."
    }
    if ((Get-Item -LiteralPath $resolvedOutputPath).Length -eq 0) {
        throw "PostgreSQL backup was empty."
    }
    Write-Host "Backup complete: $resolvedOutputPath"
} finally {
    & $docker.Source compose exec -T postgres sh -c 'rm -f "$1"' sh $containerPath 2>$null
    Pop-Location
}
