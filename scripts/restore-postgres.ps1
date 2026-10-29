[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $BackupPath,
    [Parameter(Mandatory)] [ValidatePattern('^cyberlens_restore_[A-Za-z0-9_]+$')] [string] $DatabaseName
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$docker = Get-Command docker -ErrorAction Stop
$backup = (Resolve-Path -LiteralPath $BackupPath).Path
$containerPath = "/tmp/$([IO.Path]::GetFileName($backup))"

Push-Location $repoRoot
try {
    $existsQuery = "SELECT 1 FROM pg_database WHERE datname = '$DatabaseName'"
    $existsOutput = & $docker.Source compose exec -T postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAc "$1"' sh $existsQuery
    if ($LASTEXITCODE -ne 0) { throw 'Could not check the target database before restore.' }
    $exists = ($existsOutput -join '').Trim()
    if ($exists -eq '1') {
        throw "Refusing to overwrite existing database '$DatabaseName'. Use a new disposable cyberlens_restore_* name."
    }
    & $docker.Source compose cp $backup "postgres:$containerPath"
    if ($LASTEXITCODE -ne 0) { throw "Could not copy the backup into the PostgreSQL container." }
    & $docker.Source compose exec -T postgres sh -c 'createdb -U "$POSTGRES_USER" "$1"' sh $DatabaseName
    if ($LASTEXITCODE -ne 0) { throw "Could not create disposable restore database '$DatabaseName'." }
    & $docker.Source compose exec -T postgres sh -c 'pg_restore -U "$POSTGRES_USER" -d "$1" --no-owner --exit-on-error "$2"' sh $DatabaseName $containerPath
    if ($LASTEXITCODE -ne 0) { throw "PostgreSQL restore failed for '$DatabaseName'." }
    Write-Host "Restore complete in disposable database '$DatabaseName'."
} finally {
    & $docker.Source compose exec -T postgres sh -c 'rm -f "$1"' sh $containerPath 2>$null
    Pop-Location
}
