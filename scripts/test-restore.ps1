[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $BackupPath
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$docker = Get-Command docker -ErrorAction Stop
$database = "cyberlens_restore_{0}" -f ([guid]::NewGuid().ToString('N').Substring(0, 12))
$countQuery = "SELECT concat_ws(':', (SELECT count(*) FROM users), (SELECT count(*) FROM assets), (SELECT count(*) FROM investigations), (SELECT count(*) FROM evidence_snapshots), (SELECT count(*) FROM findings), (SELECT count(*) FROM incidents), (SELECT count(*) FROM reports))"
Push-Location $repoRoot
try {
    $sourceCounts = (& $docker.Source compose exec -T postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atc "$1"' sh $countQuery).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'Could not read source record counts before restore.' }
    & (Join-Path $PSScriptRoot 'restore-postgres.ps1') -BackupPath $BackupPath -DatabaseName $database
    if ($LASTEXITCODE -ne 0) { throw "Restore script failed." }
    $tableQuery = "SELECT to_regclass('public.users')"
    $tableOutput = & $docker.Source compose exec -T postgres sh -c 'psql -U "$POSTGRES_USER" -d "$1" -tAc "$2"' sh $database $tableQuery
    if ($LASTEXITCODE -ne 0) { throw 'Could not verify the restored users table.' }
    $table = ($tableOutput -join '').Trim()
    if ($table -ne 'users') { throw "Disposable restore did not contain the expected users table." }
    $restoredCounts = (& $docker.Source compose exec -T postgres sh -c 'psql -U "$POSTGRES_USER" -d "$1" -Atc "$2"' sh $database $countQuery).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'Could not read restored record counts.' }
    if ($restoredCounts -ne $sourceCounts) {
        throw "Restored core record counts differ from the source. Source: $sourceCounts; restored: $restoredCounts."
    }
    Write-Host "Disposable restore verification passed for '$database'. Core table counts matched (users, assets, investigations, evidence, findings, incidents, reports)."
} finally {
    & $docker.Source compose exec -T postgres sh -c 'dropdb -U "$POSTGRES_USER" "$1"' sh $database 2>$null
    Pop-Location
}
