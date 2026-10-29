[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$savedEnvironment = @{}
$demoNames = @('DEMO_POSTGRES_USER', 'DEMO_POSTGRES_DB', 'DEMO_POSTGRES_PASSWORD', 'DEMO_REDIS_PASSWORD', 'DEMO_BOOTSTRAP_ADMIN_USERNAME', 'DEMO_BOOTSTRAP_ADMIN_PASSWORD')
$liveValues = @{
    POSTGRES_USER = 'live_isolation_user'
    POSTGRES_DB = 'live_isolation_db'
    POSTGRES_PASSWORD = 'Live-Isolation-Database-2026!'
    REDIS_PASSWORD = 'Live-Isolation-Redis-2026!'
    BOOTSTRAP_ADMIN_USERNAME = 'live-isolation-admin'
    BOOTSTRAP_ADMIN_PASSWORD = 'Live-Isolation-Admin-2026!'
}
$emptyEnvironmentFile = [System.IO.Path]::GetTempFileName()

function Assert-Equal($Actual, $Expected, [string] $Message) {
    if ($Actual -cne $Expected) { throw $Message }
}

function Read-Compose([switch] $Demo) {
    $arguments = @('compose', '--env-file', $emptyEnvironmentFile, '--project-name', 'cyberlens-config-isolation', '-f', 'docker-compose.yml')
    if ($Demo) { $arguments += @('-f', 'docker-compose.demo.yml') }
    $configuration = & docker @arguments config --format json
    if ($LASTEXITCODE -ne 0) { throw 'Compose configuration failed.' }
    return ($configuration | ConvertFrom-Json)
}

Push-Location $repoRoot
try {
    foreach ($name in @($liveValues.Keys) + $demoNames) {
        $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
    }
    foreach ($name in $liveValues.Keys) { [Environment]::SetEnvironmentVariable($name, $liveValues[$name], 'Process') }
    foreach ($name in $demoNames) { [Environment]::SetEnvironmentVariable($name, $null, 'Process') }

    $configuration = Read-Compose -Demo
    foreach ($service in @('api', 'worker', 'dispatcher')) {
        $settings = $configuration.services.$service.environment
        Assert-Equal $settings.APP_MODE 'demo' "$service must remain offline Demo."
        Assert-Equal $settings.DATABASE_URL 'postgresql+psycopg://cyberlens:CyberLensDemoDb2026@postgres:5432/cyberlens' "$service inherited Live database settings."
        Assert-Equal $settings.REDIS_URL 'redis://:CyberLensDemoRedis2026@redis:6379/0' "$service inherited Live Redis settings."
        Assert-Equal $settings.COOKIE_SECURE 'true' "$service must retain secure cookies."
        if ($settings.PSObject.Properties.Name -contains 'HIBP_API_KEY') { throw "$service inherited the Live env_file." }
    }
    Assert-Equal $configuration.services.api.environment.BOOTSTRAP_ADMIN_USERNAME 'admin' 'Demo inherited the Live administrator name.'
    Assert-Equal $configuration.services.api.environment.BOOTSTRAP_ADMIN_PASSWORD '' 'Demo inherited the Live bootstrap password.'
    Assert-Equal $configuration.services.postgres.environment.POSTGRES_PASSWORD 'CyberLensDemoDb2026' 'Demo PostgreSQL inherited a Live password.'
    Assert-Equal $configuration.services.redis.environment.REDIS_PASSWORD 'CyberLensDemoRedis2026' 'Demo Redis inherited a Live password.'

    foreach ($name in $demoNames) { [Environment]::SetEnvironmentVariable($name, ('isolated-' + $name.ToLowerInvariant()), 'Process') }
    $custom = Read-Compose -Demo
    Assert-Equal $custom.services.api.environment.BOOTSTRAP_ADMIN_PASSWORD 'isolated-demo_bootstrap_admin_password' 'Explicit Demo administrator override was ignored.'
    Assert-Equal $custom.services.postgres.environment.POSTGRES_PASSWORD 'isolated-demo_postgres_password' 'Explicit Demo database override was ignored.'
    foreach ($service in @('api', 'worker', 'dispatcher')) {
        Assert-Equal $custom.services.$service.environment.DATABASE_URL 'postgresql+psycopg://isolated-demo_postgres_user:isolated-demo_postgres_password@postgres:5432/isolated-demo_postgres_db' "$service does not share the explicit Demo database settings."
        Assert-Equal $custom.services.$service.environment.REDIS_PASSWORD 'isolated-demo_redis_password' "$service does not share the explicit Demo Redis settings."
    }

    $live = Read-Compose
    Assert-Equal $live.services.api.environment.APP_MODE 'live' 'The base stack must remain Live.'
    Assert-Equal $live.services.postgres.environment.POSTGRES_PASSWORD $liveValues.POSTGRES_PASSWORD 'Demo variables changed the Live database configuration.'
    Assert-Equal $live.services.api.environment.BOOTSTRAP_ADMIN_PASSWORD $liveValues.BOOTSTRAP_ADMIN_PASSWORD 'Demo variables changed Live bootstrap.'
    Write-Host 'Compose isolation passed: Demo defaults, explicit Demo overrides, and unchanged Live settings. No containers or records changed.'
} finally {
    foreach ($name in $savedEnvironment.Keys) { [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name], 'Process') }
    Remove-Item -LiteralPath $emptyEnvironmentFile -ErrorAction SilentlyContinue
    Pop-Location
}
