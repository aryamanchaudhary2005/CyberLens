# CyberLens setup and run modes

CyberLens is a local single-workspace application. Docker Compose runs a React static frontend, FastAPI, PostgreSQL, Redis, an RQ worker, an outbox dispatcher, and a loopback-only local HTTPS gateway. Live is the normal Compose mode. Copy `.env.example` only if `.env` does not already exist; never replace an existing `.env` as part of setup.

## Offline Demo mode

1. Install Docker Desktop and wait until its engine is running.
2. In PowerShell, create `.env` only if it is absent:

   ```powershell
   if (-not (Test-Path .env)) { Copy-Item .env.example .env }
   ```

3. Start an isolated Demo project (it has separately named PostgreSQL and Redis volumes):

   ```powershell
   docker compose --project-name cyberlens-demo -f docker-compose.yml -f docker-compose.demo.yml up --build -d --wait --wait-timeout 180
   ```

4. Open `https://localhost:8443`. API reference: `https://localhost:8443/docs`. The local Caddy CA is stored in the Demo project's own volume. Trust its local root certificate or accept the browser warning for this local test.

The first Demo administrator is `admin` with temporary password `CyberLens-Demo-Only-2026!`, unless explicitly overridden by `DEMO_BOOTSTRAP_ADMIN_USERNAME` / `DEMO_BOOTSTRAP_ADMIN_PASSWORD`. The password must be changed at first sign-in. Existing accounts keep their changed passwords. Demo collectors, password screening, and the optional XposedOrNot example use deterministic offline fixtures and make no provider or website requests.

Demo database/queue settings use `DEMO_POSTGRES_USER`, `DEMO_POSTGRES_DB`, `DEMO_POSTGRES_PASSWORD`, and `DEMO_REDIS_PASSWORD`; the defaults match the published offline fixture stack. They intentionally do not inherit Live credentials from `.env`. Existing volumes keep their database role passwords; a rebuild does not reinitialize them. Use matching explicit `DEMO_*` overrides for a previously customized Demo volume. `./scripts/test-compose-isolation.ps1` checks default isolation, explicit overrides, and unchanged Live configuration without starting containers or accessing records.

Live and Demo share port8443. Before starting Demo, stop Live with `docker compose --project-name cyberlens stop`. To return to Live, stop Demo using its project/files, then start Live as below. Follow Demo logs with `docker compose --project-name cyberlens-demo -f docker-compose.yml -f docker-compose.demo.yml logs -f`; Ctrl+C stops only log following. Preserve all existing volumes.

Optional sample assets can be added without resetting existing workspace data:

```powershell
docker compose --project-name cyberlens-demo -f docker-compose.yml -f docker-compose.demo.yml exec api python -m app.cli seed-demo
```

The seed command is additive and idempotent. `reset-demo` and `reset-and-seed-demo` are separate destructive Demo-only commands; they are not used by verification, benchmarks, or startup.

## Isolated release verification

For a disposable browser/runtime check, use a unique Compose project name and the optional verification overlay. It publishes the gateway on loopback port `18443` and the API on loopback port `18000` by default; set `CYBERLENS_VERIFY_PORT` or `CYBERLENS_VERIFY_API_PORT` to another unused port if needed. Compose creates project-specific PostgreSQL, Redis, and Caddy volumes, so this check does not attach to the default Live volumes:

```powershell
$env:CYBERLENS_VERIFY_PORT = '18443'
$env:CYBERLENS_VERIFY_API_PORT = '18000'
$project = "cyberlens-verify-$([guid]::NewGuid().ToString('N').Substring(0, 8))"
docker compose --project-name $project -f docker-compose.yml -f docker-compose.demo.yml -f docker-compose.verify.yml up --build -d --wait
```

Open `https://localhost:18443`. After startup, `./scripts/test-migration-upgrade.ps1 -ProjectName <verification-project>` can validate a forward upgrade in a unique temporary database, seed synthetic legacy rows, verify their preservation, and drop only that database. Stop only the named verification project with the same Compose files and `down`; do not add `--volumes` when its data should be retained. The overlay changes the host port only. Demo mode remains offline. This is a local verification profile, not a deployment mode. Actual Module 31 startup, migration, backup/restore, restart, browser, benchmark, and scanner results are in [the test-results record](test-results.md#module-31-whole-project-debugging-and-release-verification).

## Local Live-style mode

Set unique `POSTGRES_PASSWORD` and `REDIS_PASSWORD` values and an operator-chosen `BOOTSTRAP_ADMIN_PASSWORD` of at least 12 characters in `.env`; keep `COOKIE_SECURE=true`. Do not replace any existing `.env` values wholesale. Never use the published Demo password for Live bootstrap. The default Compose project reuses existing `postgres_data` and `redis_data` volumes, preserving their contents. If that PostgreSQL volume was initialized with the old published Demo database password, start only `postgres`, connect with `docker compose exec postgres psql -U cyberlens -d cyberlens`, run `\password cyberlens`, enter the configured new value at the hidden prompts, then start the full stack. This changes the role password in place and does not recreate the volume.

Start Live with `docker compose --project-name cyberlens up --build -d --wait --wait-timeout 180` after stopping Demo with `docker compose --project-name cyberlens-demo -f docker-compose.yml -f docker-compose.demo.yml stop`. Open `https://localhost:8443`; API docs are at `/docs`. Caddy's local CA is persisted in `caddy_data`. Trust that CA on the local machine or accept the browser warning. The gateway is the only published service and listens on `127.0.0.1:8443`. Follow Live logs with `docker compose --project-name cyberlens logs -f`. Hard-refresh Ctrl+F5 after a frontend rebuild.

Do not expose this stack to the public internet. The local Live profile is an operational exercise, not a public-production deployment. Optional RDAP/NVD/CISA/EPSS requests are public network traffic; FIRST EPSS needs no API key. EPSS uses its own shared Redis cache and rate limit, and its value remains separate from CVSS, KEV, applicability, evidence, and risk scoring. VirusTotal and HIBP email-breach checks require their relevant credentials; authorized website checks require a current authorization record. New passwords in Live mode also use the keyless HIBP Pwned Passwords range API. This needs no additional setting or API key and fails closed with a retryable message if the provider is unavailable. Existing passwords are not screened during login. See [password screening behavior](../README.md#use-live-collectors) and [threat model](threat-model.md).

The XposedOrNot community email lookup is independently disabled by default. Enable it only for use allowed by its [community terms and endpoint limits](xposedornot.md). Set `XPOSEDORNOT_ENABLED=true`, `XPOSEDORNOT_COMMUNITY_USE_ACK=true`, and a unique Fernet-compatible `XPOSEDORNOT_CACHE_KEY`; generate one with `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`. `XPOSEDORNOT_CACHE_TTL_SECONDS` defaults to 900 seconds and is clamped to 60–3600. The collector requires Redis for shared quota enforcement and encrypted result caching; it fails closed if Redis is unavailable. The lookup is selected per email investigation and requires an Analyst/Admin to confirm permission to send that exact address to XposedOrNot. It does not replace HIBP, use domain-wide enumeration, or import the provider's risk value. See [XposedOrNot privacy, coverage, and configuration](xposedornot.md).

Spamhaus DROP uses two fixed official JSON feeds to build a shared local IPv4/IPv6 snapshot. Demo mode reads only its synthetic fixture. Live mode schedules refreshes at the configured interval, which cannot be less than 24 hours; a failed attempt preserves the last good snapshot and does not permit an early manual retry. Defaults are `SPAMHAUS_DROP_ENABLED=true`, `SPAMHAUS_DROP_REFRESH_INTERVAL_HOURS=24`, `SPAMHAUS_DROP_FRESHNESS_HOURS=48`, and `SPAMHAUS_DROP_MAX_DOWNLOAD_BYTES=1000000`. An Admin can queue a refresh from **Integrations**; the dispatcher and worker do the download. Investigations use only the current local snapshot and check directly submitted public IP assets. See [Spamhaus DROP operation and privacy](spamhaus-drop.md).

CINS Army is a distinct IP-list source using the same shared snapshot, dispatcher, worker, safe download, cooldown, checksum, and retention infrastructure. Defaults are `CINS_ARMY_ENABLED=true`, `CINS_ARMY_REFRESH_INTERVAL_HOURS=24`, `CINS_ARMY_FRESHNESS_HOURS=48`, and `CINS_ARMY_MAX_DOWNLOAD_BYTES=2000000`. The 24-hour default is CyberLens configuration, not a claim about provider publication frequency. An Admin can queue its refresh from **Integrations**. Investigations only match the exact submitted public IP against a local snapshot; they do not contact CINS or the investigated IP during collection. See [CINS Army integration and limitations](cins-army.md).

OpenPhish is optional and disabled by default. Before Live ingestion, review the [official community feed repository](https://github.com/openphish/public_feed) and [current terms](https://www.openphish.com/terms.html). Community-feed use is limited to permitted personal/research purposes; business use and disclosure require prior written provider permission. An acknowledgement does not grant provider rights. For a permitted personal-only deployment, set `OPENPHISH_ENABLED=true`, `OPENPHISH_USE_ACK=true`, and `OPENPHISH_PERSONAL_OWNER_USERNAME` to one active account. The app restricts all Live workspace APIs and reports to that owner while OpenPhish data is retained. Shared/business use stays unavailable unless prior written provider permission applies and `OPENPHISH_PROVIDER_SHARING_PERMISSION_ACK=true` is explicitly configured. CyberLens refreshes every 12 hours by default (local configuration), stores a bounded validated snapshot, and matches URLs locally without visiting destinations. Demo remains independent of these Live settings and uses reserved synthetic URL scenarios only. See [OpenPhish permitted use, privacy, and limitations](openphish.md).

OSV package lookups also use public network access but require no API key. Add the exact npm or PyPI package name and version to the application inventory before queueing an investigation; only those selected fields are sent to OSV. A CPE-only row continues to use NVD and does not trigger a package lookup. No SBOM upload or dependency discovery is performed. Offline Demo mode makes no external OSV request and includes one synthetic `npm/cyberlens-demo-widget@1.0.0` example; see [the Demo walkthrough](demo-and-viva.md).

An Admin may use the **ATT&CK catalog versions** panel under an incident technique matrix to queue an official Enterprise STIX 2.1 synchronization. The status panel reports the active/retrieved version, source commit reference, checksum, counts, and any import failure. Synchronization is available only outside Demo mode; the bundled legacy catalog remains available offline. MITRE URLs embedded inside STIX objects are stored only as references and are never fetched. A checksum detects byte changes but does not independently prove source authenticity. See the [versioned catalog API behavior](api.md#versioned-mitre-attck-catalog).

The static frontend and API are reachable only through the loopback local HTTPS gateway at `https://localhost:8443`. API, worker, dispatcher, PostgreSQL, and Redis have no published host ports. The gateway and locally generated certificate are operational convenience for a single-user machine; they do not make this a public-production deployment.

## Existing installations with Demo history

The Live-mode change does not relabel or delete historical synthetic assets, findings, investigations, incidents, or evidence. Live collection views exclude records marked synthetic, while existing saved report bytes and their original provenance remain intact. Monitoring schedules retain the mode in which their history was created; an unrun legacy schedule is kept in Demo mode by the additive migration. For an ordinary upgrade, keep the records and use the Live projections rather than manually deleting rows.

If an installation needs an offline archival copy, first create a custom-format PostgreSQL backup with `scripts/backup-postgres.ps1`, then validate it using `scripts/test-restore.ps1` and retain the backup in access-controlled storage. Do not use `docker compose down --volumes`, Demo reset commands, or ad-hoc SQL deletes to separate synthetic rows: related evidence, audit entries, and point-in-time reports must remain linked. CyberLens does not currently provide a selective physical-export tool for synthetic records. Until such an export is available, the safe archival approach is to retain the original labeled records in place, keep a verified protected backup, and rely on Live-mode filtering.

## Database migrations and backups

API startup applies Alembic migrations. To validate a clean PostgreSQL database and model drift, CI runs `alembic upgrade head` followed by `alembic check`. Legacy SQLite upgrade tests start from older revisions, retain representative saved rows, and upgrade through the current head.

Create a custom-format backup and restore it into a disposable database:

```powershell
.\scripts\backup-postgres.ps1 -OutputPath .\backups\cyberlens.dump
.\scripts\test-restore.ps1 -BackupPath .\backups\cyberlens.dump
```

The restore check creates a unique `cyberlens_restore_*` database, checks that the `users` table exists, and compares counts in users, assets, investigations, evidence, findings, incidents, and reports. It removes only that disposable database. Compose volumes are not removed. No local backup/restore result is implied by these instructions; see [verification results](test-results.md).

## Development checks

Run `./scripts/verify.ps1` to run backend tests, frontend dependency installation (unless `-SkipDependencyInstall`), frontend TypeScript checks/build, and Compose config validation. CI separately runs clean PostgreSQL migrations, legacy migration upgrades, and Playwright checks. Docker and browser validations need an available Docker engine.

## Reproducible Demo benchmark

The benchmark uses a loopback API, synthetic assets, and Demo collectors. It appends investigations and JSON report snapshots; it never resets or deletes workspace records. Follow [benchmark instructions](benchmarks.md) and inspect the output before running it against a workspace you want to keep small.
