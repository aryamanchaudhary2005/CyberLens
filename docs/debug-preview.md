# Isolated UI debug preview

This disposable Demo preview uses the dedicated Compose project
`cyberlens-debug-20261020`, with the current frontend and backend sources. Its
PostgreSQL and Redis data are in container `tmpfs` storage. Stopping or
recreating those containers discards the preview records. This preview does not
use the normal `postgres_data` or `redis_data` volumes and does not load `.env`.

Open the UI at <http://localhost:15173>. The API documentation is at
<http://localhost:18000/docs>. After the startup smoke check, the synthetic
administrator is `admin` / `CyberLens-Smoke-Changed-Password-2026!`. This password
is for this disposable local preview only.

The PostgreSQL-backed startup and full analyst workflow passed on 2026-10-20.
The Docker Desktop engine pipe was unavailable when checked on 2026-10-21. The
Docker Desktop CLI also failed to start it because the installation registry
key was missing, so the preview could not be confirmed reachable or rebuilt.
After Docker Desktop is available and its engine is running, use the command
below to restore the disposable preview. Its database and Redis use temporary
container storage, so a container recreation starts those services with empty
preview data.

The preview runs in Demo mode and uses synthetic offline provider fixtures.
Workers, the dispatcher, PostgreSQL, and Redis share an internal Docker network.
Only the API and static frontend also join a browser-access network; their
published ports bind to `127.0.0.1`. No provider keys are configured.

Start or rebuild the preview from the repository root:

```powershell
docker compose --env-file .env.example --project-name cyberlens-debug-20261020 --file .debug-runtime.compose.yml up --build -d --wait --wait-timeout 180
```

Run browser tests from `frontend` against this preview. The smoke test requires
a freshly bootstrapped preview; it changes the initial password.

```powershell
$env:CYBERLENS_SMOKE_PASSWORD = 'CyberLens-Debug-Disposable-2026!'
$env:CYBERLENS_API_ORIGIN = 'http://localhost:18000'
npm run smoke:e2e -- e2e/smoke.spec.ts --config .debug-runtime.playwright.config.ts
npm run smoke:e2e -- e2e/full-workflow.spec.ts --config .debug-runtime.playwright.config.ts
```

Stop only this preview when it is no longer needed:

```powershell
docker compose --env-file .env.example --project-name cyberlens-debug-20261020 --file .debug-runtime.compose.yml down
```

This is a local debugging preview, not a production deployment profile. The
ordinary Compose project and its persisted data remain separate.

## Checks performed on 2026-10-20

- A fresh PostgreSQL 16 database upgraded from the empty schema through
  `20261020_0020`. `alembic check` reported `No new upgrade operations detected.`
- Aggregate API readiness returned `ready` with database, Redis, and worker
  dependencies all `true`. API, frontend, PostgreSQL, Redis, and worker
  container health checks passed; the dispatcher was running.
- The startup and first-administrator password-change smoke test passed:
  **1 test in 4.4 seconds**.
- The real Admin/Analyst/Viewer workflow passed: **1 test in 28.5 seconds**. It
  exercised account provisioning and password changes, an asset, two queued
  investigations, findings, an incident, timeline notes, task saving, linked
  remediation/actions/control mapping, an immutable JSON report, comparisons,
  deep links, and Viewer restrictions.

The first runtime attempt exposed an actual dashboard query parsing failure for
`range_days=30`; the backend fix was included in the final rebuilt image. Earlier
browser attempts also identified stale readiness text, login-response timing,
and ambiguous test selectors, which were corrected before the passing checks.
No live provider verification was performed. Demo jobs used offline fixtures;
the investigation worker had no external network connection.
