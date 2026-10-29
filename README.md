# CyberLens

CyberLens is a local cyber threat intelligence, security analysis, and incident response workspace. Analysts register assets, start background investigations, review evidence and CVE applicability, calculate an explainable prioritization score, manage response cases, and download saved PDF or JSON reports.

The normal local Compose mode uses live provider integrations where configured; the separate Demo mode provides an offline synthetic workflow. It does not perform exploitation, password attacks, network-wide scanning, automatic containment, or external notifications.

## Why a browser interface?

CyberLens is an application with a browser interface and local backend services. The browser presents the analyst workspace while PostgreSQL, Redis, the API, and investigation workers keep durable records and perform background work. Provider credentials stay on the backend, and every client uses the same authentication, authorization, and audit rules. A browser also gives Windows, macOS, and Linux users the same interface without a separate desktop installer and update process.

The offline Demo can run entirely on the local machine after its images and dependencies are installed. A desktop wrapper could provide a dedicated window later, but would still need the database, queue, and worker services; it would add packaging, updates, and platform maintenance. The current browser approach fits the shared analyst workflow and keeps those operations in one place.

The optional evidence-grounded AI case briefing is currently disabled. No local inference runtime is installed or configured, and the project does not send evidence or analyst notes to an external AI service. See [the AI briefing status and privacy boundary](docs/ai-briefing.md).

For current measured verification results, browser captures, benchmark output, test skips, and environment limits, see [the whole-project release verification record](docs/test-results.md#module-31-whole-project-debugging-and-release-verification) and [known limitations](docs/known-limitations.md).

For the integrated UI-00–UI-09/UI-REF review, working rotating Earth and dashboard effects, and 79 passing final browser checks, see [the 2026-10-26 UI verification](docs/ui-final-review-20261026.md). For a panel/conclave presentation, use [the offline Demo startup and rehearsal guide](docs/panel-demo.md).

The subsequent supplied Bento reference is implemented as a rotating network sphere, floating geometry and halftone ripple. See [the dashboard effects follow-up](docs/dashboard-reference-effects-20261026.md) for captures and its separate 46-test verification.

## Start on Windows (Live mode)

1. Install Docker Desktop and wait for **Engine running**.
2. Open PowerShell in this project directory. Create `.env` only if it does not already exist. If it already exists, preserve it and set only missing Live secrets:

   ```powershell
   if (-not (Test-Path .env)) { Copy-Item .env.example .env }
   ```

3. Set unique `POSTGRES_PASSWORD`, `REDIS_PASSWORD`, and `BOOTSTRAP_ADMIN_PASSWORD` values in `.env`. The bootstrap password must be at least 12 characters and cannot be the published Demo password. Keep `COOKIE_SECURE=true`. Start the local Live stack:

   ```powershell
   docker compose --project-name cyberlens up --build -d --wait --wait-timeout 180
   docker compose --project-name cyberlens logs -f
   ```

4. Open [CyberLens](https://localhost:8443). The API reference is at [https://localhost:8443/docs](https://localhost:8443/docs), and readiness is at [https://localhost:8443/api/v1/health/ready](https://localhost:8443/api/v1/health/ready). Caddy creates a local CA certificate on first startup; trust that local certificate on this machine or accept the browser's local certificate warning. The gateway binds only to loopback.

If the existing PostgreSQL volume was initialized with the published Demo database password, rotate its database role to the new `.env` password before starting the API. Run `docker compose up -d postgres`, connect locally with `docker compose exec postgres psql -U cyberlens -d cyberlens`, enter `\password cyberlens`, type the exact `POSTGRES_PASSWORD` value from `.env` twice at the hidden prompts, then exit with `\q`. This updates the role inside the existing database without replacing the volume. A bootstrap account is created only when it does not already exist; changing `BOOTSTRAP_ADMIN_PASSWORD` later does not reset an account.

The sign-in form starts with an empty password field. Outside Demo mode, first startup requires an explicit `BOOTSTRAP_ADMIN_PASSWORD` of at least 12 characters; the published Demo password is rejected for Live bootstrap, so configure a private operator-chosen password. User password changes rotate that user's active sessions. Administrator resets revoke the target user's sessions and require a change at next sign-in. Login throttling is shared through Redis. New passwords are screened once on submission against HIBP Pwned Passwords using its padded five-character range protocol; only the first five SHA-1 hex characters are sent, while Argon2 remains the password storage algorithm. Existing passwords are not screened during login. A match is rejected with an explanation; if Live screening is unavailable, password creation/change/reset/bootstrap fails without changing the account or its sessions. Demo mode uses a deterministic offline result. This password screening does not require `HIBP_API_KEY`; that optional key is for explicit email-breach lookups.

Investigation creation and retries commit their attempt and outbox delivery event in PostgreSQL together. The dispatcher delivers events to RQ with stable job IDs; worker claims and persisted collector runs are attempt-scoped, so repeated delivery does not duplicate execution or findings. Transient provider/network failures receive at most two automatic retries with exponential backoff. Permanent failures and deterministic Demo provider-outage scenarios do not auto-retry. The API exposes separate `/api/v1/health/postgres`, `/api/v1/health/redis`, and `/api/v1/health/worker` checks; aggregate readiness requires all three. Compose runs the API, dispatcher, RQ worker, PostgreSQL, Redis, and frontend.

Keep the terminal open to see container logs. Stop the services with **Ctrl+C**. Start them again with `docker compose up`. PostgreSQL and Redis use named volumes, so records survive container restarts.

### Explicit offline Demo mode

Live mode is the normal application mode. Demo is an explicit, isolated offline workflow with its own named volumes so it cannot attach to the Live database or Redis data. Start it with:

```powershell
docker compose --project-name cyberlens-demo -f docker-compose.yml -f docker-compose.demo.yml up --build -d --wait --wait-timeout 180
```

Open [CyberLens Demo](https://localhost:8443). Demo uses bundled synthetic collectors and makes no provider or website requests. Its initial local administrator is `admin` / `CyberLens-Demo-Only-2026!` and must change the password at first sign in. Live-mode screens omit Demo-scenario rows from ordinary workspace collections, details, summaries, and reports. Those historical records remain stored with their original provenance in the existing database; switching modes does not delete or relabel them.

Demo uses independent `DEMO_POSTGRES_USER`, `DEMO_POSTGRES_DB`, `DEMO_POSTGRES_PASSWORD`, `DEMO_REDIS_PASSWORD`, `DEMO_BOOTSTRAP_ADMIN_USERNAME`, and `DEMO_BOOTSTRAP_ADMIN_PASSWORD` overrides. With none set, the published offline Demo defaults apply; Live `.env` passwords do not override them. An existing database retains its original role password, and an existing administrator retains its current account password. Changing bootstrap settings does not reset an account.

Live and Demo both use the loopback HTTPS port **8443**, so run one gateway at a time. To switch modes without deleting data:

```powershell
# Live -> offline Demo
docker compose --project-name cyberlens stop
docker compose --project-name cyberlens-demo -f docker-compose.yml -f docker-compose.demo.yml up --build -d --wait --wait-timeout 180

# Demo -> Live
docker compose --project-name cyberlens-demo -f docker-compose.yml -f docker-compose.demo.yml stop
docker compose --project-name cyberlens up --build -d --wait --wait-timeout 180
```

`logs -f` follows output; Ctrl+C stops log following and leaves detached services running. Do not use `docker compose down --volumes`; Live and Demo use separate named volumes. After a frontend rebuild, use Ctrl+F5 in the browser. Existing app/system reduced-motion settings intentionally keep decorative effects static.

If startup reports an unhealthy API, inspect the actual cause with `docker compose --project-name cyberlens-demo -f docker-compose.yml -f docker-compose.demo.yml logs --tail 80 api` (use the Live project/files for Live). `password authentication failed` means the configured database credential differs from the persisted database role; rebuilding images does not reset it. Do not delete the volume as a fix. The Demo credential isolation regression can be checked without starting containers using `./scripts/test-compose-isolation.ps1`.

To prefill Demo sample assets, run this in another PowerShell window:

```powershell
docker compose --project-name cyberlens-demo -f docker-compose.yml -f docker-compose.demo.yml exec api python -m app.cli seed-demo
```

The Demo stack has separate `cyberlens-demo_postgres_data` and `cyberlens-demo_redis_data` volumes. Do not add `--volumes` to `docker compose down` unless you intentionally want to delete that project's persisted records. Live mode uses the default Compose project and its existing volumes. Local Live is an operational exercise, not a public-production deployment configuration. Provider credentials remain backend-only. The authenticated `GET /api/v1/metrics` endpoint reports request totals, queue depth, observed job duration, worker heartbeat, and collector provider status.

## Continuous monitoring

In Live mode, an Admin or Analyst can create a daily or weekly schedule for a domain or URL after recording an active website authorization. Each due check appears as its own investigation in the asset's monitoring history; the prior completed run can be compared with Change Radar. Pause, resume, and cancel control future schedule slots. Expired or revoked authorization blocks future work. Demo mode remains offline with synthetic collector results, and no automatic containment or external notifications are sent. See [monitoring API behavior](docs/api.md#controlled-continuous-monitoring).

Create a PostgreSQL custom-format backup without touching volumes:

```powershell
.\scripts\backup-postgres.ps1 -OutputPath .\backups\cyberlens.dump
```

Restore only into a new disposable database and verify it with:

```powershell
.\scripts\test-restore.ps1 -BackupPath .\backups\cyberlens.dump
```

The restore scripts refuse to overwrite an existing database and never remove Compose volumes.

## Demonstrate the sample scenarios

The UI lets you register an asset and choose a matching synthetic scenario. To prefill the five sample assets, open a second PowerShell window in the project and run:

```powershell
docker compose --project-name cyberlens-demo -f docker-compose.yml -f docker-compose.demo.yml exec api python -m app.cli seed-demo
```

The included scenarios are routine website, suspicious website, exposed email, vulnerable application, and provider outage. Demo mode uses bundled synthetic results and makes **no external requests**. Vulnerable-application findings include fixed synthetic CVSS, KEV, and EPSS values; EPSS is shown as an estimate, not evidence of exploitation or compromise. The UI and reports label demo data.

The Threat modeling workspace is available in Demo and Live modes. It records analyst-entered asset context and STRIDE scenarios; it does not alter synthetic collector output or technical risk scoring. Likelihood, business impact, confidence, assumptions, and unconfirmed information are shown separately, and scenario records can be marked for review before confirmation.

Incident details include a locally versioned MITRE ATT&CK Enterprise technique matrix. Existing mappings remain bound to the bundled `cyberlens-attack-enterprise-subset-1.0` legacy catalog and preserve their saved technique text. In Live mode, an Admin can queue a synchronization from the catalog versions panel; the dispatcher and RQ worker fetch the official Enterprise index and versioned STIX bundle from MITRE's repository and store a checksum-addressed immutable catalog version. Demo mode stays on the bundled catalog and never sends synchronization requests. Revoked and deprecated techniques remain in stored snapshots but are excluded from new selections. Every mapping still requires analyst review and evidence linked to its finding or incident; suggestions do not claim that an ATT&CK behavior occurred. Checksums detect later byte changes but do not independently authenticate MITRE or prove forensic authenticity. See [catalog behavior and API](docs/api.md#versioned-mitre-attck-catalog).

The Integrity workspace verifies the append-only audit hash chain and recomputes checksums for saved evidence. Authorized Analysts and Admins can export the audit chain as JSONL. A verified checksum detects later changes to stored content; it does not prove forensic authenticity, collection provenance, or chain of custody. See [integrity API and limitations](docs/api.md#audit-and-evidence-integrity).

To remove only demo investigations, cases, reports, and synthetic assets, run:

```powershell
docker compose --project-name cyberlens-demo -f docker-compose.yml -f docker-compose.demo.yml exec api python -m app.cli reset-demo
```

To reset and seed the five samples again:

```powershell
docker compose --project-name cyberlens-demo -f docker-compose.yml -f docker-compose.demo.yml exec api python -m app.cli reset-and-seed-demo
```

These reset commands refuse to run unless `APP_MODE=demo`; live investigations and non-synthetic assets are retained. They target only the separate Demo project above. Avoid `docker compose down --volumes` unless you intend to delete the selected project's database and queue data.

## Use live collectors

Live is the normal Compose mode; configure its required secrets as described in [setup](docs/setup.md). Live mode makes public DNS/RDAP, NVD/CISA, and FIRST EPSS requests. EPSS lookups use the public API without a key, a shared Redis cache, and a per-provider request limit. EPSS remains separate from CVSS, KEV membership, applicability, and evidence; provider failures appear as unavailable instead of a zero score. VirusTotal and HIBP email-breach lookup need optional provider keys. Website checks require an authorization record with a selected expiry (1–365 days); analysts and admins can revoke it, and the worker verifies it remains active before the website check. Existing authorization notes are preserved during migration and receive a 30-day renewal window. Only existing VirusTotal reports are queried; URL query strings and fragments are stripped before reputation lookup, while case-sensitive path spelling is preserved. HIBP email lookup checks only an explicitly registered email address. Provider keys remain backend-only and are sent only to their configured provider origin.

Live account-password screening uses the separate, keyless [HIBP Pwned Passwords range API](https://haveibeenpwned.com/API/V3#PwnedPasswords). It sends the five-character SHA-1 prefix over HTTPS with `Add-Padding: true`, compares returned suffixes in memory, and ignores padding rows with a zero count. The complete lookup hash and submitted password are not stored in evidence, reports, or audit metadata. Screening runs only after a password is submitted for account creation, password change, administrator reset, or Live first-admin bootstrap. A confirmed match asks for a different password and does not imply an account compromise. A provider outage blocks Live password-setting operations and can be retried; login with an existing password remains available. Demo mode makes no request.

XposedOrNot is a separate, optional community source for explicitly selected email assets. It is disabled by default and is never a fallback for HIBP. The community service documents personal, low-volume use and per-IP limits of 2 requests/second, 25/hour, and 100/day; use it only if your deployment's use is within those terms. If you are building a product on breach data or need higher throughput, the provider directs users to its paid offering. A Live investigation requires an Analyst/Admin confirmation that the selected email may be sent to XposedOrNot. The email is transmitted to its API over HTTPS; breach response content is allowlisted, and cached sensitive metadata is encrypted. No-match means only “No record found in this provider's dataset.” Coverage differs from HIBP. See [XposedOrNot privacy, coverage, and configuration](docs/xposedornot.md).

Application software can also include an optional package ecosystem (`npm` or `PyPI`) and exact package name on each inventoried version. Live investigations send only that package identity and explicit version to OSV; CyberLens does not inspect a website to guess dependencies and does not upload source code, credentials, or project files. OSV advisory matches start as `needs_review`, and only an analyst-confirmed applicable finding affects vulnerability risk. CPE/NVD analysis remains available for the same component. Demo mode makes no provider requests; its bundled walkthrough fixture matches only `npm`, `cyberlens-demo-widget`, version `1.0.0`.

Do not put API keys in frontend variables or commit `.env`. The local Live HTTPS gateway and required secret setup are documented in [setup](docs/setup.md).

Missing keys and provider failures appear as unavailable or failed collectors. Live results are never replaced with fixtures. Public network destinations are checked before each connection and redirect; all A/AAAA answers are checked, connections use a validated pinned address, and the full request/redirect chain shares one deadline. Credentialed requests cannot cross provider origins or downgrade from HTTPS to HTTP. Private, loopback, link-local, reserved, and metadata targets are blocked.

## Local development and checks

Run the local baseline checks from PowerShell:

```powershell
./scripts/verify.ps1
```

The script runs backend tests, installs the frontend from its lockfile, checks TypeScript (application and smoke-test code), builds the production frontend, and validates Compose configuration. Use `./scripts/verify.ps1 -SkipDependencyInstall` to reuse an already-installed frontend dependency tree.

After starting a disposable Demo stack and completing the initial admin password change, run `npm run workflow:e2e` from `frontend` for account/role and analyst workflow coverage. It creates test users, an asset, investigations, an incident, and a report; do not run it against records you need to preserve. For repeatable measured workload data, use [the benchmark instructions](docs/benchmarks.md); benchmark runs also append investigation and report records.

The backend tests use an in-memory SQLite fixture. CI separately verifies migrations against a clean PostgreSQL 16 database and legacy saved-record upgrades, then runs Chromium Playwright startup/login and full analyst/viewer workflow checks against a newly started Compose stack. See [the CI workflow](.github/workflows/ci.yml) and [the test record](docs/test-results.md) for current results.

The backend Docker image uses pinned versions from `backend/requirements.lock`; the frontend dependency tree is pinned by `frontend/package-lock.json`. To run individual checks manually:

```powershell
cd backend
python -m pip install -r requirements.lock .
python -m pytest -q

cd frontend
npm ci
npm run typecheck
npm run build
```

For the browser smoke check, start a clean local Compose stack with a disposable demo database, install Chromium with `npx playwright install chromium`, then run `npm run smoke:e2e` from `frontend`. Do not point this check at a workspace whose initial administrator password or records you need to preserve; it changes the temporary admin password during the test.

FastAPI is the source of the frontend route contract. After backend API changes, regenerate the committed TypeScript OpenAPI types:

```powershell
cd backend
$previousAppMode = $env:APP_MODE
try {
  $env:APP_MODE = 'demo'
  python -m app.export_openapi
} finally {
  if ($null -eq $previousAppMode) { Remove-Item Env:APP_MODE -ErrorAction SilentlyContinue }
  else { $env:APP_MODE = $previousAppMode }
}
cd ..\frontend
npm run api:types
```

## Modules

1. **Foundation:** React, FastAPI, PostgreSQL, Redis/RQ, Docker Compose, health checks, logging, and Alembic.
2. **Authentication and assets:** Argon2 passwords, hashed server sessions, CSRF, Redis-shared login throttling, last-admin safeguards, audited role/password administration, admin/analyst/viewer write permissions, validated assets, and expiring/revocable website authorization records.
3. **Investigation pipeline:** transactional outbox, idempotent job delivery, distinct retry attempts and collector history, bounded transient retries, stale-job recovery, worker heartbeat, evidence snapshots, and finding deduplication.
4. **DNS and RDAP:** A/AAAA/MX/NS/TXT/CAA, SPF/DMARC context, IANA RDAP discovery, and domain-to-IP evidence.
5. **Website and TLS:** bounded authorized HTTP(S), certificate validity/trust/hostname observations, subject/SAN/fingerprint context, SNI hostname, TLS version, negotiated ALPN, redirect-hop status, shared deadline, and response caps.
6. **Reputation and breach intelligence:** optional existing VirusTotal reports and explicit-account HIBP queries; opt-in XposedOrNot community lookup has distinct coverage and terms.
7. **Vulnerability matching:** NVD CPE selection checked against the recorded vendor/product/exact version and audited, paginated CVE candidates, separate CVSS/CISA KEV/FIRST EPSS metadata, visible provider status/freshness, and analyst applicability decisions.
8. **Correlation and risk:** deterministic policy version 1 scoring over explicit records, immutable input-addressed revisions, severity floors, applicable KEV prioritization, visible missing coverage, exact contributors, provenance/freshness, and weight sensitivity analysis.
9. **Analyst UI:** login, dashboard, assets, authorization, inventory, investigation history/results, comparisons, applicability review, evidence graph with a list alternative, change radar, integration status, stable list filters, deep links, resilient cancellable polling, accessible loading/error states, and risk history visualization.
10. **Incident response:** linked findings and evidence, classifications, status workflow, timeline, versioned playbooks, and analyst-recorded tasks.
11. **Reports:** immutable PDF/JSON snapshots, demo labels, source attribution, and SHA-256 checksums.
12. **Evidence graph and change radar:** typed PostgreSQL relationship projections grounded in saved evidence, direct/contextual edge labels, accessible interactive/list views, and coverage-aware investigation diffs.
13. **Submission package:** deterministic scenarios, guarded demo reset, dependency locks, architecture/data model, demo walkthrough, and recorded test results.
14. **Reproducible benchmarks and engineering docs:** a versioned five-scenario Demo workload, measured-only benchmark output, migration-upgrade CI, full role/workflow Playwright coverage, and disposable backup/restore count verification.
15. **Remediation plans and security-control mapping:** analyst-owned plans/actions linked to findings, incidents, and playbook tasks; versioned local controls; evidence-required validation; and point-in-time report support.
16. **MITRE ATT&CK mapping:** versioned local Enterprise subset, evidence-linked analyst decisions, incident technique matrix, and report trace support.
17. **Audit and evidence integrity:** transactional append-only audit hash chain, evidence checksum verification, integrity APIs and UI, report snapshots, and authorized audit export.
18. **Security posture scorecard:** read-only PostgreSQL aggregation for risk, assessment coverage, latest-observed high/critical findings, repeats, trends, incident timing, provider freshness, asset criticality, and validated control mappings, with scope/status metadata and immutable PDF/JSON exports.
19. **OSV package vulnerability analysis:** explicit npm/PyPI version lookups through the safe outbound client, evidence-linked advisory candidates, visible provider state, analyst applicability review, and same-component NVD alias deduplication. Demo uses a bundled synthetic fixture with no external requests.
20. **Versioned MITRE ATT&CK synchronization:** official Enterprise STIX 2.1 imports pinned to immutable GitHub commit references, staged and atomically activated catalog versions, Admin-only background synchronization, legacy mapping compatibility, and fully offline Demo behavior.
21. **Privacy-preserving password screening:** keyless HIBP range checks for new passwords with transient lookup hashes, Argon2 storage, fail-closed Live password updates, and offline Demo behavior.
22. **Optional XposedOrNot community lookup:** explicitly authorized single-email checks with separate coverage, shared quota enforcement, encrypted short-lived caching, evidence attribution, and synthetic offline Demo fixtures.
23. **Professional Bento UI:** responsive, accessible navigation and overview styling with reduced-motion support and no added UI dependency.
24. **Shared threat-feed snapshots:** daily Spamhaus DROP IPv4/IPv6 refreshes stored centrally in PostgreSQL and matched locally against directly submitted public IP assets; no feed request occurs during an investigation.
25. **CINS Army corroborating IP evidence:** exact IP snapshots from the fixed public CINS Army list, source-preserving comparison with Spamhaus and VirusTotal, and history that treats failed refreshes as unknown.
26. **Optional OpenPhish community phishing intelligence:** an opt-in local URL feed snapshot, exact canonical URL matches, restricted personal-use access, and synthetic offline Demo scenarios.

CINS Army uses the shared Module 24 snapshot and worker flow. Its 24-hour default is a configurable CyberLens refresh interval, not a provider publication schedule. A direct fresh match is medium severity and requires analyst applicability before risk can change. “Listed by two sources” means both address-list observations matched; it is not two VirusTotal verdicts, an independence claim, or an automatic severity increase. A later successful snapshot without an address is not proof of remediation. Demo uses reserved synthetic addresses and makes no network requests. See [CINS Army integration and limitations](docs/cins-army.md).

OpenPhish is disabled by default and uses the official [public community feed](https://github.com/openphish/public_feed) only for an operator-confirmed permitted use. Its terms limit community-feed use to personal, academic, or independent research that does not support an organization's business; business/security operations and third-party disclosure require prior written permission. The configuration acknowledgement records operator intent and does not grant rights. Without separate provider permission, the Live workspace is restricted to one configured owner while source data is retained. CyberLens stores and locally matches a bounded snapshot; it never submits asset URLs or visits listed destinations. Fresh exact matches are medium-severity review candidates, and hostname-only matches are contextual. Demo uses synthetic reserved-domain scenarios without network access. See [OpenPhish terms and operation](docs/openphish.md).

Controlled continuous monitoring adds authorization-bound daily/weekly schedules, distinct saved investigations, Change Radar history, and analyst pause/resume/cancel controls.

The scorecard is a saved-record projection; it does not run collectors or alter assessments. It labels missing, stale, partial, empty, and unavailable values instead of substituting zero. Findings have no open/closed lifecycle, so the high/critical metric is explicitly the count of latest observations and is not described as unresolved. See the [scorecard API and metric scope](docs/api.md#security-posture-scorecard) and [known limitations](docs/known-limitations.md#security-posture-scorecard).

## Module 7 collection and navigation contract

Assets, findings, investigations, incidents, reports, and audit events support `page`, `page_size`, `sort`, and `order` query parameters plus endpoint-specific filters. Responses retain their existing JSON arrays and expose `X-Total-Count`, `X-Page`, `X-Page-Size`, and `X-Has-Next` headers. Sorting is deterministic because the API adds the record ID as a tie breaker. The frontend uses generated OpenAPI operation types and hash deep links such as `#/assets/{id}`, `#/investigations/{id}`, `#/findings/{id}`, `#/incidents/{id}`, `#/remediation/{id}`, and `#/reports/{id}`.

## Project guides

- [Architecture and trust boundaries](docs/architecture.md)
- [Database relationship map](docs/data-model.md)
- [Setup and Demo/Live run modes](docs/setup.md)
- [API guide](docs/api.md)
- [Remediation workflow and control catalog](docs/remediation.md)
- [Threat model](docs/threat-model.md)
- [XposedOrNot community lookup](docs/xposedornot.md)
- [Shared Spamhaus DROP snapshots](docs/spamhaus-drop.md)
- [Frontend design system and responsive UI](docs/ui-design-system.md)
- [CyberLens brand guide and logo assets](docs/brand-guide.md)
- [Known limitations](docs/known-limitations.md)
- [Reproducible benchmark method](docs/benchmarks.md)
- [Demonstration script and viva notes](docs/demo-and-viva.md)
- [Test record and known limitations](docs/test-results.md)

## Risk score and source limitations

The score is an **academic prioritization score**, not a probability of compromise or a validated industry metric. Policy `cyberlens-academic-1.0` uses the highest applicable severity per category and weights assessed categories only. Each changed input set is stored as an immutable risk assessment revision; saved reports remain unchanged. Vulnerability candidates start as `needs_review`; only an analyst decision of `applies` contributes to vulnerability risk. An applicable KEV finding receives the existing 90-point floor even when CVSS severity is unavailable. FIRST EPSS is stored separately and does not affect the risk score; its 30-day exploitation-likelihood estimate is not proof of exploitation or compromise. Authenticated users can run a side-effect-free what-if simulation for evidence-backed remediation actions; it returns a projected score and assumptions without changing stored records. “Applies” confirms inventory relevance, not exploitation or compromise. Missing or unavailable sources reduce coverage and do not imply safety. The UI shows exact score contributors, source coverage, freshness, excluded categories, and rule version, and the sensitivity view varies one category weight at a time. No calibration claim is made because the project has no labeled incident outcome set.

Live results depend on public provider data, rate limits, service availability, and optional account tiers. HIBP account searches require an eligible API subscription. VirusTotal usage follows the selected account's access tier. NVD CVE/CPE results are candidates for analyst review. Evidence snapshots include a shared provenance envelope for source, provider/version, observation time, collection status, freshness state, and any provider source timestamp. The TLS result observes one negotiated connection and selected headers; it is not a complete protocol or cipher audit.

Spamhaus DROP is an optional narrow advisory feed, refreshed no more than once per 24 hours by default. The dispatcher downloads the two fixed official IPv4/IPv6 JSON feeds through the bounded safe HTTP client and activates a PostgreSQL snapshot only after both validate. Investigations compare an explicitly submitted public IP with that saved snapshot, pinning its ID and checksum in collector history. A match is medium severity and needs analyst applicability review; a no-match means only that the address was absent from that snapshot. Demo mode uses a synthetic local fixture and never contacts Spamhaus. Configure `SPAMHAUS_DROP_ENABLED`, `SPAMHAUS_DROP_REFRESH_INTERVAL_HOURS` (minimum 24), `SPAMHAUS_DROP_FRESHNESS_HOURS`, and `SPAMHAUS_DROP_MAX_DOWNLOAD_BYTES`; see [Spamhaus DROP details](docs/spamhaus-drop.md). Preserve Spamhaus copyright/date attribution and follow its [official DROP documentation](https://www.spamhaus.org/blocklists/do-not-route-or-peer/) and [Fair Use Policy](https://www.spamhaus.org/blocklists/drop-fair-use-policy/).
