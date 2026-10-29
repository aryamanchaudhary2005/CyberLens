# Reproducible benchmark method

## Dataset

`benchmarks/datasets/demo_scenarios.json` is a versioned manifest of the five synthetic scenarios already supported by `app.cli seed-demo` and the offline collector fixtures:

| Scenario | Existing seeded record | Fixture behavior |
| --- | --- | --- |
| Routine website | `shop.example.test` | Synthetic DNS/website context and routine findings. |
| Suspicious website | `signin-example.test` | Synthetic unfamiliar redirect and adverse reputation findings. |
| Breached email | `student@example.test` | Synthetic historical email exposure; not a current-compromise claim. |
| Vulnerable application | `Demo customer portal` | Synthetic CVE candidates, including needs-review applicability. |
| Provider outage | `outage.example.test` | Website fixture plus unavailable reputation, HIBP, and NVD collectors; no substitute findings for unavailable providers. |

The manifest is deterministic and has a SHA-256 hash in each run output. Application record IDs, observations, and reports retain normal generated IDs and observation timestamps, so a repeated run uses the same fixture inputs but produces different database records and timings.

## Run conditions and safety

With the local Demo stack running, set credentials in the current PowerShell session without putting them on a command line:

```powershell
$env:CYBERLENS_BENCHMARK_USERNAME = 'admin'
$env:CYBERLENS_BENCHMARK_PASSWORD = '<your changed Demo password>'
./scripts/run-benchmark.ps1 -Requests 100 -Concurrency 5 -TimeoutSeconds 180 -OutputPath .\benchmark-results\run-01.json
```

The PowerShell wrapper first reads and verifies `APP_MODE=demo`, then calls the existing additive `seed-demo` command. The Python harness independently checks for Demo mode, worker readiness, and a loopback IP origin before sending login credentials. It does not make provider requests, reset data, or delete records. It appends five investigations and five JSON report snapshots per successful run. Choose a workspace whose database can retain these records. An existing output file is never overwritten.

The benchmark harness requires the backend's already-locked `httpx` dependency. Run it from a backend virtual environment or install the locked backend requirements. The `--requests`, `--concurrency`, timeout, poll interval, API origin, fixture hash, test date, Git revision (when present), CPU/OS/platform, and system memory are recorded.

The benchmark accepts HTTP or HTTPS only when the API origin uses a loopback IP literal or the exact `localhost` name whose resolved addresses are all loopback. For HTTPS it disables certificate validation only for that local origin, to support the self-signed local Caddy certificate; other hosts and hostnames are rejected before credentials are sent. Use the verification overlay's HTTPS gateway when secure cookies are enabled.

## Reported measures and definitions

- **API latency:** elapsed milliseconds for authenticated `GET /api/v1/assets?page=1&page_size=25&sort=identifier&order=asc`, using parallel samples up to the configured concurrency. p50, p95, and p99 use the nearest-rank method (`ceil(p*n)`, minimum rank 1). Each sample uses a new local HTTP connection, and response bodies are read before timing stops.
- **Queue wait:** `attempt.started_at - attempt.created_at`, in milliseconds, across persisted attempts.
- **Investigation duration:** `attempt.finished_at - attempt.started_at`, in milliseconds, across persisted attempts.
- **Retry rate:** benchmark investigations with more than one persisted attempt divided by benchmark investigations.
- **Investigation failure rate:** terminal `failed` investigations divided by benchmark investigations.
- **Collector status and unavailable rate:** counts by persisted collector status; unavailable runs divided by all collector runs. Provider outage is expected to show unavailability, not failed Demo findings.
- **Duplicate rate:** repeated category/severity/title/source signatures inside an investigation divided by all finding occurrences. This is an observable signature check, not a direct database-constraint audit; the output labels it accordingly.
- **Resource use:** benchmark client CPU time and peak process working set/RSS before and after, system memory, plus Docker `stats --no-stream` snapshots for containers listed by this Compose project when its CLI/engine is available. If Docker stats fail, output marks that measurement unavailable and gives only the exception class.
- **Report generation:** elapsed time for each `POST /api/v1/reports` creating a JSON snapshot from a completed scenario.
- **Runtime operations snapshot:** existing authenticated `/api/v1/metrics` output after the workload, including queue depth, average attempt duration, worker heartbeat, request summary, and provider status counters.

No result file is committed as a universal performance claim. Measurements are specific to the recorded hardware, operating system, Compose configuration, dataset size, and concurrency. Repeated runs against an already-used workspace append more records and may change query latency.

## Measured results and proposed targets

The JSON output contains measured observations only and sets `targets_included` to `false`. This repository does not currently define ratified numeric service-level or performance targets. Proposed targets should be agreed separately after the hardware, dataset scale, concurrency, and acceptable failure semantics are chosen. Never present a proposal as a measured result.

See [verification results](test-results.md) for commands actually run in the current environment, including explicit unavailable checks.

## CINS exact-IP index microbenchmark

Run from the repository root; this is a local synthetic microbenchmark and requires only the existing Python runtime:

```powershell
backend/.venv/Scripts/python.exe benchmarks/benchmark_cins_lookup.py --dataset-size 15000 --lookups 100000 --workers 1 --seed 2501
```

The script generates canonical addresses in the reserved RFC 2544 benchmark range `198.18.0.0/15`; no production feed data is read or committed. Queries use a deterministic 50% hit/miss distribution and exercise IP string parsing plus exact `frozenset` membership. It does not measure the public-address eligibility gate, HTTP download, database snapshot loading, investigation worker, or API. It records the test date, Python/OS/CPU environment, dataset size, seed, concurrency, throughput, index build time, and traced index memory. This measures the local exact-address index path only; it is not an end-to-end collector or service benchmark.

## Module 31 measured run

The 2026-10-22 full synthetic Demo run is saved as [`module31-2026-10-22-01.json`](../benchmarks/results/module31-2026-10-22-01.json). It records the five scenario names and fixture SHA-256, 13 existing workspace assets, five benchmark investigations, 10 findings, concurrency 5, 100 paginated `GET /api/v1/assets` requests, exact local HTTPS origin, hardware, queue/job/report percentiles, retry/failure/duplicate rates, provider statuses, and Docker memory/CPU snapshots. There are no proposed targets in the result.

The API timing measures a new local client connection for every sample through the Caddy TLS gateway. Thus the measured p50/p95/p99 (2,137.201/2,223.156/2,246.526 ms) includes local connection and TLS setup; it is not an estimate of backend-only request time or public-provider delay. The five investigation fixtures used offline Demo collectors, so their 173.851 ms p50 duration is application/queue processing without a Live provider request. JSON report generation was 2,123.516 ms p50. Interpret these numbers only for the recorded local Windows/Docker Desktop environment and dataset.

`benchmark_local_connection.py` measures this connection effect using only `GET /api/v1/health/live` on validated loopback origins:

```powershell
backend/.venv/Scripts/python.exe benchmarks/benchmark_local_connection.py --samples 20 --output benchmarks/results/module31-local-connection-diagnostic.json
```

On the same machine, 20 fresh `httpx` clients to `https://localhost:18443` measured p50/p95/p99 **2,060.040/2,078.340/2,084.461 ms**. One client reused for 20 sequential requests measured **4.711/6.240/2,055.012 ms**; one sample was 2,055 ms. Direct HTTP to `127.0.0.1:18000` measured **9.359/25.959/26.783 ms** with new clients and **5.049/24.061/28.229 ms** with reuse. A separate five-request curl timing split showed hostname-pinned TLS with `--resolve localhost:18443:127.0.0.1` completed in **21–50 ms**, while ordinary localhost resolution completed in **231–248 ms**. These measurements identify cold Windows client/address selection and gateway connection overhead as the likely source of the two-second `httpx` cold timing; the precise OS-level cause was not isolated. The raw-IP TLS attempt failed because Caddy uses the `localhost` SNI/host. The detailed 20-sample result includes environment and is saved as [module31-local-connection-diagnostic.json](../benchmarks/results/module31-local-connection-diagnostic.json).

The actual run from 2026-10-20 is recorded in [test-results](test-results.md). It used 15,000 synthetic entries, 100,000 lookups, one worker, and seed 2501. It measured 192,562.58 canonicalized membership lookups/second, a 0.174048-second index build, and 1,326,351 bytes peak traced allocation. These are observations from the listed Windows/Python environment, not proposed targets or a claim of improvement. Hardware details not reported by the runtime are marked unavailable in the JSON output.

## Other repeatable engineering checks

- `frontend` CI runs Playwright against a clean Demo stack. It tests first administrator login, account creation, analyst asset/investigation/case/timeline/playbook/report flow, comparison and deep links, and Viewer read-only behavior; separate checks cover keyboard/focus and labels.
- The backend migration suite upgrades legacy SQLite database shapes to `head`, verifies saved records/relationships/revisions, and checks schema drift. CI also migrates a fresh PostgreSQL service database and runs `alembic check`.
- `scripts/backup-postgres.ps1` makes a custom-format backup. `scripts/test-restore.ps1` restores into a unique disposable database and compares core table row counts. It never deletes or recreates named Compose volumes.
