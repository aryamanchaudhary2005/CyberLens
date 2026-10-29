# Shared Spamhaus DROP snapshots

CyberLens uses Spamhaus DROP only as a narrow shared advisory feed. The integration is separate from per-asset collectors: a scheduled dispatcher or an Admin's explicit refresh request downloads the IPv4 and IPv6 files once for the workspace, stores a validated snapshot in PostgreSQL, and later investigations match directly submitted public IP addresses against that local snapshot.

## Provider scope and attribution

The implementation uses only the fixed official IPv4 and IPv6 JSON endpoints documented on the [Spamhaus DROP page](https://www.spamhaus.org/blocklists/do-not-route-or-peer/). It does not accept a configurable URL, follow redirects, fetch any URLs found in feed content, or perform reverse DNS / website requests for an IP. It reads CIDR ranges as networks and never expands a range into individual addresses.

The provider documentation describes these lists as advisory data, not complete reputation coverage. CyberLens carries forward each feed's publication timestamp and copyright line with source attribution in integration status, evidence, and newly generated reports. Follow the provider's [Fair Use Policy](https://www.spamhaus.org/blocklists/drop-fair-use-policy/); automated refresh is limited locally to at least 24 hours between requests, and the default interval is 24 hours. Check the current provider terms before operating a Live deployment.

## Configuration

The checked-in defaults are:

```dotenv
SPAMHAUS_DROP_ENABLED=true
SPAMHAUS_DROP_REFRESH_INTERVAL_HOURS=24
SPAMHAUS_DROP_FRESHNESS_HOURS=48
SPAMHAUS_DROP_MAX_DOWNLOAD_BYTES=1000000
```

The interval is validated to be between 24 and 720 hours. Freshness must be 1–720 hours; the response-size cap must be 1 KB–10 MB. Demo mode always uses the bundled synthetic fixture regardless of these Live settings and never makes an outbound request. Set `SPAMHAUS_DROP_ENABLED=false` to disable Live refresh and collection.

## Refresh lifecycle

`threat_feed_sources` stores the source identity, two fixed URLs, conditional request validators, refresh interval state, active snapshot pointer, and the separate last-successful-revalidation time. `threat_feed_refresh_attempts` stores the scheduled or Admin request and its lifecycle. Refresh attempts are delivered through the existing dispatcher and RQ worker with stable job IDs. Database uniqueness and source locking make a pending refresh idempotent across API processes.

The worker calls the existing DNS-pinned safe HTTP client with TLS verification, redirects disabled, one shared deadline, response-size bounds, and `If-None-Match` / `If-Modified-Since` when available. It validates both complete feeds and their JSONL metadata before writing the canonical rows and changing the active snapshot pointer in a transaction. `304 Not Modified` reuses the prior parsed feed and advances only the source's revalidation time. If a request or validation fails, the attempt records a safe error code and the old active snapshot remains available; the cooldown is not bypassed by clicking refresh again.

An Admin can queue a refresh from **Integrations → Spamhaus DROP snapshot** outside Demo mode. Other authenticated roles can view status but cannot queue it. The endpoint uses the normal session and CSRF checks. The UI displays current snapshot ID/hash, count, parser version, retrieval and provider dates, age/freshness, last attempt, next permitted refresh, and provider attribution. It never displays raw provider response bodies.

## Investigation and risk behavior

For an IP asset, the `spamhaus_drop` collector reads only the active PostgreSQL snapshot. It verifies the canonical content checksum, freshness, and direct public-IP scope. The CollectorRun records `feed_snapshot_id`; the EvidenceSnapshot records the exact lookup result, observation time, matched CIDR/SBL IDs if present, provider date, attribution, freshness, and hash. New reports copy this evidence and the pin into their point-in-time snapshot.

A current match produces a medium-severity finding candidate with `needs_review`. It represents a direct CIDR match only; it does not prove compromise, activity, ownership, or that a submitted address was assigned to a particular service at the time of observation. Only an analyst applicability decision of `applies` allows the finding to contribute to the existing reputation category under risk-policy v1. Failed, missing, stale, or checksum-invalid snapshots report unknown/unavailable coverage. A no-match says “Not listed in this snapshot.” It does not mean safe or uncompromised.

Demo mode uses synthetic reserved ranges from `backend/app/data/spamhaus_drop_demo.json`, labels its evidence as synthetic, and makes zero provider requests. Saved investigation evidence, findings, risk revisions, and reports are not rewritten when a later shared snapshot is activated.

## Integrity and limits

Snapshots store SHA-256 over CyberLens's canonical normalized representation of provider metadata and CIDR/SBL records. This supports detecting later changes to saved snapshot content. It is not an independent verification of the source, a digital signature, proof of provider authenticity, or a forensic chain-of-custody statement.

The parser expects the documented JSON-lines form with network rows and one final metadata row containing the provider timestamp and copyright. A provider format change causes the refresh to fail closed and leaves the prior active snapshot in place. DROP is only a narrow advisory source; it is not a general IP reputation service, an allowlist, a block action, or a substitute for other evidence. Live endpoint behavior, quota responses, and a PostgreSQL service deployment were not locally verified for this module; automated tests mock provider requests.

## API

- `GET /api/v1/integrations/spamhaus-drop/status` — authenticated status.
- `POST /api/v1/integrations/spamhaus-drop/refresh` — Admin-only, CSRF-protected refresh queue request. Demo returns `409`; early requests after a completed attempt return `429` with the next allowed time.
- `GET /api/v1/investigations/{id}` — includes `feed_snapshot_id` in collector-run records and provider evidence in the saved evidence list.
- `GET /api/v1/reports/{id}` — serves the unchanged report snapshot created at report time; new reports include the Spamhaus snapshot evidence section.
