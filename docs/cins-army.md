# CINS Army IP intelligence

## Source and permitted use

CyberLens reads the fixed public [CINS Army text feed](https://cinsscore.com/list/ci-badguys.txt). The [CINS site](https://cinsscore.com/) describes the Army list as a subset of CINS Active Threat Intelligence and provides it as a simple text file for parsing and use. The feed reviewed on 2026-10-20 contains individual IP address lines; it does not provide a record ID, score, attack category, report count, first-seen date, or per-indicator observation time. CyberLens records when it retrieved and observed a saved snapshot. It does not treat that time as a provider publication time.

The configured 24-hour refresh interval is a conservative CyberLens default. It is not a statement about how often CINS publishes updates. Configure `CINS_ARMY_ENABLED`, `CINS_ARMY_REFRESH_INTERVAL_HOURS` (24–720; minimum 24), `CINS_ARMY_FRESHNESS_HOURS` (1–720), and `CINS_ARMY_MAX_DOWNLOAD_BYTES` (1 KiB–10 MB). The defaults are enabled, 24 hours, 48 hours, and 2 MB. The snapshot loader applies the configured freshness limit; stale snapshots remain visible but cannot establish a current clean or listed result.

## Snapshot lifecycle

CINS shares Module 24's PostgreSQL snapshot tables, refresh attempt state machine, dispatcher, RQ queue, safe outbound client, per-source cooldown, stale delivery reconciliation, checksum validation, retention, and atomic active-snapshot pointer. It is a separate source identity and gets an independent cooldown. The worker downloads only the fixed HTTPS feed, validates the full bounded response, parses comments and blank lines, rejects malformed entries, canonicalizes IPv4/IPv6, and deduplicates exact addresses. It never expands an address into a CIDR or network range. A failed, malformed, oversized, timed-out, or unsafe response leaves the prior active snapshot and its records intact.

The authenticated Admin integration panel can queue an explicit refresh. Demo mode reads only the committed synthetic RFC 5737 documentation-address fixture and never requests the feed. The snapshot SHA-256 detects changes to the stored canonical address list; it is an integrity check, not independent proof of provider authenticity or forensic authenticity.

## Investigation behavior

The `cins_army` collector reads the pinned PostgreSQL snapshot and performs exact local IP matching. It does not contact the investigated IP or CINS during an investigation. Direct fresh matches create medium-severity `needs_review` candidates. The existing risk policy counts only analyst-confirmed applicable findings. A listing is not evidence that an asset is compromised or that an attack occurred. Missing, stale, or checksum-invalid snapshots produce unknown/unavailable coverage; a fresh no-match means only “Not listed in this snapshot.”

CINS evidence is grouped in the IP intelligence view with separate Spamhaus and VirusTotal records, source IDs, evidence IDs, snapshot IDs, observation times, and freshness. “Listed by two sources” is displayed only when both saved address-list observations are fresh (or synthetic Demo observations) and positive. VirusTotal remains separate and is not counted as a second list. The list overlap is not treated as independent measurements and does not automatically raise severity.

History distinguishes baseline, newly observed, continuing, and no longer observed list states. A removal is shown only when the later observation uses a different, successfully validated snapshot. A failed or stale refresh contributes unknown coverage and does not advance the comparison. Absence from a new snapshot is not proof of remediation. Each source keeps its own evidence, so grouping does not merge provider records. New report snapshots include both source evidence references and the history summary; already saved reports are unchanged.

## API

- `GET /api/v1/integrations/cins-army/status` returns configuration, active snapshot/checksum/parser/count, retrieval and revalidation times, age/freshness, attribution, and latest refresh status.
- `POST /api/v1/integrations/cins-army/refresh` is Admin-only, session/CSRF protected, and queues work through the shared feed dispatcher. Demo mode and a cooldown return a clear error.
- `GET /api/v1/investigations/{id}` includes `ip_intelligence` for IP assets, with independent provider evidence and the saved listing history.
- New JSON/PDF reports include `ip_intelligence` plus the pinned feed snapshot and evidence ID for each collector run.

Automated tests use synthetic IPs and mocked feed responses. No production indicator is committed as a fixture. Live endpoint compatibility remains dependent on the upstream text format and local network availability.
