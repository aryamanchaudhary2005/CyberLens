# Threat model and trust boundaries

## Scope

CyberLens is a local, single-workspace academic analysis and incident-response application. The threat model describes current code boundaries; it is not a security certification, independent penetration test, or public-production readiness claim.

## Data and components

- PostgreSQL stores users, hashed sessions, assets, authorization records, investigations, attempts/outbox entries, collector evidence, findings, risk revisions, incidents, audit events, and immutable report snapshots.
- Redis is a shared login-rate-limit store and RQ queue/worker heartbeat store. Investigation delivery intent remains in PostgreSQL.
- The browser holds an HTTP-only session cookie and a readable CSRF cookie. State-changing API calls require the matching CSRF header.
- Provider credentials are backend-only configuration. Collector response bodies and provider text are untrusted evidence; they do not execute commands or control response actions.
- The normal Compose project runs Live mode; the explicitly selected Demo overlay has separate named volumes, bundled synthetic fixtures, and no external provider requests. The optional evidence-grounded AI briefing remains disabled.

## Main protections in the current implementation

- Passwords are hashed with Argon2. Sessions are stored as token digests, expire, can be revoked, and rotate after a password change. Administrator resets revoke a user's sessions.
- New passwords are screened only after submission through the fixed HTTPS HIBP Pwned Passwords range endpoint. A transient SHA-1 digest is used only to derive the range request prefix; Argon2 remains the storage hash. The request contains only the first five hexadecimal characters and `Add-Padding: true`; returned suffixes and zero-count padding are compared/discarded in memory. Passwords, complete lookup hashes, prefixes, suffixes, URLs containing prefixes, and provider bodies are excluded from application logs, audit metadata, evidence, reports, and analytics. Password-screen audit entries on accepted operations contain only outcome and safe reason. No screening endpoint is exposed to unauthenticated callers.
- Live password-setting operations fail closed on provider timeout, quota, malformed data, or unavailability and do not change account/session state. Existing-password login remains independent of the provider. Demo uses a deterministic local result and makes no request.
- Redis-backed login throttling is shared across API processes. Admin-only account/role management has last-active-admin safeguards and audit events. Viewers are read-only for protected workspace records.
- Write routes enforce session and CSRF checks. Live website inspection requires an unexpired, unrevoked authorization record.
- Public HTTP targets resolve to checked addresses before connection; private, loopback, reserved, link-local, and metadata addresses are blocked. DNS answers are pinned for the request, redirects are revalidated, and response/deadline limits apply. Credentialed provider requests are restricted to their intended HTTPS origin.
- PostgreSQL is the source of truth for investigation attempts and the transactional outbox. Stable RQ job IDs and database claim/lease checks constrain duplicate delivery/execution. Collector results, findings, and graph relationships retain evidence references.
- Structured logs redact configured sensitive data and include request IDs. Services bind to loopback by default and use non-root container users where practical.
- Backup restore validation targets a new disposable database and does not remove named volumes.
- XposedOrNot is disabled by default and is not a HIBP fallback. Live email lookups require an Analyst/Admin confirmation and an expiring, revocable authorization tied to one email asset and the XposedOrNot provider; the worker checks it again before collection. The email appears in the intended HTTPS provider request path, but is omitted from general logs, metrics labels, audit metadata, and provider-response evidence. Only allowlisted breach metadata is persisted; any raw provider body is discarded. The optional cache uses a keyed email digest and Fernet encryption. One Redis-backed rolling limiter is shared across app processes and workers and stops on the 2/second, 25/hour, or 100/day caps; Redis failure fails closed. Separate deployments do not share quota state.

## Residual risks and limitations

- Compose is for one local workspace, not public deployment. The default project runs Live behind a loopback-only Caddy gateway with a local internal certificate; Demo is a separate overlay/project. This local gateway certificate is not a publicly trusted service certificate. External secret management, network segmentation, host hardening, external monitoring, high availability, and operational alerting are not supplied as a public deployment package.
- This is one workspace, not a tenant-isolated service. PostgreSQL and Redis availability, backups, storage encryption, access to the host, retention, and recovery-point objectives depend on the operator.
- Live collectors depend on DNS, external provider data, network policy, optional API entitlements, quotas, and third-party availability. A successful response is a time-bounded observation, not proof of safety or compromise.
- Live password creation/change/reset/bootstrap depends on HIBP availability. A confirmed match means the password appears in the Pwned Passwords dataset; it does not establish that the CyberLens account was compromised. The lookup protocol uses SHA-1 transiently as required by HIBP and does not replace Argon2 storage.
- XposedOrNot's dataset is separate from HIBP and may have different coverage. A no-match says only that this provider returned no record; it does not establish safety or current account status. Basic endpoint data may not provide per-record verification, in which case records stay unverified/unknown for risk purposes. Community access is documented for personal, low-volume use; operators must not enable it where their use is outside those terms. A `429` stops further retries until the quota window resets.
- Findings and CVE matches require analyst review. Missing, stale, failed, unavailable, or unrun sources are coverage gaps. They must not be interpreted as safe.
- Evidence/report hashes help detect byte changes, but do not by themselves establish a forensic chain of custody or independent provenance.
- The risk score is a deterministic academic prioritization policy, not calibrated probability. There is no labeled incident outcome set.
- AI briefing is disabled because there is no managed, reviewed local model runtime with a supported isolation/resource boundary. No external AI endpoint is configured.
- Security scanning and automated tests are not substitutes for independent review. Current test and validation limits are recorded in [known limitations](known-limitations.md).

## Threat-modeling workspace records

Asset criticality, classification, trust zone, exposure, owner, and protection requirements are business-context inputs maintained by analysts. STRIDE scenarios store analyst-entered likelihood, business impact, confidence, assumptions, and unconfirmed information. The 1–25 likelihood-times-impact value is a business-impact scenario priority only; it does not change technical severity, vulnerability applicability, or version 1 risk scoring. Unknowns remain visible, and a scenario with unresolved unconfirmed information cannot be marked confirmed. Scenario links are constrained to the same asset and newly generated reports snapshot the current workspace scenarios.
