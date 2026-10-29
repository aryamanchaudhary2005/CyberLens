# XposedOrNot community email lookup

## Provider scope and permitted use

CyberLens supports XposedOrNot as an explicit, optional email-breach provider. It remains separate from Have I Been Pwned (HIBP): selecting XposedOrNot never silently switches or falls back from HIBP, and its dataset does not have identical coverage. A negative lookup is reported exactly as **“No record found in this provider's dataset.”** It does not mean the address or account is safe or currently uncompromised.

The [official XposedOrNot API quick reference](https://xon-web-test.xposedornot.com/api_doc) was reviewed on 2026-10-19; that page says it was last updated 03-Jun-2026. It documents the keyless basic endpoint `GET https://api.xposedornot.com/v1/check-email/{email}`, an optional `details` boolean, the success payload (`breaches`, `email`, `status`) and the no-match payload (`{"Error":"Not found","email":null}`). Its free limits for this endpoint are **2 requests per second, 25 per hour, and 100 per day per IP address**. The provider describes community access as personal and low-volume use and directs users building a product on breach data or needing more throughput to its paid offering. Operators are responsible for confirming their deployment's use is permitted before enabling this feature. CyberLens does not rotate IPs/accounts or retry through exhausted quota.

The basic response example contains breach names and a `Verified` marker but does not establish a verification value per record. CyberLens preserves such provider markers as unscoped verification metadata and does not mark those individual records verified. Explicit `verified` values, if returned by the documented optional details response, remain attached to their record. Only a record whose provider verification is explicitly true can produce the historical-exposure finding; records with missing/false verification remain evidence only. The implementation makes a single request to the basic endpoint with `details=true`; it does not call breach analytics, domain endpoints, or any paid endpoint. The docs describe the `details` parameter but do not specify its complete `check-email` response schema, so unsupported shapes are reported as malformed instead of guessed.

## Authorization, privacy, and retention

Only authenticated Analysts and Admins can queue an investigation. The provider must be explicitly selected, and the user must confirm that the selected registered email may be sent to XposedOrNot for this lookup. CyberLens stores a provider-scoped authorization record linked to the email asset and actor; it expires after 30 days, can be revoked from the asset view, and is rechecked by the worker immediately before collection. The confirmation is not proof of ownership; the analyst is responsible for recording appropriate authorization.

The provider request intentionally transmits the selected email in the encoded HTTPS path. CyberLens does not put the email into application request logs, general audit metadata, metric labels, or persisted provider evidence. The provider response is parsed into an allowlist: provider record ID, name, breach date, exposed-data categories, explicit verification value, provider source, and observation time. Email echoes, raw response bodies, descriptions, logos, password details, and unused provider risk metrics are discarded. No leaked passwords or breach dumps are requested or stored. Error handling does not expose request URLs, response bodies, or exception text.

The optional Redis cache stores normalized result data encrypted with Fernet. Its key uses an HMAC digest of the email and never contains the address. Cache lifetime defaults to 15 minutes, and the operator setting is clamped between 60 and 3600 seconds. `XPOSEDORNOT_CACHE_KEY` is a dedicated secret used for the cache encryption and keyed digest; it is not sent to the provider. Redis must be available for both the shared rate limiter and the cache; the collector fails closed if it cannot enforce the limits.

The Redis quota is a single shared rolling-window counter across API and worker processes in one deployment, with time obtained from Redis itself. It caps requests at the provider's published 2/25/100 values, and a provider `429` stops retries until the provider window resets. Independently operated deployments do not share this Redis counter and can still exceed a shared egress IP's provider cap; coordinate the total use for that egress IP.

The provider result is one time-bounded observation, not evidence that an account is currently compromised. HIBP and XposedOrNot findings retain separate source evidence. Risk policy version 1 already takes the highest applicable finding per category, so adding a second verified breach source does not add a second breach-category score. Provider risk scores are not imported into CyberLens scoring.

## Configuration and Demo mode

The default settings in `.env.example` keep XposedOrNot disabled:

```dotenv
XPOSEDORNOT_ENABLED=false
XPOSEDORNOT_COMMUNITY_USE_ACK=false
XPOSEDORNOT_CACHE_KEY=
XPOSEDORNOT_CACHE_TTL_SECONDS=900
```

Only after confirming permitted use, set `XPOSEDORNOT_ENABLED=true`, `XPOSEDORNOT_COMMUNITY_USE_ACK=true`, and a unique Fernet key. Generate a key locally with:

```powershell
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Keep this cache key private and out of source control. No XposedOrNot API key is used for the basic email endpoint. Provider status exposes whether the integration is enabled/configured but does not reveal the cache key.

Demo mode uses bundled synthetic fixtures and makes no external request, regardless of the Live provider settings. It does not create real-provider authorization or send a registered email outside the application. Automated tests use synthetic addresses and mocked calls only.

## Data model and validation boundary

Forward-only migration `20261019_0016` adds `email_breach_authorizations` and nullable `investigations.email_breach_provider` / `email_breach_authorization_id` fields. Existing investigations, findings, evidence, risk assessment revisions, and saved report bytes/snapshots are not rewritten. New reports include the selected provider, collector status, evidence reference, and no-match/coverage note where applicable.

Local tests cover the official basic match/no-match response forms, optional details records, absent/false verification, malformed responses, sensitive-field removal, timeouts, quota outcomes and concurrency, shared-cache encryption, provider-selection authorization, revocation/expiry, Demo no-network behavior, and HIBP/XposedOrNot duplicate category scoring. Provider calls are mocked; this project does not query real email addresses in its tests.

## Live verification limitations

The official docs and limits were reviewed, but no real provider request, real email address lookup, provider account/terms approval, current external quota behavior, or upstream response variation has been live-verified. Operators should validate that their use is permitted and keep provider behavior under review. A successful response from this dataset is not proof of account compromise; missing, malformed, unavailable, or quota-limited data remains unknown coverage.
