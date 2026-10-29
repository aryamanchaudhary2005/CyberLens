# OpenPhish Community Feed

CyberLens supports an optional local snapshot of the [OpenPhish Community Feed](https://github.com/openphish/public_feed). The source is disabled by default. CyberLens's configured default refresh interval is 12 hours; this is a local schedule and does not guarantee when a new provider release is published.

## Provider terms and permitted use

The repository currently describes the community feed as non-commercial and updated every 12 hours. The [current terms](https://www.openphish.com/terms.html) limit use to personal, academic, or independent research that does not support an organization's business operations. The terms prohibit organizational commercial use—including security operations and product functions—without prior written consent. They also prohibit third-party disclosure or distribution absent express permission.

Read the current terms before enabling the provider. An environment-variable acknowledgement records operator intent only; it does not grant a license, permission, or disclosure right.

CyberLens has two explicit access settings:

- **Personal-only:** Set OPENPHISH_ENABLED=true, OPENPHISH_USE_ACK=true, and OPENPHISH_PERSONAL_OWNER_USERNAME to one active workspace account. Access to the Live workspace, including saved investigation data and reports, is restricted to that owner while OpenPhish data is retained. Turning the feature off does not remove snapshots or immediately lift this access restriction.
- **Separately authorized shared use:** Set OPENPHISH_PROVIDER_SHARING_PERMISSION_ACK=true only when prior written provider permission covers the intended shared or organizational use and disclosure. Keep OPENPHISH_ENABLED=true and OPENPHISH_USE_ACK=true. The setting is an operator attestation, not evidence of the provider grant.

When no separate provider permission has been recorded, the application fails closed to personal-owner access. If the configured owner is missing or inactive, sign-in and data access fail closed until an operator corrects the configuration.

## Configuration

Add these values to .env for a permitted Live use. Never commit .env.

    OPENPHISH_ENABLED=true
    OPENPHISH_USE_ACK=true
    OPENPHISH_PERSONAL_OWNER_USERNAME=admin
    OPENPHISH_PROVIDER_SHARING_PERMISSION_ACK=false
    OPENPHISH_REFRESH_INTERVAL_HOURS=12
    OPENPHISH_FRESHNESS_HOURS=24
    OPENPHISH_MAX_DOWNLOAD_BYTES=2000000

Demo mode ignores Live synchronization settings and uses one synthetic .example.test fixture without network access. It never downloads the provider feed.

## Collection and exact URL matching

The worker downloads only the fixed official feed.txt source over the existing bounded DNS-pinned HTTPS client. Redirects are disabled; TLS verification, response-size limits, timeout, conditional validators, refresh coordination, immutable checksummed snapshots, and atomic activation reuse Module 24's threat-feed infrastructure. A failed, oversized, malformed, or incomplete response leaves the last validated snapshot active.

Each valid feed line is parsed as one HTTP(S) URL, canonicalized, and deduplicated. Only the URL scheme and hostname are case-insensitive. Path, query, fragment, path case, query case, and encoded reserved characters are preserved. Credential-bearing URLs are rejected. The collector performs exact local matching against the pinned PostgreSQL snapshot and never contacts an investigated URL or follows a listed destination.

A fresh exact URL match is a medium-severity needs_review reputation candidate. Only analyst-confirmed applies findings contribute to the existing risk score. Hostname-only association is contextual evidence and creates no risk finding. A no-match means only “No exact URL match in this snapshot.” Stale snapshots and failed refreshes produce unknown coverage; they do not create removals or imply safety. The feed does not provide per-indicator confidence, brand, discovery time, or observation time.

Newly registered URLs retain complete canonical components. Migration marks existing URL assets as incomplete because older versions removed query strings and fragments. An Analyst or Admin must review and confirm the full saved URL before an old asset can qualify for a direct match. If the exact URL differs, register it as a separate asset; previous reports remain snapshots and are not rewritten.

## Privacy and reporting

Personal-only mode blocks other users from reading workspace APIs, evidence, reports, integrations, and exports while retained feed data is present. New reports that include an OpenPhish run identify the source and include the current-use restrictions. Do not share or distribute such reports unless provider terms and any written permission allow it.

Audit events record only that a URL was added/confirmed or a source refresh was requested. Refresh errors, logs, integration status, and provider metrics do not include feed indicator lines. Investigation reports contain the submitted asset identifier, as they do for all assets, but do not copy feed records into result evidence.

## Known limits

- The feed is not a complete phishing dataset or a verdict that an asset is compromised.
- Provider terms and service behavior can change; recheck the current official sources before use.
- The checksum detects later snapshot modification but does not independently prove source authenticity.
- Old saved reports remain unchanged and may reflect earlier URL normalization behavior.
- Live provider collection was not used for automated tests; tests use synthetic reserved-domain URLs.

Official sources: [repository and feed README](https://github.com/openphish/public_feed), [feed file](https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt), and [Terms of Use](https://www.openphish.com/terms.html).
