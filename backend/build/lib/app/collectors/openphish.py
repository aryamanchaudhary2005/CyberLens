"""Local exact-URL matching against an authorized OpenPhish snapshot."""

from __future__ import annotations

import hashlib

from app.collectors.common import finding, now_iso
from app.collectors.types import CollectorResult
from app.services.threat_feeds import OPENPHISH_ATTRIBUTION
from app.url_normalization import canonicalize_http_url

SOURCE = "OpenPhish Community Feed"


def collect_openphish(asset, snapshot: dict | None) -> CollectorResult:
    """Match only local snapshot content; this function never contacts a URL asset."""
    if asset.kind != "url":
        return CollectorResult(status="not_applicable", source=SOURCE, evidence={
            "provider": SOURCE, "provider_status": "not_applicable", "result": "unknown",
            "observed_at": now_iso(), "match_scope": "url_only",
        }, error_explanation="OpenPhish checks only explicitly submitted URL assets.")
    if snapshot is None:
        return CollectorResult(status="unavailable", source=SOURCE, evidence={
            "provider": SOURCE, "source_id": "openphish", "provider_status": "missing_snapshot",
            "result": "unknown", "observed_at": now_iso(), "freshness": "unknown",
            "coverage_note": "No validated local snapshot is available. No clean result was inferred.",
        }, error_explanation="No validated OpenPhish snapshot is available.")
    if snapshot.get("integrity_valid") is not True:
        return CollectorResult(status="unavailable", source=SOURCE, evidence={
            "provider": SOURCE, "source_id": "openphish", "provider_status": "snapshot_integrity_failed",
            "result": "unknown", "observed_at": now_iso(), "snapshot_id": snapshot.get("snapshot_id"),
            "freshness": "unknown",
        }, error_explanation="The stored OpenPhish snapshot did not pass its checksum check.")

    try:
        canonical_url, hostname = canonicalize_http_url(asset.identifier)
    except ValueError:
        return CollectorResult(status="not_applicable", source=SOURCE, evidence={
            "provider": SOURCE, "source_id": "openphish", "provider_status": "invalid_asset_url",
            "result": "unknown", "observed_at": now_iso(), "freshness": "unknown",
        }, error_explanation="The saved URL could not be safely canonicalized for an exact lookup.")

    records = snapshot.get("urls") if isinstance(snapshot.get("urls"), (list, tuple)) else []
    digest = hashlib.sha256(canonical_url.encode("utf-8")).hexdigest()
    exact_record = next((record for record in records
                         if isinstance(record, dict)
                         and record.get("canonical_sha256") == digest
                         and record.get("canonical_url") == canonical_url), None)
    hostname_match = any(isinstance(record, dict) and record.get("hostname") == hostname for record in records)
    retention_complete = bool(getattr(asset, "url_retention_complete", False))
    direct_match = exact_record is not None and retention_complete
    contextual_match = not direct_match and hostname_match
    freshness = "fresh" if snapshot.get("fresh") is True else "stale"
    result = "listed" if direct_match else "contextual_hostname_match" if contextual_match else "not_listed_in_snapshot"
    evidence = {
        "provider": SOURCE, "source_id": "openphish",
        "provider_version": snapshot.get("parser_version"),
        "provider_status": result, "result": result, "observed_at": now_iso(),
        "match_scope": "exact_url" if direct_match else "contextual_hostname" if contextual_match else "exact_url",
        "snapshot_id": snapshot.get("snapshot_id"), "content_sha256": snapshot.get("content_sha256"),
        "parser_version": snapshot.get("parser_version"), "snapshot_record_count": snapshot.get("record_count"),
        "snapshot_retrieved_at": _iso(snapshot.get("retrieved_at")),
        "last_successful_revalidation_at": _iso(snapshot.get("last_successful_revalidation_at")),
        "snapshot_age_seconds": snapshot.get("snapshot_age_seconds"), "freshness": freshness,
        "attribution": OPENPHISH_ATTRIBUTION,
        "coverage_note": (
            "OpenPhish Community Feed provides URL strings without per-indicator confidence, brand, discovery date, "
            "or observation time. Hostname matches are contextual only. CyberLens does not visit listed destinations."
        ),
    }
    if not retention_complete:
        evidence["url_retention_limitation"] = (
            "This URL predates complete URL retention. It was not eligible for direct matching; hostname comparison is contextual only."
        )
    if freshness == "stale":
        evidence["provider_status"] = "stale_snapshot"
        evidence["result"] = "unknown"
        evidence["review_note"] = "A stale snapshot cannot establish current listing status."
        return CollectorResult(status="unavailable", source=SOURCE, evidence=evidence,
                               error_explanation="The saved OpenPhish snapshot is stale; listing coverage is unknown.")
    if direct_match:
        evidence["provider_status"] = "listed"
        evidence["result"] = "listed"
        candidate = finding(
            "reputation", "medium", "URL listed in OpenPhish snapshot",
            "The submitted URL exactly matches a record in the saved OpenPhish Community Feed snapshot. This listing does not establish that the page remains reachable, that a user encountered it, or that the asset is compromised. Analyst confirmation is required before the finding affects risk.",
            "Review the source and snapshot provenance, confirm the exact URL belongs to the assessed asset, and verify context using an approved safe process without visiting the listed destination from this workspace.",
            SOURCE,
            {**evidence, "severity_policy": "CyberLens medium-priority review rule v1",
             "applicability_basis": "exact canonical URL match against a fresh validated snapshot",
             "risk_contribution_requires": "analyst applicability = applies"},
            applicability="needs_review",
        )
        return CollectorResult(status="success", source=SOURCE, evidence=evidence, findings=[candidate])
    if contextual_match:
        evidence["provider_status"] = "contextual_match"
        evidence["result"] = "contextual_hostname_match"
        evidence["message"] = "The hostname appears in this snapshot, but the exact submitted URL does not. This is contextual evidence only."
        return CollectorResult(status="partial", source=SOURCE, evidence=evidence,
                               error_explanation="A hostname-only association was observed; it is not a direct URL match.")
    evidence["provider_status"] = "no_match"
    evidence["result"] = "not_listed_in_snapshot"
    evidence["message"] = "No exact URL match in this snapshot."
    return CollectorResult(status="no_match", source=SOURCE, evidence=evidence)


def _iso(value):
    return value.isoformat() if hasattr(value, "isoformat") else value
