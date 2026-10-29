"""Snapshot-only exact-IP matching against the CINS Army feed."""

from app.collectors.common import finding, now_iso
from app.collectors.types import CollectorResult
from app.config import get_settings
from app.services.threat_feeds import CINS_ATTRIBUTION, match_cins_ip

SOURCE = "CINS Army"


def collect_cins_army(asset, snapshot: dict | None) -> CollectorResult:
    settings = get_settings()
    if settings.app_mode != "live" or not settings.cins_army_enabled:
        return CollectorResult(status="unavailable", source=SOURCE, evidence={
            "provider": "CINS Army", "provider_status": "disabled", "result": "unknown",
            "observed_at": now_iso(), "match_scope": "direct_public_ip",
        }, error_explanation="CINS Army collection is disabled by the operator.")
    if asset.kind != "ip":
        return CollectorResult(status="not_applicable", source=SOURCE, evidence={
            "provider": "CINS Army", "provider_status": "not_applicable", "result": "unknown",
            "observed_at": now_iso(), "match_scope": "direct_public_ip",
        }, error_explanation="CINS Army checks only explicitly submitted IP assets.")
    if snapshot is None:
        return CollectorResult(status="unavailable", source=SOURCE, evidence={
            "provider": "CINS Army", "provider_status": "missing_snapshot", "result": "unknown",
            "observed_at": now_iso(), "match_scope": "direct_public_ip",
            "coverage_note": "No validated local snapshot is available. No clean result was inferred.",
        }, error_explanation="No validated CINS Army snapshot is available.")
    if snapshot.get("integrity_valid") is not True:
        return CollectorResult(status="unavailable", source=SOURCE, evidence={
            "provider": "CINS Army", "provider_status": "snapshot_integrity_failed", "result": "unknown",
            "snapshot_id": snapshot.get("snapshot_id"), "observed_at": now_iso(),
            "match_scope": "direct_public_ip",
        }, error_explanation="The stored CINS Army snapshot did not pass its checksum check.")

    matched_ip = match_cins_ip(asset.identifier, snapshot)
    freshness = "fresh" if snapshot.get("fresh") else "stale"
    result = "listed" if matched_ip else "not_listed_in_snapshot"
    evidence = {
        "provider": "CINS Army", "source_id": "cins_army",
        "provider_version": snapshot.get("parser_version"), "provider_status": result, "result": result,
        "observed_at": now_iso(), "match_scope": "direct_public_ip", "asset_ip": asset.identifier,
        "matched_ip": matched_ip, "snapshot_id": snapshot.get("snapshot_id"),
        "content_sha256": snapshot.get("content_sha256"), "parser_version": snapshot.get("parser_version"),
        "snapshot_record_count": snapshot.get("record_count"),
        "snapshot_retrieved_at": _iso(snapshot.get("retrieved_at")),
        "provider_published_at": None,
        "last_successful_revalidation_at": _iso(snapshot.get("last_successful_revalidation_at")),
        "snapshot_age_seconds": snapshot.get("snapshot_age_seconds"), "freshness": freshness,
        "attribution": CINS_ATTRIBUTION,
        "coverage_note": (
            "A no-match means only that this exact IP was not listed in this snapshot. The feed contains IP addresses only; "
            "it provides no per-indicator score, attack category, report count, or first-seen time."
        ),
    }
    if freshness == "stale":
        evidence["provider_status"] = "stale_cached_evidence"
        evidence["result"] = "stale_match" if matched_ip else "stale_no_match"
        evidence["review_note"] = "The cached snapshot is stale and cannot establish current listing status."
        status = "unavailable"
    else:
        status = "success" if matched_ip else "no_match"
    if not matched_ip:
        evidence["message"] = "Not listed in this snapshot." if freshness == "fresh" else "Not listed in this stale snapshot."
        return CollectorResult(status=status, source=SOURCE, evidence=evidence)

    candidate = finding(
        "reputation", "medium", "Direct IP listed in a CINS Army snapshot",
        f"The exact submitted IP {matched_ip} appears in the saved CINS Army snapshot. This is a provider listing for analyst review, not evidence that the asset is compromised or that an attack occurred.",
        "Confirm that the IP is current and belongs to the assessed asset, review the provider and snapshot provenance, and record an applicability decision before using it in risk prioritization.",
        SOURCE,
        {**evidence, "severity_policy": "CyberLens medium-priority review rule v1",
         "applicability_basis": "exact direct public IP match",
         "risk_contribution_requires": "analyst applicability = applies"},
        applicability="needs_review",
    )
    return CollectorResult(status=status, source=SOURCE, evidence=evidence, findings=[candidate])


def _iso(value):
    return value.isoformat() if hasattr(value, "isoformat") else value
