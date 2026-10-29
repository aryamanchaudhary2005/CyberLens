"""Snapshot-only Spamhaus DROP matching for directly submitted IP assets."""

from app.collectors.common import finding, now_iso
from app.collectors.types import CollectorResult
from app.config import get_settings
from app.services.threat_feeds import ATTRIBUTION, match_public_ip
import ipaddress


SOURCE = "Spamhaus Project DROP"


def collect_spamhaus_drop(asset, snapshot: dict | None) -> CollectorResult:
    settings = get_settings()
    if settings.app_mode != "live" or not settings.spamhaus_drop_enabled:
        return CollectorResult(status="unavailable", source=SOURCE, evidence={
            "provider_status": "disabled", "observed_at": now_iso(), "match_scope": "direct_public_ip",
        }, error_explanation="Spamhaus DROP collection is disabled by the operator.")
    if asset.kind != "ip":
        return CollectorResult(status="not_applicable", source=SOURCE, evidence={
            "provider_status": "not_applicable", "observed_at": now_iso(), "match_scope": "direct_public_ip",
        }, error_explanation="Spamhaus DROP checks only explicitly submitted IP assets.")
    try:
        submitted_ip = ipaddress.ip_address(asset.identifier)
    except ValueError:
        return CollectorResult(status="not_applicable", source=SOURCE, evidence={
            "provider_status": "invalid_ip_asset", "observed_at": now_iso(), "match_scope": "direct_public_ip",
        }, error_explanation="Spamhaus DROP requires a valid, directly submitted IP asset.")
    if not submitted_ip.is_global:
        return CollectorResult(status="not_applicable", source=SOURCE, evidence={
            "provider_status": "non_public_ip", "observed_at": now_iso(), "match_scope": "direct_public_ip",
            "asset_ip": asset.identifier,
        }, error_explanation="Spamhaus DROP direct matching is limited to public IP addresses.")
    if snapshot is None:
        return CollectorResult(status="unavailable", source=SOURCE, evidence={
            "provider_status": "missing_snapshot", "observed_at": now_iso(), "match_scope": "direct_public_ip",
            "coverage_note": "No validated local snapshot is available. No clean result was inferred.",
        }, error_explanation="No validated Spamhaus DROP snapshot is available.")
    if snapshot.get("integrity_valid") is not True:
        return CollectorResult(status="unavailable", source=SOURCE, evidence={
            "provider_status": "snapshot_integrity_failed", "snapshot_id": snapshot.get("snapshot_id"),
            "observed_at": now_iso(), "match_scope": "direct_public_ip",
        }, error_explanation="The stored feed snapshot did not pass its content checksum check.")

    freshness = "fresh" if snapshot.get("fresh") else "stale"
    networks = snapshot.get("networks") if isinstance(snapshot.get("networks"), list) else []
    matches = match_public_ip(asset.identifier, networks)
    evidence = {
        "provider": "Spamhaus Project",
        "provider_version": snapshot.get("parser_version"),
        "provider_status": "listed" if matches else "not_listed_in_snapshot",
        "result": "listed" if matches else "not_listed_in_snapshot",
        "observed_at": now_iso(),
        "match_scope": "direct_public_ip",
        "asset_ip": asset.identifier,
        "snapshot_id": snapshot.get("snapshot_id"),
        "content_sha256": snapshot.get("content_sha256"),
        "parser_version": snapshot.get("parser_version"),
        "snapshot_record_count": snapshot.get("record_count"),
        "snapshot_retrieved_at": _iso(snapshot.get("retrieved_at")),
        "provider_published_at": _iso(snapshot.get("published_at")),
        "last_successful_revalidation_at": _iso(snapshot.get("last_successful_revalidation_at")),
        "snapshot_age_seconds": snapshot.get("snapshot_age_seconds"),
        "freshness": freshness,
        "attribution": ATTRIBUTION,
        "feed_metadata": snapshot.get("metadata"),
        "matched_networks": matches,
        "coverage_note": "A no-match means only that this direct IP is not listed in this snapshot. DROP is a narrow advisory list and does not establish safety or complete reputation coverage.",
    }
    if freshness == "stale":
        evidence["provider_status"] = "stale_cached_evidence"
        evidence["result"] = "stale_match" if matches else "stale_no_match"
        evidence["review_note"] = "This cached snapshot is stale; it must not be treated as a current reputation result."
        status = "unavailable"
    else:
        status = "success" if matches else "no_match"
    if not matches:
        evidence["message"] = "Not listed in this snapshot." if freshness == "fresh" else "Not listed in this snapshot; the cached snapshot is stale."
        return CollectorResult(status=status, source=SOURCE, evidence=evidence)

    matched_display = ", ".join(f"{row['network']} ({row['sbl_id']})" for row in matches)
    candidate = finding(
        "reputation", "medium", "Direct IP listed in a Spamhaus DROP snapshot",
        f"The submitted IP address matches {matched_display}. This is a candidate for analyst review; it does not show that the asset is compromised or that activity originated from the listed range.",
        "Verify that the address is current and belongs to the assessed asset, review the provider record and snapshot date, and record an applicability decision before using it in risk prioritization.",
        SOURCE,
        {**evidence, "severity_policy": "CyberLens medium-priority review rule v1",
         "applicability_basis": "direct IP CIDR match", "risk_contribution_requires": "analyst applicability = applies"},
        applicability="needs_review",
    )
    return CollectorResult(status=status, source=SOURCE, evidence=evidence, findings=[candidate])


def _iso(value):
    return value.isoformat() if hasattr(value, "isoformat") else value
