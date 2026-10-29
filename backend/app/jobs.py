"""RQ investigation runner with attempt fencing and durable collector history."""

import hashlib
import json
import logging
from datetime import datetime, timezone

from sqlalchemy import select, update

from app.collectors.demo import demo_result
from app.collectors.dns_rdap import collect_dns_rdap
from app.collectors.intelligence import collect_hibp, collect_virustotal
from app.collectors.xposedornot import collect_xposedornot
from app.collectors.nvd import collect_nvd
from app.collectors.osv import collect_osv
from app.collectors.spamhaus_drop import collect_spamhaus_drop
from app.collectors.cins_army import collect_cins_army
from app.collectors.openphish import collect_openphish
from app.collectors.website import collect_website
from app.authorization import active_email_breach_authorization, active_website_authorization
from app.config import get_settings
from app.database import SessionLocal
from app.graph import ensure_relationships
from app.models import (
    Asset,
    AuditEvent,
    CollectorRun,
    EvidenceSnapshot,
    Finding,
    Investigation,
    InvestigationAttempt,
    MonitoringRun,
    MonitoringSchedule,
    SoftwareComponent,
    new_id,
    now_utc,
)
from app.orchestration import _is_transient_evidence, _queue_automatic_retry, create_attempt
from app.monitoring import schedule_authorization_is_active
from app.openphish_access import collection_allowed, openphish_configuration
from app.services.risk import assess_investigation
from app.collectors.common import now_iso

logger = logging.getLogger("cyberlens.jobs")
TERMINAL_COLLECTOR_STATUSES = {"success", "no_match", "partial", "failed", "unavailable", "quota_limited", "not_applicable"}
COLLECTOR_PROVIDERS = {
    "dns_rdap": ("DNS and IANA RDAP", "DNS record lookup; IANA RDAP bootstrap registry"),
    "web_tls": ("Authorized website observer", "CyberLens bounded HTTP/1.1 and TLS observation"),
    "reputation": ("VirusTotal", "VirusTotal API v3"),
    "hibp": ("Have I Been Pwned", "HIBP API v3"),
    "xposedornot": ("XposedOrNot community API", "GET /v1/check-email/{email}?details=true · API docs 2026-06-03"),
    "nvd_kev": ("NVD, CISA KEV, and FIRST EPSS", "NVD CVE/CPE REST API 2.0; CISA KEV JSON feed; FIRST API v1"),
    "osv": ("OSV.dev", "OSV API 1.0 · POST /v1/query"),
    "spamhaus_drop": ("Spamhaus Project", "DROP IPv4 and IPv6 JSON snapshots"),
    "cins_army": ("CINS Army", "Public exact-IP text list; local snapshots"),
    "openphish": ("OpenPhish Community Feed", "OpenPhish Community Feed local exact-URL snapshot"),
}


def _sha256(payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _fail_monitoring_for_inactive_authorization(db, investigation, attempt, monitor_run, schedule) -> None:
    now = now_utc()
    reason = "The linked website authorization expired or was revoked; no further scheduled checks were run."
    attempt.status = "failed"
    attempt.progress = 100
    attempt.error_summary = reason
    attempt.finished_at = now
    attempt.heartbeat_at = now
    attempt.lease_token = new_id()
    investigation.status = "failed"
    investigation.progress = 100
    investigation.error_summary = reason
    investigation.finished_at = now
    monitor_run.status = "failed"
    monitor_run.finished_at = now
    monitor_run.failure_detail = reason
    schedule.last_run_at = now
    schedule.updated_at = now
    if schedule.status == "active":
        schedule.status = "failed"
        schedule.failure_code = "authorization_inactive"
        schedule.failure_detail = reason
    db.add(AuditEvent(actor_id=None, action="monitoring.run_blocked", entity_type="monitoring_run",
                      entity_id=monitor_run.id, details_json={"reason": "authorization_inactive"}))
    db.commit()


def _collectors(asset: Asset, email_breach_provider: str | None = None, mode: str | None = None) -> list[str]:
    if asset.kind in {"domain", "url"}:
        names = ["dns_rdap", "reputation", "web_tls"]
        if asset.kind == "url":
            settings = get_settings()
            if (mode or settings.app_mode) == "demo" or openphish_configuration(settings)["ready"]:
                names.append("openphish")
        return names
    if asset.kind == "ip":
        return ["reputation", "spamhaus_drop", "cins_army"]
    if asset.kind == "email":
        return ["xposedornot" if email_breach_provider == "xposedornot" else "hibp"]
    return ["nvd_kev", "osv"]


def _run_collector(name: str, asset: Asset, components: list[SoftwareComponent], mode: str,
                   scenario: str | None, authorized: bool, feed_snapshot: dict | None = None):
    if mode == "demo":
        return demo_result(asset, scenario or "routine_website", name, components=components)
    if name == "dns_rdap":
        return collect_dns_rdap(asset)
    if name == "web_tls":
        if not authorized:
            from app.collectors.types import CollectorResult
            return CollectorResult(status="not_applicable", source="Authorized HTTP(S) and TLS inspection",
                                   error_explanation="Active website checks require a recorded authorization confirmation.")
        return collect_website(asset)
    if name == "reputation":
        return collect_virustotal(asset)
    if name == "hibp":
        return collect_hibp(asset)
    if name == "xposedornot":
        return collect_xposedornot(asset, authorized=authorized)
    if name == "nvd_kev":
        return collect_nvd(asset, components)
    if name == "osv":
        return collect_osv(asset, components)
    if name == "spamhaus_drop":
        return collect_spamhaus_drop(asset, feed_snapshot)
    if name == "cins_army":
        return collect_cins_army(asset, feed_snapshot)
    if name == "openphish":
        return collect_openphish(asset, feed_snapshot)
    raise ValueError(f"Unknown collector {name}")


def run_investigation(investigation_id: str) -> None:
    """Compatibility entry point for already queued jobs and local Demo workflows."""
    db = SessionLocal()
    try:
        attempt = (db.query(InvestigationAttempt).filter_by(investigation_id=investigation_id)
                   .order_by(InvestigationAttempt.attempt_number.desc()).first())
        if attempt is None:
            investigation = db.get(Investigation, investigation_id)
            if (investigation is None or investigation.status != "queued" or
                    investigation.mode != get_settings().app_mode):
                return
            attempt = create_attempt(db, investigation, "initial")
            db.commit()
        attempt_id = attempt.id
    finally:
        db.close()
    run_investigation_attempt(investigation_id, attempt_id)


def sync_attack_catalog(catalog_version_id: str) -> None:
    """RQ entry point for an administrator-requested official ATT&CK import."""
    from app.services.attack_catalog_sync import process_catalog_sync

    process_catalog_sync(catalog_version_id)


def refresh_threat_feed(attempt_id: str) -> None:
    """RQ entry point for one shared durable threat-feed refresh attempt."""
    from app.services.threat_feeds import process_refresh_attempt

    process_refresh_attempt(attempt_id)


def refresh_spamhaus_drop(attempt_id: str) -> None:
    """Compatibility entry point for previously queued DROP jobs."""
    refresh_threat_feed(attempt_id)


def _lease_is_current(db, attempt_id: str, lease_token: str) -> bool:
    row = db.execute(select(InvestigationAttempt.status, InvestigationAttempt.lease_token)
                     .where(InvestigationAttempt.id == attempt_id).with_for_update()).first()
    return bool(row and row.status == "running" and row.lease_token == lease_token)


def _finding_fingerprint(asset_id: str, item: dict) -> str:
    details = item.get("details", {})
    if details.get("advisory_id"):
        source = f"{asset_id}|{item['category']}|OSV|{details.get('component_id', '')}|{details['advisory_id']}"
    else:
        source = f"{asset_id}|{item['category']}|{item['title']}|{details.get('cve_id', '')}"
    return hashlib.sha256(source.casefold().encode()).hexdigest()


def _evidence_with_provenance(result, collector: str, mode: str) -> dict:
    evidence = dict(result.evidence)
    observed_at = evidence.get("observed_at") or now_iso()
    provider, provider_version = COLLECTOR_PROVIDERS.get(collector, (result.source, "unspecified"))
    if mode == "demo":
        freshness_state = "synthetic"
        provider, provider_version = "Synthetic fixture", "bundled fixture schema 1"
    elif result.status in {"failed", "unavailable", "quota_limited", "not_applicable"}:
        freshness_state = "unavailable" if result.status != "not_applicable" else "not_assessed"
    else:
        freshness_state = "response_observed"
    source_timestamp = next((evidence.get(key) for key in ("last_analysis_date", "last_modified", "published")
                             if evidence.get(key) is not None), None)
    if isinstance(source_timestamp, (int, float)):
        try:
            source_timestamp = datetime.fromtimestamp(source_timestamp, timezone.utc).isoformat()
        except (OverflowError, OSError, ValueError):
            source_timestamp = None
    evidence["provenance"] = {
        "schema_version": 1,
        "source": result.source,
        "provider": provider,
        "provider_version": provider_version,
        "observed_at": observed_at,
        "freshness": {"state": freshness_state, "source_timestamp": source_timestamp},
        "status": result.status,
    }
    return evidence


def _epss_observed_at(details: dict):
    value = details.get("epss_observed_at")
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _epss_fields(details: dict) -> dict:
    """Keep EPSS values separate from CVSS, KEV, and analyst applicability."""
    return {
        "epss_score": details.get("epss_score"),
        "epss_percentile": details.get("epss_percentile"),
        "epss_observed_at": _epss_observed_at(details),
        "epss_provider_status": details.get("epss_provider_status"),
        "epss_freshness": details.get("epss_freshness"),
    }


def run_investigation_attempt(investigation_id: str, attempt_id: str) -> None:
    """Run exactly once per attempt; duplicate RQ deliveries fail the atomic claim."""
    db = SessionLocal()
    lease_token = new_id()
    try:
        candidate = db.get(Investigation, investigation_id)
        if candidate is None or candidate.mode != get_settings().app_mode:
            logger.info("skipping investigation delivery outside the active workspace mode",
                        extra={"investigation_id": investigation_id, "attempt_id": attempt_id})
            return
        now = now_utc()
        claimed = db.execute(
            update(InvestigationAttempt)
            .where(InvestigationAttempt.id == attempt_id,
                   InvestigationAttempt.investigation_id == investigation_id,
                   InvestigationAttempt.status == "queued")
            .values(status="running", started_at=now, heartbeat_at=now, lease_token=lease_token,
                    error_summary=None)
        )
        if claimed.rowcount != 1:
            db.rollback()
            return
        investigation = db.get(Investigation, investigation_id)
        attempt = db.get(InvestigationAttempt, attempt_id)
        if investigation is None or attempt is None:
            db.rollback()
            return
        investigation.status = "running"
        investigation.progress = 1
        investigation.started_at = now
        investigation.finished_at = None
        investigation.error_summary = None
        attempt.progress = 1
        db.commit()

        asset = db.get(Asset, investigation.asset_id)
        if asset is None:
            attempt.status = "failed"
            attempt.progress = 100
            attempt.error_summary = "The investigation asset no longer exists."
            attempt.finished_at = now_utc()
            investigation.status = attempt.status
            investigation.progress = attempt.progress
            investigation.error_summary = attempt.error_summary
            investigation.finished_at = attempt.finished_at
            db.commit()
            return

        monitoring_run = db.query(MonitoringRun).filter_by(investigation_id=investigation.id).one_or_none()
        monitoring_schedule = db.get(MonitoringSchedule, monitoring_run.schedule_id) if monitoring_run else None
        if monitoring_run and (monitoring_schedule is None or
                               not schedule_authorization_is_active(db, monitoring_schedule)):
            if monitoring_schedule is not None:
                _fail_monitoring_for_inactive_authorization(
                    db, investigation, attempt, monitoring_run, monitoring_schedule,
                )
            else:
                db.rollback()
            return

        mode = investigation.mode
        scenario = investigation.scenario
        names = _collectors(asset, investigation.email_breach_provider, mode=investigation.mode)
        components = db.query(SoftwareComponent).filter_by(asset_id=asset.id).all()
        transient_failure = False

        for index, name in enumerate(names, start=1):
            if not _lease_is_current(db, attempt_id, lease_token):
                db.rollback()
                logger.info("stale investigation worker fenced", extra={"investigation_id": investigation_id,
                                                                         "attempt_id": attempt_id})
                return
            if monitoring_run and (monitoring_schedule is None or
                                   not schedule_authorization_is_active(db, monitoring_schedule)):
                if monitoring_schedule is not None:
                    _fail_monitoring_for_inactive_authorization(
                        db, investigation, attempt, monitoring_run, monitoring_schedule,
                    )
                else:
                    db.rollback()
                return
            run = db.query(CollectorRun).filter_by(attempt_id=attempt_id, collector=name).one_or_none()
            if run is not None and run.status in TERMINAL_COLLECTOR_STATUSES:
                continue
            if run is None:
                run = CollectorRun(investigation_id=investigation.id, attempt_id=attempt_id,
                                   collector=name, status="running", source=name)
                db.add(run)
            run.status = "running"
            run.error_explanation = None
            run.started_at = now_utc()
            feed_snapshot = None
            openphish_access = True
            if name in {"spamhaus_drop", "cins_army", "openphish"} and mode != "demo":
                from app.services.threat_feeds import load_active_snapshot_for_collection

                source_id = name
                if name != "openphish" or collection_allowed(db, get_settings(), investigation.requested_by):
                    feed_snapshot = load_active_snapshot_for_collection(db, source_id=source_id)
                    run.feed_snapshot_id = feed_snapshot.get("snapshot_id") if feed_snapshot else None
                else:
                    openphish_access = False
            attempt.heartbeat_at = run.started_at
            db.commit()
            db.refresh(run)

            try:
                if name == "xposedornot":
                    authorized = mode == "demo" or active_email_breach_authorization(
                        db, asset.id, investigation.email_breach_authorization_id,
                    ) is not None
                else:
                    authorized = mode == "demo" or active_website_authorization(db, asset.id) is not None
                if name in {"spamhaus_drop", "cins_army", "openphish"}:
                    if name == "openphish" and not openphish_access:
                        from app.collectors.types import CollectorResult
                        result = CollectorResult(status="unavailable", source="OpenPhish Community Feed",
                            evidence={"provider_status": "access_scope_changed", "result": "unknown",
                                      "freshness": "unknown", "match_scope": "none"},
                            error_explanation="OpenPhish data access changed before collection; coverage is unknown.")
                    else:
                        result = _run_collector(name, asset, components, mode, scenario, authorized,
                                                feed_snapshot=feed_snapshot)
                else:
                    result = _run_collector(name, asset, components, mode, scenario, authorized)
            except Exception as exc:
                logger.warning("collector failed", extra={"collector": name, "exception_type": type(exc).__name__})
                from app.collectors.types import CollectorResult
                result = CollectorResult(status="failed", source=name, evidence={"error": type(exc).__name__},
                                         error_explanation="The collector could not complete; inspect its status and retry later.")

            if not _lease_is_current(db, attempt_id, lease_token):
                db.rollback()
                logger.info("stale collector result discarded", extra={"investigation_id": investigation_id,
                                                                         "attempt_id": attempt_id, "collector": name})
                return

            evidence_json = _evidence_with_provenance(result, name, mode)
            evidence_row = EvidenceSnapshot(
                investigation_id=investigation.id, collector_run_id=run.id, source=result.source,
                evidence_json=evidence_json, sha256=_sha256(evidence_json), is_synthetic=mode == "demo",
            )
            db.add(evidence_row)
            db.flush()
            run.source = result.source
            run.status = result.status
            run.error_explanation = result.error_explanation
            run.record_count = len(result.findings)
            run.finished_at = now_utc()
            if mode != "demo" and _is_transient_evidence(result.evidence):
                transient_failure = True
            for item in result.findings:
                fingerprint = _finding_fingerprint(asset.id, item)
                existing = db.query(Finding).filter_by(investigation_id=investigation.id, fingerprint=fingerprint).first()
                if existing:
                    evidence_ids = list(existing.details_json.get("additional_evidence_ids", []))
                    evidence_ids.append(evidence_row.id)
                    epss_details = {key: item.get("details", {}).get(key) for key in (
                        "epss_score", "epss_percentile", "epss_observed_at", "epss_provider_status",
                        "epss_freshness", "epss_source_date", "epss_provider", "epss_provider_version",
                        "epss_cache_state") if key in item.get("details", {})}
                    existing.details_json = {**existing.details_json, **epss_details,
                                             "additional_evidence_ids": sorted(set(evidence_ids))}
                    if "epss_provider_status" in epss_details:
                        for key, value in _epss_fields(item.get("details", {})).items():
                            setattr(existing, key, value)
                    continue
                details = item.get("details", {})
                db.add(Finding(
                    asset_id=asset.id, investigation_id=investigation.id, evidence_id=evidence_row.id,
                    fingerprint=fingerprint, category=item["category"], severity=item["severity"],
                    title=item["title"], explanation=item["explanation"], recommendation=item["recommendation"],
                    source=item["source"], applicability=item.get("applicability", "applies"),
                    is_synthetic=mode == "demo", details_json=details, **_epss_fields(details),
                ))
            attempt.progress = round(index / len(names) * 95)
            attempt.heartbeat_at = now_utc()
            investigation.progress = attempt.progress
            db.flush()
            ensure_relationships(db, investigation)
            db.commit()

        statuses = [item.status for item in db.query(CollectorRun).filter_by(attempt_id=attempt_id).all()]
        success = sum(status in {"success", "no_match", "partial"} for status in statuses)
        failures = sum(status in {"failed", "unavailable", "quota_limited", "partial"} for status in statuses)
        if failures and success:
            outcome = "partial"
        elif failures:
            outcome = "failed"
        else:
            outcome = "completed"

        finished = now_utc()
        attempt.status = outcome
        attempt.progress = 100
        attempt.finished_at = finished
        attempt.heartbeat_at = finished
        if outcome == "failed":
            attempt.error_summary = "No collector produced an assessed result. Review collector status for details."
        else:
            attempt.error_summary = None
        retry_scheduled = transient_failure and _queue_automatic_retry(db, investigation, attempt, now=finished)
        if retry_scheduled:
            db.add(AuditEvent(actor_id=None, action="investigation.retry_scheduled", entity_type="investigation",
                              entity_id=investigation.id,
                              details_json={"attempt_id": attempt.id, "reason": "transient_collector_failure"}))
        else:
            investigation.status = outcome
            investigation.progress = 100
            investigation.finished_at = finished
            investigation.error_summary = attempt.error_summary
        assess_investigation(db, investigation)
        db.commit()
    except Exception:
        logger.exception("investigation orchestration failed", extra={"investigation_id": investigation_id,
                                                                         "attempt_id": attempt_id})
        db.rollback()
        raise
    finally:
        db.close()
