"""Read-only workspace scorecard built only from saved CyberLens records."""

from __future__ import annotations

from collections import defaultdict
from datetime import date, datetime, timedelta, timezone
from statistics import mean, median
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import (
    Asset,
    CollectorRun,
    EvidenceSnapshot,
    Finding,
    FindingControlMapping,
    Incident,
    IncidentEvent,
    Investigation,
    MonitoringRun,
    RiskAssessment,
    RiskAssessmentRevision,
    SoftwareComponent,
    now_utc,
)
from app.services.risk import risk_band
from app.visibility import live_projection, visible_assets, visible_findings, visible_incidents, visible_investigations


RISK_CATEGORIES_BY_ASSET_KIND: dict[str, set[str]] = {
    "domain": {"reputation", "tls_web", "dns_email"},
    "url": {"reputation", "tls_web", "dns_email"},
    "ip": {"reputation"},
    "email": {"breach_exposure"},
    "application": {"vulnerabilities"},
}
COLLECTOR_PROVIDERS: dict[str, dict[str, Any]] = {
    "dns_rdap": {"name": "DNS and IANA RDAP", "asset_kinds": {"domain", "url"}, "setting": None},
    "reputation": {"name": "VirusTotal", "asset_kinds": {"domain", "url", "ip"}, "setting": "virustotal_api_key"},
    "web_tls": {"name": "Authorized HTTP(S) and TLS", "asset_kinds": {"domain", "url"}, "setting": None},
    "hibp": {"name": "Have I Been Pwned", "asset_kinds": {"email"}, "setting": "hibp_api_key"},
    "xposedornot": {"name": "XposedOrNot community lookup", "asset_kinds": {"email"}, "setting": "xposedornot_enabled"},
    "nvd_kev": {"name": "NVD and CISA KEV", "asset_kinds": {"application"}, "setting": None},
    "osv": {"name": "OSV.dev package intelligence", "asset_kinds": {"application"}, "setting": None},
    "epss": {"name": "FIRST EPSS", "asset_kinds": {"application"}, "setting": None},
}
USABLE_STATES = {"completed", "partial"}


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    normalized = _utc(value)
    return normalized.isoformat() if normalized else ""


def _metric(state: str, scope: str, start: datetime, end: datetime, days: int, note: str | None = None, **values: Any) -> dict[str, Any]:
    return {
        "state": state,
        "scope": scope,
        "range_days": days,
        "window_start": _iso(start),
        "window_end": _iso(end),
        "note": note,
        **values,
    }


def _expected_categories(asset: Asset) -> set[str]:
    return RISK_CATEGORIES_BY_ASSET_KIND.get(asset.kind, set())


def _latest_by_asset(rows: list[Investigation]) -> dict[str, Investigation]:
    result: dict[str, Investigation] = {}
    for row in rows:
        existing = result.get(row.asset_id)
        row_time = _utc(row.finished_at or row.created_at)
        existing_time = _utc(existing.finished_at or existing.created_at) if existing else None
        if existing is None or (row_time, row.id) > (existing_time, existing.id):
            result[row.asset_id] = row
    return result


def _bucket_start(value: datetime, days: int) -> date:
    moment = _utc(value) or value.replace(tzinfo=timezone.utc)
    current = moment.date()
    if days <= 30:
        return current
    if days <= 90:
        return current - timedelta(days=current.weekday())
    return current.replace(day=1)


def _build_provider_health(db: Session, assets: list[Asset], start: datetime, end: datetime, days: int) -> dict[str, Any]:
    eligible_counts = {
        collector: sum(asset.kind in details["asset_kinds"] for asset in assets)
        for collector, details in COLLECTOR_PROVIDERS.items()
    }
    cpe_asset_ids = {
        item[0] for item in db.query(SoftwareComponent.asset_id).filter(SoftwareComponent.cpe_name.is_not(None)).distinct().all()
    }
    eligible_counts["epss"] = sum(asset.id in cpe_asset_ids and asset.kind == "application" for asset in assets)
    asset_ids = {asset.id for asset in assets if asset.kind == "application"}
    package_asset_ids = {
        item[0] for item in db.query(SoftwareComponent.asset_id).filter(
            SoftwareComponent.asset_id.in_(asset_ids), SoftwareComponent.package_ecosystem.is_not(None),
            SoftwareComponent.package_name.is_not(None),
        ).distinct().all()
    } if asset_ids else set()
    eligible_counts["osv"] = len(package_asset_ids)

    scoped_asset_ids = {asset.id for asset in assets}
    latest_run_query = (
        db.query(
            CollectorRun.id.label("run_id"),
            func.row_number().over(
                partition_by=CollectorRun.collector,
                order_by=(CollectorRun.finished_at.desc(), CollectorRun.id.desc()),
            ).label("row_number"),
        )
        .join(Investigation, Investigation.id == CollectorRun.investigation_id)
        .filter(CollectorRun.finished_at.is_not(None))
    )
    if scoped_asset_ids:
        latest_run_query = latest_run_query.filter(Investigation.asset_id.in_(scoped_asset_ids))
    else:
        latest_run_query = latest_run_query.filter(False)
    if live_projection():
        latest_run_query = latest_run_query.filter(Investigation.mode == "live")
    latest_runs_subquery = latest_run_query.subquery()
    latest_run_rows = (
        db.query(CollectorRun, Investigation)
        .join(latest_runs_subquery, latest_runs_subquery.c.run_id == CollectorRun.id)
        .join(Investigation, Investigation.id == CollectorRun.investigation_id)
        .filter(latest_runs_subquery.c.row_number == 1)
        .all()
    )
    latest_runs: dict[str, tuple[CollectorRun, Investigation]] = {}
    for run, investigation in latest_run_rows:
        latest_runs.setdefault(run.collector, (run, investigation))

    settings = get_settings()
    provider_rows: list[dict[str, Any]] = []
    status_values: list[str] = []
    for provider_id, details in COLLECTOR_PROVIDERS.items():
        latest = latest_runs.get(provider_id)
        eligible = eligible_counts.get(provider_id, 0)
        configured = True if settings.app_mode == "demo" or details["setting"] is None else bool(getattr(settings, details["setting"]))
        last_status = latest[0].status if latest else None
        last_source = latest[0].source if latest else None
        observed_at = _utc(latest[0].finished_at) if latest else None
        mode = latest[1].mode if latest else None
        provider_note = None
        if eligible == 0:
            state = "empty"
            freshness = "not_applicable"
            provider_note = "No in-scope asset is eligible for this provider."
        elif not configured:
            state = "unavailable"
            freshness = "unknown" if observed_at is None else ("stale" if observed_at < start else "fresh")
            provider_note = "The provider credential or configuration is not present."
        elif latest is None:
            state = "unavailable"
            freshness = "unavailable"
            provider_note = "No completed provider observation is stored."
        elif observed_at is not None and observed_at < start:
            state = "stale"
            freshness = "stale"
            provider_note = "The most recent saved observation predates the selected window."
        elif last_status in {"failed", "unavailable", "quota_limited"}:
            state = "unavailable"
            freshness = "fresh"
        elif last_status == "partial":
            state = "partial"
            freshness = "fresh"
        elif last_status == "not_applicable":
            state = "empty"
            freshness = "not_applicable"
            provider_note = "The most recent collector run did not assess this provider."
        else:
            state = "available"
            freshness = "synthetic" if mode == "demo" else "fresh"
        provider_rows.append({
            "id": provider_id,
            "name": details["name"],
            "state": state,
            "configured": configured,
            "eligible_asset_count": eligible,
            "provider_status": last_status,
            "source": last_source,
            "last_observed_at": _iso(observed_at) if observed_at else None,
            "freshness": freshness,
            "data_mode": mode,
            "note": provider_note,
        })

    # EPSS is nested inside NVD evidence rather than a separate investigation collector.
    nvd_latest = latest_runs.get("nvd_kev")
    epss_row = next(row for row in provider_rows if row["id"] == "epss")
    if epss_row["eligible_asset_count"] > 0 and nvd_latest:
        run, investigation = nvd_latest
        evidence = db.query(EvidenceSnapshot).filter_by(collector_run_id=run.id).order_by(EvidenceSnapshot.observed_at.desc()).first()
        epss_entries = (evidence.evidence_json or {}).get("epss", []) if evidence else []
        epss_statuses = {str(item.get("status", "unknown")) for item in epss_entries if isinstance(item, dict) and item.get("status")}
        epss_observed = _utc(evidence.observed_at) if evidence else _utc(run.finished_at)
        if epss_statuses:
            if epss_observed is not None and epss_observed < start:
                epss_row.update(state="stale", freshness="stale", note="The most recent EPSS evidence predates the selected window.")
            elif epss_statuses & {"unavailable", "quota_limited", "failed"}:
                epss_row.update(state="partial" if epss_statuses & {"success", "no_match"} else "unavailable", freshness="fresh")
            else:
                epss_row.update(state="available", freshness="synthetic" if investigation.mode == "demo" else "fresh")
            epss_row.update(provider_status=sorted(epss_statuses), source=evidence.source if evidence else run.source,
                            last_observed_at=_iso(epss_observed) if epss_observed else None, data_mode=investigation.mode)
        else:
            epss_row.update(state="unavailable" if run.status in {"failed", "unavailable", "quota_limited"} else "empty",
                            freshness="unavailable" if run.status in {"failed", "unavailable", "quota_limited"} else "not_observed",
                            note="EPSS status is absent from the latest saved NVD evidence; the enrichment may not have been queried.")
    status_values = [row["state"] for row in provider_rows if row["eligible_asset_count"] > 0]
    if not status_values:
        overall_state = "empty"
    elif all(value == "unavailable" for value in status_values):
        overall_state = "unavailable"
    elif any(value in {"unavailable", "stale", "partial"} for value in status_values):
        overall_state = "partial"
    else:
        overall_state = "available"
    return _metric(
        overall_state,
        "Latest saved collector result per applicable provider across all in-scope assets; provider freshness is evaluated against the selected window.",
        start, end, days,
        "Provider state reflects the latest stored result, not a live connectivity probe or service-level guarantee. Demo results are synthetic. Freshness is relative to the selected window.",
        providers=provider_rows,
    )


def build_scorecard(db: Session, range_days: int = 30, *, now: datetime | None = None) -> dict[str, Any]:
    """Aggregate workspace posture without mutating assessments or reports."""
    if range_days not in {7, 30, 90, 365}:
        raise ValueError("range_days must be one of 7, 30, 90, or 365")
    end = _utc(now or now_utc()) or now_utc()
    start = end - timedelta(days=range_days)
    assets = visible_assets(db).filter(Asset.created_at <= end).order_by(Asset.id).all()
    asset_map = {asset.id: asset for asset in assets}
    asset_ids = set(asset_map)
    expected = {asset.id: _expected_categories(asset) for asset in assets}
    all_expected_categories = sorted({category for values in expected.values() for category in values})
    total_expected_slots = sum(len(values) for values in expected.values())

    usable_investigations = []
    if asset_ids:
        usable_investigations = (
            visible_investigations(db)
            .filter(Investigation.asset_id.in_(asset_ids), Investigation.status.in_(USABLE_STATES),
                    Investigation.finished_at.is_not(None), Investigation.finished_at >= start,
                    Investigation.finished_at <= end)
            .order_by(Investigation.finished_at.desc(), Investigation.id.desc())
            .all()
        )
    latest_usable = _latest_by_asset(usable_investigations)
    latest_ids = {item.id for item in latest_usable.values()}

    revision_by_investigation: dict[str, RiskAssessmentRevision] = {}
    if latest_ids:
        revisions = (db.query(RiskAssessmentRevision)
                     .filter(RiskAssessmentRevision.investigation_id.in_(latest_ids))
                     .order_by(RiskAssessmentRevision.revision_number.desc(), RiskAssessmentRevision.id.desc()).all())
        for revision in revisions:
            revision_by_investigation.setdefault(revision.investigation_id, revision)
    current_assessment_by_investigation: dict[str, RiskAssessment] = {}
    if latest_ids:
        current_assessment_by_investigation = {
            item.investigation_id: item for item in db.query(RiskAssessment)
            .filter(RiskAssessment.investigation_id.in_(latest_ids)).all()
        }

    score_by_asset: dict[str, float] = {}
    assessed_by_asset: dict[str, set[str]] = {}
    excluded_by_asset: dict[str, set[str]] = {}
    for asset_id, investigation in latest_usable.items():
        assessment = revision_by_investigation.get(investigation.id) or current_assessment_by_investigation.get(investigation.id)
        assessed = set(getattr(assessment, "assessed_categories", []) or []) if assessment else set()
        excluded = set(getattr(assessment, "excluded_categories", []) or []) if assessment else set()
        assessed_by_asset[asset_id] = assessed
        excluded_by_asset[asset_id] = excluded
        score = getattr(assessment, "score", None) if assessment else None
        if score is not None:
            score_by_asset[asset_id] = float(score)

    coverage_count = sum(len(assessed_by_asset.get(asset.id, set()) & expected[asset.id]) for asset in assets)
    unassessed_by_category = {
        category: sum(category in expected[asset.id] and category not in assessed_by_asset.get(asset.id, set()) for asset in assets)
        for category in all_expected_categories
    }
    unassessed_count = total_expected_slots - coverage_count
    if not assets:
        coverage_state = "empty"
        coverage_pct = None
    elif total_expected_slots == 0:
        coverage_state = "empty"
        coverage_pct = None
    else:
        coverage_pct = round(coverage_count * 100 / total_expected_slots, 2)
        coverage_state = "available" if unassessed_count == 0 else "partial" if coverage_count else "unavailable"
    assessment_coverage = _metric(
        coverage_state,
        "All registered assets as of the scorecard end time, using categories applicable to each asset kind; the denominator includes assets without a recent assessment.",
        start, end, range_days,
        "Coverage is based on saved risk assessment categories. A missing assessment or excluded category is unassessed, never a passing result.",
        assessed_category_slots=coverage_count,
        expected_category_slots=total_expected_slots,
        coverage_percent=coverage_pct,
        assets_in_scope=len(assets),
        assets_with_recent_assessment=len(latest_usable),
        assets_with_score=len(score_by_asset),
        unassessed_category_slots=unassessed_count,
    )

    older_usable_exists = False
    if asset_ids:
        older_usable_exists = visible_investigations(db).with_entities(Investigation.id).filter(
            Investigation.asset_id.in_(asset_ids), Investigation.status.in_(USABLE_STATES),
            Investigation.finished_at.is_not(None), Investigation.finished_at < start,
        ).first() is not None
    if not assets:
        overall_state = "empty"
    elif score_by_asset and len(score_by_asset) == len(assets) and coverage_state == "available":
        overall_state = "available"
    elif score_by_asset:
        overall_state = "partial"
    elif older_usable_exists:
        overall_state = "stale"
    elif usable_investigations:
        overall_state = "unavailable"
    else:
        overall_state = "empty"
    average_score = round(mean(score_by_asset.values()), 2) if score_by_asset else None
    overall_risk = _metric(
        overall_state,
        "Equal-weighted mean of the latest saved, numeric risk assessment per registered asset, where the underlying investigation finished within the selected window.",
        start, end, range_days,
        "This workspace aggregate is an academic prioritization aid, not a probability of compromise or a calibrated score. Assets without an in-window numeric assessment are excluded from the mean and remain in the denominator counts.",
        average_score=average_score,
        band=risk_band(average_score) if average_score is not None else None,
        assets_in_scope=len(assets),
        assets_with_score=len(score_by_asset),
        assessments_used=len(score_by_asset),
    )

    unassessed_state = coverage_state
    unassessed_categories = _metric(
        unassessed_state,
        "Count of in-scope assets per applicable risk category whose latest in-window completed/partial investigation did not cover that category.",
        start, end, range_days,
        "Categories absent because no recent assessment exists are counted as unassessed. Counts are assets, not findings.",
        counts={category: unassessed_by_category[category] for category in all_expected_categories},
        assets_without_recent_assessment=len(assets) - len(latest_usable),
        total_unassessed_category_slots=unassessed_count,
    )

    findings: list[Finding] = []
    if latest_ids:
        findings = visible_findings(db).filter(Finding.investigation_id.in_(latest_ids)).all()
    selected_findings: dict[tuple[str, str], Finding] = {}
    for finding in findings:
        if finding.applicability == "not_applicable":
            continue
        asset_finding_key = (finding.asset_id, finding.fingerprint)
        previous = selected_findings.get(asset_finding_key)
        if previous is None or (_utc(finding.observed_at), finding.id) > (_utc(previous.observed_at), previous.id):
            selected_findings[asset_finding_key] = finding
    severity_counts = {"high": 0, "critical": 0}
    for finding in selected_findings.values():
        severity = finding.severity.lower()
        if severity in severity_counts:
            severity_counts[severity] += 1
    if not assets:
        finding_state = "empty"
        count_high = count_critical = count_total = None
    elif not latest_usable:
        finding_state = "stale" if older_usable_exists else "unavailable"
        count_high = count_critical = count_total = None
    else:
        finding_state = "available" if len(latest_usable) == len(assets) else "partial"
        if any(excluded_by_asset.get(asset_id, set()) & expected.get(asset_id, set()) for asset_id in latest_usable):
            finding_state = "partial"
        count_high, count_critical = severity_counts["high"], severity_counts["critical"]
        count_total = count_high + count_critical
    current_findings = _metric(
        finding_state,
        "Unique asset/fingerprint pairs observed in each asset's latest in-window completed/partial investigation; analyst-marked not-applicable findings are excluded.",
        start, end, range_days,
        "Finding records have no open/closed lifecycle field. These are latest-observed high/critical counts, not verified unresolved or unremediated counts. Unconfirmed vulnerability applicability may still be represented.",
        high=count_high,
        critical=count_critical,
        total=count_total,
        open_high=None,
        open_critical=None,
        open_total=None,
        open_counts_available=False,
        assets_with_recent_observation=len(latest_usable),
        assets_in_scope=len(assets),
        lifecycle_status_available=False,
    )

    all_finished_window = []
    if asset_ids:
        all_finished_window = (visible_investigations(db)
                               .filter(Investigation.asset_id.in_(asset_ids), Investigation.status.in_(USABLE_STATES),
                                       Investigation.finished_at >= start, Investigation.finished_at <= end)
                               .order_by(Investigation.finished_at.asc(), Investigation.id.asc()).all())
    findings_by_investigation: dict[str, list[Finding]] = defaultdict(list)
    inv_ids = {item.id for item in all_finished_window}
    if inv_ids:
        for finding in visible_findings(db).filter(Finding.investigation_id.in_(inv_ids)).all():
            if finding.applicability != "not_applicable":
                findings_by_investigation[finding.investigation_id].append(finding)
    sightings: dict[tuple[str, str], set[str]] = defaultdict(set)
    for investigation in all_finished_window:
        for finding in findings_by_investigation.get(investigation.id, []):
            sightings[(finding.asset_id, finding.fingerprint)].add(investigation.id)
    repeated_keys = {key: ids for key, ids in sightings.items() if len(ids) >= 2}
    if not all_finished_window:
        repeated_state = "empty"
        repeated_value = None
    elif any(item.status == "partial" for item in all_finished_window):
        repeated_state = "partial"
        repeated_value = len(repeated_keys)
    else:
        repeated_state = "available"
        repeated_value = len(repeated_keys)
    repeated_findings = _metric(
        repeated_state,
        "Distinct asset/fingerprint finding identities present in at least two completed/partial investigations finished in the selected window.",
        start, end, range_days,
        "Repeat counts are observations across runs; they do not prove continuous exposure between investigations. Partial investigations can understate recurrence.",
        repeated_finding_count=repeated_value,
        repeated_observation_count=sum(len(ids) for ids in repeated_keys.values()) if repeated_value is not None else None,
        distinct_finding_identities=len(sightings) if all_finished_window else None,
        investigations_in_scope=len(all_finished_window),
    )

    risk_revision_query = (
        db.query(RiskAssessmentRevision, Investigation)
        .join(Investigation, Investigation.id == RiskAssessmentRevision.investigation_id)
        .filter(Investigation.asset_id.in_(asset_ids), Investigation.status.in_(USABLE_STATES), RiskAssessmentRevision.created_at >= start,
                RiskAssessmentRevision.created_at <= end)
        .order_by(RiskAssessmentRevision.revision_number.desc(), RiskAssessmentRevision.id.desc())
    )
    if live_projection():
        risk_revision_query = risk_revision_query.filter(Investigation.mode == "live")
    risk_revision_rows = risk_revision_query.all()
    latest_trend_revision: dict[str, tuple[RiskAssessmentRevision, Investigation]] = {}
    for revision, investigation in risk_revision_rows:
        latest_trend_revision.setdefault(investigation.id, (revision, investigation))
    trend_groups: dict[str, dict[str, tuple[datetime, float, str]]] = defaultdict(dict)
    for revision, investigation in latest_trend_revision.values():
        if revision.score is None:
            continue
        observed = _utc(revision.created_at) or end
        bucket = _bucket_start(observed, range_days).isoformat()
        current = trend_groups[bucket].get(investigation.asset_id)
        explanation = revision.explanation_json if isinstance(revision.explanation_json, dict) else {}
        policy_version = str(explanation.get("rule_version") or revision.version or "unknown")
        if current is None or observed > current[0]:
            trend_groups[bucket][investigation.asset_id] = (observed, float(revision.score), policy_version)
    risk_points = []
    for bucket in sorted(trend_groups):
        asset_points = list(trend_groups[bucket].values())
        scores = [item[1] for item in asset_points]
        policy_versions = sorted({item[2] for item in asset_points})
        risk_points.append({"period_start": bucket, "average_score": round(mean(scores), 2), "asset_count": len(scores), "policy_versions": policy_versions})
    if risk_points:
        risk_trend_state = "available"
        if any(revision.score is None for revision, _ in latest_trend_revision.values()):
            risk_trend_state = "partial"
    else:
        risk_trend_state = "unavailable" if usable_investigations else "stale" if older_usable_exists else "empty"
    risk_trend = _metric(
        risk_trend_state,
        "Latest immutable risk revision per investigation in the selected window; each plotted period averages the latest scored revision per asset within that period.",
        start, end, range_days,
        "Empty periods are omitted rather than plotted as zero. Revision timestamps represent saved assessment changes; the score is not calibrated.",
        interval="day" if range_days <= 30 else "week" if range_days <= 90 else "month",
        points=risk_points,
        assessments_in_scope=len(latest_trend_revision),
    )

    investigation_rows = []
    monitoring_rows = []
    if asset_ids:
        investigation_rows = (visible_investigations(db)
                              .filter(Investigation.asset_id.in_(asset_ids), Investigation.created_at >= start,
                                      Investigation.created_at <= end)
                              .order_by(Investigation.created_at, Investigation.id).all())
        monitoring_query = (db.query(MonitoringRun)
                            .join(Investigation, Investigation.id == MonitoringRun.investigation_id)
                            .filter(Investigation.asset_id.in_(asset_ids), MonitoringRun.scheduled_for >= start,
                                    MonitoringRun.scheduled_for <= end))
        if live_projection():
            monitoring_query = monitoring_query.filter(Investigation.mode == "live")
        monitoring_rows = monitoring_query.order_by(MonitoringRun.scheduled_for, MonitoringRun.id).all()
    investigation_groups: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for item in investigation_rows:
        bucket = _bucket_start(item.created_at, range_days).isoformat()
        investigation_groups[bucket][item.status] += 1
        investigation_groups[bucket]["total"] += 1
    monitoring_groups: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for item in monitoring_rows:
        bucket = _bucket_start(item.scheduled_for, range_days).isoformat()
        monitoring_groups[bucket][item.status] += 1
        monitoring_groups[bucket]["total"] += 1
    periods = sorted(set(investigation_groups) | set(monitoring_groups))
    workflow_points = [{
        "period_start": period,
        "investigations": dict(investigation_groups.get(period, {})),
        "monitoring_runs": dict(monitoring_groups.get(period, {})),
    } for period in periods]
    workflow_state = "empty" if not investigation_rows and not monitoring_rows else "available"
    if any(item.status in {"queued", "running", "partial", "failed"} for item in investigation_rows) or any(item.status in {"queued", "running", "partial", "failed"} for item in monitoring_rows):
        workflow_state = "partial"
    workflow_trend = _metric(
        workflow_state,
        "Investigations created and monitoring occurrences scheduled for registered assets in the selected window, grouped by the same calendar interval.",
        start, end, range_days,
        "Counts are saved jobs/runs, not proof that every scheduled occurrence was delivered on time.",
        interval="day" if range_days <= 30 else "week" if range_days <= 90 else "month",
        points=workflow_points,
        investigations_count=len(investigation_rows),
        monitoring_run_count=len(monitoring_rows),
    )

    incidents = (visible_incidents(db).filter(Incident.created_at >= start, Incident.created_at <= end)
                 .order_by(Incident.created_at, Incident.id).all())
    incident_ids = {item.id for item in incidents}
    events = (db.query(IncidentEvent).filter(IncidentEvent.incident_id.in_(incident_ids),
                                              IncidentEvent.event_type == "status_changed")
              .order_by(IncidentEvent.created_at, IncidentEvent.id).all()) if incident_ids else []
    triage_seconds: dict[str, float] = {}
    resolution_seconds: dict[str, float] = {}
    incident_by_id = {item.id: item for item in incidents}
    for event in events:
        incident = incident_by_id.get(event.incident_id)
        if incident is None:
            continue
        target_status = (event.details_json or {}).get("to")
        delta = ((_utc(event.created_at) or end) - (_utc(incident.created_at) or end)).total_seconds()
        if delta < 0:
            continue
        if target_status == "triaged":
            triage_seconds.setdefault(incident.id, delta)
        if target_status in {"resolved", "closed"}:
            resolution_seconds.setdefault(incident.id, delta)
    incident_state = "empty" if not incidents else "available"
    if incidents and (len(triage_seconds) < len(incidents) or len(resolution_seconds) < len(incidents)):
        incident_state = "partial"
    incident_timings = _metric(
        incident_state,
        "Incident cohort created within the selected window. Durations use the first saved status_changed event to triaged and resolved/closed.",
        start, end, range_days,
        "Only saved transition events are measured; unresolved cases are pending, not zero-duration. Missing transition events are not inferred from updated_at.",
        incident_count=len(incidents),
        triaged_count=len(triage_seconds),
        triage_pending_or_unrecorded_count=len(incidents) - len(triage_seconds),
        triage_mean_seconds=round(mean(triage_seconds.values()), 2) if triage_seconds else None,
        triage_median_seconds=round(median(triage_seconds.values()), 2) if triage_seconds else None,
        resolved_count=len(resolution_seconds),
        unresolved_or_unrecorded_count=len(incidents) - len(resolution_seconds),
        resolution_mean_seconds=round(mean(resolution_seconds.values()), 2) if resolution_seconds else None,
        resolution_median_seconds=round(median(resolution_seconds.values()), 2) if resolution_seconds else None,
    )

    known_criticalities = ("critical", "high", "medium", "low")
    criticality_counts = {key: sum(asset.criticality == key for asset in assets) for key in known_criticalities}
    criticality_counts["unknown"] = sum(asset.criticality not in known_criticalities for asset in assets)
    if not assets:
        criticality_state = "empty"
    elif criticality_counts["unknown"]:
        criticality_state = "partial"
    else:
        criticality_state = "available"
    asset_distribution = _metric(
        criticality_state,
        "Current criticality values on all registered assets as of the scorecard end time.",
        start, end, range_days,
        "Unknown criticality remains explicitly unknown and is not treated as low risk.",
        counts=criticality_counts,
        asset_count=len(assets),
    )

    current_finding_ids = {item.id for item in selected_findings.values()}
    mappings = (db.query(FindingControlMapping).filter(FindingControlMapping.finding_id.in_(current_finding_ids)).all()
                if current_finding_ids else [])
    mapping_by_finding: dict[str, list[FindingControlMapping]] = defaultdict(list)
    for mapping in mappings:
        mapping_by_finding[mapping.finding_id].append(mapping)
    mapped = {
        finding_id for finding_id, rows in mapping_by_finding.items()
        if any(row.status not in {"rejected", "not_applicable"} for row in rows)
    }
    validated = {finding_id for finding_id, rows in mapping_by_finding.items() if any(row.status == "validated" for row in rows)}
    validated_controls = {row.control_id for row in mappings if row.status == "validated"}
    finding_denominator = len(current_findings.values()) if count_total is not None else 0
    if finding_denominator == 0:
        control_state = "empty" if finding_state == "empty" or count_total == 0 else "unavailable"
        mapped_percent = validated_percent = None
    else:
        mapped_percent = round(len(mapped) * 100 / finding_denominator, 2)
        validated_percent = round(len(validated) * 100 / finding_denominator, 2)
        control_state = "available" if len(validated) == finding_denominator else "partial"
        if finding_state in {"partial", "stale", "unavailable"}:
            control_state = finding_state
    from app.services.security_controls import SECURITY_CONTROLS
    control_coverage = _metric(
        control_state,
        "Finding-control mappings for unique findings in the latest in-window observations; validation counts require the existing evidence-backed validated state.",
        start, end, range_days,
        "This measures recorded mapping coverage only. It is not a control-effectiveness, certification, or framework-compliance assessment.",
        findings_in_scope=finding_denominator,
        findings_with_mapping=len(mapped) if finding_denominator else None,
        findings_with_validated_mapping=len(validated) if finding_denominator else None,
        mapped_finding_percent=mapped_percent,
        validated_finding_percent=validated_percent,
        catalog_version="cyberlens-controls-1.0",
        catalog_control_count=len(SECURITY_CONTROLS),
        controls_with_validated_findings=len(validated_controls) if finding_denominator else None,
    )

    provider_health = _build_provider_health(db, assets, start, end, range_days)
    data_modes = sorted({item.mode for item in investigation_rows})
    return {
        "schema_version": "cyberlens-posture-1.0",
        "generated_at": _iso(end),
        "range_days": range_days,
        "window_start": _iso(start),
        "window_end": _iso(end),
        "data_scope": {
            "source": "PostgreSQL saved workspace records",
            "asset_count": len(assets),
            "investigation_count": len(investigation_rows),
            "data_modes": data_modes,
        },
        "overall_risk": overall_risk,
        "assessment_coverage": assessment_coverage,
        "unassessed_categories": unassessed_categories,
        "high_critical_findings": current_findings,
        "repeated_findings": repeated_findings,
        "risk_trend": risk_trend,
        "workflow_trend": workflow_trend,
        "incident_timings": incident_timings,
        "provider_health": provider_health,
        "asset_criticality": asset_distribution,
        "security_control_coverage": control_coverage,
    }
