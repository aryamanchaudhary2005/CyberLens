"""Deterministic risk scoring and immutable assessment history."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
import hashlib
import json
import re
from typing import Any, Iterable, Mapping, Sequence

from app.models import CollectorRun, EvidenceSnapshot, Finding, Investigation, RiskAssessment, RiskAssessmentRevision

RISK_VERSION = "cyberlens-academic-1.0"
WEIGHTS: dict[str, int] = {"vulnerabilities": 35, "reputation": 30, "tls_web": 15, "breach_exposure": 10, "dns_email": 10}
SEVERITY_VALUES = {"informational": 0, "info": 0, "low": 20, "medium": 45, "high": 70, "critical": 95}
SEVERITY_FLOORS = {"medium": 25, "high": 50, "critical": 75}
SUCCESS_STATUSES = {"success", "no_match", "partial"}
CATEGORY_COLLECTORS = {"vulnerabilities": {"nvd_kev", "osv"}, "reputation": {"reputation", "spamhaus_drop", "cins_army", "openphish"}, "tls_web": {"web_tls"}, "breach_exposure": {"hibp", "xposedornot"}, "dns_email": {"dns_rdap"}}
_CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)


@dataclass(frozen=True)
class RiskFindingRecord:
    id: str
    fingerprint: str
    category: str
    severity: str
    applicability: str = "applies"
    details: Mapping[str, Any] = field(default_factory=dict)
    source: str = ""
    observed_at: str | None = None
    evidence_id: str | None = None
    epss_score: float | None = None
    epss_percentile: float | None = None
    epss_observed_at: str | None = None
    epss_provider_status: str | None = None
    epss_freshness: str | None = None


@dataclass(frozen=True)
class RiskEvidenceRecord:
    id: str
    source: str
    observed_at: str | None
    provenance: Mapping[str, Any] = field(default_factory=dict)


def risk_band(score: float) -> str:
    if score < 25:
        return "low"
    if score < 50:
        return "medium"
    if score < 75:
        return "high"
    return "critical"


def _iso(value: Any) -> str | None:
    if value is None:
        return None
    return value.isoformat() if isinstance(value, datetime) else str(value)


def _status_map(statuses: Mapping[str, str] | Iterable[tuple[str, str]]) -> dict[str, str]:
    return dict(statuses) if isinstance(statuses, Mapping) else dict(statuses)


def _record(value: RiskFindingRecord | Mapping[str, Any]) -> RiskFindingRecord:
    if isinstance(value, RiskFindingRecord):
        return value
    return RiskFindingRecord(
        id=str(value.get("id", "")), fingerprint=str(value.get("fingerprint", value.get("id", ""))),
        category=str(value.get("category", "")), severity=str(value.get("severity", "")).lower(),
        applicability=str(value.get("applicability", "applies")), details=value.get("details", value.get("details_json", {})) or {},
        source=str(value.get("source", "")), observed_at=_iso(value.get("observed_at")), evidence_id=value.get("evidence_id"),
        epss_score=value.get("epss_score"), epss_percentile=value.get("epss_percentile"),
        epss_observed_at=_iso(value.get("epss_observed_at")), epss_provider_status=value.get("epss_provider_status"),
        epss_freshness=value.get("epss_freshness"),
    )


def _evidence_record(value: RiskEvidenceRecord | Mapping[str, Any]) -> RiskEvidenceRecord:
    if isinstance(value, RiskEvidenceRecord):
        return value
    return RiskEvidenceRecord(
        id=str(value.get("id", "")), source=str(value.get("source", "")), observed_at=_iso(value.get("observed_at")),
        provenance=value.get("provenance", value.get("evidence_json", {}).get("provenance", {})) or {},
    )


def _vulnerability_identity_map(findings: Sequence[RiskFindingRecord]) -> dict[str, str]:
    """Join explicit CVE aliases only within the same inventoried component."""
    parents: dict[str, str] = {}

    def find(value: str) -> str:
        parents.setdefault(value, value)
        if parents[value] != value:
            parents[value] = find(parents[value])
        return parents[value]

    def union(left: str, right: str) -> None:
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            # Lexicographic roots make the result independent of input order.
            first, second = sorted((left_root, right_root))
            parents[second] = first

    aliases_by_finding: dict[str, tuple[str, list[str]]] = {}
    for item in findings:
        if item.category != "vulnerabilities":
            continue
        details = item.details
        component_id = details.get("component_id")
        raw_aliases = details.get("aliases", [])
        osv = details.get("osv")
        if isinstance(osv, Mapping):
            raw_aliases = list(raw_aliases if isinstance(raw_aliases, list) else []) + list(osv.get("aliases", []))
        if not isinstance(raw_aliases, (list, tuple, set)):
            raw_aliases = []
        cve_id = details.get("cve_id")
        values = [str(value).upper() for value in raw_aliases if isinstance(value, str) and _CVE_PATTERN.fullmatch(value)]
        if isinstance(cve_id, str) and _CVE_PATTERN.fullmatch(cve_id):
            values.append(cve_id.upper())
        normalized = sorted(set(values))
        if component_id is None or not normalized:
            continue
        component = str(component_id)
        nodes = [f"{component}\0{alias}" for alias in normalized]
        for node in nodes:
            find(node)
        for node in nodes[1:]:
            union(nodes[0], node)
        aliases_by_finding[item.id] = (component, nodes)

    result: dict[str, str] = {}
    for item in findings:
        aliases = aliases_by_finding.get(item.id)
        result[item.id] = find(aliases[1][0]) if aliases else item.fingerprint
    return result


def score_records(
    findings: Sequence[RiskFindingRecord | Mapping[str, Any]], collector_statuses: Mapping[str, str] | Iterable[tuple[str, str]],
    evidence: Sequence[RiskEvidenceRecord | Mapping[str, Any]] = (), *, weights: Mapping[str, float] | None = None,
    policy_version: str = RISK_VERSION,
) -> dict[str, Any]:
    """Score explicit records without reading application state."""
    selected_weights = dict(weights or WEIGHTS)
    statuses = _status_map(collector_statuses)
    all_findings = [_record(item) for item in findings]
    identity_by_finding = _vulnerability_identity_map(all_findings)
    unique: dict[str, RiskFindingRecord] = {}
    kev_priority: dict[str, RiskFindingRecord] = {}
    for finding in all_findings:
        severity = finding.severity.lower()
        identity = identity_by_finding.get(finding.id, finding.fingerprint)
        if finding.applicability != "applies":
            continue
        if finding.category == "vulnerabilities" and finding.details.get("kev"):
            current_kev = kev_priority.get(identity)
            if current_kev is None or finding.id < current_kev.id:
                kev_priority[identity] = finding
        if severity not in SEVERITY_VALUES:
            continue
        current = unique.get(identity)
        if current is None or (SEVERITY_VALUES[severity], finding.id) > (SEVERITY_VALUES[current.severity.lower()], current.id):
            unique[identity] = finding

    assessed: list[str] = []
    excluded: list[str] = []
    category_scores: dict[str, int] = {}
    category_items: dict[str, list[RiskFindingRecord]] = {}
    coverage: dict[str, dict[str, Any]] = {}
    for category, collectors in CATEGORY_COLLECTORS.items():
        category_statuses = {name: statuses[name] for name in sorted(collectors) if name in statuses}
        usable = bool(category_statuses) and any(status in SUCCESS_STATUSES for status in category_statuses.values())
        coverage[category] = {"collectors": category_statuses, "covered": usable}
        if not usable:
            excluded.append(category)
            continue
        assessed.append(category)
        items = sorted((item for item in unique.values() if item.category == category), key=lambda item: item.id)
        category_items[category] = items
        category_scores[category] = max((SEVERITY_VALUES[item.severity.lower()] for item in items), default=0)

    if not assessed:
        score = None
        band = "insufficient_data"
    else:
        weight_total = sum(selected_weights.get(category, 0) for category in assessed)
        score = sum(selected_weights.get(category, 0) * category_scores[category] for category in assessed) / weight_total if weight_total else None
        if score is not None:
            for finding in unique.values():
                floor = SEVERITY_FLOORS.get(finding.severity.lower())
                if floor is not None:
                    score = max(score, floor)
            if kev_priority:
                score = max(score, 90)
            score = round(min(score, 100), 2)
        band = risk_band(score) if score is not None else "insufficient_data"

    evidence_records = [_evidence_record(item) for item in evidence]
    source_coverage: dict[str, dict[str, Any]] = {}
    freshness: dict[str, dict[str, Any]] = {}
    for item in evidence_records:
        provenance = dict(item.provenance)
        source_coverage[item.source or provenance.get("source", item.id)] = {"status": provenance.get("status", "unknown"), "provider": provenance.get("provider", item.source), "provider_version": provenance.get("provider_version", "unspecified")}
        freshness[item.id] = {"source": item.source, "observed_at": item.observed_at, "state": (provenance.get("freshness") or {}).get("state", "unknown"), "source_timestamp": (provenance.get("freshness") or {}).get("source_timestamp")}

    contributors: list[dict[str, Any]] = []
    for category in assessed:
        items = category_items.get(category, [])
        if not items:
            continue
        strongest = max(SEVERITY_VALUES[item.severity.lower()] for item in items)
        for item in items:
            if SEVERITY_VALUES[item.severity.lower()] != strongest:
                continue
            contributors.append({"finding_id": item.id, "category": category, "severity": item.severity.lower(), "severity_value": SEVERITY_VALUES[item.severity.lower()], "source": item.source, "evidence_id": item.evidence_id, "observed_at": item.observed_at, "category_score": category_scores[category], "weight_percent": selected_weights.get(category, 0), "kev_floor": bool(item.details.get("kev")) and category == "vulnerabilities"})
    contributor_ids = {item["finding_id"] for item in contributors}
    for item in sorted(kev_priority.values(), key=lambda finding: finding.id):
        if item.id in contributor_ids:
            continue
        contributors.append({"finding_id": item.id, "category": "vulnerabilities", "severity": item.severity.lower(),
            "severity_value": SEVERITY_VALUES.get(item.severity.lower()), "source": item.source,
            "evidence_id": item.evidence_id, "observed_at": item.observed_at,
            "category_score": category_scores.get("vulnerabilities", 0),
            "weight_percent": selected_weights.get("vulnerabilities", 0), "kev_floor": True,
            "cvss_unavailable": item.severity.lower() not in SEVERITY_VALUES})
    contributors.sort(key=lambda item: (item["category"], item["finding_id"]))
    vulnerability_intelligence = []
    for item in sorted((item for item in all_findings if item.category == "vulnerabilities"), key=lambda row: (row.fingerprint, row.id)):
        details = item.details
        osv = details.get("osv") if isinstance(details.get("osv"), Mapping) else None
        if osv is None and details.get("advisory_id"):
            osv = {
                "advisory_id": details.get("advisory_id"), "aliases": details.get("aliases", []),
                "package": details.get("package"), "affected": details.get("affected", []),
                "fixed_versions": details.get("fixed_versions", []), "references": details.get("references", []),
                "severity_metadata": details.get("severity_metadata", []),
                "published": details.get("published"), "modified": details.get("modified"),
                "withdrawn": details.get("withdrawn"), "observed_at": details.get("observed_at"),
                "provider_status": details.get("provider_status", "unknown"),
                "freshness": details.get("freshness", "unknown"),
                "provider_version": details.get("provider_version", "unknown"),
                "advisory_status": details.get("advisory_status", "unknown"),
            }
        vulnerability_intelligence.append({
            "finding_id": item.id,
            "cve_id": details.get("cve_id"),
            "cvss": {"version": details.get("cvss_version"), "score": details.get("cvss_score"),
                     "severity": item.severity, "vector": details.get("vector")},
            "epss": {"score": item.epss_score if item.epss_score is not None else details.get("epss_score"),
                     "percentile": item.epss_percentile if item.epss_percentile is not None else details.get("epss_percentile"),
                     "observed_at": item.epss_observed_at or details.get("epss_observed_at"),
                     "provider_status": item.epss_provider_status or details.get("epss_provider_status", "not_assessed"),
                     "freshness": item.epss_freshness or details.get("epss_freshness", "unknown"),
                     "source_date": details.get("epss_source_date"), "provider": details.get("epss_provider", "FIRST EPSS API"),
                     "provider_version": details.get("epss_provider_version", "FIRST API v1"),
                     "cache_state": details.get("epss_cache_state", "unknown")},
            "kev": details.get("kev"),
            "osv": osv,
            "applicability": item.applicability,
            "evidence_id": item.evidence_id,
        })
    explanation = {"weights_percent": selected_weights, "severity_values": SEVERITY_VALUES, "severity_floors": SEVERITY_FLOORS, "kev_floor": 90, "method": "Highest applicable severity per category; weighted average over assessed categories; severity floors applied. An applicable CISA KEV listing applies a score floor of 90 even when CVSS severity is unavailable.", "metric_notice": "Academic prioritization score; not a probability of compromise or a validated industry metric.", "calibration_notice": "No calibration claim: no labeled incident outcome set is stored for this policy.", "rule_version": policy_version, "contributors": contributors, "freshness": freshness, "source_coverage": source_coverage, "coverage": coverage, "excluded_categories": excluded, "vulnerability_intelligence": vulnerability_intelligence, "epss_notice": "EPSS estimates the probability of exploitation in the wild over the next 30 days. It is not evidence that exploitation or compromise occurred, and it does not alter the risk score."}
    # Keep the version 1 API meaning: every deduplicated applicable finding in
    # a covered category is listed.  The detailed contributor records above
    # identify which of those findings supplied the category maximum.
    contributing_ids = sorted({item.id for item in unique.values() if item.category in assessed} |
                              {item.id for item in kev_priority.values() if "vulnerabilities" in assessed})
    return {"version": policy_version, "score": score, "band": band, "assessed_categories": assessed, "excluded_categories": excluded, "category_scores": category_scores, "contributing_finding_ids": contributing_ids, "explanation": explanation}


def _canonical_input(findings: Sequence[RiskFindingRecord], statuses: Mapping[str, str], evidence: Sequence[RiskEvidenceRecord], weights: Mapping[str, float], policy_version: str) -> str:
    payload = {"policy_version": policy_version, "weights": dict(sorted(weights.items())), "collector_statuses": dict(sorted(statuses.items())), "findings": [asdict(item) for item in sorted(findings, key=lambda item: (item.fingerprint, item.id))], "evidence": [asdict(item) for item in sorted(evidence, key=lambda item: (item.id, item.source))]}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def investigation_inputs(db, investigation: Investigation) -> tuple[list[RiskFindingRecord], dict[str, str], list[RiskEvidenceRecord]]:
    runs = {run.collector: run.status for run in db.query(CollectorRun).filter_by(investigation_id=investigation.id).all()}
    findings = [RiskFindingRecord(id=item.id, fingerprint=item.fingerprint, category=item.category, severity=item.severity,
        applicability=item.applicability, details=item.details_json, source=item.source, observed_at=_iso(item.observed_at),
        evidence_id=item.evidence_id, epss_score=item.epss_score, epss_percentile=item.epss_percentile,
        epss_observed_at=_iso(item.epss_observed_at), epss_provider_status=item.epss_provider_status,
        epss_freshness=item.epss_freshness) for item in db.query(Finding).filter_by(investigation_id=investigation.id).all()]
    evidence = [RiskEvidenceRecord(id=item.id, source=item.source, observed_at=_iso(item.observed_at), provenance=(item.evidence_json or {}).get("provenance", {})) for item in db.query(EvidenceSnapshot).filter_by(investigation_id=investigation.id).all()]
    return findings, runs, evidence


def assess_investigation(db, investigation: Investigation) -> RiskAssessment:
    findings, runs, evidence = investigation_inputs(db, investigation)
    result = score_records(findings, runs, evidence)
    existing = db.query(RiskAssessment).filter_by(investigation_id=investigation.id).first()
    if existing is None:
        existing = RiskAssessment(investigation_id=investigation.id, version=RISK_VERSION, band=result["band"])
        db.add(existing)
    existing.version = result["version"]
    existing.score = result["score"]
    existing.band = result["band"]
    existing.weights_json = result["explanation"]["weights_percent"]
    existing.assessed_categories = result["assessed_categories"]
    existing.excluded_categories = result["excluded_categories"]
    existing.category_scores = result["category_scores"]
    existing.contributing_finding_ids = result["contributing_finding_ids"]
    existing.explanation_json = result["explanation"]
    db.flush()
    fingerprint = _canonical_input(findings, runs, evidence, WEIGHTS, RISK_VERSION)
    revision = db.query(RiskAssessmentRevision).filter_by(investigation_id=investigation.id, input_fingerprint=fingerprint).first()
    if revision is None:
        latest = db.query(RiskAssessmentRevision).filter_by(investigation_id=investigation.id).order_by(RiskAssessmentRevision.revision_number.desc()).first()
        db.add(RiskAssessmentRevision(investigation_id=investigation.id, revision_number=(latest.revision_number + 1 if latest else 1), input_fingerprint=fingerprint, version=result["version"], score=result["score"], band=result["band"], weights_json=result["explanation"]["weights_percent"], assessed_categories=result["assessed_categories"], excluded_categories=result["excluded_categories"], category_scores=result["category_scores"], contributing_finding_ids=result["contributing_finding_ids"], explanation_json=result["explanation"]))
    return existing


def sensitivity_analysis(findings: Sequence[RiskFindingRecord | Mapping[str, Any]], collector_statuses: Mapping[str, str] | Iterable[tuple[str, str]], evidence: Sequence[RiskEvidenceRecord | Mapping[str, Any]] = (), *, delta: float = 0.2) -> dict[str, Any]:
    """Show how a ±delta change to one category weight affects the score."""
    if not 0 < delta < 1:
        raise ValueError("delta must be between 0 and 1")
    baseline = score_records(findings, collector_statuses, evidence)
    variants: list[dict[str, Any]] = []
    for category, weight in WEIGHTS.items():
        lower_weights, upper_weights = dict(WEIGHTS), dict(WEIGHTS)
        lower_weights[category], upper_weights[category] = weight * (1 - delta), weight * (1 + delta)
        lower = score_records(findings, collector_statuses, evidence, weights=lower_weights)
        upper = score_records(findings, collector_statuses, evidence, weights=upper_weights)
        variants.append({"category": category, "weight_percent": weight, "lower_weight_percent": lower_weights[category], "upper_weight_percent": upper_weights[category], "lower_score": lower["score"], "upper_score": upper["score"], "lower_delta": None if baseline["score"] is None or lower["score"] is None else round(lower["score"] - baseline["score"], 2), "upper_delta": None if baseline["score"] is None or upper["score"] is None else round(upper["score"] - baseline["score"], 2)})
    return {"version": RISK_VERSION, "baseline_score": baseline["score"], "variants": variants}
