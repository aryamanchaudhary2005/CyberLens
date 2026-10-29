"""Side-effect-free remediation scenarios over saved, evidence-backed findings."""

from __future__ import annotations

import re
from typing import Any, Mapping

from sqlalchemy.orm import Session

from app.models import CollectorRun, EvidenceSnapshot, Finding, Investigation, InvestigationAttempt, RiskAssessment
from app.services.risk import (
    RISK_VERSION,
    RiskEvidenceRecord,
    RiskFindingRecord,
    WEIGHTS,
    investigation_inputs,
    score_records,
)

ACTION_LABELS = {
    "patch_applicable_cve": "Patch applicable CVE",
    "fix_security_headers": "Fix security headers",
    "replace_expired_or_mismatched_certificate": "Replace expired or mismatched certificate",
    "fix_spf_or_dmarc": "Fix SPF or DMARC configuration",
    "resolve_validated_reputation_finding": "Resolve validated reputation finding",
    "resolve_verified_breach_issue": "Resolve verified breach-related issue",
}

ACTION_ASSUMPTIONS = {
    "patch_applicable_cve": "The selected, analyst-confirmed CVE is patched to a version outside the affected range; no other software or findings change.",
    "fix_security_headers": "The observed missing header control is configured with a site-appropriate value and verified; other website controls remain unchanged.",
    "replace_expired_or_mismatched_certificate": "A current certificate matching the authorized hostname is installed and verified; other TLS settings remain unchanged.",
    "fix_spf_or_dmarc": "The specifically observed SPF or DMARC configuration issue is corrected and verified; mail senders and other DNS records remain unchanged.",
    "resolve_validated_reputation_finding": "The directly observed adverse reputation verdict is resolved and a subsequent provider check no longer reports it; no unrelated reputation signals change.",
    "resolve_verified_breach_issue": "The account-protection issue associated with the verified breach record is remediated; the historical breach evidence is retained and is not erased.",
}

SIMULATION_ASSUMPTIONS = [
    "This is a hypothetical projection using the existing risk policy; it is not a forecast or guarantee of remediation effectiveness.",
    "Only the selected finding is removed from the in-memory scoring inputs; all other findings, evidence, collector coverage, weights, and policy version are unchanged.",
    "No stored finding, report, evidence snapshot, risk assessment, investigation, incident, or remediation task is modified.",
    "A real remediation must be independently verified with a new investigation before saved risk can change.",
]

_CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)
class SimulationError(ValueError):
    """A requested action cannot be grounded in the selected saved finding."""


def _normal_headers(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    return {str(key).lower(): item for key, item in value.items()}


def _header_control(title: str, observed: Mapping[str, Any]) -> str | None:
    value = title.casefold()
    if "strict-transport-security" in value or "hsts" in value:
        return "strict-transport-security" if not observed.get("strict-transport-security") else None
    if "content security policy" in value or "content-security-policy" in value:
        return "content-security-policy" if not observed.get("content-security-policy") else None
    if "content type protection" in value or "x-content-type-options" in value:
        return "x-content-type-options" if not observed.get("x-content-type-options") else None
    if "framing protection" in value or "frame-ancestors" in value or "x-frame-options" in value:
        csp = str(observed.get("content-security-policy") or "").casefold()
        return "x-frame-options" if not observed.get("x-frame-options") and "frame-ancestors" not in csp else None
    return None


def _spf_dmarc_target(title: str, evidence: Mapping[str, Any]) -> str | None:
    normalized = title.casefold()
    config = evidence.get("email_configuration")
    config = config if isinstance(config, Mapping) else {}
    records = evidence.get("records")
    records = records if isinstance(records, Mapping) else {}
    if "spf" in normalized:
        record = records.get("TXT", {})
        values = record.get("values", []) if isinstance(record, Mapping) else []
        found = config.get("spf_present")
        if found is None:
            found = any(isinstance(item, str) and item.casefold().startswith("v=spf1") for item in values)
        if "not found" in normalized or "missing" in normalized:
            return "SPF" if config.get("mx_present", True) and found is False else None
        if "monitor only" in normalized:
            return "SPF" if any(isinstance(item, str) and item.casefold().strip() == "v=spf1 -all" for item in values) else None
    if "dmarc" in normalized:
        record = records.get("DMARC", {})
        values = record.get("values", []) if isinstance(record, Mapping) else []
        found = config.get("dmarc_present")
        if found is None:
            found = any(isinstance(item, str) and item.casefold().startswith("v=dmarc1") for item in values)
        if "not found" in normalized or "missing" in normalized:
            return "DMARC" if config.get("mx_present", True) and found is False else None
        if "monitor only" in normalized:
            return "DMARC" if any(isinstance(item, str) and re.search(r"(?:^|;)\s*p\s*=\s*none(?:\s*;|$)", item, re.IGNORECASE) for item in values) else None
    return None


def _finding_mapping(finding: Finding | RiskFindingRecord | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(finding, Finding):
        return {
            "id": finding.id, "fingerprint": finding.fingerprint, "category": finding.category,
            "severity": finding.severity, "applicability": finding.applicability,
            "details": finding.details_json or {}, "source": finding.source, "observed_at": finding.observed_at,
            "evidence_id": finding.evidence_id, "title": finding.title,
        }
    if isinstance(finding, RiskFindingRecord):
        return {
            "id": finding.id, "fingerprint": finding.fingerprint, "category": finding.category,
            "severity": finding.severity, "applicability": finding.applicability,
            "details": finding.details, "source": finding.source, "observed_at": finding.observed_at,
            "evidence_id": finding.evidence_id,
        }
    return dict(finding)


def _linked_evidence_ids(finding: Mapping[str, Any]) -> list[str]:
    details = finding.get("details") or finding.get("details_json") or {}
    ids = [finding.get("evidence_id")]
    if isinstance(details, Mapping):
        additional = details.get("additional_evidence_ids", [])
        if isinstance(additional, list):
            ids.extend(additional)
    return list(dict.fromkeys(value for value in ids if isinstance(value, str) and value))


def _evidence_matches_action(
    action: str,
    finding: Mapping[str, Any],
    evidence_row: EvidenceSnapshot,
    collector_statuses: Mapping[str, str],
) -> bool:
    details = finding.get("details") or finding.get("details_json") or {}
    details = details if isinstance(details, Mapping) else {}
    evidence = evidence_row.evidence_json if isinstance(evidence_row.evidence_json, Mapping) else {}
    provenance = evidence.get("provenance", {})
    provenance = provenance if isinstance(provenance, Mapping) else {}
    provenance_status = provenance.get("status")
    if provenance_status is not None and provenance_status not in {"success", "partial"}:
        return False

    if action == "patch_applicable_cve":
        return (
            finding.get("category") == "vulnerabilities"
            and finding.get("applicability") == "applies"
            and isinstance(details.get("cve_id"), str)
            and _CVE_PATTERN.fullmatch(details["cve_id"]) is not None
            and collector_statuses.get("nvd_kev") in {"success", "partial"}
        )

    if action == "fix_security_headers":
        headers = _normal_headers(evidence.get("security_headers"))
        return (
            finding.get("category") == "tls_web"
            and finding.get("applicability") == "applies"
            and isinstance(evidence.get("security_headers"), Mapping)
            and _header_control(str(finding.get("title", "")), headers) is not None
            and collector_statuses.get("web_tls") in {"success", "partial"}
        )

    if action == "replace_expired_or_mismatched_certificate":
        certificate = evidence.get("certificate", {})
        certificate = certificate if isinstance(certificate, Mapping) else {}
        expired = certificate.get("expired", details.get("expired"))
        hostname_match = certificate.get("hostname_match", details.get("hostname_match"))
        return (
            finding.get("category") == "tls_web"
            and finding.get("applicability") == "applies"
            and "certificate" in str(finding.get("title", "")).casefold()
            and (expired is True or hostname_match is False)
            and collector_statuses.get("web_tls") in {"success", "partial"}
        )

    if action == "fix_spf_or_dmarc":
        return (
            finding.get("category") == "dns_email"
            and finding.get("applicability") == "applies"
            and _spf_dmarc_target(str(finding.get("title", "")), evidence) is not None
            and collector_statuses.get("dns_rdap") in {"success", "partial"}
        )

    if action == "resolve_validated_reputation_finding":
        stats = evidence.get("analysis_stats", {})
        stats = stats if isinstance(stats, Mapping) else {}
        malicious = details.get("malicious", stats.get("malicious", 0))
        suspicious = details.get("suspicious", stats.get("suspicious", 0))
        return (
            finding.get("category") == "reputation"
            and finding.get("applicability") == "applies"
            and details.get("asset_context", evidence.get("asset_context")) == "direct"
            and (isinstance(malicious, int) and malicious > 0 or isinstance(suspicious, int) and suspicious > 0)
            and collector_statuses.get("reputation") == "success"
        )

    if action == "resolve_verified_breach_issue":
        collector = "hibp"
        breaches = evidence.get("breaches")
        count = details.get("breach_count", evidence.get("breach_count"))
        if finding.get("source") == "XposedOrNot community API":
            collector = "xposedornot"
            breaches = evidence.get("records")
            count = details.get("breach_count", evidence.get("verified_record_count"))
            if isinstance(breaches, list):
                breaches = [item for item in breaches if isinstance(item, Mapping) and item.get("verified") is True]
        return (
            finding.get("category") == "breach_exposure"
            and finding.get("applicability") == "applies"
            and isinstance(breaches, list) and len(breaches) > 0
            and isinstance(count, int) and count > 0
            and collector_statuses.get(collector) == "success"
        )
    return False


def _matching_evidence(
    action: str,
    finding: Mapping[str, Any],
    evidence_by_id: Mapping[str, EvidenceSnapshot],
    collector_statuses: Mapping[str, str],
) -> EvidenceSnapshot | None:
    for evidence_id in _linked_evidence_ids(finding):
        row = evidence_by_id.get(evidence_id)
        if row is not None and _evidence_matches_action(action, finding, row, collector_statuses):
            return row
    return None


def _simulation_score(result: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "policy_version": result["version"], "score": result["score"], "band": result["band"],
        "category_scores": result["category_scores"], "assessed_categories": result["assessed_categories"],
        "excluded_categories": result["excluded_categories"],
    }


def _inputs(db: Session, investigation: Investigation):
    findings, statuses, evidence = investigation_inputs(db, investigation)
    assessment = db.query(RiskAssessment).filter_by(investigation_id=investigation.id).first()
    saved_coverage = (assessment.explanation_json or {}).get("coverage", {}) if assessment else {}
    if isinstance(saved_coverage, Mapping):
        recorded_statuses = {}
        for category in saved_coverage.values():
            if isinstance(category, Mapping) and isinstance(category.get("collectors"), Mapping):
                recorded_statuses.update(category["collectors"])
        if recorded_statuses:
            statuses = recorded_statuses
        else:
            statuses = _latest_collector_statuses(db, investigation, statuses)
    else:
        statuses = _latest_collector_statuses(db, investigation, statuses)
    finding_rows = db.query(Finding).filter_by(investigation_id=investigation.id).all()
    evidence_rows = db.query(EvidenceSnapshot).filter_by(investigation_id=investigation.id).all()
    evidence_by_id = {item.id: item for item in evidence_rows}
    finding_rows_by_id = {item.id: item for item in finding_rows}
    return findings, statuses, evidence, evidence_by_id, finding_rows_by_id


def _latest_collector_statuses(db: Session, investigation: Investigation, fallback: Mapping[str, str]) -> dict[str, str]:
    rows = (db.query(CollectorRun, InvestigationAttempt.attempt_number)
            .outerjoin(InvestigationAttempt, CollectorRun.attempt_id == InvestigationAttempt.id)
            .filter(CollectorRun.investigation_id == investigation.id).all())
    rows.sort(key=lambda item: (
        item[1] or 0,
        (item[0].finished_at or item[0].started_at).isoformat() if item[0].finished_at or item[0].started_at else "",
        item[0].id,
    ), reverse=True)
    latest = {}
    for run, _attempt_number in rows:
        latest.setdefault(run.collector, run.status)
    return latest or dict(sorted(fallback.items()))


def simulation_options(db: Session, investigation: Investigation) -> list[dict[str, Any]]:
    findings, statuses, _, evidence_by_id, finding_rows_by_id = _inputs(db, investigation)
    options = []
    for record in sorted(findings, key=lambda item: (finding_rows_by_id[item.id].title.casefold(), item.id)):
        finding = _finding_mapping(finding_rows_by_id[record.id])
        for action, label in ACTION_LABELS.items():
            evidence_row = _matching_evidence(action, finding, evidence_by_id, statuses)
            if evidence_row is None:
                continue
            options.append({
                "action": action, "label": label, "finding_id": record.id,
                "finding_title": finding_rows_by_id[record.id].title,
                "category": record.category, "evidence_id": evidence_row.id, "evidence_source": evidence_row.source,
                "evidence_observed_at": evidence_row.observed_at,
            })
    return options


def simulate_remediation(db: Session, investigation: Investigation, action: str, finding_id: str) -> dict[str, Any]:
    if action not in ACTION_LABELS:
        raise SimulationError("Unsupported remediation simulation action")
    findings, statuses, evidence, evidence_by_id, finding_rows_by_id = _inputs(db, investigation)
    target_record = next((item for item in findings if item.id == finding_id), None)
    if target_record is None:
        raise SimulationError("Finding does not belong to this investigation")
    saved_finding = finding_rows_by_id[finding_id]
    target = _finding_mapping(saved_finding)
    if target.get("applicability") != "applies":
        raise SimulationError("Only applicable findings can be simulated as remediated")
    linked_ids = _linked_evidence_ids(target)
    if not any(evidence_id in evidence_by_id for evidence_id in linked_ids):
        raise SimulationError("A saved evidence snapshot linked to this finding is required")
    evidence_row = _matching_evidence(action, target, evidence_by_id, statuses)
    if evidence_row is None:
        raise SimulationError("The selected action is not supported by this finding's category and saved evidence")

    baseline_result = score_records(findings, statuses, evidence)
    projected_findings = [item for item in findings if item.id != finding_id]
    projected_result = score_records(projected_findings, statuses, evidence)
    categories = sorted(set(WEIGHTS) | set(baseline_result["category_scores"]) | set(projected_result["category_scores"]))
    category_changes = []
    for category in categories:
        before = baseline_result["category_scores"].get(category)
        after = projected_result["category_scores"].get(category)
        category_changes.append({
            "category": category, "baseline_score": before, "projected_score": after,
            "change": round(after - before, 2) if before is not None and after is not None else None,
        })
    return {
        "investigation_id": investigation.id,
        "action": action,
        "action_label": ACTION_LABELS[action],
        "risk_policy_version": RISK_VERSION,
        "baseline": _simulation_score(baseline_result),
        "projected": _simulation_score(projected_result),
        "category_changes": category_changes,
        "affected": {
            "finding_id": target_record.id, "title": saved_finding.title, "category": target_record.category,
            "severity": target_record.severity, "source": target_record.source,
            "evidence_id": evidence_row.id, "evidence_source": evidence_row.source,
            "evidence_observed_at": evidence_row.observed_at, "evidence_sha256": evidence_row.sha256,
            "evidence_synthetic": evidence_row.is_synthetic,
        },
        "assumptions": [*SIMULATION_ASSUMPTIONS, ACTION_ASSUMPTIONS[action]],
    }
