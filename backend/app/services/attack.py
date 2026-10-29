"""Curated ATT&CK lookup and conservative evidence-linked mapping helpers."""

import json
from pathlib import Path
from typing import Any

from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.models import AttackCatalogVersion, AttackMapping, EvidenceSnapshot, Finding, Incident, IncidentFinding

_CATALOG_PATH = Path(__file__).resolve().parents[1] / "data" / "attack_enterprise_subset.json"
MITRE_ATTRIBUTION = (
    "MITRE ATT&CK® is a registered trademark of The MITRE Corporation. Copyright 2020-2025 "
    "The MITRE Corporation. Approved for public release. Case number 19-3504. "
    "Used under the MITRE ATT&CK Terms of Use."
)


def attack_catalog(db: Session | None = None, version: str | None = None) -> dict[str, Any]:
    if db is not None:
        query = db.query(AttackCatalogVersion)
        row = query.filter_by(catalog_version=version).first() if version else query.filter_by(active=True).first()
        if row is not None and row.catalog_json:
            return {**row.catalog_json, "release_version": row.release_version, "source": row.source,
                    "source_reference": row.source_reference, "retrieved_at": row.retrieved_at,
                    "checksum": row.checksum, "import_status": row.import_status, "active": row.active,
                    "attribution": row.catalog_json.get("attribution", MITRE_ATTRIBUTION)}
    bundled = json.loads(_CATALOG_PATH.read_text(encoding="utf-8"))
    if version is None or version == bundled["catalog_version"]:
        return bundled
    return {**bundled, "techniques": []}


def catalog_version(db: Session | None = None) -> str:
    return str(attack_catalog(db)["catalog_version"])


def technique(
    technique_id: str, *, db: Session | None = None, version: str | None = None,
    include_retired: bool = False,
) -> dict[str, Any] | None:
    catalog = attack_catalog(db, version)
    item = next((row for row in catalog["techniques"] if row["id"] == technique_id), None)
    if item is not None and not include_retired and item.get("selectable") is False:
        return None
    return item


def mapping_payload(db: Session, item: AttackMapping) -> dict[str, Any]:
    evidence = db.get(EvidenceSnapshot, item.evidence_id)
    return _mapping_payload(item, evidence, attack_catalog(db, item.catalog_version))


def mapping_payloads(db: Session, items: list[AttackMapping]) -> list[dict[str, Any]]:
    if not items:
        return []
    evidence_ids = {item.evidence_id for item in items}
    evidence_by_id = {row.id: row for row in db.query(EvidenceSnapshot).filter(EvidenceSnapshot.id.in_(evidence_ids)).all()}
    catalogs = {version: attack_catalog(db, version) for version in {item.catalog_version for item in items}}
    return [_mapping_payload(item, evidence_by_id.get(item.evidence_id), catalogs.get(item.catalog_version)) for item in items]


def _mapping_payload(item: AttackMapping, evidence: EvidenceSnapshot | None,
                     catalog: dict[str, Any] | None = None) -> dict[str, Any]:
    catalog = catalog or attack_catalog(version=item.catalog_version)
    return {
        "id": item.id,
        "finding_id": item.finding_id,
        "incident_id": item.incident_id,
        "technique_id": item.technique_id,
        "technique_name": item.technique_name,
        "tactic": item.tactic,
        "catalog_version": item.catalog_version,
        "catalog_release_version": catalog.get("release_version"),
        "catalog_source": catalog.get("source", "MITRE ATT&CK Enterprise bundled legacy subset"),
        "catalog_source_reference": catalog.get("source_reference", catalog.get("source_url")),
        "catalog_checksum": catalog.get("checksum"),
        "catalog_attribution": catalog.get(
            "attribution", MITRE_ATTRIBUTION,
        ),
        "rationale": item.rationale,
        "confidence": item.confidence,
        "source": item.source,
        "evidence_role": item.evidence_role,
        "evidence_id": item.evidence_id,
        "evidence_source": evidence.source if evidence else "unavailable",
        "evidence_observed_at": evidence.observed_at if evidence else None,
        "decision": item.decision,
        "analyst_confirmed": item.analyst_confirmed,
        "created_by": item.created_by,
        "reviewed_by": item.reviewed_by,
        "reviewed_at": item.reviewed_at,
        "created_at": item.created_at,
        "updated_at": item.updated_at,
    }


def evidence_ids_for_finding(db: Session, finding: Finding) -> list[str]:
    candidates = {value for value in finding.details_json.get("additional_evidence_ids", []) if isinstance(value, str)}
    if finding.evidence_id:
        candidates.add(finding.evidence_id)
    if not candidates:
        return []
    return [row.id for row in db.query(EvidenceSnapshot).filter(
        EvidenceSnapshot.id.in_(candidates), EvidenceSnapshot.investigation_id == finding.investigation_id
    ).order_by(EvidenceSnapshot.observed_at, EvidenceSnapshot.id).all()]


def suggestions_for_finding(db: Session, finding: Finding) -> list[dict[str, Any]]:
    evidence_ids = evidence_ids_for_finding(db, finding)
    if not evidence_ids:
        return []
    asset = db.get(__import__("app.models", fromlist=["Asset"]).Asset, finding.asset_id)
    candidates: list[tuple[str, str, float, str, str]] = []
    if (finding.category == "vulnerabilities" and finding.applicability == "applies" and asset
            and asset.exposure_classification == "internet_facing"):
        candidates.append((
            "T1190", "vulnerability_internet_facing_app", 0.35,
            "An analyst-confirmed applicable vulnerability on an internet-facing application is contextually relevant to this technique. This is a candidate relationship only; the finding does not show that an adversary exploited the application.",
            evidence_ids[0],
        ))
    if finding.category == "breach_exposure":
        candidates.append((
            "T1589.002", "historical_email_breach_exposure", 0.25,
            "Historical email breach exposure is contextually relevant to this identity-information technique. The exposure record does not show that an adversary gathered or used the addresses.",
            evidence_ids[0],
        ))
    results = []
    for technique_id, rule_id, confidence, rationale, evidence_id in candidates:
        item = technique(technique_id, db=db)
        if not item:
            continue
        results.append({
            "finding_id": finding.id, "incident_id": None, "technique_id": technique_id,
            "technique_name": item["name"], "tactic": (item.get("selectable_tactics") or item["tactics"])[0],
            "catalog_version": catalog_version(db), "rationale": rationale, "confidence": confidence,
            "source": f"cyberlens-rule:{rule_id}", "evidence_role": "contextual",
            "evidence_id": evidence_id, "decision": "suggested",
            "notice": "Candidate only. Analyst review is required before this appears as a confirmed mapping.",
        })
    return results


def suggestions_for_incident(db: Session, incident: Incident) -> list[dict[str, Any]]:
    # A broad incident classification alone does not establish adversary behavior.
    if incident.classification != "confirmed_incident":
        return []
    links = db.query(IncidentFinding).filter_by(incident_id=incident.id).all()
    results: list[dict[str, Any]] = []
    for link in links:
        finding = db.get(Finding, link.finding_id)
        if finding is None:
            continue
        for candidate in suggestions_for_finding(db, finding):
            results.append({
                **candidate,
                "finding_id": finding.id,
                "incident_id": incident.id,
                "rationale": (
                    f"Confirmed incident classification with linked finding context. {candidate['rationale']} "
                    "The classification itself is not evidence of this technique."
                ),
            })
    return results


def incident_matrix(db: Session, incident: Incident) -> dict[str, Any]:
    links = db.query(IncidentFinding).filter_by(incident_id=incident.id).all()
    linked_finding_ids = {row.finding_id for row in links}
    scope = [AttackMapping.incident_id == incident.id]
    if linked_finding_ids:
        scope.append(AttackMapping.finding_id.in_(linked_finding_ids))
    rows = db.query(AttackMapping).filter(or_(*scope)).order_by(
        AttackMapping.tactic, AttackMapping.technique_id, AttackMapping.created_at, AttackMapping.id
    ).all()
    mappings = mapping_payloads(db, rows)
    by_tactic: dict[str, list[dict[str, Any]]] = {}
    for item in mappings:
        by_tactic.setdefault(item["tactic"], []).append(item)
    suggestions = suggestions_for_incident(db, incident)
    existing = {(row.finding_id, row.technique_id) for row in rows if row.finding_id}
    incident_techniques = {(row.technique_id, row.evidence_id) for row in rows if row.incident_id}
    suggestions = [item for item in suggestions
                   if (item["finding_id"], item["technique_id"]) not in existing
                   and (item["technique_id"], item["evidence_id"]) not in incident_techniques]
    unmapped = []
    suggested_ids = {item["finding_id"] for item in suggestions}
    mapped_ids = {row.finding_id for row in rows if row.finding_id and row.decision != "rejected"}
    mapped_evidence_ids = {row.evidence_id for row in rows if row.incident_id and row.decision != "rejected"}
    for link in links:
        finding = db.get(Finding, link.finding_id)
        if finding is None or finding.id in suggested_ids or finding.id in mapped_ids:
            continue
        if mapped_evidence_ids.intersection(evidence_ids_for_finding(db, finding)):
            continue
        reason = "No curated rule applies; the record remains unmapped."
        if incident.classification != "confirmed_incident":
            reason = "Incident classification alone is insufficient to infer an ATT&CK technique."
        elif not evidence_ids_for_finding(db, finding):
            reason = "No linked saved evidence is available; the record remains unmapped."
        unmapped.append({"finding_id": finding.id, "title": finding.title, "category": finding.category, "reason": reason})
    return {
        "incident_id": incident.id, "catalog_version": catalog_version(db),
        "tactics": [{"tactic": key, "mappings": by_tactic[key]} for key in sorted(by_tactic)],
        "mappings": mappings, "suggestions": suggestions, "unmapped": unmapped,
        "notice": "Mappings are analyst-reviewed hypotheses and do not establish adversary attribution or behavior unless the cited evidence supports that claim.",
    }


def mappings_for_targets(db: Session, finding_ids: set[str], incident_ids: set[str]) -> list[AttackMapping]:
    filters = []
    if finding_ids:
        filters.append(AttackMapping.finding_id.in_(finding_ids))
    if incident_ids:
        filters.append(AttackMapping.incident_id.in_(incident_ids))
    if not filters:
        return []
    return db.query(AttackMapping).filter(or_(*filters)).order_by(
        AttackMapping.created_at, AttackMapping.id
    ).all()
