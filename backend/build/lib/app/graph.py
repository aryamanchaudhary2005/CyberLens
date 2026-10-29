"""Evidence-backed graph projection and conservative investigation diffs.

PostgreSQL remains the source of truth: graph nodes are projections of existing
workspace records and every persisted relationship points to an evidence row.
"""

from collections.abc import Iterable
from datetime import datetime, timezone
import ipaddress
import json
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from app.models import (
    Asset,
    CollectorRun,
    EvidenceRelationship,
    EvidenceSnapshot,
    Finding,
    Incident,
    IncidentFinding,
    Investigation,
    InvestigationAttempt,
    PlaybookTask,
    SoftwareComponent,
)

NODE_TYPES = {
    "asset", "domain", "ip", "certificate", "software", "cve", "finding",
    "investigation", "incident", "playbook_task",
}
RELATIONSHIP_TYPES = {
    "investigated_in", "identifies_domain", "identifies_ip", "resolves_to",
    "redirects_to", "presents_certificate", "includes_software", "has_finding",
    "concerns_software", "references_cve", "potentially_affected_by",
    "concerns_asset", "tracks_finding", "belongs_to_incident",
}
SUCCESS_COVERAGE = {"success", "no_match"}


def node_id(node_type: str, identifier: str) -> str:
    if node_type not in NODE_TYPES:
        raise ValueError(f"Unsupported graph node type: {node_type}")
    return f"{node_type}:{identifier}"


def _canonical_domain(value: str | None) -> str | None:
    if not value:
        return None
    host = value.rstrip(".").lower()
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        return host or None


def _host(value: str | None) -> str | None:
    if not value:
        return None
    parsed = urlsplit(value if "://" in value else f"//{value}")
    return parsed.hostname


def _host_node(value: str | None) -> tuple[str, str] | None:
    if not isinstance(value, str) or not value.strip():
        return None
    candidate = _host(value) or value.strip()
    address = _ip(candidate)
    if address:
        return "ip", address
    domain = _canonical_domain(candidate)
    return ("domain", domain) if domain else None


def _ip(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        return ipaddress.ip_address(value.strip()).compressed
    except ValueError:
        return None


def _add_relationship(
    db: Session,
    investigation: Investigation,
    evidence: EvidenceSnapshot,
    *,
    from_type: str,
    from_id: str,
    from_label: str,
    to_type: str,
    to_id: str,
    to_label: str,
    relationship: str,
    role: str,
    collector: str,
    details: dict | None = None,
    observed_at: datetime | None = None,
) -> None:
    if from_type not in NODE_TYPES or to_type not in NODE_TYPES:
        return
    if relationship not in RELATIONSHIP_TYPES or role not in {"direct", "contextual"}:
        return
    source_details = {"from_label": from_label, "to_label": to_label, **(details or {})}
    values = {
        "investigation_id": investigation.id,
        "from_node_type": from_type,
        "from_node_id": node_id(from_type, from_id),
        "to_node_type": to_type,
        "to_node_id": node_id(to_type, to_id),
        "relationship_type": relationship,
        "evidence_role": role,
        "collector": collector,
        "source": evidence.source,
        "evidence_id": evidence.id,
        "observed_at": observed_at or evidence.observed_at,
        "data_mode": investigation.mode,
        "details_json": source_details,
    }
    table = EvidenceRelationship.__table__
    dialect = db.get_bind().dialect.name
    if dialect == "postgresql":
        statement = pg_insert(table).values(**values).on_conflict_do_nothing(
            constraint="uq_evidence_relationship_observation"
        )
        db.execute(statement)
    elif dialect == "sqlite":
        statement = sqlite_insert(table).values(**values).on_conflict_do_nothing(
            index_elements=["evidence_id", "from_node_id", "to_node_id", "relationship_type"]
        )
        db.execute(statement)
    else:
        exists = db.execute(select(EvidenceRelationship.id).where(
            EvidenceRelationship.evidence_id == evidence.id,
            EvidenceRelationship.from_node_id == values["from_node_id"],
            EvidenceRelationship.to_node_id == values["to_node_id"],
            EvidenceRelationship.relationship_type == relationship,
        )).first()
        if not exists:
            db.add(EvidenceRelationship(**values))


def _collector_for(db: Session, evidence: EvidenceSnapshot) -> str:
    if evidence.collector_run_id:
        run = db.get(CollectorRun, evidence.collector_run_id)
        if run:
            return run.collector
    return "unknown"


def _evidence_ids(finding: Finding) -> list[str]:
    values = [finding.evidence_id] if finding.evidence_id else []
    additional = finding.details_json.get("additional_evidence_ids", [])
    if isinstance(additional, list):
        values.extend(value for value in additional if isinstance(value, str))
    return list(dict.fromkeys(values))


def ensure_relationships(db: Session, investigation: Investigation) -> None:
    """Idempotently project persisted evidence and workflow links into edge rows."""
    asset = db.get(Asset, investigation.asset_id)
    if asset is None:
        return
    snapshots = db.query(EvidenceSnapshot).filter_by(investigation_id=investigation.id).order_by(
        EvidenceSnapshot.observed_at, EvidenceSnapshot.id
    ).all()
    evidence_by_id = {row.id: row for row in snapshots}
    components = db.query(SoftwareComponent).filter_by(asset_id=asset.id).all()
    components_by_id = {row.id: row for row in components}
    for evidence in snapshots:
        payload = evidence.evidence_json if isinstance(evidence.evidence_json, dict) else {}
        collector = _collector_for(db, evidence)
        _add_relationship(db, investigation, evidence,
            from_type="asset", from_id=asset.id, from_label=asset.identifier,
            to_type="investigation", to_id=investigation.id, to_label=f"Investigation {investigation.id[:8]}",
            relationship="investigated_in", role="contextual", collector=collector)

        raw_host = payload.get("submitted_host") if isinstance(payload.get("submitted_host"), str) else None
        if not raw_host:
            submitted_url = payload.get("submitted_url")
            fallback_target = submitted_url if isinstance(submitted_url, str) else (
                asset.identifier if asset.kind in {"domain", "url"} else None
            )
            raw_host = fallback_target
        host_reference = _host_node(raw_host)
        host = host_reference[1] if host_reference and host_reference[0] == "domain" else None
        if host:
            _add_relationship(db, investigation, evidence,
                from_type="asset", from_id=asset.id, from_label=asset.identifier,
                to_type="domain", to_id=host, to_label=host,
                relationship="identifies_domain", role="contextual", collector=collector)

        dns_values: list[tuple[str, object]] = []
        records = payload.get("records")
        if isinstance(records, dict):
            for record_type in ("A", "AAAA"):
                record = records.get(record_type)
                if isinstance(record, dict) and record.get("status") == "success" and isinstance(record.get("values"), list):
                    dns_values.extend((record_type, value) for value in record["values"])
        # Demo and older evidence may store the summarized list only.
        domain_to_ip = payload.get("domain_to_ip")
        if isinstance(domain_to_ip, dict):
            for record_type in ("A", "AAAA"):
                values = domain_to_ip.get(record_type)
                if isinstance(values, list):
                    dns_values.extend((record_type, value) for value in values)
        if host:
            for record_type, value in dns_values:
                address = _ip(value)
                if address:
                    _add_relationship(db, investigation, evidence,
                        from_type="domain", from_id=host, from_label=host,
                        to_type="ip", to_id=address, to_label=address,
                        relationship="resolves_to", role="direct", collector=collector,
                        details={"record_type": record_type})

        ip_reference = _host_node(raw_host) if raw_host else None
        if asset.kind == "ip":
            ip_reference = _host_node(asset.identifier)
        if ip_reference and ip_reference[0] == "ip":
            address = ip_reference[1]
            if address:
                _add_relationship(db, investigation, evidence,
                    from_type="asset", from_id=asset.id, from_label=asset.identifier,
                    to_type="ip", to_id=address, to_label=address,
                    relationship="identifies_ip", role="contextual", collector=collector)

        website = payload.get("https")
        if isinstance(website, dict):
            redirect_hops = website.get("redirect_hops", [])
            if isinstance(redirect_hops, list) and redirect_hops:
                for hop in redirect_hops:
                    if not isinstance(hop, dict):
                        continue
                    from_reference = _host_node(hop.get("from_url") if isinstance(hop.get("from_url"), str) else None) or host_reference
                    to_reference = _host_node(hop.get("to_url") if isinstance(hop.get("to_url"), str) else None)
                    if from_reference and to_reference:
                        _add_relationship(db, investigation, evidence,
                            from_type=from_reference[0], from_id=from_reference[1], from_label=from_reference[1],
                            to_type=to_reference[0], to_id=to_reference[1], to_label=to_reference[1],
                            relationship="redirects_to", role="direct", collector=collector,
                            details={"status_code": hop.get("status_code"), "from_url": hop.get("from_url"), "to_url": hop.get("to_url")})
            else:
                redirects = website.get("redirects", [])
                if isinstance(redirects, list):
                    for target in redirects:
                        to_reference = _host_node(target if isinstance(target, str) else None)
                        if host_reference and to_reference:
                            _add_relationship(db, investigation, evidence,
                                from_type=host_reference[0], from_id=host_reference[1], from_label=host_reference[1],
                                to_type=to_reference[0], to_id=to_reference[1], to_label=to_reference[1],
                                relationship="redirects_to", role="direct", collector=collector,
                                details={"to_url": target})

        certificate = payload.get("certificate")
        if isinstance(certificate, dict):
            fingerprint = certificate.get("sha256_fingerprint")
            if isinstance(fingerprint, str) and fingerprint.strip():
                tls_reference = _host_node(certificate.get("tls_hostname")) or host_reference
                if tls_reference:
                    _add_relationship(db, investigation, evidence,
                        from_type=tls_reference[0], from_id=tls_reference[1], from_label=tls_reference[1],
                        to_type="certificate", to_id=fingerprint.lower(),
                        to_label=certificate.get("subject") or f"SHA-256 {fingerprint[:16]}",
                        relationship="presents_certificate", role="direct", collector=collector,
                        details={key: certificate.get(key) for key in (
                            "sha256_fingerprint", "issuer", "hostname_match", "trust_valid", "not_after",
                            "tls_hostname", "tls_version", "negotiated_protocol",
                        ) if certificate.get(key) is not None})

        component_results = payload.get("components")
        if isinstance(component_results, list):
            for result in component_results:
                if not isinstance(result, dict) or result.get("status") != "success":
                    continue
                component = components_by_id.get(result.get("component_id"))
                if component:
                    label = f"{component.vendor} {component.product} {component.version}"
                    _add_relationship(db, investigation, evidence,
                        from_type="asset", from_id=asset.id, from_label=asset.identifier,
                        to_type="software", to_id=component.id, to_label=label,
                        relationship="includes_software", role="contextual", collector=collector)

    # Finding rows are the authoritative structured link between an observation,
    # the affected asset, inventory software, and a CVE identifier.
    findings = db.query(Finding).filter_by(investigation_id=investigation.id).all()
    for finding in findings:
        details = finding.details_json if isinstance(finding.details_json, dict) else {}
        finding_key = f"{asset.id}:{finding.fingerprint}"
        cve = details.get("cve_id")
        component_id = details.get("component_id")
        component = components_by_id.get(component_id) if isinstance(component_id, str) else None
        if component is None and isinstance(details.get("component"), dict):
            candidate = details["component"]
            component = next((row for row in components if
                row.vendor.casefold() == str(candidate.get("vendor", "")).casefold() and
                row.product.casefold() == str(candidate.get("product", "")).casefold() and
                row.version.casefold() == str(candidate.get("version", "")).casefold()), None)
        for evidence_id in _evidence_ids(finding):
            evidence = evidence_by_id.get(evidence_id)
            if evidence is None:
                continue
            collector = _collector_for(db, evidence)
            _add_relationship(db, investigation, evidence,
                from_type="asset", from_id=asset.id, from_label=asset.identifier,
                to_type="finding", to_id=finding_key, to_label=finding.title,
                relationship="has_finding", role="direct", collector=collector,
                details={"fingerprint": finding.fingerprint, "category": finding.category,
                         "severity": finding.severity, "source": finding.source})
            if component:
                software_label = f"{component.vendor} {component.product} {component.version}"
                _add_relationship(db, investigation, evidence,
                    from_type="finding", from_id=finding_key, from_label=finding.title,
                    to_type="software", to_id=component.id, to_label=software_label,
                    relationship="concerns_software", role="direct", collector=collector,
                    details={"component_id": component.id})
            if isinstance(cve, str) and cve.upper().startswith("CVE-"):
                cve = cve.upper()
                _add_relationship(db, investigation, evidence,
                    from_type="finding", from_id=finding_key, from_label=finding.title,
                    to_type="cve", to_id=cve, to_label=cve,
                    relationship="references_cve", role="direct", collector=collector,
                    details={"severity": finding.severity, "applicability": finding.applicability})
                if component:
                    _add_relationship(db, investigation, evidence,
                        from_type="software", from_id=component.id,
                        from_label=f"{component.vendor} {component.product} {component.version}",
                        to_type="cve", to_id=cve, to_label=cve,
                        relationship="potentially_affected_by", role="direct", collector=collector,
                        details={"component_id": component.id, "applicability": finding.applicability})

    # Incident and playbook links are workflow context. They remain evidence-
    # backed by the finding snapshots that were selected when the case was made.
    incidents = db.query(Incident).filter_by(investigation_id=investigation.id).all()
    for incident in incidents:
        links = db.query(IncidentFinding).filter_by(incident_id=incident.id).all()
        linked_findings = [db.get(Finding, row.finding_id) for row in links]
        linked_findings = [row for row in linked_findings if row is not None]
        task_rows = db.query(PlaybookTask).filter_by(incident_id=incident.id).all()
        for finding in linked_findings:
            finding_key = f"{asset.id}:{finding.fingerprint}"
            for evidence_id in _evidence_ids(finding):
                evidence = evidence_by_id.get(evidence_id)
                if evidence is None:
                    continue
                collector = _collector_for(db, evidence)
                _add_relationship(db, investigation, evidence,
                    from_type="incident", from_id=incident.id, from_label=incident.title,
                    to_type="asset", to_id=asset.id, to_label=asset.identifier,
                    relationship="concerns_asset", role="contextual", collector=collector,
                    observed_at=incident.created_at)
                _add_relationship(db, investigation, evidence,
                    from_type="incident", from_id=incident.id, from_label=incident.title,
                    to_type="finding", to_id=finding_key, to_label=finding.title,
                    relationship="tracks_finding", role="contextual", collector=collector,
                    observed_at=incident.created_at)
                for task in task_rows:
                    _add_relationship(db, investigation, evidence,
                        from_type="playbook_task", from_id=task.id, from_label=task.title,
                        to_type="incident", to_id=incident.id, to_label=incident.title,
                        relationship="belongs_to_incident", role="contextual", collector=collector,
                        observed_at=incident.created_at)


def _node_payload(node_type: str, identifier: str, label: str, details: dict | None = None) -> dict:
    return {"id": node_id(node_type, identifier), "type": node_type, "label": label,
            "details": details or {}}


def projection(db: Session, investigation: Investigation) -> dict:
    rows = db.query(EvidenceRelationship).filter_by(investigation_id=investigation.id).order_by(
        EvidenceRelationship.observed_at, EvidenceRelationship.id
    ).all()
    nodes: dict[str, dict] = {}
    asset = db.get(Asset, investigation.asset_id)
    if asset:
        node = _node_payload("asset", asset.id, asset.identifier, {"kind": asset.kind})
        nodes[node["id"]] = node
    node = _node_payload("investigation", investigation.id, f"Investigation {investigation.id[:8]}",
                         {"status": investigation.status, "mode": investigation.mode})
    nodes[node["id"]] = node
    edges = []
    for row in rows:
        for prefix, node_type, identifier_field, label_field in (
            ("from", row.from_node_type, "from_node_id", "from_label"),
            ("to", row.to_node_type, "to_node_id", "to_label"),
        ):
            typed_id = getattr(row, identifier_field)
            label = row.details_json.get(label_field) or typed_id.split(":", 1)[-1]
            details = {key: value for key, value in row.details_json.items()
                       if key not in {"from_label", "to_label"}}
            nodes.setdefault(typed_id, {"id": typed_id, "type": node_type, "label": label, "details": details})
        edges.append({
            "id": row.id,
            "from_node_id": row.from_node_id,
            "from_node_type": row.from_node_type,
            "to_node_id": row.to_node_id,
            "to_node_type": row.to_node_type,
            "relationship_type": row.relationship_type,
            "evidence_role": row.evidence_role,
            "collector": row.collector,
            "source": row.source,
            "evidence_id": row.evidence_id,
            "observed_at": row.observed_at,
            "data_mode": row.data_mode,
            "details": row.details_json,
        })
    return {"investigation_id": investigation.id,
            "generated_at": datetime.now(timezone.utc),
            "nodes": sorted(nodes.values(), key=lambda item: (item["type"], item["label"].casefold(), item["id"])),
            "edges": edges}


def _latest_edges(edges: Iterable[dict]) -> dict[tuple[str, str, str], dict]:
    latest: dict[tuple[str, str, str], dict] = {}
    for edge in edges:
        # Investigation ownership is a contextual bookkeeping edge and is not
        # itself a changing observation between scans.
        if edge["relationship_type"] == "investigated_in":
            continue
        key = (edge["from_node_id"], edge["to_node_id"], edge["relationship_type"])
        prior = latest.get(key)
        if prior is None or edge["observed_at"] >= prior["observed_at"]:
            latest[key] = edge
    return latest


def _edges_from_latest_attempt(db: Session, investigation: Investigation, edges: Iterable[dict]) -> list[dict]:
    attempts = db.query(InvestigationAttempt).filter_by(investigation_id=investigation.id).all()
    attempt_numbers = {row.id: row.attempt_number for row in attempts}
    latest_runs: dict[str, tuple[int, CollectorRun]] = {}
    for run in db.query(CollectorRun).filter_by(investigation_id=investigation.id).all():
        number = attempt_numbers.get(run.attempt_id, 0)
        if run.collector not in latest_runs or number >= latest_runs[run.collector][0]:
            latest_runs[run.collector] = (number, run)
    evidence_ids = {edge["evidence_id"] for edge in edges}
    evidence_rows = db.query(EvidenceSnapshot).filter(EvidenceSnapshot.id.in_(evidence_ids)).all() if evidence_ids else []
    evidence_run_ids = {row.id: row.collector_run_id for row in evidence_rows}
    current_run_ids = {collector: value[1].id for collector, value in latest_runs.items()}
    return [edge for edge in edges if
            (edge["collector"] not in current_run_ids and evidence_run_ids.get(edge["evidence_id"]) is None) or
            evidence_run_ids.get(edge["evidence_id"]) == current_run_ids.get(edge["collector"])]


def _edge_signature(edge: dict) -> str:
    stable = {key: edge[key] for key in ("evidence_role", "collector", "source", "data_mode", "details")}
    return json.dumps(stable, sort_keys=True, separators=(",", ":"), default=str)


def compare(db: Session, current: Investigation, previous: Investigation) -> dict:
    current_graph = projection(db, current)
    previous_graph = projection(db, previous)
    current_edges = _latest_edges(_edges_from_latest_attempt(db, current, current_graph["edges"]))
    previous_edges = _latest_edges(_edges_from_latest_attempt(db, previous, previous_graph["edges"]))
    attempts = db.query(InvestigationAttempt).filter_by(investigation_id=current.id).all()
    attempt_numbers = {row.id: row.attempt_number for row in attempts}
    runs = db.query(CollectorRun).filter_by(investigation_id=current.id).all()
    latest_runs: dict[str, tuple[int, CollectorRun]] = {}
    for run in runs:
        attempt_number = attempt_numbers.get(run.attempt_id, 0)
        if run.collector not in latest_runs or attempt_number >= latest_runs[run.collector][0]:
            latest_runs[run.collector] = (attempt_number, run)

    changes = []
    for key, edge in current_edges.items():
        old = previous_edges.get(key)
        if old is None:
            changes.append({"status": "new", "edge": edge, "previous_edge": None,
                            "reason": "This evidence-backed relationship was not present in the earlier investigation."})
        elif _edge_signature(old) != _edge_signature(edge):
            changes.append({"status": "changed", "edge": edge, "previous_edge": old,
                            "reason": "The relationship or its supporting evidence metadata changed."})
    for key, old in previous_edges.items():
        if key in current_edges:
            continue
        run_entry = latest_runs.get(old["collector"])
        status = run_entry[1].status if run_entry else "not_run"
        if status in SUCCESS_COVERAGE:
            changes.append({"status": "no_longer_observed", "edge": old, "previous_edge": old,
                            "reason": f"Collector {old['collector']} completed successfully and did not observe this relationship."})
        else:
            changes.append({"status": "unknown", "edge": old, "previous_edge": old,
                            "reason": f"Collector {old['collector']} coverage is {status}; absence is not evidence of removal."})
    order = {"new": 0, "changed": 1, "no_longer_observed": 2, "unknown": 3}
    changes.sort(key=lambda item: (order[item["status"]], item["edge"]["relationship_type"], item["edge"]["from_node_id"]))
    return {"current_investigation_id": current.id, "previous_investigation_id": previous.id,
            "changes": changes,
            "counts": {status: sum(change["status"] == status for change in changes) for status in order}}
