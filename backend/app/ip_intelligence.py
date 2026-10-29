"""Read-only source comparison and temporal IP listing history."""

from app.models import Asset, CollectorRun, EvidenceSnapshot, Investigation, InvestigationAttempt
from app.visibility import live_projection

FEED_COLLECTORS = {"spamhaus_drop": "Spamhaus DROP", "cins_army": "CINS Army"}
RELEVANT_COLLECTORS = {"spamhaus_drop", "cins_army", "reputation"}
FINISHED = {"completed", "partial", "failed"}


def _valid_feed_observation(run: CollectorRun, evidence: dict) -> bool:
    return (
        run.status in {"success", "no_match"}
        and evidence.get("freshness") in {"fresh", "synthetic"}
        and bool(evidence.get("snapshot_id"))
        and evidence.get("result") in {"listed", "not_listed_in_snapshot"}
    )


def _run_summary(run: CollectorRun | None, evidence_row: EvidenceSnapshot | None, *, source_name: str) -> dict:
    evidence = (evidence_row.evidence_json or {}) if evidence_row else {}
    status = run.status if run else "not_run"
    if source_name in FEED_COLLECTORS:
        known = bool(run and _valid_feed_observation(run, evidence))
        listed = known and evidence.get("result") == "listed"
        state = "listed" if listed else "not_listed" if known else "unknown"
        return {
            "collector": source_name, "source": FEED_COLLECTORS[source_name], "collector_status": status,
            "state": state, "result": evidence.get("result", "unknown"),
            "freshness": evidence.get("freshness", "unknown"), "snapshot_id": evidence.get("snapshot_id"),
            "content_sha256": evidence.get("content_sha256"),
            "observed_at": evidence_row.observed_at if evidence_row else (run.finished_at if run else None),
            "evidence_id": evidence_row.id if evidence_row else None,
            "evidence": evidence,
            "notice": "Absence from a later successfully refreshed snapshot is not proof of remediation." if known and not listed else None,
        }
    return {
        "collector": "reputation", "source": "VirusTotal", "collector_status": status,
        "state": "provider_result" if run and run.status in {"success", "no_match", "partial"} else "unknown",
        "result": evidence.get("provider_status", evidence.get("result", status)),
        "freshness": evidence.get("freshness", "unknown"),
        "snapshot_id": None, "content_sha256": None,
        "observed_at": evidence_row.observed_at if evidence_row else (run.finished_at if run else None),
        "evidence_id": evidence_row.id if evidence_row else None, "evidence": evidence,
        "notice": "VirusTotal provider evidence is displayed separately from address-list overlap.",
    }


def build_ip_intelligence_history(db, investigation: Investigation) -> dict | None:
    """Group evidence for one directly assessed IP and compare saved feed observations.

    A stale, failed, or missing collector run is unknown and does not replace the
    last valid observation used for the next temporal classification.
    """
    asset = db.get(Asset, investigation.asset_id)
    if asset is None or asset.kind != "ip":
        return None
    investigation_query = (db.query(Investigation)
        .filter(Investigation.asset_id == asset.id, Investigation.status.in_(FINISHED)))
    if live_projection():
        investigation_query = investigation_query.filter(Investigation.mode == "live")
    investigations = investigation_query.order_by(Investigation.created_at, Investigation.id).all()
    if investigation.id not in {item.id for item in investigations}:
        investigations.append(investigation)
        investigations.sort(key=lambda item: (item.created_at, item.id))
    investigations = investigations[-100:]
    ids = [item.id for item in investigations]

    attempts = (db.query(InvestigationAttempt).filter(InvestigationAttempt.investigation_id.in_(ids))
                .order_by(InvestigationAttempt.attempt_number.desc(), InvestigationAttempt.id.desc()).all()) if ids else []
    attempt_numbers = {}
    for attempt in attempts:
        attempt_numbers.setdefault(attempt.id, attempt.attempt_number)
    runs = (db.query(CollectorRun).filter(CollectorRun.investigation_id.in_(ids),
            CollectorRun.collector.in_(RELEVANT_COLLECTORS))
            .order_by(CollectorRun.started_at, CollectorRun.id).all()) if ids else []
    selected_runs = {}
    for run in runs:
        key = (run.investigation_id, run.collector)
        prior = selected_runs.get(key)
        run_rank = (attempt_numbers.get(run.attempt_id, 0), run.started_at.isoformat() if run.started_at else "", run.id)
        prior_rank = ((attempt_numbers.get(prior.attempt_id, 0), prior.started_at.isoformat() if prior.started_at else "", prior.id)
                      if prior is not None else None)
        if prior is None or run_rank > prior_rank:
            selected_runs[key] = run
    run_ids = [run.id for run in selected_runs.values()]
    evidence_rows = (db.query(EvidenceSnapshot).filter(EvidenceSnapshot.collector_run_id.in_(run_ids)).all()) if run_ids else []
    evidence_by_run = {item.collector_run_id: item for item in evidence_rows if item.collector_run_id}

    histories = {source_id: [] for source_id in FEED_COLLECTORS}
    last_valid = {source_id: None for source_id in FEED_COLLECTORS}
    current_sources = {}
    current_investigation = next((item for item in investigations if item.id == investigation.id), investigation)
    for item in investigations:
        for source_id, display_name in FEED_COLLECTORS.items():
            run = selected_runs.get((item.id, source_id))
            evidence_row = evidence_by_run.get(run.id) if run else None
            summary = _run_summary(run, evidence_row, source_name=source_id)
            if summary["state"] == "unknown":
                summary["classification"] = "unknown"
                summary["reason"] = "This run is missing, stale, failed, or lacks a validated snapshot; no listing change was inferred."
            else:
                previous = last_valid[source_id]
                listed = summary["state"] == "listed"
                if previous is None:
                    classification = "baseline_listed" if listed else "baseline_not_listed"
                elif listed and previous["listed"]:
                    classification = "continuing_listing"
                elif listed and not previous["listed"]:
                    classification = ("newly_observed_listing" if summary["snapshot_id"] != previous["snapshot_id"]
                                      else "unknown")
                elif not listed and previous["listed"]:
                    classification = ("no_longer_listed" if summary["snapshot_id"] != previous["snapshot_id"]
                                      else "unknown")
                else:
                    classification = "continuing_absence"
                summary["classification"] = classification
                if classification == "no_longer_listed":
                    summary["reason"] = "The exact IP is absent from a later successfully refreshed snapshot. This does not prove remediation."
                elif classification == "newly_observed_listing":
                    summary["reason"] = "The exact IP appears in a newer successfully refreshed snapshot."
                elif classification == "unknown":
                    summary["reason"] = "The result changed without a different validated snapshot; no change event was inferred."
                else:
                    summary["reason"] = None
                last_valid[source_id] = {"listed": listed, "snapshot_id": summary["snapshot_id"]}
            summary["investigation_id"] = item.id
            summary["investigation_created_at"] = item.created_at
            histories[source_id].append(summary)
            if item.id == current_investigation.id:
                current_sources[source_id] = summary

    vt_run = selected_runs.get((investigation.id, "reputation"))
    vt_evidence = evidence_by_run.get(vt_run.id) if vt_run else None
    if vt_run or vt_evidence:
        current_sources["reputation"] = _run_summary(vt_run, vt_evidence, source_name="reputation")
    else:
        current_sources["reputation"] = _run_summary(None, None, source_name="reputation")

    listed_sources = [source for source in ("spamhaus_drop", "cins_army")
                      if current_sources.get(source, {}).get("state") == "listed"]
    both_known = all(current_sources.get(source, {}).get("state") in {"listed", "not_listed"}
                     for source in FEED_COLLECTORS)
    if len(listed_sources) == 2:
        label = "Listed by two sources"
    elif len(listed_sources) == 1:
        label = "Listed by one source"
    elif both_known:
        label = "No listing found in these snapshots"
    else:
        label = "Listing coverage unknown or partial"
    return {
        "asset_ip": asset.identifier,
        "sources": [current_sources.get(source_id) for source_id in ("spamhaus_drop", "cins_army", "reputation")],
        "listed_sources": [FEED_COLLECTORS[source] for source in listed_sources],
        "corroboration_label": label,
        "corroboration_note": "These feeds are separate datasets. Their overlap is not treated as independent measurements and does not automatically increase severity.",
        "history": [entry for source_id in FEED_COLLECTORS for entry in histories[source_id]],
    }
