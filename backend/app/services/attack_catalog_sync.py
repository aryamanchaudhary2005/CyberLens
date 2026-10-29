"""Safe synchronization and durable activation for MITRE ATT&CK Enterprise STIX."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import logging
import re
import time
from typing import Any, Callable
from urllib.parse import urlsplit
import uuid

from redis import Redis
from rq import Queue
from rq.exceptions import DuplicateJobError
from sqlalchemy import update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from app.config import Settings, get_settings
from app.database import SessionLocal
from app.logging_config import redact_secrets
from app.models import AttackCatalogVersion, AuditEvent, User, new_id, now_utc

logger = logging.getLogger("cyberlens.attack_catalog")

MITRE_REPOSITORY = "https://github.com/mitre-attack/attack-stix-data"
GITHUB_COMMIT_API = "https://api.github.com/repos/mitre-attack/attack-stix-data/commits/master"
RAW_ROOT = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data"
ENTERPRISE_COLLECTION_ID = "x-mitre-collection--1f5f1533-f617-4ca8-9ab4-6a02367fa019"
MAX_INDEX_BYTES = 2_000_000
MAX_BUNDLE_BYTES = 50_000_000
MAX_STIX_OBJECTS = 80_000
MAX_IMPORT_SECONDS = 150.0
MAX_DISPATCH_ATTEMPTS = 8
STALE_IMPORT_SECONDS = 15 * 60
RELEASE_PATTERN = re.compile(r"^(\d{1,3})\.(\d{1,3})$")
EXTERNAL_TECHNIQUE_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$")
STIX_ID_PATTERN = re.compile(r"^[a-z0-9-]+--[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
OFFICIAL_SOURCE = "MITRE ATT&CK Enterprise STIX 2.1"
MITRE_ATTRIBUTION = (
    "MITRE ATT&CK® is a registered trademark of The MITRE Corporation. Copyright 2020-2025 "
    "The MITRE Corporation. Approved for public release. Case number 19-3504. "
    "Used under the MITRE ATT&CK Terms of Use."
)


class AttackCatalogImportError(ValueError):
    """Safe operator-facing import error without remote response content."""


def _parse_time(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 40:
        raise AttackCatalogImportError("A required STIX timestamp is missing or invalid.")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AttackCatalogImportError("A required STIX timestamp is missing or invalid.") from exc
    if parsed.tzinfo is None:
        raise AttackCatalogImportError("A required STIX timestamp must include a timezone.")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _validate_stix_id(value: Any, expected_type: str | None = None) -> str:
    if not isinstance(value, str) or not STIX_ID_PATTERN.fullmatch(value):
        raise AttackCatalogImportError("The bundle contains an invalid STIX identifier.")
    if expected_type and not value.startswith(expected_type + "--"):
        raise AttackCatalogImportError("A STIX object identifier does not match its object type.")
    return value


def _external_reference(obj: dict[str, Any]) -> dict[str, str]:
    refs = obj.get("external_references")
    if not isinstance(refs, list):
        raise AttackCatalogImportError("An Enterprise technique has no external ATT&CK identifier.")
    matches = [row for row in refs if isinstance(row, dict) and row.get("source_name") == "mitre-attack"]
    if len(matches) != 1:
        raise AttackCatalogImportError("An Enterprise technique has missing or ambiguous ATT&CK references.")
    ref = matches[0]
    external_id = ref.get("external_id")
    if not isinstance(external_id, str) or not EXTERNAL_TECHNIQUE_PATTERN.fullmatch(external_id):
        raise AttackCatalogImportError("An Enterprise technique has an invalid external technique ID.")
    return {key: str(ref[key]) for key in ("source_name", "external_id", "url") if isinstance(ref.get(key), str)}


def _saved_references(obj: dict[str, Any]) -> list[dict[str, str]]:
    refs = obj.get("external_references", [])
    if not isinstance(refs, list):
        raise AttackCatalogImportError("A STIX external_references field is malformed.")
    saved = []
    for ref in refs:
        if not isinstance(ref, dict):
            raise AttackCatalogImportError("A STIX external reference is malformed.")
        value = {key: str(ref[key])[:2000] for key in ("source_name", "external_id", "url", "description")
                 if isinstance(ref.get(key), str)}
        if value:
            saved.append(value)
    return saved


def normalize_enterprise_bundle(
    bundle: dict[str, Any], *, release_version: str, source_reference: str,
    retrieved_at: datetime, checksum: str,
) -> dict[str, Any]:
    """Validate the required Enterprise ATT&CK object set and build local records.

    URL-valued STIX references are retained as attribution only; this importer
    never fetches them.
    """
    if not isinstance(bundle, dict) or bundle.get("type") != "bundle" or bundle.get("spec_version") != "2.1":
        raise AttackCatalogImportError("The response is not a STIX 2.1 bundle.")
    _validate_stix_id(bundle.get("id"), "bundle")
    objects = bundle.get("objects")
    if not isinstance(objects, list) or not objects or len(objects) > MAX_STIX_OBJECTS:
        raise AttackCatalogImportError("The STIX bundle is empty or exceeds the object limit.")

    by_stix_id: dict[str, dict[str, Any]] = {}
    for obj in objects:
        if not isinstance(obj, dict) or not isinstance(obj.get("type"), str):
            raise AttackCatalogImportError("The bundle contains a malformed STIX object.")
        stix_id = _validate_stix_id(obj.get("id"), obj["type"])
        if stix_id in by_stix_id:
            raise AttackCatalogImportError("The STIX bundle contains duplicate object identifiers.")
        by_stix_id[stix_id] = obj

    tactic_rows: dict[str, dict[str, Any]] = {}
    tactic_by_shortname: dict[str, dict[str, Any]] = {}
    for obj in objects:
        if obj["type"] != "x-mitre-tactic":
            continue
        domains = obj.get("x_mitre_domains")
        if not isinstance(domains, list) or "enterprise-attack" not in domains:
            continue
        shortname = obj.get("x_mitre_shortname")
        name = obj.get("name")
        description = obj.get("description")
        if not isinstance(shortname, str) or not re.fullmatch(r"[a-z0-9-]{2,80}", shortname):
            raise AttackCatalogImportError("An Enterprise tactic has an invalid short name.")
        if not isinstance(name, str) or not name.strip() or not isinstance(description, str):
            raise AttackCatalogImportError("An Enterprise tactic is missing its name or description.")
        revoked, deprecated = obj.get("revoked", False), obj.get("x_mitre_deprecated", False)
        if not isinstance(revoked, bool) or not isinstance(deprecated, bool):
            raise AttackCatalogImportError("An Enterprise tactic lifecycle flag is malformed.")
        if shortname in tactic_by_shortname:
            raise AttackCatalogImportError("The STIX bundle contains duplicate Enterprise tactics.")
        row = {
            "stix_id": obj["id"], "shortname": shortname, "name": name.strip(),
            "description": description, "created": _parse_time(obj.get("created")),
            "modified": _parse_time(obj.get("modified")),
            "revoked": revoked, "deprecated": deprecated,
        }
        row["selectable"] = not row["revoked"] and not row["deprecated"]
        tactic_by_shortname[shortname] = row
        tactic_rows[row["stix_id"]] = row

    techniques: dict[str, dict[str, Any]] = {}
    stix_to_external: dict[str, str] = {}
    for obj in objects:
        if obj["type"] != "attack-pattern":
            continue
        domains = obj.get("x_mitre_domains")
        if not isinstance(domains, list) or "enterprise-attack" not in domains:
            continue
        name = obj.get("name")
        description = obj.get("description")
        if not isinstance(name, str) or not name.strip() or not isinstance(description, str):
            raise AttackCatalogImportError("An Enterprise technique is missing its name or description.")
        external_ref = _external_reference(obj)
        external_id = external_ref["external_id"]
        if external_id in techniques:
            raise AttackCatalogImportError("The STIX bundle contains duplicate Enterprise technique IDs.")
        is_subtechnique = obj.get("x_mitre_is_subtechnique", False)
        if not isinstance(is_subtechnique, bool):
            raise AttackCatalogImportError("An Enterprise technique has an invalid sub-technique flag.")
        if is_subtechnique != ("." in external_id):
            raise AttackCatalogImportError("A sub-technique flag does not match its external ID.")
        phases = obj.get("kill_chain_phases")
        if not isinstance(phases, list):
            raise AttackCatalogImportError("An Enterprise technique has no tactic relationships.")
        tactic_shortnames: set[str] = set()
        for phase in phases:
            if not isinstance(phase, dict):
                raise AttackCatalogImportError("An Enterprise technique has a malformed tactic relationship.")
            if phase.get("kill_chain_name") == "mitre-attack":
                phase_name = phase.get("phase_name")
                if not isinstance(phase_name, str) or phase_name not in tactic_by_shortname:
                    raise AttackCatalogImportError("A technique references a missing Enterprise tactic.")
                tactic_shortnames.add(phase_name)
        if not tactic_shortnames:
            raise AttackCatalogImportError("An Enterprise technique has no Enterprise tactic relationship.")
        tactic_names = [tactic_by_shortname[key]["name"] for key in sorted(tactic_shortnames)]
        selectable_tactic_names = [tactic_by_shortname[key]["name"] for key in sorted(tactic_shortnames)
                                   if tactic_by_shortname[key]["selectable"]]
        revoked, deprecated = obj.get("revoked", False), obj.get("x_mitre_deprecated", False)
        if not isinstance(revoked, bool) or not isinstance(deprecated, bool):
            raise AttackCatalogImportError("A technique lifecycle flag is malformed.")
        row = {
            "id": external_id, "external_id": external_id, "stix_id": obj["id"],
            "name": name.strip(), "description": description,
            "tactics": tactic_names, "selectable_tactics": selectable_tactic_names,
            "tactic_ids": [tactic_by_shortname[key]["stix_id"] for key in sorted(tactic_shortnames)],
            "url": f"https://attack.mitre.org/techniques/{external_id.replace('.', '/')}/",
            "references": _saved_references(obj), "created": _parse_time(obj.get("created")),
            "modified": _parse_time(obj.get("modified")), "revoked": revoked,
            "deprecated": deprecated, "is_subtechnique": is_subtechnique,
            "parent_id": None, "parent_stix_id": None,
            "selectable": not revoked and not deprecated and bool(selectable_tactic_names),
        }
        techniques[external_id] = row
        stix_to_external[obj["id"]] = external_id

    if not techniques or not tactic_rows:
        raise AttackCatalogImportError("The bundle contains no Enterprise tactics or techniques.")

    relationships: dict[str, dict[str, str]] = {}
    relationship_records: list[dict[str, Any]] = []
    for obj in objects:
        if obj["type"] != "relationship" or obj.get("relationship_type") != "subtechnique-of":
            continue
        rel_id = obj["id"]
        source_ref = obj.get("source_ref")
        target_ref = obj.get("target_ref")
        _validate_stix_id(source_ref, "attack-pattern")
        _validate_stix_id(target_ref, "attack-pattern")
        child_id, parent_id = stix_to_external.get(source_ref), stix_to_external.get(target_ref)
        if child_id is None or parent_id is None:
            raise AttackCatalogImportError("A sub-technique relationship references a missing Enterprise technique.")
        if child_id in relationships or "." not in child_id or "." in parent_id:
            raise AttackCatalogImportError("A sub-technique relationship is inconsistent or duplicated.")
        relationships[child_id] = {"parent_id": parent_id, "parent_stix_id": target_ref}
        revoked = obj.get("revoked", False)
        if not isinstance(revoked, bool):
            raise AttackCatalogImportError("A sub-technique relationship lifecycle flag is malformed.")
        relationship_records.append({
            "stix_id": rel_id, "relationship_type": "subtechnique-of", "source_id": child_id,
            "target_id": parent_id, "modified": _parse_time(obj.get("modified")),
            "revoked": revoked,
        })

    for technique_id, row in techniques.items():
        if row["is_subtechnique"]:
            relationship = relationships.get(technique_id)
            if relationship is None:
                raise AttackCatalogImportError("A sub-technique has no valid parent relationship.")
            row.update(relationship)
        elif technique_id in relationships:
            raise AttackCatalogImportError("A parent technique is incorrectly marked as a sub-technique.")

    techniques_list = sorted(techniques.values(), key=lambda item: item["id"])
    tactics_list = sorted(tactic_rows.values(), key=lambda item: item["shortname"])
    return {
        "catalog_version": "", "framework": "MITRE ATT&CK Enterprise",
        "release_version": release_version, "snapshot_date": retrieved_at.date().isoformat(),
        "source_url": "https://attack.mitre.org/", "source": OFFICIAL_SOURCE,
        "source_reference": source_reference, "retrieved_at": retrieved_at.isoformat(),
        "checksum": checksum, "stix_spec_version": "2.1", "tactics": tactics_list,
        "techniques": techniques_list, "relationships": relationship_records,
        "attribution": MITRE_ATTRIBUTION,
    }


def _json_response(response: Any, *, expected_url: str, label: str, max_bytes: int) -> dict[str, Any]:
    if response.status != 200:
        raise AttackCatalogImportError(f"The official {label} endpoint returned HTTP {response.status}.")
    if response.final_url != expected_url:
        raise AttackCatalogImportError(f"The official {label} endpoint redirected away from its approved location.")
    if len(response.body) > max_bytes:
        raise AttackCatalogImportError(f"The official {label} response exceeded the configured size limit.")
    try:
        value = json.loads(response.body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AttackCatalogImportError(f"The official {label} response was not valid JSON.") from exc
    if not isinstance(value, dict):
        raise AttackCatalogImportError(f"The official {label} response had an unexpected shape.")
    return value


def fetch_current_enterprise_catalog(*, clock: Callable[[], datetime] = now_utc) -> dict[str, Any]:
    """Download an index and Enterprise bundle from fixed, approved official hosts."""
    from app.network import safe_get

    deadline = time.monotonic() + MAX_IMPORT_SECONDS
    commit_response = safe_get(
        GITHUB_COMMIT_API, timeout=30, max_bytes=100_000, max_redirects=0,
        headers={"accept": "application/vnd.github+json", "user-agent": "CyberLens-ATTACK-catalog-sync"},
        deadline=deadline,
    )
    commit_data = _json_response(commit_response, expected_url=GITHUB_COMMIT_API,
                                 label="GitHub commit", max_bytes=100_000)
    commit_sha = commit_data.get("sha")
    if not isinstance(commit_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", commit_sha):
        raise AttackCatalogImportError("GitHub did not return a valid immutable commit reference.")

    index_url = f"{RAW_ROOT}/{commit_sha}/index.json"
    index = _json_response(safe_get(index_url, timeout=30, max_bytes=MAX_INDEX_BYTES, max_redirects=0,
                                    headers={"accept": "application/json"}, deadline=deadline),
                           expected_url=index_url, label="collection index", max_bytes=MAX_INDEX_BYTES)
    collections = index.get("collections")
    if not isinstance(collections, list):
        raise AttackCatalogImportError("The official collection index has no collections list.")
    enterprise = [item for item in collections if isinstance(item, dict)
                  and item.get("name") == "Enterprise ATT&CK" and item.get("id") == ENTERPRISE_COLLECTION_ID]
    if len(enterprise) != 1 or not isinstance(enterprise[0].get("versions"), list):
        raise AttackCatalogImportError("The official index does not contain one recognized Enterprise ATT&CK collection.")
    versions = []
    for item in enterprise[0]["versions"]:
        if not isinstance(item, dict):
            raise AttackCatalogImportError("The official Enterprise collection index contains a malformed release.")
        version, modified, listed_url = item.get("version"), item.get("modified"), item.get("url")
        if not isinstance(version, str) or not RELEASE_PATTERN.fullmatch(version):
            raise AttackCatalogImportError("The official Enterprise index contains an invalid release version.")
        expected_master_url = f"{RAW_ROOT}/master/enterprise-attack/enterprise-attack-{version}.json"
        if listed_url != expected_master_url:
            raise AttackCatalogImportError("The official Enterprise index contains a release outside the approved source path.")
        versions.append((tuple(int(part) for part in version.split(".")), version, modified))
    if not versions:
        raise AttackCatalogImportError("The official Enterprise index contains no releases.")
    _version_sort, release_version, source_modified = max(versions, key=lambda item: item[0])
    if source_modified is not None:
        source_modified = _parse_time(source_modified)

    bundle_url = f"{RAW_ROOT}/{commit_sha}/enterprise-attack/enterprise-attack-{release_version}.json"
    response = safe_get(bundle_url, timeout=120, max_bytes=MAX_BUNDLE_BYTES, max_redirects=0,
                        headers={"accept": "application/json"}, deadline=deadline)
    bundle_json = _json_response(response, expected_url=bundle_url, label="Enterprise STIX bundle",
                                 max_bytes=MAX_BUNDLE_BYTES)
    raw = response.body
    checksum = hashlib.sha256(raw).hexdigest()
    retrieved_at = clock().astimezone(timezone.utc)
    source_reference = (
        f"https://github.com/mitre-attack/attack-stix-data/blob/{commit_sha}/"
        f"enterprise-attack/enterprise-attack-{release_version}.json"
    )
    catalog = normalize_enterprise_bundle(
        bundle_json, release_version=release_version, source_reference=source_reference,
        retrieved_at=retrieved_at, checksum=checksum,
    )
    catalog["index_source_reference"] = f"https://github.com/mitre-attack/attack-stix-data/blob/{commit_sha}/index.json"
    catalog["release_modified"] = source_modified
    catalog_version = f"mitre-attack-enterprise-{release_version}-{checksum}"
    catalog["catalog_version"] = catalog_version
    return {
        "catalog_version": catalog_version, "release_version": release_version,
        "source_reference": source_reference, "retrieved_at": retrieved_at,
        "checksum": checksum, "catalog_json": catalog,
        "result_json": {
            "technique_count": len(catalog["techniques"]),
            "tactic_count": len(catalog["tactics"]),
            "subtechnique_count": sum(1 for item in catalog["techniques"] if item["is_subtechnique"]),
            "revoked_count": sum(1 for item in catalog["techniques"] if item["revoked"]),
            "deprecated_count": sum(1 for item in catalog["techniques"] if item["deprecated"]),
            "source_modified": source_modified,
        },
    }


def queue_catalog_sync(db: Session, actor: User) -> AttackCatalogVersion:
    now = now_utc()
    row_id = new_id()
    row = AttackCatalogVersion(
        id=row_id, catalog_version=f"sync-{row_id}", source=OFFICIAL_SOURCE,
        source_reference=None, import_status="queued", active=False,
        available_at=now, dispatch_attempts=0, requested_by=actor.id,
        created_at=now, updated_at=now,
    )
    db.add(row)
    db.add(AuditEvent(
        actor_id=actor.id, action="attack.catalog_sync_requested", entity_type="attack_catalog_sync",
        entity_id=row.id, details_json={"catalog_version_id": row.id, "scope": "Enterprise ATT&CK only"},
        created_at=now,
    ))
    db.commit()
    db.refresh(row)
    return row


def dispatch_pending_catalog_syncs(
    db: Session, limit: int = 10, *, queue: Any = None, now: datetime | None = None,
) -> int:
    """Deliver durable sync requests with stable RQ job IDs."""
    now = now or now_utc()
    rows = (db.query(AttackCatalogVersion).filter(
        AttackCatalogVersion.import_status == "queued",
        (AttackCatalogVersion.available_at.is_(None) | (AttackCatalogVersion.available_at <= now)),
    ).order_by(AttackCatalogVersion.created_at, AttackCatalogVersion.id)
        .limit(max(1, min(limit, 50))).with_for_update(skip_locked=True).all())
    if not rows:
        return 0
    owned_connection = None
    if queue is None:
        owned_connection = Redis.from_url(get_settings().redis_url, socket_timeout=2)
        queue = Queue("attack-catalog", connection=owned_connection, default_timeout=180)
    delivered = 0
    try:
        for row in rows:
            job_id = f"attack-catalog-sync-{row.id}"
            try:
                queue.enqueue("app.jobs.sync_attack_catalog", row.id, job_id=job_id, retry=None, job_timeout=180)
            except DuplicateJobError:
                # The dispatcher may have published successfully before it committed its status update.
                pass
            except Exception as exc:
                row.dispatch_attempts += 1
                row.error_summary = f"Queue delivery failed ({type(exc).__name__})."
                delay = min(2 ** min(row.dispatch_attempts, 6), 60)
                row.available_at = now + timedelta(seconds=delay)
                row.updated_at = now
                if row.dispatch_attempts >= MAX_DISPATCH_ATTEMPTS:
                    row.import_status = "failed"
                    row.completed_at = now
                    db.add(AuditEvent(actor_id=row.requested_by, action="attack.catalog_sync_failed",
                                      entity_type="attack_catalog_sync", entity_id=row.id,
                                      details_json={"status": "failed", "reason": "queue_delivery_exhausted"},
                                      created_at=now))
                db.commit()
                logger.warning("ATT&CK catalog job delivery failed", extra={"job_id": job_id,
                                                                              "attempt": row.dispatch_attempts})
                continue
            db.execute(update(AttackCatalogVersion).where(
                AttackCatalogVersion.id == row.id, AttackCatalogVersion.import_status == "queued"
            ).values(import_status="dispatched", updated_at=now))
            db.commit()
            delivered += 1
    finally:
        if owned_connection is not None:
            owned_connection.close()
    return delivered


def reconcile_stale_catalog_syncs(db: Session, *, now: datetime | None = None) -> int:
    now = now or now_utc()
    cutoff = now - timedelta(seconds=STALE_IMPORT_SECONDS)
    stale = db.query(AttackCatalogVersion).filter(
        AttackCatalogVersion.import_status.in_(["downloading", "validating"]),
        AttackCatalogVersion.updated_at < cutoff,
        AttackCatalogVersion.active.is_(False),
    ).with_for_update(skip_locked=True).all()
    for row in stale:
        row.import_status = "failed"
        row.error_summary = "The import worker stopped before activation. Start a new synchronization to retry."
        row.completed_at = now
        row.updated_at = now
        db.add(AuditEvent(
            actor_id=row.requested_by, action="attack.catalog_sync_failed", entity_type="attack_catalog_sync",
            entity_id=row.id, details_json={"status": "failed", "reason": "stale_worker"}, created_at=now,
        ))
    if stale:
        db.commit()
    return len(stale)


def mark_catalog_sync_failed(catalog_version_id: str, reason: str, *, session_factory: sessionmaker = SessionLocal) -> None:
    """Record unexpected RQ worker termination without touching the active version."""
    now = now_utc()
    with session_factory() as db:
        row = db.get(AttackCatalogVersion, catalog_version_id)
        if row is None or row.active or row.import_status in {"active", "available", "duplicate", "failed"}:
            return
        row.import_status = "failed"
        row.error_summary = redact_secrets(reason)[:500]
        row.completed_at = now
        row.updated_at = now
        db.add(AuditEvent(actor_id=row.requested_by, action="attack.catalog_sync_failed",
                          entity_type="attack_catalog_sync", entity_id=row.id,
                          details_json={"status": "failed", "reason": "worker_terminated"}, created_at=now))
        db.commit()


def _safe_import_error(exc: Exception) -> str:
    if isinstance(exc, AttackCatalogImportError):
        return redact_secrets(str(exc))[:500]
    if isinstance(exc, TimeoutError):
        return "The official ATT&CK request exceeded its configured deadline."
    return f"Import failed ({type(exc).__name__}). Check the worker log for the request ID."


def process_catalog_sync(
    catalog_version_id: str, *, session_factory: sessionmaker = SessionLocal,
    settings: Settings | None = None, fetcher: Callable[[], dict[str, Any]] = fetch_current_enterprise_catalog,
) -> None:
    """Fetch, stage and atomically activate one catalog without touching old mappings."""
    settings = settings or get_settings()
    now = now_utc()
    with session_factory() as db:
        row = db.get(AttackCatalogVersion, catalog_version_id, with_for_update=True)
        if row is None or row.import_status not in {"queued", "dispatched", "downloading", "validating"}:
            return
        if settings.app_mode == "demo":
            row.import_status = "failed"
            row.error_summary = "ATT&CK synchronization is disabled in Demo mode. The bundled catalog remains available."
            row.completed_at = now
            row.updated_at = now
            db.add(AuditEvent(actor_id=row.requested_by, action="attack.catalog_sync_failed",
                              entity_type="attack_catalog_sync", entity_id=row.id,
                              details_json={"status": "failed", "reason": "demo_mode"}, created_at=now))
            db.commit()
            return
        if row.import_status in {"downloading", "validating"} and row.updated_at and row.updated_at > now - timedelta(seconds=30):
            return
        row.import_status = "downloading"
        row.updated_at = now
        db.commit()

    try:
        fetched = fetcher()
        required = {"catalog_version", "release_version", "source_reference", "retrieved_at", "checksum", "catalog_json", "result_json"}
        if not required.issubset(fetched) or not re.fullmatch(r"[0-9a-f]{64}", str(fetched.get("checksum", ""))):
            raise AttackCatalogImportError("The staged Enterprise import is incomplete.")
        with session_factory() as db:
            row = db.get(AttackCatalogVersion, catalog_version_id, with_for_update=True)
            if row is None:
                return
            row.import_status = "validating"
            row.updated_at = now_utc()
            db.commit()

        with session_factory() as db:
            row = db.get(AttackCatalogVersion, catalog_version_id, with_for_update=True)
            if row is None:
                return
            existing = db.query(AttackCatalogVersion).filter(
                AttackCatalogVersion.release_version == fetched["release_version"],
                AttackCatalogVersion.checksum == fetched["checksum"],
                AttackCatalogVersion.import_status.in_(["active", "available"]),
            ).order_by(AttackCatalogVersion.created_at).first()
            if existing:
                row.release_version = fetched["release_version"]
                row.source_reference = fetched["source_reference"]
                row.retrieved_at = fetched["retrieved_at"]
                row.checksum = fetched["checksum"]
                row.import_status = "duplicate"
                row.duplicate_of = existing.catalog_version
                row.result_json = {**(fetched.get("result_json") or {}), "duplicate": True}
                row.error_summary = None
                row.completed_at = now_utc()
                row.updated_at = row.completed_at
                db.add(AuditEvent(actor_id=row.requested_by, action="attack.catalog_sync_completed",
                                  entity_type="attack_catalog_version", entity_id=existing.id,
                                  details_json={"status": "duplicate", "catalog_version": existing.catalog_version,
                                                "checksum": fetched["checksum"]}, created_at=row.completed_at))
                db.commit()
                return

            # Lock the existing versions before switching the one-active pointer.
            # The partial unique index remains the final cross-process race guard.
            db.query(AttackCatalogVersion).with_for_update().all()
            for current in db.query(AttackCatalogVersion).filter(AttackCatalogVersion.active.is_(True)).all():
                current.active = False
                if current.import_status == "active":
                    current.import_status = "available"
                current.updated_at = now_utc()
            # The partial unique index must observe the old active flag cleared
            # before the incoming version's active flag is written.
            db.flush()

            catalog_json = fetched["catalog_json"]
            if not isinstance(catalog_json, dict) or catalog_json.get("catalog_version") != fetched["catalog_version"]:
                raise AttackCatalogImportError("The staged Enterprise catalog version does not match its import record.")
            row.catalog_version = fetched["catalog_version"]
            row.source = OFFICIAL_SOURCE
            row.release_version = fetched["release_version"]
            row.source_reference = fetched["source_reference"]
            row.retrieved_at = fetched["retrieved_at"]
            row.checksum = fetched["checksum"]
            row.catalog_json = catalog_json
            row.result_json = fetched["result_json"]
            row.error_summary = None
            row.duplicate_of = None
            row.import_status = "active"
            row.active = True
            row.completed_at = now_utc()
            row.updated_at = row.completed_at
            db.add(AuditEvent(actor_id=row.requested_by, action="attack.catalog_activated",
                              entity_type="attack_catalog_version", entity_id=row.id,
                              details_json={"catalog_version": row.catalog_version,
                                            "release_version": row.release_version,
                                            "checksum": row.checksum, **(row.result_json or {})},
                              created_at=row.completed_at))
            try:
                db.commit()
            except IntegrityError as exc:
                db.rollback()
                raise AttackCatalogImportError("Another synchronization activated a catalog at the same time; the previous active catalog remains available.") from exc
    except Exception as exc:
        message = _safe_import_error(exc)
        with session_factory() as db:
            row = db.get(AttackCatalogVersion, catalog_version_id)
            if row is not None and not row.active:
                row.import_status = "failed"
                row.error_summary = message
                row.completed_at = now_utc()
                row.updated_at = row.completed_at
                db.add(AuditEvent(actor_id=row.requested_by, action="attack.catalog_sync_failed",
                                  entity_type="attack_catalog_sync", entity_id=row.id,
                                  details_json={"status": "failed", "error": message}, created_at=row.completed_at))
                db.commit()
        logger.warning("ATT&CK catalog synchronization failed", extra={"catalog_version_id": catalog_version_id,
                                                                           "reason": message})


def version_payload(row: AttackCatalogVersion) -> dict[str, Any]:
    result = row.result_json or {}
    return {
        "id": row.id, "catalog_version": row.catalog_version, "source": row.source,
        "release_version": row.release_version, "source_reference": row.source_reference,
        "retrieved_at": row.retrieved_at, "checksum": row.checksum,
        "import_status": row.import_status, "active": row.active,
        "technique_count": result.get("technique_count", 0), "tactic_count": result.get("tactic_count", 0),
        "subtechnique_count": result.get("subtechnique_count", 0), "revoked_count": result.get("revoked_count", 0),
        "deprecated_count": result.get("deprecated_count", 0), "error_summary": row.error_summary,
        "duplicate_of": row.duplicate_of, "requested_by": row.requested_by,
        "created_at": row.created_at, "completed_at": row.completed_at,
    }


def catalog_versions_payload(db: Session) -> dict[str, Any]:
    rows = db.query(AttackCatalogVersion).order_by(AttackCatalogVersion.created_at.desc(), AttackCatalogVersion.id.desc()).limit(100).all()
    active = next((row for row in rows if row.active), None)
    return {
        "active_catalog_version": active.catalog_version if active else None,
        "active": version_payload(active) if active else None,
        "versions": [version_payload(row) for row in rows],
        "attribution": MITRE_ATTRIBUTION,
        "checksum_notice": "The checksum detects changes to the retrieved bytes. It does not independently authenticate the source or prove forensic authenticity.",
    }
