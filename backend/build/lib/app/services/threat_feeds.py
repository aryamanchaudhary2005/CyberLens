"""Durable, attributed snapshots for fixed public threat-feed sources.

The persisted PostgreSQL snapshot is the investigation source of truth. RQ is
used only to deliver refresh requests; an investigation never contacts the
feed provider and always pins the exact snapshot it read.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
import logging
import time
from pathlib import Path
from typing import Any, Callable

from redis import Redis
from rq import Queue
from rq.exceptions import DuplicateJobError
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from app.config import Settings, get_settings
from app.database import SessionLocal
from app.models import (
    AuditEvent,
    ThreatFeedNetwork,
    ThreatFeedRefreshAttempt,
    ThreatFeedSnapshot,
    ThreatFeedSource,
    ThreatFeedUrl,
    User,
    new_id,
    now_utc,
)
from app.network import OutboundTimeout, SafeResponse, UnsafeDestination, safe_get
from app.openphish_access import assert_personal_owner, openphish_configuration
from app.url_normalization import canonicalize_http_url

logger = logging.getLogger("cyberlens.threat_feeds")

SOURCE_ID = "spamhaus_drop"
SOURCE_NAME = "Spamhaus DROP IPv4 and IPv6"
PARSER_VERSION = "spamhaus-drop-jsonl-v1"
FEED_URLS = {
    4: "https://www.spamhaus.org/drop/drop_v4.json",
    6: "https://www.spamhaus.org/drop/drop_v6.json",
}
ATTRIBUTION = "Spamhaus Project DROP data. Retain the provider date and copyright with this data."
CINS_SOURCE_ID = "cins_army"
CINS_SOURCE_NAME = "CINS Army IP list"
CINS_PARSER_VERSION = "cins-army-ip-list-v1"
CINS_FEED_URL = "https://cinsscore.com/list/ci-badguys.txt"
CINS_ATTRIBUTION = (
    "CINS Army list, provided by CINS Score / Sentinel IPS. The feed contains IP addresses only; "
    "it does not supply per-indicator scores, attack categories, report counts, or first-seen times."
)
OPENPHISH_SOURCE_ID = "openphish"
OPENPHISH_SOURCE_NAME = "OpenPhish Community Feed"
OPENPHISH_PARSER_VERSION = "openphish-url-list-v1"
OPENPHISH_FEED_URL = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
OPENPHISH_ATTRIBUTION = (
    "OpenPhish Community Phishing Feed. Community-feed use is non-commercial and limited by the provider's current terms."
)
MAX_REFRESH_AGE_SECONDS = 15 * 60
MAX_DISPATCH_ATTEMPTS = 5


class ThreatFeedError(ValueError):
    """A feed payload or refresh result did not pass validation."""


class ThreatFeedCooldown(ThreatFeedError):
    def __init__(self, next_refresh_at: datetime, source_name: str = SOURCE_NAME):
        self.next_refresh_at = next_refresh_at
        super().__init__(f"The {source_name} refresh interval has not elapsed.")


@dataclass(frozen=True)
class ParsedDropFeed:
    family: int
    networks: tuple[dict[str, Any], ...]
    metadata: dict[str, Any]
    published_at: datetime


@dataclass(frozen=True)
class ParsedCinsFeed:
    addresses: tuple[dict[str, Any], ...]
    metadata: dict[str, Any]


@dataclass(frozen=True)
class ParsedOpenPhishFeed:
    urls: tuple[dict[str, Any], ...]
    metadata: dict[str, Any]


FEED_SOURCE_IDS = (SOURCE_ID, CINS_SOURCE_ID, OPENPHISH_SOURCE_ID)


def _source_name(source_id: str) -> str:
    return {CINS_SOURCE_ID: CINS_SOURCE_NAME, OPENPHISH_SOURCE_ID: OPENPHISH_SOURCE_NAME}.get(source_id, SOURCE_NAME)


def _source_enabled(source_id: str, settings: Settings) -> bool:
    if source_id == CINS_SOURCE_ID:
        return settings.cins_army_enabled
    if source_id == OPENPHISH_SOURCE_ID:
        return bool(openphish_configuration(settings)["ready"])
    return settings.spamhaus_drop_enabled


def _source_interval_hours(source_id: str, settings: Settings) -> int:
    if source_id == CINS_SOURCE_ID:
        return settings.cins_army_refresh_interval_hours
    if source_id == OPENPHISH_SOURCE_ID:
        return settings.openphish_refresh_interval_hours
    return settings.spamhaus_drop_refresh_interval_hours


def _source_freshness_hours(source_id: str, settings: Settings) -> int:
    if source_id == CINS_SOURCE_ID:
        return settings.cins_army_freshness_hours
    if source_id == OPENPHISH_SOURCE_ID:
        return settings.openphish_freshness_hours
    return settings.spamhaus_drop_freshness_hours


def parse_cins_army_feed(content: bytes, *, max_bytes: int | None = None) -> ParsedCinsFeed:
    """Parse the official text list as exact canonical IPs, never CIDR ranges."""
    settings = get_settings()
    byte_limit = max_bytes or settings.cins_army_max_download_bytes
    if not content or not content.strip():
        raise ThreatFeedError("The CINS Army feed was empty.")
    if len(content) > byte_limit:
        raise ThreatFeedError("The provider response exceeded the configured size limit.")
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ThreatFeedError("The CINS Army feed was not UTF-8 text.") from exc
    if "<html" in text[:512].casefold() or "<!doctype" in text[:512].casefold():
        raise ThreatFeedError("The provider returned HTML instead of an IP list.")
    addresses: dict[str, dict[str, Any]] = {}
    for line_number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith(("#", ";", "//")):
            continue
        try:
            address = ipaddress.ip_address(line)
        except ValueError as exc:
            raise ThreatFeedError(f"Invalid IP address at CINS feed line {line_number}.") from exc
        canonical = str(address)
        addresses[canonical] = {
            "address_family": address.version,
            # The legacy column stores the exact bare IP when indicator_type=ip.
            # Do not append a prefix or infer a network from an individual entry.
            "network": canonical,
            "sbl_id": "",
            "indicator_type": "ip",
        }
    if not addresses:
        raise ThreatFeedError("The CINS Army feed had no valid IP entries.")
    records = tuple(addresses[key] for key in sorted(addresses, key=lambda item: (ipaddress.ip_address(item).version,
                                                                                  int(ipaddress.ip_address(item)))))
    return ParsedCinsFeed(
        records,
        {"provider": "CINS Army", "record_count": len(records),
         "source_url": CINS_FEED_URL, "attribution": CINS_ATTRIBUTION,
         "indicator_type": "ip"},
    )


def parse_openphish_feed(content: bytes, *, max_bytes: int | None = None) -> ParsedOpenPhishFeed:
    """Validate one HTTP(S) URL per line without visiting any listed URL."""
    settings = get_settings()
    byte_limit = settings.openphish_max_download_bytes if max_bytes is None else max_bytes
    if not content or not content.strip():
        raise ThreatFeedError("The OpenPhish feed was empty.")
    if len(content) > byte_limit:
        raise ThreatFeedError("The provider response exceeded the configured size limit.")
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ThreatFeedError("The OpenPhish feed was not UTF-8 text.") from exc
    if "<html" in text[:512].casefold() or "<!doctype" in text[:512].casefold():
        raise ThreatFeedError("The provider returned HTML instead of a URL list.")
    urls: dict[str, dict[str, str]] = {}
    for line_number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith(("#", ";", "//")):
            continue
        try:
            canonical, hostname = canonicalize_http_url(line)
        except ValueError as exc:
            raise ThreatFeedError(f"Invalid URL at OpenPhish feed line {line_number}.") from exc
        urls[canonical] = {
            "canonical_url": canonical,
            "canonical_sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
            "hostname": hostname,
        }
    if not urls:
        raise ThreatFeedError("The OpenPhish feed had no valid URL entries.")
    records = tuple(urls[key] for key in sorted(urls))
    return ParsedOpenPhishFeed(records, {
        "provider": OPENPHISH_SOURCE_NAME,
        "source_url": OPENPHISH_FEED_URL,
        "attribution": OPENPHISH_ATTRIBUTION,
        "indicator_type": "url",
        "record_count": len(records),
        "per_indicator_metadata": False,
        "coverage_note": (
            "The community feed contains URL strings only. It does not supply brand names, confidence scores, "
            "discovery dates, or per-indicator timestamps. CyberLens does not visit listed destinations."
        ),
    })


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def parse_drop_feed(content: bytes, family: int, *, max_bytes: int | None = None) -> ParsedDropFeed:
    """Parse the official JSON-lines feed shape, preserving terminal metadata."""
    if family not in (4, 6):
        raise ThreatFeedError("Unsupported address family.")
    if not content or not content.strip():
        raise ThreatFeedError("The provider returned an empty feed.")
    if len(content) > (max_bytes or get_settings().spamhaus_drop_max_download_bytes):
        raise ThreatFeedError("The provider response exceeded the configured size limit.")
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ThreatFeedError("The provider feed was not UTF-8 JSON.") from exc
    if "<html" in text[:512].casefold() or "<!doctype" in text[:512].casefold():
        raise ThreatFeedError("The provider returned HTML instead of a feed.")

    records: list[dict[str, Any]] = []
    metadata_rows: list[dict[str, Any]] = []
    metadata_seen = False
    lines = text.splitlines()
    if not lines:
        raise ThreatFeedError("The provider returned an empty feed.")
    for number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line:
            raise ThreatFeedError(f"Malformed empty line at feed line {number}.")
        try:
            item = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ThreatFeedError(f"Malformed JSON at feed line {number}.") from exc
        if not isinstance(item, dict):
            raise ThreatFeedError(f"Unexpected record at feed line {number}.")
        if item.get("type") is not None:
            if metadata_seen or number != len(lines):
                raise ThreatFeedError("Feed metadata must appear once as the final line.")
            metadata_seen = True
            metadata_rows.append(item)
            continue
        if metadata_seen:
            raise ThreatFeedError("Network records followed feed metadata.")
        cidr = item.get("cidr")
        sbl_id = item.get("sblid")
        if not isinstance(cidr, str) or not isinstance(sbl_id, str) or not sbl_id.strip():
            raise ThreatFeedError(f"A network record at line {number} is missing cidr or SBL ID.")
        try:
            network = ipaddress.ip_network(cidr, strict=True)
        except ValueError as exc:
            raise ThreatFeedError(f"Invalid CIDR at feed line {number}.") from exc
        if network.version != family:
            raise ThreatFeedError(f"Address family mismatch at feed line {number}.")
        if len(sbl_id) > 40:
            raise ThreatFeedError(f"SBL identifier at feed line {number} is too long.")
        records.append({"address_family": family, "network": network.with_prefixlen, "sbl_id": sbl_id.strip()})

    if len(metadata_rows) != 1:
        raise ThreatFeedError("The provider feed must end with exactly one metadata record.")
    provider_metadata = metadata_rows[0]
    timestamp = provider_metadata.get("timestamp")
    copyright_text = provider_metadata.get("copyright")
    if isinstance(timestamp, bool) or not isinstance(timestamp, (int, float)) or timestamp <= 0:
        raise ThreatFeedError("The provider feed metadata has no valid publication timestamp.")
    if not isinstance(copyright_text, str) or not copyright_text.strip() or len(copyright_text) > 500:
        raise ThreatFeedError("The provider feed metadata has no valid copyright notice.")
    declared_records = provider_metadata.get("records")
    if declared_records is not None and (
        isinstance(declared_records, bool) or not isinstance(declared_records, int)
        or declared_records < 0 or declared_records != len(records)
    ):
        raise ThreatFeedError("The provider metadata record count does not match the complete feed.")
    try:
        published_at = datetime.fromtimestamp(timestamp, tz=timezone.utc)
    except (OverflowError, OSError, ValueError) as exc:
        raise ThreatFeedError("The provider feed publication timestamp is invalid.") from exc
    safe_metadata = {
        key: provider_metadata[key]
        for key in ("type", "timestamp", "size", "records", "copyright", "terms")
        if key in provider_metadata and isinstance(provider_metadata[key], (str, int, float, bool))
    }
    safe_metadata["copyright"] = copyright_text.strip()
    safe_metadata["record_count"] = len(records)
    return ParsedDropFeed(family, tuple(records), safe_metadata, published_at)


def _ensure_source(db: Session, source_id: str = SOURCE_ID) -> ThreatFeedSource:
    source = db.get(ThreatFeedSource, source_id)
    if source is not None:
        return source
    urls = ({CINS_SOURCE_ID: [CINS_FEED_URL], OPENPHISH_SOURCE_ID: [OPENPHISH_FEED_URL]}
            .get(source_id, list(FEED_URLS.values())))
    source = ThreatFeedSource(
        id=source_id, display_name=_source_name(source_id), source_urls_json=urls,
        validators_json={}, created_at=now_utc(), updated_at=now_utc(),
    )
    db.add(source)
    db.flush()
    return source


def queue_refresh(
    db: Session,
    *,
    requested_by: User | None = None,
    trigger_kind: str = "admin",
    source_id: str = SOURCE_ID,
    now: datetime | None = None,
    settings: Settings | None = None,
) -> ThreatFeedRefreshAttempt:
    """Reserve one cooldown slot and persist one idempotent refresh request."""
    if trigger_kind not in {"scheduled", "admin"}:
        raise ValueError("Unsupported refresh trigger.")
    if source_id not in FEED_SOURCE_IDS:
        raise ValueError("Unsupported threat-feed source.")
    settings = settings or get_settings()
    if source_id == OPENPHISH_SOURCE_ID:
        if settings.app_mode != "live":
            raise ThreatFeedError("Demo mode uses a synthetic OpenPhish fixture and does not refresh provider data.")
        config = openphish_configuration(settings)
        if not config["ready"]:
            raise ThreatFeedError(str(config["reason"]))
    now = _utc(now or now_utc())
    source = db.query(ThreatFeedSource).filter_by(id=source_id).with_for_update().one_or_none()
    if source is None:
        source = _ensure_source(db, source_id)
        db.flush()
    if source_id == OPENPHISH_SOURCE_ID:
        config = openphish_configuration(settings)
        if config["access_scope"] == "personal_only":
            owner = (db.query(User).filter_by(username=settings.openphish_personal_owner_username.strip().lower(),
                                              is_active=True).one_or_none())
            if owner is None:
                raise ThreatFeedError("The configured OpenPhish personal owner is not an active account.")
            if requested_by is not None and requested_by.id != owner.id:
                raise ThreatFeedError("Only the configured personal owner may request OpenPhish refreshes.")
            try:
                assert_personal_owner(db, settings, owner)
            except ValueError as exc:
                raise ThreatFeedError(str(exc)) from exc
    existing = (db.query(ThreatFeedRefreshAttempt)
                .filter(ThreatFeedRefreshAttempt.source_id == source_id,
                        ThreatFeedRefreshAttempt.status.in_(["queued", "dispatched", "running"]))
                .order_by(ThreatFeedRefreshAttempt.created_at.desc()).first())
    if existing is not None:
        return existing
    next_refresh = _utc(source.next_refresh_at)
    if next_refresh is not None and now < next_refresh:
        raise ThreatFeedCooldown(next_refresh, source.display_name)
    attempt = ThreatFeedRefreshAttempt(
        id=new_id(), source_id=source_id, trigger_kind=trigger_kind,
        requested_by=requested_by.id if requested_by else None, status="queued", available_at=now,
        created_at=now, updated_at=now,
    )
    source.next_refresh_at = now + timedelta(hours=_source_interval_hours(source_id, settings))
    source.dispatch_attempts = 0
    source.updated_at = now
    db.add(attempt)
    if requested_by is not None:
        db.add(AuditEvent(actor_id=requested_by.id, action="threat_feed.refresh_requested",
                          entity_type="threat_feed", entity_id=source_id,
                          details_json={"attempt_id": attempt.id, "trigger_kind": trigger_kind}, created_at=now))
    try:
        db.flush()
    except IntegrityError:
        # The partial unique index is the final guard when simultaneous queue
        # requests reach PostgreSQL before the source-row lock is acquired.
        db.rollback()
        existing = (db.query(ThreatFeedRefreshAttempt)
                    .filter(ThreatFeedRefreshAttempt.source_id == source_id,
                            ThreatFeedRefreshAttempt.status.in_(["queued", "dispatched", "running"]))
                    .order_by(ThreatFeedRefreshAttempt.created_at.desc()).first())
        if existing is not None:
            return existing
        raise
    return attempt


def enqueue_due_refresh(db: Session, *, now: datetime | None = None, settings: Settings | None = None) -> bool:
    settings = settings or get_settings()
    if settings.app_mode != "live":
        return False
    now = _utc(now or now_utc())
    scheduled = False
    for source_id in FEED_SOURCE_IDS:
        if not _source_enabled(source_id, settings):
            continue
        source = db.query(ThreatFeedSource).filter_by(id=source_id).with_for_update().one_or_none()
        if source is None:
            source = _ensure_source(db, source_id)
            db.flush()
        next_refresh = _utc(source.next_refresh_at)
        if next_refresh is not None and next_refresh > now:
            continue
        existing = db.query(ThreatFeedRefreshAttempt).filter(
            ThreatFeedRefreshAttempt.source_id == source_id,
            ThreatFeedRefreshAttempt.status.in_(["queued", "dispatched", "running"]),
        ).first()
        if existing:
            continue
        queue_refresh(db, trigger_kind="scheduled", source_id=source_id, now=now, settings=settings)
        scheduled = True
    if scheduled:
        db.commit()
    return scheduled


def dispatch_pending_refreshes(db: Session, *, queue: Any = None, limit: int = 10,
                               now: datetime | None = None, settings: Settings | None = None) -> int:
    """Publish durable refresh attempts using stable RQ identities."""
    settings = settings or get_settings()
    now = _utc(now or now_utc())
    rows = (db.query(ThreatFeedRefreshAttempt).filter(
        ThreatFeedRefreshAttempt.status == "queued", ThreatFeedRefreshAttempt.available_at <= now,
    ).order_by(ThreatFeedRefreshAttempt.created_at, ThreatFeedRefreshAttempt.id)
        .limit(max(1, min(limit, 50))).with_for_update(skip_locked=True).all())
    if not rows:
        return 0
    owned = None
    if queue is None:
        owned = Redis.from_url(settings.redis_url, socket_timeout=2)
        queue = Queue("threat-feeds", connection=owned, default_timeout=max(60, int(settings.collector_timeout_seconds * 4)))
    delivered = 0
    try:
        for attempt in rows:
            job_id = f"threat-feed-refresh-{attempt.id}"
            try:
                queue.enqueue("app.jobs.refresh_threat_feed", attempt.id, job_id=job_id, retry=None,
                              job_timeout=max(60, int(settings.collector_timeout_seconds * 4)))
            except DuplicateJobError:
                pass
            except Exception as exc:
                attempt.dispatch_attempts += 1
                attempt.error_code = "queue_delivery_failed"
                attempt.updated_at = now
                if attempt.dispatch_attempts >= MAX_DISPATCH_ATTEMPTS:
                    attempt.status = "failed"
                    attempt.completed_at = now
                    _audit_refresh(db, attempt, "threat_feed.refresh_failed", {"reason": "queue_delivery_exhausted"})
                else:
                    attempt.available_at = now + timedelta(seconds=min(2 ** attempt.dispatch_attempts, 60))
                db.commit()
                logger.warning("threat feed job delivery failed", extra={"attempt_id": attempt.id,
                                                                           "exception_type": type(exc).__name__})
                continue
            attempt.status = "dispatched"
            attempt.dispatch_attempts += 1
            attempt.error_code = None
            attempt.updated_at = now
            db.commit()
            delivered += 1
    finally:
        if owned is not None:
            owned.close()
    return delivered


def reconcile_stale_refreshes(db: Session, *, now: datetime | None = None,
                              stale_after_seconds: int = MAX_REFRESH_AGE_SECONDS) -> int:
    now = _utc(now or now_utc())
    cutoff = now - timedelta(seconds=stale_after_seconds)
    rows = db.query(ThreatFeedRefreshAttempt).filter(
        ThreatFeedRefreshAttempt.status.in_(["dispatched", "running"]),
        ThreatFeedRefreshAttempt.updated_at < cutoff,
    ).with_for_update(skip_locked=True).all()
    for attempt in rows:
        if attempt.status == "dispatched":
            # Re-deliver the same attempt/job ID. The database claim below fences duplicate execution.
            attempt.status = "queued"
            attempt.available_at = now
            attempt.error_code = "stale_delivery_reconciled"
            attempt.updated_at = now
        else:
            attempt.status = "failed"
            attempt.completed_at = now
            attempt.error_code = "stale_worker"
            attempt.updated_at = now
            _audit_refresh(db, attempt, "threat_feed.refresh_failed", {"reason": "stale_worker"})
    if rows:
        db.commit()
    return len(rows)


def _audit_refresh(db: Session, attempt: ThreatFeedRefreshAttempt, action: str, details: dict[str, Any]) -> None:
    db.add(AuditEvent(actor_id=attempt.requested_by, action=action, entity_type="threat_feed_refresh",
                      entity_id=attempt.id, details_json=details, created_at=now_utc()))


def active_snapshot_payload(db: Session, *, now: datetime | None = None,
                            settings: Settings | None = None, source_id: str = SOURCE_ID) -> dict[str, Any]:
    settings = settings or get_settings()
    now = _utc(now or now_utc())
    source = db.get(ThreatFeedSource, source_id)
    snapshot = db.get(ThreatFeedSnapshot, source.active_snapshot_id) if source and source.active_snapshot_id else None
    revalidated = _utc(source.last_successful_revalidation_at) if source else None
    age_seconds = max(0, int((now - revalidated).total_seconds())) if revalidated else None
    freshness = "unavailable" if snapshot is None else (
        "fresh" if age_seconds is not None and age_seconds <= _source_freshness_hours(source_id, settings) * 3600 else "stale"
    )
    latest = (db.query(ThreatFeedRefreshAttempt).filter_by(source_id=source_id)
              .order_by(ThreatFeedRefreshAttempt.created_at.desc(), ThreatFeedRefreshAttempt.id.desc()).first())
    attribution = (OPENPHISH_ATTRIBUTION if source_id == OPENPHISH_SOURCE_ID else
                   CINS_ATTRIBUTION if source_id == CINS_SOURCE_ID else ATTRIBUTION)
    coverage_note = ("The OpenPhish community feed lists URL strings only. Exact canonical URL matches are direct; "
                     "same-host matches are contextual. The feed has no per-indicator confidence or observation time. "
                     "CyberLens does not visit listed destinations. No match does not establish safety."
                     if source_id == OPENPHISH_SOURCE_ID else
                     "The CINS Army feed is a list of IP indicators without provider-supplied per-indicator scores, "
                     "attack categories, report counts, or first-seen times. A no-match only means the exact IP was not in this snapshot."
                     if source_id == CINS_SOURCE_ID else
                     "DROP is a narrow advisory list. A no-match means only that an IP is not listed in this snapshot; it does not establish safety or complete reputation coverage.")
    return {
        "id": source_id,
        "name": source.display_name if source else _source_name(source_id),
        "enabled": settings.app_mode == "live" and _source_enabled(source_id, settings),
        "mode": settings.app_mode,
        "freshness": freshness,
        "snapshot_id": snapshot.id if snapshot else None,
        "content_sha256": snapshot.content_sha256 if snapshot else None,
        "parser_version": snapshot.parser_version if snapshot else (
            OPENPHISH_PARSER_VERSION if source_id == OPENPHISH_SOURCE_ID else
            CINS_PARSER_VERSION if source_id == CINS_SOURCE_ID else PARSER_VERSION),
        "record_count": snapshot.record_count if snapshot else 0,
        "retrieved_at": snapshot.retrieved_at if snapshot else None,
        "published_at": snapshot.published_at if snapshot else None,
        "last_successful_revalidation_at": source.last_successful_revalidation_at if source else None,
        "snapshot_age_seconds": age_seconds,
        "freshness_limit_seconds": _source_freshness_hours(source_id, settings) * 3600,
        "next_refresh_at": source.next_refresh_at if source else None,
        "metadata": snapshot.metadata_json if snapshot else None,
        "attribution": attribution,
        "latest_attempt": _attempt_payload(latest) if latest else None,
        "coverage_note": coverage_note,
    }


def _attempt_payload(attempt: ThreatFeedRefreshAttempt) -> dict[str, Any]:
    return {
        "id": attempt.id, "trigger_kind": attempt.trigger_kind, "status": attempt.status,
        "requested_at": attempt.created_at, "started_at": attempt.started_at,
        "completed_at": attempt.completed_at, "snapshot_id": attempt.snapshot_id,
        "error_code": attempt.error_code,
    }


def load_active_snapshot_for_collection(db: Session, *, now: datetime | None = None,
                                         settings: Settings | None = None,
                                         source_id: str = SOURCE_ID) -> dict[str, Any] | None:
    settings = settings or get_settings()
    source = db.get(ThreatFeedSource, source_id)
    if source is None or not source.active_snapshot_id:
        return None
    snapshot = db.get(ThreatFeedSnapshot, source.active_snapshot_id)
    if snapshot is None:
        return None
    revalidated = _utc(source.last_successful_revalidation_at)
    current = _utc(now or now_utc())
    age_seconds = max(0, int((current - revalidated).total_seconds())) if revalidated else None
    fresh = age_seconds is not None and age_seconds <= _source_freshness_hours(source_id, settings) * 3600
    if source_id == OPENPHISH_SOURCE_ID:
        url_rows = (db.query(ThreatFeedUrl).filter_by(snapshot_id=snapshot.id)
                    .order_by(ThreatFeedUrl.canonical_sha256).all())
        records = [{"canonical_url": row.canonical_url, "canonical_sha256": row.canonical_sha256,
                    "hostname": row.hostname} for row in url_rows]
        try:
            integrity_valid = (snapshot.parser_version == OPENPHISH_PARSER_VERSION
                               and len(records) == snapshot.record_count
                               and _canonical_openphish_hash(records) == snapshot.content_sha256)
        except (KeyError, TypeError, ValueError):
            integrity_valid = False
        return {
            "source_id": source_id, "snapshot_id": snapshot.id, "content_sha256": snapshot.content_sha256,
            "parser_version": snapshot.parser_version, "record_count": snapshot.record_count,
            "retrieved_at": snapshot.retrieved_at, "published_at": snapshot.published_at,
            "last_successful_revalidation_at": source.last_successful_revalidation_at,
            "snapshot_age_seconds": age_seconds, "fresh": fresh, "metadata": snapshot.metadata_json,
            "integrity_valid": integrity_valid, "urls": records,
        }
    rows = (db.query(ThreatFeedNetwork).filter_by(snapshot_id=snapshot.id)
            .order_by(ThreatFeedNetwork.address_family, ThreatFeedNetwork.network, ThreatFeedNetwork.sbl_id).all())
    if source_id == CINS_SOURCE_ID:
        records = [{"address_family": row.address_family, "network": row.network, "sbl_id": row.sbl_id,
                    "indicator_type": row.indicator_type}
                   for row in rows if row.indicator_type == "ip"]
        try:
            integrity_valid = (snapshot.parser_version == CINS_PARSER_VERSION and
                               len(records) == snapshot.record_count and
                               _canonical_cins_hash(records) == snapshot.content_sha256)
        except (KeyError, TypeError, ValueError):
            integrity_valid = False
        return {
            "source_id": source_id, "snapshot_id": snapshot.id, "content_sha256": snapshot.content_sha256,
            "parser_version": snapshot.parser_version, "record_count": snapshot.record_count,
            "retrieved_at": snapshot.retrieved_at, "published_at": snapshot.published_at,
            "last_successful_revalidation_at": source.last_successful_revalidation_at,
            "snapshot_age_seconds": age_seconds, "fresh": fresh, "metadata": snapshot.metadata_json,
            "integrity_valid": integrity_valid, "networks": records,
            "addresses": frozenset(row["network"] for row in records),
        }
    rows_by_family: dict[int, list[dict[str, Any]]] = {4: [], 6: []}
    for row in rows:
        rows_by_family.setdefault(row.address_family, []).append({
            "address_family": row.address_family, "network": row.network, "sbl_id": row.sbl_id,
        })
    feeds: dict[int, ParsedDropFeed] = {}
    metadata_by_family = (snapshot.metadata_json or {}).get("feeds", {})
    for family, key in ((4, "ipv4"), (6, "ipv6")):
        item = metadata_by_family.get(key)
        if not isinstance(item, dict) or not isinstance(item.get("provider_metadata"), dict):
            continue
        try:
            published_at = datetime.fromisoformat(str(item.get("published_at")).replace("Z", "+00:00"))
        except ValueError:
            continue
        feeds[family] = ParsedDropFeed(
            family=family,
            networks=tuple(sorted(rows_by_family.get(family, []), key=lambda record: (record["network"], record["sbl_id"]))),
            metadata=item["provider_metadata"], published_at=_utc(published_at),
        )
    integrity_valid = len(feeds) == 2 and _canonical_snapshot_hash(feeds) == snapshot.content_sha256
    return {
        "source_id": source_id, "snapshot_id": snapshot.id, "content_sha256": snapshot.content_sha256,
        "parser_version": snapshot.parser_version, "record_count": snapshot.record_count,
        "retrieved_at": snapshot.retrieved_at, "published_at": snapshot.published_at,
        "last_successful_revalidation_at": source.last_successful_revalidation_at,
        "snapshot_age_seconds": age_seconds, "fresh": fresh,
        "metadata": snapshot.metadata_json, "integrity_valid": integrity_valid,
        "networks": [{"address_family": row.address_family, "network": row.network, "sbl_id": row.sbl_id} for row in rows],
    }


def match_public_ip(value: str, records: list[dict[str, Any]] | tuple[dict[str, Any], ...]) -> list[dict[str, str]]:
    """Return every matching CIDR without expanding a network into addresses."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return []
    if not address.is_global:
        return []
    matches: list[dict[str, str]] = []
    for record in records:
        try:
            network = ipaddress.ip_network(record["network"], strict=True)
        except (KeyError, ValueError, TypeError):
            continue
        if network.version == address.version and address in network:
            matches.append({"network": network.with_prefixlen, "sbl_id": str(record["sbl_id"])})
    return sorted(matches, key=lambda item: (-ipaddress.ip_network(item["network"]).prefixlen,
                                             item["network"], item["sbl_id"]))


def match_cins_ip(value: str, snapshot: dict[str, Any] | set[str] | frozenset[str] | list[dict[str, Any]] | tuple[dict[str, Any], ...]) -> str | None:
    """Match a directly submitted public IP against exact CINS IP indicators."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if not address.is_global:
        return None
    canonical = str(address)
    if isinstance(snapshot, (set, frozenset)):
        return canonical if canonical in snapshot else None
    if isinstance(snapshot, dict):
        addresses = snapshot.get("addresses")
        records = snapshot.get("networks", [])
        if isinstance(addresses, (set, frozenset)):
            return canonical if canonical in addresses else None
    else:
        records = snapshot
    for record in records if isinstance(records, (list, tuple)) else ():
        if record.get("indicator_type") == "ip" and record.get("network") == canonical:
            return canonical
    return None


def _validators_for(headers: dict[str, str]) -> dict[str, str]:
    result = {}
    for key, header_name in (("etag", "etag"), ("last_modified", "last-modified")):
        value = headers.get(header_name)
        if value and len(value) <= 500 and "\r" not in value and "\n" not in value:
            result[key] = value
    return result


def _fetch_one(family: int, existing_validators: dict[str, str], *, settings: Settings,
               deadline: float, fetcher: Callable[..., SafeResponse]) -> tuple[ParsedDropFeed | None, dict[str, str], int]:
    headers = {"accept": "application/json, text/json"}
    validators = existing_validators if isinstance(existing_validators, dict) else {}
    if validators.get("etag"):
        headers["if-none-match"] = validators["etag"]
    if validators.get("last_modified"):
        headers["if-modified-since"] = validators["last_modified"]
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise OutboundTimeout("Spamhaus request exceeded the shared refresh deadline")
    response = fetcher(
        FEED_URLS[family], timeout=min(settings.collector_timeout_seconds, remaining),
        deadline=deadline, max_bytes=settings.spamhaus_drop_max_download_bytes,
        max_redirects=0, headers=headers, verify_tls=True,
    )
    if response.status == 304:
        return None, {**validators, **_validators_for(response.headers)}, response.status
    if response.status != 200:
        raise ThreatFeedError(f"The provider returned HTTP status {response.status}.")
    content_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type and content_type not in {"application/json", "text/json", "application/x-ndjson", "application/ndjson"}:
        raise ThreatFeedError("The provider returned an unexpected content type.")
    return parse_drop_feed(response.body, family, max_bytes=settings.spamhaus_drop_max_download_bytes), _validators_for(response.headers), response.status


def _canonical_snapshot_hash(feeds: dict[int, ParsedDropFeed]) -> str:
    canonical = {
        "parser_version": PARSER_VERSION,
        "feeds": {
            str(family): {
                "metadata": feed.metadata,
                "networks": sorted(feed.networks, key=lambda row: (row["network"], row["sbl_id"])),
            }
            for family, feed in sorted(feeds.items())
        },
    }
    payload = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _canonical_cins_hash(records: list[dict[str, Any]] | tuple[dict[str, Any], ...]) -> str:
    addresses = []
    for item in records:
        address = ipaddress.ip_address(item["network"])
        if item.get("indicator_type") != "ip" or item.get("address_family") != address.version:
            raise ValueError("The CINS snapshot contains a non-canonical IP indicator.")
        if item.get("sbl_id", "") != "":
            raise ValueError("The CINS feed does not provide per-indicator identifiers.")
        addresses.append(str(address))
    canonical = {
        "parser_version": CINS_PARSER_VERSION,
        "indicator_type": "ip",
        "addresses": sorted(addresses,
                             key=lambda item: (ipaddress.ip_address(item).version, int(ipaddress.ip_address(item)))),
    }
    payload = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _canonical_openphish_hash(records: list[dict[str, Any]] | tuple[dict[str, Any], ...]) -> str:
    urls = []
    for item in records:
        canonical, hostname = canonicalize_http_url(item["canonical_url"])
        expected_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        if (canonical != item["canonical_url"] or item.get("canonical_sha256") != expected_hash
                or item.get("hostname") != hostname):
            raise ValueError("The OpenPhish snapshot contains a non-canonical URL indicator.")
        urls.append(canonical)
    canonical_payload = {"parser_version": OPENPHISH_PARSER_VERSION, "urls": sorted(set(urls))}
    payload = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _openphish_previous_records(db: Session, snapshot_id: str | None) -> list[dict[str, str]]:
    if not snapshot_id:
        return []
    snapshot = db.get(ThreatFeedSnapshot, snapshot_id)
    if snapshot is None or snapshot.source_id != OPENPHISH_SOURCE_ID or snapshot.parser_version != OPENPHISH_PARSER_VERSION:
        return []
    rows = (db.query(ThreatFeedUrl).filter_by(snapshot_id=snapshot.id)
            .order_by(ThreatFeedUrl.canonical_sha256).all())
    records = [{"canonical_url": row.canonical_url, "canonical_sha256": row.canonical_sha256,
                "hostname": row.hostname} for row in rows]
    try:
        valid = len(records) == snapshot.record_count and _canonical_openphish_hash(records) == snapshot.content_sha256
    except (KeyError, TypeError, ValueError):
        valid = False
    return records if valid else []


def _load_previous_feeds(db: Session, snapshot_id: str | None) -> dict[int, ParsedDropFeed]:
    if not snapshot_id:
        return {}
    snapshot = db.get(ThreatFeedSnapshot, snapshot_id)
    if snapshot is None:
        return {}
    feeds: dict[int, ParsedDropFeed] = {}
    raw_meta = snapshot.metadata_json.get("feeds", {})
    for family, family_key in ((4, "ipv4"), (6, "ipv6")):
        data = raw_meta.get(family_key)
        if not isinstance(data, dict):
            continue
        rows = (db.query(ThreatFeedNetwork).filter_by(snapshot_id=snapshot.id, address_family=family)
                .order_by(ThreatFeedNetwork.network, ThreatFeedNetwork.sbl_id).all())
        published = data.get("published_at")
        if isinstance(published, str):
            try:
                published = datetime.fromisoformat(published.replace("Z", "+00:00"))
            except ValueError:
                published = None
        if published is None:
            continue
        feeds[family] = ParsedDropFeed(
            family=family,
            networks=tuple({"address_family": family, "network": row.network, "sbl_id": row.sbl_id} for row in rows),
            metadata=data.get("provider_metadata", {}),
            published_at=_utc(published),
        )
    if len(feeds) != 2 or _canonical_snapshot_hash(feeds) != snapshot.content_sha256:
        # Never combine an HTTP 304 with locally altered/incomplete rows. A
        # fresh full download can still replace this snapshot in one transaction.
        return {}
    return feeds


def _source_metadata(feeds: dict[int, ParsedDropFeed], validators: dict[int, dict[str, str]]) -> dict[str, Any]:
    return {
        "provider": "Spamhaus Project",
        "feed_name": "DROP / DROPv6",
        "attribution": ATTRIBUTION,
        "source_urls": list(FEED_URLS.values()),
        "feeds": {
            {4: "ipv4", 6: "ipv6"}[family]: {
                "provider_metadata": feed.metadata,
                "published_at": feed.published_at.isoformat(),
                "record_count": len(feed.networks),
                "source_url": FEED_URLS[family],
                "etag": validators.get(family, {}).get("etag"),
                "last_modified": validators.get(family, {}).get("last_modified"),
            }
            for family, feed in sorted(feeds.items())
        },
        "coverage_note": "A no-match means only that the directly checked IP was not listed in this snapshot. DROP is a narrow advisory list, not complete reputation coverage or proof that an asset is safe.",
    }


def _activate_snapshot(db: Session, *, feeds: dict[int, ParsedDropFeed], validators: dict[int, dict[str, str]],
                       source: ThreatFeedSource, attempt: ThreatFeedRefreshAttempt, now: datetime) -> tuple[str, bool]:
    all_networks = [row for feed in feeds.values() for row in feed.networks]
    if not all_networks:
        raise ThreatFeedError("The combined IPv4 and IPv6 feeds contained no network records.")
    digest = _canonical_snapshot_hash(feeds)
    published = max(feed.published_at for feed in feeds.values())
    return _activate_validated_snapshot(
        db, source=source, attempt=attempt, now=now, digest=digest, parser_version=PARSER_VERSION,
        records=all_networks, metadata=_source_metadata(feeds, validators), published_at=published,
        validators={str(family): value for family, value in validators.items()},
    )


def _activate_validated_snapshot(
    db: Session, *, source: ThreatFeedSource, attempt: ThreatFeedRefreshAttempt, now: datetime,
    digest: str, parser_version: str, records: list[dict[str, Any]], metadata: dict[str, Any],
    published_at: datetime | None, validators: dict[str, Any],
) -> tuple[str, bool]:
    """Atomically retain validated records and advance one source's active pointer."""
    if not records:
        raise ThreatFeedError("The validated feed contained no indicator records.")
    snapshot = (db.query(ThreatFeedSnapshot).filter_by(source_id=source.id, content_sha256=digest)
                .with_for_update().one_or_none())
    changed = snapshot is None
    if snapshot is None:
        snapshot = ThreatFeedSnapshot(
            id=new_id(), source_id=source.id, content_sha256=digest, parser_version=parser_version,
            record_count=len(records), retrieved_at=now, published_at=published_at, metadata_json=metadata,
        )
        db.add(snapshot)
        db.flush()
        if source.id == OPENPHISH_SOURCE_ID:
            db.bulk_insert_mappings(ThreatFeedUrl, [
                {"id": new_id(), "snapshot_id": snapshot.id, **record}
                for record in sorted(records, key=lambda row: row["canonical_sha256"])
            ])
        else:
            db.bulk_insert_mappings(ThreatFeedNetwork, [
                {"id": new_id(), "snapshot_id": snapshot.id, **record}
                for record in sorted(records, key=lambda row: (row["address_family"], row["network"], row.get("sbl_id", "")))
            ])
    source.active_snapshot_id = snapshot.id
    source.validators_json = validators
    source.last_successful_revalidation_at = now
    source.updated_at = now
    attempt.snapshot_id = snapshot.id
    attempt.status = "succeeded" if changed else "unchanged"
    attempt.completed_at = now
    attempt.updated_at = now
    attempt.error_code = None
    _audit_refresh(db, attempt, "threat_feed.refresh_completed", {
        "snapshot_id": snapshot.id, "content_sha256": digest,
        "record_count": snapshot.record_count, "changed": changed,
    })
    return snapshot.id, changed


def _cins_previous_records(db: Session, snapshot_id: str | None) -> list[dict[str, Any]]:
    if not snapshot_id:
        return []
    snapshot = db.get(ThreatFeedSnapshot, snapshot_id)
    if snapshot is None or snapshot.source_id != CINS_SOURCE_ID or snapshot.parser_version != CINS_PARSER_VERSION:
        return []
    rows = (db.query(ThreatFeedNetwork).filter_by(snapshot_id=snapshot.id, indicator_type="ip")
            .order_by(ThreatFeedNetwork.address_family, ThreatFeedNetwork.network).all())
    records = [{"address_family": row.address_family, "network": row.network, "sbl_id": row.sbl_id,
                "indicator_type": row.indicator_type} for row in rows]
    try:
        valid = len(records) == snapshot.record_count and _canonical_cins_hash(records) == snapshot.content_sha256
    except (KeyError, TypeError, ValueError):
        valid = False
    if not valid:
        return []
    return records


def _fetch_cins_feed(validators: dict[str, str], *, settings: Settings, deadline: float,
                     fetcher: Callable[..., SafeResponse]) -> tuple[ParsedCinsFeed | None, dict[str, str], int]:
    headers = {"accept": "text/plain, text/*;q=0.9, */*;q=0.1"}
    if validators.get("etag"):
        headers["if-none-match"] = validators["etag"]
    if validators.get("last_modified"):
        headers["if-modified-since"] = validators["last_modified"]
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise OutboundTimeout("CINS Army request exceeded the shared refresh deadline")
    response = fetcher(
        CINS_FEED_URL, timeout=min(settings.collector_timeout_seconds, remaining), deadline=deadline,
        max_bytes=settings.cins_army_max_download_bytes, max_redirects=0, headers=headers, verify_tls=True,
    )
    if response.status == 304:
        return None, {**validators, **_validators_for(response.headers)}, response.status
    if response.status != 200:
        raise ThreatFeedError(f"The provider returned HTTP status {response.status}.")
    content_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type and content_type not in {"text/plain", "text/x-log", "application/octet-stream"}:
        raise ThreatFeedError("The provider returned an unexpected content type.")
    return parse_cins_army_feed(response.body, max_bytes=settings.cins_army_max_download_bytes), _validators_for(response.headers), response.status


def _cins_snapshot_metadata(validators: dict[str, str], record_count: int) -> dict[str, Any]:
    return {
        "provider": "CINS Army", "feed_name": "CINS Army IP list", "attribution": CINS_ATTRIBUTION,
        "source_urls": [CINS_FEED_URL], "indicator_type": "ip", "record_count": record_count,
        "feed": {"source_url": CINS_FEED_URL, "etag": validators.get("etag"),
                 "last_modified": validators.get("last_modified")},
        "coverage_note": "The CINS Army list provides IP addresses only. CyberLens records snapshot observation time; no per-indicator score, attack category, report count, or first-seen time is present in the feed.",
    }


def _process_cins_attempt(attempt_id: str, *, session_factory: sessionmaker, settings: Settings,
                           fetcher: Callable[..., SafeResponse]) -> None:
    with session_factory() as db:
        attempt = db.get(ThreatFeedRefreshAttempt, attempt_id, with_for_update=True)
        if attempt is None or attempt.status != "running" or attempt.source_id != CINS_SOURCE_ID:
            return
        source = db.query(ThreatFeedSource).filter_by(id=CINS_SOURCE_ID).with_for_update().one()
        previous_id = source.active_snapshot_id
        validators = (source.validators_json or {}).get("feed", {})
        if not isinstance(validators, dict):
            validators = {}
        previous_records = _cins_previous_records(db, previous_id)
        previous_snapshot = db.get(ThreatFeedSnapshot, previous_id) if previous_id else None

    deadline = time.monotonic() + settings.collector_timeout_seconds
    parsed, response_validators, _status = _fetch_cins_feed(
        validators, settings=settings, deadline=deadline, fetcher=fetcher,
    )
    if parsed is None:
        if not previous_records or previous_snapshot is None:
            raise ThreatFeedError("The provider returned not-modified before a valid CINS Army snapshot existed.")
        records = previous_records
        digest = previous_snapshot.content_sha256
    else:
        records = list(parsed.addresses)
        digest = _canonical_cins_hash(records)
    next_validators = response_validators or validators
    metadata = _cins_snapshot_metadata(next_validators, len(records))
    now = now_utc()
    with session_factory() as db:
        source = db.query(ThreatFeedSource).filter_by(id=CINS_SOURCE_ID).with_for_update().one()
        attempt = db.get(ThreatFeedRefreshAttempt, attempt_id, with_for_update=True)
        if attempt is None or attempt.status != "running":
            return
        _activate_validated_snapshot(
            db, source=source, attempt=attempt, now=now, digest=digest,
            parser_version=CINS_PARSER_VERSION, records=records, metadata=metadata,
            published_at=None, validators={"feed": next_validators},
        )
        db.commit()


def _fetch_openphish_feed(validators: dict[str, str], *, settings: Settings, deadline: float,
                          fetcher: Callable[..., SafeResponse]) -> tuple[ParsedOpenPhishFeed | None, dict[str, str], int]:
    headers = {"accept": "text/plain, text/*;q=0.9, */*;q=0.1"}
    if validators.get("etag"):
        headers["if-none-match"] = validators["etag"]
    if validators.get("last_modified"):
        headers["if-modified-since"] = validators["last_modified"]
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise OutboundTimeout("OpenPhish request exceeded the shared refresh deadline")
    response = fetcher(
        OPENPHISH_FEED_URL, timeout=min(settings.collector_timeout_seconds, remaining), deadline=deadline,
        max_bytes=settings.openphish_max_download_bytes, max_redirects=0, headers=headers, verify_tls=True,
    )
    if response.status == 304:
        return None, {**validators, **_validators_for(response.headers)}, response.status
    if response.status != 200:
        raise ThreatFeedError(f"The provider returned HTTP status {response.status}.")
    content_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type and content_type not in {"text/plain", "text/x-log", "application/octet-stream"}:
        raise ThreatFeedError("The provider returned an unexpected content type.")
    parsed = parse_openphish_feed(response.body, max_bytes=settings.openphish_max_download_bytes)
    return parsed, _validators_for(response.headers), response.status


def _openphish_snapshot_metadata(validators: dict[str, str], record_count: int) -> dict[str, Any]:
    return {
        "provider": OPENPHISH_SOURCE_NAME, "feed_name": "OpenPhish Community Phishing Feed",
        "attribution": OPENPHISH_ATTRIBUTION, "source_urls": [OPENPHISH_FEED_URL],
        "indicator_type": "url", "record_count": record_count,
        "feed": {"source_url": OPENPHISH_FEED_URL, "etag": validators.get("etag"),
                 "last_modified": validators.get("last_modified")},
        "coverage_note": (
            "The feed lists URL strings only. It does not supply brands, confidence scores, discovery dates, or "
            "per-indicator observation times. CyberLens matches exact canonical URLs; same-host matches are context only. "
            "CyberLens does not visit listed destinations."
        ),
    }


def _process_openphish_attempt(attempt_id: str, *, session_factory: sessionmaker, settings: Settings,
                               fetcher: Callable[..., SafeResponse]) -> None:
    with session_factory() as db:
        attempt = db.get(ThreatFeedRefreshAttempt, attempt_id, with_for_update=True)
        if attempt is None or attempt.status != "running" or attempt.source_id != OPENPHISH_SOURCE_ID:
            return
        source = db.query(ThreatFeedSource).filter_by(id=OPENPHISH_SOURCE_ID).with_for_update().one_or_none()
        if source is None:
            raise ThreatFeedError("The OpenPhish source configuration is unavailable.")
        config = openphish_configuration(settings)
        if config["access_scope"] == "personal_only":
            owner = db.query(User).filter_by(
                username=(settings.openphish_personal_owner_username or "").strip().lower(), is_active=True,
            ).one_or_none()
            if owner is None:
                raise ThreatFeedError("The configured OpenPhish personal owner is not active.")
            try:
                assert_personal_owner(db, settings, owner)
            except ValueError as exc:
                raise ThreatFeedError(str(exc)) from exc
        previous_id = source.active_snapshot_id
        validators = (source.validators_json or {}).get("feed", {})
        if not isinstance(validators, dict):
            validators = {}
        previous_records = _openphish_previous_records(db, previous_id)
        previous_snapshot = db.get(ThreatFeedSnapshot, previous_id) if previous_id else None

    deadline = time.monotonic() + settings.collector_timeout_seconds
    parsed, response_validators, _status = _fetch_openphish_feed(
        validators, settings=settings, deadline=deadline, fetcher=fetcher,
    )
    if parsed is None:
        if not previous_records or previous_snapshot is None:
            raise ThreatFeedError("The provider returned not-modified before a valid OpenPhish snapshot existed.")
        records = previous_records
        digest = previous_snapshot.content_sha256
    else:
        records = list(parsed.urls)
        digest = _canonical_openphish_hash(records)
    next_validators = response_validators or validators
    metadata = _openphish_snapshot_metadata(next_validators, len(records))
    now = now_utc()
    with session_factory() as db:
        source = db.query(ThreatFeedSource).filter_by(id=OPENPHISH_SOURCE_ID).with_for_update().one()
        attempt = db.get(ThreatFeedRefreshAttempt, attempt_id, with_for_update=True)
        if attempt is None or attempt.status != "running":
            return
        _activate_validated_snapshot(
            db, source=source, attempt=attempt, now=now, digest=digest,
            parser_version=OPENPHISH_PARSER_VERSION, records=records, metadata=metadata,
            published_at=None, validators={"feed": next_validators},
        )
        db.commit()


def process_refresh_attempt(attempt_id: str, *, session_factory: sessionmaker = SessionLocal,
                            settings: Settings | None = None,
                            fetcher: Callable[..., SafeResponse] = safe_get) -> None:
    settings = settings or get_settings()
    with session_factory() as db:
        queued_attempt = db.get(ThreatFeedRefreshAttempt, attempt_id)
        if queued_attempt is None:
            return
        source_id = queued_attempt.source_id
    if source_id not in FEED_SOURCE_IDS:
        mark_refresh_failed(attempt_id, "unsupported_source", session_factory=session_factory)
        return
    if settings.app_mode != "live" or not _source_enabled(source_id, settings):
        mark_refresh_failed(attempt_id, "disabled", session_factory=session_factory,
                            message=f"{_source_name(source_id)} collection is disabled.")
        return
    with session_factory() as db:
        attempt = db.get(ThreatFeedRefreshAttempt, attempt_id, with_for_update=True)
        if attempt is None or attempt.status not in {"queued", "dispatched"}:
            return
        now = now_utc()
        attempt.status = "running"
        attempt.started_at = now
        attempt.updated_at = now
        db.commit()

    try:
        if source_id == OPENPHISH_SOURCE_ID:
            _process_openphish_attempt(attempt_id, session_factory=session_factory, settings=settings,
                                       fetcher=fetcher)
            return
        if source_id == CINS_SOURCE_ID:
            _process_cins_attempt(attempt_id, session_factory=session_factory, settings=settings, fetcher=fetcher)
            return
        with session_factory() as db:
            source = db.query(ThreatFeedSource).filter_by(id=SOURCE_ID).with_for_update().one()
            attempt = db.get(ThreatFeedRefreshAttempt, attempt_id, with_for_update=True)
            if attempt is None or attempt.status != "running":
                return
            previous_id = source.active_snapshot_id
            validators = {int(family): value for family, value in (source.validators_json or {}).items()
                          if str(family) in {"4", "6"} and isinstance(value, dict)}
            old_feeds = _load_previous_feeds(db, previous_id)

        deadline = time.monotonic() + settings.collector_timeout_seconds
        feeds: dict[int, ParsedDropFeed] = {}
        next_validators: dict[int, dict[str, str]] = {}
        statuses = {}
        for family in (4, 6):
            parsed, response_validators, status = _fetch_one(
                family, validators.get(family, {}), settings=settings, deadline=deadline, fetcher=fetcher,
            )
            statuses[family] = status
            next_validators[family] = response_validators or validators.get(family, {})
            if parsed is not None:
                feeds[family] = parsed
            elif family in old_feeds:
                feeds[family] = old_feeds[family]
            else:
                raise ThreatFeedError("The provider returned not-modified before a valid snapshot existed.")

        now = now_utc()
        with session_factory() as db:
            source = db.query(ThreatFeedSource).filter_by(id=SOURCE_ID).with_for_update().one()
            attempt = db.get(ThreatFeedRefreshAttempt, attempt_id, with_for_update=True)
            if attempt is None or attempt.status != "running":
                return
            attempt.http_status_v4 = statuses.get(4)
            attempt.http_status_v6 = statuses.get(6)
            _activate_snapshot(db, feeds=feeds, validators=next_validators,
                               source=source, attempt=attempt, now=now)
            db.commit()
    except Exception as exc:
        if isinstance(exc, UnsafeDestination):
            error_code = "unsafe_destination"
        elif isinstance(exc, OutboundTimeout) or isinstance(exc, TimeoutError):
            error_code = "timeout"
        elif isinstance(exc, ThreatFeedError):
            error_code = "invalid_or_unavailable_feed"
        else:
            error_code = "provider_request_failed"
        mark_refresh_failed(attempt_id, error_code, session_factory=session_factory)
        logger.warning("threat feed refresh failed", extra={"attempt_id": attempt_id, "source_id": source_id,
                                                              "error_code": error_code,
                                                              "exception_type": type(exc).__name__})


def mark_refresh_failed(attempt_id: str, error_code: str, *, session_factory: sessionmaker = SessionLocal,
                        message: str | None = None) -> None:
    with session_factory() as db:
        attempt = db.get(ThreatFeedRefreshAttempt, attempt_id, with_for_update=True)
        if attempt is None or attempt.status in {"succeeded", "unchanged", "failed"}:
            return
        now = now_utc()
        attempt.status = "failed"
        attempt.error_code = error_code[:80]
        attempt.completed_at = now
        attempt.updated_at = now
        _audit_refresh(db, attempt, "threat_feed.refresh_failed", {"reason": error_code})
        db.commit()


def spamhaus_status_payload(db: Session, *, now: datetime | None = None,
                            settings: Settings | None = None) -> dict[str, Any]:
    """Build live persisted status or the deterministic no-network Demo status."""
    settings = settings or get_settings()
    if settings.app_mode != "demo":
        return active_snapshot_payload(db, now=now, settings=settings)
    return {
        "id": SOURCE_ID, "name": SOURCE_NAME, "enabled": False, "mode": "demo",
        "freshness": "synthetic", "snapshot_id": "synthetic-spamhaus-drop-demo-v1",
        "content_sha256": None, "parser_version": PARSER_VERSION, "record_count": 2,
        "retrieved_at": None, "published_at": None, "last_successful_revalidation_at": None,
        "snapshot_age_seconds": 0, "freshness_limit_seconds": settings.spamhaus_drop_freshness_hours * 3600,
        "next_refresh_at": None, "metadata": {"provider": "Synthetic Spamhaus DROP fixture",
            "attribution": "Synthetic Demo fixture; no Spamhaus data is downloaded."},
        "attribution": "Synthetic Demo fixture; no Spamhaus data is downloaded.", "latest_attempt": None,
        "coverage_note": "Demo uses a synthetic local fixture and performs no external request.",
    }


def cins_army_status_payload(db: Session, *, now: datetime | None = None,
                             settings: Settings | None = None) -> dict[str, Any]:
    """Build CINS persisted status or synthetic Demo status without network access."""
    settings = settings or get_settings()
    if settings.app_mode != "demo":
        payload = active_snapshot_payload(db, now=now, settings=settings, source_id=CINS_SOURCE_ID)
        snapshot = load_active_snapshot_for_collection(db, now=now, settings=settings, source_id=CINS_SOURCE_ID)
        payload["integrity_valid"] = snapshot.get("integrity_valid") if snapshot else None
        if snapshot and not snapshot.get("integrity_valid"):
            payload["freshness"] = "integrity_failed"
        return payload
    fixture_path = Path(__file__).resolve().parents[1] / "data" / "cins_army_demo.json"
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    return {
        "id": CINS_SOURCE_ID, "name": CINS_SOURCE_NAME, "enabled": False, "mode": "demo",
        "freshness": "synthetic", "snapshot_id": "synthetic-cins-army-demo-v1",
        "content_sha256": None, "parser_version": fixture["fixture_version"],
        "record_count": len(fixture["addresses"]), "retrieved_at": None, "published_at": None,
        "last_successful_revalidation_at": None, "snapshot_age_seconds": 0,
        "integrity_valid": True,
        "freshness_limit_seconds": settings.cins_army_freshness_hours * 3600,
        "next_refresh_at": None, "metadata": {"provider": "Synthetic CINS Army fixture",
            "attribution": fixture["attribution"]},
        "attribution": fixture["attribution"], "latest_attempt": None,
        "coverage_note": "Demo uses synthetic reserved IPs, performs no external requests, and represents only the fields available from the provider feed.",
    }


def openphish_status_payload(db: Session, *, now: datetime | None = None,
                             settings: Settings | None = None) -> dict[str, Any]:
    """Expose configuration and snapshot health without returning indicators."""
    settings = settings or get_settings()
    config = openphish_configuration(settings)
    if settings.app_mode == "demo":
        fixture_path = Path(__file__).resolve().parents[1] / "data" / "openphish_demo.json"
        fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
        return {
            "id": OPENPHISH_SOURCE_ID, "name": OPENPHISH_SOURCE_NAME, "enabled": False, "mode": "demo",
            "configuration_state": "synthetic_demo", "configuration_reason": config["reason"],
            "access_scope": "synthetic_demo", "freshness": "synthetic",
            "snapshot_id": "synthetic-openphish-demo-v1", "content_sha256": None,
            "parser_version": fixture["fixture_version"], "record_count": len(fixture["listed_urls"]),
            "retrieved_at": None, "published_at": None, "last_successful_revalidation_at": None,
            "snapshot_age_seconds": 0, "freshness_limit_seconds": settings.openphish_freshness_hours * 3600,
            "next_refresh_at": None, "metadata": {"provider": "Synthetic OpenPhish fixture",
                "attribution": fixture["attribution"]},
            "attribution": fixture["attribution"], "latest_attempt": None, "integrity_valid": True,
            "coverage_note": "Demo uses one synthetic reserved-domain URL fixture and performs no external request.",
        }
    payload = active_snapshot_payload(db, now=now, settings=settings, source_id=OPENPHISH_SOURCE_ID)
    snapshot = load_active_snapshot_for_collection(db, now=now, settings=settings, source_id=OPENPHISH_SOURCE_ID)
    payload.update({
        "enabled": bool(config["ready"]),
        "configuration_state": config["state"],
        "configuration_reason": config["reason"],
        "access_scope": config["access_scope"],
        "integrity_valid": snapshot.get("integrity_valid") if snapshot else None,
    })
    if snapshot and not snapshot.get("integrity_valid"):
        payload["freshness"] = "integrity_failed"
    return payload
