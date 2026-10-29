"""FIRST EPSS lookups with provider-scoped Redis caching and throttling."""

from __future__ import annotations

from datetime import date, datetime, timezone
import hashlib
import json
import math
import re
from typing import Any, Iterable
from urllib.parse import urlencode

from redis import Redis
from redis.exceptions import RedisError

from app.config import get_settings
from app.network import UnsafeDestination, safe_get

EPSS_ENDPOINT = "https://api.first.org/data/v1/epss"
EPSS_SOURCE = "FIRST EPSS API"
EPSS_VERSION = "FIRST API v1"
EPSS_CACHE_TTL_SECONDS = 6 * 60 * 60
EPSS_RATE_WINDOW_SECONDS = 60
EPSS_MAX_REQUESTS_PER_WINDOW = 60
_CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)
_RATE_LIMIT_SCRIPT = """
local count = redis.call('INCR', KEYS[1])
if count == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
return count
"""


def _redis_client() -> Redis:
    return Redis.from_url(get_settings().redis_url, socket_connect_timeout=1, socket_timeout=1)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _cache_key(cve_ids: list[str]) -> str:
    digest = hashlib.sha256(",".join(cve_ids).encode("ascii")).hexdigest()
    return f"cyberlens:provider:epss:batch:{digest}"


def _parse_probability(value: Any, field: str) -> float:
    if not isinstance(value, (str, int, float)) or isinstance(value, bool):
        raise ValueError(f"FIRST EPSS returned an invalid {field}")
    try:
        parsed = float(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError(f"FIRST EPSS returned an invalid {field}") from exc
    if not math.isfinite(parsed) or not 0 <= parsed <= 1:
        raise ValueError(f"FIRST EPSS returned an out-of-range {field}")
    return parsed


def _freshness(source_date: str | None, observed_at: datetime) -> str:
    if source_date is None:
        return "unknown"
    try:
        score_date = date.fromisoformat(source_date)
    except (TypeError, ValueError):
        return "unknown"
    age_days = (observed_at.date() - score_date).days
    return "fresh" if 0 <= age_days <= 1 else "stale" if age_days > 1 else "unknown"


def _parse_response(payload: Any, requested: set[str], observed_at: datetime) -> dict[str, dict[str, Any]]:
    if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
        raise ValueError("FIRST EPSS response contains a malformed data list")
    result: dict[str, dict[str, Any]] = {}
    for item in payload["data"]:
        if not isinstance(item, dict) or not isinstance(item.get("cve"), str):
            raise ValueError("FIRST EPSS response contains a malformed record")
        cve_id = item["cve"].upper()
        if cve_id not in requested:
            raise ValueError("FIRST EPSS returned an unrequested CVE")
        if cve_id in result:
            raise ValueError("FIRST EPSS returned duplicate CVE records")
        source_date = item.get("date") or item.get("created")
        if not isinstance(source_date, str):
            raise ValueError("FIRST EPSS response is missing its score date")
        try:
            date.fromisoformat(source_date)
        except ValueError as exc:
            raise ValueError("FIRST EPSS response contains an invalid score date") from exc
        result[cve_id] = {
            "epss_score": _parse_probability(item.get("epss"), "score"),
            "epss_percentile": _parse_probability(item.get("percentile"), "percentile"),
            "epss_observed_at": observed_at.isoformat(),
            "epss_provider_status": "success",
            "epss_freshness": _freshness(source_date, observed_at),
            "epss_source_date": source_date,
            "epss_provider": EPSS_SOURCE,
            "epss_provider_version": EPSS_VERSION,
        }
    for cve_id in requested - result.keys():
        result[cve_id] = {
            "epss_score": None,
            "epss_percentile": None,
            "epss_observed_at": observed_at.isoformat(),
            "epss_provider_status": "no_match",
            "epss_freshness": "not_found",
            "epss_source_date": None,
            "epss_provider": EPSS_SOURCE,
            "epss_provider_version": EPSS_VERSION,
        }
    return result


def _failed(cve_ids: Iterable[str], status: str, observed_at: datetime, *, cache_state: str = "miss") -> dict[str, dict[str, Any]]:
    return {cve_id: {
        "epss_score": None,
        "epss_percentile": None,
        "epss_observed_at": observed_at.isoformat(),
        "epss_provider_status": status,
        "epss_freshness": "unavailable",
        "epss_source_date": None,
        "epss_provider": EPSS_SOURCE,
        "epss_provider_version": EPSS_VERSION,
        "epss_cache_state": cache_state,
    } for cve_id in cve_ids}


def lookup_epss(cve_ids: Iterable[str], *, deadline: float | None = None) -> dict[str, dict[str, Any]]:
    """Return one explicit EPSS status per CVE without hiding provider failures."""
    normalized = sorted({value.upper() for value in cve_ids if isinstance(value, str) and _CVE_PATTERN.fullmatch(value)})
    if not normalized:
        return {}
    observed_at = _utc_now()
    if getattr(get_settings(), "app_mode", "live") == "demo":
        return _failed(normalized, "not_assessed", observed_at, cache_state="not_used")

    if len(",".join(normalized)) > 1900:
        return _failed(normalized, "failed", observed_at)

    client: Redis | None = None
    try:
        client = _redis_client()
        cache_key = _cache_key(normalized)
        cached = client.get(cache_key)
        if cached:
            decoded = json.loads(cached)
            if not isinstance(decoded, dict) or set(decoded) != set(normalized):
                raise ValueError("cached FIRST EPSS response is malformed")
            for record in decoded.values():
                if not isinstance(record, dict):
                    raise ValueError("cached FIRST EPSS record is malformed")
                record["epss_cache_state"] = "hit"
            return decoded

        count = int(client.eval(_RATE_LIMIT_SCRIPT, 1, "cyberlens:provider:epss:requests", EPSS_RATE_WINDOW_SECONDS))
        if count > EPSS_MAX_REQUESTS_PER_WINDOW:
            return _failed(normalized, "quota_limited", observed_at)

        query = urlencode({"cve": ",".join(normalized), "limit": len(normalized)})
        response = safe_get(EPSS_ENDPOINT + "?" + query, timeout=get_settings().collector_timeout_seconds,
                            max_bytes=1_000_000, max_redirects=0, headers={"Accept": "application/json"},
                            deadline=deadline)
        if response.status == 429:
            return _failed(normalized, "quota_limited", observed_at)
        if response.status != 200:
            status = "unavailable" if response.status >= 500 else "failed"
            return _failed(normalized, status, observed_at)
        try:
            payload = json.loads(response.body.decode("utf-8")) if response.body else {}
        except (UnicodeDecodeError, json.JSONDecodeError):
            return _failed(normalized, "failed", observed_at)
        result = _parse_response(payload, set(normalized), observed_at)
        serializable = {key: {name: value for name, value in record.items() if name != "epss_cache_state"}
                        for key, record in result.items()}
        client.setex(cache_key, EPSS_CACHE_TTL_SECONDS, json.dumps(serializable, separators=(",", ":")))
        for record in result.values():
            record["epss_cache_state"] = "miss"
        return result
    except RedisError:
        # Without shared throttling/cache state, fail closed instead of making
        # an uncoordinated request from every worker process.
        return _failed(normalized, "unavailable", observed_at, cache_state="redis_unavailable")
    except (OSError, TimeoutError):
        return _failed(normalized, "unavailable", observed_at)
    except UnsafeDestination:
        return _failed(normalized, "unavailable", observed_at)
    except (ValueError, TypeError):
        return _failed(normalized, "failed", observed_at)
    except Exception:
        # Keep an EPSS adapter fault from discarding valid NVD/KEV results.
        return _failed(normalized, "unavailable", observed_at)
    finally:
        if client is not None:
            client.close()


def aggregate_status(records: Iterable[dict[str, Any]]) -> str:
    statuses = {record.get("epss_provider_status", "unavailable") for record in records}
    if not statuses:
        return "not_assessed"
    if statuses & {"failed", "unavailable", "quota_limited"}:
        return "unavailable" if len(statuses) == 1 else "partial"
    if statuses == {"no_match"}:
        return "no_match"
    if statuses == {"not_assessed"}:
        return "not_assessed"
    return "success" if statuses == {"success"} else "partial"
