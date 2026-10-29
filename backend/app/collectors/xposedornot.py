"""Explicit, privacy-conscious XposedOrNot community email lookup.

Only one basic email endpoint call is made. Provider results are normalized to
small metadata records, encrypted in the shared Redis cache, and never logged.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime
from typing import Any
from urllib.parse import quote
from uuid import uuid4

from cryptography.fernet import Fernet, InvalidToken
from redis import Redis
from redis.exceptions import RedisError

from app.collectors.common import finding, now_iso
from app.collectors.types import CollectorResult
from app.config import get_settings
from app.network import OutboundTimeout, safe_get

XON_BASE = "https://api.xposedornot.com/v1/check-email/"
XON_PROVIDER_HOST = "api.xposedornot.com"
XON_SOURCE = "XposedOrNot community API"
XON_CACHE_TTL_DEFAULT = 900
XON_CACHE_TTL_MAX = 3600
XON_RESPONSE_MAX_BYTES = 256 * 1024
MAX_RECORDS = 500

# A single Redis sorted-set is shared by every API/worker process. The rolling
# windows are stricter around clock boundaries than fixed-window counters.
_RESERVE_SHARED_QUOTA = """
local key = KEYS[1]
local redis_time = redis.call('TIME')
local now = tonumber(redis_time[1]) * 1000 + math.floor(tonumber(redis_time[2]) / 1000)
local member = ARGV[1]
redis.call('ZREMRANGEBYSCORE', key, '-inf', now - 86400000)
local second = redis.call('ZCOUNT', key, now - 1000, now)
local hour = redis.call('ZCOUNT', key, now - 3600000, now)
local day = redis.call('ZCOUNT', key, now - 86400000, now)
if second >= 2 or hour >= 25 or day >= 100 then
  return 0
end
redis.call('ZADD', key, now, member)
redis.call('PEXPIRE', key, 86460000)
return 1
"""


def _result(status: str, evidence: dict[str, Any], message: str | None = None) -> CollectorResult:
    return CollectorResult(status=status, source=XON_SOURCE, evidence=evidence, error_explanation=message)


def _date(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    candidate = value.strip()[:64]
    try:
        datetime.fromisoformat(candidate.replace("Z", "+00:00"))
    except ValueError:
        try:
            if len(candidate) == 4 and candidate.isdigit():
                datetime(int(candidate), 1, 1)
            else:
                return None
        except ValueError:
            return None
    return candidate


def _verified(value: Any) -> tuple[bool | None, str | None]:
    if isinstance(value, bool):
        return value, str(value).lower()
    if isinstance(value, str):
        normalized = value.strip().casefold()
        if normalized in {"yes", "true", "verified"}:
            return True, value.strip()[:40]
        if normalized in {"no", "false", "unverified"}:
            return False, value.strip()[:40]
    return None, value.strip()[:40] if isinstance(value, str) else None


def _record(value: Any) -> dict[str, Any] | None:
    if isinstance(value, str):
        name = value.strip()[:200]
        if not name or name.casefold() == "verified":
            return None
        return {"record_id": None, "name": name, "breach_date": None,
                "exposed_data": [], "verified": None, "verification_value": None,
                "source": "XposedOrNot"}
    if not isinstance(value, dict):
        return None
    record_id = next((value.get(key) for key in ("breachID", "breach_id", "id")
                      if isinstance(value.get(key), str) and value.get(key).strip()), None)
    name = next((value.get(key) for key in ("breach", "name", "site", "BreachName")
                 if isinstance(value.get(key), str) and value.get(key).strip()), None)
    if name is None and isinstance(record_id, str):
        name = record_id
    if not isinstance(name, str):
        return None
    raw_categories = next((value.get(key) for key in ("exposedData", "xposed_data", "data_classes", "exposed_data")
                           if key in value), [])
    if isinstance(raw_categories, str):
        categories = [part.strip()[:100] for part in raw_categories.replace(",", ";").split(";") if part.strip()]
    elif isinstance(raw_categories, list) and all(isinstance(item, str) for item in raw_categories):
        categories = [item.strip()[:100] for item in raw_categories if item.strip()]
    elif raw_categories in (None, []):
        categories = []
    else:
        return None
    verified, verification_value = _verified(value.get("verified", value.get("Verified")))
    return {
        "record_id": record_id[:200] if isinstance(record_id, str) else None,
        "name": name.strip()[:200],
        "breach_date": _date(next((value.get(key) for key in ("breachedDate", "xposed_date", "breach_date", "date")
                                    if key in value), None)),
        "exposed_data": categories[:100],
        "verified": verified,
        "verification_value": verification_value,
        "source": "XposedOrNot",
    }


def parse_response(payload: Any) -> tuple[str, list[dict[str, Any]], list[str]]:
    """Return found/no_match/malformed plus normalized, non-sensitive metadata."""
    if not isinstance(payload, dict):
        return "malformed", [], []
    error = payload.get("Error")
    if isinstance(error, str) and error.strip().casefold() == "not found":
        return "no_match", [], []

    marker_values: list[str] = []
    raw_records: list[Any] | None = None
    if isinstance(payload.get("breaches"), list):
        raw_records = []
        for group in payload["breaches"]:
            if isinstance(group, list):
                for item in group:
                    if isinstance(item, str) and item.strip().casefold() == "verified":
                        marker_values.append(item.strip()[:40])
                    else:
                        raw_records.append(item)
            else:
                raw_records.append(group)

    # The optional details response uses the documented per-breach field
    # names. Accept its known containers without retaining descriptions/logos.
    containers = (
        payload.get("exposedBreaches"), payload.get("ExposedBreaches"),
        payload.get("breaches_details"),
    )
    for container in containers:
        if isinstance(container, dict):
            container = container.get("breaches_details")
        if isinstance(container, list):
            # Keep the basic endpoint's names if the optional details list is
            # empty; an incomplete detail expansion must not become no-match.
            if container or not raw_records:
                raw_records = container
            break

    if raw_records is None:
        if payload.get("status") == "success" and payload.get("breaches") == []:
            return "no_match", [], marker_values
        return "malformed", [], marker_values
    if len(raw_records) > MAX_RECORDS:
        raw_records = raw_records[:MAX_RECORDS]
        limited = True
    else:
        limited = False
    normalized: list[dict[str, Any]] = []
    for item in raw_records:
        record = _record(item)
        if record is None:
            return "malformed", [], marker_values
        normalized.append(record)
    if not normalized:
        if payload.get("status") in {"success", None} or error:
            return "no_match", [], marker_values
        return "malformed", [], marker_values
    return ("partial" if limited else "found"), normalized, marker_values


def _findings(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    # CyberLens's historical-exposure policy requires provider verification.
    # Unverified/unknown records stay available as evidence but do not affect risk.
    verified = [record for record in records if record.get("verified") is True]
    if not verified:
        return []
    return [finding(
        "breach_exposure", "medium", "Verified historical email breach exposure found",
        f"XposedOrNot returned {len(verified)} provider-verified historical breach record(s) for the explicitly supplied email account. This does not show that the account is currently compromised.",
        "Confirm account ownership, review the recorded exposed-data categories, and follow the organization's account protection process.",
        XON_SOURCE,
        {"provider": "xposedornot", "breach_count": len(verified),
         "verified_record_ids": [item["record_id"] for item in verified if item["record_id"]],
         "account_context": "historical exposure"},
    )]


def _cache_key(secret: str, email: str) -> tuple[str, Fernet]:
    cipher = Fernet(secret.encode("ascii"))
    digest = hmac.new(secret.encode("ascii"), email.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"cyberlens:provider:xon:email:{digest}", cipher


def _cached_result(redis: Redis, key: str, cipher: Fernet) -> CollectorResult | None:
    value = redis.get(key)
    if value is None:
        return None
    try:
        raw = value.encode("ascii") if isinstance(value, str) else bytes(value)
        payload = json.loads(cipher.decrypt(raw).decode("utf-8"))
        if not isinstance(payload, dict) or payload.get("source") != XON_SOURCE:
            raise ValueError("invalid cached provider result")
        return CollectorResult(status=payload["status"], source=XON_SOURCE,
                               evidence=payload["evidence"], findings=payload["findings"],
                               error_explanation=payload.get("error_explanation"))
    except (InvalidToken, UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError):
        redis.delete(key)
        return None


def _cache_result(redis: Redis, key: str, cipher: Fernet, result: CollectorResult, ttl: int) -> None:
    payload = {"source": XON_SOURCE, "status": result.status, "evidence": result.evidence,
               "findings": result.findings, "error_explanation": result.error_explanation}
    encrypted = cipher.encrypt(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    redis.setex(key, ttl, encrypted)


def _reserve(redis: Redis) -> bool:
    return bool(redis.eval(_RESERVE_SHARED_QUOTA, 1, "cyberlens:provider:xon:check-email:shared-quota",
                           uuid4().hex))


def collect_xposedornot(asset, *, authorized: bool = False, redis_client: Redis | None = None) -> CollectorResult:
    """Perform one explicitly authorized email lookup or fail closed without network I/O."""
    settings = get_settings()
    if asset.kind != "email":
        return _result("not_applicable", {"provider_status": "not_applicable"},
                       "XposedOrNot community lookup applies only to an explicitly registered email address.")
    if not authorized:
        return _result("not_applicable", {"provider_status": "authorization_required"},
                       "An active authorization record for this email and provider is required.")
    if not getattr(settings, "xposedornot_enabled", False) or not getattr(settings, "xposedornot_community_use_ack", False):
        return _result("unavailable", {"provider_status": "disabled"},
                       "XposedOrNot community lookup is disabled by the operator.")
    secret = getattr(settings, "xposedornot_cache_key", None)
    if not secret:
        return _result("unavailable", {"provider_status": "cache_key_missing"},
                       "XposedOrNot lookup is unavailable because its protected cache is not configured.")
    email = str(getattr(asset, "normalized_identifier", None) or asset.identifier)
    try:
        key, cipher = _cache_key(secret, email)
    except (ValueError, UnicodeError, TypeError):
        return _result("unavailable", {"provider_status": "cache_key_invalid"},
                       "XposedOrNot lookup is unavailable because its protected cache key is invalid.")

    owned = redis_client is None
    redis = redis_client
    try:
        if redis is None:
            redis = Redis.from_url(settings.redis_url, socket_connect_timeout=2, socket_timeout=2)
        def done(result: CollectorResult) -> CollectorResult:
            if owned and redis is not None:
                redis.close()
            return result

        cached = _cached_result(redis, key, cipher)
        if cached is not None:
            return done(cached)
        if not _reserve(redis):
            return done(_result("quota_limited", {"provider_status": "shared_quota_exhausted", "observed_at": now_iso()},
                           "XposedOrNot's shared workspace request limit is reached. Wait for the applicable window to reset; no request was sent."))
    except (RedisError, OSError, TimeoutError):
        if owned and redis is not None:
            redis.close()
        return _result("unavailable", {"provider_status": "shared_rate_limit_or_cache_unavailable", "observed_at": now_iso()},
                       "XposedOrNot lookup is unavailable because shared rate limiting or its protected cache is unavailable.")

    endpoint = f"{XON_BASE}{quote(email, safe='')}?details=true"
    try:
        response = safe_get(endpoint, timeout=settings.collector_timeout_seconds, max_bytes=XON_RESPONSE_MAX_BYTES,
                            max_redirects=0, headers={"accept": "application/json",
                            "user-agent": "CyberLens explicit low-volume email lookup"}, send_range_header=False)
    except OutboundTimeout:
        return done(_result("unavailable", {"provider_status": "timeout", "transient": True, "observed_at": now_iso()},
                       "XposedOrNot did not respond before the outbound deadline. Retry later."))
    except Exception as exc:
        # Do not expose exception text: a transport/library exception may echo
        # the request URL, which contains the selected email address.
        transient = isinstance(exc, (OSError, TimeoutError))
        return done(_result("unavailable" if transient else "failed",
                       {"provider_status": "connection_error" if transient else "request_failed", "error_type": type(exc).__name__,
                        "transient": transient, "observed_at": now_iso()},
                       "XposedOrNot request failed safely; the address and provider response were not logged."))
    if response.status == 429:
        # Do not put a numeric 429 in evidence: the shared retry policy treats
        # generic HTTP 429 responses as transient, while this provider's terms
        # explicitly require stopping until the quota window resets.
        result = _result("quota_limited", {"provider_status": "provider_quota_exhausted",
                                            "observed_at": now_iso()},
                         "XposedOrNot's per-IP endpoint limit was reached. Do not retry until its window resets.")
        return done(result)
    if response.status == 404:
        evidence = {"provider_status": "no_match", "result": "no_match",
                    "no_match_message": "No record found in this provider's dataset.", "records": [],
                    "breach_count": 0, "observed_at": now_iso()}
        result = _result("no_match", evidence)
    elif response.status != 200:
        is_transient = response.status in {408, 425} or 500 <= response.status <= 599
        result = _result("unavailable" if is_transient else "failed",
                         {"provider_status": "provider_unavailable" if is_transient else "request_rejected" if response.status in {401, 403} else "failed_request",
                          "http_status": response.status, "transient": is_transient, "observed_at": now_iso()},
                         "XposedOrNot is unavailable or returned an unsuccessful response.")
        return done(result)
    else:
        try:
            payload = json.loads(response.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return done(_result("failed", {"provider_status": "malformed_response", "observed_at": now_iso()},
                           "XposedOrNot returned malformed JSON; its response body was discarded."))
        parsed, records, markers = parse_response(payload)
        if parsed == "malformed":
            return done(_result("failed", {"provider_status": "malformed_response", "observed_at": now_iso()},
                           "XposedOrNot returned an unsupported breach response; its response body was discarded."))
        if parsed == "no_match":
            result = _result("no_match", {"provider_status": "no_match", "result": "no_match",
                "no_match_message": "No record found in this provider's dataset.", "records": [],
                "verification_flags": markers, "breach_count": 0, "observed_at": now_iso()})
        else:
            status = "partial" if parsed == "partial" else "success"
            verified_count = sum(item.get("verified") is True for item in records)
            evidence = {"provider_status": "partial" if status == "partial" else "found", "result": "found",
                "records": records, "verification_flags": markers, "breach_count": len(records),
                "verified_record_count": verified_count, "observed_at": now_iso(),
                "account_context": "historical exposure",
                "coverage_note": "XposedOrNot has its own community dataset and does not have identical coverage to HIBP."}
            if status == "partial":
                evidence["record_limit_reached"] = True
            result = CollectorResult(status=status, source=XON_SOURCE, evidence=evidence,
                                     findings=_findings(records))

    if redis is not None and result.status in {"success", "partial", "no_match"}:
        ttl = min(max(int(getattr(settings, "xposedornot_cache_ttl_seconds", XON_CACHE_TTL_DEFAULT)), 60), XON_CACHE_TTL_MAX)
        try:
            _cache_result(redis, key, cipher, result, ttl)
        except (RedisError, OSError, TimeoutError):
            # The live result is valid; a failed cache write only skips reuse.
            pass
    return done(result)
