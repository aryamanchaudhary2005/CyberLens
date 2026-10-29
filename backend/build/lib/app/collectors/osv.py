"""OSV.dev lookup for explicitly inventoried npm and PyPI package versions."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import re
import time
from typing import Any
from urllib.parse import urlsplit

from redis import Redis
from redis.exceptions import RedisError

from app.collectors.common import finding
from app.collectors.types import CollectorResult
from app.config import get_settings
from app.network import OutboundTimeout, UnsafeDestination, safe_post_json
from app.package_names import normalize_package_name

OSV_ENDPOINT = "https://api.osv.dev/v1/query"
OSV_SOURCE = "OSV.dev"
OSV_VERSION = "OSV API 1.0 · POST /v1/query"
OSV_CACHE_TTL_SECONDS = 6 * 60 * 60
OSV_RATE_WINDOW_SECONDS = 60
OSV_MAX_REQUESTS_PER_WINDOW = 60
OSV_MAX_COMPONENTS = 20
OSV_MAX_PAGES_PER_PACKAGE = 3
OSV_MAX_ADVISORIES = 3000
OSV_MAX_RESPONSE_BYTES = 2_000_000
OSV_TRANSIENT_RETRIES = 1
_RATE_LIMIT_SCRIPT = """
local count = redis.call('INCR', KEYS[1])
if count == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
return count
"""
_CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)
_SEVERITIES = {"critical", "high", "medium", "moderate", "low", "info", "informational"}


def _redis_client() -> Redis:
    return Redis.from_url(get_settings().redis_url, socket_connect_timeout=1, socket_timeout=1)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _cache_key(ecosystem: str, package_name: str, version: str) -> str:
    payload = f"{ecosystem}\0{package_name}\0{version}".encode("utf-8")
    digest = hashlib.sha256(payload).hexdigest()
    return f"cyberlens:provider:osv:package:{digest}"


def _parse_timestamp(value: Any, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError(f"OSV returned an invalid {field} timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"OSV returned an invalid {field} timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"OSV returned a timezone-free {field} timestamp")
    return parsed.astimezone(timezone.utc).isoformat()


def _text(value: Any, field: str, max_length: int = 20_000) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > max_length:
        raise ValueError(f"OSV returned an invalid {field}")
    return value.strip()


def _parse_affected(value: Any) -> tuple[list[dict[str, Any]], list[str]]:
    if value is None:
        return [], []
    if not isinstance(value, list):
        raise ValueError("OSV affected data is not a list")
    affected: list[dict[str, Any]] = []
    fixed_versions: set[str] = set()
    for entry in value[:100]:
        if not isinstance(entry, dict):
            raise ValueError("OSV affected entry is malformed")
        package = entry.get("package")
        if package is not None and not isinstance(package, dict):
            raise ValueError("OSV affected package is malformed")
        if isinstance(package, dict):
            selected_package = {
                key: _text(package[key], f"affected package {key}", 500)
                for key in ("name", "ecosystem", "purl") if package.get(key) is not None
            }
        else:
            selected_package = None
        raw_ranges = entry.get("ranges", [])
        raw_versions = entry.get("versions", [])
        if not isinstance(raw_ranges, list) or not isinstance(raw_versions, list):
            raise ValueError("OSV affected version ranges are malformed")
        ranges = []
        for raw_range in raw_ranges[:50]:
            if not isinstance(raw_range, dict):
                raise ValueError("OSV affected range is malformed")
            range_type = raw_range.get("type")
            if range_type is not None and not isinstance(range_type, str):
                raise ValueError("OSV affected range type is malformed")
            raw_events = raw_range.get("events", [])
            if not isinstance(raw_events, list):
                raise ValueError("OSV affected range events are malformed")
            events: list[dict[str, str]] = []
            for event in raw_events[:500]:
                if not isinstance(event, dict):
                    raise ValueError("OSV affected range event is malformed")
                clean_event = {}
                for event_name in ("introduced", "fixed", "last_affected", "limit"):
                    if event_name in event:
                        clean_event[event_name] = _text(event[event_name], "range event", 200)
                        if event_name == "fixed":
                            fixed_versions.add(clean_event[event_name])
                if not clean_event:
                    raise ValueError("OSV affected range event has no supported boundary")
                events.append(clean_event)
            selected_range: dict[str, Any] = {"type": range_type or "unknown", "events": events}
            if raw_range.get("repo") is not None:
                selected_range["repo"] = _text(raw_range["repo"], "affected range repository", 2048)
            ranges.append(selected_range)
        versions = [_text(item, "affected version", 200) for item in raw_versions[:1000]]
        for specific in (entry.get("ecosystem_specific"), entry.get("database_specific")):
            if specific is not None and not isinstance(specific, dict):
                raise ValueError("OSV affected severity metadata is malformed")
        severity_metadata = {}
        for specific_name in ("ecosystem_specific", "database_specific"):
            specific = entry.get(specific_name)
            if isinstance(specific, dict) and isinstance(specific.get("severity"), str):
                severity_metadata[specific_name] = specific["severity"][:100]
        affected.append({"package": selected_package, "ranges": ranges, "versions": versions,
                         **severity_metadata})
    return affected, sorted(fixed_versions)


def _severity(advisory: dict[str, Any], affected: list[dict[str, Any]]) -> str:
    candidates: list[Any] = []
    for key in ("severity",):
        value = advisory.get(key)
        if isinstance(value, str):
            candidates.append(value)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    candidates.extend(item.get(name) for name in ("severity", "level") if name in item)
    for name in ("database_specific", "ecosystem_specific"):
        data = advisory.get(name)
        if isinstance(data, dict):
            candidates.append(data.get("severity"))
    for package in affected:
        candidates.extend(package.get(name) for name in ("database_specific", "ecosystem_specific") if package.get(name))
    for candidate in candidates:
        if isinstance(candidate, str) and candidate.casefold() in _SEVERITIES:
            value = candidate.casefold()
            return "medium" if value == "moderate" else "informational" if value == "info" else value
    return "unknown"


def _parse_advisory(raw: Any, observed_at: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValueError("OSV vulnerability record is malformed")
    advisory_id = _text(raw.get("id"), "advisory ID", 200)
    raw_aliases = raw.get("aliases", [])
    if not isinstance(raw_aliases, list) or any(not isinstance(alias, str) or not alias.strip() or len(alias) > 200 for alias in raw_aliases):
        raise ValueError("OSV aliases are malformed")
    aliases = sorted({alias.strip() for alias in raw_aliases})
    affected, fixed_versions = _parse_affected(raw.get("affected", []))
    raw_references = raw.get("references", [])
    if not isinstance(raw_references, list):
        raise ValueError("OSV references are malformed")
    references: list[dict[str, str]] = []
    for entry in raw_references[:50]:
        if not isinstance(entry, dict):
            raise ValueError("OSV reference is malformed")
        reference_url = _text(entry.get("url"), "reference URL", 2048)
        parsed_url = urlsplit(reference_url)
        if parsed_url.scheme not in {"http", "https"} or not parsed_url.hostname:
            raise ValueError("OSV reference URL is not HTTP(S)")
        reference_type = entry.get("type", "")
        if not isinstance(reference_type, str) or len(reference_type) > 40:
            raise ValueError("OSV reference type is malformed")
        references.append({"type": reference_type, "url": reference_url})
    raw_severity = raw.get("severity", [])
    if not isinstance(raw_severity, list):
        raise ValueError("OSV severity metadata is malformed")
    severity_metadata: list[dict[str, str]] = []
    for entry in raw_severity[:20]:
        if not isinstance(entry, dict):
            raise ValueError("OSV severity record is malformed")
        record: dict[str, str] = {}
        for key in ("type", "score"):
            if key in entry:
                record[key] = _text(entry[key], f"severity {key}", 200)
        if record:
            severity_metadata.append(record)
    for key in ("database_specific", "ecosystem_specific"):
        if raw.get(key) is not None and not isinstance(raw.get(key), dict):
            raise ValueError(f"OSV {key} data is malformed")
    published = _parse_timestamp(raw.get("published"), "published")
    modified = _parse_timestamp(raw.get("modified"), "modified")
    withdrawn = _parse_timestamp(raw.get("withdrawn"), "withdrawn")
    record = {
        "advisory_id": advisory_id,
        "aliases": aliases,
        "summary": raw.get("summary", "")[:2000] if isinstance(raw.get("summary", ""), str) else "",
        "details": raw.get("details", "")[:20_000] if isinstance(raw.get("details", ""), str) else "",
        "affected": affected,
        "fixed_versions": fixed_versions,
        "references": references,
        "severity_metadata": severity_metadata,
        "severity": _severity(raw, affected),
        "published": published,
        "modified": modified,
        "withdrawn": withdrawn,
        "observed_at": observed_at,
        "advisory_status": "withdrawn" if withdrawn else "active",
    }
    return record


def _request_page(payload: dict[str, Any], client: Redis, deadline: float) -> tuple[dict[str, Any] | None, str, dict[str, Any]]:
    for attempt in range(OSV_TRANSIENT_RETRIES + 1):
        if time.monotonic() >= deadline:
            return None, "unavailable", {"provider_status": "timeout", "error": "timeout"}
        try:
            count = int(client.eval(_RATE_LIMIT_SCRIPT, 1, "cyberlens:provider:osv:requests", OSV_RATE_WINDOW_SECONDS))
        except RedisError:
            return None, "unavailable", {"provider_status": "redis_unavailable", "error": "redis_unavailable"}
        if count > OSV_MAX_REQUESTS_PER_WINDOW:
            return None, "quota_limited", {"provider_status": "quota_limited", "error": "local_rate_limit"}
        try:
            response = safe_post_json(OSV_ENDPOINT, payload, timeout=get_settings().collector_timeout_seconds,
                max_bytes=OSV_MAX_RESPONSE_BYTES, max_body_bytes=4096, max_redirects=0,
                headers={"accept": "application/json"}, deadline=deadline)
        except OutboundTimeout:
            if attempt < OSV_TRANSIENT_RETRIES and time.monotonic() < deadline:
                time.sleep(min(0.1 * (2 ** attempt), max(0.0, deadline - time.monotonic())))
                continue
            return None, "unavailable", {"provider_status": "timeout", "error": "timeout"}
        except (OSError, TimeoutError):
            if attempt < OSV_TRANSIENT_RETRIES and time.monotonic() < deadline:
                time.sleep(min(0.1 * (2 ** attempt), max(0.0, deadline - time.monotonic())))
                continue
            return None, "unavailable", {"provider_status": "connection_error", "error": "connection_error"}
        except UnsafeDestination:
            return None, "unavailable", {"provider_status": "blocked_destination", "error": "blocked_destination"}
        status = response.status
        if status == 429:
            return None, "quota_limited", {"provider_status": "quota_limited", "http_status": status}
        if status >= 500:
            if attempt < OSV_TRANSIENT_RETRIES and time.monotonic() < deadline:
                time.sleep(min(0.1 * (2 ** attempt), max(0.0, deadline - time.monotonic())))
                continue
            return None, "unavailable", {"provider_status": "unavailable", "http_status": status}
        if status != 200:
            return None, "failed", {"provider_status": "failed", "http_status": status}
        try:
            decoded = json.loads(response.body.decode("utf-8")) if response.body else {}
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None, "failed", {"provider_status": "failed", "error": "malformed_json", "http_status": status}
        if not isinstance(decoded, dict):
            return None, "failed", {"provider_status": "failed", "error": "malformed_response", "http_status": status}
        return decoded, "success", {"http_status": status}
    return None, "unavailable", {"provider_status": "unavailable", "error": "retry_limit"}


def lookup_package(ecosystem: str, package_name: str, version: str, *, deadline: float | None = None) -> dict[str, Any]:
    """Return full, validated OSV advisory records for one explicit package version."""
    normalized_name = normalize_package_name(ecosystem, package_name)
    if not isinstance(version, str) or not version.strip() or len(version.strip()) > 100 or any(ord(char) < 32 for char in version):
        raise ValueError("An explicit valid package version is required for OSV lookup")
    normalized_version = version.strip()
    observed_at = _utc_now().isoformat()
    if get_settings().app_mode == "demo":
        return {"provider_status": "not_assessed", "advisories": [], "observed_at": observed_at,
                "cache_state": "not_used", "error": "demo_mode_no_network"}

    operation_deadline = deadline if deadline is not None else time.monotonic() + get_settings().collector_timeout_seconds
    client: Redis | None = None
    try:
        client = _redis_client()
        key = _cache_key(ecosystem, normalized_name, normalized_version)
        cached = client.get(key)
        if cached:
            decoded = json.loads(cached)
            if (not isinstance(decoded, dict) or not isinstance(decoded.get("advisories"), list) or
                    decoded.get("provider_status") not in {"success", "no_match"} or
                    not isinstance(decoded.get("observed_at"), str)):
                client.delete(key)
            else:
                return {**decoded, "cache_state": "hit", "freshness": "cached"}

        advisories: dict[str, dict[str, Any]] = {}
        page_token: str | None = None
        pages = 0
        partial = False
        errors: list[dict[str, Any]] = []
        while pages < OSV_MAX_PAGES_PER_PACKAGE and len(advisories) < OSV_MAX_ADVISORIES:
            request: dict[str, Any] = {"package": {"ecosystem": ecosystem, "name": normalized_name},
                                       "version": normalized_version}
            if page_token is not None:
                request["page_token"] = page_token
            payload, status, metadata = _request_page(request, client, operation_deadline)
            pages += 1
            if payload is None:
                errors.append({**metadata, "result_status": status})
                partial = bool(advisories)
                break
            vulnerabilities = payload.get("vulns", [])
            if not isinstance(vulnerabilities, list):
                return {"provider_status": "failed", "advisories": [], "observed_at": observed_at,
                        "cache_state": "miss", "error": "malformed_vulns_list", "http_status": metadata.get("http_status")}
            try:
                for raw in vulnerabilities:
                    parsed = _parse_advisory(raw, observed_at)
                    if parsed["advisory_id"] in advisories:
                        continue
                    if len(advisories) >= OSV_MAX_ADVISORIES:
                        partial = True
                        break
                    advisories.setdefault(parsed["advisory_id"], parsed)
            except (TypeError, ValueError):
                return {"provider_status": "failed", "advisories": [], "observed_at": observed_at,
                        "cache_state": "miss", "error": "malformed_advisory", "http_status": metadata.get("http_status")}
            page_token = payload.get("next_page_token")
            if page_token is not None and (not isinstance(page_token, str) or not page_token.strip() or len(page_token) > 4096):
                return {"provider_status": "failed", "advisories": [], "observed_at": observed_at,
                        "cache_state": "miss", "error": "malformed_page_token", "http_status": metadata.get("http_status")}
            if not page_token:
                page_token = None
                break
        if page_token is not None or len(advisories) >= OSV_MAX_ADVISORIES:
            partial = True
        provider_status = ("partial" if partial else errors[0].get("result_status", "unavailable") if errors
                           else "no_match" if not advisories else "success")
        result = {"provider_status": provider_status, "advisories": list(advisories.values()),
                  "observed_at": observed_at, "cache_state": "miss", "freshness": "observed",
                  "pages": pages, "partial_result": partial, "error": errors[0].get("error") if errors else None,
                  "http_status": errors[0].get("http_status") if errors else None}
        if not partial and not errors:
            client.setex(key, OSV_CACHE_TTL_SECONDS, json.dumps(result, separators=(",", ":"), ensure_ascii=False))
        return result
    except RedisError:
        return {"provider_status": "unavailable", "advisories": [], "observed_at": observed_at,
                "cache_state": "redis_unavailable", "error": "redis_unavailable", "freshness": "unavailable"}
    except UnsafeDestination:
        return {"provider_status": "unavailable", "advisories": [], "observed_at": observed_at,
                "cache_state": "miss", "error": "blocked_destination", "freshness": "unavailable"}
    except (OSError, OutboundTimeout, TimeoutError):
        return {"provider_status": "unavailable", "advisories": [], "observed_at": observed_at,
                "cache_state": "miss", "error": "timeout_or_connection_error", "freshness": "unavailable"}
    except (TypeError, ValueError, json.JSONDecodeError):
        return {"provider_status": "failed", "advisories": [], "observed_at": observed_at,
                "cache_state": "miss", "error": "invalid_package_or_cached_response", "freshness": "unavailable"}
    finally:
        if client is not None:
            client.close()


def collect_osv(asset: Any, components: list[Any]) -> CollectorResult:
    source = "OSV.dev package query API"
    if asset.kind != "application":
        return CollectorResult(status="not_applicable", source=source,
                               error_explanation="OSV lookup requires explicitly inventoried npm or PyPI package versions.")
    configured = [item for item in components if item.package_ecosystem and item.package_name]
    if not configured:
        return CollectorResult(status="not_applicable", source=source,
            evidence={"provider_status": "not_assessed", "package_count": 0,
                      "message": "No explicit npm or PyPI package name and version was entered; no package was inferred."},
            error_explanation="No package ecosystem/name is selected. No OSV request was sent.")

    observed_at = _utc_now().isoformat()
    deadline = time.monotonic() + get_settings().collector_timeout_seconds
    evidence: dict[str, Any] = {"observed_at": observed_at, "provider": OSV_SOURCE,
        "provider_version": OSV_VERSION, "provider_status": "success", "components": [], "advisories": [],
        "pagination_limit": OSV_MAX_PAGES_PER_PACKAGE, "component_limit": OSV_MAX_COMPONENTS}
    findings: list[dict[str, Any]] = []
    statuses: list[str] = []
    error_details: list[dict[str, Any]] = []
    for component in configured[:OSV_MAX_COMPONENTS]:
        result = lookup_package(component.package_ecosystem, component.package_name, component.version,
                                deadline=deadline)
        provider_status = result["provider_status"]
        statuses.append(provider_status)
        component_record = {"component_id": component.id, "ecosystem": component.package_ecosystem,
            "package_name": component.package_name, "version": component.version,
            "status": provider_status, "cache_state": result.get("cache_state", "unknown"),
            "freshness": result.get("freshness", "unknown"), "pages": result.get("pages", 0),
            "advisory_count": len(result.get("advisories", [])), "partial_result": bool(result.get("partial_result"))}
        if result.get("error"):
            component_record["error"] = result["error"]
            error_details.append({key: result.get(key) for key in ("error", "http_status") if result.get(key) is not None})
        evidence["components"].append(component_record)
        for advisory in result.get("advisories", []):
            evidence_advisory = {**advisory, "component_id": component.id,
                "ecosystem": component.package_ecosystem, "package_name": component.package_name,
                "package_version": component.version, "provider_status": provider_status,
                "freshness": result.get("freshness", "observed"), "provider_version": OSV_VERSION}
            evidence["advisories"].append(evidence_advisory)
            if advisory.get("withdrawn"):
                continue
            aliases = advisory["aliases"]
            cve_aliases = sorted(alias.upper() for alias in aliases if _CVE_PATTERN.fullmatch(alias))
            details = {
                "advisory_id": advisory["advisory_id"], "aliases": aliases,
                "cve_id": cve_aliases[0] if cve_aliases else None, "component_id": component.id,
                "package": {"ecosystem": component.package_ecosystem, "name": component.package_name,
                            "version": component.version},
                "affected": advisory["affected"], "fixed_versions": advisory["fixed_versions"],
                "references": advisory["references"], "severity_metadata": advisory["severity_metadata"],
                "published": advisory["published"], "modified": advisory["modified"],
                "withdrawn": advisory["withdrawn"], "observed_at": advisory["observed_at"],
                "provider_status": provider_status, "freshness": result.get("freshness", "observed"),
                "provider_version": OSV_VERSION, "advisory_status": advisory["advisory_status"],
                "summary": advisory["summary"],
            }
            fixed_text = (" Documented fixed version(s): " + ", ".join(advisory["fixed_versions"]) + ".") if advisory["fixed_versions"] else " No fixed version was documented by OSV."
            findings.append(finding("vulnerabilities", advisory["severity"],
                f"{advisory['advisory_id']} package applicability candidate",
                advisory["summary"] or f"OSV advisory {advisory['advisory_id']} matched the explicitly entered package version.",
                "Review the advisory, affected package ranges, and installed version; then record an analyst applicability decision." + fixed_text,
                source, details, applicability="needs_review"))

    component_limit_reached = len(configured) > OSV_MAX_COMPONENTS
    if component_limit_reached:
        evidence["component_limit_reached"] = True
    failures = [status for status in statuses if status in {"failed", "unavailable", "quota_limited"}]
    successes = [status for status in statuses if status in {"success", "no_match"}]
    if component_limit_reached or "partial" in statuses or (failures and successes):
        status = "partial"
    elif failures:
        status = ("unavailable" if all(item == "unavailable" for item in failures) else
                  "quota_limited" if all(item == "quota_limited" for item in failures) else "failed")
    elif findings or "success" in statuses:
        status = "success"
    else:
        status = "no_match"
    evidence["provider_status"] = "partial" if status == "partial" else status
    evidence["partial_result"] = status == "partial"
    if error_details:
        evidence["provider_errors"] = error_details
    error_explanation = ("OSV returned partial coverage or one or more package lookups failed; inspect component provider status." if status in {"partial", "failed", "unavailable", "quota_limited"} else None)
    return CollectorResult(status=status, source=source, evidence=evidence, findings=findings,
                           error_explanation=error_explanation)
