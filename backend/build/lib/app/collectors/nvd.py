"""NVD CVE candidate collection and CISA KEV enrichment."""

import json
import re
import time
from urllib.parse import quote, urlsplit

from app.cpe import cpe_inventory_mismatch, split_cpe_fields
from app.collectors.common import finding, now_iso
from app.collectors.epss import EPSS_SOURCE, EPSS_VERSION, aggregate_status, lookup_epss
from app.collectors.types import CollectorResult
from app.config import get_settings
from app.network import safe_get

NVD_CVE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CPE = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
CISA_KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_kev_cache: tuple[float, set[str]] | None = None
_cpe_cache: dict[str, tuple[float, dict]] = {}
_cve_cache: dict[str, tuple[float, dict]] = {}


def _provider_failed(page: dict) -> bool:
    if page.get("kev_status") == "unavailable":
        return True
    return any(item.get("epss_provider_status") in {"unavailable", "quota_limited", "failed"}
               for item in page.get("results", []))


def _get_json(url: str, *, max_bytes: int = 4_000_000, include_nvd_key: bool = False,
              deadline: float | None = None) -> tuple[int, dict]:
    headers = {}
    if include_nvd_key and get_settings().nvd_api_key:
        parsed = urlsplit(url)
        if parsed.scheme != "https" or parsed.hostname != "services.nvd.nist.gov":
            raise ValueError("NVD credentials may only be sent to the NVD API origin")
        headers = {"apiKey": get_settings().nvd_api_key}
    response = safe_get(url, timeout=get_settings().collector_timeout_seconds, max_bytes=max_bytes,
                        max_redirects=1, headers=headers, deadline=deadline)
    if response.status not in {200, 404}:
        return response.status, {}
    try:
        payload = json.loads(response.body.decode("utf-8")) if response.body else {}
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("NVD or CISA returned invalid JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("NVD or CISA returned an invalid JSON object")
    return response.status, payload


def search_cpes(keyword: str, limit: int = 20, start_index: int = 0) -> dict:
    query = keyword.strip()[:200]
    if not query:
        return {"total_results": 0, "start_index": 0, "results_per_page": limit, "results": []}
    limit = min(max(limit, 1), 100)
    start_index = max(start_index, 0)
    cache_key = f"{query.casefold()}|{start_index}|{limit}"
    cached = _cpe_cache.get(cache_key)
    if cached and time.monotonic() - cached[0] < 3600:
        return {**cached[1], "results": list(cached[1]["results"])}
    url = f"{NVD_CPE}?keywordSearch={quote(query)}&resultsPerPage={limit}&startIndex={start_index}"
    status, data = _get_json(url, include_nvd_key=True)
    if status == 403 or status == 429:
        raise RuntimeError("NVD rate limit or access limit reached")
    if status != 200:
        raise RuntimeError(f"NVD CPE search returned HTTP {status}")
    results = []
    products = data.get("products", [])
    if not isinstance(products, list):
        raise ValueError("NVD CPE response contains a malformed products list")
    for item in products:
        if not isinstance(item, dict) or not isinstance(item.get("cpe"), dict):
            raise ValueError("NVD CPE response contains a malformed product")
        cpe = item.get("cpe", {})
        cpe_name = cpe.get("cpeName")
        if not isinstance(cpe_name, str) or split_cpe_fields(cpe_name) is None:
            raise ValueError("NVD CPE response contains an invalid CPE name")
        titles = cpe.get("titles") or []
        if not isinstance(titles, list) or any(not isinstance(title, dict) for title in titles):
            raise ValueError("NVD CPE response contains malformed titles")
        results.append({"cpe_name": cpe_name, "title": (titles or [{}])[0].get("title"),
                        "deprecated": cpe.get("deprecated", False)})
    page = {"total_results": data.get("totalResults", len(results)), "start_index": data.get("startIndex", start_index),
            "results_per_page": data.get("resultsPerPage", len(results)), "results": results}
    _cpe_cache[cache_key] = (time.monotonic(), page)
    return dict(page)


def _kev_ids(deadline: float | None = None) -> set[str]:
    global _kev_cache
    if _kev_cache and time.monotonic() - _kev_cache[0] < 86400:
        return _kev_cache[1]
    status, data = _get_json(CISA_KEV, max_bytes=12_000_000, deadline=deadline)
    if status != 200:
        raise RuntimeError(f"CISA KEV returned HTTP {status}")
    vulnerabilities = data.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        raise ValueError("CISA KEV response contains a malformed vulnerabilities list")
    result = set()
    for item in vulnerabilities:
        if not isinstance(item, dict) or not isinstance(item.get("cveID"), str) or not re.fullmatch(r"CVE-\d{4}-\d+", item["cveID"]):
            raise ValueError("CISA KEV response contains a malformed vulnerability")
        result.add(item["cveID"])
    _kev_cache = (time.monotonic(), result)
    return result


def _cve_severity(metrics: dict) -> tuple[str, float | None, str | None, str | None]:
    for metric_type in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(metric_type) or []
        if entries:
            if not isinstance(entries, list) or not isinstance(entries[0], dict):
                raise ValueError("NVD returned malformed CVSS metrics")
            metric = entries[0].get("cvssData", {})
            if not isinstance(metric, dict):
                raise ValueError("NVD returned malformed CVSS data")
            severity = (metric.get("baseSeverity") or entries[0].get("baseSeverity") or "unknown").lower()
            if not isinstance(severity, str):
                raise ValueError("NVD returned an invalid severity")
            return severity, metric.get("baseScore"), metric.get("vectorString"), metric.get("version")
    return "unknown", None, None, None


def search_cve_page(cpe_name: str, limit: int = 100, start_index: int = 0,
                    deadline: float | None = None) -> dict:
    if split_cpe_fields(cpe_name) is None:
        raise ValueError("A selected CPE 2.3 identifier is required")
    limit = min(max(limit, 1), 100)
    start_index = max(start_index, 0)
    cache_key = f"{cpe_name}|{start_index}|{limit}"
    cached = _cve_cache.get(cache_key)
    if cached and time.monotonic() - cached[0] < 900 and not _provider_failed(cached[1]):
        return cached[1]
    url = f"{NVD_CVE}?cpeName={quote(cpe_name, safe=':.*_-')}&resultsPerPage={limit}&startIndex={start_index}"
    status, payload = _get_json(url, include_nvd_key=True, deadline=deadline)
    if status in {403, 429}:
        raise RuntimeError("NVD rate limit or access limit reached")
    if status != 200:
        raise RuntimeError(f"NVD returned HTTP {status}")
    try:
        kev = _kev_ids(deadline)
        kev_error = None
    except Exception as exc:
        kev = set()
        kev_error = type(exc).__name__
    wrappers = payload.get("vulnerabilities", [])
    if not isinstance(wrappers, list):
        raise ValueError("NVD CVE response contains a malformed vulnerabilities list")
    candidates = []
    for wrapper in wrappers:
        if not isinstance(wrapper, dict) or not isinstance(wrapper.get("cve"), dict):
            raise ValueError("NVD CVE response contains a malformed vulnerability")
        cve = wrapper.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue
        if not isinstance(cve_id, str) or not re.fullmatch(r"CVE-\d{4}-\d+", cve_id):
            raise ValueError("NVD returned an invalid CVE identifier")
        descriptions = cve.get("descriptions", [])
        if not isinstance(descriptions, list) or any(not isinstance(item, dict) for item in descriptions):
            raise ValueError("NVD CVE response contains malformed descriptions")
        description = next((item.get("value", "") for item in descriptions if item.get("lang") == "en"), "No English description supplied by NVD.")
        metrics = cve.get("metrics", {})
        if not isinstance(metrics, dict):
            raise ValueError("NVD CVE response contains malformed metrics")
        severity, score, vector, version = _cve_severity(metrics)
        raw_references = cve.get("references", [])
        if not isinstance(raw_references, list):
            raise ValueError("NVD CVE response contains malformed references")
        references = [item.get("url") for item in raw_references if isinstance(item, dict) and item.get("url")][:20]
        affected = []
        configurations = cve.get("configurations", [])
        if not isinstance(configurations, list):
            raise ValueError("NVD CVE response contains malformed configurations")
        for config in configurations:
            if not isinstance(config, dict):
                raise ValueError("NVD CVE response contains a malformed configuration")
            nodes = config.get("nodes", [])
            if not isinstance(nodes, list):
                raise ValueError("NVD CVE response contains malformed configuration nodes")
            for node in nodes:
                if not isinstance(node, dict):
                    raise ValueError("NVD CVE response contains a malformed configuration node")
                matches = node.get("cpeMatch", [])
                if not isinstance(matches, list):
                    raise ValueError("NVD CVE response contains malformed CPE matches")
                for match in matches:
                    if not isinstance(match, dict):
                        raise ValueError("NVD CVE response contains a malformed CPE match")
                    affected.append({key: match.get(key) for key in ("criteria", "versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding") if match.get(key) is not None})
        candidates.append({"cve_id": cve_id, "description": description, "severity": severity,
            "cvss_version": version, "cvss_score": score, "vector": vector, "affected_versions": affected[:50],
            "references": references, "kev": (cve_id in kev) if kev_error is None else None, "applicability": "needs_review",
            "published": cve.get("published"), "last_modified": cve.get("lastModified")})
    epss_records = lookup_epss((candidate["cve_id"] for candidate in candidates), deadline=deadline) if candidates else {}
    for candidate in candidates:
        candidate.update(epss_records.get(candidate["cve_id"], {}))
    epss_status = aggregate_status(epss_records.values())
    result = {"total_results": payload.get("totalResults", len(candidates)), "start_index": payload.get("startIndex", start_index),
        "results_per_page": payload.get("resultsPerPage", limit), "kev_status": "success" if not kev_error else "unavailable",
        "epss_status": epss_status,
        "epss": {"provider": EPSS_SOURCE, "provider_version": EPSS_VERSION, "status": epss_status,
                 "results": [{"cve_id": cve_id, **record} for cve_id, record in sorted(epss_records.items())]},
        "results": candidates}
    if not _provider_failed(result):
        _cve_cache[cache_key] = (time.monotonic(), result)
    return result


def collect_nvd(asset, components: list) -> CollectorResult:
    source = "NVD CVE API and CISA KEV"
    if asset.kind != "application":
        return CollectorResult(status="not_applicable", source=source, error_explanation="NVD matching requires an application asset and manually entered software inventory.")
    configured = [item for item in components if item.cpe_name]
    if not configured:
        return CollectorResult(status="unavailable", source=source, evidence={"component_count": len(components)},
            error_explanation="Select a CPE identifier for at least one software component to request CVE candidates.")
    selected = []
    evidence = {"observed_at": now_iso(), "components": [], "kev_status": "unknown", "epss": [], "page_size": 100}
    for component in configured:
        mismatch = cpe_inventory_mismatch(component.cpe_name, component.vendor, component.product, component.version)
        if mismatch:
            evidence["components"].append({"component_id": component.id, "cpe_name": component.cpe_name,
                                           "status": "invalid_selection", "validation_error": mismatch})
        else:
            selected.append(component)
    if not selected:
        return CollectorResult(status="unavailable", source=source, evidence=evidence,
            error_explanation="Stored CPE selections do not match their software inventory; reselect a matching CPE.")
    findings = []
    validation_errors = len(configured) - len(selected)
    lookup_errors = 0
    deadline = time.monotonic() + get_settings().collector_timeout_seconds
    for component in selected[:20]:
        try:
            page = search_cve_page(component.cpe_name, 100, 0, deadline=deadline)
            evidence["kev_status"] = page["kev_status"]
            evidence["epss"].append({"component_id": component.id, **page["epss"]})
        except Exception as exc:
            lookup_errors += 1
            evidence["components"].append({"component_id": component.id, "cpe_name": component.cpe_name, "status": "unavailable", "error": type(exc).__name__})
            continue
        evidence["components"].append({"component_id": component.id, "cpe_name": component.cpe_name, "status": "success",
            "candidate_count": page["total_results"], "start_index": page["start_index"],
            "results_per_page": page["results_per_page"], "has_more": page["start_index"] + page["results_per_page"] < page["total_results"]})
        for candidate in page["results"]:
            cve_id = candidate["cve_id"]
            details = {**candidate, "component_id": component.id,
                "component": {"vendor": component.vendor, "product": component.product, "version": component.version}}
            findings.append(finding("vulnerabilities", candidate["severity"], f"{cve_id} applicability candidate", candidate["description"],
                "Confirm the exact installed version and configuration against NVD affected-version ranges and vendor guidance, then record applicability.",
                "NVD CVE API", details, applicability="needs_review"))
    status = "failed" if lookup_errors == len(selected) else "partial" if lookup_errors or validation_errors else "success"
    return CollectorResult(status=status, source=source, evidence=evidence, findings=findings,
        error_explanation="One or more NVD component lookups failed or had invalid stored CPE selections."
        if lookup_errors or validation_errors else None)
