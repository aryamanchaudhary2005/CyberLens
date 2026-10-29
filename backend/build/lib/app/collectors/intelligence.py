import base64
from urllib.parse import quote, urlsplit, urlunsplit

from app.collectors.common import finding, host_for_asset, now_iso
from app.collectors.types import CollectorResult
from app.config import get_settings
from app.network import safe_get

VT_BASE = "https://www.virustotal.com/api/v3"
HIBP_BASE = "https://haveibeenpwned.com/api/v3"


def _request_json(url: str, headers: dict[str, str], *, provider_host: str) -> tuple[int, dict, dict[str, str]]:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname != provider_host:
        raise ValueError("Provider credentials may only be sent to the intended HTTPS provider")
    response = safe_get(url, timeout=get_settings().collector_timeout_seconds, max_bytes=1_000_000,
                        max_redirects=1, headers=headers)
    import json
    if response.status not in {200, 404}:
        return response.status, {}, response.headers
    try:
        payload = json.loads(response.body.decode("utf-8")) if response.body else {}
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Provider returned invalid JSON") from exc
    if not isinstance(payload, (dict, list)):
        raise ValueError("Provider returned an unsupported JSON value")
    return response.status, payload, response.headers


def collect_virustotal(asset) -> CollectorResult:
    settings = get_settings()
    if asset.kind not in {"domain", "ip", "url"}:
        return CollectorResult(status="not_applicable", source="VirusTotal", error_explanation="VirusTotal reputation applies to domains, IP addresses, and URLs.")
    if not settings.virustotal_api_key:
        return CollectorResult(status="unavailable", source="VirusTotal", error_explanation="VIRUSTOTAL_API_KEY is not configured.")
    if asset.kind == "url":
        parsed = urlsplit(asset.identifier)
        clean_url = urlunsplit((parsed.scheme.lower(), parsed.netloc, parsed.path or "/", "", ""))
        object_id = base64.urlsafe_b64encode(clean_url.encode("utf-8")).decode("ascii").rstrip("=")
        endpoint = f"{VT_BASE}/urls/{quote(object_id, safe='')}"
    else:
        object_type = "ip_addresses" if asset.kind == "ip" else "domains"
        endpoint = f"{VT_BASE}/{object_type}/{quote(asset.identifier, safe='.')}"
    try:
        status, payload, _ = _request_json(endpoint, {"x-apikey": settings.virustotal_api_key, "accept": "application/json"},
                                            provider_host="www.virustotal.com")
    except Exception as exc:
        return CollectorResult(status="failed", source="VirusTotal", evidence={"error": type(exc).__name__},
                               error_explanation="VirusTotal could not be reached safely.")
    if status == 404:
        return CollectorResult(status="no_match", source="VirusTotal", evidence={"status": 404})
    if status in {401, 403}:
        return CollectorResult(status="unavailable", source="VirusTotal", evidence={"http_status": status}, error_explanation="VirusTotal rejected the configured API key or access tier.")
    if status == 429:
        return CollectorResult(status="unavailable", source="VirusTotal", evidence={"http_status": status}, error_explanation="VirusTotal quota or rate limit was reached.")
    if status != 200:
        return CollectorResult(status="failed", source="VirusTotal", evidence={"http_status": status}, error_explanation="VirusTotal returned an unexpected response.")
    if not isinstance(payload, dict):
        return CollectorResult(status="failed", source="VirusTotal", evidence={"http_status": status},
                               error_explanation="VirusTotal returned malformed JSON data.")
    data = payload.get("data")
    if not isinstance(data, dict) or not isinstance(data.get("attributes"), dict):
        return CollectorResult(status="failed", source="VirusTotal", evidence={"http_status": status},
                               error_explanation="VirusTotal returned malformed object data.")
    attrs = data["attributes"]
    stats = attrs.get("last_analysis_stats", {})
    if not isinstance(stats, dict):
        return CollectorResult(status="failed", source="VirusTotal", evidence={"http_status": status},
                               error_explanation="VirusTotal returned malformed analysis statistics.")
    try:
        clean_stats = {key: int(value or 0) for key, value in stats.items()}
        if any(value < 0 for value in clean_stats.values()):
            raise ValueError("negative analysis count")
    except (TypeError, ValueError):
        return CollectorResult(status="failed", source="VirusTotal", evidence={"http_status": status},
                               error_explanation="VirusTotal returned malformed analysis statistics.")
    malicious = clean_stats.get("malicious", 0)
    suspicious = clean_stats.get("suspicious", 0)
    evidence = {
        "asset_context": "direct",
        "object_type": data.get("type"),
        "analysis_stats": clean_stats,
        "last_analysis_date": attrs.get("last_analysis_date"),
        "reputation": attrs.get("reputation"),
        "observed_at": now_iso(),
    }
    findings = []
    if malicious or suspicious:
        severity = "high" if malicious >= 2 else "medium"
        findings.append(finding("reputation", severity, "Existing reputation report has adverse verdicts",
            f"VirusTotal reports {malicious} malicious and {suspicious} suspicious engine verdicts for the submitted asset.",
            "Review the providers and timestamps, confirm the asset relationship, and investigate before taking action.",
            "VirusTotal", {"malicious": malicious, "suspicious": suspicious, "asset_context": "direct"}))
    return CollectorResult(status="success", source="VirusTotal", evidence=evidence, findings=findings)


def collect_hibp(asset) -> CollectorResult:
    settings = get_settings()
    if asset.kind != "email":
        return CollectorResult(status="not_applicable", source="Have I Been Pwned", error_explanation="HIBP account search applies to an explicitly supplied email address.")
    if not settings.hibp_api_key:
        return CollectorResult(status="unavailable", source="Have I Been Pwned", error_explanation="HIBP_API_KEY is not configured.")
    account = quote(asset.identifier, safe="")
    endpoint = f"{HIBP_BASE}/breachedaccount/{account}?truncateResponse=false"
    try:
        status, payload, _ = _request_json(endpoint, {
            "hibp-api-key": settings.hibp_api_key,
            "user-agent": "CyberLens Academic Security Analysis/0.1",
            "accept": "application/json",
        }, provider_host="haveibeenpwned.com")
    except Exception as exc:
        return CollectorResult(status="failed", source="Have I Been Pwned", evidence={"error": type(exc).__name__},
                               error_explanation="HIBP could not be reached safely.")
    if status == 404:
        return CollectorResult(status="no_match", source="Have I Been Pwned", evidence={"breach_count": 0, "observed_at": now_iso()})
    if status in {401, 403}:
        return CollectorResult(status="unavailable", source="Have I Been Pwned", evidence={"http_status": status}, error_explanation="HIBP rejected the API key or subscription does not permit this search.")
    if status == 429:
        return CollectorResult(status="unavailable", source="Have I Been Pwned", evidence={"http_status": status}, error_explanation="HIBP rate limit was reached.")
    if status != 200 or not isinstance(payload, list):
        return CollectorResult(status="failed", source="Have I Been Pwned", evidence={"http_status": status}, error_explanation="HIBP returned an unexpected response.")
    if any(not isinstance(item, dict) or not isinstance(item.get("DataClasses", []), list)
           or any(not isinstance(value, str) for value in item.get("DataClasses", [])) for item in payload):
        return CollectorResult(status="failed", source="Have I Been Pwned", evidence={"http_status": status},
                               error_explanation="HIBP returned malformed breach data.")
    breaches = [{"name": item.get("Name"), "title": item.get("Title"), "breach_date": item.get("BreachDate"),
                 "data_classes": item.get("DataClasses", [])} for item in payload]
    evidence = {"breaches": breaches, "breach_count": len(breaches), "observed_at": now_iso(), "account_context": "historical exposure"}
    findings = []
    if breaches:
        findings.append(finding("breach_exposure", "medium", "Historical email breach exposure found",
            f"HIBP returned {len(breaches)} breach record(s) for the explicitly supplied email account. This does not show that the account is currently compromised.",
            "Confirm account ownership, review exposed data categories, and follow the organization's account protection process.",
            "Have I Been Pwned", {"breach_count": len(breaches), "account_context": "historical exposure"}))
    return CollectorResult(status="success", source="Have I Been Pwned", evidence=evidence, findings=findings)
