import json
from datetime import datetime, timezone
from urllib.parse import urlsplit

from app.config import get_settings
from app.network import safe_get


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def json_get(url: str, *, headers: dict[str, str] | None = None, max_bytes: int = 2_000_000,
             deadline: float | None = None) -> tuple[int, dict, dict[str, str]]:
    response = safe_get(url, timeout=get_settings().collector_timeout_seconds, max_bytes=max_bytes,
                        max_redirects=2, headers=headers, deadline=deadline)
    try:
        payload = json.loads(response.body.decode("utf-8")) if response.body else {}
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Provider returned invalid JSON") from exc
    return response.status, payload, response.headers


def host_for_asset(asset) -> str:
    if asset.kind == "url":
        return urlsplit(asset.identifier).hostname or asset.identifier
    return asset.identifier


def finding(category: str, severity: str, title: str, explanation: str, recommendation: str,
            source: str, details: dict | None = None, applicability: str = "applies") -> dict:
    return {
        "category": category,
        "severity": severity,
        "title": title,
        "explanation": explanation,
        "recommendation": recommendation,
        "source": source,
        "details": details or {},
        "applicability": applicability,
    }
