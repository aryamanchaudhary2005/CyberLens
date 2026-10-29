import json
import logging
import re
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any

SECRET_PATTERNS = (
    re.compile(r"(?i)(password|passwd|token|secret|api[_-]?key)(\s*[=:]\s*)([^\s,;]+)"),
    re.compile(r"(?i)(://[^:/\s]+:)([^@/\s]+)(@)"),
    re.compile(r"(?i)\b(bearer)\s+([^\s,;]+)"),
)
request_id_context: ContextVar[str] = ContextVar("cyberlens_request_id", default="-")


def redact_secrets(value: str) -> str:
    value = SECRET_PATTERNS[0].sub(r"\1\2[REDACTED]", value)
    value = SECRET_PATTERNS[1].sub(r"\1[REDACTED]\3", value)
    return SECRET_PATTERNS[2].sub(r"\1 [REDACTED]", value)


def _safe_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact_secrets(value)
    if isinstance(value, dict):
        return {str(key): _safe_value(item) for key, item in value.items() if key not in {"password", "token", "secret", "api_key"}}
    if isinstance(value, (list, tuple)):
        return [_safe_value(item) for item in value]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return redact_secrets(str(value))


class JsonFormatter(logging.Formatter):
    """Emit one structured JSON object per log record."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": redact_secrets(record.getMessage()),
            "request_id": getattr(record, "request_id", None) or request_id_context.get(),
        }
        safe_fields = {"event", "method", "path", "status_code", "duration_ms", "user_id",
                       "collector", "attempt_id", "investigation_id", "provider", "queue",
                       "worker_id", "job_id", "reason"}
        for field in safe_fields:
            if hasattr(record, field):
                payload[field] = _safe_value(getattr(record, field))
        if record.exc_info:
            payload["exception"] = redact_secrets(self.formatException(record.exc_info))
        return json.dumps(payload, ensure_ascii=False)


def configure_logging(level: str) -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level.upper())
