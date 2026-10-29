import json
import logging

from app.logging_config import JsonFormatter


def test_json_logs_redact_secret_values() -> None:
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="api_key=sample-key database=postgres://analyst:sample-pass@localhost/db",
        args=(),
        exc_info=None,
    )

    formatted = JsonFormatter().format(record)
    payload = json.loads(formatted)

    assert "sample-key" not in formatted
    assert "sample-pass" not in formatted
    assert payload["message"].endswith("database=postgres://analyst:[REDACTED]@localhost/db")
