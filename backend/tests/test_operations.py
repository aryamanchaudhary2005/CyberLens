import json
import logging

import pytest
from pydantic import ValidationError

from app import main
from app.config import Settings
from app.logging_config import JsonFormatter

from conftest import login


def test_live_settings_reject_published_defaults() -> None:
    with pytest.raises(ValidationError):
        Settings(
            app_mode="live",
            cookie_secure=False,
            database_url="postgresql+psycopg://cyberlens:cyberlens@db:5432/cyberlens",
            redis_url="redis://redis:6379/0",
        )


def test_live_settings_accept_explicit_operator_secrets() -> None:
    settings = Settings(
        app_mode="live",
        cookie_secure=True,
        database_url="postgresql+psycopg://operator:unique-db-secret@db:5432/cyberlens",
        redis_url="redis://:unique-redis-secret@redis:6379/0",
        bootstrap_admin_password="unique-bootstrap-secret-2026",
    )
    assert settings.app_mode == "live"
    assert settings.cookie_secure is True


def test_requests_have_stable_response_request_id(workspace) -> None:
    client, _factory = workspace
    response = client.get("/api/v1/health/live", headers={"X-Request-ID": "ops-test-123"})
    assert response.status_code == 200
    assert response.headers["X-Request-ID"] == "ops-test-123"


def test_metrics_endpoint_exposes_operational_snapshot(workspace, monkeypatch) -> None:
    client, _factory = workspace
    login(client)
    monkeypatch.setattr(main, "metrics_snapshot", lambda _db, _redis: {
        "generated_at": "2026-10-17T00:00:00Z",
        "requests": {"count": 1, "errors": 0, "duration_ms_total": 4.5},
        "queue_depth": 0,
        "job_duration_ms": None,
        "worker_ready": True,
        "worker_heartbeat_ttl_seconds": 40,
        "provider_status": {"DNS": {"success": 1}},
    })
    response = client.get("/api/v1/metrics")
    assert response.status_code == 200
    assert response.json()["queue_depth"] == 0
    assert response.json()["worker_ready"] is True


def test_structured_logs_include_request_id_and_redact_extra_fields() -> None:
    record = logging.LogRecord("test", logging.INFO, __file__, 1, "request", (), None)
    record.request_id = "request-42"
    record.event = "request.completed"
    record.path = "/api/v1/metrics?token=hidden"
    record.user_id = "user-1"
    rendered = JsonFormatter().format(record)
    payload = json.loads(rendered)
    assert payload["request_id"] == "request-42"
    assert payload["event"] == "request.completed"
    assert "hidden" not in rendered
