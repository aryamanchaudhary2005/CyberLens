from fastapi.testclient import TestClient

from app import main

client = TestClient(main.app)


class FakeHealthRedis:
    def __init__(self, worker=True):
        self.worker = worker

    def ping(self):
        return True

    def exists(self, _key):
        return int(self.worker)

    def close(self):
        pass


def test_liveness_does_not_require_services() -> None:
    response = client.get("/api/v1/health/live")

    assert response.status_code == 200
    assert response.json() == {"status": "alive", "service": "cyberlens-api"}


def test_readiness_reports_demo_mode(monkeypatch) -> None:
    monkeypatch.setattr(main, "dependency_status", lambda: {"database": True, "redis": True, "worker": True})

    response = client.get("/api/v1/health/ready")

    assert response.status_code == 200
    assert response.json()["mode"] in {"demo", "live"}
    assert response.json()["demo_data"] is (response.json()["mode"] == "demo")


def test_readiness_is_unavailable_when_a_dependency_fails(monkeypatch) -> None:
    monkeypatch.setattr(main, "dependency_status", lambda: {"database": True, "redis": False, "worker": False})

    response = client.get("/api/v1/health/ready")

    assert response.status_code == 503
    assert response.json()["detail"]["dependencies"] == {"database": True, "redis": False, "worker": False}


def test_readiness_reports_worker_independently(monkeypatch) -> None:
    monkeypatch.setattr(main, "dependency_status", lambda: {"database": True, "redis": True, "worker": False})

    response = client.get("/api/v1/health/ready")

    assert response.status_code == 503
    assert response.json()["detail"]["dependencies"] == {"database": True, "redis": True, "worker": False}


def test_component_health_endpoints_report_services_separately(monkeypatch) -> None:
    monkeypatch.setattr(main, "check_database", lambda: True)
    monkeypatch.setattr(main.Redis, "from_url", lambda *_args, **_kwargs: FakeHealthRedis(worker=True))

    assert client.get("/api/v1/health/postgres").json() == {"status": "ready", "postgres": True}
    assert client.get("/api/v1/health/redis").json() == {"status": "ready", "redis": True}
    assert client.get("/api/v1/health/worker").json() == {"status": "ready", "worker": True}

    monkeypatch.setattr(main.Redis, "from_url", lambda *_args, **_kwargs: FakeHealthRedis(worker=False))
    worker = client.get("/api/v1/health/worker")
    assert worker.status_code == 503
    assert worker.json()["detail"] == {"status": "not_ready", "worker": False}
