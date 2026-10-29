import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Test collection must not inherit Live cookie/database settings from the
# developer's .env. API tests provide their own in-memory database fixtures.
os.environ["APP_MODE"] = "demo"
os.environ["COOKIE_SECURE"] = "false"

from app import main
from app.config import get_settings
from app.database import Base, get_db
from app.models import User
from app.rate_limit import get_login_rate_limit_redis
from app.routes import auth
from app.security import hash_password


class MemoryRedis:
    def __init__(self, state: dict[str, tuple[int, float]]) -> None:
        self.state = state

    def eval(self, _script: str, _num_keys: int, key: str, window_seconds: int) -> int:
        import time

        count, expiry = self.state.get(key, (0, 0))
        if expiry <= time.monotonic():
            count = 0
        count += 1
        self.state[key] = (count, time.monotonic() + window_seconds)
        return count

    def delete(self, key: str) -> int:
        return int(self.state.pop(key, None) is not None)

    def close(self) -> None:
        pass


@pytest.fixture(autouse=True)
def reset_settings_cache():
    """Keep per-test mode/credential overrides from leaking through lru_cache."""
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def cookie_value(client: TestClient, name: str) -> str:
    matches = [cookie.value for cookie in client.cookies.jar if cookie.name == name]
    return matches[-1] if matches else ""


@pytest.fixture
def workspace(monkeypatch):
    monkeypatch.setenv("APP_MODE", "demo")
    # The project .env is configured for Live's secure cookies. TestClient uses
    # plain HTTP, so the isolated Demo fixture must set its cookie policy too.
    monkeypatch.setenv("COOKIE_SECURE", "false")
    get_settings.cache_clear()
    settings = get_settings()
    monkeypatch.setattr(main, "settings", settings)
    monkeypatch.setattr(auth, "settings", settings)
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)

    def override_db():
        db = factory()
        try:
            yield db
        finally:
            db.close()

    main.app.dependency_overrides[get_db] = override_db
    login_limit_state: dict[str, tuple[int, float]] = {}
    main.app.dependency_overrides[get_login_rate_limit_redis] = lambda: MemoryRedis(login_limit_state)
    db = factory()
    db.add(User(username="admin", password_hash=hash_password("Test-Admin-Password-2026!"), role="admin", must_change_password=False))
    db.add(User(username="viewer", password_hash=hash_password("Test-Viewer-Password-2026!"), role="viewer", must_change_password=False))
    db.commit()
    db.close()
    with TestClient(main.app) as client:
        yield client, factory
    main.app.dependency_overrides.clear()
    Base.metadata.drop_all(engine)
    engine.dispose()


def login(client: TestClient, username: str = "admin", password: str = "Test-Admin-Password-2026!") -> None:
    response = client.get("/api/v1/auth/csrf")
    assert response.status_code == 200
    token = cookie_value(client, "cyberlens_csrf")
    response = client.post("/api/v1/auth/login", json={"username": username, "password": password},
                           headers={"X-CSRF-Token": token})
    assert response.status_code == 200, response.text


def csrf(client: TestClient) -> dict[str, str]:
    return {"X-CSRF-Token": cookie_value(client, "cyberlens_csrf")}
