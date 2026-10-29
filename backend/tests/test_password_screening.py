from datetime import timedelta
import hashlib
import json
from types import SimpleNamespace

import pytest
from fastapi import HTTPException, Response
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.requests import Request

from app import bootstrap
from app.database import Base
from app.models import Asset, AuditEvent, EvidenceSnapshot, Investigation, Report, User, UserSession, now_utc
from app.network import OutboundTimeout, SafeResponse
from app.routes import auth, reports, users
from app.schemas import AdminPasswordReset, LoginInput, PasswordChange, UserCreate
from app.security import hash_password, token_digest, verify_password
from app.services import password_screening as screening

SYNTHETIC_PASSWORD = "Synthetic-Password-Only-2026!"


@pytest.fixture
def db_session():
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    db = factory()
    try:
        yield db, factory
    finally:
        db.close()
        Base.metadata.drop_all(engine)
        engine.dispose()


def _password_hash_parts(password: str) -> tuple[str, str]:
    value = hashlib.sha1(password.encode("utf-8"), usedforsecurity=False).hexdigest().upper()
    return value[:5], value[5:]


def _seed_accounts(db: Session) -> tuple[User, User, UserSession]:
    admin = User(username="screen-admin", password_hash=hash_password("Synthetic-Admin-Password-2026!"), role="admin")
    target = User(username="screen-target", password_hash=hash_password("Synthetic-Old-Password-2026!"), role="analyst",
                  must_change_password=False)
    db.add_all([admin, target])
    db.flush()
    session = UserSession(user_id=target.id, token_hash=token_digest("synthetic-session-token"),
                          csrf_token_hash=token_digest("synthetic-csrf-token"),
                          expires_at=now_utc() + timedelta(hours=1))
    db.add(session)
    db.commit()
    return admin, target, session


def test_range_lookup_sends_only_five_character_prefix_and_padding(monkeypatch):
    prefix, suffix = _password_hash_parts(SYNTHETIC_PASSWORD)
    expected_url = f"{screening.HIBP_RANGE_BASE}/{prefix}"
    calls = []

    def fake_safe_get(url, **kwargs):
        calls.append((url, kwargs))
        return SafeResponse(status=200, headers={"content-type": "text/plain"},
                            body=f"{suffix}:9\r\n{'A' * 35}:0\r\n".encode(),
                            final_url=url, redirects=[])

    monkeypatch.setattr(screening, "safe_get", fake_safe_get)
    result = screening.check_password_candidate(SYNTHETIC_PASSWORD, app_mode="live")

    assert result.outcome == "found" and result.reason == "matching_nonzero_count"
    assert len(calls) == 1 and calls[0][0] == expected_url
    assert calls[0][0].startswith("https://api.pwnedpasswords.com/range/")
    assert calls[0][0].rsplit("/", 1)[-1] == prefix and len(prefix) == 5
    assert calls[0][1]["headers"]["Add-Padding"] == "true"
    assert calls[0][1]["max_redirects"] == 0 and calls[0][1]["send_range_header"] is False
    assert calls[0][1]["max_bytes"] <= screening.HIBP_RANGE_RESPONSE_BYTES
    sent_metadata = calls[0][0] + json.dumps(calls[0][1])
    full_hash = prefix + suffix
    assert "password" not in json.dumps(calls[0][1]).lower()
    assert SYNTHETIC_PASSWORD not in sent_metadata and full_hash not in sent_metadata
    assert suffix not in json.dumps(calls[0][1]) and prefix not in json.dumps(calls[0][1])


def test_zero_count_padded_candidate_is_not_a_match(monkeypatch):
    prefix, suffix = _password_hash_parts(SYNTHETIC_PASSWORD)
    monkeypatch.setattr(screening, "safe_get", lambda url, **_kwargs: SafeResponse(
        status=200, headers={}, body=f"{suffix}:0\r\n{'B' * 35}:3\r\n".encode(), final_url=url, redirects=[]))
    result = screening.check_password_candidate(SYNTHETIC_PASSWORD, app_mode="live")
    assert result.outcome == "not_found" and result.reason == "no_matching_suffix"
    assert prefix not in result.reason and suffix not in result.reason


def test_range_lookup_not_found_malformed_timeout_and_quota(monkeypatch, caplog):
    prefix, suffix = _password_hash_parts(SYNTHETIC_PASSWORD)
    monkeypatch.setattr(screening, "safe_get", lambda url, **_kwargs: SafeResponse(
        status=200, headers={}, body=f"{'C' * 35}:2\r\n".encode(), final_url=url, redirects=[]))
    assert screening.check_password_candidate(SYNTHETIC_PASSWORD, app_mode="live").outcome == "not_found"

    monkeypatch.setattr(screening, "safe_get", lambda url, **_kwargs: SafeResponse(
        status=200, headers={}, body=f"{suffix}:not-a-count\r\n".encode(), final_url=url, redirects=[]))
    malformed = screening.check_password_candidate(SYNTHETIC_PASSWORD, app_mode="live")
    assert malformed.outcome == "unavailable" and malformed.reason == "provider_response_invalid"

    def timeout(url, **_kwargs):
        raise OutboundTimeout(f"timeout {url} password={SYNTHETIC_PASSWORD}")

    monkeypatch.setattr(screening, "safe_get", timeout)
    timed_out = screening.check_password_candidate(SYNTHETIC_PASSWORD, app_mode="live")
    assert timed_out.outcome == "unavailable" and timed_out.reason == "provider_timeout"

    provider_body = b"private response body"
    monkeypatch.setattr(screening, "safe_get", lambda url, **_kwargs: SafeResponse(
        status=429, headers={}, body=provider_body, final_url=url, redirects=[]))
    quota = screening.check_password_candidate(SYNTHETIC_PASSWORD, app_mode="live")
    assert quota.outcome == "unavailable" and quota.reason == "provider_rate_limited"
    full_hash = prefix + suffix
    assert SYNTHETIC_PASSWORD not in caplog.text and prefix not in caplog.text
    assert suffix not in caplog.text and full_hash not in caplog.text
    assert provider_body.decode() not in caplog.text


@pytest.mark.parametrize("response", [
    SafeResponse(status=200, headers={}, body=b"", final_url="https://api.pwnedpasswords.com/range/ABCDE", redirects=[]),
    SafeResponse(status=200, headers={}, body=b"bad-body", final_url="https://api.pwnedpasswords.com/range/ABCDE", redirects=[]),
    SafeResponse(status=200, headers={}, body=b"A" * 128_001, final_url="https://api.pwnedpasswords.com/range/ABCDE", redirects=[]),
    SafeResponse(status=200, headers={}, body=f"{'D' * 35}:1\r\n".encode(), final_url="https://other.example/range/ABCDE", redirects=[]),
])
def test_malformed_or_oversized_range_response_is_unavailable(monkeypatch, response):
    monkeypatch.setattr(screening, "safe_get", lambda _url, **_kwargs: response)
    result = screening.check_password_candidate(SYNTHETIC_PASSWORD, app_mode="live")
    assert result.outcome == "unavailable" and result.reason == "provider_response_invalid"


def test_demo_uses_offline_not_found_fixture(monkeypatch):
    monkeypatch.setattr(screening, "safe_get", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("Demo made a network call")))
    assert screening.check_password_candidate(SYNTHETIC_PASSWORD, app_mode="demo") == screening.PasswordScreeningResult(
        "not_found", "demo_offline_fixture",
    )


@pytest.mark.parametrize("operation", ["create", "change", "reset"])
@pytest.mark.parametrize("outcome, expected_status", [("found", 422), ("unavailable", 503)])
def test_rejected_or_unavailable_screening_does_not_change_accounts_or_sessions(
    db_session, monkeypatch, operation, outcome, expected_status,
):
    db, _factory = db_session
    admin, target, session = _seed_accounts(db)

    def reject(_password, **_kwargs):
        raise screening.PasswordScreeningError(outcome, "synthetic_test_outcome")

    monkeypatch.setattr(users, "get_settings", lambda: SimpleNamespace(app_mode="live"))
    monkeypatch.setattr(users, "require_password_not_compromised", reject)
    monkeypatch.setattr(auth, "require_password_not_compromised", reject)
    monkeypatch.setattr(auth, "settings", SimpleNamespace(app_mode="live", cookie_secure=True))

    before_password = target.password_hash
    before_users = db.query(User).count()
    before_sessions = [(row.id, row.revoked_at) for row in db.query(UserSession).order_by(UserSession.id).all()]
    before_audits = db.query(AuditEvent).count()
    before_evidence = db.query(EvidenceSnapshot).count()
    before_reports = db.query(Report).count()
    with pytest.raises(HTTPException) as rejected:
        if operation == "create":
            users.create_user(UserCreate(username="new-screen-user", password=SYNTHETIC_PASSWORD), admin, db)
        elif operation == "change":
            auth.change_password(PasswordChange(current_password="Synthetic-Old-Password-2026!",
                                                new_password=SYNTHETIC_PASSWORD), Response(), target, db)
        else:
            users.reset_user_password(target.id, AdminPasswordReset(new_password=SYNTHETIC_PASSWORD), admin, db)

    assert rejected.value.status_code == expected_status
    if outcome == "unavailable":
        assert rejected.value.headers == {"Retry-After": "15"}
        assert "temporarily unavailable" in rejected.value.detail
    else:
        assert "Choose a different password" in rejected.value.detail
        assert "does not mean your CyberLens account was breached" in rejected.value.detail
    db.expire_all()
    assert db.query(User).count() == before_users
    assert db.get(User, target.id).password_hash == before_password
    assert [(row.id, row.revoked_at) for row in db.query(UserSession).order_by(UserSession.id).all()] == before_sessions
    assert db.query(AuditEvent).count() == before_audits
    assert db.query(EvidenceSnapshot).count() == before_evidence
    assert db.query(Report).count() == before_reports


def test_successful_password_setting_paths_keep_argon2_and_safe_audits(db_session, monkeypatch):
    db, _factory = db_session
    admin, target, old_session = _seed_accounts(db)
    result = screening.PasswordScreeningResult("not_found", "synthetic_test_fixture")
    monkeypatch.setattr(users, "get_settings", lambda: SimpleNamespace(app_mode="live"))
    monkeypatch.setattr(users, "require_password_not_compromised", lambda *_args, **_kwargs: result)
    monkeypatch.setattr(auth, "require_password_not_compromised", lambda *_args, **_kwargs: result)
    monkeypatch.setattr(auth, "settings", SimpleNamespace(app_mode="live", cookie_secure=True))

    created = users.create_user(UserCreate(username="new-screen-user", password="Synthetic-Create-Password-2026!"), admin, db)
    assert created.password_hash.startswith("$argon2id$")
    assert verify_password(created.password_hash, "Synthetic-Create-Password-2026!")

    auth.change_password(PasswordChange(current_password="Synthetic-Old-Password-2026!",
                                        new_password="Synthetic-Change-Password-2026!"), Response(), target, db)
    db.refresh(old_session)
    assert old_session.revoked_at is not None
    assert verify_password(target.password_hash, "Synthetic-Change-Password-2026!")

    reset_target = User(username="reset-screen-user", password_hash=hash_password("Synthetic-Reset-Old-Password-2026!"), role="analyst")
    db.add(reset_target)
    db.flush()
    reset_session = UserSession(user_id=reset_target.id, token_hash=token_digest("synthetic-reset-session"),
                                csrf_token_hash=token_digest("synthetic-reset-csrf"), expires_at=now_utc() + timedelta(hours=1))
    db.add(reset_session)
    db.commit()
    users.reset_user_password(reset_target.id, AdminPasswordReset(new_password="Synthetic-Reset-Password-2026!"), admin, db)
    db.refresh(reset_session)
    assert reset_session.revoked_at is not None and reset_target.must_change_password is True
    assert verify_password(reset_target.password_hash, "Synthetic-Reset-Password-2026!")

    events = db.query(AuditEvent).filter_by(action="auth.password_screened").all()
    assert len(events) == 3
    assert all(set(event.details_json) == {"outcome", "reason"} for event in events)
    audit_json = json.dumps([event.details_json for event in events])
    for password in [SYNTHETIC_PASSWORD, "Synthetic-Create-Password-2026!", "Synthetic-Change-Password-2026!", "Synthetic-Reset-Password-2026!"]:
        digest = hashlib.sha1(password.encode(), usedforsecurity=False).hexdigest().upper()
        assert password not in audit_json and digest not in audit_json and digest[:5] not in audit_json and digest[5:] not in audit_json
    assert db.query(AuditEvent).filter(AuditEvent.action == "auth.password_screened").count() == 3
    # Exercise the same report projection used by JSON/PDF exports after screening.
    asset = Asset(kind="application", identifier="screening-report-fixture", normalized_identifier="screening-report-fixture",
                  created_by=admin.id)
    db.add(asset)
    db.flush()
    investigation = Investigation(asset_id=asset.id, requested_by=admin.id, mode="demo", scenario="routine", status="completed")
    db.add(investigation)
    db.commit()
    report_projection = json.dumps(reports._investigation_snapshot(db, investigation))
    for password in [SYNTHETIC_PASSWORD, "Synthetic-Create-Password-2026!", "Synthetic-Change-Password-2026!", "Synthetic-Reset-Password-2026!"]:
        digest = hashlib.sha1(password.encode(), usedforsecurity=False).hexdigest().upper()
        assert password not in report_projection and digest not in report_projection
        assert digest[:5] not in report_projection and digest[5:] not in report_projection
    # Screening creates no evidence rows; reports receive neither password nor screening fields.
    assert db.query(Report).count() == 0 and db.query(EvidenceSnapshot).count() == 0


@pytest.mark.parametrize("outcome", ["found", "unavailable"])
def test_bootstrap_fails_closed_without_creating_admin(db_session, monkeypatch, outcome):
    _db, factory = db_session
    monkeypatch.setattr(bootstrap, "SessionLocal", factory)
    monkeypatch.setattr(bootstrap, "get_settings", lambda: SimpleNamespace(
        app_mode="live", bootstrap_admin_password="Synthetic-Live-Bootstrap-Password-2026!",
        bootstrap_admin_username="bootstrap-admin"))

    def reject(_password, **_kwargs):
        raise screening.PasswordScreeningError(outcome, "synthetic_test_outcome")

    monkeypatch.setattr(bootstrap, "require_password_not_compromised", reject)
    with pytest.raises(RuntimeError) as rejected:
        bootstrap.main()
    assert "temporarily unavailable" in str(rejected.value) if outcome == "unavailable" else "Choose a different password" in str(rejected.value)
    with factory() as db:
        assert db.query(User).filter_by(username="bootstrap-admin").count() == 0
        assert db.query(AuditEvent).count() == 0


def test_demo_bootstrap_remains_offline_and_argon2_backed(db_session, monkeypatch):
    _db, factory = db_session
    monkeypatch.setattr(bootstrap, "SessionLocal", factory)
    monkeypatch.setattr(bootstrap, "get_settings", lambda: SimpleNamespace(
        app_mode="demo", bootstrap_admin_password=None, bootstrap_admin_username="demo-admin"))
    monkeypatch.setattr(screening, "safe_get", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("Demo made a network call")))
    bootstrap.main()
    with factory() as db:
        user = db.query(User).filter_by(username="demo-admin").one()
        assert user.password_hash.startswith("$argon2id$")
        assert verify_password(user.password_hash, "CyberLens-Demo-Only-2026!")
        audit = db.query(AuditEvent).filter_by(action="auth.password_screened", entity_id=user.id).one()
        assert audit.details_json == {"outcome": "not_found", "reason": "demo_offline_fixture"}


def test_login_never_calls_password_screening_and_remains_usable(db_session, monkeypatch):
    db, _factory = db_session
    user = User(username="login-synthetic", password_hash=hash_password(SYNTHETIC_PASSWORD), role="admin")
    db.add(user)
    db.commit()
    monkeypatch.setattr(auth, "require_password_not_compromised", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("Login screened an existing password")))
    scope = {
        "type": "http", "http_version": "1.1", "method": "POST", "scheme": "http", "path": "/auth/login",
        "raw_path": b"/auth/login", "query_string": b"", "headers": [(b"cookie", b"cyberlens_csrf=test-csrf"),
        (b"x-csrf-token", b"test-csrf")], "server": ("test", 80), "client": ("127.0.0.1", 50000),
    }

    class RedisCounter:
        def eval(self, *_args):
            return 1
        def delete(self, *_args):
            return 1

    result = auth.login(
        LoginInput(username=user.username, password=SYNTHETIC_PASSWORD),
        Request(scope), Response(), db, RedisCounter(),
    )
    assert result["user"]["username"] == user.username
    assert db.query(UserSession).filter_by(user_id=user.id, revoked_at=None).count() == 1
