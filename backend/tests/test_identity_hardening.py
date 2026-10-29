from datetime import timedelta
from types import SimpleNamespace

from fastapi.testclient import TestClient

from app import authorization, bootstrap, jobs
from app.main import app
from app.models import Asset, AuditEvent, Investigation, User, UserSession, WebsiteAuthorization, now_utc
from app.security import token_digest, verify_password

from conftest import cookie_value, csrf, login


def test_viewer_cannot_mutate_protected_records(workspace):
    client, _factory = workspace
    login(client)
    client.post("/api/v1/auth/logout", headers=csrf(client))
    login(client, "viewer", "Test-Viewer-Password-2026!")

    attempts = [
        ("post", "/api/v1/assets", {"kind": "domain", "identifier": "viewer.example.test"}),
        ("patch", "/api/v1/assets/missing", {"notes": "updated by viewer"}),
        ("post", "/api/v1/assets/missing/authorization", {"authorized": True, "note": "Written approval exists"}),
        ("delete", "/api/v1/assets/missing/authorization", None),
        ("post", "/api/v1/assets/missing/components", {"vendor": "Acme", "product": "Portal", "version": "1.0"}),
        ("delete", "/api/v1/assets/missing/components/missing", None),
        ("post", "/api/v1/investigations", {"asset_id": "missing"}),
        ("post", "/api/v1/investigations/missing/retry", None),
        ("patch", "/api/v1/findings/missing/applicability", {"applicability": "applies", "reason": "Reviewed evidence"}),
        ("post", "/api/v1/incidents", {"title": "Viewer case", "asset_id": "missing", "finding_ids": ["missing"]}),
        ("patch", "/api/v1/incidents/missing", {"priority": "high"}),
        ("post", "/api/v1/incidents/missing/events", {"message": "Viewer event"}),
        ("patch", "/api/v1/incidents/missing/tasks/missing", {"status": "completed"}),
        ("post", "/api/v1/reports", {"format": "json", "investigation_id": "missing"}),
        ("post", "/api/v1/users", {"username": "other", "password": "Another-Account-Password-2026!", "role": "viewer"}),
        ("patch", "/api/v1/users/missing/active?active=false", {}),
        ("patch", "/api/v1/users/missing/role", {"role": "admin"}),
        ("post", "/api/v1/users/missing/password-reset", {"new_password": "Reset-Account-Password-2026!"}),
    ]
    for method, path, body in attempts:
        kwargs = {"headers": csrf(client)}
        if body is not None:
            kwargs["json"] = body
        response = getattr(client, method)(path, **kwargs)
        assert response.status_code == 403, f"{method.upper()} {path}: {response.status_code} {response.text}"

    cpe = client.put(
        "/api/v1/integrations/assets/missing/components/missing/cpe?cpe_name=cpe:2.3:a:acme:portal:1:*:*:*:*:*:*:*",
        headers=csrf(client),
    )
    assert cpe.status_code == 403
    assert client.get("/api/v1/assets").status_code == 200
    assert client.get("/api/v1/reports").status_code == 200


def test_login_throttle_is_shared_and_resets_after_success(workspace):
    client, _factory = workspace
    login(client)
    client.post("/api/v1/auth/logout", headers=csrf(client))
    token = client.get("/api/v1/auth/csrf").json()["csrf_token"]
    headers = {"X-CSRF-Token": token}
    for _ in range(3):
        denied = client.post("/api/v1/auth/login", json={"username": "admin", "password": "wrong"}, headers=headers)
        assert denied.status_code == 401
    client.cookies.clear()
    login(client)
    client.post("/api/v1/auth/logout", headers=csrf(client))

    token = client.get("/api/v1/auth/csrf").json()["csrf_token"]
    headers = {"X-CSRF-Token": token}
    for _ in range(5):
        denied = client.post("/api/v1/auth/login", json={"username": "admin", "password": "wrong"}, headers=headers)
        assert denied.status_code == 401
    limited = client.post("/api/v1/auth/login", json={"username": "admin", "password": "wrong"}, headers=headers)
    assert limited.status_code == 429

    # Each request gets a new Redis dependency client in the fixture; the shared
    # backing state models the shared Redis store used by separate API workers.


def test_password_change_rotates_current_session_and_audits(workspace):
    client, factory = workspace
    login(client)
    original_token = cookie_value(client, "cyberlens_session")
    old_csrf = cookie_value(client, "cyberlens_csrf")
    response = client.post("/api/v1/auth/change-password", headers={"X-CSRF-Token": old_csrf},
                           json={"current_password": "Test-Admin-Password-2026!", "new_password": "Changed-Admin-Password-2026!"})
    assert response.status_code == 200, response.text
    rotated_token = cookie_value(client, "cyberlens_session")
    assert rotated_token and rotated_token != original_token
    assert cookie_value(client, "cyberlens_csrf") != old_csrf
    assert client.get("/api/v1/auth/me").status_code == 200

    db = factory()
    old_session = db.query(UserSession).filter_by(token_hash=token_digest(original_token)).one()
    new_session = db.query(UserSession).filter_by(token_hash=token_digest(rotated_token)).one()
    assert old_session.revoked_at is not None
    assert new_session.revoked_at is None
    assert db.query(AuditEvent).filter_by(action="auth.password_changed").count() == 1
    db.close()

    assert client.get("/api/v1/auth/me", headers={"Cookie": f"cyberlens_session={original_token}"}).status_code == 401


def test_admin_password_reset_revokes_target_sessions_and_requires_change(workspace):
    client, factory = workspace
    with TestClient(app) as target_client:
        login(target_client, "viewer", "Test-Viewer-Password-2026!")
        old_session_token = cookie_value(target_client, "cyberlens_session")
        login(client)
        db = factory()
        target_id = db.query(User).filter_by(username="viewer").one().id
        db.close()
        reset = client.post(f"/api/v1/users/{target_id}/password-reset", headers=csrf(client),
                            json={"new_password": "Reset-Viewer-Password-2026!"})
        assert reset.status_code == 200, reset.text
        assert reset.json()["must_change_password"] is True
        assert target_client.get("/api/v1/auth/me").status_code == 401

        db = factory()
        old_session = db.query(UserSession).filter_by(token_hash=token_digest(old_session_token)).one()
        assert old_session.revoked_at is not None
        audit = db.query(AuditEvent).filter_by(action="user.password_reset", entity_id=reset.json()["id"]).one()
        assert audit.details_json["sessions_revoked"] >= 1
        db.close()

        target_client.cookies.clear()
        login(target_client, "viewer", "Reset-Viewer-Password-2026!")
        assert target_client.get("/api/v1/auth/me").json()["must_change_password"] is True


def test_last_active_admin_cannot_be_disabled_or_demoted(workspace):
    client, factory = workspace
    login(client)
    db = factory()
    admin_id = db.query(User).filter_by(username="admin").one().id
    db.close()
    last_admin = client.patch(f"/api/v1/users/{admin_id}/active?active=false", headers=csrf(client))
    assert last_admin.status_code == 409
    demote_last_admin = client.patch(f"/api/v1/users/{admin_id}/role", headers=csrf(client), json={"role": "analyst"})
    assert demote_last_admin.status_code == 409

    created = client.post("/api/v1/users", headers=csrf(client), json={
        "username": "backup-admin", "password": "Backup-Admin-Password-2026!", "role": "admin"
    })
    assert created.status_code == 201, created.text
    allowed = client.patch(f"/api/v1/users/{admin_id}/role", headers=csrf(client), json={"role": "viewer"})
    assert allowed.status_code == 200

    client.post("/api/v1/auth/logout", headers=csrf(client))
    login(client, "backup-admin", "Backup-Admin-Password-2026!")
    backup_id = created.json()["id"]
    changed = client.post("/api/v1/auth/change-password", headers=csrf(client), json={
        "current_password": "Backup-Admin-Password-2026!",
        "new_password": "Backup-Admin-Rotated-Password-2026!",
    })
    assert changed.status_code == 200, changed.text
    last_admin_demote = client.patch(f"/api/v1/users/{backup_id}/role", headers=csrf(client), json={"role": "viewer"})
    assert last_admin_demote.status_code == 409
    last_admin_disable = client.patch(f"/api/v1/users/{backup_id}/active?active=false", headers=csrf(client))
    assert last_admin_disable.status_code == 409

    db = factory()
    role_event = db.query(AuditEvent).filter_by(action="user.role_changed", entity_id=backup_id)
    assert role_event.count() == 0
    # The successful self-demotion event targets the original administrator's generated ID.
    original_admin = db.query(User).filter_by(username="admin").one()
    assert db.query(AuditEvent).filter_by(action="user.role_changed", entity_id=original_admin.id).count() == 1
    db.close()


def test_login_logout_and_csrf_audit_contract(workspace):
    client, factory = workspace
    client.get("/api/v1/auth/csrf")
    no_header = client.post("/api/v1/auth/login", json={"username": "admin", "password": "wrong"})
    assert no_header.status_code == 403
    login(client)
    session_csrf = cookie_value(client, "cyberlens_csrf")
    wrong_cookie_token = "not-the-session-csrf"
    invalid = client.post("/api/v1/assets", json={"kind": "domain", "identifier": "csrf.example.test"},
                          headers={"X-CSRF-Token": wrong_cookie_token,
                                   "Cookie": f"cyberlens_session={cookie_value(client, 'cyberlens_session')}; cyberlens_csrf={wrong_cookie_token}"})
    assert invalid.status_code == 403
    assert session_csrf
    logout = client.post("/api/v1/auth/logout", headers=csrf(client))
    assert logout.status_code == 200
    db = factory()
    actions = {row.action for row in db.query(AuditEvent).all()}
    assert "auth.login" in actions
    assert "auth.logout" in actions
    db.close()


def test_website_authorization_expires_and_can_be_revoked(workspace, monkeypatch):
    client, factory = workspace
    login(client)
    created = client.post("/api/v1/assets", headers=csrf(client), json={"kind": "domain", "identifier": "scope.example.test"})
    assert created.status_code == 201, created.text
    asset_id = created.json()["id"]
    grant = client.post(f"/api/v1/assets/{asset_id}/authorization", headers=csrf(client),
                        json={"authorized": True, "note": "Written owner permission", "expires_in_days": 1})
    assert grant.status_code == 200, grant.text
    active = grant.json()
    assert active["authorization_id"]
    assert active["authorization_expires_at"]
    assert active["authorized_at"]

    db = factory()
    authorization_row = db.get(WebsiteAuthorization, active["authorization_id"])
    assert authorization_row is not None
    assert authorization.active_website_authorization(db, asset_id) is not None
    history = client.get(f"/api/v1/assets/{asset_id}/authorizations")
    assert history.status_code == 200
    assert len(history.json()) == 1

    from datetime import datetime, timezone
    future = datetime.now(timezone.utc) + timedelta(days=2)
    monkeypatch.setattr(authorization, "now_utc", lambda: future)
    assert authorization.active_website_authorization(db, asset_id) is None
    monkeypatch.undo()

    revoke = client.delete(f"/api/v1/assets/{asset_id}/authorization", headers=csrf(client))
    assert revoke.status_code == 200, revoke.text
    assert revoke.json()["authorized_at"] is None
    history = client.get(f"/api/v1/assets/{asset_id}/authorizations").json()
    assert history[0]["revoked_at"] is not None
    audit_actions = {row.action for row in db.query(AuditEvent).filter(AuditEvent.entity_type == "website_authorization").all()}
    db.close()
    assert "website_authorization.granted" in audit_actions
    assert "website_authorization.revoked" in audit_actions


def test_worker_skips_expired_or_revoked_website_authorizations(workspace, monkeypatch):
    _client, factory = workspace
    db = factory()
    admin = db.query(User).filter_by(username="admin").one()
    asset = Asset(kind="domain", identifier="scope.example.test", normalized_identifier="scope.example.test", created_by=admin.id)
    db.add(asset)
    db.flush()
    db.add(WebsiteAuthorization(asset_id=asset.id, authorized_by=admin.id, note="approved",
                                expires_at=now_utc() + timedelta(days=1)))
    expired_run = Investigation(asset_id=asset.id, requested_by=admin.id, mode="live", status="queued")
    db.add(expired_run)
    db.flush()
    db.add(WebsiteAuthorization(asset_id=asset.id, authorized_by=admin.id, note="revoked",
                                expires_at=now_utc() + timedelta(days=30), revoked_at=now_utc(), revoked_by=admin.id))
    revoked_run = Investigation(asset_id=asset.id, requested_by=admin.id, mode="live", status="queued")
    db.add(revoked_run)
    db.commit()
    expired_id, revoked_id, asset_id = expired_run.id, revoked_run.id, asset.id
    db.close()

    monkeypatch.setattr(jobs, "SessionLocal", factory)
    monkeypatch.setattr(jobs, "get_settings", lambda: SimpleNamespace(app_mode="live"))
    monkeypatch.setattr(jobs, "_collectors", lambda _asset, *_args, **_kwargs: ["web_tls"])
    monkeypatch.setattr(jobs, "collect_website", lambda _asset: (_ for _ in ()).throw(AssertionError("website check ran")))
    future = now_utc() + timedelta(days=2)
    monkeypatch.setattr(authorization, "now_utc", lambda: future)
    jobs.run_investigation(expired_id)
    jobs.run_investigation(revoked_id)

    db = factory()
    results = db.query(jobs.CollectorRun).filter(jobs.CollectorRun.investigation_id.in_([expired_id, revoked_id])).all()
    assert len(results) == 2
    assert {item.status for item in results} == {"not_applicable"}
    assert asset_id
    db.close()


def test_bootstrap_preserves_local_demo_and_rejects_unsafe_live_passwords(workspace, monkeypatch):
    _client, factory = workspace
    monkeypatch.setattr(bootstrap, "SessionLocal", factory)
    db = factory()
    db.query(User).delete()
    db.commit()
    db.close()

    monkeypatch.setattr(bootstrap, "get_settings", lambda: SimpleNamespace(
        app_mode="demo", bootstrap_admin_password=None, bootstrap_admin_username="admin"))
    bootstrap.main()
    db = factory()
    demo_admin = db.query(User).filter_by(username="admin").one()
    assert verify_password(demo_admin.password_hash, "CyberLens-Demo-Only-2026!")
    db.query(User).delete()
    db.commit()
    db.close()

    for unsafe_password in (None, "short", "CyberLens-Demo-Only-2026!"):
        monkeypatch.setattr(bootstrap, "get_settings", lambda password=unsafe_password: SimpleNamespace(
            app_mode="live", bootstrap_admin_password=password, bootstrap_admin_username="admin"))
        try:
            bootstrap.main()
        except RuntimeError:
            pass
        else:
            raise AssertionError(f"Unsafe live bootstrap password was accepted: {unsafe_password!r}")

    monkeypatch.setattr(bootstrap, "get_settings", lambda: SimpleNamespace(
        app_mode="live", bootstrap_admin_password="Unique-Live-Admin-Password-2026!", bootstrap_admin_username="admin"))
    from app.services.password_screening import PasswordScreeningResult
    monkeypatch.setattr(bootstrap, "require_password_not_compromised",
                        lambda *_args, **_kwargs: PasswordScreeningResult("not_found", "synthetic_test_fixture"))
    bootstrap.main()
    db = factory()
    assert db.query(User).filter_by(username="admin", role="admin", must_change_password=True).count() == 1
    db.close()
