from app.models import AuditEvent, Incident, Report, User, new_id, now_utc

from conftest import csrf, login


def test_collection_pagination_is_stable_and_filterable(workspace):
    client, factory = workspace
    login(client)
    for identifier in ("alpha.example.test", "bravo.example.test", "charlie.example.test"):
        response = client.post("/api/v1/assets", headers=csrf(client), json={"kind": "domain", "identifier": identifier})
        assert response.status_code == 201, response.text

    first = client.get("/api/v1/assets?page=1&page_size=2&sort=identifier&order=asc&q=.example.test")
    second = client.get("/api/v1/assets?page=1&page_size=2&sort=identifier&order=asc&q=.example.test")
    assert first.status_code == second.status_code == 200
    assert [row["identifier"] for row in first.json()] == ["alpha.example.test", "bravo.example.test"]
    assert [row["id"] for row in first.json()] == [row["id"] for row in second.json()]
    assert first.headers["X-Total-Count"] == "3"
    assert first.headers["X-Page"] == "1"
    assert first.headers["X-Page-Size"] == "2"
    assert first.headers["X-Has-Next"] == "true"

    page_two = client.get("/api/v1/assets?page=2&page_size=2&sort=identifier&order=asc")
    assert [row["identifier"] for row in page_two.json()] == ["charlie.example.test"]
    assert page_two.headers["X-Has-Next"] == "false"


def test_collection_filters_cover_incidents_reports_and_audit_events(workspace):
    client, factory = workspace
    login(client)
    db = factory()
    admin = db.query(User).filter_by(username="admin").one()
    asset = client.post("/api/v1/assets", headers=csrf(client), json={"kind": "application", "identifier": "Query target"}).json()
    db.add(Incident(id=new_id(), title="High priority case", summary="Needs review", classification="security_issue",
                    status="new", priority="high", owner_id=admin.id, asset_id=asset["id"], created_by=admin.id,
                    created_at=now_utc(), updated_at=now_utc()))
    db.add(Incident(id=new_id(), title="Low priority case", summary="Routine", classification="security_issue",
                    status="new", priority="low", owner_id=admin.id, asset_id=asset["id"], created_by=admin.id,
                    created_at=now_utc(), updated_at=now_utc()))
    db.add(Report(id=new_id(), format="json", created_by=admin.id, is_demo=True, snapshot_json={}, content=b"{}", sha256="a" * 64))
    db.add(AuditEvent(actor_id=admin.id, action="query.marker", entity_type="test", entity_id=new_id(), details_json={}))
    db.commit()
    db.close()

    incidents = client.get("/api/v1/incidents?priority=high&page_size=10&sort=priority&order=asc")
    assert incidents.status_code == 200
    assert [item["title"] for item in incidents.json()] == ["High priority case"]
    reports = client.get("/api/v1/reports?format=json&is_demo=true&page_size=10")
    assert reports.status_code == 200
    assert len(reports.json()) == 1
    audit = client.get("/api/v1/audit-events?action=query.marker&page_size=10&sort=action&order=asc")
    assert audit.status_code == 200
    assert audit.json()[0]["actor"] == "admin"
    assert audit.json()[0]["action"] == "query.marker"
