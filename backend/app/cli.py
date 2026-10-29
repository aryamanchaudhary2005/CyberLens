"""Explicit demo-data seed and reset commands. Reset refuses live mode."""

import argparse

from app.config import get_settings
from app.database import SessionLocal
from app.models import (Asset, AuditEvent, EvidenceSnapshot, Finding, Incident, IncidentEvent, IncidentFinding,
                        Investigation, PlaybookTask, Report, RiskAssessment, SoftwareComponent, User, CollectorRun, now_utc)

DEMO_ASSET_DEFINITIONS = (
    ("domain", "shop.example.test", "routine_website", "Routine website fixture"),
    ("domain", "signin-example.test", "suspicious_website", "Suspicious website fixture"),
    ("email", "student@example.test", "exposed_email", "Historical breach fixture"),
    ("application", "Demo customer portal", "vulnerable_application", "Software CVE fixture"),
    ("domain", "outage.example.test", "provider_outage", "Partial result fixture"),
)


def seed_demo(db) -> int:
    if get_settings().app_mode != "demo":
        raise RuntimeError("Refusing to seed synthetic records unless APP_MODE=demo")
    created = 0
    for kind, identifier, scenario, notes in DEMO_ASSET_DEFINITIONS:
        normalized = identifier.casefold()
        asset = db.query(Asset).filter_by(kind=kind, normalized_identifier=normalized).first()
        if asset is None:
            admin = db.query(User).filter_by(role="admin", is_active=True).order_by(User.created_at).first()
            if admin is None:
                raise RuntimeError("Create the bootstrap administrator before seeding demo assets")
            asset = Asset(kind=kind, identifier=identifier, normalized_identifier=normalized, notes=notes,
                is_synthetic=True, demo_scenario=scenario, created_by=admin.id)
            db.add(asset)
            db.flush()
            created += 1
        if kind == "application" and not db.query(SoftwareComponent).filter_by(asset_id=asset.id).first():
            db.add(SoftwareComponent(asset_id=asset.id, vendor="Apache", product="HTTP Server", version="2.4.49",
                cpe_name="cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"))
    db.commit()
    return created


def reset_demo(db) -> int:
    settings = get_settings()
    if settings.app_mode != "demo":
        raise RuntimeError("Refusing to reset records unless APP_MODE=demo")
    demo_investigations = [row.id for row in db.query(Investigation).filter_by(mode="demo").all()]
    demo_incidents = []
    for row in db.query(Incident).all():
        if row.investigation_id in demo_investigations:
            demo_incidents.append(row.id)
            continue
        linked_findings = db.query(Finding).join(IncidentFinding, IncidentFinding.finding_id == Finding.id).filter(
            IncidentFinding.incident_id == row.id).all()
        if linked_findings and all(item.is_synthetic for item in linked_findings):
            demo_incidents.append(row.id)
    preserved_reports = db.query(Report).filter(Report.is_demo.is_(False), Report.incident_id.in_(demo_incidents)).all() if demo_incidents else []
    protected_incidents = {item.incident_id for item in preserved_reports}
    demo_incidents = [item for item in demo_incidents if item not in protected_incidents]
    live_reports = db.query(Report).filter(Report.is_demo.is_(False)).all()
    protected_demo_investigations = {item.investigation_id for item in live_reports if item.investigation_id in demo_investigations}
    protected_demo_investigations.update(row.investigation_id for row in db.query(Incident).all()
        if row.id not in demo_incidents and row.investigation_id in demo_investigations)
    demo_investigations = [item for item in demo_investigations if item not in protected_demo_investigations]
    if demo_incidents:
        db.query(Report).filter(Report.incident_id.in_(demo_incidents)).delete(synchronize_session=False)
        db.query(IncidentEvent).filter(IncidentEvent.incident_id.in_(demo_incidents)).delete(synchronize_session=False)
        db.query(IncidentFinding).filter(IncidentFinding.incident_id.in_(demo_incidents)).delete(synchronize_session=False)
        db.query(PlaybookTask).filter(PlaybookTask.incident_id.in_(demo_incidents)).delete(synchronize_session=False)
        db.query(Incident).filter(Incident.id.in_(demo_incidents)).delete(synchronize_session=False)
    db.query(Report).filter(Report.is_demo.is_(True)).delete(synchronize_session=False)
    if demo_investigations:
        db.query(RiskAssessment).filter(RiskAssessment.investigation_id.in_(demo_investigations)).delete(synchronize_session=False)
        db.query(Finding).filter(Finding.investigation_id.in_(demo_investigations)).delete(synchronize_session=False)
        db.query(EvidenceSnapshot).filter(EvidenceSnapshot.investigation_id.in_(demo_investigations)).delete(synchronize_session=False)
        db.query(CollectorRun).filter(CollectorRun.investigation_id.in_(demo_investigations)).delete(synchronize_session=False)
        db.query(Investigation).filter(Investigation.id.in_(demo_investigations)).delete(synchronize_session=False)
    protected_assets = {row.asset_id for row in db.query(Investigation).filter(Investigation.mode != "demo").all()}
    protected_assets.update(row.asset_id for row in db.query(Incident).all())
    for report in live_reports:
        if report.investigation_id:
            linked = db.get(Investigation, report.investigation_id)
            if linked: protected_assets.add(linked.asset_id)
        if report.incident_id:
            linked = db.get(Incident, report.incident_id)
            if linked: protected_assets.add(linked.asset_id)
    synthetic_assets = [row.id for row in db.query(Asset).filter_by(is_synthetic=True).all() if row.id not in protected_assets]
    if synthetic_assets:
        db.query(SoftwareComponent).filter(SoftwareComponent.asset_id.in_(synthetic_assets)).delete(synchronize_session=False)
        db.query(Asset).filter(Asset.id.in_(synthetic_assets)).delete(synchronize_session=False)
    db.add(AuditEvent(action="demo.reset", entity_type="workspace", entity_id="demo",
        details_json={"removed_investigations": len(demo_investigations), "removed_incidents": len(demo_incidents)}, created_at=now_utc()))
    db.commit()
    return len(demo_investigations) + len(demo_incidents) + len(synthetic_assets)


def main() -> None:
    parser = argparse.ArgumentParser(prog="cyberlens")
    parser.add_argument("command", choices=("seed-demo", "reset-demo", "reset-and-seed-demo"))
    args = parser.parse_args()
    db = SessionLocal()
    try:
        if args.command == "seed-demo":
            count = seed_demo(db)
            print(f"Seeded {count} synthetic demo assets.")
        elif args.command == "reset-demo":
            count = reset_demo(db)
            print(f"Removed {count} demo records. Live investigations and assets were retained.")
        else:
            count = reset_demo(db)
            created = seed_demo(db)
            print(f"Reset {count} demo records and seeded {created} synthetic demo assets.")
    finally:
        db.close()


if __name__ == "__main__":
    main()
