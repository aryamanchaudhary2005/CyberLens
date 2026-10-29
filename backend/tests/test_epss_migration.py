from pathlib import Path
import hashlib

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import Session

from app.models import Asset, Finding, Investigation, Report, User, new_id


def test_epss_migration_adds_nullable_fields_without_rewriting_findings(tmp_path, monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    project_root = Path(__file__).resolve().parents[2]
    config = Config(str(project_root / "backend" / "alembic.ini"))
    database_path = tmp_path / "epss-migration.db"
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database_path.as_posix()}")
    command.upgrade(config, "20261017_0007")
    engine = create_engine(f"sqlite:///{database_path.as_posix()}")
    with Session(engine) as db:
        user = User(username="epss-migration-admin", password_hash="not-used", role="admin")
        db.add(user)
        db.flush()
        asset = Asset(kind="application", identifier="EPSS migration target", normalized_identifier="epss-migration-target",
                      created_by=user.id)
        db.add(asset)
        db.flush()
        investigation = Investigation(asset_id=asset.id, requested_by=user.id, mode="live", status="completed")
        db.add(investigation)
        db.flush()
        finding = Finding(asset_id=asset.id, investigation_id=investigation.id, fingerprint="a" * 64,
            category="vulnerabilities", severity="unknown", title="CVE candidate", explanation="candidate",
            recommendation="review", source="NVD", applicability="needs_review",
            details_json={"cve_id": "CVE-2021-41773", "cvss_score": None, "kev": None})
        db.add(finding)
        db.flush()
        report_content = b"saved report bytes before EPSS migration"
        report = Report(id=new_id(), investigation_id=investigation.id, format="json", created_by=user.id,
                        is_demo=False, snapshot_json={"risk": {"score": None}, "findings": [{"id": finding.id}]},
                        content=report_content, sha256=hashlib.sha256(report_content).hexdigest())
        db.add(report)
        db.commit()
        finding_id, report_id = finding.id, report.id

    # Recreate the pre-Module-11 table shape to exercise the additive path for
    # an existing database; saved finding content must survive the upgrade.
    fields = ("epss_score", "epss_percentile", "epss_observed_at", "epss_provider_status", "epss_freshness")
    with engine.begin() as connection:
        for name in fields:
            connection.execute(text(f'ALTER TABLE findings DROP COLUMN "{name}"'))
    command.upgrade(config, "20261017_0008")
    columns = {column["name"] for column in inspect(engine).get_columns("findings")}
    assert set(fields) <= columns
    with Session(engine) as db:
        migrated = db.get(Finding, finding_id)
        assert migrated.details_json == {"cve_id": "CVE-2021-41773", "cvss_score": None, "kev": None}
        assert migrated.applicability == "needs_review"
        assert migrated.epss_score is None and migrated.epss_provider_status is None
        saved_report = db.get(Report, report_id)
        assert saved_report.snapshot_json == {"risk": {"score": None}, "findings": [{"id": finding_id}]}
        assert saved_report.content == report_content
        assert saved_report.sha256 == hashlib.sha256(report_content).hexdigest()
    command.upgrade(config, "head")
    command.check(config)
    engine.dispose()
