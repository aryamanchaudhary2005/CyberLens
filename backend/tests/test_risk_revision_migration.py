from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import Session

from app.models import Asset, Investigation, RiskAssessment, RiskAssessmentRevision, User


def test_risk_revision_migration_creates_table_and_backfills_current_assessment(tmp_path, monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    project_root = Path(__file__).resolve().parents[2]
    config = Config(str(project_root / "backend" / "alembic.ini"))
    database_path = tmp_path / "risk-revision.db"
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database_path.as_posix()}")
    command.upgrade(config, "20261017_0006")
    engine = create_engine(f"sqlite:///{database_path.as_posix()}")
    with Session(engine) as db:
        admin = User(username="risk-migration-admin", password_hash="not-used", role="admin")
        db.add(admin)
        db.flush()
        asset = Asset(kind="domain", identifier="migration.example.test", normalized_identifier="migration.example.test", created_by=admin.id)
        db.add(asset)
        db.flush()
        investigation = Investigation(asset_id=asset.id, requested_by=admin.id, mode="demo", status="completed")
        db.add(investigation)
        db.flush()
        db.add(RiskAssessment(investigation_id=investigation.id, version="cyberlens-academic-1.0", score=42.0, band="medium",
                              assessed_categories=["reputation"], excluded_categories=["vulnerabilities"], category_scores={"reputation": 42},
                              contributing_finding_ids=["finding-1"], explanation_json={"rule_version": "cyberlens-academic-1.0", "weights_percent": {"reputation": 30}}))
        db.commit()
        investigation_id = investigation.id
    with engine.begin() as connection:
        connection.execute(text("DROP TABLE risk_assessment_revisions"))
    command.upgrade(config, "20261017_0007")
    assert "risk_assessment_revisions" in inspect(engine).get_table_names()
    with Session(engine) as db:
        revision = db.query(RiskAssessmentRevision).filter_by(investigation_id=investigation_id).one()
        assert revision.revision_number == 1
        assert revision.score == 42.0
        assert revision.weights_json == {"reputation": 30}
        assert revision.input_fingerprint
    engine.dispose()
