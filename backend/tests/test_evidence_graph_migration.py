from pathlib import Path
import os
from datetime import datetime, timezone

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import Session

from app.models import Asset, CollectorRun, EvidenceRelationship, EvidenceSnapshot, Investigation, User


def test_graph_revision_adds_evidence_backed_relationship_table(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    project_root = Path(__file__).resolve().parents[2]
    config = Config(str(project_root / "backend" / "alembic.ini"))
    database_path = Path(__file__).parent / f".evidence-graph-{os.getpid()}.db"
    if database_path.exists():
        raise RuntimeError("Refusing to overwrite a pre-existing graph migration test database")
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database_path.as_posix()}")

    try:
        command.upgrade(config, "20261017_0005")
        engine = create_engine(f"sqlite:///{database_path.as_posix()}")
        observed_at = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
        with Session(engine) as db:
            admin = User(username="legacy-graph-admin", password_hash="not-used", role="admin")
            db.add(admin)
            db.flush()
            asset = Asset(kind="domain", identifier="legacy.example.test", normalized_identifier="legacy.example.test",
                          created_by=admin.id, is_synthetic=True)
            db.add(asset)
            db.flush()
            investigation = Investigation(asset_id=asset.id, requested_by=admin.id, mode="demo", status="completed",
                                          progress=100, created_at=observed_at, finished_at=observed_at)
            db.add(investigation)
            db.flush()
            run = CollectorRun(investigation_id=investigation.id, collector="dns_rdap", status="success",
                               source="Synthetic DNS fixture", started_at=observed_at, finished_at=observed_at)
            db.add(run)
            db.flush()
            evidence = EvidenceSnapshot(investigation_id=investigation.id, collector_run_id=run.id,
                source="Synthetic DNS fixture", observed_at=observed_at, sha256="d" * 64, is_synthetic=True,
                evidence_json={"submitted_host": "legacy.example.test", "records": {
                    "A": {"status": "success", "values": ["203.0.113.9"]},
                    "AAAA": {"status": "no_match", "values": []}}})
            db.add(evidence)
            db.commit()
            investigation_id, evidence_id = investigation.id, evidence.id
        engine.dispose()

        command.upgrade(config, "20261017_0006")
        engine = create_engine(f"sqlite:///{database_path.as_posix()}")
        try:
            inspector = inspect(engine)
            assert "evidence_relationships" in inspector.get_table_names()
            columns = {column["name"] for column in inspector.get_columns("evidence_relationships")}
            assert {"from_node_type", "to_node_type", "relationship_type", "evidence_role", "source",
                    "evidence_id", "observed_at", "data_mode"} <= columns
            foreign_keys = {tuple(key["constrained_columns"]) for key in inspector.get_foreign_keys("evidence_relationships")}
            assert ("evidence_id",) in foreign_keys
            assert ("investigation_id",) in foreign_keys
            unique_constraints = {item["name"] for item in inspector.get_unique_constraints("evidence_relationships")}
            assert "uq_evidence_relationship_observation" in unique_constraints
        finally:
            engine.dispose()

        # Legacy evidence is projected only after every column consumed by the
        # current ORM exists, in the later dedicated backfill revision.
        command.upgrade(config, "head")
        engine = create_engine(f"sqlite:///{database_path.as_posix()}")
        try:
            with Session(engine) as db:
                edge = db.query(EvidenceRelationship).filter_by(
                    investigation_id=investigation_id, relationship_type="resolves_to").one()
                assert edge.evidence_id == evidence_id
                assert edge.from_node_id == "domain:legacy.example.test"
                assert edge.to_node_id == "ip:203.0.113.9"
                assert edge.data_mode == "demo"
        finally:
            engine.dispose()
        command.check(config)
    finally:
        if database_path.exists() and database_path.parent.resolve() == Path(__file__).parent.resolve():
            database_path.unlink()
