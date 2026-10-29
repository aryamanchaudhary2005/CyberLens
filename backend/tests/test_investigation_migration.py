import sqlite3
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import MetaData, Table, create_engine, inspect, select
from sqlalchemy.orm import Session

from app.models import Asset, CollectorRun, Investigation, InvestigationAttempt, User


def test_forward_migration_backfills_saved_investigations_and_collector_history(tmp_path, monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    project_root = Path(__file__).resolve().parents[2]
    config = Config(str(project_root / "backend" / "alembic.ini"))
    database_path = tmp_path / "legacy-investigations.db"
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database_path.as_posix()}")
    command.upgrade(config, "20261016_0003")

    engine = create_engine(f"sqlite:///{database_path.as_posix()}")
    with Session(engine) as db:
        user = User(username="migration-investigator", password_hash="test", role="admin")
        db.add(user)
        db.flush()
        asset = Asset(kind="application", identifier="Existing saved asset", normalized_identifier="existing-saved-asset",
                      created_by=user.id)
        db.add(asset)
        db.flush()
        investigation = Investigation(asset_id=asset.id, requested_by=user.id, mode="demo", scenario="vulnerable_application",
                                      status="completed", progress=100)
        db.add(investigation)
        db.flush()
        run = CollectorRun(investigation_id=investigation.id, collector="nvd_kev", status="success", source="legacy")
        db.add(run)
        db.commit()
        investigation_id = investigation.id
        run_id = run.id
    engine.dispose()

    # Recreate the relevant v3 shape, which predates attempt and outbox tables.
    connection = sqlite3.connect(database_path)
    connection.execute("PRAGMA foreign_keys = OFF")
    connection.execute("DROP TABLE investigation_outbox")
    connection.execute("DROP TABLE investigation_attempts")
    connection.execute("""
        CREATE TABLE collector_runs_legacy (
            id VARCHAR(36) NOT NULL PRIMARY KEY,
            investigation_id VARCHAR(36) NOT NULL,
            collector VARCHAR(80) NOT NULL,
            status VARCHAR(20) NOT NULL,
            source VARCHAR(200) NOT NULL,
            error_explanation TEXT,
            record_count INTEGER NOT NULL,
            started_at DATETIME,
            finished_at DATETIME,
            CONSTRAINT uq_collector_run_investigation UNIQUE (investigation_id, collector),
            FOREIGN KEY (investigation_id) REFERENCES investigations (id) ON DELETE CASCADE
        )
    """)
    connection.execute("""
        INSERT INTO collector_runs_legacy
        (id, investigation_id, collector, status, source, error_explanation, record_count, started_at, finished_at)
        SELECT id, investigation_id, collector, status, source, error_explanation, record_count, started_at, finished_at
        FROM collector_runs
    """)
    connection.execute("DROP TABLE collector_runs")
    connection.execute("ALTER TABLE collector_runs_legacy RENAME TO collector_runs")
    connection.execute("CREATE INDEX ix_collector_runs_investigation_id ON collector_runs (investigation_id)")
    connection.commit()
    connection.close()

    # Test this historical upgrade at its own schema boundary. Later feed
    # migrations use PostgreSQL ALTER constraints, which SQLite cannot apply
    # to this deliberately reconstructed legacy collector table.
    command.upgrade(config, "20261016_0004")
    migrated_engine = create_engine(f"sqlite:///{database_path.as_posix()}")
    with Session(migrated_engine) as db:
        investigation = db.get(Investigation, investigation_id)
        collector_table = Table("collector_runs", MetaData(), autoload_with=migrated_engine)
        run = db.execute(select(collector_table).where(collector_table.c.id == run_id)).mappings().one()
        attempt = db.query(InvestigationAttempt).filter_by(investigation_id=investigation_id).one()
        assert investigation.status == "completed"
        assert attempt.retry_kind == "initial"
        assert attempt.status == "completed"
        assert run["attempt_id"] == attempt.id
        assert run["collector"] == "nvd_kev" and run["source"] == "legacy" and run["status"] == "success"
        assert inspect(migrated_engine).get_table_names().count("investigation_outbox") == 1
        unique_constraints = {item["name"] for item in inspect(migrated_engine).get_unique_constraints("collector_runs")}
        assert "uq_collector_run_attempt" in unique_constraints
        assert "uq_collector_run_investigation" not in unique_constraints
    migrated_engine.dispose()
