"""The DROP feed migration is additive and leaves saved investigation reports intact."""

import hashlib
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import Session

from app.models import Asset, Investigation, Report, ThreatFeedSource, User, new_id


def test_spamhaus_drop_migration_adds_snapshot_tables_without_rewriting_reports(tmp_path, monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    root = Path(__file__).resolve().parents[2]
    config = Config(str(root / "backend" / "alembic.ini"))
    config.set_main_option("script_location", str(root / "backend" / "alembic"))
    database_path = tmp_path / "spamhaus-drop.db"
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database_path.as_posix()}")
    command.upgrade(config, "20261019_0016")
    engine = create_engine(f"sqlite:///{database_path.as_posix()}")

    report_bytes = b"saved report before Spamhaus snapshot migration"
    with Session(engine) as db:
        user = User(username="drop-migration-user", password_hash="unused", role="admin")
        db.add(user)
        db.flush()
        asset = Asset(kind="ip", identifier="8.8.8.8", normalized_identifier="8.8.8.8", created_by=user.id)
        db.add(asset)
        db.flush()
        investigation = Investigation(asset_id=asset.id, requested_by=user.id, mode="live", status="completed")
        db.add(investigation)
        db.flush()
        report = Report(
            id=new_id(), investigation_id=investigation.id, format="json", created_by=user.id,
            is_demo=False, snapshot_json={"finding": "existing"}, content=report_bytes,
            sha256=hashlib.sha256(report_bytes).hexdigest(),
        )
        db.add(report)
        db.commit()
        report_id = report.id

    command.upgrade(config, "head")
    inspector = inspect(engine)
    assert {"threat_feed_sources", "threat_feed_snapshots", "threat_feed_networks",
            "threat_feed_refresh_attempts"} <= set(inspector.get_table_names())
    assert "feed_snapshot_id" in {column["name"] for column in inspector.get_columns("collector_runs")}
    with Session(engine) as db:
        source = db.get(ThreatFeedSource, "spamhaus_drop")
        report = db.get(Report, report_id)
        assert source is not None and source.active_snapshot_id is None
        assert report.snapshot_json == {"finding": "existing"}
        assert report.content == report_bytes
        assert report.sha256 == hashlib.sha256(report_bytes).hexdigest()
    command.check(config)
    engine.dispose()
