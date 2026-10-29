"""OpenPhish migration preserves legacy URLs and report snapshots."""

import hashlib
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import Session

from app.models import Asset, Investigation, Report, ThreatFeedSource, User


def test_openphish_migration_adds_snapshot_storage_without_rewriting_saved_data(tmp_path, monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    root = Path(__file__).resolve().parents[2]
    config = Config(str(root / "backend" / "alembic.ini"))
    config.set_main_option("script_location", str(root / "backend" / "alembic"))
    database_path = tmp_path / "openphish-upgrade.db"
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database_path.as_posix()}")
    command.upgrade(config, "20261020_0018")
    engine = create_engine(f"sqlite:///{database_path.as_posix()}")

    report_bytes = b"immutable report before OpenPhish"
    report_snapshot = {"legacy": "report text", "url": "https://example.test/Admin?x=1#part"}
    with Session(engine) as db:
        user = User(username="module26-migration", password_hash="unused", role="admin")
        db.add(user)
        db.flush()
        asset = Asset(kind="url", identifier=report_snapshot["url"],
                      normalized_identifier=report_snapshot["url"], url_retention_complete=False,
                      created_by=user.id)
        db.add(asset)
        db.flush()
        investigation = Investigation(asset_id=asset.id, requested_by=user.id, mode="live", status="completed")
        db.add(investigation)
        db.flush()
        report = Report(
            id="module26-legacy-report", investigation_id=investigation.id, format="json",
            created_by=user.id, is_demo=False, snapshot_json=report_snapshot,
            content=report_bytes, sha256=hashlib.sha256(report_bytes).hexdigest(),
        )
        db.add(report)
        db.commit()
        asset_id = asset.id

    command.upgrade(config, "head")
    inspector = inspect(engine)
    columns = {item["name"] for item in inspector.get_columns("assets")}
    indexes = {item["name"] for item in inspector.get_indexes("threat_feed_urls")}
    assert "url_retention_complete" in columns
    assert "ix_threat_feed_urls_snapshot_hostname" in indexes
    assert "ix_threat_feed_sources_personal_owner_user_id" in {
        item["name"] for item in inspector.get_indexes("threat_feed_sources")
    }
    with Session(engine) as db:
        source = db.get(ThreatFeedSource, "openphish")
        asset = db.get(Asset, asset_id)
        report = db.get(Report, "module26-legacy-report")
        assert source.source_urls_json == [
            "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
        ]
        assert source.active_snapshot_id is None
        assert asset.url_retention_complete is False
        assert asset.identifier == report_snapshot["url"]
        assert report.snapshot_json == report_snapshot
        assert report.content == report_bytes
        assert report.sha256 == hashlib.sha256(report_bytes).hexdigest()
    command.check(config)
    engine.dispose()
