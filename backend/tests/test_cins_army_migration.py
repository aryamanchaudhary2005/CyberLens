"""The CINS migration is additive and retains prior snapshot/report data."""

import hashlib
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import Session

from app.models import Asset, Investigation, Report, ThreatFeedNetwork, ThreatFeedSnapshot, ThreatFeedSource, User


def test_cins_migration_adds_indicator_kind_and_source_without_rewriting_reports(tmp_path, monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    root = Path(__file__).resolve().parents[2]
    config = Config(str(root / "backend" / "alembic.ini"))
    config.set_main_option("script_location", str(root / "backend" / "alembic"))
    database_path = tmp_path / "cins-army.db"
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database_path.as_posix()}")
    command.upgrade(config, "20261020_0017")
    engine = create_engine(f"sqlite:///{database_path.as_posix()}")

    legacy_snapshot_id = "module24-spamhaus-snapshot"
    with engine.begin() as connection:
        connection.execute(text(
            "INSERT INTO threat_feed_snapshots (id, source_id, content_sha256, parser_version, record_count, "
            "retrieved_at, published_at, metadata_json) VALUES "
            "(:id, 'spamhaus_drop', :digest, 'spamhaus-drop-jsonl-v1', 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, '{}')"
        ), {"id": legacy_snapshot_id, "digest": "a" * 64})
        connection.execute(text(
            "INSERT INTO threat_feed_networks (id, snapshot_id, address_family, network, sbl_id) "
            "VALUES ('module24-spamhaus-row', :snapshot_id, 4, '8.8.8.0/24', 'SBL-OLD')"
        ), {"snapshot_id": legacy_snapshot_id})
        connection.execute(text(
            "UPDATE threat_feed_sources SET active_snapshot_id = :snapshot_id WHERE id = 'spamhaus_drop'"
        ), {"snapshot_id": legacy_snapshot_id})

    report_bytes = b"immutable report before CINS source"
    with Session(engine) as db:
        user = User(username="module25", password_hash="unused", role="admin")
        db.add(user)
        db.flush()
        asset = Asset(kind="ip", identifier="8.8.8.8", normalized_identifier="8.8.8.8", created_by=user.id)
        db.add(asset)
        db.flush()
        investigation = Investigation(asset_id=asset.id, requested_by=user.id, mode="live", status="completed")
        db.add(investigation)
        db.flush()
        report = Report(
            id="module25-report", investigation_id=investigation.id, format="json", created_by=user.id,
            is_demo=False, snapshot_json={"finding": "existing"}, content=report_bytes,
            sha256=hashlib.sha256(report_bytes).hexdigest(),
        )
        db.add(report)
        db.commit()

    command.upgrade(config, "head")
    inspector = inspect(engine)
    columns = {item["name"]: item for item in inspector.get_columns("threat_feed_networks")}
    indexes = {item["name"] for item in inspector.get_indexes("threat_feed_networks")}
    assert columns["indicator_type"]["nullable"] is False
    assert "ix_threat_feed_networks_snapshot_indicator" in indexes
    with Session(engine) as db:
        cins = db.get(ThreatFeedSource, "cins_army")
        existing = db.get(ThreatFeedSource, "spamhaus_drop")
        old_snapshot = db.get(ThreatFeedSnapshot, legacy_snapshot_id)
        old_row = db.get(ThreatFeedNetwork, "module24-spamhaus-row")
        report = db.get(Report, "module25-report")
        assert cins.source_urls_json == ["https://cinsscore.com/list/ci-badguys.txt"]
        assert cins.active_snapshot_id is None
        assert existing is not None and existing.active_snapshot_id == legacy_snapshot_id
        assert old_snapshot.record_count == 1 and old_row.network == "8.8.8.0/24"
        assert old_row.sbl_id == "SBL-OLD" and old_row.indicator_type == "network"
        assert report.content == report_bytes
        assert report.sha256 == hashlib.sha256(report_bytes).hexdigest()
    command.check(config)
    engine.dispose()
