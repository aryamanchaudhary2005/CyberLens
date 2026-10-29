from datetime import datetime, timezone
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import DatabaseError
from sqlalchemy.orm import Session

from app.integrity import verify_audit_chain


def test_audit_chain_migration_backfills_history_and_installs_append_only_triggers(tmp_path, monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    root = Path(__file__).resolve().parents[2]
    database = tmp_path / "audit-integrity.db"
    url = f"sqlite:///{database.as_posix()}"
    config = Config(str(root / "backend" / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "20261017_0011")
    engine = create_engine(url)
    try:
        # Recreate the pre-Module-16 audit table shape to exercise the real
        # historical backfill even though the bootstrap migration snapshots
        # current ORM metadata for newly initialized workspaces.
        with engine.begin() as connection:
            connection.exec_driver_sql("DROP TABLE IF EXISTS audit_chain_heads")
            connection.exec_driver_sql("DROP TABLE audit_events")
            connection.exec_driver_sql("""CREATE TABLE audit_events (
                id VARCHAR(36) NOT NULL PRIMARY KEY,
                actor_id VARCHAR(36) NULL REFERENCES users(id) ON DELETE SET NULL,
                action VARCHAR(80) NOT NULL,
                entity_type VARCHAR(80) NOT NULL,
                entity_id VARCHAR(36) NOT NULL,
                details_json JSON NOT NULL,
                created_at DATETIME NOT NULL
            )""")
            connection.exec_driver_sql("CREATE INDEX ix_audit_events_action ON audit_events (action)")
            connection.execute(text("INSERT INTO audit_events (id, actor_id, action, entity_type, entity_id, details_json, created_at) VALUES (:id, NULL, :action, :entity_type, :entity_id, :metadata, :created_at)"), {
                "id": "legacy-event-1", "action": "auth.login", "entity_type": "user", "entity_id": "legacy-user",
                "metadata": '{"method":"password"}', "created_at": datetime(2026, 10, 1, tzinfo=timezone.utc),
            })

        command.upgrade(config, "head")
        columns = {item["name"] for item in inspect(engine).get_columns("audit_events")}
        assert {"event_sequence", "previous_hash", "current_hash"} <= columns
        with Session(engine) as db:
            result = verify_audit_chain(db)
            assert result["state"] == "verified"
            assert result["event_count"] == 1
            assert result["last_sequence"] == 1

        with pytest.raises(DatabaseError, match="append-only"):
            with engine.begin() as connection:
                connection.exec_driver_sql("UPDATE audit_events SET action='tampered' WHERE id='legacy-event-1'")
        with pytest.raises(DatabaseError, match="append-only"):
            with engine.begin() as connection:
                connection.exec_driver_sql("DELETE FROM audit_events WHERE id='legacy-event-1'")
    finally:
        engine.dispose()
