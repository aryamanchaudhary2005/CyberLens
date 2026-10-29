from pathlib import Path
import os

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text


def test_threat_model_migration_adds_context_and_preserves_existing_asset(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    root = Path(__file__).resolve().parents[2]
    config = Config(str(root / "backend" / "alembic.ini"))
    path = Path(__file__).parent / f".threat-model-migration-{os.getpid()}.db"
    if path.exists():
        raise RuntimeError("Refusing to overwrite a pre-existing threat model migration test database")
    config.set_main_option("sqlalchemy.url", f"sqlite:///{path.as_posix()}")
    engine = None
    try:
        command.upgrade(config, "20261017_0009")
        engine = create_engine(f"sqlite:///{path.as_posix()}")
        with engine.begin() as connection:
            connection.execute(text("DROP TABLE threat_scenarios"))
            for column in ("criticality", "data_classification", "trust_zone", "exposure_classification", "business_owner", "protection_requirements"):
                connection.execute(text(f"ALTER TABLE assets DROP COLUMN {column}"))
            connection.execute(text("INSERT INTO users (id, username, password_hash, role, is_active, must_change_password, created_at) VALUES ('user-1', 'legacy-admin', 'unused', 'admin', 1, 0, '2026-01-01T00:00:00')"))
            connection.execute(text("INSERT INTO assets (id, kind, identifier, normalized_identifier, notes, is_synthetic, created_by, created_at, updated_at) VALUES ('asset-1', 'domain', 'legacy.example.test', 'legacy.example.test', 'existing note', 0, 'user-1', '2026-01-01T00:00:00', '2026-01-01T00:00:00')"))
        engine.dispose()

        command.upgrade(config, "20261017_0010")
        engine = create_engine(f"sqlite:///{path.as_posix()}")
        try:
            inspector = inspect(engine)
            asset_columns = {column["name"] for column in inspector.get_columns("assets")}
            assert {"criticality", "data_classification", "trust_zone", "exposure_classification", "business_owner", "protection_requirements"} <= asset_columns
            assert "threat_scenarios" in inspector.get_table_names()
            with engine.connect() as connection:
                asset = connection.execute(text("SELECT identifier, notes, criticality, data_classification, trust_zone, exposure_classification, business_owner, protection_requirements FROM assets WHERE id='asset-1'")).one()
                assert tuple(asset[:6]) == ("legacy.example.test", "existing note", "unknown", "unknown", "unknown", "unknown")
                assert asset[6] is None and asset[7] == "[]"
            foreign_keys = {tuple(item["constrained_columns"]) for item in inspector.get_foreign_keys("threat_scenarios")}
            assert {("asset_id",), ("finding_id",), ("investigation_id",), ("incident_id",)} <= foreign_keys
        finally:
            engine.dispose()
        command.upgrade(config, "head")
        command.check(config)
    finally:
        if engine is not None:
            engine.dispose()
        if path.exists() and path.parent.resolve() == Path(__file__).parent.resolve():
            path.unlink()
