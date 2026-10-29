"""The XposedOrNot authorization schema is additive and forward-only."""

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect


def test_xposedornot_migration_adds_scoped_authorization_and_provider_fields(tmp_path, monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    root = Path(__file__).resolve().parents[2]
    config = Config(str(root / "backend" / "alembic.ini"))
    config.set_main_option("script_location", str(root / "backend" / "alembic"))
    database = tmp_path / "xon-upgrade.db"
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database.as_posix()}")
    command.upgrade(config, "head")
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    try:
        inspector = inspect(engine)
        assert "email_breach_authorizations" in inspector.get_table_names()
        auth_columns = {item["name"] for item in inspector.get_columns("email_breach_authorizations")}
        assert {"asset_id", "provider", "authorized_by", "consent_version", "expires_at", "revoked_at", "revoked_by"} <= auth_columns
        investigation_columns = {item["name"] for item in inspector.get_columns("investigations")}
        assert {"email_breach_provider", "email_breach_authorization_id"} <= investigation_columns
        assert any(item["name"] == "ix_email_breach_authorizations_asset_active"
                   for item in inspector.get_indexes("email_breach_authorizations"))
        command.check(config)
    finally:
        engine.dispose()
