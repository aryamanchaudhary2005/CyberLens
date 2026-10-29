from datetime import datetime, timedelta, timezone
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import Session

from app.database import Base
from app.models import Asset, WebsiteAuthorization, User, now_utc


def test_forward_migration_backfills_existing_asset_authorizations(tmp_path, monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    project_root = Path(__file__).resolve().parents[2]
    config = Config(str(project_root / "backend" / "alembic.ini"))
    database_path = tmp_path / "legacy-auth.db"
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database_path.as_posix()}")
    command.upgrade(config, "20261011_0002")
    engine = create_engine(f"sqlite:///{database_path.as_posix()}")

    with Session(engine) as db:
        user = User(username="migration-admin", password_hash="test", role="admin")
        db.add(user)
        db.flush()
        authorized_at = datetime(2025, 1, 2, tzinfo=timezone.utc)
        asset = Asset(kind="domain", identifier="legacy.example.test", normalized_identifier="legacy.example.test",
                      authorized_at=authorized_at, authorization_note="Existing written approval", created_by=user.id)
        db.add(asset)
        db.commit()
        asset_id = asset.id

    # A database stamped at the old head predates the new table; this exercises
    # the upgrade path used by existing workspaces, not only clean creation.
    Base.metadata.tables["website_authorizations"].drop(engine)
    assert "website_authorizations" not in inspect(engine).get_table_names()
    command.upgrade(config, "head")

    with Session(engine) as db:
        migrated = db.query(WebsiteAuthorization).filter_by(asset_id=asset_id).one()
        assert migrated.note == "Existing written approval"
        assert migrated.created_at.replace(tzinfo=timezone.utc) == authorized_at
        assert now_utc() < migrated.expires_at.replace(tzinfo=timezone.utc) <= now_utc() + timedelta(days=31)
        assert migrated.revoked_at is None

    command.check(config)

    engine.dispose()
