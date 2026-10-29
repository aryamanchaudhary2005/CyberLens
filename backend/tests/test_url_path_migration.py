from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.models import Asset, User
from app.routes.assets import normalize_asset


def test_forward_migration_restores_case_sensitive_url_keys(tmp_path, monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    project_root = Path(__file__).resolve().parents[2]
    config = Config(str(project_root / "backend" / "alembic.ini"))
    database_path = tmp_path / "url-path-canonicalization.db"
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database_path.as_posix()}")
    command.upgrade(config, "20261016_0004")
    engine = create_engine(f"sqlite:///{database_path.as_posix()}")
    with Session(engine) as db:
        user = User(username="url-migration-admin", password_hash="test", role="admin")
        db.add(user)
        db.flush()
        asset = Asset(kind="url", identifier="https://example.test/Admin/Case",
                      normalized_identifier="https://example.test/admin/case", created_by=user.id)
        db.add(asset)
        db.commit()
        asset_id = asset.id
    engine.dispose()

    command.upgrade(config, "head")
    migrated_engine = create_engine(f"sqlite:///{database_path.as_posix()}")
    with Session(migrated_engine) as db:
        migrated = db.get(Asset, asset_id)
        assert migrated.normalized_identifier == migrated.identifier
        alternate, alternate_key = normalize_asset("url", "https://example.test/admin/case")
        db.add(Asset(kind="url", identifier=alternate, normalized_identifier=alternate_key,
                     created_by=migrated.created_by))
        db.commit()
        assert db.query(Asset).filter_by(kind="url").count() == 2
    migrated_engine.dispose()
