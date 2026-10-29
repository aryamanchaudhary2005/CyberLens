"""Forward-only OSV inventory migration preserves existing CPE/report data."""

import hashlib
from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import Session

from app.models import Asset, Investigation, Report, SoftwareComponent, User, new_id


def test_osv_package_fields_upgrade_without_rewriting_cpe_inventory_or_reports(tmp_path, monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    root = Path(__file__).resolve().parents[2]
    config = Config(str(root / "backend" / "alembic.ini"))
    config.set_main_option("script_location", str(root / "backend" / "alembic"))
    database_path = tmp_path / "osv-inventory.db"
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database_path.as_posix()}")
    command.upgrade(config, "20261017_0013")
    engine = create_engine(f"sqlite:///{database_path.as_posix()}")

    content = b"immutable saved report before package inventory migration"
    with Session(engine) as db:
        user = User(username="osv-migration-user", password_hash="unused", role="admin")
        db.add(user)
        db.flush()
        asset = Asset(kind="application", identifier="Existing CPE app", normalized_identifier="existing-cpe-app",
                      created_by=user.id)
        db.add(asset)
        db.flush()
        component = SoftwareComponent(asset_id=asset.id, vendor="Apache", product="HTTP Server", version="2.4.49",
            cpe_name="cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")
        db.add(component)
        db.flush()
        investigation = Investigation(asset_id=asset.id, requested_by=user.id, mode="live", status="completed")
        db.add(investigation)
        db.flush()
        report = Report(id=new_id(), investigation_id=investigation.id, format="json", created_by=user.id,
            is_demo=False, snapshot_json={"findings": [{"source": "NVD"}]}, content=content,
            sha256=hashlib.sha256(content).hexdigest())
        db.add(report)
        db.commit()
        component_id, report_id = component.id, report.id

    # The initial historical metadata migration is metadata-driven in this
    # repository. Recreate the actual pre-Module-19 component table shape so
    # this checks the additive upgrade path used by already-running installs.
    with engine.begin() as connection:
        operations = Operations(MigrationContext.configure(connection))
        with operations.batch_alter_table("software_components", recreate="always") as batch:
            batch.drop_constraint("ck_software_component_package_identity", type_="check")
            batch.drop_column("package_ecosystem")
            batch.drop_column("package_name")

    command.upgrade(config, "head")
    component_columns = {item["name"] for item in inspect(engine).get_columns("software_components")}
    assert {"package_ecosystem", "package_name"} <= component_columns
    assert "ck_software_component_package_identity" in {
        item["name"] for item in inspect(engine).get_check_constraints("software_components")
    }
    with Session(engine) as db:
        component = db.get(SoftwareComponent, component_id)
        report = db.get(Report, report_id)
        assert (component.vendor, component.product, component.version) == ("Apache", "HTTP Server", "2.4.49")
        assert component.cpe_name == "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
        assert component.package_ecosystem is None and component.package_name is None
        assert report.snapshot_json == {"findings": [{"source": "NVD"}]}
        assert report.content == content and report.sha256 == hashlib.sha256(content).hexdigest()
    command.check(config)
    engine.dispose()
