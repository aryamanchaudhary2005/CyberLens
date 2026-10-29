import copy
import zlib

from reportlab.pdfbase.pdfutils import asciiBase85Decode
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import get_settings
from app.database import Base
from app.models import Report, User
from app.routes.reports import _json_bytes, _pdf_bytes, download_report


def test_new_report_pdf_has_local_light_background_brand_header_without_mutating_snapshot():
    snapshot = {
        "report_type": "investigation",
        "created_at": "2026-10-21T08:00:00+00:00",
        "scope": {"kind": "domain", "identifier": "brand.example.test"},
        "findings": [],
        "evidence": [],
    }
    saved_snapshot = copy.deepcopy(snapshot)
    saved_json = _json_bytes(snapshot)

    content = _pdf_bytes(snapshot)
    stream_marker = content.find(b"stream")
    stream_end = content.find(b"endstream", stream_marker)
    encoded_stream = content[stream_marker + len(b"stream"):stream_end].strip()
    pdf_text = zlib.decompress(asciiBase85Decode(encoded_stream))

    assert content.startswith(b"%PDF-")
    assert b"CyberLens" in pdf_text
    assert b"SECURITY ANALYSIS WORKSPACE" in pdf_text
    assert b"Investigation Report" in pdf_text
    assert snapshot == saved_snapshot
    assert _json_bytes(snapshot) == saved_json


def test_downloading_an_existing_report_returns_the_saved_bytes_unchanged(monkeypatch):
    monkeypatch.setenv("APP_MODE", "demo")
    get_settings.cache_clear()
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    db = factory()
    user = User(id="brand-admin", username="brand-admin", password_hash="test-hash", role="admin",
                must_change_password=False, is_active=True)
    saved_bytes = b"historically generated report bytes stay as saved"
    report = Report(id="old-report", investigation_id=None, incident_id=None, format="pdf",
                    created_by=user.id, is_demo=True, snapshot_json={"report_type": "investigation"},
                    content=saved_bytes, sha256="a" * 64)
    db.add_all([user, report])
    db.commit()

    response = download_report(report.id, user, db)

    assert response.body == saved_bytes
    db.refresh(report)
    assert report.content == saved_bytes
    assert report.snapshot_json == {"report_type": "investigation"}
    db.close()
    Base.metadata.drop_all(engine)
    engine.dispose()
