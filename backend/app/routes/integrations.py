from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.cpe import cpe_inventory_mismatch, demo_cpe_name
from app.config import get_settings
from app.database import get_db
from app.dependencies import get_current_user, require_roles_csrf
from app.models import AuditEvent, SoftwareComponent, ThreatFeedSource, User, now_utc
from app.schemas import CinsArmyStatusOut, OpenPhishStatusOut, SpamhausDropStatusOut, ThreatFeedRefreshQueuedOut
from app.services.threat_feeds import (
    CINS_SOURCE_ID,
    OPENPHISH_SOURCE_ID,
    ThreatFeedCooldown,
    ThreatFeedError,
    queue_refresh,
    cins_army_status_payload,
    openphish_status_payload,
    spamhaus_status_payload,
)
from app.openphish_access import openphish_configuration
from app.collectors.nvd import search_cpes, search_cve_page
from app.collectors.demo import demo_result
from app.visibility import visible_row
from app.models import Asset

router = APIRouter(prefix="/integrations", tags=["integrations"])


@router.get("/status")
def integration_status(_user: User = Depends(get_current_user)) -> dict:
    settings = get_settings()
    openphish = openphish_configuration(settings)
    return {"mode": settings.app_mode, "demo_data": settings.app_mode == "demo", "integrations": [
        {"id": "dns_rdap", "name": "DNS and RDAP", "configured": True, "behavior": "Live public lookups" if settings.app_mode == "live" else "Synthetic fixtures"},
        {"id": "web_tls", "name": "Website and TLS", "configured": True, "behavior": "Authorized targets only" if settings.app_mode == "live" else "Synthetic fixtures"},
        {"id": "virustotal", "name": "VirusTotal", "configured": bool(settings.virustotal_api_key) if settings.app_mode == "live" else True, "behavior": "Existing reports only" if settings.app_mode == "live" else "Synthetic fixtures"},
        {"id": "hibp", "name": "Have I Been Pwned", "configured": bool(settings.hibp_api_key) if settings.app_mode == "live" else True, "behavior": "Account search key required" if settings.app_mode == "live" else "Synthetic fixtures"},
        {"id": "xposedornot", "name": "XposedOrNot community lookup",
         "configured": bool(settings.xposedornot_enabled and settings.xposedornot_community_use_ack and settings.xposedornot_cache_key) if settings.app_mode == "live" else True,
         "enabled": bool(settings.xposedornot_enabled and settings.xposedornot_community_use_ack),
         "behavior": "Explicit personal/low-volume use only; selected email is sent over HTTPS, shared limits apply, and coverage differs from HIBP" if settings.app_mode == "live" and settings.xposedornot_enabled else "Bundled synthetic fixture only; no network requests" if settings.app_mode == "demo" else "Disabled by operator; HIBP remains unchanged"},
        {"id": "nvd_kev", "name": "NVD and CISA KEV", "configured": True, "behavior": "Public APIs; NVD key optional" if settings.app_mode == "live" else "Synthetic fixtures"},
        {"id": "epss", "name": "FIRST EPSS", "configured": True, "behavior": "Public score lookup; no key required" if settings.app_mode == "live" else "Synthetic fixtures; no network requests"},
        {"id": "osv", "name": "OSV.dev package intelligence", "configured": True, "behavior": "Explicit npm/PyPI package versions; public lookup, no key required" if settings.app_mode == "live" else "Bundled synthetic package fixture; no network requests"},
        {"id": "spamhaus_drop", "name": "Spamhaus DROP snapshot", "configured": settings.app_mode == "demo" or settings.spamhaus_drop_enabled,
         "enabled": settings.app_mode == "live" and settings.spamhaus_drop_enabled,
         "behavior": "Local PostgreSQL IPv4/IPv6 snapshots; refreshed no more than daily" if settings.app_mode == "live" else "Synthetic local fixture; no network requests"},
        {"id": "cins_army", "name": "CINS Army IP snapshot", "configured": settings.app_mode == "demo" or settings.cins_army_enabled,
         "enabled": settings.app_mode == "live" and settings.cins_army_enabled,
         "behavior": "Local exact-IP snapshots from the public text list; CyberLens refresh interval defaults to 24 hours" if settings.app_mode == "live" else "Synthetic reserved-IP fixture; no network requests"},
        {"id": "openphish", "name": "OpenPhish Community URL feed",
         "configured": settings.app_mode == "demo" or bool(openphish["ready"]),
         "enabled": settings.app_mode == "live" and bool(openphish["ready"]),
         "state": openphish["state"], "access_scope": openphish["access_scope"],
         "terms_url": "https://www.openphish.com/terms.html",
         "behavior": ("Synthetic reserved-domain fixture; no network requests" if settings.app_mode == "demo" else
                      f"{openphish['reason']} CyberLens refresh interval defaults to 12 hours; matching is exact URL only, with hostname context excluded from risk.")},
    ]}


@router.get("/spamhaus-drop/status", response_model=SpamhausDropStatusOut)
def spamhaus_drop_status(_user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> dict:
    return spamhaus_status_payload(db)


@router.post("/spamhaus-drop/refresh", response_model=ThreatFeedRefreshQueuedOut, status_code=202)
def refresh_spamhaus_drop(user: User = Depends(require_roles_csrf("admin")),
                          db: Session = Depends(get_db)) -> dict:
    settings = get_settings()
    if settings.app_mode != "live":
        raise HTTPException(409, "Demo mode uses a local synthetic fixture and does not refresh provider data.")
    if not settings.spamhaus_drop_enabled:
        raise HTTPException(409, "Spamhaus DROP refresh is disabled by the operator.")
    try:
        attempt = queue_refresh(db, requested_by=user)
        db.commit()
    except ThreatFeedCooldown as exc:
        db.rollback()
        raise HTTPException(429, detail={"message": str(exc), "next_refresh_at": exc.next_refresh_at.isoformat()}) from exc
    return {
        "id": attempt.id, "status": attempt.status, "trigger_kind": attempt.trigger_kind,
        "requested_at": attempt.created_at,
        "next_refresh_at": db.get(ThreatFeedSource, "spamhaus_drop").next_refresh_at,
        "message": "Refresh queued. The current snapshot remains active until a complete replacement validates.",
    }


@router.get("/cins-army/status", response_model=CinsArmyStatusOut)
def cins_army_status(_user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> dict:
    return cins_army_status_payload(db)


@router.get("/openphish/status", response_model=OpenPhishStatusOut)
def openphish_status(_user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> dict:
    return openphish_status_payload(db)


@router.post("/openphish/refresh", response_model=ThreatFeedRefreshQueuedOut, status_code=202)
def refresh_openphish(user: User = Depends(require_roles_csrf("admin")),
                      db: Session = Depends(get_db)) -> dict:
    settings = get_settings()
    if settings.app_mode != "live":
        raise HTTPException(409, "Demo mode uses a local synthetic fixture and does not refresh provider data.")
    try:
        attempt = queue_refresh(db, requested_by=user, source_id=OPENPHISH_SOURCE_ID)
        db.commit()
    except ThreatFeedCooldown as exc:
        db.rollback()
        raise HTTPException(429, detail={"message": str(exc), "next_refresh_at": exc.next_refresh_at.isoformat()}) from exc
    except ThreatFeedError as exc:
        db.rollback()
        raise HTTPException(409, str(exc)) from exc
    source = db.get(ThreatFeedSource, OPENPHISH_SOURCE_ID)
    return {
        "id": attempt.id, "status": attempt.status, "trigger_kind": attempt.trigger_kind,
        "requested_at": attempt.created_at,
        "next_refresh_at": source.next_refresh_at if source else None,
        "message": "Refresh queued. The current snapshot remains active until a complete replacement validates.",
    }


@router.post("/cins-army/refresh", response_model=ThreatFeedRefreshQueuedOut, status_code=202)
def refresh_cins_army(user: User = Depends(require_roles_csrf("admin")),
                      db: Session = Depends(get_db)) -> dict:
    settings = get_settings()
    if settings.app_mode != "live":
        raise HTTPException(409, "Demo mode uses a local synthetic fixture and does not refresh provider data.")
    if not settings.cins_army_enabled:
        raise HTTPException(409, "CINS Army refresh is disabled by the operator.")
    try:
        attempt = queue_refresh(db, requested_by=user, source_id=CINS_SOURCE_ID)
        db.commit()
    except ThreatFeedCooldown as exc:
        db.rollback()
        raise HTTPException(429, detail={"message": str(exc), "next_refresh_at": exc.next_refresh_at.isoformat()}) from exc
    source = db.get(ThreatFeedSource, CINS_SOURCE_ID)
    return {
        "id": attempt.id, "status": attempt.status, "trigger_kind": attempt.trigger_kind,
        "requested_at": attempt.created_at,
        "next_refresh_at": source.next_refresh_at if source else None,
        "message": "Refresh queued. The active snapshot remains available until the complete feed validates.",
    }


@router.get("/nvd/cpes")
def cpe_search(keyword_search: str = Query(min_length=2, max_length=200), limit: int = Query(default=20, ge=1, le=100),
               start_index: int = Query(default=0, ge=0, le=10000),
               software_vendor: str | None = Query(default=None, max_length=200),
               software_product: str | None = Query(default=None, max_length=200),
               software_version: str | None = Query(default=None, max_length=100),
               _user: User = Depends(get_current_user)) -> dict:
    inventory = (software_vendor, software_product, software_version)
    if any(inventory) and not all(value and value.strip() for value in inventory):
        raise HTTPException(422, "Supply vendor, product, and version together to validate CPE candidates")
    if get_settings().app_mode == "demo":
        if all(inventory):
            cpe = demo_cpe_name(software_vendor or "", software_product or "", software_version or "")
            results = ([{"cpe_name": cpe, "title": f"{software_vendor} {software_product} {software_version} (synthetic)", "deprecated": False}]
                       if cpe else [])
            return {"demo_data": True, "total_results": len(results), "start_index": start_index,
                    "results_per_page": len(results), "results": results}
        return {"demo_data": True, "total_results": 1, "start_index": start_index, "results_per_page": 1,
            "results": [{"cpe_name": "cpe:2.3:a:example:sample_product:1.0:*:*:*:*:*:*:*", "title": "Example Sample Product 1.0 (synthetic)", "deprecated": False}]}
    try:
        page = search_cpes(keyword_search, limit, start_index)
        if all(inventory):
            page["results"] = [item for item in page["results"] if item.get("cpe_name") and
                                cpe_inventory_mismatch(item["cpe_name"], software_vendor or "",
                                                       software_product or "", software_version or "") is None]
            page["results_per_page"] = len(page["results"])
        return {"demo_data": False, **page}
    except Exception as exc:
        raise HTTPException(503, f"NVD CPE search is unavailable ({type(exc).__name__})") from exc


@router.get("/nvd/cves")
def cve_search(cpe_name: str = Query(min_length=13, max_length=1024), limit: int = Query(default=100, ge=1, le=100),
               start_index: int = Query(default=0, ge=0, le=10000), _user: User = Depends(get_current_user)) -> dict:
    if not cpe_name.startswith("cpe:2.3:"):
        raise HTTPException(422, "Select a CPE 2.3 identifier first")
    if get_settings().app_mode == "demo":
        asset = type("DemoAsset", (), {"kind": "application", "identifier": "Synthetic software inventory"})()
        fixture = demo_result(asset, "vulnerable_application", "nvd_kev")
        candidates = [item["details"] for item in fixture.findings]
        return {"demo_data": True, "total_results": len(candidates), "start_index": start_index,
            "results_per_page": limit, "results": candidates[start_index:start_index + limit]}
    try:
        return {"demo_data": False, **search_cve_page(cpe_name, limit, start_index)}
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(503, f"NVD CVE search is unavailable ({type(exc).__name__})") from exc


@router.put("/assets/{asset_id}/components/{component_id}/cpe")
def select_component_cpe(asset_id: str, component_id: str, cpe_name: str = Query(min_length=13, max_length=1024),
                         user: User = Depends(require_roles_csrf("admin", "analyst")), db: Session = Depends(get_db)) -> dict:
    if visible_row(db, Asset, asset_id) is None:
        raise HTTPException(404, "Asset not found")
    component = db.query(SoftwareComponent).filter_by(id=component_id, asset_id=asset_id).first()
    if component is None: raise HTTPException(404, "Software component not found")
    mismatch = cpe_inventory_mismatch(cpe_name, component.vendor, component.product, component.version)
    if mismatch:
        raise HTTPException(422, mismatch)
    previous_cpe = component.cpe_name
    component.cpe_name = cpe_name
    db.add(AuditEvent(actor_id=user.id, action="software_component.cpe_selected",
        entity_type="software_component", entity_id=component.id,
        details_json={"asset_id": asset_id, "previous_cpe_name": previous_cpe, "cpe_name": cpe_name,
                      "inventory": {"vendor": component.vendor, "product": component.product,
                                    "version": component.version}, "selected_at": now_utc().isoformat()}))
    db.commit()
    return {"id": component.id, "asset_id": component.asset_id, "vendor": component.vendor,
        "product": component.product, "version": component.version, "cpe_name": component.cpe_name,
        "package_ecosystem": component.package_ecosystem, "package_name": component.package_name}
