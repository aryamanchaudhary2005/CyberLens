import ipaddress
import re
from datetime import timedelta

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.database import get_db
from app.cpe import cpe_inventory_mismatch
from app.authorization import active_website_authorization
from app.dependencies import get_current_user, require_roles_csrf
from app.models import Asset, AuditEvent, EmailBreachAuthorization, SoftwareComponent, User, WebsiteAuthorization, new_id, now_utc
from app.pagination import Page, apply_page, page_params
from app.schemas import AssetCreate, AssetOut, AssetUpdate, AuthorizationInput, ComponentCreate, URLRetentionConfirmation, WebsiteAuthorizationOut
from app.url_normalization import canonicalize_http_url, normalize_domain_name
from app.visibility import visible_assets, visible_row

router = APIRouter(prefix="/assets", tags=["assets"])


def normalize_asset(kind: str, value: str) -> tuple[str, str]:
    value = value.strip()
    if kind == "domain":
        try:
            domain = normalize_domain_name(value)
        except ValueError as exc:
            raise HTTPException(422, "Enter a valid domain name") from exc
        return domain, domain
    if kind == "ip":
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise HTTPException(422, "Enter a valid IPv4 or IPv6 address") from exc
        return address.compressed, address.compressed
    if kind == "url":
        try:
            safe_url, _hostname = canonicalize_http_url(value)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        # Only scheme and hostname are case-insensitive. Resource components
        # remain byte-for-byte represented, including queries and fragments.
        return safe_url, safe_url
    if kind == "email":
        if value.count("@") != 1:
            raise HTTPException(422, "Enter a valid email address")
        local, domain = value.rsplit("@", 1)
        try:
            domain = normalize_domain_name(domain)
        except ValueError as exc:
            raise HTTPException(422, "Enter a valid email address") from exc
        if "." not in domain or len(local) > 64 or not local or not re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+", local):
            raise HTTPException(422, "Enter a valid email address")
        normalized = f"{local.lower()}@{domain}"
        return normalized, normalized
    cleaned = re.sub(r"\s+", " ", value)
    if not cleaned:
        raise HTTPException(422, "Application name cannot be empty")
    return cleaned, cleaned.casefold()


@router.get("", response_model=list[AssetOut])
def list_assets(
    _user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    response: Response = None,
    kind: str | None = Query(default=None),
    q: str | None = Query(default=None, max_length=200),
    sort: Literal["updated_at", "created_at", "identifier", "kind"] = Query(default="updated_at"),
    order: Literal["asc", "desc"] = Query(default="desc"),
    page: Page = Depends(page_params),
) -> list[dict]:
    query = visible_assets(db)
    if kind:
        query = query.filter(Asset.kind == kind)
    if q:
        query = query.filter(Asset.normalized_identifier.contains(q.strip().lower()))
    sort_column = {"updated_at": Asset.updated_at, "created_at": Asset.created_at,
                   "identifier": Asset.normalized_identifier, "kind": Asset.kind}[sort]
    ordering = sort_column.asc() if order == "asc" else sort_column.desc()
    query = query.order_by(ordering, Asset.id.asc())
    rows = apply_page(query, page, response)
    ids = [asset.id for asset in rows]
    authorizations = {}
    email_authorizations = {}
    if ids:
        for authorization in (db.query(WebsiteAuthorization)
                               .filter(WebsiteAuthorization.asset_id.in_(ids), WebsiteAuthorization.revoked_at.is_(None),
                                       WebsiteAuthorization.expires_at > now_utc())
                               .order_by(WebsiteAuthorization.created_at.desc(), WebsiteAuthorization.id.desc()).all()):
            authorizations.setdefault(authorization.asset_id, authorization)
        for authorization in (db.query(EmailBreachAuthorization)
                               .filter(EmailBreachAuthorization.asset_id.in_(ids), EmailBreachAuthorization.revoked_at.is_(None),
                                       EmailBreachAuthorization.expires_at > now_utc())
                               .order_by(EmailBreachAuthorization.created_at.desc(), EmailBreachAuthorization.id.desc()).all()):
            email_authorizations.setdefault(authorization.asset_id, authorization)
    components: dict[str, list[SoftwareComponent]] = {asset_id: [] for asset_id in ids}
    if ids:
        for component in db.query(SoftwareComponent).filter(SoftwareComponent.asset_id.in_(ids)).all():
            components.setdefault(component.asset_id, []).append(component)
    return [_asset_payload(asset, db, authorization=authorizations.get(asset.id),
                            email_authorization=email_authorizations.get(asset.id), email_authorization_loaded=True,
                            components=components.get(asset.id, [])) for asset in rows]


@router.post("", status_code=201, response_model=AssetOut)
def create_asset(payload: AssetCreate, user: User = Depends(require_roles_csrf("admin", "analyst")), db: Session = Depends(get_db)) -> dict:
    identifier, normalized = normalize_asset(payload.kind, payload.identifier)
    asset = Asset(kind=payload.kind, identifier=identifier, normalized_identifier=normalized,
                  url_retention_complete=payload.kind == "url", notes=payload.notes.strip(), created_by=user.id)
    db.add(asset)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409, "This asset is already registered") from exc
    db.add(AuditEvent(actor_id=user.id, action="asset.created", entity_type="asset", entity_id=asset.id,
                      details_json={"kind": asset.kind}))
    db.commit()
    db.refresh(asset)
    return _asset_payload(asset, db)


@router.get("/{asset_id}", response_model=AssetOut)
def get_asset(asset_id: str, _user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> dict:
    asset = visible_row(db, Asset, asset_id)
    if asset is None:
        raise HTTPException(404, "Asset not found")
    return _asset_payload(asset, db)


@router.patch("/{asset_id}", response_model=AssetOut)
def update_asset(asset_id: str, payload: AssetUpdate, user: User = Depends(require_roles_csrf("admin", "analyst")), db: Session = Depends(get_db)) -> dict:
    asset = visible_row(db, Asset, asset_id)
    if asset is None:
        raise HTTPException(404, "Asset not found")
    asset.notes = payload.notes.strip()
    asset.updated_at = now_utc()
    db.add(AuditEvent(actor_id=user.id, action="asset.updated", entity_type="asset", entity_id=asset.id))
    db.commit()
    return _asset_payload(asset, db)


@router.post("/{asset_id}/url-retention-confirmation", response_model=AssetOut)
def confirm_complete_url(asset_id: str, payload: URLRetentionConfirmation,
                        user: User = Depends(require_roles_csrf("admin", "analyst")),
                        db: Session = Depends(get_db)) -> dict:
    asset = visible_row(db, Asset, asset_id)
    if asset is None:
        raise HTTPException(404, "Asset not found")
    if asset.kind != "url":
        raise HTTPException(409, "Only URL assets can confirm complete URL retention")
    identifier, normalized = normalize_asset("url", payload.identifier)
    saved_identifier, _saved_key = normalize_asset("url", asset.identifier)
    if identifier != saved_identifier:
        raise HTTPException(
            409,
            "The entered URL differs from the saved URL. Register it as a separate asset to retain its exact path, query, and fragment.",
        )
    if asset.url_retention_complete:
        return _asset_payload(asset, db)
    asset.identifier = identifier
    asset.normalized_identifier = normalized
    asset.url_retention_complete = True
    asset.updated_at = now_utc()
    db.add(AuditEvent(actor_id=user.id, action="asset.url_retention_confirmed", entity_type="asset",
                      entity_id=asset.id, details_json={"confirmation": "exact_url_components_reviewed"}))
    db.commit()
    return _asset_payload(asset, db)


@router.post("/{asset_id}/authorization", response_model=AssetOut)
def confirm_authorization(
    asset_id: str,
    payload: AuthorizationInput,
    user: User = Depends(require_roles_csrf("admin", "analyst")),
    db: Session = Depends(get_db),
) -> dict:
    asset = visible_row(db, Asset, asset_id)
    if asset is None:
        raise HTTPException(404, "Asset not found")
    if asset.kind not in {"domain", "url"}:
        raise HTTPException(422, "Authorization records are for website assets")
    created_at = now_utc()
    for previous in (
        db.query(WebsiteAuthorization)
        .filter(
            WebsiteAuthorization.asset_id == asset.id,
            WebsiteAuthorization.revoked_at.is_(None),
            WebsiteAuthorization.expires_at > created_at,
        )
        .all()
    ):
        previous.revoked_at = created_at
        previous.revoked_by = user.id
        db.add(AuditEvent(actor_id=user.id, action="website_authorization.revoked", entity_type="website_authorization",
                          entity_id=previous.id, details_json={"asset_id": asset.id, "reason": "superseded"}))
    authorization = WebsiteAuthorization(
        id=new_id(),
        asset_id=asset.id,
        authorized_by=user.id,
        note=payload.note.strip(),
        created_at=created_at,
        expires_at=created_at + timedelta(days=payload.expires_in_days),
    )
    db.add(authorization)
    asset.authorized_at = created_at
    asset.authorization_note = authorization.note
    db.add(AuditEvent(actor_id=user.id, action="website_authorization.granted", entity_type="website_authorization",
                      entity_id=authorization.id, details_json={"asset_id": asset.id,
                      "expires_at": authorization.expires_at.isoformat()}))
    db.commit()
    return _asset_payload(asset, db)


@router.get("/{asset_id}/authorizations", response_model=list[WebsiteAuthorizationOut])
def list_authorizations(
    asset_id: str,
    _user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[WebsiteAuthorization]:
    if visible_row(db, Asset, asset_id) is None:
        raise HTTPException(404, "Asset not found")
    return db.query(WebsiteAuthorization).filter_by(asset_id=asset_id).order_by(WebsiteAuthorization.created_at.desc()).all()


@router.delete("/{asset_id}/authorization", response_model=AssetOut)
def revoke_authorization(
    asset_id: str,
    user: User = Depends(require_roles_csrf("admin", "analyst")),
    db: Session = Depends(get_db),
) -> dict:
    asset = visible_row(db, Asset, asset_id)
    if asset is None:
        raise HTTPException(404, "Asset not found")
    authorization = active_website_authorization(db, asset.id)
    if authorization is None:
        raise HTTPException(409, "No active website authorization to revoke")
    authorization.revoked_at = now_utc()
    authorization.revoked_by = user.id
    db.add(AuditEvent(actor_id=user.id, action="website_authorization.revoked", entity_type="website_authorization",
                      entity_id=authorization.id, details_json={"asset_id": asset.id, "reason": "revoked_by_user"}))
    db.commit()
    return _asset_payload(asset, db)


@router.delete("/{asset_id}/email-breach-authorization", response_model=AssetOut)
def revoke_email_breach_authorization(
    asset_id: str,
    user: User = Depends(require_roles_csrf("admin", "analyst")),
    db: Session = Depends(get_db),
) -> dict:
    asset = visible_row(db, Asset, asset_id)
    if asset is None:
        raise HTTPException(404, "Asset not found")
    if asset.kind != "email":
        raise HTTPException(422, "Third-party email breach authorization applies only to an email asset")
    authorization = (db.query(EmailBreachAuthorization)
                     .filter(EmailBreachAuthorization.asset_id == asset.id,
                             EmailBreachAuthorization.provider == "xposedornot",
                             EmailBreachAuthorization.revoked_at.is_(None),
                             EmailBreachAuthorization.expires_at > now_utc())
                     .order_by(EmailBreachAuthorization.created_at.desc()).first())
    if authorization is None:
        raise HTTPException(409, "No active XposedOrNot authorization to revoke")
    authorization.revoked_at = now_utc()
    authorization.revoked_by = user.id
    db.add(AuditEvent(actor_id=user.id, action="email_breach.authorization_revoked",
        entity_type="email_breach_authorization", entity_id=authorization.id,
        details_json={"provider": "xposedornot", "outcome": "revoked", "reason": "revoked_by_user"}))
    db.commit()
    return _asset_payload(asset, db)


@router.get("/{asset_id}/components")
def list_components(asset_id: str, _user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> list[dict]:
    if visible_row(db, Asset, asset_id) is None:
        raise HTTPException(404, "Asset not found")
    return [_component_payload(component) for component in db.query(SoftwareComponent).filter_by(asset_id=asset_id).all()]


@router.post("/{asset_id}/components", status_code=201)
def add_component(
    asset_id: str,
    payload: ComponentCreate,
    user: User = Depends(require_roles_csrf("admin", "analyst")),
    db: Session = Depends(get_db),
) -> dict:
    asset = visible_row(db, Asset, asset_id)
    if asset is None:
        raise HTTPException(404, "Asset not found")
    if asset.kind != "application":
        raise HTTPException(422, "Software components can only be added to application assets")
    if payload.cpe_name:
        mismatch = cpe_inventory_mismatch(payload.cpe_name, payload.vendor, payload.product, payload.version)
        if mismatch:
            raise HTTPException(422, mismatch)
    component = SoftwareComponent(asset_id=asset.id, vendor=payload.vendor.strip(), product=payload.product.strip(),
                                  version=payload.version.strip(), cpe_name=payload.cpe_name,
                                  package_ecosystem=payload.package_ecosystem, package_name=payload.package_name)
    db.add(component)
    db.flush()
    db.add(AuditEvent(actor_id=user.id, action="software_component.created", entity_type="software_component",
        entity_id=component.id, details_json={"asset_id": asset.id, "vendor": component.vendor,
        "product": component.product, "version": component.version, "cpe_name": component.cpe_name,
        "package_ecosystem": component.package_ecosystem, "package_name": component.package_name}))
    db.commit()
    return _component_payload(component)


@router.delete("/{asset_id}/components/{component_id}", status_code=204)
def remove_component(asset_id: str, component_id: str, _user: User = Depends(require_roles_csrf("admin", "analyst")), db: Session = Depends(get_db)) -> None:
    if visible_row(db, Asset, asset_id) is None:
        raise HTTPException(404, "Asset not found")
    component = db.query(SoftwareComponent).filter_by(id=component_id, asset_id=asset_id).first()
    if component is None:
        raise HTTPException(404, "Software component not found")
    db.delete(component)
    db.commit()


def _component_payload(component: SoftwareComponent) -> dict:
    return {"id": component.id, "asset_id": component.asset_id, "vendor": component.vendor,
            "product": component.product, "version": component.version, "cpe_name": component.cpe_name,
            "package_ecosystem": component.package_ecosystem, "package_name": component.package_name,
            "created_at": component.created_at}


def _asset_payload(asset: Asset, db: Session, *, authorization=None, email_authorization=None,
                   email_authorization_loaded: bool = False,
                   components: list[SoftwareComponent] | None = None) -> dict:
    if authorization is None:
        authorization = active_website_authorization(db, asset.id)
    if email_authorization is None and not email_authorization_loaded:
        email_authorization = (db.query(EmailBreachAuthorization)
            .filter(EmailBreachAuthorization.asset_id == asset.id,
                    EmailBreachAuthorization.provider == "xposedornot",
                    EmailBreachAuthorization.revoked_at.is_(None), EmailBreachAuthorization.expires_at > now_utc())
            .order_by(EmailBreachAuthorization.created_at.desc()).first())
    if components is None:
        components = db.query(SoftwareComponent).filter_by(asset_id=asset.id).all()
    return {
        "id": asset.id, "kind": asset.kind, "identifier": asset.identifier,
        "url_retention_complete": asset.url_retention_complete, "notes": asset.notes,
        "criticality": asset.criticality, "data_classification": asset.data_classification,
        "trust_zone": asset.trust_zone, "exposure_classification": asset.exposure_classification,
        "business_owner": asset.business_owner, "protection_requirements": asset.protection_requirements or [],
        "authorized_at": authorization.created_at if authorization else None,
        "authorization_note": authorization.note if authorization else None,
        "authorization_id": authorization.id if authorization else None,
        "authorization_expires_at": authorization.expires_at if authorization else None,
        "email_breach_authorization_id": email_authorization.id if email_authorization else None,
        "email_breach_authorization_expires_at": email_authorization.expires_at if email_authorization else None,
        "created_at": asset.created_at, "updated_at": asset.updated_at,
        "components": [_component_payload(item) for item in components],
    }
