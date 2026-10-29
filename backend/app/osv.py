"""Stable API projection for OSV-backed vulnerability findings."""

from typing import Any


def osv_finding_payload(details: dict[str, Any] | None, evidence_id: str | None) -> dict[str, Any] | None:
    details = details or {}
    advisory_id = details.get("advisory_id")
    package = details.get("package")
    if not isinstance(advisory_id, str) or not isinstance(package, dict):
        return None
    return {
        "advisory_id": advisory_id,
        "aliases": details.get("aliases", []),
        "ecosystem": package.get("ecosystem"),
        "package_name": package.get("name"),
        "package_version": package.get("version"),
        "affected": details.get("affected", []),
        "fixed_versions": details.get("fixed_versions", []),
        "references": details.get("references", []),
        "severity_metadata": details.get("severity_metadata", []),
        "published": details.get("published"),
        "modified": details.get("modified"),
        "withdrawn": details.get("withdrawn"),
        "observed_at": details.get("observed_at"),
        "provider_status": details.get("provider_status", "unknown"),
        "freshness": details.get("freshness", "unknown"),
        "provider_version": details.get("provider_version", "unknown"),
        "advisory_status": details.get("advisory_status", "unknown"),
        "evidence_id": evidence_id,
    }
