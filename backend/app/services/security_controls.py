"""Small, locally maintained security-control catalog for analyst mapping."""

CATALOG_VERSION = "cyberlens-controls-1.0"

SECURITY_CONTROLS: tuple[dict, ...] = (
    {
        "id": "AC-6",
        "title": "Least privilege",
        "objective": "Limit access to the minimum privileges needed for assigned work.",
        "guidance": "Review privileged and service accounts, remove unnecessary access, and retain an approval record.",
        "frameworks": ["NIST SP 800-53 Rev. 5"],
        "finding_categories": ["identity", "access_control", "configuration"],
    },
    {
        "id": "CM-6",
        "title": "Configuration settings",
        "objective": "Establish and monitor secure configuration settings for systems and services.",
        "guidance": "Apply a documented baseline, record deviations, and verify the effective configuration.",
        "frameworks": ["NIST SP 800-53 Rev. 5", "CIS Controls v8"],
        "finding_categories": ["tls_web", "dns_email", "configuration"],
    },
    {
        "id": "SI-2",
        "title": "Flaw remediation",
        "objective": "Identify, report, and correct system flaws within defined timeframes.",
        "guidance": "Confirm applicability, test the vendor fix, deploy it through change control, and rescan.",
        "frameworks": ["NIST SP 800-53 Rev. 5", "CIS Controls v8"],
        "finding_categories": ["vulnerabilities", "software"],
    },
    {
        "id": "SC-8",
        "title": "Transmission confidentiality and integrity",
        "objective": "Protect the confidentiality and integrity of transmitted information.",
        "guidance": "Use valid certificates and approved TLS configuration, then verify the served endpoint.",
        "frameworks": ["NIST SP 800-53 Rev. 5"],
        "finding_categories": ["tls_web", "network"],
    },
    {
        "id": "SC-7",
        "title": "Boundary protection",
        "objective": "Monitor and control communications at external and key internal boundaries.",
        "guidance": "Review exposed services and reputation evidence, confirm ownership, and document containment decisions.",
        "frameworks": ["NIST SP 800-53 Rev. 5", "CIS Controls v8"],
        "finding_categories": ["reputation", "network", "exposure"],
    },
    {
        "id": "SI-4",
        "title": "System monitoring",
        "objective": "Monitor systems to detect attacks, indicators of compromise, and unauthorized use.",
        "guidance": "Correlate validated signals with local telemetry; an external reputation or breach match alone is not proof of compromise.",
        "frameworks": ["NIST SP 800-53 Rev. 5"],
        "finding_categories": ["reputation", "breach_exposure", "monitoring"],
    },
    {
        "id": "IA-5",
        "title": "Authenticator management",
        "objective": "Manage authenticators through their issuance, use, compromise, and revocation lifecycle.",
        "guidance": "Rotate exposed credentials, revoke compromised authenticators, and verify recovery with approved identity evidence.",
        "frameworks": ["NIST SP 800-53 Rev. 5"],
        "finding_categories": ["identity", "breach_exposure", "authentication"],
    },
    {
        "id": "CA-7",
        "title": "Continuous monitoring",
        "objective": "Maintain ongoing awareness of security posture and control effectiveness.",
        "guidance": "Schedule repeatable checks, track collector coverage, and distinguish missing observations from passing results.",
        "frameworks": ["NIST SP 800-53 Rev. 5"],
        "finding_categories": ["monitoring", "vulnerabilities", "tls_web", "dns_email"],
    },
)

_BY_ID = {control["id"]: control for control in SECURITY_CONTROLS}


def get_control(control_id: str, catalog_version: str = CATALOG_VERSION) -> dict | None:
    if catalog_version != CATALOG_VERSION:
        return None
    control = _BY_ID.get(control_id)
    if control is None:
        return None
    return {**control, "catalog_version": CATALOG_VERSION}


def control_catalog() -> list[dict]:
    return [{**control, "catalog_version": CATALOG_VERSION} for control in SECURITY_CONTROLS]
