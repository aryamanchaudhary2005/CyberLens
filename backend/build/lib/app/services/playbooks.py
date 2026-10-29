PLAYBOOK_VERSION = "1.0"

PLAYBOOKS = {
    "website_phishing": [
        ("validation", "Validate the website evidence", "Review the captured source evidence and confirm the suspicious behavior."),
        ("containment_planning", "Plan safe containment", "Document approved containment options and required owner authorization."),
        ("remediation", "Remediate the website issue", "Record hosting, DNS, certificate, or reputation remediation steps."),
        ("recovery_verification", "Verify recovery", "Recheck the authorized website and record validation evidence."),
        ("lessons_learned", "Capture lessons learned", "Document gaps, decisions, and follow-up actions."),
    ],
    "exposed_account": [
        ("validation", "Validate breach exposure", "Confirm the account belongs to the organization and assess exposed data categories."),
        ("containment_planning", "Plan account protection", "Record approved credential rotation and session revocation steps; no reset is performed here."),
        ("remediation", "Complete account remediation", "Document identity-provider actions and user notification decision."),
        ("recovery_verification", "Verify account recovery", "Confirm access controls and monitoring with the account owner."),
        ("lessons_learned", "Capture lessons learned", "Record preventive actions and ownership."),
    ],
    "vulnerable_application": [
        ("validation", "Confirm inventory applicability", "Review product, version, configuration, and the analyst applicability decision."),
        ("containment_planning", "Plan exposure reduction", "Document approved temporary mitigations and change constraints."),
        ("remediation", "Plan and apply an update", "Record the vendor fix or mitigation selected for the affected component."),
        ("recovery_verification", "Verify remediation", "Confirm installed version and repeat the vulnerability review."),
        ("lessons_learned", "Capture lessons learned", "Record patch process improvements and owners."),
    ],
    "website_configuration": [
        ("validation", "Validate configuration evidence", "Confirm the finding and affected website scope."),
        ("containment_planning", "Plan change controls", "Record approvals, owner, rollback, and maintenance window."),
        ("remediation", "Apply configuration changes", "Document the approved TLS, header, or DNS configuration change."),
        ("recovery_verification", "Verify configuration", "Repeat the authorized check and preserve the result."),
        ("lessons_learned", "Capture lessons learned", "Record standards and monitoring updates."),
    ],
}


def select_playbook(asset_kind: str, findings: list) -> str:
    categories = {finding.category for finding in findings}
    if asset_kind == "email" or "breach_exposure" in categories:
        return "exposed_account"
    if asset_kind == "application" or "vulnerabilities" in categories:
        return "vulnerable_application"
    if "reputation" in categories:
        return "website_phishing"
    return "website_configuration"
