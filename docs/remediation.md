# Remediation plans and control mappings

CyberLens remediation records track analyst intent and verification. They are additive operational records and do not edit the source finding, evidence, risk assessment, incident history, or an existing report snapshot.

## Workflow records

A plan can be linked to a finding, an incident, and a versioned playbook task. It records a title, description, action type, owner, priority, due date, status, assumptions, notes, creator, and timestamps. Each plan can have multiple actions; actions additionally carry verification instructions and an optional saved verification-evidence reference. Plan and action states are `proposed`, `planned`, `implemented`, `validated`, `rejected`, and `not_applicable`.

Analysts and Admins can create or update plans, actions, and control mappings. Viewers can read them. Updates emit an audit event. There is no hard-delete API; rejected and not-applicable statuses preserve the decision trail.

## Local control catalog

`cyberlens-controls-1.0` is a small versioned catalog maintained in `backend/app/services/security_controls.py`. It includes practical guidance for least privilege, configuration, flaw remediation, transmission protection, boundary protection, system monitoring, authenticator management, and continuous monitoring. Control identifiers include their familiar NIST SP 800-53 Rev. 5 names; selected controls also include CIS Controls v8 as a reference. The catalog is a convenience for consistent analyst mapping, not a complete framework implementation, certification, or compliance assessment.

A mapping stores the catalog version, control identifier, analyst-entered rationale, confidence from 0 to 1, status, and optional verification evidence. The selected control is not inferred or applied automatically based only on finding category.

## Verification evidence

An action or finding-control mapping cannot be marked `validated` without a saved `EvidenceSnapshot` from the linked finding's investigation. If the plan has no finding, it needs an incident with an investigation, and the evidence must belong to that investigation. API validation checks the evidence foreign key and investigation association. The evidence reference records what the analyst used; it does not by itself prove that a production change succeeded or that a control is broadly effective. Verification instructions and notes should describe the independent check performed.

The UI exposes evidence snapshots for the plan's investigation. Demo evidence remains clearly synthetic. Live verification must rely on the evidence and follow-up investigation appropriate to the change.

## Reports and scoring

New investigation and incident JSON/PDF reports include the plan/action state, control mappings, catalog version, and validation evidence references that existed at report generation time. Saved reports remain immutable. Remediation records are excluded from risk scoring and cannot change finding applicability. Run a new investigation to observe and assess a real remediation outcome.

## API

See [API documentation](api.md#remediation-plans-and-control-mapping) for list filters, payload routes, role restrictions, and validation behavior. Schema changes use the additive forward-only Alembic revision `20261017_0009`.
