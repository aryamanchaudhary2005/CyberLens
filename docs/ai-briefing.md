# Optional evidence-grounded AI briefing

## Status: disabled

Module 9 is intentionally not enabled in this workspace. The local inspection found no `ollama`, `llama-server`, `llama-cli`, or `local-ai` executable or process. The backend virtual environment also has none of `ollama`, `llama_cpp`, `transformers`, `torch`, `openai`, or `anthropic` installed. The locked runtime dependencies contain no inference engine or model client, and the project has no configured local model endpoint or model artifact.

The project already depends on `httpx`, so it could technically send HTTP requests to a local model server without adding a Python client package. That alone is not a supported local model: this workspace has no managed inference runtime, reviewed model, resource limit, or tested request isolation. Adding or enabling a model server would create a new service boundary and dependency. Existing case material can contain registered email addresses, provider data, and free-form analyst notes, so sending that content to an unconfigured service would not meet the current privacy boundary. No model request, fallback, external AI call, or deterministic pseudo-AI briefing has been added.

## Current supported workflow

Investigation evidence and provenance stay in PostgreSQL `evidence_snapshots`; findings retain their evidence IDs; graph edges reference evidence snapshots; incident cases link selected findings and preserve evidence references in their timeline. Analysts can review the investigation comparison, findings, and incident timeline directly. These deterministic workflows remain available regardless of this disabled feature decision.

No case-brief endpoint, UI, persistence model, AI environment setting, prompt template, or external AI dependency is present. No AI-generated claims are saved, and no scoring, applicability, incident status, response task, or remediation state can be changed by an AI component.

## Requirements before enabling

Reconsider implementation only after the workspace has an operator-managed local inference runtime and a reviewed model with an explicit resource budget. Any future adapter must be opt-in and loopback-only, send only selected saved evidence/findings/comparisons/notes after secret and personal-data minimization, disable tools and network access, treat model text as untrusted, validate every claim against evidence IDs in the requested case, and label claims as supported, inferred, or unknown. It must return a draft for analyst review and must not write incident state, risk, applicability, tasks, remediation, or response actions. Adversarial injection, schema, privacy, no-runtime fallback, and human-reviewed evaluation fixtures must pass before the feature is enabled.

## Evaluation record

No model evaluation was run because no local model or inference runtime is available. There are no model outputs or quality claims to report.
