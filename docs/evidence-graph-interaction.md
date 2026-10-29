# Evidence graph interaction and chart behavior

The evidence graph is a client-side view of the existing PostgreSQL-backed graph projection. It does not change graph vocabulary, evidence records, scoring, permissions, or the accessible list alternative. Every displayed relationship continues to carry its evidence ID, provider/source, observation time, mode, role, and relationship details.

## Exploring the graph

- Zoom, reset, and fit controls operate on the SVG viewBox. The graph has pointer drag and arrow-button panning; keyboard users can focus the SVG and use arrow keys, plus/minus, and Home.
- Search only examines saved node labels and focuses the selected result. Node type, relationship type, and direct/contextual evidence-role filters are independent and report the number of records left in view.
- Selecting a node highlights its neighborhood. Selecting a relationship exposes its source, observation time, evidence ID/checksum when available, freshness, applicability, evidence role, mode, and saved relationship context.
- Asset, software, CVE, finding, incident, certificate, and workflow records use distinct SVG silhouettes and short symbols. Solid edges denote direct evidence; dashed edges denote contextual relationships. Text and the legend identify each role as well.
- The Evidence list view remains available for the same filtered nodes and evidence relationships and works with keyboard controls. External labels are inserted as text.
- Failed or unavailable collectors produce a partial-coverage message, not missing edges. The API returns the full saved projection; the current UI does not truncate graph data. A genuinely empty or unavailable projection has its own state. Large projections retain every returned node and edge but simplify their rendering.
- Poll refreshes reuse cached node positions and keep the SVG viewport, selected record, display mode, and filters in place for the current investigation. Comparison effects apply only to explicit new and changed classifications.

The node entrance uses opacity only so it cannot replace SVG node translations. Selection transitions highlight focus and neighbors; reduced-motion mode and large projections disable nonessential graph movement.

## Charts

The lazily loaded chart module uses the installed Recharts 2.15.4 API. Risk history keeps null scores as gaps and does not join observations across different or unknown policy versions. The posture trend API includes the saved policy versions represented by each period; mixed-policy and unknown-policy periods are isolated rather than connected to another period. Empty posture periods remain omitted per the API metric's scope description, never plotted as zero. The exact-value text and table remain available beside the charts.

Line, bar, and score-ring entrance animations run once per mount, use stable Recharts animation IDs, and follow both the application preference and system reduced-motion setting. Polling a mounted chart does not restart the animation. Bar tooltips and axes use saved-run counts; risk axes and tooltips use scores out of 100. Workflow nulls remain unavailable rather than becoming zero.

## Synthetic browser measurements

The graph test generates deterministic synthetic data only. It does not use production indicators or call external providers. One browser run was recorded on **2026-10-21 18:23:26 UTC** with:

- Node platform win32, x64 architecture
- Intel Core i7-13620H, 16 logical CPUs
- System-reported memory: 16,890,322,944 bytes
- Headless Chromium build 156.0.8078.4
- Browser viewport 1280 × 720; responsive captures were checked at widths 390, 768, and 1440

Render time measures from clicking graph refresh until the requested node and edge counts appear. Search time measures from starting a local label search until its matching result is visible. These are single-run UI interaction intervals under a local mocked API, not percentile latency or a production-device claim.

| Synthetic projection | Render interval | Search interval | Rendering profile |
| --- | ---: | ---: | --- |
| 20 nodes / 28 edges | 473.0 ms | 529.6 ms | Full |
| 120 nodes / 240 edges | 893.1 ms | 568.4 ms | Full |
| 400 nodes / 800 edges | 1,663.9 ms | 907.6 ms | Simplified |

The effect threshold is explicit: full entrance effects are used through 120 nodes and 240 edges; crossing either limit disables entrance motion and shortens labels. No graph data is removed. The tested upper bound is 400 nodes and 800 edges; larger projections have not been measured and are not claimed to be supported at the same responsiveness.

## Validation and captures

- Backend command .venv/Scripts/python.exe -m pytest -q tests/test_posture_scorecard.py tests/test_evidence_graph.py: **12 passed** in 6.39 seconds.
- Frontend command npm run typecheck (application and E2E TypeScript): **passed**.
- OpenAPI generation command npm run api:types: **passed**.
- Production frontend command npm run build: **passed**. Emitted CSS: 95.03 kB (20.28 kB gzip); entry JS: 366.84 kB (101.60 kB gzip); lazy charts chunk: 398.47 kB (109.51 kB gzip).
- Browser command npm run smoke:e2e -- e2e/evidence-graph.spec.ts e2e/posture-scorecard.spec.ts: **8 passed** in 2.0 minutes, including graph controls, click and keyboard selection, stable polling positions, empty/unavailable states, synthetic size profiles, policy-version separation, application and system reduced-motion preferences, and one-time chart animation after refresh.

Backend test output included an upstream Starlette/httpx deprecation warning and a pytest cache-directory access warning; neither failed a test. The browser run also emitted a Node color-environment warning.

An earlier browser iteration exposed two real graph defects: the entrance animation overrode SVG translations, and canvas pointer capture intercepted node clicks. Both were fixed and are covered by the final passing graph test. The animation test was also narrowed to check the visible overview ring rather than a ring mounted inside a closed disclosure.

Screenshots are deterministic mocked UI captures, not production records. During capture only, the sticky top bar is made static so it cannot cover the graph; application styles are not changed:

- [Interactive graph, desktop](design-system/screenshots/module30/module30-evidence-graph-interactive-desktop.png)
- [Accessible evidence list, desktop](design-system/screenshots/module30/module30-evidence-graph-accessible-list-desktop.png)
- [Graph, 390 px](design-system/screenshots/module30/module30-evidence-graph-390.png)
- [Graph, 768 px](design-system/screenshots/module30/module30-evidence-graph-768.png)
- [Graph, 1440 px](design-system/screenshots/module30/module30-evidence-graph-1440.png)

The graph browser test command is npm run smoke:e2e -- e2e/evidence-graph.spec.ts; the posture chart test is npm run smoke:e2e -- e2e/posture-scorecard.spec.ts. Synthetic data is defined in frontend/e2e/evidence-graph.spec.ts.

## Repeat measurement during Module 31

A fresh run on **2026-10-21 19:55:14 UTC** (local date 2026-10-22) used the same Windows 11 x64 laptop, Intel Core i7-13620H, 16 logical CPUs, 16,890,322,944 system-reported memory bytes, headless Chromium 156.0.8078.4, and 1280 × 720 viewport. It used isolated deterministic synthetic graph data and mocked API responses. The test completed all three size profiles:

| Synthetic projection | Render interval | Search interval | Rendering profile |
| --- | ---: | ---: | --- |
| 20 nodes / 28 edges | 421.2 ms | 256.9 ms | Full |
| 120 nodes / 240 edges | 437.9 ms | 291.3 ms | Full |
| 400 nodes / 800 edges | 588.5 ms | 339.8 ms | Simplified |

The measured threshold remains full entrance effects through 120 nodes and 240 edges; 400/800 uses simplified rendering. These are single-run local UI intervals, not percentiles. The **3 graph browser tests passed in 1.5 minutes** on the rebuilt application. Overview screenshots from the same real application run at 390, 768, and 1440 px are in `design-system/screenshots/module31/`; graph-specific captures from Module 30 remain linked above.
