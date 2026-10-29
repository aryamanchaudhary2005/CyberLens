# CyberLens UI reference and animation verification

Verified on 2026-10-24–25, local time. This is a new presentation pass following the earlier UI-00–UI-09 work and the separate workspace debugging follow-up. Earlier results remain historical. See [the individual reference and module analysis](ui-reference-analysis.md).

A later 2026-10-25 startup/effects follow-up repairs Demo credential isolation and adds a continuing title highlight with shared login pause. Its current file changes and validation results are recorded separately in [the startup and implementation review](debug-review-20261025.md). The measurements below describe the earlier pass.

## What changed

- The decorative CyberLens lettering now draws nine original local monoline SVG paths in writing order, followed by a flourish. The previous effect animated outlines over mostly filled text and appeared static. Existing accessible branding, logo, and login form remain present.
- The dashboard orb now receives actual elapsed seconds instead of being slowed a second time before the shader. Restrained light and rotation are visible behind existing opaque panels. A local CSS gradient also moves when WebGL is unavailable or loses its context.
- The dashboard has keyboard-operable **Pause background / Resume background** and **Replay CyberLens title** controls. Pausing freezes the lettering as well as the orb. System/app reduced motion or browser data saving starts with complete static artwork and disables these controls with an explanation. Rendering is also suspended when the document is hidden or the decoration is offscreen.
- The existing motion hooks register panels arriving after async loading or disclosure. A panel reveals once, polling and focus do not replay it, and observer failure leaves content visible. Route/panel/button feedback uses the existing motion tokens. The authenticated TextRoll now moves its outgoing ink while the incoming glyph rolls in, retaining its original triggers, duration, accessible name, and allocated width.
- No animation framework, font download, icon framework, dependency, lockfile, backend source, API definition, calculation, report generator, or database changed in this presentation pass. No example security counts or detections were copied from the reference images.

## Files changed in this pass

Application presentation:

- `frontend/src/components/motion.ts`
- `frontend/src/components/CyberLensHelloEffect.tsx`
- `frontend/src/components/cyberlens-hello-effect.css`
- `frontend/src/components/GradientOrbBackground.tsx`
- `frontend/src/components/gradient-orb-background.css`
- `frontend/src/features/overview.tsx` — decorative state/controls only; existing requests, transformations, values, and operational handlers retained.
- `frontend/src/design-system.css` — edits to existing scoped motion/feedback rules.

Verification and records:

- `frontend/e2e/brand-identity.spec.ts`
- `frontend/e2e/ui-design-system.spec.ts`
- `frontend/e2e/login-globe.spec.ts`
- `docs/ui-reference-analysis.md`, this record, `docs/ui-design-system.md`, `docs/test-results.md`, `PROGRESS.md`, and the new `docs/design-system/screenshots/ui-motion-20261025/` evidence directory.

`App.tsx`, `WorkspaceGraphic.tsx`, `Brand.tsx`, `TextRoll.tsx`, login form markup, `.graphic-*` rules, and protected login layout/style rules were not edited. An attempted login-globe opacity increase was reverted to the original .19 desktop / .18 mobile after the existing preservation assertion rejected it. The final login-globe stylesheet retains the original values.

The workspace has no committed Git baseline: `git -c safe.directory=C:/Users/aryam/OneDrive/Documents/PROJECTS/CyberLens status --short` lists project files as untracked. This file list identifies this pass; a historical whole-project diff cannot be proven from Git. Nothing was staged, committed, reset, or removed, and no global Git ownership setting was changed.

## Actual commands and results

Run from `frontend/` unless stated otherwise:

```powershell
npm run typecheck
npm run build -- --outDir C:/Users/aryam/AppData/Local/Temp/cyberlens-ui-motion-release-20261024

$env:CYBERLENS_BASE_URL='http://127.0.0.1:15175'
$env:CYBERLENS_BROWSER_CHANNEL='chrome'
npx playwright test e2e/brand-identity.spec.ts e2e/ui-design-system.spec.ts e2e/login-globe.spec.ts e2e/evidence-graph.spec.ts e2e/posture-scorecard.spec.ts e2e/monitoring.spec.ts e2e/attack-matrix.spec.ts e2e/attack-catalog.spec.ts e2e/integrity.spec.ts e2e/accessibility.spec.ts e2e/workspace-resilience.spec.ts --reporter=line --output=C:/Users/aryam/AppData/Local/Temp/cyberlens-ui-motion-release-e2e-20261025
```

- Type-check: **passed**, application and E2E projects. Repeated successfully after test changes.
- Production build: **passed**, 683 modules in 4.94 seconds, temporary output; the workspace `frontend/dist` was not replaced by this command.
- Selected production browser suites: **58 passed in 3.3 minutes**, no skips. These use installed Chrome and **mocked APIs**, without accessing user records or external providers. [Retained full output](design-system/screenshots/ui-motion-20261025/production-browser-results.log).
- Clean development-cache check: Vite started with `npm run dev -- --host 127.0.0.1 --port 15173 --strictPort --force`; `e2e/posture-scorecard.spec.ts` against that URL: **5 passed in 24.3 seconds**, mocked APIs.
- Before screenshot check against preserved pre-change static assets on port 15174: `e2e/ui-design-system.spec.ts --grep 'TextRoll settles'`: **1 passed in 8.1 seconds**. These are actual pre-change bundle captures, not reconstructed source or refreshed golden baselines.
- Final motion video/responsive capture check against port 15175: `e2e/brand-identity.spec.ts --grep 'CyberLens strokes actually'`: **1 passed in 10.7 seconds**. Viewport captures wait for the mobile header entrance to settle; the video includes movement.

The passing selection covers existing route/role restrictions, drawer trap/Escape/focus restoration, form/applicability drafts during polling, investigation presentation, graph selection/filter/search/pan/zoom/list and size safeguards, chart values/null gaps/policy-version separation, monitoring actions, ATT&CK/integrity controls, long errors, partial/empty/unavailable data, and decorative motion failure/cleanup. It is not a fresh real-backend execution of every workflow. The earlier debugging record's isolated real Admin–Analyst–Viewer workflow and 335 backend tests were **not rerun** in this UI pass; Live providers and real target behavior remain unverified here.

## Protected login comparison

The existing UI-00 geometry/computed-style/text assertions passed at 390, 768, and 1440px. Responsive checks additionally passed at 390, 679, 680, 681, 767, 768, 899, 900, 901, and 1440px. The diagram/form were not masked out and the original expected geometry, colors, typography, fields, validation, request payload, keyboard order, and mobile visibility assertions remain.

The protected SVG SHA-256 remains:

```text
44e80fa6ef682f2b9e82dc8ff3be593ba5aedfb3020026d4e39683a2e068fd17
```

React development StrictMode and production generate different `useId` namespaces (`r1-line` / `r0-line`). The comparison normalizes only that generated gradient ID and its matching URL reference to UI-00's namespace; every path, label, attribute, color, and geometry is still checked against the original hash. Production minification also serializes motion tokens as seconds; tests compare the same durations numerically in milliseconds.

The public served Live page independently produced that same normalized SVG hash, .19 globe opacity, and **120s** revolution duration. The existing `.login-story` is **hidden at <=680px**; this limitation is preserved. There is no claim that the diagram is visible at all widths. The decorative signature is outside protected content flow; the dashboard signature is hidden on small phones to reserve room for controls.

The login globe remains the existing lightweight local SVG/CSS scene. It has no WebGL dependency or JavaScript frame loop. Import failure, image failure, reduced motion, app preference, pause/resume, hidden/offscreen behavior, input transparency, responsive overflow, and repeated login/logout checks passed. WebGL/context-loss cases apply to the dashboard orb, not this SVG globe.

## Runtime and bundle observations

Same-run baseline build: CSS **130.26 kB / 25.01 kB gzip**, entry JS **375.56 / 104.96**. Final: CSS **132.71 / 25.51**, entry JS **378.10 / 106.13**. Increase: CSS **2.45 / .50**, entry JS **2.54 / 1.17**. Lazy charts stayed **399.01 / 109.59**, and lazy login globe **3.40 / 1.46**. These are emitted assets, not runtime memory or loading-time benchmarks. No package changed.

The orb draw cap is 30 per second; its render buffer is capped at 1100×700 pixels (770,000 pixels). A sampled 0.600-second interval observed **13 WebGL draws at 947×547**. Tests observed real time progression, no ongoing draws while paused/hidden/offscreen, no growing frame work after repeated route mount/unmount, CSS fallback following simulated context loss, and no WebGL context request when data saving initially requires static artwork. This is not a GPU memory or sustained frame-time profile; the draw cap does not imply the RAF callback itself is capped at 30/sec.

Synthetic graph sample on Windows x64, Intel Core i7-13620H, 16 logical CPUs, 16,890,322,944 reported memory bytes, Chrome 155.0.8059.86, 1280×720: render/search intervals were **356.9/235.0ms** for 20 nodes/28 edges, **384.9/250.0ms** for 120/240, and **628.4/359.9ms** for 400/800 using the existing simplified profile. Single samples are not evidence of a performance improvement.

Focused rendered accessibility assertions reported minimum sampled text contrast **4.62:1**, focus-indicator contrast **8.76:1**, and no unnamed or undersized controls in the sampled set. Status labels remain distinct beyond color; chart/graph alternatives remain. Manual screenshot review is separate from those assertions. No screen-reader audit, physical-device test, second browser engine, native browser zoom test, or accessibility certification was performed. Effective CSS-width checks approximate zoom reflow only.

## Screenshots and video

Before images use the old deployed static bundle preserved before replacement, with mocked API fixtures. After dashboard and workflow images also use isolated mocked fixtures. The separately labeled public Live login capture is unauthenticated and contains no saved records. No fixture was inserted into an application database.

- [Motion video](design-system/screenshots/ui-motion-20261025/after/video.webm) and [writing in progress](design-system/screenshots/ui-motion-20261025/after/cyberlens-writing-in-progress.png).
- Login [before](design-system/screenshots/ui-motion-20261025/before/login-desktop.png), [after desktop](design-system/screenshots/ui-motion-20261025/after/login-globe-1440.png), [tablet](design-system/screenshots/ui-motion-20261025/after/login-globe-768.png), [phone](design-system/screenshots/ui-motion-20261025/after/login-globe-390.png), and [served public Live login](design-system/screenshots/ui-motion-20261025/after/live-public-login-1440.png).
- Dashboard before: [desktop](design-system/screenshots/ui-motion-20261025/before/overview-wide-1440.png), [tablet](design-system/screenshots/ui-motion-20261025/before/overview-tablet-768.png), [phone](design-system/screenshots/ui-motion-20261025/before/overview-mobile-390.png). After: [desktop](design-system/screenshots/ui-motion-20261025/after/motion-overview-1440.png), [tablet](design-system/screenshots/ui-motion-20261025/after/motion-overview-768.png), [phone](design-system/screenshots/ui-motion-20261025/after/motion-overview-390.png). Before full-page and after viewport images have different heights; they are visual evidence rather than pixel-diff goldens.
- [Interactive graph](design-system/screenshots/ui-motion-20261025/after/module30-evidence-graph-interactive-desktop.png), [accessible graph list](design-system/screenshots/ui-motion-20261025/after/module30-evidence-graph-accessible-list-desktop.png), [risk chart](design-system/screenshots/ui-motion-20261025/after/ui05-risk-history-chart.png), and [monitoring](design-system/screenshots/ui-motion-20261025/after/ui05-monitoring-change-radar.png).
- [Unavailable assessment](design-system/screenshots/ui-motion-20261025/after/overview-posture-unavailable-1440.png), [empty scorecard](design-system/screenshots/ui-motion-20261025/after/posture-scorecard-empty-1440.png), [long phone error](design-system/screenshots/ui-motion-20261025/after/ui08-long-error-390.png), and [mobile drawer](design-system/screenshots/ui-motion-20261025/after/ui03-shell-mobile-drawer.png).

## Local deployment and reversible state

Only the frontend image was rebuilt. From the repository root:

```powershell
docker compose --project-name cyberlens build frontend
docker compose --project-name cyberlens up -d --no-deps frontend
docker compose --project-name cyberlens start --wait --wait-timeout 180
```

The existing stopped Live services were resumed using their existing images and volumes. All seven services were running; six reported healthy, while the dispatcher has no container health check. Public readiness at `https://localhost:8443/api/v1/health/ready` returned `ready`, `mode: live`, `demo_data: false`, with database/Redis/worker true. Public login loaded `/assets/index-wGGy7sfK.js` and `/assets/index-CGmC4tzX.css`, with no page errors, failed requests, or unexpected HTTP errors. The expected unauthenticated session response was excluded from the HTTP-error check. No credentials were submitted to the Live database.

The old served bundle (`index-DUVnnKx-.js` / `index-DC_10rqD.css`) is preserved in local image **`cyberlens-frontend:before-ui-motion-20261025`**, built from copied old public assets before replacement. Its original image ID could not be tagged, so that failed tag attempt did not mutate the stack; the public-asset copy supplied the rollback instead. The explicit local static backup also remains at `C:/Users/aryam/AppData/Local/Temp/cyberlens-before-ui-static-20261025/html`; temp files are not a permanent source backup.

The pre-existing Demo project's six running services and stopped gateway were left alone. No volume was deleted or recreated. `.env` remains 1066 bytes with its original 2026-10-22 03:57 UTC modification time. Temporary browser preview servers were stopped after verification; the normal Live stack remains running at **https://localhost:8443**. Hard-refresh with **Ctrl+F5** to discard an older cached frontend. Existing app/system motion preferences are respected; the user menu's **Reduce animations** setting can intentionally make the effects static.

## Failures encountered and resolved

- An initial new test needed a TypeScript canvas-element narrowing. SVG computed dash offsets serialize as `0px`, not `0`; test expectations were corrected to the actual type/value.
- An exact bounding-box comparison caught a .01px difference while the route entrance was settling. The test now waits for the route animation and checks subpixel preservation within .05px; original UI-00 geometry assertions remain unchanged.
- A temporary source comparison preview shared the dev `node_modules/.vite` prebundle cache and triggered duplicate-React/invalid-hook errors in Recharts. Both dev previews were stopped and verification moved to static production previews. The clean `--force` dev chart run subsequently passed all five tests. This was a verification environment problem introduced by the comparison setup; it was not repaired by changing application logic or weakening chart assertions.
- A first production run had 53 passes and four failures: the attempted globe opacity increase was reverted; dev/prod generated-ID and CSS-unit serialization differences were normalized as described above. The original SVG hash, opacity ceiling, durations, and geometry requirements remain in place. The later 58-test production run passed.
- Playwright rejected a video option set inside a describe block. It is now scoped at the brand test file level. A full-page capture after viewport changes showed a Chromium sticky-header capture artifact; final stills explicitly scroll to the top and capture the viewport. The animation video is retained separately.
- The first ad hoc public login probe used a nonexistent `.login-screen` selector and timed out. The corrected `.login-wrap` probe passed; a subsequent read-only probe checked the actual globe object and original SVG hash.

No unresolved source defect was demonstrated by these final selected checks. Limits remain: no committed whole-project baseline, no fresh full real-backend workflow in this pass, and no new external provider/production-load/accessibility certification results.
