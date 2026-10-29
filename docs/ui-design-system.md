# CyberLens interface design system

CyberLens uses a dark, compact analyst workspace with a persistent navigation rail and a responsive content area. The overview uses a Bento grid to summarize saved posture, provider observations, incidents, investigations, Change Radar, monitoring, risk history, and service readiness. The underlying routes and feature workflows remain the source of truth; the overview is a read-only projection over their existing APIs.

## Interface structure

- `frontend/src/App.tsx` owns authentication, role-aware navigation, hash routes, the desktop sidebar, mobile drawer, mode indicator, user menu, and shared notices.
- `frontend/src/features/overview.tsx` composes the overview cards from loaded workspace data and read-only scorecard, monitoring, and evidence-comparison APIs. It labels the data scope and distinguishes saved observations from live readiness.
- `frontend/src/features/` contains the existing asset, investigation, incident, remediation, threat-model, report, integrity, integration, administration, monitoring, and posture workflows.
- `frontend/src/components/ui.tsx`, `icons.tsx`, `Brand.tsx`, and `TextRoll.tsx` provide shared display states, local SVG navigation icons, the reusable brand lockup, and the wordmark animation.
- `frontend/src/components/motion.ts` owns once-per-entry viewport reveals (including async panels), sticky-header state, and the decorative visibility/data-saving playback gate. It skips nonessential movement under either reduced-motion preference and cleans up observers/listeners when the route or shell changes.
- `frontend/src/components/form-drafts.ts` keeps unsent, non-secret form values in memory when analysts move between workspace routes. Passwords, credentials, tokens, and other secret fields are excluded; successful form actions clear saved drafts while failed actions keep them.
- `frontend/src/design-system.css` adds the shared design tokens and responsive shell/components. Existing feature stylesheets remain in use. `frontend/src/main.tsx` imports the design-system stylesheet after those existing styles so the shared tokens and layout rules have final precedence.
- `frontend/src/api.ts` remains the typed API boundary and uses `frontend/src/generated/api.d.ts`, generated from FastAPI OpenAPI.

## Visual tokens and components

The authenticated workspace now uses Midnight Iris, the reference-guided evolution of Arctic Graphite: page `#0C1420`, secondary `#121F2E`, panel `#17283A`, elevated `#1D3146`, border `#30445A`, indigo action `#7156E8`, lavender series `#A794FF`, highlight/focus `#BCB0FF`, and ice-blue chart accent `#81D9E8`. Primary text is `#EDF4FC`, secondary `#C7D5E5`, muted `#A7B9CC`, and quiet `#98ABC0`. Tokens remain scoped to `.app-shell`; protected login/password defaults are unchanged.

Color roles remain distinct: success uses green; unavailable uses muted violet; unknown and not-assessed use neutral gray; no-match uses blue-gray; partial and stale use amber. Critical/high/medium/low retain their established red/orange/amber/neutral meanings. State labels remain visible so color is never the only signal.

Implemented sRGB contrast ratios: primary/panel 13.52:1; secondary/elevated 8.91:1; muted/elevated 6.62:1; quiet/elevated 5.65:1; secondary accent/elevated 5.27:1; highlight/elevated 6.83:1; white/action 5.00:1. These pairs pass 4.5:1 normal-text contrast. This is not an accessibility certification.

The shared CSS custom properties in `design-system.css` define page/surface/text/accent/severity/status colors, typography sizes, spacing, radii, focus, elevation, motion durations, and system font stacks. Repeated status and error colors resolve through semantic tokens while retaining their prior displayed values. Midnight Iris values are scoped to `.app-shell`; root defaults remain for the protected login/password surfaces. Motion tokens are 150ms for controls, 180ms for overview cards, 200ms for the mobile drawer, 160ms for its backdrop, 220ms for page and graph-node entry, 240ms for panels/disclosures/notices, and 1.6s for loading shimmer; overview cards stagger by 16ms up to 96ms. TextRoll, score rings, charts, and the decorative login globe retain their component-specific motion durations. The implementation uses local system fonts and inline SVG icons; it does not fetch fonts, images, icon packs, or other remote UI assets. No UI dependency was added.

The primary overview is a 12-column Bento grid with paired summary cards, a balanced Change Radar/monitoring row, and a full-width risk history. It becomes a drawer-based navigation shell below 900px and stacks cards at 680px. At 390px and below, metric and status layouts simplify further. Shared elements include:

- status and severity badges with explicit labels;
- labeled, visible keyboard focus for controls and links;
- loading, empty, partial, error, unavailable, stale, and read-only states;
- responsive tables with horizontal overflow where the data cannot be safely condensed;
- a detailed posture view available on demand, with a text/table alternative for chart data;
- an accessible modal-like mobile navigation drawer with initial focus, focus trapping, Escape dismissal, and focus restoration.

The desktop welcome screen includes a local, static SVG illustration of the existing assets/evidence/review workflow. It does not depict live activity. The risk ring draws the exact saved score; coverage uses the saved category-slot percentage. Their accompanying text remains the accessible source of the values. Unknown scores do not draw a filled score arc. Provider summary counts describe freshness of saved records, never safety.

Recharts components live in a separate dynamic module. They load only when a nonempty chart is rendered, with a fixed-height loading state and an exact-value table alternative. Short line, bar, and ring entrance effects run once; exact values remain in adjacent text and the table. Risk trend series stay separated by saved policy version, null values remain gaps, and missing workflow counts stay unavailable rather than being converted to zero. No external fonts, images, or UI packages are required.

## Branding and motion

The original geometric C-lens mark and color direction are documented in the [brand guide](brand-guide.md). `BrandLockup` uses local SVG artwork in the login, password change, sidebar, and mobile header. The wordmark rolls once when a brand area first appears; each glyph moves over 320ms with a 16ms stagger (about 448ms across CyberLens). Its base reserves the final width; the authenticated shell moves outgoing and incoming ink within that space. The protected login lockup keeps its established styling. Pointer hover and keyboard focus on the sidebar home control intentionally replay it; routine state updates and navigation do not. One accessible name is exposed for the lockup. The app preference and system reduced-motion preference both present a complete static title immediately. New PDFs use a local vector header on the light page; previously generated reports remain unchanged.

The User menu exposes **Reduce animations**. The preference is stored locally in the browser. System-level `prefers-reduced-motion` takes precedence for the interface and original branding; reduced mode removes page, card, and viewport-reveal movement, disables smooth scrolling and the TextRoll, and keeps the full content visible. Focus indicators remain visible in either mode. Viewport reveals observe existing and newly arriving panels once per entry; cards stay visible if observation is unavailable, and focused panels remain visible. Polling and focus changes do not restart route or card motion. Native scrolling remains in use. Decorative CyberLens writing and the dashboard orb additionally respect browser data saving, hidden tabs, offscreen state, and the overview pause control. The title replay control does not modify operational values.

## Overview data rules

The overview reads saved asset/investigation/incident and provider records, the posture scorecard, monitoring schedules, health readiness, and completed/partial investigation comparisons. Change Radar selects the newest eligible pair for one asset, even if the newest workspace investigation has no pair. Failed runs are not selected as successful observations. It links to the existing report workflow without treating reports as a new metric source and does not run collectors. Summaries show loaded list counts, scorecard window and scope, provider observation freshness, and service availability separately. Missing and unassessed data is explicitly not represented as safe. A provider configuration label is not presented as a connectivity check, and API/database/Redis/worker readiness is not conflated with provider freshness.

Opening the detailed posture disclosure mounts the existing detailed scorecard and chart workflow. The overview does not duplicate its scoring logic, modify an assessment, or replace historical reports.

## Validation record

Module 29's before and after captures use deterministic mocked API data at 390px, 768px, and 1440px. The responsive overview and investigation screenshots are saved in [`docs/design-system/screenshots/before/`](design-system/screenshots/before/) and [`docs/design-system/screenshots/after/`](design-system/screenshots/after/). They show empty, partial, and synthetic result states and are not production data. The separate [brand guide](brand-guide.md) links Module 28 brand captures.

The production bundle measured before the changes was 89.59 kB CSS (19.66 kB gzip), 342.16 kB entry JavaScript (93.90 kB gzip), and a 395.25 kB charts chunk (108.51 kB gzip). The final Module 29 build measured 84.56 kB CSS (18.56 kB gzip), 346.10 kB entry JavaScript (95.37 kB gzip), and the same 395.25 kB charts chunk (108.51 kB gzip). CSS decreased by 5.03 kB; entry JavaScript increased by 3.94 kB. These are emitted asset sizes, not runtime performance claims.

Computed interaction timing samples changed from 140ms to 150ms for button feedback and from 200ms to 220ms for page entry. A single mocked route-ready sample was 357.5ms before and 197.4ms after; these samples are noisy and are not evidence of a speed improvement. The focused Module 29 browser suite passed 9/9 in 1.1 minutes, including responsive overflow, keyboard focus, reduced motion, polling stability, slow request/retry, observer failure, and route draft preservation. Frontend TypeScript checks passed. The broader workflow suite could not be completed: its analyst login received an API 500 and the run then stopped making progress; no result is claimed for the broader workflows. The disposable Docker preview and its runtime checks are documented in [debug-preview.md](debug-preview.md).

The supplied Figma link was not accessible from the review environment, so this implementation follows the written design brief and the existing CyberLens workflows rather than claiming pixel-by-pixel Figma fidelity.

Module 30 extends the evidence graph controls, provenance details, accessible list, reduced-motion behavior, and policy-aware charts. Its synthetic measurements, tested size limit, validation results, and screenshots are in the [graph interaction notes](evidence-graph-interaction.md).

## UI-01 Arctic Graphite implementation record

The authenticated `.app-shell` now owns the Arctic Graphite color, radius, border, and elevation tokens. Shared panels, navigation, tables, forms, buttons, badges, dialog surfaces, loading states, empty states, errors, and the existing simulation, vulnerability, and ATT&CK catalog panels consume those tokens. Semantic severity colors and status distinctions remain explicit. The primary indigo fill is reserved for controls; accessible accent text uses `#AFA6FF`. Existing reusable components in `components/ui.tsx` and all event handlers remain unchanged.

The root palette, global defaults, and generic `.panel` declarations were retained for authentication screens. Authenticated panel styling is scoped under `.app-shell`. The login card and submit button keep their measured pre-change colors and elevation. No login layout, form, SVG component, `.login-*` geometry, or `.graphic-*` styling was changed. The SVG markup SHA-256 recorded by the test is `44e80fa6ef682f2b9e82dc8ff3be593ba5aedfb3020026d4e39683a2e068fd17`; its three labels, `0 0 500 290` viewBox, and computed fills/strokes are asserted.

The UI-00 login geometry baseline and post-change regression checks use mocked API responses in Microsoft Edge. At 390×844 the story/diagram stays hidden, as required by the existing `max-width: 680px` rule. At 768×900 the story is 376.36×534.28px and the graphic wrapper is 406.36×252.73px; at 1440×900 the story is 552.88×580.66px and the wrapper is 582.88×307.05px. The form card, field, submit button, body typography, caption, diagram markup, and graphic colors are asserted against the pre-change capture.

Screenshots below are isolated Demo-mode UI test captures. The overview’s figures are synthetic fixtures used by the existing Playwright mock, not real workspace data. The login screenshot keeps the diagram visible at desktop width; the 390px login capture intentionally does not show it.

- [Login baseline, desktop](design-system/screenshots/ui01/before-login-1440.png)
- [Login after UI-01, desktop](design-system/screenshots/ui01/after-login-1440.png)
- [Login after UI-01, tablet](design-system/screenshots/ui01/after-login-768.png)
- [Login after UI-01, mobile (story hidden by existing breakpoint)](design-system/screenshots/ui01/after-login-390.png)
- [Overview after UI-01, desktop](design-system/screenshots/ui01/overview-1440.png)
- [Overview after UI-01, tablet](design-system/screenshots/ui01/overview-768.png)
- [Overview after UI-01, mobile](design-system/screenshots/ui01/overview-390.png)

Final validation on 2026-10-24 (fresh UI-01 run):

- `npm run typecheck` — passed with exit code 0 for the application and Playwright TypeScript projects.
- `npm run build -- --outDir C:/Users/aryam/AppData/Local/Temp/CyberLens-UI01-20261024-dist` — passed; Vite 7.3.7 transformed 679 modules in 5.07 seconds. Emitted CSS: 107.51 kB (21.60 kB gzip); entry JavaScript: 367.62 kB (101.83 kB gzip); lazy charts: 398.47 kB (109.51 kB gzip); lazy login background: 3.40 kB (1.46 kB gzip). The output directory was outside the project. Vite noted that the external `outDir` was not emptied; this was informational and the build succeeded.
- `npm run smoke:e2e -- e2e/ui-design-system.spec.ts --reporter=list --output C:/Users/aryam/AppData/Local/Temp/CyberLens-UI01-20261024` — 14/14 Playwright tests passed in 41.2 seconds. Coverage included the UI-01 palette and state-distinction checks, the protected login diagram/form at 390px, 768px, and 1440px, navigation, role differences, polling and form drafts, empty/slow/error states, long content, and reduced motion. API responses were mocked; this is browser UI validation, not backend integration. The Vite test server required loopback access on `127.0.0.1:5173`.
- Visual captures from this run are saved under [`design-system/screenshots/ui01/`](design-system/screenshots/ui01/). I inspected the 1440px overview, 390px overview, and 1440px login capture. The 390px login screenshot intentionally has no story/diagram because the existing `max-width: 680px` rule hides it; the desktop login test confirms its measured geometry and computed styles against the UI-00 baseline.
- Contrast checks in the browser test retain the measured primary/secondary text and highlight pairs at or above WCAG AA normal-text contrast. The secondary accent is 4.43:1 against the elevated surface and is therefore reserved for decorative strokes, chart series, and borders rather than small text.
- No API, backend, database, authentication, authorization, or dependency files changed. `WorkspaceGraphic.tsx` and `components/ui.tsx` were not edited; protected login defaults and `.graphic-*` styles remain unchanged.

## UI-02 decorative login globe

The login background adds an original, locally authored SVG Earth with a dark radial ocean, simplified continent silhouettes, latitude/longitude lines, a few decorative connection arcs, and a soft edge fade. These marks are decorative artwork, not detected activity. The source asset is [`frontend/public/login-globe.svg`](../frontend/public/login-globe.svg); it is 4,156 bytes and has no external attribution requirement. The rotation is a CSS transform with a 120-second duration, not a Three.js/WebGL scene. Three.js was not present in the frontend dependencies or lockfile; for this low-detail, offline background, the vector scene avoids a large runtime, external texture requirements, and WebGL failure modes. No dependency or lockfile changed.

`LoginGlobeGate` lazy-loads the animation only when the login screen appears. Login content renders immediately with the same local SVG as a static Suspense and import-error fallback. If the SVG itself fails, the scene renders an inline static vector fallback. The animated component uses the existing app/system reduced-motion state, stays static for data-saving mode, and exposes a keyboard-operable pause/resume button. The button is absolutely positioned above the login content and follows the unchanged form tab order. A visibility listener and IntersectionObserver pause its CSS animation while hidden/offscreen and are cleaned up on unmount; no canvas or JavaScript animation loop is used. Existing authenticated sessions do not request the lazy globe module.

The globe is a page-background sibling after the existing login layout. Only `.login-wrap` receives positioning/isolation needed to contain it; the background layer has `pointer-events:none` and `aria-hidden`. No login fields, validation, request payloads, content, `WorkspaceGraphic` markup, `.graphic-*` CSS, or layout dimensions changed. The screenshot and Playwright geometry checks cover 390×844, 768×900, and 1440×900. At 390px, the diagram remains hidden by the existing `max-width:680px` rule; the globe is repositioned to show a subdued partial Earth in the available area above the form without changing that layout.

The focused Playwright suite uses mocked Demo readiness and API responses. It checks the preserved layout geometry, content/tab order, local asset loading and no cross-origin requests, background pointer behavior, pause/resume, system reduced motion, lazy-import failure, asset failure, successful login payload, and two login/logout cycles with no canvases accumulating. The UI-01 suite was also rerun to verify its captured login geometry and computed styles.

Captures are in [`docs/design-system/screenshots/ui02/`](design-system/screenshots/ui02/):

- [Desktop login, 1440px](design-system/screenshots/ui02/login-globe-1440.png)
- [Tablet login, 768px](design-system/screenshots/ui02/login-globe-768.png)
- [Mobile login, 390px; diagram hidden by existing breakpoint](design-system/screenshots/ui02/login-globe-390.png)

Current measured output: the separately loaded `LoginGlobeBackground` JavaScript chunk is 3.40 kB (1.46 kB gzip), the local SVG is 4,156 bytes, and `login-globe.css` source is 3,034 bytes. The production build emits 107.51 kB CSS (21.60 kB gzip), 367.62 kB entry JavaScript (101.83 kB gzip), and the existing 398.47 kB chart chunk (109.51 kB gzip). Vite combines the small login stylesheet into the shared CSS output. The component was already present when this verification started, so these are current output sizes rather than a controlled before/after delta. They are emitted file sizes, not runtime performance claims.

Runtime observations from the browser checks: the CSS animation duration is 120 seconds; the local asset loads without cross-origin requests; hidden-document and offscreen transitions pause the animation and restore it when visible. The implementation uses no canvas, WebGL context, GPU texture, per-frame React state, or JavaScript render loop, so StrictMode cannot create duplicate animation loops. No CPU/frame-time benchmark was run.

Validation on 2026-10-24:

- `npm run typecheck` — passed for app and E2E TypeScript projects after the final test changes.
- `npm run build -- --outDir C:/Users/aryam/AppData/Local/Temp/CyberLens-UI02-final-dist` — passed; Vite transformed 679 modules in 5.07 seconds. Emitted CSS was 107.51 kB (21.60 kB gzip), entry JavaScript 367.62 kB (101.83 kB gzip), lazy login background 3.40 kB (1.46 kB gzip), and lazy charts 398.47 kB (109.51 kB gzip). Vite printed its informational warning that it would not empty an `outDir` outside the project; the build completed successfully.
- `npm run smoke:e2e -- e2e/login-globe.spec.ts --reporter=list --output C:/Users/aryam/AppData/Local/Temp/CyberLens-UI02-final-e2e` — 6/6 focused Playwright tests passed in 12.6 seconds. Checks cover original login geometry and tab order, external-request absence, pause/resume, system and app reduced-motion preferences, hidden/offscreen pause and resume, failed lazy import, failed local asset, and two login/logout cycles.
- `npm run smoke:e2e -- e2e/login-globe.spec.ts e2e/ui-design-system.spec.ts --reporter=list --output C:/Users/aryam/AppData/Local/Temp/CyberLens-UI02-final-regression` — 20/20 browser tests passed in 47.5 seconds. This includes the 6 globe tests and all 14 UI-01 preservation/workflow regressions, including the UI-00 diagram/form measurements at 390px, 768px, and 1440px.
- Playwright responses were mocked; these are browser checks, not backend integration or live-provider checks. The test server required loopback access at `127.0.0.1:5173`, granted for this run. Screenshots were refreshed from the isolated test run; the mobile view shows a clipped globe while its diagram remains hidden by the original breakpoint.
- No dependency or lockfile changed. The only new test assertion added during this run covers hidden/offscreen pause behavior. No backend, API, database, authentication, or login form behavior changed.

## UI-03 authenticated sidebar and header refinement

The signed-in shell keeps the existing navigation destinations, hash routing, admin-only Administration entry, local collapse preference, user-menu actions, and `BrandLockup`/TextRoll instances. The rail now uses a tighter icon scale, clearer Workspace/Manage grouping, a stronger indigo active state, subtler hover feedback, and animated collapsed-label tooltips. Header surfaces, breadcrumb truncation, mode status, and user-menu controls have clearer contrast and alignment. These changes are scoped to the authenticated shell; the login and password-change screens retain their existing styles.

The mobile drawer retains the existing React focus trap, Escape dismissal, and focus restoration. Browser testing exposed that the drawer's CSS delayed `visibility: visible` until the end of its opening transition, so initial focus could run while links were still hidden. The shell stylesheet now makes visibility immediate while opening and delays hiding until the closing slide finishes. Reduced-motion mode removes that transition and delay. No login markup, diagram, geometry, form, validation, or request behavior changed.

Captured with the UI test's mocked Demo API responses at 1440×900 and 390×844. The mobile drawer is shown open in its own screenshot. The screenshots are isolated test captures, not live workspace data:

- [Desktop shell, 1440px](design-system/screenshots/ui03/shell-desktop-1440.png)
- [Collapsed sidebar, 1440px](design-system/screenshots/ui03/sidebar-collapsed-1440.png)
- [Mobile shell, 390px](design-system/screenshots/ui03/shell-mobile-390.png)
- [Mobile drawer open, 390px](design-system/screenshots/ui03/mobile-drawer-open-390.png)

Validation refreshed on 2026-10-24:

- `npm run typecheck` — passed for application and Playwright TypeScript projects.
- `npm run build -- --outDir C:/Users/aryam/AppData/Local/Temp/CyberLens-UI03-20261024-dist` — passed; Vite transformed 679 modules in 5.12 seconds. Output: CSS 107.51 kB (21.60 kB gzip), main JavaScript 367.62 kB (101.83 kB gzip), lazy login globe 3.40 kB (1.46 kB gzip), and lazy charts 398.47 kB (109.51 kB gzip). Vite emitted an informational notice that it does not empty an output directory outside the project; build exit code was 0.
- `npm run smoke:e2e -- e2e/ui-design-system.spec.ts e2e/brand-identity.spec.ts --reporter=list --output C:/Users/aryam/AppData/Local/Temp/CyberLens-UI03-20261024-e2e` — 18/18 Playwright tests passed in Chromium (50.0 seconds). Coverage includes hash navigation/history and selected state, admin versus viewer navigation, collapse preference and tooltip, mobile drawer initial focus/trap/Escape restoration, login diagram/form preservation at 390/768/1440px, and TextRoll stability during polling. API responses are mocked; this is a browser UI suite, not a backend integration test. Playwright's temporary Vite server required loopback permission.
- Fresh isolated screenshots were captured at 1440×900 (expanded and collapsed) and 390×844 (mobile shell and open drawer). The screenshots use mocked Demo responses, not saved workspace records.
- No application source, dependency, API contract, database, authentication rule, or saved record changed in this verification pass. `components/icons.tsx` remains as inspected; existing inline SVGs use shell-scoped CSS sizing and alignment.

The existing rule continues to hide the login story/diagram at widths up to 680px. UI-03 does not alter that rule.

## UI-08 responsive and accessibility refinement

Responsive checks cover the authenticated workspace at 390, 679, 680, 681, 768, 899, 900, 901, 1119, 1120, 1121, and 1440 CSS pixels. The shell menu remains visible through 900px, and the workspace document did not gain horizontal overflow at those widths. Effective CSS widths of 1152px and 720px were also checked to approximate 125% and 200% browser zoom on a 1440px display; browser chrome zoom itself was not changed.

The login preservation check was extended across 390, 679, 680, 681, 768, 899, 900, 901, and 1440px. At each width it checks the original SVG markup hash, diagram labels, visibility breakpoint, login card/form geometry and styles, and document width. `.login-story` remains hidden at widths up to and including 680px and visible above 680px. The layout was not moved or resized to expose it on small screens.

The rendered overview audit found that disabled buttons inherited a 62% opacity rule. That lowered the disabled primary button text to 3.26:1 against its rendered face. The authenticated-shell-only disabled state now keeps full text opacity and uses a subdued surface; its sampled text contrast is 10.40:1. Login and password-screen controls do not inherit this adjustment. In the deterministic Demo overview, a DOM text scan measured 108 rendered HTML text items; the lowest sampled contrast was 4.62:1 on the primary button. Success, critical, high, medium, low/informational, unavailable, not-assessed, and no-match badge samples ranged from 8.59:1 to 10.74:1. Collapsed-navigation tooltip contrast measured 13.74:1, and the visible focus outline measured 8.76:1. The overview scan found no visible interactive element without a computed name and no visible target below 24×24 CSS pixels.

A 960px synthetic table remained inside its 322px mobile `.table-wrap`; the document stayed 390px wide. A test-only long error string in the existing alert remained visible without widening the page at 390, 720, 1152, and 1440px. Existing role, draft, drawer focus restoration, graph-list, chart/data, reduced-motion, and login-globe pause/fallback checks also ran in the final browser suite. Fixtures and screenshots are isolated; no saved workspace records were used or changed.

Responsive captures show the authenticated overview at all five requested widths and the login page at matching widths. These screenshots use the deterministic mocked Demo workspace and should not be read as current saved data:

- Workspace: [390px](design-system/screenshots/ui08/workspace-390.png) · [680px](design-system/screenshots/ui08/workspace-680.png) · [768px](design-system/screenshots/ui08/workspace-768.png) · [900px](design-system/screenshots/ui08/workspace-900.png) · [1440px](design-system/screenshots/ui08/workspace-1440.png)
- Login preservation: [390px](design-system/screenshots/ui08/login-390.png) · [680px; diagram hidden by the existing breakpoint](design-system/screenshots/ui08/login-680-diagram-hidden.png) · [768px](design-system/screenshots/ui08/login-768.png) · [900px](design-system/screenshots/ui08/login-900.png) · [1440px](design-system/screenshots/ui08/login-1440.png)
- Additional states: [mobile drawer keyboard focus](design-system/screenshots/ui08/mobile-drawer-focus-390.png) · [long error at 390px](design-system/screenshots/ui08/long-error-390.png) · [long error at 720px effective zoom width](design-system/screenshots/ui08/long-error-720-effective-zoom.png) · [long error at 1440px](design-system/screenshots/ui08/long-error-1440.png)

Validation on 2026-10-24:

- `npm run typecheck` — passed for application and Playwright TypeScript projects.
- `npm run build -- --outDir C:/Users/aryam/AppData/Local/Temp/CyberLens-UI08-final-20261024-dist` — passed; Vite transformed 679 modules. Emitted assets: CSS 125.69 kB (24.20 kB gzip), entry JavaScript 367.79 kB (101.88 kB gzip), lazy login globe 3.40 kB (1.46 kB gzip), and lazy charts 399.01 kB (109.59 kB gzip). The build emitted Vite's informational notice that the temporary output directory is outside the project and will not be emptied.
- The last successful combined browser run, before adding the final login-form edge-alignment assertions, was `npm run smoke:e2e -- e2e/accessibility.spec.ts e2e/ui-design-system.spec.ts e2e/evidence-graph.spec.ts e2e/posture-scorecard.spec.ts e2e/login-globe.spec.ts --reporter=list --output C:/Users/aryam/AppData/Local/Temp/CyberLens-UI08-final-20261024-e2e` — 35/35 Chromium tests passed in 2.7 minutes. APIs were mocked; no backend or live provider was exercised.
- After the final test-only login geometry assertions, `npm run typecheck` and the production build passed again. A fresh focused browser rerun could not start: Playwright timed out waiting for its local Vite server, and a direct loopback probe returned `socket access forbidden`. This environment restriction prevented execution of the final assertion revision; the successful 35/35 run covers the preceding test revision and the same CSS. The login edge-alignment assertion accounts for the card's 1px border.
- Automated accessibility checks are focused DOM/contrast/target assertions, not a complete accessibility engine. Manual review covered screenshots at 390, 680, 768, 900, and 1440px plus keyboard operation of the mobile drawer. No screen-reader audit, external accessibility certification, other browser engine, physical device, or native browser zoom test was performed.
- No route, API contract, event handler, form state, permission, data model, or login component/style changed. The only application presentation change is the disabled button styling scoped under `.app-shell`; the other changes are Playwright checks, documentation, and synthetic screenshots.

## UI-04 overview and posture presentation

The overview and posture pages use a consistent card rhythm, clearer metric spacing, balanced risk-ring placement, and inset chart surfaces. Posture assessment coverage exposes its existing state to CSS so partial and stale coverage use amber, while unavailable/empty coverage uses a neutral meter. The percentage, category-slot counts, risk-ring SVG, scorecard calculations, API calls, chart series, exact-value tables, links, status text, and existing overview summary limits remain sourced from their existing records. This verification pass found the requested presentation already present, so no feature component or application stylesheet changes were needed.

Captured screenshots use isolated Playwright API fixtures; they are not saved workspace data. They show a partial overview on desktop and mobile, an unavailable scorecard while service readiness remains independently ready, and detailed posture in available and empty states. The unavailable overview capture uses a 1440px viewport; detailed posture screenshots are focused panel captures at that viewport width:

- [Overview partial, 1440px](design-system/screenshots/ui04/overview-partial-1440.png)
- [Overview partial, 390px](design-system/screenshots/ui04/overview-partial-390.png)
- [Overview posture unavailable, 1440px](design-system/screenshots/ui04/overview-posture-unavailable-1440.png)
- [Posture scorecard available, 1440px](design-system/screenshots/ui04/posture-scorecard-available-1440.png)
- [Posture scorecard empty, 1440px](design-system/screenshots/ui04/posture-scorecard-empty-1440.png)

Validation refreshed on 2026-10-24:

- `npm run typecheck` — passed for application and E2E TypeScript projects.
- `npm run build -- --outDir C:/Users/aryam/AppData/Local/Temp/CyberLens-UI04-20261024-dist` — passed; Vite transformed 679 modules in 5.09 seconds. Output: CSS 107.51 kB (21.60 kB gzip), main JavaScript 367.62 kB (101.83 kB gzip), lazy login globe 3.40 kB (1.46 kB gzip), and lazy charts 398.47 kB (109.51 kB gzip). Vite emitted an informational notice that it does not empty an output directory outside the project; build exit code was 0. These are emitted asset sizes, not runtime performance measurements.
- `npm run smoke:e2e -- e2e/ui-design-system.spec.ts e2e/posture-scorecard.spec.ts --reporter=list --output C:/Users/aryam/AppData/Local/Temp/CyberLens-UI04-20261024-e2e-final` — 19/19 Playwright tests passed in Chromium (52.7 seconds). Coverage includes existing fixture values and destinations, partial/empty/unavailable states, exports and role restrictions, mobile/tablet/desktop overflow, long content, chart policy separation, reduced motion, retry behavior, and login geometry/form preservation at 390px, 768px, and 1440px. API responses are mocked; these are browser UI checks, not backend integration or Live-provider checks. The test's unavailable-state viewport was set explicitly to 1440px so the screenshot matches its filename.
- Refreshed captures: overview partial at 1440×2013 and 390×3655; overview with unavailable posture at 1440×1815; available and empty posture panel captures at 1088×1863 and 1088×1517 respectively. These are full-page or focused-panel PNG dimensions, not viewport sizes.
- No backend, API, database, authentication, authorization, scoring, collector, monitoring, dependency, report-generation, feature component, or application stylesheet changed. The only test source adjustment sets the unavailable overview screenshot viewport to 1440×1000. Login styling and `WorkspaceGraphic` files were not edited; `.login-story` remains hidden at widths up to 680px.

## UI-05 analytical interface presentation

The investigation result surface now gives its history/result panels, saved risk coverage, collector and attempt rows, running progress, evidence disclosures, applicability review controls, findings, and comparison output clearer spacing and readable type. Decision reason fields occupy their own row, while the existing three applicability actions remain side by side where space allows and wrap at narrow widths. Existing severity and monitoring status classes still drive the same semantic colors and labels.

Monitoring schedule cards distinguish the next and last run fields from actions and history. Change Radar entries keep their existing unknown/no-removal caveat visible. The graph keeps the existing SVG nodes, evidence-role line styles, filter/search controls, viewport state, list alternative, reduced-motion behavior, keyboard controls, and 120-node/240-edge animation threshold. The list view now highlights the selected item; direct links remain solid and contextual relationships dashed. Chart series use the workspace's indigo/lilac plus restrained teal/amber/pink palette, with stronger grid/tick/tooltip contrast. Chart scales, values, null gaps, policy-version separation, exact-value disclosures, lazy loading, and one-time/reduced-motion animation remain unchanged.

Before/after captures use the focused Playwright tests' isolated synthetic fixtures and mocked API responses; they are not saved workspace data or live provider results:

- [Investigation presentation before](design-system/screenshots/ui05/before/investigation-desktop.png) · [after, desktop](design-system/screenshots/ui05/after/investigation-desktop.png) · [after, tablet](design-system/screenshots/ui05/after/investigation-768.png) · [after, mobile](design-system/screenshots/ui05/after/investigation-390.png)
- [Graph before](design-system/screenshots/ui05/before/evidence-graph-interactive-desktop.png) · [graph after](design-system/screenshots/ui05/after/evidence-graph-interactive-desktop.png) · [accessible list after](design-system/screenshots/ui05/after/evidence-graph-accessible-list-desktop.png) · [graph after, mobile](design-system/screenshots/ui05/after/evidence-graph-390.png)
- [Monitoring before](design-system/screenshots/ui05/before/monitoring-change-radar.png) · [monitoring and Change Radar after](design-system/screenshots/ui05/after/monitoring-change-radar.png)
- [Posture charts before](design-system/screenshots/ui05/before/posture-charts-desktop.png) · [risk history chart after](design-system/screenshots/ui05/after/risk-history-chart.png)

Validation on 2026-10-24:

- Baseline `npm run typecheck` — passed for application and E2E TypeScript projects. Baseline `npm run build -- --outDir C:/Users/aryam/AppData/Local/Temp/CyberLens-UI05-before-20261024-dist` — passed. Assets were CSS 107.51 kB (21.60 kB gzip), entry JS 367.62 kB (101.83 kB gzip), charts 398.47 kB (109.51 kB gzip), and login background 3.40 kB (1.46 kB gzip).
- Baseline focused browser command `npm run smoke:e2e -- e2e/evidence-graph.spec.ts e2e/monitoring.spec.ts e2e/posture-scorecard.spec.ts e2e/ui-design-system.spec.ts --reporter=list --output C:/Users/aryam/AppData/Local/Temp/CyberLens-UI05-before-20261024-e2e` — 24/24 passed in 1.2 minutes. API responses were mocked.
- After `npm run typecheck` — passed. After `npm run build -- --outDir C:/Users/aryam/AppData/Local/Temp/CyberLens-UI05-20261024-dist` — passed. Assets were CSS 113.68 kB (22.65 kB gzip), entry JS 367.62 kB (101.83 kB gzip), charts 399.01 kB (109.59 kB gzip), and login background 3.40 kB (1.46 kB gzip). Relative to the same-run baseline, CSS increased 6.17 kB raw (1.05 kB gzip), the lazy charts chunk increased 0.54 kB raw (0.08 kB gzip), and entry/login chunks did not change. No dependency was added.
- After focused browser command `npm run smoke:e2e -- e2e/evidence-graph.spec.ts e2e/monitoring.spec.ts e2e/posture-scorecard.spec.ts e2e/ui-design-system.spec.ts --reporter=list --output C:/Users/aryam/AppData/Local/Temp/CyberLens-UI05-after-20261024-e2e` — 24/24 passed in 2.0 minutes. A final monitoring screenshot-only rerun passed 2/2, and an isolated graph rerun passed 3/3. These tests cover graph navigation/filter/selection/provenance and responsive overflow; analyst/viewer monitoring permissions and schedule actions; chart values, policy separation, color, and motion; and investigation applicability drafts and polling. They are mocked browser tests, not backend or provider integration tests.
- The existing deterministic graph profile reported on Windows x64 with an Intel Core i7-13620H, 16 logical CPUs, 16,890,322,944 system-reported memory bytes, Chromium 156.0.8078.4, and 1280×720 viewport. The pre-style single run measured render/search intervals of 352.0/190.8 ms (20/28), 395.0/252.5 ms (120/240), and 721.1/417.2 ms (400/800). The final isolated run measured 570.3/537.4 ms, 945.8/628.4 ms, and 1,658.7/936.1 ms respectively; the full focused run measured similar values. These single local samples varied substantially and do not prove that styling caused or improved performance. Existing full/simplified rendering thresholds were not changed; the tested upper profile remains 400 nodes/800 edges.
- The regression suite's login preservation test passed at 390px, 768px, and 1440px. No login styles, diagram markup, feature JSX, API types, backend source, provider requests, or dependencies changed. Existing login visibility at widths up to 680px is unchanged.

## UI-06 remaining workflow presentation

The existing Assets, Incidents/ATT&CK, Remediation, Threat model, Integrations, Reports, Integrity, and Administration screens now use more consistent spacing, input sizing, surface hierarchy, status metadata, long-value wrapping, and responsive controls. These refinements remain scoped to the authenticated workspace. ATT&CK mapping provenance and review actions now share space more evenly on wide incident panels and stack at narrower sizes. Account details, CPE fields, evidence identifiers, feed metadata, and integrity hashes can wrap without widening the page.

Before/after captures use the existing test harness with synthetic fixtures and mocked API responses. They do not contain saved workspace data or live provider results. The `before` captures were taken before UI-06 CSS changes; the `after` captures were refreshed after the final CSS and screenshot adjustments:

- [Assets before](design-system/screenshots/ui06/before/screen-assets-1440.png) · [after](design-system/screenshots/ui06/after/screen-assets-1440.png) · [long asset after](design-system/screenshots/ui06/after/ui06-long-asset-desktop.png)
- [Incidents before](design-system/screenshots/ui06/before/screen-incidents-1440.png) · [after](design-system/screenshots/ui06/after/screen-incidents-1440.png) · [ATT&CK review after](design-system/screenshots/ui06/after/ui06-attack-matrix.png) · [catalog administration after](design-system/screenshots/ui06/after/ui06-attack-catalog.png)
- [Remediation before](design-system/screenshots/ui06/before/screen-remediation-1440.png) · [after](design-system/screenshots/ui06/after/screen-remediation-1440.png)
- [Threat model before](design-system/screenshots/ui06/before/screen-threat-model-1440.png) · [after](design-system/screenshots/ui06/after/screen-threat-model-1440.png)
- [Integrations before](design-system/screenshots/ui06/before/screen-integrations-1440.png) · [after](design-system/screenshots/ui06/after/screen-integrations-1440.png) · [feed status and refresh permissions after](design-system/screenshots/ui06/after/ui06-integration-feeds.png)
- [Reports before](design-system/screenshots/ui06/before/screen-reports-1440.png) · [after](design-system/screenshots/ui06/after/screen-reports-1440.png)
- [Integrity before](design-system/screenshots/ui06/before/screen-integrity-1440.png) · [after](design-system/screenshots/ui06/after/screen-integrity-1440.png) · [verified-chain and export after](design-system/screenshots/ui06/after/ui06-integrity-verified.png)
- [Administration before](design-system/screenshots/ui06/before/screen-admin-1440.png) · [after](design-system/screenshots/ui06/after/screen-admin-1440.png) · long account details [desktop](design-system/screenshots/ui06/after/ui06-admin-users-desktop.png) and [mobile](design-system/screenshots/ui06/after/ui06-admin-users-mobile.png)

Validation on 2026-10-24:

- Baseline `npm run typecheck` — passed. The baseline empty-screen Playwright case passed 1/1 in 17.2 seconds and captured the ten listed screen states at 1440px before editing; it also checked page overflow at 390px, 768px, and 1440px.
- Final `npm run typecheck` — passed for application and E2E TypeScript projects.
- Final `npm run build` — passed; Vite transformed 679 modules in 26.03 seconds. Output: CSS 125.07 kB (24.11 kB gzip), entry JavaScript 367.62 kB (101.83 kB gzip), lazy charts 399.01 kB (109.59 kB gzip), and lazy login background 3.40 kB (1.46 kB gzip). This is the current emitted bundle size; no dependency was added and no controlled UI-06 before/after bundle benchmark was run.
- Final focused command `npm run smoke:e2e -- e2e/ui-design-system.spec.ts e2e/attack-matrix.spec.ts e2e/attack-catalog.spec.ts e2e/integrity.spec.ts e2e/spamhaus-drop.spec.ts e2e/openphish.spec.ts --reporter=list --output C:/Users/aryam/AppData/Local/Temp/CyberLens-UI06-final-20261024-e2e` — 25/25 Chromium tests passed in 2.0 minutes. API responses were mocked. Checks include route/overflow states at 390px, 768px, and 1440px, long asset/account values, retained account actions, asset draft preservation, analyst ATT&CK review/override, administrator catalog/feed operations, viewer restrictions, integrity export permissions, report-list state, retry/empty/unavailable states, and login diagram/form preservation.
- A final focused ATT&CK screenshot rerun passed 1/1 after changing only the capture method to avoid the fixed-shell artifact in a full-page Chromium screenshot. All browser checks ran against local Vite/Chromium with mocked API responses; no backend, database, provider, report-generation/download, or real saved-record workflow was exercised.
- No feature JSX, event handler, API request/payload/type, permission, form validation, report renderer, login style, backend source, or database file changed. Existing reports and saved records were not opened or modified. The login preservation regression passed at 390px, 768px, and 1440px; `.login-story` remains hidden at widths up to 680px.

## UI-07 motion consistency

Motion remains in the existing `motion.ts` hooks and the design-system stylesheet. The existing fast, route, and panel durations remain 150ms, 220ms, and 240ms. The established card (180ms), drawer (200ms), backdrop (160ms), and loading shimmer (1.6s) timings are now named tokens and are shared by their existing CSS call sites. Graph node entry uses the route token; comparison change entry and workspace notices use the panel token. Overview card staggering remains 16ms per card, capped at 96ms. TextRoll, score-ring/chart entrances, and the 120-second decorative login globe keep their existing timings and behavior.

Route reveals still run once per route entry, skip focused panels, and do not restart during polling. Their observer cleanup now also removes the per-element reveal-delay style values. The sticky-header scroll listener, reduced-motion media listener, application preference observer, chart entrance timers, graph effects, and login globe listeners/observer retain their existing teardown behavior. Reduced motion continues to make page content immediately visible and disables nonessential CSS/JavaScript movement. Workspace notices enter with a short opacity/transform transition; their text is fully present throughout. No data, operational text, scores, evidence, or numeric values are animated.

Validation on 2026-10-24:

- `npm run typecheck` — passed for application and E2E TypeScript projects.
- `npm run build -- --outDir C:/Users/aryam/AppData/Local/Temp/CyberLens-UI07-20261024-dist` — passed; Vite transformed 679 modules. Output: CSS 125.52 kB (24.17 kB gzip), entry JavaScript 367.79 kB (101.88 kB gzip), lazy charts 399.01 kB (109.59 kB gzip), and lazy login background 3.40 kB (1.46 kB gzip). Build output was written outside the repository.
- `npm run smoke:e2e -- e2e/ui-design-system.spec.ts e2e/posture-scorecard.spec.ts e2e/evidence-graph.spec.ts e2e/brand-identity.spec.ts e2e/login-globe.spec.ts --reporter=list --output C:/Users/aryam/AppData/Local/Temp/CyberLens-UI07-final-combined-20261024-e2e` — 35/35 Chromium tests passed in 2.0 minutes. These used mocked API responses and local Vite; no backend or external provider was contacted. Coverage included polling without replay, CSS and JS reduced-motion states, observer failure, route/sign-out listener cleanup, TextRoll stability, graph effects, chart entrance behavior, and login diagram/globe preservation.
- Browser console page errors during the new repeated-navigation/sign-out lifecycle check — none. The observer-failure check confirmed content remains visible and reveal-delay styles are cleaned up.
- During validation, the first type check exposed test-only TypeScript casts, and the first combined browser run exposed two assertions that did not account for multi-property duration output and a duplicate visible Assets action. Those test issues were corrected; the final type check and combined browser run above passed.
- No animation library, dependency, application route, feature JSX, login styles, API contract, backend source, or database file changed. Existing `prefers-reduced-motion` and the saved application preference both disable nonessential movement. Browser tests use deterministic synthetic fixtures; these results do not claim backend or live-provider behavior.

## UI-09 final redesign validation

### Source and preservation review

The current checkout has no Git commit (`HEAD` is absent) and `git ls-files` reports an empty index; every project file is untracked. `git diff` therefore cannot reconstruct or independently verify the complete UI-01–UI-08 change set. I inspected the current UI implementation and prior module records instead. This UI-09 pass changed this document only. No backend, API, generated type, schema, security, dependency, application, `.env`, or data file was edited in this pass. The existing `.env` was left untouched.

The current generated frontend API definitions match a fresh `openapi-typescript` generation from `backend/openapi.json` (`Compare-Object` found no differences). The current frontend dependency tree resolves with `npm ls --depth=0`; it contains the existing React, Vite, TypeScript, Playwright, OpenAPI generator, and Recharts stack. No 3D/WebGL library is installed. Historical module records likewise describe UI changes as presentation-scoped, but the absent Git baseline means that assertion cannot be checked against a repository diff here.

The UI-00 SVG markup hash recorded by the preservation tests is `44e80fa6ef682f2b9e82dc8ff3be593ba5aedfb3020026d4e39683a2e068fd17`. Existing UI-01/UI-02/UI-08 browser runs assert the original diagram labels, SVG hash, breakpoint visibility, login card and field styles, and geometry. The last recorded successful UI-08 combined run passed 35/35 before the final test-only edge-alignment assertion was added; a new execution of that final assertion was blocked by the local test-server restriction recorded below. Visual comparison of the available baseline/current captures shows the original diagram, caption, and login form in their prior positions and proportions. The globe is the intended separate decorative layer behind the login content. At widths up to and including 680px, the existing `.login-story` rule still hides the diagram.

Before/after captures already present in the workspace:

- Login: [UI-00/UI-01 baseline at 1440px](design-system/screenshots/ui01/before-login-1440.png), [current login at 1440px](design-system/screenshots/ui08/login-1440.png), [current login at 390px](design-system/screenshots/ui08/login-390.png), and [current 680px login with the diagram hidden](design-system/screenshots/ui08/login-680-diagram-hidden.png).
- Overview: [earlier 1440px overview](design-system/screenshots/before/overview-1440.png), [current 1440px overview](design-system/screenshots/ui08/workspace-1440.png), [current 768px overview](design-system/screenshots/ui08/workspace-768.png), and [current 390px overview](design-system/screenshots/ui08/workspace-390.png).
- Other presentation states: [partial overview](design-system/screenshots/ui04/overview-partial-1440.png), [interactive evidence graph](design-system/screenshots/ui05/after/evidence-graph-interactive-desktop.png), [long mobile error](design-system/screenshots/ui08/long-error-390.png), and [accessible graph list](design-system/screenshots/ui05/after/evidence-graph-accessible-list-desktop.png).

### Globe and application behavior

The login globe is a local SVG with a CSS transform animation, not a Three.js scene. It has no canvas, WebGL context, GPU texture, external asset request, or JavaScript render loop. Consequently WebGL unavailability and WebGL context loss do not apply. A lazy-component error and a failed local image use static fallback artwork; reduced motion and the saved motion preference show a static globe; pause/resume is keyboard accessible; hidden-document and offscreen states pause movement. The prior Playwright globe coverage also checks resize at 390/768/1440px and repeated login/logout without canvas accumulation. These checks passed in the prior recorded UI-08 combined run; they were not rerun in this UI-09 environment.

The current production build emits the lazy globe JavaScript chunk at 3.40 kB (1.46 kB gzip). The local SVG is 4,156 bytes, and its stylesheet is 3,032 bytes. There is no recurring JavaScript frame work or WebGL resource to dispose. No CPU/frame-time benchmark was run.

The previously recorded mocked browser checks cover login payload and password-change UI, logout, role-specific navigation, assets, investigation polling and review, Change Radar, incidents and tasks, monitoring controls, remediation, report lists, integrity export permissions, integrations, administration, keyboard navigation, reduced motion, and chart/graph text alternatives. Those are UI/API-mock checks, not a current real-backend workflow. The dated `docs/debug-preview.md` result from 2026-10-20 is historical and was not reused as a result of this validation run.

### Checks run on 2026-10-24

- `npm run typecheck` — passed for the application and E2E TypeScript projects.
- `npm run build -- --outDir C:/Users/aryam/AppData/Local/Temp/CyberLens-UI09-20261024-dist` — passed; Vite transformed 679 modules. Emitted CSS was 125.69 kB (24.20 kB gzip), entry JavaScript 367.79 kB (101.88 kB gzip), lazy globe 3.40 kB (1.46 kB gzip), and lazy charts 399.01 kB (109.59 kB gzip). The output was outside the workspace.
- `npm ls --depth=0` — passed with the existing dependency tree; no dependency was added in UI-09.
- Temporary OpenAPI type generation and comparison — passed; generated types match the existing generated source file in the workspace.
- `docker compose --env-file .env.example --project-name cyberlens-ui09-validation -f docker-compose.yml -f docker-compose.verify.yml config --quiet` — passed. This validates configuration only; it did not start containers or mount volumes.
- `docker info --format '{{.ServerVersion}} {{.OperatingSystem}}'` — blocked: Docker could not connect to `//./pipe/dockerDesktopLinuxEngine` because the engine pipe is absent. No isolated PostgreSQL/Redis/worker stack or real backend test was started; no Compose volume was created, removed, or recreated.
- `npm run workflow:e2e -- --list` — passed and discovered 55 tests in 16 files. `npm run workflow:e2e -- --reporter=list --output C:/Users/aryam/AppData/Local/Temp/CyberLens-UI09-workflow-20261024` did not produce a test result; the local web server did not become reachable and the stalled run was stopped. The focused `npm run smoke:e2e -- e2e/ui-design-system.spec.ts --grep "UI-08" --reporter=list --output C:/Users/aryam/AppData/Local/Temp/CyberLens-UI08-loopback-20261024-e2e` ended with `Timed out waiting 30000ms from config.webServer`. `Invoke-WebRequest http://127.0.0.1:5173/` reported `An attempt was made to access a socket in a way forbidden by its access permissions.` Therefore no current UI-09 browser result or real-stack workflow result is claimed.
- Manual review of stored screenshots covered login and overview at 390/680/768/900/1440px, the mobile long-error state, partial overview data, and the graph plus its list alternative. This review is separate from automated tests. There was no fresh browser console session, screen-reader audit, native browser zoom check, second browser engine, physical-device check, or accessibility certification. The 720/1152 CSS-width captures approximate zoom reflow but are not native browser zoom tests.

No additional presentation regression requiring a source edit was confirmed from the reviewed screenshots and prior passing UI tests. Remaining verification blockers for that UI-09 run were the missing Git baseline, unavailable Docker engine, and denied local loopback for Playwright's Vite server. The prior tests and screenshots remain labeled as prior evidence rather than results newly produced by that run.

## 2026-10-24–25 reference and working-animation follow-up

All UI-00–UI-09 instructions and the seven supplied references were reviewed against the actual implementation. This follow-up fixes the effects that appeared static: real per-letter CyberLens SVG writing, a visible time-based dashboard orb with an animated CSS fallback, keyboard pause/replay controls, late-arriving panel reveals, and clearer authenticated TextRoll/control feedback. Existing component architecture, palette, security semantics, form state, values, routes, graph/chart behavior, and protected login content are retained. No dependency was added.

New validation: application/E2E type-check and production build passed; **58 mocked production browser tests passed in 3.3 minutes**; a clean development chart run passed **5/5**. The original UI-00 SVG hash, geometry, colors, typography, keyboard order, and <=680px hidden diagram behavior passed. Public login on the updated local Live frontend loaded without browser errors and readiness was healthy. Historical backend/full-stack results above are not new results of this pass.

See [complete commands, preservation comparison, bundle/runtime samples, source list, failure resolutions, and limitations](ui-motion-verification-20261025.md), [reference/module analysis](ui-reference-analysis.md), and the [recorded motion preview](design-system/screenshots/ui-motion-20261025/after/video.webm). Fresh responsive stills: [desktop](design-system/screenshots/ui-motion-20261025/after/motion-overview-1440.png), [tablet](design-system/screenshots/ui-motion-20261025/after/motion-overview-768.png), [phone](design-system/screenshots/ui-motion-20261025/after/motion-overview-390.png), and [public Live login](design-system/screenshots/ui-motion-20261025/after/live-public-login-1440.png). Preview data uses mocked fixtures; no user records were changed.

### Later 2026-10-25 presentation follow-up

The decorative title now keeps a restrained moving highlight after its one-time writing entrance. Its seven-second cycle affects only background lettering; original TextRoll/logo behavior and operational values stay unchanged. The login's existing keyboard pause control now pauses the globe and decorative lettering together. Reduced motion/data saving disable the highlight, and hidden/offscreen states pause it. Only decorative state and sibling props changed in `LoginScreen`; its diagram/form markup and typography/layout rules remain protected. See [current startup, final validation, and panel-review instructions](debug-review-20261025.md).


### 2026-10-26 spherical Earth and explicit decorative motion

The current login globe rotates geographic points around a 3D sphere using a small lazy Canvas2D module, replacing the historical flat SVG spin described in UI-02 above. Local SVG remains the fallback. The animated scene adds sparse moving connection lights and a subdued atmospheric rim; none is security telemetry. Reduced-motion users start static and can explicitly choose **Enable effects** for decorations only. This opt-in also enables the dashboard orb and title while original form, diagram, branding, chart, and navigation motion policies remain unchanged. Data saving still disables renderer work. See [implementation, exact checks, bundle impact, and captures](digital-earth-effects-20261025.md).
