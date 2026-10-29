# Dashboard reference effects — 2026-10-26

The supplied “Aegis Security — Remixed Bento” HTML is adapted into the existing React dashboard. Its three visual motifs appear together in a compact decorative strip above the real scorecard: a rotating connected sphere, floating geometric layers, and a radial halftone ripple. CyberLens retains its Arctic Graphite/indigo palette and system fonts. The reference's marketing claims and example product identity are not application functionality.

## Implementation

- `frontend/src/components/DashboardBentoScene.tsx`: React component and effect lifecycle, existing shared motion gate, local static SVG fallback, lazy renderer import, failure/context-loss handling, cleanup.
- `frontend/src/components/dashboard-bento-renderer.ts`: deterministic 96-point spherical topology with depth shading, local layered geometry, and time-based ripple. A single Canvas2D loop runs at a maximum of 30 rendered frames per second, caps DPR at 1.5 and buffer width at 1600px, and performs no per-frame React state updates.
- `frontend/src/components/dashboard-bento-scene.css`: isolated decorative frame, fine grain, separators and responsive dimensions. All decorative layers are aria-hidden and pointer-transparent.
- `frontend/src/features/overview.tsx`: inserts the scene and passes the existing pause/reduced-motion state. The same Pause/Resume background control governs the scene, orb and lettering. No metrics, data queries, filters, routes or actions are changed.
- `frontend/src/design-system.css`: authenticated panels receive consistent hover elevation and a distinct focus-within border. The focus treatment takes precedence over hover. Existing reveal, button, navigation and disclosure motion remains on the current motion system.

Reduced motion and data saving skip the renderer import. Explicit decorative opt-in remains available through the existing control. Hidden/offscreen rendering pauses; unmount disposes RAF, resize listeners and observers. Static SVG remains available if the lazy module or canvas fails. No CDN resources, remote image, external font, GSAP, Tailwind, Three.js or icon package was added. The reference's geometric image is recreated locally in code.

The protected login form, WorkspaceGraphic, original branding, and <=680px diagram visibility rule are outside these changes. Existing backend, authentication, provider behavior, evidence and reports remain attached to their original implementation.

## Verification

Tests use mocked API fixtures on a local frontend, never writes against the normal Live database. Existing login preservation and UI assertions remain; the combined renderer cleanup test now also loses the new canvas context before asserting that every dashboard RAF has stopped.

The new tests compare actual canvas pixels before/after movement, require identical pixels while paused, verify resume, cover 390/680/768/900px overflow, confirm no renderer request under reduced motion, and abort the lazy import to check fallback and continued navigation. Existing renderer tests cover hidden/offscreen gating and repeated navigation cleanup.

- [Desktop capture](design-system/screenshots/reference-bento-20261026/reference-bento-desktop.png)
- [Mobile capture](design-system/screenshots/reference-bento-20261026/reference-bento-390.png)
- [Recorded animated test](design-system/screenshots/reference-bento-20261026/video.webm)

These captures show mocked empty workspace data. The scene is entirely decorative.

Actual checks on 2026-10-26:

- `npm run typecheck` passed, including the added E2E cases.
- `npm run build -- --outDir C:/Users/aryam/AppData/Local/Temp/cyberlens-bento-dist-20261026` passed: 687 modules. New lazy renderer: 2.33kB / 1.27kB gzip; entry JS: 380.84kB / 107.02kB gzip. No dependency or lockfile changes.
- `CYBERLENS_BROWSER_CHANNEL=chrome npx playwright test e2e/brand-identity.spec.ts e2e/ui-design-system.spec.ts e2e/login-globe.spec.ts --reporter=line --output=C:/Users/aryam/AppData/Local/Temp/cyberlens-bento-tests-20261026` passed **46 tests in 4.6 minutes**. All API responses in this run were mocked. [Complete log](design-system/screenshots/reference-bento-20261026/browser-tests.log).
- Existing viewport/breakpoint and protected-login computed-style checks passed without regenerating baselines. The measured text contrast sample minimum was 4.62; focus indicator ratio was 8.76. These checks are not accessibility certification.
- The previous Live frontend was retained as `cyberlens-frontend:before-reference-bento-20261026` before rebuilding.
- `docker compose --project-name cyberlens build frontend` passed with the final focus-priority CSS. `docker compose --project-name cyberlens up -d --no-deps --wait --wait-timeout 60 frontend` replaced only the frontend and reported healthy. The served entry is `index-CgHzxmy0.js` and CSS `index-DVOoBbzO.css`.
- A read-only request to `/api/v1/health/ready` returned `status: ready`, `mode: live`, `demo_data: false`, and true database/Redis/worker dependencies. No Live account login or operational test writes were performed.
- Final served-production check: `CYBERLENS_BROWSER_CHANNEL=chrome CYBERLENS_BASE_URL=https://localhost:8443 npx playwright test e2e/brand-identity.spec.ts --grep 'reference Bento scene|dashboard renderer advances real time' --reporter=line` — **3 passed in 24.8 seconds**. The browser used the actual served production assets, with every API request mocked. Pixel movement, pause/resume, static/import-failure fallback, responsive fit, context-loss and repeated navigation cleanup passed. [Production log](design-system/screenshots/reference-bento-20261026/production-tests.log).
