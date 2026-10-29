# Digital Earth and accessible effects â€” 2026-10-25

This follow-up addresses the supplied screenshot showing a disabled **Static globe** control. The previous implementation rotated a flat SVG in the image plane. It did not rotate continents around a spherical axis. Static mode was selected by reduced motion, data saving, or asset failure; the screenshot alone cannot establish which browser preference caused it.

## Implementation

- Replaced the flat CSS spin with a locally authored dotted Earth, projected from longitude/latitude onto a sphere with fixed axial tilt. Continents revolve once per 120 seconds. Five sparse elevated connections carry moving light points. These connections are decorative, not detections or operational telemetry.
- `digital-earth.ts` is a separate lazy chunk. Canvas2D projects the 3D coordinates; no Three.js/React Three Fiber, GPU requirement, CDN texture, telemetry, package, or lockfile change is needed. Original simplified geographic silhouettes are bundled directly in that module. Existing local SVG remains the immediate static fallback.
- Pixel ratio is capped at 1.5 and the drawing buffer at 960 pixels per side. Rendering is limited to 30 frames/second, with elapsed-time rotation and no per-frame React state. Existing motion hooks stop work when paused, hidden, or offscreen. Cleanup cancels animation frames and removes resize observers/listeners; late imports cannot create a renderer after unmount.
- Renderer import failure, missing Canvas2D, context loss, or fallback asset failure leave login usable. WebGL being disabled does not prevent the Earth animation; the existing dashboard shader keeps its CSS fallback.
- Reduced motion still starts static and does not load the Earth renderer. The formerly disabled control now explains the setting and offers **Reduced motion Â· Enable effects**. This explicit opt-in enables decorative Earth, lettering, and dashboard orb for the current mounted app. It does not change saved preferences, protected logo/TextRoll behavior, chart motion, page transitions, or form styles. Changing the system motion preference or the application checkbox resets the opt-in. Data saving continues to prevent renderer work.
- The authenticated overview also exposes **Enable decorative motion** when appropriate. Existing pause/resume and title replay controls remain. CSS exceptions target only the opted-in decorations, including the fallback orb and title highlight.

## Scope and preservation

Runtime files: `frontend/src/components/digital-earth.ts` (new), `LoginGlobeBackground.tsx`, `LoginGlobeGate.tsx`, `login-globe.css`, `cyberlens-hello-effect.css`, `gradient-orb-background.css`, plus decorative state/props in `App.tsx` and decorative controls in `features/overview.tsx`. Focused tests are in `login-globe.spec.ts` and `brand-identity.spec.ts`.

The diagram, `.graphic-*` styles, form fields, handlers, authentication requests, original branding, backend, database, and API code were not edited. The existing <=680px hidden diagram rule remains. Tests retain the original UI-00 geometry/style/hash assertions; only renderer-specific assertions were updated from a CSS image spin to actual canvas pixels and render-loop state. No screenshot baseline was regenerated.

## Verification

- `npm run typecheck`: passed.
- `npm run build -- --outDir C:/Users/aryam/AppData/Local/Temp/cyberlens-digital-earth-dist-20261025`: passed, 684 modules, 14.39 seconds.
- Development browser run: `npx playwright test e2e/login-globe.spec.ts --reporter=line`: **10 passed in 1.3 minutes**, using isolated mocked API responses. Covers original login geometry/keyboard order at 390/768/1440px; changing canvas pixels and rotation; pause; reduced motion; explicit opt-in; hidden/offscreen stop; import/asset/context failure; no WebGL; repeated login/logout and detached renderer inactivity. One sample buffer was 749Ã—749. This is not a device benchmark.
- Production image build: `docker compose --project-name cyberlens-demo -f docker-compose.yml -f docker-compose.demo.yml build frontend`: passed; existing dependency-install layer reused.

Production bundle: CSS 134.25 kB /25.67 gzip; entry 379.12 /106.47; lazy background 3.90 /1.69; lazy Earth **4.43 /2.16**; charts unchanged at399.01 /109.59. Compared with the immediately preceding build, entry +0.76/+0.27, CSS +0.86/+0.06, background +0.50/+0.22 kB. Earth code is downloaded only when motion is allowed.

The prior frontend image is retained as `cyberlens-demo-frontend:before-digital-earth-20261025`. Existing earlier verification reports describe historical implementations and results.


## Production preservation and deployment — 2026-10-26

The 44-case production browser selection initially reported **42 passed / 2 failed**. One test still assumed logout left no render loop; it was updated to assert exactly one new login-globe loop, unchanged stopped dashboard draw count, and zero pending frames after pausing the globe. A parallel recheck and the empty-screen case hit the existing 30-second timeout. A final sequential recheck, with the original timeouts and remaining assertions, passed **2/2 in45.8seconds**. These failures are retained in the raw logs; the first run is not described as wholly passing.

The original UI-00 diagram hash, computed geometry, typography, form styling, responsive breakpoints, keyboard behavior, data-state distinctions, and motion cleanup checks passed. The supplied screenshot has been retained as before evidence. No golden snapshot was regenerated.

On 2026-10-26 Docker was stopped. Docker Desktop was started, and only the normal Demo frontend container was replaced with the already-built image. The deployed entry is **index-D9PZpShf.js**, CSS **index-BcK7xYUa.css**, lazy Earth **digital-earth-C3rMTLFC.js**. A fresh unauthenticated Chrome check on https://localhost:8443, starting with system reduced motion, clicked the explicit opt-in and measured **0.221676 radians** of rotation over approximately four seconds, changed canvas pixels, frozen frames during pause, resumed motion, and zero page exceptions. The normalized diagram hash remained **44e80fa6ef682f2b9e82dc8ff3be593ba5aedfb3020026d4e39683a2e068fd17**. No login credentials were submitted to the normal Demo workspace.

- [Reported static screenshot](design-system/screenshots/digital-earth-20261025/reported-static.png)
- [Deployed animated login](design-system/screenshots/digital-earth-20261025/public-animated-login.png)
- [Actual deployed motion recording](design-system/screenshots/digital-earth-20261025/public-digital-earth.webm)
- [Dashboard with explicit decorative motion](design-system/screenshots/digital-earth-20261025/dashboard-explicit-motion.png)

The broad UI-00–UI-09 workflow revalidation is recorded separately in [the final module review](ui-final-review-20261026.md). Historical backend and earlier browser counts are not new runs in this follow-up.
