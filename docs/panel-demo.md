# CyberLens panel demonstration

Use **offline Demo** for the main panel/conclave walkthrough. It exercises the application with clearly labeled synthetic fixtures and does not depend on provider credentials or network availability. Describe those results as synthetic examples, not real incidents or detected attacks. Use Live only as an optional, separately prepared demonstration with authorized targets and configured providers.

## Start Demo

Start Docker Desktop and wait for the engine to run. In PowerShell:

```powershell
cd "C:\Users\aryam\OneDrive\Documents\PROJECTS\CyberLens"
docker compose --project-name cyberlens stop
docker compose --project-name cyberlens-demo -f docker-compose.yml -f docker-compose.demo.yml up --build -d --wait --wait-timeout 180
```

Open **https://localhost:8443** and press **Ctrl+F5** after a rebuild. The initial Demo account is `admin` / `CyberLens-Demo-Only-2026!`, unless explicitly customized with `DEMO_BOOTSTRAP_ADMIN_*`. Existing accounts keep their changed passwords. Complete the first password change before the panel arrives. Preserve `.env` and existing volumes.

Follow logs in another terminal:

```powershell
docker compose --project-name cyberlens-demo -f docker-compose.yml -f docker-compose.demo.yml logs -f
```

Ctrl+C ends log following; the detached app keeps running. For a status check, replace `logs -f` with `ps`, or open **https://localhost:8443/api/v1/health/ready**. Six services expose container health checks; the dispatcher is a running process without a container health check.

## Rehearse the walkthrough

1. **Login and purpose:** explain the asset → evidence → analyst-review workflow. Show the decorative globe and CyberLens writing. The existing top-right pause control stops both background effects. The protected diagram remains hidden at <=680px, so use a desktop viewport for this introduction.
2. **Overview:** explain saved observations, assessment coverage, provider freshness, and unavailable/unassessed distinctions. Show the moving background and Pause/Resume/Replay controls. User menu → Reduce animations and the operating-system preference intentionally make effects static.
3. **Assets and investigation:** use Demo data and an offline scenario. Follow queued/running/completed progress and collector evidence. No fabricated operational counts are added to fill empty cards.
4. **Findings and graph:** show provenance, the direct/contextual relationship distinction, search/filter/zoom, the list alternative, and analyst applicability review. Describe prioritization as an explainable calculation, not proof of compromise.
5. **Incident and response:** show an evidence-linked case, timeline note, response task, and remediation plan. These record analyst decisions; they do not automatically contain a real system.
6. **Reports and roles:** generate/download a saved report, show integrity context, and demonstrate restricted Viewer controls with a prepared separate account. Do not display `.env`, provider keys, or private passwords on the projector.

For optional additive sample assets, run the existing command yourself before rehearsal:

```powershell
docker compose --project-name cyberlens-demo -f docker-compose.yml -f docker-compose.demo.yml exec api python -m app.cli seed-demo
```

Seeding adds Demo records; it is not needed to start the app and was not run against your normal Demo workspace during the debugging checks. Do not use reset commands or delete volumes for a presentation.

## Switch to Live

Both normal gateways use port8443, so stop Demo first:

```powershell
docker compose --project-name cyberlens-demo -f docker-compose.yml -f docker-compose.demo.yml stop
docker compose --project-name cyberlens up --build -d --wait --wait-timeout 180
```

Use your existing Live account. The Demo password is not a Live credential. Rebuilding does not reset account or database passwords. To return to Demo, stop `cyberlens` and use the Demo startup command above.

## If something fails

Check the failing service's logs. An API `password authentication failed` means configuration does not match the persisted PostgreSQL role. Demo now uses dedicated `DEMO_*` settings, preventing Live `.env` credentials from overriding published Demo defaults. A customized older Demo volume still needs its matching `DEMO_POSTGRES_*` values. **Do not use `down --volumes` as a repair.**

The application is a local research/analyst workspace. Automated test results establish the covered behavior; they do not establish production readiness, complete vulnerability coverage, or accessibility certification. See the dated verification records in [test results](test-results.md).


### Showing the current effects

After rebuilding, use Ctrl+F5. If the login shows **Reduced motion � Enable effects**, click it to opt into decorative animation for this page session. The same option is available in the dashboard. **Pause motion/Pause background** stops the decorations. The Earth rotates slowly while connection lights move more quickly; the original workflow diagram stays static. Data-saver mode intentionally retains a static scene. [Recorded deployed example](design-system/screenshots/digital-earth-20261025/public-digital-earth.webm).
