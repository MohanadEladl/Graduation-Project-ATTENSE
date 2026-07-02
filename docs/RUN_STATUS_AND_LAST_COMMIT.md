# Project Run Status and Latest Commit

Date checked: 2026-06-30

## Running the Project

The project was started from the repository root with:

```powershell
docker compose up -d
```

The dev overlay command was not used because `infra/compose.dev.yml` currently defines an `attense-react` service without an image or build context.

## Main Portals

- Red Team portal: http://127.0.0.1:3000
- Blue Team portal: http://127.0.0.1:3100

There is no separate unified `frontends/portal` directory in the current repo. The actual frontend apps present are:

- `frontends/red-team`
- `frontends/blue-team`

## Verified Endpoints

- Red Team API health: http://127.0.0.1:8000/health
- Control API health: http://127.0.0.1:8020/health

At the time of checking, the main UI and API paths were reachable. Some heavier security services were still initializing or reporting unhealthy in Compose status, including TheHive, Elasticsearch, Cassandra, Wazuh Manager, Postgres, and ZAP.

## Latest Top Commit Reviewed

Commit: `2d497059d3343693fd04ab6c8b0699b52a4ec139`

Short hash: `2d49705`

Branch: `refactor/restructure-and-pipeline-integration`

Author: `DarineNadaa`

Date: `2026-06-29T23:27:14+03:00`

Message:

```text
Remove design instruction source folder
```

## Latest Commit Changes

This commit removed the old design instruction source folder and its generated/design assets.

Deleted files:

- `Instructions for design setup/.thumbnail`
- `Instructions for design setup/assets/ATTENSELOGO.png`
- `Instructions for design setup/dashboard.dc.html`
- `Instructions for design setup/report.dc.html`
- `Instructions for design setup/rooms.dc.html`
- `Instructions for design setup/support.js`
- `Instructions for design setup/uploads/prompt_blueteam_pages.md`

Git reported:

```text
7 files changed, 2506 deletions(-)
```
## Portal UI Commit Reviewed

Commit: `a33b1f6994a30babc28bb98c8ccd45c9ca5b805f`

Short hash: `a33b1f6`

Date: `2026-06-29T21:29:29+03:00`

Message:

```text
Integrate portal roles and encrypted database storage
```

Frontend scope:

```text
9 files changed, 992 insertions(+), 410 deletions(-)
```

Portal and UI changes in this commit:

- Added Blue Team role/permission UI state, including default role permissions for CISO, SOC manager, SOC L1, SOC L2, and Red Team.
- Added a Blue Team admin permissions panel for granting and revoking permissions from the UI.
- Added notification/invitation state in the Blue Team app, including a sidebar notification trigger, a notification drawer, invitation badges, and local-storage synchronization.
- Updated the Blue Team portal demo flow so rooms can pass a TheHive launch URL into the Blue Team UI.
- Added Blue Team sidebar user/profile presentation with avatar, role text, and active status indicator.
- Updated Blue Team styling for the notification drawer, invitation cards, admin cards, permission pills, sidebar footer, and notification badges.
- Updated `frontends/portal/blue-report.html` so team and solo room entries carry a `hiveLaunchUrl` and pass it to the Blue Team UI.
- Removed the separate notification drawer markup from `blue-report.html`; notification display moved into the Blue Team UI flow.
- Updated `frontends/portal/red-login.html` so after the final login/role step it redirects to the Red Team UI at `http://127.0.0.1:3000/`.
- Added a new Red Team `GauntletIntro` animation component for the Gauntlet page.
- Reworked the Red Team Gauntlet route with a cinematic entrance, image-backed operation cards, revised phase tracking, and delayed section reveal animation.

Frontend files touched:

- `frontends/blue-team/src/App.jsx`
- `frontends/blue-team/src/styles.css`
- `frontends/portal/blue-report.html`
- `frontends/portal/red-login.html`
- `frontends/red-team/src/App.jsx`
- `frontends/red-team/src/components/GauntletIntro.jsx`
- `frontends/red-team/src/routes/Gauntlet.jsx`
- `frontends/blue-team/.npmrc`
- `frontends/red-team/.npmrc`

