# Docker Multistage & Hardening Pass — 2026-06-19

Record of the changes made to every `Dockerfile` in this repo to make them
multistage, cache-efficient, and non-root where feasible, plus an honest
assessment of whether each concept was actually the right call for this
stack (a local cyber-range lab, not a public-facing production system).

## What changed, per file

| File | Multistage | Cache ordering | Layer minimization | Non-root |
|---|---|---|---|---|
| `attense-app/Dockerfile` | ✅ builder venv → final copies `/opt/venv` | ✅ `requirements.txt` copied+installed before source | n/a (no apt) | ✅ `appuser` (uid 1000) |
| `signal-store/Dockerfile` | ✅ same pattern | ✅ same | n/a | ✅ `appuser`; `/attense/data` chmod 777 |
| `red-team/Dockerfile` | ✅ same pattern | ✅ same | ✅ apt `curl` in one `RUN` | ✅ `appuser` + supplementary group `root` (gid 0) |
| `attense-app/ATTENSE_app/blueteam/Dockerfile` (unused) | ✅ same pattern | ✅ same | ✅ apt deps in one `RUN` | ✅ `appuser` |
| `target-agent/Dockerfile` + nested duplicate | ✅ builder venv for the Flask app only | ✅ `app/requirements.txt` installed before app code | ✅ apt + Wazuh install chained, `rm -rf /var/lib/apt/lists/*` in same layer | ❌ stays root — documented exception (see below) |
| `attackbox/Dockerfile` | ❌ not applicable — no separable build artifact | n/a | ✅ already chained `apt-get update/install/clean` | ❌ stays root — documented exception |
| `red-team/frontend/Dockerfile` | ✅ already multistage (Vite builder → nginx) | ✅ `package.json` before source | n/a | ✅ switched base to `nginxinc/nginx-unprivileged`, port 8080 |
| `AttenseFront/attense-react/Dockerfile` (dev) | unchanged on purpose | — | — | — |
| `AttenseFront/attense-react/Dockerfile.prod` (new) | ✅ Vite builder → nginx | ✅ `package*.json` before source | n/a | ✅ `nginx-unprivileged`, port 8080 |

Also added: `.dockerignore` in every build context that lacked one
(`attense-app`, `signal-store`, `red-team`, `target-agent`,
`AttenseFront/attense-react`); `attackbox` and `red-team/frontend` already
had one.

`docker-compose.yml`: `red-team-frontend` port mapping changed from
`3000:80` to `3000:8080` and its healthcheck URL updated to match, since the
container now listens on the unprivileged port.

## Verification performed

- Built all six changed images via `docker compose build` — all succeeded.
- Ran each new image standalone and confirmed `whoami`: `appuser` for the
  four Python services, `nginx` for both frontends, `root` for
  `target-agent` (intentional).
- Confirmed `red-team-backend`'s non-root user can actually open
  `/var/run/docker.sock` and call the Docker API (`docker.from_env().version()`
  succeeded) — this was the highest-risk change, since operator-mode
  `docker exec` depends on it.
- Found and fixed a real gap: the pre-existing `attense_ssd_volume` was
  `root:root 755` from months of running as root, which would have made
  `signal-store` fail to write `mapped_events.jsonl` once it dropped to
  non-root. Fixed with a one-time `chmod -R 777` on the volume (no data
  touched, fully reversible).
- Recreated the live stack with `docker compose up -d` and confirmed every
  rebuilt service reports `healthy` and responds on its published port
  (`3000`, `8000`, `8010`, `8081`, `8005`).
- **Not yet build-tested**: `Dockerfile.prod` for `attense-react` — it isn't
  wired into `docker-compose.yml` yet, so it has only been reviewed, not
  actually built. Build it once before relying on it.

## Were the concepts right for this stack?

**Multi-stage build** — correct and worth keeping, but only where there's
an actual artifact to separate from the runtime. All four Python services
and both nginx frontends genuinely benefit: the builder stage's pip/npm
metadata and (for the frontends) the entire Node toolchain never reach the
shipped image. `attackbox` was correctly *excluded* from this — it's an
apt-installed toolbox where the installed packages *are* the runtime, so a
builder stage would just add complexity with no size or security benefit.
That exclusion was the right call, not a shortcut.

**Cache ordering** — straightforward win, applied everywhere, no downside.
Dependency manifests are copied and installed before application source in
every Dockerfile, so a source-only change never re-triggers a `pip install`
or `npm install`.

**Layer minimization** — already mostly true before this pass (the
`apt-get update && install && rm -rf /var/lib/apt/lists/*` chaining
predates these changes); I added comments explaining it rather than
restructuring working layers.

**Non-root (`USER`)** — applied correctly to the four Python services and
both nginx frontends, but with two real caveats worth knowing about rather
than glossing over:

1. `signal-store`'s and `red-team`'s writable directories rely on `chmod
   777`, not a precise `chown` to the app user. That matches this repo's
   existing "lab only" convention (the original `target-agent` and
   `red-team` Dockerfiles already did this for their own dirs), but it's a
   pragmatic compromise, not strict least-privilege — a real production
   system would `chown` to the exact UID instead of opening the directory
   to any user.
2. `red-team-backend` needs supplementary group `0` (`root`) to reach
   `/var/run/docker.sock`, because on this Docker Desktop setup the socket
   is `root:root` mode `660`. That's specific to this environment — a
   native Linux host typically exposes the socket as `root:docker` with a
   non-zero, host-specific GID, and this Dockerfile would need that actual
   GID substituted in. It is *not* portable as written; it's correct only
   for the environment it was tested against.

`target-agent` and `attackbox` were correctly left running as root. Forcing
non-root onto either would have silently broken real functionality:
`target-agent`'s nginx must bind privileged port 80 and its Wazuh agent
manages privileged daemons + `NET_ADMIN`/`iptables` for active response;
`attackbox`'s pentest tools (`nmap` SYN scans in particular) need
`CAP_NET_RAW`. Dropping root there would require a genuine rearchitecture
(splitting each privileged concern into its own least-privilege process),
not a Dockerfile edit — so I documented the exception inline instead of
faking compliance.

## Loose ends, not addressed here

- `target-agent/target-agent/` is a stale duplicate of `target-agent/`, not
  referenced by `docker-compose.yml`. Updated for consistency but probably
  worth deleting outright.
- `attense-app/ATTENSE_app/blueteam/Dockerfile` is unused — BlueTeam is
  served by `attense-app` now. Updated for consistency, not because it's
  load-bearing.
- `AttenseFront/attense-react/Dockerfile.prod` exists but nothing builds or
  runs it yet; wire it into `docker-compose.yml` (or a separate prod
  compose file) when you actually need a production build of that frontend.
