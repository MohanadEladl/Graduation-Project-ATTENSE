# Known Issues

## 1. TheHive → BlueTeam webhook notifications do not fire (TheHive 4.1.24 CE)

**Status: RESOLVED (2026-06-16)**

**Fix:**
1. `thehive/application.conf` now has the real `notification.webhook.endpoints` array
   with a named endpoint `"blueteam"` pointing to `http://attense-app:8010/internal/webhook/hive`.
2. `PUT /api/config/organisation/notification` is called per-org (blue-team) with
   `{"value":[{"trigger":{"name":"AnyEvent"},"notifier":{"name":"webhook","endpoint":"blueteam"},"delegate":false}]}`.
   This is now automated by `scripts/setup_thehive.py` running as the `thehive-init`
   docker-compose service on every fresh stack start.
3. The config persists in JanusGraph (Cassandra-backed) and survives TheHive restarts.

Confirmed working: POST to `/internal/webhook/hive` received (200 OK) on every case
create/update in the blue-team org, and persists after a full TheHive container restart.

---

**Investigation history (kept for reference):**

The 2026-06-15 config change (`notification.notifier.*`) is confirmed to be a
no-op for TheHive 4.1.24 — see 2026-06-16 update below. Not a blocker — see
workaround below.

**Update (2026-06-15, post-merge):** The teammate's `application.conf` update
added:

```
notification.notifier.webhook.default {
  url = "http://attense-app:8010/internal/webhook/hive"
}
notification.notifier.active = ["webhook"]
```

This was hoped to be the fix, but a live test after pulling/rebuilding shows
it is **not**: a case was created via the API as `ahmed2` (tagged
`attense:incident-postmerge-001`), the case was created successfully (HTTP
201), but:
- `attense_app` (which now hosts the BlueTeam API on port 8010) received
  **no** request to `/internal/webhook/hive`.
- `GET /blueteam/analyst-actions/postmerge-001` returned `count: 0`.
- TheHive's logs show **zero** `NotificationActor`/`NotificationSrv` activity
  for this event — not even the "Notification is related to Audit(...),
  ..., blue-team" line that the old org-level config produced (see original
  diagnosis below). This suggests `notification.notifier.active` /
  `notification.notifier.webhook.default` are not real, read config keys for
  TheHive 4.1.24's Play config schema and are simply inert — i.e. this was
  not an effective fix.

**Update (2026-06-16): root cause confirmed — config keys do not exist in TheHive 4.1.24's schema.**

Two further tests were run:

1. **Fresh-org test**: created a brand-new organisation `attense-soc` (via
   `POST /api/v1/organisation`) and a brand-new user `ahmed3@lab.local` in it
   (via `POST /api/user`), then created a case tagged
   `attense:incident-freshorg-001`. Result: case created (201), but
   `GET /blueteam/analyst-actions/freshorg-001` still returns `count: 0`, and
   `docker logs attense_thehive` for the request window contains **zero**
   lines matching `notif|webhook|trigger` (case-insensitive) — not even the
   `NotificationActor` "Notification is related to..." line seen with the old
   org-level config. So this is not a stale-org issue either.

2. **reference.conf inspection**: extracted
   `org.thp.thehive-core-4.1.24-1.jar` from the running `attense_thehive`
   container and grepped its bundled `reference.conf`. The actual schema
   TheHive 4.1.24 reads is:

   ```
   notification {
     webhook {
       endpoints: []     # named webhook endpoint definitions
     }
     ...
   }
   organisation {
     defaults {
       notification: []  # list of {trigger, notifier, ...} configs
     }
   }
   ```

   **The keys added to `application.conf` — `notification.notifier.webhook.default`
   and `notification.notifier.active` — do not exist anywhere in this schema.**
   They are silently ignored by Typesafe Config (unknown keys are not errors).
   The correct mechanism is `notification.webhook.endpoints` (to define a
   named webhook target) combined with a per-organisation notification trigger
   config (either via `organisation.defaults.notification` in
   `application.conf`, applied at org-creation time, or via
   `PUT /api/config/organisation/notification` at runtime — which is the
   approach from the **original** diagnosis below, and which already showed
   `triggerMap()` resolving to an empty map for `blue-team`).

   **Conclusion:** the 2026-06-15 merge's config change was based on an
   incorrect (possibly TheHive 5 / community-fork) config schema and has no
   effect on TheHive 4.1.24. The underlying webhook-delivery bug (whatever
   causes `triggerMap()` to resolve empty, as documented in the original
   diagnosis below) has **not** been touched by any change so far.

3. **Clean-org test (final, 2026-06-16)**: to rule out "polluted by earlier
   broken `PUT /api/config/organisation/notification` calls on `blue-team`/
   `attense-soc`", created a brand-new org `clean-test` with a brand-new user
   `cleanuser@lab.local` (org-admin profile, set via
   `PATCH /api/v1/user/{login}` with `{"profile":"org-admin","organisation":"clean-test"}`
   — note: `POST /api/user` with `profile` set at creation time silently
   produces a `read-only` profile in this TheHive build; the profile must be
   patched afterwards). **Zero** prior config calls of any kind were made
   against this org. Created a case tagged `attense:incident-clean-001`
   (201, case `~163844168`). Result:
   - `GET /blueteam/analyst-actions/clean-001` → `count: 0`.
   - `docker logs attense_thehive` for the request window → zero lines
     matching `notif|webhook|trigger|audit`.

   **This permanently closes the "global default webhook" hypothesis.** The
   `notification.notifier.webhook.default` / `notification.notifier.active`
   keys have no effect on any org — new or old, configured or unconfigured —
   because (per the `reference.conf` inspection above) they are not real
   config keys for TheHive 4.1.24. No further testing of this approach is
   needed; any future fix must either (a) use the real
   `notification.webhook.endpoints` / `organisation.defaults.notification`
   schema, (b) resolve the JanusGraph `triggerMap()` edge-direction issue from
   the original diagnosis for the runtime-API-config approach, or (c) upgrade
   to TheHive 5.

Separately, while bringing the stack back up after the merge, TheHive was
stuck in a crash/restart loop. The real cause was unrelated to the webhook
investigation: the teammate's new `cortex { servers = [...] }` block was
missing the required `auth { type = "bearer", key = "..." }` wrapper, which
made Guice dependency injection fail (`JsResultException` on `.../auth`,
`error.path.missing`) and crashed the whole app before it could bind to a
port — masquerading as a JanusGraph/Cassandra "session is closed" loop. This
**was** fixed (added the `auth` block) and is a real, confirmed fix —
TheHive now starts and serves `/api/status` correctly.

**Original status:** Unresolved, paused. Not a blocker — see workaround below.

**Symptom:** Configuring TheHive's organisation notification config
(`PUT /api/config/organisation/notification`) with an `AnyEvent` trigger,
`webhook` notifier (`endpointName: "blueteam"`), and `delegate: true` persists
correctly (confirmed via `GET /api/config/organisation/notification`, which
returns the saved `value`), but TheHive never delivers the webhook to
`http://blueteam:8010/internal/webhook/hive`.

**Root cause (as far as identified):** Bytecode analysis of
`org.thp.thehive.services.notification.NotificationActor` and
`org.thp.thehive.services.ConfigOps$ConfigOpsDefs.triggerMap()` shows:

- The `Config` vertex for blue-team's `notification` setting is created and
  populated correctly (`ConfigSrv.organisation.setConfigValue` creates the
  `Config` vertex and an `OrganisationConfig` edge linking it to the
  Organisation vertex).
- `NotificationActor.triggerMap()` builds a
  `Map[EntityId, Map[Trigger, (Boolean, Seq[EntityId])]]` keyed by Organisation
  entity ID, via a Gremlin traversal: `Config` vertices →
  `in[OrganisationConfig]` → Organisation `_id`.
- For every audit event in `blue-team`, `NotificationActor` logs
  `"Notification is related to Audit(...), ..., blue-team"`, but
  `triggerMap().getOrElse(blueTeamOrgId, Map.empty)` resolves to an **empty
  map** — so the `executeNotification` path (and its "Checking trigger" /
  "Execution of notifier" / webhook-call logging) is never reached.
- JSON parsing of the stored config (`NotificationConfig.reads`) was verified
  to accept the shape we wrote (`trigger`, `notifier`, `delegate`), ruling out
  a parsing failure.
- This was confirmed across multiple test cases and after a full `thehive`
  container restart (ruling out the 5-minute `notification-triggers` cache as
  the cause).

**Most likely cause:** A mismatch between the edge direction used when
`OrganisationConfig` edges are created vs. the direction `triggerMap()`'s
`in[OrganisationConfig]` traversal expects when resolving `Config` → `Organisation`
in JanusGraph. Confirming this definitively would require direct inspection of
the JanusGraph data (via Cassandra CQL) or a TheHive 5 upgrade (which
restructures the notification/config services).

**Workaround / current state:** The **watcher agent** is the primary
mechanism for capturing analyst actions from TheHive and is fully
operational — it does not depend on TheHive's webhook notification config.

**Next steps (if revisited):**
- Inspect Cassandra/JanusGraph tables directly for the `Config` vertex and its
  `OrganisationConfig` edge for `blue-team`, and check the edge's
  in/out vertex IDs against the Organisation vertex ID.
- Or upgrade to TheHive 5, which has a reworked notification/config service.

## 1b. Analyst-action pipeline — internal webhook test (2026-06-16) and a real bug found+fixed

Ran `attense-app/test_webhook_local.py` inside `attense_app`
(`docker exec attense_app python /app/test_webhook_local.py`), which POSTs 7
synthetic TheHive payloads directly to `/internal/webhook/hive`, bypassing
TheHive's notification system entirely. This isolates whether our re-ported
pipeline (webhook_router → HiveEventTranslator → analyst_action_extractor →
analyst-actions store) works, independent of issue #1 above.

All 7 payloads translated correctly (`"status":"translated"`, correct
`attense_event_type` for each). However, `GET
/blueteam/analyst-actions/inc-001` initially returned `count: 0` even though
the logs showed 3 of the 7 events were correctly extracted as analyst actions
(`alert_denied`, `investigation_started`, `containment_initiated`).

**Root cause:** `core/blueactions/hive_event_translator.py` imported
`store_analyst_action`/`extract_analyst_action` via the absolute path
`ATTENSE_app.blueteam.routers.analyst_actions` /
`ATTENSE_app.blueteam.core.blueactions.analyst_action_extractor`, while
`main.py` registers the analyst-actions router via the relative path
`routers.analyst_actions`. Python loaded these as **two separate module
instances**, each with its own in-memory `_actions` defaultdict — so
`store_analyst_action()` writes from the translator went into a store the GET
endpoint never read from.

**Fix:** changed the imports in `hive_event_translator.py` to
`from core.blueactions.analyst_action_extractor import extract_analyst_action`
and `from routers.analyst_actions import store_analyst_action` (matching the
relative-import convention `main.py`/`webhook_router.py` already use).
Restarted `attense-app`, re-ran the test script — `/blueteam/analyst-actions/inc-001`
now correctly returns `count: 3` with the expected analyst actions.

**Status: fixed and confirmed working.** This pipeline is independent of
issue #1 (TheHive's own webhook delivery) — it works correctly when fed a
payload directly. The Watcher Agent (which calls this same endpoint) is
therefore unaffected by issue #1 and fully functional.

## 2. BlueTeam → TheHive (raise-alert) — confirmed working

As of this session, the BlueTeam → TheHive direction (BlueTeam raising
alerts/cases into TheHive via its API) was tested end-to-end and confirmed
working correctly.
