# Why only "blue-team" seemed able to use the webhook (and the fix)

## The question

> why is the blueteam org the only one allowed to use webhook? i think this
> is a bug

Confirmed — this was a real bug, not intended behavior. It's a direct
consequence of this session's earlier fix that gave every room its own
TheHive organisation instead of sharing one.

## Why TheHive only lets specific orgs use the webhook at all

TheHive's webhook plugin config
(`integrations/thehive/application.conf:40`) has an explicit allow-list:

```
includedTheHiveOrganisations = ["blue-team"]
```

TheHive 4.1.24 does **not** support a wildcard here (`"all"` is not special
to it) and the match is case-sensitive. Any org not on this literal list
gets its webhook events (case creation, alerts) silently rejected by TheHive
itself — the request never even reaches `apps/blue-team-api`'s
`webhook_router.py`, so there's nothing for our own code to log either. That
plugin-level allow-list is a hard requirement of this TheHive version, not
something we can bypass — every org that needs auto-attach (attacker log
attachment, case notifications) has to be added to this list, individually.

## How the rest of the organizations *are supposed* to get added

They already are, dynamically — that part isn't missing. The comment right
above the config line documents it:

```
# MANAGED AUTOMATICALLY, additively, by two independent writers:
# scripts/setup_thehive.py (bootstrap; merges THEHIVE_ORG_NAME in, doesn't
# replace) and core.hive_provisioner.authorize_org_for_webhook (apps/control-api;
# appends a room's own org the first time that room is entered, then
# restarts TheHive).
```

`apps/control-api/core/hive_provisioner.py:359`'s `authorize_org_for_webhook()`
reads the live config file inside the running TheHive container, appends the
new org name if it isn't already there, writes it back, and restarts TheHive
so the change takes effect. This is called from `room_manager.py`'s
`_ensure_room_hive()` — the function that runs every time a Blue Team user
enters a room.

## The actual bug: it only ever tried once, with no retry

Before this fix, the call was gated like this:

```python
if is_new_org and not reused_from_pool:
    try:
        hive_provisioner.authorize_org_for_webhook(org)
    except Exception:
        logger.exception("Could not authorise org '%s' on the TheHive webhook", org)
```

`is_new_org` is only `True` the *very first* time a room's org is minted.
The authorization attempt is wrapped in a bare `try/except` and treated as
best-effort — intentionally, since a restart failing shouldn't block the
person from entering their room. But that means:

- If the TheHive restart failed, timed out, or hit any transient error
  during that one attempt, the failure was just logged and swallowed.
- `room["hive_org"]` was already set regardless of whether authorization
  actually succeeded.
- Since `is_new_org` is only ever `True` once, **every subsequent entry to
  that room — by anyone — permanently skipped the authorization attempt
  forever.**

The room itself worked fine (analysts could see the case, log in, etc.) —
but that room's org was never on TheHive's webhook allow-list, so every
CaseCreated/alert event for it was silently rejected by TheHive, and the
attacker-log auto-attach feature (`attacker_log_attacher.py`) never fired
for that room. No error surfaces anywhere a user would see it; the only
observable symptom is "auto-attach doesn't work," which — since restarting
a live container is exactly the kind of operation that fails intermittently
— would understandably look like "only the original bootstrap org
(`blue-team`) ever actually works."

## The fix

`authorize_org_for_webhook()` was already idempotent — it reads the current
list and returns early (no restart) if the org is already on it:

```python
if org_name in current:
    return False
```

That means calling it is *safe* to retry on every room entry: when
everything already succeeded, it costs one cheap file read and a list
membership check, no restart. So the fix removes the one-shot gate entirely
— `room_manager.py`'s `_ensure_room_hive()` now retries both
`authorize_org_for_webhook()` and `ensure_notification_rule()` (also
idempotent — a PUT that just re-sets the same config) on **every** room
entry, not just the first:

```python
try:
    hive_provisioner.authorize_org_for_webhook(org)
except Exception:
    logger.exception("Could not authorise org '%s' on the TheHive webhook", org)
retry_key = key or room.get("hive_api_key")
if retry_key:
    hive_provisioner.ensure_notification_rule(org, retry_key)
```

The one change beyond removing the gate: `ensure_notification_rule` needs
the room's org API key, which is only freshly generated on the manager's
*first* entry (`key`). On every later entry `key` is `None`, so the fix
falls back to the key already stored on the room
(`room.get("hive_api_key")`) so the retry has something to call it with.

## What this means going forward

Every time *anyone* enters a room now, the system re-checks and, if needed,
re-attempts webhook authorization for that room's org — so a transient
failure at room-creation time is no longer permanent. The very next entry
(by the creator or any invited teammate) will retry and, once TheHive
answers, succeed. No manual intervention or restart is required from an
operator; it self-heals on the next visit.

One thing this doesn't fully solve: if a room is created and genuinely
*nobody* ever enters it again (e.g., only the automated deferred-visibility
flow creates it and no analyst ever opens it), the retry never gets a
chance to run, since it's driven by room entry. That's an acceptable gap —
a room nobody looks at has no auto-attach to matter in the first place.

## Verifying this live

1. Enter a brand-new room (fresh org) while TheHive is briefly interrupted
   or under load, so the first `authorize_org_for_webhook` call plausibly
   fails — confirm the room still lets you in (best-effort, unchanged).
2. Re-enter the same room (or have a teammate accept the invite) — confirm
   `integrations/thehive/application.conf`'s `includedTheHiveOrganisations`
   now includes that room's org name, without you having to do anything
   manually.
3. Trigger a case/alert in that room and confirm the attacker-activity-log
   auto-attach now fires.
