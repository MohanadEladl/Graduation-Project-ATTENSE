# Bug: attack completion isn't reflected, Operator Mode commands don't register

## Reported symptoms

1. **Target-node attacks give no completion feedback.** Launching an attack
   against target-agent (via the Workspace's "Execute Attack" button, or a
   guided-mode module) appears to succeed, but the UI never shows that
   anything was accomplished — no progress-bar movement, no success banner,
   no evidence card.
2. **Operator Mode doesn't register manually-typed commands as an attack.**
   Typing a command in the AttackBox terminal in Operator Mode doesn't count
   toward completing the module. Separately, the UI offers "you're done" /
   "View Report" in a way that doesn't match what the learner actually did —
   it seems to expect a specific, undocumented level of detail from Operator
   Mode before it recognizes success.

## What the code says *should* happen

Both scripted "Execute Attack" and manually-typed AttackBox commands are
supposed to count from any channel, in any mode. This is explicit in
`apps/red-team-api/backend/lab_progress.py`'s `compute()` docstring:

> task completion and mission success both count evidence from any channel
> (browser, attackbox, unknown) in both "tutorial" and "lab" mode ... a
> genuine exploit through the browser iframe (or anything else) always
> counts.

`events_for_progress = raw_events` (lab_progress.py:2011) confirms this is
not filtered by channel. So on paper, neither symptom should be possible.
The rest of this document is about where that theory and the reported
behavior might actually diverge.

## Investigation findings

### 1. Scripted attacks never tag a session

`apps/red-team-api/backend/session_manager.py`'s `SessionManager.execute()`
(line 410) runs the module directly: `record.attack._cmd_execute([])`. That
call chain — `engine/session.py` → `core/base_module.py` → the module files
in `modules/*.py` (e.g. `brute_force.py` makes real HTTP requests to
`target.base_url` via `self._get(...)`) — **never sets `attense_sid` or
`X-Attense-Session`** anywhere. I grepped all three files for both strings
and got zero matches.

That means every scripted attack's resulting evidence lands on target-agent
completely **untagged** (`session_id=None`). This is not automatically fatal
— target-agent's `evidence.py` (fixed earlier this project) explicitly
includes untagged events in every session-scoped query, specifically so
AttackBox-terminal traffic (which has the same problem) isn't excluded. So
in isolation this shouldn't hide the evidence.

**But it does mean two things worth checking against what you're actually
seeing:**

- If two learners run the *same* module around the same time on the shared
  target-agent container, their untagged evidence is indistinguishable —
  each could see (or miss) the other's attack in their own progress feed.
  This is a plausible source of "the attack succeeded but the panel doesn't
  reflect it" if you were testing with another session/module active
  concurrently.
- Untagged evidence is a symptom that a request never reached target-agent
  as an *identifiable* learner action at all — worth confirming directly
  (see "How to confirm" below) rather than assuming the "any channel counts"
  design is actually working end-to-end for the scripted-execute path,
  since it appears to have never been exercised with real session tagging.

### 2. Mode/variant plumbing looks intact, but is complex enough to hide a mismatch

`check_progress()` (`apps/red-team-api/backend/main.py:341`) does several
things on every poll:

- Normalizes and persists `mode` from the query string onto the session
  record (`guided`→`tutorial`, `operator`→`lab`).
- Passes `rec.mode`, `variant_id`, and `session_id=sid` into
  `lab_progress.compute()`.
- `compute()` then picks the task ladder from `variant["tasks"]` (if a
  variant is set) **or** falls back to the module's legacy default ladder —
  and separately, success criteria come from `variant["success_event_types"]`
  **or** the legacy `success_lab`/`success_tutorial` keys.

If a session has a `variant_id` set but that variant's `tasks`/
`success_event_types` don't line up with what the attack (or a manually
typed AttackBox command aimed at the *default*, non-variant flow) actually
produces, the learner can perform a fully valid attack that satisfies the
*legacy* success criteria while the code is scoring against the *variant's*
criteria (or vice versa). This is a real, structural way to get "I clearly
did the attack, nothing lit up" without any single line being "wrong" — it's
two correct-looking pieces of config silently not matching each other for a
specific module/variant combination.

### 3. Operator Mode's harder backend (`/op/...`) is a separate, parallel implementation

Every module has an operator-mode-hardened backend under
`apps/target-lab/app/routes_op/`. These are written to *look* identical in
the UI but enforce different (harder) rules — e.g. `routes_op/auth.py`'s
credential set is deliberately not in the default wordlist, per-attempt
delay, generic error messages (no username enumeration). If a learner in
Operator Mode is instructed to attack a module whose task ladder still
references the **guided-mode** event shapes/paths, or if the specific
command they typed targets `/auth/login` instead of `/op/auth/login` (easy
to do by habit, and nothing in the terminal warns about it), the request
would succeed against the *wrong*, easier backend and never trip the
harder-mode evidence the Operator-mode task ladder is actually watching for.
This matches your description of Operator Mode feeling like it "expects
something in more detail" — it likely expects the exact `/op/...` path and
harder-mode command shape, and gives no feedback when that expectation isn't
met (a UX gap, not necessarily a logic bug).

### 4. Two changes landed in this same work session that touch this path directly

Earlier in this session, `apps/red-team-api/backend/operator_api.py`'s
command validator and executor were rewritten (tool allowlist, enforced
timeout), and `apps/target-lab/app/routes_op/auth.py`'s credentials moved
from hardcoded to an environment-variable/secrets-file loader
(`OPERATOR_AUTH_USERS_JSON`). Both were tested in isolation and pass, but
**neither has been exercised against a live, running docker stack yet** —
only unit/integration tests with mocked Docker/HTTP. If your report predates
this session's edits (i.e., you were testing the deployed containers before
they get rebuilt with today's changes), it's unrelated. If you rebuild and
re-test after these changes land, and the operator-mode credential loader's
env var isn't actually picked up by a running container (e.g., stale image,
compose file not reloaded), `routes_op/auth.py`'s `_USERS` would come back
`{}` and **every** operator-mode login would fail closed — which would look
exactly like "operator mode doesn't let me do anything."

## What I could not confirm from static reading alone

I don't have a running docker stack in this environment, so I could not:

- Reproduce the exact module/variant you were using when this happened.
- Confirm whether `target-agent`'s `app.log` actually recorded an evidence
  event for your attack (this is the single fastest way to tell "target-agent
  never saw it" apart from "target-agent saw it, but scoring didn't count
  it").
- Confirm the operator-mode credential loader is actually resolving to a
  non-empty user set in your current deployment.

## How to confirm which of these is actually happening

1. **Tail target-agent's evidence during a repro**:
   `docker exec attense_target_agent tail -f /app/logs/app.log` (or query
   `GET http://target-agent/lab/events?since=<mission_started_at>` directly)
   while you run the attack. If nothing appears at all, the request never
   reached target-agent as a recognized action (wrong host/path, blocked
   command, or the module silently failed). If something appears but
   `check-progress` still shows no success, the mismatch is in scoring
   (variant vs. legacy ladder, or `success_event_types` not matching the
   `event_type`s actually recorded).
2. **Check which path Operator Mode commands actually hit** — confirm the
   terminal command you typed targeted `/op/...`, not the guided-mode path.
3. **Check the operator credential loader** — `docker exec
   attense_target_agent env | grep OPERATOR_AUTH_USERS_JSON` should show the
   JSON credential map, not be empty, once the container is rebuilt with
   today's changes.

## Suggested next step

Rather than guess further, the fastest path to a real fix is reproducing
once with target-agent's log tailed live, which will immediately show
whether this is a "never reached target-agent" problem, a "reached
target-agent but wrong backend/path" problem, or a "reached target-agent
correctly but the scoring config doesn't match" problem — each has a
different, much narrower fix.
