# routes_op/ — Operator-mode parallel routes.
#
# Mounted under /op/* on target-agent. Reached by the lab browser via the
# nginx /target-op/ proxy and by the AttackBox via direct
# http://target-agent/op/... calls.
#
# Same Jinja templates as routes/* (so the UI is visually identical) but with
# HARDER backend logic per module:
#   - auth   : different cred set, 600ms delay, no username enumeration
#   - search : partial XSS sanitization (strips <script> but allows event handlers)
#   - system : filters `;` and `|`, but allows backticks / $()
#   - files  : filters literal `..` but not URL-encoded variants
#   - upload : rejects .php/.exe but allows .phtml / .svg / .html
#   - profile: enforces Origin check but not Referer (lure page bypass works)
#   - home   : same recon surface, marked harder via headers
#
# Phase A ships only `auth_op_bp` as a pilot. The rest land in Phase B.
