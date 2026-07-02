# Source naming audit

Reviewed: 2026-07-01

## Corrected

- `apps/blue-team-api/requirments.txt` was renamed to `apps/blue-team-api/requirements.txt`.
- Legacy domain folders under `apps/control-api/ATTENSE_app` were removed after imports moved to `packages/attense-core/attense_core`.
- Misspelled legacy concepts such as `matrics` are now represented by canonical modules under `attense_core.evaluation`.

## Names intentionally retained

- `main.py` is the conventional application entry-point name in each service.
- `__init__.py` is Python package metadata, not a business-domain filename.
- `run_gemini_test.py` and `inject_test.py` are manual validation/fixture scripts. Their module documentation states their purpose; they are not collected by the automated test suites.
- Hashed files under `frontends/portal/public/assets/` are third-party or generated build assets. They are excluded from source naming rules.

## Result

All first-party runtime modules should use names that identify their API, domain concept, integration, or responsibility. New shared domain code belongs under `packages/attense-core/attense_core` using lowercase `snake_case` for Python modules.