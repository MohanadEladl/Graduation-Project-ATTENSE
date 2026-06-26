# Source naming audit

Reviewed: 2026-06-26

## Corrected

- `apps/blue-team-api/requirments.txt` was renamed to
  `apps/blue-team-api/requirements.txt`.  The Blue Team Dockerfile and its
  documentation now reference the corrected name.

## Names intentionally retained

- `main.py` is the conventional application entry-point name in each service.
- `__init__.py` is Python package metadata, not a business-domain filename.
- `run_gemini_test.py` and `inject_test.py` are manual validation/fixture
  scripts. Their module documentation states their purpose; they are not
  collected by the automated test suites.
- `apps/control-api/ATTENSE_app/matrics`, `Outcomes`, and `Scenarios` are
  legacy compatibility paths.  `MIGRATION.md` maps each to its canonical
  `packages/attense-core/attense_core/` location. Renaming them now would break
  established imports without improving runtime behavior.
- Hashed files under `frontends/portal/public/assets/` are third-party or
  generated build assets. They are excluded from source naming rules.

## Result

All first-party runtime modules use names that identify their API, domain
concept, integration, or responsibility. New modules should follow the same
pattern: lowercase `snake_case` for Python, descriptive `PascalCase` for React
components, and no placeholder names such as `example`, `new`, or `misc`.
