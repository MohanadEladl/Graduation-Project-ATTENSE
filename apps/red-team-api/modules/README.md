# Red Team Modules

This directory is still active.

The backend module loader discovers module metadata and scenario definitions here. Some modules also retain scripted attack/demo routines used by the CLI fallback and instructor-only auto-run paths. The normal student workflow is objective-based through the browser, ZAP Workspace, AttackBox safety validator, and `/op/` Operator evidence model.

Do not delete or split this directory until a dedicated refactor separates:

- `modules/metadata/` for active mission definitions
- `modules/scripted_demo/` for instructor/debug automation
