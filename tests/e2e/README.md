# tests/e2e — empty by design (for now)

No full-stack end-to-end tests exist yet. Every test in `tests/unit/` and
`tests/integration/` was built and verified without a running Docker stack
(no live TheHive/Cortex/Wazuh/Ollama available in this environment) — see
`tests/README.md` and `MIGRATION.md` for what was verified offline vs. what
still needs a live stack.

A real e2e suite here would drive the boot-the-stack smoke test the report's
Phase 9 CI section calls for:

```
exercise start -> malicious action -> Wazuh alert -> Blue Team investigation
                                    -> containment -> final report
```

Add it once the Phase 5/7 topology cutover (one shared Blue Team API, decoupled
compose profiles) lands and there's a stack to run it against.
