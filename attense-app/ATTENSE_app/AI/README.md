# ATTENSE AI attack dataset

`Data/APP-*.json` contains the canonical attack-exercise records consumed by the AI evaluation layer. All records use schema version `2.0.0`; `attack-dataset.schema.json` documents the contract.

## Evaluation contract

- CVSS v3.1 measures vulnerability severity. It is not an incident-response SLA.
- The TTC and MTTA values are explicit ATTENSE exercise policy. They are not attributed to FIRST, NIST, MITRE, OWASP, or Wazuh.
- `t_offset_sec` is measured from `alert_raised`. Consequently, `alert_investigation_started` measures response/acknowledgement delay, not true time-to-detect.
- The final score is always between 0 and 100. Missing or late containment sets the TTC factor to zero.
- The response-difficulty bonus is awarded only when `containment_succeeded` exists.
- The bonus denominator is `max(investigation_delay_sec, 1)`, so a same-second investigation receives the capped bonus instead of causing division by zero.
- Successful response order is confirmation, evidence preservation, containment, eradication, recovery validation, and lessons learned.

## Wazuh rule policy

`wazuh.stock_rules` records only IDs and meanings verified against the linked upstream Wazuh ruleset. `wazuh.custom_rules` defines project detection requirements where no suitable stock rule exists.

Custom rule IDs use Wazuh's recommended `100000-120000` range. They are specifications, not a claim that the deployed manager already contains those rules. Before production use, implement the required decoders/rules against the application's actual structured logs and validate them with `wazuh-logtest` as described by the linked Wazuh custom-rule documentation.

## MITRE ATT&CK policy

ATT&CK mappings describe adversary behavior and are not vulnerability classifications. Each record distinguishes primary and related techniques and includes a mapping limitation. CSRF is intentionally marked as having no direct Enterprise ATT&CK technique.

## Validation

From `attense-app` run:

```powershell
python -m unittest test_ai_dataset.py -v
```

The tests validate all CVSS v3.1 calculations and rationale keys, timing thresholds, zero-delay safety, Wazuh declarations, ATT&CK URLs, event ordering, lifecycle completeness, score bounds, verdicts, and removal of legacy fields.
