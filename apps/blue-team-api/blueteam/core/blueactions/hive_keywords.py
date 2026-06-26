"""
hive_keywords.py — Shared keyword patterns for TheHive task-log event detection.

Imported by hive_event_translator.py (incident state machine path) and
analyst_action_extractor.py (scoring JSONL path). Single source so both
consumers stay in sync when keyword lists change.
"""

import re

# Matches any note expressing approval of an alert dismissal.
# Fires on: "dismissal approved", "approved dismissal", "dismiss approved", "approve dismissal"
# (with optional separators: space, underscore, hyphen).
DISMISSAL_APPROVED_RE = re.compile(
    r"\b(dismissal[\s_-]?approved|approved[\s_-]?dismissal|"
    r"dismiss[\s_-]?approved|approve[\s_-]?dismissal)\b",
    re.IGNORECASE,
)

# Matches any note or task title indicating a post-incident review was recorded.
# Fires on: "lessons learned", "post-incident", "post incident", "postmortem", "pir"
LESSONS_LEARNED_RE = re.compile(
    r"\b(lessons[\s_-]?learned|post[\s-]?incident|postmortem|pir)\b",
    re.IGNORECASE,
)
