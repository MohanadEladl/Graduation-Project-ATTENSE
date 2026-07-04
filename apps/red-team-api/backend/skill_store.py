"""
backend/skill_store.py — Persistent learner skill graph for ATTENSE.

Maintains a JSON file at /data/skills.json (inside the container) that tracks
each learner's attempts, best scores, grades, and last-played timestamps for
every module/variant combination. Falls back to in-memory storage if /data
is not writable.

Thread-safe via threading.Lock.
"""
from __future__ import annotations

import json
import logging as _logging
import os
import tempfile
import threading
import time
from typing import Any, Dict, List, Optional

_LOCK = threading.Lock()
_log = _logging.getLogger(__name__)
_SKILLS_PATH = "/data/skills.json"


def _zeroed_entry() -> Dict[str, Any]:
    return {
        "attempts": 0,
        "best_score": 0,
        "best_grade": None,
        "last_played": None,
        "technique_scores": [],
    }


def _zeroed_structure() -> Dict[str, Any]:
    """Return a zeroed skill graph for all 7 modules x 3 variants."""
    # Import here to avoid a hard circular dependency at module load time.
    from backend.lab_progress import MODULE_VARIANTS
    data: Dict[str, Any] = {}
    for module_id, variants in MODULE_VARIANTS.items():
        data[module_id] = {}
        for variant_id in variants:
            data[module_id][variant_id] = _zeroed_entry()
    return data


def load() -> Dict[str, Any]:
    """Read /data/skills.json.

    Returns the full skill graph.  If the file is missing, unreadable, or
    contains invalid JSON, a zeroed structure for all 21 entries is returned.
    Callers needing read-modify-write consistency must hold _LOCK.
    """
    try:
        with open(_SKILLS_PATH, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        # Ensure all known module/variant keys exist (new variants added later)
        base = _zeroed_structure()
        for module_id, variants in base.items():
            if module_id not in data:
                data[module_id] = variants
            else:
                for variant_id, entry in variants.items():
                    if variant_id not in data[module_id]:
                        data[module_id][variant_id] = entry
        return data
    except (OSError, ValueError, KeyError):
        return _zeroed_structure()


def save(data: Dict[str, Any]) -> None:
    """Thread-safe write to /data/skills.json using atomic replace."""
    try:
        dir_path = os.path.dirname(_SKILLS_PATH)
        os.makedirs(dir_path, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(dir=dir_path, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2)
            os.replace(tmp_path, _SKILLS_PATH)
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
    except OSError as _exc:
        _log.warning("skill_store: save skipped: %s", _exc)


def update(module_id: str, variant_id: Optional[str], score: int, grade: str) -> Dict[str, Any]:
    """Update the skill entry for (module_id, variant_id) with a new attempt.

    - attempts += 1
    - best_score / best_grade updated if score improves
    - score appended to technique_scores (last 10 kept)
    - last_played set to current epoch time

    Returns the full updated skill graph.
    """
    with _LOCK:
        data = load()

        if module_id not in data:
            data[module_id] = {}

        # Resolve variant_id: fall back to first known variant for the module
        if not variant_id:
            try:
                from backend.lab_progress import MODULE_VARIANTS
                variant_id = next(iter(MODULE_VARIANTS.get(module_id, {})), None)
            except Exception:
                variant_id = None

        if variant_id is None:
            return data

        if variant_id not in data[module_id]:
            data[module_id][variant_id] = _zeroed_entry()

        entry = data[module_id][variant_id]
        entry["attempts"] += 1
        if score > entry.get("best_score", 0):
            entry["best_score"] = score
            entry["best_grade"] = grade
        scores = entry.get("technique_scores", [])
        scores.append(score)
        entry["technique_scores"] = scores[-10:]
        entry["last_played"] = time.time()

        save(data)
        return data


def get_radar() -> List[Dict[str, Any]]:
    """Return one entry per module for a radar/spider chart.

    Each entry:
      {
        "module_id": str,
        "label": str,
        "score": float (0-100, avg best_score across variants),
        "variants": [{"variant_id", "name", "attempts", "best_score", "best_grade"}]
      }
    """
    try:
        from backend.lab_progress import MODULE_VARIANTS
    except Exception:
        return []

    with _LOCK:
        data = load()

    result = []
    for module_id, variants_spec in MODULE_VARIANTS.items():
        module_data = data.get(module_id, {})
        variant_list = []
        best_scores = []
        for variant_id, variant_spec in variants_spec.items():
            entry = module_data.get(variant_id, _zeroed_entry())
            best_scores.append(entry.get("best_score", 0))
            variant_list.append({
                "variant_id":  variant_id,
                "name":        variant_spec.get("name", variant_id),
                "attempts":    entry.get("attempts", 0),
                "best_score":  entry.get("best_score", 0),
                "best_grade":  entry.get("best_grade", None),
            })
        avg_score = sum(best_scores) / len(best_scores) if best_scores else 0.0
        # Humanize the module label: replace underscores with spaces, title-case
        label = module_id.replace("_", " ").title()
        result.append({
            "module_id": module_id,
            "label":     label,
            "score":     round(avg_score, 1),
            "variants":  variant_list,
        })
    return result


def get_recommendation() -> Optional[Dict[str, Any]]:
    """Return the highest-priority variant to practice next.

    Priority: never-played (attempts == 0) first, then lowest best_score.
    Returns {"module_id", "variant_id", "variant_name", "reason"} or None.
    """
    try:
        from backend.lab_progress import MODULE_VARIANTS
    except Exception:
        return None

    with _LOCK:
        data = load()

    best_unplayed: Optional[tuple] = None   # (module_id, variant_id, name)
    best_low: Optional[tuple] = None        # (module_id, variant_id, name, best_score)

    for module_id, variants_spec in MODULE_VARIANTS.items():
        module_data = data.get(module_id, {})
        for variant_id, variant_spec in variants_spec.items():
            entry = module_data.get(variant_id, _zeroed_entry())
            attempts = entry.get("attempts", 0)
            best_score = entry.get("best_score", 0)
            name = variant_spec.get("name", variant_id)

            if attempts == 0:
                if best_unplayed is None:
                    best_unplayed = (module_id, variant_id, name)
            else:
                if best_low is None or best_score < best_low[3]:
                    best_low = (module_id, variant_id, name, best_score)

    if best_unplayed:
        module_id, variant_id, name = best_unplayed
        return {
            "module_id":    module_id,
            "variant_id":   variant_id,
            "variant_name": name,
            "reason":       "You have not attempted this variant yet.",
        }
    if best_low:
        module_id, variant_id, name, score = best_low
        return {
            "module_id":    module_id,
            "variant_id":   variant_id,
            "variant_name": name,
            "reason":       "This is your lowest-scoring variant — practice makes perfect.",
        }
    return None
