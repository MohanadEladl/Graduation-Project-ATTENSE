import time
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)

from app.agent import run_agent

t0 = time.time()
print(f"[TIMER] Agent start: {t0:.3f}")

analysis, report_path = run_agent()

t1 = time.time()
elapsed_ms = (t1 - t0) * 1000

print(f"[TIMER] Agent done: {t1:.3f}")
print(f"[TIMER] Total elapsed: {elapsed_ms:.0f} ms")
print(f"[RESULT] zero_day_detected: {analysis.get('zero_day_detected')}")
print(f"[RESULT] classification:    {analysis.get('classification')}")
print(f"[RESULT] confidence:        {analysis.get('confidence')}")
print(f"[RESULT] reasoning:         {str(analysis.get('reasoning', ''))[:150]}")
print(f"[RESULT] report_path:       {report_path}")
