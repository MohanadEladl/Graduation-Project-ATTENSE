"""
Continuous Watcher — runs the Zero-Day Detection Agent every N seconds.
Usage: python -m app.watcher --interval 60
"""

import argparse
import logging
import time
from datetime import datetime

from app.agent import run_agent

logger = logging.getLogger("zeroday-agent.watcher")


def watch(interval: int):
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    logger.info("Zero-Day Watcher (MITRE ATT&CK Edition)")
    logger.info("Scanning every %ds | Press Ctrl+C to stop", interval)

    run_count = 0
    zero_day_count = 0

    while True:
        run_count += 1
        logger.info("Scan #%d — %s", run_count, datetime.now().strftime("%H:%M:%S"))

        try:
            analysis, report_path = run_agent()
            if analysis.get("zero_day_detected"):
                zero_day_count += 1
                mitre = analysis.get("closest_mitre_technique", {})
                logger.critical(
                    "ZERO-DAY #%d detected! Report: %s | "
                    "Closest MITRE: %s — %s | Match Level: %s",
                    zero_day_count, report_path,
                    mitre.get("id"), mitre.get("name"),
                    mitre.get("match_level"),
                )
        except Exception as e:
            logger.error("Agent error: %s", e)

        logger.info(
            "Next scan in %ds... (zero-days found so far: %d)",
            interval, zero_day_count,
        )
        time.sleep(interval)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Zero-Day Detection Watcher (MITRE ATT&CK)")
    parser.add_argument("--interval", type=int, default=60,
                        help="Scan interval in seconds (default: 60)")
    args = parser.parse_args()
    watch(args.interval)
