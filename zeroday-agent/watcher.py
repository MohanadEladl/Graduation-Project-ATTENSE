"""
Continuous Watcher — runs the Zero-Day Detection Agent every N seconds.
Usage: python watcher.py --interval 60
"""

import time
import argparse
from datetime import datetime

from agent import run_agent


def watch(interval: int):
    print(f"\n👁️  Zero-Day Watcher (MITRE ATT&CK Edition)")
    print(f"   Scanning every {interval}s | Press Ctrl+C to stop\n")

    run_count = 0
    zero_day_count = 0

    while True:
        run_count += 1
        print(f"\n{'─'*60}")
        print(f"🔄 Scan #{run_count} — {datetime.now().strftime('%H:%M:%S')}")
        print(f"{'─'*60}")

        try:
            analysis, report_path = run_agent()
            if analysis.get("zero_day_detected"):
                zero_day_count += 1
                print(f"\n🚨 ZERO-DAY #{zero_day_count} detected! Report: {report_path}")
                mitre = analysis.get("closest_mitre_technique", {})
                print(f"   Closest MITRE: {mitre.get('id')} — {mitre.get('name')}")
                print(f"   Match Level: {mitre.get('match_level')} → deviation = zero-day")
        except Exception as e:
            print(f"❌ Agent error: {e}")

        print(f"\n⏳ Next scan in {interval}s... (zero-days found so far: {zero_day_count})")
        time.sleep(interval)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Zero-Day Detection Watcher (MITRE ATT&CK)")
    parser.add_argument("--interval", type=int, default=60,
                        help="Scan interval in seconds (default: 60)")
    args = parser.parse_args()
    watch(args.interval)
