"""
reader.py – Continuously tail the Wazuh alerts JSONL file.

Each line in alerts.json is a self-contained JSON object written by Wazuh.
On startup we fast-forward past existing content (so we only process *new*
alerts), then poll for additional lines indefinitely.

File rotation is handled transparently: when the file is truncated or replaced
we detect it via inode / size changes and re-open.
"""
from __future__ import annotations

import json
import logging
import os
import time
from typing import Generator

from app.config import settings

logger = logging.getLogger("signal-mapper.reader")


def _wait_for_file(path: str, timeout: int) -> None:
    """Block until *path* exists or raise RuntimeError on timeout."""
    deadline = time.monotonic() + timeout
    logged = False
    while not os.path.exists(path):
        if time.monotonic() > deadline:
            raise RuntimeError(
                f"[reader] Timed out after {timeout}s waiting for: {path}"
            )
        if not logged:
            logger.info("[reader] Waiting for alerts file: %s", path)
            logged = True
        time.sleep(0.5)
    logger.info("[reader] Alerts file found: %s", path)


def tail_alerts(path: str | None = None) -> Generator[dict, None, None]:
    """
    Generator that yields parsed Wazuh alert dicts from *path*.

    Behaviour
    ---------
    * Skips all lines already present when the process starts.
    * Polls for new lines using :attr:`~config.Settings.poll_interval`.
    * Detects file rotation (truncation or replacement) and re-opens.
    * Skips malformed / non-JSON lines with a warning log.
    * Never raises; any error is logged and the loop continues.
    """
    path = path or settings.wazuh_alerts_path
    _wait_for_file(path, settings.file_wait_timeout)

    while True:  # outer loop handles rotation
        try:
            inode = os.stat(path).st_ino
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                # Fast-forward past existing content
                for _ in fh:
                    pass
                logger.info(
                    "[reader] Following new alerts in %s (inode=%s)", path, inode
                )

                while True:
                    line: str = fh.readline()

                    if not line:
                        # Check for rotation: new inode or file became smaller
                        try:
                            st = os.stat(path)
                            if st.st_ino != inode or st.st_size < fh.tell():
                                logger.info("[reader] File rotation detected – reopening.")
                                break  # break inner loop → re-open
                        except FileNotFoundError:
                            logger.warning("[reader] Alerts file disappeared – waiting.")
                            time.sleep(2)
                            break
                        time.sleep(settings.poll_interval)
                        continue

                    line = line.strip()
                    if not line:
                        continue

                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError as exc:
                        logger.warning(
                            "[reader] Malformed JSON skipped (%s): %.120s", exc, line
                        )

        except FileNotFoundError:
            logger.warning("[reader] File not found: %s – retrying in 5s.", path)
            time.sleep(5)
        except Exception as exc:
            logger.error("[reader] Unexpected error: %s – retrying in 5s.", exc, exc_info=True)
            time.sleep(5)
