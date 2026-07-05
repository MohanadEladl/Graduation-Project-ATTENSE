"""engine/timer.py — Simple stopwatch for attack sessions."""
from __future__ import annotations

import time
from datetime import datetime
from typing import Optional


class Timer:
    """Wallclock + monotonic stopwatch. Call start(), stop(), read elapsed()."""

    def __init__(self) -> None:
        self._t0: Optional[float] = None
        self._t1: Optional[float] = None
        self._started_wall: Optional[datetime] = None
        self._stopped_wall: Optional[datetime] = None

    def start(self) -> None:
        self._t0 = time.monotonic()
        self._t1 = None
        self._started_wall = datetime.now()
        self._stopped_wall = None

    def stop(self) -> None:
        if self._t0 is None:
            return
        self._t1 = time.monotonic()
        self._stopped_wall = datetime.now()

    def reset(self) -> None:
        self._t0 = self._t1 = None
        self._started_wall = self._stopped_wall = None

    @property
    def is_running(self) -> bool:
        return self._t0 is not None and self._t1 is None

    @property
    def started_at(self) -> Optional[str]:
        return self._started_wall.strftime("%H:%M:%S") if self._started_wall else None

    @property
    def stopped_at(self) -> Optional[str]:
        return self._stopped_wall.strftime("%H:%M:%S") if self._stopped_wall else None

    def elapsed_seconds(self) -> float:
        if self._t0 is None:
            return 0.0
        end = self._t1 if self._t1 is not None else time.monotonic()
        return end - self._t0

    def elapsed(self) -> str:
        """Return 'Xm Ys' formatted elapsed time."""
        s = self.elapsed_seconds()
        if s < 60:
            return f"{s:.1f}s"
        m = int(s // 60)
        r = int(s % 60)
        return f"{m}m {r}s"
