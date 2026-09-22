"""
Time and timestamp utilities.
"""

import time
import datetime
from typing import Optional, Union


def now_iso() -> str:
    return datetime.datetime.now().isoformat(timespec="seconds")


def now_utc_iso() -> str:
    return datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"


def now_epoch() -> float:
    return time.time()


def format_timestamp(ts: Optional[Union[float, int, datetime.datetime]] = None,
                     fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
    if ts is None:
        dt = datetime.datetime.now()
    elif isinstance(ts, (int, float)):
        try:
            dt = datetime.datetime.fromtimestamp(float(ts))
        except (ValueError, OSError, OverflowError):
            dt = datetime.datetime.now()
    elif isinstance(ts, datetime.datetime):
        dt = ts
    else:
        return str(ts)
    try:
        return dt.strftime(fmt)
    except (ValueError, TypeError, AttributeError):
        return str(ts)


def format_hms(seconds: Union[int, float]) -> str:
    seconds = int(seconds)
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h:02d}:{m:02d}:{s:02d}"
    return f"{m:02d}:{s:02d}"


def elapsed_since(start_epoch: float) -> str:
    elapsed = max(0.0, time.time() - start_epoch)
    return format_hms(elapsed)


def humanize_bytes(n: Union[int, float]) -> str:
    try:
        n = int(n)
    except (TypeError, ValueError):
        return "0 B"
    if n < 1024:
        return f"{n} B"
    units = ["KB", "MB", "GB", "TB"]
    value = float(n) / 1024.0
    for unit in units:
        if value < 1024.0:
            return f"{value:.2f} {unit}"
        value /= 1024.0
    return f"{value:.2f} PB"


def short_moment(ts_epoch: float) -> str:
    try:
        dt = datetime.datetime.fromtimestamp(ts_epoch)
    except (ValueError, OSError, OverflowError):
        return "--:--:--"
    return dt.strftime("%H:%M:%S")
