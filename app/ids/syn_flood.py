"""
SYN flood detection via rolling windows per source/destination pair.
"""

import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any, Deque, Dict, Optional, Tuple

from app.ids.alerts import (
    IDSAlert, Severity, AlertManager, ALERT_SYN_FLOOD,
)
from app.analysis.protocol_detector import ProtocolDetector


@dataclass
class SYNEvent:
    timestamp: float
    source_ip: str
    destination_ip: str


class SYNFloodDetector:
    def __init__(self, threshold: int = 100, window_seconds: int = 60,
                 alert_manager: Optional[AlertManager] = None):
        self._lock = threading.RLock()
        self._threshold = max(1, int(threshold))
        self._window_seconds = max(1, int(window_seconds))
        self._events: Dict[Tuple[str, str], Deque[float]] = defaultdict(deque)
        self._alert_mgr = alert_manager
        self._total_syns = 0

    def configure(self, threshold: Optional[int] = None,
                  window_seconds: Optional[int] = None) -> None:
        with self._lock:
            if threshold is not None:
                self._threshold = max(1, int(threshold))
            if window_seconds is not None:
                self._window_seconds = max(1, int(window_seconds))

    def _prune(self, q: Deque[float], now: float) -> None:
        cutoff = now - self._window_seconds
        while q and q[0] < cutoff:
            q.popleft()

    def observe(self, parsed: Any) -> Optional[IDSAlert]:
        if parsed is None:
            return None
        flags = getattr(parsed, "tcp_flags", "") or ""
        protocol = getattr(parsed, "protocol", "") or ""
        if "S" not in flags or "A" in flags:
            return None
        src_ip = getattr(parsed, "source_ip", "") or ""
        dst_ip = getattr(parsed, "destination_ip", "") or ""
        if not src_ip or not dst_ip:
            return None
        ts = getattr(parsed, "timestamp", None) or time.time()
        with self._lock:
            self._total_syns += 1
            key = (src_ip, dst_ip)
            q = self._events[key]
            q.append(ts)
            self._prune(q, ts)
            count = len(q)
            alert_needed = count >= self._threshold
            if alert_needed:
                rate = count / max(1.0, self._window_seconds)
                ratio = count / max(1, self._threshold)
                if ratio >= 5.0:
                    severity = Severity.CRITICAL
                elif ratio >= 2.5:
                    severity = Severity.HIGH
                elif ratio >= 1.5:
                    severity = Severity.MEDIUM
                else:
                    severity = Severity.LOW
                alert = IDSAlert(
                    alert_id=f"synf-{int(ts * 1000):x}",
                    alert_type=ALERT_SYN_FLOOD,
                    severity=severity,
                    timestamp=ts,
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    observed_rate=rate,
                    threshold=self._threshold / max(1.0, self._window_seconds),
                    time_window_seconds=self._window_seconds,
                    message=(
                        f"Possible SYN flood detected: observed {count} SYN packets "
                        f"from {src_ip} to {dst_ip} within {self._window_seconds}s window "
                        f"(threshold {self._threshold})."
                    ),
                    recommended_action=(
                        "Investigate source host; consider rate-limiting, firewall drops, "
                        "or enabling SYN cookies on the target."
                    ),
                    details={"syn_count": count, "threshold": self._threshold},
                    is_demo=bool(getattr(parsed, "is_demo", False)),
                )
                q.clear()
                return alert
            return None
