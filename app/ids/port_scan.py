"""
Port scan detection: tracks distinct destination ports per source.
"""

import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, Optional, Set, Tuple

from app.ids.alerts import (
    IDSAlert, Severity, AlertManager, ALERT_PORT_SCAN,
)


@dataclass
class PortScanEvent:
    timestamp: float
    destination_port: int


class PortScanDetector:
    def __init__(self, ports_threshold: int = 20, window_seconds: int = 60,
                 alert_manager: Optional[AlertManager] = None):
        self._lock = threading.RLock()
        self._ports_threshold = max(2, int(ports_threshold))
        self._window_seconds = max(1, int(window_seconds))
        self._events: Dict[Tuple[str, str], Deque[PortScanEvent]] = defaultdict(deque)
        self._ports_seen: Dict[Tuple[str, str], Set[int]] = defaultdict(set)
        self._alert_mgr = alert_manager

    def configure(self, ports_threshold: Optional[int] = None,
                  window_seconds: Optional[int] = None) -> None:
        with self._lock:
            if ports_threshold is not None:
                self._ports_threshold = max(2, int(ports_threshold))
            if window_seconds is not None:
                self._window_seconds = max(1, int(window_seconds))

    def _prune(self, key: Tuple[str, str], now: float) -> None:
        cutoff = now - self._window_seconds
        q = self._events[key]
        while q and q[0].timestamp < cutoff:
            ev = q.popleft()
            port_set = self._ports_seen[key]
            port_set.discard(ev.destination_port)
        if not q:
            self._events.pop(key, None)
            self._ports_seen.pop(key, None)

    def observe(self, parsed: Any) -> Optional[IDSAlert]:
        if parsed is None:
            return None
        src_ip = getattr(parsed, "source_ip", "") or ""
        dst_ip = getattr(parsed, "destination_ip", "") or ""
        dport = int(getattr(parsed, "destination_port", 0) or 0)
        protocol = getattr(parsed, "protocol", "") or ""
        if not src_ip or not dst_ip or dport <= 0:
            return None
        if protocol not in ("TCP", "UDP", "HTTP", "HTTPS", "FTP", "SSH", "SMTP", "DNS", "Other"):
            return None
        ts = getattr(parsed, "timestamp", None) or time.time()
        with self._lock:
            key = (src_ip, dst_ip)
            self._events[key].append(PortScanEvent(timestamp=ts, destination_port=dport))
            self._ports_seen[key].add(dport)
            self._prune(key, ts)
            port_set = self._ports_seen.get(key, set())
            distinct_ports = len(port_set)
            if distinct_ports >= self._ports_threshold:
                ratio = distinct_ports / max(1, self._ports_threshold)
                if ratio >= 5.0:
                    severity = Severity.CRITICAL
                elif ratio >= 2.5:
                    severity = Severity.HIGH
                elif ratio >= 1.5:
                    severity = Severity.MEDIUM
                else:
                    severity = Severity.LOW
                sample = sorted(port_set)[:20]
                alert = IDSAlert(
                    alert_id=f"pscn-{int(ts * 1000):x}",
                    alert_type=ALERT_PORT_SCAN,
                    severity=severity,
                    timestamp=ts,
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    ports_count=distinct_ports,
                    time_window_seconds=self._window_seconds,
                    message=(
                        f"Possible port scan: {distinct_ports} distinct destination ports "
                        f"contacted by {src_ip} -> {dst_ip} within {self._ports_threshold} "
                        f"threshold over {self._window_seconds}s window. Sample ports: {sample}."
                    ),
                    recommended_action=(
                        "Verify source host intent; consider rate-limiting or blocking "
                        "the source IP if unauthorised."
                    ),
                    details={
                        "distinct_ports": distinct_ports,
                        "threshold": self._ports_threshold,
                        "sample_ports": sample,
                    },
                    is_demo=bool(getattr(parsed, "is_demo", False)),
                )
                self._events.pop(key, None)
                self._ports_seen.pop(key, None)
                return alert
            return None
