"""
Unified IDS orchestrator combining multiple defensive detectors.
"""

import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from config import AppConfig
from app.ids.alerts import (
    AlertManager, IDSAlert, Severity,
    ALERT_SYN_FLOOD, ALERT_PORT_SCAN, ALERT_ICMP_FLOOD, ALERT_UDP_FLOOD,
    ALERT_PING_SWEEP, ALERT_SUSPICIOUS_FLAGS, ALERT_PACKET_RATE,
)
from app.ids.syn_flood import SYNFloodDetector
from app.ids.port_scan import PortScanDetector
from app.logging.logger import log_ids, log_error
from app.analysis.protocol_detector import ProtocolDetector


class IntrusionDetectionSystem:
    def __init__(self, config: Optional[AppConfig] = None,
                 alert_manager: Optional[AlertManager] = None):
        self._lock = threading.RLock()
        self._config = config or AppConfig()
        self._alert_mgr = alert_manager or AlertManager(
            cooldown_seconds=self._config.ids.alert_cooldown_seconds,
        )
        self._enabled = bool(self._config.ids.enabled)
        self._syn = SYNFloodDetector(
            threshold=self._config.ids.syn_flood_threshold,
            window_seconds=self._config.ids.detection_window_seconds,
            alert_manager=self._alert_mgr,
        )
        self._portscan = PortScanDetector(
            ports_threshold=self._config.ids.port_scan_threshold,
            window_seconds=self._config.ids.detection_window_seconds,
            alert_manager=self._alert_mgr,
        )
        self._icmp_events: Dict[str, deque] = defaultdict(deque)
        self._udp_events: Dict[str, deque] = defaultdict(deque)
        self._ping_dst: Dict[str, deque] = defaultdict(deque)
        self._rate_events: deque = deque()
        self._last_rate_check = time.time()
        self._rate_in_window = 0

    @property
    def alert_manager(self) -> AlertManager:
        return self._alert_mgr

    def is_enabled(self) -> bool:
        with self._lock:
            return self._enabled

    def set_enabled(self, enabled: bool) -> None:
        with self._lock:
            self._enabled = bool(enabled)
            self._config.ids.enabled = self._enabled
            try:
                self._config.save()
            except Exception:
                pass
            log_ids(f"IDS {'ENABLED' if self._enabled else 'DISABLED'}.", "INFO")

    def configure_from_config(self, cfg: Optional[AppConfig] = None) -> None:
        cfg = cfg or self._config
        with self._lock:
            self._syn.configure(
                threshold=cfg.ids.syn_flood_threshold,
                window_seconds=cfg.ids.detection_window_seconds,
            )
            self._portscan.configure(
                ports_threshold=cfg.ids.port_scan_threshold,
                window_seconds=cfg.ids.detection_window_seconds,
            )
            self._alert_mgr.set_cooldown(cfg.ids.alert_cooldown_seconds)
            self._enabled = bool(cfg.ids.enabled)

    def _severity_for_ratio(self, ratio: float) -> Severity:
        if ratio >= 5.0:
            return Severity.CRITICAL
        if ratio >= 2.5:
            return Severity.HIGH
        if ratio >= 1.5:
            return Severity.MEDIUM
        return Severity.LOW

    def _prune_and_count(self, q: deque, window: float, now: float) -> int:
        cutoff = now - window
        while q and q[0] < cutoff:
            q.popleft()
        return len(q)

    def _check_icmp_flood(self, parsed: Any) -> Optional[IDSAlert]:
        proto = getattr(parsed, "protocol", "") or ""
        if proto not in ("ICMP", "ICMPv6"):
            return None
        src_ip = getattr(parsed, "source_ip", "") or ""
        if not src_ip:
            return None
        ts = getattr(parsed, "timestamp", None) or time.time()
        window = self._config.ids.detection_window_seconds
        threshold = max(1, self._config.ids.icmp_flood_threshold)
        q = self._icmp_events[src_ip]
        q.append(ts)
        count = self._prune_and_count(q, window, ts)
        if count >= threshold:
            q.clear()
            ratio = count / max(1, threshold)
            return IDSAlert(
                alert_id=f"icmpf-{int(ts * 1000):x}",
                alert_type=ALERT_ICMP_FLOOD,
                severity=self._severity_for_ratio(ratio),
                timestamp=ts,
                source_ip=src_ip,
                observed_rate=count / max(1.0, window),
                threshold=threshold / max(1.0, window),
                time_window_seconds=window,
                message=(
                    f"Possible ICMP flood detected from {src_ip}: {count} ICMP packets "
                    f"within {window}s window (threshold {threshold})."
                ),
                recommended_action=(
                    "Investigate source; consider ICMP rate-limiting or ACL blocks."
                ),
                details={"icmp_count": count, "threshold": threshold},
                is_demo=bool(getattr(parsed, "is_demo", False)),
            )
        return None

    def _check_udp_flood(self, parsed: Any) -> Optional[IDSAlert]:
        proto = getattr(parsed, "protocol", "") or ""
        if proto != "UDP":
            return None
        src_ip = getattr(parsed, "source_ip", "") or ""
        dst_ip = getattr(parsed, "destination_ip", "") or ""
        if not src_ip:
            return None
        ts = getattr(parsed, "timestamp", None) or time.time()
        window = self._config.ids.detection_window_seconds
        threshold = max(1, self._config.ids.udp_flood_threshold)
        key = f"{src_ip}|{dst_ip}"
        q = self._udp_events[key]
        q.append(ts)
        count = self._prune_and_count(q, window, ts)
        if count >= threshold:
            q.clear()
            ratio = count / max(1, threshold)
            return IDSAlert(
                alert_id=f"udpf-{int(ts * 1000):x}",
                alert_type=ALERT_UDP_FLOOD,
                severity=self._severity_for_ratio(ratio),
                timestamp=ts,
                source_ip=src_ip,
                destination_ip=dst_ip,
                observed_rate=count / max(1.0, window),
                threshold=threshold / max(1.0, window),
                time_window_seconds=window,
                message=(
                    f"Possible UDP flood detected {src_ip} -> {dst_ip}: {count} UDP packets "
                    f"within {window}s window (threshold {threshold})."
                ),
                recommended_action=(
                    "Investigate application endpoints; consider UDP rate-limits or firewall drops."
                ),
                details={"udp_count": count, "threshold": threshold},
                is_demo=bool(getattr(parsed, "is_demo", False)),
            )
        return None

    def _check_ping_sweep(self, parsed: Any) -> Optional[IDSAlert]:
        proto = getattr(parsed, "protocol", "") or ""
        if proto not in ("ICMP", "ICMPv6"):
            return None
        src_ip = getattr(parsed, "source_ip", "") or ""
        dst_ip = getattr(parsed, "destination_ip", "") or ""
        if not src_ip or not dst_ip:
            return None
        ts = getattr(parsed, "timestamp", None) or time.time()
        window = self._config.ids.detection_window_seconds
        threshold = max(2, self._config.ids.ping_sweep_threshold)
        q = self._ping_dst[src_ip]
        q.append((ts, dst_ip))
        cutoff = ts - window
        while q and q[0][0] < cutoff:
            q.popleft()
        distinct = len({d for _, d in q})
        if distinct >= threshold:
            q.clear()
            ratio = distinct / max(1, threshold)
            return IDSAlert(
                alert_id=f"ping-{int(ts * 1000):x}",
                alert_type=ALERT_PING_SWEEP,
                severity=self._severity_for_ratio(ratio),
                timestamp=ts,
                source_ip=src_ip,
                observed_rate=distinct / max(1.0, window),
                threshold=threshold,
                time_window_seconds=window,
                message=(
                    f"Possible ping sweep from {src_ip}: ICMP probes to {distinct} distinct "
                    f"destination IPs within {window}s window (threshold {threshold})."
                ),
                recommended_action=(
                    "Verify source host intent; consider ICMP rate-limits or blocking."
                ),
                details={"distinct_dst": distinct, "threshold": threshold},
                is_demo=bool(getattr(parsed, "is_demo", False)),
            )
        return None

    def _check_suspicious_flags(self, parsed: Any, pkt: Any) -> Optional[IDSAlert]:
        if not self._config.ids.suspicious_flags_enabled:
            return None
        flags = getattr(parsed, "tcp_flags", "") or ""
        if not flags:
            return None
        bad_combos = [
            ("SF", "SYN+FIN"),
            ("SR", "SYN+RST"),
            ("FPU", "XMAS"),
            ("NULL", "NULL"),
        ]
        detected = None
        if "S" in flags and "F" in flags:
            detected = "SYN+FIN"
        elif "S" in flags and "R" in flags:
            detected = "SYN+RST"
        elif "F" in flags and "P" in flags and "U" in flags:
            detected = "XMAS (FIN+PSH+URG)"
        elif flags == "":
            detected = "NULL (no flags)"
        elif not any(c in flags for c in "SAFRPU"):
            detected = "Suspicious empty/rare flags"
        if detected is None:
            return None
        src_ip = getattr(parsed, "source_ip", "") or ""
        dst_ip = getattr(parsed, "destination_ip", "") or ""
        ts = getattr(parsed, "timestamp", None) or time.time()
        return IDSAlert(
            alert_id=f"flag-{int(ts * 1000):x}",
            alert_type=ALERT_SUSPICIOUS_FLAGS,
            severity=Severity.MEDIUM,
            timestamp=ts,
            source_ip=src_ip,
            destination_ip=dst_ip,
            source_port=int(getattr(parsed, "source_port", 0) or 0),
            destination_port=int(getattr(parsed, "destination_port", 0) or 0),
            message=(
                f"Packet with suspicious TCP flags [{flags}] detected "
                f"({detected}) from {src_ip} to {dst_ip}."
            ),
            recommended_action=(
                "Investigate potential OS fingerprinting or stealth scan attempt."
            ),
            details={"flags": flags, "combo": detected},
            is_demo=bool(getattr(parsed, "is_demo", False)),
        )

    def _check_packet_rate(self, parsed: Any) -> Optional[IDSAlert]:
        ts = getattr(parsed, "timestamp", None) or time.time()
        warning = max(100, self._config.ids.packet_rate_warning)
        critical = max(warning + 1, self._config.ids.packet_rate_critical)
        window = self._config.ids.detection_window_seconds
        self._rate_events.append(ts)
        cutoff = ts - window
        while self._rate_events and self._rate_events[0] < cutoff:
            self._rate_events.popleft()
        count = len(self._rate_events)
        if count >= critical:
            ratio = count / max(1, critical)
            self._rate_events.clear()
            return IDSAlert(
                alert_id=f"rate-{int(ts * 1000):x}",
                alert_type=ALERT_PACKET_RATE,
                severity=self._severity_for_ratio(ratio),
                timestamp=ts,
                observed_rate=count / max(1.0, window),
                threshold=critical / max(1.0, window),
                time_window_seconds=window,
                message=(
                    f"Abnormal packet rate: observed {count} packets in {window}s window "
                    f"(critical threshold {critical})."
                ),
                recommended_action=(
                    "Investigate capture interface traffic; consider sampling or raising thresholds."
                ),
                details={"count": count, "warning": warning, "critical": critical},
                is_demo=bool(getattr(parsed, "is_demo", False)),
            )
        return None

    def process(self, parsed: Any, raw_packet: Any = None) -> List[IDSAlert]:
        with self._lock:
            if not self._enabled:
                return []
        fired: List[IDSAlert] = []
        try:
            for check in (
                lambda p: self._syn.observe(p),
                lambda p: self._portscan.observe(p),
                lambda p: self._check_icmp_flood(p),
                lambda p: self._check_udp_flood(p),
                lambda p: self._check_ping_sweep(p),
                lambda p: self._check_suspicious_flags(p, raw_packet),
                lambda p: self._check_packet_rate(p),
            ):
                try:
                    alert = check(parsed)
                except Exception as e:
                    log_error("IDS check raised exception.", e)
                    continue
                if alert is None:
                    continue
                try:
                    recorded = self._alert_mgr.record(alert)
                except Exception as e:
                    log_error("IDS alert recording failed.", e)
                    recorded = False
                if not recorded:
                    continue
                fired.append(alert)
                try:
                    log_ids(alert.summary(), "WARNING")
                except Exception:
                    pass
        except Exception as e:
            log_error("Unexpected IDS processing error.", e)
        return fired
