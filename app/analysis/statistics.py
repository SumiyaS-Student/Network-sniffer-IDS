"""
Packet statistics aggregation with protocol counts and IP rankings.
"""

import threading
import time
from collections import defaultdict, Counter, deque
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, List, Optional, Tuple

from app.analysis.packet_parser import ParsedPacket, PacketParser, KNOWN_PROTOCOLS
from app.analysis.protocol_detector import (
    PROTO_TCP, PROTO_UDP, PROTO_ICMP, PROTO_ICMPV6, PROTO_DNS, PROTO_DHCP,
    PROTO_ARP, PROTO_HTTP, PROTO_HTTPS, PROTO_FTP, PROTO_SSH, PROTO_SMTP,
    PROTO_OTHER, PROTO_IPV4, PROTO_IPV6,
)


RATE_WINDOW_SECONDS = 1


@dataclass
class ProtocolCounts:
    TCP: int = 0
    UDP: int = 0
    ICMP: int = 0
    ICMPv6: int = 0
    DNS: int = 0
    DHCP: int = 0
    ARP: int = 0
    HTTP: int = 0
    HTTPS: int = 0
    FTP: int = 0
    SSH: int = 0
    SMTP: int = 0
    IPv4: int = 0
    IPv6: int = 0
    Other: int = 0

    def total(self) -> int:
        return (self.TCP + self.UDP + self.ICMP + self.ICMPv6 + self.DNS
                + self.DHCP + self.ARP + self.HTTP + self.HTTPS + self.FTP
                + self.SSH + self.SMTP + self.Other)

    def items(self) -> List[Tuple[str, int]]:
        return [
            ("TCP", self.TCP), ("UDP", self.UDP), ("ICMP", self.ICMP),
            ("ICMPv6", self.ICMPv6), ("DNS", self.DNS), ("DHCP", self.DHCP),
            ("ARP", self.ARP), ("HTTP", self.HTTP), ("HTTPS", self.HTTPS),
            ("FTP", self.FTP), ("SSH", self.SSH), ("SMTP", self.SMTP),
            ("Other", self.Other),
        ]


@dataclass
class RateSample:
    timestamp: float
    packets: int
    bytes: int


class Statistics:
    def __init__(self, rate_history_seconds: int = 600):
        self._lock = threading.RLock()
        self._parser = PacketParser()
        self._total_packets = 0
        self._total_bytes = 0
        self._protocols = ProtocolCounts()
        self._src_ip_counter: Counter = Counter()
        self._dst_ip_counter: Counter = Counter()
        self._src_port_counter: Counter = Counter()
        self._dst_port_counter: Counter = Counter()
        self._rate_window_start = time.time()
        self._rate_window_packets = 0
        self._rate_window_bytes = 0
        self._last_packets_per_second = 0.0
        self._last_bytes_per_second = 0.0
        self._rate_history: Deque[RateSample] = deque(maxlen=max(60, int(rate_history_seconds / max(1, RATE_WINDOW_SECONDS))))
        self._first_seen: Optional[float] = None
        self._last_seen: Optional[float] = None
        self._demo_packets = 0

    @property
    def parser(self) -> PacketParser:
        return self._parser

    def reset(self) -> None:
        with self._lock:
            self._total_packets = 0
            self._total_bytes = 0
            self._protocols = ProtocolCounts()
            self._src_ip_counter.clear()
            self._dst_ip_counter.clear()
            self._src_port_counter.clear()
            self._dst_port_counter.clear()
            self._rate_window_start = time.time()
            self._rate_window_packets = 0
            self._rate_window_bytes = 0
            self._last_packets_per_second = 0.0
            self._last_bytes_per_second = 0.0
            self._rate_history.clear()
            self._first_seen = None
            self._last_seen = None
            self._demo_packets = 0
            self._parser.clear_cache()

    def _bump_rate(self, now: float, length: int) -> None:
        elapsed = now - self._rate_window_start
        if elapsed >= RATE_WINDOW_SECONDS:
            if elapsed <= 0:
                elapsed = 1.0
            pps = self._rate_window_packets / elapsed
            bps = self._rate_window_bytes / elapsed
            self._last_packets_per_second = pps
            self._last_bytes_per_second = bps
            self._rate_history.append(RateSample(
                timestamp=self._rate_window_start, packets=self._rate_window_packets,
                bytes=self._rate_window_bytes,
            ))
            self._rate_window_start = now
            self._rate_window_packets = 0
            self._rate_window_bytes = 0
        self._rate_window_packets += 1
        self._rate_window_bytes += max(0, int(length))

    def update(self, parsed: ParsedPacket) -> None:
        if parsed is None:
            return
        with self._lock:
            self._total_packets += 1
            self._total_bytes += max(0, int(parsed.length))
            if self._first_seen is None or parsed.timestamp < self._first_seen:
                self._first_seen = parsed.timestamp
            if self._last_seen is None or parsed.timestamp > self._last_seen:
                self._last_seen = parsed.timestamp
            if parsed.is_demo:
                self._demo_packets += 1
            proto = (parsed.protocol or PROTO_OTHER).strip()
            if hasattr(self._protocols, proto):
                setattr(self._protocols, proto, getattr(self._protocols, proto) + 1)
            else:
                self._protocols.Other += 1
            if parsed.source_ip:
                self._src_ip_counter[parsed.source_ip] += 1
            if parsed.destination_ip:
                self._dst_ip_counter[parsed.destination_ip] += 1
            if parsed.source_port:
                self._src_port_counter[int(parsed.source_port)] += 1
            if parsed.destination_port:
                self._dst_port_counter[int(parsed.destination_port)] += 1
            now = parsed.timestamp or time.time()
            self._bump_rate(now, parsed.length)

    def update_from_record(self, record: Any, force: bool = False) -> None:
        parsed = self._parser.parse_record(record, force=force)
        self.update(parsed)

    @property
    def total_packets(self) -> int:
        with self._lock:
            return self._total_packets

    @property
    def total_bytes(self) -> int:
        with self._lock:
            return self._total_bytes

    @property
    def demo_packets(self) -> int:
        with self._lock:
            return self._demo_packets

    def packets_per_second(self) -> float:
        with self._lock:
            now = time.time()
            elapsed = now - self._rate_window_start
            if elapsed <= 0:
                return self._last_packets_per_second
            recent = (self._rate_window_packets / elapsed) if elapsed > 0 else 0.0
            if self._rate_history:
                return max(self._last_packets_per_second, recent)
            return recent

    def bytes_per_second(self) -> float:
        with self._lock:
            now = time.time()
            elapsed = now - self._rate_window_start
            if elapsed <= 0:
                return self._last_bytes_per_second
            recent = (self._rate_window_bytes / elapsed) if elapsed > 0 else 0.0
            if self._rate_history:
                return max(self._last_bytes_per_second, recent)
            return recent

    def protocol_counts(self) -> ProtocolCounts:
        with self._lock:
            p = ProtocolCounts()
            for name, value in self._protocols.items():
                if hasattr(p, name):
                    setattr(p, name, value)
            return p

    def top_source_ips(self, limit: int = 10) -> List[Tuple[str, int]]:
        with self._lock:
            return self._src_ip_counter.most_common(limit)

    def top_destination_ips(self, limit: int = 10) -> List[Tuple[str, int]]:
        with self._lock:
            return self._dst_ip_counter.most_common(limit)

    def top_source_ports(self, limit: int = 10) -> List[Tuple[int, int]]:
        with self._lock:
            return self._src_port_counter.most_common(limit)

    def top_destination_ports(self, limit: int = 10) -> List[Tuple[int, int]]:
        with self._lock:
            return self._dst_port_counter.most_common(limit)

    def rate_history(self, limit: Optional[int] = None) -> List[RateSample]:
        with self._lock:
            items = list(self._rate_history)
            if limit and len(items) > limit:
                return items[-limit:]
            return items

    def uptime_seconds(self) -> float:
        with self._lock:
            if self._first_seen is None:
                return 0.0
            end = self._last_seen or time.time()
            return max(0.0, end - self._first_seen)
