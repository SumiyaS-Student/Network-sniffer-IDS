"""
Packet parsing: extracts structured fields from Scapy packets.
"""

import binascii
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from app.capture.packet_queue import PacketRecord
from app.analysis.protocol_detector import (
    ProtocolDetector, PROTO_TCP, PROTO_UDP, PROTO_ICMP, PROTO_ICMPV6,
    PROTO_ARP, PROTO_DNS, PROTO_DHCP, PROTO_OTHER,
)
from app.utils.time_utils import format_timestamp


KNOWN_PROTOCOLS = (
    "TCP", "UDP", "ICMP", "ICMPv6", "DNS", "DHCP", "ARP",
    "HTTP", "HTTPS", "FTP", "SSH", "SMTP", "IPv4", "IPv6", "Other",
)


@dataclass
class ParsedPacket:
    packet_number: int = 0
    timestamp: float = 0.0
    timestamp_str: str = ""
    source_ip: str = ""
    destination_ip: str = ""
    protocol: str = ""
    source_port: int = 0
    destination_port: int = 0
    length: int = 0
    ttl: int = 0
    tcp_flags: str = ""
    interface: str = ""
    status: str = "OK"
    is_demo: bool = False
    protocol_inferred: bool = False
    layers: List[str] = field(default_factory=list)
    raw_summary: str = ""
    raw_bytes: bytes = b""
    payload: bytes = b""
    source_mac: str = ""
    destination_mac: str = ""
    checksums: Dict[str, str] = field(default_factory=dict)
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_row(self) -> Tuple:
        return (
            self.packet_number,
            self.timestamp_str,
            self.source_ip,
            self.destination_ip,
            self.protocol,
            self.source_port or "",
            self.destination_port or "",
            self.length,
            self.interface,
            "DEMO" if self.is_demo else self.status,
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "packet_number": self.packet_number,
            "timestamp": self.timestamp,
            "timestamp_str": self.timestamp_str,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "protocol": self.protocol,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "length": self.length,
            "ttl": self.ttl,
            "tcp_flags": self.tcp_flags,
            "interface": self.interface,
            "status": self.status,
            "is_demo": self.is_demo,
            "protocol_inferred": self.protocol_inferred,
            "layers": self.layers,
            "raw_summary": self.raw_summary,
            "source_mac": self.source_mac,
            "destination_mac": self.destination_mac,
            "checksums": self.checksums,
        }

    def hex_view(self, width: int = 16) -> str:
        data = self.raw_bytes or b""
        lines = []
        for i in range(0, len(data), width):
            chunk = data[i:i + width]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"{i:08x}  {hex_part:<{width * 3}}  {ascii_part}")
        return "\n".join(lines)

    def ascii_view(self) -> str:
        data = self.raw_bytes or b""
        return "".join(chr(b) if 32 <= b < 127 else "." for b in data)

    def decoded_view(self) -> str:
        parts = [
            f"Packet #{self.packet_number} @ {self.timestamp_str}",
            f"Interface: {self.interface or 'N/A'}    Length: {self.length} bytes"
            + (f"    [DEMO DATA]" if self.is_demo else ""),
            "",
            f"Source:      {self.source_ip or 'N/A'}"
            + (f":{self.source_port}" if self.source_port else "")
            + (f"  ({self.source_mac})" if self.source_mac else ""),
            f"Destination: {self.destination_ip or 'N/A'}"
            + (f":{self.destination_port}" if self.destination_port else "")
            + (f"  ({self.destination_mac})" if self.destination_mac else ""),
            f"Protocol:    {self.protocol or PROTO_OTHER}"
            + ("  (port-based inference)" if self.protocol_inferred else ""),
        ]
        if self.ttl:
            parts.append(f"TTL:         {self.ttl}")
        if self.tcp_flags:
            parts.append(f"TCP Flags:   {self.tcp_flags}")
        if self.checksums:
            cks = ", ".join(f"{k}={v}" for k, v in self.checksums.items())
            parts.append(f"Checksums:   {cks}")
        if self.layers:
            parts.append(f"Layers:      {' / '.join(self.layers)}")
        if self.raw_summary:
            parts.append("")
            parts.append(f"Summary: {self.raw_summary}")
        extra = self.extra or {}
        if extra:
            parts.append("")
            parts.append("Protocol Details:")
            for k, v in extra.items():
                parts.append(f"  {k}: {v}")
        if self.payload:
            parts.append("")
            parts.append("Payload Preview (first 512 bytes):")
            try:
                text = self.payload[:512].decode("utf-8", errors="replace")
            except Exception:
                text = repr(self.payload[:512])
            parts.append(text)
        return "\n".join(parts)


class PacketParser:
    def __init__(self):
        self._lock = threading.RLock()
        self._cache: Dict[int, ParsedPacket] = {}
        self._cache_size = 10000

    def _ensure_l2_dst(self, pkt: Any) -> None:
        try:
            if not ProtocolDetector.has_layer(pkt, "Ether"):
                return
            ether = pkt["Ether"]
            if not ether.fields.get("dst"):
                ether.setfieldval("dst", "00:00:00:00:00:00")
            if not ether.fields.get("src"):
                ether.setfieldval("src", "00:00:00:00:00:00")
        except Exception:
            pass

    def _safe_get(self, pkt: Any, layer: str, field: str, default: Any = "") -> Any:
        try:
            layer_obj = pkt[layer]
            val = getattr(layer_obj, field, default)
            if val is None:
                return default
            return val
        except Exception:
            return default

    def parse_record(self, record: PacketRecord, force: bool = False) -> ParsedPacket:
        if record is None:
            return ParsedPacket()
        with self._lock:
            if not force and record.packet_number in self._cache:
                return self._cache[record.packet_number]
        parsed = ParsedPacket()
        parsed.packet_number = record.packet_number
        parsed.timestamp = record.timestamp
        parsed.timestamp_str = format_timestamp(record.timestamp)
        parsed.interface = record.interface or ""
        parsed.is_demo = record.is_demo

        pkt = record.scapy_packet
        if pkt is None:
            with self._lock:
                self._store_cache(parsed)
            return parsed

        self._ensure_l2_dst(pkt)

        try:
            parsed.length = len(pkt)
        except Exception:
            parsed.length = 0

        try:
            parsed.raw_summary = pkt.summary() if hasattr(pkt, "summary") else ""
        except Exception:
            parsed.raw_summary = ""

        try:
            parsed.raw_bytes = ProtocolDetector.raw_bytes(pkt)
        except Exception:
            parsed.raw_bytes = b""

        try:
            parsed.payload = bytes(pkt.payload) if hasattr(pkt, "payload") else b""
        except Exception:
            parsed.payload = b""

        parsed.layers = ProtocolDetector.detect_layers(pkt)

        try:
            parsed.source_mac = str(self._safe_get(pkt, "Ether", "src", ""))
            parsed.destination_mac = str(self._safe_get(pkt, "Ether", "dst", ""))
        except Exception:
            pass

        if ProtocolDetector.has_layer(pkt, "IP"):
            parsed.source_ip = str(self._safe_get(pkt, "IP", "src", ""))
            parsed.destination_ip = str(self._safe_get(pkt, "IP", "dst", ""))
            try:
                parsed.ttl = int(self._safe_get(pkt, "IP", "ttl", 0))
            except Exception:
                parsed.ttl = 0
            try:
                ip = pkt["IP"]
                if hasattr(ip, "chksum"):
                    parsed.checksums["IP"] = hex(int(ip.chksum))
            except Exception:
                pass
        elif ProtocolDetector.has_layer(pkt, "IPv6"):
            parsed.source_ip = str(self._safe_get(pkt, "IPv6", "src", ""))
            parsed.destination_ip = str(self._safe_get(pkt, "IPv6", "dst", ""))
            try:
                parsed.ttl = int(self._safe_get(pkt, "IPv6", "hlim", 0))
            except Exception:
                parsed.ttl = 0

        if ProtocolDetector.has_layer(pkt, PROTO_TCP):
            try:
                parsed.source_port = int(self._safe_get(pkt, "TCP", "sport", 0))
                parsed.destination_port = int(self._safe_get(pkt, "TCP", "dport", 0))
            except Exception:
                pass
            parsed.tcp_flags = ProtocolDetector.detect_tcp_flags(pkt)
            try:
                tcp = pkt["TCP"]
                if hasattr(tcp, "chksum"):
                    parsed.checksums["TCP"] = hex(int(tcp.chksum))
            except Exception:
                pass
        elif ProtocolDetector.has_layer(pkt, PROTO_UDP):
            try:
                parsed.source_port = int(self._safe_get(pkt, "UDP", "sport", 0))
                parsed.destination_port = int(self._safe_get(pkt, "UDP", "dport", 0))
            except Exception:
                pass
            try:
                udp = pkt["UDP"]
                if hasattr(udp, "chksum"):
                    parsed.checksums["UDP"] = hex(int(udp.chksum))
            except Exception:
                pass

        if ProtocolDetector.has_layer(pkt, PROTO_ARP):
            try:
                parsed.source_ip = str(self._safe_get(pkt, "ARP", "psrc", parsed.source_ip))
                parsed.destination_ip = str(self._safe_get(pkt, "ARP", "pdst", parsed.destination_ip))
                parsed.source_mac = str(self._safe_get(pkt, "ARP", "hwsrc", parsed.source_mac))
                parsed.destination_mac = str(self._safe_get(pkt, "ARP", "hwdst", parsed.destination_mac))
                op = self._safe_get(pkt, "ARP", "op", 0)
                op_map = {1: "Request", 2: "Reply", 3: "RARP Request", 4: "RARP Reply"}
                parsed.extra["ARP Opcode"] = op_map.get(int(op) if op else 0, f"Unknown({op})")
            except Exception:
                pass

        if ProtocolDetector.has_layer(pkt, PROTO_DNS) or ProtocolDetector.has_layer(pkt, "DNSQR") or ProtocolDetector.has_layer(pkt, "DNSRR"):
            try:
                dns = pkt["DNS"] if ProtocolDetector.has_layer(pkt, "DNS") else None
                if dns is not None:
                    qr = self._safe_get(dns, "DNS", "qr", None)
                    if qr is None:
                        qr = getattr(dns, "qr", None)
                    parsed.extra["DNS Response"] = bool(qr) if qr is not None else "N/A"
                    if hasattr(dns, "qd") and dns.qd is not None:
                        try:
                            parsed.extra["DNS Query"] = str(dns.qd.qname.decode("utf-8", errors="replace") if hasattr(dns.qd, "qname") else dns.qd)
                        except Exception:
                            pass
                    if hasattr(dns, "ancount"):
                        parsed.extra["DNS Answer Count"] = int(dns.ancount)
            except Exception:
                pass

        if ProtocolDetector.has_layer(pkt, PROTO_DHCP) or ProtocolDetector.has_layer(pkt, "BOOTP"):
            try:
                if ProtocolDetector.has_layer(pkt, PROTO_DHCP):
                    dhcp = pkt["DHCP"]
                    opts = getattr(dhcp, "options", None)
                    if opts:
                        parsed.extra["DHCP Options"] = str(opts)[:200]
                bootp = pkt["BOOTP"] if ProtocolDetector.has_layer(pkt, "BOOTP") else None
                if bootp is not None:
                    try:
                        parsed.extra["DHCP Client IP"] = str(getattr(bootp, "ciaddr", ""))
                        parsed.extra["DHCP Your IP"] = str(getattr(bootp, "yiaddr", ""))
                    except Exception:
                        pass
            except Exception:
                pass

        protocol, inferred = ProtocolDetector.primary_protocol(pkt)
        parsed.protocol = protocol or PROTO_OTHER
        parsed.protocol_inferred = inferred

        if parsed.protocol == PROTO_ICMP:
            try:
                icmp = pkt["ICMP"]
                t = int(getattr(icmp, "type", 0) or 0)
                c = int(getattr(icmp, "code", 0) or 0)
                parsed.extra["ICMP Type/Code"] = f"{t}/{c}"
            except Exception:
                pass

        if parsed.is_demo:
            parsed.status = "DEMO"
        else:
            parsed.status = "OK"

        with self._lock:
            self._store_cache(parsed)
        return parsed

    def _store_cache(self, parsed: ParsedPacket) -> None:
        key = parsed.packet_number
        if key <= 0:
            return
        self._cache[key] = parsed
        if len(self._cache) > self._cache_size * 2:
            keys = sorted(self._cache.keys())
            drop = len(keys) - self._cache_size
            if drop > 0:
                for k in keys[:drop]:
                    self._cache.pop(k, None)

    def clear_cache(self) -> None:
        with self._lock:
            self._cache.clear()
