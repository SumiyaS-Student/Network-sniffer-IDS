"""
Protocol detection using Scapy layers with application-level inferences.
"""

from typing import Any, List, Tuple, Dict, Optional


PROTO_TCP = "TCP"
PROTO_UDP = "UDP"
PROTO_ICMP = "ICMP"
PROTO_ICMPV6 = "ICMPv6"
PROTO_DNS = "DNS"
PROTO_DHCP = "DHCP"
PROTO_ARP = "ARP"
PROTO_HTTP = "HTTP"
PROTO_HTTPS = "HTTPS"
PROTO_FTP = "FTP"
PROTO_SSH = "SSH"
PROTO_SMTP = "SMTP"
PROTO_IPV6 = "IPv6"
PROTO_IPV4 = "IPv4"
PROTO_OTHER = "Other"


COMMON_APP_PORTS = {
    80: PROTO_HTTP,
    8080: PROTO_HTTP,
    8000: PROTO_HTTP,
    443: PROTO_HTTPS,
    8443: PROTO_HTTPS,
    21: PROTO_FTP,
    20: PROTO_FTP,
    22: PROTO_SSH,
    25: PROTO_SMTP,
    465: PROTO_SMTP,
    587: PROTO_SMTP,
    53: PROTO_DNS,
    67: PROTO_DHCP,
    68: PROTO_DHCP,
}


HTTP_METHODS = (
    b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ",
    b"OPTIONS ", b"TRACE ", b"CONNECT ", b"PATCH ",
    b"HTTP/1.", b"HTTP/2",
)

TLS_RECORD_TYPES = {0x14, 0x15, 0x16, 0x17, 0x18}


class ProtocolDetector:
    @staticmethod
    def detect_layers(pkt: Any) -> List[str]:
        layers: List[str] = []
        if pkt is None:
            return layers
        try:
            layer = pkt
            count = 0
            while layer is not None and count < 30:
                name = layer.__class__.__name__
                if name and name not in layers:
                    layers.append(name)
                if not hasattr(layer, "payload") or layer.payload is None:
                    break
                layer = layer.payload
                if layer is getattr(layer, "__class__", type(None)):
                    break
                count += 1
        except Exception:
            pass
        return layers

    @staticmethod
    def has_layer(pkt: Any, layer_name: str) -> bool:
        if pkt is None:
            return False
        try:
            return pkt.haslayer(layer_name)
        except Exception:
            return any(layer_name in l for l in ProtocolDetector.detect_layers(pkt))

    @staticmethod
    def _payload_bytes(pkt: Any) -> bytes:
        try:
            return bytes(pkt.payload)
        except Exception:
            try:
                return raw(pkt) if False else b""
            except Exception:
                return b""

    @staticmethod
    def raw_bytes(pkt: Any) -> bytes:
        if pkt is None:
            return b""
        try:
            from scapy.compat import raw
            return raw(pkt)
        except Exception:
            try:
                return bytes(pkt)
            except Exception:
                return b""

    @staticmethod
    def detect_tcp_flags(pkt: Any) -> str:
        if not ProtocolDetector.has_layer(pkt, "TCP"):
            return ""
        try:
            tcp = pkt["TCP"]
            flags_val = int(tcp.flags)
            flag_map = [
                ("S", 0x02), ("F", 0x01), ("R", 0x04), ("P", 0x08),
                ("A", 0x10), ("U", 0x20), ("E", 0x40), ("C", 0x80),
                ("N", 0x100),
            ]
            flags = "".join(ch for ch, bit in flag_map if flags_val & bit)
            return flags
        except Exception:
            return ""

    @staticmethod
    def is_tcp_flag_combo(pkt: Any, expected: str) -> bool:
        flags = ProtocolDetector.detect_tcp_flags(pkt)
        if not flags or not expected:
            return False
        return all(c in flags for c in expected)

    @staticmethod
    def detect_application_protocol(pkt: Any, sport: int, dport: int) -> Tuple[str, bool]:
        inferred = False
        protocol = PROTO_OTHER

        if ProtocolDetector.has_layer(pkt, "DNS") or ProtocolDetector.has_layer(pkt, "DNSQR") or ProtocolDetector.has_layer(pkt, "DNSRR"):
            return PROTO_DNS, False
        if ProtocolDetector.has_layer(pkt, "DHCP") or ProtocolDetector.has_layer(pkt, "BOOTP"):
            return PROTO_DHCP, False
        if sport == 53 or dport == 53:
            payload = ProtocolDetector.raw_bytes(pkt)
            if len(payload) >= 12:
                try:
                    flags = int.from_bytes(payload[2:4], "big")
                    qd = int.from_bytes(payload[4:6], "big")
                    if qd <= 100 and (flags & 0x8000 == 0 or True):
                        return PROTO_DNS, True
                except Exception:
                    pass

        raw = ProtocolDetector.raw_bytes(pkt)
        if raw and (raw[:3] == b"\x16\x03\x01" or raw[:3] == b"\x16\x03\x02" or raw[:3] == b"\x16\x03\x03"):
            return PROTO_HTTPS, False
        if len(raw) >= 5 and raw[0] in TLS_RECORD_TYPES and raw[1] == 0x03 and raw[2] in (0x00, 0x01, 0x02, 0x03, 0x04):
            return PROTO_HTTPS, False

        payload = ProtocolDetector._payload_bytes(pkt) or raw
        if payload:
            head = payload[:512]
            for method in HTTP_METHODS:
                if head.startswith(method):
                    return PROTO_HTTP, False
            stripped = head.lstrip()
            for method in HTTP_METHODS:
                if stripped.startswith(method):
                    return PROTO_HTTP, False

        if sport in COMMON_APP_PORTS:
            protocol = COMMON_APP_PORTS[sport]
            inferred = True
        elif dport in COMMON_APP_PORTS:
            protocol = COMMON_APP_PORTS[dport]
            inferred = True
        return protocol, inferred

    @staticmethod
    def primary_protocol(pkt: Any) -> Tuple[str, bool]:
        if pkt is None:
            return PROTO_OTHER, False

        if ProtocolDetector.has_layer(pkt, "ARP"):
            return PROTO_ARP, False

        sport = 0
        dport = 0
        transport = PROTO_OTHER
        if ProtocolDetector.has_layer(pkt, "TCP"):
            transport = PROTO_TCP
            try:
                sport = int(pkt["TCP"].sport)
                dport = int(pkt["TCP"].dport)
            except Exception:
                pass
        elif ProtocolDetector.has_layer(pkt, "UDP"):
            transport = PROTO_UDP
            try:
                sport = int(pkt["UDP"].sport)
                dport = int(pkt["UDP"].dport)
            except Exception:
                pass
        elif ProtocolDetector.has_layer(pkt, "ICMP"):
            return PROTO_ICMP, False
        elif ProtocolDetector.has_layer(pkt, "ICMPv6") or \
                ProtocolDetector.has_layer(pkt, "ICMPv6ND_NS") or \
                ProtocolDetector.has_layer(pkt, "ICMPv6ND_RA") or \
                ProtocolDetector.has_layer(pkt, "ICMPv6EchoRequest") or \
                ProtocolDetector.has_layer(pkt, "ICMPv6EchoReply"):
            return PROTO_ICMPV6, False

        app, inferred = ProtocolDetector.detect_application_protocol(pkt, sport, dport)
        if app != PROTO_OTHER:
            return app, inferred

        if ProtocolDetector.has_layer(pkt, "IPv6"):
            return PROTO_IPV6 if transport == PROTO_OTHER else transport, False
        if ProtocolDetector.has_layer(pkt, "IP"):
            return PROTO_IPV4 if transport == PROTO_OTHER else transport, False
        return transport, False
