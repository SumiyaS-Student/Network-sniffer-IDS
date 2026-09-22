"""
Demo / Test mode generator: injects synthetic packets for safe local testing.
"""

import threading
import time
import random
from dataclasses import dataclass
from typing import Any, Callable, List, Optional

from app.logging.logger import log_capture, log_error


def _ensure_scapy():
    try:
        from scapy.all import (
            Ether, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, DHCP, BOOTP,
            Raw, ARP, RandShort,
        )
        return True
    except Exception:
        return False


SCAPY_AVAILABLE = _ensure_scapy()


@dataclass
class DemoScenario:
    name: str
    duration_seconds: float = 3.0
    packets_per_second: float = 20.0
    description: str = ""

    def label(self) -> str:
        return f"{self.name} — {self.description}"


SCENARIOS = [
    DemoScenario("Normal TCP", 4.0, 20.0, "Standard TCP handshakes and data (HTTP-like)"),
    DemoScenario("Normal UDP + DNS", 4.0, 25.0, "DNS queries and replies over UDP"),
    DemoScenario("ICMP Pings", 3.0, 15.0, "ICMP echo request/reply pairs"),
    DemoScenario("DHCP Discover/Offer", 3.0, 5.0, "Simulated DHCP handshake over UDP"),
    DemoScenario("SYN Flood Pattern", 5.0, 80.0, "SYN packets from single source to trigger detection"),
    DemoScenario("Port Scan Pattern", 5.0, 30.0, "Distinct destination ports to trigger scan detection"),
    DemoScenario("Mixed Traffic", 5.0, 25.0, "TCP / UDP / ICMP / ARP mix for demo tables"),
]


class DemoGenerator:
    def __init__(self, packet_injector: Callable[[Any, Optional[int]], None]):
        self._inject = packet_injector
        self._lock = threading.RLock()
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._active = False

    def is_active(self) -> bool:
        with self._lock:
            return self._active

    def available(self) -> bool:
        return True

    def scenarios(self) -> List[DemoScenario]:
        return list(SCENARIOS)

    def start_scenario(self, scenario: DemoScenario) -> bool:
        with self._lock:
            if self._active:
                return False
            self._stop.clear()
            self._thread = threading.Thread(
                target=self._run_scenario, args=(scenario,),
                name=f"DemoGen-{scenario.name}", daemon=True,
            )
            self._active = True
            self._thread.start()
            log_capture(
                f"DEMO scenario started: {scenario.name} ({scenario.description})",
                "INFO",
            )
            return True

    def stop(self) -> None:
        with self._lock:
            self._stop.set()
            t = self._thread
        if t and t.is_alive():
            t.join(timeout=5.0)
        with self._lock:
            self._active = False

    def _run_scenario(self, scenario: DemoScenario) -> None:
        if not SCAPY_AVAILABLE:
            try:
                from scapy.all import (
                    Ether, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, DHCP, BOOTP,
                    Raw, ARP, RandShort,
                )
            except Exception as e:
                log_error("Demo mode requires Scapy; please install Scapy.", e)
                with self._lock:
                    self._active = False
                return
        from scapy.all import (
            Ether, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, DHCP, BOOTP,
            Raw, ARP, RandShort,
        )
        try:
            rng = random.Random(0xA5A5A5)
            start = time.time()
            pps = max(1.0, float(scenario.packets_per_second))
            interval = 1.0 / pps
            while not self._stop.is_set():
                elapsed = time.time() - start
                if elapsed >= float(scenario.duration_seconds):
                    break
                pkt = self._build_packet(scenario, rng)
                try:
                    length = len(pkt)
                except Exception:
                    length = 0
                try:
                    self._inject(pkt, length)
                except Exception as e:
                    log_error("Demo packet injection failed.", e)
                    break
                # small jitter
                sleep_time = max(0.0, interval * (0.7 + 0.6 * rng.random()))
                if self._stop.wait(sleep_time):
                    break
        finally:
            with self._lock:
                self._active = False
            log_capture(f"DEMO scenario finished: {scenario.name}", "INFO")

    def _build_packet(self, scenario: DemoScenario, rng: random.Random) -> Any:
        from scapy.all import (
            Ether, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, DHCP, BOOTP,
            Raw, ARP, RandShort,
        )
        name = scenario.name
        src_mac = "02:00:00:DE:AD:01"
        dst_mac = "02:00:00:DE:AD:02"
        src_ip = f"10.0.0.{rng.randint(2, 254)}"
        dst_ip = f"10.0.1.{rng.randint(2, 254)}"
        if "TCP" in name and "Flood" in name:
            src_ip = "10.99.99.99"
            dst_ip = "10.99.1.1"
            return (Ether(src=src_mac, dst=dst_mac) /
                    IP(src=src_ip, dst=dst_ip, ttl=64) /
                    TCP(sport=rng.randint(1024, 65535), dport=80, flags="S",
                        seq=rng.randint(1000, 999999999)))
        if "Port Scan" in name:
            src_ip = "10.77.77.77"
            dst_ip = "10.77.1.5"
            try:
                port_list = list(range(1, 1025))
                rng.shuffle(port_list)
                dport = port_list[0]
            except Exception:
                dport = rng.randint(1, 1024)
            return (Ether(src=src_mac, dst=dst_mac) /
                    IP(src=src_ip, dst=dst_ip, ttl=64) /
                    TCP(sport=rng.randint(1024, 65535), dport=dport, flags="S"))
        if "TCP" in name:
            payload = b"GET / HTTP/1.1\r\nHost: demo.local\r\n\r\n" if rng.random() < 0.5 else b""
            flags = "S" if rng.random() < 0.3 else ("PA" if payload else "A")
            return (Ether(src=src_mac, dst=dst_mac) /
                    IP(src=src_ip, dst=dst_ip, ttl=64) /
                    TCP(sport=rng.randint(1024, 65535),
                        dport=rng.choice([80, 443, 22, 25, 21, 8080]),
                        flags=flags) /
                    (Raw(load=payload) if payload else b""))
        if "DNS" in name:
            qname = rng.choice([b"example.com", b"test.local", b"demo.corp", b"site.example"])
            is_reply = rng.random() < 0.5
            if is_reply:
                return (Ether(src=src_mac, dst=dst_mac) /
                        IP(src=dst_ip, dst=src_ip) /
                        UDP(sport=53, dport=rng.randint(1024, 65535)) /
                        DNS(qr=1, qd=DNSQR(qname=qname)))
            return (Ether(src=src_mac, dst=dst_mac) /
                    IP(src=src_ip, dst=dst_ip) /
                    UDP(sport=rng.randint(1024, 65535), dport=53) /
                    DNS(rd=1, qd=DNSQR(qname=qname)))
        if "DHCP" in name:
            mac = "02:00:DE:AD:00:%02x" % rng.randint(1, 254)
            # DHCP discover/offer simplified
            return (Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") /
                    IP(src="0.0.0.0", dst="255.255.255.255") /
                    UDP(sport=68, dport=67) /
                    BOOTP(chaddr=mac.replace(":", ""), xid=rng.randint(1, 2**32 - 1)) /
                    DHCP(options=[("message-type", "discover" if rng.random() < 0.5 else "offer"),
                                  "end"]))
        if "ICMP" in name:
            t = 8 if rng.random() < 0.5 else 0
            return (Ether(src=src_mac, dst=dst_mac) /
                    IP(src=src_ip, dst=dst_ip, ttl=64) /
                    ICMP(type=t, id=rng.randint(1, 65535),
                         seq=rng.randint(1, 65535)) /
                    Raw(load=bytes(range(32))))
        if "Mixed" in name:
            kinds = ["tcp", "udp", "icmp", "arp", "dns"]
            k = rng.choice(kinds)
            if k == "arp":
                return (Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff") /
                        ARP(op=1, psrc=src_ip, pdst=dst_ip,
                            hwsrc=src_mac, hwdst="00:00:00:00:00:00"))
            if k == "tcp":
                return (Ether(src=src_mac, dst=dst_mac) /
                        IP(src=src_ip, dst=dst_ip) /
                        TCP(sport=rng.randint(1024, 65535),
                            dport=rng.choice([80, 443, 22, 25, 21]),
                            flags="S" if rng.random() < 0.2 else "A"))
            if k == "udp":
                return (Ether(src=src_mac, dst=dst_mac) /
                        IP(src=src_ip, dst=dst_ip) /
                        UDP(sport=rng.randint(1024, 65535),
                            dport=rng.choice([53, 123, 161, 5060])) /
                        Raw(load=bytes(range(16))))
            if k == "dns":
                return (Ether(src=src_mac, dst=dst_mac) /
                        IP(src=src_ip, dst=dst_ip) /
                        UDP(sport=rng.randint(1024, 65535), dport=53) /
                        DNS(rd=1, qd=DNSQR(qname=b"mixed-demo.local")))
            # icmp
            return (Ether(src=src_mac, dst=dst_mac) /
                    IP(src=src_ip, dst=dst_ip) /
                    ICMP(type=8))
        # default = normal TCP
        return (Ether(src=src_mac, dst=dst_mac) /
                IP(src=src_ip, dst=dst_ip) /
                TCP(sport=rng.randint(1024, 65535), dport=80, flags="S"))
