"""
Automated tests using synthetic Scapy packets. No real network capture required.
"""

import os
import sys
import time
import unittest
import tempfile
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app.utils.paths import ensure_all_directories, PROJECT_ROOT as PR
from app.utils.security import hash_password, verify_password, generate_token, constant_time_compare
from app.utils.time_utils import (
    now_epoch, format_timestamp, format_hms, humanize_bytes, short_moment,
)

ensure_all_directories()


def _make_packet(layers_spec):
    from scapy.all import (
        Ether, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, DNSRR,
        DHCP, BOOTP, ARP, Raw,
    )
    pkt = None
    for name, kwargs in layers_spec:
        if name == "Ether":
            layer = Ether(**kwargs)
        elif name == "IP":
            layer = IP(**kwargs)
        elif name == "IPv6":
            layer = IPv6(**kwargs)
        elif name == "TCP":
            layer = TCP(**kwargs)
        elif name == "UDP":
            layer = UDP(**kwargs)
        elif name == "ICMP":
            layer = ICMP(**kwargs)
        elif name == "DNS":
            layer = DNS(**kwargs)
        elif name == "DNSQR":
            layer = DNSQR(**kwargs)
        elif name == "ARP":
            layer = ARP(**kwargs)
        elif name == "BOOTP":
            layer = BOOTP(**kwargs)
        elif name == "DHCP":
            layer = DHCP(**kwargs)
        elif name == "Raw":
            layer = Raw(**kwargs)
        else:
            continue
        pkt = pkt / layer if pkt is not None else layer
    return pkt


class TestSecurity(unittest.TestCase):
    def test_hash_and_verify_password_roundtrip(self):
        pw = "correct horse battery staple"
        h, s = hash_password(pw)
        self.assertTrue(verify_password(pw, h, s))

    def test_verify_rejects_wrong_password(self):
        h, s = hash_password("good")
        self.assertFalse(verify_password("bad", h, s))

    def test_verify_rejects_bad_base64(self):
        self.assertFalse(verify_password("x", "!!!", "!!!"))

    def test_generate_token_is_unique(self):
        self.assertNotEqual(generate_token(8), generate_token(8))

    def test_constant_time_compare(self):
        self.assertTrue(constant_time_compare("abc", "abc"))
        self.assertFalse(constant_time_compare("abc", "abd"))


class TestTimeUtils(unittest.TestCase):
    def test_humanize_bytes(self):
        self.assertEqual(humanize_bytes(0), "0 B")
        self.assertTrue(humanize_bytes(2048).endswith("KB"))

    def test_format_hms(self):
        self.assertEqual(format_hms(61), "01:01")
        self.assertEqual(format_hms(3661), "01:01:01")

    def test_format_timestamp_does_not_raise(self):
        for v in [None, 0, time.time(), "invalid"]:
            format_timestamp(v)  # just ensure no exceptions


class TestConfig(unittest.TestCase):
    def test_setup_and_verify_password(self):
        from config import AppConfig
        from app.utils.paths import unique_path

        path = unique_path(tempfile.gettempdir(), "test_config.json")
        try:
            cfg = AppConfig(config_path=path)
            self.assertTrue(cfg.setup_password("some_password"))
            self.assertTrue(cfg.verify_password("some_password"))
            self.assertFalse(cfg.verify_password("wrong"))
            self.assertTrue(cfg.is_password_setup())
            cfg2 = AppConfig(config_path=path)
            self.assertTrue(cfg2.verify_password("some_password"))
        finally:
            try:
                os.remove(path)
            except OSError:
                pass


class TestAuthManager(unittest.TestCase):
    def setUp(self):
        self.path = Path(tempfile.mkdtemp()) / "auth_test.json"
        from config import AppConfig
        AppConfig(config_path=self.path)  # create default
        # override singleton for this test by creating fresh instance with saved path
        self.cfg = AppConfig(config_path=self.path)
        self.cfg.setup_password("initial123")
        self.cfg.save()

    def tearDown(self):
        try:
            os.remove(self.path)
        except OSError:
            pass

    def test_authenticate_ok(self):
        from app.authentication.auth_manager import AuthManager
        mgr = AuthManager()
        # Re-bind AuthManager singleton internals by creating fresh instance
        mgr._config = self.cfg
        sid = mgr.authenticate("admin", "initial123")
        self.assertIsNotNone(sid)
        self.assertTrue(mgr.validate_session(sid))

    def test_authenticate_wrong(self):
        from app.authentication.auth_manager import AuthManager
        mgr = AuthManager()
        mgr._config = self.cfg
        sid = mgr.authenticate("admin", "wrong")
        self.assertIsNone(sid)


class TestProtocolDetector(unittest.TestCase):
    def test_tcp_detection(self):
        from app.analysis.protocol_detector import ProtocolDetector
        pkt = _make_packet([("Ether", {}), ("IP", {"src": "1.1.1.1", "dst": "2.2.2.2"}),
                            ("TCP", {"sport": 1234, "dport": 80, "flags": "S"})])
        proto, _inferred = ProtocolDetector.primary_protocol(pkt)
        self.assertEqual(proto, "HTTP")

    def test_udp_detection(self):
        from app.analysis.protocol_detector import ProtocolDetector
        pkt = _make_packet([("Ether", {}), ("IP", {"src": "1.1.1.1", "dst": "2.2.2.2"}),
                            ("UDP", {"sport": 1234, "dport": 1111})])
        proto, _ = ProtocolDetector.primary_protocol(pkt)
        self.assertEqual(proto, "UDP")

    def test_icmp_detection(self):
        from app.analysis.protocol_detector import ProtocolDetector
        pkt = _make_packet([("Ether", {}), ("IP", {}), ("ICMP", {"type": 8})])
        proto, _ = ProtocolDetector.primary_protocol(pkt)
        self.assertEqual(proto, "ICMP")

    def test_dns_via_layer(self):
        from app.analysis.protocol_detector import ProtocolDetector
        pkt = _make_packet([("Ether", {}), ("IP", {}),
                            ("UDP", {"sport": 1234, "dport": 53}),
                            ("DNS", {"rd": 1, "qd": _make_packet([("DNSQR", {"qname": b"example.com"})])})])
        proto, inferred = ProtocolDetector.primary_protocol(pkt)
        self.assertEqual(proto, "DNS")
        self.assertFalse(inferred)

    def test_arp(self):
        from app.analysis.protocol_detector import ProtocolDetector
        pkt = _make_packet([("Ether", {}),
                            ("ARP", {"op": 1, "psrc": "10.0.0.1", "pdst": "10.0.0.2"})])
        proto, _ = ProtocolDetector.primary_protocol(pkt)
        self.assertEqual(proto, "ARP")

    def test_tcp_flags(self):
        from app.analysis.protocol_detector import ProtocolDetector
        pkt = _make_packet([("Ether", {}), ("IP", {}),
                            ("TCP", {"sport": 1234, "dport": 22, "flags": "SA"})])
        flags = ProtocolDetector.detect_tcp_flags(pkt)
        self.assertIn("S", flags)
        self.assertIn("A", flags)


class TestPacketParser(unittest.TestCase):
    def test_parse_basic_tcp(self):
        from app.capture.packet_queue import PacketRecord
        from app.analysis.packet_parser import PacketParser
        pkt = _make_packet([("Ether", {"src": "aa:bb:cc:dd:ee:ff", "dst": "11:22:33:44:55:66"}),
                            ("IP", {"src": "10.0.0.1", "dst": "10.0.0.2", "ttl": 64}),
                            ("TCP", {"sport": 1234, "dport": 443, "flags": "S"})])
        rec = PacketRecord(packet_number=1, timestamp=time.time(),
                           scapy_packet=pkt, interface="eth0")
        parser = PacketParser()
        parsed = parser.parse_record(rec)
        self.assertEqual(parsed.packet_number, 1)
        self.assertEqual(parsed.source_ip, "10.0.0.1")
        self.assertEqual(parsed.destination_ip, "10.0.0.2")
        self.assertEqual(parsed.source_port, 1234)
        self.assertEqual(parsed.destination_port, 443)
        self.assertEqual(parsed.ttl, 64)
        self.assertIn("S", parsed.tcp_flags)
        self.assertTrue(parsed.length > 0)

    def test_hex_ascii_views(self):
        from app.capture.packet_queue import PacketRecord
        from app.analysis.packet_parser import PacketParser
        pkt = _make_packet([("Ether", {}), ("IP", {}),
                            ("TCP", {"sport": 1, "dport": 2, "flags": "S"})])
        rec = PacketRecord(packet_number=2, timestamp=time.time(), scapy_packet=pkt)
        p = PacketParser().parse_record(rec)
        self.assertIn("00000000", p.hex_view())
        # ASCII view is always a string of same length as bytes
        self.assertEqual(len(p.ascii_view()), len(p.raw_bytes or b""))


class TestStatistics(unittest.TestCase):
    def test_counts(self):
        from app.analysis.statistics import Statistics
        from app.capture.packet_queue import PacketRecord
        s = Statistics()
        for i in range(50):
            pkt = _make_packet([("Ether", {}), ("IP", {"src": f"10.0.0.{i % 10}", "dst": "10.1.0.1"}),
                                ("TCP", {"sport": 1000 + i, "dport": 80})])
            rec = PacketRecord(packet_number=i + 1, timestamp=time.time() + i,
                               scapy_packet=pkt, interface="eth0")
            s.update_from_record(rec)
        self.assertEqual(s.total_packets, 50)
        self.assertGreater(s.protocol_counts().HTTP + s.protocol_counts().TCP, 0)
        self.assertTrue(len(s.top_source_ips(5)) <= 5)


class TestIDS(unittest.TestCase):
    def test_syn_flood_triggers(self):
        from app.ids.syn_flood import SYNFloodDetector
        det = SYNFloodDetector(threshold=20, window_seconds=1,
                                alert_manager=None)
        alerts = []
        for i in range(25):
            pkt = _make_packet([("Ether", {}), ("IP", {"src": "9.9.9.9", "dst": "8.8.8.8"}),
                                ("TCP", {"sport": 1000 + i, "dport": 80, "flags": "S"})])
            from app.analysis.packet_parser import PacketParser
            from app.capture.packet_queue import PacketRecord
            rec = PacketRecord(packet_number=i, timestamp=time.time(), scapy_packet=pkt)
            parsed = PacketParser().parse_record(rec)
            a = det.observe(parsed)
            if a:
                alerts.append(a)
        self.assertTrue(any(a.alert_type.startswith("Possible SYN Flood") for a in alerts))

    def test_port_scan_triggers(self):
        from app.ids.port_scan import PortScanDetector
        det = PortScanDetector(ports_threshold=10, window_seconds=1,
                               alert_manager=None)
        alerts = []
        for i in range(1, 20):
            pkt = _make_packet([("Ether", {}), ("IP", {"src": "1.2.3.4", "dst": "5.6.7.8"}),
                                ("TCP", {"sport": 2000, "dport": i, "flags": "S"})])
            from app.analysis.packet_parser import PacketParser
            from app.capture.packet_queue import PacketRecord
            rec = PacketRecord(packet_number=i, timestamp=time.time(), scapy_packet=pkt)
            parsed = PacketParser().parse_record(rec)
            a = det.observe(parsed)
            if a:
                alerts.append(a)
        self.assertTrue(any(a.alert_type.startswith("Possible Port Scan") for a in alerts))

    def test_alert_cooldown(self):
        from app.ids.alerts import AlertManager, IDSAlert, Severity
        mgr = AlertManager(cooldown_seconds=10)
        a1 = IDSAlert(alert_id="a1", alert_type="A", severity=Severity.LOW,
                      timestamp=time.time(), source_ip="1.1.1.1")
        a2 = IDSAlert(alert_id="a2", alert_type="A", severity=Severity.LOW,
                      timestamp=time.time(), source_ip="1.1.1.1")
        self.assertTrue(mgr.record(a1))
        self.assertFalse(mgr.record(a2))  # same dedupe key within cooldown
        self.assertEqual(mgr.total_alerts(), 1)

    def test_ids_processes(self):
        from app.ids.detector import IntrusionDetectionSystem
        from app.capture.packet_queue import PacketRecord
        from app.analysis.packet_parser import PacketParser
        ids = IntrusionDetectionSystem()
        ids.set_enabled(True)
        ids.configure_from_config.__wrapped__ if False else None
        # Raise many SYNs quickly to trigger
        for i in range(ids._config.ids.syn_flood_threshold + 20):
            pkt = _make_packet([("Ether", {}), ("IP", {"src": "3.3.3.3", "dst": "4.4.4.4"}),
                                ("TCP", {"sport": 1000 + i, "dport": 80, "flags": "S"})])
            rec = PacketRecord(packet_number=i, timestamp=time.time(), scapy_packet=pkt)
            parsed = PacketParser().parse_record(rec)
            ids.process(parsed, pkt)
        self.assertGreater(ids.alert_manager.total_alerts(), 0)


class TestPacketQueue(unittest.TestCase):
    def test_bounded_queue_and_history(self):
        from app.capture.packet_queue import PacketQueue
        q = PacketQueue(maxsize=100)
        for i in range(150):
            q.put("packet_" + str(i), interface="eth0", length=60)
        self.assertGreaterEqual(q.dropped, 50)
        self.assertEqual(q.history_size(), 100)
        self.assertEqual(q.qsize(), 100)


class TestExport(unittest.TestCase):
    def test_csv_export(self):
        from app.capture.packet_queue import PacketQueue
        from app.export.csv_exporter import CSVExporter
        q = PacketQueue()
        for i in range(10):
            pkt = _make_packet([("Ether", {}), ("IP", {"src": f"10.0.0.{i}", "dst": "10.1.0.1"}),
                                ("UDP", {"sport": 1000, "dport": 2000})])
            q.put(pkt, interface="eth0", length=100)
        path = Path(tempfile.mkdtemp()) / "out.csv"
        res = CSVExporter().export_queue(q, output_path=path)
        self.assertIsNotNone(res)
        self.assertTrue(os.path.exists(res))
        with open(res, "r", encoding="utf-8") as f:
            lines = f.read().splitlines()
        self.assertTrue(lines[0].startswith("Timestamp"))
        self.assertGreaterEqual(len(lines), 11)  # header + 10 packets

    def test_pcap_export(self):
        from app.capture.packet_queue import PacketQueue
        from app.export.pcap_exporter import PCAPExporter
        q = PacketQueue()
        for i in range(10):
            pkt = _make_packet([("Ether", {}), ("IP", {}), ("ICMP", {})])
            q.put(pkt, interface="lo", length=60)
        path = Path(tempfile.mkdtemp()) / "out.pcap"
        res = PCAPExporter().export_queue(q, output_path=path)
        self.assertIsNotNone(res)
        self.assertTrue(os.path.exists(res))
        self.assertGreater(os.path.getsize(res), 24)  # pcap global header is 24 bytes

    def tearDown(self):
        pass


class TestLogging(unittest.TestCase):
    def test_setup_and_write(self):
        from app.logging.logger import (
            setup_logging, log_application, log_authentication, log_ids,
            log_error, read_log_tail, APP_LOG, AUTH_LOG, IDS_LOG, ERROR_LOG,
        )
        tmpdir = Path(tempfile.mkdtemp())
        setup_logging(log_level="DEBUG", log_dir=tmpdir)
        log_application("hello app", "INFO")
        log_authentication("hello auth", "INFO")
        log_ids("hello ids", "INFO")
        log_error("hello error")
        time.sleep(0.2)
        self.assertIn("hello app", read_log_tail(APP_LOG, lines=100))
        self.assertIn("hello auth", read_log_tail(AUTH_LOG, lines=100))
        self.assertIn("hello ids", read_log_tail(IDS_LOG, lines=100))
        self.assertIn("hello error", read_log_tail(ERROR_LOG, lines=100))


if __name__ == "__main__":
    unittest.main(verbosity=2)
