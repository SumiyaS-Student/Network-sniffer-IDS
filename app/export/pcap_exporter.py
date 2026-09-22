"""
PCAP exporter using Scapy's wrpcap to produce Wireshark-compatible files.
"""

import threading
from typing import Any, Iterable, List, Optional
from pathlib import Path

from app.utils.paths import CAPTURES_DIR, ensure_directory, unique_path, safe_filename
from app.capture.packet_queue import PacketQueue, PacketRecord
from app.logging.logger import log_application, log_error


class PCAPExporter:
    def __init__(self):
        self._lock = threading.RLock()

    def _scapy_write(self, path: Path, scapy_packets: List[Any]) -> bool:
        try:
            from scapy.utils import wrpcap
        except Exception as e:
            log_error("Scapy wrpcap is not available for PCAP export.", e)
            return False
        try:
            ensure_directory(path.parent)
            wrpcap(str(path), scapy_packets, linktype=None)
            return True
        except Exception as e:
            log_error(f"wrpcap failed to write {path}.", e)
            return False

    def export_records(self, records: Iterable[Any], output_path: Optional[Path] = None,
                       filename_hint: str = "capture.pcap") -> Optional[Path]:
        with self._lock:
            packets: List[Any] = []
            for rec in records:
                if isinstance(rec, PacketRecord):
                    pkt = rec.scapy_packet
                else:
                    pkt = getattr(rec, "scapy_packet", None) or rec
                if pkt is not None:
                    packets.append(pkt)
            if not packets:
                log_application("PCAP export skipped: no packets to write.", "WARNING")
                return None
            if output_path is None:
                filename = safe_filename(filename_hint, "capture.pcap")
                if not filename.lower().endswith(".pcap"):
                    filename += ".pcap"
                output_path = unique_path(ensure_directory(CAPTURES_DIR), filename)
            output_path = Path(output_path)
            ok = self._scapy_write(output_path, packets)
            if ok:
                log_application(
                    f"PCAP export written to {output_path} ({len(packets)} packets).",
                    "INFO",
                )
                return output_path
            return None

    def export_queue(self, packet_queue: PacketQueue,
                     output_path: Optional[Path] = None,
                     limit: Optional[int] = None) -> Optional[Path]:
        records = packet_queue.snapshot_history(limit=limit)
        return self.export_records(records, output_path=output_path)
