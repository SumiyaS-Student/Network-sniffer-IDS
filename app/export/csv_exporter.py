"""
CSV exporter for parsed packet records.
"""

import csv
import threading
from typing import Any, Iterable, List, Optional
from pathlib import Path

from app.utils.paths import CAPTURES_DIR, ensure_directory, unique_path, safe_filename
from app.analysis.packet_parser import ParsedPacket, PacketParser
from app.capture.packet_queue import PacketQueue, PacketRecord
from app.logging.logger import log_application, log_error


CSV_HEADER = [
    "Timestamp",
    "Source",
    "Destination",
    "Protocol",
    "Source Port",
    "Destination Port",
    "Length",
    "Interface",
    "Status",
]


class CSVExporter:
    def __init__(self):
        self._lock = threading.RLock()
        self._parser = PacketParser()

    def export_records(self, records: Iterable[Any], output_path: Optional[Path] = None,
                       filename_hint: str = "capture.csv") -> Optional[Path]:
        with self._lock:
            if output_path is None:
                filename = safe_filename(filename_hint, "capture.csv")
                if not filename.lower().endswith(".csv"):
                    filename += ".csv"
                output_path = unique_path(ensure_directory(CAPTURES_DIR), filename)
            output_path = Path(output_path)
            ensure_directory(output_path.parent)
            rows_written = 0
            try:
                with open(output_path, "w", encoding="utf-8", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow(CSV_HEADER)
                    for rec in records:
                        if isinstance(rec, ParsedPacket):
                            parsed = rec
                        elif isinstance(rec, PacketRecord):
                            parsed = self._parser.parse_record(rec)
                        else:
                            continue
                        writer.writerow([
                            parsed.timestamp_str,
                            parsed.source_ip,
                            parsed.destination_ip,
                            parsed.protocol,
                            parsed.source_port or "",
                            parsed.destination_port or "",
                            parsed.length,
                            parsed.interface,
                            "DEMO" if parsed.is_demo else parsed.status,
                        ])
                        rows_written += 1
            except (OSError, IOError) as e:
                log_error(f"CSV export to {output_path} failed.", e)
                return None
            log_application(f"CSV export written to {output_path} ({rows_written} rows).", "INFO")
            return output_path

    def export_queue(self, packet_queue: PacketQueue,
                     output_path: Optional[Path] = None,
                     limit: Optional[int] = None) -> Optional[Path]:
        records = packet_queue.snapshot_history(limit=limit)
        return self.export_records(records, output_path=output_path)
