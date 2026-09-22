"""
Thread-safe bounded packet queue with packet record model.
"""

import threading
import time
import collections
from dataclasses import dataclass, field
from typing import Any, Deque, List, Optional, Tuple

from app.utils.time_utils import now_epoch


MAX_QUEUE_SIZE = 50000


@dataclass
class PacketRecord:
    packet_number: int = 0
    timestamp: float = field(default_factory=now_epoch)
    scapy_packet: Any = None
    interface: str = ""
    is_demo: bool = False
    _parsed_cache: Optional[dict] = field(default=None, repr=False, compare=False)

    def clear_scapy(self) -> None:
        self.scapy_packet = None
        self._parsed_cache = None


class PacketQueue:
    def __init__(self, maxsize: int = MAX_QUEUE_SIZE):
        self._lock = threading.RLock()
        self._not_empty = threading.Condition(self._lock)
        self._maxsize = max(100, int(maxsize))
        self._queue: Deque[PacketRecord] = collections.deque()
        self._history: Deque[PacketRecord] = collections.deque(maxlen=self._maxsize)
        self._counter = 0
        self._total_packets = 0
        self._total_bytes = 0
        self._dropped = 0

    @property
    def maxsize(self) -> int:
        return self._maxsize

    @property
    def total_packets(self) -> int:
        with self._lock:
            return self._total_packets

    @property
    def total_bytes(self) -> int:
        with self._lock:
            return self._total_bytes

    @property
    def dropped(self) -> int:
        with self._lock:
            return self._dropped

    def qsize(self) -> int:
        with self._lock:
            return len(self._queue)

    def history_size(self) -> int:
        with self._lock:
            return len(self._history)

    def clear(self) -> None:
        with self._lock:
            self._queue.clear()
            self._history.clear()
            self._counter = 0
            self._total_packets = 0
            self._total_bytes = 0
            self._dropped = 0

    def put(self, scapy_packet: Any, interface: str = "", is_demo: bool = False,
            length: Optional[int] = None) -> Optional[PacketRecord]:
        with self._lock:
            self._counter += 1
            record = PacketRecord(
                packet_number=self._counter,
                timestamp=now_epoch(),
                scapy_packet=scapy_packet,
                interface=interface,
                is_demo=is_demo,
            )
            if length is None:
                try:
                    length = len(scapy_packet) if scapy_packet is not None else 0
                except Exception:
                    length = 0
            self._total_bytes += max(0, int(length))
            self._total_packets += 1
            if len(self._queue) >= self._maxsize:
                try:
                    self._queue.popleft()
                    self._dropped += 1
                except IndexError:
                    pass
            self._queue.append(record)
            self._history.append(record)
            self._not_empty.notify(n=1)
            return record

    def get(self, timeout: Optional[float] = None) -> Optional[PacketRecord]:
        with self._lock:
            if not self._queue:
                if timeout is None or timeout <= 0:
                    return None
                self._not_empty.wait(timeout=timeout)
                if not self._queue:
                    return None
            try:
                return self._queue.popleft()
            except IndexError:
                return None

    def get_batch(self, max_batch: int = 200) -> List[PacketRecord]:
        with self._lock:
            n = min(max_batch, len(self._queue))
            if n <= 0:
                return []
            batch = [self._queue.popleft() for _ in range(n)]
            return batch

    def snapshot_history(self, limit: Optional[int] = None) -> List[PacketRecord]:
        with self._lock:
            if limit is None or limit <= 0:
                return list(self._history)
            limit = min(limit, len(self._history))
            return list(self._history)[-limit:]

    def last_packet_time(self) -> Optional[float]:
        with self._lock:
            if not self._history:
                return None
            return self._history[-1].timestamp

    def rate_since(self, since_ts: float) -> Tuple[int, int]:
        with self._lock:
            packets = 0
            bytes_sum = 0
            for r in self._history:
                if r.timestamp >= since_ts:
                    packets += 1
                    try:
                        bytes_sum += len(r.scapy_packet) if r.scapy_packet is not None else 0
                    except Exception:
                        pass
            return packets, bytes_sum
