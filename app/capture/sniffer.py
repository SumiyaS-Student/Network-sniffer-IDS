"""
Scapy-based packet capture engine running in background threads.

Supports START / PAUSE / RESUME / STOP and safe shutdown.
"""

import threading
import time
from typing import Optional, Callable, List, Any

from app.capture.interface_manager import InterfaceManager, NetworkInterface
from app.capture.packet_queue import PacketQueue
from app.logging.logger import log_capture, log_error, log_application


STATE_IDLE = "IDLE"
STATE_CAPTURING = "CAPTURING"
STATE_PAUSED = "PAUSED"
STATE_STOPPING = "STOPPING"
STATE_ERROR = "ERROR"


class Sniffer:
    def __init__(self, interface_manager: InterfaceManager,
                 packet_queue: Optional[PacketQueue] = None,
                 max_queue_size: int = 50000):
        self._iface_mgr = interface_manager
        self._queue = packet_queue or PacketQueue(maxsize=max_queue_size)
        self._lock = threading.RLock()
        self._state = STATE_IDLE
        self._capture_thread: Optional[threading.Thread] = None
        self._sniffer_socket: Any = None
        self._selected_iface: Optional[NetworkInterface] = None
        self._filter_expr: str = ""
        self._scapy_available = False
        self._on_state_change: Optional[Callable[[str, str], None]] = None
        self._start_time: Optional[float] = None
        self._try_import_scapy()

    def _try_import_scapy(self) -> None:
        try:
            import scapy.all as _  # noqa: F401
            self._scapy_available = True
        except Exception as e:
            self._scapy_available = False
            log_error("Scapy is not available. Capture engine will operate in limited/demo-only mode.", e)

    @property
    def queue(self) -> PacketQueue:
        return self._queue

    @property
    def state(self) -> str:
        with self._lock:
            return self._state

    @property
    def start_time(self) -> Optional[float]:
        return self._start_time

    @property
    def scapy_available(self) -> bool:
        return self._scapy_available

    def selected_interface(self) -> Optional[NetworkInterface]:
        with self._lock:
            return self._selected_iface

    def set_on_state_change(self, callback: Optional[Callable[[str, str], None]]) -> None:
        self._on_state_change = callback

    def _change_state(self, new_state: str, reason: str = "") -> None:
        with self._lock:
            old = self._state
            self._state = new_state
        try:
            if self._on_state_change:
                self._on_state_change(old, new_state)
        except Exception as e:
            log_error("Exception in Sniffer state-change callback.", e)

    def set_filter(self, bpf_filter: str) -> None:
        with self._lock:
            self._filter_expr = (bpf_filter or "").strip()

    def get_filter(self) -> str:
        with self._lock:
            return self._filter_expr

    def select_interface(self, name: str) -> Optional[NetworkInterface]:
        with self._lock:
            if self._state not in (STATE_IDLE, STATE_ERROR):
                log_capture("Cannot change interface while capture is active.", "WARNING")
                return None
        iface = self._iface_mgr.select_interface(name)
        with self._lock:
            self._selected_iface = iface
        return iface

    def start(self, bpf_filter: str = "") -> bool:
        with self._lock:
            if self._state in (STATE_CAPTURING, STATE_PAUSED):
                return True
            if self._state == STATE_STOPPING:
                return False
            self._selected_iface = self._iface_mgr.get_selected()
            if not self._selected_iface:
                log_capture("Cannot start capture: no interface selected.", "ERROR")
                return False
            if bpf_filter:
                self._filter_expr = bpf_filter.strip()
        self._queue.clear()
        self._start_time = time.time()
        self._change_state(STATE_CAPTURING, "start requested")
        log_capture(
            f"Starting capture on interface '{self._selected_iface.label}' "
            f"[filter='{self._filter_expr or '(none)'}']",
            "INFO",
        )
        self._capture_thread = threading.Thread(
            target=self._capture_loop,
            name="ScapyCaptureThread",
            daemon=True,
        )
        self._capture_thread.start()
        return True

    def pause(self) -> bool:
        with self._lock:
            if self._state != STATE_CAPTURING:
                return False
            self._change_state(STATE_PAUSED, "pause requested")
            log_capture("Capture PAUSED by user.", "INFO")
            return True

    def resume(self) -> bool:
        with self._lock:
            if self._state != STATE_PAUSED:
                return False
            self._change_state(STATE_CAPTURING, "resume requested")
            log_capture("Capture RESUMED by user.", "INFO")
            return True

    def stop(self) -> bool:
        with self._lock:
            if self._state == STATE_IDLE:
                return True
            self._change_state(STATE_STOPPING, "stop requested")
        t = self._capture_thread
        sock = self._sniffer_socket
        try:
            if sock is not None and hasattr(sock, "close"):
                try:
                    sock.close()
                except Exception:
                    pass
        except Exception:
            pass
        if t is not None and t.is_alive():
            t.join(timeout=5.0)
        with self._lock:
            self._sniffer_socket = None
            self._capture_thread = None
            self._change_state(STATE_IDLE, "stopped")
        log_capture("Capture STOPPED.", "INFO")
        return True

    def clear(self) -> None:
        with self._lock:
            if self._state in (STATE_CAPTURING, STATE_PAUSED, STATE_STOPPING):
                log_capture("Cannot clear queue while capture is active.", "WARNING")
                return
        self._queue.clear()
        log_capture("Capture buffers cleared.", "INFO")

    def inject_demo_packet(self, scapy_packet: Any, length: Optional[int] = None) -> None:
        iface_name = ""
        with self._lock:
            if self._selected_iface:
                iface_name = self._selected_iface.name
        self._queue.put(scapy_packet, interface=iface_name, is_demo=True, length=length)

    def _prn_handler(self, scapy_packet: Any) -> None:
        if scapy_packet is None:
            return
        with self._lock:
            state = self._state
        if state == STATE_PAUSED:
            return
        if state != STATE_CAPTURING:
            return
        try:
            iface_name = ""
            with self._lock:
                if self._selected_iface:
                    iface_name = self._selected_iface.name
            self._queue.put(scapy_packet, interface=iface_name, is_demo=False)
        except Exception as e:
            log_error("Error enqueuing captured packet.", e)

    def _stop_filter(self, _packet: Any) -> bool:
        with self._lock:
            return self._state in (STATE_STOPPING, STATE_IDLE, STATE_ERROR)

    def _capture_loop(self) -> None:
        iface_name = ""
        with self._lock:
            if self._selected_iface:
                iface_name = self._selected_iface.name
        if not self._scapy_available:
            with self._lock:
                self._change_state(STATE_ERROR, "scapy not importable")
            log_capture("Capture loop cannot start: Scapy is not available.", "ERROR")
            return
        try:
            from scapy.sendrecv import sniff
        except Exception as e:
            log_error("Failed to import scapy.sendrecv.sniff.", e)
            with self._lock:
                self._change_state(STATE_ERROR, "scapy.sniff unavailable")
            return
        try:
            kwargs = {
                "prn": self._prn_handler,
                "store": False,
                "stop_filter": self._stop_filter,
            }
            if iface_name:
                kwargs["iface"] = iface_name
            if self._filter_expr:
                kwargs["filter"] = self._filter_expr
            sniff(**kwargs)
        except PermissionError as pe:
            log_error(
                "Capture requires elevated permissions (Admin/root) or Npcap/WinPcap/libpcap.",
                pe,
            )
            with self._lock:
                self._change_state(STATE_ERROR, "permission denied")
        except OSError as oe:
            log_error("Capture encountered OS error.", oe)
            with self._lock:
                self._change_state(STATE_ERROR, "os error")
        except Exception as e:
            log_error("Unexpected error in Scapy sniff loop.", e)
            with self._lock:
                self._change_state(STATE_ERROR, "sniff exception")
        finally:
            with self._lock:
                if self._state in (STATE_CAPTURING, STATE_PAUSED, STATE_STOPPING):
                    self._change_state(STATE_IDLE, "loop exited")
