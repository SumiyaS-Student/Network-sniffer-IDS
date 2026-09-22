"""
Main application window: navigation, toolbar, worker threads, view switching.
"""

import sys
import time
import threading
import traceback
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from datetime import datetime

import tkinter as tk
from tkinter import ttk, messagebox

from app.gui.theme import (
    COLORS, BASE_FONT, BASE_FONT_BOLD, SMALL_FONT, H1_FONT, H2_FONT, H3_FONT,
    status_colors, severity_bg, severity_fg,
)
from app.gui.auth_dialog import SetupDialog, LoginDialog
from app.gui.dashboard import DashboardView
from app.gui.capture_view import CaptureView
from app.gui.packet_details import PacketDetailsView
from app.gui.ids_view import IDSView
from app.gui.statistics_view import StatisticsView
from app.gui.logs_view import LogsView
from app.gui.settings_view import SettingsView
from app.gui.export_view import ExportView

from config import AppConfig
from app.authentication.auth_manager import AuthManager
from app.capture.interface_manager import InterfaceManager, NetworkInterface
from app.capture.sniffer import (
    Sniffer, STATE_IDLE, STATE_CAPTURING, STATE_PAUSED, STATE_STOPPING, STATE_ERROR,
)
from app.capture.packet_queue import PacketQueue, PacketRecord
from app.analysis.packet_parser import PacketParser, ParsedPacket
from app.analysis.statistics import Statistics
from app.ids.detector import IntrusionDetectionSystem
from app.ids.alerts import IDSAlert, Severity, ALERT_DEMO
from app.export.csv_exporter import CSVExporter
from app.export.pcap_exporter import PCAPExporter
from app.email.smtp_alerts import SMTPAlerts
from app.logging.logger import (
    setup_logging, log_application, log_capture, log_error, log_ids, log_authentication,
)
from app.utils.paths import ensure_all_directories
from app.utils.demo_generator import DemoGenerator, DemoScenario, SCENARIOS


NAV_ITEMS = [
    ("Dashboard", "dashboard"),
    ("Live Capture", "capture"),
    ("Packet Details", "details"),
    ("IDS", "ids"),
    ("Statistics", "statistics"),
    ("Logs", "logs"),
    ("Export", "export"),
    ("Settings", "settings"),
]


VIEW_KEYS = {key for _, key in NAV_ITEMS}


AUTH_REQUIRED_VIEWS = {"capture", "details", "logs", "export", "ids", "statistics", "settings"}
AUTH_REQUIRED_ACTIONS = {
    "start_capture", "pause_capture", "resume_capture", "stop_capture",
    "clear_display", "toggle_ids", "clear_alerts",
    "send_test_smtp_alert", "export_csv", "export_pcap", "export_csv_as",
    "export_pcap_as",
}


class MainWindow:
    def __init__(self, root: tk.Tk):
        self.root = root
        ensure_all_directories()
        setup_logging()
        log_application("Application starting.", "INFO")

        self.config = AppConfig()
        self.auth = AuthManager()
        self.interface_manager = InterfaceManager()
        self.sniffer = Sniffer(self.interface_manager,
                               max_queue_size=self.config.capture.max_retained_packets)
        self.parser = PacketParser()
        self.statistics = Statistics()
        self.ids = IntrusionDetectionSystem(self.config)
        self.csv_exporter = CSVExporter()
        self.pcap_exporter = PCAPExporter()
        self.smtp = SMTPAlerts(self.config)
        self.demo = DemoGenerator(self._demo_inject)

        self._parsed_history: List[ParsedPacket] = []
        self._current_view: str = "dashboard"
        self._last_gui_refresh = 0.0
        self._last_full_refresh = 0.0
        self._last_chart_refresh = 0.0
        self._worker_running = False
        self._worker_thread: Optional[threading.Thread] = None
        self._pending_toasts: List[str] = []
        self._current_session: Optional[str] = None

        self.ids.alert_manager.add_listener(self._on_ids_alert)
        self.sniffer.set_on_state_change(self._on_capture_state_change)

        self._configure_root()
        self._build_ui()
        self._post_auth_views_init()
        self._start_worker()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        self.root.after(200, self._maybe_prompt_auth_on_start)
        self.root.after(400, self._refresh_views_loop)

    # ---------- Window setup ----------
    def _configure_root(self) -> None:
        self.root.title("Network Packet Sniffer & IDS")
        try:
            width = min(1600, max(1280, self.root.winfo_screenwidth() - 80))
            height = min(960, max(820, self.root.winfo_screenheight() - 120))
            x = max(0, (self.root.winfo_screenwidth() - width) // 2)
            y = max(0, (self.root.winfo_screenheight() - height) // 2 - 20)
            self.root.geometry(f"{width}x{height}+{x}+{y}")
        except Exception:
            self.root.geometry("1280x820")
        self.root.minsize(1024, 720)
        self.root.configure(bg=COLORS["bg"])
        try:
            from assets.logo import get_logo_image
            img = get_logo_image(size=32)
            if img is not None:
                self.root.iconphoto(True, img)
        except Exception:
            pass

    def _build_ui(self) -> None:
        outer = tk.Frame(self.root, bg=COLORS["bg"])
        outer.pack(fill="both", expand=True)

        header = tk.Frame(outer, bg=COLORS["header_bg"],
                          highlightbackground=COLORS["header_border"],
                          highlightthickness=1, height=64)
        header.pack(fill="x")
        header.pack_propagate(False)
        self._build_header(header)

        body = tk.Frame(outer, bg=COLORS["bg"])
        body.pack(fill="both", expand=True)

        nav = tk.Frame(body, bg=COLORS["nav_bg"], width=200,
                       highlightbackground=COLORS["header_border"],
                       highlightthickness=1)
        nav.pack(side="left", fill="y")
        nav.pack_propagate(False)
        self._build_nav(nav)

        content_container = tk.Frame(body, bg=COLORS["bg"])
        content_container.pack(side="left", fill="both", expand=True)

        self.status_bar = tk.Frame(outer, bg=COLORS["panel"],
                                   highlightbackground=COLORS["header_border"],
                                   highlightthickness=1, height=30)
        self.status_bar.pack(fill="x", side="bottom")
        self.status_bar.pack_propagate(False)
        self._build_status_bar(self.status_bar)

        self.views: Dict[str, tk.Frame] = {}
        self.views["dashboard"] = DashboardView(content_container, self._dashboard_state)
        self.views["capture"] = CaptureView(
            content_container,
            interface_provider=self.interface_manager.list_interfaces,
            refresh_interfaces=self._refresh_interfaces,
            select_interface=self._select_interface,
            selected_provider=self.interface_manager.get_selected,
            actions=self._capture_actions(),
            auth_required=self._auth_wrap_action,
        )
        self.views["details"] = PacketDetailsView(content_container)
        self.views["ids"] = IDSView(
            content_container, actions=self._ids_actions(),
            state_provider=self._ids_state,
            auth_wrap=self._auth_wrap_action,
        )
        self.views["statistics"] = StatisticsView(content_container,
                                                  state_provider=self._stats_state)
        self.views["logs"] = LogsView(content_container,
                                      auth_wrap=self._auth_wrap_action)
        self.views["settings"] = SettingsView(
            content_container, self.config,
            auth_wrap=self._auth_wrap_action,
            save_hook=self._apply_settings,
            test_smtp_hook=self._test_smtp,
        )
        self.views["export"] = ExportView(
            content_container, actions=self._export_actions(),
            state_provider=self._dashboard_state,
            auth_wrap=self._auth_wrap_action,
        )

        for v in self.views.values():
            v.place(relx=0, rely=0, relwidth=1, relheight=1)

        self.views["capture"].set_on_row_select(self._on_packet_row_select)
        self._switch_view("dashboard")

    def _build_header(self, parent: tk.Frame) -> None:
        left = tk.Frame(parent, bg=COLORS["header_bg"])
        left.pack(side="left", fill="y", padx=18, pady=10)
        try:
            from assets.logo import get_logo_photoimage
            self._logo = get_logo_photoimage(size=40)
            if self._logo is not None:
                tk.Label(left, image=self._logo, bg=COLORS["header_bg"]).pack(side="left")
        except Exception:
            self._logo = None
        titles = tk.Frame(left, bg=COLORS["header_bg"])
        titles.pack(side="left", padx=(12, 0))
        tk.Label(titles, text="Network Packet Sniffer & IDS", bg=COLORS["header_bg"],
                 fg=COLORS["text"], font=H2_FONT, anchor="w").pack(anchor="w")
        tk.Label(titles, text="Defensive Network Monitoring · Packet Capture · Intrusion Detection",
                 bg=COLORS["header_bg"], fg=COLORS["text_secondary"],
                 font=SMALL_FONT, anchor="w").pack(anchor="w")

        right = tk.Frame(parent, bg=COLORS["header_bg"])
        right.pack(side="right", fill="y", padx=18, pady=10)

        demo_row = tk.Frame(right, bg=COLORS["header_bg"])
        demo_row.pack(side="right", fill="y", padx=(20, 0))
        tk.Label(demo_row, text="Demo/Test:", bg=COLORS["header_bg"],
                 fg=COLORS["text"], font=BASE_FONT).pack(side="left", padx=(0, 6))
        self._demo_var = tk.StringVar(value="Normal TCP")
        demo_combo = ttk.Combobox(
            demo_row, textvariable=self._demo_var, state="readonly", width=22,
            values=[s.name for s in SCENARIOS], font=BASE_FONT,
        )
        demo_combo.pack(side="left", padx=(0, 8))
        self._demo_btn = tk.Button(
            demo_row, text="Run Scenario", font=BASE_FONT_BOLD,
            bg=COLORS["info_surface"], fg=COLORS["info"],
            activebackground=COLORS["primary_surface"], relief="flat", bd=0,
            padx=12, pady=6, cursor="hand2",
            command=self._run_demo_scenario,
            highlightbackground=COLORS["info"], highlightthickness=1,
        )
        self._demo_btn.pack(side="left")

        sep = tk.Frame(right, bg=COLORS["divider"], width=1)
        sep.pack(side="right", fill="y", padx=18)

        self._clock_lbl = tk.Label(right, text="", bg=COLORS["header_bg"],
                                   fg=COLORS["text"], font=BASE_FONT_BOLD,
                                   anchor="e", width=22)
        self._clock_lbl.pack(side="right", fill="y")

        auth_row = tk.Frame(right, bg=COLORS["header_bg"])
        auth_row.pack(side="right", fill="y", padx=(0, 18))
        self._session_badge = tk.Label(
            auth_row, text="Signed Out",
            bg=status_colors("IDLE")[1], fg=status_colors("IDLE")[0],
            font=BASE_FONT_BOLD, padx=12, pady=6,
        )
        self._session_badge.pack(side="right", padx=(8, 0))
        tk.Button(
            auth_row, text="Sign In", font=BASE_FONT_BOLD,
            bg=COLORS["primary"], fg="#FFFFFF",
            activebackground=COLORS["primary_hover"],
            activeforeground="#FFFFFF", relief="flat", bd=0,
            padx=14, pady=6, cursor="hand2", command=self._prompt_login,
        ).pack(side="right")
        tk.Button(
            auth_row, text="Sign Out", font=BASE_FONT,
            bg=COLORS["surface"], fg=COLORS["text"],
            activebackground=COLORS["border"], relief="flat", bd=0,
            padx=12, pady=6, cursor="hand2", command=self._sign_out,
            highlightbackground=COLORS["border"], highlightthickness=1,
        ).pack(side="right", padx=(0, 6))

    def _build_nav(self, parent: tk.Frame) -> None:
        self._nav_buttons: Dict[str, tk.Button] = {}
        brand = tk.Frame(parent, bg=COLORS["nav_bg"])
        brand.pack(fill="x", pady=(16, 12))
        tk.Label(brand, text="  NAVIGATION", bg=COLORS["nav_bg"],
                 fg=COLORS["text_muted"], font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=18)
        for label, key in NAV_ITEMS:
            btn = tk.Button(
                parent, text=f"  {label}", anchor="w",
                bg=COLORS["nav_bg"], fg=COLORS["nav_text"],
                activebackground=COLORS["nav_active"],
                activeforeground=COLORS["nav_active_text"],
                relief="flat", bd=0, cursor="hand2",
                font=BASE_FONT, padx=18, pady=10,
                command=lambda k=key: self._on_nav_click(k),
            )
            btn.pack(fill="x")
            self._nav_buttons[key] = btn
        tk.Frame(parent, bg=COLORS["nav_bg"]).pack(fill="both", expand=True)
        v_lbl = tk.Label(parent, text=f"  v1.0.0 · SumiyaS-Student",
                         bg=COLORS["nav_bg"], fg=COLORS["text_muted"],
                         font=SMALL_FONT, anchor="w")
        v_lbl.pack(fill="x", pady=(0, 14))

    def _build_status_bar(self, parent: tk.Frame) -> None:
        self._sb_app = self._sb_chip(parent, "App: READY", "OK")
        self._sb_app.pack(side="left", padx=(12, 8), pady=4)
        self._sb_cap = self._sb_chip(parent, "Capture: IDLE", "IDLE")
        self._sb_cap.pack(side="left", padx=8, pady=4)
        self._sb_iface = self._sb_chip(parent, "Interface: (none)", "IDLE")
        self._sb_iface.pack(side="left", padx=8, pady=4)
        self._sb_ids = self._sb_chip(parent, "IDS: OFF", "IDLE")
        self._sb_ids.pack(side="left", padx=8, pady=4)
        self._sb_toast = tk.Label(parent, text="", bg=COLORS["panel"],
                                  fg=COLORS["text_secondary"],
                                  font=SMALL_FONT, anchor="w")
        self._sb_toast.pack(side="left", fill="x", expand=True, padx=14)

    def _sb_chip(self, parent: tk.Frame, text: str, status: str) -> tk.Label:
        fg, bg = status_colors(status)
        return tk.Label(parent, text=text, bg=bg, fg=fg,
                        font=BASE_FONT_BOLD, padx=10, pady=2)

    def _update_sb(self, lbl: tk.Label, text: str, status: str) -> None:
        fg, bg = status_colors(status)
        try:
            lbl.configure(text=text, fg=fg, bg=bg)
        except Exception:
            pass

    def _post_auth_views_init(self) -> None:
        self.views["capture"].refresh_interfaces_ui()
        self.views["capture"].set_display_limit(self.config.capture.display_limit)
        self.views["ids"].set_ids_enabled(self.ids.is_enabled())
        self.views["ids"].set_alerts(self.ids.alert_manager.list_alerts(limit=5000))
        self.views["logs"].refresh_logs()

    # ---------- Actions & auth wrapping ----------
    def _capture_actions(self) -> Dict[str, Callable]:
        return {
            "start_capture": self._start_capture,
            "pause_capture": self._pause_capture,
            "resume_capture": self._resume_capture,
            "stop_capture": self._stop_capture,
            "clear_display": self._clear_display,
        }

    def _ids_actions(self) -> Dict[str, Callable]:
        return {
            "toggle_ids": self._toggle_ids,
            "clear_alerts": self._clear_alerts,
            "send_test_smtp_alert": self._send_test_ids_alert,
        }

    def _export_actions(self) -> Dict[str, Callable]:
        return {
            "export_csv": self._export_csv,
            "export_pcap": self._export_pcap,
            "export_csv_as": self._export_csv,
            "export_pcap_as": self._export_pcap,
        }

    def _auth_wrap_action(self, fn: Callable) -> Callable:
        def wrapped(*args, **kwargs):
            if not self._ensure_authenticated():
                return None
            try:
                return fn(*args, **kwargs)
            except Exception as e:
                log_error("Action handler failed.", e)
                messagebox.showerror("Error", f"Action failed:\n{e}")
                return None
        return wrapped

    def _ensure_authenticated(self) -> bool:
        if self.auth.is_authenticated():
            return True
        return self._prompt_login()

    # ---------- View switching ----------
    def _on_nav_click(self, key: str) -> None:
        if key in AUTH_REQUIRED_VIEWS and not self._ensure_authenticated():
            return
        self._switch_view(key)

    def _switch_view(self, key: str) -> None:
        if key not in self.views:
            return
        self._current_view = key
        for k, v in self.views.items():
            if k == key:
                v.tkraise()
        for k, btn in self._nav_buttons.items():
            if k == key:
                btn.configure(bg=COLORS["nav_active"], fg=COLORS["nav_active_text"],
                              font=BASE_FONT_BOLD)
            else:
                btn.configure(bg=COLORS["nav_bg"], fg=COLORS["nav_text"],
                              font=BASE_FONT)

    # ---------- Authentication ----------
    def _maybe_prompt_auth_on_start(self) -> None:
        if self.auth.is_setup_required():
            dlg = SetupDialog(self.root, self.auth, on_success=self._on_session_created)
            self.root.wait_window(dlg)
            if dlg.result() is None:
                self._toast("Setup incomplete — some features will be locked.")
        else:
            dlg = LoginDialog(self.root, self.auth, on_success=self._on_session_created,
                              allow_cancel=True)
            self.root.wait_window(dlg)
            if dlg.result() is None:
                self._toast("Signed out — sign in for full access.")

    def _prompt_login(self) -> bool:
        if self.auth.is_setup_required():
            dlg = SetupDialog(self.root, self.auth, on_success=self._on_session_created)
            self.root.wait_window(dlg)
            return dlg.result() is not None
        dlg = LoginDialog(self.root, self.auth, on_success=self._on_session_created,
                          allow_cancel=True)
        self.root.wait_window(dlg)
        return dlg.result() is not None

    def _on_session_created(self, sid: str) -> None:
        self._current_session = sid
        session = self.auth.get_current_session()
        who = session.username if session else "admin"
        self._session_badge.configure(text=f"Signed in as {who}")
        fg, bg = status_colors("OK")
        self._session_badge.configure(fg=fg, bg=bg)
        self.views["logs"].refresh_logs()
        self._toast(f"Welcome, {who}.")

    def _sign_out(self) -> None:
        self.auth.logout()
        self._current_session = None
        self._session_badge.configure(text="Signed Out")
        fg, bg = status_colors("IDLE")
        self._session_badge.configure(fg=fg, bg=bg)
        self._switch_view("dashboard")
        self._toast("You have been signed out.")
        log_authentication("User signed out via UI.", "INFO")

    # ---------- Interface / capture ----------
    def _refresh_interfaces(self) -> None:
        self.interface_manager.refresh()

    def _select_interface(self, name: str) -> Optional[NetworkInterface]:
        iface = self.sniffer.select_interface(name)
        log_capture(f"Interface selection: {name} -> {iface.label if iface else '(none)'}", "INFO")
        return iface

    def _start_capture(self) -> None:
        if self.sniffer.state in (STATE_CAPTURING, STATE_PAUSED):
            return
        iface = self.interface_manager.get_selected()
        if iface is None:
            messagebox.showwarning(
                "Start Capture",
                "Select a network interface before starting capture.\n"
                "You can also use the Demo/Test mode for synthetic packets.",
            )
            return
        if not self.sniffer.scapy_available:
            ok = messagebox.askyesno(
                "Scapy Not Available",
                "Scapy is not importable. Real network capture will not work.\n\n"
                "Would you like to run a Demo/Test scenario instead?"
            )
            if ok:
                self._switch_view("capture")
                self._run_demo_scenario()
            return
        try:
            ok = self.sniffer.start()
        except PermissionError as pe:
            log_error("Capture start permission denied.", pe)
            messagebox.showerror(
                "Capture Requires Elevation",
                "Packet capture requires administrator/root privileges and "
                "Npcap/WinPcap (Windows) or libpcap (Linux/macOS).\n\n"
                "Run the application elevated, or use Demo/Test mode."
            )
            return
        except Exception as e:
            log_error("Capture start failed.", e)
            messagebox.showerror("Start Capture", f"Could not start capture:\n{e}")
            return
        if ok:
            log_capture(f"Capture started on {iface.label}.", "INFO")
            self._toast("Capture started.")
        else:
            messagebox.showwarning("Start Capture",
                                   "Could not start capture. Check interface and permissions.")

    def _pause_capture(self) -> None:
        if self.sniffer.pause():
            self._toast("Capture paused.")

    def _resume_capture(self) -> None:
        if self.sniffer.resume():
            self._toast("Capture resumed.")

    def _stop_capture(self) -> None:
        if self.sniffer.stop():
            self._toast("Capture stopped.")

    def _clear_display(self) -> None:
        if self.sniffer.state in (STATE_CAPTURING, STATE_PAUSED):
            if not messagebox.askyesno(
                "Clear Display",
                "Capture is active. Clear only the GUI display, without stopping capture?"
            ):
                return
        self.views["capture"].clear_display()
        self._parsed_history.clear()
        self.parser.clear_cache()
        self.statistics.reset()
        self.views["details"].set_packet(None)
        self._toast("Display and statistics cleared.")

    # ---------- IDS ----------
    def _toggle_ids(self, enabled: bool) -> None:
        self.ids.set_enabled(bool(enabled))
        self.views["ids"].set_ids_enabled(bool(enabled))
        self._toast(f"IDS {'ENABLED' if enabled else 'DISABLED'}.")
        log_ids(f"IDS engine set to enabled={bool(enabled)}.", "INFO")

    def _clear_alerts(self) -> None:
        self.ids.alert_manager.clear()
        self.views["ids"].set_alerts([])
        self._toast("IDS alerts cleared.")

    def _send_test_ids_alert(self) -> None:
        alert = IDSAlert(
            alert_id=f"test-{int(time.time()*1000):x}",
            alert_type=ALERT_DEMO,
            severity=Severity.LOW,
            timestamp=time.time(),
            source_ip="192.0.2.100",
            destination_ip="198.51.100.2",
            observed_rate=0.0,
            threshold=0.0,
            message="Manual test IDS alert for SMTP and GUI verification.",
            recommended_action="No action required. This is a test.",
            is_demo=True,
        )
        self.ids.alert_manager.record(alert, force=True)
        try:
            self.smtp.send_alert(alert)
        except Exception as e:
            log_error("Test IDS alert SMTP send error.", e)
        self.views["ids"].set_alerts(self.ids.alert_manager.list_alerts(limit=5000))
        self._toast("Test IDS alert recorded.")

    def _on_ids_alert(self, alert: IDSAlert) -> None:
        self._pending_toasts.append(
            f"[IDS {alert.severity.value}] {alert.alert_type} from {alert.source_ip or '—'}")
        try:
            self.smtp.send_alert(alert)
        except Exception as e:
            log_error("SMTP alert dispatch failed.", e)

    # ---------- Export ----------
    def _export_csv(self, **kwargs) -> None:
        limit = kwargs.get("limit")
        filename_hint = kwargs.get("filename_hint", "capture.csv")
        output_path = kwargs.get("output_path")
        records = self.sniffer.queue.snapshot_history(limit=limit)
        path = self.csv_exporter.export_records(records, output_path=output_path,
                                                filename_hint=filename_hint)
        if path:
            messagebox.showinfo("CSV Export", f"Export completed:\n{path}")
            self._toast(f"CSV saved: {path.name}")
        else:
            messagebox.showerror("CSV Export", "Failed to write CSV file. Check error log.")

    def _export_pcap(self, **kwargs) -> None:
        limit = kwargs.get("limit")
        filename_hint = kwargs.get("filename_hint", "capture.pcap")
        output_path = kwargs.get("output_path")
        records = self.sniffer.queue.snapshot_history(limit=limit)
        path = self.pcap_exporter.export_records(records, output_path=output_path,
                                                 filename_hint=filename_hint)
        if path:
            messagebox.showinfo("PCAP Export",
                                f"Export completed (Wireshark compatible):\n{path}")
            self._toast(f"PCAP saved: {path.name}")
        else:
            messagebox.showerror("PCAP Export",
                                 "Failed to write PCAP file. Scapy may be unavailable "
                                 "or there are no packets to export.")

    def _test_smtp(self):
        try:
            ok = bool(self.smtp.send_test_email())
        except Exception as e:
            log_error("Test SMTP send error.", e)
            return (False, str(e))
        return (ok, self.smtp.last_error)

    # ---------- Settings ----------
    def _apply_settings(self) -> None:
        try:
            self.sniffer.queue._maxsize = max(100, int(self.config.capture.max_retained_packets))
        except Exception:
            pass
        try:
            self.views["capture"].set_display_limit(self.config.capture.display_limit)
        except Exception:
            pass
        try:
            self.ids.configure_from_config(self.config)
        except Exception as e:
            log_error("Re-apply IDS settings failed.", e)
        try:
            self.smtp.save_config(
                self.config.smtp.host, self.config.smtp.port,
                self.config.smtp.username, self.config.smtp.password,
                self.config.smtp.use_tls,
                self.config.smtp.from_email, self.config.smtp.to_email,
                self.config.smtp.enabled,
            )
        except Exception as e:
            log_error("Re-apply SMTP settings failed.", e)

    # ---------- Demo mode ----------
    def _run_demo_scenario(self) -> None:
        name = self._demo_var.get()
        scenario = next((s for s in SCENARIOS if s.name == name), None)
        if scenario is None:
            scenario = SCENARIOS[0]
        iface = self.interface_manager.get_selected()
        if iface is None:
            ifaces = self.interface_manager.list_interfaces()
            if ifaces:
                self.sniffer.select_interface(ifaces[0].name)
        started = self.demo.start_scenario(scenario)
        if started:
            self._switch_view("capture")
            self._toast(f"DEMO scenario started: {scenario.name}")
            self._demo_btn.configure(text="Stop Scenario",
                                     bg=COLORS["danger_surface"], fg=COLORS["danger"],
                                     command=self._stop_demo)
        else:
            self._toast("A demo scenario is already running. Stop it first.")

    def _stop_demo(self) -> None:
        self.demo.stop()
        self._demo_btn.configure(text="Run Scenario",
                                 bg=COLORS["info_surface"], fg=COLORS["info"],
                                 command=self._run_demo_scenario)
        self._toast("Demo scenario stopped.")

    def _demo_inject(self, pkt: Any, length: Optional[int]) -> None:
        self.sniffer.inject_demo_packet(pkt, length=length)

    # ---------- State providers for views ----------
    def _dashboard_state(self) -> Dict[str, Any]:
        return {
            "total_packets": self.statistics.total_packets,
            "total_bytes": self.statistics.total_bytes,
            "total_alerts": self.ids.alert_manager.total_alerts(),
            "packets_per_second": self.statistics.packets_per_second(),
            "uptime_seconds": self.sniffer.start_time and (time.time() - self.sniffer.start_time),
            "capture_state": self.sniffer.state,
            "ids_enabled": self.ids.is_enabled(),
            "selected_iface": self.interface_manager.get_selected(),
            "selected_iface_label": getattr(self.interface_manager.get_selected(), "label", "—"),
            "scapy_available": self.sniffer.scapy_available,
            "demo_active": self.demo.is_active(),
            "last_packet_time": self._last_packet_time_label(),
            "protocol_counts": self._protocol_counts_dict(),
            "top_source_ips": self.statistics.top_source_ips(limit=15),
            "top_destination_ips": self.statistics.top_destination_ips(limit=15),
            "highest_severity": self.ids.alert_manager.highest_severity().value,
            "severity_counts": {k: v for k, v in self.ids.alert_manager.severity_counts().items()},
        }

    def _ids_state(self) -> Dict[str, Any]:
        return {
            "ids_enabled": self.ids.is_enabled(),
            "total_alerts": self.ids.alert_manager.total_alerts(),
            "severity_counts": self.ids.alert_manager.severity_counts(),
            "highest_severity": self.ids.alert_manager.highest_severity().value,
        }

    def _stats_state(self) -> Dict[str, Any]:
        return {
            "total_packets": self.statistics.total_packets,
            "total_bytes": self.statistics.total_bytes,
            "packets_per_second": self.statistics.packets_per_second(),
            "bytes_per_second": self.statistics.bytes_per_second(),
            "demo_packets": self.statistics.demo_packets,
            "protocol_counts": self._protocol_counts_dict(),
            "rate_history": self.statistics.rate_history(limit=180),
            "top_source_ips": self.statistics.top_source_ips(limit=15),
            "top_destination_ips": self.statistics.top_destination_ips(limit=15),
            "top_destination_ports": self.statistics.top_destination_ports(limit=15),
        }

    def _protocol_counts_dict(self) -> Dict[str, int]:
        c = self.statistics.protocol_counts()
        return {name: val for name, val in c.items()}

    def _last_packet_time_label(self) -> str:
        ts = self.sniffer.queue.last_packet_time()
        if ts is None:
            return "—"
        try:
            return datetime.fromtimestamp(ts).strftime("%H:%M:%S")
        except Exception:
            return "—"

    # ---------- Capture state change callback ----------
    def _on_capture_state_change(self, old_state: str, new_state: str) -> None:
        try:
            log_capture(f"Capture state transition: {old_state} -> {new_state}.", "INFO")
        except Exception:
            pass

    # ---------- Selection ----------
    def _on_packet_row_select(self, parsed: Optional[ParsedPacket]) -> None:
        self.views["details"].set_packet(parsed)
        if parsed is not None and self._current_view != "details":
            pass

    # ---------- Worker ----------
    def _start_worker(self) -> None:
        if self._worker_running:
            return
        self._worker_running = True
        self._worker_thread = threading.Thread(
            target=self._worker_loop, name="PacketProcessingWorker", daemon=True,
        )
        self._worker_thread.start()

    def _worker_loop(self) -> None:
        batch_limit = 500
        while self._worker_running:
            try:
                batch = self.sniffer.queue.get_batch(max_batch=batch_limit)
                if batch:
                    self._process_batch(batch)
                else:
                    time.sleep(0.02)
            except Exception as e:
                log_error("Background packet processing worker crashed.", e)
                time.sleep(0.5)

    def _process_batch(self, batch: List[PacketRecord]) -> None:
        new_parsed: List[ParsedPacket] = []
        for record in batch:
            try:
                parsed = self.parser.parse_record(record)
            except Exception as e:
                log_error("Parse packet record failed.", e)
                continue
            try:
                self.statistics.update(parsed)
            except Exception as e:
                log_error("Statistics update failed.", e)
            try:
                self.ids.process(parsed, raw_packet=record.scapy_packet)
            except Exception as e:
                log_error("IDS process error.", e)
            new_parsed.append(parsed)
        if new_parsed:
            self._parsed_history.extend(new_parsed)
            limit = max(5000, self.config.capture.display_limit * 2)
            if len(self._parsed_history) > limit * 2:
                self._parsed_history = self._parsed_history[-limit:]

    # ---------- GUI refresh loop ----------
    def _refresh_views_loop(self) -> None:
        try:
            self._do_gui_refresh()
        except Exception as e:
            log_error("GUI refresh loop failed.", e)
        finally:
            self.root.after(250, self._refresh_views_loop)

    def _do_gui_refresh(self) -> None:
        now = time.time()
        self._clock_lbl.configure(text=datetime.now().strftime("%a %Y-%m-%d  %H:%M:%S"))
        cap_state = self.sniffer.state
        self._update_sb(self._sb_cap, f"Capture: {cap_state}", cap_state)
        iface = self.interface_manager.get_selected()
        iface_label = iface.label if iface else "(none)"
        self._update_sb(self._sb_iface, f"Interface: {iface_label}",
                        "OK" if iface else "IDLE")
        self._update_sb(self._sb_ids,
                        f"IDS: {'ON' if self.ids.is_enabled() else 'OFF'}",
                        "OK" if self.ids.is_enabled() else "IDLE")
        self.views["capture"].set_capture_badge(cap_state)
        displayed_count = 0
        if self._parsed_history:
            self.views["capture"].append_rows(self._parsed_history)
            if (now - self._last_full_refresh) >= 2.0:
                self.views["capture"].replace_all_rows(self._parsed_history)
                self._last_full_refresh = now
            displayed_count = self.views["capture"].displayed_count()
        total = self.statistics.total_packets
        queued = self.sniffer.queue.qsize()
        self.views["capture"].set_counters(displayed_count, total, queued)
        if (now - self._last_gui_refresh) >= 1.0:
            try:
                self.views["dashboard"].update_view()
            except Exception as e:
                log_error("Dashboard view refresh failed.", e)
            try:
                self.views["statistics"].update_view()
            except Exception as e:
                log_error("Statistics view refresh failed.", e)
            try:
                self.views["ids"].update_view()
            except Exception as e:
                log_error("IDS view refresh failed.", e)
            try:
                self.views["export"].update_view()
            except Exception as e:
                log_error("Export view refresh failed.", e)
            try:
                self.views["ids"].set_alerts(self.ids.alert_manager.list_alerts(limit=5000))
            except Exception as e:
                log_error("IDS alert list refresh failed.", e)
            self._last_gui_refresh = now
        # Toasts
        if self._pending_toasts:
            msg = self._pending_toasts.pop(0)
            self._sb_toast.configure(text=msg)
            self.root.after(6000, lambda: self._sb_toast.configure(text=""))

    # ---------- Misc ----------
    def _toast(self, message: str) -> None:
        self._pending_toasts.append(str(message))

    def _on_close(self) -> None:
        try:
            log_application("Application close requested.", "INFO")
            if self.sniffer.state in (STATE_CAPTURING, STATE_PAUSED):
                self.sniffer.stop()
            self._worker_running = False
            self.demo.stop()
        except Exception as e:
            log_error("Error during application shutdown.", e)
        try:
            self.config.save()
        except Exception:
            pass
        self.root.destroy()

    def run(self) -> None:
        self.root.mainloop()
