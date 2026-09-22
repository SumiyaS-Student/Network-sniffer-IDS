"""
Settings view with capture, IDS, email, logging and password sections.
"""

import tkinter as tk
from tkinter import ttk, messagebox
from typing import Any, Callable, Dict, Optional

from app.gui.theme import (
    COLORS, BASE_FONT, BASE_FONT_BOLD, SMALL_FONT, H2_FONT, H3_FONT,
)
from config import AppConfig


class SettingsView(tk.Frame):
    def __init__(self, master, config: AppConfig,
                 auth_wrap: Callable[[Callable], Callable],
                 save_hook: Optional[Callable[[], None]] = None,
                 test_smtp_hook: Optional[Callable[[], bool]] = None):
        super().__init__(master, bg=COLORS["bg"])
        self._config = config
        self._auth_wrap = auth_wrap
        self._save_hook = save_hook
        self._test_smtp_hook = test_smtp_hook
        self._build()
        self.load_from_config()

    def _build(self):
        outer = tk.Frame(self, bg=COLORS["bg"])
        outer.pack(fill="both", expand=True, padx=20, pady=18)
        header = tk.Frame(outer, bg=COLORS["bg"])
        header.pack(fill="x")
        tk.Label(header, text="Settings", bg=COLORS["bg"], fg=COLORS["text"],
                 font=H2_FONT).pack(side="left")
        tk.Button(
            header, text="Save All", font=BASE_FONT_BOLD,
            bg=COLORS["primary"], fg="#FFFFFF",
            activebackground=COLORS["primary_hover"],
            activeforeground="#FFFFFF", relief="flat", bd=0,
            padx=18, pady=8, cursor="hand2",
            command=self._auth_wrap(self._save_all),
        ).pack(side="right")

        canvas = tk.Canvas(outer, bg=COLORS["bg"], highlightthickness=0,
                           bd=0, relief="flat")
        vsb = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
        inner = tk.Frame(canvas, bg=COLORS["bg"])
        inner.bind(
            "<Configure>",
            lambda _e: canvas.configure(scrollregion=canvas.bbox("all")),
        )
        canvas.create_window((0, 0), window=inner, anchor="nw")
        canvas.configure(yscrollcommand=vsb.set)
        canvas.pack(side="left", fill="both", expand=True, pady=(14, 0))
        vsb.pack(side="right", fill="y", pady=(14, 0))

        self._cap_vars: Dict[str, Any] = {}
        self._ids_vars: Dict[str, Any] = {}
        self._smtp_vars: Dict[str, Any] = {}
        self._log_vars: Dict[str, Any] = {}
        self._pw_vars: Dict[str, Any] = {}

        self._build_capture(inner)
        self._build_ids(inner)
        self._build_email(inner)
        self._build_logging(inner)
        self._build_password(inner)

        inner.columnconfigure(0, weight=1)
        inner.columnconfigure(1, weight=1)

    def _section_card(self, parent, title: str, row: int, col: int) -> tk.Frame:
        card = tk.Frame(parent, bg=COLORS["panel"],
                        highlightbackground=COLORS["border"], highlightthickness=1)
        card.grid(row=row, column=col, sticky="nsew", padx=(0, 14 if col == 0 else 0),
                  pady=(0, 14))
        head = tk.Frame(card, bg=COLORS["panel"])
        head.pack(fill="x", padx=14, pady=(12, 8))
        accent = tk.Frame(head, bg=COLORS["primary"], height=4, width=40)
        accent.pack(side="left")
        tk.Label(head, text=title, bg=COLORS["panel"], fg=COLORS["text"],
                 font=H3_FONT).pack(side="left", padx=(10, 0))
        body = tk.Frame(card, bg=COLORS["panel"])
        body.pack(fill="both", expand=True, padx=14, pady=(0, 14))
        return body

    def _labelled_entry(self, parent, label, var_row, var_key,
                        var, show=None, width=30, row=None, numeric=False):
        if row is None:
            row = len(var_row)
        tk.Label(parent, text=label, bg=COLORS["panel"], fg=COLORS["text_secondary"],
                 font=SMALL_FONT, anchor="w").grid(row=row * 2, column=0,
                                                     sticky="we", pady=(0, 2))
        entry = tk.Entry(
            parent, textvariable=var, show=show or "", font=BASE_FONT, relief="flat",
            bg=COLORS["input_bg"], fg=COLORS["text"],
            highlightthickness=1,
            highlightbackground=COLORS["input_border"],
            highlightcolor=COLORS["input_focus"],
            insertbackground=COLORS["primary"], bd=0, width=width,
        )
        entry.grid(row=row * 2 + 1, column=0, sticky="we", pady=(0, 10))
        parent.columnconfigure(0, weight=1)
        var_row[(var_key, label)] = var
        return var

    def _build_capture(self, parent):
        body = self._section_card(parent, "Capture Settings", 0, 0)
        grid = tk.Frame(body, bg=COLORS["panel"])
        grid.pack(fill="x")
        vars_row = {}
        self._cap_vars["max_retained"] = tk.IntVar(value=50000)
        self._cap_vars["display_limit"] = tk.IntVar(value=5000)
        self._cap_vars["auto_save"] = tk.BooleanVar(value=False)
        self._cap_vars["auto_save_interval"] = tk.IntVar(value=300)
        self._labelled_entry(grid, "Maximum retained packets", vars_row, "max_retained",
                             self._cap_vars["max_retained"])
        self._labelled_entry(grid, "Live display limit (rows)", vars_row, "display_limit",
                             self._cap_vars["display_limit"])
        self._labelled_entry(grid, "Auto-save interval (seconds)", vars_row, "auto_save_interval",
                             self._cap_vars["auto_save_interval"])
        auto_row = tk.Frame(body, bg=COLORS["panel"])
        auto_row.pack(fill="x", pady=(2, 10))
        tk.Checkbutton(auto_row, text="Enable auto-save of captures",
                       variable=self._cap_vars["auto_save"],
                       bg=COLORS["panel"], fg=COLORS["text"],
                       activebackground=COLORS["panel"], selectcolor=COLORS["panel"],
                       font=BASE_FONT).pack(anchor="w")

    def _build_ids(self, parent):
        body = self._section_card(parent, "IDS Settings", 0, 1)
        grid = tk.Frame(body, bg=COLORS["panel"])
        grid.pack(fill="x")
        vars_row = {}
        self._ids_vars["enabled"] = tk.BooleanVar(value=True)
        self._ids_vars["syn_threshold"] = tk.IntVar(value=100)
        self._ids_vars["ports_threshold"] = tk.IntVar(value=20)
        self._ids_vars["icmp_threshold"] = tk.IntVar(value=150)
        self._ids_vars["udp_threshold"] = tk.IntVar(value=200)
        self._ids_vars["ping_threshold"] = tk.IntVar(value=20)
        self._ids_vars["window"] = tk.IntVar(value=60)
        self._ids_vars["cooldown"] = tk.IntVar(value=300)
        self._ids_vars["rate_warn"] = tk.IntVar(value=5000)
        self._ids_vars["rate_crit"] = tk.IntVar(value=15000)
        self._ids_vars["suspicious_flags"] = tk.BooleanVar(value=True)
        tk.Checkbutton(body, text="IDS enabled by default",
                       variable=self._ids_vars["enabled"],
                       bg=COLORS["panel"], fg=COLORS["text"],
                       activebackground=COLORS["panel"], selectcolor=COLORS["panel"],
                       font=BASE_FONT).pack(anchor="w", pady=(0, 6))
        self._labelled_entry(grid, "SYN flood threshold (count per window)",
                             vars_row, "", self._ids_vars["syn_threshold"])
        self._labelled_entry(grid, "Port scan distinct ports threshold",
                             vars_row, "", self._ids_vars["ports_threshold"])
        self._labelled_entry(grid, "ICMP flood threshold", vars_row, "",
                             self._ids_vars["icmp_threshold"])
        self._labelled_entry(grid, "UDP flood threshold", vars_row, "",
                             self._ids_vars["udp_threshold"])
        self._labelled_entry(grid, "Ping sweep distinct destinations", vars_row, "",
                             self._ids_vars["ping_threshold"])
        self._labelled_entry(grid, "Detection window (seconds)", vars_row, "",
                             self._ids_vars["window"])
        self._labelled_entry(grid, "Alert cooldown (seconds)", vars_row, "",
                             self._ids_vars["cooldown"])
        self._labelled_entry(grid, "Packet rate warning (pkts/window)", vars_row, "",
                             self._ids_vars["rate_warn"])
        self._labelled_entry(grid, "Packet rate critical (pkts/window)", vars_row, "",
                             self._ids_vars["rate_crit"])
        tk.Checkbutton(body, text="Detect suspicious TCP flag combinations",
                       variable=self._ids_vars["suspicious_flags"],
                       bg=COLORS["panel"], fg=COLORS["text"],
                       activebackground=COLORS["panel"], selectcolor=COLORS["panel"],
                       font=BASE_FONT).pack(anchor="w")

    def _build_email(self, parent):
        body = self._section_card(parent, "Email (SMTP) Alerts", 1, 0)
        vars_row = {}
        self._smtp_vars["enabled"] = tk.BooleanVar(value=False)
        self._smtp_vars["host"] = tk.StringVar(value="")
        self._smtp_vars["port"] = tk.IntVar(value=587)
        self._smtp_vars["username"] = tk.StringVar(value="")
        self._smtp_vars["password"] = tk.StringVar(value="")
        self._smtp_vars["use_tls"] = tk.BooleanVar(value=True)
        self._smtp_vars["from_email"] = tk.StringVar(value="")
        self._smtp_vars["to_email"] = tk.StringVar(value="")
        top_row = tk.Frame(body, bg=COLORS["panel"])
        top_row.pack(fill="x", pady=(0, 8))
        tk.Checkbutton(top_row, text="Enable email alerts when IDS fires",
                       variable=self._smtp_vars["enabled"],
                       bg=COLORS["panel"], fg=COLORS["text"],
                       activebackground=COLORS["panel"], selectcolor=COLORS["panel"],
                       font=BASE_FONT).pack(side="left")
        tk.Button(
            top_row, text="Test Email", font=BASE_FONT_BOLD,
            bg=COLORS["warning_surface"], fg=COLORS["warning"],
            activebackground=COLORS["warning_surface"], relief="flat", bd=0,
            padx=14, pady=6, cursor="hand2",
            command=self._auth_wrap(self._on_test_email),
            highlightbackground=COLORS["warning"], highlightthickness=1,
        ).pack(side="right")
        grid = tk.Frame(body, bg=COLORS["panel"])
        grid.pack(fill="x")
        self._labelled_entry(grid, "SMTP host", vars_row, "", self._smtp_vars["host"])
        self._labelled_entry(grid, "SMTP port", vars_row, "", self._smtp_vars["port"])
        self._labelled_entry(grid, "SMTP username", vars_row, "", self._smtp_vars["username"])
        self._labelled_entry(grid, "SMTP password", vars_row, "",
                             self._smtp_vars["password"], show="•")
        self._labelled_entry(grid, "Sender email", vars_row, "", self._smtp_vars["from_email"])
        self._labelled_entry(grid, "Recipient email", vars_row, "", self._smtp_vars["to_email"])
        tls_row = tk.Frame(body, bg=COLORS["panel"])
        tls_row.pack(fill="x")
        tk.Checkbutton(tls_row, text="Use STARTTLS / SSL (recommended)",
                       variable=self._smtp_vars["use_tls"],
                       bg=COLORS["panel"], fg=COLORS["text"],
                       activebackground=COLORS["panel"], selectcolor=COLORS["panel"],
                       font=BASE_FONT).pack(anchor="w")

    def _build_logging(self, parent):
        body = self._section_card(parent, "Logging Settings", 1, 1)
        self._log_vars["log_level"] = tk.StringVar(value="INFO")
        self._log_vars["directory"] = tk.StringVar(value="")
        levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        level_row = tk.Frame(body, bg=COLORS["panel"])
        level_row.pack(fill="x", pady=(0, 10))
        tk.Label(level_row, text="Log level:", bg=COLORS["panel"],
                 fg=COLORS["text_secondary"], font=BASE_FONT).pack(side="left")
        combo = ttk.Combobox(level_row, textvariable=self._log_vars["log_level"],
                             state="readonly", values=levels, width=12, font=BASE_FONT)
        combo.pack(side="left", padx=(8, 0))
        log_grid = tk.Frame(body, bg=COLORS["panel"])
        log_grid.pack(fill="x")
        self._labelled_entry(log_grid, "Log directory (leave blank for default)",
                             {}, "", self._log_vars["directory"], width=40)
        note = tk.Label(
            body,
            text="Logs are written to data/logs by default. Restart the application for "
                 "log level and directory changes to take effect.",
            bg=COLORS["panel"], fg=COLORS["text_muted"], font=SMALL_FONT,
            wraplength=420, justify="left",
        )
        note.pack(fill="x", pady=(4, 0))

    def _build_password(self, parent):
        body = self._section_card(parent, "Application Password", 2, 0)
        self._pw_vars["old"] = tk.StringVar(value="")
        self._pw_vars["new"] = tk.StringVar(value="")
        self._pw_vars["confirm"] = tk.StringVar(value="")
        vars_row = {}
        grid = tk.Frame(body, bg=COLORS["panel"])
        grid.pack(fill="x")
        self._labelled_entry(grid, "Current password", vars_row, "",
                             self._pw_vars["old"], show="•")
        self._labelled_entry(grid, "New password (min. 8 chars)", vars_row, "",
                             self._pw_vars["new"], show="•")
        self._labelled_entry(grid, "Confirm new password", vars_row, "",
                             self._pw_vars["confirm"], show="•")
        btn_row = tk.Frame(body, bg=COLORS["panel"])
        btn_row.pack(fill="x", pady=(6, 0))
        tk.Button(
            btn_row, text="Change Password", font=BASE_FONT_BOLD,
            bg=COLORS["primary_surface"], fg=COLORS["primary"],
            activebackground=COLORS["info_surface"], relief="flat", bd=0,
            padx=14, pady=8, cursor="hand2",
            command=self._auth_wrap(self._on_change_password),
            highlightbackground=COLORS["primary"], highlightthickness=1,
        ).pack(side="right")

    def load_from_config(self) -> None:
        c = self._config
        self._cap_vars["max_retained"].set(c.capture.max_retained_packets)
        self._cap_vars["display_limit"].set(c.capture.display_limit)
        self._cap_vars["auto_save"].set(c.capture.auto_save)
        self._cap_vars["auto_save_interval"].set(c.capture.auto_save_interval_seconds)

        self._ids_vars["enabled"].set(c.ids.enabled)
        self._ids_vars["syn_threshold"].set(c.ids.syn_flood_threshold)
        self._ids_vars["ports_threshold"].set(c.ids.port_scan_threshold)
        self._ids_vars["icmp_threshold"].set(c.ids.icmp_flood_threshold)
        self._ids_vars["udp_threshold"].set(c.ids.udp_flood_threshold)
        self._ids_vars["ping_threshold"].set(c.ids.ping_sweep_threshold)
        self._ids_vars["window"].set(c.ids.detection_window_seconds)
        self._ids_vars["cooldown"].set(c.ids.alert_cooldown_seconds)
        self._ids_vars["rate_warn"].set(c.ids.packet_rate_warning)
        self._ids_vars["rate_crit"].set(c.ids.packet_rate_critical)
        self._ids_vars["suspicious_flags"].set(c.ids.suspicious_flags_enabled)

        self._smtp_vars["enabled"].set(c.smtp.enabled)
        self._smtp_vars["host"].set(c.smtp.host)
        self._smtp_vars["port"].set(c.smtp.port)
        self._smtp_vars["username"].set(c.smtp.username)
        self._smtp_vars["password"].set(c.smtp.password)
        self._smtp_vars["use_tls"].set(c.smtp.use_tls)
        self._smtp_vars["from_email"].set(c.smtp.from_email)
        self._smtp_vars["to_email"].set(c.smtp.to_email)

        self._log_vars["log_level"].set(c.logging.log_level)
        self._log_vars["directory"].set(c.logging.log_directory)

    def _collect_values(self) -> None:
        c = self._config
        try:
            c.capture.max_retained_packets = max(100, int(self._cap_vars["max_retained"].get()))
        except Exception:
            pass
        try:
            c.capture.display_limit = max(100, int(self._cap_vars["display_limit"].get()))
        except Exception:
            pass
        c.capture.auto_save = bool(self._cap_vars["auto_save"].get())
        try:
            c.capture.auto_save_interval_seconds = max(10, int(self._cap_vars["auto_save_interval"].get()))
        except Exception:
            pass

        c.ids.enabled = bool(self._ids_vars["enabled"].get())
        try:
            c.ids.syn_flood_threshold = max(1, int(self._ids_vars["syn_threshold"].get()))
            c.ids.port_scan_threshold = max(2, int(self._ids_vars["ports_threshold"].get()))
            c.ids.icmp_flood_threshold = max(1, int(self._ids_vars["icmp_threshold"].get()))
            c.ids.udp_flood_threshold = max(1, int(self._ids_vars["udp_threshold"].get()))
            c.ids.ping_sweep_threshold = max(2, int(self._ids_vars["ping_threshold"].get()))
            c.ids.detection_window_seconds = max(1, int(self._ids_vars["window"].get()))
            c.ids.alert_cooldown_seconds = max(0, int(self._ids_vars["cooldown"].get()))
            c.ids.packet_rate_warning = max(100, int(self._ids_vars["rate_warn"].get()))
            c.ids.packet_rate_critical = max(c.ids.packet_rate_warning + 1,
                                             int(self._ids_vars["rate_crit"].get()))
        except Exception:
            pass
        c.ids.suspicious_flags_enabled = bool(self._ids_vars["suspicious_flags"].get())

        c.smtp.enabled = bool(self._smtp_vars["enabled"].get())
        c.smtp.host = (self._smtp_vars["host"].get() or "").strip()
        try:
            c.smtp.port = max(1, min(65535, int(self._smtp_vars["port"].get())))
        except Exception:
            c.smtp.port = 587
        c.smtp.username = (self._smtp_vars["username"].get() or "").strip()
        c.smtp.password = self._smtp_vars["password"].get() or ""
        c.smtp.use_tls = bool(self._smtp_vars["use_tls"].get())
        c.smtp.from_email = (self._smtp_vars["from_email"].get() or "").strip()
        c.smtp.to_email = (self._smtp_vars["to_email"].get() or "").strip()

        c.logging.log_level = (self._log_vars["log_level"].get() or "INFO").strip()
        c.logging.log_directory = (self._log_vars["directory"].get() or "").strip()

    def _save_all(self) -> None:
        self._collect_values()
        ok = self._config.save()
        if self._save_hook:
            try:
                self._save_hook()
            except Exception:
                pass
        if ok:
            messagebox.showinfo("Settings Saved",
                                "Configuration has been saved successfully.")
        else:
            messagebox.showerror("Save Failed",
                                 "Could not write configuration file.")

    def _on_test_email(self) -> None:
        self._collect_values()
        self._config.save()
        if self._test_smtp_hook is None:
            messagebox.showinfo("Test Email", "Test email hook is not configured.")
            return
        result = self._test_smtp_hook()
        if isinstance(result, tuple):
            ok, err = bool(result[0]), str(result[1] or "")
        else:
            ok, err = bool(result), ""
        if ok:
            messagebox.showinfo("Test Email", "Test email sent successfully.")
        else:
            messagebox.showerror(
                "Test Email Failed",
                "Could not send test email.\n\n" + err if err else
                "Could not send test email. Check SMTP settings and consult error.log.",
            )

    def _on_change_password(self) -> None:
        old = self._pw_vars["old"].get()
        new = self._pw_vars["new"].get()
        confirm = self._pw_vars["confirm"].get()
        if not new or len(new) < 8:
            messagebox.showwarning("Password", "New password must be at least 8 characters.")
            return
        if new != confirm:
            messagebox.showwarning("Password", "New passwords do not match.")
            return
        ok = self._config.change_password(old, new)
        if ok:
            self._pw_vars["old"].set("")
            self._pw_vars["new"].set("")
            self._pw_vars["confirm"].set("")
            messagebox.showinfo("Password Updated",
                                "Password changed. All sessions have been closed.")
        else:
            messagebox.showerror("Password", "Current password is incorrect.")
