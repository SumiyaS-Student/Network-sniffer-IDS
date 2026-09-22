"""
IDS alerts view with enable toggle, KPIs, alert table, and details.
"""

import tkinter as tk
from tkinter import ttk
from typing import Any, Callable, Dict, List, Optional

from app.gui.theme import (
    COLORS, BASE_FONT, BASE_FONT_BOLD, SMALL_FONT, H2_FONT, H3_FONT, MONO_FONT,
    severity_bg, severity_fg, status_colors,
)
from app.ids.alerts import IDSAlert, Severity


SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]

ALERT_COLUMNS = ("time", "sev", "type", "src", "dst", "info", "status")
ALERT_HEADERS = ("Time", "Severity", "Alert Type", "Source IP",
                 "Destination IP", "Info", "Status")
ALERT_WIDTHS = (150, 90, 200, 130, 130, 150, 90)


class IDSView(tk.Frame):
    def __init__(self, master,
                 actions: Dict[str, Callable],
                 state_provider: Callable[[], Dict[str, Any]],
                 auth_wrap: Callable[[Callable], Callable]):
        super().__init__(master, bg=COLORS["bg"])
        self._actions = actions
        self._state = state_provider
        self._auth_wrap = auth_wrap
        self._alerts_cache: List[IDSAlert] = []
        self._row_to_alert: Dict[str, IDSAlert] = {}
        self._selected_alert_id: Optional[str] = None
        self._build()

    def _build(self):
        container = tk.Frame(self, bg=COLORS["bg"])
        container.pack(fill="both", expand=True, padx=20, pady=18)
        header = tk.Frame(container, bg=COLORS["bg"])
        header.pack(fill="x")
        tk.Label(header, text="Intrusion Detection System",
                 bg=COLORS["bg"], fg=COLORS["text"], font=H2_FONT).pack(side="left")
        head_right = tk.Frame(header, bg=COLORS["bg"])
        head_right.pack(side="right")
        self._enabled_var = tk.BooleanVar(value=False)
        self._ids_toggle = tk.Checkbutton(
            head_right, text="IDS ENGINE", variable=self._enabled_var,
            bg=COLORS["danger"], fg="#FFFFFF", selectcolor=COLORS["success"],
            activebackground=COLORS["danger"], activeforeground="#FFFFFF",
            font=BASE_FONT_BOLD, indicatoron=False, relief="flat", bd=0,
            padx=14, pady=8, cursor="hand2",
            command=self._on_toggle_ids,
        )
        self._ids_toggle.pack(side="right")
        self._status_badge = tk.Label(head_right, text="IDS: OFF",
                                      bg=status_colors("IDLE")[1],
                                      fg=status_colors("IDLE")[0],
                                      font=BASE_FONT_BOLD, padx=14, pady=8)
        self._status_badge.pack(side="right", padx=(0, 10))

        kpis = tk.Frame(container, bg=COLORS["bg"])
        kpis.pack(fill="x", pady=(14, 14))
        self._kpi_widgets = {}
        for label, key, accent in [
            ("Total Alerts", "total", COLORS["primary"]),
            ("Critical", "CRITICAL", COLORS["critical"]),
            ("High", "HIGH", COLORS["danger"]),
            ("Medium", "MEDIUM", COLORS["warning"]),
            ("Low", "LOW", COLORS["success"]),
            ("Highest Severity", "highest", "#6A4CB8"),
        ]:
            card = tk.Frame(kpis, bg=COLORS["panel"],
                            highlightbackground=COLORS["border"], highlightthickness=1)
            card.pack(side="left", fill="both", expand=True, padx=(0, 12))
            top = tk.Frame(card, bg=COLORS["panel"])
            top.pack(fill="x", padx=14, pady=(12, 2))
            bar = tk.Frame(top, bg=accent, height=4, width=40)
            bar.pack(side="left")
            tk.Label(top, text=label, bg=COLORS["panel"],
                     fg=COLORS["text_secondary"], font=SMALL_FONT).pack(side="left", padx=(10, 0))
            var = tk.StringVar(value="0")
            lbl = tk.Label(card, textvariable=var, bg=COLORS["panel"],
                           fg=accent if key in ("CRITICAL", "HIGH", "highest") else COLORS["text"],
                           font=("Segoe UI Semibold", 18), anchor="w")
            lbl.pack(fill="x", padx=14, pady=(2, 10))
            self._kpi_widgets[key] = var

        paned = tk.PanedWindow(container, orient="horizontal", bg=COLORS["bg"],
                               sashrelief="flat", sashwidth=4, opaqueresize=False)
        paned.pack(fill="both", expand=True)

        left_card = tk.Frame(paned, bg=COLORS["panel"],
                             highlightbackground=COLORS["border"], highlightthickness=1)
        paned.add(left_card, minsize=480, width=720)
        inner_l = tk.Frame(left_card, bg=COLORS["panel"])
        inner_l.pack(fill="both", expand=True, padx=14, pady=14)
        top_l = tk.Frame(inner_l, bg=COLORS["panel"])
        top_l.pack(fill="x")
        tk.Label(top_l, text="Alerts", bg=COLORS["panel"], fg=COLORS["text"],
                 font=H3_FONT).pack(side="left")
        btn_frame = tk.Frame(top_l, bg=COLORS["panel"])
        btn_frame.pack(side="right")
        self._button(btn_frame, "Test SMTP Alert", "send_test_smtp_alert").pack(side="right", padx=(6, 0))
        self._button(btn_frame, "Clear Alerts", "clear_alerts",
                     bg=COLORS["danger_surface"], fg=COLORS["danger"]).pack(side="right")

        tree_frame = tk.Frame(inner_l, bg=COLORS["panel"])
        tree_frame.pack(fill="both", expand=True, pady=(10, 0))
        style = ttk.Style(self)
        style.configure("IDS.Treeview",
                        background=COLORS["panel"], foreground=COLORS["text"],
                        fieldbackground=COLORS["panel"], rowheight=24,
                        font=BASE_FONT, borderwidth=0)
        style.map("IDS.Treeview",
                  background=[("selected", COLORS["primary_surface"])],
                  foreground=[("selected", COLORS["primary"])])
        style.configure("IDS.Treeview.Heading",
                        background=COLORS["table_header_bg"], foreground=COLORS["text"],
                        font=BASE_FONT_BOLD, borderwidth=0)
        self._tree = ttk.Treeview(tree_frame, columns=ALERT_COLUMNS,
                                  show="headings", style="IDS.Treeview", height=14)
        for col, head, width in zip(ALERT_COLUMNS, ALERT_HEADERS, ALERT_WIDTHS):
            self._tree.heading(col, text=head)
            self._tree.column(col, width=width, anchor="w")
        for sev in Severity:
            self._tree.tag_configure(
                sev.value, background=severity_bg(sev.value),
                foreground=severity_fg(sev.value))
        self._tree.tag_configure("DEMO", background=COLORS["info_surface"])
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)
        self._tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        self._tree.bind("<<TreeviewSelect>>", self._on_select)

        right_card = tk.Frame(paned, bg=COLORS["panel"],
                              highlightbackground=COLORS["border"], highlightthickness=1)
        paned.add(right_card, minsize=320, width=440)
        inner_r = tk.Frame(right_card, bg=COLORS["panel"])
        inner_r.pack(fill="both", expand=True, padx=14, pady=14)
        tk.Label(inner_r, text="Alert Details", bg=COLORS["panel"],
                 fg=COLORS["text"], font=H3_FONT).pack(anchor="w")
        self._details_title = tk.Label(inner_r, text="Select an alert to view details.",
                                       bg=COLORS["panel"], fg=COLORS["text_secondary"],
                                       font=BASE_FONT, wraplength=400, justify="left")
        self._details_title.pack(fill="x", pady=(8, 10), anchor="w")
        text_frame = tk.Frame(inner_r, bg=COLORS["bg"])
        text_frame.pack(fill="both", expand=True)
        self._text = tk.Text(text_frame, font=MONO_FONT, wrap="word",
                             bg=COLORS["panel"], fg=COLORS["text"],
                             insertbackground=COLORS["primary"], relief="flat", bd=0,
                             highlightthickness=1,
                             highlightbackground=COLORS["border"],
                             highlightcolor=COLORS["input_focus"],
                             padx=12, pady=10, state="disabled")
        vsb2 = ttk.Scrollbar(text_frame, orient="vertical", command=self._text.yview)
        self._text.configure(yscrollcommand=vsb2.set)
        self._text.pack(side="left", fill="both", expand=True)
        vsb2.pack(side="right", fill="y")

    def _button(self, parent, label: str, action_key: str, bg=None, fg=None):
        return tk.Button(
            parent, text=label, font=BASE_FONT,
            bg=bg or COLORS["primary_surface"],
            fg=fg or COLORS["primary"],
            activebackground=COLORS["info_surface"],
            relief="flat", bd=0, padx=12, pady=6, cursor="hand2",
            highlightbackground=COLORS["border"] if not bg else bg,
            highlightthickness=1,
            command=self._wrap(action_key),
        )

    def _wrap(self, action_key: str):
        def _cb():
            fn = self._actions.get(action_key)
            if fn is None:
                return
            self._auth_wrap(fn)()
        return _cb

    def _on_toggle_ids(self) -> None:
        fn = self._actions.get("toggle_ids")
        if fn is None:
            return
        self._auth_wrap(fn)(self._enabled_var.get())

    def set_ids_enabled(self, enabled: bool) -> None:
        self._enabled_var.set(bool(enabled))
        self._status_badge.configure(
            text=f"IDS: {'ON' if enabled else 'OFF'}",
            fg=(COLORS["success"] if enabled else COLORS["text_secondary"]),
            bg=(COLORS["success_surface"] if enabled else COLORS["surface"]),
        )
        self._ids_toggle.configure(
            bg=COLORS["success"] if enabled else COLORS["danger"],
            activebackground=COLORS["primary_hover"] if not enabled else COLORS["success"],
        )

    def set_alerts(self, alerts: List[IDSAlert]) -> None:
        new_ids = [a.alert_id for a in alerts]
        old_ids = [a.alert_id for a in self._alerts_cache]
        if new_ids == old_ids:
            return
        selected_id = self._selected_alert_id
        self._alerts_cache = list(alerts)
        for r in self._tree.get_children():
            self._tree.delete(r)
        self._row_to_alert.clear()
        restore_id = None
        for alert in reversed(self._alerts_cache[-5000:]):
            tags = [alert.severity.value]
            if alert.is_demo:
                tags.append("DEMO")
            row_id = self._tree.insert("", "end", values=alert.to_row(), tags=tags)
            self._row_to_alert[row_id] = alert
            if selected_id is not None and alert.alert_id == selected_id:
                restore_id = row_id
        if restore_id is not None:
            self._tree.selection_set(restore_id)
            self._tree.see(restore_id)
            self._on_select()
        elif selected_id is not None:
            self._selected_alert_id = None
            self._details_title.configure(text="Select an alert to view details.")
            self._set_text("")

    def _on_select(self, _event=None) -> None:
        sel = self._tree.selection()
        if not sel:
            self._selected_alert_id = None
            self._details_title.configure(text="Select an alert to view details.")
            self._set_text("")
            return
        alert = self._row_to_alert.get(sel[-1])
        if alert is None:
            return
        self._selected_alert_id = alert.alert_id
        self._details_title.configure(
            text=f"{alert.alert_type} · {alert.severity.value}"
                 + (" · DEMO DATA" if alert.is_demo else ""))
        self._set_text(alert.summary())

    def _set_text(self, text: str) -> None:
        self._text.configure(state="normal")
        self._text.delete("1.0", "end")
        self._text.insert("1.0", text)
        self._text.configure(state="disabled")

    def update_view(self) -> None:
        state = self._state() or {}
        self.set_ids_enabled(bool(state.get("ids_enabled")))
        total = int(state.get("total_alerts", 0) or 0)
        sev_counts = state.get("severity_counts") or {}
        highest = state.get("highest_severity") or "—"
        self._kpi_widgets["total"].set(f"{total:,}")
        for s in Severity:
            self._kpi_widgets[s.value].set(f"{int(sev_counts.get(s, 0) or 0):,}")
        self._kpi_widgets["highest"].set(highest)
