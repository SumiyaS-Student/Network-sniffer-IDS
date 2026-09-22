"""
Export view: CSV / PCAP export with user-chosen path and counts.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from typing import Any, Callable, Dict, Optional

from app.gui.theme import (
    COLORS, BASE_FONT, BASE_FONT_BOLD, SMALL_FONT, H2_FONT, H3_FONT,
)
from app.utils.time_utils import humanize_bytes


class ExportView(tk.Frame):
    def __init__(self, master,
                 actions: Dict[str, Callable],
                 state_provider: Callable[[], Dict[str, Any]],
                 auth_wrap: Callable[[Callable], Callable]):
        super().__init__(master, bg=COLORS["bg"])
        self._actions = actions
        self._state = state_provider
        self._auth_wrap = auth_wrap
        self._build()

    def _build(self):
        container = tk.Frame(self, bg=COLORS["bg"])
        container.pack(fill="both", expand=True, padx=20, pady=18)

        header = tk.Frame(container, bg=COLORS["bg"])
        header.pack(fill="x")
        tk.Label(header, text="Export Captured Data", bg=COLORS["bg"],
                 fg=COLORS["text"], font=H2_FONT).pack(side="left")

        summary_card = tk.Frame(container, bg=COLORS["panel"],
                                highlightbackground=COLORS["border"], highlightthickness=1)
        summary_card.pack(fill="x", pady=(14, 14))
        s = tk.Frame(summary_card, bg=COLORS["panel"])
        s.pack(fill="both", expand=True, padx=16, pady=14)
        tk.Label(s, text="Current Capture Summary", bg=COLORS["panel"],
                 fg=COLORS["text"], font=H3_FONT).pack(anchor="w")
        info_grid = tk.Frame(s, bg=COLORS["panel"])
        info_grid.pack(fill="x", pady=(10, 0))
        self._info_labels: Dict[str, tk.Label] = {}
        rows = [
            ("packets", "Total packets in memory"),
            ("bytes", "Approximate total traffic"),
            ("capture_state", "Capture state"),
            ("selected_iface", "Selected interface"),
            ("demo", "Demo packets included"),
        ]
        for i, (key, label) in enumerate(rows):
            r = tk.Frame(info_grid, bg=COLORS["panel"])
            r.pack(fill="x", pady=(0 if i else 0, 3))
            tk.Label(r, text=f"{label}:", bg=COLORS["panel"],
                     fg=COLORS["text_secondary"], font=BASE_FONT, width=24,
                     anchor="w").pack(side="left")
            lbl = tk.Label(r, text="—", bg=COLORS["panel"],
                           fg=COLORS["text"], font=BASE_FONT, anchor="w")
            lbl.pack(side="left", fill="x", expand=True)
            self._info_labels[key] = lbl

        export_card = tk.Frame(container, bg=COLORS["panel"],
                               highlightbackground=COLORS["border"], highlightthickness=1)
        export_card.pack(fill="x")
        inner = tk.Frame(export_card, bg=COLORS["panel"])
        inner.pack(fill="both", expand=True, padx=16, pady=14)
        tk.Label(inner, text="Export Options", bg=COLORS["panel"],
                 fg=COLORS["text"], font=H3_FONT).pack(anchor="w")

        limit_row = tk.Frame(inner, bg=COLORS["panel"])
        limit_row.pack(fill="x", pady=(10, 10))
        tk.Label(limit_row, text="Limit rows (0 = all):", bg=COLORS["panel"],
                 fg=COLORS["text"], font=BASE_FONT).pack(side="left")
        self._limit_var = tk.IntVar(value=0)
        spin = tk.Spinbox(limit_row, from_=0, to=10_000_000, increment=1000,
                          textvariable=self._limit_var, width=12, font=BASE_FONT)
        spin.pack(side="left", padx=(8, 16))
        tk.Label(limit_row, text="Filename hint:", bg=COLORS["panel"],
                 fg=COLORS["text"], font=BASE_FONT).pack(side="left")
        self._hint_var = tk.StringVar(value="capture")
        e = tk.Entry(
            limit_row, textvariable=self._hint_var, font=BASE_FONT, relief="flat",
            bg=COLORS["input_bg"], fg=COLORS["text"],
            highlightthickness=1,
            highlightbackground=COLORS["input_border"],
            highlightcolor=COLORS["input_focus"],
            insertbackground=COLORS["primary"], bd=0, width=28,
        )
        e.pack(side="left", padx=(8, 0))

        btn_row = tk.Frame(inner, bg=COLORS["panel"])
        btn_row.pack(fill="x", pady=(4, 0))
        self._action_btn(btn_row, "Export CSV", "export_csv",
                         COLORS["primary"], "#FFFFFF").pack(side="left", padx=(0, 10))
        self._action_btn(btn_row, "Export PCAP", "export_pcap",
                         COLORS["success"], "#FFFFFF").pack(side="left", padx=(0, 10))
        self._action_btn(btn_row, "Export CSV As…", "export_csv_as",
                         COLORS["primary_surface"], COLORS["primary"]).pack(side="left", padx=(0, 10))
        self._action_btn(btn_row, "Export PCAP As…", "export_pcap_as",
                         COLORS["success_surface"], COLORS["success"]).pack(side="left")

        hint = tk.Label(
            inner,
            text="PCAP files written here are compatible with Wireshark and other tools "
                 "that read standard libpcap format. Exports respect the capture history "
                 "stored in memory.",
            bg=COLORS["panel"], fg=COLORS["text_muted"], font=SMALL_FONT,
            wraplength=900, justify="left",
        )
        hint.pack(fill="x", pady=(18, 0))

    def _action_btn(self, parent, label, action_key, bg, fg):
        return tk.Button(
            parent, text=label, font=BASE_FONT_BOLD,
            bg=bg, fg=fg,
            activebackground=COLORS["primary_hover"] if bg == COLORS["primary"] else COLORS["border"],
            activeforeground="#FFFFFF" if fg == "#FFFFFF" else COLORS["text"],
            relief="flat", bd=0, padx=18, pady=10, cursor="hand2",
            command=self._wrapped(action_key),
            highlightbackground=bg, highlightthickness=1,
        )

    def _wrapped(self, action_key):
        def _cb():
            fn = self._actions.get(action_key)
            if fn is None:
                return
            kwargs = {}
            try:
                limit = int(self._limit_var.get()) or None
            except Exception:
                limit = None
            hint = (self._hint_var.get() or "capture").strip() or "capture"
            if action_key in ("export_csv", "export_pcap"):
                kwargs = {"limit": limit, "filename_hint": hint, "output_path": None}
            else:
                default_name = hint
                if action_key == "export_csv_as":
                    default_name += ".csv"
                    fp = filedialog.asksaveasfilename(
                        defaultextension=".csv",
                        initialfile=default_name,
                        filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
                        title="Export CSV As",
                    )
                    if not fp:
                        return
                    kwargs = {"limit": limit, "filename_hint": hint, "output_path": fp}
                else:
                    default_name += ".pcap"
                    fp = filedialog.asksaveasfilename(
                        defaultextension=".pcap",
                        initialfile=default_name,
                        filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")],
                        title="Export PCAP As",
                    )
                    if not fp:
                        return
                    kwargs = {"limit": limit, "filename_hint": hint, "output_path": fp}
            self._auth_wrap(fn)(**kwargs)
        return _cb

    def update_view(self) -> None:
        s = self._state() or {}
        packets = int(s.get("total_packets", 0) or 0)
        bytes_total = int(s.get("total_bytes", 0) or 0)
        self._info_labels["packets"].configure(text=f"{packets:,} packets")
        self._info_labels["bytes"].configure(text=humanize_bytes(bytes_total))
        self._info_labels["capture_state"].configure(text=str(s.get("capture_state", "IDLE")))
        self._info_labels["selected_iface"].configure(
            text=str(s.get("selected_iface_label", "—") or "—"))
        demo = int(s.get("demo_packets", 0) or 0)
        self._info_labels["demo"].configure(
            text=f"{demo:,} packets" + ("  (clearly labelled in output)" if demo else ""))
