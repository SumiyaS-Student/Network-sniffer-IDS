"""
Dashboard view with KPI cards, quick status, and top items.
"""

import tkinter as tk
from tkinter import ttk
from typing import Any, Callable, Dict, Optional

from app.gui.theme import (
    COLORS, BASE_FONT, BASE_FONT_BOLD, SMALL_FONT, H2_FONT, H3_FONT,
    protocol_color, severity_bg, severity_fg, status_colors,
)
from app.utils.time_utils import humanize_bytes, format_hms


class DashboardView(tk.Frame):
    def __init__(self, master, state_provider: Callable[[], Dict[str, Any]]):
        super().__init__(master, bg=COLORS["bg"])
        self._state_provider = state_provider
        self._kpis: Dict[str, tk.Label] = {}
        self._status_badges: Dict[str, tk.Label] = {}
        self._build()

    def _card(self, parent, title: str, value_key: str, unit: str = "",
              fg: Optional[str] = None, accent: str = COLORS["primary"]):
        card = tk.Frame(parent, bg=COLORS["panel"],
                        highlightbackground=COLORS["border"],
                        highlightthickness=1)
        card.pack(side="left", fill="both", expand=True, padx=(0, 12))
        top = tk.Frame(card, bg=COLORS["panel"])
        top.pack(fill="x", padx=16, pady=(14, 4))
        accent_bar = tk.Frame(top, bg=accent, height=4, width=40)
        accent_bar.pack(side="left")
        tk.Label(top, text=title, bg=COLORS["panel"],
                 fg=COLORS["text_secondary"], font=SMALL_FONT).pack(
            side="left", padx=(10, 0))
        value_var = tk.StringVar(value="—")
        value_lbl = tk.Label(
            card, textvariable=value_var, bg=COLORS["panel"],
            fg=fg or COLORS["text"], font=("Segoe UI Semibold", 22), anchor="w",
        )
        value_lbl.pack(fill="x", padx=16, pady=(2, 0))
        unit_lbl = tk.Label(card, text=unit, bg=COLORS["panel"],
                            fg=COLORS["text_muted"], font=SMALL_FONT, anchor="w")
        unit_lbl.pack(fill="x", padx=16, pady=(0, 14))
        self._kpis[value_key] = value_lbl
        value_lbl._var = value_var
        return card

    def _build(self):
        outer = tk.Frame(self, bg=COLORS["bg"])
        outer.pack(fill="both", expand=True)

        canvas = tk.Canvas(outer, bg=COLORS["bg"], highlightthickness=0, bd=0)
        vsb = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
        hsb = ttk.Scrollbar(outer, orient="horizontal", command=canvas.xview)
        canvas.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        canvas.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        hsb.pack(side="bottom", fill="x")

        container = tk.Frame(canvas, bg=COLORS["bg"])
        win_id = canvas.create_window((0, 0), window=container, anchor="nw")
        container.bind(
            "<Configure>",
            lambda _e: canvas.configure(scrollregion=canvas.bbox("all")),
        )
        canvas.bind(
            "<Configure>",
            lambda e: canvas.itemconfigure(win_id, width=e.width),
        )
        for w in (canvas, container):
            try:
                w.bind("<MouseWheel>",
                       lambda e, c=canvas: c.yview_scroll(int(-1 * (e.delta / 120)), "units"))
                w.bind("<Shift-MouseWheel>",
                       lambda e, c=canvas: c.xview_scroll(int(-1 * (e.delta / 120)), "units"))
            except Exception:
                pass

        inner = tk.Frame(container, bg=COLORS["bg"])
        inner.pack(fill="both", expand=True, padx=20, pady=18)

        header = tk.Frame(inner, bg=COLORS["bg"])
        header.pack(fill="x")
        tk.Label(header, text="Dashboard", bg=COLORS["bg"], fg=COLORS["text"],
                 font=H2_FONT).pack(side="left")
        header_right = tk.Frame(header, bg=COLORS["bg"])
        header_right.pack(side="right")
        self._status_badges["app"] = self._make_badge(header_right, "App Status: READY",
                                                       status_colors("OK"))
        self._status_badges["app"].pack(side="right", padx=(6, 0))
        self._status_badges["ids"] = self._make_badge(header_right, "IDS: OFF",
                                                       status_colors("IDLE"))
        self._status_badges["ids"].pack(side="right", padx=(6, 0))
        self._status_badges["capture"] = self._make_badge(header_right, "Capture: IDLE",
                                                           status_colors("IDLE"))
        self._status_badges["capture"].pack(side="right")

        kpis = tk.Frame(inner, bg=COLORS["bg"])
        kpis.pack(fill="x", pady=(14, 18))
        self._card(kpis, "Total Packets", "packets", "packets processed",
                   accent=COLORS["primary"])
        self._card(kpis, "Total Traffic", "bytes", "approximate data",
                   accent=COLORS["success"])
        self._card(kpis, "Packets / sec", "pps", "recent rate",
                   accent=COLORS["info"])
        self._card(kpis, "IDS Alerts", "alerts", "all severities",
                   accent=COLORS["warning"])
        self._card(kpis, "Uptime", "uptime", "elapsed capture time",
                   accent="#6A4CB8")

        body = tk.PanedWindow(inner, orient="horizontal",
                              bg=COLORS["bg"], sashrelief="flat", sashwidth=4,
                              opaqueresize=False)
        body.pack(fill="both", expand=True)

        left = tk.Frame(body, bg=COLORS["bg"])
        body.add(left, minsize=360, width=480)
        right = tk.Frame(body, bg=COLORS["bg"])
        body.add(right, minsize=360, width=480)

        self._status_panel = self._build_status_panel(left)
        self._status_panel.pack(fill="x")

        proto_card = self._build_list_card(left, "Protocol Distribution", "protocol")
        proto_card.pack(fill="both", expand=True, pady=(14, 0))

        iface_card = self._build_info_card(right, "Selected Interface", "iface")
        iface_card.pack(fill="x")

        src_card = self._build_list_card(right, "Top Source IPs", "top_src")
        src_card.pack(fill="both", expand=True, pady=(14, 0))

        dst_inner = tk.Frame(right, bg=COLORS["bg"])
        dst_inner.pack(fill="both", expand=True, pady=(14, 0))
        self._build_list_card(dst_inner, "Top Destination IPs", "top_dst").pack(fill="both", expand=True)

    def _make_badge(self, parent, text: str, colors):
        fg, bg = colors
        lbl = tk.Label(parent, text=text, bg=bg, fg=fg,
                       font=BASE_FONT_BOLD, padx=12, pady=5, cursor="arrow")
        return lbl

    def _update_badge(self, key: str, text: str, status: str):
        lbl = self._status_badges.get(key)
        if lbl is None:
            return
        fg, bg = status_colors(status)
        lbl.configure(text=text, fg=fg, bg=bg)

    def _build_status_panel(self, parent):
        card = tk.Frame(parent, bg=COLORS["panel"],
                        highlightbackground=COLORS["border"], highlightthickness=1)
        inner = tk.Frame(card, bg=COLORS["panel"])
        inner.pack(fill="x", padx=16, pady=14)
        tk.Label(inner, text="System & Capture Status", bg=COLORS["panel"],
                 fg=COLORS["text"], font=H3_FONT).pack(anchor="w")
        self._status_lines = tk.Frame(inner, bg=COLORS["panel"])
        self._status_lines.pack(fill="x", pady=(10, 0))
        self._status_widgets: Dict[str, tk.Label] = {}
        for i, (key, label) in enumerate([
            ("capture_state", "Capture state"),
            ("selected_iface", "Selected interface"),
            ("scapy", "Scapy capture driver"),
            ("demo_mode", "Demo / test mode"),
            ("last_packet", "Last packet time"),
        ]):
            row = tk.Frame(self._status_lines, bg=COLORS["panel"])
            row.pack(fill="x", pady=(2 if i else 0, 2))
            tk.Label(row, text=f"{label}:", bg=COLORS["panel"],
                     fg=COLORS["text_secondary"], font=BASE_FONT, width=18,
                     anchor="w").pack(side="left")
            value_lbl = tk.Label(row, text="—", bg=COLORS["panel"],
                                 fg=COLORS["text"], font=BASE_FONT, anchor="w")
            value_lbl.pack(side="left", fill="x", expand=True)
            self._status_widgets[key] = value_lbl
        return card

    def _build_info_card(self, parent, title: str, key: str):
        card = tk.Frame(parent, bg=COLORS["panel"],
                        highlightbackground=COLORS["border"], highlightthickness=1)
        inner = tk.Frame(card, bg=COLORS["panel"])
        inner.pack(fill="both", expand=True, padx=16, pady=14)
        tk.Label(inner, text=title, bg=COLORS["panel"],
                 fg=COLORS["text"], font=H3_FONT).pack(anchor="w")
        self._iface_widgets: Dict[str, tk.Label] = {}
        rows = [("name", "Interface"), ("description", "Description"),
                ("ipv4", "IPv4"), ("ipv6", "IPv6"), ("mac", "MAC")]
        body = tk.Frame(inner, bg=COLORS["panel"])
        body.pack(fill="x", pady=(10, 0))
        for i, (k, label) in enumerate(rows):
            row = tk.Frame(body, bg=COLORS["panel"])
            row.pack(fill="x", pady=(2 if i else 0, 2))
            tk.Label(row, text=f"{label}:", bg=COLORS["panel"],
                     fg=COLORS["text_secondary"], font=BASE_FONT, width=14,
                     anchor="w").pack(side="left")
            value = tk.Label(row, text="—", bg=COLORS["panel"],
                             fg=COLORS["text"], font=BASE_FONT, anchor="w")
            value.pack(side="left", fill="x", expand=True)
            self._iface_widgets[k] = value
        return card

    def _build_list_card(self, parent, title: str, key: str):
        card_parent = parent or tk.Frame()
        card = tk.Frame(card_parent, bg=COLORS["panel"],
                        highlightbackground=COLORS["border"], highlightthickness=1)
        inner = tk.Frame(card, bg=COLORS["panel"])
        inner.pack(fill="both", expand=True, padx=16, pady=14)
        header = tk.Frame(inner, bg=COLORS["panel"])
        header.pack(fill="x")
        tk.Label(header, text=title, bg=COLORS["panel"],
                 fg=COLORS["text"], font=H3_FONT).pack(side="left")
        tk.Label(header, text="Top items are updated live.",
                 bg=COLORS["panel"], fg=COLORS["text_muted"],
                 font=SMALL_FONT).pack(side="right")
        body = tk.Frame(inner, bg=COLORS["panel"])
        body.pack(fill="both", expand=True, pady=(10, 0))
        tree = ttk.Treeview(body, columns=("item", "count", "pct"),
                            show="headings", height=8)
        tree.heading("item", text="Item")
        tree.heading("count", text="Count")
        tree.heading("pct", text="Share")
        tree.column("item", width=220, anchor="w")
        tree.column("count", width=80, anchor="e")
        tree.column("pct", width=80, anchor="e")
        vsb = ttk.Scrollbar(body, orient="vertical", command=tree.yview)
        hsb = ttk.Scrollbar(body, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        hsb.pack(side="bottom", fill="x", pady=(4, 0))
        self._bind_wheel(tree)
        self._list_trees = getattr(self, "_list_trees", {})
        self._list_trees[key] = tree
        return card

    def _bind_wheel(self, widget) -> None:
        try:
            widget.bind("<MouseWheel>",
                        lambda e: widget.yview_scroll(int(-1 * (e.delta / 120)), "units"))
            widget.bind("<Shift-MouseWheel>",
                        lambda e: widget.xview_scroll(int(-1 * (e.delta / 120)), "units"))
        except Exception:
            pass

    def _set_kpi(self, key: str, value: str, fg: Optional[str] = None):
        lbl = self._kpis.get(key)
        if lbl is None:
            return
        var = getattr(lbl, "_var", None)
        if var is not None:
            var.set(value)
        else:
            lbl.configure(text=value)
        if fg is not None:
            lbl.configure(fg=fg)

    def update_view(self) -> None:
        try:
            s = self._state_provider() or {}
        except Exception:
            s = {}
        packets = int(s.get("total_packets", 0) or 0)
        bytes_ = int(s.get("total_bytes", 0) or 0)
        alerts = int(s.get("total_alerts", 0) or 0)
        pps = float(s.get("packets_per_second", 0.0) or 0.0)
        uptime_s = float(s.get("uptime_seconds", 0.0) or 0.0)
        self._set_kpi("packets", f"{packets:,}")
        self._set_kpi("bytes", humanize_bytes(bytes_))
        self._set_kpi("pps", f"{pps:,.1f}")
        self._set_kpi("alerts", f"{alerts:,}",
                      fg=COLORS["danger"] if alerts > 0 else None)
        self._set_kpi("uptime", format_hms(uptime_s))

        self._update_badge("capture", f"Capture: {s.get('capture_state', 'IDLE')}",
                           s.get("capture_state", "IDLE"))
        self._update_badge("ids", f"IDS: {'ON' if s.get('ids_enabled') else 'OFF'}",
                           "OK" if s.get("ids_enabled") else "IDLE")

        for k, v in [
            ("capture_state", s.get("capture_state", "IDLE")),
            ("selected_iface", s.get("selected_iface_label", "—")),
            ("scapy", "Available" if s.get("scapy_available") else "Unavailable (demo only)"),
            ("demo_mode", "Active" if s.get("demo_active") else "Inactive"),
            ("last_packet", s.get("last_packet_time", "—") or "—"),
        ]:
            w = self._status_widgets.get(k)
            if w:
                w.configure(text=str(v))

        iface = s.get("selected_iface")
        if iface is None:
            for k in ("name", "description", "ipv4", "ipv6", "mac"):
                self._iface_widgets[k].configure(text="—")
        else:
            self._iface_widgets["name"].configure(text=getattr(iface, "name", "—") or "—")
            self._iface_widgets["description"].configure(
                text=getattr(iface, "description", "") or getattr(iface, "friendly_name", "—") or "—")
            self._iface_widgets["ipv4"].configure(text=getattr(iface, "ipv4", "—") or "—")
            self._iface_widgets["ipv6"].configure(text=getattr(iface, "ipv6", "—") or "—")
            self._iface_widgets["mac"].configure(text=getattr(iface, "mac", "—") or "—")

        self._populate_protocol(s.get("protocol_counts", None), packets)
        self._populate_ip_list("top_src", s.get("top_source_ips", []), packets)
        self._populate_ip_list("top_dst", s.get("top_destination_ips", []), packets)

    def _populate_protocol(self, counts, total_packets: int) -> None:
        tree = self._list_trees.get("protocol")
        if tree is None:
            return
        items = []
        if counts is not None:
            try:
                for name, value in counts.items():
                    if isinstance(value, int) and value > 0:
                        items.append((name, value))
            except Exception:
                items = []
        items.sort(key=lambda x: -x[1])
        for r in tree.get_children():
            tree.delete(r)
        for name, value in items:
            pct = f"{(value / total_packets * 100):.1f}%" if total_packets else "0.0%"
            tag = str(name)
            tree.tag_configure(tag, foreground=protocol_color(name))
            tree.insert("", "end", values=(name, f"{value:,}", pct), tags=(tag,))

    def _populate_ip_list(self, tree_key: str, rows, total_packets: int) -> None:
        tree = self._list_trees.get(tree_key)
        if tree is None:
            return
        for r in tree.get_children():
            tree.delete(r)
        for ip, count in rows or []:
            pct = f"{(count / total_packets * 100):.1f}%" if total_packets else "0.0%"
            tree.insert("", "end", values=(ip, f"{count:,}", pct))
