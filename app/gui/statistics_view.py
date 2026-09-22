"""
Statistics view with protocol counts, IP rankings, and matplotlib charts.
"""

import tkinter as tk
from tkinter import ttk
from typing import Any, Callable, Dict, List, Optional

from app.gui.theme import (
    COLORS, BASE_FONT, BASE_FONT_BOLD, SMALL_FONT, H2_FONT, H3_FONT,
    protocol_color,
)
from app.utils.time_utils import humanize_bytes


class StatisticsView(tk.Frame):
    def __init__(self, master, state_provider: Callable[[], Dict[str, Any]]):
        super().__init__(master, bg=COLORS["bg"])
        self._state = state_provider
        self._mpl_available = False
        self._mpl_fig = None
        self._mpl_canvas = None
        self._try_init_mpl()
        self._build()

    def _try_init_mpl(self) -> None:
        try:
            import matplotlib
            matplotlib.use("TkAgg")
            from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg  # noqa: F401
            from matplotlib.figure import Figure  # noqa: F401
            self._mpl_available = True
        except Exception:
            self._mpl_available = False

    def _build(self):
        container = tk.Frame(self, bg=COLORS["bg"])
        container.pack(fill="both", expand=True, padx=20, pady=18)

        header = tk.Frame(container, bg=COLORS["bg"])
        header.pack(fill="x")
        tk.Label(header, text="Statistics & Visualization", bg=COLORS["bg"],
                 fg=COLORS["text"], font=H2_FONT).pack(side="left")

        kpis = tk.Frame(container, bg=COLORS["bg"])
        kpis.pack(fill="x", pady=(14, 14))
        self._kpi_vars: Dict[str, tk.StringVar] = {}
        cards = [
            ("Total Packets", "packets", COLORS["primary"]),
            ("Total Traffic", "bytes", COLORS["success"]),
            ("Packets / sec", "pps", COLORS["info"]),
            ("Bytes / sec", "bps", "#6A4CB8"),
            ("Demo packets", "demo", COLORS["warning"]),
        ]
        for label, key, accent in cards:
            card = tk.Frame(kpis, bg=COLORS["panel"],
                            highlightbackground=COLORS["border"], highlightthickness=1)
            card.pack(side="left", fill="both", expand=True, padx=(0, 12))
            top = tk.Frame(card, bg=COLORS["panel"])
            top.pack(fill="x", padx=14, pady=(12, 2))
            tk.Frame(top, bg=accent, height=4, width=40).pack(side="left")
            tk.Label(top, text=label, bg=COLORS["panel"],
                     fg=COLORS["text_secondary"], font=SMALL_FONT).pack(side="left", padx=(10, 0))
            var = tk.StringVar(value="—")
            tk.Label(card, textvariable=var, bg=COLORS["panel"],
                     fg=COLORS["text"], font=("Segoe UI Semibold", 18)).pack(
                fill="x", padx=14, pady=(2, 10), anchor="w")
            self._kpi_vars[key] = var

        body = tk.PanedWindow(container, orient="vertical", sashrelief="flat",
                              sashwidth=4, bg=COLORS["bg"], opaqueresize=False)
        body.pack(fill="both", expand=True)

        top_row = tk.PanedWindow(body, orient="horizontal", sashrelief="flat",
                                 sashwidth=4, bg=COLORS["bg"], opaqueresize=False)
        body.add(top_row, minsize=260, height=340)

        proto_card = self._protocol_card(top_row)
        top_row.add(proto_card, minsize=320, width=480)

        rate_card = self._rate_card(top_row)
        top_row.add(rate_card, minsize=320, width=480)

        bottom_row = tk.PanedWindow(body, orient="horizontal", sashrelief="flat",
                                    sashwidth=4, bg=COLORS["bg"], opaqueresize=False)
        body.add(bottom_row, minsize=260, height=340)

        src_card = self._top_card(bottom_row, "Top Source IPs", "top_src")
        bottom_row.add(src_card, minsize=300, width=420)
        dst_card = self._top_card(bottom_row, "Top Destination IPs", "top_dst")
        bottom_row.add(dst_card, minsize=300, width=420)
        ports_card = self._top_card(bottom_row, "Top Destination Ports", "top_dports")
        bottom_row.add(ports_card, minsize=260, width=360)

    def _protocol_card(self, parent):
        card = tk.Frame(parent, bg=COLORS["panel"],
                        highlightbackground=COLORS["border"], highlightthickness=1)
        inner = tk.Frame(card, bg=COLORS["panel"])
        inner.pack(fill="both", expand=True, padx=14, pady=14)
        tk.Label(inner, text="Protocol Distribution", bg=COLORS["panel"],
                 fg=COLORS["text"], font=H3_FONT).pack(anchor="w")
        if self._mpl_available:
            from matplotlib.figure import Figure
            from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
            fig = Figure(figsize=(4.5, 3.2), dpi=100, facecolor=COLORS["panel"])
            self._ax_pie = fig.add_subplot(111)
            self._mpl_fig = fig
            fig.subplots_adjust(left=0.02, right=0.98, top=0.92, bottom=0.05)
            canvas = FigureCanvasTkAgg(fig, master=inner)
            canvas.get_tk_widget().pack(fill="both", expand=True, pady=(8, 0))
            self._mpl_canvas_pie = canvas
            self._draw_empty_pie()
        else:
            self._protocol_list = tk.Listbox(inner, font=BASE_FONT,
                                             relief="flat", bd=0,
                                             bg=COLORS["panel"], fg=COLORS["text"],
                                             highlightthickness=1,
                                             highlightbackground=COLORS["border"])
            self._protocol_list.pack(fill="both", expand=True, pady=(8, 0))
        return card

    def _draw_empty_pie(self) -> None:
        if not self._mpl_available:
            return
        ax = getattr(self, "_ax_pie", None)
        if ax is None:
            return
        ax.clear()
        ax.set_facecolor(COLORS["panel"])
        ax.pie([1], labels=["No data"], colors=[COLORS["text_muted"]],
               startangle=90, textprops={"color": COLORS["text_secondary"], "fontsize": 10})
        ax.set_title("Protocol Distribution", color=COLORS["text_secondary"], fontsize=11)
        self._mpl_canvas_pie.draw_idle()

    def _rate_card(self, parent):
        card = tk.Frame(parent, bg=COLORS["panel"],
                        highlightbackground=COLORS["border"], highlightthickness=1)
        inner = tk.Frame(card, bg=COLORS["panel"])
        inner.pack(fill="both", expand=True, padx=14, pady=14)
        tk.Label(inner, text="Packet Rate Over Time", bg=COLORS["panel"],
                 fg=COLORS["text"], font=H3_FONT).pack(anchor="w")
        if self._mpl_available:
            from matplotlib.figure import Figure
            from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
            fig = Figure(figsize=(4.5, 3.2), dpi=100, facecolor=COLORS["panel"])
            self._ax_rate = fig.add_subplot(111)
            if self._mpl_fig is None:
                self._mpl_fig = fig
            fig.subplots_adjust(left=0.1, right=0.97, top=0.92, bottom=0.15)
            canvas = FigureCanvasTkAgg(fig, master=inner)
            canvas.get_tk_widget().pack(fill="both", expand=True, pady=(8, 0))
            self._mpl_canvas_rate = canvas
            self._draw_empty_rate()
        else:
            self._rate_text = tk.Text(inner, font=BASE_FONT, relief="flat", bd=0,
                                      bg=COLORS["panel"], fg=COLORS["text_secondary"],
                                      state="disabled", height=10, wrap="word")
            self._rate_text.pack(fill="both", expand=True, pady=(8, 0))
        return card

    def _draw_empty_rate(self) -> None:
        if not self._mpl_available:
            return
        ax = getattr(self, "_ax_rate", None)
        if ax is None:
            return
        ax.clear()
        ax.set_facecolor(COLORS["panel"])
        ax.plot([], [], color=COLORS["primary"])
        ax.set_title("Packets / sec", color=COLORS["text_secondary"], fontsize=11)
        for spine in ax.spines.values():
            spine.set_color(COLORS["border"])
        ax.tick_params(colors=COLORS["text_secondary"])
        self._mpl_canvas_rate.draw_idle()

    def _top_card(self, parent, title: str, key: str):
        card = tk.Frame(parent, bg=COLORS["panel"],
                        highlightbackground=COLORS["border"], highlightthickness=1)
        inner = tk.Frame(card, bg=COLORS["panel"])
        inner.pack(fill="both", expand=True, padx=14, pady=14)
        tk.Label(inner, text=title, bg=COLORS["panel"], fg=COLORS["text"],
                 font=H3_FONT).pack(anchor="w")
        tree_frame = tk.Frame(inner, bg=COLORS["panel"])
        tree_frame.pack(fill="both", expand=True, pady=(8, 0))
        style = ttk.Style(self)
        style.configure(f"Top{key}.Treeview",
                        background=COLORS["panel"], foreground=COLORS["text"],
                        fieldbackground=COLORS["panel"], rowheight=22,
                        font=BASE_FONT, borderwidth=0)
        style.map(f"Top{key}.Treeview",
                  background=[("selected", COLORS["primary_surface"])])
        style.configure(f"Top{key}.Treeview.Heading",
                        background=COLORS["table_header_bg"], foreground=COLORS["text"],
                        font=BASE_FONT_BOLD, borderwidth=0)
        cols = ("item", "count")
        tree = ttk.Treeview(tree_frame, columns=cols, show="headings",
                            style=f"Top{key}.Treeview", height=10)
        tree.heading("item", text="Item")
        tree.heading("count", text="Packets")
        tree.column("item", width=180, anchor="w")
        tree.column("count", width=80, anchor="e")
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=vsb.set)
        tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        self._top_trees = getattr(self, "_top_trees", {})
        self._top_trees[key] = tree
        return card

    def _set_kpi(self, key: str, value: str) -> None:
        var = self._kpi_vars.get(key)
        if var is not None:
            var.set(value)

    def update_view(self, force: bool = False) -> None:
        state = self._state() or {}
        packets = int(state.get("total_packets", 0) or 0)
        bytes_total = int(state.get("total_bytes", 0) or 0)
        pps = float(state.get("packets_per_second", 0.0) or 0.0)
        bps = float(state.get("bytes_per_second", 0.0) or 0.0)
        demo = int(state.get("demo_packets", 0) or 0)
        self._set_kpi("packets", f"{packets:,}")
        self._set_kpi("bytes", humanize_bytes(bytes_total))
        self._set_kpi("pps", f"{pps:,.1f}")
        self._set_kpi("bps", humanize_bytes(bps) + "/s")
        self._set_kpi("demo", f"{demo:,}")

        counts = state.get("protocol_counts")
        total = packets
        self._update_protocol_chart(counts, total)
        self._update_rate_chart(state.get("rate_history", []))
        self._update_top_tree("top_src", state.get("top_source_ips", []))
        self._update_top_tree("top_dst", state.get("top_destination_ips", []))
        self._update_top_tree("top_dports", state.get("top_destination_ports", []))

    def _update_protocol_chart(self, counts, total: int) -> None:
        if self._mpl_available:
            ax = getattr(self, "_ax_pie", None)
            if ax is None:
                return
            labels = []
            values = []
            colors_list = []
            data_items = []
            if counts is not None:
                try:
                    items = list(counts.items())
                except Exception:
                    items = []
                for name, val in items:
                    try:
                        val_int = int(val)
                    except (TypeError, ValueError):
                        continue
                    if val_int > 0:
                        data_items.append((name, val_int))
            data_items.sort(key=lambda x: -x[1])
            for name, val in data_items:
                labels.append(name)
                values.append(val)
                colors_list.append(protocol_color(name))
            ax.clear()
            ax.set_facecolor(COLORS["panel"])
            if labels and values:
                ax.pie(values, labels=labels, colors=colors_list,
                       autopct=lambda pct: f"{pct:.0f}%" if pct > 3 else "",
                       startangle=90,
                       textprops={"color": COLORS["text"], "fontsize": 9})
            else:
                ax.pie([1], labels=["No data"], colors=[COLORS["text_muted"]],
                       startangle=90,
                       textprops={"color": COLORS["text_secondary"], "fontsize": 10})
            ax.set_title("Protocol Distribution", color=COLORS["text"], fontsize=11, pad=8)
            self._mpl_canvas_pie.draw_idle()
        else:
            lb = getattr(self, "_protocol_list", None)
            if lb is None:
                return
            lb.configure(state="normal")
            lb.delete(0, "end")
            items = []
            if counts is not None:
                try:
                    items = list(counts.items())
                except Exception:
                    items = []
                items = [(n, int(v)) for n, v in items if int(v) > 0]
                items.sort(key=lambda x: -x[1])
            for n, v in items:
                pct = (v / total * 100) if total else 0
                lb.insert("end", f"{n:<10}  {v:>8,}  ({pct:5.1f}%)")
            lb.configure(state="disabled")

    def _update_rate_chart(self, samples) -> None:
        if not self._mpl_available:
            txt = getattr(self, "_rate_text", None)
            if txt is None:
                return
            lines = []
            for s in samples[-20:]:
                ts = getattr(s, "timestamp", 0)
                pkts = getattr(s, "packets", 0)
                lines.append(f"t={ts:.0f}  packets={pkts}")
            txt.configure(state="normal")
            txt.delete("1.0", "end")
            if lines:
                txt.insert("1.0", "\n".join(lines))
            else:
                txt.insert("1.0", "No rate samples yet.")
            txt.configure(state="disabled")
            return
        ax = getattr(self, "_ax_rate", None)
        if ax is None:
            return
        x = []
        y = []
        try:
            sample_list = list(samples or [])
        except Exception:
            sample_list = []
        for s in sample_list:
            try:
                ts = float(getattr(s, "timestamp", 0))
                pkts = float(getattr(s, "packets", 0))
            except Exception:
                continue
            x.append(ts)
            y.append(pkts)
        ax.clear()
        ax.set_facecolor(COLORS["panel"])
        if x and y:
            ax.plot(x, y, color=COLORS["primary"], linewidth=1.8, marker="", alpha=0.9)
            ax.fill_between(x, y, 0, color=COLORS["primary_surface"], alpha=0.4)
        for spine in ax.spines.values():
            spine.set_color(COLORS["border"])
        ax.tick_params(colors=COLORS["text_secondary"], labelsize=8)
        ax.set_title("Packets / sec (rolling samples)",
                     color=COLORS["text"], fontsize=11, pad=8)
        ax.set_xlabel("Time (epoch)", color=COLORS["text_secondary"])
        ax.set_ylabel("Packets", color=COLORS["text_secondary"])
        try:
            self._mpl_canvas_rate.draw_idle()
        except Exception:
            pass

    def _update_top_tree(self, key: str, items) -> None:
        tree = self._top_trees.get(key)
        if tree is None:
            return
        for r in tree.get_children():
            tree.delete(r)
        for item, count in items or []:
            tree.insert("", "end", values=(item, f"{count:,}"))
