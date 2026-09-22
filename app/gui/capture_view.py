"""
Live packet capture view with toolbar, interface selection, filters, table.
"""

import tkinter as tk
from tkinter import ttk, messagebox
from typing import Any, Callable, Dict, List, Optional, Set

from app.gui.theme import (
    COLORS, BASE_FONT, BASE_FONT_BOLD, SMALL_FONT, H2_FONT, H3_FONT,
    MONO_FONT, status_colors, protocol_color,
)
from app.capture.interface_manager import NetworkInterface
from app.analysis.packet_parser import ParsedPacket
from app.analysis import KNOWN_PROTOCOLS


TABLE_COLUMNS = (
    "num", "time", "src", "dst", "proto", "sport", "dport", "length", "iface", "status",
)
TABLE_HEADERS = (
    "#", "Time", "Source IP", "Destination IP", "Protocol",
    "Src Port", "Dst Port", "Length", "Interface", "Status",
)
TABLE_WIDTHS = (60, 140, 140, 140, 90, 80, 80, 80, 150, 80)


class CaptureView(tk.Frame):
    def __init__(self, master,
                 interface_provider: Callable[[], List[NetworkInterface]],
                 refresh_interfaces: Callable[[], None],
                 select_interface: Callable[[str], Optional[NetworkInterface]],
                 selected_provider: Callable[[], Optional[NetworkInterface]],
                 actions: Dict[str, Callable],
                 auth_required: Callable[[Callable], Callable]):
        super().__init__(master, bg=COLORS["bg"])
        self._iface_provider = interface_provider
        self._refresh_ifaces = refresh_interfaces
        self._select_iface = select_interface
        self._selected_provider = selected_provider
        self._actions = actions
        self._auth_wrap = auth_required
        self._search_var = tk.StringVar(value="")
        self._filter_vars: Dict[str, tk.BooleanVar] = {}
        self._row_to_parsed: Dict[str, ParsedPacket] = {}
        self._all_rows: List[ParsedPacket] = []
        self._last_inserted = 0
        self._display_limit = 5000
        self._selected_packet_number: Optional[int] = None
        self._on_row_select: Optional[Callable[[Optional[ParsedPacket]], None]] = None
        self._build()

    def set_display_limit(self, limit: int) -> None:
        self._display_limit = max(100, int(limit))

    def set_on_row_select(self, cb: Callable[[Optional[ParsedPacket]], None]) -> None:
        self._on_row_select = cb

    def _button(self, parent, label: str, action_key: str, *, bg=None, fg=None,
                primary=False, auth=True):
        if primary:
            bg = bg or COLORS["primary"]
            fg = fg or "#FFFFFF"
            abg = COLORS["primary_hover"]
            afg = "#FFFFFF"
            font = BASE_FONT_BOLD
        else:
            bg = bg or COLORS["panel"]
            fg = fg or COLORS["text"]
            abg = COLORS["surface"]
            afg = COLORS["text"]
            font = BASE_FONT
        btn = tk.Button(
            parent, text=label, font=font, bg=bg, fg=fg,
            activebackground=abg, activeforeground=afg,
            relief="flat", padx=14, pady=7, cursor="hand2",
            command=self._wrap_click(action_key, auth),
            highlightbackground=COLORS["border"], highlightthickness=1,
            bd=0,
        )
        return btn

    def _wrap_click(self, action_key: str, auth: bool):
        def _cb():
            fn = self._actions.get(action_key)
            if fn is None:
                return
            if auth:
                wrapped = self._auth_wrap(fn)
                wrapped()
            else:
                fn()
        return _cb

    def _build(self):
        container = tk.Frame(self, bg=COLORS["bg"])
        container.pack(fill="both", expand=True, padx=20, pady=18)

        toolbar = tk.Frame(container, bg=COLORS["panel"],
                           highlightbackground=COLORS["border"], highlightthickness=1)
        toolbar.pack(fill="x")
        self._build_toolbar(toolbar)

        actions_row = tk.Frame(container, bg=COLORS["panel"],
                               highlightbackground=COLORS["border"], highlightthickness=1)
        actions_row.pack(fill="x", pady=(10, 0))
        self._build_actions_bar(actions_row)

        filter_row = tk.Frame(container, bg=COLORS["panel"],
                              highlightbackground=COLORS["border"], highlightthickness=1)
        filter_row.pack(fill="x", pady=(12, 12))
        self._build_filters(filter_row)

        body = tk.Frame(container, bg=COLORS["bg"])
        body.pack(fill="both", expand=True)
        self._build_table(body)

        footer = tk.Frame(container, bg=COLORS["bg"])
        footer.pack(fill="x", pady=(8, 0))
        self._counter_lbl = tk.Label(
            footer, text="Displayed: 0    Total processed: 0    Queue: 0",
            bg=COLORS["bg"], fg=COLORS["text"], font=BASE_FONT,
        )
        self._counter_lbl.pack(side="left")
        self._capture_badge = tk.Label(
            footer, text="Capture: IDLE",
            bg=status_colors("IDLE")[1], fg=status_colors("IDLE")[0],
            font=BASE_FONT_BOLD, padx=12, pady=4,
        )
        self._capture_badge.pack(side="right")

    def _build_toolbar(self, parent):
        left = tk.Frame(parent, bg=COLORS["panel"])
        left.pack(side="left", padx=14, pady=10)
        tk.Label(left, text="Interface:", bg=COLORS["panel"], fg=COLORS["text"],
                 font=BASE_FONT).pack(side="left")
        self._iface_var = tk.StringVar()
        self._iface_combo = ttk.Combobox(
            left, textvariable=self._iface_var, state="readonly", width=60,
            font=BASE_FONT,
        )
        self._iface_combo.pack(side="left", padx=(8, 6))
        self._iface_combo.bind("<<ComboboxSelected>>", self._on_iface_selected)
        tk.Button(
            left, text="Refresh", font=BASE_FONT, bg=COLORS["surface"],
            fg=COLORS["text"], activebackground=COLORS["border"], relief="flat",
            padx=12, pady=6, cursor="hand2",
            highlightbackground=COLORS["border"], highlightthickness=1, bd=0,
            command=self.refresh_interfaces_ui,
        ).pack(side="left")
        self._displayed_badge = tk.Label(
            left, text="Displayed: 0", bg=COLORS["primary_surface"],
            fg=COLORS["primary"], font=BASE_FONT_BOLD, padx=12, pady=6,
        )
        self._displayed_badge.pack(side="left", padx=(12, 0))

    def _build_actions_bar(self, parent):
        left = tk.Frame(parent, bg=COLORS["panel"])
        left.pack(side="left", padx=14, pady=10)
        self._button(left, "START", "start_capture", primary=True).pack(side="left", padx=6)
        self._button(left, "PAUSE", "pause_capture").pack(side="left", padx=6)
        self._button(left, "RESUME", "resume_capture").pack(side="left", padx=6)
        self._button(left, "STOP", "stop_capture",
                     bg=COLORS["danger_surface"], fg=COLORS["danger"]).pack(side="left", padx=6)
        self._button(left, "CLEAR", "clear_display",
                     bg=COLORS["panel"], fg=COLORS["text_secondary"]).pack(side="left", padx=6)

    def _build_filters(self, parent):
        top = tk.Frame(parent, bg=COLORS["panel"])
        top.pack(fill="x", padx=14, pady=(12, 6))
        tk.Label(top, text="Protocol Display Filters", bg=COLORS["panel"],
                 fg=COLORS["text"], font=H3_FONT).pack(side="left")
        tk.Label(top, text="These affect the displayed packet list only (not capture).",
                 bg=COLORS["panel"], fg=COLORS["text_muted"],
                 font=SMALL_FONT).pack(side="right")
        prots_wrap = tk.Frame(parent, bg=COLORS["panel"])
        prots_wrap.pack(fill="x", padx=12, pady=(0, 6))
        prots_canvas = tk.Canvas(prots_wrap, bg=COLORS["panel"],
                                 highlightthickness=0, bd=0, height=38)
        prots_hsb = ttk.Scrollbar(prots_wrap, orient="horizontal",
                                  command=prots_canvas.xview)
        prots = tk.Frame(prots_canvas, bg=COLORS["panel"])
        prots_win = prots_canvas.create_window((0, 0), window=prots, anchor="nw")
        prots.bind("<Configure>",
                   lambda _e: prots_canvas.configure(scrollregion=prots_canvas.bbox("all")))
        prots_canvas.configure(xscrollcommand=prots_hsb.set)
        prots_canvas.pack(side="left", fill="x", expand=True)
        prots_hsb.pack(side="bottom", fill="x")
        try:
            prots_canvas.bind("<Shift-MouseWheel>",
                              lambda e: prots_canvas.xview_scroll(
                                  int(-1 * (e.delta / 120)), "units"))
        except Exception:
            pass
        all_var = tk.BooleanVar(value=True)
        self._filter_vars["ALL"] = all_var
        tk.Checkbutton(
            prots, text="ALL", variable=all_var, bg=COLORS["panel"],
            fg=COLORS["text"], selectcolor=COLORS["panel"], font=BASE_FONT,
            activebackground=COLORS["panel"],
            command=lambda: self._toggle_all(all_var.get()),
        ).pack(side="left", padx=6, pady=4)
        for p in KNOWN_PROTOCOLS:
            if p == "Other":
                continue
            v = tk.BooleanVar(value=True)
            self._filter_vars[p] = v
            tk.Checkbutton(
                prots, text=p, variable=v, bg=COLORS["panel"],
                fg=protocol_color(p), selectcolor=COLORS["panel"],
                font=BASE_FONT, activebackground=COLORS["panel"],
                command=self._sync_all_var,
            ).pack(side="left", padx=6, pady=4)
        other_var = tk.BooleanVar(value=True)
        self._filter_vars["Other"] = other_var
        tk.Checkbutton(
            prots, text="Other", variable=other_var, bg=COLORS["panel"],
            fg=protocol_color("Other"), selectcolor=COLORS["panel"],
            font=BASE_FONT, activebackground=COLORS["panel"],
            command=self._sync_all_var,
        ).pack(side="left", padx=6, pady=4)

        bottom = tk.Frame(parent, bg=COLORS["panel"])
        bottom.pack(fill="x", padx=14, pady=(0, 12))
        tk.Label(bottom, text="Search:", bg=COLORS["panel"], fg=COLORS["text"],
                 font=BASE_FONT).pack(side="left")
        entry = tk.Entry(
            bottom, textvariable=self._search_var, font=BASE_FONT, relief="flat",
            bg=COLORS["input_bg"], fg=COLORS["text"],
            highlightthickness=1,
            highlightbackground=COLORS["input_border"],
            highlightcolor=COLORS["input_focus"],
            insertbackground=COLORS["primary"], bd=0, width=40,
        )
        entry.pack(side="left", padx=(8, 8))
        entry.bind("<KeyRelease>", lambda _e: self._apply_search())
        tk.Label(bottom, text="(match time / source / dest / protocol / ports / interface)",
                 bg=COLORS["panel"], fg=COLORS["text_muted"],
                 font=SMALL_FONT).pack(side="left")
        self._search_entry = entry

    def _toggle_all(self, all_on: bool) -> None:
        for k, v in self._filter_vars.items():
            try:
                v.set(all_on)
            except Exception:
                pass
        self._sync_all_var()

    def _sync_all_var(self) -> None:
        try:
            all_on = all(
                v.get() for k, v in self._filter_vars.items() if k != "ALL"
            )
            self._filter_vars["ALL"].set(all_on)
        except Exception:
            pass

    def _build_table(self, parent):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("Capture.Treeview",
                        background=COLORS["panel"],
                        foreground=COLORS["text"],
                        fieldbackground=COLORS["panel"],
                        rowheight=24,
                        font=BASE_FONT,
                        borderwidth=0)
        style.map("Capture.Treeview",
                  background=[("selected", COLORS["primary_surface"])],
                  foreground=[("selected", COLORS["primary"])])
        style.configure("Capture.Treeview.Heading",
                        background=COLORS["table_header_bg"],
                        foreground=COLORS["text"],
                        font=BASE_FONT_BOLD,
                        borderwidth=0,
                        relief="flat")

        card = tk.Frame(parent, bg=COLORS["panel"],
                        highlightbackground=COLORS["border"], highlightthickness=1)
        card.pack(fill="both", expand=True)
        tree_frame = tk.Frame(card, bg=COLORS["panel"])
        tree_frame.pack(fill="both", expand=True, padx=12, pady=12)
        tree = ttk.Treeview(
            tree_frame, columns=TABLE_COLUMNS, show="headings",
            style="Capture.Treeview", height=20,
        )
        for col, header, width in zip(TABLE_COLUMNS, TABLE_HEADERS, TABLE_WIDTHS):
            tree.heading(col, text=header,
                         command=lambda c=col: self._sort_by(c, False))
            tree.column(col, width=width, anchor="w" if col not in ("num", "sport", "dport", "length") else "e")
        tree.tag_configure("alt", background=COLORS["table_alt"])
        tree.tag_configure("DEMO", background=COLORS["info_surface"])
        for proto in KNOWN_PROTOCOLS:
            tree.tag_configure(f"P_{proto}", foreground=protocol_color(proto))
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        hsb.pack(side="bottom", fill="x", pady=(6, 0))
        tree.bind("<<TreeviewSelect>>", self._on_tree_select)
        try:
            tree.bind("<MouseWheel>",
                      lambda e: tree.yview_scroll(int(-1 * (e.delta / 120)), "units"))
            tree.bind("<Shift-MouseWheel>",
                      lambda e: tree.xview_scroll(int(-1 * (e.delta / 120)), "units"))
        except Exception:
            pass
        self._tree = tree

    def _sort_by(self, col: str, descending: bool) -> None:
        try:
            items = [(self._tree.set(k, col), k) for k in self._tree.get_children("")]
            def _key(pair):
                val, _k = pair
                try:
                    if col in ("num", "sport", "dport", "length"):
                        return (0, int(val)) if str(val).isdigit() else (1, str(val))
                    return (1, str(val))
                except Exception:
                    return (1, str(val))
            items.sort(key=_key, reverse=descending)
            for idx, (_val, k) in enumerate(items):
                self._tree.move(k, "", idx)
            self._tree.heading(col,
                               command=lambda c=col: self._sort_by(c, not descending))
        except Exception:
            pass

    def _on_iface_selected(self, _event=None) -> None:
        label = self._iface_var.get()
        self._select_iface(label)

    def refresh_interfaces_ui(self) -> None:
        self._refresh_ifaces()
        ifaces = self._iface_provider()
        labels = [i.label for i in ifaces]
        self._iface_combo.configure(values=labels)
        current = self._selected_provider()
        if current and current.label in labels:
            self._iface_var.set(current.label)
        elif labels:
            self._iface_var.set(labels[0])
            self._select_iface(labels[0])

    def set_capture_badge(self, state: str, extra: str = "") -> None:
        text = f"Capture: {state}"
        if extra:
            text = f"{text} · {extra}"
        fg, bg = status_colors(state)
        self._capture_badge.configure(text=text, fg=fg, bg=bg)

    def set_counters(self, displayed: int, processed: int, queued: int) -> None:
        self._counter_lbl.configure(
            text=f"Displayed: {displayed:,}    Total processed: {processed:,}    Queue backlog: {queued:,}")
        try:
            limit_note = f" (limit {self._display_limit:,})" if displayed >= self._display_limit else ""
            self._displayed_badge.configure(text=f"Displayed: {displayed:,}{limit_note}")
        except Exception:
            pass

    def selected_protocol_filter(self) -> Set[str]:
        result: Set[str] = set()
        for key, var in self._filter_vars.items():
            if key == "ALL":
                continue
            if var.get():
                result.add(key)
        return result

    def search_query(self) -> str:
        return (self._search_var.get() or "").strip().lower()

    def _apply_search(self) -> None:
        try:
            self.replace_all_rows(self._all_rows)
        except Exception:
            pass

    def _matches(self, p: ParsedPacket) -> bool:
        protos = self.selected_protocol_filter()
        query = self.search_query()
        if p.protocol not in protos:
            return False
        if query:
            hay = " ".join([
                str(p.packet_number), p.timestamp_str, p.source_ip, p.destination_ip,
                p.protocol, str(p.source_port), str(p.destination_port),
                p.interface, p.status,
            ]).lower()
            if query not in hay:
                return False
        return True

    def replace_all_rows(self, parsed_rows: List[ParsedPacket]) -> None:
        self._all_rows = list(parsed_rows)
        filtered: List[ParsedPacket] = []
        for p in parsed_rows[-self._display_limit:]:
            if self._matches(p):
                filtered.append(p)
        selected_num = self._selected_packet_number
        for r in self._tree.get_children():
            self._tree.delete(r)
        self._row_to_parsed.clear()
        n = min(len(filtered), self._display_limit)
        for i, p in enumerate(filtered[-n:]):
            tags = []
            if i % 2 == 1:
                tags.append("alt")
            if p.is_demo:
                tags.append("DEMO")
            ptags = [f"P_{p.protocol}"] if p.protocol else []
            tags.extend(ptags)
            row_id = self._tree.insert("", "end", values=p.to_row(), tags=tags)
            self._row_to_parsed[row_id] = p
        if parsed_rows:
            self._last_inserted = max(
                int(getattr(p, "packet_number", 0) or 0) for p in parsed_rows)
        self.set_counters(n, len(parsed_rows), 0)
        self._restore_selection(selected_num)

    def append_rows(self, new_rows: List[ParsedPacket]) -> int:
        if not new_rows:
            return 0
        added = 0
        max_seen = self._last_inserted
        for p in new_rows:
            num = int(getattr(p, "packet_number", 0) or 0)
            if num > max_seen:
                max_seen = num
            if num <= self._last_inserted:
                continue
            self._all_rows.append(p)
            if not self._matches(p):
                continue
            children = self._tree.get_children()
            if len(children) >= self._display_limit:
                evicted = children[0]
                self._tree.delete(evicted)
                self._row_to_parsed.pop(evicted, None)
                children = self._tree.get_children()
            tags = []
            if len(children) % 2 == 1:
                tags.append("alt")
            if p.is_demo:
                tags.append("DEMO")
            if p.protocol:
                tags.append(f"P_{p.protocol}")
            row_id = self._tree.insert("", "end", values=p.to_row(), tags=tags)
            self._row_to_parsed[row_id] = p
            added += 1
        self._last_inserted = max_seen
        return added

    def displayed_count(self) -> int:
        return len(self._row_to_parsed)

    def clear_display(self) -> None:
        for r in self._tree.get_children():
            self._tree.delete(r)
        self._row_to_parsed.clear()
        self._all_rows.clear()
        self._last_inserted = 0
        self._selected_packet_number = None
        self.set_counters(0, 0, 0)

    def _restore_selection(self, packet_number: Optional[int]) -> None:
        if packet_number is None:
            return
        for row_id, p in self._row_to_parsed.items():
            if p.packet_number == packet_number:
                try:
                    self._tree.selection_set(row_id)
                    self._tree.see(row_id)
                except Exception:
                    pass
                if self._on_row_select is not None:
                    try:
                        self._on_row_select(p)
                    except Exception:
                        pass
                return

    def scroll_to_bottom(self) -> None:
        try:
            children = self._tree.get_children()
            if children:
                self._tree.see(children[-1])
        except Exception:
            pass

    def _on_tree_select(self, _event=None) -> None:
        sel = self._tree.selection()
        if not sel:
            self._selected_packet_number = None
            return
        last = sel[-1]
        parsed = self._row_to_parsed.get(last)
        if parsed is not None:
            self._selected_packet_number = parsed.packet_number
        if self._on_row_select is None:
            return
        try:
            self._on_row_select(parsed)
        except Exception:
            pass
