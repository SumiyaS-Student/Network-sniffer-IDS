"""
Packet details panel with decoded / raw / hex / ASCII views.
"""

import tkinter as tk
from tkinter import ttk
from typing import Optional

from app.gui.theme import (
    COLORS, BASE_FONT, BASE_FONT_BOLD, SMALL_FONT, H2_FONT, H3_FONT, MONO_FONT,
)
from app.analysis.packet_parser import ParsedPacket


class PacketDetailsView(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg=COLORS["bg"])
        self._current: Optional[ParsedPacket] = None
        self._build()

    def _build(self):
        container = tk.Frame(self, bg=COLORS["bg"])
        container.pack(fill="both", expand=True, padx=20, pady=18)
        header = tk.Frame(container, bg=COLORS["bg"])
        header.pack(fill="x")
        tk.Label(header, text="Packet Details", bg=COLORS["bg"], fg=COLORS["text"],
                 font=H2_FONT).pack(side="left")
        self._title = tk.Label(header, text="No packet selected.",
                               bg=COLORS["bg"], fg=COLORS["text_secondary"],
                               font=BASE_FONT)
        self._title.pack(side="left", padx=(18, 0))

        body = tk.Frame(container, bg=COLORS["bg"])
        body.pack(fill="both", expand=True, pady=(14, 0))
        paned = tk.PanedWindow(body, orient="horizontal", sashrelief="flat",
                               sashwidth=4, bg=COLORS["bg"], opaqueresize=False)
        paned.pack(fill="both", expand=True)

        left_card = tk.Frame(paned, bg=COLORS["panel"],
                             highlightbackground=COLORS["border"], highlightthickness=1)
        paned.add(left_card, minsize=320, width=420)
        inner_l = tk.Frame(left_card, bg=COLORS["panel"])
        inner_l.pack(fill="both", expand=True, padx=16, pady=14)
        tk.Label(inner_l, text="Summary", bg=COLORS["panel"], fg=COLORS["text"],
                 font=H3_FONT).pack(anchor="w")
        self._summary_vars = {}
        fields = [
            ("num", "Packet #"), ("time", "Timestamp"), ("iface", "Interface"),
            ("src", "Source"), ("dst", "Destination"),
            ("proto", "Protocol"), ("len", "Length"), ("ttl", "TTL"),
            ("flags", "TCP Flags"), ("status", "Status"),
        ]
        form = tk.Frame(inner_l, bg=COLORS["panel"])
        form.pack(fill="x", pady=(10, 0))
        for i, (key, label) in enumerate(fields):
            row = tk.Frame(form, bg=COLORS["panel"])
            row.pack(fill="x", pady=(2 if i else 0, 3))
            tk.Label(row, text=f"{label}:", width=14, anchor="w",
                     bg=COLORS["panel"], fg=COLORS["text_secondary"],
                     font=BASE_FONT).pack(side="left")
            var = tk.StringVar(value="—")
            lbl = tk.Label(row, textvariable=var, bg=COLORS["panel"],
                           fg=COLORS["text"], font=BASE_FONT, anchor="w",
                           justify="left")
            lbl.pack(side="left", fill="x", expand=True)
            self._summary_vars[key] = var

        tk.Label(inner_l, text="Protocol Layers", bg=COLORS["panel"],
                 fg=COLORS["text"], font=H3_FONT).pack(anchor="w", pady=(14, 6))
        self._layers_var = tk.StringVar(value="—")
        layers_lbl = tk.Label(inner_l, textvariable=self._layers_var,
                              bg=COLORS["panel"], fg=COLORS["text"],
                              font=BASE_FONT, justify="left", anchor="w",
                              wraplength=380)
        layers_lbl.pack(fill="x")

        tk.Label(inner_l, text="Checksums", bg=COLORS["panel"],
                 fg=COLORS["text"], font=H3_FONT).pack(anchor="w", pady=(14, 6))
        self._checksums_var = tk.StringVar(value="—")
        tk.Label(inner_l, textvariable=self._checksums_var, bg=COLORS["panel"],
                 fg=COLORS["text"], font=BASE_FONT, anchor="w",
                 justify="left").pack(fill="x")

        right_card = tk.Frame(paned, bg=COLORS["panel"],
                              highlightbackground=COLORS["border"], highlightthickness=1)
        paned.add(right_card, minsize=360, width=520)
        inner_r = tk.Frame(right_card, bg=COLORS["panel"])
        inner_r.pack(fill="both", expand=True, padx=16, pady=14)
        tabs_row = tk.Frame(inner_r, bg=COLORS["panel"])
        tabs_row.pack(fill="x")
        self._mode = tk.StringVar(value="decoded")
        modes = [("Decoded", "decoded"), ("Raw", "raw"),
                 ("Hex", "hex"), ("ASCII", "ascii")]
        for i, (label, value) in enumerate(modes):
            tk.Radiobutton(
                tabs_row, text=label, value=value, variable=self._mode,
                bg=COLORS["panel"], fg=COLORS["text"], activebackground=COLORS["panel"],
                selectcolor=COLORS["primary_surface"], indicatoron=False,
                relief="flat", font=BASE_FONT_BOLD, bd=0, padx=14, pady=7,
                command=self._refresh_view,
            ).pack(side="left", padx=(0 if i else 0, 6))

        tk.Frame(inner_r, bg=COLORS["divider"], height=1).pack(fill="x", pady=(10, 8))
        text_frame = tk.Frame(inner_r, bg=COLORS["bg"])
        text_frame.pack(fill="both", expand=True)
        self._text = tk.Text(
            text_frame, font=MONO_FONT, wrap="none",
            bg=COLORS["panel"], fg=COLORS["text"],
            insertbackground=COLORS["primary"], relief="flat", bd=0,
            highlightthickness=1,
            highlightbackground=COLORS["border"],
            highlightcolor=COLORS["input_focus"],
            padx=12, pady=10, state="disabled",
        )
        vsb = ttk.Scrollbar(text_frame, orient="vertical", command=self._text.yview)
        hsb = ttk.Scrollbar(text_frame, orient="horizontal", command=self._text.xview)
        self._text.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self._text.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        hsb.pack(side="bottom", fill="x", pady=(6, 0))

    def set_packet(self, parsed: Optional[ParsedPacket]) -> None:
        self._current = parsed
        self._sync_labels()
        self._refresh_view()

    def _sync_labels(self) -> None:
        p = self._current
        if p is None:
            self._title.configure(text="No packet selected.")
            for v in self._summary_vars.values():
                v.set("—")
            self._layers_var.set("—")
            self._checksums_var.set("—")
            return
        self._title.configure(
            text=f"Packet #{p.packet_number} · {p.protocol}"
                 + (" · DEMO DATA" if p.is_demo else ""))
        vals = {
            "num": str(p.packet_number),
            "time": p.timestamp_str or "—",
            "iface": p.interface or "—",
            "src": f"{p.source_ip or '—'}"
                   + (f":{p.source_port}" if p.source_port else ""),
            "dst": f"{p.destination_ip or '—'}"
                   + (f":{p.destination_port}" if p.destination_port else ""),
            "proto": p.protocol + ("  (port-based inference)" if p.protocol_inferred else ""),
            "len": f"{p.length} bytes",
            "ttl": str(p.ttl) if p.ttl else "—",
            "flags": p.tcp_flags or "—",
            "status": ("DEMO DATA" if p.is_demo else p.status) or "OK",
        }
        for k, v in vals.items():
            self._summary_vars[k].set(v)
        self._layers_var.set(" / ".join(p.layers) if p.layers else "—")
        if p.checksums:
            self._checksums_var.set(
                ", ".join(f"{k}={v}" for k, v in p.checksums.items()))
        else:
            self._checksums_var.set("—")

    def _set_text(self, content: str) -> None:
        self._text.configure(state="normal")
        self._text.delete("1.0", "end")
        self._text.insert("1.0", content or "")
        self._text.configure(state="disabled")

    def _refresh_view(self) -> None:
        p = self._current
        mode = self._mode.get()
        if p is None:
            self._set_text(
                "Select a packet from the Live Capture table to view its details.\n\n"
                "Use the options above to switch between Decoded, Raw, Hex and ASCII views."
            )
            return
        try:
            if mode == "decoded":
                self._set_text(p.decoded_view())
            elif mode == "hex":
                self._set_text(p.hex_view())
            elif mode == "ascii":
                self._set_text(p.ascii_view())
            elif mode == "raw":
                data = p.raw_bytes or b""
                preview = data[:4096]
                parts = [
                    f"Raw bytes length: {len(data)} bytes",
                    f"First 4096 bytes repr:\n\n{repr(preview)}",
                ]
                self._set_text("\n".join(parts))
            else:
                self._set_text(p.decoded_view())
        except Exception as e:
            self._set_text(f"Error rendering view: {e}")
