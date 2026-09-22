"""
Log viewer view with multi-log selection, tail and filter.
"""

import tkinter as tk
from tkinter import ttk, messagebox
from typing import Any, Callable, Dict, Optional

from app.gui.theme import (
    COLORS, BASE_FONT, BASE_FONT_BOLD, SMALL_FONT, H2_FONT, H3_FONT, MONO_FONT,
)
from app.logging.logger import (
    APP_LOG, CAPTURE_LOG, AUTH_LOG, IDS_LOG, ERROR_LOG, read_log_tail, get_log_path,
)


LOG_OPTIONS = [
    ("Application", APP_LOG),
    ("Capture", CAPTURE_LOG),
    ("Authentication", AUTH_LOG),
    ("IDS", IDS_LOG),
    ("Error", ERROR_LOG),
]


class LogsView(tk.Frame):
    def __init__(self, master, auth_wrap: Callable[[Callable], Callable]):
        super().__init__(master, bg=COLORS["bg"])
        self._auth_wrap = auth_wrap
        self._current_log = APP_LOG
        self._build()

    def _build(self):
        container = tk.Frame(self, bg=COLORS["bg"])
        container.pack(fill="both", expand=True, padx=20, pady=18)
        header = tk.Frame(container, bg=COLORS["bg"])
        header.pack(fill="x")
        tk.Label(header, text="Log Viewer", bg=COLORS["bg"],
                 fg=COLORS["text"], font=H2_FONT).pack(side="left")
        tk.Label(header, text="Authentication is required to view logs.",
                 bg=COLORS["bg"], fg=COLORS["text_muted"],
                 font=SMALL_FONT).pack(side="right")

        card = tk.Frame(container, bg=COLORS["panel"],
                        highlightbackground=COLORS["border"], highlightthickness=1)
        card.pack(fill="both", expand=True, pady=(14, 0))
        inner = tk.Frame(card, bg=COLORS["panel"])
        inner.pack(fill="both", expand=True, padx=14, pady=14)

        toolbar = tk.Frame(inner, bg=COLORS["panel"])
        toolbar.pack(fill="x")
        tk.Label(toolbar, text="Log file:", bg=COLORS["panel"], fg=COLORS["text"],
                 font=BASE_FONT).pack(side="left")
        self._log_var = tk.StringVar(value=LOG_OPTIONS[0][0])
        combo = ttk.Combobox(toolbar, textvariable=self._log_var, state="readonly",
                             values=[label for label, _ in LOG_OPTIONS],
                             font=BASE_FONT, width=18)
        combo.pack(side="left", padx=(8, 12))
        combo.bind("<<ComboboxSelected>>", lambda _e: self._switch_log())

        self._tail_lines = tk.IntVar(value=500)
        tk.Label(toolbar, text="Tail lines:", bg=COLORS["panel"], fg=COLORS["text"],
                 font=BASE_FONT).pack(side="left")
        tk.Spinbox(toolbar, from_=100, to=10000, increment=100,
                   textvariable=self._tail_lines, width=7,
                   font=BASE_FONT, command=self.refresh_logs).pack(side="left", padx=(6, 12))

        tk.Label(toolbar, text="Search:", bg=COLORS["panel"], fg=COLORS["text"],
                 font=BASE_FONT).pack(side="left")
        self._search_var = tk.StringVar(value="")
        e = tk.Entry(
            toolbar, textvariable=self._search_var, font=BASE_FONT, relief="flat",
            bg=COLORS["input_bg"], fg=COLORS["text"],
            highlightthickness=1,
            highlightbackground=COLORS["input_border"],
            highlightcolor=COLORS["input_focus"],
            insertbackground=COLORS["primary"], bd=0, width=24,
        )
        e.pack(side="left", padx=(6, 12))
        self._search_var.trace_add("write", lambda *_: self._apply_search())

        tk.Button(
            toolbar, text="Refresh", font=BASE_FONT,
            bg=COLORS["primary_surface"], fg=COLORS["primary"],
            activebackground=COLORS["info_surface"], relief="flat", bd=0,
            padx=14, pady=6, cursor="hand2",
            command=self._auth_wrap(self.refresh_logs),
            highlightbackground=COLORS["border"], highlightthickness=1,
        ).pack(side="left", padx=(0, 6))
        tk.Button(
            toolbar, text="Open File Location", font=BASE_FONT,
            bg=COLORS["surface"], fg=COLORS["text"],
            activebackground=COLORS["border"], relief="flat", bd=0,
            padx=14, pady=6, cursor="hand2",
            command=self._open_location,
            highlightbackground=COLORS["border"], highlightthickness=1,
        ).pack(side="left")

        self._path_lbl = tk.Label(inner, text="", bg=COLORS["panel"],
                                  fg=COLORS["text_secondary"],
                                  font=SMALL_FONT, anchor="w", justify="left")
        self._path_lbl.pack(fill="x", pady=(10, 6))

        text_frame = tk.Frame(inner, bg=COLORS["bg"])
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

    def _log_key_for_label(self, label: str) -> str:
        for lab, key in LOG_OPTIONS:
            if lab == label:
                return key
        return APP_LOG

    def _switch_log(self) -> None:
        self._current_log = self._log_key_for_label(self._log_var.get())
        self.refresh_logs()

    def _open_location(self) -> None:
        import os
        import sys
        import subprocess
        try:
            path = get_log_path(self._current_log)
            directory = path.parent
            if sys.platform.startswith("win"):
                os.startfile(str(directory))  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(directory)])
            else:
                subprocess.Popen(["xdg-open", str(directory)])
        except Exception as e:
            messagebox.showerror("Error", f"Could not open log location:\n{e}")

    def refresh_logs(self) -> None:
        try:
            lines = int(self._tail_lines.get())
        except (tk.TclError, TypeError, ValueError):
            lines = 500
        content = read_log_tail(self._current_log, lines=lines)
        path = get_log_path(self._current_log)
        self._path_lbl.configure(
            text=f"Log file: {path}  ({lines} lines requested, "
                 f"{len(content.splitlines())} shown)"
        )
        self._raw_content = content
        self._apply_search()

    def _set_text(self, text: str) -> None:
        self._text.configure(state="normal")
        self._text.delete("1.0", "end")
        self._text.insert("1.0", text or "(no log content to display)")
        self._text.configure(state="disabled")

    def _apply_search(self) -> None:
        content = getattr(self, "_raw_content", "") or ""
        query = (self._search_var.get() or "").strip()
        if not query:
            self._set_text(content)
            return
        q = query.lower()
        lines = content.splitlines()
        filtered = [ln for ln in lines if q in ln.lower()]
        self._set_text("\n".join(filtered))
