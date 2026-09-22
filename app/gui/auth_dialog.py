"""
Authentication dialog: first-time password setup + login dialog.
"""

import tkinter as tk
from tkinter import ttk, messagebox
from typing import Callable, Optional

from app.gui.theme import (
    COLORS, BASE_FONT, BASE_FONT_BOLD, SMALL_FONT, H1_FONT, H2_FONT,
)
from app.authentication.auth_manager import AuthManager


class SetupDialog(tk.Toplevel):
    def __init__(self, master, auth: AuthManager,
                 on_success: Optional[Callable[[str], None]] = None):
        super().__init__(master)
        self._auth = auth
        self._on_success = on_success
        self._result_session: Optional[str] = None

        self.title("Network Packet Sniffer & IDS — Setup Password")
        self.configure(bg=COLORS["bg"])
        self.resizable(False, False)
        self.transient(master)
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self._cancel)

        self._build()
        self._center_on(master)

    def _center_on(self, parent) -> None:
        self.update_idletasks()
        try:
            pw = parent.winfo_width()
            ph = parent.winfo_height()
            px = parent.winfo_rootx()
            py = parent.winfo_rooty()
            w = self.winfo_width()
            h = self.winfo_height()
            x = px + (pw - w) // 2
            y = py + (ph - h) // 2
            self.geometry(f"+{max(0, x)}+{max(0, y)}")
        except Exception:
            pass

    def _build(self) -> None:
        outer = tk.Frame(self, bg=COLORS["panel"], padx=28, pady=24)
        outer.pack(fill="both", expand=True)

        title = tk.Label(
            outer, text="Set Application Password",
            bg=COLORS["panel"], fg=COLORS["text"], font=H1_FONT,
        )
        title.pack(anchor="w")
        subtitle = tk.Label(
            outer,
            text="Create a strong password to protect the Network Sniffer & IDS workspace.",
            bg=COLORS["panel"], fg=COLORS["text_secondary"], font=BASE_FONT,
            wraplength=460, justify="left",
        )
        subtitle.pack(anchor="w", pady=(6, 18))

        form = tk.Frame(outer, bg=COLORS["panel"])
        form.pack(fill="x")

        tk.Label(form, text="New Password", bg=COLORS["panel"],
                 fg=COLORS["text"], font=BASE_FONT_BOLD).grid(row=0, column=0, sticky="w", pady=(0, 4))
        self.pw1 = tk.StringVar()
        self.entry1 = self._make_entry(form, self.pw1, show="•")
        self.entry1.grid(row=1, column=0, sticky="we", pady=(0, 4))
        self.show1 = tk.BooleanVar(value=False)
        tk.Checkbutton(form, text="Show password", variable=self.show1,
                       bg=COLORS["panel"], fg=COLORS["text_secondary"],
                       activebackground=COLORS["panel"], font=SMALL_FONT,
                       command=self._toggle_show).grid(row=2, column=0, sticky="w", pady=(0, 12))

        tk.Label(form, text="Confirm Password", bg=COLORS["panel"],
                 fg=COLORS["text"], font=BASE_FONT_BOLD).grid(row=3, column=0, sticky="w", pady=(0, 4))
        self.pw2 = tk.StringVar()
        self.entry2 = self._make_entry(form, self.pw2, show="•")
        self.entry2.grid(row=4, column=0, sticky="we", pady=(0, 4))

        self.status_var = tk.StringVar(value="")
        status_label = tk.Label(
            form, textvariable=self.status_var, bg=COLORS["panel"],
            fg=COLORS["danger"], font=SMALL_FONT, justify="left", wraplength=460,
        )
        status_label.grid(row=5, column=0, sticky="we", pady=(10, 10))

        form.columnconfigure(0, weight=1)

        buttons = tk.Frame(outer, bg=COLORS["panel"])
        buttons.pack(fill="x", pady=(10, 0))
        tk.Button(
            buttons, text="Cancel", font=BASE_FONT,
            bg=COLORS["surface"], fg=COLORS["text"],
            activebackground=COLORS["border"], relief="flat",
            padx=16, pady=8, cursor="hand2", command=self._cancel,
        ).pack(side="right", padx=(8, 0))
        tk.Button(
            buttons, text="Set Password & Unlock", font=BASE_FONT_BOLD,
            bg=COLORS["primary"], fg="#FFFFFF",
            activebackground=COLORS["primary_hover"],
            activeforeground="#FFFFFF", relief="flat", padx=18, pady=8,
            cursor="hand2", command=self._submit,
        ).pack(side="right")

        self.entry1.focus_set()
        self.bind("<Return>", lambda _e: self._submit())
        self.bind("<Escape>", lambda _e: self._cancel())

    def _make_entry(self, parent, var, show=None):
        e = tk.Entry(
            parent, textvariable=var, show=show or "", font=BASE_FONT,
            relief="flat", bg=COLORS["input_bg"], fg=COLORS["text"],
            highlightthickness=1,
            highlightbackground=COLORS["input_border"],
            highlightcolor=COLORS["input_focus"],
            insertbackground=COLORS["primary"],
        )
        e.configure(bd=0)
        return e

    def _toggle_show(self) -> None:
        show = self.show1.get()
        self.entry1.configure(show="" if show else "•")
        self.entry2.configure(show="" if show else "•")

    def _cancel(self) -> None:
        self._result_session = None
        self.grab_release()
        self.destroy()

    def _submit(self) -> None:
        p1 = self.pw1.get()
        p2 = self.pw2.get()
        if not p1:
            self.status_var.set("Please enter a password.")
            return
        if len(p1) < 8:
            self.status_var.set("Password must be at least 8 characters.")
            return
        if p1 != p2:
            self.status_var.set("Passwords do not match.")
            return
        ok = self._auth.setup_password(p1)
        if not ok:
            self.status_var.set("Failed to store password. Try again.")
            return
        sid = self._auth.authenticate("admin", p1)
        if not sid:
            self.status_var.set("Password stored but auto-login failed.")
            return
        self._result_session = sid
        if self._on_success:
            try:
                self._on_success(sid)
            except Exception:
                pass
        self.grab_release()
        self.destroy()

    def result(self) -> Optional[str]:
        return self._result_session


class LoginDialog(tk.Toplevel):
    def __init__(self, master, auth: AuthManager,
                 on_success: Optional[Callable[[str], None]] = None,
                 allow_cancel: bool = True):
        super().__init__(master)
        self._auth = auth
        self._on_success = on_success
        self._allow_cancel = allow_cancel
        self._result_session: Optional[str] = None

        self.title("Network Packet Sniffer & IDS — Authentication Required")
        self.configure(bg=COLORS["bg"])
        self.resizable(False, False)
        self.transient(master)
        self.grab_set()
        if not allow_cancel:
            self.protocol("WM_DELETE_WINDOW", lambda: None)
        else:
            self.protocol("WM_DELETE_WINDOW", self._cancel)

        self._build()
        self._center_on(master)

    def _center_on(self, parent) -> None:
        self.update_idletasks()
        try:
            pw = parent.winfo_width()
            ph = parent.winfo_height()
            px = parent.winfo_rootx()
            py = parent.winfo_rooty()
            w = self.winfo_width()
            h = self.winfo_height()
            x = px + (pw - w) // 2
            y = py + (ph - h) // 2
            self.geometry(f"+{max(0, x)}+{max(0, y)}")
        except Exception:
            pass

    def _build(self) -> None:
        outer = tk.Frame(self, bg=COLORS["panel"], padx=28, pady=24)
        outer.pack(fill="both", expand=True)

        header = tk.Frame(outer, bg=COLORS["panel"])
        header.pack(fill="x")
        try:
            from assets.logo import get_logo_photoimage
            self._logo = get_logo_photoimage(size=56)
            if self._logo is not None:
                logo_lbl = tk.Label(header, image=self._logo, bg=COLORS["panel"])
                logo_lbl.pack(side="left", padx=(0, 14))
        except Exception:
            pass
        title_box = tk.Frame(header, bg=COLORS["panel"])
        title_box.pack(side="left", fill="both", expand=True)
        tk.Label(title_box, text="Sign In", bg=COLORS["panel"],
                 fg=COLORS["text"], font=H1_FONT).pack(anchor="w")
        tk.Label(
            title_box,
            text="Authentication is required for capture, export, logs and IDS.",
            bg=COLORS["panel"], fg=COLORS["text_secondary"],
            font=BASE_FONT, wraplength=420, justify="left",
        ).pack(anchor="w", pady=(4, 0))

        form = tk.Frame(outer, bg=COLORS["panel"])
        form.pack(fill="x", pady=(22, 0))

        tk.Label(form, text="Username", bg=COLORS["panel"],
                 fg=COLORS["text"], font=BASE_FONT_BOLD).grid(row=0, column=0, sticky="w", pady=(0, 4))
        self.username_var = tk.StringVar(value="admin")
        user_entry = tk.Entry(
            form, textvariable=self.username_var, font=BASE_FONT, relief="flat",
            bg=COLORS["input_bg"], fg=COLORS["text"],
            highlightthickness=1,
            highlightbackground=COLORS["input_border"],
            highlightcolor=COLORS["input_focus"],
            insertbackground=COLORS["primary"], bd=0,
        )
        user_entry.grid(row=1, column=0, sticky="we", pady=(0, 12))

        tk.Label(form, text="Password", bg=COLORS["panel"],
                 fg=COLORS["text"], font=BASE_FONT_BOLD).grid(row=2, column=0, sticky="w", pady=(0, 4))
        self.password_var = tk.StringVar()
        self.pw_entry = tk.Entry(
            form, textvariable=self.password_var, show="•", font=BASE_FONT, relief="flat",
            bg=COLORS["input_bg"], fg=COLORS["text"],
            highlightthickness=1,
            highlightbackground=COLORS["input_border"],
            highlightcolor=COLORS["input_focus"],
            insertbackground=COLORS["primary"], bd=0,
        )
        self.pw_entry.grid(row=3, column=0, sticky="we", pady=(0, 4))

        self.show_var = tk.BooleanVar(value=False)
        tk.Checkbutton(
            form, text="Show password", variable=self.show_var,
            bg=COLORS["panel"], fg=COLORS["text_secondary"],
            activebackground=COLORS["panel"], font=SMALL_FONT,
            command=self._toggle_show,
        ).grid(row=4, column=0, sticky="w", pady=(0, 10))

        self.status_var = tk.StringVar(value="")
        tk.Label(
            form, textvariable=self.status_var, bg=COLORS["panel"],
            fg=COLORS["danger"], font=SMALL_FONT, justify="left", wraplength=460,
        ).grid(row=5, column=0, sticky="we", pady=(2, 10))

        form.columnconfigure(0, weight=1)

        buttons = tk.Frame(outer, bg=COLORS["panel"])
        buttons.pack(fill="x", pady=(8, 0))
        if self._allow_cancel:
            tk.Button(
                buttons, text="Cancel", font=BASE_FONT,
                bg=COLORS["surface"], fg=COLORS["text"],
                activebackground=COLORS["border"], relief="flat",
                padx=16, pady=8, cursor="hand2", command=self._cancel,
            ).pack(side="right", padx=(8, 0))
        tk.Button(
            buttons, text="Sign In", font=BASE_FONT_BOLD,
            bg=COLORS["primary"], fg="#FFFFFF",
            activebackground=COLORS["primary_hover"],
            activeforeground="#FFFFFF", relief="flat", padx=22, pady=8,
            cursor="hand2", command=self._submit,
        ).pack(side="right")

        self.pw_entry.focus_set()
        self.bind("<Return>", lambda _e: self._submit())
        if self._allow_cancel:
            self.bind("<Escape>", lambda _e: self._cancel())

    def _toggle_show(self) -> None:
        self.pw_entry.configure(show="" if self.show_var.get() else "•")

    def _cancel(self) -> None:
        self._result_session = None
        if self._allow_cancel:
            try:
                self.grab_release()
            except Exception:
                pass
            self.destroy()

    def _submit(self) -> None:
        user = self.username_var.get() or "admin"
        pw = self.password_var.get()
        if not pw:
            self.status_var.set("Please enter your password.")
            return
        sid = self._auth.authenticate(user, pw)
        if not sid:
            recent = self._auth.recent_attempts(limit=1)
            msg = "Authentication failed. Please try again."
            if recent and recent[-1].message:
                msg = recent[-1].message
            self.status_var.set(msg)
            self.password_var.set("")
            self.pw_entry.focus_set()
            return
        self._result_session = sid
        if self._on_success:
            try:
                self._on_success(sid)
            except Exception:
                pass
        try:
            self.grab_release()
        except Exception:
            pass
        self.destroy()

    def result(self) -> Optional[str]:
        return self._result_session
