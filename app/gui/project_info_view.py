"""
Project info view: editable fields and Open HTML button using tempfile + webbrowser.
"""

import html
import tempfile
import webbrowser
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox
from typing import Callable, Dict

from app.gui.theme import (
    COLORS, BASE_FONT, BASE_FONT_BOLD, SMALL_FONT, H2_FONT, H3_FONT,
)
from config import AppConfig, ProjectInfo


class ProjectInfoView(tk.Frame):
    def __init__(self, master, config: AppConfig,
                 save_hook: Callable[[], None] = None):
        super().__init__(master, bg=COLORS["bg"])
        self._config = config
        self._save_hook = save_hook
        self._vars: Dict[str, tk.StringVar] = {}
        self._build()
        self.load_fields()

    def _build(self):
        outer = tk.Frame(self, bg=COLORS["bg"])
        outer.pack(fill="both", expand=True, padx=20, pady=18)

        header = tk.Frame(outer, bg=COLORS["bg"])
        header.pack(fill="x")
        tk.Label(header, text="Project Info", bg=COLORS["bg"], fg=COLORS["text"],
                 font=H2_FONT).pack(side="left")
        tk.Button(
            header, text="Open HTML Report", font=BASE_FONT_BOLD,
            bg=COLORS["primary"], fg="#FFFFFF",
            activebackground=COLORS["primary_hover"],
            activeforeground="#FFFFFF", relief="flat", bd=0,
            padx=18, pady=8, cursor="hand2", command=self._open_html,
        ).pack(side="right", padx=(0, 8))
        tk.Button(
            header, text="Save", font=BASE_FONT_BOLD,
            bg=COLORS["primary_surface"], fg=COLORS["primary"],
            activebackground=COLORS["info_surface"], relief="flat", bd=0,
            padx=18, pady=8, cursor="hand2", command=self._save,
            highlightbackground=COLORS["primary"], highlightthickness=1,
        ).pack(side="right")

        canvas = tk.Canvas(outer, bg=COLORS["bg"], highlightthickness=0, bd=0)
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

        card = tk.Frame(inner, bg=COLORS["panel"],
                        highlightbackground=COLORS["border"], highlightthickness=1)
        card.pack(fill="x")
        body = tk.Frame(card, bg=COLORS["panel"])
        body.pack(fill="both", expand=True, padx=16, pady=16)
        tk.Label(body, text="Project Metadata", bg=COLORS["panel"],
                 fg=COLORS["text"], font=H3_FONT).pack(anchor="w", pady=(0, 6))
        tk.Label(body,
                 text="Edit the fields below and click Save. Then click Open HTML Report to "
                      "preview the project information page in your default web browser.",
                 bg=COLORS["panel"], fg=COLORS["text_muted"],
                 font=SMALL_FONT, wraplength=900, justify="left").pack(fill="x", pady=(0, 10))

        fields = [
            ("project_title", "Project title", False),
            ("college", "College / Institution", False),
            ("department", "Department", False),
            ("academic_year", "Academic year", False),
            ("project_guide", "Project guide / supervisor", False),
            ("team_members", "Team members (one per line)", True),
            ("employee_ids", "Employee / Student IDs (one per line)", True),
            ("contact_emails", "Contact emails (one per line)", True),
        ]
        text_fields = set()
        for key, label, is_text in fields:
            row = tk.Frame(body, bg=COLORS["panel"])
            row.pack(fill="x", pady=(0, 10))
            tk.Label(row, text=label, bg=COLORS["panel"],
                     fg=COLORS["text_secondary"], font=BASE_FONT, width=32,
                     anchor="nw").pack(side="left")
            if is_text:
                sv = tk.StringVar()
                txt = tk.Text(
                    row, height=3, font=BASE_FONT, relief="flat", bd=0,
                    bg=COLORS["input_bg"], fg=COLORS["text"], wrap="word",
                    highlightthickness=1,
                    highlightbackground=COLORS["input_border"],
                    highlightcolor=COLORS["input_focus"], padx=10, pady=8,
                )
                txt.pack(side="left", fill="x", expand=True)
                self._vars[key] = txt
                text_fields.add(key)
            else:
                sv = tk.StringVar()
                self._vars[key] = sv
                e = tk.Entry(
                    row, textvariable=sv, font=BASE_FONT, relief="flat", bd=0,
                    bg=COLORS["input_bg"], fg=COLORS["text"],
                    highlightthickness=1,
                    highlightbackground=COLORS["input_border"],
                    highlightcolor=COLORS["input_focus"],
                    insertbackground=COLORS["primary"],
                )
                e.pack(side="left", fill="x", expand=True)

        prob_row = tk.Frame(body, bg=COLORS["panel"])
        prob_row.pack(fill="x", pady=(0, 10))
        tk.Label(prob_row, text="Problem statement", bg=COLORS["panel"],
                 fg=COLORS["text_secondary"], font=BASE_FONT, width=32,
                 anchor="nw").pack(side="left")
        prob_txt = tk.Text(
            prob_row, height=5, font=BASE_FONT, relief="flat", bd=0,
            bg=COLORS["input_bg"], fg=COLORS["text"], wrap="word",
            highlightthickness=1,
            highlightbackground=COLORS["input_border"],
            highlightcolor=COLORS["input_focus"], padx=10, pady=8,
        )
        prob_txt.pack(side="left", fill="x", expand=True)
        self._vars["problem_statement"] = prob_txt
        text_fields.add("problem_statement")

        obj_row = tk.Frame(body, bg=COLORS["panel"])
        obj_row.pack(fill="x", pady=(0, 10))
        tk.Label(obj_row, text="Objectives", bg=COLORS["panel"],
                 fg=COLORS["text_secondary"], font=BASE_FONT, width=32,
                 anchor="nw").pack(side="left")
        obj_txt = tk.Text(
            obj_row, height=7, font=BASE_FONT, relief="flat", bd=0,
            bg=COLORS["input_bg"], fg=COLORS["text"], wrap="word",
            highlightthickness=1,
            highlightbackground=COLORS["input_border"],
            highlightcolor=COLORS["input_focus"], padx=10, pady=8,
        )
        obj_txt.pack(side="left", fill="x", expand=True)
        self._vars["objectives"] = obj_txt
        text_fields.add("objectives")
        self._text_fields = text_fields

    def _get_var(self, key: str) -> str:
        widget = self._vars.get(key)
        if widget is None:
            return ""
        if key in self._text_fields:
            try:
                return widget.get("1.0", "end").rstrip("\n")
            except Exception:
                return ""
        try:
            return widget.get()
        except Exception:
            return ""

    def _set_var(self, key: str, value: str) -> None:
        widget = self._vars.get(key)
        if widget is None:
            return
        if key in self._text_fields:
            try:
                widget.delete("1.0", "end")
                widget.insert("1.0", value or "")
            except Exception:
                pass
        else:
            try:
                widget.set(value or "")
            except Exception:
                pass

    def load_fields(self) -> None:
        p = self._config.project
        self._set_var("project_title", p.project_title)
        self._set_var("problem_statement", p.problem_statement)
        self._set_var("objectives", p.objectives)
        self._set_var("team_members", p.team_members)
        self._set_var("employee_ids", p.employee_ids)
        self._set_var("contact_emails", p.contact_emails)
        self._set_var("college", p.college)
        self._set_var("department", p.department)
        self._set_var("academic_year", p.academic_year)
        self._set_var("project_guide", p.project_guide)

    def _save(self) -> bool:
        p: ProjectInfo = self._config.project
        p.project_title = self._get_var("project_title") or p.project_title
        p.problem_statement = self._get_var("problem_statement") or p.problem_statement
        p.objectives = self._get_var("objectives") or p.objectives
        p.team_members = self._get_var("team_members")
        p.employee_ids = self._get_var("employee_ids")
        p.contact_emails = self._get_var("contact_emails")
        p.college = self._get_var("college")
        p.department = self._get_var("department")
        p.academic_year = self._get_var("academic_year")
        p.project_guide = self._get_var("project_guide")
        ok = self._config.save()
        if self._save_hook:
            try:
                self._save_hook()
            except Exception:
                pass
        if ok:
            messagebox.showinfo("Project Info", "Project information saved.")
        else:
            messagebox.showerror("Save Failed",
                                 "Could not save project information.")
        return ok

    def _html(self) -> str:
        p = self._config.project

        def hx(s: str) -> str:
            return html.escape(s or "", quote=True)

        def lines_html(s: str) -> str:
            text = s or ""
            items = [ln.strip() for ln in text.splitlines() if ln.strip()]
            if not items:
                return "<li class='placeholder'>—</li>"
            return "".join(f"<li>{hx(it)}</li>" for it in items)

        generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        body = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<title>{hx(p.project_title)} — Project Info</title>
<style>
  body {{ font-family: "Segoe UI", Arial, sans-serif; margin: 0; background: #F4F6F8; color: #1F2937; }}
  header {{ background: linear-gradient(135deg, #1B5EA5, #0277BD); color: #fff;
           padding: 48px 48px 36px 48px; }}
  header h1 {{ margin: 0; font-size: 32px; letter-spacing: 0.3px; }}
  header p.subtitle {{ margin: 10px 0 0 0; opacity: 0.9; font-size: 15px; }}
  main {{ max-width: 1080px; margin: -24px auto 48px auto; padding: 0 24px; }}
  .card {{ background: #fff; border-radius: 12px; box-shadow: 0 2px 10px rgba(27,94,165,0.06);
           padding: 28px 32px; margin-bottom: 22px; border: 1px solid #E6ECF2; }}
  h2 {{ color: #1B5EA5; margin-top: 0; font-size: 20px; border-left: 4px solid #1B5EA5;
        padding-left: 10px; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 18px; }}
  .cell {{ background: #F7F9FC; border-radius: 10px; padding: 16px 18px; }}
  .cell b {{ display: block; color: #6B7280; font-size: 12px; text-transform: uppercase;
              letter-spacing: 0.5px; margin-bottom: 6px; }}
  ul {{ padding-left: 20px; margin: 0; line-height: 1.7; }}
  ul li.placeholder {{ color: #9AA4B2; list-style: none; margin-left: -20px; }}
  footer {{ text-align: center; color: #9AA4B2; padding: 0 0 32px 0; font-size: 12px; }}
  pre {{ background: #F4F6F8; padding: 14px 16px; border-radius: 8px;
         white-space: pre-wrap; line-height: 1.6; border: 1px solid #E6ECF2; }}
</style>
</head>
<body>
<header>
  <h1>{hx(p.project_title)}</h1>
  <p class="subtitle">Academic / Portfolio Project Report · Generated {hx(generated)}</p>
</header>
<main>
  <section class="card">
    <h2>Problem Statement</h2>
    <pre>{hx(p.problem_statement)}</pre>
  </section>
  <section class="card">
    <h2>Objectives</h2>
    <pre>{hx(p.objectives)}</pre>
  </section>
  <section class="card">
    <h2>Organisation</h2>
    <div class="grid">
      <div class="cell"><b>College / Institution</b><span>{hx(p.college) or "—"}</span></div>
      <div class="cell"><b>Department</b><span>{hx(p.department) or "—"}</span></div>
      <div class="cell"><b>Academic Year</b><span>{hx(p.academic_year) or "—"}</span></div>
      <div class="cell"><b>Project Guide</b><span>{hx(p.project_guide) or "—"}</span></div>
    </div>
  </section>
  <section class="card">
    <h2>Team Members</h2>
    <div class="grid">
      <div class="cell"><b>Names</b><ul>{lines_html(p.team_members)}</ul></div>
      <div class="cell"><b>Employee / Student IDs</b><ul>{lines_html(p.employee_ids)}</ul></div>
      <div class="cell"><b>Contact Emails</b><ul>{lines_html(p.contact_emails)}</ul></div>
    </div>
  </section>
  <section class="card">
    <h2>About the Application</h2>
    <p>This desktop application provides a professional, defensive network monitoring
       workspace. It supports live Scapy packet capture from a user-selected interface,
       protocol-level analysis, a live packet table with filter/search, packet-level
       details, statistics, visualisations, and a rule-based Intrusion Detection System
       (IDS) that can raise email alerts via SMTP.</p>
    <p>Captures can be exported as CSV (summaries) and standard PCAP files (readable by
       Wireshark and compatible tools). All sensitive operational events are timestamped
       and written to rotating log files.</p>
  </section>
</main>
<footer>Generated by Network Packet Sniffer &amp; IDS · {hx(generated)}</footer>
</body>
</html>
"""
        return body

    def _open_html(self) -> None:
        html_content = self._html()
        try:
            with tempfile.NamedTemporaryFile(
                "w", prefix="project_info_", suffix=".html",
                delete=False, encoding="utf-8",
            ) as f:
                f.write(html_content)
                path = Path(f.name)
            try:
                webbrowser.open(path.as_uri())
            except Exception as e:
                messagebox.showerror(
                    "Open Browser",
                    f"Could not open the browser. The report was saved to:\n{path}\n{e}")
        except Exception as e:
            messagebox.showerror(
                "Generate HTML", f"Could not create temporary HTML file:\n{e}")
