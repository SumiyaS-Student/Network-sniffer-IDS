"""
Light theme color palette and common GUI helpers.
"""

from typing import Dict, Tuple


COLORS: Dict[str, str] = {
    "bg": "#FAFBFC",
    "panel": "#FFFFFF",
    "surface": "#F4F6F8",
    "border": "#DCE3EA",
    "divider": "#E6ECF2",
    "text": "#1F2937",
    "text_secondary": "#6B7280",
    "text_muted": "#9AA4B2",
    "primary": "#1B5EA5",
    "primary_hover": "#154A82",
    "primary_surface": "#E8F0FA",
    "success": "#2E7D32",
    "success_surface": "#E6F3E7",
    "info": "#0277BD",
    "info_surface": "#E1F2FC",
    "warning": "#FB8C00",
    "warning_surface": "#FFF1E0",
    "danger": "#C62828",
    "danger_surface": "#FCE8E8",
    "critical": "#8E0000",
    "critical_surface": "#F8DADA",
    "header_bg": "#FFFFFF",
    "header_border": "#DCE3EA",
    "nav_bg": "#F7F9FC",
    "nav_active": "#E8F0FA",
    "nav_text": "#475569",
    "nav_active_text": "#1B5EA5",
    "table_header_bg": "#EEF2F7",
    "table_alt": "#F8FAFC",
    "input_bg": "#FFFFFF",
    "input_border": "#CBD5E1",
    "input_focus": "#1B5EA5",
}


SEVERITY_COLORS_BG = {
    "LOW": COLORS["success_surface"],
    "MEDIUM": COLORS["warning_surface"],
    "HIGH": "#FCE5D3",
    "CRITICAL": COLORS["critical_surface"],
}

SEVERITY_COLORS_FG = {
    "LOW": COLORS["success"],
    "MEDIUM": "#B36100",
    "HIGH": COLORS["danger"],
    "CRITICAL": COLORS["critical"],
}


STATUS_BADGE = {
    "IDLE": (COLORS["text_secondary"], "#E5E7EB"),
    "CAPTURING": (COLORS["success"], COLORS["success_surface"]),
    "PAUSED": (COLORS["warning"], COLORS["warning_surface"]),
    "STOPPING": (COLORS["info"], COLORS["info_surface"]),
    "ERROR": (COLORS["danger"], COLORS["danger_surface"]),
    "OK": (COLORS["success"], COLORS["success_surface"]),
    "DEMO": (COLORS["info"], COLORS["info_surface"]),
}


FONT_FAMILY = "Segoe UI" if True else "TkDefaultFont"


BASE_FONT = (FONT_FAMILY, 10)
BASE_FONT_BOLD = (FONT_FAMILY, 10, "bold")
SMALL_FONT = (FONT_FAMILY, 9)
LARGE_FONT = (FONT_FAMILY, 12)
LARGE_FONT_BOLD = (FONT_FAMILY, 12, "bold")
H1_FONT = (FONT_FAMILY, 18, "bold")
H2_FONT = (FONT_FAMILY, 14, "bold")
H3_FONT = (FONT_FAMILY, 11, "bold")
MONO_FONT = ("Consolas", 10)


PROT_COLORS = {
    "TCP": COLORS["primary"],
    "UDP": "#6A4CB8",
    "ICMP": COLORS["warning"],
    "ICMPv6": "#C65A00",
    "DNS": "#00838F",
    "DHCP": "#558B2F",
    "ARP": "#5D4037",
    "HTTP": COLORS["success"],
    "HTTPS": "#2E7D32",
    "FTP": "#6D4C41",
    "SSH": COLORS["primary_hover"],
    "SMTP": "#D84315",
    "Other": COLORS["text_secondary"],
    "IPv4": COLORS["info"],
    "IPv6": "#4527A0",
}


def severity_bg(level: str) -> str:
    return SEVERITY_COLORS_BG.get(str(level).upper(), COLORS["surface"])


def severity_fg(level: str) -> str:
    return SEVERITY_COLORS_FG.get(str(level).upper(), COLORS["text"])


def status_colors(status: str) -> Tuple[str, str]:
    return STATUS_BADGE.get(str(status).upper(), (COLORS["text_secondary"], COLORS["surface"]))


def protocol_color(protocol: str) -> str:
    return PROT_COLORS.get(str(protocol).strip(), PROT_COLORS["Other"])
