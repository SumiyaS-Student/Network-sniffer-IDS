"""
Path utilities for the Network Packet Sniffer application.
"""

import os
import sys
from pathlib import Path
from typing import Optional


def get_project_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent.parent


def get_writable_root() -> Path:
    """Location for config.json and data/ (logs, captures, reports).

    When frozen (packaged exe) we store runtime data under the current
    user's LOCALAPPDATA so the program folder stays clean and the exe is
    never locked or re-marked by OneDrive/Defender on every launch.
    """
    if getattr(sys, "frozen", False):
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA") \
            or str(Path.home())
        return Path(base) / "NetworkSnifferIDS"
    return get_project_root()


PROJECT_ROOT: Path = get_project_root()
WRITABLE_ROOT: Path = get_writable_root()

APP_DIR: Path = PROJECT_ROOT / "app"
ASSETS_DIR: Path = PROJECT_ROOT / "assets"
DATA_DIR: Path = WRITABLE_ROOT / "data"
TESTS_DIR: Path = PROJECT_ROOT / "tests"
DOCS_DIR: Path = PROJECT_ROOT / "docs"

LOGS_DIR: Path = DATA_DIR / "logs"
CAPTURES_DIR: Path = DATA_DIR / "captures"
REPORTS_DIR: Path = DATA_DIR / "reports"

CONFIG_FILE: Path = WRITABLE_ROOT / "config.json"
ENV_FILE: Path = WRITABLE_ROOT / ".env"
ENV_EXAMPLE_FILE: Path = PROJECT_ROOT / ".env.example"


def ensure_directory(path: Path) -> Path:
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    return path


def ensure_all_directories() -> None:
    import sys
    if getattr(sys, "frozen", False):
        for d in (DATA_DIR, LOGS_DIR, CAPTURES_DIR, REPORTS_DIR):
            ensure_directory(d)
        return
    for d in (APP_DIR, ASSETS_DIR, DATA_DIR, TESTS_DIR, DOCS_DIR,
              LOGS_DIR, CAPTURES_DIR, REPORTS_DIR):
        ensure_directory(d)


def safe_filename(name: str, default: str = "output") -> str:
    keep = "-_.() "
    cleaned = "".join(c for c in name if c.isalnum() or c in keep).strip()
    cleaned = cleaned.rstrip(".")
    return cleaned or default


def unique_path(directory: Path, filename: str) -> Path:
    directory = ensure_directory(Path(directory))
    base, ext = os.path.splitext(filename)
    candidate = directory / filename
    counter = 1
    while candidate.exists():
        candidate = directory / f"{base}_{counter}{ext}"
        counter += 1
    return candidate
