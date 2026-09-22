"""
Central application configuration with persistent JSON storage.
"""

import json
import threading
import os
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Any
from pathlib import Path

from app.utils.paths import CONFIG_FILE, ensure_directory, get_project_root
from app.utils.security import hash_password, verify_password
from app.utils.crypt import encrypt_string, decrypt_string, PREFIX
from app.utils.time_utils import now_iso


@dataclass
class IDSConfig:
    enabled: bool = True
    syn_flood_threshold: int = 100
    port_scan_threshold: int = 20
    icmp_flood_threshold: int = 150
    udp_flood_threshold: int = 200
    ping_sweep_threshold: int = 20
    detection_window_seconds: int = 60
    alert_cooldown_seconds: int = 300
    suspicious_flags_enabled: bool = True
    packet_rate_warning: int = 5000
    packet_rate_critical: int = 15000

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CaptureConfig:
    max_retained_packets: int = 50000
    display_limit: int = 5000
    auto_save: bool = False
    auto_save_interval_seconds: int = 300
    default_filter: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SMTPConfig:
    enabled: bool = False
    host: str = ""
    port: int = 587
    username: str = ""
    password: str = ""
    use_tls: bool = True
    from_email: str = ""
    to_email: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class LoggingConfig:
    log_directory: str = ""
    log_level: str = "INFO"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ProjectInfo:
    project_title: str = "Network Packet Sniffer & Real-Time Intrusion Detection System"
    problem_statement: str = (
        "Design and implement a defensive desktop application for real-time "
        "network packet capture, protocol analysis, visual statistics, and "
        "intrusion detection suitable for educational, laboratory, and "
        "portfolio demonstration."
    )
    objectives: str = (
        "1. Capture live network packets from a user-selected interface.\n"
        "2. Parse and identify L2-L4 and common application protocols.\n"
        "3. Visualise statistics with charts and a live packet table.\n"
        "4. Implement a defensive IDS for SYN flood, port scans and anomalies.\n"
        "5. Provide CSV/PCAP export and optional SMTP alerting.\n"
        "6. Deliver a professional, responsive Tkinter GUI."
    )
    team_members: str = "[Team Member 1]\n[Team Member 2]\n[Team Member 3]"
    employee_ids: str = "[Employee ID 1]\n[Employee ID 2]\n[Employee ID 3]"
    contact_emails: str = "[member1@example.edu]\n[member2@example.edu]\n[member3@example.edu]"
    college: str = "[College / Institution Name]"
    department: str = "[Department Name]"
    academic_year: str = "[Academic Year]"
    project_guide: str = "[Guide / Supervisor Name]"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AuthState:
    password_hash: str = ""
    password_salt: str = ""
    is_setup_required: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class AppConfig:
    _instance = None
    _lock = threading.RLock()

    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self, config_path: Optional[Path] = None):
        if getattr(self, "_initialized", False):
            return
        self._initialized = True
        self._path = Path(config_path) if config_path else CONFIG_FILE
        self._rwlock = threading.RLock()
        self.ids = IDSConfig()
        self.capture = CaptureConfig()
        self.smtp = SMTPConfig()
        self.logging = LoggingConfig()
        self.project = ProjectInfo()
        self.auth = AuthState()
        self.load()

    def _to_dict(self) -> Dict[str, Any]:
        smtp = self.smtp.to_dict()
        password = smtp.get("password", "") or ""
        if password and not password.startswith(PREFIX):
            smtp["password"] = encrypt_string(password)
        return {
            "version": 1,
            "saved_at": now_iso(),
            "ids": self.ids.to_dict(),
            "capture": self.capture.to_dict(),
            "smtp": smtp,
            "logging": self.logging.to_dict(),
            "project": self.project.to_dict(),
            "auth": self.auth.to_dict(),
        }

    def _from_dict(self, data: Dict[str, Any]) -> None:
        ids = data.get("ids") or {}
        cap = data.get("capture") or {}
        smtp = data.get("smtp") or {}
        log = data.get("logging") or {}
        proj = data.get("project") or {}
        auth = data.get("auth") or {}
        try:
            self.ids = IDSConfig(**ids)
        except TypeError:
            self.ids = IDSConfig()
        try:
            self.capture = CaptureConfig(**cap)
        except TypeError:
            self.capture = CaptureConfig()
        smtp = dict(smtp)
        smtp["password"] = decrypt_string(str(smtp.get("password", "") or ""))
        try:
            self.smtp = SMTPConfig(**smtp)
        except TypeError:
            self.smtp = SMTPConfig()
        try:
            self.logging = LoggingConfig(**log)
        except TypeError:
            self.logging = LoggingConfig()
        try:
            self.project = ProjectInfo(**proj)
        except TypeError:
            self.project = ProjectInfo()
        try:
            self.auth = AuthState(**auth)
        except TypeError:
            self.auth = AuthState()

    def load(self) -> bool:
        with self._rwlock:
            if not self._path.exists():
                self._migrate_legacy_config()
            if not self._path.exists():
                self.save()
                return False
            try:
                with open(self._path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self._from_dict(data or {})
                return True
            except (json.JSONDecodeError, OSError, TypeError, ValueError):
                return False

    def _migrate_legacy_config(self) -> None:
        import sys
        if not getattr(sys, "frozen", False):
            return
        if self._path == CONFIG_FILE:
            legacy = get_project_root() / "config.json"
            try:
                if legacy.is_file() and legacy.resolve() != self._path.resolve():
                    ensure_directory(self._path.parent)
                    import shutil
                    shutil.copy2(str(legacy), str(self._path))
            except (OSError, ValueError):
                pass

    def save(self) -> bool:
        with self._rwlock:
            try:
                ensure_directory(self._path.parent)
                tmp_path = self._path.with_suffix(self._path.suffix + ".tmp")
                with open(tmp_path, "w", encoding="utf-8") as f:
                    json.dump(self._to_dict(), f, indent=2)
                os.replace(tmp_path, self._path)
                return True
            except (OSError, TypeError, ValueError):
                return False

    def is_password_setup(self) -> bool:
        with self._rwlock:
            return bool(self.auth.password_hash and self.auth.password_salt)

    def setup_password(self, new_password: str) -> bool:
        if not new_password:
            return False
        with self._rwlock:
            pw_hash, salt = hash_password(new_password)
            self.auth.password_hash = pw_hash
            self.auth.password_salt = salt
            self.auth.is_setup_required = False
            return self.save()

    def change_password(self, old_password: str, new_password: str) -> bool:
        if not new_password:
            return False
        with self._rwlock:
            if not self.verify_password(old_password):
                return False
            pw_hash, salt = hash_password(new_password)
            self.auth.password_hash = pw_hash
            self.auth.password_salt = salt
            return self.save()

    def verify_password(self, password: str) -> bool:
        with self._rwlock:
            if not self.auth.password_hash or not self.auth.password_salt:
                return False
            return verify_password(password, self.auth.password_hash, self.auth.password_salt)
