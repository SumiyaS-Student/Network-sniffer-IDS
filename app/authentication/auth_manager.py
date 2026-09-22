"""
Authentication manager with secure PBKDF2 password storage and session tracking.
"""

import threading
import time
import secrets
from dataclasses import dataclass, field
from typing import Optional, Dict, List

from config import AppConfig
from app.logging.logger import log_authentication, log_application, log_error
from app.utils.security import generate_token


MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 60
SESSION_IDLE_TIMEOUT = 1800


@dataclass
class AuthAttempt:
    timestamp: float
    success: bool
    username: str
    remote: str = "local"
    message: str = ""


@dataclass
class Session:
    session_id: str
    username: str
    created_at: float
    last_active: float
    is_active: bool = True


class AuthManager:
    _instance = None
    _lock = threading.RLock()

    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self):
        if getattr(self, "_initialized", False):
            return
        self._initialized = True
        self.config = AppConfig()
        self._sessions: Dict[str, Session] = {}
        self._attempts: List[AuthAttempt] = []
        self._failed_count: Dict[str, int] = {}
        self._lockout_until: Dict[str, float] = {}
        self._current_session: Optional[Session] = None

    def is_setup_required(self) -> bool:
        return not self.config.is_password_setup()

    def setup_password(self, password: str) -> bool:
        ok = self.config.setup_password(password)
        if ok:
            log_authentication("Initial password configuration completed successfully.", "INFO")
        else:
            log_authentication("Initial password configuration FAILED.", "WARNING")
        return ok

    def change_password(self, old_password: str, new_password: str) -> bool:
        ok = self.config.change_password(old_password, new_password)
        if ok:
            log_authentication("Password changed successfully.", "INFO")
            self.logout_all()
        else:
            log_authentication("Password change attempt FAILED.", "WARNING")
        return ok

    def _is_locked_out(self, username: str) -> bool:
        until = self._lockout_until.get(username, 0.0)
        if until > time.time():
            return True
        if until:
            self._lockout_until.pop(username, None)
            self._failed_count[username] = 0
        return False

    def _record_attempt(self, username: str, success: bool, message: str = "") -> None:
        attempt = AuthAttempt(
            timestamp=time.time(), success=success,
            username=username or "<none>", message=message,
        )
        self._attempts.append(attempt)
        if len(self._attempts) > 2000:
            self._attempts = self._attempts[-1000:]

    def authenticate(self, username: str, password: str) -> Optional[str]:
        with self._lock:
            if self.is_setup_required():
                self._record_attempt(username, False, "Password not yet configured.")
                log_authentication(f"Login failed for user '{username}': password not configured.", "WARNING")
                return None
            if self._is_locked_out(username):
                self._record_attempt(username, False, "Account locked due to too many failed attempts.")
                log_authentication(f"Login denied for user '{username}': account locked.", "WARNING")
                return None
            if self.config.verify_password(password):
                self._failed_count[username] = 0
                self._record_attempt(username, True, "Login successful.")
                log_authentication(f"User '{username}' authenticated successfully.", "INFO")
                session_id = self._create_session(username)
                return session_id
            self._failed_count[username] = self._failed_count.get(username, 0) + 1
            remaining = max(0, MAX_ATTEMPTS - self._failed_count[username])
            if self._failed_count[username] >= MAX_ATTEMPTS:
                self._lockout_until[username] = time.time() + LOCKOUT_SECONDS
                msg = f"Max failed attempts reached; user '{username}' locked for {LOCKOUT_SECONDS}s."
                self._record_attempt(username, False, msg)
                log_authentication(msg, "ERROR")
                return None
            self._record_attempt(username, False, f"Invalid password ({remaining} attempts remaining).")
            log_authentication(
                f"Failed login attempt for user '{username}'; {remaining} attempts remaining.",
                "WARNING",
            )
            return None

    def _create_session(self, username: str) -> str:
        sid = generate_token(32)
        now = time.time()
        session = Session(
            session_id=sid, username=username, created_at=now, last_active=now,
        )
        self._sessions[sid] = session
        self._current_session = session
        log_application(f"Session created for user '{username}'.", "INFO")
        return sid

    def validate_session(self, session_id: Optional[str]) -> bool:
        with self._lock:
            if not session_id or session_id not in self._sessions:
                return False
            s = self._sessions[session_id]
            if not s.is_active:
                return False
            if time.time() - s.last_active > SESSION_IDLE_TIMEOUT:
                s.is_active = False
                log_authentication(f"Session for user '{s.username}' timed out.", "WARNING")
                if self._current_session and self._current_session.session_id == session_id:
                    self._current_session = None
                return False
            s.last_active = time.time()
            return True

    def get_current_session(self) -> Optional[Session]:
        return self._current_session

    def is_authenticated(self) -> bool:
        s = self._current_session
        if not s:
            return False
        return self.validate_session(s.session_id)

    def logout(self, session_id: Optional[str] = None) -> None:
        with self._lock:
            sid = session_id or (self._current_session.session_id if self._current_session else None)
            if sid and sid in self._sessions:
                s = self._sessions[sid]
                s.is_active = False
                log_authentication(f"User '{s.username}' logged out.", "INFO")
                self._sessions.pop(sid, None)
            if self._current_session and self._current_session.session_id == sid:
                self._current_session = None

    def logout_all(self) -> None:
        with self._lock:
            for sid, s in list(self._sessions.items()):
                s.is_active = False
                log_authentication(f"User '{s.username}' force-logged out.", "INFO")
            self._sessions.clear()
            self._current_session = None

    def recent_attempts(self, limit: int = 50) -> List[AuthAttempt]:
        with self._lock:
            return list(self._attempts[-limit:])
