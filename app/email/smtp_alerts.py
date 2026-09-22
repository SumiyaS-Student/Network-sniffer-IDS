"""
SMTP alert client with safe configuration persistence and Test Email button support.
"""

import ssl
import threading
import smtplib
import socket
from email.message import EmailMessage
from typing import Optional

from config import AppConfig, SMTPConfig
from app.logging.logger import log_application, log_ids, log_error
from app.ids.alerts import IDSAlert


TEST_SUBJECT = "Network Packet Sniffer IDS - Test Email"
TEST_BODY = (
    "This is a test email sent by the Network Packet Sniffer & IDS application.\n\n"
    "If you are reading this message, your SMTP configuration is working correctly.\n\n"
    "Generated automatically by the application."
)


class SMTPAlerts:
    def __init__(self, config: Optional[AppConfig] = None):
        self._lock = threading.RLock()
        self._config = config or AppConfig()
        self._last_error: str = ""

    def _cfg(self) -> SMTPConfig:
        return self._config.smtp

    @property
    def last_error(self) -> str:
        return self._last_error

    def is_configured(self) -> bool:
        c = self._cfg()
        return bool(c.host and c.port and c.from_email and c.to_email)

    def is_enabled(self) -> bool:
        with self._lock:
            return bool(self._cfg().enabled and self.is_configured())

    def set_enabled(self, enabled: bool) -> None:
        with self._lock:
            self._cfg().enabled = bool(enabled)
            try:
                self._config.save()
            except Exception:
                pass

    def save_config(self, host: str, port: int, username: str, password: str,
                    use_tls: bool, from_email: str, to_email: str,
                    enabled: bool) -> None:
        with self._lock:
            c = self._cfg()
            c.host = (host or "").strip()
            try:
                c.port = max(1, min(65535, int(port)))
            except (TypeError, ValueError):
                c.port = 587
            c.username = (username or "").strip()
            c.password = (password or "")
            c.use_tls = bool(use_tls)
            c.from_email = (from_email or "").strip()
            c.to_email = (to_email or "").strip()
            c.enabled = bool(enabled)
            try:
                self._config.save()
            except Exception as e:
                log_error("Failed to persist SMTP configuration.", e)

    def _connect_send(self, message: EmailMessage, timeout: int = 20) -> None:
        c = self._cfg()
        host = c.host
        port = int(c.port)
        use_tls = bool(c.use_tls)
        username = c.username
        password = c.password
        context = ssl.create_default_context() if use_tls else None
        if use_tls and port in (465,):
            with smtplib.SMTP_SSL(host, port, context=context, timeout=timeout) as smtp:
                if username:
                    smtp.login(username, password)
                smtp.send_message(message)
            return
        with smtplib.SMTP(host, port, timeout=timeout) as smtp:
            smtp.ehlo()
            if use_tls:
                smtp.starttls(context=context)
                smtp.ehlo()
            if username:
                smtp.login(username, password)
            smtp.send_message(message)

    def _send_message(self, subject: str, body: str,
                      recipient: Optional[str] = None) -> bool:
        with self._lock:
            if not self.is_configured():
                self._last_error = (
                    "SMTP is not fully configured. Host, port, sender email and "
                    "recipient email are required."
                )
                log_ids("SMTP send aborted: SMTP is not fully configured.", "WARNING")
                return False
            c = self._cfg()
            msg = EmailMessage()
            msg["Subject"] = subject
            msg["From"] = c.from_email
            msg["To"] = recipient or c.to_email
            msg.set_content(body)
            try:
                self._connect_send(msg)
            except (smtplib.SMTPException, socket.error, OSError, ssl.SSLError) as e:
                self._last_error = str(e)
                log_error(f"SMTP send failed for subject '{subject}'.", e)
                return False
            except Exception as e:
                self._last_error = str(e)
                log_error(f"Unexpected error while sending email: {subject}", e)
                return False
            self._last_error = ""
            log_ids(
                f"SMTP alert sent: '{subject}' -> {msg['To']}",
                "INFO",
            )
            return True

    def send_test_email(self) -> bool:
        ok = self._send_message(TEST_SUBJECT, TEST_BODY)
        if ok:
            log_application("Test email delivered successfully.", "INFO")
        return ok

    def send_alert(self, alert: IDSAlert) -> bool:
        if not self.is_enabled():
            return False
        subject = f"[IDS {alert.severity.value}] {alert.alert_type}"
        body = alert.email_body()
        return self._send_message(subject, body)
