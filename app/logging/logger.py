"""
Logging module with multiple log files and severity levels.
"""

import os
import sys
import logging
import traceback
from logging.handlers import RotatingFileHandler
from typing import Optional
from pathlib import Path

from ..utils.paths import LOGS_DIR, ensure_directory


LOG_LEVELS = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
}

LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)-18s | %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

_LOGGERS_INITIALIZED = False
_ROOT_LOGGER = None


APP_LOG = "application"
CAPTURE_LOG = "capture"
AUTH_LOG = "authentication"
IDS_LOG = "ids"
ERROR_LOG = "error"


def _setup_file_handler(logger_name: str, file_name: str, level: int,
                        log_dir: Path) -> RotatingFileHandler:
    log_path = log_dir / file_name
    handler = RotatingFileHandler(
        str(log_path), maxBytes=5 * 1024 * 1024, backupCount=5,
        encoding="utf-8",
    )
    handler.setLevel(level)
    handler.setFormatter(logging.Formatter(LOG_FORMAT, DATE_FORMAT))
    logger = logging.getLogger(logger_name)
    logger.addHandler(handler)
    return handler


def setup_logging(log_level: str = "INFO", log_dir: Optional[Path] = None) -> logging.Logger:
    global _LOGGERS_INITIALIZED, _ROOT_LOGGER
    if _LOGGERS_INITIALIZED:
        return _ROOT_LOGGER

    log_dir = ensure_directory(log_dir or LOGS_DIR)
    level = LOG_LEVELS.get(str(log_level).upper(), logging.INFO)

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    root.handlers.clear()

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setLevel(max(level, logging.WARNING))
    stream_handler.setFormatter(logging.Formatter(LOG_FORMAT, DATE_FORMAT))
    root.addHandler(stream_handler)

    _setup_file_handler(APP_LOG, "application.log", level, log_dir)
    _setup_file_handler(CAPTURE_LOG, "capture.log", level, log_dir)
    _setup_file_handler(AUTH_LOG, "authentication.log", logging.INFO, log_dir)
    _setup_file_handler(IDS_LOG, "ids.log", logging.INFO, log_dir)
    _setup_file_handler(ERROR_LOG, "error.log", logging.ERROR, log_dir)

    for name in (APP_LOG, CAPTURE_LOG, AUTH_LOG, IDS_LOG, ERROR_LOG):
        logging.getLogger(name).setLevel(logging.DEBUG)
        logging.getLogger(name).propagate = True

    logging.getLogger("scapy").setLevel(logging.WARNING)
    logging.getLogger("matplotlib").setLevel(logging.WARNING)

    _ROOT_LOGGER = root
    _LOGGERS_INITIALIZED = True

    app_log(APP_LOG, logging.INFO, "Application logging subsystem initialized.")
    return root


def _logger(name: str) -> logging.Logger:
    if not _LOGGERS_INITIALIZED:
        setup_logging()
    return logging.getLogger(name)


def app_log(log_name: str, level: int, message: str, *args, **kwargs) -> None:
    logger = _logger(log_name)
    logger.log(level, message, *args, **kwargs)


def log_application(message: str, level: str = "INFO") -> None:
    lvl = LOG_LEVELS.get(str(level).upper(), logging.INFO)
    app_log(APP_LOG, lvl, message)


def log_capture(message: str, level: str = "INFO") -> None:
    lvl = LOG_LEVELS.get(str(level).upper(), logging.INFO)
    app_log(CAPTURE_LOG, lvl, message)


def log_authentication(message: str, level: str = "INFO") -> None:
    lvl = LOG_LEVELS.get(str(level).upper(), logging.INFO)
    app_log(AUTH_LOG, lvl, message)


def log_ids(message: str, level: str = "INFO") -> None:
    lvl = LOG_LEVELS.get(str(level).upper(), logging.INFO)
    app_log(IDS_LOG, lvl, message)


def log_error(message: str, exc_info: Optional[BaseException] = None) -> None:
    logger = _logger(ERROR_LOG)
    if exc_info is not None:
        logger.error(f"{message}\n{''.join(traceback.format_exception(type(exc_info), exc_info, exc_info.__traceback__))}")
    else:
        logger.error(message)


def get_log_path(log_name: str) -> Path:
    mapping = {
        APP_LOG: "application.log",
        CAPTURE_LOG: "capture.log",
        AUTH_LOG: "authentication.log",
        IDS_LOG: "ids.log",
        ERROR_LOG: "error.log",
    }
    return ensure_directory(LOGS_DIR) / mapping.get(log_name, "application.log")


def read_log_tail(log_name: str, lines: int = 200) -> str:
    path = get_log_path(log_name)
    if not path.exists():
        return ""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            content = f.readlines()
        return "".join(content[-lines:])
    except (OSError, IOError):
        return ""
