"""
Common utilities for the application.
"""

from .paths import (
    PROJECT_ROOT, APP_DIR, ASSETS_DIR, DATA_DIR, TESTS_DIR, DOCS_DIR,
    LOGS_DIR, CAPTURES_DIR, REPORTS_DIR, CONFIG_FILE, ENV_FILE, ENV_EXAMPLE_FILE,
    ensure_directory, ensure_all_directories, safe_filename, unique_path,
)
from .security import (
    hash_password, verify_password, generate_token,
    constant_time_compare, obfuscate_value,
)
from .time_utils import (
    now_iso, now_utc_iso, now_epoch, format_timestamp,
    format_hms, elapsed_since, humanize_bytes, short_moment,
)

__all__ = [
    "PROJECT_ROOT", "APP_DIR", "ASSETS_DIR", "DATA_DIR", "TESTS_DIR", "DOCS_DIR",
    "LOGS_DIR", "CAPTURES_DIR", "REPORTS_DIR", "CONFIG_FILE", "ENV_FILE",
    "ENV_EXAMPLE_FILE", "ensure_directory", "ensure_all_directories",
    "safe_filename", "unique_path",
    "hash_password", "verify_password", "generate_token",
    "constant_time_compare", "obfuscate_value",
    "now_iso", "now_utc_iso", "now_epoch", "format_timestamp",
    "format_hms", "elapsed_since", "humanize_bytes", "short_moment",
]
