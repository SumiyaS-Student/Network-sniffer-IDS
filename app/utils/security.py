"""
Security and password utilities using PBKDF2-HMAC.
"""

import hmac
import hashlib
import secrets
import base64
from typing import Tuple, Optional


PBKDF2_ITERATIONS = 200_000
SALT_BYTES = 32
HASH_ALGORITHM = "sha256"


def generate_salt(length: int = SALT_BYTES) -> bytes:
    return secrets.token_bytes(length)


def hash_password(password: str, salt: Optional[bytes] = None) -> Tuple[str, str]:
    if salt is None:
        salt = generate_salt()
    password_bytes = password.encode("utf-8")
    dk = hashlib.pbkdf2_hmac(
        HASH_ALGORITHM,
        password_bytes,
        salt,
        PBKDF2_ITERATIONS,
        dklen=32,
    )
    hash_b64 = base64.b64encode(dk).decode("ascii")
    salt_b64 = base64.b64encode(salt).decode("ascii")
    return hash_b64, salt_b64


def verify_password(password: str, stored_hash: str, stored_salt: str) -> bool:
    try:
        salt = base64.b64decode(stored_salt.encode("ascii"))
        expected_hash_bytes = base64.b64decode(stored_hash.encode("ascii"))
    except (ValueError, base64.binascii.Error):
        return False
    password_bytes = password.encode("utf-8")
    computed = hashlib.pbkdf2_hmac(
        HASH_ALGORITHM,
        password_bytes,
        salt,
        PBKDF2_ITERATIONS,
        dklen=32,
    )
    return hmac.compare_digest(computed, expected_hash_bytes)


def generate_token(length: int = 32) -> str:
    return secrets.token_urlsafe(length)


def constant_time_compare(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def obfuscate_value(value: str, keep_chars: int = 2) -> str:
    if not value:
        return ""
    if len(value) <= keep_chars:
        return "*" * len(value)
    return value[:keep_chars] + "*" * (len(value) - keep_chars)
