"""
At-rest credential protection using Windows DPAPI (CryptProtectData).

Encrypted secrets are stored as "<prefix>:<base64>". On non-Windows systems
(or if DPAPI is unavailable) values are stored as-is so the application
remains functional; the plaintext password is then no worse than before.
"""

import base64
import ctypes
import ctypes.wintypes as wt

PREFIX = "dpapi:"
_UI_FORBIDDEN = 0x00000001


class DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", wt.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_char)),
    ]


def _blob(data: bytes):
    buf = ctypes.create_string_buffer(data, len(data))
    blob = DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    return blob, buf


def _protect(data: bytes) -> bytes:
    if not data:
        return b""
    blob_in, _buf = _blob(data)
    blob_out = DATA_BLOB()
    ok = ctypes.windll.crypt32.CryptProtectData(
        ctypes.byref(blob_in), None, None, None, None, _UI_FORBIDDEN,
        ctypes.byref(blob_out),
    )
    if not ok:
        raise OSError(f"CryptProtectData failed (error {ctypes.GetLastError()})")
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)


def _unprotect(data: bytes) -> bytes:
    if not data:
        return b""
    blob_in, _buf = _blob(data)
    blob_out = DATA_BLOB()
    ok = ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(blob_in), None, None, None, None, _UI_FORBIDDEN,
        ctypes.byref(blob_out),
    )
    if not ok:
        raise OSError(f"CryptUnprotectData failed (error {ctypes.GetLastError()})")
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)


def is_available() -> bool:
    try:
        return bool(ctypes.windll.crypt32.CryptProtectData)
    except Exception:
        return False


def encrypt_string(plain: str) -> str:
    if not plain:
        return ""
    if not is_available():
        return plain
    try:
        token = _protect(plain.encode("utf-8"))
        return PREFIX + base64.b64encode(token).decode("ascii")
    except Exception:
        return plain


def decrypt_string(token: str) -> str:
    if not token:
        return ""
    if not token.startswith(PREFIX):
        return token
    try:
        payload = base64.b64decode(token[len(PREFIX):].encode("ascii"))
        return _unprotect(payload).decode("utf-8", errors="replace")
    except Exception:
        return ""
