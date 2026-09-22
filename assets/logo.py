"""
Application logo generated programmatically with Pillow at runtime.

A small generic cybersecurity-themed placeholder image.
"""

import base64
import io
import os
from typing import Optional


def _generate_logo_png_bytes(size: int = 128) -> bytes:
    try:
        from PIL import Image, ImageDraw  # type: ignore
    except Exception:
        return b""
    w = h = int(size)
    img = Image.new("RGBA", (w, h), (255, 255, 255, 0))
    d = ImageDraw.Draw(img)
    pad = max(2, w // 16)
    try:
        d.rounded_rectangle((pad, pad, w - pad, h - pad), radius=w // 7,
                            fill=(27, 94, 165, 255))
    except Exception:
        d.rectangle((pad, pad, w - pad, h - pad), fill=(27, 94, 165, 255))
    r = w // 2 - pad * 2
    cx = cy = w // 2
    d.ellipse((cx - r, cy - r, cx + r, cy + r),
              outline=(255, 255, 255, 255), width=max(2, w // 25))
    d.line((cx - r + pad, cy, cx + r - pad, cy),
           fill=(255, 255, 255, 255), width=max(2, w // 20))
    d.line((cx, cy - r + pad, cx, cy + r - pad),
           fill=(255, 255, 255, 255), width=max(2, w // 20))
    dot = max(3, w // 18)
    d.ellipse((cx - dot, cy - dot, cx + dot, cy + dot), fill=(46, 125, 50, 255))
    buf = io.BytesIO()
    try:
        img.save(buf, format="PNG")
    except Exception:
        return b""
    return buf.getvalue()


_CACHED_LOGO_BYTES: Optional[bytes] = None


def get_logo_bytes(size: int = 128) -> bytes:
    global _CACHED_LOGO_BYTES
    if _CACHED_LOGO_BYTES is None:
        _CACHED_LOGO_BYTES = _generate_logo_png_bytes(size=size)
    return _CACHED_LOGO_BYTES or b""


def get_logo_image(size: Optional[int] = None):
    try:
        from PIL import Image  # type: ignore
    except Exception:
        return None
    try:
        data = get_logo_bytes(size=size or 128)
        if not data:
            return None
        img = Image.open(io.BytesIO(data))
        if size:
            try:
                img = img.resize((int(size), int(size)), Image.LANCZOS)
            except Exception:
                pass
        return img
    except Exception:
        return None


def get_logo_photoimage(size: Optional[int] = None):
    try:
        from PIL import Image, ImageTk  # type: ignore
    except Exception:
        return None
    img = get_logo_image(size=size)
    if img is None:
        return None
    try:
        return ImageTk.PhotoImage(img)
    except Exception:
        return None


LOGO_BASE64 = ""


def _ensure_base64() -> str:
    global LOGO_BASE64
    if not LOGO_BASE64:
        data = get_logo_bytes()
        if data:
            LOGO_BASE64 = base64.b64encode(data).decode("ascii")
    return LOGO_BASE64
