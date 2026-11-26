"""Quasi-identifier layer: per-patient date shifting, truthful age bands, location generalisation.

Dates shift by one secret per-patient offset (HMAC of the cluster key), so every interval inside a
patient's history is exact (a 9-day stay stays 9 days) while the calendar position is hidden.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import os
import re

import regex as rx

from .security import mask_bombs
from .translit import ascii_digits

_SECRET = os.environ.get("RAKSHA_SECRET", "").encode()  # never printed or written

MONTHS = {m: i + 1 for i, m in enumerate("jan feb mar apr may jun jul aug sep oct nov dec".split())}
MONTHS["sept"] = 9


def configure(secret: bytes):
    global _SECRET
    _SECRET = secret


def shift_days(key: str, max_days: int = 365, min_days: int = 90) -> int:
    """Per-patient secret shift, magnitude in [min_days, max_days] and random sign: never close to zero, so the visit month (and
    usually the year) an attacker may know from gossip or a voter-list story no longer matches. Same shift for one patient."""
    d = hmac.new(_SECRET, b"shift|" + key.encode("utf-8"), hashlib.sha256).digest()
    span = max(1, max_days - min_days + 1)
    mag = min_days + int.from_bytes(d[:4], "big") % span
    return mag if d[4] & 1 else -mag


_ALPH = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def pseudonym(key: str) -> str:
    d = hmac.new(_SECRET, b"psn|" + key.encode("utf-8"), hashlib.sha256).digest()
    n = int.from_bytes(d[:6], "big")
    return "PSN-" + "".join(_ALPH[(n >> (5 * i)) & 31] for i in range(8))


# ------------------------------------------------------------------------------------ dates
_ISO = rx.compile(r"(?<![\d])(\d{4})-(\d{2})-(\d{2})(?:([T ])(\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?)(Z|[+-]\d{2}:?\d{2})?)?(?![\d])")
_NUM = rx.compile(r"(?<![\d.])(\d{1,2})([/.\-])(\d{1,2})\2(\d{4}|\d{2})(?![\d])")
_YMD_SLASH = rx.compile(r"(?<![\d])(\d{4})([/.])(\d{1,2})\2(\d{1,2})(?![\d])")
_WRITTEN = rx.compile(r"(?i)(?<![\d\w])(\d{1,2})(?:st|nd|rd|th)?[\s\-]+(jan|feb|mar|apr|may|jun|jul|aug|sept?|oct|nov|dec)[a-z]*\.?,?[\s\-]+(\d{4})(?![\d])")
_WRITTEN2 = rx.compile(r"(?i)(?<![\w])(jan|feb|mar|apr|may|jun|jul|aug|sept?|oct|nov|dec)[a-z]*\.?\s+(\d{1,2})(?:st|nd|rd|th)?,?\s+(\d{4})(?![\d])")


HI_MONTHS = {"जनवरी": 1, "फरवरी": 2, "फ़रवरी": 2, "मार्च": 3, "अप्रैल": 4, "अप्रेल": 4, "मई": 5, "जून": 6, "जुलाई": 7, "अगस्त": 8,
             "सितंबर": 9, "सितम्बर": 9, "अक्टूबर": 10, "अक्तूबर": 10, "नवंबर": 11, "नवम्बर": 11, "दिसंबर": 12, "दिसम्बर": 12}
_HINDI = rx.compile(r"(?<![\d\w])(\d{1,2})\s+(" + "|".join(sorted(map(rx.escape, HI_MONTHS), key=len, reverse=True)) + r")\s+(\d{4})(?![\d])")


def _safe(y, m, d):
    try:
        return dt.date(y, m, d)
    except ValueError:
        return None


def infer_order(text: str, default: str = "dmy") -> str | None:
    """'dmy' or 'mdy' from unambiguous numeric dates in `text`; None when no evidence."""
    t = ascii_digits(text)
    dmy = mdy = 0
    for m in _NUM.finditer(t):
        a, b = int(m.group(1)), int(m.group(3))
        if a > 12 >= b >= 1:
            dmy += 1
        elif b > 12 >= a >= 1:
            mdy += 1
    if dmy == mdy:
        return None
    return "dmy" if dmy > mdy else "mdy"


def shift_text_dates(text: str, days: int, order: str = "dmy") -> tuple[str, int]:
    """Shift every date in `text` by `days`, preserving each date's own format. Returns (text, n)."""
    if not text:
        return text, 0
    t = ascii_digits(mask_bombs(text))
    edits: list[tuple[int, int, str]] = []

    def add(m, new):
        edits.append((m.start(), m.end(), new))

    for m in _ISO.finditer(t):
        d = _safe(int(m.group(1)), int(m.group(2)), int(m.group(3)))
        if d is None or not (1900 <= d.year <= 2100):
            continue
        n = d + dt.timedelta(days=days)
        s = f"{n.year:04d}-{n.month:02d}-{n.day:02d}"
        if m.group(5):
            s += (m.group(4) or "T") + m.group(5) + (m.group(6) or "")
        add(m, s)
    for m in _NUM.finditer(t):
        a, sep, b, y = int(m.group(1)), m.group(2), int(m.group(3)), m.group(4)
        yy = int(y) if len(y) == 4 else 2000 + int(y)
        if a > 12:
            order_ = "dmy"
        elif b > 12:
            order_ = "mdy"
        else:
            order_ = order
        d, mo = (a, b) if order_ == "dmy" else (b, a)
        dd = _safe(yy, mo, d)
        if dd is None or not (1900 <= yy <= 2100):
            continue
        n = dd + dt.timedelta(days=days)
        p1, p2 = (n.day, n.month) if order_ == "dmy" else (n.month, n.day)
        w1, w2 = len(m.group(1)), len(m.group(3))
        ys = f"{n.year:04d}" if len(y) == 4 else f"{n.year % 100:02d}"
        add(m, f"{p1:0{w1}d}{sep}{p2:0{w2}d}{sep}{ys}")
    for m in _YMD_SLASH.finditer(t):
        d = _safe(int(m.group(1)), int(m.group(3)), int(m.group(4)))
        if d is None:
            continue
        n = d + dt.timedelta(days=days)
        sep = m.group(2)
        add(m, f"{n.year:04d}{sep}{n.month:02d}{sep}{n.day:02d}")
    mon_names = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
    for m in _WRITTEN.finditer(t):
        d = _safe(int(m.group(3)), MONTHS[m.group(2).lower()[:4] if m.group(2).lower() == "sept" else m.group(2).lower()[:3]], int(m.group(1)))
        if d is None:
            continue
        n = d + dt.timedelta(days=days)
        add(m, f"{n.day} {mon_names[n.month - 1]} {n.year}")
    for m in _WRITTEN2.finditer(t):
        d = _safe(int(m.group(3)), MONTHS[m.group(1).lower()[:3]], int(m.group(2)))
        if d is None:
            continue
        n = d + dt.timedelta(days=days)
        add(m, f"{mon_names[n.month - 1]} {n.day}, {n.year}")
    inv = {v: k for k, v in reversed(list(HI_MONTHS.items()))}
    for m in _HINDI.finditer(t):
        d = _safe(int(m.group(3)), HI_MONTHS[m.group(2)], int(m.group(1)))
        if d is None:
            continue
        n = d + dt.timedelta(days=days)
        add(m, f"{n.day} {inv[n.month]} {n.year}")
    if not edits:
        return text, 0
    edits.sort(key=lambda e: (e[0], -(e[1] - e[0])))
    out, pos, n = [], 0, 0
    for s, e, new in edits:
        if s < pos:
            continue
        out.append(text[pos:s])
        out.append(new)
        pos = e
        n += 1
    out.append(text[pos:])
    return "".join(out), n


def parse_date_value(s: str, order: str = "dmy") -> dt.date | None:
    t = ascii_digits(s.strip())
    m = _ISO.fullmatch(t)
    if m:
        return _safe(int(m.group(1)), int(m.group(2)), int(m.group(3)))
    m = _NUM.fullmatch(t)
    if m:
        a, b, y = int(m.group(1)), int(m.group(3)), m.group(4)
        yy = int(y) if len(y) == 4 else 2000 + int(y)
        o = "dmy" if a > 12 else "mdy" if b > 12 else order
        return _safe(yy, b if o == "dmy" else a, a if o == "dmy" else b)
    return None


# ------------------------------------------------------------------------------------ ages
POLICY = {"age_band_years": 5, "age_topcode": 85, "tehsil_level": 1, "pin_digits": 3}


def set_policy(p: dict):
    POLICY.update({k: v for k, v in p.items() if k in POLICY})


def band(age: int) -> str:
    """Truthful band that always contains `age`; open-ended top band hides the very old (rare, unique)."""
    top = int(POLICY["age_topcode"])
    if age >= top:
        return f"{top}+"
    w = int(POLICY["age_band_years"])
    lo = age // w * w
    return f"{lo}-{min(lo + w - 1, top - 1)}"


_AGE_UNIT = r"(?:years?|yrs?\.?|y\b|वर्ष|साल|baras)"
_AGE_PATTERNS = [
    # Age: 47 [Yrs]   Age/Sex: 46 Yrs/M   आयु: 39 वर्ष
    rx.compile(r"(?i)((?:\bage(?:\s*/\s*sex)?|आयु|उम्र|umar|\bumr)\s*[:\-=]?\s*)(\d{1,3})(?![\d/]\d)(?!\s*(?:mg|ml|g|%|/\d))"),
    # 48 Y / F, 46 Yrs/M, 47 yrs female, 52 वर्ष महिला
    rx.compile(r"(?i)(?<![\d.:/\-x×])()(\d{1,3})(?=\s*" + _AGE_UNIT + r"\s*[/,|\-]?\s*(?:m|f|male|female|man|woman|पुरुष|महिला)\b)"),
    # 65/F  58 / M   (age_sex style)
    rx.compile(r"(?<![\d.:/\-x×])()(\d{1,3})(?=\s*/\s*(?:M|F|Male|Female|male|female)\b)"),
    # 47-year-old / 47 year old
    rx.compile(r"(?i)(?<![\d.:/\-x×])()(\d{1,3})(?=[\s\-]*years?[\s\-]*old)"),
]


def band_ages_in_text(text: str) -> tuple[str, int]:
    t = ascii_digits(mask_bombs(text))
    edits = []
    for p in _AGE_PATTERNS:
        for m in p.finditer(t):
            a = int(m.group(2))
            if 0 <= a <= 120:
                edits.append((m.start(2), m.end(2), band(a)))
    if not edits:
        return text, 0
    edits.sort()
    out, pos, n = [], 0, 0
    for s, e, new in edits:
        if s < pos:
            continue
        out.append(text[pos:s])
        out.append(new)
        pos = e
        n += 1
    out.append(text[pos:])
    return "".join(out), n


def band_age_value(v) -> str | None:
    """Structured age cell: '48', 48, '48 वर्ष', '48 Y' -> band string keeping any suffix."""
    s = ascii_digits(str(v)).strip()
    m = re.fullmatch(r"(\d{1,3})(\s*\D*)", s)
    if not m:
        return None
    a = int(m.group(1))
    if not 0 <= a <= 120:
        return None
    return band(a) + m.group(2)
