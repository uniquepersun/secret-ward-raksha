"""Static, offline inspection of untrusted input bytes. Nothing here executes, imports, unpacks or opens a file:
it only looks at bytes. A file that fails inspection is quarantined with a reason code (never copied raw).

Network lookups of hash reputation (VirusTotal and the like) are deliberately NOT done: any network call during the run is
grounds for disqualification. Instead a hash blocklist ships in data/known_bad_sha256.txt (public test-file hashes; extend it
at setup time if you want a larger offline list).
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

_BLOCKLIST_FILE = Path(__file__).resolve().parent.parent / "data" / "known_bad_sha256.txt"

# The standard antivirus test string (harmless by design; every scanner flags it, so it must never be exported).
EICAR = b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE"

# (magic prefix, reason). Executables, archives, Office/OLE containers, disk images: never parsed, never extracted.
_MAGIC = [
    (b"MZ", "executable_content"), (b"\x7fELF", "executable_content"),
    (b"\xfe\xed\xfa\xce", "executable_content"), (b"\xfe\xed\xfa\xcf", "executable_content"),
    (b"\xce\xfa\xed\xfe", "executable_content"), (b"\xcf\xfa\xed\xfe", "executable_content"),
    (b"\xca\xfe\xba\xbe", "executable_content"), (b"\xca\xfe\xd0\x0d", "executable_content"),
    (b"#!", "script_content"),
    (b"PK\x03\x04", "archive_not_extracted"), (b"PK\x05\x06", "archive_not_extracted"), (b"Rar!\x1a\x07", "archive_not_extracted"),
    (b"7z\xbc\xaf\x27\x1c", "archive_not_extracted"), (b"\x1f\x8b", "archive_not_extracted"), (b"BZh", "archive_not_extracted"),
    (b"\xfd7zXZ\x00", "archive_not_extracted"), (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "office_container"),
    (b"%PDF", "unsupported_format"), (b"\x89PNG", "unsupported_format"), (b"\xff\xd8\xff", "unsupported_format"),
    (b"GIF8", "unsupported_format"), (b"II*\x00", "unsupported_format"), (b"MM\x00*", "unsupported_format"),
    (b"\x00\x00\x01\x00", "unsupported_format"),
]

# Active content inside otherwise-text files (a discharge note has no business containing these).
_ACTIVE = re.compile(
    rb"(?i)<\s*script\b|<\?php|javascript\s*:|\bon(?:error|load)\s*=|powershell(?:\.exe)?\s+-|\biex\s*\(|invoke-expression|"
    rb"cmd(?:\.exe)?\s*/c|wscript\.shell|vbscript|\bcurl\b[^\n]{0,80}\|\s*(?:ba)?sh|\bwget\b[^\n]{0,80}\|\s*(?:ba)?sh|"
    rb"/bin/(?:ba)?sh\s+-c|\bsub\s+auto_?open\b|\bdocument_open\b|\bmshta\b|\bregsvr32\b|base64\s+-d\s*\|")

_blocklist: set[str] | None = None


def blocklist() -> set[str]:
    global _blocklist
    if _blocklist is None:
        try:
            _blocklist = {l.split("#", 1)[0].strip().lower() for l in _BLOCKLIST_FILE.read_text(encoding="utf-8").splitlines()
                          if l.split("#", 1)[0].strip()}
        except OSError:
            _blocklist = set()
    return _blocklist


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def inspect(raw: bytes) -> str | None:
    """Return a reason code if the bytes must not be processed or exported, else None. Pure inspection."""
    if sha256(raw) in blocklist():
        return "known_malware_hash"
    if EICAR in raw or EICAR in raw.replace(b"\x00", b""):          # also catches UTF-16 encodings
        return "malware_signature"
    head = raw[:16]
    if head.startswith(b"MZ"):                                    # a real PE file, not a note that starts with "MZ"
        return "executable_content" if b"PE\x00\x00" in raw[:2048] or b"This program" in raw[:200] else None
    if head.startswith(b"BZh"):
        return "archive_not_extracted" if head[3:4].isdigit() and raw[4:10] == b"1AY&SY" else None
    if head.startswith(b"#!"):
        return "script_content" if re.match(rb"#!\s*/", raw[:64]) else None
    for magic, reason in _MAGIC:
        if magic not in (b"MZ", b"BZh", b"#!") and head.startswith(magic):
            return reason
    if _ACTIVE.search(raw[:5_000_000]):
        return "active_content"
    return None


def inspect_payload(raw: bytes) -> str | None:
    """Same inspection for a decoded attachment (base64 / hex) found inside a text or JSON file."""
    return inspect(raw) or (None if _mostly_text(raw) else "binary_attachment")


def _mostly_text(raw: bytes) -> bool:
    if not raw:
        return True
    try:
        t = raw.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return sum(c.isprintable() or c in "\r\n\t" for c in t) / len(t) >= 0.95


_FORMULA = re.compile(r"^\s*(?:[=@]|[+\-]\s*(?:cmd|powershell|msexcel|hyperlink|dde|exec)\b|[+\-]\s*\d+(?:\.\d+)?\s*[+\-*/]\s*[\d(]|[+\-]\s*\w+\s*\()", re.I)


def neutralise_cell(v: str) -> str:
    """Spreadsheet formula injection (=cmd|'/C calc'!A0, @SUM(...), =HYPERLINK(...)): prefix an apostrophe so no
    spreadsheet program evaluates it. Ordinary numbers such as -5.2 are untouched."""
    return "'" + v if v and _FORMULA.match(v) else v


def percent_decode(s: str) -> str:
    """Local %XX decoder (kept here so no network-capable library such as urllib is imported)."""
    def rep(m):
        return chr(int(m.group(1), 16))
    raw = re.sub(r"%([0-9A-Fa-f]{2})", lambda m: "%%%s" % m.group(1), s)
    try:
        b = re.sub(rb"%([0-9A-Fa-f]{2})", lambda m: bytes([int(m.group(1), 16)]), s.encode("utf-8"))
        return b.decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return raw


_LONG_NONSPACE = re.compile(r"\S{300,}")
_LONG_SPACE = re.compile(r"[ \t\r\n\f\v]{100,}")


def mask_bombs(text: str) -> str:
    """Same-length masking of runs that real documents never contain: 300+ non-space characters (no word or identifier is
    that long) and 100+ whitespace characters. Cue-word-plus-whitespace floods are what make backtracking regexes
    quadratic; once masked they cannot be built. Offsets are unchanged, so spans still map onto the original text."""
    if len(text) < 100:
        return text
    text = _LONG_NONSPACE.sub(lambda m: "\x00" * len(m.group(0)), text)
    return _LONG_SPACE.sub(lambda m: "\x00" * len(m.group(0)), text)
