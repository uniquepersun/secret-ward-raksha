"""Rule-based Devanagari -> Latin transliteration and a phonetic 'skeleton' key.

The skeleton makes Mohammad / Mohd. / Md. / मोहम्मद collapse to the same key, which is what
cross-script name matching and linkage compare. Pure stdlib, deterministic, no model.
"""
import re
import unicodedata

_IND = {  # 1:1 digit maps (same length, so offsets in the original text stay valid)
    **{chr(0x0966 + i): str(i) for i in range(10)},   # Devanagari
    **{chr(0x09E6 + i): str(i) for i in range(10)},   # Bengali
    **{chr(0xFF10 + i): str(i) for i in range(10)},   # full-width
    **{chr(0x0AE6 + i): str(i) for i in range(10)},   # Gujarati
    **{chr(0x0A66 + i): str(i) for i in range(10)},   # Gurmukhi
    **{chr(0x0BE6 + i): str(i) for i in range(10)},   # Tamil
}
_DIGIT_TABLE = str.maketrans(_IND)
_ZW = dict.fromkeys(map(ord, "​‌‍⁠﻿"), None)


def clean(s: str) -> str:
    """Strip zero-width chars and normalise to NFC (output text is always NFC)."""
    return unicodedata.normalize("NFC", s.translate(_ZW))


def ascii_digits(s: str) -> str:
    """Indic/full-width digits -> ASCII. Same length as input."""
    return s.translate(_DIGIT_TABLE)


_V = {"अ": "a", "आ": "aa", "इ": "i", "ई": "ii", "उ": "u", "ऊ": "uu", "ऋ": "ri", "ए": "e", "ऐ": "ai",
      "ओ": "o", "औ": "au", "ऑ": "o", "ऍ": "e"}
_M = {"ा": "aa", "ि": "i", "ी": "ii", "ु": "u", "ू": "uu", "ृ": "ri", "े": "e", "ै": "ai", "ो": "o",
      "ौ": "au", "ॉ": "o", "ॅ": "e"}
_C = {"क": "k", "ख": "kh", "ग": "g", "घ": "gh", "ङ": "n", "च": "ch", "छ": "chh", "ज": "j", "झ": "jh",
      "ञ": "n", "ट": "t", "ठ": "th", "ड": "d", "ढ": "dh", "ण": "n", "त": "t", "थ": "th", "द": "d",
      "ध": "dh", "न": "n", "प": "p", "फ": "f", "ब": "b", "भ": "bh", "म": "m", "य": "y", "र": "r",
      "ल": "l", "व": "v", "श": "sh", "ष": "sh", "स": "s", "ह": "h", "ळ": "l",
      "क़": "q", "ख़": "kh", "ग़": "g", "ज़": "z", "ड़": "d", "ढ़": "dh", "फ़": "f", "य़": "y"}
VIRAMA, NUKTA = "्", "़"
DEV = re.compile(r"[ऀ-ॿ]")


def has_deva(s: str) -> bool:
    return bool(DEV.search(s))


def deva_to_latin(s: str) -> str:
    s = unicodedata.normalize("NFD", s)
    s = unicodedata.normalize("NFC", s)
    out, i, n = [], 0, len(s)
    while i < n:
        ch = s[i]
        if i + 1 < n and s[i + 1] == NUKTA and (ch + NUKTA) in _C:
            ch, i = ch + NUKTA, i + 1
        if ch in _C:
            out.append(_C[ch])
            nxt = s[i + 1] if i + 1 < n else ""
            if nxt == VIRAMA:
                i += 1
            elif nxt in _M:
                out.append(_M[nxt])
                i += 1
            else:
                # inherent 'a', deleted at the end of a word (schwa deletion)
                after = s[i + 1] if i + 1 < n else ""
                if after and "ऀ" <= after <= "ॿ" and after not in "।॥":
                    out.append("a")
        elif ch in _V:
            out.append(_V[ch])
        elif ch in "ंँ":
            out.append("n")
        elif ch == "ः":
            out.append("h")
        elif ch in _M:
            out.append(_M[ch])
        elif ch in (VIRAMA, NUKTA):
            pass
        else:
            out.append(ch)
        i += 1
    return "".join(out)


_DIG = (("chh", "C"), ("sh", "S"), ("ch", "C"), ("kh", "K"), ("gh", "G"), ("th", "T"), ("dh", "D"),
        ("bh", "B"), ("jh", "J"), ("ph", "f"), ("ck", "k"))


def skeleton(token: str) -> str:
    """Phonetic consonant skeleton of one name token (Latin or Devanagari)."""
    t = ascii_digits(token)
    if has_deva(t):
        t = deva_to_latin(t)
    t = unicodedata.normalize("NFKD", t)
    t = "".join(c for c in t if not unicodedata.combining(c)).lower()
    t = re.sub(r"[^a-z]", "", t)
    for a, b in _DIG:
        t = t.replace(a, b)
    t = t.replace("w", "v").replace("z", "j").replace("q", "k").replace("x", "ks")
    t = re.sub(r"[aeiouyh]", "", t)           # vowels and h carry no identity across scripts
    t = re.sub(r"(.)\1+", r"\1", t)
    return t
