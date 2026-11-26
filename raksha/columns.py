"""Content-first role inference for CSV columns and JSON key paths.

Header text is only a weak prior: renamed (`Patient's Name`, `Naam`, `Gram/Mohalla`) or Hindi headers still
resolve from what the values look like. Roles:
NAME RELNAME PHONE AADHAAR ABHA PAN EMAIL HID(hospital id) INSID DOB DATE AGE AGESEX SEX VILLAGE TEHSIL DISTRICT
PIN ADDRESS TEXT KEEP
"""
from __future__ import annotations

import re
from collections import Counter

from . import lex
from .translit import ascii_digits, has_deva, skeleton

_H = lambda p: re.compile(p, re.I | re.U)  # noqa: E731

HDR_RELNAME = _H(r"relative|guardian|father|mother|spouse|husband|wife|\bpita\b|\bpati\b|attendant|next.?of.?kin|\bnok\b|"
                 r"care.?of|\bc/?o\b|कर्ता|अभिभावक|पिता|पति|संबंधी|रिश्ते")
HDR_NAME = _H(r"(?:^|[\s_\-.:/])(name|naam|nm|patient|pt|full|first|last|given|family|surname|local|middle|caller|"
              r"contact.?person|informant|नाम|मरीज|रोगी)(?:$|[\s_\-.:/'’s])")
HDR_NONPERSON = _H(r"hospital|facility|lab|test|drug|medic|ward|dept|department|diagnos|display|title|system|file|"
                   r"form|panel|package|procedure|payer|insurer|company|city.?name|organisation|organization|"
                   r"clinic|source|unit|category|type|schema|status|consultant|doctor|physician|referr?ed|practitioner|"
                   r"author|ref.?doc|\bdr\b|औषधि|दवा|अस्पताल")
HDR_DOCTOR = _H(r"doctor|consultant|physician|practitioner|referr?ed.?by|ref.?doctor|author|\bdr\b|surgeon|डॉक्टर")
HDR_CODE = _H(r"package|procedure|code|coding|loinc|snomed|icd|cpt|system|schema|version|\bunit\b|range")
HDR_PHONE = _H(r"phone|mobile|mob\b|cell|contact|tel|callback|whatsapp|फोन|मोबाइल|संपर्क|दूरभाष")
HDR_AADHAAR = _H(r"aadhaar|aadhar|adhar|uid\b|आधार")
HDR_ABHA = _H(r"abha|health.?id|healthid|ndhm|abdm")
HDR_PAN = _H(r"\bpan\b|pan.?no|pan.?card")
HDR_EMAIL = _H(r"e.?mail|mail.?id")
HDR_HID = _H(r"uhid|mrn|\bmr.?no|ipd|opd.?no|reg.?no|registration|patient.?(?:id|ref)|hosp(?:ital)?.?id|\bid\b|"
             r"ref(?:erence)?\b|admission.?no|adm.?no|case.?no|file.?no|record.?no|पंजीकरण|यूएचआईडी|क्रमांक")
HDR_INSID = _H(r"pmjay|policy|insurance|claim|payer.?id|card.?no|beneficiary|scheme.?id")
HDR_DOB = _H(r"dob|birth|janm|जन्म|d\.o\.b")
HDR_DATE = _H(r"date|dt\b|tithi|tarikh|तारीख|तिथि|दिनांक|admitted|discharged|collected|reported|timestamp|generated|_on$|_at$|\bon\b")
HDR_AGE = _H(r"\bage\b|umar|umr|aayu|ayu|आयु|उम्र|years?\b|\byrs?\b")
HDR_SEX = _H(r"\bsex\b|gender|ling\b|लिंग|जेंडर")
HDR_VILLAGE = _H(r"village|vill\b|gram|gaon|gaanv|mohalla|locality|area|colony|hamlet|ग्राम|गाँव|गांव|मोहल्ला|city$|town")
HDR_TEHSIL = _H(r"tehsil|tahsil|taluk|block|तहसील")
HDR_DISTRICT = _H(r"district|distt|jila|zila|जिला|state|राज्य")
HDR_PIN = _H(r"\bpin\b|pin.?code|pincode|zip|postal|पिन")
HDR_ADDRESS = _H(r"address|addr|pata|line|street|residence|पता|निवास")

_PHONE_V = re.compile(r"^\+?\(?(?:91|0)?\)?[\s\-.]?[6-9]\d{4}[\s\-.]?\d{5}$")
_AADH_V = re.compile(r"^[2-9]\d{3}[\s\-]?\d{4}[\s\-]?\d{4}$")
_MASK_V = re.compile(r"^(?:[Xx*•]{2,4}[\s\-]?){2}\d{4}$")
_ABHA_V = re.compile(r"^\d{2}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}$")
_PAN_V = re.compile(r"^[A-Z]{5}\d{4}[A-Z]$")
_EMAIL_V = re.compile(r"^[\w.+\-]+@[\w\-]+(?:\.[\w\-]+)+$")
_ID_V = re.compile(r"^(?=.*\d)(?:[A-Za-z]{1,6}[\-/ ]?)?(?:[A-Za-z0-9]{1,8}[\-/])*\d{3,}[A-Za-z0-9]*$")
_PIN_V = re.compile(r"^[1-9]\d{5}$")
_DATE_V = re.compile(r"^\d{1,4}[/\-.]\d{1,2}[/\-.]\d{1,4}(?:[T ].*)?$")
_AGE_V = re.compile(r"^\d{1,3}\s*(?:years?|yrs?\.?|y|वर्ष|साल)?$", re.I)
_AGESEX_V = re.compile(r"^\d{1,3}\s*/\s*[MFmf]$|^\d{1,3}\s*(?:y|yrs?)?\s*/\s*[MFmf]$", re.I)
_SEX_VALS = {"m", "f", "male", "female", "other", "o", "t", "पुरुष", "महिला", "स्त्री", "पु", "म", "man", "woman", "boy", "girl"}
_NAMEY = re.compile(r"^(?:[\p{Lu}\p{Lo}][\p{L}\p{M}'’\-.]*)(?:\s+[\p{L}\p{M}'’\-.]+){0,4}$".replace(r"\p{Lu}", "A-Z").replace(r"\p{Lo}", "ऀ-ॿ").replace(r"\p{L}", "A-Za-zऀ-ॿ").replace(r"\p{M}", "ऀ-ॿ"))
_ADDR_V = re.compile(r"(?i)\b(?:h\.?no|house|makan|ward|mohalla|near|opp|tehsil|distt|gali|colony|nagar|road|marg|c/o)\b|मकान|मोहल्ला|वार्ड|तहसील")


def norm_header(h: str) -> str:
    return re.sub(r"\s+", " ", (h or "").replace("_", " ")).strip()


def is_namey(v: str) -> bool:
    v = v.strip()
    if not v or len(v) > 60 or any(c.isdigit() for c in ascii_digits(v)):
        return False
    if re.search(r"[,;:()/\[\]]", v):
        return False
    if not _NAMEY.match(v):
        return False
    toks = [t for t in re.split(r"\s+", v) if t]
    if len(toks) > 5:
        return False
    return not any(lex.known_nonname(t.strip(".")) for t in toks)


def _share(vals, pred) -> float:
    return sum(1 for v in vals if pred(v)) / len(vals) if vals else 0.0


def infer_role(header: str, values: list, known_names=None) -> str:
    """Return a role for one column / key path. `values` may hold non-strings (JSON)."""
    h = norm_header(header)
    sv = [str(v).strip() for v in values if v is not None and str(v).strip() != ""]
    if not sv:
        return "KEEP"
    sv = sv[:400]
    dv = [ascii_digits(v) for v in sv]
    n = len(sv)

    if _share(dv, lambda v: bool(_AGESEX_V.match(v))) >= 0.6:
        return "AGESEX"
    if _share(dv, lambda v: bool(_EMAIL_V.match(v))) >= 0.5:
        return "EMAIL"
    if _share(dv, lambda v: bool(_PAN_V.match(v))) >= 0.5:
        return "PAN"
    if _share(dv, lambda v: bool(_MASK_V.match(v))) >= 0.5:
        return "AADHAAR"
    digs = [re.sub(r"\D", "", v) for v in dv]
    if _share(dv, lambda v: bool(_ABHA_V.match(v)) and len(re.sub(r"\D", "", v)) == 14) >= 0.5:
        return "ABHA"
    if _share(dv, lambda v: bool(_AADH_V.match(v))) >= 0.6 and not HDR_PHONE.search(h):
        return "AADHAAR"
    if _share(dv, lambda v: bool(_PHONE_V.match(v))) >= 0.6:
        return "PHONE"
    if HDR_PHONE.search(h) and _share(digs, lambda d: len(d) >= 10) >= 0.5:
        return "PHONE"
    if HDR_AADHAAR.search(h) and _share(digs, lambda d: len(d) >= 8) >= 0.4:
        return "AADHAAR"
    if HDR_ABHA.search(h) and _share(digs, lambda d: len(d) >= 12) >= 0.4:
        return "ABHA"
    if _share(dv, lambda v: bool(_PIN_V.match(v))) >= 0.7 and (HDR_PIN.search(h) or not HDR_HID.search(h)):
        return "PIN"
    if _share(dv, lambda v: bool(_DATE_V.match(v))) >= 0.6:
        return "DOB" if HDR_DOB.search(h) else "DATE"
    if HDR_DOB.search(h) and _share(dv, lambda v: bool(_DATE_V.match(v)) or bool(re.match(r"^\d{4}$", v))) >= 0.4:
        return "DOB"
    if HDR_INSID.search(h) and _share(dv, lambda v: bool(_ID_V.match(v))) >= 0.4:
        return "INSID"
    if _share(dv, lambda v: bool(_ID_V.match(v)) and len(v) >= 6) >= 0.7:
        if HDR_CODE.search(h) and not HDR_HID.search(h):
            return "KEEP"
        return "HID" if not HDR_INSID.search(h) else "INSID"
    if HDR_AGE.search(h) and _share(dv, lambda v: bool(_AGE_V.match(v))) >= 0.6:
        return "AGE"
    if _share([v.lower() for v in sv], lambda v: v in _SEX_VALS) >= 0.8:
        return "SEX"
    if HDR_PIN.search(h) and _share(dv, lambda v: bool(re.match(r"^\d{3,6}", v))) >= 0.5:
        return "PIN"
    long_share = _share(sv, lambda v: len(v) > 45 or v.count(" ") >= 5)
    if _share(sv, lambda v: bool(_ADDR_V.search(v))) >= 0.3 or (HDR_ADDRESS.search(h) and long_share >= 0.3):
        return "ADDRESS"
    if long_share >= 0.3:
        return "TEXT"

    doctorish = HDR_DOCTOR.search(h) or _share(sv, lambda v: bool(re.match(r"(?i)^\s*(dr|doctor|डॉ)\b", v))) >= 0.5
    if doctorish:
        return "KEEP"
    nameshape = _share(sv, is_namey)
    namehits = 0.0
    if known_names is not None and nameshape >= 0.5:
        namehits = _share(sv, lambda v: any(skeleton(t) in known_names for t in re.split(r"[\s.]+", v) if len(t) >= 3))
    seedhits = _share(sv, lambda v: any(t.lower().strip(".") in lex.SEED_GIVEN or t.lower().strip(".") in lex.SEED_SURNAME
                                        for t in re.split(r"\s+", v)))
    hdr_name = bool(HDR_NAME.search(h)) and not HDR_NONPERSON.search(h)
    if HDR_VILLAGE.search(h) and not hdr_name and nameshape >= 0.4:
        return "VILLAGE"
    hdr_rel = bool(HDR_RELNAME.search(h))
    if nameshape >= 0.6 and (hdr_name or hdr_rel or namehits >= 0.4 or seedhits >= 0.3):
        return "RELNAME" if hdr_rel else "NAME"
    if hdr_name and nameshape >= 0.3:
        return "RELNAME" if hdr_rel else "NAME"
    if hdr_name and HDR_NAME.search(h) and not HDR_NONPERSON.search(h) and _share(sv, lambda v: bool(re.search(r"[\p{L}]".replace(r"\p{L}", "A-Za-zऀ-ॿ"), v))) >= 0.8 and n >= 1:
        return "RELNAME" if hdr_rel else "NAME"
    if HDR_VILLAGE.search(h) and nameshape >= 0.4:
        return "VILLAGE"
    if HDR_TEHSIL.search(h):
        return "TEHSIL"
    if HDR_DISTRICT.search(h):
        return "DISTRICT"
    # unlabelled low-cardinality place-like column of short Title-case words stays (district/dept/etc.)
    return "KEEP"


def column_values(rows: list[list[str]], j: int) -> list[str]:
    return [r[j] for r in rows if j < len(r)]
