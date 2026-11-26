"""PII span detection for free text, judged in two views (PII vs medical) with context re-checks.

A span is (start, end, kind, role). kind: ID | NAME | ADDR | VILLAGE | PIN. role (names): patient | relative | other.
Everything here works on the original string; the digit-normalised view has identical length.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

import regex as rx
from rapidfuzz.distance import JaroWinkler

from . import lex
from .translit import ascii_digits, has_deva, skeleton

L = r"[\p{L}\p{M}]"
TOK = rf"{L}+(?:['’\-]{L}+)*\.?"
TITLE_TOK = rf"(?:\p{{Lu}}[\p{{L}}\p{{M}}]*(?:['’\-]{L}+)*\.?|{L}*[\u0900-\u097F]{L}*)"
SEQ_STRONG = rf"{TOK}(?:[ \t]{{1,2}}{TOK}){{0,3}}"
SEQ_TITLE = rf"{TITLE_TOK}(?:[ \t]{{1,2}}{TITLE_TOK}){{0,3}}"
F = rx.IGNORECASE | rx.UNICODE | rx.MULTILINE

# ---------------------------------------------------------------- identifiers (digit view)
_RUN = rx.compile(r"(?<![\w])\+?\(?\d(?:\)?[ \-.]{0,2}\d){5,}(?![\w])")
_MASKED = rx.compile(r"(?<![\w])(?:[Xx*•#]{2,4}[\s\-]?){2}\d{4}(?!\d)|(?<![\w])[Xx*•]{4}[\s-]?[Xx*•]{4}[\s-]?[Xx*•\d]{4}")
_EMAIL = rx.compile(r"[\w.+\-]+@[\w\-]+(?:\.[\w\-]+)+|(?<![\w])[\w.\-]{3,}@(?:abdm|sbx|ndhm|abha)\b", rx.I)
_PAN = rx.compile(r"(?<![A-Za-z0-9])[A-Z]{5}\d{4}[A-Z](?![A-Za-z0-9])")
_ALNUM_ID = rx.compile(r"(?<![\w/\-])(?=[A-Za-z0-9/\-]*\d)[A-Za-z]{2,6}(?:[\-/][A-Za-z0-9]{1,10}){1,4}(?![\w])|"
                       r"(?<![\w])[A-Za-z]{2,5}\d{4,}[A-Za-z0-9]*(?![\w])")
_LABELLED_ID = rx.compile(r"(?i)(?:uhid|mrn|ipd(?:\s*no)?|opd(?:\s*no)?|reg(?:istration)?(?:\s*no)?|patient[\s_]*(?:id|ref)|"
                          r"hosp(?:ital)?[\s_]*id|policy(?:\s*no)?|claim(?:\s*no)?|pmjay|abha|aadhaar|aadhar|uid|pan|"
                          r"आधार|यूएचआईडी|पंजीकरण)[\s_]*(?:no\.?|number|id|संख्या|नंबर)?[\s:#.\-=]*([A-Za-z]{0,6}[\-/]?\d[\dA-Za-z/\-]{3,})")
_DIGITS_AFTER_NAME = rx.compile(r"(?<=[A-Za-z\u0900-\u097F_])_(\d{4,})(?!\d)")
_MEDCODE = rx.compile(r"^(?:[A-Z]\d{2}(?:\.\d+)?|\d{3,5}-\d|[A-Z]{1,3}\d{2,3}[A-Z]?)$")  # ICD / LOINC / package codes
_URL = rx.compile(r"(?i)\b(?:https?://|www\.)\S+")
_DATEISH = rx.compile(r"^\d{1,4}[/\-.]\d{1,2}[/\-.]\d{1,4}$")

# ---------------------------------------------------------------- address pieces
_HOUSE = rx.compile(rf"(?i)(?<![\w])(?:h\.?\s*no\.?|house(?:\s*no\.?)?|makan(?:\s*no\.?)?|flat(?:\s*no\.?)?|plot(?:\s*no\.?)?|"
                    rf"quarter(?:\s*no\.?)?|room\s*no\.?|मकान(?:\s*नं?\.?|\s*नंबर)?|मकान\s*सं\.?|घर\s*नं?\.?)\s*[:\-]?\s*"
                    rf"\d+[A-Za-z]?(?:[/\-]\d+[A-Za-z]?)*")
_LOCALITY = rx.compile(rf"(?i)(?<![\w])(?:(?<=,\s*)ward\s*(?:no\.?)?\s*\d+(?!\s*\()|mohalla\s+{SEQ_TITLE}|mohalle\s+{SEQ_TITLE}|"
                       rf"colony\s+{SEQ_TITLE}|nagar\s+{SEQ_TITLE}|मोहल्ला\s+{TOK}(?:\s+{TOK}){{0,2}}|"
                       rf"वार्ड\s*(?:नं\.?)?\s*\d+|कॉलोनी\s+{TOK}(?:\s+{TOK}){{0,2}})")
_LANDMARK = rx.compile(rf"(?i)(?<![\w])(?:near|opp(?:osite)?\.?|behind|beside|adjacent\s+to|next\s+to|nr\.?)\s+"
                       rf"(?:{TITLE_TOK}(?:\s+{TITLE_TOK}){{0,3}})|"
                       rf"(?:{L}+(?:\s+{L}+){{0,3}})\s+(?:के\s+)?(?:पास|पीछे|सामने|बगल)")
_TEHSIL_CUE = rx.compile(rf"(?i)(?<![\w])(?:tehsil|tahsil|taluk|block|तहसील)\s*[:\-.]?\s*({SEQ_STRONG})")
_VILLAGE_CUE = rx.compile(rf"(?i)(?<![\w])(?:village|vill\.?|gram|gaon|gaanv|grm|ग्राम|गाँव|गांव|मौजा)\s*[:\-.]?\s*({SEQ_STRONG})")
_PIN = rx.compile(r"(?i)(?:pin\s*(?:code)?|postal\s*code|पिन(?:\s*कोड)?)\s*[:\-]?\s*([1-9]\d{5})(?!\d)|"
                  r"(?:(?<=[A-Za-z\u0900-\u097F\)])\s*[\-,]\s*)([1-9]\d{5})(?!\d)")
_BARE_PIN = rx.compile(r"(?<![\d.])[1-9]\d{5}(?![\d.]|\s*(?:mg|ml|g|kg|iu|%))")

# ---------------------------------------------------------------- name cues
_STRONG_LABEL = rx.compile(rf"(?i)(?<![\w])(?:patient(?:['’]s)?[\s_]*name|pt\.?[\s_]*name|name[\s_]*of[\s_]*(?:the[\s_]*)?patient|"
                           rf"full[\s_]*name|first[\s_]*name|last[\s_]*name|name|naam|नाम|मरीज\s*का\s*नाम|रोगी\s*का\s*नाम|"
                           rf"पूरा\s*नाम|nom)\s*[:\-=]\s*({SEQ_STRONG})")
_WEAK_LABEL = rx.compile(rf"(?i)(?<![\w])(?:patient|pt\.?|caller|informant|contact(?:\s*person)?|witness(?:ed)?(?:\s*by)?|"
                         rf"attendant|guardian|visitor|bystander|relative|raised\s*by|called\s*by|signed\s*by|reported\s*by|"
                         rf"requested\s*by|handed\s*over\s*to|spoke\s*(?:to|with)|note\s*for|report\s*(?:for|of)|"
                         rf"record\s*(?:for|of)|letter\s*(?:for|of)|referral\s*for|certificate\s*(?:for|of)|consent\s*(?:of|for)|"
                         rf"mr\.?|mrs\.?|ms\.?|miss|mx|smt\.?|shri|shree|sri|km\.?|kumari|master|baby|late|"
                         rf"श्रीमती|श्री|कुमारी|सुश्री|मास्टर|मरीज|रोगी|पेशेंट|स्व\.?)[\s:.\-]+({SEQ_TITLE})")
_RELATION = rx.compile(rf"(?i)(?<![\w])(?:s\s*/\s*o|d\s*/\s*o|w\s*/\s*o|h\s*/\s*o|c\s*/\s*o|son\s+of|daughter\s+of|wife\s+of|"
                       rf"husband\s+of|father|mother|guardian|spouse|relative|attendant|पुत्र|पुत्री|पत्नी|पति|सुपुत्र|"
                       rf"सुपुत्री|पिता|माता|द्वारा)\b?\.?[\s:\-]*(?:(?:name|naam|नाम)\s*[:\-]?\s*)?(?:श्री(?:मती)?\s+|mr\.?\s+|mrs\.?\s+|smt\.?\s+|shri\s+)?"
                       rf"({SEQ_TITLE})")
_RELATION_LOW = rx.compile(rf"(?i)(?<![\w])(?:s\s*/\s*o|d\s*/\s*o|w\s*/\s*o)\b\.?[\s:\-]*({SEQ_STRONG})")
_SUFFIX = rx.compile(rf"(?<![\w])({SEQ_TITLE})\s+(?:(?i:ji|sahab|saheb|sahib|bhai|bhaiya|bhaiyya|didi|behen|behan|behenji|behnji|"
                     rf"madam|mataji|bhabhi|chacha|chachi|mausi|amma|appa|anna|akka|dada|dadi|nani|nana)|जी|साहब|साहेब|भाई|भैया|दीदी|बहन|"
                     rf"बहनजी|मैडम|माता|भाभी|चाचा|चाची|मौसी|ताई|अम्मा)(?![\w\p{{M}}])")
_ROLE_AFTER = rx.compile(rf"(?<![\w])({SEQ_TITLE})\s*[,(]\s*(?:\(?\s*)?(?i:attendant|relative|visitor|caller|guardian|father|mother|"
                         rf"wife|husband|brother|sister|son|daughter|friend|neighbou?r|patient|pt)\b")
_NAME_PHONE = rx.compile(rf"(?<![\w])({SEQ_TITLE})\s*[,:\-(]?\s*(?:(?i:mob(?:ile)?|ph(?:one)?|tel|contact|cell|call|no\.?)\s*[:.\-]?\s*)?"
                         rf"\+?\(?\d{{3,5}}")
_WA_SENDER = rx.compile(rf"(?m)^\[[^\]\n]{{4,30}}\]\s*({SEQ_STRONG}):")
_DOCTOR_BEFORE = rx.compile(r"(?i)(?:\bdr|\bdoctor|डॉ|डा|डॉक्टर|\bprof)\.?\s*$")
_DOCTOR_PHRASE = rx.compile(rf"(?i)(?<![\w])(?:dr|doctor|डॉ|डा|डॉक्टर|prof)\.?\s*({SEQ_STRONG})")
_HINDI_PARTICLE = rx.compile(rf"(?<![\w\p{{M}}])([\u0900-\u097F\p{{M}}]+(?:\s+[\u0900-\u097F\p{{M}}]+){{0,2}})\s+(?:को|का|की|के|ने)\s")

_TOKEN = rx.compile(rf"{TOK}")


def _valid_run(raw: str, digits: str, groups: list) -> bool:
    """Reject numeric ranges (150000-410000) and over-long runs; accept phone / Aadhaar / ABHA groupings."""
    n = len(digits)
    if n < 8 or n > 14:
        return False
    plus = raw.lstrip().startswith("+")
    if n == 10:
        return digits[0] in "6789" or (len(groups) == 1 and not plus and False)
    if n == 11:
        return digits[0] == "0" and digits[1] in "6789"
    if n == 12:
        if len(groups) == 2 and len(groups[0]) >= 5 and len(groups[1]) >= 5:
            return False
        return True
    if n == 13:
        return plus or digits.startswith(("091", "910"))
    if n == 14:
        return len(groups) in (1, 4, 3)
    return plus


@dataclass
class Span:
    start: int
    end: int
    kind: str          # ID | NAME | ADDR | VILLAGE | PIN
    role: str = ""     # patient | relative | other   (names) / id subtype
    prio: int = 5

    @property
    def length(self) -> int:
        return self.end - self.start


class Lexicon:
    """Corpus-level knowledge learned in pass 1 (names, villages, ids). Built by pipeline."""

    def __init__(self):
        self.name_tokens: dict[str, str] = {}     # casefolded latin/deva token -> role
        self.name_skels: dict[str, str] = {}      # skeleton -> role
        self.generic_skels = {lex_skel for lex_skel in (skeleton(w) for w in lex.GENERIC_NAME_PARTS) if lex_skel}
        self.doctor_tokens: set[str] = set()
        self.village_phr: set[tuple[str, ...]] = set()   # tuples of skeleton tokens
        self.village_skels: set[str] = set()
        self.ids: set[str] = set()                # normalised alnum ids
        self.id_cores: set[str] = set()           # digit cores >=5
        self.phones: set[str] = set()
        self.pins: set[str] = set()
        self.places: set[str] = set()             # casefolded district / tehsil names (kept, never villages)
        self.df: dict[str, int] = {}              # Title-Case sequence -> number of files
        self.dev_common = DEV_COMMON

    # ---- learning
    def add_name(self, value: str, role: str = "patient"):
        for tok in _TOKEN.findall(value or ""):
            t = tok.strip(".'’-")
            if len(t) < 2 or lex.known_nonname(t) or t.lower() in lex.STOP_NAME_TOKENS:
                continue
            tl = t.casefold()
            if tl in lex.HONORIFIC_PRE or tl in lex.HONORIFIC_POST or tl in lex.DOCTOR_PRE:
                continue
            self.name_tokens.setdefault(tl, role)
            sk = skeleton(t)
            if len(sk) >= 2 and sk not in self.generic_skels and t.casefold() not in lex.GENERIC_NAME_PARTS:
                self.name_skels.setdefault(sk, role)

    def add_village(self, value: str):
        toks = tuple(skeleton(t) for t in _TOKEN.findall(value or "") if skeleton(t))
        if toks:
            self.village_phr.add(toks)

    def add_place(self, value: str):
        v = (value or "").strip().casefold()
        if v:
            self.places.add(v)

    def add_id(self, value: str):
        v = ascii_digits(value or "")
        n = re.sub(r"[^A-Za-z0-9]", "", v).upper()
        if len(n) >= 5:
            self.ids.add(n)
            for m in re.findall(r"\d{5,}", n):
                self.id_cores.add(m.lstrip("0") or "0")
        digits = re.sub(r"\D", "", v)
        if len(digits) >= 10:
            self.phones.add(digits[-10:])


DEV_COMMON = frozenset("""
है हैं था थी थे हो हुआ हुई हुए गया गयी गए रहा रही रहे कर करो करना करें किया और या भी नहीं अब अभी जब तब कल आज रात सुबह
दोपहर शाम दिन से तक लिए लेना देना वाला वाली वाले मत दवा दवाई गोली बुखार खांसी खाँसी दर्द पेट सर सिर बहुत थोड़ा ज्यादा कम ठीक अच्छा
बुरा सब कुछ कोई एक दो तीन चार पाँच पांच छह सात आठ नौ दस घर यहाँ वहाँ क्यों कैसे कौन कब कितना पानी खाना नींद उल्टी दस्त मरीज
डॉक्टर अस्पताल आयु उम्र वर्ष साल महीने माह सप्ताह नाम तारीख दिनांक पता ग्राम गाँव जिला तहसील मोबाइल फोन नंबर लिंग पुरुष महिला
रोगी भर्ती छुट्टी जांच जाँच रिपोर्ट सलाह परामर्श भोजन नमक कम खुराक सुबह शाम रात बाद पहले अगले पिछले हफ्ते बजे में पर को का की के ने
ओपीडी पर्चा नर्सिंग वार्ड बिस्तर दिनों दिनो घंटे तक मिलाकर साथ बाद ऊपर नीचे अंदर बाहर सामान्य उच्च निम्न रक्तचाप नाड़ी तापमान
""".split())

_NOT_NAME_FIRST = frozenset("""
the a an of for with and or in on at by to from as is are was were not no yes if when where what who how this that these those
all any each every both some none other another same such only also then than there here
""".split())


def _tok_ok_latin_name(tok: str, strong: bool) -> bool:
    t = tok.strip(".'’-")
    if len(t) < 2 and not (len(tok) == 2 and tok.endswith(".")):   # allow initials like "R."
        return False
    if lex.known_nonname(t):
        return False
    if t.lower() in lex.STOP_NAME_TOKENS or t.lower() in _NOT_NAME_FIRST:
        return False
    if not strong and not (t[:1].isupper() or has_deva(t)):
        return False
    return True


def _trim_seq(text: str, start: int, end: int, strong: bool) -> tuple[int, int]:
    """Shrink a candidate name sequence to the leading run of acceptable tokens."""
    seg = text[start:end]
    keep_end = start
    count = 0
    for m in _TOKEN.finditer(seg):
        tok = m.group(0)
        tl = tok.strip(".'’-").casefold()
        if tl in lex.GENERIC_NAME_PARTS and tl not in ("kumar", "devi", "singh", "kaur", "md", "mohd", "mohammad", "bano", "begum", "khan", "lal", "ram"):
            if count == 0:
                return start, start
            break
        if has_deva(tok):
            if tok in DEV_COMMON or tok in lex.STOP_NAME_TOKENS:
                break
        elif not _tok_ok_latin_name(tok, strong):
            break
        keep_end = start + m.end()
        count += 1
        if count >= 4:
            break
    return (start, keep_end) if keep_end > start else (start, start)


def _is_doctor_context(text: str, pos: int) -> bool:
    return bool(_DOCTOR_BEFORE.search(text[max(0, pos - 14):pos]))


def find_spans(text: str, lx: Lexicon, hint: str = "") -> list[Span]:
    """Detect PII in one string. `hint` is a field-role hint ('' for free text)."""
    if not text or not text.strip():
        return []
    v = ascii_digits(text)
    spans: list[Span] = []

    def add(s, e, kind, role="", prio=5):
        if e > s:
            spans.append(Span(s, e, kind, role, prio))

    urls = [(m.start(), m.end()) for m in _URL.finditer(text)]
    # ---- identifiers --------------------------------------------------------------------
    for m in _EMAIL.finditer(v):
        add(m.start(), m.end(), "ID", "EMAIL", 1)
    for m in _MASKED.finditer(v):
        add(m.start(), m.end(), "ID", "AADHAAR_MASKED", 1)
    for m in _PAN.finditer(v):
        add(m.start(), m.end(), "ID", "PAN", 1)
    for m in _RUN.finditer(v):
        digits = re.sub(r"\D", "", m.group(0))
        groups = re.findall(r"\d+", m.group(0))
        if not _valid_run(m.group(0), digits, groups):
            continue
        if len(digits) >= 10 or (len(digits) >= 8 and m.group(0).lstrip().startswith("+")):
            if _DATEISH.match(m.group(0).strip()):
                continue
            s, e = m.start(), m.end()
            while s < e and v[s] in " (":
                s += 1
            add(s, e, "ID", "NUMBER", 2)
    for m in _LABELLED_ID.finditer(v):
        add(m.start(1), m.end(1), "ID", "LABELLED", 2)
    for m in _ALNUM_ID.finditer(v):
        tok = m.group(0)
        if _MEDCODE.match(tok) or _DATEISH.match(tok):
            continue
        digs = sum(c.isdigit() for c in tok)
        if digs >= 4 or (digs >= 3 and "/" in tok and sum(c.isalpha() for c in tok) >= 2):
            if lex.known_nonname(tok.split("-")[0]) and digs < 6:
                continue
            add(m.start(), m.end(), "ID", "ALNUM", 3)
    for m in _DIGITS_AFTER_NAME.finditer(v):
        add(m.start(1), m.end(1), "ID", "TAIL", 3)
    # learned ids / phones / pins / cores (exact normalised match)
    if lx.id_cores or lx.ids:
        for m in re.finditer(r"[A-Za-z]{0,6}[\-/]?\d[\dA-Za-z/\-]{4,}", v):
            n = re.sub(r"[^A-Za-z0-9]", "", m.group(0)).upper()
            core = (re.sub(r"\D", "", n)).lstrip("0")
            if n in lx.ids or (len(core) >= 5 and core in lx.id_cores and not _DATEISH.match(m.group(0))):
                add(m.start(), m.end(), "ID", "LEARNED", 2)
    for m in _BARE_PIN.finditer(v):
        if m.group(0) in lx.pins:
            add(m.start(), m.end(), "PIN", "PIN", 3)

    # ---- address pieces -----------------------------------------------------------------
    for m in _HOUSE.finditer(text):
        add(m.start(), m.end(), "ADDR", "HOUSE", 3)
    for m in _LOCALITY.finditer(text):
        add(m.start(), m.end(), "ADDR", "LOCALITY", 3)
    for m in _LANDMARK.finditer(text):
        add(m.start(), m.end(), "ADDR", "LANDMARK", 3)
    for m in _PIN.finditer(v):
        g = 1 if m.group(1) else 2
        add(m.start(g), m.end(g), "PIN", "PIN", 3)
    for m in _TEHSIL_CUE.finditer(text):
        s, e = _trim_seq(text, m.start(1), m.end(1), True)
        add(s, e, "TEHSIL", "TEHSIL", 4)
    for m in _VILLAGE_CUE.finditer(text):
        s, e = _trim_seq(text, m.start(1), m.end(1), True)
        add(s, e, "VILLAGE", "VILLAGE", 4)

    # ---- names (cue based) --------------------------------------------------------------
    def add_name(s, e, role, strong, prio=4):
        if e <= s or _is_doctor_context(text, s):
            return
        s2, e2 = _trim_seq(text, s, e, strong)
        if e2 > s2:
            add(s2, e2, "NAME", role, prio)

    for m in _STRONG_LABEL.finditer(text):
        add_name(m.start(1), m.end(1), "patient", True, 3)
    for m in _WEAK_LABEL.finditer(text):
        add_name(m.start(1), m.end(1), "patient", False, 4)
    for m in _RELATION.finditer(text):
        label = m.group(0).lower()
        if re.match(r"\s*(?:c\s*/\s*o|h\s*/\s*o)", label) or label.startswith(("father", "mother", "guardian", "spouse", "relative", "attendant")):
            first = _TOKEN.search(text, m.start(1))
            if first is None or lex.known_nonname(first.group(0)) or not first.group(0)[:1].isupper() and not has_deva(first.group(0)):
                continue
        add_name(m.start(1), m.end(1), "relative", False, 3)
    for m in _RELATION_LOW.finditer(text):
        add_name(m.start(1), m.end(1), "relative", True, 3)
    for m in _SUFFIX.finditer(text):
        add_name(m.start(1), m.end(1), "patient", False, 4)
    for m in _ROLE_AFTER.finditer(text):
        add_name(m.start(1), m.end(1), "other", False, 5)
    for m in _NAME_PHONE.finditer(text):
        s, e = _trim_seq(text, m.start(1), m.end(1), False)
        if e - s > 0 and len(_TOKEN.findall(text[s:e])) >= 2:
            add(s, e, "NAME", "other", 5)
    for m in _WA_SENDER.finditer(text):
        add_name(m.start(1), m.end(1), "other", True, 5)
    if hint in ("name", "patient_name", "relative_name"):
        s, e = _trim_seq(text, 0, len(text), True)
        if e > s and not _is_doctor_context(text, s):
            add(s, e, "NAME", "relative" if hint == "relative_name" else "patient", 2)

    # ---- names (corpus lexicon, cross-script by skeleton) ----------------------------------
    toks_all = list(_TOKEN.finditer(text))
    for ti, m in enumerate(toks_all):
        tok = m.group(0)
        t = tok.strip(".'’-")
        end = m.end()
        poss = re.search(r"['’]s$", t)
        if poss:
            t = t[:poss.start()]
            end = m.start() + len(tok.rstrip(".")) - 2 if tok.endswith(".") is False else end
            end = m.start() + len(t)
        if len(t) < 2:
            continue
        tl = t.casefold()
        deva = has_deva(t)
        hit = None
        if deva:
            if t in DEV_COMMON or t in lex.STOP_NAME_TOKENS:
                continue
            sk = skeleton(t)
            if len(sk) >= 2 and (sk in lx.name_skels):
                hit = lx.name_skels[sk]
        else:
            if not (t[:1].isupper()) or lex.known_nonname(t) or tl in lex.STOP_NAME_TOKENS:
                continue
            if t == "ASHA" and ti + 1 < len(toks_all) and toks_all[ti + 1].group(0).lower() in ("worker", "workers", "didi", "sahayika", "program", "scheme", "visit", "kiran"):
                continue
            if tl in lx.name_tokens:
                hit = lx.name_tokens[tl]
            elif len(t) >= 4:
                sk = skeleton(t)
                if len(sk) >= 2 and sk in lx.name_skels and any(
                        JaroWinkler.similarity(tl, k) >= 0.8 for k in lx.name_tokens if k[:1] == tl[:1] and skeleton(k) == sk):
                    hit = lx.name_skels[sk]
        if hit and not _is_doctor_context(text, m.start()):
            add(m.start(), end, "NAME", hit, 6)
    # village phrases
    if lx.village_phr:
        toks = [(m.start(), m.end(), skeleton(m.group(0))) for m in _TOKEN.finditer(text)]
        for i in range(len(toks)):
            for n in (3, 2, 1):
                seq = tuple(t[2] for t in toks[i:i + n])
                if len(seq) == n and all(seq) and seq in lx.village_phr and (n > 1 or len(seq[0]) >= 3):
                    add(toks[i][0], toks[i + n - 1][1], "VILLAGE", "VILLAGE", 4)
                    break
    # generic last resort: rare Title-Case 2-3 token sequence made of plausible name tokens
    for m in rx.finditer(rf"(?<![\w\p{{M}}])({TITLE_TOK}(?:[ \t]{{1,2}}{TITLE_TOK}){{1,2}})(?![\w\p{{M}}])", text):
        seq = m.group(1)
        toks = [t.strip(".'’-") for t in _TOKEN.findall(seq)]
        if len(toks) < 2 or any(len(t) < 2 or lex.known_nonname(t) for t in toks):
            continue
        if any(has_deva(t) for t in toks):
            continue
        if _is_doctor_context(text, m.start(1)):
            continue
        seed = sum(t.lower() in lex.SEED_GIVEN or t.lower() in lex.SEED_SURNAME for t in toks)
        if seed >= 1 and lx.df.get(seq.casefold(), 0) <= 4:
            add(m.start(1), m.end(1), "NAME", "other", 7)

    spans = [sp for sp in spans if not any(sp.start >= us and sp.end <= ue for us, ue in urls)]
    # doctors stay: protect "Dr. X Y" so neither cues nor the lexicon remove them
    prot = []
    for m in _DOCTOR_PHRASE.finditer(text):
        s2, e2 = _trim_seq(text, m.start(1), m.end(1), True)
        if e2 > s2:
            prot.append((s2, e2))
    spans = [sp for sp in spans if not (sp.kind == "NAME" and any(sp.start < pe and sp.end > ps for ps, pe in prot))]
    return merge_names(text, _resolve(spans))


def doctor_names(text: str) -> list[str]:
    out = []
    for m in _DOCTOR_PHRASE.finditer(text):
        s2, e2 = _trim_seq(text, m.start(1), m.end(1), True)
        if e2 > s2:
            out.append(text[s2:e2])
    return out


def _resolve(spans: list[Span]) -> list[Span]:
    """Longest-first greedy selection; ties go to the more specific (lower prio number) kind."""
    spans = sorted(spans, key=lambda s: (-(s.end - s.start), s.prio, s.start))
    taken: list[Span] = []
    for s in spans:
        if all(s.end <= t.start or s.start >= t.end for t in taken):
            taken.append(s)
    taken.sort(key=lambda s: s.start)
    return taken


def merge_names(text: str, spans: list[Span]) -> list[Span]:
    """Adjacent NAME spans separated only by blanks/dots become one phrase ("Mohd." + "Shahid")."""
    out: list[Span] = []
    for s in spans:
        if out and s.kind == "NAME" and out[-1].kind == "NAME" and re.fullmatch(r"[ \t.]{1,3}", text[out[-1].end:s.start]):
            prev = out[-1]
            role = prev.role if prev.prio <= s.prio else s.role
            out[-1] = Span(prev.start, s.end, "NAME", role, min(prev.prio, s.prio))
        else:
            out.append(s)
    return out
