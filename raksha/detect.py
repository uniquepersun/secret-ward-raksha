"""PII span detection for free text, judged in two views (PII vs medical) with context re-checks.

A span is (start, end, kind, role). kind: ID | NAME | ADDR | VILLAGE | PIN. role (names): patient | relative | other.
Everything here works on the original string; the digit-normalised view has identical length.
"""
from __future__ import annotations

import re
import signal
import threading
from dataclasses import dataclass

import regex as rx
from rapidfuzz.distance import JaroWinkler

from . import lex
from .security import mask_bombs
from .translit import ascii_digits, has_deva, skeleton

REGEX_TIMEOUT = 5.0           # seconds per regex call (interrupts the engine itself; SIGALRM cannot)


class _TP:
    """Compiled pattern whose every call carries the regex module's own timeout."""
    __slots__ = ("p",)

    def __init__(self, p):
        self.p = p

    def _call(self, name, *a, **k):
        try:
            return getattr(self.p, name)(*a, timeout=REGEX_TIMEOUT, **k)
        except TimeoutError:
            raise SpanTimeout()

    def finditer(self, *a, **k):
        it = self._call("finditer", *a, **k)
        try:
            while True:
                yield next(it)
        except StopIteration:
            return
        except TimeoutError:
            raise SpanTimeout()

    def search(self, *a, **k):
        return self._call("search", *a, **k)

    def match(self, *a, **k):
        return self._call("match", *a, **k)

    def fullmatch(self, *a, **k):
        return self._call("fullmatch", *a, **k)

    def sub(self, *a, **k):
        return self._call("sub", *a, **k)

    def findall(self, *a, **k):
        return self._call("findall", *a, **k)


def _tc(*a, **k):
    return _TP(rx.compile(*a, **k))


L = r"[\p{L}\p{M}]"
TOK = rf"{L}+(?:['’\-]{L}+)*\.?"
TITLE_TOK = rf"(?:\p{{Lu}}[\p{{L}}\p{{M}}]*(?:['’\-]{L}+)*\.?|{L}*[\u0900-\u097F]{L}*)"
SEQ_STRONG = rf"{TOK}(?:[ \t]{{1,2}}{TOK}){{0,3}}"
SEQ_TITLE = rf"{TITLE_TOK}(?:[ \t]{{1,2}}{TITLE_TOK}){{0,3}}"
F = rx.IGNORECASE | rx.UNICODE | rx.MULTILINE

# ---------------------------------------------------------------- identifiers (digit view)
_RUN = _tc(r"(?<![\d])\+?\(?\d(?:\)?[ \-.]{0,2}\d){5,}(?![\d])")
_MASKED = _tc(r"(?<![\w])(?:[Xx*•#]{2,4}[\s\-]?){2}\d{4}(?!\d)|(?<![\w])[Xx*•]{4}[\s-]?[Xx*•]{4}[\s-]?[Xx*•\d]{4}")
_EMAIL_OBF = _tc(r"(?i)\b[\w.+\-]{1,}\s*(?:\[at\]|\(at\)|\{at\}|\sat\s)\s*[\w\-]{2,}\s*(?:\[dot\]|\(dot\)|\{dot\}|\sdot\s)\s*[a-z]{2,}\b")
_EMAIL = _tc(r"(?<![\w.+\-])[\w.+\-]+@[\w\-]+(?:\.[\w\-]+)+|(?<![\w])[\w.\-]{3,}@(?:abdm|sbx|ndhm|abha)\b", rx.I)
_MASKED_PHONE = _tc(r"(?<![\w])(?:\+?91[\s-]?)?[6-9]\d[Xx*\u2022]{4,7}\d{2,4}(?![\w])")
_IPV4 = _tc(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d]|\.\d)")
_HANDLE = _tc(r"(?<![\w@.])@[A-Za-z][\w.]{2,29}(?![\w@])")
_GEO = _tc(r"(?<![\d.])-?\d{1,3}\.\d{4,}\s*[,/;]\s*-?\d{1,3}\.\d{4,}(?![\d])")
_PAN = _tc(r"(?<![A-Za-z0-9])[A-Z]{5}\d{4}[A-Z](?![A-Za-z0-9])")
_ALNUM_ID = _tc(r"(?<![\w/\-])(?=[A-Za-z0-9/\-]*\d)[A-Za-z]{2,6}(?:[\-/][A-Za-z0-9]{1,10}){1,4}(?![\w])|"
                       r"(?<![\w])[A-Za-z]{2,5}\d{4,}[A-Za-z0-9]*(?![\w])")
_LABELLED_ID = _tc(r"(?i)(?<![A-Za-z])(?:uhid|mrn|ipd(?:\s*no)?|opd(?:\s*no)?|reg(?:istration)?(?:\s*no)?|patient[\s_]*(?:id|ref)|"
                          r"hosp(?:ital)?[\s_]*id|policy(?:\s*no)?|claim(?:\s*no)?|pmjay|abha|aadhaar|aadhar|uid|pan|"
                          r"आधार|यूएचआईडी|पंजीकरण)[\s_]*(?:no\.?|number|id|संख्या|नंबर)?[\s:#.\-=]*([A-Za-z]{0,6}[\-/]?\d[\dA-Za-z/\-]{3,})")
_DIGITS_AFTER_NAME = _tc(r"(?<=[A-Za-z\u0900-\u097F_])_(?!(?:19|20)\d\d(?!\d))(\d{4,})(?!\d)")   # a 4-digit year in a file name is not an id
_MEDCODE = _tc(r"^(?:[A-Z]\d{2}(?:\.\d+)?|\d{3,5}-\d|[A-Z]{1,3}\d{2,3}[A-Z]?)$")  # ICD / LOINC / package codes
_PHONE_CUE = _tc(r"(?i)(?:mob(?:ile)?|ph(?:one)?|tel|contact|cell|call|whatsapp|no\.?)\s*[:.\-]?\s*$")
_SPLIT_PHONE = _tc(r"(?<![\d])[6-9]\d{4}[ \t]*\r?\n[ \t]*\d{5}(?![\d])")
_DW_EN = r"(?:zero|one|two|three|four|five|six|seven|eight|nine|oh)"
_DW_HI = r"(?:शून्य|एक|दो|तीन|चार|पांच|पाँच|छह|छः|सात|आठ|नौ)"
_DW_RO = r"(?:shunya|sifar|ek|do|teen|char|chaar|paanch|panch|chhe|chheh|chhah|saat|aath|nau)"
_DIGIT_WORDS = _tc(rf"(?i)(?<![\w\p{{M}}])(?:{_DW_EN}(?:[ ,\-]+{_DW_EN}){{9,13}}|{_DW_HI}(?:[ ,\-]+{_DW_HI}){{9,13}}|{_DW_RO}(?:[ ,\-]+{_DW_RO}){{9,13}})(?![\w\p{{M}}])")
_SPACED = _tc(r"(?<![\w])(?:\p{L}[ .\-_]){4,}\p{L}(?![\w])")
_CUE_THEN_WORD = _tc(r"(?i:\b(?:said|says|told|informed|named|called|neighbou?r|friend|brother|sister|uncle|aunt|cousin|nephew|niece|colleague|boss|landlord|driver|maid|son|daughter|wife|husband|mother|father|(?:son|daughter|brother|sister|mother|father)-in-law)\s+)(\p{Lu}\p{Ll}{3,})(?![\p{L}\p{M}])")
_UUID = _tc(r"(?i)(?<![0-9a-f])[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?![0-9a-f])")
_URL = _tc(r"(?i)\b(?:https?://|www\.)[^\s\"'<>)\]]+|(?<![0-9a-f])[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?![0-9a-f])")  # URLs and UUIDs are never PII
_DATEISH = _tc(r"^\d{1,4}[/\-.]\d{1,2}[/\-.]\d{1,4}$")

# ---------------------------------------------------------------- address pieces
_HOUSE = _tc(rf"(?i)(?<![\w])(?:h\.?\s*no\.?|house(?:\s*(?:no\.?|number))?|ghar\s*(?:no\.?|number|sankhya)?|makan(?:\s*no\.?)?|flat(?:\s*no\.?)?|plot(?:\s*no\.?)?|"
                    rf"quarter(?:\s*no\.?)?|room\s*no\.?|मकान(?:\s*नंबर|\s*नं?\.?)?|मकान\s*सं\.?|घर\s*नं?\.?|घर\s*क्र\.?|मकान\s*क्र\.?|घर\s*नंबर)\s*(?:[:\-]\s*)?"
                    rf"\d+[A-Za-z]?(?:[/\-]\d+[A-Za-z]?)*")
_LOCALITY = _tc(rf"(?i)(?<![\w])(?:(?<!\bbed\s*\d{1,3}\s*,\s*)ward(?<=,\s*ward)\s*(?:no\.?\s*)?\d+(?!\s*[(/]|\s+bed\b|\s*[,\-]\s*bed\b|\s*(?:icu|ward)\b)|mohalla\s+{SEQ_TITLE}|mohalle\s+{SEQ_TITLE}|"
                       rf"colony\s+{SEQ_TITLE}|nagar\s+{SEQ_TITLE}|मोहल्ला\s+{TOK}(?:\s+{TOK}){{0,2}}|"
                       rf"वार्ड\s*(?:नं\.?\s*)?\d+|कॉलोनी\s+{TOK}(?:\s+{TOK}){{0,2}})")
_LANDMARK = _tc(rf"(?i)(?<![\w])(?:near|opp(?:osite)?\.?|behind|beside|adjacent\s+to|next\s+to|nr\.?)\s+"
                       rf"(?:{TITLE_TOK}(?:\s+{TITLE_TOK}){{0,3}})|"
                       rf"(?<![\w\p{{M}}])(?:{L}+(?:\s+{L}+){{0,3}})\s+(?:के\s+)?(?:पास|पीछे|सामने|बगल)")
_TEHSIL_CUE = _tc(rf"(?i)(?<![\w])(?:tehsil|tahsil|taluk|block|तहसील)\s*(?:[:\-.]\s*)?({SEQ_STRONG})")
_VILLAGE_CUE = _tc(rf"(?i)(?<![\w])(?:village|vill\.?|gram|gaon|gaanv|grm|ग्राम|गाँव|गांव|गाव|मौजा)\s*(?:[:\-.]\s*)?({SEQ_STRONG})")
_PIN = _tc(r"(?i)(?:pin\s*(?:code)?|postal\s*code|पिन(?:\s*कोड)?)\s*(?:[:\-]\s*)?([1-9]\d{5})(?!\d)|"
                  r"(?:(?<=[A-Za-z\u0900-\u097F\)])\s*[\-,]\s*)([1-9]\d{5})(?!\d)")
_RELWORD_BEFORE = _tc(r"(?i)(?:father|mother|husband|wife|spouse|guardian|relative|attendant|son|daughter|brother|sister|kin|caregiver|care-giver|pita|patni|pati|bhai|behen|माता|पिता|पति|पत्नी)(?:'?s)?[\s_\-]*(?:of)?[\s_\-]*$")
_RELWORD_INSIDE = _tc(r"(?i)^(?:father|mother|husband|wife|spouse|guardian|relative|attendant|kin|caregiver)(?:'?s)?[\s_\-]*name")
_DEVTOK = r"(?:[\u0900-\u097F]{2,})"
_DEVSEQ = rf"{_DEVTOK}(?:[ \t]{{1,2}}{_DEVTOK}){{0,2}}"
_DEV_REL = "पिताजी|पिता जी|माताजी|माता जी|बेटे|बेटों|भैया|बेटी|बेटा|पुत्र|पुत्री|भाई|बहन|माँ|मां|माता|पिता|पति|पत्नी|ससुर|सास|दादा|दादी|चाचा|चाची|मामा|मौसी|बहू|दामाद|देवर|भाभी|बच्चा|बच्ची"
_DEV_AFTER_REL = _tc(rf"(?<![\w\p{{M}}])(?:{_DEV_REL})\s*[-:–]?\s*({_DEVSEQ})")
_DEV_BEFORE_REL = _tc(rf"(?<![\w\p{{M}}])({_DEVSEQ})\s+(?:की|का|के)\s+(?:{_DEV_REL})(?![\w\p{{M}}])")
_DEV_PT = _tc(rf"(?<![\w\p{{M}}])(?:रोगी|मरीज़?|पेशेंट|अटेंडेंट|परिजन|देखभालकर्ता)\s*(?:का\s*नाम)?\s*[:\-–]\s*({_DEVSEQ})")
_ORG_CUE = _tc(rf"(?i)(?<![\w])(?:employer|company|workplace|works?\s+(?:at|for)|employed\s+(?:at|by)|studies\s+at|studying\s+at|college|school|university)\s*[:\-]?\s*({SEQ_TITLE})")
_ADDR_END = _tc(r"(?i)\.\s+\p{Lu}|;|(?<![\w])(?:was|is|were|with|admitted|who|presented|came|has|had|complains|reports|since)(?![\w])")
_ADDR_LABEL = _tc(r"(?i)(?<![\w\p{M}])(?:address|resident\s+of|residing\s+at|resides\s+at|r/o|पता|निवास|पते)\s*(?:\([^)\n]{0,30}\))?\s*[:\-–]?\s*([^\n]{3,160})")
_KEEP_SEG = _tc(r"(?i)^\s*(?:tehsil|tahsil|distt?\.?|district|dist\.?|zila|जिला|तहसील)\b|\[")
_DEV_SURNAMES = frozenset("यादव शर्मा वर्मा गुप्ता सिंह कुमार मिश्रा पांडे पाण्डेय तिवारी चौहान पटेल खान अंसारी सिद्दीकी राजपूत निषाद पासवान कुशवाहा मौर्य ठाकुर जैन अग्रवाल श्रीवास्तव दुबे शुक्ला त्रिपाठी बानो खातून देवी कौर बेगम".split())
_NEXTWORD = _tc(r"[ \t]+(\p{L}+)")
_MEDICAL_ONLY = lex.LABS | lex.DRUGS | lex.DISEASES | lex.UNITS | lex.DOSAGE_FORMS | lex.ANATOMY | lex.PROCEDURES | lex.ABBREV
_GAON = _tc(r"(?<![\w\p{M}])(\p{Lu}[\p{L}]{2,}(?:\s+\p{Lu}[\p{L}]{2,})?)\s+(?i:gaon|gaanv|gram|village|vill\.?)(?![\w\p{M}])")
_PLACE_PIN = _tc(r"(?<![\w.,])(\p{Lu}[\p{L}]{2,})\s+([1-8]\d{5})(?![\d.,]|\s*(?:mg|ml|g|kg|iu|/|%|cells|per|x10|u/l|/ul))")
_BARE_PIN = _tc(r"(?<![\d.])[1-9]\d{5}(?![\d.]|\s*(?:mg|ml|g|kg|iu|%))")

# ---------------------------------------------------------------- name cues
_STRONG_LABEL = _tc(rf"(?i)(?<![\w])(?:patient(?:['’]s)?[\s_]*name|pt\.?[\s_]*name|name[\s_]*of[\s_]*(?:the[\s_]*)?patient|"
                           rf"full[\s_]*name|first[\s_]*name|last[\s_]*name|name|naam|नाम|मरीज\s*का\s*नाम|रोगी\s*का\s*नाम|रुग्णाचे\s*(?:नाव|नांव)|पेशंटचे\s*नाव|नाव|नांव|रुग्णाचे\s*(?:नाव|नांव)|पेशंटचे\s*नाव|नाव|नांव|"
                           rf"पूरा\s*नाम|nom)\s*[:\-=]\s*({SEQ_STRONG})")
_WEAK_LABEL = _tc(rf"(?i)(?<![\w])(?:patient|pt\.?|note\s*for|report\s*(?:for|of)|record\s*(?:for|of)|letter\s*(?:for|of)|"
                         rf"referral\s*for|certificate\s*(?:for|of)|consent\s*(?:of|for)|admitted\s*:|"
                         rf"mr\.?|mrs\.?|ms\.?|miss|mx|smt\.?|shri|shree|sri|km\.?|kumari|master|baby|late|"
                         rf"श्रीमती|श्री|कुमारी|सुश्री|मास्टर|मरीज|रोगी|पेशेंट|स्व\.?)[\s:.\-]+({SEQ_TITLE})")
_OTHER_LABEL = _tc(rf"(?i)(?<![\w])(?:caller|informant|contact(?:\s*person)?|witness(?:ed)?(?:\s*by)?|attendant|guardian|"
                          rf"visitor|bystander|relative|next\s*of\s*kin|emergency\s*contact|raised\s*by|called\s*by|signed\s*by|"
                          rf"reported\s*by|requested\s*by|handed\s*over\s*to|spoke\s*(?:to|with)|accompanied\s*by|brought\s*by)"
                          rf"[\s:.\-]+({SEQ_TITLE})")
_RELATION = _tc(rf"(?i)(?<![\w])(?:s\s*/\s*o|d\s*/\s*o|w\s*/\s*o|h\s*/\s*o|c\s*/\s*o|son\s+of|daughter\s+of|wife\s+of|"
                       rf"husband\s+of|father|mother|guardian|spouse|relative|attendant|पुत्र|पुत्री|पत्नी|पति|सुपुत्र|"
                       rf"सुपुत्री|वडिलांचे\s*नाव|पतीचे\s*नाव|पत्नीचे\s*नाव|आईचे\s*नाव|नातेवाईकाचे\s*नाव|पिता|माता|द्वारा)\b?\.?[\s:\-]*(?:(?:name|naam|नाम)\s*(?:[:\-]\s*)?)?(?:श्री(?:मती)?\s+|mr\.?\s+|mrs\.?\s+|smt\.?\s+|shri\s+)?"
                       rf"({SEQ_TITLE})")
_STOPW = r"(?!(?:hai|hain|he|ho|aur|and|ke|ki|ka|ko|se|is|are|was|has|with|saath|bhi|ne)(?![\p{L}\p{M}]))"
_REL_LOW = _tc(rf"(?i)(?<![\w])(?:pita|pati|patni|bhai|behen|beti|mata|maa|attendant|father|mother|husband|wife|guardian|relative)"
               rf"(?:\s+(?:ka|ki)\s+naam)?\s*[:\-]\s*({TOK}(?:[ \t]{{1,2}}{_STOPW}{TOK})?)|"
               rf"(?<![\w])(?:ka|ki)\s+naam\s+({TOK}(?:[ \t]{{1,2}}{_STOPW}{TOK})?)")
_REL_LOW2 = _tc(rf"(?i)(?<![\w])(?:beti|beta|bete)\s+({TOK})(?![\p{{L}}\p{{M}}])")
_RELATION_LOW = _tc(rf"(?i)(?<![\w])(?:s\s*/\s*o|d\s*/\s*o|w\s*/\s*o)\b\.?[\s:\-]*({SEQ_STRONG})")
_SUFFIX = _tc(rf"(?<![\w])({SEQ_TITLE})\s+(?:(?i:ji|sahab|saheb|sahib|bhai|bhaiya|bhaiyya|didi|behen|behan|behenji|behnji|"
                     rf"madam|mataji|bhabhi|chacha|chachi|mausi|amma|appa|anna|akka|dada|dadi|nani|nana)|जी|साहब|साहेब|भाई|भैया|दीदी|बहन|"
                     rf"बहनजी|मैडम|माता|भाभी|चाचा|चाची|मौसी|ताई|अम्मा)(?![\w\p{{M}}])")
_ROLE_AFTER = _tc(rf"(?<![\w])({SEQ_TITLE})\s*[,(]\s*(?:\(?\s*)?(?i:attendant|relative|visitor|caller|guardian|father|mother|"
                         rf"wife|husband|brother|sister|son|daughter|friend|neighbou?r|patient|pt)\b")
_NAME_PHONE = _tc(rf"(?<![\w])({SEQ_TITLE})\s*[,:\-(]?\s*(?:(?i:mob(?:ile)?|ph(?:one)?|tel|contact|cell|call|no\.?)\s*[:.\-]?\s*)?"
                         rf"\+?\(?\d{{3,5}}")
_WA_SENDER = _tc(rf"(?m)^\[[^\]\n]{{4,30}}\]\s*({SEQ_STRONG}):")
_DOCTOR_BEFORE = _tc(r"(?i)(?:\bdr|\bdoctor|डॉ|डा|डॉक्टर|\bprof)\.?\s*$")
_DOCTOR_PHRASE = _tc(rf"(?i)(?<![\w])(?:dr|doctor|डॉ|डा|डॉक्टर|prof)\.?\s*({SEQ_STRONG})")
_HINDI_PARTICLE = _tc(rf"(?<![\w\p{{M}}])([\u0900-\u097F\p{{M}}]+(?:\s+[\u0900-\u097F\p{{M}}]+){{0,2}})\s+(?:को|का|की|के|ने)\s")

_CLINICAL_WORDS = frozenset("started given monitor monitoring seen transfused transfuse possible inform informed continue continued advised review reviewed suspected known refer referred discharge discharged admitted admit plan follow check repeat stopped stop stable ordered send sent noted denies reports presented presents examination exam".split())
_TOKEN = _tc(rf"{TOK}")


def _valid_run(raw: str, digits: str, groups: list, ctx_before: str = "") -> bool:
    """Reject numeric ranges (150000-410000) and over-long runs; accept phone / Aadhaar / ABHA groupings."""
    n = len(digits)
    if n < 8 or n > 14:
        return False
    plus = raw.lstrip().startswith("+")
    if n == 10:
        if digits[0] in "6789":
            return True
        # not a valid mobile start (landline / unusual / canary): still an id when grouped like a phone or cued
        grouped = len(groups) >= 2 and "-" not in raw.strip("-")
        return grouped or plus or bool(_PHONE_CUE.search(ctx_before))
    if n == 11:
        return digits[0] == "0"          # 0 + mobile, or STD code + landline
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
        self.short_skels: dict[str, str] = {}
        self.skel_tokens: dict[str, set] = {}      # skeleton -> learned latin tokens (fast fuzzy check)
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
            self.skel_tokens.setdefault(sk, set()).add(tl)
            if len(sk) >= 2 and sk not in self.generic_skels and t.casefold() not in lex.GENERIC_NAME_PARTS:
                self.name_skels.setdefault(sk, role)
            elif sk and t.casefold() not in lex.GENERIC_NAME_PARTS:
                self.short_skels.setdefault(sk, role)      # Raju / Asha / Meera: too short or too common to match alone

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
आया आई आए आये आयी गए गये गयी आता आती जाता जाती करता करती दिया दी दिए लिया ली लिए बताया बताई बोला बोली कहा कहा। रहता रहती आते
है हैं था थी थे हो हुआ हुई हुए गया गयी गए रहा रही रहे कर करो करना करें किया और या भी नहीं अब अभी जब तब कल आज रात सुबह
दोपहर शाम दिन से तक लिए लेना देना वाला वाली वाले मत दवा दवाई गोली बुखार खांसी खाँसी दर्द पेट सर सिर बहुत थोड़ा ज्यादा कम ठीक अच्छा
बुरा सब कुछ कोई एक दो तीन चार पाँच पांच छह सात आठ नौ दस घर यहाँ वहाँ क्यों कैसे कौन कब कितना पानी खाना नींद उल्टी दस्त मरीज
डॉक्टर अस्पताल आयु उम्र वर्ष साल महीने माह सप्ताह नाम तारीख दिनांक पता ग्राम गाँव जिला तहसील मोबाइल फोन नंबर लिंग पुरुष महिला
रोगी भर्ती छुट्टी जांच जाँच रिपोर्ट सलाह परामर्श भोजन नमक कम खुराक सुबह शाम रात बाद पहले अगले पिछले हफ्ते बजे में पर को का की के ने
ओपीडी पर्चा नर्सिंग वार्ड बिस्तर दिनों दिनो घंटे तक मिलाकर साथ बाद ऊपर नीचे अंदर बाहर सामान्य उच्च निम्न रक्तचाप नाड़ी तापमान
""".split())
DEV_COMMON = DEV_COMMON | frozenset({"कोड", "पिन"})

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
            keep_end = start + m.end()         # a surname-like part after a real name token ("geeta rani") is part of the name
            count += 1
            continue
        if tl in ("m", "f", "t") and tok.rstrip(".").upper() in ("M", "F", "T"):
            break                              # "50/F": a sex marker, not an initial
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


SPAN_TIMEOUT = 20.0          # seconds per scan; set from policy (span_timeout_s)


class SpanTimeout(Exception):
    """A single scan exceeded its time cap (pathological input)."""


def _on_alarm(signum, frame):
    raise SpanTimeout()


_CAPWORD = _tc(r"\p{Lu}\p{Ll}*")
_LONGRUN = _tc(r"\S{300,}")
CHUNK = 100_000


def find_spans(text: str, lx: Lexicon, hint: str = "", loose: bool = True) -> list[Span]:
    """Detect PII in one string (linear-time guards): non-space runs over 300 chars are never words or
    identifiers, so they are masked before scanning; very large texts are scanned in line-aligned chunks."""
    if not text or not text.strip():
        return []
    masked = mask_bombs(text)
    armed = hasattr(signal, "setitimer") and threading.current_thread() is threading.main_thread() and SPAN_TIMEOUT > 0
    prev = signal.signal(signal.SIGALRM, _on_alarm) if armed else None

    def scan(chunk):
        if armed:                                  # hard wall-clock cap per chunk: a crafted input cannot stall the run
            signal.setitimer(signal.ITIMER_REAL, SPAN_TIMEOUT)
        return _find_spans(chunk, lx, hint, loose)

    try:
        if len(masked) <= CHUNK:
            return scan(masked)
        out, pos = [], 0
        while pos < len(masked):
            end = min(len(masked), pos + CHUNK)
            if end < len(masked):
                nl = masked.rfind("\n", pos, end)
                end = nl + 1 if nl > pos else end
            for sp in scan(masked[pos:end]):
                out.append(Span(sp.start + pos, sp.end + pos, sp.kind, sp.role, sp.prio))
            pos = end
        return out
    finally:
        if armed:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, prev)


def _find_spans(text: str, lx: Lexicon, hint: str = "", loose: bool = True) -> list[Span]:
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
    for m in _EMAIL_OBF.finditer(v):
        add(m.start(), m.end(), "ID", "EMAIL", 1)
    for m in _MASKED.finditer(v):
        add(m.start(), m.end(), "ID", "AADHAAR_MASKED", 1)
    for m in _PAN.finditer(v):
        add(m.start(), m.end(), "ID", "PAN", 1)
    for m in _MASKED_PHONE.finditer(v):
        add(m.start(), m.end(), "ID", "NUMBER", 1)
    for m in _IPV4.finditer(v):
        add(m.start(), m.end(), "ID", "NUMBER", 2)
    for m in _HANDLE.finditer(v):
        add(m.start(), m.end(), "ID", "EMAIL", 2)
    for m in _GEO.finditer(v):
        add(m.start(), m.end(), "ID", "NUMBER", 2)
    for m in _RUN.finditer(v):
        digits = re.sub(r"\D", "", m.group(0))
        groups = re.findall(r"\d+", m.group(0))
        if not _valid_run(m.group(0), digits, groups, v[max(0, m.start() - 16):m.start()]):
            continue
        if len(digits) >= 10 or (len(digits) >= 8 and m.group(0).lstrip().startswith("+")):
            if _DATEISH.match(m.group(0).strip()):
                continue
            s, e = m.start(), m.end()
            while s < e and v[s] == " ":
                s += 1
            add(s, e, "ID", "NUMBER", 2)
    for m in _DIGIT_WORDS.finditer(text):
        add(m.start(), m.end(), "ID", "NUMBER", 2)
    for m in _SPLIT_PHONE.finditer(v):
        add(m.start(), m.end(), "ID", "NUMBER", 2)
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
    for m in _PLACE_PIN.finditer(v):            # "Pune 411001": a 6-digit PIN right after a place name
        if m.group(1).lower() not in _MEDICAL_ONLY:
            add(m.start(2), m.end(2), "PIN", "PIN", 3)
    for m in _PIN.finditer(v):
        g = 1 if m.group(1) else 2
        add(m.start(g), m.end(g), "PIN", "PIN", 3)
    def addr_segments(value: str, base: int):
        off = 0
        for seg in value.split(","):
            cut = _ADDR_END.search(seg)                # "resident of Nashik, was admitted ...": the address ends at the clause
            if cut:
                seg = seg[:cut.start()]
                if not seg.strip():
                    break
            t = seg.strip(" \t-–")
            if len(t) >= 3 and not _KEEP_SEG.search(seg) and t.casefold() not in lx.places and any(c.isalnum() for c in t):
                a = base + off + (len(seg) - len(seg.lstrip()))
                add(a, a + len(seg.strip()), "ADDR", "ADDRESS", 4)
            off += len(seg) + 1

    for m in _ADDR_LABEL.finditer(text):         # a 6-digit PIN inside an address value ("कोल्हापूर 416002")
        for pm in re.finditer(r"(?<!\d)[1-9]\d{5}(?!\d)", ascii_digits(m.group(1))):
            add(m.start(1) + pm.start(), m.start(1) + pm.end(), "PIN", "PIN", 3)
    for m in _ADDR_LABEL.finditer(text):         # address segments other than district / tehsil / placeholders leak house, lane, locality
        addr_segments(m.group(1), m.start(1))
    if hint == "address":                        # a cell already typed as an address (FHIR address.line, "Ghar ka Pata")
        addr_segments(text, 0)
    for m in _GAON.finditer(text):               # "Rampur gaon"
        if not lex.known_nonname(m.group(1).split()[0]):
            add(m.start(1), m.end(1), "VILLAGE", "VILLAGE", 4)
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
        nxt = _NEXTWORD.match(text[e2:e2 + 24]) if e2 > s2 else None
        if nxt and role != "relative" and nxt.group(1).casefold() in lex.HOSPITAL_WORDS:
            return                                     # "Shri Balaji Clinic": an organisation, not a person
        if e2 > s2:
            add(s2, e2, "NAME", role, prio)

    for m in _STRONG_LABEL.finditer(text):
        before = text[max(0, m.start() - 24):m.start()]
        rel = bool(_RELWORD_BEFORE.search(before)) or bool(_RELWORD_INSIDE.search(m.group(0)))
        add_name(m.start(1), m.end(1), "relative" if rel else "patient", True, 3)
    for m in _WEAK_LABEL.finditer(text):
        add_name(m.start(1), m.end(1), "patient", False, 4)
    for m in _ORG_CUE.finditer(text):            # employer / college names single out a person
        s0, e0 = _trim_seq(text, m.start(1), m.end(1), False)
        add(s0, e0, "NAME", "other", 5)
    for m in _OTHER_LABEL.finditer(text):
        add_name(m.start(1), m.end(1), "other", False, 4)
    for m in _RELATION.finditer(text):
        label = m.group(0).lower()
        if re.match(r"\s*(?:c\s*/\s*o|h\s*/\s*o)", label) or label.startswith(("father", "mother", "guardian", "spouse", "relative", "attendant")):
            first = _TOKEN.search(text, m.start(1))
            if first is None or lex.known_nonname(first.group(0)) or not first.group(0)[:1].isupper() and not has_deva(first.group(0)):
                continue
        add_name(m.start(1), m.end(1), "relative", False, 3)
    for m in _RELATION_LOW.finditer(text):
        add_name(m.start(1), m.end(1), "relative", True, 3)
    for m in _REL_LOW.finditer(text):
        g = 1 if m.group(1) else 2
        add_name(m.start(g), m.end(g), "relative", True, 3)
    for m in _REL_LOW2.finditer(text):
        if not lex.known_nonname(m.group(1)) and m.group(1).casefold() not in ("blocker", "blockers", "thalassemia", "agonist", "carotene", "lactam", "hcg"):
            add_name(m.start(1), m.end(1), "relative", True, 3)
    for pat, role in ((_DEV_AFTER_REL, "relative"), (_DEV_BEFORE_REL, "relative"), (_DEV_PT, "patient")):
        for m in pat.finditer(text):
            add_name(m.start(1), m.end(1), role, True, 3)
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
            elif sk in lx.short_skels and ti + 1 < len(toks_all) and text[m.start() + len(t):toks_all[ti + 1].start()].strip() == "":
                nt = toks_all[ti + 1].group(0)        # a short given name counts only next to a surname: "राजू प्रसाद"
                if (nt in _DEV_SURNAMES or skeleton(nt) in lx.name_skels or skeleton(nt) in lx.generic_skels) and nt not in DEV_COMMON:
                    hit = lx.short_skels[sk]
                    add(toks_all[ti + 1].start(), toks_all[ti + 1].end(), "NAME", hit, 6)
        else:
            nxt = toks_all[ti + 1].group(0).casefold() if ti + 1 < len(toks_all) else ""
            lower_ok = (not t[:1].isupper()) and tl in lx.name_tokens and len(t) >= 3 and (
                nxt in lex.HONORIFIC_POST or (len(t) >= 5 and not lex.known_nonname(t)))
            if (not (t[:1].isupper()) and not lower_ok) or lex.known_nonname(t) or tl in lex.STOP_NAME_TOKENS:
                continue
            if t == "ASHA" and ti + 1 < len(toks_all) and toks_all[ti + 1].group(0).lower() in ("worker", "workers", "didi", "sahayika", "program", "scheme", "visit", "kiran"):
                continue
            if tl in lx.name_tokens:
                hit = lx.name_tokens[tl]
            elif len(t) >= 4:
                sk = skeleton(t)
                if len(sk) >= 2 and sk in lx.name_skels and any(
                        JaroWinkler.similarity(tl, k) >= 0.8 for k in lx.skel_tokens.get(sk, ()) if k[:1] == tl[:1]):
                    hit = lx.name_skels[sk]
        if hit and not _is_doctor_context(text, m.start()):
            add(m.start(), end, "NAME", hit, 6)
            if deva and ti + 1 < len(toks_all) and toks_all[ti + 1].group(0) in _DEV_SURNAMES and text[end:toks_all[ti + 1].start()].strip() == "":
                add(toks_all[ti + 1].start(), toks_all[ti + 1].end(), "NAME", hit, 6)
    # letter-spaced words ("K i s h o r i l a l"): collapse, then test as a name token or two
    if loose:
        for m in _SPACED.finditer(text):
            seg = m.group(0)
            word = re.sub(r"[ .\-_]", "", seg)
            tl = word.casefold()
            parts = _CAPWORD.findall(word) or [word]
            hit = any(len(w) >= 4 and (w.casefold() in lx.name_tokens or w.casefold() in lex.SEED_GIVEN
                                       or w.casefold() in lex.SEED_SURNAME) and not lex.known_nonname(w) for w in parts + [word])
            if len(word) >= 5 and hit:
                add(m.start(), m.end(), "NAME", "patient", 5)
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
    pair_rx = _tc(rf"(?<![\w\p{{M}}])({TITLE_TOK}(?:[ \t]{{1,2}}{TITLE_TOK}){{1,2}})(?![\w\p{{M}}])")
    for m in (pair_rx.finditer(text) if loose else ()):
        seq_start = m.start(1)
        run, runs = [], []
        for tm in _TOKEN.finditer(m.group(1)):
            t = tm.group(0).strip(".'’-")
            ok = len(t) >= 3 and not lex.known_nonname(t) and not has_deva(t) and not (len(t) >= 2 and t.isupper()) \
                and t.casefold() not in _CLINICAL_WORDS
            if ok:
                run.append((seq_start + tm.start(), seq_start + tm.end(), t))
                if tm.group(0).endswith(".") and len(tm.group(0)) > 3:       # a sentence ends here: "Started Ferrous Sulphate. Transfused"
                    runs.append(run)
                    run = []
            else:
                if run:
                    runs.append(run)
                run = []
        if run:
            runs.append(run)
        for r in runs:
            if len(r) < 2 or _is_doctor_context(text, r[0][0]):
                continue
            nxt = _NEXTWORD.match(text[r[-1][1]:r[-1][1] + 24])
            if nxt and nxt.group(1).casefold() in lex.HOSPITAL_WORDS:      # "Lotus Care Hospital": an organisation, not a person
                continue
            seq = text[r[0][0]:r[-1][1]]
            seed = sum(t.lower() in lex.SEED_GIVEN or t.lower() in lex.SEED_SURNAME for _, _, t in r)
            df = lx.df.get(seq.casefold(), 0)
            # unknown but rare Title-Case run, clear of every vocabulary: very likely a person (canary-style names)
            if (seed >= 1 and df <= 4) or df <= 3:
                add(r[0][0], r[-1][1], "NAME", "other", 7)
    # an unknown Title-Case word right after a person-cue word ("neighbour Raghunath", "said Raghunath")
    if loose:
        for m in _CUE_THEN_WORD.finditer(text):
            t = m.group(1)
            if len(t) >= 4 and not lex.known_nonname(t) and not t.isupper() and t.lower() not in lex.STOP_NAME_TOKENS:
                add(m.start(1), m.end(1), "NAME", "other", 7)
    # a lone, mid-sentence Title-Case token that is a common given name / surname ("said Raghunath stayed")
    if loose:
        for m in _TOKEN.finditer(text):
            t = m.group(0).strip(".'’-")
            tl = t.lower()
            if len(t) >= 4 and t[:1].isupper() and not t.isupper() and (tl in lex.SEED_GIVEN or tl in lex.SEED_SURNAME) \
                    and not lex.known_nonname(t) and not _is_doctor_context(text, m.start()):
                before = text[max(0, m.start() - 3):m.start()]
                if re.search(r"[A-Za-z,]\s+$", before) and not re.search(r"[.!?:]\s+$", before):    # mid-sentence only
                    add(m.start(), m.start() + len(t), "NAME", "other", 7)

    uuids = [(m.start(), m.end()) for m in _UUID.finditer(text)]

    def _in_url(sp):
        if any(sp.start >= us and sp.end <= ue for us, ue in uuids):
            return True
        if not any(sp.start >= us and sp.end <= ue for us, ue in urls):
            return False
        if any(sp.start >= us and sp.end <= ue for us, ue in uuids):      # anything inside a UUID is never PII
            return True
        # a phone / e-mail / PAN / known name inside a link (wa.me/9198..., mailto:) is still PII
        keep = (sp.kind == "ID" and sp.role in ("NUMBER", "EMAIL", "PAN", "AADHAAR_MASKED")) or (sp.kind == "NAME" and sp.prio <= 6)
        return not keep
    spans = [sp for sp in spans if not _in_url(sp)]
    # doctors stay: protect "Dr. X Y" so neither cues nor the lexicon remove them
    prot = _doctor_spans(text)
    spans = [sp for sp in spans if not (sp.kind == "NAME" and any(sp.start < pe and sp.end > ps for ps, pe in prot))]
    return _repeat_names(text, merge_names(text, _resolve(spans)))


def _doctor_spans(text: str) -> list[tuple[int, int]]:
    """Spans of "Dr. Anil Kumar": the leading Title-case words only (max 3), never "Dr. Mehta reviewed. Mr. Naidu"."""
    out = []
    for m in _DOCTOR_PHRASE.finditer(text):
        s2, e2 = _trim_seq(text, m.start(1), m.end(1), True)
        end, n = s2, 0
        for t in _TOKEN.finditer(text, s2, e2):
            w = t.group(0)
            if not (w[:1].isupper() or has_deva(w)) or n >= 3:
                break
            end, n = t.end(), n + 1
            if w.endswith(".") and len(w) > 2:
                break
        if end > s2:
            out.append((s2, end))
    return out


def doctor_names(text: str) -> list[str]:
    return [text[a:b] for a, b in _doctor_spans(text)]


def _resolve(spans: list[Span]) -> list[Span]:
    """Longest-first greedy selection; ties go to the more specific (lower prio number) kind. O(n log n)."""
    import bisect
    spans = sorted(spans, key=lambda s: (-(s.end - s.start), s.prio, s.start))
    starts: list[int] = []
    taken: list[Span] = []
    for s in spans:
        i = bisect.bisect_left(starts, s.start)
        if i > 0 and taken[i - 1].end > s.start:
            continue
        if i < len(taken) and taken[i].start < s.end:
            continue
        starts.insert(i, s.start)
        taken.insert(i, s)
    return taken


_COLLIDE = _tc(r"(?<![\w\p{M}])(?:Das|Sona|Diya|Dev|Raj|Nath|Rani|Ganga|Gulab|Hari|Moti|Prem|Neel)(?![\w\p{M}])")


def _extend_collisions(text: str, spans: list[Span]) -> list[Span]:
    """"Rohit Das", "Sona Ghosh": a capitalised word that is also an ordinary Hindi word (das = ten, sona = sleep, diya = gave) is a
    name when it sits right next to a detected name, so the detector must not stop in front of it."""
    out = []
    for sp in spans:
        if sp.kind == "NAME":
            m = _COLLIDE.match(text, sp.end + 1) if text[sp.end:sp.end + 1] == " " else None
            if m:
                sp = Span(sp.start, m.end(), sp.kind, sp.role, sp.prio)
            if sp.start >= 2 and text[sp.start - 1] == " ":
                for k in range(max(0, sp.start - 8), sp.start - 1):
                    m = _COLLIDE.match(text, k)
                    if m and m.end() == sp.start - 1:
                        sp = Span(m.start(), sp.end, sp.kind, sp.role, sp.prio)
                        break
        out.append(sp)
    return sorted(out, key=lambda x: (x.start, x.end))


def _repeat_names(text: str, spans: list[Span]) -> list[Span]:
    """A name found once in a text (by any cue) is the same person wherever else it appears in that text: "Called Rohit Das ...
    Rohit Das will visit". Exact, case-sensitive repeats of a Title-case name of 4+ letters are added as spans."""
    seen = {text[sp.start:sp.end] for sp in spans if sp.kind == "NAME" and sp.end - sp.start >= 4 and text[sp.start:sp.start + 1].isupper()}
    if not seen:
        return spans
    add_, taken = [], [(sp.start, sp.end) for sp in spans]
    for nm in seen:
        if any(lex.known_nonname(t.strip(".'’-")) and t.strip(".'’-") not in ("Das", "Sona", "Diya") for t in nm.split()):
            continue
        pos = text.find(nm)
        while pos != -1:
            e = pos + len(nm)
            ok = (pos == 0 or not text[pos - 1].isalnum()) and (e >= len(text) or not text[e].isalnum())
            if ok and not any(a < e and pos < b for a, b in taken):
                add_.append(Span(pos, e, "NAME", "patient", 6))
                taken.append((pos, e))
            pos = text.find(nm, e)
    return sorted(spans + add_, key=lambda x: (x.start, x.end)) if add_ else spans


def merge_names(text: str, spans: list[Span]) -> list[Span]:
    """Adjacent NAME spans separated only by blanks/dots become one phrase ("Mohd." + "Shahid")."""
    spans = _extend_collisions(text, spans)
    out: list[Span] = []
    for s in spans:
        if out and s.kind == "NAME" and out[-1].kind == "NAME" and re.fullmatch(r"[ \t.]{1,3}", text[out[-1].end:s.start]):
            prev = out[-1]
            role = prev.role if prev.prio <= s.prio else s.role
            out[-1] = Span(prev.start, s.end, "NAME", role, min(prev.prio, s.prio))
        else:
            out.append(s)
    return out
