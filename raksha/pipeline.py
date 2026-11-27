"""End-to-end pipeline: ingest -> learn corpus lexicon -> evidence -> link -> scrub -> report."""
from __future__ import annotations

import base64
import html as _html
import binascii
import csv
import hashlib
import io
import json
import os
import re
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import regex as rx

from . import lex, privacy, security
from .columns import HDR_DOCTOR, infer_role, is_namey
from . import detect as _detect
from .detect import Lexicon, Span, SpanTimeout, doctor_names, find_spans
from .link import Ev, Linker, name_set, partial
from .privacy import band, band_age_value, band_ages_in_text, infer_order, parse_date_value, shift_text_dates
from .translit import ascii_digits, clean, has_deva, skeleton

CSV_EXT, JSON_EXT, TEXT_EXT = {".csv", ".tsv"}, {".json"}, {".txt", ".text", ".log", ".md"}
MAX_BYTES = 100 * 1024 * 1024   # larger files are quarantined (memory budget is 4 GB)
_DR = re.compile(r"(?i)^\s*(?:dr|doctor|डॉ|डा|डॉक्टर)\b")
_B64 = re.compile(r"^[A-Za-z0-9+/]{24,}={0,2}$")
_B64RUN = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")
_HEXRUN = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){12,}(?![0-9A-Fa-f])")
_UESC = re.compile(r"\\u([0-9a-fA-F]{4})")
from .detect import DEV_COMMON as DEV_COMMON_NAMES
_PSN_REPEAT = re.compile(r"(PSN-[0-9A-Z]{8})(?:[ _\-]+\1)+")


@dataclass
class Unit:
    loc: str
    ev: Ev = field(default_factory=Ev)
    node: Any = None            # json subtree / csv row index
    base: tuple = ()            # key path of the container (JSON), so role signatures match
    cluster: int = -1


@dataclass
class DocState:
    rel: str
    sha: str
    ext: str
    kind: str = ""              # csv | json | text
    text: str = ""
    delim: str = ","
    synth_header: bool = False
    nl: str = "\n"
    header: list = field(default_factory=list)
    rows: list = field(default_factory=list)
    data: Any = None
    units: list = field(default_factory=list)
    roles: list = field(default_factory=list)
    order: str | None = None
    status: str = "sanitized"
    reason: str = ""
    out_rel: str | None = None
    jsonl: bool = False


class Ctx:
    """Per-record scrub context."""
    __slots__ = ("psn", "shift", "order", "skels", "ids", "cores", "ident", "names", "rare")

    def __init__(self, psn=None, shift=None, order="dmy", skels=frozenset(), ids=frozenset(), cores=frozenset(), ident=False, names=()):
        self.psn, self.shift, self.order, self.skels, self.ids, self.cores, self.ident = psn, shift, order, skels, ids, cores, ident
        self.names = names
        self.rare = ()


NOCTX = Ctx()


# ------------------------------------------------------------------------------------- decoding
def decode_bytes(raw: bytes) -> tuple[str | None, str]:
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw[3:].decode("utf-8", "replace"), "utf-8-sig"
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16", "replace"), "utf-16"
    if len(raw) >= 4 and raw[1:2] == b"\x00" and raw[3:4] == b"\x00":
        return raw.decode("utf-16-le", "replace"), "utf-16le"
    if len(raw) >= 4 and raw[0:1] == b"\x00" and raw[2:3] == b"\x00":
        return raw.decode("utf-16-be", "replace"), "utf-16be"
    try:
        return raw.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        pass
    try:
        from charset_normalizer import from_bytes
        best = from_bytes(raw).best()
        if best is not None:
            return str(best), best.encoding
    except Exception:  # noqa: BLE001
        pass
    for enc in ("cp1252", "latin-1"):
        try:
            return raw.decode(enc), enc
        except UnicodeDecodeError:
            continue
    return None, ""


def json_depth(text: str) -> int:
    """Max bracket nesting of a JSON text (string-aware, iterative: safe on 1,500-deep input)."""
    depth = best = 0
    in_str = esc = False
    for ch in text:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch in "[{":
            depth += 1
            best = max(best, depth)
        elif ch in "]}":
            depth -= 1
    return best


def looks_binary(raw: bytes) -> bool:
    if raw[:4] in (b"%PDF", b"\x89PNG", b"PK\x03\x04", b"GIF8") or raw[:3] == b"\xff\xd8\xff":
        return True
    head = raw[:4096]
    return bool(head) and head.count(b"\x00") > len(head) * 0.2 and not head.startswith((b"\xff\xfe", b"\xfe\xff")) \
        and not (len(head) > 3 and (head[1:2] == b"\x00" or head[0:1] == b"\x00"))


# ------------------------------------------------------------------------------------- helpers
def norm_id(v: str) -> str:
    return re.sub(r"[^A-Za-z0-9]", "", ascii_digits(v or "")).upper()


def id_core(n: str) -> str | None:
    m = re.findall(r"\d{5,}", n)
    return (m[-1].lstrip("0") or "0") if m else None


def phone10(v: str) -> str | None:
    d = re.sub(r"\D", "", ascii_digits(v))
    if len(d) >= 10:
        d = d[-10:]
        if d[0] in "6789":
            return d
    return None


def _looks_like_data_row(cells) -> bool:
    """Two or more cells shaped like phones, ids, dates, PINs or Aadhaar numbers: real header cells are labels, not values."""
    from .columns import _AADH_V, _DATE_V, _PHONE_V, _PIN_V
    n = 0
    for c in cells:
        c = ascii_digits(c.strip())
        if c and (_PHONE_V.match(c) or _AADH_V.match(c) or _DATE_V.match(c) or _PIN_V.match(c) or re.fullmatch(r"[A-Za-z]{1,6}[\-/]?\d{3,}[\w\-/]*", c)):
            n += 1
    return n >= 2


_FHIR_CODE_KEYS = frozenset("use system code gender status type language rank mode intent kind".split())


def sig_join(parts) -> str:
    return " ".join(parts)


def pointer_escape(k: str) -> str:
    return k.replace("~", "~0").replace("/", "~1")


# ------------------------------------------------------------------------------------- pipeline
_CONTAINER_KEYS = frozenset("data patients patient records record results result items item entries rows row payload response visits visit encounters encounter cases case persons person".split())


class Pipeline:
    def __init__(self, inp: Path, out: Path, secret: bytes, policy: dict):
        self.inp, self.out, self.policy = inp, out, policy
        privacy.configure(secret)
        privacy.set_policy(policy)
        self.lx = Lexicon()
        self.docs: list[DocState] = []
        self.entities = Counter()
        self.n_generalized = 0
        self.json_roles: dict[str, str] = {}
        self.order_votes: dict[str, list[int]] = defaultdict(lambda: [0, 0])
        self.global_order = "dmy"
        self.cl_info: dict[int, dict] = {}
        self.id_cluster: dict[str, int] = {}
        self.name_cluster: dict[frozenset, set] = defaultdict(set)
        self.age_max = int(policy.get("date_shift_max_days", 365))
        self.age_min = int(policy.get("date_shift_min_days", 90))
        self.rare_max = int(policy.get("rare_dx_max_patients", 1))
        self.rare_proc = int(policy.get("rare_procedures", 1))      # 1 = also generalise procedures held by a single patient
        self.dx_display: dict = defaultdict(set)
        self.dx_patients: Counter = Counter()
        _detect.SPAN_TIMEOUT = float(policy.get("span_timeout_s", 20))
        _detect.REGEX_TIMEOUT = float(policy.get("regex_timeout_s", 5))
        csv.field_size_limit(100 * 1024 * 1024)
        self.t0 = time.monotonic()
        self.budget = float(policy.get("time_budget_s", 540))   # leave margin under the 15-minute limit

    def over_budget(self) -> bool:
        return time.monotonic() - self.t0 > self.budget

    # =========================================================================== load
    def load_all(self):
        found = []
        for dp, dns, fns in os.walk(self.inp, followlinks=False):
            dns.sort()
            for fn in sorted(fns):
                found.append(Path(dp) / fn)
        for path in sorted(found):
            rel = path.relative_to(self.inp).as_posix()
            if path.is_symlink() or not path.is_file():
                # never follow a link out of the input folder, never open a device / pipe / socket
                self.docs.append(DocState(rel, hashlib.sha256(b"").hexdigest(), path.suffix.lower(), status="quarantined",
                                          reason="symlink" if path.is_symlink() else "special_file"))
                continue
            try:
                if path.stat().st_size > MAX_BYTES:
                    self.docs.append(DocState(rel, self._sha_stream(path), path.suffix.lower(), status="quarantined", reason="too_large"))
                    continue
                raw = path.read_bytes()
            except OSError:
                self.docs.append(DocState(rel, "0" * 64, path.suffix.lower(), status="quarantined", reason="unreadable"))
                continue
            d = DocState(rel, hashlib.sha256(raw).hexdigest(), path.suffix.lower())
            try:
                self._parse(d, raw)
            except RecursionError:
                d.status, d.reason = "quarantined", "too_deeply_nested"
            except Exception:  # noqa: BLE001 - never leak content through an error message
                d.status, d.reason = "quarantined", "parse_error"
            self.docs.append(d)

    @staticmethod
    def _sha_stream(path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()

    def _parse(self, d: DocState, raw: bytes):
        if not raw.strip():
            d.status, d.reason = "quarantined", "empty_file"
            return
        threat = security.inspect(raw)          # static byte inspection only: hash blocklist, signatures, magic, active content
        if threat:
            d.status, d.reason = "quarantined", threat
            return
        if len(raw) > MAX_BYTES or looks_binary(raw):
            d.status, d.reason = "quarantined", "unsupported_format"
            return
        if d.ext not in CSV_EXT | JSON_EXT | TEXT_EXT:
            d.status, d.reason = "quarantined", "unsupported_format"
            return
        text, enc = decode_bytes(raw)
        if text is None:
            d.status, d.reason = "quarantined", "undecodable_text"
            return
        if text and sum(c == "\ufffd" or (ord(c) < 32 and c not in "\r\n\t") or 0x80 <= ord(c) < 0xa0 for c in text[:20000]) > 0.1 * len(text[:20000]):
            d.status, d.reason = "quarantined", "unsupported_format"      # random bytes behind a .csv / .txt name
            return
        text = clean(text)
        if text.lstrip().startswith(("<?xml", "<!DOCTYPE", "<html", "<ClinicalDocument")):
            d.status, d.reason = "quarantined", "unsupported_format"
            return
        d.text = text
        d.nl = "\r\n" if "\r\n" in text[:20000] else "\n"
        stripped = text.lstrip()
        if d.ext in JSON_EXT or (stripped[:1] in "{[" and d.ext in CSV_EXT):
            if json_depth(text) > 100:
                d.status, d.reason = "quarantined", "too_deeply_nested"
                return
            try:
                d.data = json.loads(text)
            except (ValueError, RecursionError):
                d.data = None
                lines = [l for l in text.splitlines() if l.strip()]
                if len(lines) >= 2:
                    try:                                  # JSON Lines: one object per line, written back the same way
                        d.data = [json.loads(l) for l in lines]
                        d.jsonl = True
                    except (ValueError, RecursionError):
                        d.data = None
                if d.data is None and d.ext in JSON_EXT:
                    d.status, d.reason = "quarantined", "malformed_json"
                    return
            if d.data is not None:
                d.kind = "json"
                self._json_units(d)
                return
        if d.ext in CSV_EXT:
            delim = "\t" if d.ext == ".tsv" else ","
            delim = self._sniff_delim(text, delim)
            d.delim, d.kind = delim, "csv"
            rows = list(csv.reader(io.StringIO(text, newline=""), delimiter=delim))
            if not rows:
                d.status, d.reason = "quarantined", "empty_file"
                return
            d.header, d.rows = rows[0], rows[1:]
            if _looks_like_data_row(rows[0]):         # headerless export: row 0 is a record, not column labels
                d.header, d.rows, d.synth_header = [f"col{i + 1}" for i in range(len(rows[0]))], rows, True
            d.units = [Unit(f"row:{i}", node=i) for i in range(len(d.rows))]
            return
        d.kind = "text"
        d.units = [Unit("doc")]

    @staticmethod
    def _sniff_delim(text: str, default: str) -> str:
        """Pick the delimiter that gives the most consistent multi-column rows over the first lines."""
        lines = [l for l in text.splitlines()[:30] if l.strip()]
        best, score = default, -1.0
        for dl in (default, ",", ";", "\t", "|"):
            try:
                counts = [len(r) for r in csv.reader(io.StringIO("\n".join(lines)), delimiter=dl)]
            except csv.Error:
                continue
            if not counts or max(counts) < 2:
                continue
            mode = max(set(counts), key=counts.count)
            sc = counts.count(mode) / len(counts) + 0.05 * min(mode, 10) - (0.05 if dl != default else 0)
            if sc > score:
                best, score = dl, sc
        return best

    def _json_units(self, d: DocState):
        data = d.data
        d.units = []
        if isinstance(data, list) and data and all(isinstance(x, dict) for x in data):
            d.units = [Unit(f"/{i}", node=x) for i, x in enumerate(data)]
        elif isinstance(data, dict) and data.get("resourceType") is None and not any(
                re.fullmatch(r"(?:patient|patient_?name|name|uhid|mrn|patient_?id)", str(k), re.I) and not isinstance(v, list) for k, v in data.items()):
            level = [((), data)]       # a top-level patient object means the whole document belongs to one patient (lab report with panels)                       # {"data": {"patients": [...]}}: the record list may sit a few levels down
            for _ in range(5):
                nxt = []
                for path, node in level:
                    for k, v in node.items():
                        if isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
                            pp = path + (k,)
                            d.units += [Unit("/" + "/".join(pointer_escape(x) for x in pp) + f"/{i}", node=x, base=pp) for i, x in enumerate(v)]
                        elif isinstance(v, dict):
                            nxt.append((path + (k,), v))
                if d.units or not nxt:
                    break
                level = nxt
            if not d.units:                            # a dict of records keyed by id or name: {"patient_1": {...}, "patient_2": {...}}
                level = [((), data)]
                for _ in range(5):
                    nxt = []
                    for path, node in level:
                        vals = [(k, v) for k, v in node.items() if isinstance(v, dict)]
                        if len(vals) >= 2 and len(vals) == len(node):
                            d.units += [Unit("/" + "/".join(pointer_escape(x) for x in path + (k,)), node=v, base=path) for k, v in vals]
                            d.keyed_names = [k for k, _ in vals if " " in k.strip() and is_namey(k)]
                        else:
                            nxt.extend((path + (k,), v) for k, v in vals)
                    if d.units or not nxt:
                        break
                    level = nxt
        if not d.units:
            d.units = [Unit("doc", node=data)]

    # =========================================================================== JSON leaves
    @staticmethod
    def _iter_json(node, parts=(), unit_root=False):
        """Yield (sig_parts, key, value) for scalar leaves. Parts carry resourceType markers."""
        if isinstance(node, dict):
            rt = node.get("resourceType")
            for k, v in node.items():
                p = parts + ((f"{k}<{rt}>" if rt and k == "resourceType" else k),)
                if rt and k != "resourceType":
                    p = parts + (f"<{rt}>", k)
                yield from Pipeline._iter_json(v, p)
        elif isinstance(node, list):
            for x in node:
                yield from Pipeline._iter_json(x, parts)
        elif node is not None and not isinstance(node, bool):
            yield parts, (parts[-1] if parts else ""), node

    def learn_json_roles(self):  # container words ("data.patients.enc.dx") must not make every leaf look like a name column
        vals = defaultdict(list)
        for d in self.docs:
            if d.kind != "json" or d.status != "sanitized":
                continue
            if len(d.units) > 1 or (d.units and d.units[0].loc != "doc"):
                its = (x for u in d.units for x in self._iter_json(u.node, u.base))
            else:
                its = self._iter_json(d.data)
            for parts, key, v in its:
                vals[sig_join(parts)].append(v)
        known = {s for s in self.lx.name_skels}
        for sig, vs in vals.items():
            self.json_roles[sig] = infer_role(" ".join(t for t in sig.split(" ") if t.lower() not in _CONTAINER_KEYS) or sig, vs, known or None)

    # =========================================================================== place columns
    ADDR_SIBLINGS = {"PIN", "ADDRESS", "ADDRESSH", "TEHSIL", "DISTRICT"}

    def _place_like(self, vals: list) -> str | None:
        """'VILLAGE' / 'KEEP' for an unlabelled name-shaped column inside an address block."""
        sv = [str(v).strip() for v in vals if v is not None and str(v).strip()][:400]
        if not sv or sum(is_namey(v) for v in sv) / len(sv) < 0.6:
            return None
        known = sum(v.casefold() in self.lx.places for v in sv) / len(sv)
        return "KEEP" if known >= 0.6 else "VILLAGE"

    def _infer_places_csv(self, d: DocState):
        if not (self.ADDR_SIBLINGS & set(d.roles)):
            return
        for j, role in enumerate(d.roles):
            if role == "KEEP":
                r = self._place_like([row[j] for row in d.rows if j < len(row)])
                if r == "VILLAGE":
                    d.roles[j] = "VILLAGE"

    def _infer_places_json(self):
        kids = defaultdict(set)
        for sig, role in self.json_roles.items():
            kids[sig.rsplit(" ", 1)[0] if " " in sig else ""].add(role)
        vals = defaultdict(list)
        for d in self.docs:
            if d.kind == "json" and d.status == "sanitized":
                for parts, key, v in self._iter_json(d.data):
                    sg = sig_join(parts)
                    if self.json_roles.get(sg) == "KEEP" and isinstance(v, str):
                        vals[sg].append(v)
        for sig, vs in vals.items():
            parent = sig.rsplit(" ", 1)[0] if " " in sig else ""
            if self.ADDR_SIBLINGS & kids.get(parent, set()) and self._place_like(vs) == "VILLAGE":
                self.json_roles[sig] = "VILLAGE"

    # =========================================================================== learning
    def learn(self):
        # 1) CSV columns
        for it in (0, 1):
            known = set(self.lx.name_skels) if it else None
            for d in self.docs:
                if d.kind != "csv" or d.status != "sanitized":
                    continue
                d.roles = []
                for j, h in enumerate(d.header):
                    vals = [r[j] for r in d.rows if j < len(r)]
                    d.roles.append(infer_role(h, vals, known))
                self._learn_table(d)
            for d in self.docs:
                if d.kind == "csv" and d.status == "sanitized":
                    self._infer_places_csv(d)
                    self._learn_table(d)
            for d in self.docs:
                for k in getattr(d, "keyed_names", ()):
                    self.lx.add_name(k)
            self.learn_json_roles()
            self._infer_places_json()
            for d in self.docs:
                if d.kind == "json" and d.status == "sanitized":
                    self._learn_json(d)
        # 2) text docs: cue-based names / villages / ids / doctors
        for d in self.docs:
            if d.kind == "text" and d.status == "sanitized":
                self._learn_text(d.text)
        # 3) free-text columns / json strings may hold cue-based names too
        for d in self.docs:
            if d.status != "sanitized":
                continue
            if d.kind == "csv":
                for j, r in enumerate(d.roles):
                    if r in ("TEXT", "ADDRESS", "ADDRESSH"):
                        for row in d.rows:
                            if j < len(row):
                                self._learn_text(row[j])
            elif d.kind == "json":
                for parts, key, v in self._iter_json(d.data):
                    if isinstance(v, str) and (" " in v) and self.json_roles.get(sig_join(parts)) in ("TEXT", "ADDRESS", "ADDRESSH", "KEEP"):
                        self._learn_text(v)
        # document frequency of Title-Case sequences (hospital names, headings) for the last-resort name heuristic
        seqdf = Counter()
        for d in self.docs:
            if d.status == "sanitized":
                seq = set(m.group(0).casefold() for m in re.finditer(r"\b[A-Z][a-z]+(?: [A-Z][a-z]+){1,2}\b", self._doc_text(d)))
                seqdf.update(seq)
        self.lx.df = dict(seqdf)
        self._learn_orders()

    def _doc_text(self, d: DocState) -> str:
        if d.kind == "csv":
            return "\n".join(" | ".join(r) for r in d.rows[:5000])
        if d.kind == "json":
            return " | ".join(str(v) for _, _, v in self._iter_json(d.data) if isinstance(v, str))
        return d.text

    def _learn_value(self, role: str, v: str):
        v = str(v).strip()
        if not v:
            return
        if role in ("NAME", "RELNAME") and not _DR.match(v):
            self.lx.add_name(v, "relative" if role == "RELNAME" else "patient")
        elif role == "VILLAGE":
            self.lx.add_village(v)
        elif role in ("HID", "ENCID", "INSID", "AADHAAR", "ABHA", "PAN", "PHONE", "EMAIL"):
            self.lx.add_id(v)
            if role == "PHONE":
                p = phone10(v)
                if p:
                    self.lx.phones.add(p)
        elif role == "PIN":
            self.lx.pins.add(ascii_digits(v).strip())
        elif role in ("TEHSIL", "DISTRICT"):
            self.lx.add_place(v)

    def _learn_table(self, d: DocState):
        for j, role in enumerate(d.roles):
            if role in ("NAME", "RELNAME", "VILLAGE", "HID", "ENCID", "INSID", "AADHAAR", "ABHA", "PAN", "PHONE", "EMAIL", "PIN", "TEHSIL", "DISTRICT"):
                for r in d.rows:
                    if j < len(r):
                        self._learn_value(role, r[j])
        # split first/last name columns: tokens are learned individually via add_name already

    def _learn_json(self, d: DocState):
        for parts, key, v in self._iter_json(d.data):
            role = self.json_roles.get(sig_join(parts), "KEEP")
            if role in ("NAME", "RELNAME", "VILLAGE", "HID", "ENCID", "INSID", "AADHAAR", "ABHA", "PAN", "PHONE", "EMAIL", "PIN", "TEHSIL", "DISTRICT"):
                self._learn_value(role, str(v))
        # keys that look like ids / names (dicts keyed by patient)
        def keys(node):
            if isinstance(node, dict):
                for k, v in node.items():
                    yield k
                    yield from keys(v)
            elif isinstance(node, list):
                for x in node:
                    yield from keys(x)
        for k in keys(d.data):
            if isinstance(k, str) and re.search(r"[A-Za-z]{2,}[\-/_]?\d{4,}", k):
                self.lx.add_id(k)

    def _learn_text(self, text: str):
        if not text or len(text) < 3 or self.over_budget():
            return
        try:
            self._learn_text_inner(text)
        except SpanTimeout:
            return                                   # pathological text teaches us nothing; it is handled (and capped) later

    def _learn_text_inner(self, text: str):
        for s in find_spans(text, self.lx):
            if s.kind == "NAME" and s.prio <= 4:
                self.lx.add_name(text[s.start:s.end], s.role if s.role in ("patient", "relative") else "patient")
            elif s.kind == "VILLAGE" and s.prio <= 4:
                self.lx.add_village(text[s.start:s.end])
            elif s.kind == "ID" and s.role in ("LABELLED", "ALNUM"):
                self.lx.add_id(text[s.start:s.end])
        for m in re.finditer(r"(?i)(?:distt?\.?|district|tehsil|jila|जिला|तहसील)\s*[:\-.]?\s*([A-Z\u0900-\u097F][\w\u0900-\u097F]+(?: [A-Z\u0900-\u097F][\w\u0900-\u097F]+)?)", text):
            self.lx.add_place(m.group(1))
        for nm in doctor_names(text):
            for t in re.split(r"\s+", nm):
                self.lx.doctor_tokens.add(t.casefold())

    def _learn_orders(self):
        """Per-hospital date-order votes from unambiguous dates (dd/mm vs mm/dd)."""
        for d in self.docs:
            if d.status != "sanitized":
                continue
            o = infer_order(self._doc_text(d))
            toks = self._family_tokens(d)
            if o:
                for t in toks:
                    self.order_votes[t][0 if o == "dmy" else 1] += 1
                self.order_votes["*"][0 if o == "dmy" else 1] += 1
            d.order = o
        a, b = self.order_votes["*"]
        self.global_order = "mdy" if b > a else "dmy"
        for d in self.docs:
            if d.status == "sanitized" and d.order is None:
                best, score = None, 0.0
                for t in self._family_tokens(d):
                    a, b = self.order_votes.get(t, (0, 0))
                    if a + b >= 2 and abs(a - b) / (a + b) >= 0.9 and (a + b) > score:
                        best, score = ("dmy" if a > b else "mdy"), a + b
                d.order = best or self.global_order

    @staticmethod
    def _family_tokens(d: DocState) -> set:
        toks = {t for t in re.split(r"[^a-z]+", d.rel.lower()) if len(t) >= 4}
        head = (d.text[:400] if d.kind == "text" else "")
        if d.kind == "csv":
            head = " ".join(d.header[:3])
        toks |= {t for t in re.split(r"[^a-z]+", head.lower()) if len(t) >= 5}
        return toks - {"discharge", "summary", "report", "reports", "nursing", "notes", "registration", "prescriptions", "opd", "export", "legacy"}

    # =========================================================================== evidence
    def build_evidence(self):
        for d in self.docs:
            if d.status != "sanitized":
                continue
            if self.over_budget():
                d.status, d.reason = "quarantined", "time_budget_exceeded"
                continue
            try:
                self._evidence_for(d)
            except SpanTimeout:
                d.status, d.reason = "quarantined", "file_timeout"
            except Exception:  # noqa: BLE001 - one odd file must never stop the run; it is quarantined
                d.status, d.reason = "quarantined", "processing_error"

    @staticmethod
    def _plausible(ev: Ev) -> Ev:
        """One record = one patient. A record listing many patients (an index, a ward sheet, a roster) must not
        bridge their clusters, so evidence that no single patient could own is dropped for linking."""
        if len(ev.ids) >= 3:                         # a record naming 3+ hospital ids is a roster, not one patient
            ev.ids, ev.cores = set(), set()
        by_type = Counter(t for t, _ in ev.strong)
        for typ in ("AADHAAR", "ABHA", "PAN"):
            if by_type[typ] > 1:
                ev.strong = {x for x in ev.strong if x[0] != typ}
        if len(ev.phones) > 3:
            ev.phones = set()
        if len(ev.names) > 5:
            ev.names, ev.rels = [], []
        # two mutually incompatible patient names in one record = a multi-patient note: its names cannot define one identity
        if any(not partial(x, y) for i, x in enumerate(ev.names) for y in ev.names[i + 1:]):
            ev.names, ev.rels = [], []       # names are ambiguous here; ids still link the note to its patient
        return ev

    def _evidence_for(self, d: DocState):
        try:
            self._evidence_raw(d)
        finally:
            for u in d.units:
                u.ev = self._plausible(u.ev)

    def _evidence_raw(self, d: DocState):
        if True:
            order = d.order or self.global_order
            if d.kind == "csv":
                for u in d.units:
                    row = d.rows[u.node]
                    pairs = [(d.roles[j], row[j]) for j in range(min(len(row), len(d.roles)))]
                    u.ev = self._ev_from_pairs(pairs, order, d.rel)
                    self._ev_from_text(u.ev, " ".join(row[j] for j in range(len(row)) if j < len(d.roles) and d.roles[j] in ("TEXT", "ADDRESS", "ADDRESSH")), skip_names=True)
            elif d.kind == "json":
                for u in d.units:
                    pairs, texts, groups = [], [], defaultdict(list)
                    for parts, key, v in self._iter_json(u.node, u.base):
                        role = self.json_roles.get(sig_join(parts), "KEEP")
                        sv = str(v)
                        if role in ("NAME", "RELNAME"):
                            groups[(role, parts[:-1])].append(sv)
                        else:
                            pairs.append((role, sv))
                        if isinstance(v, str) and role in ("TEXT", "ADDRESS", "ADDRESSH", "KEEP") and " " in v:
                            texts.append(v)
                    ev = self._ev_from_pairs(pairs, order, d.rel)
                    texts += self._kv_texts(u.node)
                    for (role, _), toks in sorted(groups.items(), key=lambda kv: str(kv[0])):
                        toks = [t for t in toks if not _DR.match(t)]
                        if toks:
                            ns = name_set(re.split(r"[\s.]+", " ".join(toks)))
                            (ev.rels if role == "RELNAME" else ev.names).append(ns) if ns else None
                    u.ev = ev
                    self._ev_from_text(ev, "\n".join(texts), skip_names=False)
            else:
                d.units[0].ev = Ev()
                self._ev_from_text(d.units[0].ev, d.text, skip_names=False)

    def _ev_from_pairs(self, pairs, order, scope: str = "") -> Ev:
        ev = Ev()
        namebuf = {"NAME": [], "RELNAME": []}
        for role, v in pairs:
            v = (v or "").strip()
            if not v:
                continue
            if role == "HID" or role == "INSID":
                n = norm_id(v)
                if role == "HID" and 2 <= len(n) < 5 and scope:
                    ev.ids.add(f"{scope}#{n}")           # short ids (P1001) link rows within one file only
                if len(n) >= 5:
                    (ev.ids.add(n) if role == "HID" else ev.strong.add(("INSID", n)))
                    c = id_core(n)
                    if c and role == "HID":
                        ev.cores.add(c)
            elif role in ("AADHAAR", "ABHA", "PAN"):
                n = norm_id(v)
                if role != "AADHAAR" or not n.startswith("X"):
                    if len(n) >= 8 and "X" not in n[:8]:
                        ev.strong.add((role, n))
            elif role == "EMAIL":
                ev.strong.add(("EMAIL", v.lower()))
            elif role == "PHONE":
                p = phone10(v)
                if p:
                    ev.phones.add(p)
            elif role in ("NAME", "RELNAME"):
                namebuf[role].append(v)
            elif role == "AGE":
                m = re.match(r"\d{1,3}", ascii_digits(v))
                if m:
                    ev.age = int(m.group(0))
            elif role == "AGESEX":
                m = re.match(r"(\d{1,3})\D*([MFmf])", ascii_digits(v))
                if m:
                    ev.age, ev.sex = int(m.group(1)), m.group(2).upper()
            elif role == "SEX":
                s = v.lower()
                ev.sex = "M" if s[:1] in "mp" or s in ("पुरुष", "पु") else "F" if s[:1] in "fw" or s in ("महिला", "स्त्री") else None
            elif role == "DOB":
                dd = parse_date_value(v, order)
                if dd:
                    ev.dob = dd.isoformat()
            elif role == "VILLAGE":
                toks = tuple(skeleton(t) for t in re.split(r"[\s.]+", v) if skeleton(t))
                ev.village = toks or None
            elif role == "PIN":
                ev.pin = ascii_digits(v)[:6]
        for role, vs in namebuf.items():
            # one name per name-role cell group (first/last columns are merged by the caller order)
            for v in vs:
                ns = name_set(re.split(r"[\s.]+", v))
                if ns:
                    (ev.rels if role == "RELNAME" else ev.names).append(ns)
        return ev

    def _ev_from_text(self, ev: Ev, text: str, skip_names: bool):
        if not text or not text.strip():
            return
        text = security.mask_bombs(text)
        t = ascii_digits(text)
        for s in find_spans(text, self.lx):
            seg = text[s.start:s.end]
            if s.kind == "NAME" and not skip_names:
                ns = name_set(re.split(r"[\s.]+", seg))
                if not ns:
                    continue
                if s.role == "relative":
                    ev.rels.append(ns)
                elif s.role == "patient":
                    ev.names.append(ns)
            elif s.kind == "ID":
                n = norm_id(seg)
                if s.role in ("ALNUM", "LABELLED", "LEARNED", "TAIL") and len(n) >= 5:
                    if s.role == "TAIL":
                        c = id_core(n)
                        if c:
                            ev.cores.add(c)
                    else:
                        ev.ids.add(n)
                        c = id_core(n)
                        if c:
                            ev.cores.add(c)
                elif s.role == "NUMBER":
                    dg = re.sub(r"\D", "", ascii_digits(seg))
                    if len(dg) == 12 and not (dg.startswith("91") and dg[2] in "6789"):
                        ev.strong.add(("AADHAAR", dg))
                    elif len(dg) == 14:
                        ev.strong.add(("ABHA", dg))
                    else:
                        p = phone10(seg)
                        if p:
                            ev.phones.add(p)
                elif s.role == "EMAIL":
                    ev.strong.add(("EMAIL", seg.lower()))
                elif s.role == "PAN":
                    ev.strong.add(("PAN", seg))
            elif s.kind == "VILLAGE" and ev.village is None:
                toks = tuple(skeleton(x) for x in re.split(r"[\s.]+", seg) if skeleton(x))
                ev.village = toks or None
            elif s.kind == "PIN" and ev.pin is None:
                ev.pin = ascii_digits(seg)[:6]
        if ev.age is None:
            m = re.search(r"(?i)(?:\bage(?:\s*/\s*sex)?|आयु|उम्र)\s*[:\-=]?\s*(\d{1,3})(?!\d)|(?<![\d.:/\-x])(\d{1,3})\s*(?:y|yrs?|years?|वर्ष)?\s*/\s*[MF]\b", t)
            if m:
                ev.age = int(m.group(1) or m.group(2))
        if ev.sex is None:
            m = re.search(r"(?i)(?:\d\s*(?:y|yrs?|years?|वर्ष)?\s*/\s*([MF])\b)|\b(?:sex|gender)\s*[:\-]\s*(male|female|m|f)\b", t)
            if m:
                ev.sex = (m.group(1) or m.group(2))[0].upper()
            elif re.search(r"(?i)\bw\s*/\s*o\b|\bd\s*/\s*o\b|\bbehen\b|\bbehenji\b|\bdidi\b|श्रीमती|बहन|दीदी|महिला", text):
                ev.sex = "F"
            elif re.search(r"(?i)\bs\s*/\s*o\b|\bbhai\b|\bbhaiya\b|\bsahab\b|\bsaheb\b|पुरुष|भैया|साहब", text):
                ev.sex = "M"
        if ev.dob is None:
            m = re.search(r"(?i)(?:dob|date of birth|d\.o\.b|जन्म\s*(?:तिथि|तारीख)?)\s*[:\-]?\s*([\d/.\-]{6,10})", t)
            if m:
                dd = parse_date_value(m.group(1), "dmy")
                if dd:
                    ev.dob = dd.isoformat()

    # =========================================================================== linking
    _ICD = re.compile(r"[A-TV-Z]\d{2}(?:\.\d{1,2})?")
    _DX_TEXT = re.compile(r"([^;:\n()\[\]]{3,80}?)\s*\(\s*([A-TV-Z]\d{2}(?:\.\d{1,2})?)\s*\)")
    _DX_JSON = re.compile(r'"code"\s*:\s*"([A-TV-Z]\d{2}(?:\.\d{1,2})?)"\s*,\s*"display"\s*:\s*"([^"]{3,120})"|"display"\s*:\s*"([^"]{3,120})"\s*,\s*"code"\s*:\s*"([A-TV-Z]\d{2}(?:\.\d{1,2})?)"')

    def _unit_codes(self, d: DocState, u: Unit) -> set:
        """ICD-10 codes (and their display text) a record states: `Anaemia, unspecified (D64.9)` or {"code": ..., "display": ...}."""
        if d.kind == "csv":
            blob = " ".join(d.rows[u.node])
        elif d.kind == "json":
            blob = json.dumps(u.node, ensure_ascii=False)
        else:
            blob = d.text
        blob = security.mask_bombs(blob)            # whitespace / long-token floods make these plain-re scans quadratic
        found = set()
        for m in self._DX_TEXT.finditer(blob):
            found.add(m.group(2))
            self.dx_display[m.group(2)].add(m.group(1).strip(" ,-"))
        for m in self._DX_JSON.finditer(blob):
            code, disp = (m.group(1), m.group(2)) if m.group(1) else (m.group(4), m.group(3))
            found.add(code)
            self.dx_display[code].add(disp.strip())
        if d.kind == "json":
            for parts, key, v in self._iter_json(u.node, u.base):
                if isinstance(v, str) and key.lower() in ("code", "icd", "icd10", "icd_code", "diagnosis_code") and self._ICD.fullmatch(v.strip()):
                    found.add(v.strip())
        if self.rare_proc:
            for term in self._procedure_terms(d, u, blob):
                found.add("P:" + term.casefold())
                self.dx_display["P:" + term.casefold()].add(term)
        return found

    _PROC_TEXT = re.compile(r"(?im)\bprocedures?\s*[:\-]\s*([A-Za-z][A-Za-z \-]{3,60}?)(?=\s*[(.,;\n]|\s+done\b|\s+on\s+day|$)")
    _PROC_KEYS = ("procedure", "surgery", "operation", "treatment_name", "procedure_name")

    def _procedure_terms(self, d: DocState, u: Unit, blob: str) -> set:
        out = {m.group(1).strip() for m in self._PROC_TEXT.finditer(blob)}
        if d.kind == "json":
            for parts, key, v in self._iter_json(u.node, u.base):
                if isinstance(v, str) and key.lower() in self._PROC_KEYS and 4 <= len(v.strip()) <= 80:
                    out.add(v.strip())
        elif d.kind == "csv":
            for j, h in enumerate(d.header):
                if re.search(r"(?i)procedure|surgery|operation", h) and j < len(d.rows[u.node]) and 4 <= len(d.rows[u.node][j].strip()) <= 80:
                    out.add(d.rows[u.node][j].strip())
        return out

    def link(self):
        units = [(d, u) for d in self.docs if d.status == "sanitized" for u in d.units]
        evs = [u.ev for _, u in units]
        try:
            roots = Linker(evs).run() if evs else []
        except Exception:  # noqa: BLE001 - fall back to "link nothing" (a wrong link costs more than none)
            roots = list(range(len(evs)))
        members = defaultdict(list)
        for i, r in enumerate(roots):
            members[r].append(i)
        # pass 1: cluster keys (strongest identifier, else the first unit's path)
        keys = {}
        for r, idx in sorted(members.items()):
            ids = set().union(*(evs[i].ids for i in idx))
            strong = set().union(*({s for s in evs[i].strong if s[0] in ("AADHAAR", "ABHA", "PAN", "EMAIL")} for i in idx))
            i0 = min(idx, key=lambda i: (units[i][0].rel, units[i][1].loc))
            first = f"{units[i0][0].rel}|{units[i0][1].loc}"
            cand = sorted(ids) + sorted(f"{a}:{b}" for a, b in strong)
            keys[r] = (cand[0] if cand else first, first)
        # two clusters can share an id when a conflict vetoed their merge: they are different people, so
        # their pseudonyms must differ (a shared pseudonym would be a false merge)
        count = Counter(k for k, _ in keys.values())
        for r, idx in sorted(members.items()):
            ids, strong, names, cores = set(), set(), [], set()
            for i in idx:
                e = evs[i]
                ids |= e.ids
                cores |= e.cores
                strong |= {s for s in e.strong if s[0] in ("AADHAAR", "ABHA", "PAN", "EMAIL")}
                names += e.names
            ident = any(evs[i].has_identity for i in idx)
            key, first = keys[r]
            if count[key] > 1:
                key = f"{key}#{first}"
            skey = key
            if key == first and names:               # no id: one person's rows share a shift through their name
                skey = "nm:" + "|".join(sorted(max(names, key=len)))
            skels = frozenset(s for nm in names for s in nm if s not in self.lx.generic_skels) or frozenset(s for nm in names for s in nm)
            # a record with no identity at all still gets its dates shifted (one shift per unit), never left raw
            self.cl_info[r] = {"key": key, "ident": ident, "psn": privacy.pseudonym(key) if ident else None,
                               "shift": privacy.shift_days(skey, self.age_max, self.age_min),
                               "skels": skels, "ids": frozenset(ids), "cores": frozenset(cores), "n": len(idx), "names": tuple(set(names))}
            codes = set()
            for i in idx:
                units[i][1].cluster = r
                try:
                    codes |= self._unit_codes(*units[i])
                except Exception:  # noqa: BLE001
                    pass
            self.cl_info[r]["codes"] = codes
            if ident:
                self.dx_patients.update(codes)
            for k in ids:
                self.id_cluster.setdefault(k, r)
            for nm in names:
                self.name_cluster[nm].add(r)

    def _rare_terms(self, r) -> tuple:
        """A condition held by at most `rare_dx_max_patients` patients singles them out against a voter list (who was treated
        for what, and when), so for those patients the code and its display text are generalised away."""
        info = self.cl_info.get(r) or {}
        if self.rare_max <= 0 or not info.get("ident"):
            return ()
        out = set()
        for c in info.get("codes", ()):
            if self.dx_patients[c] <= self.rare_max:
                out.add(c)
                out |= {x for x in self.dx_display.get(c, ()) if len(x) >= 4}
        return tuple(sorted(out, key=lambda x: -len(x)))

    def ctx_for(self, d: DocState, u: Unit) -> Ctx:
        info = self.cl_info.get(u.cluster)
        if info and not info["ident"] and info["shift"] is not None:
            return Ctx(None, info["shift"], d.order or self.global_order)
        if not info or not info["ident"]:
            return Ctx(order=d.order or self.global_order)
        c = Ctx(info["psn"], info["shift"], d.order or self.global_order, info["skels"], info["ids"], info["cores"], True, info["names"])
        c.rare = info.setdefault("rare", self._rare_terms(u.cluster))
        return c

    def ctx_from_string(self, s: str, d: DocState) -> Ctx:
        """Best-effort cluster resolution for a header / key / filename via embedded ids."""
        for m in re.finditer(r"[A-Za-z]{0,6}[\-/_]?\d[\dA-Za-z/\-]{4,}", ascii_digits(s)):
            n = norm_id(m.group(0))
            r = self.id_cluster.get(n)
            if r is None:
                c = id_core(n)
                if c:
                    for k, rr in self.id_cluster.items():
                        if id_core(k) == c:
                            r = rr
                            break
            if r is not None and self.cl_info[r]["ident"]:
                info = self.cl_info[r]
                return Ctx(info["psn"], None, d.order or self.global_order, info["skels"], info["ids"], info["cores"], True, info["names"])
        return Ctx(order=d.order or self.global_order)

    # =========================================================================== scrubbing
    def placeholder(self, span: Span, seg: str, ctx: Ctx, plain: bool) -> str:
        br = (lambda x: x) if plain else (lambda x: f"[{x}]")
        k, r = span.kind, span.role
        self.entities[k if k != "ID" else (r or "ID")] += 1
        if k == "NAME":
            toks = [t for t in re.split(r"[\s.]+", seg) if t]
            sk = {skeleton(t) for t in toks if skeleton(t)}
            core = frozenset({s for s in sk if s not in self.lx.generic_skels} or sk)
            # only a name that matches one of THIS patient's own names takes the pseudonym; a wife, a visitor or another
            # patient mentioned in the same note is just [NAME]
            own = any(partial(core, n) for n in ctx.names) if ctx.names else (r == "patient" and span.prio <= 3)
            if ctx.psn and r != "relative" and core and own:
                return ctx.psn
            return br("NAME")
        if k == "ID":
            if r in ("ALNUM", "LABELLED", "LEARNED", "TAIL"):
                n = norm_id(seg)
                c = id_core(n)
                if ctx.psn and (n in ctx.ids or (c and c in ctx.cores) or r == "LABELLED" and ctx.ident and not ctx.ids):
                    return ctx.psn
                return br("ID")
            if r == "EMAIL":
                return br("EMAIL")
            if r == "PAN":
                return br("PAN")
            if r == "AADHAAR_MASKED":
                return br("AADHAAR")
            dg = len(re.sub(r"\D", "", ascii_digits(seg)))
            return br("ABHA") if dg == 14 else br("AADHAAR") if dg == 12 and not seg.strip().startswith("+") else br("PHONE")
        if k == "PIN":
            dg = re.sub(r"\D", "", ascii_digits(seg))
            self.n_generalized += 1
            nd = int(privacy.POLICY["pin_digits"])
            return dg[:nd] + "***" if nd else br("PIN")
        if k == "VILLAGE":
            return br("VILLAGE")
        if k == "TEHSIL":
            return seg if int(privacy.POLICY["tehsil_level"]) else br("TEHSIL")
        if k == "ADDR":
            return br(r or "ADDRESS")
        return br("REDACTED")

    def scrub_text(self, text: str, ctx: Ctx, hint: str = "", plain: bool = False, dates: bool = True, loose: bool = True) -> str:
        if not text:
            return text
        text = clean(text)
        if not plain:
            text = self._decode_payloads(text, ctx)
            text = self._decoded_view(text, hint, loose)
        spans = find_spans(text, self.lx, hint, loose)
        out, pos = [], 0
        for s in spans:
            out.append(text[pos:s.start])
            out.append(self.placeholder(s, text[s.start:s.end], ctx, plain))
            pos = s.end
        out.append(text[pos:])
        t = "".join(out)
        for term in ctx.rare:
            t, n = re.subn(re.escape(term), "[RARE CONDITION]", t, flags=re.I)
            self.entities["RARE_CONDITION"] += n
        t = _PSN_REPEAT.sub(r"\1", t)
        if not plain:
            t, n = band_ages_in_text(t)
            self.n_generalized += n
            if dates and ctx.shift is not None:
                t, n = shift_text_dates(t, ctx.shift, ctx.order)
                self.n_generalized += n
        return t

    def _decode_payloads(self, text: str, ctx: Ctx) -> str:
        """base64 / hex blobs hiding inside plain text: decode, scrub, re-encode in the same encoding."""
        def printable(b: bytes):
            try:
                t = b.decode("utf-8")
            except UnicodeDecodeError:
                return None
            return t if t and sum(c.isprintable() or c in "\r\n\t" for c in t) / len(t) >= 0.95 else None

        def b64(m):
            try:
                t = printable(base64.b64decode(m.group(0) + "=" * (-len(m.group(0)) % 4), validate=True))
            except (binascii.Error, ValueError):
                return m.group(0)
            if t is None:
                return m.group(0)
            c = self.scrub_text(t, ctx)
            return base64.b64encode(c.encode("utf-8")).decode("ascii") if c != t else m.group(0)

        def hx(m):
            t = printable(bytes.fromhex(m.group(0)))
            if t is None:
                return m.group(0)
            c = self.scrub_text(t, ctx)
            return c.encode("utf-8").hex() if c != t else m.group(0)

        if len(text) < 24:
            return text
        return _HEXRUN.sub(hx, _B64RUN.sub(b64, text))

    def _decoded_view(self, text: str, hint: str, loose: bool) -> str:
        """HTML entities, %-encoding and \\uXXXX escapes: if decoding exposes PII the decoded text is used."""
        if not any(x in text for x in ("&#", "&amp;", "%", "\\u", "&lt", "&gt", "&quot")):
            return text
        alt = _UESC.sub(lambda m: chr(int(m.group(1), 16)), security.percent_decode(_html.unescape(text)))
        if alt == text:
            return text
        alt = clean(alt)
        return alt if find_spans(alt, self.lx, hint, loose) else text

    def scrub_cell(self, role: str, v: str, ctx: Ctx, row_extra: dict | None = None) -> str:
        if v is None or v == "":
            return v
        sv = clean(v)
        if role == "NAME":
            if _DR.match(sv):
                return sv
            self.entities["PATIENT_NAME"] += 1
            return ctx.psn or "[NAME]"
        if role == "RELNAME":
            self.entities["RELATIVE_NAME"] += 1
            return "[NAME]"
        if role == "PHONE":
            self.entities["PHONE"] += 1
            return "[PHONE]"
        if role == "AADHAAR":
            self.entities["AADHAAR"] += 1
            return "[AADHAAR]"
        if role == "ABHA":
            self.entities["ABHA_NUMBER"] += 1
            return "[ABHA]"
        if role == "PAN":
            self.entities["PAN"] += 1
            return "[PAN]"
        if role == "EMAIL":
            self.entities["EMAIL"] += 1
            return "[EMAIL]"
        if role == "INSID":
            self.entities["INSURANCE_ID"] += 1
            return "[ID]"
        if role == "HID":
            self.entities["MRN"] += 1
            return ctx.psn or "[ID]"
        if role == "ENCID":
            self.entities["ENCOUNTER_ID"] += 1
            return "[ID]"
        if role in ("DOB", "DATE"):
            if role == "DOB":
                self.entities["DOB"] += 1
            if ctx.shift is not None:
                t, n = shift_text_dates(sv, ctx.shift, ctx.order)
                self.n_generalized += n
                return t
            return sv
        if role == "AGE":
            b = band_age_value(sv)
            if b:
                self.n_generalized += 1
                return b
            return sv
        if role == "AGESEX":
            t, n = band_ages_in_text(sv)
            self.n_generalized += n
            return t
        if role == "PIN":
            dg = re.sub(r"\D", "", ascii_digits(sv))
            self.entities["PIN"] += 1
            self.n_generalized += 1
            nd = int(privacy.POLICY["pin_digits"])
            return dg[:nd] + "***" if nd and len(dg) >= nd else "[PIN]"
        if role == "VILLAGE":
            self.entities["VILLAGE"] += 1
            return "[VILLAGE]"
        if role == "TEHSIL":
            return sv if int(privacy.POLICY["tehsil_level"]) else "[TEHSIL]"
        if role in ("SEX", "DISTRICT"):
            return sv
        if role == "NUM" and re.fullmatch(r"[\d.,\s\-]+", sv):
            return sv
        return self.scrub_text(sv, ctx, "address" if role == "ADDRESSH" else "")

    # ----------------------------------------------------------------------- csv / text / json writers
    def render_csv(self, d: DocState) -> str:
        buf = io.StringIO()
        w = csv.writer(buf, delimiter=d.delim, lineterminator=d.nl)
        head_ctx = Ctx(order=d.order or self.global_order)
        if not d.synth_header:
            w.writerow([security.neutralise_cell(self.scrub_header(h, d)) for h in d.header])
        for u in d.units:
            if self.over_budget():                     # one huge file must not outlive the run's time budget
                raise SpanTimeout
            row = d.rows[u.node]
            ctx = self.ctx_for(d, u)
            new = []
            for j, v in enumerate(row):
                role = d.roles[j] if j < len(d.roles) else "KEEP"
                new.append(security.neutralise_cell(self.scrub_cell(role, v, ctx)))
            w.writerow(new)
        return buf.getvalue()

    def scrub_header(self, h: str, d: DocState) -> str:
        h = clean(h)
        ctx = self.ctx_from_string(h, d)
        spans = [sp for sp in find_spans(h, self.lx, loose=False) if sp.kind == "ID" or (sp.kind == "NAME" and sp.prio >= 5)]
        if any(sp.kind == "ID" for sp in spans):
            # "JJC-5533781 Chakraborty": next to an id, a remaining capitalised non-medical word is a name
            taken = [(sp.start, sp.end) for sp in spans]
            for m in re.finditer(r"[A-Z][A-Za-z'\u2019\-]{2,}|[\u0900-\u097F]{3,}", h):
                if not any(a < m.end() and m.start() < b for a, b in taken) and not lex.known_nonname(m.group(0)) \
                        and m.group(0).lower() not in lex.STOP_NAME_TOKENS:
                    spans.append(Span(m.start(), m.end(), "NAME", "patient", 5))
            spans.sort(key=lambda x: x.start)
        out, pos = [], 0
        for sp in spans:
            out += [h[pos:sp.start], self.placeholder(sp, h[sp.start:sp.end], ctx, False)]
            pos = sp.end
        out.append(h[pos:])
        return _PSN_REPEAT.sub(r"\1", "".join(out))

    def render_text(self, d: DocState) -> str:
        u = d.units[0]
        ctx = self.ctx_for(d, u)
        t = self.scrub_text(d.text, ctx)
        if ctx.psn and ctx.psn not in t:
            t = f"Patient: {ctx.psn}{d.nl}" + t
        return t

    def scrub_key(self, k: str, d: DocState, ctx: Ctx) -> str:
        if not isinstance(k, str):
            return k
        return self.scrub_text(k, self.ctx_from_string(k, d), dates=False, loose=False)

    LABEL_KEYS = ("field", "key", "label", "attribute", "attr", "question", "prompt", "fieldname", "field_name")
    VALUE_KEYS = ("value", "val", "answer", "response", "data", "text")

    def _kv_texts(self, node, depth=0) -> list:
        out = []
        if depth > 12:
            return out
        if isinstance(node, dict):
            kv = self._kv_pair(node)
            if kv:
                out.append(f"{node[kv[0]]}: {node[kv[1]]}")
            for v in node.values():
                out += self._kv_texts(v, depth + 1)
        elif isinstance(node, list):
            for x in node:
                out += self._kv_texts(x, depth + 1)
        return out

    def _kv_pair(self, node: dict):
        """{"field": "Patient Name", "value": "..."}: the sibling label decides how the value is read."""
        if len(node) > 4:
            return None
        lk = [k for k in node if k.lower() in self.LABEL_KEYS and isinstance(node[k], str)]
        vk = [k for k in node if k.lower() in self.VALUE_KEYS and isinstance(node[k], str)]
        return (lk[0], vk[0]) if len(lk) == 1 and len(vk) == 1 else None

    def walk_json(self, node, parts, d: DocState, ctx: Ctx):
        if isinstance(node, dict):
            kv = self._kv_pair(node)
            if kv is not None:
                label, val = node[kv[0]], node[kv[1]]
                text = f"{label}: {val}"
                res = self.scrub_text(text, ctx)
                if res.startswith(f"{label}: "):
                    node = dict(node)
                    node[kv[1]] = res[len(label) + 2:]
                    node[kv[0]] = label
                    out = {}
                    for k, v in node.items():
                        out[self.scrub_key(k, d, ctx)] = v if k in kv else self.walk_json(v, parts + (k,), d, ctx)
                    return out
            rt = node.get("resourceType")
            out, seen = {}, set()
            for k, v in node.items():
                p = parts + ((f"<{rt}>", k) if rt and k != "resourceType" else (k,))
                nk = self.scrub_key(k, d, ctx)
                if nk in seen:
                    i = 2
                    while f"{nk}_{i}" in seen:
                        i += 1
                    nk = f"{nk}_{i}"
                seen.add(nk)
                out[nk] = self.walk_json(v, p, d, ctx)
            return out
        if isinstance(node, list):
            return [self.walk_json(x, parts, d, ctx) for x in node]
        if isinstance(node, bool) or node is None:
            return node
        if parts and str(parts[-1]).split("<")[0] == "resourceType":
            return node                                  # structural: a FHIR resource type is never PII
        if parts and any(str(x).startswith("<") for x in parts) and str(parts[-1]).lower() in _FHIR_CODE_KEYS \
                and isinstance(node, str) and len(node) <= 40 and " " not in node:
            return node                                  # structural FHIR code (name.use, telecom.system, gender, coding.code): never PII
        role = self.json_roles.get(sig_join(parts), "KEEP")
        if isinstance(node, (int, float)):
            digs = re.sub(r"\D", "", str(int(node))) if isinstance(node, int) or float(node).is_integer() else ""
            if role == "NUM":
                return node
            if role in ("PHONE", "AADHAAR", "ABHA", "HID", "ENCID", "INSID", "PAN") or (len(digs) >= 10 and abs(node) >= 10 ** 9):
                self.entities[role if role != "KEEP" else "NUMBER"] += 1
                return 0
            if role == "AGE" and isinstance(node, int) and 0 <= node <= 120:
                self.n_generalized += 1
                return band(node)
            return node
        s = node
        key = parts[-1] if parts else ""
        if len(s) >= 24 and _B64.match(s.replace("\n", "")):
            dec = self._try_b64(s, d, ctx)
            if dec is not None:
                return dec
        if key == "div" and "<" in s:
            return self.scrub_text(s, ctx)
        if role == "NAME" and HDR_DOCTOR.search(key):
            return s
        return self.scrub_cell(role, s, ctx)

    def _try_b64(self, s: str, d: DocState, ctx: Ctx):
        try:
            raw = base64.b64decode(s + "=" * (-len(s) % 4), validate=True)
        except (binascii.Error, ValueError):
            return None
        threat = security.inspect_payload(raw)
        if threat and (len(s) >= 64 or threat != "binary_attachment"):
            # a binary or hostile attachment is never copied through: replaced by a placeholder of the same kind
            self.entities["ATTACHMENT_REMOVED"] += 1
            return base64.b64encode(b"[ATTACHMENT REMOVED]").decode("ascii")
        try:
            txt = raw.decode("utf-8")
        except UnicodeDecodeError:
            return None
        if not txt or sum(c.isprintable() or c in "\r\n\t" for c in txt) / len(txt) < 0.95:
            return None
        cleaned = self.scrub_text(txt, ctx if ctx.ident else Ctx(order=ctx.order))
        self.entities["BASE64"] += 1
        return base64.b64encode(cleaned.encode("utf-8")).decode("ascii")

    def render_json(self, d: DocState) -> str:
        data = d.data
        base = Ctx(order=d.order or self.global_order)
        if len(d.units) == 1 and d.units[0].loc == "doc":
            res = self.walk_json(data, (), d, self.ctx_for(d, d.units[0]))
        else:
            # records get their own context; the surrounding structure is walked with the doc context
            res = self._walk_with_units(data, d)
        if d.jsonl and isinstance(res, list):
            return "\n".join(json.dumps(x, ensure_ascii=False) for x in res) + "\n"
        return json.dumps(res, ensure_ascii=False, indent=2) + "\n"

    def _walk_with_units(self, data, d: DocState):
        by_id = {id(u.node): u for u in d.units}
        base = Ctx(order=d.order or self.global_order)

        def rec(node, parts, ctx):
            u = by_id.get(id(node))
            if u is not None:
                return self.walk_json(node, u.base, d, self.ctx_for(d, u))
            if isinstance(node, dict):
                out, seen = {}, set()
                for k, v in node.items():
                    nk = self.scrub_key(k, d, ctx)
                    if nk in seen:
                        i = 2
                        while f"{nk}_{i}" in seen:
                            i += 1
                        nk = f"{nk}_{i}"
                    seen.add(nk)
                    out[nk] = rec(v, parts + (k,), ctx)
                return out
            if isinstance(node, list):
                return [rec(x, parts, ctx) for x in node]
            return self.walk_json(node, parts, d, ctx)

        return rec(data, (), base)

    # =========================================================================== output
    def out_name(self, d: DocState, taken: set) -> str:
        rel = d.rel
        parts = rel.split("/")
        new = []
        for i, p in enumerate(parts):
            stem, dot, ext = p.rpartition(".") if i == len(parts) - 1 and "." in p else (p, "", "")
            ctx = self.ctx_from_string(p, d)
            s = self.scrub_text(stem.replace("_", " "), ctx, plain=True, dates=False, loose=True) if self._needs_scrub(stem) else stem
            s = re.sub(r"[\u0900-\u097F]{2,}", lambda m: m.group(0) if m.group(0) in DEV_COMMON_NAMES else "NAME", s)
            if s != stem:
                s = re.sub(r"\s+", "_", s.strip())
                s = _PSN_REPEAT.sub(r"\1", s)
            new.append(s + (dot + ext if dot else ""))
        out = "/".join(new)
        base, n = out, 1
        while out.lower() in taken:
            n += 1
            stem, dot, ext = base.rpartition(".")
            out = f"{stem}_{n}.{ext}" if dot else f"{base}_{n}"
        taken.add(out.lower())
        return out

    def _needs_scrub(self, s: str) -> bool:
        return bool(find_spans(s.replace("_", " "), self.lx, loose=True))

    @staticmethod
    def confined(dest: Path, root: Path) -> bool:
        """The write target must resolve inside the sanitized/ folder (no ../ or absolute-path tricks)."""
        try:
            dest.resolve().relative_to(root.resolve())
            return True
        except ValueError:
            return False

    def write_all(self):
        san = self.out / "sanitized"
        if san.is_dir() and not san.is_symlink():      # a previous run's files must not linger unreported
            import shutil
            shutil.rmtree(san, ignore_errors=True)
        san.mkdir(parents=True, exist_ok=True)
        taken: set = set()
        for d in self.docs:
            if d.status != "sanitized":
                continue
            if self.over_budget():
                d.status, d.reason, d.out_rel = "quarantined", "time_budget_exceeded", None
                continue
            try:
                if d.kind == "csv":
                    body = self.render_csv(d)
                elif d.kind == "json":
                    body = self.render_json(d)
                else:
                    body = self.render_text(d)
                d.out_rel = self.out_name(d, taken)
                dest = san / d.out_rel
                if not self.confined(dest, san):
                    raise ValueError("path_escape")
                dest.parent.mkdir(parents=True, exist_ok=True)
                if dest.is_symlink():
                    raise ValueError("path_escape")
                dest.write_text(body, encoding="utf-8", newline="")
            except SpanTimeout:
                d.status, d.reason, d.out_rel = "quarantined", "file_timeout", None
            except Exception:  # noqa: BLE001 - fail safe: quarantine, never leak the cause
                d.status, d.reason, d.out_rel = "quarantined", "processing_error", None

    def records(self) -> list[dict]:
        recs = []
        for d in self.docs:
            if d.status != "sanitized" or not d.out_rel:
                continue
            for u in d.units:
                info = self.cl_info.get(u.cluster)
                psn = info["psn"] if info and info["ident"] else None      # null = deliberately not linked (allowed by the spec)
                recs.append({"file": f"sanitized/{d.out_rel}", "loc": u.loc, "patient": psn})
        return recs
