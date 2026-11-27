"""Cross-document, cross-script identity linkage (Fellegi-Sunter-flavoured rules, conservative).

A wrong merge costs more than a missed link, so records merge only on evidence, and any merge is vetoed
if the merged cluster would hold contradictory facts (two Aadhaar numbers, two sexes, ages > 2 years
apart, two different dates of birth, or no compatible patient names at all).
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from rapidfuzz.distance import JaroWinkler

from .translit import skeleton


@dataclass
class Ev:
    ids: set = field(default_factory=set)        # full normalised hospital/admission ids
    cores: set = field(default_factory=set)      # digit cores of those ids (>=5 digits)
    strong: set = field(default_factory=set)     # ("AADHAAR", x) / ("ABHA", x) / ("PAN", x) / ("EMAIL", x)
    phones: set = field(default_factory=set)
    names: list = field(default_factory=list)    # patient names: frozenset of skeletons
    rels: list = field(default_factory=list)     # relative names
    age: int | None = None
    sex: str | None = None
    dob: str | None = None
    village: tuple | None = None
    pin: str | None = None

    @property
    def has_identity(self) -> bool:
        # patient-role evidence only: a lone phone number may be a caller, visitor or attendant
        return bool(self.ids or self.strong or self.names)


def name_set(tokens) -> frozenset:
    sk = [skeleton(t) for t in tokens]
    return frozenset(s for s in sk if s)


def _tok_match(a: str, b: str) -> bool:
    if a == b:
        return True
    if len(a) >= 3 and len(b) >= 3:
        return JaroWinkler.similarity(a, b) >= 0.93
    return False


def match_count(A: frozenset, B: frozenset) -> int:
    used, n = set(), 0
    for a in sorted(A):
        for b in sorted(B):
            if b not in used and _tok_match(a, b):
                used.add(b)
                n += 1
                break
    return n


def strict_eq(A, B) -> bool:
    return len(A) >= 2 and len(B) >= 2 and match_count(A, B) >= min(len(A), len(B)) and match_count(A, B) >= 2


def partial(A, B) -> bool:
    return bool(A) and bool(B) and match_count(A, B) >= min(len(A), len(B))


class Linker:
    def __init__(self, evs: list[Ev]):
        self.evs = evs
        n = len(evs)
        self.parent = list(range(n))
        self.agg = [self._agg(e) for e in evs]

    @staticmethod
    def _agg(e: Ev) -> dict:
        return {"sex": {e.sex} if e.sex else set(), "age": [e.age] if e.age is not None else [],
                "dob": {e.dob} if e.dob else set(),
                "strong": {t: {v} for t, v in [(k[0], k[1]) for k in e.strong]},
                "names": list(e.names), "rels": list(e.rels), "villages": {e.village} if e.village else set()}

    def find(self, x):
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def _conflict(self, a: int, b: int, need_name: bool) -> bool:
        A, B = self.agg[a], self.agg[b]
        if A["sex"] and B["sex"] and A["sex"] | B["sex"] != A["sex"] and len(A["sex"] | B["sex"]) > 1:
            return True
        ages = A["age"] + B["age"]
        if ages and max(ages) - min(ages) > 4:       # recorded ages drift up to ~2 y per record
            return True
        if A["dob"] and B["dob"] and (A["dob"] | B["dob"]) != A["dob"] and len(A["dob"] | B["dob"]) > 1:
            return True
        for t in set(A["strong"]) & set(B["strong"]):
            if t in ("AADHAAR", "ABHA", "PAN") and len(A["strong"][t] | B["strong"][t]) > 1:
                return True
        if need_name and A["names"] and B["names"]:
            if not any(partial(x, y) for x in A["names"] for y in B["names"]):
                return True
        return False

    def union(self, i: int, j: int, need_name: bool = True) -> bool:
        a, b = self.find(i), self.find(j)
        if a == b:
            return True
        if self._conflict(a, b, need_name):
            return False
        self.parent[b] = a
        A, B = self.agg[a], self.agg[b]
        A["sex"] |= B["sex"]
        A["age"] += B["age"]
        A["dob"] |= B["dob"]
        for t, vs in B["strong"].items():
            A["strong"].setdefault(t, set()).update(vs)
        A["names"] += B["names"]
        A["rels"] += B["rels"]
        A["villages"] |= B["villages"]
        return True

    def run(self) -> list[int]:
        evs = self.evs
        by = defaultdict(list)
        for i, e in enumerate(evs):
            for k in e.ids:
                by[("id", k)].append(i)
            for k in e.strong:
                by[("strong",) + tuple(k)].append(i)
        # E1: strong identifiers (full hospital id, Aadhaar, ABHA, PAN, e-mail)
        for key, members in sorted(by.items(), key=lambda kv: str(kv[0])):
            for m in members[1:]:                      # a shared e-mail or family-floater policy is often a family's: it needs a compatible name
                self.union(members[0], m, need_name=(len(key) > 1 and key[1] in ("EMAIL", "INSID")))
        # E5: digit cores (filename / path fragments) need compatible names
        core = defaultdict(list)
        for i, e in enumerate(evs):
            for c in e.cores:
                core[c].append(i)
        for c, members in sorted(core.items()):
            if 1 < len(members) <= 12:
                for m in members[1:]:
                    self.union(members[0], m, need_name=True)
        # E2: phones need compatible names (a phone may be a shared family or attendant number)
        ph = defaultdict(list)
        for i, e in enumerate(evs):
            for p in e.phones:
                ph[p].append(i)
        for p, members in sorted(ph.items()):
            if len(members) < 2 or len(members) > 15:
                continue
            for m in members[1:]:
                a, b = members[0], m
                ea, eb = evs[a], evs[b]
                if ea.names and eb.names:
                    if any(partial(x, y) for x in ea.names for y in eb.names):
                        self.union(a, b)
                elif (not ea.names or not eb.names) and (self._soft(ea, eb)):
                    self.union(a, b)
        # E3: same full name + one corroborating fact
        tok = defaultdict(list)
        for i, e in enumerate(evs):
            for nm in e.names:
                for t in nm:
                    tok[t].append(i)
        seen = set()
        for t, members in sorted(tok.items()):
            if len(members) > 400:
                continue
            for x in range(len(members)):
                for y in range(x + 1, len(members)):
                    a, b = members[x], members[y]
                    if (a, b) in seen or self.find(a) == self.find(b):
                        continue
                    seen.add((a, b))
                    ea, eb = evs[a], evs[b]
                    if self._name_link(ea, eb):
                        self.union(a, b)
        return [self.find(i) for i in range(len(evs))]

    @staticmethod
    def _soft(ea: Ev, eb: Ev) -> bool:
        if ea.age is not None and eb.age is not None and abs(ea.age - eb.age) <= 1:
            return True
        return bool(ea.village and ea.village == eb.village)

    @staticmethod
    def _name_link(ea: Ev, eb: Ev) -> bool:
        strict = any(strict_eq(x, y) for x in ea.names for y in eb.names)
        part = any(partial(x, y) for x in ea.names for y in eb.names)
        if not part:
            return False
        rel_ok = any(partial(x, y) for x in ea.rels for y in eb.rels) if ea.rels and eb.rels else None
        if ea.dob and eb.dob:
            if ea.dob == eb.dob and (strict or rel_ok):
                return True
            if ea.dob != eb.dob:
                return False
        same_village = bool(ea.village and eb.village and ea.village == eb.village)
        diff_village = bool(ea.village and eb.village and ea.village != eb.village)
        age_ok = ea.age is not None and eb.age is not None and abs(ea.age - eb.age) <= 2
        age_bad = ea.age is not None and eb.age is not None and abs(ea.age - eb.age) > 1
        if rel_ok is False and (diff_village or age_bad):
            return False        # homonyms: same name, different relative and place/age
        if strict and (rel_ok or (same_village and age_ok) or (same_village and (ea.age is None or eb.age is None))):
            return True
        if strict and rel_ok is None and age_ok and not diff_village and (ea.village or eb.village) is None:
            return False
        if part and rel_ok and (same_village or age_ok):
            return True
        return False
