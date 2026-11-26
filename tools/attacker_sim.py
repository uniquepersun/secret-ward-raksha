#!/usr/bin/env python3
"""Dev-only re-identification attacker (approximation of docs/ATTACKS.md) to tune config/policy.yaml.

    python3 tools/attacker_sim.py --output out --kit ../Secret-Wards-ToolKit

Reports: record-linkage risk (mean probability mass on the true person), profile re-identification
(share of patients pinned down with p >= 0.5 after pooling records by pseudonym), targeted success
(known visit date / condition / stay length), plus k-anonymity of the released quasi-identifiers.
"""
import argparse, csv, io, json, re, sys, unicodedata
from collections import Counter, defaultdict
from pathlib import Path


def norm(s):
    return " ".join(unicodedata.normalize("NFKC", s).casefold().split())


def unit_texts(out, truth):
    rep = json.loads((out / "report.json").read_text(encoding="utf-8"))
    ren = {e["input_sha256"]: (e["output"] or "").replace("sanitized/", "", 1) for e in rep["files"]}
    recs = defaultdict(dict)
    for line in (out / "records.jsonl").read_text(encoding="utf-8").splitlines():
        r = json.loads(line)
        recs[r["file"].replace("sanitized/", "", 1)][r["loc"]] = r["patient"]
    cache = {}
    for rel, f in truth["files"].items():
        o = ren.get(f["sha256"], rel)
        p = out / "sanitized" / o
        if not o or not p.is_file():
            continue
        raw = p.read_text(encoding="utf-8", errors="replace")
        if rel not in cache:
            if p.suffix.lower() in (".csv", ".tsv"):
                d = "\t" if p.suffix.lower() == ".tsv" else ","
                rows = list(csv.reader(io.StringIO(raw, newline=""), delimiter=d))
                cache[rel] = ("csv", rows[0], rows[1:]) if rows else ("csv", [], [])
            elif p.suffix.lower() == ".json":
                try:
                    cache[rel] = ("json", json.loads(raw))
                except ValueError:
                    cache[rel] = ("text", raw)
            else:
                cache[rel] = ("text", raw)
        c = cache[rel]
        for loc, u in f["units"].items():
            if not u.get("patient"):
                continue
            txt = None
            if c[0] == "csv" and loc.startswith("row:"):
                i = int(loc[4:])
                if i < len(c[2]):
                    txt = " | ".join(f"{h}: {v}" for h, v in zip(c[1], c[2][i]))
            elif c[0] == "json":
                node = c[1]
                if loc.startswith("/"):
                    try:
                        for part in loc.strip("/").split("/"):
                            part = part.replace("~1", "/").replace("~0", "~")
                            node = node[int(part)] if isinstance(node, list) else node[part]
                    except (KeyError, IndexError, ValueError, TypeError):
                        node = None
                if node is not None:
                    txt = json.dumps(node, ensure_ascii=False)
            else:
                txt = raw if c[0] == "text" else None
            if txt:
                yield rel, loc, u["patient"], txt, recs.get(o, {}).get(loc)


AGE_RX = [re.compile(r"(?i)(?:\bage\b|आयु|उम्र)[^0-9]{0,8}(\d{1,3})(?:\s*-\s*(\d{1,3}))?(\+)?"),
          re.compile(r"(?<![\d.:/-])(\d{1,3})(?:\s*-\s*(\d{1,3}))?(\+)?\s*(?:y|yrs?|years?|वर्ष)?\s*/\s*[MFmf]\b")]


def all_dates(txt):
    """ISO strings for every date in txt, trying both dd/mm and mm/dd (the attacker is order-agnostic)."""
    import datetime as dt
    out = set(re.findall(r"\d{4}-\d{2}-\d{2}", txt))
    for m in re.finditer(r"(?<![\d.])(\d{1,2})[/.\-](\d{1,2})[/.\-](\d{4})(?!\d)", txt):
        a, b, y = int(m.group(1)), int(m.group(2)), int(m.group(3))
        for d, mo in ((a, b), (b, a)):
            try:
                out.add(dt.date(y, mo, d).isoformat())
            except ValueError:
                pass
    return out


def evidence(txt, vocab):
    ev = {"age": None, "sex": None, "district": set(), "tehsil": set(), "village": set(), "pin": None, "dates": set()}
    for rx in AGE_RX:
        m = rx.search(txt)
        if m:
            lo = int(m.group(1)); hi = int(m.group(2)) if m.group(2) else (200 if m.group(3) else lo)
            ev["age"] = (lo, hi); break
    t = txt.lower()
    if re.search(r"(?i)\"?(?:sex|gender|ling)\"?[\s:\"|]*(?:f\b|female|महिला)|/f\b|\bw/o\b|\bd/o\b", txt):
        ev["sex"] = "F"
    elif re.search(r"(?i)\"?(?:sex|gender|ling)\"?[\s:\"|]*(?:m\b|male|पुरुष)|/m\b|\bs/o\b", txt):
        ev["sex"] = "M"
    for kind in ("district", "tehsil", "village"):
        for name in vocab[kind]:
            if name in t:
                ev[kind].add(name)
    m = re.search(r"(?<!\d)([1-9]\d{2})(\d{3}|\*{3})(?!\d)", txt)
    if m:
        ev["pin"] = m.group(1)
    ev["dates"] = all_dates(txt)
    return ev


def merge(a, b):
    o = dict(a)
    if b["age"]:
        o["age"] = b["age"] if not a["age"] else (max(a["age"][0], b["age"][0]), min(a["age"][1], b["age"][1]))
    o["sex"] = a["sex"] or b["sex"]
    for k in ("district", "tehsil", "village"):
        o[k] = a[k] | b[k] if not (a[k] and b[k]) else a[k] & b[k] or a[k]
    o["pin"] = a["pin"] or b["pin"]
    o["dates"] = a["dates"] | b["dates"]
    return o


def weights(c, txt):
    """Attacker weights: full-name x60, given x8, surname x3, relative x8; phone match restricts."""
    t = norm(txt)
    digits = re.sub(r"\D", "", txt)
    ph = [r for r in c if r.get("phone") and len(r["phone"]) >= 10 and r["phone"][-10:] in digits]
    if ph:
        c = ph
    w = []
    for r in c:
        x = 1.0
        nm = norm(r["name"]).split()
        if nm and norm(r["name"]) in t:
            x *= 60
        else:
            if nm and nm[0] in t.split():
                x *= 8
            if len(nm) > 1 and nm[-1] in t.split():
                x *= 3
        rn = norm(r.get("relative_name", ""))
        if rn and rn in t:
            x *= 8
        w.append(x)
    return c, w


def candidates(ev, reg):
    c = reg
    def keep(f):
        nonlocal c
        n = [r for r in c if f(r)]
        if n:
            c = n
    if ev["sex"]:
        keep(lambda r: r["gender"] == ev["sex"])
    if ev["age"]:
        lo, hi = ev["age"]
        keep(lambda r: lo - 1 <= int(r["age"] or 0) <= hi + 2)
    if ev["district"]:
        keep(lambda r: norm(r["district"]) in ev["district"])
    if ev["tehsil"]:
        keep(lambda r: norm(r["tehsil"]) in ev["tehsil"])
    if ev["village"]:
        keep(lambda r: norm(r["village"]) in ev["village"])
    if ev["pin"]:
        keep(lambda r: r["pin"].startswith(ev["pin"]))
    return c


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", required=True)
    ap.add_argument("--kit", default="../Secret-Wards-ToolKit")
    a = ap.parse_args()
    kit, out = Path(a.kit), Path(a.output)
    truth = json.loads((kit / "dev/truth/truth.json").read_text(encoding="utf-8"))
    reg = list(csv.DictReader((kit / "dev/attacker/registry.csv").open(encoding="utf-8")))
    vocab = {k: {norm(r[k]) for r in reg if r[k]} for k in ("district", "tehsil", "village")}
    pat_rid = {p: v["rid"] for p, v in truth["patients"].items()}
    by_rid = {r["rid"]: r for r in reg}

    prof = defaultdict(lambda: {"ev": None, "pat": Counter(), "txt": []})
    rec_risk = []
    for rel, loc, pt, txt, psn in unit_texts(out, truth):
        ev = evidence(txt, vocab)
        c, w = weights(candidates(ev, reg), txt)
        true = pat_rid.get(pt)
        rec_risk.append(sum(x for r, x in zip(c, w) if r["rid"] == true) / sum(w))
        key = psn or f"{rel}|{loc}"
        P = prof[key]
        P["ev"] = ev if P["ev"] is None else merge(P["ev"], ev)
        P["pat"][pt] += 1
        P["txt"].append(txt)

    reid = defaultdict(float)
    for key, P in prof.items():
        pt = P["pat"].most_common(1)[0][0]
        c, w = weights(candidates(P["ev"], reg), " ".join(P["txt"]))
        true = pat_rid.get(pt)
        p = sum(x for r, x in zip(c, w) if r["rid"] == true) / sum(w)
        reid[pt] = max(reid[pt], p)
    n_pat = len(pat_rid)
    reid_rate = sum(1 for p in reid.values() if p >= 0.5) / n_pat

    facts = [json.loads(l) for l in (kit / "dev/attacker/known_facts.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    rid_pat = {v: k for k, v in pat_rid.items()}
    hits = tot = 0
    for f in facts:
        pt = rid_pat.get(f["rid"])
        if pt is None:
            continue
        tot += 1
        cond = norm(f.get("condition_hint", "")) if f.get("condition_hint") else None
        dates = set(f.get("visit_dates") or [])
        cand = []
        for key, P in prof.items():
            blob = norm(" ".join(P["txt"]))
            ok = (cond and cond in blob) or (dates & P["ev"]["dates"])
            if ok:
                cand.append(P)
        mine = [P for P in cand if P["pat"].most_common(1)[0][0] == pt]
        if mine:
            hits += len(mine) / len(cand) if cand else 0
    targeted = hits / tot if tot else 0.0

    # k-anonymity of released (sex, age band, district) over patients
    q = Counter()
    for P in prof.values():
        e = P["ev"]
        q[(e["sex"], e["age"], tuple(sorted(e["district"])), tuple(sorted(e["tehsil"])))] += 1
    ks = sorted(q.values())
    print(f"records attacked        {len(rec_risk)}")
    print(f"record linkage risk     {sum(rec_risk) / max(1, len(rec_risk)):.3f}   (raw ~0.92)")
    print(f"patients re-identified  {reid_rate:.3f}   (raw ~0.98)")
    print(f"targeted success        {targeted:.3f}   (raw ~1.00; {tot} targets)")
    print(f"profiles k=1: {sum(1 for k in ks if k == 1)}  k<5: {sum(1 for k in ks if k < 5)}  of {len(ks)}")


if __name__ == "__main__":
    sys.exit(main())
