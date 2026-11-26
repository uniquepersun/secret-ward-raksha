#!/usr/bin/env python3
"""Dev-only canary / PII scanner with the official scorer's normalisation: NFKC, homoglyph fold, zero-width strip, Indic digits -> ASCII,
casefold, and decoding of base64 / hex / \\uXXXX / HTML entities / %-encoding. Scans file contents AND file names of an output tree,
plus optional stdout/stderr capture files.   python3 tools/canary_scan.py <output_dir> <truth.json> [capture files...]"""
import base64, html, json, os, re, sys, unicodedata
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from raksha.translit import clean, ascii_digits

def fold(s): return " ".join(ascii_digits(clean(s)).casefold().split())

def views(t):
    out = [t, html.unescape(t), re.sub(r"%([0-9A-Fa-f]{2})", lambda m: chr(int(m.group(1), 16)), t),
           re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), t)]
    for _ in range(2):
        for x in list(out):
            for m in re.finditer(r"[A-Za-z0-9+/]{16,}={0,2}", x):
                try: out.append(base64.b64decode(m.group(0) + "=" * (-len(m.group(0)) % 4)).decode("utf-8", "ignore"))
                except Exception: pass
            for m in re.finditer(r"\b(?:[0-9a-fA-F]{2}){10,}\b", x):
                try: out.append(bytes.fromhex(m.group(0)).decode("utf-8", "ignore"))
                except Exception: pass
    return fold(" ".join(out))

out, truth = sys.argv[1], json.load(open(sys.argv[2], encoding="utf-8"))
keys, canaries = set(), set()
for f in truth["files"].values():
    for u in f["units"].values():
        for e in u["entities"]:
            if e["type"] in ("PATIENT_NAME", "RELATIVE_NAME", "PHONE", "AADHAAR", "ABHA_NUMBER", "MRN", "PAN", "EMAIL", "INSURANCE_ID", "CANARY") and len(e["surface"]) >= 5:
                (canaries if e["type"] == "CANARY" else keys).add(fold(e["surface"]))
digits = lambda s: re.sub(r"\D", "", s)
hits = []
targets = [(os.path.join(dp, n), n) for dp, _, fn in os.walk(out) for n in fn] + [(c, c) for c in sys.argv[3:]]
for p, name in targets:
    try: raw = open(p, encoding="utf-8", errors="ignore").read()
    except OSError: continue
    v = re.sub(r"\bdr\.?\s+\w+(?:\s+\w+)?", " ", views(raw) + " " + fold(name))      # doctor lines are allowed
    nz = digits(views(raw))
    for k in keys | canaries:
        if k in v or (digits(k) and len(digits(k)) >= 9 and digits(k) in nz):
            hits.append(("CANARY" if k in canaries else "PII", os.path.relpath(p, out) if p.startswith(out) else p))
print(f"scanned {len(targets)} files; canaries leaked: {sum(h[0]=='CANARY' for h in hits)}; other PII hits: {sum(h[0]=='PII' for h in hits)}")
for h in hits[:10]: print("  ", h)
sys.exit(1 if hits else 0)
