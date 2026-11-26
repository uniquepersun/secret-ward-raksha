#!/usr/bin/env python3
"""Dev-only over-redaction detector: which NON-PII words vanished from the sanitised text, and what share survived.
python3 tools/token_loss.py <kit> <output_dir>"""
import collections, hashlib, json, re, sys, unicodedata
from pathlib import Path
kit, out = Path(sys.argv[1]), Path(sys.argv[2])
t = json.load(open(kit / "dev/truth/truth.json"))
rep = json.load(open(out / "report.json"))
ren = {e["input_sha256"]: e["output"] for e in rep["files"]}
W = re.compile(r"[^\W\d_]{2,}", re.U)
def toks(s): return [w.casefold() for w in W.findall(unicodedata.normalize("NFKC", s))]
lost = collections.Counter(); kept = tot = 0
for rel, f in t["files"].items():
    o = ren.get(f["sha256"])
    if not o: continue
    src = (kit / "dev/input" / rel).read_bytes().decode("utf-8-sig", "ignore")
    dst = (out / o).read_text(encoding="utf-8", errors="ignore")
    pii = collections.Counter()
    for u in f["units"].values():
        for e in u["entities"]:
            for w in toks(e["surface"]): pii[w] += 1
    a, b = collections.Counter(toks(src)), collections.Counter(toks(dst))
    for w, n in a.items():
        n2 = max(0, n - pii.get(w, 0))      # non-PII occurrences
        if n2 == 0: continue
        keep = min(n2, b.get(w, 0))
        kept += keep; tot += n2
        if keep < n2: lost[w] += n2 - keep
print(f"non-PII token retention: {kept}/{tot} = {kept/max(1,tot):.4f}")
print(lost.most_common(40))
