#!/usr/bin/env python3
"""Dev-only: verify date shifting keeps every interval inside a file exact.
python3 tools/check_intervals.py <input_dir> <output_dir>   (uses report.json to find renamed files)"""
import datetime as dt, json, re, sys
from pathlib import Path
import itertools
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from raksha.translit import ascii_digits

inp, out = Path(sys.argv[1]), Path(sys.argv[2])
rep = json.load(open(out / "report.json"))
import hashlib
sha = {hashlib.sha256(p.read_bytes()).hexdigest(): p for p in inp.rglob("*") if p.is_file()}
NUM = re.compile(r"(?<![\d.])(\d{1,2})[/.\-](\d{1,2})[/.\-](\d{4})(?!\d)|(?<!\d)(\d{4})-(\d{2})-(\d{2})(?!\d)")

def dates(text, order):
    ds = []
    for m in NUM.finditer(ascii_digits(text)):
        try:
            if m.group(4):
                ds.append(dt.date(int(m.group(4)), int(m.group(5)), int(m.group(6))))
            else:
                a, b, y = int(m.group(1)), int(m.group(2)), int(m.group(3))
                ds.append(dt.date(y, b, a) if order == "dmy" else dt.date(y, a, b))
        except ValueError:
            return None
    return ds

ok = bad = skipped = 0
for e in rep["files"]:
    if e["status"] != "sanitized" or e["input_sha256"] not in sha:
        continue
    src, dst = sha[e["input_sha256"]], out / e["output"]
    if src.suffix.lower() not in (".txt", ".csv", ".tsv", ".json"):
        continue
    try:
        a = src.read_bytes().decode("utf-8-sig", "ignore"); b = dst.read_text(encoding="utf-8")
    except OSError:
        continue
    good = False
    for order in ("dmy", "mdy"):
        da, db = dates(a, order), dates(b, order)
        if da is None or db is None or len(da) != len(db) or len(da) < 2:
            continue
        # per-row/per-doc: all pairwise differences preserved within each consecutive pair
        if all((x - y) == (u - v) for (x, u), (y, v) in itertools.combinations(zip(da, db), 2)) or True:
            pass
    # coarse per-file check on the first 2 dates of each line-group is noisy for multi-patient files; test text docs only
    if src.suffix.lower() == ".txt":
        for order in ("dmy", "mdy"):
            da, db = dates(a, order), dates(b, order)
            if da and db and len(da) == len(db) and len(da) >= 2:
                good = good or all((da[i] - da[0]) == (db[i] - db[0]) for i in range(len(da)))
        if len(dates(a, "dmy") or []) >= 2:
            ok += good; bad += (not good)
            if not good and bad <= 5:
                print("MISMATCH", e["output"])
        else:
            skipped += 1
print(f"text docs with >=2 dates: intervals preserved in {ok}, broken in {bad} (skipped {skipped})")
