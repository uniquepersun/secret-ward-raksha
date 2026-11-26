"""Dev-only: show which true patients each of our pseudonyms mixes (needs truth.json)."""
import json, sys, collections
out, truth = sys.argv[1], sys.argv[2]
t = json.load(open(truth))
recs = collections.defaultdict(dict)
for line in open(out + "/records.jsonl"):
    r = json.loads(line)
    recs[r["file"].replace("sanitized/", "", 1)][r["loc"]] = r["patient"]
rep = json.load(open(out + "/report.json"))
ren = {e["input_sha256"]: (e["output"] or "").replace("sanitized/", "", 1) for e in rep["files"]}
cl = collections.defaultdict(list)
for rel, f in t["files"].items():
    o = ren.get(f["sha256"], rel)
    for loc, u in f["units"].items():
        if u.get("link") != "required" or not u.get("patient"):
            continue
        r = recs.get(o, {})
        p = r.get(loc)
        if p is None and "/" in loc:
            parts = loc.split("/")
            for i in range(len(parts) - 1, 1, -1):
                if "/".join(parts[:i]) in r:
                    p = r["/".join(parts[:i])]; break
        if p is None:
            p = r.get("doc")
        cl[p].append((u["patient"], rel, loc))
bad = [(p, v) for p, v in cl.items() if p and len({x[0] for x in v}) > 1]
print("pseudonyms:", len([p for p in cl if p]), "unlinked units:", len(cl.get(None, [])), "mixed:", len(bad))
for p, v in sorted(bad, key=lambda kv: -len(kv[1]))[:int(sys.argv[3]) if len(sys.argv) > 3 else 6]:
    c = collections.Counter(x[0] for x in v)
    print(p, dict(c))
    seen = set()
    for pt, rel, loc in v:
        if (pt, rel) not in seen and len(seen) < 14:
            seen.add((pt, rel)); print("   ", pt, rel, loc)

if len(sys.argv) > 4:   # fragmentation view: python linkdebug.py out truth N frag
    frag = collections.defaultdict(lambda: collections.defaultdict(list))
    for p, v in cl.items():
        for pt, rel, loc in v:
            frag[pt][p].append(rel.split("/")[0] + "/" + rel.split("/")[-1][:34])
    rows = sorted(frag.items(), key=lambda kv: -len(kv[1]))[:int(sys.argv[3])]
    for pt, d in rows:
        print(pt, "psn:", len(d), "traps:", t["patients"][pt].get("traps"))
        for p, files in sorted(d.items(), key=lambda kv: -len(kv[1])):
            print("    ", p, len(files), sorted(set(files))[:5])
