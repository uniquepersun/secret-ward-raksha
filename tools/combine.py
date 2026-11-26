#!/usr/bin/env python3
"""Dev-only: merge several mutated copies (tools/mutate.py --seed N) into one big dataset + truth.
Each copy lives under c<i>/ with its own patient ids, so name collisions across copies are true homonyms.
python3 tools/combine.py --kit KIT --out OUT --seeds 1 2 3 4 5 [--hard]"""
import argparse, json, shutil, subprocess, sys, tempfile
from pathlib import Path
ap = argparse.ArgumentParser()
ap.add_argument("--kit", required=True); ap.add_argument("--out", required=True)
ap.add_argument("--seeds", type=int, nargs="+", default=[1, 2, 3, 4, 5]); ap.add_argument("--hard", action="store_true")
a = ap.parse_args()
here, out = Path(__file__).resolve().parent, Path(a.out)
shutil.rmtree(out, ignore_errors=True)
(out / "dev/input").mkdir(parents=True); (out / "dev/truth").mkdir(parents=True)
shutil.copytree(Path(a.kit) / "dev/attacker", out / "dev/attacker")
files, patients = {}, {}
for i, seed in enumerate(a.seeds):
    tmp = Path(tempfile.mkdtemp())
    subprocess.run([sys.executable, str(here / "mutate.py"), "--kit", a.kit, "--out", str(tmp), "--seed", str(seed)] + (["--hard"] if a.hard else []),
                   check=True, capture_output=True)
    shutil.copytree(tmp / "dev/input", out / "dev/input" / f"c{i}")
    t = json.loads((tmp / "dev/truth/truth.json").read_text(encoding="utf-8"))
    pre = f"c{i}_"
    for rel, f in t["files"].items():
        for u in f["units"].values():
            if u.get("patient"): u["patient"] = pre + u["patient"]
            if u.get("cid"): u["cid"] = pre + u["cid"]
        files[f"c{i}/{rel}"] = f
    for pid, p in t["patients"].items():
        patients[pre + pid] = p
    t0 = t
    shutil.rmtree(tmp, ignore_errors=True)
t0["files"], t0["patients"] = files, patients
(out / "dev/truth/truth.json").write_text(json.dumps(t0, ensure_ascii=False), encoding="utf-8")
print(f"combined {len(a.seeds)} copies: {len(files)} files, {len(patients)} patients -> {out}")
