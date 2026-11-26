#!/usr/bin/env python3
"""One line per dataset: python3 tools/scorecard.py --kit ../Secret-Wards-ToolKit [--mutated /tmp/mut1] [--seed 1]

Runs main.py on the practice data (and, if given, a mutated 'unseen-format' copy built by tools/mutate.py),
then prints leaks / canaries / medical kept / linking / simulated re-identification / runtime.
Rough guide only: the official score uses hidden data and the organisers' evaluator."""
import argparse, json, os, re, subprocess, sys, tempfile, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = str(ROOT / ".venv/bin/python") if (ROOT / ".venv/bin/python").exists() else sys.executable


def sh(cmd, env=None):
    return subprocess.run(cmd, capture_output=True, text=True, env=env).stdout


def grab(pat, text, group=1, cast=float, default=float("nan")):
    m = re.search(pat, text)
    return cast(m.group(group)) if m else default


def run_one(name, inp, truth, kit, out):
    env = dict(os.environ, RAKSHA_SECRET="practice")
    t0 = time.monotonic()
    subprocess.run([PY, str(ROOT / "main.py"), "--input", str(inp), "--output", str(out)], env=env, capture_output=True)
    secs = time.monotonic() - t0
    contract = "CONTRACT OK" in sh([sys.executable, str(kit / "validate_output.py"), "--input", str(inp), "--output", str(out)])
    chk = sh([sys.executable, str(kit / "check_dev.py"), "--truth", str(truth), "--output", str(out)])
    sim = sh([sys.executable, str(ROOT / "tools/attacker_sim.py"), "--output", str(out), "--kit", str(truth.parents[2])]) \
        if (truth.parents[2] / "dev/attacker").exists() else ""
    leak = grab(r"\(\s*([\d.]+)% leaked", chk)
    med = grab(r"MEDICAL DATA KEPT: .*\(\s*([\d.]+)%", chk)
    canary = grab(r"CANARIES: (\d+) of", chk, cast=int)
    f05 = grab(r"F0\.5 ([\d.]+)", chk)
    wrong = grab(r"wrongly merge different people: (\d+)", chk, cast=int)
    reid = grab(r"patients re-identified\s+([\d.]+)", sim)
    tgt = grab(r"targeted success\s+([\d.]+)", sim)
    print(f"{name:<10} contract={'OK' if contract else 'FAIL'} leak%={leak:<5} canaries={canary} medical%={med:<6} "
          f"linkF0.5={f05:<5} wrongMerges={wrong} reid={reid:<5} targeted={tgt:<5} secs={secs:.1f}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--kit", required=True)
    ap.add_argument("--mutated", help="dir produced by tools/mutate.py")
    ap.add_argument("--seed", type=int, default=1)
    a = ap.parse_args()
    kit = Path(a.kit).resolve()
    tmp = Path(tempfile.mkdtemp(prefix="scorecard-"))
    run_one("practice", kit / "dev/input", kit / "dev/truth/truth.json", kit, tmp / "p")
    mut = Path(a.mutated) if a.mutated else tmp / "mut"
    if not a.mutated:
        subprocess.run([sys.executable, str(ROOT / "tools/mutate.py"), "--kit", str(kit), "--out", str(mut), "--seed", str(a.seed)], capture_output=True)
    run_one(f"mutated{a.seed}", mut / "dev/input", mut / "dev/truth/truth.json", kit, tmp / "m")


if __name__ == "__main__":
    main()
