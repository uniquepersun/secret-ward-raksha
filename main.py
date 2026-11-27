#!/usr/bin/env python3
"""Raksha privacy firewall. Usage: python main.py --input <dir> --output <dir>   (RAKSHA_SECRET in env)."""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.dont_write_bytecode = True          # never write .pyc files into the repository
sys.path.insert(0, str(HERE))


def harden_process():
    """Defence in depth for an untrusted-input run: no core dumps (a dump would contain PII and the secret) and a
    memory ceiling below the sandbox's 4 GB kill limit, so a memory bomb raises MemoryError for one file (caught,
    quarantined) instead of getting the whole run killed."""
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        soft, hard = resource.getrlimit(resource.RLIMIT_AS)
        cap = 3_500_000_000
        if hard == resource.RLIM_INFINITY or hard >= cap:
            resource.setrlimit(resource.RLIMIT_AS, (cap, hard))
    except Exception:  # noqa: BLE001 - not available on every OS (macOS ignores RLIMIT_AS); never fatal
        pass


def _hook(exc_type, exc, tb):  # scrubbed: type name only, never the message (it could hold PII)
    sys.stderr.write(f"fatal: {exc_type.__name__}\n")


sys.excepthook = _hook


def load_policy(path: Path) -> dict:
    policy = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip()
            if ":" in line:
                k, v = (x.strip() for x in line.split(":", 1))
                policy[k] = int(v) if v.lstrip("-").isdigit() else v
    return policy


def peak_rss_mb() -> float:
    try:
        import resource
        r = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return round(r / 1048576 if sys.platform == "darwin" else r / 1024, 1)
    except Exception:  # noqa: BLE001
        return 0.0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--policy", default=str(HERE / "config" / "policy.yaml"))
    a = ap.parse_args()
    harden_process()
    t0 = time.monotonic()
    from raksha.pipeline import Pipeline  # imported late so the hook covers import errors

    secret = os.environ.get("RAKSHA_SECRET", "").encode()
    if not secret:                       # an empty key would make pseudonyms predictable; use a random per-run key instead
        secret = os.urandom(32)
        sys.stderr.write("warning: RAKSHA_SECRET is not set; using a random key (output is not reproducible)\n")
    policy = load_policy(Path(a.policy))
    inp, out = Path(a.input), Path(a.output)
    if not inp.is_dir():
        sys.stderr.write("fatal: input is not a directory\n")
        return 2
    out.mkdir(parents=True, exist_ok=True)
    sys.setrecursionlimit(3000)

    p = Pipeline(inp, out, secret, policy)
    try:
        p.load_all()
        p.learn()
        p.build_evidence()
        p.link()
        p.write_all()
        recs = p.records()
    except Exception:  # noqa: BLE001 - last resort: never crash, never copy raw; quarantine what was not written
        for d in p.docs:
            if not d.out_rel:
                d.status, d.reason = "quarantined", "pipeline_error"
        recs = [r for r in (p.records() if any(d.out_rel for d in p.docs) else [])]

    with open(out / "records.jsonl", "w", encoding="utf-8") as f:
        for r in recs:
            f.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")

    files = []
    for d in p.docs:
        if d.status == "sanitized":
            files.append({"input_sha256": d.sha, "output": f"sanitized/{d.out_rel}", "status": "sanitized"})
        else:
            files.append({"input_sha256": d.sha, "output": None, "status": "quarantined", "reason": d.reason})
    n_san = sum(e["status"] == "sanitized" for e in files)
    n_units = sum(len(d.units) for d in p.docs if d.status == "sanitized")
    report = {
        "schema": "raksha-report/1",
        "files": files,
        "counts": {
            "files_total": len(files), "files_sanitized": n_san, "files_quarantined": len(files) - n_san,
            "records_processed": n_units, "identifiers_detected": int(sum(p.entities.values())),
            "records_linked": sum(r["patient"] is not None for r in recs),
            "records_generalized": int(p.n_generalized), "records_suppressed": 0, "records_quarantined": 0,
        },
        "entities": dict(sorted(p.entities.items())),
        "timing": {"seconds": round(time.monotonic() - t0, 2)},
        "resources": {"peak_rss_mb": peak_rss_mb()},
    }
    (out / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"files {len(files)} sanitized {n_san} quarantined {len(files) - n_san} records {n_units} linked {report['counts']['records_linked']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
