#!/usr/bin/env python3
"""Dev-only: every sanitized FHIR bundle must validate as R4 with unique fullUrls and resolving references.
Needs fhir.resources (not a runtime dependency):  /path/to/venv/bin/python tools/check_fhir.py <output_dir>"""
import glob, json, sys
from fhir.resources.R4B.bundle import Bundle
files = sorted(glob.glob(sys.argv[1] + "/sanitized/**/*.json", recursive=True)); bad = n = 0
for f in files:
    try:
        b = json.load(open(f, encoding="utf-8"))
    except ValueError:
        continue
    if not (isinstance(b, dict) and b.get("resourceType") == "Bundle"):
        continue
    n += 1
    try:
        Bundle.model_validate(b)
        urls = [e["fullUrl"] for e in b["entry"]]
        refs = []
        def walk(x):
            if isinstance(x, dict):
                for k, v in x.items():
                    if k == "reference" and isinstance(v, str): refs.append(v)
                    walk(v)
            elif isinstance(x, list):
                [walk(i) for i in x]
        walk(b)
        assert len(urls) == len(set(urls)) and all(r in urls for r in refs)
    except Exception as e:
        bad += 1; print("INVALID", f, str(e)[:120].replace("\n", " "))
print(f"FHIR bundles: {n}, invalid: {bad}")
sys.exit(1 if bad else 0)
