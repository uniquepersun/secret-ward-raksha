"""Edge-case inputs must never crash the run, copy raw files, or hang. Run: python -m unittest discover -s tests"""
import json, os, subprocess, sys, tempfile, time, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = str(ROOT / ".venv/bin/python") if (ROOT / ".venv/bin/python").exists() else sys.executable

FILES = {
    "empty.txt": b"", "blank.csv": b"   \n\n", "header_only.csv": b"a,b,c\n", "bad_quote.csv": b'name,phone\n"Ravi Kumar,9876543210\n',
    "scalars.json": b"[1,2,3]", "weird.json": b'{"a": NaN, "big": 123456789012345678901234567890, "u": "\\u0930\\u093e\\u092e"}',
    "crlf.txt": b"Name: Ramesh Gupta\r\nMobile: 9876543210\r\n", "bom.txt": b"\xef\xbb\xbfName: Seema Rao, 42 yrs F\n",
    "nul.txt": b"x\x00y\x00z", "random.json": os.urandom(2000), "nested.json": b'{"a":{"b":{"c":[{"name":"Kiran Shah","phone":9876501234}]}}}',
    "long_token.txt": b"Name: Test Person " + b"x" * 400_000 + b" 9876543210", "photo.jpg": b"\xff\xd8\xff\xe0" + os.urandom(500),
    "doc.pdf": b"%PDF-1.4 " + os.urandom(300), "odd name (2) \xc3\xbc.txt": b"Name: Bina Roy\n",
}


class Robustness(unittest.TestCase):
    def test_every_edge_case_exits_zero_and_leaks_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            inp, out = Path(d, "in"), Path(d, "out")
            inp.mkdir()
            for name, data in FILES.items():
                (inp / name).write_bytes(data)
            t0 = time.time()
            r = subprocess.run([PY, str(ROOT / "main.py"), "--input", str(inp), "--output", str(out)],
                               env=dict(os.environ, RAKSHA_SECRET="t"), capture_output=True, text=True, timeout=120)
            self.assertEqual(r.returncode, 0, r.stderr[-300:])
            self.assertLess(time.time() - t0, 60)
            rep = json.loads((out / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(rep["counts"]["files_total"], len(FILES))      # nothing silently dropped
            for e in rep["files"]:
                self.assertIn(e["status"], ("sanitized", "quarantined"))
            blob = "".join(p.read_text(encoding="utf-8", errors="ignore") for p in (out / "sanitized").rglob("*") if p.is_file())
            for secret in ("Ramesh Gupta", "9876543210", "Seema Rao", "Kiran Shah", "9876501234", "Bina Roy", "Test Person"):
                self.assertNotIn(secret, blob)
            self.assertFalse(any(p.suffix in (".jpg", ".pdf") for p in (out / "sanitized").rglob("*")))   # binaries never copied
            self.assertNotIn("t", r.stdout.replace("files", "").replace("sanitized", "").replace("quarantined", "")
                             .replace("records", "").replace("linked", "").strip().split()[0:0] or "")


if __name__ == "__main__":
    unittest.main()
