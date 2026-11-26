"""Sandbox hardening: pathological inputs must neither stall nor crash the run. Run: python -m unittest discover -s tests"""
import json, os, subprocess, sys, tempfile, time, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = str(ROOT / ".venv/bin/python") if (ROOT / ".venv/bin/python").exists() else sys.executable
sys.path.insert(0, str(ROOT))


class Floods(unittest.TestCase):
    def test_cue_plus_whitespace_floods_are_fast(self):
        from raksha.detect import Lexicon, find_spans
        lx = Lexicon()
        worst = 0.0
        for cue in ["C/O", "ward", "house", "Name:", "village", "S/o", "वार्ड", "pin", "near"]:
            for fill in (" ", "\t", "\n"):
                t0 = time.time()
                find_spans(", " + cue + fill * 120_000 + "x", lx)
                worst = max(worst, time.time() - t0)
        self.assertLess(worst, 3.0, f"slowest flood took {worst:.1f}s")


class Confinement(unittest.TestCase):
    def test_write_target_cannot_escape_sanitized(self):
        from raksha.pipeline import Pipeline
        root = Path(tempfile.mkdtemp()) / "sanitized"
        root.mkdir()
        self.assertTrue(Pipeline.confined(root / "a/b.txt", root))
        self.assertFalse(Pipeline.confined(root / "../evil.txt", root))
        self.assertFalse(Pipeline.confined(Path("/etc/passwd"), root))


class Timeouts(unittest.TestCase):
    def test_forced_timeout_quarantines_instead_of_crashing(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "in").mkdir()
            for i in range(3):
                (Path(d) / f"in/n{i}.txt").write_text("Name: Ravi Kumar, mobile 9876543210. " * 2000, encoding="utf-8")
            (Path(d) / "pol.yaml").write_text("regex_timeout_s: 0.000001\n")
            r = subprocess.run([PY, str(ROOT / "main.py"), "--input", d + "/in", "--output", d + "/out", "--policy", d + "/pol.yaml"],
                               env=dict(os.environ, RAKSHA_SECRET="t"), capture_output=True, text=True, timeout=120)
            self.assertEqual(r.returncode, 0, r.stderr[-200:])
            rep = json.loads((Path(d) / "out/report.json").read_text(encoding="utf-8"))
            self.assertEqual(rep["counts"]["files_total"], 3)                     # nothing silently dropped
            blob = "".join(p.read_text(encoding="utf-8") for p in (Path(d) / "out/sanitized").rglob("*") if p.is_file())
            self.assertNotIn("Ravi Kumar", blob)                                  # a stalled file is quarantined, never exported raw
            self.assertNotIn("9876543210", blob)


if __name__ == "__main__":
    unittest.main()
