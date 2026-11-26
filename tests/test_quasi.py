"""Quasi-identifier defences: 'who was treated for what, and when'. Run: python -m unittest discover -s tests"""
import os, subprocess, sys, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = str(ROOT / ".venv/bin/python") if (ROOT / ".venv/bin/python").exists() else sys.executable
sys.path.insert(0, str(ROOT))


class Shifts(unittest.TestCase):
    def test_shift_is_never_small_and_stays_within_a_year(self):
        from raksha import privacy
        privacy.configure(b"k")
        mags = [abs(privacy.shift_days(f"patient-{i}")) for i in range(500)]
        self.assertGreaterEqual(min(mags), 90)        # the visit month cannot survive
        self.assertLessEqual(max(mags), 365)          # a shifted DOB stays within a year (utility)
        self.assertGreater(len({privacy.shift_days(f"p{i}") for i in range(200)}), 100)


class RareConditions(unittest.TestCase):
    def test_rare_condition_is_generalised_common_one_is_kept(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "in").mkdir()
            names = ["Asha Rao", "Ravi Menon", "Neha Iyer", "Omkar Joshi"]
            for i, n in enumerate(names):
                dx = "Crohn's disease, unspecified (K50.9)" if i == 0 else "Anaemia, unspecified (D64.9)"
                (Path(d) / f"in/ds{i}.txt").write_text(
                    f"Patient Name: {n}\nUHID: UH-100{i}\nDiagnosis: {dx}\nTab Paracetamol 650mg 1-1-1\nDate of Admission: 02/03/2026\n", encoding="utf-8")
            subprocess.run([PY, str(ROOT / "main.py"), "--input", d + "/in", "--output", d + "/out"],
                           env=dict(os.environ, RAKSHA_SECRET="t"), check=True, capture_output=True)
            rare = (Path(d) / "out/sanitized/ds0.txt").read_text(encoding="utf-8")
            common = (Path(d) / "out/sanitized/ds1.txt").read_text(encoding="utf-8")
            self.assertNotIn("K50.9", rare)
            self.assertNotIn("Crohn", rare)
            self.assertIn("[RARE CONDITION]", rare)
            self.assertIn("Tab Paracetamol 650mg 1-1-1", rare)        # treatments / doses of the patient stay
            self.assertIn("Anaemia, unspecified (D64.9)", common)     # a common condition is medical data: kept exactly


if __name__ == "__main__":
    unittest.main()
