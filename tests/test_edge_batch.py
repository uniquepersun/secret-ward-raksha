"""Structural edge cases found by the third test batch. Run: python -m unittest discover -s tests"""
import os, subprocess, sys, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = str(ROOT / ".venv/bin/python") if (ROOT / ".venv/bin/python").exists() else sys.executable
REG = "UHID,Name,Age,Sex,Phone\nE-1001,Kiran Patil,34,F,9876501001\nE-1002,Ganga Devi,61,F,9876501002\nE-1003,Rose Fernandes,29,F,9876501003\n"
FILES = {
    "semicolon.csv": ("id;name;phone;note\nE-1001;Kiran Patil;9876501001;\"line one\nline two with 9876501002\"\n",
                      ["Kiran Patil", "9876501001", "9876501002"], ["id;name;phone;note", "line one", "line two with"]),
    "amounts.csv": ("bill,patient,amount_inr,ref\nB1,Kiran Patil,1500000,x\nB2,Ganga Devi,123456789012,x\n",
                    ["Kiran Patil", "Ganga Devi"], ["1500000", "123456789012"]),
    "lines.json": ('{"name":"Kiran Patil"}\n{"name":"Ganga Devi","phone":"9876501002"}\n', ["Kiran Patil", "Ganga Devi", "9876501002"], []),
    "collide.txt": ("Kiran Patil complained of fever. Rose Fernandes reviewed; rose in BP noted. Tab Crocin 500mg.",
                    ["Kiran Patil", "Rose Fernandes"], ["rose in BP", "Tab Crocin 500mg", "fever"]),
}


class EdgeBatch(unittest.TestCase):
    def test_cases(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "in").mkdir()
            (Path(d) / "in/reg.csv").write_text(REG, encoding="utf-8")
            for n, (t, _, _) in FILES.items():
                (Path(d) / "in" / n).write_text(t, encoding="utf-8")
            subprocess.run([PY, str(ROOT / "main.py"), "--input", d + "/in", "--output", d + "/out"],
                           env=dict(os.environ, RAKSHA_SECRET="t"), check=True, capture_output=True)
            for n, (_, go, stay) in FILES.items():
                out = (Path(d) / "out/sanitized" / n).read_text(encoding="utf-8")
                for g in go:
                    self.assertNotIn(g, out, f"{n}: {g}")
                for s in stay:
                    self.assertIn(s, out, f"{n}: {s}")


if __name__ == "__main__":
    unittest.main()
