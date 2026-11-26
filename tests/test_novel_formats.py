"""A hand-made dataset in formats unlike the practice data. Run: python -m unittest discover -s tests"""
import os, subprocess, sys, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = str(ROOT / ".venv/bin/python") if (ROOT / ".venv/bin/python").exists() else sys.executable
REG = ("Case Ref,Pt Full Name,Sex,Born,Guardian,Residence,Locality,Postal,Cell,Govt ID\n"
       "MRN-88123,Chandrakant Bhosale,M,04-Mar-1971,Pushpa Bhosale,\"Plot 14, Shivaji Chowk, Near Mahadev Temple\",Sawargaon,411045,+91-98221-33445,Aadhaar 4521 7788 9012\n"
       "MRN-88124,Vaishali Kulkarni,F,19 July 1985,Prakash Kulkarni,\"Flat 3B, Ganesh Apartments\",Talegaon,410507,(0212) 5567788,Aadhaar 6612 0034 5521\n")
NOTE = ("Bed 3: Chandrakant Bhosale (MRN-88123), 55 yrs M, c/o chest pain. BP 150/90. Tab Aspirin 75mg 1-0-0.\n"
        "His wife Pushpa Bhosale at bedside, reachable on 98221 33445.\n"
        "Bed 5: Vaishali ji ki sugar 245 mg/dL, Metformin 500mg BD. Husband Prakash Kulkarni informed.\n"
        "Dr. Anil Deshmukh reviewed.\nSocial worker: Ms. Revati Joglekar, family contact Sudhir Joglekar 9890011223.\n")


class Novel(unittest.TestCase):
    def test_no_leaks_and_no_cross_patient_pseudonyms(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "in").mkdir()
            (Path(d) / "in/reg.csv").write_text(REG, encoding="utf-8")
            (Path(d) / "in/note.txt").write_text(NOTE, encoding="utf-8")
            r = subprocess.run([PY, str(ROOT / "main.py"), "--input", d + "/in", "--output", d + "/out"],
                               env=dict(os.environ, RAKSHA_SECRET="t"), capture_output=True, text=True)
            self.assertEqual(r.returncode, 0)
            out = (Path(d) / "out/sanitized/note.txt").read_text(encoding="utf-8")
            csv_out = (Path(d) / "out/sanitized/reg.csv").read_text(encoding="utf-8")
            for leak in ["Chandrakant", "Bhosale", "Pushpa", "Vaishali", "Kulkarni", "Revati", "Joglekar", "Sudhir",
                         "98221", "9890011223", "5567788", "4521", "MRN-88123"]:
                self.assertNotIn(leak, out + csv_out, leak)
            for keep in ["Dr. Anil Deshmukh", "Aspirin 75mg 1-0-0", "150/90", "245 mg/dL", "Metformin 500mg BD"]:
                self.assertIn(keep, out)
            self.assertIn("Pt Full Name", csv_out)                           # header words are not names
            self.assertEqual(len(set(__import__("re").findall(r"PSN-\w{8}", out))), 1)   # only the first patient's pseudonym


if __name__ == "__main__":
    unittest.main()
