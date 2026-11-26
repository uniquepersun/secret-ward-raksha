"""Obfuscated-PII regression (the official scorer decodes these before counting). Run: python -m unittest discover -s tests"""
import base64, os, subprocess, sys, tempfile, unittest, urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = str(ROOT / ".venv/bin/python") if (ROOT / ".venv/bin/python").exists() else sys.executable
REG = "UHID,Patient Name,Mobile\nATK-1,Kishorilal Bhandari,9811122233\nATK-2,Meenakshi Sundaram,9811199988\n"
CASES = {
    "zero_width": "Patient: Kishori​lal Bhan​dari called 98111​22233.",
    "homoglyph": "Name: Kіshorіlal Bhandarі. Phone 9811122233",
    "entities": "Patient &#75;ishorilal Bhandari, phone 98111&#50;2233, mail kb&#64;example.org",
    "percent": "ref=" + urllib.parse.quote("Kishorilal Bhandari 9811122233"),
    "hex": "blob " + "Kishorilal Bhandari 9811122233".encode().hex(),
    "b64": "attachment: " + base64.b64encode(b"Patient Kishorilal Bhandari phone 9811122233").decode(),
    "split_phone": "phone 98111\n22233 for the patient",
    "lowercase": "reviewed kishorilal bhandari today, bp high",
    "fullwidth": "Name Ｋｉｓｈｏｒｉｌａｌ Ｂｈａｎｄａｒｉ",
    "link": "https://wa.me/919811122233?text=Hi mailto:kb@example.org",
    "double_b64": base64.b64encode(base64.b64encode(b"Kishorilal Bhandari 9811122233")).decode(),
}
SECRETS = ["Kishorilal", "Bhandari", "9811122233", "kishorilal"]


class Attacks(unittest.TestCase):
    def test_obfuscated_pii_is_removed(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "in").mkdir()
            (Path(d) / "in/reg.csv").write_text(REG, encoding="utf-8")
            for k, v in CASES.items():
                (Path(d) / f"in/{k}.txt").write_text(v, encoding="utf-8")
            subprocess.run([PY, str(ROOT / "main.py"), "--input", d + "/in", "--output", d + "/out"],
                           env=dict(os.environ, RAKSHA_SECRET="t"), check=True, capture_output=True)
            for k in CASES:
                out = (Path(d) / f"out/sanitized/{k}.txt").read_text(encoding="utf-8")
                dec = out
                for blob in __import__("re").findall(r"[A-Za-z0-9+/=]{16,}", out):
                    for _ in range(2):
                        try:
                            blob = base64.b64decode(blob + "=" * (-len(blob) % 4)).decode("utf-8")
                            dec += " " + blob
                        except Exception:
                            try:
                                dec += " " + bytes.fromhex(blob).decode("utf-8")
                            except Exception:
                                break
                for s in SECRETS:
                    self.assertNotIn(s, dec, f"{k}: {s}")


if __name__ == "__main__":
    unittest.main()
