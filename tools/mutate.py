#!/usr/bin/env python3
"""Dev-only: build an 'unseen format' proxy of the practice data (and a matching truth file).

    python3 tools/mutate.py --kit ../Secret-Wards-ToolKit --out /tmp/mut1 --seed 1

Mutations (all consistent between inputs and truth, so check_dev.py scores the result unchanged):
  names      every patient/relative name token -> an unseen name (Latin), case pattern preserved
  ids        hospital-id prefixes renamed (SNJ/JJH/UHID/...)
  phones     10-digit phones re-formatted
  headers    CSV headers and JSON leaf keys renamed (English / Hinglish / Hindi), CSV columns shuffled
  layout     CRLF line endings, BOMs
The score on this dataset is our proxy for the hidden unseen-format dataset. Never accept a change that
raises the practice score but lowers this one.
"""
import argparse, csv, hashlib, io, json, random, re, shutil
from pathlib import Path

GIVEN = """Aadil Bhuvan Chirag Devansh Eshaan Faizan Girish Harsh Indrajit Jatin Kabir Lakshya Madhav Nakul Omkar Pranav
Qamar Rudra Samar Tanmay Udit Vedant Waqar Yatin Zaheer Aaradhya Bhavya Charu Disha Esha Falak Gargi Hetal Ishita
Jahnavi Kriti Lavanya Mrinal Nidhi Oindrila Prachi Ridhima Saanvi Tanvi Urvashi Vaishali Yamini Zoya Advait Brijmohan
Chandrakant Dhruv Elango Firoz Gopal Hiten Ilyas Jignesh Kalpesh Laxmikant Manav Narayan Ojas Parth Raghav Siddharth
Tarak Umesh Vasant Wamiq Yuvraj Zubin Anvi Bindiya Chhaya Damini Eknoor Fiza Geetanjali Harleen Indu Jhanvi Kanika
Leela Madhuri Navya Ojaswi Paridhi Rasika Shreya Tripti Ujjwala Vrinda Yashika Zeba""".split()
SURN = """Bhardwaj Chakraborty Dixit Ekka Fernandes Gawande Hazarika Inamdar Jaiswal Khuntia Lingayat Mahajan Nayak Oberoi
Pradhan Qazi Raut Sabharwal Talwar Uppal Vohra Wadhwa Yadava Zacharia Barua Chandel Deol Eapen Gadkari Hooda Ingle Jindal
Kamboj Lamba Mallick Naskar Oraon Purohit Rangnekar Solanki Trivedi Upreti Vyas Wagh Zutshi Anand Biswas Cherian Dalal
Ganguly Haldar Iyyer Kakkar Lad Mehrotra Nanda Pathak Rawal Sodhi Tomar Vaidya""".split()
GENERIC = {"kumar", "devi", "singh", "kaur", "md", "mohd", "mohammad", "bano", "begum", "khan", "lal", "ram", "ji"}

HDR = {
    r"patient.?s? ?name|^name$|^naam$|patient_name": ["Pt. Full Name", "Naam (Patient)", "Beneficiary Name", "मरीज का नाम"],
    r"mobile|phone|^mob": ["Contact#", "Cell No.", "संपर्क नंबर", "Tel"],
    r"aadhaar|aadhar": ["UID Number", "आधार संख्या", "Govt ID No"],
    r"abha": ["Health ID", "ABHA Id"],
    r"^uhid$|reg no|patient_ref|hospital_uhid|^uhid": ["Hospital Ref", "MRN", "File No."],
    r"^dob$|date of birth|janm": ["Date of Birth", "Born On", "DOB (dd-mm-yy)"],
    r"^age$|^umar$": ["Years", "Patient Age", "आयु"],
    r"^address$|^pata$": ["Residence", "Pata", "पता"],
    r"village|^gaon$": ["Gram/Mohalla", "Locality", "Native Place"],
    r"relative name|guardian": ["Attendant Name", "Guardian / Spouse", "Sambandhi"],
    r"^pin|pin code": ["Postal Code", "ZIP"],
}
JKEY = {"name": "patient_fullname", "phone": "contact_no", "mobile": "contact_no", "uhid": "mrn", "hospital_uhid": "hosp_ref",
        "patient_ref": "pt_reference", "aadhaar": "uid", "aadhar_no": "govt_uid", "dob": "date_of_birth", "age": "years",
        "email": "mail", "pin": "postal", "village": "gaon", "address": "residence", "diagnosis": "dx"}


def case_like(src, new):
    return new.upper() if src.isupper() and len(src) > 1 else new.capitalize() if src[:1].isupper() else new.lower()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--kit", required=True); ap.add_argument("--out", required=True); ap.add_argument("--seed", type=int, default=1)
    a = ap.parse_args()
    rnd = random.Random(a.seed)
    kit, out = Path(a.kit), Path(a.out)
    t = json.loads((kit / "dev/truth/truth.json").read_text(encoding="utf-8"))
    shutil.rmtree(out, ignore_errors=True)
    (out / "dev/input").mkdir(parents=True)
    (out / "dev/truth").mkdir(parents=True)
    shutil.copytree(kit / "dev/attacker", out / "dev/attacker")

    # ---- name mapping (Latin tokens from patient / relative entities)
    toks = set()
    for f in t["files"].values():
        for u in f["units"].values():
            for e in u["entities"]:
                if e["type"] in ("PATIENT_NAME", "RELATIVE_NAME") and e["script"] != "deva":
                    for tk in re.findall(r"[A-Za-z]{3,}", e["surface"]):
                        if tk.lower() not in GENERIC:
                            toks.add(tk.lower())
    toks = sorted(toks)
    pool_g, pool_s = GIVEN[:], SURN[:]
    rnd.shuffle(pool_g); rnd.shuffle(pool_s)
    nmap = {}
    for i, tk in enumerate(toks):
        nmap[tk] = (pool_g if i % 2 == 0 else pool_s)[(i // 2) % len(pool_g if i % 2 == 0 else pool_s)]
    name_rx = re.compile(r"(?<![A-Za-z])(" + "|".join(sorted(map(re.escape, nmap), key=len, reverse=True)) + r")(?![A-Za-z])", re.I)

    idmap = {"SNJ": "SWH", "JJH": "JJC", "UHID": "MRNO", "ADM": "ADT", "DHH": "DHD", "IPD": "IPN", "PMJAY": "PMJ"}
    id_rx = re.compile(r"(?<![A-Za-z])(" + "|".join(idmap) + r")(?=[-/\d])")

    # ---- phone mapping from truth surfaces (exact string -> new format)
    phones = {}
    for f in t["files"].values():
        for u in f["units"].values():
            for e in u["entities"]:
                if e["type"] == "PHONE":
                    d = re.sub(r"\D", "", e["surface"])[-10:]
                    if len(d) == 10 and e["surface"] not in phones:
                        fmt = rnd.choice([f"{d[:5]} {d[5:]}", f"+91-{d}", f"0{d[:5]}-{d[5:]}", f"({d[:5]}) {d[5:]}", d, f"+91 {d[:5]} {d[5:]}"])
                        phones[e["surface"]] = fmt
    phone_items = sorted(phones.items(), key=lambda kv: -len(kv[0]))

    def mutate_text(s, deva_safe=True):
        s = name_rx.sub(lambda m: case_like(m.group(1), nmap[m.group(1).lower()]), s)
        s = id_rx.sub(lambda m: idmap[m.group(1)], s)
        for old, new in phone_items:
            if old in s:
                s = s.replace(old, new)
        return s

    def hdr_new(h):
        for pat, alts in HDR.items():
            if re.search(pat, h.strip().lower()):
                return alts[hash(h) % len(alts)] if False else alts[sum(map(ord, h)) % len(alts)]
        return h

    def rename_keys(node):
        if isinstance(node, dict):
            res = {}
            for k, v in node.items():
                nk = JKEY.get(k, k) if not isinstance(v, (list, dict)) else k
                res[nk] = rename_keys(v)
            return res
        if isinstance(node, list):
            return [rename_keys(x) for x in node]
        return node

    changed = 0
    for rel, f in t["files"].items():
        src = kit / "dev/input" / rel
        raw = src.read_bytes()
        enc = f["encoding"]
        dst = out / "dev/input" / mutate_text(rel)
        dst.parent.mkdir(parents=True, exist_ok=True)
        try:
            text = raw.decode({"utf-8-sig": "utf-8-sig"}.get(enc, enc))
        except (UnicodeDecodeError, LookupError):
            dst.write_bytes(raw)
            f["sha256"] = hashlib.sha256(raw).hexdigest()
            continue
        text = mutate_text(text)
        ext = src.suffix.lower()
        if f["format"] in ("csv", "tsv") and ext in (".csv", ".tsv") and not text.lstrip().startswith(("{", "[")):
            d = "\t" if ext == ".tsv" else ","
            rows = list(csv.reader(io.StringIO(text, newline=""), delimiter=d))
            if rows and enc not in ("cp1252",):
                hdr = [hdr_new(h) for h in rows[0]]
                perm = list(range(len(hdr)))
                if len({len(r) for r in rows}) == 1:     # shuffle only rectangular tables
                    rnd.shuffle(perm)
                buf = io.StringIO()
                w = csv.writer(buf, delimiter=d, lineterminator="\n")
                w.writerow([hdr[i] for i in perm])
                for r in rows[1:]:
                    w.writerow([r[i] for i in perm] if len(r) == len(hdr) else r)
                text = buf.getvalue()
        elif f["format"] in ("json", "fhir") and ext == ".json":
            try:
                text = json.dumps(rename_keys(json.loads(text)), ensure_ascii=False, indent=1)
            except (ValueError, RecursionError):
                pass
        if f["format"] in ("text", "csv", "tsv") and rnd.random() < 0.3:
            text = text.replace("\r\n", "\n").replace("\n", "\r\n")
        data = text.encode({"utf-8-sig": "utf-8-sig"}.get(enc, enc), errors="replace") if enc != "utf-16" else text.encode("utf-16")
        dst.write_bytes(data)
        f["sha256"] = hashlib.sha256(data).hexdigest()
        changed += 1

    # ---- rewrite truth strings consistently
    def walk(x):
        if isinstance(x, str):
            return mutate_text(x)
        if isinstance(x, list):
            return [walk(i) for i in x]
        if isinstance(x, dict):
            return {walk(k): walk(v) for k, v in x.items()}
        return x
    shas = {rel: f["sha256"] for rel, f in t["files"].items()}
    t2 = walk(t)
    new_files = {}
    for rel, f in t2["files"].items():
        new_files[rel] = f
    # files dict keys (paths) were rewritten by walk(); re-attach the new sha256 values
    for (old_rel, sha), (new_rel, f) in zip(shas.items(), new_files.items()):
        f["sha256"] = sha
    (out / "dev/truth/truth.json").write_text(json.dumps(t2, ensure_ascii=False), encoding="utf-8")
    print(f"mutated {changed} files; {len(nmap)} names, {len(phones)} phone formats -> {out}")


if __name__ == "__main__":
    main()
