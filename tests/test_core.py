"""Run: .venv/bin/python -m unittest discover -s tests -v   (offline, ~1 s)."""
import datetime as dt
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from raksha import privacy
from raksha.detect import Lexicon, find_spans
from raksha.link import Ev, Linker, name_set
from raksha.translit import skeleton


def lexicon(*names):
    lx = Lexicon()
    for n in names:
        lx.add_name(n)
    return lx


def scrub(text, lx=None):
    lx = lx or lexicon()
    out, pos = [], 0
    for s in find_spans(text, lx):
        out += [text[pos:s.start], f"<{s.kind}>"]
        pos = s.end
    return "".join(out) + text[pos:]


class MeaningTraps(unittest.TestCase):
    def test_complaint_vs_relative(self):
        self.assertEqual(scrub("C/O fever for 3 days"), "C/O fever for 3 days")
        self.assertIn("<NAME>", scrub("C/O Ramesh Gupta, house near school"))

    def test_history_codes_are_not_names(self):
        self.assertEqual(scrub("No K/C/O DM/HTN. K/C/O addison's disease"), "No K/C/O DM/HTN. K/C/O addison's disease")

    def test_doctor_stays_relative_goes(self):
        lx = lexicon("Ramesh Yadav")
        t = scrub("Dr. Ramesh Srivastava reviewed. S/o Ramesh Yadav", lx)
        self.assertIn("Dr. Ramesh Srivastava", t)
        self.assertNotIn("Ramesh Yadav", t)

    def test_doses_and_vitals_survive(self):
        t = "Tab Dolo 650 BD x 5 days, Ramipril 5 mg 1-0-1, BP 150/90, Hb 9.9 g/dL, Parkinson's disease, Hodgkin lymphoma"
        self.assertEqual(scrub(t), t)

    def test_asha_worker_is_not_asha_the_patient(self):
        lx = lexicon("Asha Rajput")
        self.assertEqual(scrub("Referred by ASHA worker", lx), "Referred by ASHA worker")
        self.assertIn("<NAME>", scrub("Report of Asha ji 48 Y / F", lx))


class Identifiers(unittest.TestCase):
    def test_phone_formats(self):
        for p in ["+91 72864 90658", "072864-90658", "7286490658", "(72864) 90658", "+91-7286490658", "७२८६४९०६५८"]:
            self.assertIn("<ID>", scrub(f"call {p} now"), p)

    def test_aadhaar_abha_pan_email(self):
        for v in ["3972 0583 9628", "91-7938-3729-8403", "ABCDE1234F", "a.b@x.org", "XXXX XXXX 5866"]:
            self.assertIn("<ID>", scrub(f"id {v}"), v)

    def test_ranges_uuids_and_codes_are_kept(self):
        for t in ['<div xmlns="http://www.w3.org/1999/xhtml">x</div>', "id 6cd93b57-6d6d-453c-aaf2-829280011963 ok",  '"system": "http://terminology.hl7.org/CodeSystem/v2-0203"', "range 150000-410000", "urn:uuid:3e8b02cd-9e10-4da8-9053-d47573e43248", "ICD D64.9 LOINC 718-7 pkg SG050A"]:
            self.assertEqual(scrub(t), t)


class CrossScript(unittest.TestCase):
    def test_skeletons_collapse_variants(self):
        self.assertEqual(skeleton("Mohammad"), skeleton("मोहम्मद"))
        self.assertEqual(skeleton("Mohd."), skeleton("Md"))
        self.assertEqual(skeleton("Shahid"), skeleton("शाहिद"))
        self.assertEqual(skeleton("Reena"), skeleton("Rina"))

    def test_devanagari_name_found_via_latin_lexicon(self):
        self.assertIn("<NAME>", scrub("मोहम्मद शाहिद को बुखार है", lexicon("Shahid Khan")))


class Privacy(unittest.TestCase):
    def setUp(self):
        privacy.configure(b"unit-test-secret")

    def test_interval_preserved_and_format_kept(self):
        a, _ = privacy.shift_text_dates("Admitted 02/01/2026, discharged 02/06/2026", 37, "mdy")
        import re
        d = [dt.datetime.strptime(x, "%m/%d/%Y") for x in re.findall(r"\d\d/\d\d/\d{4}", a)]
        self.assertEqual(len(d), 2)
        self.assertEqual((d[1] - d[0]).days, 5)

    def test_band_contains_age(self):
        for age in range(0, 100):
            lo, hi = privacy.band(age).rstrip("+").split("-")[0], privacy.band(age)
            self.assertLessEqual(int(lo), age)
            if "-" in hi:
                self.assertGreaterEqual(int(hi.split("-")[1]), age)

    def test_keys_change_with_secret(self):
        a = privacy.pseudonym("k")
        privacy.configure(b"other")
        self.assertNotEqual(a, privacy.pseudonym("k"))


class Linkage(unittest.TestCase):
    def ev(self, name, **kw):
        e = Ev(names=[name_set(name.split())])
        for k, v in kw.items():
            setattr(e, k, v)
        return e

    def test_homonyms_stay_apart(self):
        a = self.ev("Rakesh Verma", age=40, village=("rjpr",), rels=[name_set(["Mohan", "Verma"])])
        b = self.ev("Rakesh Verma", age=62, village=("snjy",), rels=[name_set(["Hari", "Verma"])])
        roots = Linker([a, b]).run()
        self.assertNotEqual(roots[0], roots[1])

    def test_same_person_links_on_second_clue(self):
        a = self.ev("Rakesh Verma", age=40, village=("rjpr",))
        b = self.ev("Rakesh Verma", age=41, village=("rjpr",))
        roots = Linker([a, b]).run()
        self.assertEqual(roots[0], roots[1])

    def test_conflicting_aadhaar_blocks_merge(self):
        a = self.ev("Rakesh Verma", ids={"UHID1"}, strong={("AADHAAR", "111122223333")})
        b = self.ev("Rakesh Verma", ids={"UHID1"}, strong={("AADHAAR", "999988887777")})
        roots = Linker([a, b]).run()
        self.assertNotEqual(roots[0], roots[1])


class IndexDocuments(unittest.TestCase):
    def test_list_record_cannot_bridge_patients(self):
        from raksha.pipeline import Pipeline
        index = Ev(ids={"JJC1", "JJC2", "JJC3", "JJC4", "JJC5"}, cores={"11111", "22222"})
        a = Ev(ids={"JJC1"}, names=[name_set(["Asha", "Rao"])])
        b = Ev(ids={"JJC2"}, names=[name_set(["Ravi", "Menon"])])
        evs = [a, b, Pipeline._plausible(index)]
        roots = Linker(evs).run()
        self.assertNotEqual(roots[0], roots[1])          # two different patients stay apart
        self.assertEqual(evs[2].ids, set())              # the index owns no identity

    def test_two_aadhaar_numbers_in_one_record_are_dropped(self):
        from raksha.pipeline import Pipeline
        e = Ev(strong={("AADHAAR", "111122223333"), ("AADHAAR", "444455556666"), ("PAN", "ABCDE1234F")})
        e = Pipeline._plausible(e)
        self.assertEqual({t for t, _ in e.strong}, {"PAN"})


if __name__ == "__main__":
    unittest.main()
