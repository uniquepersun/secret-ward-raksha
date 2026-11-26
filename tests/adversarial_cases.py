"""Novel, unseen-style snippets. (text, must_be_removed[list], must_survive[list]). Run: python tests/adversarial_cases.py"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from raksha.detect import Lexicon, find_spans
from raksha.privacy import band_ages_in_text

CASES = [
 ("Patient: Lalitha Venkatesh, 52 yrs F. Contact 98450 12345.", ["Lalitha Venkatesh", "98450 12345"], ["52"]),
 ("Pt. Name - Omprakash Tiwari; Relative: Hari Tiwari; Ph (0522) 2345678", ["Omprakash Tiwari", "Hari Tiwari", "2345678"], []),
 ("Son of Shri Baldev Raj Sharma, resident of Gram Rampur, Distt. Etawah", ["Baldev Raj Sharma", "Rampur"], ["Etawah"]),
 ("पिता का नाम: रामलाल यादव, मोबाइल: ९८३९१२३४५६", ["रामलाल यादव", "९८३९१२३४५६"], []),
 ("Smt. Kavita Devi w/o Shri Rajan Lal admitted with fever", ["Kavita Devi", "Rajan Lal"], ["fever"]),
 ("Aadhaar: XXXX-XXXX-1234 ABHA: ramesh.k@abdm PAN: BQRPK4821J", ["1234", "ramesh.k@abdm", "BQRPK4821J"], []),
 ("Informant: Neelam Kapoor (sister) 9810099100", ["Neelam Kapoor", "9810099100"], ["sister"]),
 ("Referred by Dr. Anil Joshi. Next of kin: Sunil Joshi, brother.", ["Sunil Joshi"], ["Dr. Anil Joshi", "brother"]),
 ("Tab Metformin 500mg 1-0-1 x 30 days; BP 140/90; Hb 11.2 g/dL; C/O chest pain", [], ["Metformin 500mg 1-0-1", "140/90", "11.2 g/dL", "C/O chest pain"]),
 ("Known case of Parkinson's disease and Hodgkin lymphoma, on Levodopa 100mg TDS", [], ["Parkinson's disease", "Hodgkin lymphoma", "Levodopa 100mg TDS"]),
 ("Contact person: Tenzin Dorjee, phone 91-8800112233", ["Tenzin Dorjee", "8800112233"], []),
 ("Mr. Aarav Mehta, 34 years old male, UHID MH-2026-004512", ["Aarav Mehta", "MH-2026-004512"], ["34"]),
 ("Emergency contact - Pooja Reddy (wife) +91 99001 22334", ["Pooja Reddy", "99001 22334"], ["wife"]),
 ("Sample collected from Farhan Qureshi at bedside; reported to Dr. Meena Iyer", ["Farhan Qureshi"], ["Dr. Meena Iyer"]),
 ("mob no. 6201234567 / alt 07408123456", ["6201234567", "07408123456"], []),
 ("Shobha ji ki dawa Dolo 650 BD x 5 days de di gayi", ["Shobha"], ["Dolo 650 BD x 5 days"]),
 ("Visitor: Gurdev Singh Sandhu entered at 17:40", ["Gurdev Singh Sandhu"], ["17:40"]),
 ("Caller Ananya Bose reported fall, ward 3 bed 7", ["Ananya Bose"], ["ward 3 bed 7"]),
 ("Guardian: Tabassum Khatoon, Mohalla Chowk, near Jama Masjid, PIN 226003", ["Tabassum Khatoon", "Chowk", "Jama Masjid", "226003"], []),
 ("shahid sahab ka BP theek hai, dawa de di", ["shahid"], ["BP theek hai"]),
 ("Born 12 अप्रैल 1977, admitted 3 मई 2026", ["12 अप्रैल 1977", "3 मई 2026"], []),
 ("Call nine eight one one one two two two three three for the report", ["nine eight one one one two two two three three"], ["report"]),
 ("फोन नंबर नौ आठ एक एक एक दो दो दो तीन तीन है", ["नौ आठ एक एक एक दो दो दो तीन तीन"], []),
 ("Patient K i s h o r i l a l B h a n d a r i arrived", ["K i s h o r i l a l"], ["arrived"]),
 ("Name: Kishori-\nlal Bhandari seen today", ["Kishori-\nlal"], ["seen today"]),
 ("Yesterday Ramchandra Joshi came with fever and cough", ["Ramchandra Joshi"], ["fever and cough"]),
 ("The family said Raghunath stayed overnight with the patient", ["Raghunath"], ["stayed overnight"]),
 ("मोहम्मद इमरान की बेटी फातिमा बानो भर्ती है", ["फातिमा बानो", "मोहम्मद इमरान"], ["भर्ती है"]),
 ("रोगी का भाई - गोलू आया", ["गोलू"], ["आया"]),
 ("अटेंडेंट: दीपक शर्मा (बेटा)", ["दीपक शर्मा"], []),
 ("मरीज की माँ सीता बाई ने बताया", ["सीता बाई"], ["ने बताया"]),
 ("Name - geeta rani admitted", ["geeta rani"], ["admitted"]),
 ("Mob 9876543210x call", ["9876543210"], ["call"]),
 ("Resident of Sitapur 261001 near the road", ["261001"], []),
 ("Rampur gaon, Sitapur district", ["Rampur"], []),
 ("Father's name: Ramasprasad Verma", ["Ramasprasad Verma"], []),
 ("Caregiver: Gudiya didi stayed", ["Gudiya"], ["stayed"]),
 ("Patient 50/F seen today", [], ["50/F"]),
 ("Lotus Care Hospital reviewed the case", [], ["Lotus Care Hospital"]),
 ("write x at gmail dot com", ["x at gmail dot com"], []),
 ("Insurance PMJAY-UP-5521908834 policy POL/21/99887766 claim BL/26/00123", ["5521908834", "99887766", "BL/26/00123"], []),
]

def main():
    lx = Lexicon()
    lx.add_name("Shahid Khan"); lx.add_name("Kishorilal Bhandari")      # lowercase "shahid sahab" must still be caught once the name is known
    bad = 0
    for text, gone, stay in CASES:
        out, pos = [], 0
        for s in find_spans(text, lx):
            out += [text[pos:s.start], "#" * (s.end - s.start)]
            pos = s.end
        res = "".join(out) + text[pos:]
        from raksha.privacy import shift_text_dates
        res, _ = shift_text_dates(res, 37, "dmy")
        miss = [g for g in gone if g in res]
        lost = [k for k in stay if k not in res]
        if miss or lost:
            bad += 1
            print("FAIL:", text, "\n   leaked:", miss, " lost:", lost, "\n   ->", res)
    print(f"{len(CASES) - bad}/{len(CASES)} adversarial cases pass")
    return bad

if __name__ == "__main__":
    sys.exit(1 if main() else 0)
