"""Static vocabularies: negative gazetteer (never a person), honorifics, cue words, seed names.

All entries are public vocabulary (generic drug/disease/anatomy terms, common English words,
common South-Asian given names and surnames). Nothing here comes from the practice truth file.
Provenance is listed in DATA_SOURCES.md.
"""
import re

_w = lambda s: frozenset(x for x in s.lower().split())  # noqa: E731

# --- medical / clinical vocabulary: a Title-Case token here is NEVER a person ------------------
DRUGS = _w("""
paracetamol acetaminophen dolo crocin calpol ibuprofen diclofenac aspirin ecosprin clopidogrel atorvastatin
rosuvastatin simvastatin statin metformin glimepiride gliclazide insulin glargine amlodipine telmisartan losartan
ramipril enalapril lisinopril atenolol metoprolol bisoprolol carvedilol propranolol furosemide torsemide
spironolactone hydrochlorothiazide chlorthalidone digoxin amiodarone warfarin heparin enoxaparin rivaroxaban
pantoprazole omeprazole rabeprazole esomeprazole ranitidine famotidine domperidone ondansetron metoclopramide
amoxicillin amoxyclav augmentin azithromycin clarithromycin ceftriaxone cefixime cefuroxime cefpodoxime ciprofloxacin
levofloxacin ofloxacin norfloxacin doxycycline tetracycline gentamicin amikacin vancomycin meropenem imipenem
piperacillin tazobactam metronidazole tinidazole clindamycin linezolid cotrimoxazole nitrofurantoin fluconazole
itraconazole acyclovir oseltamivir ivermectin albendazole artesunate artemether lumefantrine chloroquine
hydroxychloroquine primaquine rifampicin isoniazid pyrazinamide ethambutol salbutamol levosalbutamol budesonide
formoterol ipratropium montelukast levocetirizine cetirizine fexofenadine chlorpheniramine prednisolone
prednisone dexamethasone hydrocortisone methylprednisolone levothyroxine carbimazole thyroxine folic ferrous
iron calcium vitamin cholecalciferol cyanocobalamin methylcobalamin zinc ors oral rehydration tramadol morphine
fentanyl diazepam alprazolam clonazepam lorazepam levetiracetam phenytoin valproate carbamazepine gabapentin
pregabalin amitriptyline escitalopram sertraline fluoxetine olanzapine risperidone haloperidol quetiapine
tamsulosin finasteride sildenafil tadalafil pioglitazone sitagliptin vildagliptin teneligliptin dapagliflozin
empagliflozin glibenclamide acarbose nifedipine diltiazem verapamil hydralazine clonidine isosorbide nitroglycerin
ranolazine ivabradine sacubitril trimetazidine lactulose bisacodyl loperamide racecadotril sucralfate
mebeverine dicyclomine drotaverine hyoscine tranexamic ethamsylate oxytocin misoprostol methotrexate
hydroxyurea allopurinol febuxostat colchicine alendronate saline dextrose ringer lactate normal
betadine povidone chlorhexidine lignocaine lidocaine bupivacaine propofol ketamine atropine adrenaline
noradrenaline dopamine dobutamine neostigmine glycopyrrolate cefoperazone sulbactam teicoplanin colistin
faropenem nimesulide aceclofenac etoricoxib naproxen serratiopeptidase thiocolchicoside
""")
DOSAGE_FORMS = _w("tab tablet tablets cap capsule capsules inj injection syp syrup susp suspension drops drop oint "
                  "ointment cream gel lotion spray inhaler nebulizer neb iv im sc po sos stat bd bid tds tid qid od "
                  "hs prn ac pc sl pr rx adv mg mcg ug g gm kg ml l iu units unit meq mmol dl")
LABS = _w("""
haemoglobin hemoglobin hb hba1c hct hematocrit platelet platelets wbc rbc tlc dlc esr crp cbc lft kft rft tft
bilirubin sgot sgpt ast alt alp ggt albumin globulin protein creatinine urea bun uric acid sodium potassium
chloride bicarbonate calcium magnesium phosphorus phosphate glucose sugar rbs fbs ppbs hba1c cholesterol
triglyceride triglycerides hdl ldl vldl tsh t3 t4 ft3 ft4 ferritin iron tibc vitamin b12 d3 troponin ck
cpk cpk-mb ldh amylase lipase inr pt aptt ptt dimer d-dimer procalcitonin ntprobnp lactate abg ph pco2 po2
hco3 spo2 pulse bp temp temperature weight height bmi urine culture sensitivity widal ns1 igm igg dengue
malaria hbsag hiv hcv vdrl rapid antigen antibody smear sputum afb gene xpert serology
""")
DISEASES = _w("""
fever dengue malaria typhoid enteric cholera jaundice hepatitis cirrhosis diabetes mellitus hypertension
hypotension anaemia anemia asthma copd bronchitis pneumonia tuberculosis tb covid influenza flu cough cold
sore throat tonsillitis sinusitis rhinitis pharyngitis otitis migraine headache epilepsy seizure stroke
paralysis angina infarction mi cad ihd heart failure chf arrhythmia atrial fibrillation af cardiomyopathy
valvular rheumatic endocarditis pericarditis nephritis nephrotic nephropathy uraemia ckd aki uti cystitis
pyelonephritis calculi stone renal calculus appendicitis cholecystitis cholelithiasis pancreatitis gastritis
gastroenteritis diarrhoea diarrhea dysentery constipation ulcer peptic gerd reflux hernia hemorrhoids piles
fistula fissure abscess cellulitis sepsis septicaemia shock dehydration hyponatremia hyperkalemia acidosis
alkalosis ketoacidosis dka hypoglycemia hyperglycemia thyroid hypothyroidism hyperthyroidism goitre goiter
obesity malnutrition rickets osteoporosis arthritis osteoarthritis gout spondylosis sciatica fracture
dislocation sprain cataract glaucoma conjunctivitis keratitis retinopathy deafness vertigo dermatitis eczema
psoriasis scabies fungal tinea urticaria cancer carcinoma lymphoma leukaemia leukemia tumour tumor sarcoma
melanoma neoplasm metastasis fibroid cyst polyp pcos pregnancy preeclampsia eclampsia abortion miscarriage
labour postpartum depression anxiety schizophrenia psychosis dementia delirium neuropathy encephalitis
meningitis chikungunya leptospirosis scrub typhus kala azar filariasis hookworm worm infestation
snakebite poisoning overdose burns trauma injury wound haematoma hematoma ascites effusion oedema edema
anuria oliguria dyspnoea dyspnea hypoxia cyanosis syncope palpitation chest pain abdomen abdominal
vomiting nausea ulti bukhar khansi dard pet sar chakkar kamzori weakness fatigue itching rash swelling
""")
ABBREV = _w("""dm dm2 t2dm t1dm htn cad ckd ihd copd tb cva mi af chf bph hiv gerd uti urti lrti tia dvt pe ards sob loc nad nil na wnl ama dama lama lscs fnac"""
)
EPONYMS = _w("""
parkinson parkinson's parkinsons alzheimer alzheimer's alzheimers hodgkin hodgkin's crohn crohn's crohns
addison addison's addisons cushing cushing's graves graves' basedow hashimoto hashimoto's down down's
turner turner's klinefelter huntington huntington's wilson wilson's marfan marfan's guillain barre
bell's bells raynaud raynaud's sjogren sjogren's behcet behcet's kawasaki paget paget's meniere meniere's
tourette tourette's asperger asperger's duchenne becker charcot-marie-tooth von willebrand willebrand
hirschsprung gilbert gilbert's reye reye's lyme zika ebola cooley's burkitt ewing's wegener
conn conn's kaposi mallory-weiss barrett's barretts dupuytren's peyronie's osgood-schlatter
""")
ANATOMY = _w("""
head neck chest abdomen pelvis spine back arm leg hand foot knee hip shoulder elbow wrist ankle eye ear nose
throat mouth tongue teeth gum skin heart lung lungs liver kidney kidneys spleen stomach intestine bowel colon
rectum bladder uterus ovary prostate breast brain nerve bone joint muscle artery vein blood vessel thyroid
pancreas gallbladder appendix hernia thorax cardiac renal hepatic pulmonary cerebral gastric
""")
PROCEDURES = _w("""
surgery operation procedure biopsy endoscopy colonoscopy bronchoscopy angiography angioplasty bypass cabg
dialysis haemodialysis hemodialysis transfusion ventilation intubation catheterisation catheterization
laparoscopic laparoscopy cholecystectomy appendectomy hernioplasty herniorrhaphy hysterectomy caesarean
cesarean lscs tonsillectomy phacoemulsification cataract iol lithotripsy turp nephrectomy mastectomy
thyroidectomy amputation debridement fixation arthroplasty replacement physiotherapy chemotherapy
radiotherapy ultrasound usg xray x-ray ct mri ecg ekg echo eeg emg doppler mammography pet scan
""")
UNITS = _w("mg ml mcg g dl l mmhg bpm min kg cm mm mmol iu meq mg/dl g/dl mmol/l miu/l ng/ml pg/ml ug/dl "
           "lakh lakhs days day weeks week wks wk months month mths yrs yr years year hrs hr hours hour times")

# --- ordinary English / Hindi-Hinglish function words and clinic vocabulary ---------------------
COMMON = _w("""vill village gram gaon grm tehsil tahsil taluk block distt district mohalla colony nagar ward makan house near opp opposite behind beside landmark janm tithi pin code reg date naam ling umar pata jila registration serum plasma whole total count random fasting postprandial routine panel profile function lipid cardiac complete haemogram haematology urine stool sample samples specimen collected received reference range ranges sodium potassium 
the a an and or of to in on at by for with without from into onto over under after before during about against
between through is are was were be been being am do does did has have had having will would shall should can
could may might must not no nor so than too very just also only own same such as if then else when where which
who whom whose why how all any both each few more most other some this that these those i me my we our you your
he him his she her it its they them their what there here up down out off again further once
patient patients name age sex gender male female male/female date time day week month year today tomorrow
yesterday morning evening night afternoon next last review follow followup follow-up advice advised admitted
admission discharge discharged diagnosis diagnoses history complaints complaint presenting course hospital
treatment treated conservatively stable condition medications medication medicine medicines investigation
investigations findings finding result results report reports test tests normal abnormal high low mild moderate
severe acute chronic known case cases clinical consult consultant doctor doctors dr nurse nursing staff ward
bed room icu opd ipd ot department dept medicine surgery orthopaedics paediatrics gynaecology obstetrics
cardiology neurology nephrology urology gastroenterology oncology psychiatry dermatology ent ophthalmology
radiology pathology biochemistry microbiology emergency casualty causality ambulance referral referred
referring procedure procedures done planned plan diet low salt diabetic regular soft liquid oral fluids
fluid rest exercise walk avoid continue stop start increase decrease dose doses daily twice thrice once
weekly monthly alternate needed required if/when sos stat now later soon early late good poor better worse
improved improving deteriorated unchanged vitals vital signs sign symptoms symptom pain relief relieved
attendant attendants informed informed. called call calls caller contact mobile phone phones address
village town city district tehsil block state country india indian uttar pradesh lucknow hardoi sitapur
unnao barabanki rae bareli sultanpur lakhimpur kheri kanpur faizabad ayodhya gonda bahraich basti
bank bill bills billing claim claims insurance policy package amount status settled pending approved rejected
registration registered reg registry export exports exported file files record records note notes summary
sheet form forms consent surgical scanned photo image attachment attachments letter referral discharge
list lists table data log logs ticket tickets helpdesk query billing visit visits visitor visitors round
rounds evening taking took given given. diya liya hai hain tha thi the ho hua hui hue gaya gayi gaye raha
rahi rahe kar karo karna karen kiya kiye ka ki ke ko ne se me mein par aur ya bhi nahi nhi ab abhi jab tab
kal aaj raat subah dopahar shaam din se tak liye lena dena lene dene wala wali wale mat dawa dawai goli
bukhar khansi dard pet sar sir bahut thoda zyada kam theek thik achha accha bura jyada sab kuch koi kuchh
ek do teen char paanch panch chhe saat aath nau das ghar yahan wahan idhar udhar kyun kyu kaise kaisa
kaun kab kitna kitne kitni paani pani khana khaana neend nind sona so ulti dast tatti peshab
""")
HOSPITAL_WORDS = _w("""
hospital hospitals multispeciality multispecialty speciality specialty charitable seva sadan sanjeevani jeevan
jyoti arogya district medical college institute centre center clinic nursing home diagnostics diagnostic
pathology laboratory lab labs lifeline pathkind city sadar community health primary phc chc cghs esi pmjay
ayushman bharat nhm govt government private limited ltd pvt trust foundation society mission
""")
GENERIC_NAME_PARTS = _w("""
kumar kumari devi singh kaur bano begum khatoon bibi lal prasad chand ram sri shri smt mr mrs ms md mohd
mohammad mohammed muhammad mo. mahmood sheikh shaikh khan ji sahab saheb sahib bhai bhaiya didi behen behenji
madam sir baba rani raj dev nath das
""")

HONORIFIC_PRE = ("mr", "mrs", "ms", "miss", "mx", "smt", "shri", "shree", "sri", "sh", "km", "kumari", "master",
                 "baby", "late", "mst", "kum", "श्री", "श्रीमती", "कु", "कुमारी", "मास्टर", "सुश्री", "स्व", "सर्वश्री",
                 "mohtarma", "janab", "hazrat", "sardar", "pt", "pandit")
HONORIFIC_POST = ("ji", "sahab", "saheb", "sahib", "bhai", "bhaiya", "bhaiyya", "didi", "behen", "behan", "behenji",
                  "behnji", "madam", "sir", "mata", "mataji", "babu", "bhabhi", "chacha", "chachi", "mausi", "tai",
                  "जी", "साहब", "साहेब", "भाई", "भैया", "दीदी", "बहन", "बहनजी", "बहनजी", "मैडम", "बाबू", "माता", "भाभी",
                  "चाचा", "चाची", "मौसी", "ताई", "अम्मा", "amma", "appa", "anna", "akka", "dada", "dadi", "nani", "nana")
DOCTOR_PRE = ("dr", "doctor", "डॉ", "डा", "डॉक्टर", "prof", "dr.")

RELATION_WORDS = ("s/o", "d/o", "w/o", "h/o", "c/o", "s/o.", "d/o.", "w/o.", "son of", "daughter of", "wife of",
                  "husband of", "father", "mother", "पुत्र", "पुत्री", "पत्नी", "पति", "सुपुत्र", "सुपुत्री", "पिता",
                  "माता", "द्वारा", "के", "attendant", "guardian", "spouse", "husband", "wife", "son", "daughter",
                  "father's name", "mother's name", "relative", "next of kin", "nok", "emergency contact")

# a small, diverse seed gazetteer (given names + surnames, many communities). Used only to *score*
# unlabelled Title-Case sequences; the run-time corpus lexicon (learned from structured name
# columns) is the main source of names, so unseen names are still handled.
SEED_GIVEN = _w("""
aarav aarti abdul abhay abhishek aditya ajay ajit akash akhil alok aman amit amita amrita anand anil anita
anjali ankit ankita anuj anupam anuradha arjun arun aruna arvind asha ashok ashwin atul ayesha babita balram
bhavna bharat bhawna bhim bijay brijesh chandan chetan deepak deepika devendra dharmendra dilip dinesh divya
farhan fatima fatma gagan ganesh ganga gaurav geeta gita govind gulab gurpreet hamid hanif hari harish
harpreet hema hemant imran imtiaz irfan ishwar jagdish jaspreet jaya jyoti kailash kamal kamla kanchan kapil
karan kavita kavya kiran kishore krishna kuldeep lakshmi lalita lata lalit mahesh mahendra mahima manish
manoj manju mansi meena meera mehul mina mohan mohit mukesh mumtaz muskan nadeem naseem naveen neelam neeraj
neha nikhil nirmala nisha nitin om omprakash pankaj parvati pawan poonam pooja prabhat pradeep prakash pramod
pratibha preeti priya priyanka puja pushpa radha rahul raj rajan rajendra rajesh rajni rakesh ram ramesh
ramesh rampal ranjit rashid ravi rekha renu reena rina rita rohit roshan sachin sadhna sandeep sanjay
sanjeev santosh sapna sarita saroj satish savita seema shabana shahid shanti sharad shiv shivani shobha
shyam sita sonia sonu subhash sudha sudhir sukhwinder sumit sunil sunita suresh surendra sushil sushma
swati tarun tej usha vandana vijay vikas vikram vimla vinay vinod vishal vivek yash yogesh yusuf zainab
zubair zakir zarina salma sana sabina saira shabnam shamim shaukat sultan tahir umar uzma wasim zeenat
mukesh asif akbar anwar aslam bilal farida gulshan haseena iqbal jameel javed
kaleem khalid mehboob mushtaq nasir naeem parveen qasim rafiq rukhsar sabir shakeel shahnaz tabassum
jagmohan harjeet gurmeet manpreet navjot simran amarjeet balwinder jasbir kulwant paramjit rajinder
sandhya sarla shakuntala sumitra urmila vidya yashoda lakshman bhagwan dayaram ghanshyam hariom jitendra
kailashi mamta maya nandini padma prem rama sarojini subhadra tulsi uma vasudha
""")
SEED_SURNAME = _w("""
sharma verma gupta mishra pandey tiwari tripathi dubey shukla srivastava agarwal agrawal jain singhal
yadav kushwaha maurya patel chauhan rajput thakur rathore bisht negi rawat chaudhary chaudhry choudhary
nishad paswan kori pal gautam jatav valmiki bhatt joshi kulkarni deshpande patil jadhav pawar shinde more
iyer iyengar nair menon pillai reddy naidu rao shetty hegde gowda bhattacharya banerjee chatterjee mukherjee
ghosh das dutta sen bose roy sarkar saha mondal khan ansari siddiqui qureshi sheikh shaikh pathan
mirza syed hussain ahmed ahmad ali alam akhtar rizvi naqvi kazmi zaidi baig lodhi khatri arora kapoor
kapur malhotra mehra chopra bedi sethi bajaj ahuja kohli bhalla grewal gill sandhu dhillon brar sidhu
bhasin tandon saxena kulshrestha chandra rastogi bajpai awasthi shrivastava nigam mathur kayastha
kashyap vishwakarma lohar sonkar prajapati kumhar nai sahu gupt bansal goel mittal garg singla
dwivedi chaturvedi upadhyay vajpayee sinha prasad jha mahto mandal thapa gurung tamang sherpa lepcha
namboodiri varma warrier kurup panicker bhattacharjee dorji bhutia
""")
STOP_NAME_TOKENS = _w("""
age sex uhid mrn ipd opd mobile mob phone ph tel contact address addr aadhaar aadhar abha pan dob date
admission discharge diagnosis ward bed consultant doctor relation village tehsil district pin gender
complaint complaints history rx advice review follow status email id no number
उम्र आयु लिंग ग्राम गाँव गांव पता तारीख मोबाइल फोन नंबर जन्म
""")

NEG_ALL = (ABBREV | DRUGS | DOSAGE_FORMS | LABS | DISEASES | EPONYMS | ANATOMY | PROCEDURES | UNITS | COMMON
           | HOSPITAL_WORDS)

MED_SUFFIX = re.compile(r"(?:itis|osis|aemia|emia|pathy|plasty|scopy|ectomy|otomy|ostomy|algia|oma|rrhoea|rrhea|"
                        r"cillin|mycin|micin|floxacin|azole|azine|pril|sartan|olol|statin|gliptin|glitazone|"
                        r"oxacin|vir|mab|nib|dipine|thiazide|semide|barbital|zepam|zolam|caine|profen|"
                        r"cycline|cef\w+|prazole|tidine|setron|terol|lukast|sone|solone|parin|xaban)$", re.I)


def is_medical_token(tok: str) -> bool:
    t = tok.lower().strip(".,;:()[]'\"")
    if t in NEG_ALL:
        return True
    if t.rstrip("s") in NEG_ALL or t.removesuffix("'s") in NEG_ALL:
        return True
    return bool(len(t) > 5 and MED_SUFFIX.search(t))


def known_nonname(tok: str) -> bool:
    """True when a Title-Case token is certainly not a person name."""
    t = tok.lower().strip(".,;:()[]'\"")
    return t in NEG_ALL or is_medical_token(tok)
