# Raksha: an offline privacy firewall for multilingual hospital exports

Track 3 "Secret Wards" submission. Input: a folder of messy synthetic hospital exports (CSV, TSV, JSON, FHIR R4,
text notes in English / Hindi / Hinglish, broken and unsupported files). Output: a research-safe copy in which every
direct identifier is gone, every medical value is byte-for-byte intact, the same patient carries the same keyed
pseudonym everywhere, and the quasi-identifiers an attacker could join against a voter list are generalised.

Offline, CPU only, no LLM, **no trained model at all**: deterministic rules, vocabularies and a conservative linker.
Dependencies: `regex`, `rapidfuzz`, `charset-normalizer` (all pinned in `requirements.txt`); everything else is the
standard library. Peak memory ~40 MB and ~4.5 s on the practice set; ~47 s and 150 MB on 10x the data.

## Setup and run

```sh
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt        # setup (network allowed)
RAKSHA_SECRET=practice .venv/bin/python main.py --input <dir> --output <dir>   # run (no network)
.venv/bin/python -m unittest discover -s tests                            # 19 tests, ~4 s
```

`RAKSHA_SECRET` keys the pseudonyms and the per-patient date shifts. It is read from the environment only and is never
printed, logged or written. Same input + same secret gives byte-identical output; another secret changes every pseudonym
and shift (checked: 0 of 59 pseudonyms survive a secret change).

## Architecture

```
 input files ──► ingest ──► learn corpus lexicon ──► evidence ──► link ──► scrub + generalise ──► outputs
 (any encoding,   decode,     names / villages / ids    per record   cluster   per record, with the     sanitized/
  any format,     sniff,      learned from STRUCTURED   (ids, names, (union-   cluster's pseudonym,      report.json
  broken files)   quarantine  fields, any script        age, sex,     find +   date shift, age band,    records.jsonl
                  what it                               village...)   vetoes)  placeholders
                  cannot clean
```

* `raksha/pipeline.py` orchestrates the passes; `main.py` writes `report.json` and `records.jsonl`.
* `raksha/columns.py` infers each CSV column / JSON key path's role **from its values first** (phone, Aadhaar, ABHA, PAN,
  hospital id, date, age, name, relative, village, address, free text); header words are only a weak prior, so renamed or
  Hindi headers still resolve.
* `raksha/detect.py` finds PII spans in free text; `raksha/translit.py` makes cross-script phonetic keys;
  `raksha/lex.py` holds the vocabularies; `raksha/link.py` links; `raksha/privacy.py` shifts dates and bands ages.

## How each part works

**Ingestion.** BOM / UTF-16 / UTF-8 / cp1252 detection (charset-normalizer fallback), always written as UTF-8. CSV keeps its
delimiter, header and ragged rows; JSON keeps its structure and value types; FHIR stays a valid R4 Bundle (all 19 practice
bundles validate with `fhir.resources`, `fullUrl`s stay unique and every reference resolves). A `.csv` that is really JSON is
sniffed and handled as JSON. Binary, empty, malformed, over-deep (1,500-level) and XML files are **quarantined** with a reason,
never copied. Each file is processed inside its own `try`, and the failure reason is a code, never file content.

**Detection (English, Devanagari, Hinglish).**
*Identifiers:* digit-run grouping rules for Indian phones in every written form (+91, 0-prefix, spaces, dashes, brackets,
Devanagari digits), Aadhaar, ABHA, PAN, e-mail, masked Aadhaar, UHID / MRN / IPD / policy ids, labelled ids. URLs, UUIDs,
ICD / LOINC codes and numeric ranges (`150000-410000`) are protected.
*Names:* (1) cues: `Name:` / `नाम:`, honorifics, `S/o D/o W/o`, `C/O <name>` (but not `C/O fever`), `Shahid sahab`, `Asha ji`,
"called by", WhatsApp senders; (2) a **corpus lexicon learned at run time** from the structured name columns, matched in any
script through a consonant skeleton (Mohammad = Mohd. = Md. = मोहम्मद; शाहिद = Shahid); (3) a last-resort rule for rare,
unknown Title-Case pairs.
*The meaning traps* are handled by a negative gazetteer (drugs, diseases, eponyms, anatomy, labs, units, dose forms) and by
context: doctors after `Dr.` stay while a relative with the same first name goes; `ASHA worker` stays; `Dolo 650 BD x 5 days`,
`1-0-1`, `150/90` and `Parkinson's disease` are never PII. Every candidate is effectively judged twice, "is it PII?" and "is it
medical?", and medical wins unless there is strong PII evidence.
*Hidden places:* file names, CSV headers, JSON keys and metadata strings go through the same scrubber, and base64
attachments are decoded, scrubbed and re-encoded.

**Linkage and pseudonyms.** Each record yields evidence (ids, Aadhaar / ABHA / PAN, phones, name token sets in cross-script
skeleton form, relative names, age, sex, DOB, village). Records merge on a shared strong id, or a phone plus a compatible name,
or the same full name plus one corroborating fact (DOB, relative, village and age). **Vetoes** block any merge that would put two
different Aadhaar numbers, two sexes, ages more than 2 years apart, two DOBs, or entirely incompatible names in one cluster;
homonyms with different relative and village stay apart. A pseudonym is `PSN-` + base32 of HMAC-SHA256(secret, cluster key) and is
written **inside** the cleaned record (it replaces the patient's name / hospital id), so it is present wherever `records.jsonl`
claims it. A lone phone number never creates an identity (it may belong to a caller or attendant).

**Privacy layer.** Dates: one HMAC-derived shift in +-180 days per patient, applied to every date format (ISO, dd/mm, mm/dd, written
months), so intervals and stay lengths are exact; the day/month order is inferred per hospital from unambiguous dates. Ages become
truthful 10-year bands that always contain the real age (`75+` top-code). Village, house, ward, mohalla, landmark and PIN are
removed; tehsil is dropped; district is kept. `config/policy.yaml` holds the knobs and `SCORES.md` the measurements behind them.

**Security design.** Everything is held in memory: no intermediate files, so nothing to encrypt or clean up. The secret is only
read from the environment. `sys.excepthook` prints the exception type only. stdout carries counts only. Quarantined files are
not copied anywhere. The input folder is never modified.

## Measured results (practice set, `tools/scorecard.py`)

| | practice | mutated, unseen names / headers / formats | + hard (labels, date formats) |
|---|---:|---:|---:|
| personal data still visible | 0.0 % (0 / 3,230) | 0.0 - 0.1 % (1) | 0.0 % |
| canaries found | 0 / 4 | 0 / 4 | 0 / 4 |
| medical values kept | 100.0 % | 100.0 % | 100.0 % |
| linking precision / recall / F0.5 | 1.00 / 0.91 / 0.99 | 1.00 / 0.79 / 0.95 (2) | 1.00 / 0.84 / 0.96 |
| wrongly merged patients | 0 | 0 | 0 |

(1) the 0.1 % is two registration rows where one patient's *shifted* date coincides with a different patient's DOB string in the same file;
(2) the mutation harness permutes identifier digits only inside the surface strings listed in the truth file, so id forms that appear
elsewhere (file-name fragments, metadata paths) become inconsistent and some genuine links are lost; precision is unaffected.

Simulated attacker (`tools/attacker_sim.py`, our approximation of the published attack): patients re-identified 35 % (98 % on raw
data); record-linkage risk 0.07 (0.58 on raw in our sim). Non-PII token retention 98.5 %; intervals exact in all 21 multi-date
documents. The mutated sets come from `tools/mutate.py`: every name swapped for an unseen one, headers and keys renamed (English,
Hinglish, Hindi), columns shuffled, phones and ids reformatted, labels and date formats changed, with a matching rewritten truth file.

## Reliability guards (found by fuzzing, all covered by `tests/test_robustness.py`)

* Detectors run in linear time: non-space runs over 300 characters are masked, very large texts are scanned in chunks, and two
  quadratic regexes were fixed. A 5 MB single-line file takes about 50 s instead of never finishing.
* Every stage is guarded per file: an odd file is quarantined with a reason code, never a crash. A hard time budget (`time_budget_s`,
  default 540 s) quarantines whatever is left, so the run always ends with exit 0, a valid contract and an honest report.
* A record that lists many patients (an index, a ward sheet) is stripped of linking evidence so it cannot bridge their clusters, and
  two clusters can never share a pseudonym.

## Known limitations (honest list)

* No OCR: scanned images and PDFs are quarantined. XML is quarantined too (safe, but loses its content). Legacy-font Hindi
  (Kruti Dev) is not decoded.
* A name that appears nowhere in a structured field and has no textual cue is found only by the rare-pair rule; it can be missed.
* dd/mm vs mm/dd is inferred statistically per hospital; a hospital with no unambiguous date anywhere falls back to the global majority.
* Rare diagnoses are kept (they are medical values), so a "known rare condition" targeted attack still succeeds (simulated 0.2 of raw).
* Ages in JSON become band strings, which changes that field's value type.
* All thresholds were tuned on one synthetic generator's practice set plus our own mutations; hidden data may differ.
* No trained model ships (the plan for a CRF / gradient-boosted second stage was dropped: rules plus the learned lexicon already
  saturated the practice and mutated sets). Declared models: **none**. Declared external data: **none** (`DATA_SOURCES.md`).

## Repository map

`main.py` entry point · `raksha/` package · `config/policy.yaml` privacy rules · `tests/` unit tests · `tools/` dev-only:
`scorecard.py`, `mutate.py`, `attacker_sim.py`, `linkdebug.py`, `check_intervals.py`, `token_loss.py` · `SCORES.md` experiment log ·
`brief/` the 2-page brief.
