# Experiment log (rough local guide; the official score uses hidden data)

Columns: leak% = personal data still visible (check_dev), canaries found of 4, medical% = preserve values kept, link = pairwise
precision / recall / F0.5 (wrong merges), reid = simulated share of patients re-identified (raw = 0.98), secs = wall time.

| # | experiment | practice | mutated (in-house proxy) | notes |
|---|---|---|---|---|
| 0 | starter baseline (organisers' regex skeleton) | leak 84.1, canaries 4, medical 100, link 0 | n/a | ~8/100 officially |
| 1 | v0 ingestion + detection + linking | leak 0.7, canaries 0, medical 96.1, link P0.12/R0.43 (1 wrong merge) | n/a | one cluster of 19 patients: `Patient Name` header matched `pati` (husband), village column typed as NAME, FHIR SNOMED codes treated as hospital ids |
| 2 | header regex word boundaries, URL / UUID / code guards, numeric range guard | leak 0.0, medical 100, link P1.00/R0.45 (0) | leak 0.2 (villages) | |
| 3 | place-column inference (village in an address block) | leak 0.0 | leak 0.0, medical 100, link F0.5 0.84 | mutated set: unseen names, headers, columns, phones, id prefixes |
| 4 | JSON unit key paths fixed (visits / results prefix) | link P1.00/R0.91/F0.5 0.98 (0) | link F0.5 0.97 | recall 0.45 -> 0.91 |
| 5 | privacy policy grid (see below) | reid 0.71 -> 0.35 | same | 10-year bands, district only, no PIN |
| 6 | FHIR: URLs / UUIDs protected, `uid` label anchored, loose rare-pair name rule | leak 0.0, FHIR 19/19 valid | leak 0.0 | token retention 92.8 % -> 98.5 % |
| 7 | encounter ids, caller roles, key scrubbing, patient-role identity | leak 0.0, medical 100, link F0.5 0.98 | hard tier: leak 0.0, link F0.5 0.97 | no pseudonyms for trip / ticket / caller records |

| 8 | scale / stress: 5 mutated copies (240 patients, 1,000 files) | leak 0.0, medical 100, 23 s / 95 MB | | clones across copies (same name, age, village) legitimately merge, so precision is capped by the harness |
| 9 | fuzzing: empty, binary, NUL, CRLF, BOM, 1,500-deep, 5 MB single line | exit 0, valid contract | | found a crash (text-first run), two quadratic regexes; added guards and a time budget |
| 10 | index docs cannot bridge; unique pseudonym per cluster; age veto 4 y | link P1.00/R0.91/F0.5 0.99 (0) | hard tier: P1.00/R0.84/F0.5 0.96 (0) | `patient_index.json` listed many patients' ids and merged two clusters; a vetoed merge left two clusters with one id and thus one pseudonym |
| 11 | red-team round 1: entities, hex, base64 (nested), `\u` escapes, full-width, homoglyphs, lowercase names, split phones, PII in URLs | 7 leaks found and fixed | | decoded views are used when they expose PII; NFKC + homoglyph fold |
| 12 | red-team round 2: digit words (English / Hindi), letter-spaced names, cue-less names in prose | 28 / 28 adversarial cases | leak 0.0 | caught my own regressions: URL filter deleted by a bad slice, UUID read as Aadhaar, header names; `tools/check_fhir.py` added |
| 13 | hostile input: EICAR, PE / ELF / Mach-O, scripts, archives, Office, active content, symlink, FIFO, binary attachments, formula injection | all quarantined or neutralised, exit 0 | | static inspection only; no `urllib` import left (the organisers' audit flags network use); practice still quarantines the same 6 files |
| 14 | sandbox hardening: hash-pinned requirements, bomb masking, per-call regex timeouts, resource limits, write confinement | 324 flood inputs: worst 0.42 s (was 244 s) | | SIGALRM cannot interrupt a regex in C, so the first timeout design was ineffective; fixed with the regex module's own `timeout` |
| 15 | quasi-identifiers: date shift 90-365 d (never small) + single-patient conditions generalised | medical 99.1 %, targeted 0.24 -> 0.15, link F0.5 0.98 | hard tier: leak 0.0, medical 99.2 % | threshold 2 cost more medical data (98.0 %) for no extra gain |

Privacy policy grid (attacker_sim, practice data; raw: reid 0.98, record linkage 0.58):

| band | tehsil | PIN | record linkage | patients re-identified |
|---|---|---|---:|---:|
| 5 y | kept | 3 digits | 0.124 | 0.708 |
| 5 y | dropped | 3 digits | 0.099 | 0.542 |
| 10 y | dropped | dropped | 0.070 | 0.333 |
| 15 y | dropped | dropped | 0.059 | 0.250 |
| 20 y | dropped | dropped | 0.052 | 0.229 |

Chosen: 10-year bands, tehsil and PIN dropped, `75+` top-code. By the published weights the generalisation part of utility is 10 % of
20 points while privacy is 25 points (credited in full while utility stays above 0.40), so coarser is better; 10 years is the
compromise that stays informative.

Reliability: 3 runs with the same secret are byte-identical; a different secret shares 0 of 59 pseudonyms and changes
every sanitized file; input folder hash unchanged; 4.5 s / 41 MB on practice, 46.7 s / 149 MB on 10x (2,000 files).

| 16 | final rounds: nested/dict/lab/FHIR record units, headerless CSV, feminine-ending and baby-of merge guards, linear key renaming | practice leak 0.0, medical 99.2 %, link P 1.00 / R 0.98 / F0.5 1.00, targeted 0.07 | mutated: leak 0.0-0.1, medical 99.2 %, F0.5 0.96-0.98 | independent family set (320 patients): precision 1.000, 0 false merges (was 0.859, 252) |
