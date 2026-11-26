# Starter skeleton

Copy this folder's contents to the root of **your own** repository and build from there.

```bash
RAKSHA_SECRET=practice python3 main.py --input ../dev/input --output ../my_output
```

## What it already does right

| ✅ | Done for you |
|---|---|
| reads every file in a fixed order | deterministic output |
| decodes UTF-8, UTF-8-BOM, UTF-16 and cp1252 | writes UTF-8 |
| keeps CSV as CSV and JSON as JSON | same delimiter, header and structure |
| quarantines PDF, images, XML, empty and broken JSON files | never copies them raw |
| writes `report.json` | SHA-256 per file, honest counts, timing, memory |
| writes `records.jsonl` | correct `row:N`, `/json/pointer` and `doc` locators |
| `pseudonym()` | keyed HMAC fake IDs (`PSN-XXXXXX`) from `RAKSHA_SECRET` |
| `date_shift_days()`, `shift_date()`, `age_band()` | per-patient date shifting and age bands |
| prints only counts | stdout, stderr and logs are scanned for PII |

## What it does NOT do (that's the challenge)

Search `main.py` for `TODO(team)`:

1. real **detection**: column awareness, Hindi/Hinglish names, honorifics, relatives, the meaning traps;
2. **hidden places**: file names, headers, JSON keys, metadata, base64 attachments;
3. **linking** patients across files and scripts (`link_records` returns `None` for now);
4. **quasi-identifiers**: date shifting, age bands, location generalisation, rare-value suppression;
5. writing the fake ID **inside** each cleaned record;
6. keeping FHIR a valid R4 Bundle.

As shipped it scores about **8 / 100** on the practice data with the official evaluator.
Run `python3 ../check_dev.py --output ../my_output` after each change.

`config/policy.yaml` holds your privacy settings (age band width, date shift range, minimum group size).
