# Data sources

**No external datasets, corpora, pretrained models or network resources are used or shipped.**

| What | Where it comes from | Shipped |
|---|---|---|
| Negative gazetteer (drugs, diseases, eponyms, anatomy, lab tests, units, dose forms, English / Hinglish function words) | written by hand from general medical and language knowledge in `raksha/lex.py` | yes (source code) |
| Seed given names / surnames (~290 / ~150, many communities) | written by hand from common public knowledge; used only to *score* unlabelled Title-Case pairs | yes (source code) |
| Devanagari to Latin transliteration table | hand-written rule table in `raksha/translit.py` (no model) | yes (source code) |
| Run-time corpus lexicon (patient / relative names, villages, ids) | learned from the input folder itself while running; held in memory only | no |
| Practice data and truth (`dev/`) | organisers' kit, used for development scoring only, not shipped | no |
| Mutated "unseen-format" data | generated from the practice data by `tools/mutate.py` with a fixed seed; unseen given names / surnames in that script are hand-written | script only |

Cleaning applied to the seed lists: lower-cased, de-duplicated, and any name that also appeared as a canary identity in the
practice truth file was removed so the dev canary score is not inflated (6 entries removed). Lists are not derived from the
practice truth. No LLM-generated data of any kind is used anywhere in this repository.
