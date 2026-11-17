---
title: Training corpus
description: Vigilyx's open training corpus, including current counts, labels, and how records are split for classifiers.
---

# Training corpus

[VIGILYX-Training-Data](https://github.com/HerbiusYang/VIGILYX-Training-Data) is the training mail Vigilyx shares in the open, under MIT. The gateway stays AGPL, so the corpus lives in its own repository and can be used for training and evaluation on its own. It holds JSON mail, a local viewer, and a skill that tells an agent how to search, adapt, and check new records.

Records are adapted from public activity, business process, or disclosed risk mechanisms. They are not captured production mail. A record being in the corpus does not mean it matches the latest detector rules. Third-party text and brands keep their own rights. The MIT license does not relicense those materials.

## Current file

Counted from the current `data/corpus.json`:

| | |
| --- | --- |
| Records | 5,438 |
| Malicious | 4,537 |
| Benign | 901 |
| Chinese | 5,199 |
| English | 121 |
| Chinese–English | 118 |
| `source-adapted` | 5,064 |
| Historical `synthetic` | 374 |

These are corpus counts, not a model score and not a fresh certification of every source. The published README can lag this file until the repository is updated.

Domain mix in the same file: finance 3,459, workplace 972, accounting 578, shopping 429. The default setting is mainland China, natural Chinese, and RMB. Coverage includes phishing, identity impersonation, business-process compromise, and business-email compromise, with benign controls. Consumer mail is in scope. The recipient does not have to be an employee, buyer, or finance officer.

## Record shape

Each record separates what a classifier may see from the answer and the paperwork:

- `input` is the only classifier input: the message and any prior thread.
- `target` holds the label and evidence. It is not model input.
- `provenance` holds sources and the adaptation note. It is not model input.

`source-adapted` means the body was adapted from retrieved sources and the changes are recorded. `synthetic` is the older generated set. `redacted-source` is reserved for a faithful, redacted original. Facts such as an event host, edition, prize, or eligibility are not invented. A prize, a deadline, a link, an unfamiliar brand, or a new address does not by itself make a record malicious. Thin evidence goes to a review queue and is not mixed into the training array.

## Use it locally

Python 3.9 or newer, a desktop, and `tkinter` are enough. No extra packages.

```bash
git clone https://github.com/HerbiusYang/VIGILYX-Training-Data.git
cd VIGILYX-Training-Data
python3 corpus_viewer.py
```

The viewer opens `data/corpus.json`, can hide labels for a blind read, and can export the classifier input. Check structure, labels, evidence quotes, and pair consistency with:

```bash
python3 realistic-email-threat-corpus/scripts/validate_records.py data/corpus.json --labels malicious,benign
```

A passing check does not prove that a source page is real, that the prose is natural, or that the label is right. The validator does not open links or refetch sources.
