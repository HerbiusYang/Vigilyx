# Semantic intent-model PoC (upgrade plan P0/P1)

Offline proof of concept for replacing the semantic_scan decision core with a
small sentence encoder plus intent prototypes / a few-shot head, CPU only.
Edit locally; run corpus processing, evaluation, and CPU inference on the remote
build host, and offline fine-tuning on a separately configured training host.

Use an isolated experiment directory outside source synchronization. The table
below summarizes stages, not a copy-and-paste deployment script. Repository
helpers are under `scripts/` and `scripts/semantic_intent_poc/`; resolve paths
from your checkout. Container paths such as `/work/data` refer to explicit mounts.

| Step | Command (on the remote experiment host unless marked GPU) |
|---|---|
| Corpus | `scripts/prepare_semantic_corpora.py` from the two archives; must reproduce corpus SHA `1f45629d…` |
| Split | `prepare_semantic_classifier_split.py --chinese grouped --synthetic …`; identical to `classifier-split-v3r` |
| Red-team text | `export_redteam_text.py` (evaluation only) |
| Image | `docker build --pull=false -t vigilyx-intent-poc:20261110 scripts` |
| Models | `fetch_models.sh models PROXY` (pinned commits, `models/MANIFEST.sha256`) |
| Embeddings | `run_step.sh NAME CPUS -- python3 embed_corpus.py …` |
| Baseline | `baseline.sh` (deployed semantic_scan via `semantic_external_harness`) |
| Evaluation | `run_step.sh NAME CPUS -- python3 evaluate.py …` |
| Latency | `run_step.sh NAME 4 CPUSET -- python3 bench.py …` |
| Train supplement | `python3 -I <repo>/scripts/semantic_intent_poc/supplement_en_anti_fraud.py --generator <repo>/scripts/generate_semantic_synthetic_benign.py --split data/split --output data/supplement-en-anti-fraud` |
| Split, spam labelled | `prepare_semantic_classifier_split.py … --spam by-round --output data/split-spam-by-round` (commercial mail: raw/generated/round2 benign, round3/4 malicious) |
| Fine-tune data | `run_step.sh NAME 2 -- python3 prepare_ft_data.py --data /work/data [--split-name split-spam-by-round] [--train-extra /work/data/supplement-en-anti-fraud/cases.jsonl] --train-out … --eval-out …` |
| Benign v2 types | `supplement_v2_types.py --generator … --v1 data/synthetic-benign --split data/split-spam-by-round --output data/supplement-v2-types` (train-only, with `tie-map.json`) |
| K-fold | `kfold_assign.py` on the experiment host (group-aware fold per record; `--train-only FILE TIE` ties supplements to the groups they resemble) → `build_kfold.py [--final]` on the training server → one run per fold → `kfold_finish.sh` → `kfold_report.py` / `kfold_ensemble.py` (out-of-fold accuracy over all data). Sync every edited script to both hosts and compare sha256 before building folds |
| Fine-tune (GPU) | `run_ft.sh NAME DCU -- --model-dir … --pooling cls --lowercase …` (bge needs `--lowercase`; see `train_classifier.py`) |
| Accuracy (GPU) | `report_accuracy.py --run … --model-dir … --data …` |
| CPU scoring | `run_step.sh NAME 8 -- python3 score_onnx.py --run … --eval … --data /work/data --output …` |

Data rules:
- The red-team corpus is evaluation-only. No script here fits a model on it or
  picks a threshold from it; thresholds come from the dev split.
- Prototype sentences (`intents.json`) are hand-written and fictional.
- Train-only supplements are benign, appended to train only (dev/test stay
  byte-identical), and must not reuse dev/test sentence pools: check for
  shared 5-word shingles against the dev/test types before training.
- Containers run with `--network none`; inputs are mounted read-only.

## Engine integration: shadow and explicit scored modes

The ensemble runs inside the engine (`crates/vigilyx-engine/src/semantic/intent_model.rs`,
preprocessing in `intent_text.rs`) with ONNX Runtime 1.20.1 loaded from `ORT_DYLIB_PATH`
(`deploy/docker/fetch-onnxruntime.sh`, SHA256-pinned). Its outcome is recorded in
semantic_scan details as `semantic_intent_model`.

With `SEMANTIC_INTENT_MODEL_DIR` set and valid model/runtime artifacts, the
model runs in shadow mode beside local rules by default, without changing the
module result. A valid non-empty `SEMANTIC_INTENT_SCORE_THRESHOLD` explicitly
enables scored mode, replacing local rules and subsequent Python NLP/OCR in
semantic_scan. A threshold hit contributes a review-level Low module score of
0.20 to verdict fusion, not a guaranteed final level or disposition. The
packaged research threshold is not automatically used for production scoring.
Load failures disable the model with a warning; missing coverage is not a clean
inspection. `SEMANTIC_INTENT_THREADS` defaults to 4. Current Compose model wiring
is on the mirror engine; MTA requires separate setup.

| Step | Command |
|---|---|
| Final models (GPU) | `build_kfold.py --final` → `run_ft.sh final-bge 0 -- … --lowercase --epochs 5 --lr 5e-5` and `run_ft.sh final-e5b 1 -- … --epochs 3 --lr 2e-5` on `kfold-spam3-final/final` → `report_accuracy.py` on each |
| Package (GPU) | `package_final.py --member bge=runs/final-bge --member e5b=runs/final-e5b --data out/ft/kfold-spam3-final/final --version semantic-intent-v1 --evaluation runs/ens-….json --output packages/semantic-intent-v1` |
| Text parity (remote CPU host) | `intent_parity_cases.py --split /work/data/split-spam-by-round --output …` then `INTENT_TEXT_PARITY_CASES=… cargo test -p vigilyx-engine --lib -- --ignored intent_text_parity` (must report 0 differences) |
| Model parity (remote CPU host) | `intent_parity_cases.py --package … --sample 2000 --output …` then `INTENT_PARITY_MODEL_DIR=… INTENT_PARITY_CASES=… ORT_DYLIB_PATH=… cargo test … -- --ignored intent_model_parity` |
| Load volume (remote CPU host) | copy the package into the `vigilyx_intent_models` volume (`docker run --rm -v vigilyx_intent_models:/m -v PKG:/src:ro … cp -a /src/. /m/semantic-intent-v1/`), check `SHA256SUMS`, set `SEMANTIC_INTENT_MODEL_DIR=/app/models/intent/semantic-intent-v1` in `deploy/docker/.env`, recreate the engine |
| Disable | empty `SEMANTIC_INTENT_MODEL_DIR` and recreate the engine |

The packaged weights were trained on E-PhishLLM and Fraud-R1, which ship no licence and are
for research use without redistribution: keep them inside the deployment, do not publish them.
