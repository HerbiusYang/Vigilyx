# Offline semantic intent-model tools

These optional tools prepare data, train encoders, package ONNX ensembles,
and compare preprocessing and inference outputs. Run them on an isolated,
explicitly configured remote build or training host. They are not required for
standard deployment or an application update.

## Inputs and artifacts

Supply your own authorized corpora and pinned model files. Record the source
identities, checksums, split boundaries, and tool versions for each experiment.
Use each script's `--help` for its exact arguments; experiment directory names
and results are not release configuration.

- `prepare_ft_data.py` and `build_kfold.py` prepare grouped training inputs.
- `run_ft.sh` launches offline training on a configured training host.
- `package_final.py` creates an ensemble package containing `ensemble.json`,
  each member's `model.onnx`, `tokenizer.json`, and `classifier_config.json`.
- `intent_parity_cases.py` prepares inputs for the engine's explicitly ignored
  preprocessing and model-parity tests. Supply the intended model/runtime paths
  when running those tests on the remote build host.
- Keep raw corpora, experiment output, and generated weights outside Git. Use
  read-only input mounts and network isolation where supported.
- Keep evaluation data separate from fitting and threshold selection. Synthetic
  examples and tool-contract tests do not establish production detection quality.

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

The packaged weights were trained on E-PhishLLM and Fraud-R1, which ship no licence and are
for research use without redistribution: keep them inside the deployment, do not publish them.
