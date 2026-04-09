"""
Fine-tuning pipeline for the five-class NLP phishing model.

Uses analyst feedback data to fine-tune the mDeBERTa base model as a
stateless Python service that receives batch samples from Rust.

Five-class labels:
  0 = legitimate
  1 = phishing
  2 = spoofing
  3 = social_engineering
  4 = other_threat

Training strategy:
  - Rust accumulates samples and triggers training manually
  - Python preprocesses the raw email fields and runs training
  - K-fold cross-validation gates model quality before final full-data training
  - Each run starts from the base model to avoid catastrophic forgetting
  - Balanced accuracy and macro F1 are both used as quality gates
  - Keep the latest 3 versions for rollback
"""

import gc
import json
import os
import random
import shutil
import time
import traceback
from datetime import datetime, timezone
from multiprocessing import Process, Queue
from typing import Optional

import structlog

logger = structlog.get_logger()

# Path constants
MODEL_OUTPUT_DIR = "data/nlp_models"
LATEST_LINK = "data/nlp_models/latest"
BASE_MODEL_DIR = "data/nlp_models/base"

# Training parameters
MIN_SAMPLES = 30
NUM_LABELS = 5
BASE_MODEL_HF = "MoritzLaurer/mDeBERTa-v3-base-xnli-multilingual-nli-2mil7"
NUM_EPOCHS = 5              # Maximum epochs per CV fold
LEARNING_RATE = 1e-4        # LoRA adapter learning rate
BATCH_SIZE = 16             # Default batch size once sample count is sufficient (>64)
GRADIENT_ACCUMULATION = 2   # Default gradient accumulation once sample count is sufficient (>64)
MIN_ACCURACY = 0.50         # Balanced-accuracy quality gate (5-class random baseline = 0.20)
MIN_F1 = 0.40               # Macro-F1 quality gate
MAX_VERSIONS = 3
LABEL_NAMES = ["legitimate", "phishing", "spoofing", "social_engineering", "other_threat"]

# LoRA parameters (parameter-efficient fine-tuning; trains only ~1.5% of weights)
LORA_R = 16                 # Low-rank adapter rank (8-16 works well on small datasets)
LORA_ALPHA = 32             # LoRA scaling factor (typically 2 * r)
LORA_DROPOUT = 0.1          # LoRA dropout
FOCAL_GAMMA = 2.0           # Focal-loss gamma to emphasize hard examples
MIN_CLASS_SAMPLES = 3       # Classes below this are merged into other_threat
EARLY_STOPPING_PATIENCE = 2 # Stop after N epochs without eval-loss improvement
RDROP_ALPHA = 0.7           # R-Drop KL-regularization coefficient (NeurIPS 2021)
MIN_AUG_TARGET = 10         # Rare-class augmentation target size

_STALL_TIMEOUT = int(os.environ.get("VIGILYX_TRAIN_STALL_TIMEOUT", "3600"))  # Stall timeout in seconds

# Training-progress file written by the subprocess and read by the API process
PROGRESS_FILE = os.path.join(MODEL_OUTPUT_DIR, ".training_progress.json")


def _simple_augment(text: str, rng: random.Random) -> str:
    """Structure-aware email text augmentation.

    `preprocess_email()` produces:
      From: sender@example.com
      Subject: ...
      body text...

    Only the body is augmented via token dropout / token swaps; header lines are
    preserved verbatim.
    """
    lines = text.split("\n")
    header_lines = []
    body_parts = []

    for line in lines:
        if line.startswith("From: ") or line.startswith("Subject: "):
            header_lines.append(line)
        else:
            body_parts.append(line)

    body_text = " ".join(body_parts).strip()
    words = body_text.split()
    if len(words) <= 3:
        return text  # Body too short to augment.

    strategy = rng.choice(["dropout", "swap", "both"])

    if strategy in ("dropout", "both"):
        drop_rate = rng.uniform(0.08, 0.15)
        kept = [w for w in words if rng.random() > drop_rate]
        words = kept if kept else words  # Never return an empty body.

    if strategy in ("swap", "both"):
        n_swaps = rng.randint(1, min(3, len(words) // 2))
        for _ in range(n_swaps):
            if len(words) < 2:
                break
            idx = rng.randint(0, len(words) - 2)
            words[idx], words[idx + 1] = words[idx + 1], words[idx]

    # Rebuild the sample as headers plus the augmented body.
    result_parts = header_lines + [" ".join(words)]
    return "\n".join(result_parts)


def _augment_rare_classes(
    texts: list, labels: list, min_target: int, rng_seed: int = 42,
) -> tuple:
    """Augment underrepresented classes until they reach `min_target`.

    Only training data should be augmented. Returns augmented `(texts, labels)`
    copies.
    """
    rng = random.Random(rng_seed)
    counts: dict = {}
    for lbl in labels:
        counts[lbl] = counts.get(lbl, 0) + 1

    aug_texts = list(texts)
    aug_labels = list(labels)

    for cls_idx, count in counts.items():
        if count >= min_target:
            continue
        cls_indices = [i for i, lbl in enumerate(labels) if lbl == cls_idx]
        n_needed = min_target - count
        for _ in range(n_needed):
            src_idx = rng.choice(cls_indices)
            aug_texts.append(_simple_augment(texts[src_idx], rng))
            aug_labels.append(cls_idx)

    return aug_texts, aug_labels


_progress_dir_ensured = False


def _write_progress(data: dict):
    """Atomically write training progress to the temp file used by the API."""
    global _progress_dir_ensured
    try:
        if not _progress_dir_ensured:
            _ensure_dirs()
            _progress_dir_ensured = True
        data["updated_at"] = time.time()
        tmp = PROGRESS_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f, ensure_ascii=False)
        os.replace(tmp, PROGRESS_FILE)  # Atomic rename.
    except Exception:
        pass


def _clear_progress():
    """Remove the progress file if it exists."""
    try:
        if os.path.exists(PROGRESS_FILE):
            os.remove(PROGRESS_FILE)
    except Exception:
        pass


def get_training_progress() -> Optional[dict]:
    """Read the current training-progress payload for the API endpoint."""
    try:
        if os.path.exists(PROGRESS_FILE):
            with open(PROGRESS_FILE, "r") as f:
                return json.load(f)
    except Exception:
        pass
    return None


def _ensure_dirs():
    """Ensure the model-output directory exists."""
    os.makedirs(MODEL_OUTPUT_DIR, exist_ok=True)


def _ensure_base_model() -> str:
    """
    Ensure the base model exists as a local snapshot and return its path.

    The first call downloads the model from HuggingFace into
    `data/nlp_models/base/`. Later training runs always reuse that local copy
    instead of depending on the network.

    Returns:
        Local base-model directory path.
    """
    meta_path = os.path.join(BASE_MODEL_DIR, "base_meta.json")

    if os.path.exists(meta_path):
        # Reuse the existing local snapshot.
        logger.info("Using local base model snapshot", path=BASE_MODEL_DIR)
        return BASE_MODEL_DIR

    # First run: download from HuggingFace and persist locally.
    logger.info(
        "Downloading base model for first-time snapshot",
        model=BASE_MODEL_HF,
    )
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    os.makedirs(BASE_MODEL_DIR, exist_ok=True)

    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL_HF)
    model = AutoModelForSequenceClassification.from_pretrained(
        BASE_MODEL_HF, num_labels=NUM_LABELS,
    )

    # Use semantic label mappings instead of the default LABEL_0/LABEL_1 names.
    model.config.id2label = {i: name for i, name in enumerate(LABEL_NAMES)}
    model.config.label2id = {name: i for i, name in enumerate(LABEL_NAMES)}

    tokenizer.save_pretrained(BASE_MODEL_DIR)
    model.save_pretrained(BASE_MODEL_DIR)

    # Record snapshot provenance.
    revision = _get_hf_revision(BASE_MODEL_HF)
    meta = {
        "source_model": BASE_MODEL_HF,
        "revision": revision,
        "num_labels": NUM_LABELS,
        "label_names": LABEL_NAMES,
        "downloaded_at": datetime.now(timezone.utc).isoformat(),
    }
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)

    logger.info(
        "Base model snapshot saved",
        path=BASE_MODEL_DIR,
        revision=revision,
    )
    return BASE_MODEL_DIR


def _get_hf_revision(model_id: str) -> str:
    """Try to read the HuggingFace model commit hash, else return `unknown`."""
    try:
        from huggingface_hub import model_info
        info = model_info(model_id)
        return info.sha or "unknown"
    except Exception:
        return "unknown"


def get_base_model_info() -> Optional[dict]:
    """Return metadata for the local base-model snapshot."""
    meta_path = os.path.join(BASE_MODEL_DIR, "base_meta.json")
    if os.path.exists(meta_path):
        try:
            with open(meta_path, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return None


def _get_last_trained() -> Optional[str]:
    """Return the timestamp of the most recent successful training run."""
    meta_path = os.path.join(LATEST_LINK, "training_meta.json")
    if os.path.exists(meta_path):
        try:
            with open(meta_path, "r") as f:
                meta = json.load(f)
            return meta.get("created_at")
        except Exception:
            pass
    return None


def _train_in_subprocess(samples_json: str, base_model_dir: str, result_queue: Queue):
    """
    Run five-class training in a subprocess.

    Flow:
      1. preprocess email samples
      2. run K-fold cross-validation to measure quality
      3. reject the run if quality gates fail
      4. train the final model on the full dataset using the median best epoch
      5. save the model and update the `latest` symlink
    """
    try:
        import torch
        from collections import Counter
        from sklearn.model_selection import StratifiedKFold, KFold
        from sklearn.metrics import (
            f1_score,
            classification_report,
            balanced_accuracy_score,
        )
        from transformers import (
            AutoModelForSequenceClassification,
            AutoTokenizer,
            EarlyStoppingCallback,
            Trainer,
            TrainerCallback,
            TrainingArguments,
            DataCollatorWithPadding,
        )
        from peft import LoraConfig, get_peft_model, TaskType

        # Import lazily because the subprocess needs its own module state.
        from vigilyx_ai.nlp_phishing import preprocess_email

        # Training should leave headroom for the inference process.
        _cpu = os.cpu_count() or 4
        _train_threads = max(4, int(_cpu * 0.6))
        _interop = max(2, _train_threads // 3)
        torch.set_num_threads(_train_threads)
        torch.set_num_interop_threads(_interop)

        use_cuda = torch.cuda.is_available()
        use_bf16 = False
        if use_cuda and torch.cuda.is_bf16_supported():
            use_bf16 = True
        elif not use_cuda:
            try:
                torch.tensor([1.0]).to(torch.bfloat16)
                use_bf16 = True
            except Exception:
                pass

        # Detect available memory to decide whether large-memory optimizations are safe.
        import psutil
        _avail_gb = psutil.virtual_memory().available / (1024 ** 3)
        _large_mem = _avail_gb >= 32  # Treat >=32GB available RAM as a large-memory host.

        # Internal helper classes

        class ProgressCallback(TrainerCallback):
            """Training callback that publishes progress to the API poll file."""

            def __init__(self, total_epochs, total_samples, fold_info=None):
                self.total_epochs = total_epochs
                self.total_samples = total_samples
                self.fold_info = fold_info or {}

            def on_epoch_begin(self, args, state, control, **kwargs):
                epoch = int(state.epoch) + 1 if state.epoch is not None else 1
                progress = {
                    "phase": "training",
                    "epoch": epoch,
                    "total_epochs": self.total_epochs,
                    "step": state.global_step,
                    "total_steps": state.max_steps,
                    "total_samples": self.total_samples,
                }
                progress.update(self.fold_info)
                _write_progress(progress)

            def on_log(self, args, state, control, logs=None, **kwargs):
                progress = {
                    "phase": "training",
                    "epoch": int(state.epoch) if state.epoch else 0,
                    "total_epochs": self.total_epochs,
                    "step": state.global_step,
                    "total_steps": state.max_steps,
                    "loss": round(logs.get("loss", 0), 4) if logs and "loss" in logs else None,
                    "total_samples": self.total_samples,
                }
                progress.update(self.fold_info)
                _write_progress(progress)

        class EvalLossTracker(TrainerCallback):
            """Track eval loss per epoch so CV can infer the best epoch."""

            def __init__(self):
                self.eval_losses = []

            def on_evaluate(self, args, state, control, metrics=None, **kwargs):
                if metrics:
                    self.eval_losses.append(metrics.get("eval_loss", float("inf")))

        class FocalTrainer(Trainer):
            """Trainer with focal loss, class weights, and R-Drop regularization.

            Focal Loss: FL(p_t) = -α_t * (1-p_t)^γ * log(p_t)
            R-Drop: symmetric KL regularization across two forward passes
            Combined effect: emphasize hard examples while enforcing dropout
            consistency for stronger regularization on small datasets.
            """

            def __init__(self, class_weights=None, focal_gamma=2.0,
                         rdrop_alpha=0.0, **kwargs):
                super().__init__(**kwargs)
                self._class_weights = class_weights
                self._focal_gamma = focal_gamma
                self._rdrop_alpha = rdrop_alpha

            def _focal_loss(self, logits, labels, weight):
                """Compute focal loss for a single forward pass."""
                ce = torch.nn.functional.cross_entropy(
                    logits, labels, weight=weight, reduction="none",
                )
                pt = torch.exp(-ce)
                return ((1 - pt) ** self._focal_gamma * ce).mean()

            def compute_loss(self, model, inputs, return_outputs=False, **kwargs):
                labels = inputs.pop("labels")
                outputs1 = model(**inputs)
                weight = (
                    self._class_weights.to(outputs1.logits.device)
                    if self._class_weights is not None
                    else None
                )
                focal1 = self._focal_loss(outputs1.logits, labels, weight)

                if self._rdrop_alpha > 0 and model.training:
                    # R-Drop: a second pass with a different dropout mask.
                    outputs2 = model(**inputs)
                    focal2 = self._focal_loss(outputs2.logits, labels, weight)

                    # Symmetric KL divergence: (KL(q||p) + KL(p||q)) / 2
                    log_p = torch.nn.functional.log_softmax(outputs1.logits, dim=-1)
                    log_q = torch.nn.functional.log_softmax(outputs2.logits, dim=-1)
                    kl = (
                        torch.nn.functional.kl_div(
                            log_p, log_q.exp(), reduction="batchmean")
                        + torch.nn.functional.kl_div(
                            log_q, log_p.exp(), reduction="batchmean")
                    ) / 2
                    loss = (focal1 + focal2) / 2 + self._rdrop_alpha * kl
                else:
                    loss = focal1

                return (loss, outputs1) if return_outputs else loss

        class FeedbackDataset(torch.utils.data.Dataset):
            def __init__(self, encodings, labels):
                self.encodings = encodings
                self.labels = labels

            def __len__(self):
                return len(self.labels)

            def __getitem__(self, idx):
                item = {k: v[idx] for k, v in self.encodings.items()}
                item["labels"] = self.labels[idx]
                return item

        # 1. Preprocessing
        _write_progress({"phase": "preprocessing", "message": "Preprocessing email samples..."})
        raw_samples = json.loads(samples_json)
        texts = []
        labels = []
        for s in raw_samples:
            body = s.get("body_text") or s.get("body_html") or ""
            text = preprocess_email(
                subject=s.get("subject"),
                body=body,
                mail_from=s.get("mail_from"),
            )
            if text.strip():
                texts.append(text)
                labels.append(s["label"])

        # Drop invalid labels before training.
        valid_labels = set(range(NUM_LABELS))
        filtered_texts = []
        filtered_labels = []
        skipped = 0
        for t, l in zip(texts, labels):
            if l in valid_labels:
                filtered_texts.append(t)
                filtered_labels.append(l)
            else:
                skipped += 1
        if skipped > 0:
            logger.warning(f"Skipped {skipped} samples with invalid labels")
        texts = filtered_texts
        labels = filtered_labels

        if len(texts) < MIN_SAMPLES:
            result_queue.put({
                "ok": False,
                "error": f"Insufficient valid samples: {len(texts)}/{MIN_SAMPLES}",
            })
            return

        label_counts = Counter(labels)

        # Merge extremely rare classes into `other_threat` to avoid training on
        # classes that have too few samples to learn a stable boundary.
        OTHER_THREAT_LABEL = 4
        merged_classes = []
        for cls_idx in range(NUM_LABELS):
            if cls_idx == OTHER_THREAT_LABEL:
                continue
            count = label_counts.get(cls_idx, 0)
            if 0 < count < MIN_CLASS_SAMPLES:
                merged_classes.append(f"{LABEL_NAMES[cls_idx]}({count})")
                labels = [OTHER_THREAT_LABEL if l == cls_idx else l for l in labels]
        if merged_classes:
            label_counts = Counter(labels)  # Recount after merging.
            logger.warning(
                "Auto-merged rare classes into other_threat",
                merged=merged_classes,
                new_distribution={LABEL_NAMES[k]: v for k, v in label_counts.items()},
            )

        logger.info(
            "Training data prepared",
            total=len(texts),
            distribution={LABEL_NAMES[k]: v for k, v in label_counts.items()},
        )

        # 2. Load tokenizer + data collator shared by all folds.
        tokenizer = AutoTokenizer.from_pretrained(base_model_dir)
        data_collator = DataCollatorWithPadding(tokenizer=tokenizer)

        # LoRA configuration shared across all folds and final training.
        # Use a lower-rank adapter for smaller datasets to reduce overfitting.
        n_samples = len(texts)
        if n_samples <= 50:
            adaptive_r = 8
            adaptive_alpha = 16   # alpha = 2 * r
        else:
            adaptive_r = LORA_R        # 16
            adaptive_alpha = LORA_ALPHA  # 32

        lora_config = LoraConfig(
            task_type=TaskType.SEQ_CLS,
            r=adaptive_r,
            lora_alpha=adaptive_alpha,
            lora_dropout=LORA_DROPOUT,
            target_modules=["query_proj", "value_proj"],  # DeBERTa-v3 attention projections
            modules_to_save=["classifier", "pooler"],     # Keep classifier + pooler fully trainable
        )

        # 3. Determine CV fold count and batch sizing.
        min_class_count = min(label_counts.values())
        n_folds = min(5 if len(labels) >= 60 else 3, min_class_count)
        n_folds = max(2, n_folds)

        n_total = len(texts)
        if _large_mem:
            # On large-memory hosts, increase batch size to reduce total steps.
            if n_total <= 32:
                actual_batch = min(16, n_total)
                actual_grad_accum = 1
            elif n_total <= 128:
                actual_batch = 32
                actual_grad_accum = 1
            else:
                actual_batch = 64
                actual_grad_accum = 1
        else:
            if n_total <= 32:
                actual_batch = min(8, n_total)
                actual_grad_accum = 1
            elif n_total <= 64:
                actual_batch = 8
                actual_grad_accum = 2
            else:
                actual_batch = BATCH_SIZE
                actual_grad_accum = GRADIENT_ACCUMULATION

        # Use parallel data loading only when the host can support it.
        dl_workers = min(4, max(1, _cpu // 4)) if _large_mem else (
            0 if n_total < 500 else min(4, _cpu // 4)
        )

        # Small datasets benefit from slightly more patience to avoid noisy early stops.
        actual_patience = 3 if n_total <= 50 else EARLY_STOPPING_PATIENCE

        # Disable gradient checkpointing on large-memory machines for speed.
        _use_grad_ckpt = not _large_mem

        # Output directory
        _ensure_dirs()
        existing_versions = [
            d for d in os.listdir(MODEL_OUTPUT_DIR)
            if os.path.isdir(os.path.join(MODEL_OUTPUT_DIR, d)) and d.startswith("v")
        ]
        # Derive the next numeric version from existing versioned directories.
        max_ver = 0
        for d in existing_versions:
            # Format: v{N}_{timestamp}
            try:
                max_ver = max(max_ver, int(d.split("_")[0][1:]))
            except (ValueError, IndexError):
                pass
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        version_name = f"v{max_ver + 1}_{timestamp}"
        output_dir = os.path.join(MODEL_OUTPUT_DIR, version_name)
        os.makedirs(output_dir, exist_ok=True)

        # ============================================================
        # Phase 1: K-fold cross-validation (quality evaluation)
        # ============================================================
        _write_progress({
            "phase": "cross_validation",
            "message": f"Starting {n_folds}-fold cross-validation...",
            "total_folds": n_folds,
            "total_samples": n_total,
        })

        can_stratify = all(count >= n_folds for count in label_counts.values())
        if can_stratify:
            kf = StratifiedKFold(n_splits=n_folds, shuffle=True, random_state=42)
            splits = list(kf.split(texts, labels))
        else:
            kf = KFold(n_splits=n_folds, shuffle=True, random_state=42)
            splits = list(kf.split(texts))
            logger.warning(
                "Using non-stratified KFold (some classes have too few samples for stratification)"
            )

        fold_metrics = []
        all_val_preds = [None] * n_total
        cv_start = time.time()

        for fold_idx, (train_idx, val_idx) in enumerate(splits):
            _write_progress({
                "phase": "cross_validation",
                "fold": fold_idx + 1,
                "total_folds": n_folds,
                "message": f"Training fold {fold_idx + 1}/{n_folds}...",
                "total_samples": n_total,
            })

            fold_train_texts = [texts[i] for i in train_idx]
            fold_train_labels = [labels[i] for i in train_idx]
            fold_val_texts = [texts[i] for i in val_idx]
            fold_val_labels = [labels[i] for i in val_idx]

            # Fold-specific class weights based on the original label distribution.
            fold_label_counts = Counter(fold_train_labels)
            fold_weights = torch.tensor([
                len(fold_train_labels) / (NUM_LABELS * fold_label_counts.get(i, 1))
                for i in range(NUM_LABELS)
            ], dtype=torch.float32)

            # Augment rare classes in the training split only.
            # Class weights still reflect the original distribution.
            # Target size scales with the majority class to fit different dataset sizes.
            aug_target = max(MIN_AUG_TARGET, max(fold_label_counts.values()) // 4)
            fold_train_texts, fold_train_labels = _augment_rare_classes(
                fold_train_texts, fold_train_labels, aug_target,
                rng_seed=42 + fold_idx,
            )

            # Tokenize
            fold_train_enc = tokenizer(
                fold_train_texts, truncation=True, padding=False, max_length=512,
            )
            fold_val_enc = tokenizer(
                fold_val_texts, truncation=True, padding=False, max_length=512,
            )

            fold_train_ds = FeedbackDataset(fold_train_enc, fold_train_labels)
            fold_val_ds = FeedbackDataset(fold_val_enc, fold_val_labels)

            # Reload the base model and reapply LoRA for each fold.
            fold_model = AutoModelForSequenceClassification.from_pretrained(
                base_model_dir, num_labels=NUM_LABELS,
            )
            fold_model = get_peft_model(fold_model, lora_config)
            if fold_idx == 0:
                trainable, total = fold_model.get_nb_trainable_parameters()
                logger.info(
                    "LoRA applied",
                    trainable_params=trainable,
                    total_params=total,
                    trainable_pct=f"{trainable / total * 100:.2f}%",
                )

            fold_output = os.path.join(output_dir, f"_cv_fold_{fold_idx}")
            eval_tracker = EvalLossTracker()
            fold_progress = ProgressCallback(
                total_epochs=NUM_EPOCHS,
                total_samples=n_total,
                fold_info={"fold": fold_idx + 1, "total_folds": n_folds},
            )

            fold_args_kwargs = dict(
                output_dir=fold_output,
                num_train_epochs=NUM_EPOCHS,
                per_device_train_batch_size=actual_batch,
                per_device_eval_batch_size=actual_batch * 2,
                gradient_accumulation_steps=actual_grad_accum,
                learning_rate=LEARNING_RATE,
                lr_scheduler_type="cosine",
                warmup_ratio=0.1,
                weight_decay=0.01,
                eval_strategy="epoch",
                save_strategy="epoch",
                save_total_limit=2,
                load_best_model_at_end=True,
                metric_for_best_model="eval_loss",
                logging_steps=max(1, len(fold_train_texts) // (actual_batch * 2)),
                no_cuda=not use_cuda,
                bf16=use_bf16,
                gradient_checkpointing=_use_grad_ckpt,
                dataloader_num_workers=dl_workers,
                dataloader_pin_memory=use_cuda,
                report_to="none",
            )
            if _use_grad_ckpt:
                fold_args_kwargs["gradient_checkpointing_kwargs"] = {"use_reentrant": False}
            fold_args = TrainingArguments(**fold_args_kwargs)

            fold_trainer = FocalTrainer(
                class_weights=fold_weights,
                focal_gamma=FOCAL_GAMMA,
                rdrop_alpha=RDROP_ALPHA,
                model=fold_model,
                args=fold_args,
                train_dataset=fold_train_ds,
                eval_dataset=fold_val_ds,
                data_collator=data_collator,
                callbacks=[
                    fold_progress,
                    eval_tracker,
                    EarlyStoppingCallback(early_stopping_patience=actual_patience),
                ],
            )

            fold_trainer.train()

            # Evaluate the fold.
            preds = fold_trainer.predict(fold_val_ds)
            pred_labels_arr = preds.predictions.argmax(axis=-1)

            fold_balanced_acc = balanced_accuracy_score(fold_val_labels, pred_labels_arr)
            fold_macro_f1 = f1_score(
                fold_val_labels, pred_labels_arr, average="macro", zero_division=0,
            )

            # Infer the best epoch from the eval-loss trajectory.
            best_epoch = NUM_EPOCHS
            if eval_tracker.eval_losses:
                best_epoch = (
                    min(range(len(eval_tracker.eval_losses)),
                        key=lambda i: eval_tracker.eval_losses[i])
                    + 1
                )

            fold_metrics.append({
                "fold": fold_idx + 1,
                "balanced_accuracy": round(fold_balanced_acc, 4),
                "macro_f1": round(fold_macro_f1, 4),
                "best_epoch": best_epoch,
                "eval_loss": round(preds.metrics.get("test_loss", 0.0), 4),
            })

            # Collect out-of-fold predictions for the global classification report.
            for i, vi in enumerate(val_idx):
                all_val_preds[vi] = int(pred_labels_arr[i])

            # Release fold-local resources aggressively between folds.
            del fold_model, fold_trainer, fold_train_ds, fold_val_ds
            del fold_train_enc, fold_val_enc
            gc.collect()
            if use_cuda:
                torch.cuda.empty_cache()
            shutil.rmtree(fold_output, ignore_errors=True)

            logger.info(
                f"CV fold {fold_idx + 1}/{n_folds} done",
                balanced_accuracy=round(fold_balanced_acc, 4),
                macro_f1=round(fold_macro_f1, 4),
                best_epoch=best_epoch,
            )

        cv_duration = time.time() - cv_start

        # Summarize CV metrics.
        mean_balanced_acc = sum(m["balanced_accuracy"] for m in fold_metrics) / n_folds
        std_balanced_acc = (
            sum((m["balanced_accuracy"] - mean_balanced_acc) ** 2 for m in fold_metrics)
            / n_folds
        ) ** 0.5
        mean_macro_f1 = sum(m["macro_f1"] for m in fold_metrics) / n_folds
        std_macro_f1 = (
            sum((m["macro_f1"] - mean_macro_f1) ** 2 for m in fold_metrics) / n_folds
        ) ** 0.5

        # Full out-of-fold classification report.
        per_class_report = classification_report(
            labels,
            all_val_preds,
            labels=list(range(NUM_LABELS)),
            target_names=LABEL_NAMES,
            output_dict=True,
            zero_division=0,
        )

        # Warn on weak per-class F1 scores only when the class has enough data.
        weak_classes = []
        zero_f1_classes = []
        for cls_idx, cls_name in enumerate(LABEL_NAMES):
            cls_count = label_counts.get(cls_idx, 0)
            if cls_count >= MIN_CLASS_SAMPLES:
                cls_f1 = per_class_report.get(cls_name, {}).get("f1-score", 0)
                if cls_f1 < 0.25:
                    weak_classes.append(f"{cls_name}(F1={cls_f1:.2f})")
                if cls_f1 == 0.0 and cls_count >= 5:
                    zero_f1_classes.append(f"{cls_name}(n={cls_count})")
        if weak_classes:
            logger.warning("Low per-class F1 detected", weak_classes=weak_classes)
        if zero_f1_classes:
            logger.error(
                "Classes with sufficient samples but F1=0 — model failed to learn",
                zero_f1_classes=zero_f1_classes,
            )

        logger.info(
            "Cross-validation complete",
            n_folds=n_folds,
            mean_balanced_acc=round(mean_balanced_acc, 4),
            std_balanced_acc=round(std_balanced_acc, 4),
            mean_macro_f1=round(mean_macro_f1, 4),
            cv_duration_s=round(cv_duration, 1),
        )

        # Quality gate
        _write_progress({
            "phase": "quality_check",
            "message": (
                f"CV complete: balanced_acc={mean_balanced_acc:.1%}+/-{std_balanced_acc:.1%}, "
                f"F1={mean_macro_f1:.3f}±{std_macro_f1:.3f}"
            ),
            "total_samples": n_total,
        })

        quality_pass = mean_balanced_acc >= MIN_ACCURACY and mean_macro_f1 >= MIN_F1

        if not quality_pass:
            if os.path.exists(output_dir):
                shutil.rmtree(output_dir)
            result_queue.put({
                "ok": False,
                "error": (
                    f"Model quality gate failed ({n_folds}-fold CV): "
                    f"balanced_accuracy={mean_balanced_acc:.1%}+/-{std_balanced_acc:.1%} "
                    f"(required >= {MIN_ACCURACY:.0%}), "
                    f"macro_f1={mean_macro_f1:.3f}+/-{std_macro_f1:.3f} "
                    f"(required >= {MIN_F1:.2f})"
                ),
                "cv_balanced_accuracy": round(mean_balanced_acc, 4),
                "cv_macro_f1": round(mean_macro_f1, 4),
                "fold_details": fold_metrics,
                "weak_classes": weak_classes,
                "zero_f1_classes": zero_f1_classes,
                "merged_classes": merged_classes,
            })
            return

        # ============================================================
        # Phase 2: final training on the full dataset
        # ============================================================
        # Use the median best epoch from CV as the final-training epoch count.
        sorted_best_epochs = sorted(m["best_epoch"] for m in fold_metrics)
        optimal_epochs = max(1, sorted_best_epochs[n_folds // 2])

        _write_progress({
            "phase": "final_training",
            "message": f"CV quality gate passed; training final model on the full dataset ({optimal_epochs} epochs)...",
            "total_samples": n_total,
        })

        # Class weights for the full dataset.
        class_weights = torch.tensor([
            len(labels) / (NUM_LABELS * label_counts.get(i, 1))
            for i in range(NUM_LABELS)
        ], dtype=torch.float32)

        logger.info(
            "Final training class weights",
            weights={LABEL_NAMES[i]: round(w, 2) for i, w in enumerate(class_weights.tolist())},
        )

        # Augment rare classes for final training as well.
        # Target size = max(fixed floor, 25% of the majority class size).
        aug_target = max(MIN_AUG_TARGET, max(label_counts.values()) // 4)
        final_texts, final_labels = _augment_rare_classes(
            texts, labels, aug_target, rng_seed=42,
        )
        if len(final_texts) > len(texts):
            logger.info(
                "Final training data augmented",
                original=len(texts),
                augmented=len(final_texts),
            )

        # Tokenize the full dataset, including augmented samples.
        all_encodings = tokenizer(
            final_texts, truncation=True, padding=False, max_length=512,
        )
        all_dataset = FeedbackDataset(all_encodings, final_labels)

        # Reload the base model and apply LoRA for final training.
        model = AutoModelForSequenceClassification.from_pretrained(
            base_model_dir, num_labels=NUM_LABELS,
        )
        model = get_peft_model(model, lora_config)

        final_progress = ProgressCallback(
            total_epochs=optimal_epochs,
            total_samples=n_total,
        )

        final_args_kwargs = dict(
            output_dir=output_dir,
            num_train_epochs=optimal_epochs,
            per_device_train_batch_size=actual_batch,
            gradient_accumulation_steps=actual_grad_accum,
            learning_rate=LEARNING_RATE,
            lr_scheduler_type="cosine",
            warmup_ratio=0.1,
            weight_decay=0.01,
            eval_strategy="no",
            save_strategy="no",
            logging_steps=max(1, n_total // (actual_batch * 2)),
            no_cuda=not use_cuda,
            bf16=use_bf16,
            gradient_checkpointing=_use_grad_ckpt,
            dataloader_num_workers=dl_workers,
            dataloader_pin_memory=use_cuda,
            report_to="none",
        )
        if _use_grad_ckpt:
            final_args_kwargs["gradient_checkpointing_kwargs"] = {"use_reentrant": False}
        final_args = TrainingArguments(**final_args_kwargs)

        start_time = time.time()
        final_trainer = FocalTrainer(
            class_weights=class_weights,
            focal_gamma=FOCAL_GAMMA,
            rdrop_alpha=RDROP_ALPHA,
            model=model,
            args=final_args,
            train_dataset=all_dataset,
            data_collator=data_collator,
            callbacks=[final_progress],
        )
        final_trainer.train()
        train_duration = time.time() - start_time

        # Save model artifacts.
        _write_progress({
            "phase": "saving",
            "message": "Saving final model...",
            "cv_balanced_accuracy": round(mean_balanced_acc, 4),
            "cv_macro_f1": round(mean_macro_f1, 4),
            "total_samples": n_total,
        })
        # Merge LoRA adapters into the base model so inference does not require PEFT.
        merged_model = model.merge_and_unload()
        merged_model.config.id2label = {i: name for i, name in enumerate(LABEL_NAMES)}
        merged_model.config.label2id = {name: i for i, name in enumerate(LABEL_NAMES)}
        merged_model.save_pretrained(output_dir)
        tokenizer.save_pretrained(output_dir)

        # Remove leftover training directories.
        for item in os.listdir(output_dir):
            item_path = os.path.join(output_dir, item)
            if os.path.isdir(item_path) and (
                item.startswith("checkpoint-") or item.startswith("_cv_fold_")
            ):
                shutil.rmtree(item_path, ignore_errors=True)

        # Training metadata
        label_dist = {LABEL_NAMES[k]: v for k, v in label_counts.items()}

        base_meta_path = os.path.join(base_model_dir, "base_meta.json")
        base_meta = {}
        if os.path.exists(base_meta_path):
            with open(base_meta_path, "r") as f:
                base_meta = json.load(f)

        meta = {
            "version": version_name,
            "base_model": base_meta.get("source_model", base_model_dir),
            "base_model_revision": base_meta.get("revision", "unknown"),
            "num_labels": NUM_LABELS,
            "label_names": LABEL_NAMES,
            "total_samples": n_total,
            "label_distribution": label_dist,
            # CV metrics
            "cv_folds": n_folds,
            "cv_balanced_accuracy_mean": round(mean_balanced_acc, 4),
            "cv_balanced_accuracy_std": round(std_balanced_acc, 4),
            "cv_macro_f1_mean": round(mean_macro_f1, 4),
            "cv_macro_f1_std": round(std_macro_f1, 4),
            "cv_fold_details": fold_metrics,
            "cv_duration_s": round(cv_duration, 1),
            "per_class_f1": {
                k: round(v.get("f1-score", 0), 4)
                for k, v in per_class_report.items()
                if k not in ("accuracy", "macro avg", "weighted avg")
            },
            # Training configuration
            "class_weights": {
                LABEL_NAMES[i]: round(w, 3)
                for i, w in enumerate(class_weights.tolist())
            },
            # Training method
            "training_method": "lora",
            "lora_r": adaptive_r,
            "lora_alpha": adaptive_alpha,
            "lora_dropout": LORA_DROPOUT,
            "lora_target_modules": ["query_proj", "value_proj"],
            "focal_gamma": FOCAL_GAMMA,
            "rdrop_alpha": RDROP_ALPHA,
            "aug_target": aug_target,
            "early_stopping_patience": actual_patience,
            "augmented_total": len(final_texts),
            "lr_scheduler": "cosine",
            "optimal_epochs": optimal_epochs,
            "learning_rate": LEARNING_RATE,
            "batch_size": actual_batch,
            "gradient_accumulation": actual_grad_accum,
            "effective_batch_size": actual_batch * actual_grad_accum,
            "warmup_ratio": 0.1,
            "train_duration_s": round(train_duration, 1),
            "total_duration_s": round(cv_duration + train_duration, 1),
            "device": "cuda" if use_cuda else "cpu",
            "bf16": use_bf16,
            "large_mem": _large_mem,
            "available_mem_gb": round(_avail_gb, 1),
            "gradient_checkpointing": _use_grad_ckpt,
            "cpu_count": _cpu,
            "num_threads": _train_threads,
            "dataloader_workers": dl_workers,
            "weak_classes": weak_classes,
            "zero_f1_classes": zero_f1_classes,
            "merged_classes": merged_classes,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        with open(os.path.join(output_dir, "training_meta.json"), "w") as f:
            json.dump(meta, f, indent=2, ensure_ascii=False)

        # Update the `latest` symlink.
        if os.path.islink(LATEST_LINK):
            os.unlink(LATEST_LINK)
        elif os.path.exists(LATEST_LINK):
            os.remove(LATEST_LINK)
        os.symlink(os.path.abspath(output_dir), LATEST_LINK)

        # Prune old versions using numeric version ordering.
        def _version_sort_key(name: str) -> int:
            try:
                return int(name.split("_")[0][1:])
            except (ValueError, IndexError):
                return 0

        versions = sorted(
            [d for d in os.listdir(MODEL_OUTPUT_DIR)
             if os.path.isdir(os.path.join(MODEL_OUTPUT_DIR, d)) and d.startswith("v")],
            key=_version_sort_key,
        )
        while len(versions) > MAX_VERSIONS:
            old = versions.pop(0)
            old_path = os.path.join(MODEL_OUTPUT_DIR, old)
            shutil.rmtree(old_path, ignore_errors=True)

        result_queue.put({
            "ok": True,
            "model_dir": output_dir,
            "version": version_name,
            "cv_balanced_accuracy": round(mean_balanced_acc, 4),
            "cv_macro_f1": round(mean_macro_f1, 4),
            "optimal_epochs": optimal_epochs,
            "train_duration_s": round(train_duration, 1),
            "total_duration_s": round(cv_duration + train_duration, 1),
            "total_samples": n_total,
            "num_labels": NUM_LABELS,
            "weak_classes": weak_classes,
            "zero_f1_classes": zero_f1_classes,
            "merged_classes": merged_classes,
        })

    except Exception as e:
        tb = traceback.format_exc()
        logging.getLogger(__name__).error("Training failed: %s\n%s", e, tb)
        result_queue.put({
            "ok": False,
            "error": "TRAINING_FAILED",
            # Detailed exception data stays in server logs only.
        })


class PhishingTrainer:
    """Stateless five-class trainer: receive samples, train, and return results."""

    def __init__(self):
        _ensure_dirs()
        self._is_training = False

    @property
    def is_training(self) -> bool:
        return self._is_training

    @property
    def last_trained(self) -> Optional[str]:
        return _get_last_trained()

    async def train(self, samples: list) -> dict:
        """
        Receive batch samples and trigger fine-tuning.

        Args:
            samples: list of `TrainingSampleInput` objects or plain dicts

        Returns:
            {"ok": True, "model_dir": "...", "version": "...", ...}
            or {"ok": False, "error": "..."}
        """
        if self._is_training:
            return {"ok": False, "error": "Training is already in progress. Try again later."}

        # Normalize Pydantic model instances into plain dictionaries.
        samples_data = []
        for s in samples:
            if hasattr(s, "model_dump"):
                samples_data.append(s.model_dump())
            elif hasattr(s, "dict"):
                samples_data.append(s.dict())
            else:
                samples_data.append(s)

        if len(samples_data) < MIN_SAMPLES:
            return {
                "ok": False,
                "error": f"Insufficient training samples: {len(samples_data)}/{MIN_SAMPLES}",
            }

        self._is_training = True
        logger.info(
            "Starting five-class fine-tuning training (K-Fold CV)",
            total_samples=len(samples_data),
        )

        try:
            # Ensure the local base-model snapshot exists; the first run downloads it.
            base_model_dir = _ensure_base_model()

            samples_json = json.dumps(samples_data, ensure_ascii=False)
            result_queue: Queue = Queue()
            process = Process(
                target=_train_in_subprocess,
                args=(samples_json, base_model_dir, result_queue),
            )
            process.start()

            import asyncio

            def _wait_with_stall_detection():
                """Wait for the subprocess and kill it if progress stalls too long."""
                while process.is_alive():
                    process.join(timeout=30)  # Check every 30 seconds.
                    if not process.is_alive():
                        break
                    # Read the most recent progress timestamp.
                    progress = get_training_progress()
                    last_update = (
                        progress.get("updated_at", 0) if progress else 0
                    )
                    stall_duration = time.time() - last_update if last_update else 0
                    if last_update and stall_duration > _STALL_TIMEOUT:
                        logger.error(
                            "Training subprocess stalled, killing",
                            stall_s=int(stall_duration),
                            stall_timeout=_STALL_TIMEOUT,
                            last_phase=progress.get("phase") if progress else None,
                        )
                        process.kill()
                        process.join(timeout=10)
                        return "stalled"
                return "done"

            loop = asyncio.get_event_loop()
            status = await loop.run_in_executor(None, _wait_with_stall_detection)

            if status == "stalled":
                logger.error(
                    "Training stalled beyond timeout, subprocess killed",
                    timeout_min=_STALL_TIMEOUT // 60,
                )
                return {
                    "ok": False,
                    "error": "TRAINING_STALLED",
                }

            if result_queue.empty():
                logger.error("Training subprocess exited without producing a result")
                return {"ok": False, "error": "TRAINING_SUBPROCESS_FAILED"}

            result = result_queue.get()

            if result.get("ok"):
                logger.info(
                    "Five-class fine-tuning completed",
                    version=result.get("version"),
                    cv_balanced_accuracy=result.get("cv_balanced_accuracy"),
                    cv_macro_f1=result.get("cv_macro_f1"),
                    optimal_epochs=result.get("optimal_epochs"),
                    duration_s=result.get("total_duration_s"),
                )
            else:
                logger.warning(
                    "Fine-tuning failed",
                    error=result.get("error"),
                )

            return result

        except Exception as e:
            logger.error(f"Training process error: {e}")
            return {"ok": False, "error": "TRAINING_FAILED"}

        finally:
            self._is_training = False
            _clear_progress()


# Global singleton
_trainer: Optional[PhishingTrainer] = None


def get_trainer() -> PhishingTrainer:
    """Return the global `PhishingTrainer` instance."""
    global _trainer
    if _trainer is None:
        _trainer = PhishingTrainer()
    return _trainer
