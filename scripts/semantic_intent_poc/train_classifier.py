#!/usr/bin/env python3
"""Fine-tune a small encoder as an email-level classifier (training server).

Trains on train.jsonl, picks the epoch with the best dev AUC, reports test at
the dev 1%-FPR threshold, and exports ONNX (input_ids, attention_mask ->
logit) for CPU scoring on 77. The red-team corpus is never sent here.
Tokenisation uses tokenizer.json through `tokenizers`, the same code path the
77 scorer uses, with head+tail truncation for long mail. `--lowercase` turns on
the BertNormalizer lowercase (and accent stripping) and writes the patched
tokenizer.json into the run: bge-small-zh ships lowercase=false with an
all-lowercase English vocabulary, so every capitalised English or German word
became [UNK].
Under torchrun (run_ft.sh with several DCUs) every rank trains on its share of
each global batch of --batch emails, so the recipe matches a single-DCU run;
rank 0 alone evaluates, writes the run and exports.
"""

import argparse
import copy
import json
import math
import os
from pathlib import Path
import random
import time

import numpy as np
import torch
from torch import distributed as dist
from torch import nn
from torch.nn.parallel import DistributedDataParallel
from tokenizers import Tokenizer
from transformers import AutoModel, get_linear_schedule_with_warmup


def encode_ids(tokenizer, prefix, text, max_len, head):
    ids = tokenizer.encode(prefix + text).ids
    if len(ids) > max_len:
        ids = ids[:head] + ids[-(max_len - head):]
    return ids


def load_tokenizer(model_dir, lowercase):
    """Return (Tokenizer, tokenizer.json text) for the model, lowercased on request."""
    spec = json.loads((Path(model_dir) / "tokenizer.json").read_text(encoding="utf-8"))
    if lowercase:
        if (spec.get("normalizer") or {}).get("type") != "BertNormalizer":
            raise SystemExit("--lowercase needs a BertNormalizer tokenizer")
        spec["normalizer"]["lowercase"] = True
    text = json.dumps(spec, ensure_ascii=False)
    return Tokenizer.from_str(text), text


def load(path, tokenizer, prefix, max_len, head):
    rows = [json.loads(line) for line in open(path, encoding="utf-8") if line.strip()]
    return [(encode_ids(tokenizer, prefix, r["text"], max_len, head), r["label"], r["group"], r["id"]) for r in rows]


class Classifier(nn.Module):
    def __init__(self, model_dir, pooling, attn=None, mask4d=False):
        super().__init__()
        kwargs = {"attn_implementation": attn} if attn else {}
        self.encoder = AutoModel.from_pretrained(model_dir, **kwargs)
        self.pooling = pooling
        self.mask4d = mask4d
        self.dropout = nn.Dropout(0.1)
        self.head = nn.Linear(self.encoder.config.hidden_size, 1)

    def forward(self, input_ids, attention_mask):
        mask = attention_mask
        if self.mask4d:
            # Additive 4-D mask: bypasses transformers' mask builder for the legacy exporter.
            mask = (1.0 - attention_mask[:, None, None, :].to(torch.float32)) * torch.finfo(torch.float32).min
        hidden = self.encoder(input_ids=input_ids, attention_mask=mask).last_hidden_state
        if self.pooling == "cls":
            vector = hidden[:, 0]
        else:
            mask = attention_mask.unsqueeze(-1).to(hidden.dtype)
            vector = (hidden * mask).sum(1) / mask.sum(1).clamp(min=1e-9)
        return self.head(self.dropout(vector)).squeeze(-1)


def batches(items, size, pad_id, shuffle, rng):
    order = list(range(len(items)))
    if shuffle:
        rng.shuffle(order)
    for start in range(0, len(order), size):
        chunk = [items[i] for i in order[start:start + size]]
        width = max(len(c[0]) for c in chunk)
        ids = torch.full((len(chunk), width), pad_id, dtype=torch.long)
        mask = torch.zeros((len(chunk), width), dtype=torch.long)
        for row, c in enumerate(chunk):
            ids[row, :len(c[0])] = torch.tensor(c[0])
            mask[row, :len(c[0])] = 1
        yield ids, mask, torch.tensor([float(c[1]) for c in chunk]), [order[i] for i in range(start, start + len(chunk))]


def auc(scores, labels):
    pos, neg = scores[labels == 1], scores[labels == 0]
    both = np.concatenate([pos, neg])
    order = both.argsort(kind="mergesort")
    ranks = np.empty(len(both))
    ranks[order] = np.arange(1, len(both) + 1)
    values = both[order]
    i = 0
    while i < len(values):
        j = i
        while j + 1 < len(values) and values[j + 1] == values[i]:
            j += 1
        if j > i:
            ranks[order[i:j + 1]] = (i + j + 2) / 2.0
        i = j + 1
    return float((ranks[:len(pos)].sum() - len(pos) * (len(pos) + 1) / 2) / (len(pos) * len(neg)))


def threshold(scores, labels, fpr):
    benign = np.sort(scores[labels == 0])
    return float(benign[max(int(math.ceil(len(benign) * (1 - fpr))) - 1, 0)])


@torch.no_grad()
def predict(model, items, pad_id, device, size=64):
    model.eval()
    out = np.zeros(len(items), dtype=np.float32)
    for ids, mask, _, index in batches(items, size, pad_id, False, None):
        out[index] = model(ids.to(device), mask.to(device)).float().cpu().numpy()
    return out


def report(scores, items, tau):
    labels = np.array([c[1] for c in items])
    keep = labels >= 0
    flagged = scores > tau
    groups = {}
    for (_, label, group, _), flag in zip(items, flagged):
        key = f"{label}|{group}"
        n, f = groups.get(key, (0, 0))
        groups[key] = (n + 1, f + int(flag))
    return {"auc": auc(scores[keep], labels[keep]),
            "recall": float(flagged[labels == 1].mean()), "fpr": float(flagged[labels == 0].mean()),
            "spam_flag_rate": float(flagged[labels == -1].mean()) if (labels == -1).any() else None,
            "groups": {k: {"n": n, "rate": round(f / n, 4)} for k, (n, f) in sorted(groups.items())}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model-dir", required=True)
    parser.add_argument("--pooling", choices=("cls", "mean"), required=True)
    parser.add_argument("--prefix", default="")
    parser.add_argument("--data", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--lr", type=float, default=3e-5)
    parser.add_argument("--batch", type=int, default=32)
    parser.add_argument("--max-len", type=int, default=512)
    parser.add_argument("--head-tokens", type=int, default=384)
    parser.add_argument("--seed", type=int, default=20261110)
    parser.add_argument("--lowercase", action="store_true", help="lowercase BertNormalizer input (bge-small-zh)")
    parser.add_argument("--export-only", action="store_true", help="re-export an existing model.pt")
    args = parser.parse_args()
    if args.export_only:
        tokenizer = Tokenizer.from_file(str(args.output / "tokenizer.json"))
        export(args, tokenizer.encode("export sample text for tracing only").ids)
        return
    world, rank = int(os.environ.get("WORLD_SIZE", "1")), int(os.environ.get("RANK", "0"))
    if rank == 0:
        args.output.mkdir(parents=True)
    random.seed(args.seed)
    np.random.seed(args.seed)
    torch.manual_seed(args.seed)
    if world > 1:
        local = int(os.environ["LOCAL_RANK"])
        torch.cuda.set_device(local)
        dist.init_process_group("nccl")
        device = torch.device("cuda", local)
    else:
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"device={device} visible={torch.cuda.device_count()} rank={rank}/{world}", flush=True)

    tokenizer, tokenizer_json = load_tokenizer(args.model_dir, args.lowercase)
    tokenizer.no_truncation()
    tokenizer.no_padding()
    pad = tokenizer.token_to_id("[PAD]")
    pad_id = pad if pad is not None else tokenizer.token_to_id("<pad>")
    data = {n: load(args.data / f"{n}.jsonl", tokenizer, args.prefix, args.max_len, args.head_tokens)
            for n in ("train", "dev", "test")}
    train = [c for c in data["train"] if c[1] >= 0]
    n_pos = sum(c[1] for c in train)
    print({n: len(v) for n, v in data.items()}, f"train_pos={n_pos}", flush=True)

    model = Classifier(args.model_dir, args.pooling).to(device)
    # The encoder's pooler is never used, hence find_unused_parameters.
    trained = DistributedDataParallel(model, device_ids=[device.index], find_unused_parameters=True) \
        if world > 1 else model
    loss_fn = nn.BCEWithLogitsLoss(pos_weight=torch.tensor((len(train) - n_pos) / n_pos, device=device))
    no_decay = ("bias", "LayerNorm.weight", "layer_norm.weight")
    params = [{"params": [p for n, p in model.named_parameters() if not n.endswith(no_decay)], "weight_decay": 0.01},
              {"params": [p for n, p in model.named_parameters() if n.endswith(no_decay)], "weight_decay": 0.0}]
    optimizer = torch.optim.AdamW(params, lr=args.lr)
    steps = args.epochs * math.ceil(len(train) / args.batch)
    scheduler = get_linear_schedule_with_warmup(optimizer, int(0.1 * steps), steps)
    rng = random.Random(args.seed)
    dev_labels = np.array([c[1] for c in data["dev"]])
    history, best = [], None
    started = time.time()
    for epoch in range(1, args.epochs + 1):
        trained.train()
        total, count = 0.0, 0
        for ids, mask, y, _ in batches(train, args.batch, pad_id, True, rng):
            if world > 1:
                # Same shuffled global batch on every rank (same seed); each takes its slice.
                if len(y) < world:
                    continue
                ids, mask, y = ids[rank::world], mask[rank::world], y[rank::world]
            logits = trained(ids.to(device), mask.to(device))
            loss = loss_fn(logits, y.to(device))
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            scheduler.step()
            optimizer.zero_grad()
            total += loss.item() * len(y)
            count += len(y)
        if world > 1:
            sums = torch.tensor([total, count], dtype=torch.float64, device=device)
            dist.all_reduce(sums)
            total, count = sums.tolist()
        if rank == 0:
            dev_scores = predict(model, data["dev"], pad_id, device)
            dev_auc = auc(dev_scores, dev_labels)
            history.append({"epoch": epoch, "train_loss": total / count, "dev_auc": dev_auc,
                            "seconds": round(time.time() - started, 1)})
            print(json.dumps(history[-1]), flush=True)
            if best is None or dev_auc > best[0]:
                best = (dev_auc, epoch, copy.deepcopy(model.state_dict()))
        if world > 1:
            dist.barrier()
    if world > 1:
        dist.destroy_process_group()
        if rank != 0:
            return

    model.load_state_dict(best[2])
    dev_scores = predict(model, data["dev"], pad_id, device)
    test_scores = predict(model, data["test"], pad_id, device)
    tau = threshold(dev_scores, dev_labels, 0.01)
    summary = {"args": {k: str(v) for k, v in vars(args).items()}, "world_size": world,
               "history": history, "best_epoch": best[1],
               "dev_threshold_fpr1": tau, "dev": report(dev_scores, data["dev"], tau),
               "test": report(test_scores, data["test"], tau)}
    with open(args.output / "training_report.json", "w") as stream:
        json.dump(summary, stream, indent=1)
    np.save(args.output / "dev_logits_torch.npy", dev_scores)
    print(json.dumps({k: summary[k] for k in ("best_epoch", "dev_threshold_fpr1")}),
          json.dumps({n: {k: summary[n][k] for k in ("auc", "recall", "fpr")} for n in ("dev", "test")}), flush=True)

    torch.save({k: v.detach().cpu() for k, v in best[2].items()}, args.output / "model.pt")
    with open(args.output / "classifier_config.json", "w") as stream:
        json.dump({"pooling": args.pooling, "prefix": args.prefix, "max_len": args.max_len,
                   "head_tokens": args.head_tokens, "pad_id": pad_id, "dev_threshold_fpr1": tau,
                   "lowercase": args.lowercase,
                   "source_model": (Path(args.model_dir) / "SOURCE").read_text().strip()}, stream, indent=1)
    (args.output / "tokenizer.json").write_text(tokenizer_json, encoding="utf-8")
    export(args, data["dev"][0][0])


def export(args, sample_ids):
    """Export model.pt to ONNX. transformers 5.x mask building breaks the legacy
    TorchScript exporter, so use the dynamo exporter with eager attention and
    fall back to an additive 4-D mask with the legacy exporter. Weights past
    the 2 GB protobuf limit (bge-m3) go to model.onnx.data beside model.onnx."""
    state = torch.load(args.output / "model.pt", map_location="cpu")
    large = sum(v.numel() * v.element_size() for v in state.values()) > 1_800_000_000
    ids = torch.tensor([sample_ids[:16], sample_ids[:16]])
    mask = torch.ones_like(ids)
    mask[1, 10:] = 0
    path = str(args.output / "model.onnx")
    try:
        model = Classifier(args.model_dir, args.pooling, attn="eager").eval()
        model.load_state_dict(state)
        batch, seq = torch.export.Dim("batch"), torch.export.Dim("seq")
        torch.onnx.export(model, (ids, mask), path, input_names=["input_ids", "attention_mask"],
                          output_names=["logit"], dynamo=True, external_data=large,
                          dynamic_shapes={"input_ids": {0: batch, 1: seq}, "attention_mask": {0: batch, 1: seq}})
        method = "dynamo"
    except Exception as error:
        print(f"dynamo export failed: {type(error).__name__}: {error}", flush=True)
        model = Classifier(args.model_dir, args.pooling, attn="eager", mask4d=True).eval()
        model.load_state_dict(state)
        torch.onnx.export(model, (ids, mask), path, input_names=["input_ids", "attention_mask"],
                          output_names=["logit"], opset_version=17, dynamo=False,
                          dynamic_axes={"input_ids": {0: "batch", 1: "seq"},
                                        "attention_mask": {0: "batch", 1: "seq"}, "logit": {0: "batch"}})
        method = "legacy_mask4d"
    print(f"exported via {method}", flush=True)


if __name__ == "__main__":
    main()
