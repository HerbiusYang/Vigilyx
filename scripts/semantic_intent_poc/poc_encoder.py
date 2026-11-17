"""ONNX Runtime sentence encoder for the intent-model PoC (CPU only)."""

from pathlib import Path

import numpy as np
import onnxruntime as ort
from tokenizers import Tokenizer

MODELS = {
    # bge-small-zh-v1.5: CLS pooling, no instruction for symmetric similarity.
    "bge-small-zh": {"dir": "bge-small-zh-v1.5", "pooling": "cls", "prefix": ""},
    # multilingual-e5-small: mean pooling, "query: " prefix for symmetric tasks.
    "me5-small": {"dir": "multilingual-e5-small", "pooling": "mean", "prefix": "query: "},
}
FILES = {"int8": "model_quantized.onnx", "fp32": "model.onnx"}


class Encoder:
    def __init__(self, models_root, name, variant="int8", threads=4, max_tokens=128):
        spec = MODELS[name]
        root = Path(models_root) / spec["dir"]
        self.name, self.variant = name, variant
        self.pooling, self.prefix = spec["pooling"], spec["prefix"]
        self.tokenizer = Tokenizer.from_file(str(root / "tokenizer.json"))
        self.tokenizer.enable_truncation(max_length=max_tokens)
        self.tokenizer.no_padding()
        pad = self.tokenizer.token_to_id("[PAD]")
        self.pad_id = pad if pad is not None else self.tokenizer.token_to_id("<pad>")
        options = ort.SessionOptions()
        options.intra_op_num_threads = threads
        options.inter_op_num_threads = 1
        options.execution_mode = ort.ExecutionMode.ORT_SEQUENTIAL
        options.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        self.session = ort.InferenceSession(
            str(root / "onnx" / FILES[variant]), options, providers=["CPUExecutionProvider"])
        self.inputs = {item.name for item in self.session.get_inputs()}
        outputs = [item.name for item in self.session.get_outputs()]
        self.output = "last_hidden_state" if "last_hidden_state" in outputs else outputs[0]
        self.dim = None

    def token_counts(self, texts):
        return [len(e.ids) for e in self.tokenizer.encode_batch([self.prefix + t for t in texts])]

    def encode(self, texts, batch_size=32):
        if not texts:
            return np.zeros((0, self.dim or 0), dtype=np.float32)
        encodings = self.tokenizer.encode_batch([self.prefix + t for t in texts])
        order = sorted(range(len(encodings)), key=lambda i: len(encodings[i].ids))
        result = [None] * len(encodings)
        for start in range(0, len(order), batch_size):
            batch = order[start:start + batch_size]
            width = max(len(encodings[i].ids) for i in batch)
            ids = np.full((len(batch), width), self.pad_id, dtype=np.int64)
            mask = np.zeros((len(batch), width), dtype=np.int64)
            for row, i in enumerate(batch):
                n = len(encodings[i].ids)
                ids[row, :n] = encodings[i].ids
                mask[row, :n] = 1
            feeds = {"input_ids": ids, "attention_mask": mask}
            if "token_type_ids" in self.inputs:
                feeds["token_type_ids"] = np.zeros_like(ids)
            hidden = self.session.run([self.output], feeds)[0]
            if self.pooling == "cls":
                vectors = hidden[:, 0]
            else:
                weights = mask[..., None].astype(np.float32)
                vectors = (hidden * weights).sum(1) / np.maximum(weights.sum(1), 1e-9)
            vectors = vectors / np.maximum(np.linalg.norm(vectors, axis=1, keepdims=True), 1e-12)
            for row, i in enumerate(batch):
                result[i] = vectors[row]
        stacked = np.stack(result).astype(np.float32)
        self.dim = stacked.shape[1]
        return stacked
