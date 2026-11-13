#!/usr/bin/env bash
# Download the PoC encoder candidates at pinned commits and record SHA256.
# usage: fetch_models.sh MODELS_DIR [PROXY_URL]
# Upstream models are MIT licensed (BAAI/bge-small-zh-v1.5,
# intfloat/multilingual-e5-small); the ONNX exports come from Xenova/*.
set -euo pipefail
dest=$1
proxy=${2:-}
curl_args=(-fL --retry 3 --connect-timeout 30)
[ -n "$proxy" ] && curl_args+=(-x "$proxy")

fetch() {
    local repo=$1 rev=$2 dir=$3; shift 3
    mkdir -p "$dest/$dir/onnx"
    for file in "$@"; do
        [ -s "$dest/$dir/$file" ] && continue
        curl "${curl_args[@]}" -o "$dest/$dir/$file.part" \
            "https://huggingface.co/$repo/resolve/$rev/$file"
        mv "$dest/$dir/$file.part" "$dest/$dir/$file"
    done
    printf '%s %s\n' "$repo" "$rev" > "$dest/$dir/SOURCE"
}

fetch Xenova/bge-small-zh-v1.5 75c43b069aac4d136ba6bc1122f995fedcfd2781 bge-small-zh-v1.5 \
    config.json tokenizer.json onnx/model.onnx onnx/model_quantized.onnx
fetch Xenova/multilingual-e5-small 761b726dd34fb83930e26aab4e9ac3899aa1fa78 multilingual-e5-small \
    config.json tokenizer.json onnx/model.onnx onnx/model_quantized.onnx

(cd "$dest" && find . -type f ! -name MANIFEST.sha256 ! -name '*.part' -print0 \
    | sort -z | xargs -0 sha256sum > MANIFEST.sha256)
cat "$dest/MANIFEST.sha256"
