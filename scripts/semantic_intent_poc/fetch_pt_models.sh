#!/usr/bin/env bash
# Download upstream PyTorch weights for fine-tuning at pinned commits (MIT).
# usage: fetch_pt_models.sh DEST [PROXY_URL] [MODEL_DIR...]   (no MODEL_DIR: all)
set -euo pipefail
dest=$1
proxy=${2:-}
shift $(( $# < 2 ? $# : 2 ))
only=" $* "
# -C - resumes a .part left by a dropped TLS connection (curl exit 35 seen on this proxy).
curl_args=(-fL --retry 3 --connect-timeout 30 -C -)
[ -n "$proxy" ] && curl_args+=(-x "$proxy")

fetch() {
    local repo=$1 rev=$2 dir=$3; shift 3
    [ "$only" != "  " ] && [[ "$only" != *" $dir "* ]] && return 0
    mkdir -p "$dest/$dir"
    for file in "$@"; do
        [ -s "$dest/$dir/$file" ] && continue
        curl "${curl_args[@]}" -o "$dest/$dir/$file.part" \
            "https://huggingface.co/$repo/resolve/$rev/$file"
        mv "$dest/$dir/$file.part" "$dest/$dir/$file"
    done
    printf '%s %s\n' "$repo" "$rev" > "$dest/$dir/SOURCE"
}

fetch BAAI/bge-small-zh-v1.5 7999e1d3359715c523056ef9478215996d62a620 bge-small-zh-v1.5 \
    config.json model.safetensors tokenizer.json tokenizer_config.json special_tokens_map.json vocab.txt
fetch intfloat/multilingual-e5-small 614241f622f53c4eeff9890bdc4f31cfecc418b3 multilingual-e5-small \
    config.json model.safetensors tokenizer.json tokenizer_config.json special_tokens_map.json \
    sentencepiece.bpe.model
fetch intfloat/multilingual-e5-base d128750597153bb5987e10b1c3493a34e5a4502a multilingual-e5-base \
    config.json model.safetensors tokenizer.json tokenizer_config.json special_tokens_map.json \
    sentencepiece.bpe.model
# Multilingual BGE (XLM-R large). Upstream ships only a PyTorch pickle at the
# root; transformers loads it with weights_only, and the LFS SHA256 is checked.
fetch BAAI/bge-m3 5617a9f61b028005a4858fdac845db406aefb181 bge-m3 \
    config.json pytorch_model.bin tokenizer.json tokenizer_config.json special_tokens_map.json \
    sentencepiece.bpe.model

(cd "$dest" && find . -type f ! -name MANIFEST.sha256 ! -name '*.part' -print0 \
    | sort -z | xargs -0 sha256sum > MANIFEST.sha256)
cat "$dest/MANIFEST.sha256"
