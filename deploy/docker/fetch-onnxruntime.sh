#!/usr/bin/env bash
# Fetch the pinned ONNX Runtime CPU library used by the engine's semantic
# intent model (shadow mode, loaded at run time through ORT_DYLIB_PATH).
# Idempotent. The release archive is verified by SHA256 before only the
# shared library and its licence files are extracted.
# usage: fetch-onnxruntime.sh DEST_DIR [PROXY_URL]
set -euo pipefail

VERSION=1.20.1
# onnxruntime-linux-x64-1.20.1.tgz, 6,191,581 bytes (upstream commit
# 5c1b7ccbff7e5141c1da7a9d963d660e5741c319). GitHub publishes no digest for
# this release; pinned 2026-11-11 after identical downloads over two
# independent network paths.
SHA256=67db4dc1561f1e3fd42e619575c82c601ef89849afc7ea85a003abbac1a1a105
NAME="onnxruntime-linux-x64-${VERSION}"
URL="https://github.com/microsoft/onnxruntime/releases/download/v${VERSION}/${NAME}.tgz"

dest=${1:?usage: fetch-onnxruntime.sh DEST_DIR [PROXY_URL]}
proxy=${2:-}
lib="libonnxruntime.so.${VERSION}"

if [ -f "$dest/$lib" ] && [ -f "$dest/SHA256SUMS" ] && (cd "$dest" && sha256sum -c --quiet SHA256SUMS); then
    echo "ONNX Runtime ${VERSION} already present in $dest"
    exit 0
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl_args=(-fL --retry 3 --connect-timeout 30 -o "$tmp/ort.tgz")
[ -n "$proxy" ] && curl_args+=(-x "$proxy")
curl "${curl_args[@]}" "$URL"
echo "${SHA256}  $tmp/ort.tgz" | sha256sum -c --quiet -

tar -xzf "$tmp/ort.tgz" -C "$tmp" "$NAME/lib/$lib" "$NAME/LICENSE" "$NAME/ThirdPartyNotices.txt"
mkdir -p "$dest"
install -m 0644 "$tmp/$NAME/lib/$lib" "$dest/$lib"
install -m 0644 "$tmp/$NAME/LICENSE" "$dest/LICENSE.onnxruntime"
install -m 0644 "$tmp/$NAME/ThirdPartyNotices.txt" "$dest/ThirdPartyNotices.onnxruntime.txt"
(cd "$dest" && sha256sum "$lib" > SHA256SUMS)
echo "ONNX Runtime ${VERSION} installed in $dest"
