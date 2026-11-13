#!/usr/bin/env bash
# Finish one k-fold group on the training server: wait for the fold runs
# NAME0..NAME4 started with run_ft.sh, score each with report_accuracy.py
# (fold k on DCU k), then pool out-of-fold results with kfold_report.py.
# usage: kfold_finish.sh NAME MODEL_DIR FOLDS_DATA   (paths relative to /work)
# Always uses the training-only Docker socket.
set -u
export DOCKER_HOST=unix:///run/umbella-training-docker/docker.sock
root=/root/vigilyx-training/intent-ft-20261110
image=harbor.sourcefind.cn:5443/dcu/admin/base/custom:vllm0.18.1-ubuntu22.04-dtk26.04-py3.10-20260810-qwen3.8
name=$1; model=$2; folds=$3
wait_all() {  # wait_all PREFIX: block until logs/PREFIX{0..4}.status exist
    for _ in $(seq 1 720); do
        n=0
        for k in 0 1 2 3 4; do [ -s "$root/logs/$1$k.status" ] && n=$((n + 1)); done
        [ "$n" = 5 ] && return 0
        sleep 10
    done
    return 1
}
wait_all "$name" || { echo "timeout waiting for $name"; exit 1; }
for k in 0 1 2 3 4; do echo "$name$k train=$(cat "$root/logs/$name$k.status")"; done
for k in 0 1 2 3 4; do
    rm -f "$root/logs/acc-$name$k.status"
    docker run -d --rm --name "vigilyx-acc-$name$k" --network none --device /dev/kfd --device /dev/dri \
        --group-add video --shm-size 8g -v /opt/hyhal:/opt/hyhal:ro -v "$root:/work" \
        -e HIP_VISIBLE_DEVICES="$k" -e PYTHONDONTWRITEBYTECODE=1 -w /work/scripts --entrypoint sh "$image" \
        -c "python3 report_accuracy.py --run /work/runs/$name$k --model-dir /work/$model --data /work/$folds/fold$k \
            > /work/logs/acc-$name$k.log 2>&1; echo \$? > /work/logs/acc-$name$k.status" > /dev/null
done
wait_all "acc-$name" || { echo "timeout waiting for accuracy of $name"; exit 1; }
for k in 0 1 2 3 4; do grep -v -i warning "$root/logs/acc-$name$k.log" | grep -E 'test.*acc='; done
docker run --rm --network none -v "$root:/work" -w /work -e PYTHONDONTWRITEBYTECODE=1 --entrypoint python3 "$image" \
    scripts/kfold_report.py --runs $(for k in 0 1 2 3 4; do printf 'runs/%s%d ' "$name" "$k"; done) \
    --folds-data "$folds" --notice-types out/ft/notice_types.json --spam-variants out/ft/spam_variants_all.json \
    --output "runs/$name-oof.json" 2>&1 | grep -v -i warning
