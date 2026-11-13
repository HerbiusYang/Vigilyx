#!/usr/bin/env bash
# Run train_classifier.py on the training server, offline, recording the real
# exit code. usage: run_ft.sh NAME DCU[,DCU...] -- train_classifier.py args...
# Several DCUs run one data-parallel job under torchrun (same global --batch).
# Always uses the training-only Docker socket, never the host's default daemon.
set -u
export DOCKER_HOST=unix:///run/umbella-training-docker/docker.sock
root=/root/vigilyx-training/intent-ft-20261110
image=harbor.sourcefind.cn:5443/dcu/admin/base/custom:vllm0.18.1-ubuntu22.04-dtk26.04-py3.10-20260810-qwen3.8
name=$1; dcu=$2; shift 3
ranks=$(printf '%s' "$dcu" | awk -F, '{print NF}')
launch=(train_classifier.py)
# --network none leaves only loopback and an unresolvable hostname: pin rendezvous and collectives to lo.
[ "$ranks" -gt 1 ] && launch=(-m torch.distributed.run --nnodes 1 --nproc_per_node "$ranks"
    --rdzv-backend c10d --rdzv-endpoint 127.0.0.1:29400 --local-addr 127.0.0.1 train_classifier.py)
rm -f "$root/logs/$name.status"
docker run --rm --name "vigilyx-ft-$name" --network none --device /dev/kfd --device /dev/dri \
    --group-add video --shm-size 8g -v /opt/hyhal:/opt/hyhal:ro -v "$root:/work" \
    -e HIP_VISIBLE_DEVICES="$dcu" -e PYTHONDONTWRITEBYTECODE=1 -e MASTER_ADDR=127.0.0.1 \
    -e NCCL_SOCKET_IFNAME=lo -e GLOO_SOCKET_IFNAME=lo -w /work/scripts \
    --entrypoint python3 "$image" "${launch[@]}" "$@" > "$root/logs/$name.log" 2>&1
printf '%s\n' "$?" > "$root/logs/$name.status"
