#!/usr/bin/env bash
# Run one PoC step in the offline toolbox image and record its real exit code.
# usage: run_step.sh NAME CPUS [CPUSET] -- command args...
# Inputs (data, models, scripts) are mounted read-only; results go to out/.
set -u
root=$(cd "$(dirname "$0")/.." && pwd)
name=$1; cpus=$2; shift 2
cpuset=()
if [ "$1" != "--" ]; then cpuset=(--cpuset-cpus "$1"); shift; fi
shift
mkdir -p "$root/out" "$root/logs"
rm -f "$root/logs/$name.status"
docker run --rm --name "vigilyx-intent-poc-$name" --network none --cpus "$cpus" "${cpuset[@]}" \
    -e PYTHONDONTWRITEBYTECODE=1 -e OMP_NUM_THREADS=1 \
    -v "$root/data:/work/data:ro" -v "$root/models:/work/models:ro" \
    -v "$root/scripts:/work/scripts:ro" -v "$root/baseline:/work/baseline:ro" \
    -v "$root/out:/work/out" \
    -w /work/scripts vigilyx-intent-poc:20261110 "$@" > "$root/logs/$name.log" 2>&1
printf '%s\n' "$?" > "$root/logs/$name.status"
