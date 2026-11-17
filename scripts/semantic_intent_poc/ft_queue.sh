#!/usr/bin/env bash
# Shared training queue on the training server: start one worker per DCU; each
# claims the next unclaimed line of QUEUE (atomic mkdir under logs/) and runs it
# with run_ft.sh, so cards never idle while jobs remain. Order QUEUE longest
# first. usage: ft_queue.sh QUEUE DCU
# QUEUE lines: NAME train_classifier.py-args, shell-quoted (--prefix 'query: ').
set -u
root=${VIGILYX_FT_ROOT:?set VIGILYX_FT_ROOT to the experiment root under /data/vigilyx-training}
queue=$1; dcu=$2
while read -r name args; do
    [ -z "$name" ] && continue
    mkdir "$root/logs/claim-$name" 2>/dev/null || continue
    echo "$(date '+%F %T') dcu=$dcu start $name"
    eval "set -- $args"
    "$(dirname "$0")/run_ft.sh" "$name" "$dcu" -- "$@" < /dev/null
    echo "$(date '+%F %T') dcu=$dcu done $name status=$(cat "$root/logs/$name.status")"
done < "$queue"
echo "$(date '+%F %T') dcu=$dcu queue empty"
