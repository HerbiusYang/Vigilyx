#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SCRIPT_PATH="${SCRIPT_DIR}/$(basename "${BASH_SOURCE[0]}")"

ENV_FILE="${REPO_ROOT}/deploy/docker/.env"
INTERFACE_OVERRIDE=""
INSTALL_HOOK=true
DRY_RUN=false

usage() {
    cat <<'EOF'
Usage:
  bash scripts/apply-capture-host-tuning.sh [--env-file PATH] [--interface IFACE] [--no-install-hook] [--dry-run]

Applies host-side packet-capture tuning for the sniffer interface:
  - sysctl receive-path tuning
  - NIC ring sizing (when ethtool supports it)
  - capture-hostile offload disablement (when ethtool supports it)
  - RPS/RFS steering
  - optional IRQ affinity rebalance

Behavior is controlled by deploy/docker/.env and can be reused across hosts.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --env-file)
            ENV_FILE="$2"
            shift 2
            ;;
        --interface)
            INTERFACE_OVERRIDE="$2"
            shift 2
            ;;
        --no-install-hook)
            INSTALL_HOOK=false
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

log() {
    printf '  %s\n' "$*"
}

is_truthy() {
    case "${1:-}" in
        1|true|TRUE|True|yes|YES|Yes|on|ON|On)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

run_cmd() {
    if $DRY_RUN; then
        log "DRY-RUN: $*"
        return 0
    fi
    "$@"
}

if [ -f "$ENV_FILE" ]; then
    if env_perms=$(stat -c '%a' "$ENV_FILE" 2>/dev/null); then
        :
    elif env_perms=$(stat -f '%Lp' "$ENV_FILE" 2>/dev/null); then
        :
    else
        echo "Error: unable to inspect permissions for $ENV_FILE." >&2
        exit 1
    fi
    if [[ ! "$env_perms" =~ ^[0-7]{3,4}$ ]]; then
        echo "Error: invalid permission value '$env_perms' for $ENV_FILE." >&2
        exit 1
    fi
    if [ $((8#$env_perms % 64)) -ne 0 ]; then
        echo "Error: $ENV_FILE must not be group/world-accessible before sourcing (chmod 600 $ENV_FILE)." >&2
        exit 1
    fi
    set -a
    # shellcheck source=/dev/null
    source "$ENV_FILE"
    set +a
fi

INTERFACE="${INTERFACE_OVERRIDE:-${SNIFFER_INTERFACE:-eth0}}"
if ! is_truthy "${SNIFFER_HOST_TUNING:-true}"; then
    log "Capture host tuning disabled by SNIFFER_HOST_TUNING=false"
    exit 0
fi

if [ ! -d "/sys/class/net/${INTERFACE}" ]; then
    log "Capture interface ${INTERFACE} does not exist; skipping host tuning"
    exit 0
fi

DEFAULT_WORKERS="${SNIFFER_WORKERS:-16}"
HOST_RMEM_MAX="${SNIFFER_HOST_RMEM_MAX:-1073741824}"
HOST_RMEM_DEFAULT="${SNIFFER_HOST_RMEM_DEFAULT:-67108864}"
HOST_NETDEV_MAX_BACKLOG="${SNIFFER_HOST_NETDEV_MAX_BACKLOG:-250000}"
HOST_NETDEV_BUDGET="${SNIFFER_HOST_NETDEV_BUDGET:-1200}"
HOST_NETDEV_BUDGET_USECS="${SNIFFER_HOST_NETDEV_BUDGET_USECS:-8000}"
HOST_RPS_FLOW_ENTRIES="${SNIFFER_HOST_RPS_FLOW_ENTRIES:-65536}"
HOST_SET_RING_MAX="${SNIFFER_HOST_SET_RING_MAX:-true}"
HOST_DISABLE_OFFLOADS="${SNIFFER_HOST_DISABLE_OFFLOADS:-true}"
HOST_INSTALL_HOOK="${SNIFFER_HOST_INSTALL_HOOK:-true}"
HOST_IRQ_REBALANCE="${SNIFFER_HOST_IRQ_REBALANCE:-true}"
HOST_IRQ_CPU_LIST="${SNIFFER_HOST_IRQ_CPU_LIST:-}"
HOST_IRQ_EXCLUDE_CPUS="${SNIFFER_HOST_IRQ_EXCLUDE_CPUS:-}"
HOST_IRQ_DISABLE_IRQBALANCE="${SNIFFER_HOST_IRQ_DISABLE_IRQBALANCE:-false}"
HOST_RPS_CPU_LIST="${SNIFFER_HOST_RPS_CPU_LIST:-}"
WORKER_CPU_LIST="${SNIFFER_WORKER_CPU_LIST:-}"
CAPTURE_CPU="${SNIFFER_CAPTURE_CPU:-}"

expand_cpu_spec() {
    python3 - "$1" <<'PY'
import sys

spec = (sys.argv[1] or "").strip()
if not spec:
    raise SystemExit(0)

seen = set()
cpus = []
for chunk in spec.split(","):
    chunk = chunk.strip()
    if not chunk:
        continue
    if "-" in chunk:
        start_text, end_text = chunk.split("-", 1)
        start = int(start_text)
        end = int(end_text)
        if end < start:
            start, end = end, start
        values = range(start, end + 1)
    else:
        values = [int(chunk)]
    for value in values:
        if value not in seen:
            seen.add(value)
            cpus.append(value)

for cpu in sorted(cpus):
    print(cpu)
PY
}

cpus_to_mask() {
    python3 - "$1" <<'PY'
import sys

spec = (sys.argv[1] or "").strip()

def expand(raw):
    cpus = set()
    for chunk in raw.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start_text, end_text = chunk.split("-", 1)
            start = int(start_text)
            end = int(end_text)
            if end < start:
                start, end = end, start
            cpus.update(range(start, end + 1))
        else:
            cpus.add(int(chunk))
    return sorted(cpus)

cpus = expand(spec)
if not cpus:
    print("0")
    raise SystemExit(0)

mask = 0
for cpu in cpus:
    mask |= 1 << cpu

raw = f"{mask:x}"
parts = []
while raw:
    parts.append(raw[-8:])
    raw = raw[:-8]
print(",".join(reversed(parts)) if parts else "0")
PY
}

pick_worker_cpus() {
    local explicit_spec="$1"
    python3 - "$explicit_spec" "${DEFAULT_WORKERS}" <<'PY'
import sys
from pathlib import Path

explicit_spec = sys.argv[1].strip()
worker_count = max(int(sys.argv[2] or "0"), 1)

def expand(spec: str) -> list[int]:
    cpus: set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start_text, end_text = chunk.split("-", 1)
            start = int(start_text)
            end = int(end_text)
            if end < start:
                raise ValueError(f"reversed CPU range: {chunk}")
            cpus.update(range(start, end + 1))
        else:
            cpus.add(int(chunk))
    return sorted(cpus)

online = expand(Path("/sys/devices/system/cpu/online").read_text().strip())
worker_count = min(worker_count, max(len(online) - 1, 1))
if explicit_spec:
    selected = [cpu for cpu in expand(explicit_spec) if cpu in set(online)]
    selected = selected[:worker_count]
else:
    selected = online[:worker_count]
if not selected:
    selected = online[:1]
for cpu in selected:
    print(cpu)
PY
}

pick_capture_cpu() {
    local explicit_cpu="$1"
    local worker_spec="$2"
    python3 - "$explicit_cpu" "$worker_spec" <<'PY'
import sys
from pathlib import Path

explicit_cpu = sys.argv[1].strip()
worker_spec = sys.argv[2].strip()

def expand(spec: str) -> list[int]:
    cpus: set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start_text, end_text = chunk.split("-", 1)
            start = int(start_text)
            end = int(end_text)
            if end < start:
                raise ValueError(f"reversed CPU range: {chunk}")
            cpus.update(range(start, end + 1))
        else:
            cpus.add(int(chunk))
    return sorted(cpus)

online = expand(Path("/sys/devices/system/cpu/online").read_text().strip())
workers = set(expand(worker_spec))
if explicit_cpu:
    requested = expand(explicit_cpu)
    if len(requested) != 1:
        raise ValueError("SNIFFER_CAPTURE_CPU must contain one CPU")
    if requested[0] in set(online):
        print(requested[0])
        raise SystemExit(0)
for cpu in online:
    if cpu not in workers:
        print(cpu)
        raise SystemExit(0)
print(online[0])
PY
}

pick_irq_cpus() {
    local explicit_spec="$1"
    local extra_exclude_spec="$2"
    python3 - "$explicit_spec" "$extra_exclude_spec" <<'PY'
import sys
from pathlib import Path

explicit_spec = sys.argv[1].strip()
exclude_spec = sys.argv[2].strip()

def expand(spec: str) -> list[int]:
    cpus: set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start_text, end_text = chunk.split("-", 1)
            start = int(start_text)
            end = int(end_text)
            if end < start:
                start, end = end, start
            cpus.update(range(start, end + 1))
        else:
            cpus.add(int(chunk))
    return sorted(cpus)

online_spec = Path("/sys/devices/system/cpu/online").read_text().strip()
online = expand(online_spec)
online_set = set(online)
excluded = set(expand(exclude_spec))
if explicit_spec:
    candidates = [cpu for cpu in expand(explicit_spec) if cpu in online_set and cpu not in excluded]
else:
    candidates = [cpu for cpu in online if cpu not in excluded]
if not candidates:
    candidates = [cpu for cpu in online if cpu not in excluded] or online

time_squeeze: dict[int, int] = {}
softnet_path = Path("/proc/net/softnet_stat")
if softnet_path.exists():
    for cpu_index, line in enumerate(softnet_path.read_text().splitlines()):
        parts = line.split()
        if len(parts) >= 3:
            try:
                time_squeeze[cpu_index] = int(parts[2], 16)
            except ValueError:
                pass

for cpu in sorted(candidates, key=lambda value: (time_squeeze.get(value, 0), value)):
    print(cpu)
PY
}

join_by_comma() {
    local IFS=,
    printf '%s' "$*"
}

mapfile -t WORKER_CPUS < <(pick_worker_cpus "${WORKER_CPU_LIST}")
if [ "${#WORKER_CPUS[@]}" -eq 0 ]; then
    mapfile -t WORKER_CPUS < <(expand_cpu_spec "$(cat /sys/devices/system/cpu/online)")
fi
WORKER_CPU_SPEC="$(join_by_comma "${WORKER_CPUS[@]}")"
if ! CAPTURE_CPU=$(pick_capture_cpu "${CAPTURE_CPU}" "${WORKER_CPU_SPEC}"); then
    CAPTURE_CPU="${WORKER_CPUS[0]}"
fi

# NIC IRQs must not be placed on either the libpcap reader or worker CPUs.
# `irqbalance` can legally rewrite /proc/irq/*/smp_affinity_list after this
# script exits, so the worker/capture CPUs are also banned in irqbalance's
# durable configuration below.
IRQ_EXCLUDE_SPEC="${HOST_IRQ_EXCLUDE_CPUS}"
if [ -n "${IRQ_EXCLUDE_SPEC}" ]; then IRQ_EXCLUDE_SPEC+=","; fi
IRQ_EXCLUDE_SPEC+="${WORKER_CPU_SPEC},${CAPTURE_CPU}"
mapfile -t IRQ_CPUS < <(pick_irq_cpus "${HOST_IRQ_CPU_LIST}" "${IRQ_EXCLUDE_SPEC}")
if [ "${#IRQ_CPUS[@]}" -eq 0 ]; then
    mapfile -t IRQ_CPUS < <(expand_cpu_spec "$(cat /sys/devices/system/cpu/online)")
fi
IRQ_CPU_SPEC="$(join_by_comma "${IRQ_CPUS[@]}")"

log "Applying host capture tuning on ${INTERFACE}"
log "Worker CPUs: ${WORKER_CPU_SPEC}"
log "Dedicated libpcap capture CPU: ${CAPTURE_CPU}"
log "NIC IRQ CPUs: ${IRQ_CPU_SPEC}"

if is_truthy "${HOST_SET_RING_MAX}" && command -v ethtool >/dev/null 2>&1; then
    MAX_RX="$(ethtool -g "${INTERFACE}" 2>/dev/null | awk '/Pre-set maximums:/,/Current hardware settings:/{if(/^RX:/){print $2; exit}}')"
    MAX_TX="$(ethtool -g "${INTERFACE}" 2>/dev/null | awk '/Pre-set maximums:/,/Current hardware settings:/{if(/^TX:/){print $2; exit}}')"
    CUR_RX="$(ethtool -g "${INTERFACE}" 2>/dev/null | awk '/Current hardware settings:/,0{if(/^RX:/){print $2; exit}}')"
    CUR_TX="$(ethtool -g "${INTERFACE}" 2>/dev/null | awk '/Current hardware settings:/,0{if(/^TX:/){print $2; exit}}')"
    if [ -n "${MAX_RX}" ] && [ "${CUR_RX:-}" != "${MAX_RX}" ]; then
        run_cmd ethtool -G "${INTERFACE}" rx "${MAX_RX}" tx "${MAX_TX:-${MAX_RX}}"
        log "NIC ring buffer: RX ${CUR_RX:-unknown} -> ${MAX_RX}, TX ${CUR_TX:-unknown} -> ${MAX_TX:-${MAX_RX}}"
    fi
fi

if is_truthy "${HOST_DISABLE_OFFLOADS}" && command -v ethtool >/dev/null 2>&1; then
    # GRO/GSO/TSO can coalesce or synthesize frames before libpcap observes
    # them. Disable each feature independently because virtual NICs commonly
    # expose some features as fixed/unsupported.
    for feature in gro lro gso tso rx-gro-hw; do
        if $DRY_RUN; then
            log "DRY-RUN: ethtool -K ${INTERFACE} ${feature} off"
        elif ethtool -K "${INTERFACE}" "${feature}" off >/dev/null 2>&1; then
            log "NIC offload disabled: ${feature}"
        else
            log "NIC offload unavailable or fixed (continuing): ${feature}"
        fi
    done
fi

SYSCTL_CONF="/etc/sysctl.d/99-vigilyx-capture.conf"
if $DRY_RUN; then
    log "DRY-RUN: write ${SYSCTL_CONF}"
else
    cat > "${SYSCTL_CONF}" <<EOF
# Managed by scripts/apply-capture-host-tuning.sh
net.core.rmem_max = ${HOST_RMEM_MAX}
net.core.rmem_default = ${HOST_RMEM_DEFAULT}
net.core.netdev_max_backlog = ${HOST_NETDEV_MAX_BACKLOG}
net.core.netdev_budget = ${HOST_NETDEV_BUDGET}
net.core.netdev_budget_usecs = ${HOST_NETDEV_BUDGET_USECS}
net.core.rps_sock_flow_entries = ${HOST_RPS_FLOW_ENTRIES}
net.core.somaxconn = 4096
net.ipv4.tcp_max_syn_backlog = 4096
EOF
    sysctl -p "${SYSCTL_CONF}" >/dev/null
fi
log "sysctl tuned: backlog=${HOST_NETDEV_MAX_BACKLOG} budget=${HOST_NETDEV_BUDGET}/${HOST_NETDEV_BUDGET_USECS}us rps_sock_flow_entries=${HOST_RPS_FLOW_ENTRIES}"

RX_QUEUE_COUNT="$(find "/sys/class/net/${INTERFACE}/queues" -maxdepth 1 -type d -name 'rx-*' | wc -l | tr -d ' ')"
if [ "${RX_QUEUE_COUNT}" -gt 0 ]; then
    RPS_CPU_SPEC="${HOST_RPS_CPU_LIST:-${WORKER_CPU_SPEC}}"
    RPS_MASK="$(cpus_to_mask "${RPS_CPU_SPEC}")"
    PER_QUEUE=$(( HOST_RPS_FLOW_ENTRIES / RX_QUEUE_COUNT ))
    if [ "${PER_QUEUE}" -lt 4096 ]; then
        PER_QUEUE=4096
    fi

    for queue_dir in "/sys/class/net/${INTERFACE}/queues"/rx-*; do
        [ -d "${queue_dir}" ] || continue
        if $DRY_RUN; then
            log "DRY-RUN: echo ${RPS_MASK} > ${queue_dir}/rps_cpus"
            log "DRY-RUN: echo ${PER_QUEUE} > ${queue_dir}/rps_flow_cnt"
        else
            echo "${RPS_MASK}" > "${queue_dir}/rps_cpus"
            echo "${PER_QUEUE}" > "${queue_dir}/rps_flow_cnt"
        fi
    done

    log "RPS/RFS configured: mask=${RPS_MASK}, per_queue=${PER_QUEUE}, queues=${RX_QUEUE_COUNT}"
fi

if is_truthy "${HOST_IRQ_REBALANCE}"; then
    IRQBALANCE_CONFIG="/etc/sysconfig/irqbalance"
    IRQBALANCE_BANNED_MASK="$(cpus_to_mask "${WORKER_CPU_SPEC},${CAPTURE_CPU}")"
    if [ -f "${IRQBALANCE_CONFIG}" ]; then
        existing_banned=$(sed -n 's/^[[:space:]]*IRQBALANCE_BANNED_CPUS[[:space:]]*=[[:space:]]*//p' "${IRQBALANCE_CONFIG}" | tail -n 1 | tr -d '[:space:]' | tr -d '"' | tr -d "'" || true)
        if [ -n "${existing_banned}" ]; then
            IRQBALANCE_BANNED_MASK="$(python3 - "${existing_banned}" "${IRQBALANCE_BANNED_MASK}" <<'PY'
import sys

def parse_mask(raw: str) -> int:
    return int(raw.replace(",", ""), 16)

print(f"{parse_mask(sys.argv[1]) | parse_mask(sys.argv[2]):x}")
PY
)"
        fi
    fi
    if $DRY_RUN; then
        log "DRY-RUN: configure ${IRQBALANCE_CONFIG} IRQBALANCE_BANNED_CPUS=${IRQBALANCE_BANNED_MASK}"
    else
        mkdir -p "$(dirname "${IRQBALANCE_CONFIG}")"
        if [ -f "${IRQBALANCE_CONFIG}" ]; then
            if grep -q '^[[:space:]]*IRQBALANCE_BANNED_CPUS[[:space:]]*=' "${IRQBALANCE_CONFIG}"; then
                sed -i "s/^[[:space:]]*IRQBALANCE_BANNED_CPUS[[:space:]]*=.*/IRQBALANCE_BANNED_CPUS=${IRQBALANCE_BANNED_MASK}/" "${IRQBALANCE_CONFIG}"
            else
                printf '\nIRQBALANCE_BANNED_CPUS=%s\n' "${IRQBALANCE_BANNED_MASK}" >> "${IRQBALANCE_CONFIG}"
            fi
        else
            printf 'IRQBALANCE_BANNED_CPUS=%s\n' "${IRQBALANCE_BANNED_MASK}" > "${IRQBALANCE_CONFIG}"
        fi
        log "irqbalance reserved worker/capture CPUs: ${IRQBALANCE_BANNED_MASK}"
        if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet irqbalance; then
            systemctl try-restart irqbalance >/dev/null 2>&1 || true
        fi
    fi

    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet irqbalance; then
        if is_truthy "${HOST_IRQ_DISABLE_IRQBALANCE}"; then
            run_cmd systemctl stop irqbalance
            log "Stopped irqbalance to preserve manual IRQ affinity"
        else
            log "irqbalance remains active with worker/capture CPUs banned; manual NIC IRQ placement may move among IRQ CPUs"
        fi
    fi

    IRQ_ROOT="/sys/class/net/${INTERFACE}/device/msi_irqs"
    mapfile -t IFACE_IRQS < <(
        if [ -d "${IRQ_ROOT}" ]; then
            find "${IRQ_ROOT}" -mindepth 1 -maxdepth 1 -printf '%f\n' 2>/dev/null | sort -n
        else
            awk -v iface="${INTERFACE}" '$0 ~ iface {gsub(":", "", $1); print $1}' /proc/interrupts | sort -n
        fi
    )

    if [ "${#IFACE_IRQS[@]}" -gt 0 ]; then
        for index in "${!IFACE_IRQS[@]}"; do
            irq="${IFACE_IRQS[$index]}"
            cpu="${IRQ_CPUS[$(( index % ${#IRQ_CPUS[@]} ))]}"
            current_cpu="$(cat "/proc/irq/${irq}/smp_affinity_list" 2>/dev/null || true)"
            if [ "${current_cpu}" != "${cpu}" ]; then
                if $DRY_RUN; then
                    log "DRY-RUN: echo ${cpu} > /proc/irq/${irq}/smp_affinity_list"
                else
                    echo "${cpu}" > "/proc/irq/${irq}/smp_affinity_list"
                fi
            fi
            log "IRQ ${irq} -> CPU ${cpu}"
        done
    else
        log "No interface IRQs discovered for ${INTERFACE}; skipping IRQ rebalance"
    fi
fi

if $INSTALL_HOOK && is_truthy "${HOST_INSTALL_HOOK}" && [ -d /etc/NetworkManager/dispatcher.d ]; then
    DISPATCHER="/etc/NetworkManager/dispatcher.d/99-${INTERFACE}-vigilyx-capture-tuning"
    if $DRY_RUN; then
        log "DRY-RUN: install dispatcher hook ${DISPATCHER}"
    else
        cat > "${DISPATCHER}" <<EOF
#!/usr/bin/env bash
if [ "\$1" = "${INTERFACE}" ] && [ "\$2" = "up" ]; then
    bash "${SCRIPT_PATH}" --env-file "${ENV_FILE}" --interface "${INTERFACE}" --no-install-hook >/dev/null 2>&1 || true
fi
EOF
        chmod +x "${DISPATCHER}"
        log "Installed NetworkManager dispatcher hook: ${DISPATCHER}"
    fi
fi
