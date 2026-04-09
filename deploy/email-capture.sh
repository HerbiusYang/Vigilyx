#!/bin/bash
###############################################
# Mirrored mail-traffic capture script (v2 - no FIFO architecture)
#
# Architecture changes (v2):
#   Old: dumpcap -> FIFO -> ncat (single connection, dies when disconnected)
#   New: socat/ncat fork mode, with an independent dumpcap for each connection
#
# Core improvements:
#   1. The listener process never exits - clients can reconnect at any time without restarting the service
#   2. Fork mode: each new connection spawns its own dumpcap process
#   3. Aggressive TCP keepalive: detect dead connections and reclaim resources within 25 seconds
#   4. No FIFO: removes write/read synchronization deadlocks
#   5. Local capture-to-disk is completely independent and does not interfere with the live stream
#
# Covered protocols and ports:
#   SMTP: 25/465/587/2525/2526
#   POP3: 110/995
#   IMAP: 143/993
#
# Usage:
#   systemctl start email-capture
#   Rust client: ./start.sh <IP>:5000 (can restart at any time without restarting this service)
###############################################

set -euo pipefail

# ==== Tunable parameters ====
IFACE="${SNIFFER_INTERFACE:-eth0}"       # Mirror-port interface (can be overridden via env var)
CAPTURE_DIR="/data/email-capture"       # Local pcap storage directory
LISTEN_PORT=5000                        # Live-stream listen port
DUMPCAP_BUF_MB=512                      # dumpcap kernel ring buffer (MB)
FILE_SIZE_KB=1048576                    # Local rotation: 1GB per file
MAX_FILES=200                           # Keep at most 200 files
SNAPLEN=0                               # 0 = capture full packets

# TCP keepalive (aggressive settings; detect dead peers within 25 seconds)
KEEPIDLE=10                             # Start probing after 10 seconds of idleness
KEEPINTVL=5                             # Probe every 5 seconds
KEEPCNT=3                               # Treat the connection as dead after 3 consecutive missed probes

# BPF
BPF_FILTER="(vlan and tcp and (port 25 or port 110 or port 143 or port 465 or port 587 or port 993 or port 995 or port 2525 or port 2526)) or (tcp and (port 25 or port 110 or port 143 or port 465 or port 587 or port 993 or port 995 or port 2525 or port 2526))"

# Wrapper script for streaming dumpcap (runs independently per client connection)
STREAM_WRAPPER="/usr/local/bin/email-stream-worker.sh"

# ==== Logging ====
info()  { echo -e "\033[32m[INFO]\033[0m  $(date '+%F %T') $*"; }
warn()  { echo -e "\033[33m[WARN]\033[0m  $(date '+%F %T') $*"; }
error() { echo -e "\033[31m[ERROR]\033[0m $(date '+%F %T') $*"; exit 1; }

# ==== Dependency checks ====
command -v dumpcap &>/dev/null || error "dumpcap 未安装: yum install -y wireshark"

STREAM_TOOL=""
if command -v socat &>/dev/null; then
    STREAM_TOOL="socat"
    info "使用 socat (支持 per-socket keepalive)"
elif command -v ncat &>/dev/null; then
    STREAM_TOOL="ncat"
    info "使用 ncat (建议安装 socat 以获得更精确的 keepalive)"
else
    warn "socat/ncat 均未安装，仅本地落盘模式"
    warn "推荐: yum install -y socat"
fi

# ==== Create the per-connection capture script ====
# Each client connection causes socat/ncat to fork a child process that runs this script
# The script starts an independent dumpcap and pipes stdout over TCP to the client
# When the client disconnects, socat/ncat kills this process, which also terminates dumpcap
cat > "${STREAM_WRAPPER}" << WRAPPER_EOF
#!/bin/bash
exec /usr/bin/dumpcap \\
    -i "${IFACE}" \\
    -p \\
    -B 256 \\
    -s ${SNAPLEN} \\
    -q \\
    -w - -P \\
    -f "${BPF_FILTER}"
WRAPPER_EOF
chmod +x "${STREAM_WRAPPER}"
info "流式抓包脚本: ${STREAM_WRAPPER}"

# ==== Storage directory ====
mkdir -p "${CAPTURE_DIR}"

# ==== Kernel network tuning ====
info "优化内核参数..."
sysctl -w net.core.rmem_max=268435456       >/dev/null
sysctl -w net.core.rmem_default=268435456   >/dev/null
sysctl -w net.core.wmem_max=134217728       >/dev/null
sysctl -w net.core.netdev_max_backlog=500000 >/dev/null
sysctl -w net.core.bpf_jit_enable=1         >/dev/null
sysctl -w net.core.optmem_max=134217728     >/dev/null 2>&1 || true

# System-wide TCP keepalive
sysctl -w net.ipv4.tcp_keepalive_time=${KEEPIDLE}    >/dev/null
sysctl -w net.ipv4.tcp_keepalive_intvl=${KEEPINTVL}   >/dev/null
sysctl -w net.ipv4.tcp_keepalive_probes=${KEEPCNT}    >/dev/null

# ==== NIC tuning ====
info "优化网卡 ${IFACE}..."
ethtool -G "${IFACE}" rx 4096 2>/dev/null || true
ethtool -K "${IFACE}" gro off lro off tso off gso off rx-gro-hw off 2>/dev/null || true
ip link set "${IFACE}" promisc on
ethtool -C "${IFACE}" rx-usecs 0 rx-frames 0 2>/dev/null || true

# ==== PID tracking ====
PIDS=()

cleanup() {
    info "收到退出信号，清理所有子进程..."
    for pid in "${PIDS[@]}"; do
        kill "${pid}" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    info "已全部清理"
}
trap cleanup SIGTERM SIGINT SIGHUP EXIT

###############################################
# Path 1: local capture-to-disk (fallback, fully independent)
###############################################
start_local_capture() {
    info "启动本地落盘抓包..."
    /usr/bin/dumpcap \
        -i "${IFACE}" \
        -p \
        -B "${DUMPCAP_BUF_MB}" \
        -s "${SNAPLEN}" \
        -q \
        -w "${CAPTURE_DIR}/mail.pcapng" \
        -b "filesize:${FILE_SIZE_KB}" \
        -b "files:${MAX_FILES}" \
        -f "${BPF_FILTER}" \
        &
    PIDS+=($!)
    info "本地落盘 PID: $!"
}

###############################################
# Path 2: real-time network stream (fork mode, never exits)
#
# Key difference (vs the old FIFO architecture):
#   Old: dumpcap -> FIFO -> ncat (single connection)
#        Client disconnects -> ncat misses it -> hangs -> must be restarted
#
#   New: socat/ncat (permanent listener, fork)
#        Each new connection -> fork -> dedicated dumpcap
#        Client disconnects -> only that connection's dumpcap is killed
#        Listener process is unaffected -> new connections are immediately available
###############################################
start_network_service() {
    if [[ -z "${STREAM_TOOL}" ]]; then
        warn "无网络工具，跳过实时流服务"
        return
    fi

    info "启动网络服务 (${STREAM_TOOL} fork 模式) 端口 ${LISTEN_PORT}..."

    case "${STREAM_TOOL}" in
    socat)
        # socat fork mode:
        #   - reuseaddr: reuse the port immediately
        #   - fork: fork a child process per connection (critical!)
        #   - keepalive: detect dead connections at the TCP layer
        #   - keepidle/keepintvl/keepcnt: detect dead peers within 25 seconds (10+5*3)
        #   - nodelay: low latency
        #   - EXEC: run dumpcap independently for each connection
        socat \
            "TCP-LISTEN:${LISTEN_PORT},reuseaddr,fork,keepalive,keepidle=${KEEPIDLE},keepintvl=${KEEPINTVL},keepcnt=${KEEPCNT},nodelay" \
            "EXEC:${STREAM_WRAPPER}" \
            &
        PIDS+=($!)
        ;;

    ncat)
        # ncat keep-open mode:
        #   - --keep-open: keep listening and accept multiple connections (critical!)
        #   - --exec: run an independent dumpcap per connection
        #   - --nodns: skip DNS resolution
        #   - TCP keepalive relies on system-level sysctl settings (already configured)
        ncat --listen \
            --keep-open \
            --nodns \
            -p "${LISTEN_PORT}" \
            --exec "${STREAM_WRAPPER}" \
            &
        PIDS+=($!)
        ;;
    esac

    info "网络服务 PID: ${PIDS[-1]} (fork 模式, 客户端可随时重连)"
}

###############################################
# Start all components
###############################################
start_local_capture
start_network_service

info "============================================"
info "  邮件抓包服务已启动 (v2 - 无 FIFO 架构)"
info "  本地落盘: ${CAPTURE_DIR}/"
info "  实时流:   tcp://0.0.0.0:${LISTEN_PORT}"
info "  模式:     fork (每连接独立 dumpcap)"
info "  Keepalive: idle=${KEEPIDLE}s intvl=${KEEPINTVL}s cnt=${KEEPCNT}"
info "  客户端重启无需重启本服务"
info "============================================"

# ==== Monitoring loop ====
while true; do
    sleep 30

    # Check the local capture-to-disk process
    if ! kill -0 "${PIDS[0]}" 2>/dev/null; then
        error "本地落盘 dumpcap 异常退出！"
    fi

    # Check the listener process
    if [[ ${#PIDS[@]} -ge 2 ]] && ! kill -0 "${PIDS[1]}" 2>/dev/null; then
        warn "网络监听进程退出，重启..."
        start_network_service
    fi

    # Statistics
    FILE_COUNT=$(find "${CAPTURE_DIR}" -name "mail*.pcapng" 2>/dev/null | wc -l)
    DISK_USED=$(du -sh "${CAPTURE_DIR}" 2>/dev/null | awk '{print $1}')
    RX_DROP=$(cat /sys/class/net/${IFACE}/statistics/rx_dropped 2>/dev/null || echo "N/A")
    RX_ERRORS=$(cat /sys/class/net/${IFACE}/statistics/rx_errors 2>/dev/null || echo "N/A")

    # Current number of active streaming dumpcap connections
    STREAM_COUNT=$(pgrep -c -f "email-stream-worker" 2>/dev/null || echo "0")

    info "文件: ${FILE_COUNT}/${MAX_FILES} | 空间: ${DISK_USED} | 连接: ${STREAM_COUNT} | rx_dropped: ${RX_DROP} | rx_errors: ${RX_ERRORS}"
done
