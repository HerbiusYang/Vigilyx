# ═══════════════════════════════════════════════════
# CAPEv2 sandbox - Docker image for the KVM/QEMU backend
# ═══════════════════════════════════════════════════
#
# Based on Ubuntu 22.04 plus the official CAPEv2 install script
# Uses KVM/QEMU instead of VirtualBox
#
# Build:
#   docker build --build-arg CAPEV2_REF=<tag-or-commit> \
#     -t vigilyx-sandbox -f deploy/docker/sandbox/Dockerfile deploy/docker/sandbox/
#
# Run:
#   docker run -d --privileged \
#     -v /dev/kvm:/dev/kvm \
#     -p 8000:8000 \
#     -v sandbox_storage:/opt/CAPEv2/storage \
#     --name vigilyx-sandbox vigilyx-sandbox
#
# Prerequisites:
#   - Host KVM is enabled (ls /dev/kvm)
#   - The Windows analysis VM image must be configured separately
# ═══════════════════════════════════════════════════

FROM ubuntu:22.04@sha256:eb29ed27b0821dca09c2e28b39135e185fc1302036427d5f4d70a41ce8fd7659

ARG CAPEV2_REPO=https://github.com/kevoreilly/CAPEv2.git
ARG CAPEV2_REF

ENV DEBIAN_FRONTEND=noninteractive
ENV CAPE_USER=cape
ENV CAPE_ROOT=/opt/CAPEv2

# -- System dependencies --
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Base tools (later layers depend on wget/curl/git)
    build-essential git curl wget sudo ca-certificates gnupg lsb-release \
    # KVM/QEMU
    qemu-kvm qemu-utils libvirt-daemon-system libvirt-clients bridge-utils virtinst \
    # Network capture
    tcpdump libcap2-bin \
    # Python
    python3 python3-pip python3-venv python3-dev \
    # System tools
    net-tools iproute2 iptables supervisor \
    # CAPEv2 dependencies
    libffi-dev libssl-dev libxml2-dev libxslt1-dev libjpeg-dev zlib1g-dev \
    libmagic1 ssdeep libfuzzy-dev libimage-exiftool-perl \
    && rm -rf /var/lib/apt/lists/*

# ── MongoDB 7.0 ──
RUN wget -qO - https://www.mongodb.org/static/pgp/server-7.0.asc | \
    gpg --dearmor -o /usr/share/keyrings/mongodb-server-7.0.gpg && \
    echo "deb [ signed-by=/usr/share/keyrings/mongodb-server-7.0.gpg ] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/7.0 multiverse" > \
    /etc/apt/sources.list.d/mongodb-org-7.0.list && \
    apt-get update && apt-get install -y mongodb-org && \
    mkdir -p /var/lib/mongodb /var/log && \
    rm -rf /var/lib/apt/lists/*

# -- Create the CAPE user --
RUN useradd -m -s /bin/bash -G kvm,libvirt ${CAPE_USER} && \
    echo "${CAPE_USER} ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# -- Install CAPEv2 --
RUN test -n "${CAPEV2_REF}" || (echo "CAPEV2_REF must pin an immutable CAPEv2 tag or commit" >&2; exit 1) && \
    git clone "${CAPEV2_REPO}" ${CAPE_ROOT} && \
    cd ${CAPE_ROOT} && \
    git -c advice.detachedHead=false checkout --detach "${CAPEV2_REF}" && \
    chown -R ${CAPE_USER}:${CAPE_USER} ${CAPE_ROOT}

WORKDIR ${CAPE_ROOT}

# Python virtual environment + dependencies
RUN python3 -m venv ${CAPE_ROOT}/venv && \
    ${CAPE_ROOT}/venv/bin/pip install --upgrade pip setuptools wheel && \
    ${CAPE_ROOT}/venv/bin/pip install -r ${CAPE_ROOT}/requirements.txt && \
    ${CAPE_ROOT}/venv/bin/pip check

# -- Configure CAPEv2 to use KVM --
RUN mkdir -p ${CAPE_ROOT}/storage ${CAPE_ROOT}/log && \
    chown -R ${CAPE_USER}:${CAPE_USER} ${CAPE_ROOT}

# Default configuration: KVM backend
COPY conf/cuckoo.conf ${CAPE_ROOT}/conf/cuckoo.conf
COPY conf/kvm.conf ${CAPE_ROOT}/conf/kvm.conf
COPY conf/api.conf ${CAPE_ROOT}/conf/api.conf
COPY conf/reporting.conf ${CAPE_ROOT}/conf/reporting.conf

# tcpdump permissions
RUN setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump 2>/dev/null || true

# -- Supervisor startup management --
COPY supervisord.conf /etc/supervisor/conf.d/cape.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8000

VOLUME ["${CAPE_ROOT}/storage"]

HEALTHCHECK --interval=60s --timeout=15s --start-period=300s --retries=3 \
    CMD curl -sf http://localhost:8000/apiv2/cuckoo/status/ || exit 1

ENTRYPOINT ["/entrypoint.sh"]
