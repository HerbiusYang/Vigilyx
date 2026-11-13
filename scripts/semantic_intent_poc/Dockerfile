# Offline toolbox for the semantic intent-model PoC (upgrade plan, phase P1).
# Not a runtime image. Built on 77 from the already-present Rust base image
# because Docker Hub pulls are unavailable there; run with --network none.
FROM rust:1.98.0-bookworm

COPY requirements.txt /tmp/requirements.txt
RUN curl -fsSL https://bootstrap.pypa.io/get-pip.py -o /tmp/get-pip.py \
    && python3 /tmp/get-pip.py --break-system-packages --no-cache-dir \
    && python3 -m pip install --break-system-packages --no-cache-dir -r /tmp/requirements.txt \
    && python3 -m pip freeze > /opt/poc-pip-freeze.txt \
    && rm /tmp/get-pip.py

RUN groupadd -r -g 10001 vigilyx && useradd -r -u 10001 -g vigilyx -d /work vigilyx
USER vigilyx
WORKDIR /work
