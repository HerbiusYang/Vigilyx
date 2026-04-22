#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

EXPECTED_NODE="$(tr -d '[:space:]' < "${REPO_ROOT}/.nvmrc")"
EXPECTED_NPM="$(
    python3 - <<'PY' "${REPO_ROOT}/frontend/package.json"
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as fh:
    package_json = json.load(fh)

package_manager = package_json.get("packageManager", "")
if not package_manager.startswith("npm@"):
    raise SystemExit("frontend/package.json must declare packageManager as npm@<version>")

print(package_manager.split("@", 1)[1])
PY
)"

if ! command -v node >/dev/null 2>&1; then
    echo "error: node is not installed. Expected Node ${EXPECTED_NODE}." >&2
    exit 1
fi

if ! command -v npm >/dev/null 2>&1; then
    echo "error: npm is not installed. Expected npm ${EXPECTED_NPM}." >&2
    exit 1
fi

ACTUAL_NODE="$(node -p 'process.versions.node')"
ACTUAL_NPM="$(npm -v)"

if [[ "${ACTUAL_NODE}" != "${EXPECTED_NODE}" ]]; then
    echo "error: Node version mismatch. Expected ${EXPECTED_NODE}, got ${ACTUAL_NODE}." >&2
    echo "hint: run 'nvm use' in the repository root or install Node ${EXPECTED_NODE} on the build host." >&2
    exit 1
fi

if [[ "${ACTUAL_NPM}" != "${EXPECTED_NPM}" ]]; then
    echo "error: npm version mismatch. Expected ${EXPECTED_NPM}, got ${ACTUAL_NPM}." >&2
    echo "hint: run 'npm install -g npm@${EXPECTED_NPM}' to sync the frontend toolchain." >&2
    exit 1
fi

echo "frontend toolchain OK: Node ${ACTUAL_NODE}, npm ${ACTUAL_NPM}"
