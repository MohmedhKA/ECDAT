#!/usr/bin/env bash
# ==============================================================================
# ECDAT: cbomkit-theia Setup Helper
# Downloads or builds cbomkit-theia (Linux Foundation PQCA) for high-speed
# filesystem certificate and key scanning.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BIN_DIR="${REPO_ROOT}/bin"
THEIA_TARGET="${BIN_DIR}/cbomkit-theia"

mkdir -p "${BIN_DIR}"

echo "[*] Checking for cbomkit-theia..."

if [ -x "${THEIA_TARGET}" ]; then
    echo "[+] cbomkit-theia already present at: ${THEIA_TARGET}"
    exit 0
fi

if command -v cbomkit-theia &>/dev/null; then
    echo "[+] cbomkit-theia found in PATH: $(command -v cbomkit-theia)"
    ln -sf "$(command -v cbomkit-theia)" "${THEIA_TARGET}"
    echo "[+] Linked to: ${THEIA_TARGET}"
    exit 0
fi

if command -v go &>/dev/null; then
    echo "[*] Compiling cbomkit-theia from source using Go toolchain..."
    GOBIN="${BIN_DIR}" go install github.com/PQCA/cbomkit/theia@latest
    if [ -f "${BIN_DIR}/theia" ] && [ ! -f "${THEIA_TARGET}" ]; then
        mv "${BIN_DIR}/theia" "${THEIA_TARGET}"
    fi
    chmod +x "${THEIA_TARGET}"
    echo "[+] Successfully installed cbomkit-theia to ${THEIA_TARGET}"
    exit 0
fi

echo "[!] Notice: Go compiler not found on system."
echo "[!] ECDAT will automatically use its built-in native Python ASN.1 certificate scanner fallback."
echo "[*] To install Go compiler on Debian/Ubuntu: sudo apt-get install golang-go"
exit 0
