#!/usr/bin/env bash
# Analyzer CLI installer
# Usage: curl -fsSL https://raw.githubusercontent.com/exein-io/analyzer-cli/main/dist/install.sh | bash
set -euo pipefail

REPO="exein-io/analyzer-cli"
BINARY="analyzer"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

# Detect OS and architecture
detect_platform() {
    local os arch

    os="$(uname -s)"
    arch="$(uname -m)"

    case "$os" in
        Linux)  os="unknown-linux-gnu" ;;
        Darwin) os="apple-darwin" ;;
        *)      echo "Unsupported OS: $os"; exit 1 ;;
    esac

    case "$arch" in
        x86_64|amd64)   arch="x86_64" ;;
        aarch64|arm64)   arch="aarch64" ;;
        *)               echo "Unsupported architecture: $arch"; exit 1 ;;
    esac

    echo "${arch}-${os}"
}

# Get the latest release tag
get_latest_version() {
    curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" |
        grep '"tag_name"' |
        sed -E 's/.*"([^"]+)".*/\1/'
}

main() {
    local platform version url

    platform="$(detect_platform)"
    version="${VERSION:-$(get_latest_version)}"

    echo "Installing ${BINARY} ${version} for ${platform}..."

    url="https://github.com/${REPO}/releases/download/${version}/${BINARY}-${platform}.tar.gz"

    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT

    echo "Downloading from ${url}..."
    curl -fsSL "$url" | tar xz -C "$tmp"

    echo "Installing to ${INSTALL_DIR}/${BINARY}..."
    sudo install -m 755 "${tmp}/${BINARY}" "${INSTALL_DIR}/${BINARY}"

    echo ""
    echo "Done! Run 'analyzer --help' to get started."
    echo "Tip: run 'analyzer login' to configure your API key."
}

main "$@"
