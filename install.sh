#!/usr/bin/env bash
set -euo pipefail

REPO="${SANDBOX_CHECK_REPO:-humanethq/sandbox-check}"
VERSION="${SANDBOX_CHECK_VERSION:-latest}"
INSTALL_DIR="${SANDBOX_CHECK_INSTALL_DIR:-/usr/local/bin}"

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) arch="amd64" ;;
  arm64|aarch64) arch="arm64" ;;
  *)
    echo "Humanet sandbox-check install: unsupported architecture '$arch'" >&2
    exit 1
    ;;
esac

case "$os" in
  linux|darwin) ;;
  *)
    echo "Humanet sandbox-check install: unsupported OS '$os'" >&2
    exit 1
    ;;
esac

bin_name="sandbox-check-${os}-${arch}"
if [[ "$VERSION" == "latest" ]]; then
  base_url="https://github.com/${REPO}/releases/latest/download"
else
  base_url="https://github.com/${REPO}/releases/download/${VERSION}"
fi

tmp="$(mktemp -d)"
trap 'rm -r -- "$tmp"' EXIT

echo "Downloading Humanet sandbox-check (${bin_name}) from ${base_url}..."
curl -fsSL -o "${tmp}/${bin_name}" "${base_url}/${bin_name}"
curl -fsSL -o "${tmp}/checksums.txt" "${base_url}/checksums.txt"

want_sha="$(awk -v f="$bin_name" '$2 == f || $2 == ("dist/" f) {print $1; exit}' "${tmp}/checksums.txt")"
if [[ -z "$want_sha" ]]; then
  echo "Humanet sandbox-check install: checksum entry not found for ${bin_name}" >&2
  exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
  got_sha="$(sha256sum "${tmp}/${bin_name}" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  got_sha="$(shasum -a 256 "${tmp}/${bin_name}" | awk '{print $1}')"
else
  echo "Humanet sandbox-check install: sha256sum or shasum is required to verify binary" >&2
  exit 1
fi

if [[ "$got_sha" != "$want_sha" ]]; then
  echo "Humanet sandbox-check install: sha256 mismatch (got=${got_sha}, want=${want_sha})" >&2
  exit 1
fi

chmod 0755 "${tmp}/${bin_name}"
if [[ -w "$INSTALL_DIR" ]]; then
  install -m 0755 "${tmp}/${bin_name}" "${INSTALL_DIR}/sandbox-check"
elif command -v sudo >/dev/null 2>&1; then
  sudo install -m 0755 "${tmp}/${bin_name}" "${INSTALL_DIR}/sandbox-check"
else
  mkdir -p "${HOME}/.local/bin"
  install -m 0755 "${tmp}/${bin_name}" "${HOME}/.local/bin/sandbox-check"
  INSTALL_DIR="${HOME}/.local/bin"
fi

echo "Installed Humanet sandbox-check to ${INSTALL_DIR}/sandbox-check (sha256 verified: ${got_sha})"
"${INSTALL_DIR}/sandbox-check" --version
