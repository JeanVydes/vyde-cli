#!/bin/sh
set -eu

repo="${VYDE_CLI_REPOSITORY:-JeanVydes/vyde-cli}"
version="${VYDE_CLI_VERSION:-latest}"
install_dir="${VYDE_CLI_INSTALL_DIR:-$HOME/.local/bin}"
base="https://github.com/$repo/releases"

fail() {
  printf 'vyde installer: %s\n' "$*" >&2
  exit 1
}

command -v curl >/dev/null 2>&1 || fail "curl is required"
command -v tar >/dev/null 2>&1 || fail "tar is required"

os="$(uname -s)"
arch="$(uname -m)"
case "$os:$arch" in
  Linux:x86_64|Linux:amd64) asset="vyde-linux-x86_64.tar.gz" ;;
  Darwin:arm64|Darwin:aarch64) asset="vyde-macos-aarch64.tar.gz" ;;
  *) fail "unsupported platform: $os/$arch (supported: Linux x86_64 and macOS Apple Silicon)" ;;
esac

if [ "$version" = latest ]; then
  download_base="$base/latest/download"
else
  case "$version" in
    v*) ;;
    *) version="v$version" ;;
  esac
  download_base="$base/download/$version"
fi

tmp="$(mktemp -d 2>/dev/null || mktemp -d -t vyde)"
trap 'rm -rf "$tmp"' EXIT INT TERM

printf 'Downloading Vyde CLI (%s, %s)...\n' "$asset" "$version"
curl --fail --silent --show-error --location \
  "$download_base/$asset" \
  --output "$tmp/$asset" ||
  fail "release asset not found; check VYDE_CLI_VERSION and the GitHub release"

curl --fail --silent --show-error --location \
  "$download_base/SHA256SUMS" \
  --output "$tmp/SHA256SUMS" ||
  fail "the release does not publish SHA256SUMS; refusing an unverified install"

(
  cd "$tmp"
  expected="$(awk -v file="$asset" '$2 == file || $2 == "*" file { print $1; exit }' SHA256SUMS)"
  [ -n "$expected" ] || exit 1
  if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "$asset" | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then
    actual="$(shasum -a 256 "$asset" | awk '{print $1}')"
  else
    printf '%s\n' "sha256sum or shasum is required to verify the download" >&2
    exit 1
  fi
  [ "$expected" = "$actual" ] || {
    printf '%s\n' "checksum mismatch" >&2
    exit 1
  }
) || fail "checksum verification failed; refusing to install"

mkdir -p "$install_dir"
tar -xzf "$tmp/$asset" -C "$tmp"
[ -f "$tmp/vyde" ] || fail "release archive does not contain a vyde binary"
install -m 0755 "$tmp/vyde" "$install_dir/vyde" 2>/dev/null ||
  cp "$tmp/vyde" "$install_dir/vyde" && chmod 0755 "$install_dir/vyde"

printf 'Installed vyde to %s/vyde\n' "$install_dir"
case ":${PATH:-}:" in
  *:"$install_dir":*) ;;
  *) printf 'Add it to your PATH: export PATH="%s:$PATH"\n' "$install_dir" ;;
esac
printf 'Next: set VYDE_OAUTH_CLIENT_ID and run `vyde login`.\n'
