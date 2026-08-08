#!/bin/sh
# rtun installer for macOS and Linux. No toolchain, no source tree.
#
#   curl -fsSL https://raw.githubusercontent.com/lesslucifer/RustTunnel/main/packaging/install.sh | sh
#
# RTUN_BASE     where the archives live      (default: the latest GitHub release)
# RTUN_BIN_DIR  where rtun lands             (default: ~/.local/bin)
set -eu

BASE=${RTUN_BASE:-https://github.com/${RTUN_REPO:-lesslucifer/RustTunnel}/releases/latest/download}
BIN=${RTUN_BIN_DIR:-$HOME/.local/bin}

case "$(uname -s)-$(uname -m)" in
  Darwin-arm64)   T=aarch64-apple-darwin ;;
  Darwin-x86_64)  T=x86_64-apple-darwin ;;
  Linux-x86_64)   T=x86_64-unknown-linux-musl ;;
  *) echo "no prebuilt rtun for $(uname -s)-$(uname -m) — build it with cargo" >&2; exit 1 ;;
esac

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
cd "$TMP"

echo "downloading rtun-$T.tar.gz from $BASE"
curl -fsSL "$BASE/rtun-$T.tar.gz"        -o "rtun-$T.tar.gz"
curl -fsSL "$BASE/rtun-$T.tar.gz.sha256" -o "rtun-$T.tar.gz.sha256"

# The checksum is the whole reason this is a script and not two commands: a
# truncated download would otherwise install a binary that half-runs.
if command -v shasum >/dev/null 2>&1
then shasum -a 256 -c "rtun-$T.tar.gz.sha256"
else sha256sum -c "rtun-$T.tar.gz.sha256"
fi

mkdir -p "$BIN"
tar -xzf "rtun-$T.tar.gz" -C "$BIN" rtun
chmod +x "$BIN/rtun"
echo "installed $BIN/rtun"

case ":$PATH:" in
  *":$BIN:"*) "$BIN/rtun" --version ;;
  *) echo "note: $BIN is not on your PATH — add it, or run $BIN/rtun directly" ;;
esac
