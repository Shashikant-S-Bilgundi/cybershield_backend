#!/bin/sh
# Installs the three scanners ShieldOps runs, at pinned versions, checking each download
# against the SHA-256 published with the release. Run on the ShieldOps server:
#   sudo sh scripts/install-scanners.sh
# Versions were chosen at least two weeks after release. To upgrade, change the versions and
# hashes below together (copy the hashes from each release's checksums file on GitHub).
set -eu

GITLEAKS=8.30.1
OSV=2.7.0
TRIVY=0.76.1
DEST="${DEST:-/usr/local/bin}"

case "$(uname -m)" in
  x86_64|amd64)
    GL_FILE=gitleaks_${GITLEAKS}_linux_x64.tar.gz;   GL_SHA=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
    OSV_FILE=osv-scanner_linux_amd64;                 OSV_SHA=160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b
    TV_FILE=trivy_${TRIVY}_Linux-64bit.tar.gz;        TV_SHA=c7cbe3137fb8a48a17574bede3dd6beb16742d1e9772929940fc90082c39d9c0 ;;
  aarch64|arm64)
    GL_FILE=gitleaks_${GITLEAKS}_linux_arm64.tar.gz;  GL_SHA=e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080
    OSV_FILE=osv-scanner_linux_arm64;                 OSV_SHA=4061ef4c021ed3c47f203b818f337e351336cc5cd67c0274fc36bd1dfc728dd7
    TV_FILE=trivy_${TRIVY}_Linux-ARM64.tar.gz;        TV_SHA=e174dff2a6dba5e3ae41f8d0537a6324405bd08132497340304c6b20e0f16a1f ;;
  *) echo "Unsupported CPU: $(uname -m)" >&2; exit 1 ;;
esac

command -v git >/dev/null 2>&1 || { echo "git is required (apt install git)." >&2; exit 1; }
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
fetch() { # url file sha
  curl -fsSL "$1" -o "$TMP/$2"
  echo "$3  $TMP/$2" | sha256sum -c - >/dev/null || { echo "Checksum mismatch for $2; nothing installed." >&2; exit 1; }
}

fetch "https://github.com/gitleaks/gitleaks/releases/download/v$GITLEAKS/$GL_FILE" "$GL_FILE" "$GL_SHA"
fetch "https://github.com/google/osv-scanner/releases/download/v$OSV/$OSV_FILE" "$OSV_FILE" "$OSV_SHA"
fetch "https://github.com/aquasecurity/trivy/releases/download/v$TRIVY/$TV_FILE" "$TV_FILE" "$TV_SHA"

tar -xzf "$TMP/$GL_FILE" -C "$TMP" gitleaks
tar -xzf "$TMP/$TV_FILE" -C "$TMP" trivy
install -m 0755 "$TMP/gitleaks" "$DEST/gitleaks"
install -m 0755 "$TMP/$OSV_FILE" "$DEST/osv-scanner"
install -m 0755 "$TMP/trivy" "$DEST/trivy"

echo "Installed: gitleaks $("$DEST/gitleaks" version), osv-scanner $OSV, trivy $TRIVY in $DEST"