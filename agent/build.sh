#!/bin/sh
# Builds the agent for Linux amd64 and arm64 into agent/dist, with SHA256SUMS.
# The ShieldOps API serves these files to the install script. Needs Go 1.22 or later.
set -eu
cd "$(dirname "$0")"
VERSION="${VERSION:-1.1.0}"
mkdir -p dist
for ARCH in amd64 arm64; do
  CGO_ENABLED=0 GOOS=linux GOARCH=$ARCH go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o "dist/shieldops-agent-linux-$ARCH" .
done
( cd dist && sha256sum shieldops-agent-linux-* > SHA256SUMS )
echo "built version $VERSION:"
cat dist/SHA256SUMS