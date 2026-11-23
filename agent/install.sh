#!/bin/sh
# ShieldOps agent installer. Served by your ShieldOps server, which fills in __SHIELDOPS_BASE__.
#
#   curl -fsSL __SHIELDOPS_BASE__/ingest/agent/install.sh | sudo SHIELDOPS_AGENT_TOKEN=so_agent_... sh
#
# The same binary also runs as a remote uptime probe (a second check location):
#   curl -fsSL __SHIELDOPS_BASE__/ingest/agent/install.sh | sudo SHIELDOPS_PROBE_TOKEN=so_probe_... sh
#
# Options (environment variables):
#   SHIELDOPS_DOCKER=0       do not give the agent access to Docker (container metrics off)
#   SHIELDOPS_SERVICES=a,b   report only these systemd services instead of the automatic list
#   SHIELDOPS_PM2_HOME=/home/deploy/.pm2   read PM2 processes of that user
#
# Uninstall (use shieldops-probe instead of shieldops-agent for a probe):
#   sudo systemctl disable --now shieldops-agent && sudo rm -rf /usr/local/bin/shieldops-agent /etc/shieldops /etc/systemd/system/shieldops-agent.service && sudo userdel shieldops-agent
set -eu

BASE="__SHIELDOPS_BASE__"
TOKEN="${SHIELDOPS_AGENT_TOKEN:-}"
PROBE_TOKEN="${SHIELDOPS_PROBE_TOKEN:-}"
MODE=agent
[ -n "$PROBE_TOKEN" ] && [ -z "$TOKEN" ] && MODE=probe

say() { printf 'shieldops: %s\n' "$1"; }
fail() { printf 'shieldops: %s\n' "$1" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || fail "run this with sudo."
if [ "$MODE" = probe ]; then
  case "$PROBE_TOKEN" in so_probe_*) ;; *) fail "set SHIELDOPS_PROBE_TOKEN to the probe token shown in ShieldOps (so_probe_...)." ;; esac
else
  case "$TOKEN" in so_agent_*) ;; *) fail "set SHIELDOPS_AGENT_TOKEN to the agent token shown in ShieldOps (so_agent_...)." ;; esac
fi
[ "$(uname -s)" = "Linux" ] || fail "the agent runs on Linux only."
command -v systemctl >/dev/null 2>&1 || fail "systemd was not found. Use the Docker command from ShieldOps instead."
command -v curl >/dev/null 2>&1 || fail "curl is required."
command -v sha256sum >/dev/null 2>&1 || fail "sha256sum is required."

case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) fail "unsupported CPU type $(uname -m); amd64 and arm64 are supported." ;;
esac

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
say "downloading the agent for linux-$ARCH"
curl -fsSL "$BASE/ingest/agent/download/shieldops-agent-linux-$ARCH" -o "$TMP/shieldops-agent-linux-$ARCH"
curl -fsSL "$BASE/ingest/agent/download/SHA256SUMS" -o "$TMP/SHA256SUMS"
( cd "$TMP" && grep " shieldops-agent-linux-$ARCH\$" SHA256SUMS | sha256sum -c - >/dev/null ) || fail "the download does not match its checksum; nothing was installed."

if ! id shieldops-agent >/dev/null 2>&1; then
  useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin shieldops-agent 2>/dev/null \
    || adduser -S -H -s /sbin/nologin shieldops-agent
fi

install -m 0755 "$TMP/shieldops-agent-linux-$ARCH" /usr/local/bin/shieldops-agent

if [ "$MODE" = probe ]; then
  mkdir -p /etc/shieldops
  umask 077
  printf 'SHIELDOPS_PROBE_TOKEN=%s\nSHIELDOPS_ENDPOINT=%s\n' "$PROBE_TOKEN" "$BASE/ingest" > /etc/shieldops/probe.env
  chmod 600 /etc/shieldops/probe.env
  umask 022
  cat > /etc/systemd/system/shieldops-probe.service <<UNIT
[Unit]
Description=ShieldOps uptime probe
Documentation=$BASE
After=network-online.target
Wants=network-online.target

[Service]
EnvironmentFile=/etc/shieldops/probe.env
ExecStart=/usr/local/bin/shieldops-agent probe
User=shieldops-agent
Restart=always
RestartSec=10
# Hardening: the probe only makes outbound connections to the targets it is given and to ShieldOps.
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
CapabilityBoundingSet=
AmbientCapabilities=
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
SystemCallArchitectures=native
MemoryMax=128M
CPUQuota=20%

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable shieldops-probe >/dev/null 2>&1
  systemctl restart shieldops-probe
  sleep 2
  if systemctl is-active --quiet shieldops-probe; then
    say "probe installed ($(/usr/local/bin/shieldops-agent --version)). It shows as online in ShieldOps within a minute."
    say "logs: journalctl -u shieldops-probe -f"
    exit 0
  fi
  journalctl -u shieldops-probe -n 20 --no-pager >&2 || true
  fail "the probe did not start; see the log above."
fi

# The token lives here, readable only by root; systemd passes it to the agent.
mkdir -p /etc/shieldops
umask 077
{
  echo "SHIELDOPS_AGENT_TOKEN=$TOKEN"
  echo "SHIELDOPS_ENDPOINT=$BASE/ingest/v1"
  [ -n "${SHIELDOPS_SERVICES:-}" ] && echo "SHIELDOPS_SERVICES=$SHIELDOPS_SERVICES"
  [ -n "${SHIELDOPS_PM2_HOME:-}" ] && echo "SHIELDOPS_PM2_HOME=$SHIELDOPS_PM2_HOME"
  [ "${SHIELDOPS_DOCKER:-1}" = "0" ] && echo "SHIELDOPS_DOCKER=0"
  true
} > /etc/shieldops/agent.env
chmod 600 /etc/shieldops/agent.env
umask 022

GROUPS_LINE=""
if [ "${SHIELDOPS_DOCKER:-1}" != "0" ] && getent group docker >/dev/null 2>&1; then
  # Reading container stats needs the Docker socket. Membership of the docker group is
  # equivalent to root access, so turn it off with SHIELDOPS_DOCKER=0 if you do not need containers.
  GROUPS_LINE="SupplementaryGroups=docker"
  say "Docker found: container metrics on (SHIELDOPS_DOCKER=0 to turn off)"
fi

cat > /etc/systemd/system/shieldops-agent.service <<UNIT
[Unit]
Description=ShieldOps agent
Documentation=$BASE
After=network-online.target
Wants=network-online.target

[Service]
EnvironmentFile=/etc/shieldops/agent.env
ExecStart=/usr/local/bin/shieldops-agent
User=shieldops-agent
$GROUPS_LINE
Restart=always
RestartSec=10
# Hardening: the agent only reads system information and makes outbound HTTPS requests.
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
CapabilityBoundingSet=
AmbientCapabilities=
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
SystemCallArchitectures=native
MemoryMax=128M
CPUQuota=20%

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable shieldops-agent >/dev/null 2>&1
systemctl restart shieldops-agent
sleep 2
if systemctl is-active --quiet shieldops-agent; then
  say "installed $(/usr/local/bin/shieldops-agent --version). The server appears in ShieldOps within a minute."
  say "logs: journalctl -u shieldops-agent -f"
else
  journalctl -u shieldops-agent -n 20 --no-pager >&2 || true
  fail "the agent did not start; see the log above."
fi