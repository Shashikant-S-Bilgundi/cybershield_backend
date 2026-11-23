# ShieldOps agent

A single Linux binary (amd64 or arm64) that reports host metrics, services and containers to ShieldOps every 30 seconds. Written in Go with only the standard library.

**What it does:** reads `/proc`, runs `systemctl show` and `pm2 jlist`, and makes GET requests to the local Docker socket.

**What it never does:**
- open ports
- accept commands
- send file contents, environment variables or logs

## Install (recommended)

Create an agent token in ShieldOps (Ingestion → Agent tokens), then on the server run the command it shows:

```bash
curl -fsSL https://shieldops.example.com/ingest/agent/install.sh | sudo SHIELDOPS_AGENT_TOKEN=so_agent_... sh
```

The script:

- downloads the binary for the server's CPU and **checks its SHA-256** before installing
- creates an unprivileged `shieldops-agent` user
- stores the token in `/etc/shieldops/agent.env`, readable by root only
- starts a hardened systemd service: read-only system, no capabilities, 128 MB memory cap, 20% CPU cap

| Option | Effect |
| --- | --- |
| `SHIELDOPS_DOCKER=0` | No Docker access. Being in the `docker` group is equivalent to root, so use this if you do not need container metrics. |
| `SHIELDOPS_SERVICES=nginx,api` | Report only these systemd services instead of the automatic list (running and failed services, minus OS housekeeping). |
| `SHIELDOPS_PM2_HOME=/home/deploy/.pm2` | Read the PM2 processes of that user. |

Logs: `journalctl -u shieldops-agent -f`. Check what it would send without sending: `sudo -u shieldops-agent shieldops-agent --once`.

Uninstall: `sudo systemctl disable --now shieldops-agent && sudo rm -rf /usr/local/bin/shieldops-agent /etc/shieldops /etc/systemd/system/shieldops-agent.service && sudo userdel shieldops-agent`

## Docker

Build the image with `docker build -t shieldops-agent:1 agent/`, push it to your registry, and use the Docker command from the Agent tokens page with your image name.

## Building

The API serves `agent/dist/*` to the install script. Rebuild after changing the agent:

```bash
./agent/build.sh          # Linux/macOS, needs Go 1.22+
.\agent\build.ps1         # Windows PowerShell
```

## Probe mode: a second location for uptime checks

The same binary can check your public monitors from another place, for example a small VPS in a different region. ShieldOps then marks a monitor down only if the probe cannot reach it either, so a network problem near the ShieldOps server does not raise a false outage.

1. Add a location on the **Ingestion** page under **Probe locations**. Copy the command shown once.
2. Run it on the other server:

   ```bash
   curl -fsSL https://shieldops.example.com/ingest/agent/install.sh | sudo SHIELDOPS_PROBE_TOKEN=so_probe_... sh
   ```

   It installs the `shieldops-probe` service (the agent with the `probe` argument), with the same checksum check and hardening as the agent.
3. Within a minute the location shows as online, and each monitor shows results from both places.

**What the probe sees.** It only receives monitors on assets marked as reachable from the internet; internal assets are never sent to it. It checks each one at the monitor's interval and makes no other connections.

To run it by hand instead:

```bash
SHIELDOPS_PROBE_TOKEN=so_probe_... SHIELDOPS_ENDPOINT=https://shieldops.example.com/ingest shieldops-agent probe
```