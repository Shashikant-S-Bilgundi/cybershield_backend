package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type svcCPU struct {
	nsec uint64
	at   time.Time
}

// restartTracker turns ever-growing restart counters into "restarts in the last 10 minutes".
type restartTracker struct{ seen map[string][]restartPoint }
type restartPoint struct {
	at    time.Time
	count int
}

func newRestartTracker() *restartTracker { return &restartTracker{seen: map[string][]restartPoint{}} }

func (t *restartTracker) last10m(key string, total int) int {
	now := time.Now()
	pts := append(t.seen[key], restartPoint{now, total})
	cut := 0
	for cut < len(pts)-1 && now.Sub(pts[cut].at) > 10*time.Minute {
		cut++
	}
	pts = pts[cut:]
	t.seen[key] = pts
	if d := total - pts[0].count; d > 0 {
		return d
	}
	return 0
}

// OS housekeeping services nobody wants on a dashboard. Set SHIELDOPS_SERVICES to choose your own list instead.
var skip = []string{"systemd-", "dbus", "getty@", "serial-getty@", "user@", "polkit", "snapd", "rsyslog", "cron", "atd", "unattended-upgrades",
	"networkd-dispatcher", "accounts-daemon", "multipathd", "ModemManager", "udisks2", "irqbalance", "chrony", "qemu-guest-agent", "cloud-",
	"packagekit", "fwupd", "thermald", "upower", "wpa_supplicant", "NetworkManager", "avahi", "cups", "rtkit", "colord", "lvm2", "iscsid", "open-vm-tools",
	"vgauth", "hv-", "walinuxagent", "google-", "amazon-ssm", "acpid", "kerneloops", "whoopsie", "apport", "power-profiles", "switcheroo", "bluetooth",
	"gdm", "lightdm", "blk-availability", "plymouth", "setvtrgb", "console-setup", "keyboard-setup", "finalrd", "secureboot", "ua-", "ubuntu-advantage", "esm-", "shieldops-agent"}

func interesting(name string) bool {
	for _, p := range skip {
		if strings.HasPrefix(name, p) {
			return false
		}
	}
	return true
}

func run(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	return string(out), err
}

func (c *collector) services() []Service {
	out := append([]Service{}, c.systemdServices()...)
	out = append(out, c.pm2Services()...)
	if len(out) > 60 {
		out = out[:60]
	}
	return out
}

func (c *collector) systemdServices() []Service {
	names := c.cfg.services
	if len(names) == 0 {
		list, err := run(5*time.Second, "systemctl", "list-units", "--type=service", "--state=running,failed", "--no-legend", "--plain", "--no-pager")
		if err != nil {
			return nil
		}
		for _, line := range strings.Split(list, "\n") {
			f := strings.Fields(line)
			if len(f) == 0 {
				continue
			}
			n := strings.TrimSuffix(f[0], ".service")
			if interesting(n) {
				names = append(names, n)
			}
		}
	}
	if len(names) == 0 {
		return nil
	}
	args := []string{"show", "--no-pager", "-p", "Id,ActiveState,SubState,MemoryCurrent,CPUUsageNSec,NRestarts"}
	for _, n := range names {
		if !strings.HasSuffix(n, ".service") {
			n += ".service"
		}
		args = append(args, n)
	}
	raw, err := run(5*time.Second, "systemctl", args...)
	if err != nil && raw == "" {
		return nil
	}
	out := []Service{}
	now := time.Now()
	for _, block := range strings.Split(strings.TrimSpace(raw), "\n\n") {
		p := map[string]string{}
		for _, line := range strings.Split(block, "\n") {
			if k, v, ok := strings.Cut(line, "="); ok {
				p[k] = v
			}
		}
		id := strings.TrimSuffix(p["Id"], ".service")
		if id == "" {
			continue
		}
		status := "stopped"
		switch {
		case p["ActiveState"] == "active":
			status = "running"
		case p["ActiveState"] == "failed":
			status = "failed"
		case p["ActiveState"] == "activating" && p["SubState"] == "auto-restart":
			status = "failed"
		}
		mem, _ := strconv.ParseFloat(p["MemoryCurrent"], 64)
		if mem > 1e15 { // systemd prints a huge number when memory accounting is off
			mem = 0
		}
		cpu := 0.0
		if ns, err := strconv.ParseUint(p["CPUUsageNSec"], 10, 64); err == nil && ns < 1<<62 {
			if prev, ok := c.svcCPU[id]; ok && ns >= prev.nsec {
				if secs := now.Sub(prev.at).Seconds(); secs > 0 {
					cpu = round1(float64(ns-prev.nsec) / 1e9 / secs * 100)
				}
			}
			c.svcCPU[id] = svcCPU{ns, now}
		}
		restarts, _ := strconv.Atoi(p["NRestarts"])
		out = append(out, Service{Name: id, Manager: "systemd", Status: status, Restarts10m: c.restarts.last10m("systemd:"+id, restarts), CPU: cpu, MemoryMB: round1(mem / (1 << 20))})
	}
	return out
}

func (c *collector) pm2Services() []Service {
	if _, err := exec.LookPath("pm2"); err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "pm2", "jlist")
	if c.cfg.pm2Home != "" {
		cmd.Env = append(os.Environ(), "PM2_HOME="+c.cfg.pm2Home)
	}
	raw, err := cmd.Output()
	if err != nil {
		return nil
	}
	var procs []struct {
		Name  string `json:"name"`
		Monit struct {
			CPU    float64 `json:"cpu"`
			Memory float64 `json:"memory"`
		} `json:"monit"`
		Env struct {
			Status   string `json:"status"`
			Restarts int    `json:"restart_time"`
		} `json:"pm2_env"`
	}
	// pm2 sometimes prints a banner before the JSON.
	s := string(raw)
	if i := strings.Index(s, "["); i > 0 {
		s = s[i:]
	}
	if json.Unmarshal([]byte(s), &procs) != nil {
		return nil
	}
	out := []Service{}
	for _, p := range procs {
		status := "stopped"
		switch p.Env.Status {
		case "online":
			status = "running"
		case "errored":
			status = "failed"
		}
		out = append(out, Service{Name: p.Name, Manager: "pm2", Status: status, Restarts10m: c.restarts.last10m("pm2:"+p.Name, p.Env.Restarts), CPU: round1(p.Monit.CPU), MemoryMB: round1(p.Monit.Memory / (1 << 20))})
	}
	return out
}