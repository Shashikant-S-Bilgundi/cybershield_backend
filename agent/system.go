package main

import (
	"bufio"
	"math"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type cpuTimes struct{ idle, total uint64 }
type netTotals struct {
	rx, tx uint64
	at     time.Time
}

type collector struct {
	cfg      config
	prevCPU  cpuTimes
	prevNet  netTotals
	restarts *restartTracker
	svcCPU   map[string]svcCPU
	ctrCPU   map[string]ctrCPU
}

func newCollector(cfg config) *collector {
	return &collector{cfg: cfg, restarts: newRestartTracker(), svcCPU: map[string]svcCPU{}, ctrCPU: map[string]ctrCPU{}}
}

// host turns an absolute host path into one under SHIELDOPS_HOST_ROOT (for the Docker image, /host).
func (c *collector) host(p string) string { return filepath.Join(c.cfg.hostRoot, p) }

func round1(v float64) float64 { return math.Round(v*10) / 10 }

func (c *collector) collect() *Report {
	r := &Report{AgentVersion: version, IntervalSec: int(c.cfg.interval / time.Second), Services: []Service{}, Containers: []Container{}, Disks: []Disk{}, IPs: []string{}}
	r.MachineID = c.machineID()
	r.Hostname = c.hostname()
	r.OS = c.osName()
	r.Kernel = kernel()
	r.CPUCores = runtime.NumCPU()
	r.UptimeSec = c.uptime()
	r.IPs = ips()

	memTotal, memAvail := c.meminfo()
	r.MemoryGB = round1(float64(memTotal) / (1 << 20))
	if memTotal > 0 {
		r.Usage.Memory = round1(100 * float64(memTotal-memAvail) / float64(memTotal))
	}
	r.Usage.CPU = c.cpuPercent()
	r.Usage.Load1 = c.load1()
	r.Usage.NetInKbps, r.Usage.NetOutKbps = c.netRates()
	r.Disks = c.disks()
	for _, d := range r.Disks {
		if d.Mount == "/" && d.TotalGB > 0 {
			r.Usage.Disk = round1(100 * d.UsedGB / d.TotalGB)
		}
	}
	r.Services = c.services()
	if c.cfg.docker {
		r.Containers = append([]Container{}, c.containers()...)
	}
	return r
}

func readFile(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return string(b)
}

func (c *collector) machineID() string {
	for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		if id := strings.TrimSpace(readFile(c.host(p))); id != "" {
			return id
		}
	}
	h, _ := os.Hostname()
	return "host-" + h
}

func (c *collector) hostname() string {
	if h := strings.TrimSpace(readFile(c.host("/etc/hostname"))); h != "" {
		return h
	}
	h, _ := os.Hostname()
	return h
}

func (c *collector) osName() string {
	for _, line := range strings.Split(readFile(c.host("/etc/os-release")), "\n") {
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			return strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"`)
		}
	}
	return runtime.GOOS
}

func kernel() string {
	var u syscall.Utsname
	if err := syscall.Uname(&u); err != nil {
		return ""
	}
	b := make([]byte, 0, len(u.Release))
	for _, ch := range u.Release {
		if ch == 0 {
			break
		}
		b = append(b, byte(ch))
	}
	return string(b)
}

func (c *collector) uptime() int64 {
	f := strings.Fields(readFile(c.host("/proc/uptime")))
	if len(f) == 0 {
		return 0
	}
	v, _ := strconv.ParseFloat(f[0], 64)
	return int64(v)
}

func ips() []string {
	out := []string{}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return out
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP.IsLoopback() || ipnet.IP.IsLinkLocalUnicast() {
			continue
		}
		out = append(out, ipnet.IP.String())
		if len(out) >= 8 {
			break
		}
	}
	return out
}

func (c *collector) meminfo() (total, avail uint64) {
	for _, line := range strings.Split(readFile(c.host("/proc/meminfo")), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		v, _ := strconv.ParseUint(f[1], 10, 64)
		switch f[0] {
		case "MemTotal:":
			total = v
		case "MemAvailable:":
			avail = v
		}
	}
	return
}

func (c *collector) cpuPercent() float64 {
	line := strings.SplitN(readFile(c.host("/proc/stat")), "\n", 2)[0]
	f := strings.Fields(line)
	if len(f) < 5 || f[0] != "cpu" {
		return 0
	}
	var cur cpuTimes
	for i, s := range f[1:] {
		v, _ := strconv.ParseUint(s, 10, 64)
		cur.total += v
		if i == 3 || i == 4 { // idle + iowait
			cur.idle += v
		}
	}
	prev := c.prevCPU
	c.prevCPU = cur
	if prev.total == 0 || cur.total <= prev.total {
		return 0
	}
	return round1(100 * (1 - float64(cur.idle-prev.idle)/float64(cur.total-prev.total)))
}

func (c *collector) load1() float64 {
	f := strings.Fields(readFile(c.host("/proc/loadavg")))
	if len(f) == 0 {
		return 0
	}
	v, _ := strconv.ParseFloat(f[0], 64)
	return v
}

// netRates counts physical interfaces only: not loopback, Docker bridges or container veths.
func (c *collector) netRates() (inKbps, outKbps float64) {
	var cur netTotals
	cur.at = time.Now()
	sc := bufio.NewScanner(strings.NewReader(readFile(c.host("/proc/net/dev"))))
	for sc.Scan() {
		line := sc.Text()
		i := strings.Index(line, ":")
		if i < 0 {
			continue
		}
		name := strings.TrimSpace(line[:i])
		if name == "lo" || strings.HasPrefix(name, "veth") || strings.HasPrefix(name, "docker") || strings.HasPrefix(name, "br-") || strings.HasPrefix(name, "cni") || strings.HasPrefix(name, "flannel") {
			continue
		}
		f := strings.Fields(line[i+1:])
		if len(f) < 9 {
			continue
		}
		rx, _ := strconv.ParseUint(f[0], 10, 64)
		tx, _ := strconv.ParseUint(f[8], 10, 64)
		cur.rx += rx
		cur.tx += tx
	}
	prev := c.prevNet
	c.prevNet = cur
	secs := cur.at.Sub(prev.at).Seconds()
	if prev.at.IsZero() || secs <= 0 || cur.rx < prev.rx || cur.tx < prev.tx {
		return 0, 0
	}
	return round1(float64(cur.rx-prev.rx) * 8 / 1000 / secs), round1(float64(cur.tx-prev.tx) * 8 / 1000 / secs)
}

var realFS = map[string]bool{"ext2": true, "ext3": true, "ext4": true, "xfs": true, "btrfs": true, "zfs": true, "f2fs": true, "jfs": true, "reiserfs": true, "vfat": true, "ntfs": true, "ntfs3": true}

// disks lists real filesystems (not tmpfs, overlay or snap images), largest first, at most 10.
func (c *collector) disks() []Disk {
	out := []Disk{}
	seen := map[string]bool{}
	mounts := readFile(c.host("/proc/1/mounts"))
	if mounts == "" {
		mounts = readFile(c.host("/proc/mounts"))
	}
	for _, line := range strings.Split(mounts, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || !realFS[f[2]] || seen[f[0]] || strings.HasPrefix(f[1], "/snap/") || strings.HasPrefix(f[1], "/boot/efi") {
			continue
		}
		seen[f[0]] = true
		mount := strings.ReplaceAll(f[1], `\040`, " ")
		var st syscall.Statfs_t
		if err := syscall.Statfs(c.host(mount), &st); err != nil || st.Blocks == 0 {
			continue
		}
		total := float64(st.Blocks) * float64(st.Bsize) / (1 << 30)
		free := float64(st.Bavail) * float64(st.Bsize) / (1 << 30)
		out = append(out, Disk{Mount: mount, UsedGB: round1(total - free), TotalGB: round1(total)})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Mount == "/" || (out[j].Mount != "/" && out[i].TotalGB > out[j].TotalGB)
	})
	if len(out) > 10 {
		out = out[:10]
	}
	return out
}