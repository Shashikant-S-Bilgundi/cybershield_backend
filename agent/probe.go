package main

// Probe mode: run the agent on a server in another place, and ShieldOps checks your public
// monitors from there too. A monitor is only marked down when both places fail, so a network
// problem near the ShieldOps server does not raise a false outage.
//
//   SHIELDOPS_PROBE_TOKEN=so_probe_… SHIELDOPS_ENDPOINT=https://shieldops.example.com/ingest shieldops-agent probe

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type probeCheck struct {
	ID             string `json:"id"`
	Type           string `json:"type"`
	Target         string `json:"target"`
	IntervalSec    int    `json:"intervalSec"`
	TimeoutMs      int    `json:"timeoutMs"`
	ExpectedStatus string `json:"expectedStatus"`
	Keyword        string `json:"keyword"`
	RecordType     string `json:"recordType"`
}

type probeResult struct {
	MonitorID string `json:"monitorId"`
	At        string `json:"at"`
	Status    string `json:"status"`
	LatencyMs *int   `json:"latencyMs"`
	Error     string `json:"error,omitempty"`
}

const slowMs = 2000

func statusMatches(code int, spec string) bool {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		spec = "200-399"
	}
	for _, part := range strings.Split(spec, ",") {
		bounds := strings.SplitN(strings.TrimSpace(part), "-", 2)
		a, err := strconv.Atoi(bounds[0])
		if err != nil {
			continue
		}
		if len(bounds) == 2 {
			if b, err := strconv.Atoi(bounds[1]); err == nil && code >= a && code <= b {
				return true
			}
		} else if code == a {
			return true
		}
	}
	return false
}

func ms(since time.Time) *int { v := int(time.Since(since).Milliseconds()); return &v }

func classifyErr(err error) string {
	var dnsErr *net.DNSError
	var opErr *net.OpError
	switch {
	case errors.As(err, &dnsErr):
		return "DNS lookup failed"
	case errors.Is(err, context.DeadlineExceeded) || os.IsTimeout(err):
		return "Timed out"
	case errors.As(err, &opErr) && strings.Contains(err.Error(), "refused"):
		return "Connection refused"
	case strings.Contains(err.Error(), "certificate") || strings.Contains(err.Error(), "x509"):
		return "TLS certificate problem"
	}
	msg := err.Error()
	if len(msg) > 150 {
		msg = msg[:150]
	}
	return msg
}

func runCheck(c probeCheck) probeResult {
	timeout := time.Duration(c.TimeoutMs) * time.Millisecond
	if timeout <= 0 || timeout > 60*time.Second {
		timeout = 10 * time.Second
	}
	res := probeResult{MonitorID: c.ID, At: time.Now().UTC().Format(time.RFC3339)}
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	up := func() {
		res.LatencyMs = ms(start)
		res.Status = "up"
		if *res.LatencyMs > slowMs {
			res.Status = "degraded"
		}
	}
	fail := func(reason string) { res.Status, res.Error, res.LatencyMs = "down", reason, ms(start) }

	switch c.Type {
	case "http":
		client := &http.Client{Timeout: timeout, CheckRedirect: func(r *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			return nil
		}, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, Proxy: http.ProxyFromEnvironment}}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Target, nil)
		if err != nil {
			fail("Invalid URL")
			break
		}
		req.Header.Set("User-Agent", "ShieldOps-Probe/"+version)
		resp, err := client.Do(req)
		if err != nil {
			fail(classifyErr(err))
			break
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if !statusMatches(resp.StatusCode, c.ExpectedStatus) {
			fail(fmt.Sprintf("Unexpected status %d", resp.StatusCode))
		} else if c.Keyword != "" && !bytes.Contains(body, []byte(c.Keyword)) {
			fail("Keyword not found")
		} else {
			up()
		}
	case "tcp":
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", c.Target)
		if err != nil {
			fail(classifyErr(err))
			break
		}
		conn.Close()
		up()
	case "dns":
		r := &net.Resolver{}
		var err error
		var n int
		switch strings.ToUpper(c.RecordType) {
		case "AAAA":
			var ips []net.IP
			ips, err = r.LookupIP(ctx, "ip6", c.Target)
			n = len(ips)
		case "CNAME":
			var s string
			s, err = r.LookupCNAME(ctx, c.Target)
			if s != "" {
				n = 1
			}
		case "MX":
			var mx []*net.MX
			mx, err = r.LookupMX(ctx, c.Target)
			n = len(mx)
		case "TXT":
			var t []string
			t, err = r.LookupTXT(ctx, c.Target)
			n = len(t)
		case "NS":
			var ns []*net.NS
			ns, err = r.LookupNS(ctx, c.Target)
			n = len(ns)
		default:
			var ips []net.IP
			ips, err = r.LookupIP(ctx, "ip4", c.Target)
			n = len(ips)
		}
		if err != nil || n == 0 {
			fail("DNS lookup failed")
		} else {
			up()
		}
	default:
		res.Status, res.Error = "down", "Unknown check type"
	}
	return res
}

func runProbe() {
	log.SetFlags(0)
	log.SetPrefix("shieldops-probe: ")
	token := strings.TrimSpace(os.Getenv("SHIELDOPS_PROBE_TOKEN"))
	endpoint := strings.TrimRight(strings.TrimSpace(os.Getenv("SHIELDOPS_ENDPOINT")), "/")
	if !strings.HasPrefix(token, "so_probe_") {
		log.Fatal("SHIELDOPS_PROBE_TOKEN must be set to the so_probe_… token shown when you added the location")
	}
	if !strings.HasPrefix(endpoint, "http://") && !strings.HasPrefix(endpoint, "https://") {
		log.Fatal("SHIELDOPS_ENDPOINT must be the ingestion URL, for example https://shieldops.example.com/ingest")
	}
	api := &http.Client{Timeout: 20 * time.Second}
	call := func(method, path string, body any, out any) error {
		var rd io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		}
		req, _ := http.NewRequest(method, endpoint+"/v1/probe/"+path, rd)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "shieldops-agent/"+version)
		resp, err := api.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode == 401 || resp.StatusCode == 403 {
			return fmt.Errorf("token rejected (%d): was this probe removed in ShieldOps?", resp.StatusCode)
		}
		if resp.StatusCode >= 300 {
			return fmt.Errorf("ShieldOps answered %d", resp.StatusCode)
		}
		if out != nil {
			return json.NewDecoder(resp.Body).Decode(out)
		}
		return nil
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	var mu sync.Mutex
	var pending []probeResult
	checks := map[string]probeCheck{}
	next := map[string]time.Time{}
	sem := make(chan struct{}, 8)
	var lastFetch, lastPost time.Time
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	log.Printf("version %s, reporting to %s", version, endpoint)

	for {
		select {
		case <-stop:
			log.Print("stopping")
			return
		case <-tick.C:
		}
		now := time.Now()
		if now.Sub(lastFetch) >= 60*time.Second {
			var work struct {
				Checks []probeCheck `json:"checks"`
			}
			if err := call(http.MethodGet, "work", nil, &work); err != nil {
				log.Printf("could not fetch checks: %v", err)
				lastFetch = now.Add(-45 * time.Second) // retry in 15 s
			} else {
				fresh := map[string]probeCheck{}
				for _, c := range work.Checks {
					fresh[c.ID] = c
					if _, ok := next[c.ID]; !ok {
						next[c.ID] = now
					}
				}
				checks = fresh
				lastFetch = now
			}
		}
		for id, c := range checks {
			if now.Before(next[id]) {
				continue
			}
			interval := time.Duration(c.IntervalSec) * time.Second
			if interval < 30*time.Second {
				interval = 30 * time.Second
			}
			next[id] = now.Add(interval)
			sem <- struct{}{}
			go func(c probeCheck) {
				defer func() { <-sem }()
				r := runCheck(c)
				mu.Lock()
				pending = append(pending, r)
				mu.Unlock()
			}(c)
		}
		mu.Lock()
		ready := len(pending) > 0 && (len(pending) >= 50 || now.Sub(lastPost) >= 5*time.Second)
		var batch []probeResult
		if ready {
			batch, pending = pending, nil
		}
		mu.Unlock()
		if ready {
			if err := call(http.MethodPost, "results", map[string]any{"results": batch}, nil); err != nil {
				log.Printf("could not send %d results: %v", len(batch), err)
			}
			lastPost = now
		}
	}
}