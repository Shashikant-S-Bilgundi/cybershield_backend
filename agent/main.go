// ShieldOps agent: reports host metrics, services and containers to ShieldOps every 30 seconds.
//
// It only makes outbound HTTPS requests to your ShieldOps server. It opens no ports,
// accepts no commands, and never sends file contents, environment variables or logs.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var version = "1.1.0"

type config struct {
	token    string
	endpoint string
	interval time.Duration
	hostRoot string
	docker   bool
	services []string
	pm2Home  string
}

func loadConfig() (config, error) {
	c := config{
		token:    strings.TrimSpace(os.Getenv("SHIELDOPS_AGENT_TOKEN")),
		endpoint: strings.TrimRight(strings.TrimSpace(os.Getenv("SHIELDOPS_ENDPOINT")), "/"),
		interval: 30 * time.Second,
		hostRoot: envOr("SHIELDOPS_HOST_ROOT", "/"),
		docker:   os.Getenv("SHIELDOPS_DOCKER") != "0",
		pm2Home:  os.Getenv("SHIELDOPS_PM2_HOME"),
	}
	if s := os.Getenv("SHIELDOPS_SERVICES"); s != "" {
		for _, name := range strings.Split(s, ",") {
			if n := strings.TrimSpace(name); n != "" {
				c.services = append(c.services, n)
			}
		}
	}
	if v := os.Getenv("SHIELDOPS_INTERVAL_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 10 && n <= 600 {
			c.interval = time.Duration(n) * time.Second
		}
	}
	if !strings.HasPrefix(c.token, "so_agent_") {
		return c, errors.New("SHIELDOPS_AGENT_TOKEN is missing or is not an agent token (so_agent_…)")
	}
	if !strings.HasPrefix(c.endpoint, "https://") && !strings.HasPrefix(c.endpoint, "http://") {
		return c, errors.New("SHIELDOPS_ENDPOINT must be your ShieldOps ingestion URL, like https://shieldops.example.com/ingest/v1")
	}
	return c, nil
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "probe" {
		runProbe()
		return
	}
	once := flag.Bool("once", false, "collect one report, print it as JSON and exit (sends nothing)")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println("shieldops-agent", version)
		return
	}
	log.SetFlags(0)
	log.SetPrefix("shieldops-agent: ")

	cfg, err := loadConfig()
	if *once {
		if cfg.hostRoot == "" {
			cfg.hostRoot = "/"
		}
		cfg.docker = os.Getenv("SHIELDOPS_DOCKER") != "0"
		col := newCollector(cfg)
		col.collect() // first pass primes the CPU and network counters
		time.Sleep(time.Second)
		out, _ := json.MarshalIndent(col.collect(), "", "  ")
		fmt.Println(string(out))
		return
	}
	if err != nil {
		log.Fatal(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	col := newCollector(cfg)
	col.collect()
	log.Printf("version %s reporting to %s every %s", version, cfg.endpoint, cfg.interval)

	client := &http.Client{Timeout: 15 * time.Second}
	backoff := time.Duration(0)
	ticker := time.NewTicker(cfg.interval)
	defer ticker.Stop()
	// First report after 2 seconds (enough to measure CPU), so a new server appears right away.
	first := time.After(2 * time.Second)
	for {
		select {
		case <-ctx.Done():
			log.Print("stopping")
			return
		case <-first:
		case <-ticker.C:
		}
		if backoff > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
		}
		report := col.collect()
		next, fatal, err := send(ctx, client, cfg, report)
		switch {
		case fatal != nil:
			// A revoked or wrong token will not start working by retrying quickly.
			log.Printf("%v; retrying in 10 minutes", fatal)
			backoff = 10 * time.Minute
		case err != nil:
			if backoff == 0 {
				backoff = 15 * time.Second
			} else if backoff < 5*time.Minute {
				backoff *= 2
			}
			log.Printf("send failed: %v; retrying in %s", err, backoff)
		default:
			backoff = 0
			if next > 0 && next != cfg.interval {
				cfg.interval = next
				ticker.Reset(next)
				log.Printf("interval changed to %s by the server", next)
			}
		}
	}
}

func send(ctx context.Context, client *http.Client, cfg config, report *Report) (time.Duration, error, error) {
	body, err := json.Marshal(report)
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.endpoint+"/agent/report", bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.token)
	req.Header.Set("User-Agent", "shieldops-agent/"+version)
	res, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(res.Body, 64<<10))
	if res.StatusCode == 401 || res.StatusCode == 403 {
		return 0, fmt.Errorf("token refused (%d): %s", res.StatusCode, strings.TrimSpace(string(data))), nil
	}
	if res.StatusCode >= 300 {
		return 0, nil, fmt.Errorf("server answered %d: %s", res.StatusCode, strings.TrimSpace(string(data)))
	}
	var reply struct {
		IntervalSec int `json:"intervalSec"`
	}
	_ = json.Unmarshal(data, &reply)
	if reply.IntervalSec >= 10 && reply.IntervalSec <= 600 {
		return time.Duration(reply.IntervalSec) * time.Second, nil, nil
	}
	return 0, nil, nil
}