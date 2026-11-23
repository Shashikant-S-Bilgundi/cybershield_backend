package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"
)

type ctrCPU struct{ total, system uint64 }

// Docker's API over its local socket. Only GET requests are ever made.
func dockerClient(sock string) *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		}},
	}
}

func dockerGet(cl *http.Client, path string, v any) error {
	res, err := cl.Get("http://docker" + path)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	return json.NewDecoder(res.Body).Decode(v)
}

func (c *collector) containers() []Container {
	sock := envOr("SHIELDOPS_DOCKER_SOCKET", "/var/run/docker.sock")
	cl := dockerClient(sock)
	var list []struct {
		ID    string   `json:"Id"`
		Names []string `json:"Names"`
		Image string   `json:"Image"`
		State string   `json:"State"`
	}
	if dockerGet(cl, "/containers/json?all=1", &list) != nil {
		return nil
	}
	out := []Container{}
	for _, item := range list {
		if len(out) >= 50 {
			break
		}
		state := item.State
		switch state {
		case "running", "restarting", "exited", "paused":
		case "created", "dead", "removing":
			state = "exited"
		default:
			continue
		}
		ctr := Container{ID: item.ID[:12], Image: item.Image, State: state}
		if len(item.Names) > 0 {
			ctr.Name = strings.TrimPrefix(item.Names[0], "/")
		}
		var info struct {
			RestartCount int `json:"RestartCount"`
			State        struct {
				StartedAt string `json:"StartedAt"`
			} `json:"State"`
		}
		if dockerGet(cl, "/containers/"+item.ID+"/json", &info) == nil {
			ctr.StartedAt = info.State.StartedAt
			ctr.Restarts10m = c.restarts.last10m("docker:"+item.ID, info.RestartCount)
		}
		if state == "running" {
			var st struct {
				CPU struct {
					Usage struct {
						Total uint64 `json:"total_usage"`
					} `json:"cpu_usage"`
					System uint64 `json:"system_cpu_usage"`
					Online int    `json:"online_cpus"`
				} `json:"cpu_stats"`
				Memory struct {
					Usage uint64            `json:"usage"`
					Stats map[string]uint64 `json:"stats"`
				} `json:"memory_stats"`
			}
			if dockerGet(cl, "/containers/"+item.ID+"/stats?stream=false&one-shot=true", &st) == nil {
				// CPU % from the change since the last report, like `docker stats`.
				cur := ctrCPU{st.CPU.Usage.Total, st.CPU.System}
				if prev, ok := c.ctrCPU[item.ID]; ok && cur.system > prev.system && cur.total >= prev.total {
					online := st.CPU.Online
					if online == 0 {
						online = 1
					}
					ctr.CPU = round1(float64(cur.total-prev.total) / float64(cur.system-prev.system) * float64(online) * 100)
				}
				c.ctrCPU[item.ID] = cur
				used := st.Memory.Usage
				if cache, ok := st.Memory.Stats["inactive_file"]; ok && cache < used {
					used -= cache
				}
				ctr.MemoryMB = round1(float64(used) / (1 << 20))
			}
		}
		out = append(out, ctr)
	}
	return out
}