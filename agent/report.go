package main

// Report is what the agent sends. Field names match the ShieldOps API.
type Report struct {
	AgentVersion string      `json:"agentVersion"`
	MachineID    string      `json:"machineId"`
	Hostname     string      `json:"hostname"`
	OS           string      `json:"os"`
	Kernel       string      `json:"kernel"`
	CPUCores     int         `json:"cpuCores"`
	MemoryGB     float64     `json:"memoryGb"`
	IPs          []string    `json:"ips"`
	UptimeSec    int64       `json:"uptimeSec"`
	IntervalSec  int         `json:"intervalSec"`
	Usage        Usage       `json:"usage"`
	Disks        []Disk      `json:"disks"`
	Services     []Service   `json:"services"`
	Containers   []Container `json:"containers"`
}

type Usage struct {
	CPU        float64 `json:"cpu"`
	Memory     float64 `json:"memory"`
	Disk       float64 `json:"disk"`
	Load1      float64 `json:"load1"`
	NetInKbps  float64 `json:"netInKbps"`
	NetOutKbps float64 `json:"netOutKbps"`
}

type Disk struct {
	Mount   string  `json:"mount"`
	UsedGB  float64 `json:"usedGb"`
	TotalGB float64 `json:"totalGb"`
}

type Service struct {
	Name        string  `json:"name"`
	Manager     string  `json:"manager"`
	Status      string  `json:"status"`
	Restarts10m int     `json:"restarts10m"`
	CPU         float64 `json:"cpu"`
	MemoryMB    float64 `json:"memoryMb"`
}

type Container struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Image       string  `json:"image"`
	State       string  `json:"state"`
	Restarts10m int     `json:"restarts10m"`
	CPU         float64 `json:"cpu"`
	MemoryMB    float64 `json:"memoryMb"`
	StartedAt   string  `json:"startedAt"`
}